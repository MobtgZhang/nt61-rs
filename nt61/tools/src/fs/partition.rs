//! Partition table parsing for the build tool.
//!
//! Walks the GPT (and falls back to MBR when no GPT signature is present) to
//! expose a 1-indexed list of partitions. The CLI uses this list to resolve
//! `-p <n>` to a byte range inside the disk image, then hands that slice to
//! the FAT32 image reader.

use crate::error::{BuildError, Result};

/// Information about a single partition entry.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// 1-based partition number (matches the order in the partition table).
    pub index: u32,
    /// Byte offset from the start of the disk image.
    pub byte_offset: u64,
    /// Size in bytes.
    pub byte_size: u64,
    /// GPT partition type GUID, if available.
    pub gpt_type: Option<[u8; 16]>,
    /// GPT partition name (UTF-8), if any.
    pub gpt_name: Option<String>,
}

/// Enumerate partitions. Tries GPT first, then MBR.
pub fn list_partitions(data: &[u8]) -> Result<Vec<PartitionInfo>> {
    if data.len() < 512 {
        return Err(BuildError::InvalidFormat("image smaller than MBR".into()));
    }
    if let Some(list) = try_gpt(data) {
        return Ok(list);
    }
    try_mbr(data)
}

// =====================================================================
// GPT
// =====================================================================

fn try_gpt(data: &[u8]) -> Option<Vec<PartitionInfo>> {
    // Protective MBR must be 0xEE.
    if data.len() < 1024 + 512 {
        return None;
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return None;
    }
    if data[446 + 4] != 0xEE {
        return None;
    }

    // Search for "EFI PART" signature. The GPT header can be at LBA 1
    // (sector 1) or LBA 2 (sector 2) depending on the firmware.
    // Try sector 1 first (the standard UEFI location), then scan for it.
    // GPT partition entries may not be at the header's claimed location
    // (field at offset 72), so we always use LBA 34 for the entries
    // (standard on UEFI + Windows). We only use the header to validate
    // that GPT is present.
    let _gpt_header_lba: u64 = if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
        1u64
    } else {
        // Scan sectors 2..34 for the GPT header.
        let mut found_lba = None;
        for sector in 2u64..34u64 {
            let off = (sector * 512) as usize;
            if data.len() > off + 8 && &data[off..off + 8] == b"EFI PART" {
                found_lba = Some(sector);
                break;
            }
        }
        match found_lba {
            Some(lba) => lba,
            None => return None,
        }
    };

    // Read GPT header (we know it's at LBA 1 or 2 — read LBA 1 first,
    // fall back to LBA 2).
    let hdr = if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
        &data[512..512 + 92]
    } else {
        // GPT header is at LBA 2 (sector 2).
        let off = 2 * 512;
        if data.len() < off + 92 { return None; }
        &data[off..off + 92]
    };
    if &hdr[0..8] != b"EFI PART" {
        return None;
    }

    eprintln!("[DEBUG try_gpt] GPT header found at LBA 1");
    // GPT partition entry array location.
    // Some GPT headers claim a non-standard partition entry LBA (e.g., sector 2),
    // so we validate the claimed location against the actual disk layout.
    // Canonical UEFI partition entry LBA is 34. We try the claimed LBA first,
    // and fall back to LBA 34 if the claimed location doesn't contain valid entries.
    let part_entry_lba_claimed = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_parts = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
    let part_entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
    eprintln!("[DEBUG try_gpt] claimed_entry_lba={}, num_parts={}, part_entry_size={}", part_entry_lba_claimed, num_parts, part_entry_size);
    if part_entry_size < 128 {
        return None;
    }

    // Decide which LBA to use for partition entries. The GPT header claims
    // `partition_entry_lba` (field at offset 72). We validate this by checking
    // if the claimed sector has structurally valid GPT partition entries:
    // 1. Non-zero type GUID (first 16 bytes must not all be zero)
    // 2. Non-zero starting LBA (first_lba != 0)
    // 3. first_lba <= last_lba
    // This disambiguates the case where the GPT header claims LBA 2 (which
    // is the GPT header itself on some images, where the header's first 16
    // bytes happen to match the ESP partition type GUID).
    let claimed_start = part_entry_lba_claimed as usize * 512;
    let sector_size = 512u64;

    let has_valid_partition_entries = |sector_off: usize| -> bool {
        if sector_off + part_entry_size > data.len() { return false; }
        let entry = &data[sector_off..sector_off + part_entry_size];
        // Reject sectors that start with GPT/NTFS signatures.
        if sector_off + 4 <= data.len() && &data[sector_off..sector_off + 4] == b"FILE" { return false; }
        if sector_off + 8 <= data.len() && &data[sector_off..sector_off + 8] == b"EFI PART" { return false; }
        // Must have a non-zero type GUID.
        if entry[0..16].iter().all(|b| *b == 0) { return false; }
        // Must have non-zero first_lba and first_lba <= last_lba.
        let first_lba = u64::from_le_bytes([entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38], entry[39]]);
        let last_lba = u64::from_le_bytes([entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46], entry[47]]);
        if first_lba == 0 || last_lba < first_lba { return false; }
        true
    };

    // Try the claimed LBA; if that sector doesn't have valid entries, fall back
    // to the canonical UEFI partition entry LBA (34).
    let part_start = if has_valid_partition_entries(claimed_start) {
        eprintln!("[DEBUG try_gpt] using claimed LBA {} (offset {})", part_entry_lba_claimed, claimed_start);
        claimed_start
    } else {
        let canonical = 34usize * 512;
        if has_valid_partition_entries(canonical) {
            eprintln!("[DEBUG try_gpt] using canonical LBA 34 (offset {})", canonical);
            canonical
        } else {
            eprintln!("[DEBUG try_gpt] no valid partition entry sectors found");
            return None;
        }
    };

    // Validate bounds.
    if part_start + num_parts * part_entry_size > data.len() {
        return None;
    }
    let mut out = Vec::new();
    let mut idx = 1u32;
    for i in 0..num_parts {
        let off = part_start as usize + i * part_entry_size;
        let entry = &data[off..off + part_entry_size];
        let type_guid: [u8; 16] = entry[0..16].try_into().unwrap();
        if type_guid.iter().all(|b| *b == 0) {
            continue; // empty
        }
        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        if last_lba < first_lba {
            continue;
        }
        let name_bytes = &entry[56..128];
        let name = utf16le_to_string(name_bytes);
        let byte_offset = first_lba * sector_size;
        let byte_size = (last_lba - first_lba + 1) * sector_size;
        out.push(PartitionInfo {
            index: idx,
            byte_offset,
            byte_size,
            gpt_type: Some(type_guid),
            gpt_name: name,
        });
        idx += 1;
    }
    debug_print_partitions(&out);
    Some(out)
}

fn debug_print_partitions(parts: &[PartitionInfo]) {
    eprintln!("[DEBUG try_gpt] found {} partitions:", parts.len());
    for p in parts {
        eprintln!("[DEBUG try_gpt]   partition {}: name={:?} offset={} size={}MB",
            p.index, p.gpt_name, p.byte_offset, p.byte_size / 1024 / 1024);
    }
}

fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16(&units).ok()
}

// =====================================================================
// MBR
// =====================================================================

fn try_mbr(data: &[u8]) -> Result<Vec<PartitionInfo>> {
    if data.len() < 512 {
        return Err(BuildError::InvalidFormat("image smaller than MBR".into()));
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return Err(BuildError::InvalidFormat(
            "no valid MBR signature (0x55AA)".into(),
        ));
    }
    let mut out = Vec::new();
    let mut idx = 1u32;
    for i in 0..4 {
        let off = 446 + i * 16;
        let entry = &data[off..off + 16];
        let type_byte = entry[4];
        if type_byte == 0 {
            continue;
        }
        let first_lba = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let size_lba = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as u64;
        if size_lba == 0 {
            continue;
        }
        out.push(PartitionInfo {
            index: idx,
            byte_offset: first_lba * 512,
            byte_size: size_lba * 512,
            gpt_type: None,
            gpt_name: None,
        });
        idx += 1;
    }
    Ok(out)
}
