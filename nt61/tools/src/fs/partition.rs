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
    // Protective MBR must be 0xEE; LBA1 must begin with "EFI PART"
    if data.len() < 1024 + 512 {
        return None;
    }
    if data[510] != 0x55 || data[511] != 0xAA {
        return None;
    }
    if data[446 + 4] != 0xEE {
        return None;
    }
    let hdr = &data[512..512 + 92];
    if &hdr[0..8] != b"EFI PART" {
        return None;
    }
    let part_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_parts = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
    let part_entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
    if part_entry_size < 128 {
        return None;
    }
    let part_start = part_entry_lba as usize * 512;
    if part_start + num_parts * part_entry_size > data.len() {
        return None;
    }
    let sector_size = 512u64;
    let mut out = Vec::new();
    let mut idx = 1u32;
    for i in 0..num_parts {
        let off = part_start + i * part_entry_size;
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
    Some(out)
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
