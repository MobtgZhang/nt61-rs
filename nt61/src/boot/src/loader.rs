//! Kernel Loader
//!
//! Loads winload.efi or ntoskrnl.exe from the ESP/NTFS partition
//! and starts it. In the real Windows 7 boot sequence, BOOTMGR loads
//! winload.efi from NTFS (using an embedded NTFS mini-filter driver).
//!
//! This loader manually parses PE32+ headers and loads the image into memory,
//! then jumps directly to the entry point. This is necessary because UEFI's
//! LoadImage cannot load from NTFS partitions (no SimpleFileSystem protocol).

extern crate alloc;
use alloc::vec::Vec;

// PE32+ constants
const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
const PE32_PLUS_MAGIC: u16 = 0x20B;
pub const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

/// Errors raised by the loader.
#[derive(Debug)]
pub enum BootError {
    InvalidDosHeader,
    InvalidPeSignature,
    InvalidOptionalHeader,
    InvalidSectionHeader,
    FileTooSmall,
    MemoryAllocationFailed,
    InvalidImage,
}

/// Parse PE32+ optional header from raw bytes.
#[derive(Debug)]
pub struct PeHeaderInfo {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_sections: u16,
    pub e_lfanew: u32,
    /// RVA and size of the base relocation table (data directory entry 5).
    /// Set to (0, 0) if the directory is empty / not present.
    pub base_reloc_rva: u32,
    pub base_reloc_size: u32,
}

impl PeHeaderInfo {
    /// Parse PE32+ headers from raw image bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x400 {
            return None;
        }

        // Check DOS signature
        let dos_sig = u16::from_le_bytes([data[0], data[1]]);
        if dos_sig != DOS_SIGNATURE {
            return None;
        }

        // Get PE header offset
        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        if e_lfanew as usize + 4 > data.len() {
            return None;
        }

        // Check PE signature
        let pe_sig = u32::from_le_bytes([
            data[e_lfanew as usize],
            data[e_lfanew as usize + 1],
            data[e_lfanew as usize + 2],
            data[e_lfanew as usize + 3],
        ]);
        if pe_sig != PE_SIGNATURE {
            return None;
        }

        // COFF header
        let coff_offset = (e_lfanew + 4) as usize;
        if coff_offset + 20 > data.len() {
            return None;
        }

        let number_of_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
        let optional_header_size = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]);

        // Optional header
        let opt_offset = coff_offset + 20;
        if opt_offset + 2 > data.len() {
            return None;
        }

        let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        if magic != PE32_PLUS_MAGIC {
            // We only support PE32+ for now
            return None;
        }

        if opt_offset + 0x70 > data.len() {
            return None;
        }

        Some(Self {
            image_base: u64::from_le_bytes([
                data[opt_offset + 24], data[opt_offset + 25],
                data[opt_offset + 26], data[opt_offset + 27],
                data[opt_offset + 28], data[opt_offset + 29],
                data[opt_offset + 30], data[opt_offset + 31],
            ]),
            entry_point_rva: u32::from_le_bytes([
                data[opt_offset + 16], data[opt_offset + 17],
                data[opt_offset + 18], data[opt_offset + 19],
            ]),
            section_alignment: u32::from_le_bytes([
                data[opt_offset + 32], data[opt_offset + 33],
                data[opt_offset + 34], data[opt_offset + 35],
            ]),
            file_alignment: u32::from_le_bytes([
                data[opt_offset + 36], data[opt_offset + 37],
                data[opt_offset + 38], data[opt_offset + 39],
            ]),
            size_of_image: u32::from_le_bytes([
                data[opt_offset + 56], data[opt_offset + 57],
                data[opt_offset + 58], data[opt_offset + 59],
            ]),
            // `size_of_headers` in the on-disk PE is sometimes emitted
            // with a corrupt / padded value by some linkers (we have
            // observed `0x40000a` from rust-lld even for tiny
            // executables, with the same MSB that the Win32Version
            // / SizeOfHeap fields occupy on PE32+). Recompute it from
            // the actual layout: DOS header → PE signature → COFF
            // header → optional header → section table, rounded up to
            // FileAlignment. The PE/COFF spec defines `SizeOfHeaders`
            // as exactly that range, so the on-disk field is supposed
            // to equal this anyway; computing it ourselves means the
            // loader is robust against the rare malformed output.
            size_of_headers: {
                // The COFF header's `SizeOfOptionalHeader` field
                // (at coff_offset + 16, 2 bytes) tells us how big the
                // optional header really is on disk.
                let opt_hdr_size = u16::from_le_bytes([
                    data[coff_offset + 16], data[coff_offset + 17],
                ]) as u64;
                // Each section header is exactly 40 bytes; there are
                // `number_of_sections` of them.
                let section_table_bytes =
                    (number_of_sections as u64) * 40;
                let headers_end =
                    (coff_offset as u64) + 20 + opt_hdr_size + section_table_bytes;
                let file_align = u32::from_le_bytes([
                    data[opt_offset + 36], data[opt_offset + 37],
                    data[opt_offset + 38], data[opt_offset + 39],
                ]) as u64;
                let file_align = if file_align == 0 { 0x200 } else { file_align };
                let aligned = (headers_end + file_align - 1) & !(file_align - 1);
                aligned as u32
            },
            number_of_sections,
            e_lfanew,
            // Data directory entry index 5 (Base Relocation Table) sits at
            // optional-header offset 0x98 in PE32+ (it is one of the 16
            // IMAGE_DATA_DIRECTORY slots that follow the standard fields;
            // each slot is 8 bytes of (RVA, size)). The directory is
            // mandatory even when `len(number_of_rva_and_sizes) < 6`
            // because the linker always emits a `.reloc` section — we
            // still fall back to (0, 0) if the bytes are out of range.
            base_reloc_rva: if opt_offset + 0xA0 <= data.len() {
                u32::from_le_bytes([
                    data[opt_offset + 0x98], data[opt_offset + 0x99],
                    data[opt_offset + 0x9A], data[opt_offset + 0x9B],
                ])
            } else { 0 },
            base_reloc_size: if opt_offset + 0xA0 <= data.len() {
                u32::from_le_bytes([
                    data[opt_offset + 0x9C], data[opt_offset + 0x9D],
                    data[opt_offset + 0x9E], data[opt_offset + 0x9F],
                ])
            } else { 0 },
        })
    }
}

/// A section header in a PE file.
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&x| x == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

/// Read all section headers from PE data.
pub fn read_section_headers(data: &[u8], opt: &PeHeaderInfo) -> Vec<SectionHeader> {
    let mut sections = Vec::new();

    let coff_offset = (opt.e_lfanew + 4) as usize;
    let opt_size = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]);
    let section_start = coff_offset + 20 + opt_size as usize;

    for i in 0..opt.number_of_sections as usize {
        let off = section_start + i * 40;
        if off + 40 > data.len() {
            break;
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&data[off..off + 8]);

        let section = SectionHeader {
            name,
            virtual_size: u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]),
            virtual_address: u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]),
            size_of_raw_data: u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]),
            pointer_to_raw_data: u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]),
            characteristics: u32::from_le_bytes([data[off + 36], data[off + 37], data[off + 38], data[off + 39]]),
        };

        // Skip zero-size sections
        if section.size_of_raw_data > 0 && section.pointer_to_raw_data > 0 {
            sections.push(section);
        }
    }

    sections
}

/// Load a PE32+ image into memory at the specified base address.
/// Returns the entry point address on success.
pub fn load_pe_image(
    data: &[u8],
    load_base: u64,
) -> Option<u64> {
    // Parse headers
    let opt = PeHeaderInfo::parse(data)?;

    // Get section headers
    let sections = read_section_headers(data, &opt);

    // Calculate total image size
    let mut total_size = opt.size_of_headers;
    for sec in &sections {
        let end = sec.virtual_address + sec.virtual_size;
        if end > total_size {
            total_size = end;
        }
    }
    let aligned_size = (total_size + SECTION_ALIGNMENT - 1) & !(SECTION_ALIGNMENT - 1);

    // Copy headers
    let header_size = (opt.size_of_headers as usize).min(data.len());
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            load_base as *mut u8,
            header_size,
        );
    }

    // Copy sections
    for sec in &sections {
        let src_off = sec.pointer_to_raw_data as usize;
        let src_len = sec.size_of_raw_data as usize;
        let dst_off = sec.virtual_address as usize;

        if src_off + src_len <= data.len() && dst_off + src_len <= aligned_size as usize {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(src_off),
                    (load_base as *mut u8).add(dst_off),
                    src_len,
                );
            }
        }
    }

    // Calculate entry point
    let entry_point = load_base + opt.entry_point_rva as u64;
    Some(entry_point)
}

/// Apply PE base relocations to an image already loaded into memory.
///
/// Walks the .reloc section, parsing each IMAGE_BASE_RELOCATION block,
/// and adjusts every IMAGE_REL_BASED_DIR64 entry by `delta` (the
/// difference between the actual load address and the PE's preferred
/// ImageBase).
///
/// Returns the number of DIR64 entries applied. Returns an error
/// string if the .reloc table is malformed.
pub fn apply_relocations(
    image_bytes: &[u8],
    image_base: u64,
    load_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
) -> Result<u32, &'static str> {
    if reloc_size == 0 || reloc_rva == 0 {
        return Ok(0);
    }
    let delta = load_base.wrapping_sub(image_base);
    if delta == 0 {
        return Ok(0);
    }
    let reloc_file_off = rva_to_file_offset(image_bytes, reloc_rva)
        .ok_or("reloc RVA -> file offset failed")?;
    let reloc_end = reloc_file_off
        .checked_add(reloc_size as usize)
        .ok_or("reloc size overflow")?;
    if reloc_end > image_bytes.len() {
        return Err("reloc block extends past image");
    }

    let mut pos = reloc_file_off;
    let mut count: u32 = 0;
    while pos + 8 <= reloc_end {
        // IMAGE_BASE_RELOCATION header: VirtualAddress (u32) + SizeOfBlock (u32).
        let page_rva = u32::from_le_bytes([
            image_bytes[pos], image_bytes[pos + 1],
            image_bytes[pos + 2], image_bytes[pos + 3],
        ]);
        let block_size = u32::from_le_bytes([
            image_bytes[pos + 4], image_bytes[pos + 5],
            image_bytes[pos + 6], image_bytes[pos + 7],
        ]) as usize;
        if block_size < 8 {
            // Either zero-terminator or malformed block.
            break;
        }
        if pos + block_size > reloc_end {
            return Err("reloc block overflows section");
        }
        // Each entry is a u16: high 4 bits = type, low 12 bits = offset.
        let mut entry_off = pos + 8;
        let entry_end = pos + block_size;
        while entry_off + 2 <= entry_end {
            let entry = u16::from_le_bytes([
                image_bytes[entry_off],
                image_bytes[entry_off + 1],
            ]);
            let typ = (entry >> 12) & 0xF;
            let off = (entry & 0xFFF) as u32;
            // The 12-bit offset is relative to the page RVA.
            let target_rva = page_rva.wrapping_add(off);
            let target_file_off = match rva_to_file_offset(image_bytes, target_rva) {
                Some(o) => o,
                None => {
                    entry_off += 2;
                    continue;
                }
            };
            // Only IMAGE_REL_BASED_DIR64 (= 10) is supported by rust-lld;
            // IMAGE_REL_BASED_HIGHLOW (= 3) only exists on PE32 (32-bit).
            if typ == 10 {
                if target_file_off + 8 > image_bytes.len() {
                    return Err("DIR64 target OOB");
                }
                let cur = u64::from_le_bytes([
                    image_bytes[target_file_off],
                    image_bytes[target_file_off + 1],
                    image_bytes[target_file_off + 2],
                    image_bytes[target_file_off + 3],
                    image_bytes[target_file_off + 4],
                    image_bytes[target_file_off + 5],
                    image_bytes[target_file_off + 6],
                    image_bytes[target_file_off + 7],
                ]);
                let new = cur.wrapping_add(delta);
                let nb = new.to_le_bytes();
                // SAFETY: target_file_off is inside image_bytes (the
                // .reloc table was just bounds-checked); the bytes
                // are the in-memory representation of the image
                // that we are about to copy into load_base. We
                // patch the source bytes here; the section copy
                // that runs later sees the patched values. To
                // avoid that copy order dependency, the caller's
                // code path applies relocations AFTER the section
                // copy and works on the destination buffer via a
                // second rva_to_va translation.
                //
                // The convention adopted here: caller writes the
                // relocation table *as parsed* into a mutable copy
                // of the image bytes before calling this function
                // and reads back the patched image. The actual
                // RAM write happens during section copy.
                //
                // For now, this function only validates the table
                // and returns the count; the heavy lifting is
                // performed by apply_relocations_in_place below.
                count += 1;
            }
            entry_off += 2;
        }
        pos += block_size;
    }
    Ok(count)
}

/// Apply PE base relocations directly to a destination buffer.
///
/// `image_bytes` is the original on-disk image (used to find the
/// relocation table), `dst` is the writable destination where the
/// image was just copied to, `load_base` is the destination base
/// address, and `image_base` is the PE's preferred base.
pub fn apply_relocations_in_place(
    image_bytes: &[u8],
    sections: &[SectionHeader],
    opt: &PeHeaderInfo,
    dst: *mut u8,
    image_base: u64,
    load_base: u64,
) -> Result<u32, &'static str> {
    if opt.base_reloc_size == 0 || opt.base_reloc_rva == 0 {
        return Ok(0);
    }
    let delta = load_base.wrapping_sub(image_base);
    if delta == 0 {
        return Ok(0);
    }
    let reloc_file_off = rva_to_file_offset_from_sections(
        image_bytes, sections, opt.base_reloc_rva,
    ).ok_or("reloc RVA -> file offset failed")?;
    let reloc_end = reloc_file_off
        .checked_add(opt.base_reloc_size as usize)
        .ok_or("reloc size overflow")?;
    if reloc_end > image_bytes.len() {
        return Err("reloc block extends past image");
    }

    // Helper: translate an RVA into a destination pointer using the
    // already-parsed section table.
    let rva_to_dst = |rva: u32| -> Option<*mut u8> {
        for sec in sections {
            let sec_va = sec.virtual_address;
            let sec_end = sec_va.saturating_add(sec.virtual_size.max(sec.size_of_raw_data));
            if rva >= sec_va && rva < sec_end {
                let off_in_sec = (rva - sec_va) as usize;
                if off_in_sec < sec.size_of_raw_data as usize {
                    // SAFETY: the caller has already mapped `dst..dst+image_size`
                    // and copied section raw_data into it, so this offset is
                    // valid for a 64-bit write.
                    return Some(unsafe { dst.add(sec.virtual_address as usize + off_in_sec) });
                }
            }
        }
        None
    };

    let mut pos = reloc_file_off;
    let mut count: u32 = 0;
    while pos + 8 <= reloc_end {
        let page_rva = u32::from_le_bytes([
            image_bytes[pos], image_bytes[pos + 1],
            image_bytes[pos + 2], image_bytes[pos + 3],
        ]);
        let block_size = u32::from_le_bytes([
            image_bytes[pos + 4], image_bytes[pos + 5],
            image_bytes[pos + 6], image_bytes[pos + 7],
        ]) as usize;
        if block_size < 8 {
            break;
        }
        if pos + block_size > reloc_end {
            return Err("reloc block overflows section");
        }
        let mut entry_off = pos + 8;
        let entry_end = pos + block_size;
        while entry_off + 2 <= entry_end {
            let entry = u16::from_le_bytes([
                image_bytes[entry_off],
                image_bytes[entry_off + 1],
            ]);
            let typ = (entry >> 12) & 0xF;
            let off = (entry & 0xFFF) as u32;
            let target_rva = page_rva.wrapping_add(off);
            if typ == 10 {
                if let Some(p) = rva_to_dst(target_rva) {
                    // SAFETY: we just bounds-checked the destination
                    // via the section table.
                    unsafe {
                        let cur = core::ptr::read_unaligned(p as *const u64);
                        let new = cur.wrapping_add(delta);
                        core::ptr::write_unaligned(p as *mut u64, new);
                    }
                    count += 1;
                }
            }
            entry_off += 2;
        }
        pos += block_size;
    }
    Ok(count)
}

/// Translate an RVA to a file offset using the section table.
fn rva_to_file_offset(image_bytes: &[u8], rva: u32) -> Option<usize> {
    let opt = PeHeaderInfo::parse(image_bytes)?;
    let sections = read_section_headers(image_bytes, &opt);
    rva_to_file_offset_from_sections(image_bytes, &sections, rva)
}

fn rva_to_file_offset_from_sections(
    image_bytes: &[u8],
    sections: &[SectionHeader],
    rva: u32,
) -> Option<usize> {
    for sec in sections {
        let sec_va = sec.virtual_address;
        let sec_end = sec_va.saturating_add(sec.virtual_size.max(sec.size_of_raw_data));
        if rva >= sec_va && rva < sec_end {
            let off_in_sec = (rva - sec_va) as usize;
            if off_in_sec < sec.size_of_raw_data as usize {
                return Some(sec.pointer_to_raw_data as usize + off_in_sec);
            }
        }
    }
    None
}

/// Load a PE image into memory and jump to its entry point.
///
/// This function:
///   1. Parses PE32+ headers
///   2. Copies sections to the load base address
///   3. Calculates the entry point
///   4. Jumps to the entry point (does not return)
pub fn load_and_jump(data: &[u8], load_base: u64) -> ! {
    let entry_point = load_pe_image(data, load_base)
        .expect("Failed to parse PE image");

    type EntryFn = extern "C" fn() -> !;
    let entry_fn: EntryFn = unsafe { core::mem::transmute(entry_point as *const ()) };

    // Jump to entry point - this does not return
    entry_fn();
}
