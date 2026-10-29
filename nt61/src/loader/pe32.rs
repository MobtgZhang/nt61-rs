//! pe32 — PE32 (32-bit Portable Executable) Loader
//
//! This module implements the PE32 (32-bit) specific loading functionality
//! needed for Wow64. PE32 executables have a 32-bit image base and
//! use 32-bit RVA/VA calculations.
//
//! The loader handles:
//!   * PE32 format parsing and validation
//!   * Section mapping and relocations
//!   * Import resolution
//!   * TEB/PEB setup for 32-bit processes
//
//! References:
//!   * Microsoft PE/COFF Specification
//!   * geoffchappell.com — PE32/PE32+ structures

use crate::loader::{DosHeader, FileHeader, SectionHeader, PE_SIGNATURE};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

// =============================================================================
// PE32 Constants
// =============================================================================

/// PE32 machine type (x86 32-bit).
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
/// PE32+ machine type (x64).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// PE32 optional header magic.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
/// PE32+ optional header magic.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

/// Standard PE32 image base (ntdll.dll, kernel32.dll, etc).
pub const PE32_DEFAULT_IMAGE_BASE: u32 = 0x0000_0000_4000_0000;

/// Standard image base for executables.
pub const PE32_EXE_IMAGE_BASE: u32 = 0x0000_0000_0040_0000;

/// Section alignment for PE32 (typically 0x1000).
pub const PE32_SECTION_ALIGNMENT: u32 = 0x1000;

/// File alignment for PE32 (typically 0x200).
pub const PE32_FILE_ALIGNMENT: u32 = 0x200;

/// COFF FileHeader characteristic: the image is a DLL.
/// Note that "is a DLL" is a *file header* characteristic, not a
/// `DllCharacteristics` flag — `DllCharacteristics` bit 0x2000 is
/// `IMAGE_DLLCHARACTERISTICS_WDM_DRIVER` instead.
pub const IMAGE_FILE_DLL: u16 = 0x2000;

// =============================================================================
// PE32 Optional Header (Extended)
// =============================================================================

/// Extended PE32 optional header with data directory.
#[repr(C)]
pub struct OptionalHeader32Ext {
    /// Standard fields.
    pub standard: OptionalHeader32Std,
    /// Windows-specific fields.
    pub windows: OptionalHeader32Windows,
    /// Data directories (16 entries).
    pub data_directory: [ImageDataDirectory; 16],
}

/// Standard COFF fields of the PE32 optional header.
/// Offsets are relative to the start of the optional header.
/// Size: 0x1C bytes (28 bytes).
#[repr(C)]
#[derive(Default)]
pub struct OptionalHeader32Std {
    pub magic: u16,                      // 0x00: PE32 = 0x10B
    pub major_linker_version: u8,        // 0x02
    pub minor_linker_version: u8,        // 0x03
    pub size_of_code: u32,               // 0x04
    pub size_of_initialized_data: u32,   // 0x08
    pub size_of_uninitialized_data: u32, // 0x0C
    pub address_of_entry_point: u32,     // 0x10
    pub base_of_code: u32,               // 0x14
    pub base_of_data: u32,               // 0x18
}

impl OptionalHeader32Std {
    /// Get entry point RVA.
    pub fn entry_point_rva(&self) -> u32 {
        self.address_of_entry_point
    }
}

/// Windows-specific fields of the PE32 optional header. These follow
/// the standard COFF fields and are read by the loader (image base,
/// sizes, subsystem, DLL characteristics, stack/heap defaults).
/// Size: 0x44 bytes (68 bytes); data directories follow at 0x60.
#[repr(C)]
#[derive(Default)]
pub struct OptionalHeader32Windows {
    pub image_base: u32,              // 0x1C (32-bit)
    pub section_alignment: u32,       // 0x20
    pub file_alignment: u32,          // 0x24
    pub major_os_version: u16,        // 0x28
    pub minor_os_version: u16,        // 0x2A
    pub major_image_version: u16,     // 0x2C
    pub minor_image_version: u16,     // 0x2E
    pub major_subsystem_version: u16, // 0x30
    pub minor_subsystem_version: u16, // 0x32
    pub win32_version_value: u32,     // 0x34
    pub size_of_image: u32,           // 0x38
    pub size_of_headers: u32,         // 0x3C
    pub check_sum: u32,               // 0x40
    pub subsystem: u16,               // 0x44
    pub dll_characteristics: u16,     // 0x46
    pub size_of_stack_reserve: u32,   // 0x48
    pub size_of_stack_commit: u32,    // 0x4C
    pub size_of_heap_reserve: u32,    // 0x50
    pub size_of_heap_commit: u32,     // 0x54
    pub loader_flags: u32,            // 0x58
    pub number_of_rva_and_sizes: u32, // 0x5C
}

impl OptionalHeader32Windows {
    /// Get image size.
    pub fn image_size(&self) -> u32 {
        self.size_of_image
    }
}

impl OptionalHeader32Ext {
    /// A PE32 image is a DLL when the COFF FileHeader carries
    /// `IMAGE_FILE_DLL` (0x2000) in `Characteristics`.
    pub fn is_dll(&self, file_header: &FileHeader) -> bool {
        file_header.characteristics & IMAGE_FILE_DLL != 0
    }
}

/// Image data directory entry.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ImageDataDirectory {
    /// Virtual address (RVA) of the data.
    pub virtual_address: u32,
    /// Size of the data in bytes.
    pub size: u32,
}

impl ImageDataDirectory {
    /// Check if this directory entry is valid.
    pub fn is_valid(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }

    /// Get the RVA.
    pub fn rva(&self) -> u32 {
        self.virtual_address
    }

    /// Get the size.
    pub fn size(&self) -> u32 {
        self.size
    }
}

// =============================================================================
// Import Descriptor
// =============================================================================

/// Import directory table entry.
/// Describes a DLL's import information.
#[repr(C)]
#[derive(Default)]
pub struct ImportDirectoryEntry {
    /// RVA to name (hint/name table).
    pub name_rva: u32,
    /// Time date stamp (0 for bound imports).
    pub time_date_stamp: u32,
    /// Forwarder chain (0 if none).
    pub forwarder_chain: u32,
    /// RVA to dll name.
    pub dll_name_rva: u32,
    /// RVA to first thunk (IAT).
    pub first_thunk_rva: u32,
}

/// Import lookup thunk (one entry).
#[repr(C)]
#[derive(Default)]
pub struct ImportLookupEntry {
    /// Either an RVA to a name hint, or an ordinal value.
    pub value: u32,
}

impl ImportLookupEntry {
    /// Check if this is an ordinal import.
    pub fn is_ordinal(&self) -> bool {
        self.value & 0x8000_0000 != 0
    }

    /// Get the ordinal value.
    pub fn ordinal(&self) -> u16 {
        (self.value & 0xFFFF) as u16
    }

    /// Get the hint/name RVA.
    pub fn name_rva(&self) -> u32 {
        self.value & 0x7FFF_FFFF
    }
}

// =============================================================================
// Relocation Entry
// =============================================================================

/// Base relocation block.
#[repr(C)]
#[derive(Default)]
pub struct BaseRelocBlock {
    /// RVA of the block.
    pub page_rva: u32,
    /// Size of the block (including header).
    pub block_size: u32,
}

/// Base relocation types.
pub mod reloc_type {
    pub const ABSOLUTE: u8 = 0;
    pub const HIGH: u8 = 1;
    pub const LOW: u8 = 2;
    pub const HIGHLOW: u8 = 3;
    pub const HIGHADJ: u8 = 4;
    pub const MIPS_JMPADDR: u8 = 5;
    pub const MIPS_JMPADDR16: u8 = 6;
    pub const DIR64: u8 = 10;
}

// =============================================================================
// PE32 Loaded Image
// =============================================================================

/// Represents a loaded PE32 image in memory.
pub struct LoadedImage32 {
    /// Base address where image is loaded.
    pub base_address: u32,
    /// Size of the loaded image.
    pub size_of_image: u32,
    /// Entry point RVA.
    pub entry_point_rva: u32,
    /// Image base (preferred load address).
    pub image_base: u32,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Whether this is a DLL.
    pub is_dll: bool,
    /// Subsystem (console or GUI).
    pub subsystem: u16,
    /// Section headers (copied for reference).
    pub sections: [SectionHeader; 16],
    /// Data directory.
    pub data_directory: [ImageDataDirectory; 16],
    /// Raw bytes of the image (for reading headers).
    pub headers: Vec<u8>,
    /// Loaded section data (sections mapped into image layout).
    pub image_data: Vec<u8>,
    /// Parsed import descriptors.
    pub imports: Vec<ImportDescriptor32>,
}

impl LoadedImage32 {
    /// create a new loaded image.
    pub fn new(base: u32, size: u32) -> Self {
        Self {
            base_address: base,
            size_of_image: size,
            entry_point_rva: 0,
            image_base: 0,
            number_of_sections: 0,
            is_dll: false,
            subsystem: 0,
            sections: [SectionHeader::default(); 16],
            data_directory: [ImageDataDirectory::default(); 16],
            headers: Vec::new(),
            image_data: Vec::new(),
            imports: Vec::new(),
        }
    }

    /// Get the entry point address.
    pub fn entry_point(&self) -> u32 {
        self.base_address + self.entry_point_rva
    }

    /// Convert RVA to a pointer in the loaded image.
    pub fn rva_to_ptr(&self, rva: u32) -> *const u8 {
        (self.base_address + rva) as *const u8
    }

    /// Convert RVA to a mutable pointer.
    pub fn rva_to_ptr_mut(&self, rva: u32) -> *mut u8 {
        (self.base_address + rva) as *mut u8
    }

    pub fn slice_for_rva(&self, rva: u32, length: usize) -> Option<&[u8]> {
        let start = rva as usize;
        let end = start.checked_add(length)?;
        self.image_data.get(start..end)
    }

    pub fn slice_for_rva_mut(&mut self, rva: u32, length: usize) -> Option<&mut [u8]> {
        let start = rva as usize;
        let end = start.checked_add(length)?;
        self.image_data.get_mut(start..end)
    }
}

// =============================================================================
// PE32 Parsing
// =============================================================================

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ]))
}

fn read_data_directory(
    data: &[u8],
    optional_header_offset: usize,
    index: usize,
) -> Option<ImageDataDirectory> {
    let offset = optional_header_offset
        .checked_add(0x60)?
        .checked_add(index.checked_mul(8)?)?;
    if offset.checked_add(8)? > data.len() {
        return None;
    }
    Some(ImageDataDirectory {
        virtual_address: read_u32(data, offset)?,
        size: read_u32(data, offset.checked_add(4)?)?,
    })
}

fn read_image_string(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..)?;
    let length = bytes.iter().position(|&byte| byte == 0)?;
    Some(
        core::str::from_utf8(bytes.get(..length)?)
            .unwrap_or("")
            .to_string(),
    )
}

fn file_offset(header_info: &PE32HeaderInfo, rva: u32) -> Option<usize> {
    header_info.rva_to_file_offset(rva).map(|offset| offset as usize)
}

/// Parse a PE32 image from raw bytes.
///
/// # Arguments
/// * `data` - Raw PE32 file bytes
///
/// # Returns
/// * `Some(PE32HeaderInfo)` on success
/// * `None` if the file is not a valid PE32
pub fn parse_pe32(data: &[u8]) -> Option<PE32HeaderInfo> {
    // Must be at least large enough for DOS header
    if data.len() < core::mem::size_of::<DosHeader>() {
        return None;
    }

    // Parse DOS header
    // Copy the header out of the buffer instead of forming a reference to it:
    // `e_lfanew` can place the PE header at an offset that is not aligned for
    // the struct, and a `&T` over an unaligned pointer is UB in Rust.
    let dos_header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const DosHeader) };

    if !dos_header.is_valid() {
        return None;
    }

    // Get PE header offset
    let pe_offset = dos_header.e_lfanew as usize;
    if pe_offset + 4 > data.len() {
        return None;
    }

    // Check PE signature
    let pe_sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);

    if pe_sig != PE_SIGNATURE {
        return None;
    }

    // Parse file header
    let fh_offset = pe_offset + 4;
    if fh_offset + core::mem::size_of::<FileHeader>() > data.len() {
        return None;
    }

    let file_header =
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(fh_offset) as *const FileHeader) };

    // Verify machine type is I386
    if file_header.machine != IMAGE_FILE_MACHINE_I386 {
        return None;
    }

    let num_sections = file_header.number_of_sections;
    let opt_header_size = file_header.size_of_optional_header as usize;

    // Parse optional header
    let oh_offset = fh_offset + core::mem::size_of::<FileHeader>();
    if oh_offset + opt_header_size > data.len() {
        return None;
    }

    let opt_header = unsafe {
        core::ptr::read_unaligned(
            data.as_ptr().add(oh_offset) as *const crate::loader::OptionalHeader32
        )
    };

    if opt_header.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return None;
    }

    // Parse section headers
    let sh_offset = oh_offset + opt_header_size;
    let mut sections = Vec::with_capacity(num_sections as usize);

    for i in 0..num_sections {
        let offset = sh_offset + (i as usize) * core::mem::size_of::<SectionHeader>();
        if offset + core::mem::size_of::<SectionHeader>() > data.len() {
            break;
        }
        let section =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const SectionHeader) };
        sections.push(section);
    }

    //         "[PE32] Parsed PE32: sections={}, image_base=0x{:08x}, entry=0x{:08x}",
    //         num_sections,
    //         opt_header.image_base,
    //         opt_header.address_of_entry_point
    //     );

    let mut data_directory = [ImageDataDirectory::default(); 16];
    let directory_count = core::cmp::min(16, opt_header.number_of_rva_and_sizes as usize);
    for index in 0..directory_count {
        if let Some(directory) = read_data_directory(data, oh_offset, index) {
            data_directory[index] = directory;
        }
    }

    Some(PE32HeaderInfo {
        dos_header_offset: 0,
        pe_header_offset: pe_offset,
        file_header,
        optional_header: opt_header,
        data_directory,
        section_headers: sections,
    })
}

/// Parsed PE32 header information.
pub struct PE32HeaderInfo {
    pub dos_header_offset: usize,
    pub pe_header_offset: usize,
    pub file_header: FileHeader,
    pub optional_header: crate::loader::OptionalHeader32,
    pub data_directory: [ImageDataDirectory; 16],
    pub section_headers: Vec<SectionHeader>,
}

impl PE32HeaderInfo {
    /// Get the data directory at the given index.
    pub fn get_data_directory(&self, index: usize) -> Option<ImageDataDirectory> {
        self.data_directory.get(index).copied()
    }

    /// Get the section containing an RVA.
    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        for section in &self.section_headers {
            let start = section.virtual_address;
            let end = start + section.virtual_size.max(section.size_of_raw_data);
            if rva >= start && rva < end {
                return Some(section);
            }
        }
        None
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.section_headers {
            if rva >= section.virtual_address
                && rva
                    < section.virtual_address + section.virtual_size.max(section.size_of_raw_data)
            {
                let offset_in_section = rva - section.virtual_address;
                return Some(section.pointer_to_raw_data + offset_in_section);
            }
        }
        None
    }
}

// =============================================================================
// Export Table Parsing
// =============================================================================

/// Parse the export directory of a PE32 image.
pub fn parse_export_directory(
    _data: &[u8],
    _header_info: &PE32HeaderInfo,
) -> Option<ExportDirectory32> {
    // Get export directory RVA from data directory
    // This would be at index 0 of data directories
    // For now, return None as we don't have data directories parsed
    None
}

/// Export directory table entry.
#[repr(C)]
#[derive(Default)]
pub struct ExportDirectoryTable {
    pub flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table_rva: u32,
    pub name_pointer_rva: u32,
    pub ordinal_table_rva: u32,
}

/// Export directory information.
pub struct ExportDirectory32 {
    pub dll_name: String,
    pub exports: Vec<ExportEntry32>,
}

/// A single export entry.
pub struct ExportEntry32 {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
}

// =============================================================================
// Import Table Parsing
// =============================================================================

/// Parse the import directory of a PE32 image.
pub fn parse_import_directory(
    data: &[u8],
    header_info: &PE32HeaderInfo,
) -> Vec<ImportDescriptor32> {
    let directory = match header_info.get_data_directory(1) {
        Some(directory) if directory.is_valid() => directory,
        _ => return Vec::new(),
    };

    let mut descriptors = Vec::new();
    let descriptor_count = directory.size as usize / core::mem::size_of::<ImportDirectoryEntry>();
    for index in 0..descriptor_count {
        let descriptor_rva = directory
            .rva()
            .wrapping_add((index * core::mem::size_of::<ImportDirectoryEntry>()) as u32);
        let descriptor_offset = match file_offset(header_info, descriptor_rva) {
            Some(offset) => offset,
            None => break,
        };

        let original_thunk_rva = match read_u32(data, descriptor_offset) {
            Some(value) => value,
            None => break,
        };
        let time_date_stamp = match read_u32(data, descriptor_offset + 4) {
            Some(value) => value,
            None => break,
        };
        let forwarder_chain = match read_u32(data, descriptor_offset + 8) {
            Some(value) => value,
            None => break,
        };
        let dll_name_rva = match read_u32(data, descriptor_offset + 12) {
            Some(value) => value,
            None => break,
        };
        let first_thunk_rva = match read_u32(data, descriptor_offset + 16) {
            Some(value) => value,
            None => break,
        };
        if dll_name_rva == 0 || first_thunk_rva == 0 {
            break;
        }

        let dll_name = match file_offset(header_info, dll_name_rva)
            .and_then(|offset| read_image_string(data, offset))
        {
            Some(name) => name,
            None => break,
        };

        let lookup_rva = if original_thunk_rva != 0 {
            original_thunk_rva
        } else {
            first_thunk_rva
        };
        let mut imports = Vec::new();
        let mut thunk_index = 0;
        while let Some(lookup_offset) = file_offset(
            header_info,
            lookup_rva.wrapping_add((thunk_index * 4) as u32),
        ) {
            let lookup_value = match read_u32(data, lookup_offset) {
                Some(value) => value,
                None => break,
            };
            if lookup_value == 0 {
                break;
            }
            let lookup = ImportLookupEntry { value: lookup_value };
            let iat_rva = first_thunk_rva.wrapping_add((thunk_index * 4) as u32);

            let import = if lookup.is_ordinal() {
                ImportEntry32 {
                    name: String::new(),
                    ordinal: Some(lookup.ordinal()),
                    hint: 0,
                    thunk_rva: iat_rva,
                    function_rva: 0,
                }
            } else {
                let hint_name_offset = match file_offset(header_info, lookup.name_rva()) {
                    Some(offset) => offset,
                    None => break,
                };
                let hint = match read_u16(data, hint_name_offset) {
                    Some(value) => value,
                    None => break,
                };
                let name_start = hint_name_offset + 2;
                let name = match data
                    .get(name_start..)
                    .and_then(|bytes| bytes.iter().position(|&byte| byte == 0))
                    .and_then(|length| data.get(name_start..name_start + length))
                    .map(|bytes| {
                        core::str::from_utf8(bytes)
                            .unwrap_or("")
                            .to_string()
                    })
                {
                    Some(name) => name,
                    None => break,
                };
                ImportEntry32 {
                    name,
                    ordinal: None,
                    hint,
                    thunk_rva: iat_rva,
                    function_rva: 0,
                }
            };
            imports.push(import);
            thunk_index += 1;
        }

        descriptors.push(ImportDescriptor32 {
            dll_name,
            imports,
            original_thunk_rva,
            time_date_stamp,
            forwarder_chain,
            first_thunk_rva,
        });
    }

    descriptors
}

/// Import descriptor for a single DLL.
pub struct ImportDescriptor32 {
    pub dll_name: String,
    pub imports: Vec<ImportEntry32>,
    pub original_thunk_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub first_thunk_rva: u32,
}

/// A single import entry.
pub struct ImportEntry32 {
    pub name: String,
    pub ordinal: Option<u16>,
    pub hint: u16,
    pub thunk_rva: u32,
    pub function_rva: u32,
}

// =============================================================================
// PE32 Image Loading
// =============================================================================

/// Load a PE32 image into memory.
///
/// # Arguments
/// * `data` - Raw PE32 file bytes
/// * `preferred_base` - Preferred load address (0 for any)
///
/// # Returns
/// * `Some(LoadedImage32)` on success
/// * `None` on failure
pub fn load_pe32(data: &[u8], preferred_base: u32) -> Option<LoadedImage32> {
    // Parse headers
    let header_info = parse_pe32(data)?;

    let opt = &header_info.optional_header;

    // Determine load base
    let load_base = if preferred_base != 0 {
        preferred_base
    } else {
        opt.image_base
    };

    // create loaded image structure
    let mut image = LoadedImage32::new(load_base, opt.size_of_image);
    image.entry_point_rva = opt.address_of_entry_point;
    image.image_base = opt.image_base;
    image.number_of_sections = header_info.file_header.number_of_sections;
    image.is_dll = header_info.file_header.characteristics & IMAGE_FILE_DLL != 0;
    image.subsystem = opt.subsystem;

    // Copy section headers
    for (i, section) in header_info.section_headers.iter().enumerate() {
        if i < 16 {
            image.sections[i] = *section;
        }
    }
    for i in 0..16 {
        image.data_directory[i] = header_info.data_directory[i];
    }

    let image_size = opt.size_of_image as usize;
    let mut image_buf = alloc::vec![0u8; image_size];
    let headers_size = core::cmp::min(opt.size_of_headers as usize, image_size);
    if headers_size <= data.len() {
        image_buf[..headers_size].copy_from_slice(&data[..headers_size]);
    }

    for section in &header_info.section_headers {
        let virt_addr = section.virtual_address as usize;
        let raw_size = section.size_of_raw_data as usize;
        let raw_offset = section.pointer_to_raw_data as usize;

        if virt_addr + raw_size > image_size {
            continue;
        }
        if raw_offset + raw_size > data.len() {
            let available = data.len().saturating_sub(raw_offset);
            let copy_length = available.min(raw_size);
            if copy_length > 0 {
                image_buf[virt_addr..virt_addr + copy_length]
                    .copy_from_slice(&data[raw_offset..raw_offset + copy_length]);
            }
            continue;
        }
        image_buf[virt_addr..virt_addr + raw_size]
            .copy_from_slice(&data[raw_offset..raw_offset + raw_size]);
    }

    image.image_data = image_buf;

    let delta = load_base as i64 - opt.image_base as i64;
    if delta != 0 && delta >= i32::MIN as i64 && delta <= i32::MAX as i64 {
        apply_relocations(&mut image, delta as i32);
    }

    image.imports = parse_import_directory(data, &header_info);

    Some(image)
}

// =============================================================================
// Relocation Application
// =============================================================================

/// Apply relocations to a loaded PE32 image.
///
/// # Arguments
/// * `image` - The loaded image
/// * `delta` - Difference between preferred and actual base
pub fn apply_relocations(image: &mut LoadedImage32, delta: i32) {
    if delta == 0 {
        return;
    }

    let directory = image.data_directory[5];
    if !directory.is_valid() {
        return;
    }

    let mut offset = directory.rva() as usize;
    let end = directory.size() as usize;
    let mut block_offset = 0;
    while block_offset + 8 <= end {
        let page_rva = match read_u32(&image.image_data, offset) {
            Some(value) => value,
            None => break,
        };
        let block_size = match read_u32(&image.image_data, offset + 4) {
            Some(value) => value,
            None => break,
        };
        if block_size < 8 || block_offset + block_size as usize > end {
            break;
        }

        let entry_count = (block_size as usize - 8) / 2;
        for index in 0..entry_count {
            let entry_offset = offset + 8 + index * 2;
            let entry = match read_u16(&image.image_data, entry_offset) {
                Some(value) => value,
                None => break,
            };
            let kind = (entry >> 12) as u8;
            let rva = page_rva.wrapping_add((entry & 0x0FFF) as u32);

            match kind {
                reloc_type::ABSOLUTE => {}
                reloc_type::HIGHLOW => {
                    if let Some(bytes) = image.slice_for_rva_mut(rva, 4) {
                        let value = u32::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        ]);
                        let adjusted = (value as i64 + delta as i64) as u32;
                        bytes.copy_from_slice(&adjusted.to_le_bytes());
                    }
                }
                reloc_type::HIGH => {
                    if let Some(bytes) = image.slice_for_rva_mut(rva, 2) {
                        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                        let adjusted = (value as i32 + ((delta as u32) >> 16) as i32) as u16;
                        bytes.copy_from_slice(&adjusted.to_le_bytes());
                    }
                }
                reloc_type::LOW => {
                    if let Some(bytes) = image.slice_for_rva_mut(rva, 2) {
                        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                        let adjusted = (value as i32 + ((delta as u32) & 0xFFFF) as i32) as u16;
                        bytes.copy_from_slice(&adjusted.to_le_bytes());
                    }
                }
                reloc_type::HIGHADJ => {
                    let next_offset = entry_offset + 2;
                    let next_low = match read_u16(&image.image_data, next_offset) {
                        Some(value) => value,
                        None => break,
                    };
                    if let Some(bytes) = image.slice_for_rva_mut(rva, 2) {
                        let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                        let mut high_delta = (delta as u32) >> 16;
                        let low_delta = (delta as u32) & 0xFFFF;
                        let next_low_after_delta = u32::from(next_low)
                            .checked_add(u32::from(low_delta))
                            .unwrap_or(0);
                        if next_low_after_delta > 0xFFFF
                        {
                            high_delta = high_delta.wrapping_add(1);
                        }
                        let adjusted = (value as i32 + high_delta as i32) as u16;
                        bytes.copy_from_slice(&adjusted.to_le_bytes());
                    }
                }
                _ => {}
            }
        }

        offset += block_size as usize;
        block_offset += block_size as usize;
    }
}

// =============================================================================
// Import Resolution
// =============================================================================

pub fn resolve_imports<F>(image: &mut LoadedImage32, mut resolver: F) -> bool
where
    F: FnMut(&str, &ImportEntry32) -> Option<u32>,
{
    let imports = core::mem::take(&mut image.imports);
    let mut resolved = true;

    for descriptor in &imports {
        for import in &descriptor.imports {
            match resolver(&descriptor.dll_name, import) {
                Some(function_rva) => {
                    if let Some(bytes) = image.slice_for_rva_mut(import.thunk_rva, 4) {
                        bytes.copy_from_slice(&function_rva.to_le_bytes());
                    } else {
                        resolved = false;
                    }
                }
                None => resolved = false,
            }
        }
    }

    image.imports = imports;
    resolved
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the PE32 loader.
pub fn init() {}
