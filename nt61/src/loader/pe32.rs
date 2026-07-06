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

#![allow(dead_code)]

use crate::loader::{DosHeader, FileHeader, SectionHeader, PE_SIGNATURE};
use alloc::vec::Vec;
use alloc::string::String;

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

/// Standard PE32 optional header fields.
/// Size: 0x68 bytes (96 bytes).
#[repr(C)]
#[derive(Default)]
pub struct OptionalHeader32Std {
    pub magic: u16,                      // 0x00: PE32 = 0x10B
    pub linker_version: u8,              // 0x02
    pub size_of_code: u32,               // 0x04
    pub size_of_initialized_data: u32,   // 0x08
    pub size_of_uninitialized_data: u32, // 0x0C
    pub address_of_entry_point: u32,     // 0x10
    pub base_of_code: u32,               // 0x14
    pub base_of_data: u32,               // 0x18
    pub image_base: u32,                 // 0x1C (32-bit!)
    pub section_alignment: u32,          // 0x20
    pub file_alignment: u32,             // 0x24
    pub os_version_min: u16,             // 0x28
    pub image_version_min: u16,           // 0x2A
    pub subsystem_version_min: u16,       // 0x2C
    pub win32_version_value: u32,         // 0x30
    pub size_of_image: u32,              // 0x34
    pub size_of_headers: u32,            // 0x38
    pub checksum: u32,                   // 0x3C
    pub subsystem: u16,                   // 0x40
    pub dll_characteristics: u16,         // 0x42
    pub size_of_stack_reserve: u32,      // 0x44
    pub size_of_stack_commit: u32,       // 0x48
    pub size_of_heap_reserve: u32,       // 0x4C
    pub size_of_heap_commit: u32,        // 0x50
    pub loader_flags: u32,               // 0x54
    pub number_of_rva_and_sizes: u32,    // 0x58
}

impl OptionalHeader32Std {
    /// Get entry point RVA.
    pub fn entry_point_rva(&self) -> u32 {
        self.address_of_entry_point
    }

    /// Get image size.
    pub fn image_size(&self) -> u32 {
        self.size_of_image
    }

    /// Check if this is a DLL.
    pub fn is_dll(&self) -> bool {
        self.dll_characteristics & 0x2000 != 0
    }
}

/// Windows-specific PE32 optional header fields.
/// These follow the standard fields in the optional header.
#[repr(C)]
#[derive(Default)]
pub struct OptionalHeader32Windows {
    /// Section alignment must equal memory alignment.
    pub check_sum: u32,                  // 0x5C
    pub subsystem: u16,                  // 0x60
    pub dll_characteristics: u16,         // 0x62
    pub size_of_stack_reserve: u32,      // 0x64
    pub size_of_stack_commit: u32,       // 0x68
    pub size_of_heap_reserve: u32,       // 0x6C
    pub size_of_heap_commit: u32,        // 0x70
    pub loader_flags: u32,               // 0x74
    pub number_of_rva_and_sizes: u32,    // 0x78
    // Data directories follow at 0x7C
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
}

impl LoadedImage32 {
    /// Create a new loaded image.
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
}

// =============================================================================
// PE32 Parsing
// =============================================================================

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
    let dos_header = unsafe {
        &*(data.as_ptr() as *const DosHeader)
    };

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

    let file_header = unsafe {
        &*(data.as_ptr().add(fh_offset) as *const FileHeader)
    };

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
        &*(data.as_ptr().add(oh_offset) as *const crate::loader::OptionalHeader32)
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
        let section = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(offset) as *const SectionHeader)
        };
        sections.push(section);
    }

//         "[PE32] Parsed PE32: sections={}, image_base=0x{:08x}, entry=0x{:08x}",
//         num_sections,
//         opt_header.image_base,
//         opt_header.address_of_entry_point
//     );

    Some(PE32HeaderInfo {
        dos_header_offset: 0,
        pe_header_offset: pe_offset,
        // SAFETY: These references come from `data` which is a valid slice
        // for the entire call. Copying out via `core::ptr::read` produces
        // a bitwise copy (FileHeader/OptionalHeader32 are `Copy`).
        file_header: unsafe { core::ptr::read(file_header) },
        optional_header: unsafe { core::ptr::read(opt_header) },
        section_headers: sections,
    })
}

/// Parsed PE32 header information.
pub struct PE32HeaderInfo {
    pub dos_header_offset: usize,
    pub pe_header_offset: usize,
    pub file_header: FileHeader,
    pub optional_header: crate::loader::OptionalHeader32,
    pub section_headers: Vec<SectionHeader>,
}

impl PE32HeaderInfo {
    /// Get the data directory at the given index.
    pub fn get_data_directory(&self, _index: usize) -> Option<ImageDataDirectory> {
        // Data directories start after the optional header
        // For PE32, they are at offset 0x78 from the start of optional header
        // But in our OptionalHeader32 layout, they're not included
        // This is a simplified version
        None
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
            if rva >= section.virtual_address &&
               rva < section.virtual_address + section.virtual_size.max(section.size_of_raw_data) {
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
    _data: &[u8],
    _header_info: &PE32HeaderInfo,
) -> Vec<ImportDescriptor32> {
    // Import directory is at data directory index 1
    // This is a simplified implementation
    Vec::new()
}

/// Import descriptor for a single DLL.
pub struct ImportDescriptor32 {
    pub dll_name: String,
    pub imports: Vec<ImportEntry32>,
}

/// A single import entry.
pub struct ImportEntry32 {
    pub name: String,
    pub ordinal: Option<u16>,
    pub hint: u16,
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

    // Create loaded image structure
    let mut image = LoadedImage32::new(
        load_base,
        opt.size_of_image,
    );
    image.entry_point_rva = opt.address_of_entry_point;
    image.image_base = opt.image_base;
    image.number_of_sections = header_info.file_header.number_of_sections;
    image.is_dll = opt.dll_characteristics & 0x2000 != 0;
    image.subsystem = opt.subsystem;

    // Copy section headers
    for (i, section) in header_info.section_headers.iter().enumerate() {
        if i < 16 {
            image.sections[i] = *section;
        }
    }

    // In a real implementation, we would:
    // 1. Allocate memory at load_base
    // 2. Copy sections from file to memory
    // 3. Apply relocations
    // 4. Resolve imports
    // 5. Set up TLS
    // 6. Call entry point

//         "[PE32] Loaded image: base=0x{:08x}, size=0x{:08x}, entry=0x{:08x}",
//         load_base,
//         opt.size_of_image,
//         opt.address_of_entry_point
//     );

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
pub fn apply_relocations(_image: &mut LoadedImage32, delta: i32) {
    if delta == 0 {
        return;
    }

    // Relocation types for PE32:
    // HIGHLOW (3) - 32-bit relocation
    // HIGH (1) - High 16 bits + 0x00008000
    // LOW (2) - Low 16 bits
    // ABSOLUTE (0) - No adjustment needed

    // In a real implementation:
    // 1. Parse base relocation blocks
    // 2. For each relocation entry:
    //    - Calculate target address in image
    //    - Apply the appropriate relocation
    //    - For HIGHLOW: *(u32*)addr += delta
    //    - For HIGH: high 16 bits of *(u16*)addr += high 16 of delta
    //    - etc.
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the PE32 loader.
pub fn init() {
}
