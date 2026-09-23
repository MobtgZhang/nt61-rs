//! PE Loader Utilities
//!
//! Helper functions and utilities for PE loading that match
//! Windows NT loader behavior.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LoaderError {
    InvalidImageFormat = 0xC000007B,
    DllInitFailed = 0xC0000142,
    OrdinalNotFound = 0xC0000138,
    EntryPointNotFound = 0xC0000139,
    DllNotFound = 0xC0000135,
    ProcedureNotFound = 0xC000007A,
    ImageChecksum = 0xC0000221,
    ImageAlreadyLoaded = 0xC000010E,
    ConflictingAddresses = 0xC0000018,
    InsufficientResources = 0xC000009A,
    AccessDenied = 0xC0000022,
}

impl LoaderError {
    pub fn to_ntstatus(self) -> u32 {
        self as u32
    }

    pub fn is_success(&self) -> bool {
        false // All LoaderError variants are failures
    }
}

pub mod loader_flags {
    pub const DLL: u32 = 0x00000001;
    pub const ENTRY_PROCESSED: u32 = 0x00000002;
    pub const LOAD_IN_PROGRESS: u32 = 0x00001000;
    pub const UNLOAD_IN_PROGRESS: u32 = 0x00002000;
    pub const ENTRY_POINT_FAILED: u32 = 0x00004000;
    pub const PROCESS_TERMINATING: u32 = 0x00008000;
    pub const DONT_CALL_FOR_THREADS: u32 = 0x00040000;
    pub const DEBUG_SYMBOLS_LOADED: u32 = 0x00100000;
}

/// This is used for fast symbol lookup in the export table.

pub fn hash_string(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in s.bytes() {
        let c = byte.to_ascii_uppercase();
        hash = hash.wrapping_mul(65599).wrapping_add(c as u32);
    }
    hash
}

pub fn dll_name_equal(name1: &str, name2: &str) -> bool {
    let n1 = name1.trim_end_matches(".dll").trim_end_matches(".DLL");
    let n2 = name2.trim_end_matches(".dll").trim_end_matches(".DLL");
    n1.eq_ignore_ascii_case(n2)
}

pub fn validate_checksum(data: &[u8]) -> bool {
    if data.len() < 0x100 {
        return false;
    }

    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return false;
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 0x100 > data.len() {
        return false;
    }

    let checksum_offset = pe_offset + 0x58 + 24; // +24 for file header size
    if checksum_offset + 4 > data.len() {
        return false;
    }

    let stored_checksum = u32::from_le_bytes([
        data[checksum_offset],
        data[checksum_offset + 1],
        data[checksum_offset + 2],
        data[checksum_offset + 3],
    ]);

    let mut checksum: u64 = 0;
    let mut i = 0;

    while i + 4 <= data.len() {
        if i == checksum_offset {
            i += 4;
            continue;
        }

        let dword = u32::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
        ]) as u64;

        checksum = checksum.wrapping_add(dword);
        checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        i += 4;
    }

    while i < data.len() {
        checksum = checksum.wrapping_add(data[i] as u64);
        i += 1;
    }

    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = checksum.wrapping_add(checksum >> 16);
    checksum = checksum & 0xFFFF;

    let calculated_checksum = (checksum.wrapping_add(data.len() as u64)) as u32;

    calculated_checksum == stored_checksum
}

pub fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

pub fn align_up64(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

pub fn is_valid_address_range(base: u64, size: u64) -> bool {
    if base.checked_add(size).is_none() {
        return false;
    }

    if base == 0 {
        return false;
    }

    if size > 0x8000_0000 {
        return false;
    }

    true
}

pub fn rva_to_file_offset(
    rva: u32,
    sections: &[crate::loader::SectionHeader],
) -> Option<u32> {
    for section in sections {
        if rva >= section.virtual_address
            && rva < section.virtual_address + section.virtual_size.max(section.size_of_raw_data)
        {
            let offset_in_section = rva - section.virtual_address;
            return Some(section.pointer_to_raw_data + offset_in_section);
        }
    }
    None
}

pub fn parse_forwarder(forwarder: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = forwarder.split('.').collect();
    if parts.len() != 2 {
        return None;
    }

    Some((String::from(parts[0]), String::from(parts[1])))
}

pub fn is_forwarder_rva(rva: u32, export_dir_rva: u32, export_dir_size: u32) -> bool {
    rva >= export_dir_rva && rva < export_dir_rva + export_dir_size
}

#[derive(Debug, Default)]
pub struct LoaderStats {
    pub images_loaded: usize,
    pub imports_resolved: usize,
    pub relocations_applied: usize,
    pub tls_callbacks_executed: usize,
    pub delay_imports_resolved: usize,
    pub load_time_ticks: u64,
}

impl LoaderStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

pub mod protection {
    pub const NOACCESS: u32 = 0x01;
    pub const READONLY: u32 = 0x02;
    pub const READWRITE: u32 = 0x04;
    pub const EXECUTE: u32 = 0x10;
    pub const EXECUTE_READ: u32 = 0x20;
    pub const EXECUTE_READWRITE: u32 = 0x40;
}

pub fn section_characteristics_to_protection(characteristics: u32) -> u32 {
    let mut protection = protection::NOACCESS;

    let executable = (characteristics & crate::loader::section::MEM_EXECUTE) != 0;
    let readable = (characteristics & crate::loader::section::MEM_READ) != 0;
    let writable = (characteristics & crate::loader::section::MEM_WRITE) != 0;

    if executable && writable && readable {
        protection = protection::EXECUTE_READWRITE;
    } else if executable && readable {
        protection = protection::EXECUTE_READ;
    } else if executable {
        protection = protection::EXECUTE;
    } else if writable && readable {
        protection = protection::READWRITE;
    } else if readable {
        protection = protection::READONLY;
    }

    protection
}

pub struct DependencyNode {
    pub name: String,
    pub dependencies: Vec<String>,
    pub loaded: bool,
}

/// This is used to determine the correct load order for DLLs,
pub fn build_dependency_tree(
    imports: &[(String, Vec<String>)],
) -> Vec<DependencyNode> {
    let mut nodes = Vec::new();

    for (dll_name, imports) in imports {
        nodes.push(DependencyNode {
            name: dll_name.clone(),
            dependencies: imports.clone(),
            loaded: false,
        });
    }

    nodes
}

pub fn topological_sort_dlls(nodes: &mut [DependencyNode]) -> Vec<String> {
    let mut result = Vec::new();
    let mut visited = vec![false; nodes.len()];

    fn visit(
        idx: usize,
        nodes: &[DependencyNode],
        visited: &mut [bool],
        result: &mut Vec<String>,
    ) {
        if visited[idx] {
            return;
        }

        visited[idx] = true;

        for dep in &nodes[idx].dependencies {
            if let Some(dep_idx) = nodes.iter().position(|n| dll_name_equal(&n.name, dep)) {
                visit(dep_idx, nodes, visited, result);
            }
        }

        result.push(nodes[idx].name.clone());
    }

    for i in 0..nodes.len() {
        visit(i, nodes, &mut visited, &mut result);
    }

    result
}
