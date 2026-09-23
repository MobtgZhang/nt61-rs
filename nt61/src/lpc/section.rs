//! ALPC section (shared memory) support
//!
//! Windows ALPC supports shared memory sections for efficient
//! large-data transfers between processes. This module implements:
//! - Section object creation
//! - Section view mapping
//! - Section message attributes

use core::ptr::null_mut;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AlpcSection {
    pub size: u64,
    pub base_address: u64,
    pub handle: u64,
    pub flags: u32,
    pub ref_count: u32,
    pub owner_pid: u64,
}

impl AlpcSection {
    pub const fn empty() -> Self {
        Self {
            size: 0,
            base_address: 0,
            handle: 0,
            flags: 0,
            ref_count: 0,
            owner_pid: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct AlpcSectionView {
    pub section_handle: u64,
    pub view_size: u64,
    pub view_base: u64,
    pub offset: u64,
    pub flags: u32,
}

impl AlpcSectionView {
    pub const fn empty() -> Self {
        Self {
            section_handle: 0,
            view_size: 0,
            view_base: 0,
            offset: 0,
            flags: 0,
        }
    }
}

pub const SECTION_FLAG_SECURE: u32 = 0x0001;
pub const SECTION_FLAG_READONLY: u32 = 0x0002;
pub const SECTION_FLAG_LARGE_PAGES: u32 = 0x0004;

pub const MAX_SECTIONS: usize = 16;

pub struct SectionRegistry {
    pub sections: [AlpcSection; MAX_SECTIONS],
    pub count: u32,
    pub next_handle: u64,
}

impl SectionRegistry {
    pub const fn new() -> Self {
        Self {
            sections: [const { AlpcSection::empty() }; MAX_SECTIONS],
            count: 0,
            next_handle: 1,
        }
    }
}

pub fn create_section(
    size: u64,
    flags: u32,
    owner_pid: u64,
    registry: &mut SectionRegistry,
) -> Option<u64> {
    if (registry.count as usize) >= MAX_SECTIONS {
        return None;
    }

    let idx = registry.count as usize;
    let handle = registry.next_handle;
    registry.next_handle = registry.next_handle.wrapping_add(1);

    let section = &mut registry.sections[idx];
    section.size = size;
    section.handle = handle;
    section.flags = flags;
    section.ref_count = 1;
    section.owner_pid = owner_pid;

    section.base_address = 0;

    registry.count = registry.count + 1;
    Some(handle)
}

pub fn map_section_view(
    section_handle: u64,
    view_size: u64,
    offset: u64,
    flags: u32,
    registry: &SectionRegistry,
) -> Option<AlpcSectionView> {
    for i in 0..registry.count as usize {
        if registry.sections[i].handle == section_handle {
            let section = &registry.sections[i];

            if offset + view_size > section.size {
                return None;
            }

            return Some(AlpcSectionView {
                section_handle,
                view_size,
                view_base: 0, // Would be actual mapped address
                offset,
                flags,
            });
        }
    }
    None
}

pub fn close_section(section_handle: u64, registry: &mut SectionRegistry) -> bool {
    for i in 0..registry.count as usize {
        if registry.sections[i].handle == section_handle {
            let section = &mut registry.sections[i];
            section.ref_count = section.ref_count.saturating_sub(1);

            if section.ref_count == 0 {
                *section = AlpcSection::empty();
            }
            return true;
        }
    }
    false
}

pub fn get_section_info(section_handle: u64, registry: &SectionRegistry) -> Option<AlpcSection> {
    for i in 0..registry.count as usize {
        if registry.sections[i].handle == section_handle {
            return Some(registry.sections[i]);
        }
    }
    None
}
