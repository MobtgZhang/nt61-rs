//! mm — Section Objects
//!
//! Section objects are the core mechanism for memory-mapped files and
//! shared memory in Windows NT. This module implements the kernel-side
//! section management that ntdll/section.rs calls into.
//!
//! Architecture:
//! - SECTION: The object header
//! - CONTROL_AREA: Links to the backing file
//! - SEGMENT: Describes the memory region
//! - SUBSECTION: Maps file regions to memory
//!
//! References:
//!   * Windows Internals 7th Ed. - Chapter 10
//!   * WRK base/ntos/mm/section.c

use super::pool::{self, PoolType};
use super::vas;
use crate::ke::sync::Spinlock;
use core::ptr;

fn allocate_address(size: usize, hint: Option<usize>) -> Option<u64> {
    // Use vas allocate_user_va for now
    vas::allocate_user_va(hint.unwrap_or(0) as u64, size as u64, 0x04)
}

fn free_address(address: usize) {
    vas::free_user_va(address as u64);
}


#[repr(C)]
pub struct Section {
    pub size: u64,
    pub base_address: u64,
    pub max_protection: u32,
    pub section_attributes: u32,
    pub control_area: *mut ControlArea,
    pub segment: *mut Segment,
    pub reference_count: u32,
}

impl Section {
    pub fn new() -> Self {
        Self {
            size: 0,
            base_address: 0,
            max_protection: 0,
            section_attributes: 0,
            control_area: ptr::null_mut(),
            segment: ptr::null_mut(),
            reference_count: 1,
        }
    }
}

#[repr(C)]
pub struct ControlArea {
    pub file_pointer: u64,
    pub first_subsection: *mut Subsection,
    pub number_of_subsections: u32,
    pub number_of_pages: u32,
    pub number_of_mapped_views: u32,
    pub wait_for_deletion: bool,
}

impl ControlArea {
    pub fn new() -> Self {
        Self {
            file_pointer: 0,
            first_subsection: ptr::null_mut(),
            number_of_subsections: 0,
            number_of_pages: 0,
            number_of_mapped_views: 0,
            wait_for_deletion: false,
        }
    }
}

#[repr(C)]
pub struct Segment {
    pub control_area: *mut ControlArea,
    pub total_number_of_ptes: u32,
    pub base_address: u64,
    pub size_of_segment: u64,
    pub protection_mask: u32,
}

impl Segment {
    pub fn new() -> Self {
        Self {
            control_area: ptr::null_mut(),
            total_number_of_ptes: 0,
            base_address: 0,
            size_of_segment: 0,
            protection_mask: 0,
        }
    }
}

#[repr(C)]
pub struct Subsection {
    pub next_subsection: *mut Subsection,
    pub control_area: *mut ControlArea,
    pub starting_sector: u64,
    pub number_of_full_sectors: u32,
    pub starting_pte_index: u32,
}


const MAX_SECTIONS: usize = 256;
static SECTION_TABLE: Spinlock<[Option<*mut Section>; MAX_SECTIONS]> =
    Spinlock::new([None; MAX_SECTIONS]);

fn alloc_section_slot(section: *mut Section) -> Option<usize> {
    let mut table = SECTION_TABLE.lock();
    for (i, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(section);
            return Some(i);
        }
    }
    None
}

fn get_section(index: usize) -> Option<*mut Section> {
    let table = SECTION_TABLE.lock();
    if index < MAX_SECTIONS {
        table[index]
    } else {
        None
    }
}

fn free_section_slot(index: usize) {
    let mut table = SECTION_TABLE.lock();
    if index < MAX_SECTIONS {
        table[index] = None;
    }
}


pub fn create_section(
    size: u64,
    max_protection: u32,
    section_attributes: u32,
    file_handle: u64,
) -> Result<usize, i32> {
    let section_ptr = pool::allocate_tagged(
        PoolType::NonPaged,
        core::mem::size_of::<Section>(),
        u32::from_le_bytes(*b"Sect"),
    ) as *mut Section;

    if section_ptr.is_null() {
        return Err(0xC000_0017u32 as i32); // STATUS_NO_MEMORY
    }

    unsafe {
        ptr::write(section_ptr, Section::new());
        (*section_ptr).size = size;
        (*section_ptr).max_protection = max_protection;
        (*section_ptr).section_attributes = section_attributes;
    }

    let control_area_ptr = pool::allocate_tagged(
        PoolType::NonPaged,
        core::mem::size_of::<ControlArea>(),
        u32::from_le_bytes(*b"Ctrl"),
    ) as *mut ControlArea;

    if control_area_ptr.is_null() {
        unsafe { pool::free(section_ptr as *mut u8); }
        return Err(0xC000_0017u32 as i32);
    }

    unsafe {
        ptr::write(control_area_ptr, ControlArea::new());
        (*control_area_ptr).file_pointer = file_handle;
        (*control_area_ptr).number_of_pages = ((size + 0xFFF) / 0x1000) as u32;
        (*section_ptr).control_area = control_area_ptr;
    }

    let segment_ptr = pool::allocate_tagged(
        PoolType::NonPaged,
        core::mem::size_of::<Segment>(),
        u32::from_le_bytes(*b"Segm"),
    ) as *mut Segment;

    if segment_ptr.is_null() {
        unsafe {
            pool::free(control_area_ptr as *mut u8);
            pool::free(section_ptr as *mut u8);
        }
        return Err(0xC000_0017u32 as i32);
    }

    unsafe {
        ptr::write(segment_ptr, Segment::new());
        (*segment_ptr).control_area = control_area_ptr;
        (*segment_ptr).size_of_segment = size;
        (*segment_ptr).protection_mask = max_protection;
        (*section_ptr).segment = segment_ptr;
    }

    match alloc_section_slot(section_ptr) {
        Some(index) => Ok(index),
        None => {
            unsafe {
                pool::free(segment_ptr as *mut u8);
                pool::free(control_area_ptr as *mut u8);
                pool::free(section_ptr as *mut u8);
            }
            Err(0xC000_0017u32 as i32)
        }
    }
}

pub fn destroy_section(section_index: usize) -> Result<(), i32> {
    let section_ptr = match get_section(section_index) {
        Some(ptr) => ptr,
        None => return Err(0xC000_0008u32 as i32), // STATUS_INVALID_HANDLE
    };

    unsafe {
        let section = &mut *section_ptr;

        if section.reference_count > 1 {
            section.reference_count -= 1;
            return Ok(());
        }

        if !section.control_area.is_null() {
            pool::free(section.control_area as *mut u8);
        }

        if !section.segment.is_null() {
            pool::free(section.segment as *mut u8);
        }

        pool::free(section_ptr as *mut u8);
    }

    free_section_slot(section_index);
    Ok(())
}


pub fn map_view(
    section_index: usize,
    base_address_hint: u64,
    view_size: u64,
    section_offset: u64,
    protection: u32,
) -> Result<u64, i32> {
    let section_ptr = match get_section(section_index) {
        Some(ptr) => ptr,
        None => return Err(0xC000_0008u32 as i32), // STATUS_INVALID_HANDLE
    };

    unsafe {
        let section = &mut *section_ptr;

        if section_offset >= section.size {
            return Err(0xC000_000Du32 as i32); // STATUS_INVALID_PARAMETER
        }

        let actual_size = if view_size == 0 {
            section.size - section_offset
        } else {
            view_size
        };

        if section_offset + actual_size > section.size {
            return Err(0xC000_000Du32 as i32);
        }

        let base_address = allocate_address(
            actual_size as usize,
            if base_address_hint != 0 { Some(base_address_hint as usize) } else { None },
        ).ok_or(0xC000_0017u32 as i32)?; // STATUS_NO_MEMORY

        if !section.control_area.is_null() {
            (*section.control_area).number_of_mapped_views += 1;
        }


        Ok(base_address as u64)
    }
}

pub fn unmap_view(base_address: u64) -> Result<(), i32> {

    if base_address == 0 {
        return Err(0xC000_000Du32 as i32); // STATUS_INVALID_PARAMETER
    }

    free_address(base_address as usize);

    Ok(())
}


pub fn get_section_size(section_index: usize) -> Option<u64> {
    let section_ptr = get_section(section_index)?;
    unsafe { Some((*section_ptr).size) }
}

pub fn get_section_protection(section_index: usize) -> Option<u32> {
    let section_ptr = get_section(section_index)?;
    unsafe { Some((*section_ptr).max_protection) }
}

pub fn get_mapped_views(section_index: usize) -> Option<u32> {
    let section_ptr = get_section(section_index)?;
    unsafe {
        if !(*section_ptr).control_area.is_null() {
            Some((*(*section_ptr).control_area).number_of_mapped_views)
        } else {
            Some(0)
        }
    }
}


pub fn init() {
}
