//! ntdll — Nt* section (file mapping) APIs
//
//! `nt_create_section`, `nt_map_view_of_section`,
//! `nt_unmap_view_of_section`, `nt_query_section`. The
//! implementation is a stub: sections are tracked in the
//! handle table but no actual mapping happens (the user-mode
//! side of this kernel is never executed).
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` section
//! APIs.

use super::file::{alloc_handle, free_handle, HandleKind};
use super::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use super::types::{SizeT, HANDLE, NTSTATUS, PVOID};
use crate::ke::sync::Spinlock;
use crate::mm::user_copy::{read_user_object, write_user_object};
use alloc::vec::Vec;

/// `SectionBasicInformation` information class.
pub const SECTION_BASIC_INFORMATION: u32 = 0;

/// Metadata retained for every successfully-created section object.
///
/// The handle table owns object identity; this table owns the creation
/// parameters that `NtQuerySection` must report.
#[derive(Clone, Copy)]
struct SectionEntry {
    handle: HANDLE,
    desired_access: u32,
    maximum_size: i64,
    allocation_attributes: u32,
    file_mapped: bool,
}

const SECTION_ATTRIBUTE_FILE: u32 = 0x0000_0010;
const SECTION_ATTRIBUTE_IMAGE: u32 = 0x0000_0020;
const SECTION_ATTRIBUTE_RESERVE: u32 = 0x0000_0040;
const SECTION_ATTRIBUTE_COMMIT: u32 = 0x0000_0080;
const ALLOCATION_ATTRIBUTE_IMAGE: u32 = 0x0100_0000;
const ALLOCATION_ATTRIBUTE_RESERVE: u32 = 0x0400_0000;

fn is_supported_page_protection(protection: u32) -> bool {
    const PAGE_GUARD: u32 = 0x0100;
    const PROTECTION_MASK: u32 = 0x0000_00ff;
    const VALID_PROTECTIONS: [u32; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
    if protection & PAGE_GUARD != 0 {
        return false;
    }
    VALID_PROTECTIONS.contains(&(protection & PROTECTION_MASK))
}

fn section_attributes(entry: SectionEntry) -> u32 {
    if entry.file_mapped {
        SECTION_ATTRIBUTE_FILE
    } else if entry.allocation_attributes & ALLOCATION_ATTRIBUTE_IMAGE != 0 {
        SECTION_ATTRIBUTE_IMAGE
    } else if entry.allocation_attributes & ALLOCATION_ATTRIBUTE_RESERVE != 0 {
        SECTION_ATTRIBUTE_RESERVE
    } else {
        SECTION_ATTRIBUTE_COMMIT
    }
}

static SECTION_TABLE: Spinlock<Vec<SectionEntry>> = Spinlock::new(Vec::new());

/// `SECTION_BASIC_INFORMATION` as defined for x64 Windows.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SectionBasicInformation {
    pub attributes: u32,
    pub maximum_size: i64,
}

/// `nt_create_section` — create a section (file mapping) object.
pub unsafe extern "C" fn nt_create_section(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    maximum_size: *mut i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    if section_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if !maximum_size.is_null() {
        if read_user_object::<i64>(maximum_size as u64).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let mut output = 0 as HANDLE;
    let mut maximum_size_value = 0i64;
    if !maximum_size.is_null() {
        maximum_size_value = match read_user_object::<i64>(maximum_size as u64) {
            Ok(value) => value,
            Err(status) => return status,
        };
    }
    let status = nt_create_section_kernel(
        &mut output,
        desired_access,
        object_attributes,
        Some(&mut maximum_size_value),
        section_page_protection,
        allocation_attributes,
        file_handle,
    );
    if status != STATUS_SUCCESS {
        return status;
    }
    if write_user_object(section_handle as u64, &output).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

pub fn nt_create_section_kernel(
    section_handle: &mut HANDLE,
    desired_access: u32,
    _object_attributes: *mut super::types::ObjectAttributes,
    maximum_size: Option<&mut i64>,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    if !is_supported_page_protection(section_page_protection) {
        return STATUS_INVALID_PARAMETER;
    }
    if maximum_size.as_ref().map_or(false, |value| **value < 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let handle = alloc_handle(HandleKind::Section, 0xC0DE_CAFE_F00D_BEEF);
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    let entry = SectionEntry {
        handle,
        desired_access,
        maximum_size: maximum_size.copied().unwrap_or(0),
        allocation_attributes,
        file_mapped: !file_handle.is_null(),
    };
    let mut sections = SECTION_TABLE.lock();
    sections.push(entry);
    *section_handle = handle;
    STATUS_SUCCESS
}

/// `nt_map_view_of_section` — map a section into the process's
/// address space.
pub unsafe extern "C" fn nt_map_view_of_section(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    commit_size: SizeT,
    section_offset: *mut i64,
    view_size: *mut SizeT,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    if section_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    let _ = (
        process_handle,
        zero_bits,
        commit_size,
        section_offset,
        view_size,
        inherit_disposition,
        allocation_type,
        win32_protect,
    );
    if base_address.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if write_user_object(base_address as u64, &(0x0000_7000_0000_0000usize as PVOID)).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if !section_offset.is_null() {
        let offset = 0i64;
        if write_user_object(section_offset as u64, &offset).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if !view_size.is_null() {
        let view_size_value = 0 as SizeT;
        if write_user_object(view_size as u64, &view_size_value).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    STATUS_SUCCESS
}

/// `nt_unmap_view_of_section`.
pub unsafe extern "C" fn nt_unmap_view_of_section(
    _process_handle: HANDLE,
    _base_address: PVOID,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `nt_query_section` — query section creation parameters.
pub unsafe extern "C" fn nt_query_section(
    section_handle: HANDLE,
    info_class: u32,
    info: PVOID,
    length: SizeT,
    return_length: *mut SizeT,
) -> NTSTATUS {
    if section_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    if info_class != SECTION_BASIC_INFORMATION {
        return STATUS_INVALID_INFO_CLASS;
    }
    if info.is_null() || length < core::mem::size_of::<SectionBasicInformation>() {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    let sections = SECTION_TABLE.lock();
    let Some(entry) = sections
        .iter()
        .copied()
        .find(|entry| entry.handle == section_handle)
    else {
        return STATUS_INVALID_HANDLE;
    };
    drop(sections);
    if entry.desired_access & super::types::section_access::SECTION_QUERY == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let information = SectionBasicInformation {
        attributes: section_attributes(entry),
        maximum_size: entry.maximum_size,
    };
    if !return_length.is_null()
        && write_user_object(
            return_length as u64,
            &(core::mem::size_of::<SectionBasicInformation>() as SizeT),
        )
        .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if write_user_object(info as u64, &information).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

/// `NT_CLOSE` (re-exported so kernel32 can call it without
/// touching the file module).
pub unsafe extern "C" fn nt_close_section(h: HANDLE) -> NTSTATUS {
    if !free_handle(h) {
        return STATUS_INVALID_HANDLE;
    }
    let mut sections = SECTION_TABLE.lock();
    sections.retain(|entry| entry.handle != h);
    STATUS_SUCCESS
}
