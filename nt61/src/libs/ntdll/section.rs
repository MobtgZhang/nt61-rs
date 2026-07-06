//! ntdll — Nt* section (file mapping) APIs
//
//! `NtCreateSection`, `NtMapViewOfSection`,
//! `NtUnmapViewOfSection`, `NtQuerySection`. The
//! implementation is a stub: sections are tracked in the
//! handle table but no actual mapping happens (the user-mode
//! side of this kernel is never executed).
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` section
//! APIs.

use super::file::{alloc_handle, free_handle, HandleKind};
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS,
};
use super::types::{HANDLE, NTSTATUS, PVOID, SIZE_T};
use core::ptr;

/// `NtCreateSection` — create a section (file mapping) object.
pub unsafe extern "C" fn NtCreateSection(
    section_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    maximum_size: *mut i64,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS {
    if section_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (object_attributes, maximum_size, section_page_protection,
             allocation_attributes, file_handle, desired_access);
    let h = alloc_handle(HandleKind::Section, 0xC0DE_CAFE_F00D_BEEF);
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *section_handle = h;
    STATUS_SUCCESS
}

/// `NtMapViewOfSection` — map a section into the process's
/// address space.
pub unsafe extern "C" fn NtMapViewOfSection(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: usize,
    commit_size: SIZE_T,
    section_offset: *mut i64,
    view_size: *mut SIZE_T,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS {
    if section_handle.is_null() { return STATUS_INVALID_HANDLE; }
    let _ = (process_handle, zero_bits, commit_size, section_offset,
             view_size, inherit_disposition, allocation_type, win32_protect);
    if base_address.is_null() { return STATUS_INVALID_PARAMETER; }
    // The bootstrap never executes user code, so we never
    // actually map anything. Return a fixed placeholder VA.
    *base_address = 0x0000_7000_0000_0000usize as PVOID;
    STATUS_SUCCESS
}

/// `NtUnmapViewOfSection`.
pub unsafe extern "C" fn NtUnmapViewOfSection(
    _process_handle: HANDLE,
    _base_address: PVOID,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `NtQuerySection` — returns `STATUS_NOT_IMPLEMENTED` for the
/// basic information class; the kernel can implement this
/// later.
pub unsafe extern "C" fn NtQuerySection(
    section_handle: HANDLE,
    _info_class: u32,
    _info: PVOID,
    _length: SIZE_T,
    _return_length: *mut SIZE_T,
) -> NTSTATUS {
    if section_handle.is_null() { return STATUS_INVALID_HANDLE; }
    STATUS_NOT_IMPLEMENTED
}

/// `NtClose` (re-exported so kernel32 can call it without
/// touching the file module).
pub unsafe extern "C" fn NtCloseSection(h: HANDLE) -> NTSTATUS {
    if free_handle(h) { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }
}
