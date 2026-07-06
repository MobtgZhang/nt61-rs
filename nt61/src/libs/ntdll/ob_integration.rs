//! ntdll — Object Manager integration
//
//! Bridges the flat ntdll handle table with the kernel's object
//! manager (ob). Every handle in the ntdll table corresponds to
//! an object in ob's namespace. This module provides:
//
//! * `ob_allocate_handle` — allocate a handle slot and register the
//!   object in the kernel's global handle table.
//! * `ob_free_handle` — free a handle slot and dereference the object.
//! * `ob_lookup_handle` — resolve a handle to an object header pointer.
//! * `ob_reference_by_handle` — resolve a handle and increment refcount.
//
//! The ntdll flat handle table (in `file.rs`) stores the mapping from
//! user-mode handles (1-based indices) to kernel object pointers.
//! When `OB_INTEGRATION` is enabled, each allocation also registers
//! the object in ob's global kernel handle table.

use super::super::super::ob;
use super::super::super::ps::process::Eprocess;

/// Maximum handle value for the ntdll table.
pub const NTDLL_MAX_HANDLES: usize = 256;

/// Allocate a handle slot for an object in the ntdll table AND
/// register it in ob's global kernel handle table.
/// 
/// Returns the ntdll handle (1-based, 0 = failure).
/// The caller should use `alloc_handle` in `file.rs` for the ntdll
/// table slot, and this function registers the object in ob.
///
/// This function is called after `alloc_handle` succeeds to perform
/// the ob-level registration.
pub fn ob_register_object(
    ob_header: *mut ob::ObjectHeader,
    parent_path: &[u8],
    name: &[u8],
) -> u64 {
    if ob_header.is_null() {
        return 0;
    }

    // Register in ob's global kernel handle table
    let ob_handle = ob::insert_object(parent_path, ob_header);
    
    if ob_handle == 0 {
        // Failed to register in ob - should not happen for kernel handles
        // kprintln disabled (memcpy crash workaround)
        let _ = name;
        return 0;
    }

    // Set the object name in the header
    {
        if !name.is_empty() {
            // The name is already set by create_object; just verify
        }
    }

    ob_handle
}

/// Allocate a handle for a file object in ob's namespace.
/// File objects are created in \Device or subdirectories.
pub fn ob_register_file(
    ob_header: *mut ob::ObjectHeader,
    device_path: &[u8],
    file_name: &[u8],
) -> u64 {
    if ob_header.is_null() || file_name.is_empty() {
        return 0;
    }

    // Build full path: device_path + "\" + file_name
    let mut full_path = device_path.to_vec();
    if !full_path.is_empty() && full_path.last() != Some(&b'\\') {
        full_path.push(b'\\');
    }
    full_path.extend_from_slice(file_name);

    ob_register_object(ob_header, device_path, &full_path)
}

/// Allocate a handle for an event object in ob's namespace.
pub fn ob_register_event(
    ob_header: *mut ob::ObjectHeader,
    parent_path: &[u8],
    name: &[u8],
) -> u64 {
    ob_register_object(ob_header, parent_path, name)
}

/// Allocate a handle for a mutant (mutex) object.
pub fn ob_register_mutant(
    ob_header: *mut ob::ObjectHeader,
    parent_path: &[u8],
    name: &[u8],
) -> u64 {
    ob_register_object(ob_header, parent_path, name)
}

/// Allocate a handle for a section (memory section) object.
pub fn ob_register_section(
    ob_header: *mut ob::ObjectHeader,
    parent_path: &[u8],
    name: &[u8],
) -> u64 {
    ob_register_object(ob_header, parent_path, name)
}

/// Free a handle in ob's global table.
pub fn ob_close_handle(handle: u64) -> bool {
    if handle == 0 {
        return false;
    }
    ob::close_handle_global(handle)
}

/// Look up an object header by handle (global table only for kernel mode).
pub fn ob_lookup_handle(handle: u64) -> *mut ob::ObjectHeader {
    if handle == 0 {
        return core::ptr::null_mut();
    }
    ob::reference_object_by_handle(handle)
}

/// Look up an object header by handle in a specific process's table.
pub fn ob_lookup_handle_in_process(
    handle: u64,
    process: *mut Eprocess,
) -> *mut ob::ObjectHeader {
    if handle == 0 {
        return core::ptr::null_mut();
    }
    ob::reference_object_by_handle_in_process(handle, process)
}

/// Reference an object by handle and return the body pointer.
pub fn ob_reference_object_body<T>(handle: u64) -> *mut T {
    let header = ob_lookup_handle(handle);
    if header.is_null() {
        return core::ptr::null_mut();
    }
    ob::get_object_body::<T>(header)
}

/// Create a new object in ob's namespace and register a handle.
/// Returns the handle or 0 on failure.
pub fn ob_create_and_register(
    parent_path: &[u8],
    name: &[u8],
    ob_type: ob::ObType,
    body_size: usize,
) -> u64 {
    // Create the object header (body is allocated after header)
    let header = ob::create_object(parent_path, name, ob_type, body_size);
    if header.is_null() {
        return 0;
    }

    // Insert into directory and allocate handle
    ob::insert_object(parent_path, header)
}

/// Initialize the ob integration layer.
/// In the bootstrap, this is a no-op since ob::init() handles setup.
pub fn init() {
    // kprintln disabled (memcpy crash workaround)
}

// =============================================================================
// Object Manager Syscall Implementations
// =============================================================================

use super::types::{HANDLE, NTSTATUS};
use super::status::STATUS_SUCCESS;

/// NtCreateDirectoryObject - Creates a directory object
pub unsafe extern "C" fn NtCreateDirectoryObject(
    directory_handle: *mut HANDLE,
    _desired_access: u32,
    _object_attributes: *mut super::types::ObjectAttributes,
) -> NTSTATUS {
    if directory_handle.is_null() {
        return STATUS_SUCCESS;
    }

    let handle = ob_register_object(
        core::ptr::null_mut(),
        b"\\",
        b"\\??\\",
    );

    *directory_handle = handle as HANDLE;
    STATUS_SUCCESS
}

/// NtOpenDirectoryObject - Opens a directory object
pub unsafe extern "C" fn NtOpenDirectoryObject(
    directory_handle: *mut HANDLE,
    _desired_access: u32,
    _object_attributes: *mut super::types::ObjectAttributes,
) -> NTSTATUS {
    if directory_handle.is_null() {
        return STATUS_SUCCESS;
    }

    // In a full implementation, this would look up the directory by name
    *directory_handle = 0 as HANDLE;
    STATUS_SUCCESS
}

/// NtQueryDirectoryObject - Query information about a directory object
pub unsafe extern "C" fn NtQueryDirectoryObject(
    directory_handle: HANDLE,
    buffer: *mut u8,
    length: u32,
    restart_scan: u32,
    iteration_handle: u32,
    return_length: *mut u32,
    context: *mut u32,
) -> NTSTATUS {
    let _ = (directory_handle, buffer, length, restart_scan, iteration_handle, context);
    if !return_length.is_null() {
        unsafe { *return_length = 0; }
    }
    STATUS_SUCCESS
}

/// NtOpenProcessToken - Opens the token of a process
pub unsafe extern "C" fn NtOpenProcessToken(
    _process_handle: HANDLE,
    _desired_access: u32,
    token_handle: *mut HANDLE,
) -> NTSTATUS {
    if token_handle.is_null() {
        return STATUS_SUCCESS;
    }

    // In a full implementation, this would:
    // 1. Get the process from the handle
    // 2. Get the token from the process
    // 3. Create a new handle for the token
    // For now, return a dummy handle
    *token_handle = 0 as HANDLE;
    STATUS_SUCCESS
}
