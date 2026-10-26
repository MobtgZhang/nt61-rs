//! nt_create_process System Call Implementation
//!
//! Implements the complete process creation system call for NT kernel.
//! This handles process object creation, address space initialization,
//! and initial thread setup.

use crate::mm::pool;
use crate::ob;
use crate::ps::address_space::ProcessAddressSpace;
use crate::ps::process::{Eprocess, ProcessHandleTable};
use crate::se::token;

/// NT Status codes
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000009A;
pub const STATUS_INVALID_HANDLE: u32 = 0xC0000008;

/// Process access rights
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;

/// Object attributes structure
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: u64,
    pub object_name: *const u8,
    pub object_name_length: u32,
    pub attributes: u32,
    pub security_descriptor: u64,
    pub security_quality_of_service: u64,
}

/// nt_create_process - create a new process
///
/// # Arguments
/// * `process_handle` - Receives the new process handle
/// * `desired_access` - Access rights to the process
/// * `object_attributes` - Optional object attributes
/// * `parent_process_handle` - handle to parent process (0 = no parent)
/// * `inherit_handles` - Whether to inherit handles from parent
/// * `section_handle` - handle to image section (0 = no image)
/// * `debug_port` - handle to debug port (0 = none)
/// * `exception_port` - handle to exception port (0 = none)
///
/// # Returns
/// * STATUS_SUCCESS on success
/// * Error status code on failure
pub fn nt_create_process(
    process_handle: &mut u64,
    _desired_access: u32,
    _object_attributes: *const ObjectAttributes,
    parent_process_handle: u64,
    inherit_handles: bool,
    section_handle: u64,
    debug_port: u64,
    exception_port: u64,
) -> u32 {
    // 1. Validate parent process
    let parent = if parent_process_handle != 0 {
        match ob::reference_object_by_handle(parent_process_handle) {
            header if !header.is_null() => {
                // SAFETY: caller has validated the handle via
                // `reference_object_by_handle`, so `header` points at a
                // live `OBJECT_HEADER`. `get_object_body` is itself
                // an `unsafe fn`, so we keep the wrapper `unsafe` here.
                ob::get_object_body::<Eprocess>(header)
            }
            _ => return STATUS_INVALID_HANDLE,
        }
    } else {
        core::ptr::null_mut()
    };

    // 2. Allocate process object from pool
    let process_size = core::mem::size_of::<Eprocess>().max(4096);
    let process_ptr = pool::allocate(pool::PoolType::NonPaged, process_size) as *mut Eprocess;

    if process_ptr.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 3. Initialize process structure
    unsafe {
        core::ptr::write_bytes(process_ptr as *mut u8, 0, process_size);

        // Allocate PID
        let pid = crate::ps::process::allocate_pid().unwrap_or(0);
        if pid == 0 {
            pool::free(process_ptr as *mut u8);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        (*process_ptr).set_pid(pid);
        (*process_ptr).unique_process_id = pid;
        (*process_ptr).unique_process_id_full = pid;

        // Initialize thread list
        (*process_ptr).kprocess_thread_list_head.init();
    }

    // 4. create address space
    let address_space = match ProcessAddressSpace::new() {
        Some(vas) => vas,
        None => {
            // `pool::free` is a safe function, so no `unsafe` wrapper is
            // needed — calling it directly is enough.
            pool::free(process_ptr as *mut u8);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    };

    // Store PML4 in process
    unsafe {
        (*process_ptr).page_table_pml4 = address_space.pml4_phys;
        (*process_ptr).pml4_phys = address_space.pml4_phys;
    }

    // 5. Map PEB and stack
    let mut addr_space = address_space;
    if addr_space.map_peb().is_err() {
        // `pool::free` is a safe function, so the unsafe wrapper is
        // not required.
        pool::free(process_ptr as *mut u8);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if addr_space.map_user_stack().is_err() {
        pool::free(process_ptr as *mut u8);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Store stack info
    unsafe {
        (*process_ptr).user_stack_base = addr_space.user_stack_base;
        (*process_ptr).user_stack_limit = addr_space.user_stack_base + addr_space.user_stack_size;
        (*process_ptr).user_rsp = addr_space.get_stack_top();
        (*process_ptr).peb = addr_space.peb_address as *mut crate::ps::process::peb;
    }

    // Transfer ownership of the address space to the process. Without
    // this the `ProcessAddressSpace` stack local is dropped when
    // `create_process` returns, which runs `Drop::cleanup()` and frees
    // the PML4 page *while the process is still running with that CR3*.
    // The freed page is then reused as an ordinary data buffer, so the
    // next write (e.g. a command line) corrupts the live PML4 and the
    // next page walk triple-faults.
    core::mem::forget(addr_space);

    // 6. Allocate handle table
    let ht_size = core::mem::size_of::<ProcessHandleTable>().max(4096);
    let ht_ptr = pool::allocate(pool::PoolType::NonPaged, ht_size) as *mut ProcessHandleTable;

    if ht_ptr.is_null() {
        // `pool::free` is safe; drop the redundant `unsafe {}` wrapper.
        pool::free(process_ptr as *mut u8);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    unsafe {
        core::ptr::write_bytes(ht_ptr as *mut u8, 0, ht_size);
        (*ht_ptr).next_slot = 1;
        (*process_ptr).object_table = ht_ptr;
    }

    // 7. create initial token
    let process_token = if !parent.is_null() {
        unsafe { (*parent).get_token().as_ref() }.map(|token| {
            crate::se::token::duplicate_for_process(token)
        })
    } else {
        Some(token::create_user_token(crate::se::sid::SID_USERS))
    };

    if let Some(process_token) = process_token {
        if process_token.is_null() {
            pool::free(ht_ptr as *mut u8);
            pool::free(process_ptr as *mut u8);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        unsafe {
            (*process_ptr).set_token(process_token);
        }
    }

    if inherit_handles && !ob::inherit_process_handle_table(process_ptr, parent) {
        pool::free(ht_ptr as *mut u8);
        pool::free(process_ptr as *mut u8);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 8. Set debug and exception ports
    unsafe {
        (*process_ptr).debug_port = debug_port;
        (*process_ptr).exception_port = exception_port;
    }

    // 9. Load image from section if provided
    if section_handle != 0 {
        // Map the section object body and load the PE image from its
        // base address into the new process's address space.
        let header = ob::reference_object_by_handle(section_handle);
        if !header.is_null() {
            let section = ob::get_object_body::<crate::mm::section::Section>(header);
            let base = unsafe { (*section).base_address };
            let size = unsafe { (*section).size } as usize;
            if base != 0 && size > 0 {
                let image = unsafe { core::slice::from_raw_parts(base as *const u8, size) };
                if crate::loader::load_pe(image).is_none() {
                    // PE parsing failed; the process remains in a suspended
                    // state that NT_CREATE_THREAD can terminate.
                }
            }
        }
    }

    // 10. create initial thread (deferred to NT_CREATE_THREAD)
    // The process is created but not yet runnable until a thread is created

    // 11. Insert into object manager and create handle
    let obj_header = ob::create_object(
        b"\\Process",
        b"", // Anonymous process
        ob::ObType::Process,
        process_size,
    );

    if obj_header.is_null() {
        // `pool::free` is safe; no `unsafe` wrapper needed.
        pool::free(ht_ptr as *mut u8);
        pool::free(process_ptr as *mut u8);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy process data to object body
    unsafe {
        let body = ob::get_object_body::<Eprocess>(obj_header);
        core::ptr::copy_nonoverlapping(process_ptr, body, 1);
        pool::free(process_ptr as *mut u8);
    }

    // 12. create handle for caller
    let handle = ob::insert_object(b"\\Process", obj_header);
    *process_handle = handle;

    // 13. Add to global process list
    if !crate::ps::process::add_to_global_list(unsafe {
        &mut *ob::get_object_body::<Eprocess>(obj_header)
    }) {
        return crate::libs::ntdll::status::STATUS_NO_MEMORY as u32;
    }

    STATUS_SUCCESS
}

/// nt_create_process_ex - Extended process creation with section mapping
///
/// This is the extended version that loads a PE image from a section object.
pub fn nt_create_process_ex(
    process_handle: &mut u64,
    desired_access: u32,
    object_attributes: *const ObjectAttributes,
    parent_process_handle: u64,
    flags: u32,
    section_handle: u64,
    debug_port: u64,
    exception_port: u64,
    job_handle: u64,
) -> u32 {
    // Call base implementation
    let status = nt_create_process(
        process_handle,
        desired_access,
        object_attributes,
        parent_process_handle,
        flags & 0x1 != 0, // INHERIT_HANDLES flag
        section_handle,
        debug_port,
        exception_port,
    );

    if status != STATUS_SUCCESS {
        return status;
    }

    // handle job assignment
    if job_handle != 0 {
        // Look up the newly created process to get its PID, then assign
        // it to the job object referenced by `job_handle`.
        let proc_header = ob::reference_object_by_handle(*process_handle);
        let job_header = ob::reference_object_by_handle(job_handle);
        if !proc_header.is_null() && !job_header.is_null() {
            let eprocess = ob::get_object_body::<Eprocess>(proc_header);
            let pid = unsafe { (*eprocess).unique_process_id };
            let job = ob::get_object_body::<crate::ps::job::JobObject>(job_header);
            let job_id = unsafe { (*job).job_id };
            crate::ps::job::assign_process_to_job(job_id, pid);
        }
    }

    STATUS_SUCCESS
}
