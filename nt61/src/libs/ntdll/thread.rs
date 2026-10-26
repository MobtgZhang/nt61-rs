//! ntdll — Nt* thread APIs
//
//! `nt_create_thread`, `nt_open_thread`, `nt_terminate_thread`,
//! `nt_query_information_thread`, `nt_yield_execution`. The
//! underlying thread objects live in `ps::thread`; we wrap them
//! in the ntdll handle table so kernel32's get_thread_id etc.
//! can find them.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` thread
//! APIs.

use super::file::{alloc_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY,
    STATUS_SUCCESS,
};
use super::types::{client_id, HANDLE, NTSTATUS, PVOID};
use crate::libs::ntdll::status::STATUS_ACCESS_VIOLATION;
use crate::mm::user_copy::{copy_from_user, copy_to_user, read_user_object, write_user_object};

/// Thread context structure for nt_get_context_thread/nt_set_context_thread
#[repr(C)]
#[derive(Default)]
pub struct Context {
    /// Context flags - determines which registers are valid
    pub context_flags: u32,
    /// Segment registers
    pub mx_csr: u32,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub es: u16,
    pub ds: u16,
    /// Integer registers
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// control registers
    pub rsp: u64,
    pub rip: u64,
    /// Debug registers
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    /// Floating point
    pub float_save: [u64; 8], // Simplified
    /// XMM registers
    pub xmm0: [u64; 2],
    pub xmm1: [u64; 2],
    pub xmm2: [u64; 2],
    pub xmm3: [u64; 2],
    pub xmm4: [u64; 2],
    pub xmm5: [u64; 2],
    pub xmm6: [u64; 2],
    pub xmm7: [u64; 2],
    pub xmm8: [u64; 2],
    pub xmm9: [u64; 2],
    pub xmm10: [u64; 2],
    pub xmm11: [u64; 2],
    pub xmm12: [u64; 2],
    pub xmm13: [u64; 2],
    pub xmm14: [u64; 2],
    pub xmm15: [u64; 2],
}

// Context flags for CONTEXT structure
pub const CONTEXT_INTEGER: u32 = 0x00010001;
pub const CONTEXT_CONTROL: u32 = 0x00010002;
pub const CONTEXT_SEGMENTS: u32 = 0x00010004;
pub const CONTEXT_FLOATING_POINT: u32 = 0x00010008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;
pub const CONTEXT_XSTATE: u32 = 0x00010040;
pub const CONTEXT_FULL: u32 = 0x00010007;

/// `nt_create_thread` — create a thread inside an existing
/// process.
/// nt_current_thread — pseudo-handle for the calling thread.
///
/// Windows exposes the calling thread to Nt* APIs through the
/// documented pseudo-handle value `(HANDLE)-2`. Returning it here keeps
/// the advapi32 impersonation helpers (`SetThreadToken`, `RevertToSelf`)
/// consistent with the real ntdll contract.
pub unsafe extern "C" fn nt_current_thread() -> HANDLE {
    0xFFFF_FFFF_FFFF_FFFEu64 as HANDLE
}

pub unsafe extern "C" fn nt_create_thread(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    process_handle: HANDLE,
    client_id: *mut client_id,
    start_context: PVOID,
    start_routine: PVOID,
    stack_committed: usize,
    stack_size: usize,
) -> NTSTATUS {
    use super::status::{
        STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
    };

    if thread_handle.is_null() || start_routine.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (desired_access, object_attributes, stack_committed);

    // Get target process
    let target_pid = if process_handle.is_null() {
        // Current process - get from current thread's process
        let current_ethread = crate::ps::thread::get_current_ethread();
        if current_ethread.is_null() {
            4u64 // System process as fallback
        } else {
            // Get process ID from ETHREAD's client_id
            let cid = unsafe { (*current_ethread).client_id };
            cid.unique_process as u64
        }
    } else {
        // Look up process from handle
        if let Some(entry) = lookup_handle(process_handle) {
            if entry.kind == HandleKind::Process {
                entry.target
            } else {
                return STATUS_INVALID_HANDLE;
            }
        } else {
            return STATUS_INVALID_HANDLE;
        }
    };

    // Get process EPROCESS
    let process = match crate::ps::process::get_by_pid(target_pid) {
        Some(p) => p as *mut crate::ps::process::Eprocess,
        None => return STATUS_INVALID_HANDLE,
    };

    // create the thread using kernel thread module
    let thread_ptr = match crate::ps::thread::create_thread(process, stack_size) {
        Some(t) => t,
        None => return STATUS_NO_MEMORY,
    };

    // Set thread start address (RIP)
    thread_ptr.kthread.context.user_rip = start_routine as u64;

    // Set thread stack pointer (RSP) to top of user stack
    // The kernel's create_thread allocates a stack; we set RSP to the top
    // Default stack size is 2MB (0x200000), stack grows downward
    let actual_stack_size: u64 = if stack_size > 0 {
        stack_size as u64
    } else {
        0x200000
    };
    let user_stack_top: u64 = 0x7FFF_FFFE_0000u64; // Default user stack base (2GB boundary)
    let aligned_stack = user_stack_top - actual_stack_size & !0xF; // 16-byte aligned

    thread_ptr.kthread.context.user_rsp = aligned_stack;

    // If start_context is provided, it should be passed to the thread
    // For now, we acknowledge it but don't implement full APC
    let _ = start_context;

    // Allocate handle for the thread
    let tid = thread_ptr.client_id.unique_thread;
    let h = alloc_handle(HandleKind::Thread, tid);

    if h.is_null() {
        return STATUS_NO_MEMORY;
    }

    if write_user_object(thread_handle as u64, &h).is_err() {
        return STATUS_NO_MEMORY;
    }

    // Fill in client ID if requested
    if !client_id.is_null() {
        let cid = client_id {
            unique_process: target_pid as HANDLE,
            unique_thread: tid as HANDLE,
        };
        if write_user_object(client_id as u64, &cid).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    STATUS_SUCCESS
}

/// `nt_open_thread` — open a thread by `CLIENT_ID`.
pub unsafe extern "C" fn nt_open_thread(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    client_id: *mut client_id,
) -> NTSTATUS {
    use super::status::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

    if thread_handle.is_null() || client_id.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (object_attributes, desired_access);

    let cid: client_id = match read_user_object(client_id as u64) {
        Ok(value) => value,
        Err(_) => return STATUS_INVALID_PARAMETER,
    };

    // Try to find the thread by TID in the kernel thread table
    let target_tid = cid.unique_thread as u64;
    if target_tid == 0 {
        return STATUS_INVALID_HANDLE;
    }

    // Look up the thread in the kernel's thread table
    let thread_ptr = crate::ps::thread::find_thread_by_tid(target_tid);

    if let Some(thread) = thread_ptr {
        // Thread found - allocate handle with real TID
        let actual_tid = unsafe { (*thread).client_id.unique_thread };
        let h = alloc_handle(HandleKind::Thread, actual_tid);
        if h.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        if write_user_object(thread_handle as u64, &h).is_err() {
            return STATUS_INVALID_HANDLE;
        }
        STATUS_SUCCESS
    } else {
        // Thread not found - for bootstrap compatibility, still create a handle
        // with the requested TID
        let h = alloc_handle(HandleKind::Thread, target_tid);
        if h.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        if write_user_object(thread_handle as u64, &h).is_err() {
            return STATUS_INVALID_HANDLE;
        }
        STATUS_SUCCESS
    }
}

/// `nt_terminate_thread` — terminate the specified thread.
/// If thread_handle is NULL, terminates the current thread.
pub unsafe extern "C" fn nt_terminate_thread(thread_handle: HANDLE, exit_status: u32) -> NTSTATUS {
    use super::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};

    // If thread_handle is NULL, terminate current thread
    let thread_ptr = if thread_handle.is_null() {
        // Get current thread
        crate::ps::thread::get_current_ethread()
    } else {
        // Look up the thread from handle
        if let Some(entry) = lookup_handle(thread_handle) {
            if entry.kind == HandleKind::Thread {
                // Find the thread by TID
                if let Some(thread) = crate::ps::thread::find_thread_by_tid(entry.target) {
                    thread
                } else {
                    return STATUS_INVALID_HANDLE;
                }
            } else {
                return STATUS_INVALID_HANDLE;
            }
        } else {
            return STATUS_INVALID_HANDLE;
        }
    };

    if !thread_ptr.is_null() {
        // Call the kernel thread termination
        crate::ps::thread::terminate(thread_ptr, exit_status);
    }

    STATUS_SUCCESS
}

/// `nt_suspend_thread` / `nt_resume_thread` — counters the NT
/// kernel exposes on every thread. We return 1 (the previous
/// count) for both.
pub unsafe extern "C" fn nt_suspend_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    if !previous_suspend_count.is_null() {
        *previous_suspend_count = 1;
    }
    STATUS_SUCCESS
}

pub unsafe extern "C" fn nt_resume_thread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    if !previous_suspend_count.is_null() {
        *previous_suspend_count = 1;
    }
    STATUS_SUCCESS
}

/// `nt_query_information_thread` — supports
/// `ThreadBasicInformation` (size 28) and a few others.
pub unsafe extern "C" fn nt_query_information_thread(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: PVOID,
    thread_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if thread_handle.is_null() || thread_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    match thread_information_class {
        0 => {
            // ThreadBasicInformation: ExitStatus, TebAddress, client_id, ...
            if thread_information_length < 28 {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let output = [0u8; 28];
            if copy_to_user(thread_information as u64, &output).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if write_return_length(return_length, 28).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        4 => {
            // ThreadTimes — 32 bytes
            if thread_information_length < 32 {
                return super::status::STATUS_BUFFER_TOO_SMALL;
            }
            let output = [0u8; 32];
            if copy_to_user(thread_information as u64, &output).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            if write_return_length(return_length, 32).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_SUCCESS
        }
        _ => {
            if write_return_length(return_length, 0).is_err() {
                return super::status::STATUS_ACCESS_VIOLATION;
            }
            STATUS_INVALID_INFO_CLASS
        }
    }
}

fn write_return_length(return_length: *mut u32, length: usize) -> Result<(), i32> {
    if return_length.is_null() {
        return Ok(());
    }
    copy_to_user(return_length as u64, &(length as u32).to_le_bytes())
}

/// `nt_yield_execution` — yield the timeslice of the current
/// thread. Routed to the kernel scheduler.
pub extern "C" fn nt_yield_execution() -> NTSTATUS {
    crate::ke::scheduler::yield_();
    STATUS_SUCCESS
}

/// `nt_current_teb` — returns the TEB pointer for the current
/// thread. Useful for the kernel32 layer.
///
/// On x86_64, the TEB is stored at GS:0, which points to the
/// current Thread environment Block.
pub extern "C" fn nt_current_teb() -> PVOID {
    crate::arch::current_teb().unwrap_or(0) as PVOID
}

/// `nt_create_thread_ex` — create a thread with extended parameters.
/// This is the preferred way to create threads in Windows 7+.
pub unsafe extern "C" fn nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    _desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    process_handle: HANDLE,
    start_routine: PVOID,
    start_context: PVOID,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: PVOID,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (
        object_attributes,
        zero_bits,
        maximum_stack_size,
        attribute_list,
    );

    // Debug flag: CREATE_SUSPENDED (0x1)
    let _is_suspended = create_flags & 0x1 != 0;
    // Debug flag: stack visibility (0x2)
    let _stack_win64 = create_flags & 0x2 != 0;

    // Get target process
    let target_pid = if process_handle.is_null() {
        // Current process
        4u64 // System process for now
    } else {
        // Look up process from handle
        if let Some(entry) = lookup_handle(process_handle) {
            if entry.kind == HandleKind::Process {
                entry.target
            } else {
                return STATUS_INVALID_HANDLE;
            }
        } else {
            return STATUS_INVALID_HANDLE;
        }
    };

    // Get process EPROCESS
    let process = match crate::ps::process::get_by_pid(target_pid) {
        Some(p) => p as *mut crate::ps::process::Eprocess,
        None => return STATUS_INVALID_HANDLE,
    };

    // create the thread using kernel thread module
    let thread_ptr = match crate::ps::thread::create_thread(process, stack_size) {
        Some(t) => t,
        None => return STATUS_NO_MEMORY,
    };

    // Set thread start address
    thread_ptr.kthread.context.user_rip = start_routine as u64;
    // If start_context is provided, pass it to the thread
    if !start_context.is_null() {
        thread_ptr.kthread.context.user_rsp = start_context as u64;
    }

    // Allocate handle for the thread
    let tid = thread_ptr.client_id.unique_thread;
    let h = alloc_handle(HandleKind::Thread, tid);

    if h.is_null() {
        return STATUS_NO_MEMORY;
    }

    if write_user_object(thread_handle as u64, &h).is_err() {
        return STATUS_NO_MEMORY;
    }

    STATUS_SUCCESS
}

/// `nt_get_context_thread` — get the register context of a thread.
pub unsafe extern "C" fn nt_get_context_thread(
    thread_handle: HANDLE,
    context: *mut Context,
) -> NTSTATUS {
    if thread_handle.is_null() || context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the thread from handle
    let tid = if let Some(entry) = lookup_handle(thread_handle) {
        if entry.kind == HandleKind::Thread {
            entry.target
        } else {
            return STATUS_INVALID_HANDLE;
        }
    } else {
        return STATUS_INVALID_HANDLE;
    };

    // Find the thread
    let thread = match crate::ps::thread::find_thread_by_tid(tid as u64) {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    // Fill in the context structure
    let mut ctx = Context::default();
    let ctx_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut ctx as *mut Context as *mut u8,
            core::mem::size_of::<Context>(),
        )
    };
    if copy_from_user(ctx_bytes, context as u64).is_err() {
        return super::status::STATUS_ACCESS_VIOLATION;
    }

    // Check what context flags are requested
    let flags = ctx.context_flags;

    if flags & CONTEXT_INTEGER != 0 || flags == 0 {
        ctx.rax = (*thread).kthread.context.rax;
        ctx.rcx = (*thread).kthread.context.rcx;
        ctx.rdx = (*thread).kthread.context.rdx;
        ctx.rbx = (*thread).kthread.context.rbx;
        ctx.rbp = (*thread).kthread.context.rbp;
        ctx.rsi = (*thread).kthread.context.rsi;
        ctx.rdi = (*thread).kthread.context.rdi;
    }

    if flags & CONTEXT_CONTROL != 0 || flags == 0 {
        ctx.rip = (*thread).kthread.context.user_rip;
        ctx.rsp = (*thread).kthread.context.user_rsp;
        ctx.rbp = (*thread).kthread.context.rbp;
    }

    if copy_to_user(context as u64, unsafe {
        core::slice::from_raw_parts(
            &ctx as *const Context as *const u8,
            core::mem::size_of::<Context>(),
        )
    })
    .is_err()
    {
        return super::status::STATUS_ACCESS_VIOLATION;
    }

    // Note: previous versions of this stub issued a self-assignment of
    // `ctx.context_flags` here — a no-op that clippy flags. The flag is
    // already populated above by the `InitializeContext` prologue and
    // is required to remain set for the kernel's context-restore path,
    // so leaving it untouched is the right behaviour.

    STATUS_SUCCESS
}

/// `nt_set_context_thread` — set the register context of a thread.
pub unsafe extern "C" fn nt_set_context_thread(
    thread_handle: HANDLE,
    context: *const Context,
) -> NTSTATUS {
    if thread_handle.is_null() || context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the thread from handle
    let tid = if let Some(entry) = lookup_handle(thread_handle) {
        if entry.kind == HandleKind::Thread {
            entry.target
        } else {
            return STATUS_INVALID_HANDLE;
        }
    } else {
        return STATUS_INVALID_HANDLE;
    };

    // Find the thread
    let thread = match crate::ps::thread::find_thread_by_tid(tid as u64) {
        Some(t) => t,
        None => return STATUS_INVALID_HANDLE,
    };

    let mut ctx = Context::default();
    let ctx_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut ctx as *mut Context as *mut u8,
            core::mem::size_of::<Context>(),
        )
    };
    if copy_from_user(ctx_bytes, context as u64).is_err() {
        return super::status::STATUS_ACCESS_VIOLATION;
    }

    // Check what context flags are being set
    let flags = ctx.context_flags;

    if flags & CONTEXT_INTEGER != 0 || flags == 0 {
        (*thread).kthread.context.rax = ctx.rax;
        (*thread).kthread.context.rcx = ctx.rcx;
        (*thread).kthread.context.rdx = ctx.rdx;
        (*thread).kthread.context.rbx = ctx.rbx;
        (*thread).kthread.context.rbp = ctx.rbp;
        (*thread).kthread.context.rsi = ctx.rsi;
        (*thread).kthread.context.rdi = ctx.rdi;
    }

    if flags & CONTEXT_CONTROL != 0 || flags == 0 {
        (*thread).kthread.context.user_rip = ctx.rip;
        (*thread).kthread.context.user_rsp = ctx.rsp;
        (*thread).kthread.context.rbp = ctx.rbp;
    }

    STATUS_SUCCESS
}

/// `nt_queue_apc_thread` — queue an Asynchronous Procedure Call to a thread.
/// This is a simplified implementation that just validates the parameters.
pub unsafe extern "C" fn nt_queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: PVOID,
    apc_argument1: PVOID,
    apc_argument2: PVOID,
    apc_argument3: PVOID,
) -> NTSTATUS {
    if thread_handle.is_null() || apc_routine.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (apc_argument1, apc_argument2, apc_argument3);

    // Get the thread from handle
    let _tid = if let Some(entry) = lookup_handle(thread_handle) {
        if entry.kind == HandleKind::Thread {
            entry.target
        } else {
            return STATUS_INVALID_HANDLE;
        }
    } else {
        return STATUS_INVALID_HANDLE;
    };

    // In a full implementation, we would:
    // 1. Allocate an APC object
    // 2. Add it to the thread's APC queue
    // 3. Signal the thread if it's waiting
    // For now, just validate and return success
    // crate::kprintln!("[APC] nt_queue_apc_thread queued to routine @ 0x{:016x}", apc_routine as u64);

    STATUS_SUCCESS
}

/// `nt_set_information_thread` — set thread information.
pub unsafe extern "C" fn nt_set_information_thread(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: PVOID,
    thread_information_length: u32,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = thread_information_length;

    match thread_information_class {
        0 => {
            // ThreadBasicInformation - read only, return error
            STATUS_INVALID_INFO_CLASS
        }
        17 => {
            // ThreadAffinityMask - set CPU affinity
            if thread_information.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            STATUS_SUCCESS
        }
        19 => {
            // ThreadPriority - set thread priority
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_INFO_CLASS,
    }
}
