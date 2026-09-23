//! ntdll — User-Mode APC (Asynchronous Procedure Call)
//!
//! User-mode APC queue management for Windows 7.
//! APCs are callbacks executed in the context of a specific thread.
//!
//! APC Types:
//! - User APC: Queued by NtQueueApcThread, executed when thread is alertable
//! - Special User APC: Higher priority, for kernel use
//!
//! Note: This is separate from ke/apc.rs which handles kernel-mode APCs.
//!
//! References:
//!   * Windows Internals 7th Ed. - Chapter 8
//!   * MSDN Library "Windows 7" — Asynchronous Procedure Calls

use super::types::{HANDLE, NTSTATUS, PVOID};
use super::status::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::file::{lookup_handle, HandleKind};
use crate::ke::sync::Spinlock;
use core::ptr;


pub type ApcRoutine = unsafe extern "C" fn(apc_context: PVOID);

#[derive(Clone, Copy)]
struct ApcEntry {
    routine: ApcRoutine,
    context: PVOID,
    thread_id: u64,
}

impl ApcEntry {
    const fn new() -> Self {
        Self {
            routine: dummy_apc_routine,
            context: ptr::null_mut(),
            thread_id: 0,
        }
    }
}

unsafe extern "C" fn dummy_apc_routine(_context: PVOID) {}

const MAX_APCS_PER_THREAD: usize = 32;

#[derive(Clone, Copy)]
struct ThreadApcQueue {
    apcs: [Option<ApcEntry>; MAX_APCS_PER_THREAD],
    count: usize,
}

impl ThreadApcQueue {
    const fn new() -> Self {
        Self {
            apcs: [None; MAX_APCS_PER_THREAD],
            count: 0,
        }
    }

    fn push(&mut self, entry: ApcEntry) -> bool {
        if self.count >= MAX_APCS_PER_THREAD {
            return false;
        }
        self.apcs[self.count] = Some(entry);
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<ApcEntry> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.apcs[self.count].take()
    }
}

const MAX_THREADS: usize = 256;
static APC_QUEUES: Spinlock<[ThreadApcQueue; MAX_THREADS]> =
    Spinlock::new([ThreadApcQueue::new(); MAX_THREADS]);


pub unsafe extern "C" fn NtQueueApcThread(
    thread_handle: HANDLE,
    apc_routine: ApcRoutine,
    apc_context: PVOID,
    argument1: PVOID,
    argument2: PVOID,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let entry = match lookup_handle(thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let thread_id = entry.target;
    let _ = (argument1, argument2); // Not used in basic implementation

    let apc_entry = ApcEntry {
        routine: apc_routine,
        context: apc_context,
        thread_id,
    };

    let mut queues = APC_QUEUES.lock();
    let queue_idx = (thread_id as usize) % MAX_THREADS;

    if !queues[queue_idx].push(apc_entry) {
        return STATUS_INVALID_PARAMETER; // Queue full
    }

    // 3. On next kernel->user transition, deliver APC

    STATUS_SUCCESS
}


/// - System is about to return to user mode
pub fn deliver_pending_apcs() {
    unsafe {
        let thread_id = 1u64; // Bootstrap: assume thread 1

        let mut queues = APC_QUEUES.lock();
        let queue_idx = (thread_id as usize) % MAX_THREADS;
        let queue = &mut queues[queue_idx];

        while let Some(apc) = queue.pop() {
            (apc.routine)(apc.context);
        }
    }
}

pub fn has_pending_apcs() -> bool {
    let thread_id = 1u64; // Bootstrap

    let queues = APC_QUEUES.lock();
    let queue_idx = (thread_id as usize) % MAX_THREADS;
    queues[queue_idx].count > 0
}


pub unsafe extern "C" fn NtTestAlert() -> NTSTATUS {
    if has_pending_apcs() {
        deliver_pending_apcs();
        super::status::STATUS_ALERTED
    } else {
        STATUS_SUCCESS
    }
}


pub unsafe extern "C" fn NtAlertThread(thread_handle: HANDLE) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let entry = match lookup_handle(thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _thread_id = entry.target;


    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtAlertResumeThread(
    thread_handle: HANDLE,
    previous_suspend_count: *mut u32,
) -> NTSTATUS {
    if thread_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let entry = match lookup_handle(thread_handle) {
        Some(e) if e.kind == HandleKind::Thread => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let _thread_id = entry.target;


    if !previous_suspend_count.is_null() {
        *previous_suspend_count = 0;
    }

    STATUS_SUCCESS
}
