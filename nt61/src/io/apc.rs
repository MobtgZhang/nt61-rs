//! Asynchronous Procedure Calls (APCs) for I/O
//!
//! APCs are the NT mechanism for asynchronous I/O completion notification.
//! When an I/O operation completes, the I/O manager queues an APC to the
//! requesting thread, which is delivered when the thread returns to user mode.
//!
//! # APC Types
//! - **User APC**: Queued by user-mode code (e.g., ReadFileEx/WriteFileEx).
//! - **Kernel APC**: Queued by kernel-mode drivers (e.g., I/O completion).
//! - **Special Kernel APC**: High-priority APCs that interrupt even kernel mode.
//!
//! # I/O Completion APC Flow
//! 1. User calls NtReadFile/NtWriteFile with an APC routine.
//! 2. I/O manager creates an IRP and dispatches it.
//! 3. When the IRP completes, IoCompleteRequest queues an APC.
//! 4. The APC is delivered when the thread returns to user mode.

use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pool;
use crate::libs::ntdll::status::*;

pub type ApcRoutine = unsafe extern "C" fn(
    apc_context: *mut (),
    io_status_block: *mut IoStatusBlock,
    reserved: u32,
);

/// APC modes (kernel vs user).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ApcMode {
    KernelMode = 0,
    /// User APC - delivered when returning to user mode

    UserMode = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ApcType {
    Normal = 0,
    Special = 1,
    User = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: usize,
}

impl IoStatusBlock {
    pub const fn new() -> Self {
        Self {
            status: 0,
            information: 0,
        }
    }
}

#[repr(C)]
pub struct IoApc {
    pub apc_type: ApcType,
    pub mode: ApcMode,
    pub thread_id: u64,
    pub routine: Option<ApcRoutine>,
    pub context: *mut (),
    pub io_status_block: *mut IoStatusBlock,
    pub inserted: bool,
}

impl IoApc {
    pub fn new(
        mode: ApcMode,
        thread_id: u64,
        routine: Option<ApcRoutine>,
        context: *mut (),
        io_status_block: *mut IoStatusBlock,
    ) -> Self {
        Self {
            apc_type: if mode == ApcMode::UserMode {
                ApcType::User
            } else {
                ApcType::Normal
            },
            mode,
            thread_id,
            routine,
            context,
            io_status_block,
            inserted: false,
        }
    }
}

const MAX_THREAD_APCS: usize = 64;

struct ThreadApcQueue {
    thread_id: u64,
    user_apcs: Vec<IoApc>,
    kernel_apcs: Vec<IoApc>,
}

impl ThreadApcQueue {
    fn new(thread_id: u64) -> Self {
        Self {
            thread_id,
            user_apcs: Vec::new(),
            kernel_apcs: Vec::new(),
        }
    }

    fn insert(&mut self, apc: IoApc) -> bool {
        let queue = match apc.mode {
            ApcMode::UserMode => &mut self.user_apcs,
            ApcMode::KernelMode => &mut self.kernel_apcs,
        };

        if queue.len() >= MAX_THREAD_APCS {
            return false;
        }

        queue.push(apc);
        true
    }

    fn dequeue_user(&mut self) -> Option<IoApc> {
        if !self.user_apcs.is_empty() {
            Some(self.user_apcs.remove(0))
        } else {
            None
        }
    }

    fn dequeue_kernel(&mut self) -> Option<IoApc> {
        if !self.kernel_apcs.is_empty() {
            Some(self.kernel_apcs.remove(0))
        } else {
            None
        }
    }

    fn has_user_apcs(&self) -> bool {
        !self.user_apcs.is_empty()
    }

    fn has_kernel_apcs(&self) -> bool {
        !self.kernel_apcs.is_empty()
    }
}

static APC_QUEUES: Spinlock<Vec<ThreadApcQueue>> = Spinlock::new(Vec::new());

pub fn init() {
    let mut queues = APC_QUEUES.lock();
    if queues.is_empty() {
        queues.reserve(64);
    }
}

pub fn insert_io_apc(
    thread_id: u64,
    mode: ApcMode,
    routine: Option<ApcRoutine>,
    context: *mut (),
    io_status_block: *mut IoStatusBlock,
) -> bool {
    let apc = IoApc::new(mode, thread_id, routine, context, io_status_block);

    let mut queues = APC_QUEUES.lock();

    let queue = queues.iter_mut().find(|q| q.thread_id == thread_id);

    if let Some(queue) = queue {
        queue.insert(apc)
    } else {
        let mut new_queue = ThreadApcQueue::new(thread_id);
        let result = new_queue.insert(apc);
        queues.push(new_queue);
        result
    }
}

/// Deliver pending user APCs for a thread.
/// Called when the thread returns to user mode.
pub fn deliver_user_apcs(thread_id: u64) -> usize {
    let mut delivered = 0;

    loop {
        let apc = {
            let mut queues = APC_QUEUES.lock();
            let queue = queues.iter_mut().find(|q| q.thread_id == thread_id);
            queue.and_then(|q| q.dequeue_user())
        };

        match apc {
            Some(apc) => {
                if let Some(routine) = apc.routine {
                    unsafe {
                        routine(apc.context, apc.io_status_block, 0);
                    }
                    delivered += 1;
                }
            }
            None => break,
        }
    }

    delivered
}

pub fn deliver_kernel_apcs(thread_id: u64) -> usize {
    let mut delivered = 0;

    loop {
        let apc = {
            let mut queues = APC_QUEUES.lock();
            let queue = queues.iter_mut().find(|q| q.thread_id == thread_id);
            queue.and_then(|q| q.dequeue_kernel())
        };

        match apc {
            Some(apc) => {
                if let Some(routine) = apc.routine {
                    unsafe {
                        routine(apc.context, apc.io_status_block, 0);
                    }
                    delivered += 1;
                }
            }
            None => break,
        }
    }

    delivered
}

/// Check if a thread has pending user APCs.
pub fn has_user_apcs(thread_id: u64) -> bool {
    let queues = APC_QUEUES.lock();
    queues
        .iter()
        .find(|q| q.thread_id == thread_id)
        .map_or(false, |q| q.has_user_apcs())
}

pub fn has_kernel_apcs(thread_id: u64) -> bool {
    let queues = APC_QUEUES.lock();
    queues
        .iter()
        .find(|q| q.thread_id == thread_id)
        .map_or(false, |q| q.has_kernel_apcs())
}

pub fn clear_thread_apcs(thread_id: u64) {
    let mut queues = APC_QUEUES.lock();
    queues.retain(|q| q.thread_id != thread_id);
}

pub fn get_apc_count(thread_id: u64) -> (usize, usize) {
    let queues = APC_QUEUES.lock();

    if let Some(queue) = queues.iter().find(|q| q.thread_id == thread_id) {
        (queue.user_apcs.len(), queue.kernel_apcs.len())
    } else {
        (0, 0)
    }
}
