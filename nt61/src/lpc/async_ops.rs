//! Asynchronous message delivery
//!
//! ALPC supports asynchronous operations:
//! - Non-blocking send/receive
//! - Completion notifications
//! - I/O completion ports integration

use core::sync::atomic::{AtomicU64, Ordering};

use super::{LpcMessage, LpcMessageHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsyncOpType {
    Send = 0,
    Receive = 1,
    Connect = 2,
    Accept = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AsyncStatus {
    Pending = 0,
    Completed = 1,
    Failed = 2,
    Cancelled = 3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AsyncOperation {
    pub op_type: AsyncOpType,
    pub status: AsyncStatus,
    pub port_index: u32,
    pub message: LpcMessage,
    pub result: u32,
    pub bytes_transferred: usize,
    pub op_id: u64,
    pub completion_callback: Option<fn(op_id: u64, status: AsyncStatus)>,
}

impl AsyncOperation {
    pub const fn empty() -> Self {
        Self {
            op_type: AsyncOpType::Send,
            status: AsyncStatus::Pending,
            port_index: 0,
            message: LpcMessage::empty(),
            result: 0,
            bytes_transferred: 0,
            op_id: 0,
            completion_callback: None,
        }
    }
}

pub const MAX_ASYNC_OPS: usize = 64;

pub struct AsyncQueue {
    pub operations: [AsyncOperation; MAX_ASYNC_OPS],
    pub count: u32,
}

impl AsyncQueue {
    pub const fn new() -> Self {
        Self {
            operations: [const { AsyncOperation::empty() }; MAX_ASYNC_OPS],
            count: 0,
        }
    }
}

static NEXT_OP_ID: AtomicU64 = AtomicU64::new(1);
static ASYNC_COMPLETIONS: AtomicU64 = AtomicU64::new(0);

pub fn async_send(
    port_index: u32,
    message: &LpcMessage,
    completion_callback: Option<fn(u64, AsyncStatus)>,
    queue: &mut AsyncQueue,
) -> Option<u64> {
    if (queue.count as usize) >= MAX_ASYNC_OPS {
        return None;
    }

    for i in 0..queue.operations.len() {
        if queue.operations[i].status != AsyncStatus::Pending {
            let op_id = NEXT_OP_ID.fetch_add(1, Ordering::SeqCst);

            queue.operations[i].op_type = AsyncOpType::Send;
            queue.operations[i].status = AsyncStatus::Pending;
            queue.operations[i].port_index = port_index;
            queue.operations[i].message = *message;
            queue.operations[i].op_id = op_id;
            queue.operations[i].completion_callback = completion_callback;
            queue.operations[i].result = 0;
            queue.operations[i].bytes_transferred = 0;

            queue.count = queue.count + 1;
            return Some(op_id);
        }
    }

    None
}

pub fn async_receive(
    port_index: u32,
    completion_callback: Option<fn(u64, AsyncStatus)>,
    queue: &mut AsyncQueue,
) -> Option<u64> {
    if (queue.count as usize) >= MAX_ASYNC_OPS {
        return None;
    }

    for i in 0..queue.operations.len() {
        if queue.operations[i].status != AsyncStatus::Pending {
            let op_id = NEXT_OP_ID.fetch_add(1, Ordering::SeqCst);

            queue.operations[i].op_type = AsyncOpType::Receive;
            queue.operations[i].status = AsyncStatus::Pending;
            queue.operations[i].port_index = port_index;
            queue.operations[i].op_id = op_id;
            queue.operations[i].completion_callback = completion_callback;
            queue.operations[i].result = 0;
            queue.operations[i].bytes_transferred = 0;

            queue.count = queue.count + 1;
            return Some(op_id);
        }
    }

    None
}

pub fn complete_async_operation(
    op_id: u64,
    status: AsyncStatus,
    result: u32,
    bytes_transferred: usize,
    queue: &mut AsyncQueue,
) -> bool {
    for i in 0..queue.operations.len() {
        if queue.operations[i].op_id == op_id && queue.operations[i].status == AsyncStatus::Pending {
            queue.operations[i].status = status;
            queue.operations[i].result = result;
            queue.operations[i].bytes_transferred = bytes_transferred;

            if let Some(callback) = queue.operations[i].completion_callback {
                callback(op_id, status);
            }

            queue.count = queue.count.saturating_sub(1);
            ASYNC_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }

    false
}

pub fn cancel_async_operation(op_id: u64, queue: &mut AsyncQueue) -> bool {
    complete_async_operation(op_id, AsyncStatus::Cancelled, 0, 0, queue)
}

pub fn get_async_operation(op_id: u64, queue: &AsyncQueue) -> Option<AsyncOperation> {
    for op in &queue.operations {
        if op.op_id == op_id {
            return Some(*op);
        }
    }
    None
}

pub fn async_completion_count() -> u64 {
    ASYNC_COMPLETIONS.load(Ordering::Relaxed)
}
