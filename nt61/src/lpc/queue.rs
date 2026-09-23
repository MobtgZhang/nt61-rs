//! Message queue management
//!
//! Enhanced message queue with:
//! - Message ID tracking for request/reply correlation
//! - Priority support
//! - Queue overflow handling

use core::sync::atomic::{AtomicU64, Ordering};

use super::{LpcMessage, LpcMessageType};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueuedMessage {
    pub message: LpcMessage,
    pub message_id: u64,
    pub priority: u8,
    pub timestamp: u64,
    pub is_reply: bool,
    pub reply_to_id: u64,
}

impl QueuedMessage {
    pub const fn empty() -> Self {
        Self {
            message: LpcMessage::empty(),
            message_id: 0,
            priority: 0,
            timestamp: 0,
            is_reply: false,
            reply_to_id: 0,
        }
    }
}

pub const PRIORITY_LOW: u8 = 0;
pub const PRIORITY_NORMAL: u8 = 1;
pub const PRIORITY_HIGH: u8 = 2;
pub const PRIORITY_CRITICAL: u8 = 3;

static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);
static QUEUE_FULL_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn allocate_message_id() -> u64 {
    NEXT_MESSAGE_ID.fetch_add(1, Ordering::SeqCst)
}

pub fn create_queued_message(
    message: LpcMessage,
    priority: u8,
    is_reply: bool,
    reply_to_id: u64,
) -> QueuedMessage {
    QueuedMessage {
        message,
        message_id: allocate_message_id(),
        priority,
        timestamp: 0, // Would use real timestamp in production
        is_reply,
        reply_to_id,
    }
}

pub struct MessageQueueOps;

impl MessageQueueOps {
    pub fn find_message_by_id(
        message_id: u64,
        messages: &[QueuedMessage],
        tail: u32,
        pending: u32,
    ) -> Option<usize> {
        for i in 0..pending as usize {
            let idx = ((tail as usize) + i) % messages.len();
            if messages[idx].message_id == message_id {
                return Some(idx);
            }
        }
        None
    }

    pub fn find_reply(
        request_id: u64,
        messages: &[QueuedMessage],
        tail: u32,
        pending: u32,
    ) -> Option<usize> {
        for i in 0..pending as usize {
            let idx = ((tail as usize) + i) % messages.len();
            if messages[idx].is_reply && messages[idx].reply_to_id == request_id {
                return Some(idx);
            }
        }
        None
    }

    pub fn record_overflow() {
        QUEUE_FULL_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    pub fn overflow_count() -> u64 {
        QUEUE_FULL_COUNT.load(Ordering::Relaxed)
    }
}

pub enum MessageFilter {
    Any,
    Type(LpcMessageType),
    ReplyTo(u64),
    FromPid(u64),
}

impl MessageFilter {
    pub fn matches(&self, msg: &QueuedMessage) -> bool {
        match self {
            MessageFilter::Any => true,
            MessageFilter::Type(msg_type) => {
                msg.message.header.message_type == *msg_type as u32
            }
            MessageFilter::ReplyTo(req_id) => {
                msg.is_reply && msg.reply_to_id == *req_id
            }
            MessageFilter::FromPid(pid) => {
                msg.message.header.sender_pid == *pid
            }
        }
    }
}

#[derive(Default)]
pub struct QueueStats {
    pub total_enqueued: u64,
    pub total_dequeued: u64,
    pub peak_depth: u32,
    pub current_depth: u32,
}
