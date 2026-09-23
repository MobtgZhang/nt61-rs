//! Direct (fast-path) message operations
//!
//! ALPC supports direct message passing that bypasses the kernel
//! message queue for small, synchronous messages. This provides
//! better performance for request-reply patterns.

use core::sync::atomic::{AtomicU64, Ordering};

use super::{LpcMessage, LpcMessageHeader, LpcMessageType};

#[repr(C)]
pub struct DirectBuffer {
    pub client_buffer: [u8; 256],
    pub server_buffer: [u8; 256],
    pub client_len: u32,
    pub server_len: u32,
    pub sequence: u64,
    pub flags: u32,
}

impl DirectBuffer {
    pub const fn empty() -> Self {
        Self {
            client_buffer: [0u8; 256],
            server_buffer: [0u8; 256],
            client_len: 0,
            server_len: 0,
            sequence: 0,
            flags: 0,
        }
    }
}

pub const DIRECT_FLAG_CLIENT_READY: u32 = 0x0001;
pub const DIRECT_FLAG_SERVER_READY: u32 = 0x0002;
pub const DIRECT_FLAG_CLIENT_COMPLETE: u32 = 0x0004;
pub const DIRECT_FLAG_SERVER_COMPLETE: u32 = 0x0008;

pub const MAX_DIRECT_BUFFERS: usize = 16;

pub struct DirectBufferRegistry {
    pub buffers: [DirectBuffer; MAX_DIRECT_BUFFERS],
    pub port_mapping: [u32; MAX_DIRECT_BUFFERS],
    pub count: u32,
}

impl DirectBufferRegistry {
    pub const fn new() -> Self {
        Self {
            buffers: [const { DirectBuffer::empty() }; MAX_DIRECT_BUFFERS],
            port_mapping: [0u32; MAX_DIRECT_BUFFERS],
            count: 0,
        }
    }
}

static DIRECT_SEND_COUNT: AtomicU64 = AtomicU64::new(0);
static DIRECT_RECV_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn allocate_direct_buffer(
    port_index: u32,
    registry: &mut DirectBufferRegistry,
) -> Option<u32> {
    if (registry.count as usize) >= MAX_DIRECT_BUFFERS {
        return None;
    }

    let idx = registry.count as usize;
    registry.port_mapping[idx] = port_index;
    registry.buffers[idx] = DirectBuffer::empty();
    registry.count = registry.count + 1;

    Some(idx as u32)
}

pub fn direct_send(
    buffer_id: u32,
    message: &LpcMessage,
    is_client: bool,
    registry: &mut DirectBufferRegistry,
) -> Option<usize> {
    if (buffer_id as usize) >= registry.count as usize {
        return None;
    }

    let buffer = &mut registry.buffers[buffer_id as usize];

    let (dst_buf, len_field, ready_flag, complete_flag) = if is_client {
        (&mut buffer.client_buffer[..], &mut buffer.client_len, DIRECT_FLAG_CLIENT_READY, DIRECT_FLAG_CLIENT_COMPLETE)
    } else {
        (&mut buffer.server_buffer[..], &mut buffer.server_len, DIRECT_FLAG_SERVER_READY, DIRECT_FLAG_SERVER_COMPLETE)
    };

    let copy_len = core::cmp::min(message.data_len as usize, dst_buf.len());
    dst_buf[..copy_len].copy_from_slice(&message.data[..copy_len]);
    *len_field = copy_len as u32;

    buffer.flags |= ready_flag;
    buffer.flags |= complete_flag;
    buffer.sequence = buffer.sequence.wrapping_add(1);

    DIRECT_SEND_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(copy_len)
}

pub fn direct_receive(
    buffer_id: u32,
    is_client: bool,
    registry: &DirectBufferRegistry,
) -> Option<LpcMessage> {
    if (buffer_id as usize) >= registry.count as usize {
        return None;
    }

    let buffer = &registry.buffers[buffer_id as usize];

    let (src_buf, len, ready_flag) = if is_client {
        (&buffer.server_buffer[..], buffer.server_len, DIRECT_FLAG_SERVER_READY)
    } else {
        (&buffer.client_buffer[..], buffer.client_len, DIRECT_FLAG_CLIENT_READY)
    };

    if (buffer.flags & ready_flag) == 0 {
        return None;
    }

    let mut message = LpcMessage::empty();
    let copy_len = core::cmp::min(len as usize, message.data.len());
    message.data[..copy_len].copy_from_slice(&src_buf[..copy_len]);
    message.data_len = copy_len as u32;

    DIRECT_RECV_COUNT.fetch_add(1, Ordering::Relaxed);

    Some(message)
}

pub fn free_direct_buffer(
    buffer_id: u32,
    registry: &mut DirectBufferRegistry,
) -> bool {
    if (buffer_id as usize) >= registry.count as usize {
        return false;
    }

    registry.buffers[buffer_id as usize] = DirectBuffer::empty();
    registry.port_mapping[buffer_id as usize] = 0;

    true
}

pub fn direct_stats() -> (u64, u64) {
    (
        DIRECT_SEND_COUNT.load(Ordering::Relaxed),
        DIRECT_RECV_COUNT.load(Ordering::Relaxed),
    )
}
