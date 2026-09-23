//! Connection management
//!
//! This module implements ALPC connection establishment:
//! - Connection request sending
//! - Connection acceptance/rejection
//! - Connection reply handling

use core::sync::atomic::{AtomicU64, Ordering};

use super::{LpcMessage, LpcMessageHeader, LpcMessageType, LpcRegistry, LpcPort, LpcPortType, MAX_PORTS};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionMessage {
    pub client_data: [u8; 128],
    pub client_data_len: u32,
    pub server_data: [u8; 128],
    pub server_data_len: u32,
}

impl ConnectionMessage {
    pub const fn empty() -> Self {
        Self {
            client_data: [0u8; 128],
            client_data_len: 0,
            server_data: [0u8; 128],
            server_data_len: 0,
        }
    }
}

#[repr(C)]
pub struct ConnectionRequest {
    pub server_port_index: u32,
    pub client_pid: u64,
    pub client_tid: u64,
    pub message: ConnectionMessage,
    pub pending: bool,
    pub client_port_index: u32,
    pub server_comm_port_index: u32,
}

impl ConnectionRequest {
    pub const fn empty() -> Self {
        Self {
            server_port_index: 0,
            client_pid: 0,
            client_tid: 0,
            message: ConnectionMessage::empty(),
            pending: false,
            client_port_index: 0,
            server_comm_port_index: 0,
        }
    }
}

pub const MAX_CONNECTION_REQUESTS: usize = 16;

pub struct ConnectionQueue {
    pub requests: [ConnectionRequest; MAX_CONNECTION_REQUESTS],
    pub count: u32,
}

impl ConnectionQueue {
    pub const fn new() -> Self {
        Self {
            requests: [const { ConnectionRequest::empty() }; MAX_CONNECTION_REQUESTS],
            count: 0,
        }
    }
}

static ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
static REJECT_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn send_connection_request(
    server_port_index: u32,
    client_pid: u64,
    client_tid: u64,
    client_data: &[u8],
    queue: &mut ConnectionQueue,
) -> Option<u32> {
    if (queue.count as usize) >= MAX_CONNECTION_REQUESTS {
        return None;
    }

    for i in 0..queue.requests.len() {
        if !queue.requests[i].pending {
            let req = &mut queue.requests[i];
            req.server_port_index = server_port_index;
            req.client_pid = client_pid;
            req.client_tid = client_tid;

            let copy_len = core::cmp::min(client_data.len(), 128);
            req.message.client_data[..copy_len].copy_from_slice(&client_data[..copy_len]);
            req.message.client_data_len = copy_len as u32;

            req.pending = true;
            queue.count = queue.count + 1;
            return Some(i as u32);
        }
    }

    None
}

pub fn accept_connection_request(
    request_id: u32,
    server_data: &[u8],
    queue: &mut ConnectionQueue,
    reg: &mut LpcRegistry,
) -> Option<(u32, u32)> {
    if (request_id as usize) >= queue.requests.len() {
        return None;
    }

    let req = &mut queue.requests[request_id as usize];
    if !req.pending {
        return None;
    }

    let copy_len = core::cmp::min(server_data.len(), 128);
    req.message.server_data[..copy_len].copy_from_slice(&server_data[..copy_len]);
    req.message.server_data_len = copy_len as u32;

    let server_port_index = req.server_port_index;
    let client_pid = req.client_pid;

    let mut server_comm_idx: u32 = 0;
    let client_idx = super::connect_port(server_port_index, client_pid, &mut server_comm_idx)?;

    req.client_port_index = client_idx;
    req.server_comm_port_index = server_comm_idx;
    req.pending = false;
    queue.count = queue.count.saturating_sub(1);

    ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);

    Some((client_idx, server_comm_idx))
}

pub fn reject_connection_request(
    request_id: u32,
    queue: &mut ConnectionQueue,
) -> bool {
    if (request_id as usize) >= queue.requests.len() {
        return false;
    }

    let req = &mut queue.requests[request_id as usize];
    if !req.pending {
        return false;
    }

    req.pending = false;
    queue.count = queue.count.saturating_sub(1);

    REJECT_COUNT.fetch_add(1, Ordering::Relaxed);

    true
}

pub fn get_next_connection_request(
    server_port_index: u32,
    queue: &ConnectionQueue,
) -> Option<u32> {
    for i in 0..queue.requests.len() {
        if queue.requests[i].pending && queue.requests[i].server_port_index == server_port_index {
            return Some(i as u32);
        }
    }
    None
}

pub fn connection_stats() -> (u64, u64) {
    (
        ACCEPT_COUNT.load(Ordering::Relaxed),
        REJECT_COUNT.load(Ordering::Relaxed),
    )
}
