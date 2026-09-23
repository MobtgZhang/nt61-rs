//! ALPC API - High-level interface
//!
//! This module provides the NT kernel API surface for ALPC operations.
//! These functions correspond to the NtAlpc* syscalls in Windows 7.

use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

use super::*;

pub struct AlpcSubsystem {
    pub registry: *mut LpcRegistry,
    pub callbacks: CallbackRegistry,
    pub sections: SectionRegistry,
    pub wait_queue: WaitQueue,
    pub connection_queue: ConnectionQueue,
    pub async_queue: AsyncQueue,
    pub direct_buffers: DirectBufferRegistry,
}

impl AlpcSubsystem {
    pub const fn new() -> Self {
        Self {
            registry: null_mut(),
            callbacks: CallbackRegistry::new(),
            sections: SectionRegistry::new(),
            wait_queue: WaitQueue::new(),
            connection_queue: ConnectionQueue::new(),
            async_queue: AsyncQueue::new(),
            direct_buffers: DirectBufferRegistry::new(),
        }
    }
}

static ALPC_SUBSYSTEM: Spinlock<AlpcSubsystem> = Spinlock::new(AlpcSubsystem::new());

pub fn init_alpc_subsystem() {
    let mut subsys = ALPC_SUBSYSTEM.lock();

    let reg_guard = super::REGISTRY.lock();
    subsys.registry = *reg_guard;
    drop(reg_guard);
}

pub fn nt_alpc_create_port(
    name: &[u16],
    owner_pid: u64,
    attrs: &PortAttributes,
) -> Result<u32, u32> {
    let reg_guard = super::lock_registry();
    if reg_guard.is_none() {
        return Err(0xC0000001); // STATUS_UNSUCCESSFUL
    }

    let guard = reg_guard.unwrap();
    match port::create_port_ex(name, owner_pid, attrs, guard.reg) {
        Some(idx) => Ok(idx),
        None => Err(0xC000009A), // STATUS_INSUFFICIENT_RESOURCES
    }
}

pub fn nt_alpc_connect_port(
    port_name: &[u16],
    client_pid: u64,
    connection_data: &[u8],
) -> Result<(u32, u32), u32> {
    let server_idx = match super::find_port_by_name(port_name) {
        Some(idx) => idx,
        None => return Err(0xC0000034), // STATUS_OBJECT_NAME_NOT_FOUND
    };

    let mut subsys = ALPC_SUBSYSTEM.lock();
    let req_id = match connection::send_connection_request(
        server_idx,
        client_pid,
        0, // thread_id
        connection_data,
        &mut subsys.connection_queue,
    ) {
        Some(id) => id,
        None => return Err(0xC000009A), // STATUS_INSUFFICIENT_RESOURCES
    };

    drop(subsys);

    Ok((server_idx, req_id))
}

pub fn nt_alpc_accept_connect_port(
    request_id: u32,
    server_data: &[u8],
) -> Result<(u32, u32), u32> {
    let mut subsys = ALPC_SUBSYSTEM.lock();
    let reg_guard = super::lock_registry();
    if reg_guard.is_none() {
        return Err(0xC0000001);
    }

    let guard = reg_guard.unwrap();
    match connection::accept_connection_request(
        request_id,
        server_data,
        &mut subsys.connection_queue,
        guard.reg,
    ) {
        Some((client_idx, server_comm_idx)) => Ok((client_idx, server_comm_idx)),
        None => Err(0xC0000001),
    }
}

pub fn nt_alpc_send_wait_receive_port(
    port_index: u32,
    send_message: Option<&LpcMessage>,
    receive_buffer: &mut Option<LpcMessage>,
    wait_for_reply: bool,
) -> Result<usize, u32> {
    let mut bytes_sent = 0;

    if let Some(msg) = send_message {
        match super::send(port_index, msg) {
            Some(n) => bytes_sent = n,
            None => return Err(0xC0000001),
        }
    }

    if wait_for_reply || send_message.is_none() {
        match super::receive(port_index) {
            Some(msg) => {
                *receive_buffer = Some(msg);
            }
            None => {
                return Err(0x00000102); // STATUS_TIMEOUT
            }
        }
    }

    Ok(bytes_sent)
}

pub fn nt_alpc_disconnect_port(port_index: u32) -> Result<(), u32> {
    let reg_guard = super::lock_registry();
    if reg_guard.is_none() {
        return Err(0xC0000001);
    }

    let guard = reg_guard.unwrap();
    if port::close_port(port_index, guard.reg) {
        Ok(())
    } else {
        Err(0xC0000008) // STATUS_INVALID_HANDLE
    }
}

pub fn nt_alpc_create_section(
    size: u64,
    flags: u32,
    owner_pid: u64,
) -> Result<u64, u32> {
    let mut subsys = ALPC_SUBSYSTEM.lock();
    match section::create_section(size, flags, owner_pid, &mut subsys.sections) {
        Some(handle) => Ok(handle),
        None => Err(0xC000009A),
    }
}

pub fn nt_alpc_map_section(
    section_handle: u64,
    view_size: u64,
    offset: u64,
    flags: u32,
) -> Result<AlpcSectionView, u32> {
    let subsys = ALPC_SUBSYSTEM.lock();
    match section::map_section_view(section_handle, view_size, offset, flags, &subsys.sections) {
        Some(view) => Ok(view),
        None => Err(0xC0000001),
    }
}

pub fn get_alpc_stats() -> AlpcStats {
    let (wait_count, wake_count) = waitqueue::wait_stats();
    let (accept_count, reject_count) = connection::connection_stats();
    let (direct_send, direct_recv) = direct::direct_stats();

    AlpcStats {
        total_ports: super::port_count(),
        total_connections: super::connect_count(),
        total_messages_sent: super::send_count(),
        total_messages_received: super::recv_count(),
        callback_invocations: callback::callback_invocations(),
        wait_operations: wait_count,
        wake_operations: wake_count,
        connections_accepted: accept_count,
        connections_rejected: reject_count,
        async_completions: async_ops::async_completion_count(),
        direct_sends: direct_send,
        direct_receives: direct_recv,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AlpcStats {
    pub total_ports: u32,
    pub total_connections: u64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub callback_invocations: u64,
    pub wait_operations: u32,
    pub wake_operations: u32,
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub async_completions: u64,
    pub direct_sends: u64,
    pub direct_receives: u64,
}
