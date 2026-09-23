//! RPC client operations
//!
//! Implements RPC client-side connection management and call operations.

use super::types::*;
use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

static CLIENT_STATE: Spinlock<ClientState> = Spinlock::new(ClientState::new());

pub struct ClientState {
    connections: [ClientConnection; MAX_BINDINGS],
    connection_count: usize,
}

#[derive(Clone, Copy)]
pub struct ClientConnection {
    pub binding: RPC_BINDING_HANDLE,
    pub lpc_client_port: u32,
    pub lpc_server_port: u32,
    pub connected: bool,
}

impl ClientConnection {
    const fn new() -> Self {
        Self {
            binding: null_mut(),
            lpc_client_port: 0,
            lpc_server_port: 0,
            connected: false,
        }
    }
}

impl ClientState {
    const fn new() -> Self {
        Self {
            connections: [ClientConnection::new(); MAX_BINDINGS],
            connection_count: 0,
        }
    }

    fn find_connection(&self, binding: RPC_BINDING_HANDLE) -> Option<usize> {
        for i in 0..self.connection_count {
            if self.connections[i].binding == binding {
                return Some(i);
            }
        }
        None
    }

    fn add_connection(&mut self, binding: RPC_BINDING_HANDLE) -> Option<usize> {
        if self.connection_count >= MAX_BINDINGS {
            return None;
        }

        let idx = self.connection_count;
        self.connections[idx].binding = binding;
        self.connections[idx].connected = false;
        self.connection_count += 1;
        Some(idx)
    }

    fn remove_connection(&mut self, binding: RPC_BINDING_HANDLE) {
        if let Some(idx) = self.find_connection(binding) {
            for i in idx..self.connection_count - 1 {
                self.connections[i] = self.connections[i + 1];
            }
            self.connection_count -= 1;
        }
    }
}

unsafe fn wstrcmp(s1: *const u16, s2: *const u16) -> bool {
    let mut i = 0;
    loop {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);
        if c1 != c2 {
            return false;
        }
        if c1 == 0 {
            return true;
        }
        i += 1;
    }
}

unsafe fn wstrlen(s: *const u16) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

unsafe fn establish_connection(binding: RPC_BINDING_HANDLE) -> RPC_STATUS {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    let mut state = CLIENT_STATE.lock();
    if let Some(idx) = state.find_connection(binding) {
        if state.connections[idx].connected {
            return RPC_S_OK;
        }
    } else {
        if state.add_connection(binding).is_none() {
            return RPC_S_OUT_OF_RESOURCES;
        }
    }

    let conn_idx = state.find_connection(binding).unwrap();

    let ncalrpc = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'l' as u16,
        b'r' as u16, b'p' as u16, b'c' as u16, 0,
    ];

    if !wstrcmp((*bind_internal).protseq.as_ptr(), ncalrpc.as_ptr()) {
        return RPC_S_PROTSEQ_NOT_SUPPORTED;
    }

    let mut port_name = [0u16; 128];
    let mut pos = 0;

    let prefix = [
        b'\\' as u16, b'R' as u16, b'P' as u16, b'C' as u16,
        b' ' as u16, b'C' as u16, b'o' as u16, b'n' as u16,
        b't' as u16, b'r' as u16, b'o' as u16, b'l' as u16,
        b'\\' as u16,
    ];

    for &c in &prefix {
        port_name[pos] = c;
        pos += 1;
    }

    let endpoint_ptr = (*bind_internal).endpoint.as_ptr();
    let endpoint_len = wstrlen(endpoint_ptr);

    if endpoint_len == 0 {
        return RPC_S_INVALID_BINDING;
    }

    for i in 0..endpoint_len {
        if pos >= 127 {
            break;
        }
        port_name[pos] = *endpoint_ptr.add(i);
        pos += 1;
    }
    port_name[pos] = 0;

    let server_port_idx = match crate::lpc::find_port_by_name(&port_name[..pos]) {
        Some(idx) => idx,
        None => return RPC_S_SERVER_UNAVAILABLE,
    };

    let mut server_comm_port: u32 = 0;
    let client_port_idx = match crate::lpc::connect_port(
        server_port_idx,
        0, // owner_pid (kernel mode)
        &mut server_comm_port,
    ) {
        Some(idx) => idx,
        None => return RPC_S_SERVER_TOO_BUSY,
    };

    state.connections[conn_idx].lpc_client_port = client_port_idx;
    state.connections[conn_idx].lpc_server_port = server_comm_port;
    state.connections[conn_idx].connected = true;

    (*bind_internal).lpc_port_index = client_port_idx;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcClientCall(
    binding: RPC_BINDING_HANDLE,
    opnum: u32,
    in_buffer: *const u8,
    in_size: u32,
    out_buffer: *mut u8,
    out_size: *mut u32,
) -> RPC_STATUS {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let status = establish_connection(binding);
    if status != RPC_S_OK {
        return status;
    }

    let bind_internal = binding as *mut RpcBindingInternal;
    let lpc_port = (*bind_internal).lpc_port_index;

    if lpc_port == 0 {
        return RPC_S_INVALID_BINDING;
    }

    let mut msg = crate::lpc::LpcMessage::empty();

    if in_size > 252 {
        return RPC_S_STRING_TOO_LONG;
    }

    msg.data[0] = (opnum & 0xFF) as u8;
    msg.data[1] = ((opnum >> 8) & 0xFF) as u8;
    msg.data[2] = ((opnum >> 16) & 0xFF) as u8;
    msg.data[3] = ((opnum >> 24) & 0xFF) as u8;

    if !in_buffer.is_null() && in_size > 0 {
        for i in 0..in_size as usize {
            msg.data[4 + i] = *in_buffer.add(i);
        }
    }

    msg.data_len = 4 + in_size;

    msg.header = crate::lpc::LpcMessageHeader::new(
        crate::lpc::LpcMessageType::Data,
        msg.data_len,
        0, // sender_pid
        0, // sender_tid
    );

    if crate::lpc::send(lpc_port, &msg).is_none() {
        return RPC_S_CALL_FAILED;
    }

    if let Some(reply) = crate::lpc::receive(lpc_port) {
        if !out_buffer.is_null() && !out_size.is_null() {
            let reply_len = reply.data_len.min(*out_size);
            for i in 0..reply_len as usize {
                *out_buffer.add(i) = reply.data[i];
            }
            *out_size = reply_len;
        }
        return RPC_S_OK;
    }

    RPC_S_CALL_FAILED
}

/// (Client code should use the server.rs implementation directly)

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtSetServerStackSize(
    thread_stack_size: u32,
) -> RPC_STATUS {
    let _ = thread_stack_size;
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtEnableIdleCleanup() -> RPC_STATUS {
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtSetComTimeout(
    binding: RPC_BINDING_HANDLE,
    timeout: u32,
) -> RPC_STATUS {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = timeout;
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtInqServerPrincName(
    binding: RPC_BINDING_HANDLE,
    authn_svc: u32,
    server_princ_name: *mut *mut u16,
) -> RPC_STATUS {
    if binding.is_null() || server_princ_name.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = authn_svc;

    let buffer = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        2, // Just null terminator
    ) as *mut u16;

    if buffer.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    *buffer = 0;
    *server_princ_name = buffer;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcAsyncCancelCall(
    async_handle: *mut core::ffi::c_void,
    do_not_wait: i32,
) -> RPC_STATUS {
    if async_handle.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = do_not_wait;

    RPC_S_CANNOT_SUPPORT
}

#[no_mangle]
pub unsafe extern "C" fn RpcAsyncGetCallStatus(
    async_handle: *mut core::ffi::c_void,
) -> RPC_STATUS {
    if async_handle.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    RPC_S_ASYNC_CALL_PENDING
}

#[no_mangle]
pub unsafe extern "C" fn RpcNetworkIsProtseqValidW(
    protseq: *const u16,
) -> RPC_STATUS {
    if protseq.is_null() {
        return RPC_S_INVALID_STRING_BINDING;
    }

    let ncalrpc = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'l' as u16,
        b'r' as u16, b'p' as u16, b'c' as u16, 0,
    ];
    let ncacn_np = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'c' as u16,
        b'n' as u16, b'_' as u16, b'n' as u16, b'p' as u16, 0,
    ];
    let ncacn_ip_tcp = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'c' as u16,
        b'n' as u16, b'_' as u16, b'i' as u16, b'p' as u16,
        b'_' as u16, b't' as u16, b'c' as u16, b'p' as u16, 0,
    ];

    if wstrcmp(protseq, ncalrpc.as_ptr()) {
        return RPC_S_OK;
    }
    if wstrcmp(protseq, ncacn_np.as_ptr()) {
        return RPC_S_OK;
    }
    if wstrcmp(protseq, ncacn_ip_tcp.as_ptr()) {
        return RPC_S_OK;
    }

    RPC_S_PROTSEQ_NOT_SUPPORTED
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtInqDefaultProtectLevel(
    authn_svc: u32,
    protect_level: *mut u32,
) -> RPC_STATUS {
    if protect_level.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = authn_svc;

    *protect_level = RPC_C_AUTHN_LEVEL_CONNECT;

    RPC_S_OK
}

const RPC_S_ASYNC_CALL_PENDING: RPC_STATUS = 0x3E5;
