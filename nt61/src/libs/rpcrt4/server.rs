//! RPC server operations
//!
//! Implements RPC server interface registration, protocol sequence handling,
//! and server listen loop.

use super::types::*;
use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

static SERVER_STATE: Spinlock<ServerState> = Spinlock::new(ServerState::new());

pub struct ServerState {
    interfaces: [RpcServerInterface; MAX_SERVER_INTERFACES],
    interface_count: usize,

    protseqs: [[u16; 16]; MAX_PROTSEQS],
    protseq_count: usize,

    is_listening: bool,

    max_calls: u32,

    lpc_ports: [u32; MAX_PROTSEQS],
}

impl ServerState {
    const fn new() -> Self {
        Self {
            interfaces: [const { RpcServerInterface::new() }; MAX_SERVER_INTERFACES],
            interface_count: 0,
            protseqs: [[0u16; 16]; MAX_PROTSEQS],
            protseq_count: 0,
            is_listening: false,
            max_calls: 0,
            lpc_ports: [0; MAX_PROTSEQS],
        }
    }
}

unsafe fn copy_wstr(dst: &mut [u16], src: *const u16) -> usize {
    let mut len = 0;
    while len < dst.len() - 1 {
        let c = *src.add(len);
        dst[len] = c;
        if c == 0 {
            break;
        }
        len += 1;
    }
    dst[len] = 0;
    len
}

unsafe fn compare_wstr(s1: &[u16], s2: *const u16) -> bool {
    let mut i = 0;
    while i < s1.len() {
        let c2 = *s2.add(i);
        if s1[i] != c2 {
            return false;
        }
        if s1[i] == 0 {
            return true;
        }
        i += 1;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerUseProtseqW(
    protseq: *const u16,
    max_calls: u32,
    security_descriptor: *mut core::ffi::c_void,
) -> RPC_STATUS {
    if protseq.is_null() {
        return RPC_S_INVALID_STRING_BINDING;
    }

    let mut state = SERVER_STATE.lock();

    for i in 0..state.protseq_count {
        if compare_wstr(&state.protseqs[i], protseq) {
            return RPC_S_DUPLICATE_ENDPOINT;
        }
    }

    if state.protseq_count >= MAX_PROTSEQS {
        return RPC_S_OUT_OF_RESOURCES;
    }

    let idx = state.protseq_count;
    copy_wstr(&mut state.protseqs[idx], protseq);
    state.protseq_count += 1;

    if max_calls > state.max_calls {
        state.max_calls = max_calls;
    }

    let _ = security_descriptor;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerUseProtseqEpW(
    protseq: *const u16,
    max_calls: u32,
    endpoint: *const u16,
    security_descriptor: *mut core::ffi::c_void,
) -> RPC_STATUS {
    let status = RpcServerUseProtseqW(protseq, max_calls, security_descriptor);
    if status != RPC_S_OK {
        return status;
    }

    if !endpoint.is_null() {
        let state = SERVER_STATE.lock();

        let ncalrpc = [
            b'n' as u16, b'c' as u16, b'a' as u16, b'l' as u16,
            b'r' as u16, b'p' as u16, b'c' as u16, 0,
        ];

        if compare_wstr(&ncalrpc, protseq) {
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

            let mut i = 0;
            while pos < 127 {
                let c = *endpoint.add(i);
                port_name[pos] = c;
                if c == 0 {
                    break;
                }
                pos += 1;
                i += 1;
            }
            port_name[pos] = 0;

            if let Some(port_idx) = crate::lpc::create_connection_port(&port_name[..pos], 0) {
                drop(state);
                let mut state = SERVER_STATE.lock();
                let idx = state.protseq_count - 1;
                state.lpc_ports[idx] = port_idx;
            }
        }
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerUseAllProtseqs(
    max_calls: u32,
    security_descriptor: *mut core::ffi::c_void,
) -> RPC_STATUS {
    let ncalrpc = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'l' as u16,
        b'r' as u16, b'p' as u16, b'c' as u16, 0,
    ];
    let ncacn_np = [
        b'n' as u16, b'c' as u16, b'a' as u16, b'c' as u16,
        b'n' as u16, b'_' as u16, b'n' as u16, b'p' as u16, 0,
    ];

    let mut status = RpcServerUseProtseqW(ncalrpc.as_ptr(), max_calls, security_descriptor);
    if status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT {
        return status;
    }

    status = RpcServerUseProtseqW(ncacn_np.as_ptr(), max_calls, security_descriptor);
    if status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT {
        return status;
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerUseAllProtseqsIf(
    max_calls: u32,
    if_spec: RPC_IF_HANDLE,
    security_descriptor: *mut core::ffi::c_void,
) -> RPC_STATUS {
    let _ = if_spec; // Interface spec not used in simple implementation
    RpcServerUseAllProtseqs(max_calls, security_descriptor)
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerRegisterIf(
    if_spec: RPC_IF_HANDLE,
    mgr_type_uuid: *const UUID,
    mgr_epv: *mut core::ffi::c_void,
) -> RPC_STATUS {
    if if_spec.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let mut state = SERVER_STATE.lock();

    for i in 0..state.interface_count {
        if state.interfaces[i].if_spec == if_spec {
            return RPC_S_ENTRY_ALREADY_EXISTS;
        }
    }

    if state.interface_count >= MAX_SERVER_INTERFACES {
        return RPC_S_OUT_OF_RESOURCES;
    }

    let idx = state.interface_count;
    state.interfaces[idx].if_spec = if_spec;

    if !mgr_type_uuid.is_null() {
        state.interfaces[idx].mgr_type_uuid = *mgr_type_uuid;
    }

    state.interfaces[idx].mgr_epv = mgr_epv;
    state.interfaces[idx].registered = true;
    state.interface_count += 1;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerRegisterIf2(
    if_spec: RPC_IF_HANDLE,
    mgr_type_uuid: *const UUID,
    mgr_epv: *mut core::ffi::c_void,
    flags: u32,
    max_calls: u32,
    max_rpc_size: u32,
    if_callback: *mut core::ffi::c_void,
) -> RPC_STATUS {
    if if_spec.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let mut state = SERVER_STATE.lock();

    for i in 0..state.interface_count {
        if state.interfaces[i].if_spec == if_spec {
            return RPC_S_ENTRY_ALREADY_EXISTS;
        }
    }

    if state.interface_count >= MAX_SERVER_INTERFACES {
        return RPC_S_OUT_OF_RESOURCES;
    }

    let idx = state.interface_count;
    state.interfaces[idx].if_spec = if_spec;

    if !mgr_type_uuid.is_null() {
        state.interfaces[idx].mgr_type_uuid = *mgr_type_uuid;
    }

    state.interfaces[idx].mgr_epv = mgr_epv;
    state.interfaces[idx].flags = flags;
    state.interfaces[idx].max_calls = max_calls;
    state.interfaces[idx].max_rpc_size = max_rpc_size;
    state.interfaces[idx].if_callback = if_callback;
    state.interfaces[idx].registered = true;
    state.interface_count += 1;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerUnregisterIf(
    if_spec: RPC_IF_HANDLE,
    mgr_type_uuid: *const UUID,
    wait_for_calls_to_complete: u32,
) -> RPC_STATUS {
    let mut state = SERVER_STATE.lock();

    let mut found = false;
    for i in 0..state.interface_count {
        if state.interfaces[i].if_spec == if_spec {
            if !mgr_type_uuid.is_null() {
                let mut uuid_match = true;
                let mgr_uuid = &state.interfaces[i].mgr_type_uuid;
                let search_uuid = *mgr_type_uuid;

                if mgr_uuid.data1 != search_uuid.data1
                    || mgr_uuid.data2 != search_uuid.data2
                    || mgr_uuid.data3 != search_uuid.data3
                    || mgr_uuid.data4 != search_uuid.data4
                {
                    uuid_match = false;
                }

                if !uuid_match {
                    continue;
                }
            }

            state.interfaces[i].registered = false;
            state.interfaces[i].if_spec = null_mut();
            found = true;

            for j in i..state.interface_count - 1 {
                state.interfaces[j] = state.interfaces[j + 1];
            }
            state.interface_count -= 1;
            break;
        }
    }

    if !found {
        return RPC_S_INTERFACE_NOT_FOUND;
    }

    if wait_for_calls_to_complete != 0 {
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerListen(
    min_call_threads: u32,
    max_calls: u32,
    dont_wait: u32,
) -> RPC_STATUS {
    let mut state = SERVER_STATE.lock();

    if state.is_listening {
        return RPC_S_ALREADY_LISTENING;
    }

    if state.protseq_count == 0 {
        return RPC_S_NO_PROTSEQS_REGISTERED;
    }

    if state.interface_count == 0 {
        return RPC_S_NOTHING_TO_EXPORT;
    }

    if max_calls > 0 {
        state.max_calls = max_calls;
    }

    state.is_listening = true;


    let _ = min_call_threads;
    let _ = dont_wait;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtStopServerListening(
    binding: RPC_BINDING_HANDLE,
) -> RPC_STATUS {
    let _ = binding; // Binding not used for local server

    let mut state = SERVER_STATE.lock();

    if !state.is_listening {
        return RPC_S_NOT_LISTENING;
    }

    state.is_listening = false;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtWaitServerListen() -> RPC_STATUS {
    let state = SERVER_STATE.lock();

    if state.is_listening {
        return RPC_S_OK;
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcMgmtIsServerListening(
    binding: RPC_BINDING_HANDLE,
) -> RPC_STATUS {
    let _ = binding; // Binding not used for local server

    let state = SERVER_STATE.lock();

    if state.is_listening {
        RPC_S_OK
    } else {
        RPC_S_NOT_LISTENING
    }
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerInqBindings(
    binding_vector: *mut *mut RPC_BINDING_VECTOR,
) -> RPC_STATUS {
    if binding_vector.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let state = SERVER_STATE.lock();

    if state.protseq_count == 0 {
        return RPC_S_NO_BINDINGS;
    }

    let size = core::mem::size_of::<RPC_BINDING_VECTOR>()
        + (state.protseq_count - 1) * core::mem::size_of::<RPC_BINDING_HANDLE>();

    let vector = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        size,
    ) as *mut RPC_BINDING_VECTOR;

    if vector.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    (*vector).count = state.protseq_count as u32;

    for i in 0..state.protseq_count {
        let bind_internal = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<RpcBindingInternal>(),
        ) as *mut RpcBindingInternal;

        if !bind_internal.is_null() {
            *bind_internal = RpcBindingInternal::new();

            for j in 0..16 {
                (*bind_internal).protseq[j] = state.protseqs[i][j];
                if state.protseqs[i][j] == 0 {
                    break;
                }
            }

            (*bind_internal).lpc_port_index = state.lpc_ports[i];

            let bindings_ptr = (*vector).binding_h.as_mut_ptr();
            *bindings_ptr.add(i) = bind_internal as RPC_BINDING_HANDLE;
        }
    }

    *binding_vector = vector;
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcEpRegister(
    if_spec: RPC_IF_HANDLE,
    binding_vector: *mut RPC_BINDING_VECTOR,
    uuid_vector: *mut core::ffi::c_void,
    annotation: *const u16,
) -> RPC_STATUS {
    if if_spec.is_null() || binding_vector.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = uuid_vector;
    let _ = annotation;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcEpUnregister(
    if_spec: RPC_IF_HANDLE,
    binding_vector: *mut RPC_BINDING_VECTOR,
    uuid_vector: *mut core::ffi::c_void,
) -> RPC_STATUS {
    if if_spec.is_null() || binding_vector.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = uuid_vector;

    RPC_S_OK
}
