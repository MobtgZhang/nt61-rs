//! RPC types and structures
//!
//! Core RPC data types used throughout the runtime.

use core::ptr::null_mut;

pub type RpcStatus = u32;

pub const RPC_S_OK: RpcStatus = 0;
pub const RPC_S_INVALID_BINDING: RpcStatus = 0x6A6;
pub const RPC_S_WRONG_KIND_OF_BINDING: RpcStatus = 0x6A7;
pub const RPC_S_INVALID_STRING_BINDING: RpcStatus = 0x6A4;
pub const RPC_S_STRING_TOO_LONG: RpcStatus = 0x6B4;
pub const RPC_S_INVALID_STRING_UUID: RpcStatus = 0x6A8;
pub const RPC_S_PROTSEQ_NOT_SUPPORTED: RpcStatus = 0x6A7;
pub const RPC_S_OUT_OF_MEMORY: RpcStatus = 0x6BC;
pub const RPC_S_OUT_OF_RESOURCES: RpcStatus = 0x6B9;
pub const RPC_S_SERVER_UNAVAILABLE: RpcStatus = 0x6BA;
pub const RPC_S_SERVER_TOO_BUSY: RpcStatus = 0x6BB;
pub const RPC_S_INVALID_NETWORK_OPTIONS: RpcStatus = 0x6AC;
pub const RPC_S_NO_CALL_ACTIVE: RpcStatus = 0x6BD;
pub const RPC_S_CALL_FAILED: RpcStatus = 0x6BE;
pub const RPC_S_CALL_FAILED_DNE: RpcStatus = 0x6BF;
pub const RPC_S_PROTOCOL_ERROR: RpcStatus = 0x6C0;
pub const RPC_S_UNSUPPORTED_TYPE: RpcStatus = 0x6C2;
pub const RPC_S_INVALID_TAG: RpcStatus = 0x6C5;
pub const RPC_S_INVALID_BOUND: RpcStatus = 0x6C6;
pub const RPC_S_NO_ENTRY_NAME: RpcStatus = 0x6C7;
pub const RPC_S_INVALID_NAME_SYNTAX: RpcStatus = 0x6C8;
pub const RPC_S_UNSUPPORTED_NAME_SYNTAX: RpcStatus = 0x6C9;
pub const RPC_S_UUID_NO_ADDRESS: RpcStatus = 0x6CB;
pub const RPC_S_DUPLICATE_ENDPOINT: RpcStatus = 0x6CC;
pub const RPC_S_UNKNOWN_AUTHN_TYPE: RpcStatus = 0x6CD;
pub const RPC_S_MAX_CALLS_TOO_SMALL: RpcStatus = 0x6CE;
pub const RPC_S_STRING_TOO_SHORT: RpcStatus = 0x6CF;
pub const RPC_S_PROTSEQ_NOT_FOUND: RpcStatus = 0x6D0;
pub const RPC_S_PROCNUM_OUT_OF_RANGE: RpcStatus = 0x6D1;
pub const RPC_S_BINDING_HAS_NO_AUTH: RpcStatus = 0x6D2;
pub const RPC_S_UNKNOWN_AUTHN_SERVICE: RpcStatus = 0x6D3;
pub const RPC_S_UNKNOWN_AUTHN_LEVEL: RpcStatus = 0x6D4;
pub const RPC_S_INVALID_AUTH_IDENTITY: RpcStatus = 0x6D5;
pub const RPC_S_UNKNOWN_AUTHZ_SERVICE: RpcStatus = 0x6D6;
pub const RPC_S_NOTHING_TO_EXPORT: RpcStatus = 0x6DA;
pub const RPC_S_INCOMPLETE_NAME: RpcStatus = 0x6DB;
pub const RPC_S_INVALID_VERS_OPTION: RpcStatus = 0x6DC;
pub const RPC_S_NO_MORE_MEMBERS: RpcStatus = 0x6DD;
pub const RPC_S_NOT_ALL_OBJS_UNEXPORTED: RpcStatus = 0x6DE;
pub const RPC_S_INTERFACE_NOT_FOUND: RpcStatus = 0x6DF;
pub const RPC_S_ENTRY_ALREADY_EXISTS: RpcStatus = 0x6E0;
pub const RPC_S_ENTRY_NOT_FOUND: RpcStatus = 0x6E1;
pub const RPC_S_NAME_SERVICE_UNAVAILABLE: RpcStatus = 0x6E2;
pub const RPC_S_INVALID_NAF_ID: RpcStatus = 0x6E3;
pub const RPC_S_CANNOT_SUPPORT: RpcStatus = 0x6E4;
pub const RPC_S_NO_CONTEXT_AVAILABLE: RpcStatus = 0x6E5;
pub const RPC_S_INTERNAL_ERROR: RpcStatus = 0x6E6;
pub const RPC_S_ZERO_DIVIDE: RpcStatus = 0x6E7;
pub const RPC_S_ADDRESS_ERROR: RpcStatus = 0x6E8;
pub const RPC_S_FP_DIV_ZERO: RpcStatus = 0x6E9;
pub const RPC_S_FP_UNDERFLOW: RpcStatus = 0x6EA;
pub const RPC_S_FP_OVERFLOW: RpcStatus = 0x6EB;
pub const RPC_S_ALREADY_LISTENING: RpcStatus = 0x6F3;
pub const RPC_S_NO_PROTSEQS_REGISTERED: RpcStatus = 0x6F4;
pub const RPC_S_NOT_LISTENING: RpcStatus = 0x6F5;
pub const RPC_S_UNKNOWN_MGR_TYPE: RpcStatus = 0x6F6;
pub const RPC_S_UNKNOWN_IF: RpcStatus = 0x6F7;
pub const RPC_S_NO_BINDINGS: RpcStatus = 0x6F8;
pub const RPC_S_NO_PROTSEQS: RpcStatus = 0x6F9;
pub const RPC_S_CANT_CREATE_ENDPOINT: RpcStatus = 0x6FA;
pub const RPC_S_OUT_OF_THREADS: RpcStatus = 0x6FB;
pub const RPC_S_INVALID_TIMEOUT: RpcStatus = 0x6FD;

pub type RpcBindingHandle = *mut core::ffi::c_void;

pub type RpcIfHandle = *mut core::ffi::c_void;

pub const RPC_C_AUTHN_LEVEL_DEFAULT: u32 = 0;
pub const RPC_C_AUTHN_LEVEL_NONE: u32 = 1;
pub const RPC_C_AUTHN_LEVEL_CONNECT: u32 = 2;
pub const RPC_C_AUTHN_LEVEL_CALL: u32 = 3;
pub const RPC_C_AUTHN_LEVEL_PKT: u32 = 4;
pub const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: u32 = 5;
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;

pub const RPC_C_AUTHN_NONE: u32 = 0;
pub const RPC_C_AUTHN_DCE_PRIVATE: u32 = 1;
pub const RPC_C_AUTHN_DCE_PUBLIC: u32 = 2;
pub const RPC_C_AUTHN_DEC_PUBLIC: u32 = 4;
pub const RPC_C_AUTHN_WINNT: u32 = 10;
pub const RPC_C_AUTHN_GSS_NEGOTIATE: u32 = 9;
pub const RPC_C_AUTHN_GSS_KERBEROS: u32 = 16;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFFFFFF;

pub const RPC_C_AUTHZ_NONE: u32 = 0;
pub const RPC_C_AUTHZ_NAME: u32 = 1;
pub const RPC_C_AUTHZ_DCE: u32 = 2;
pub const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFFFFFF;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const PROTSEQ_NCALRPC: &[u16] = &[
    b'n' as u16,
    b'c' as u16,
    b'a' as u16,
    b'l' as u16,
    b'r' as u16,
    b'p' as u16,
    b'c' as u16,
    0,
];
pub const PROTSEQ_NCACN_NP: &[u16] = &[
    b'n' as u16,
    b'c' as u16,
    b'a' as u16,
    b'c' as u16,
    b'n' as u16,
    b'_' as u16,
    b'n' as u16,
    b'p' as u16,
    0,
];
pub const PROTSEQ_NCACN_IP_TCP: &[u16] = &[
    b'n' as u16,
    b'c' as u16,
    b'a' as u16,
    b'c' as u16,
    b'n' as u16,
    b'_' as u16,
    b'i' as u16,
    b'p' as u16,
    b'_' as u16,
    b't' as u16,
    b'c' as u16,
    b'p' as u16,
    0,
];

#[repr(C)]
pub struct RPC_PROTSEQ_VECTOR {
    pub count: u32,
    pub protseq: [*mut u16; 1],
}

#[repr(C)]
pub struct RPC_BINDING_VECTOR {
    pub count: u32,
    pub binding_h: [RpcBindingHandle; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RPC_IF_ID {
    pub uuid: UUID,
    pub vers_major: u16,
    pub vers_minor: u16,
}

#[repr(C)]
pub struct RpcBindingInternal {
    pub protseq: [u16; 16],
    pub network_addr: [u16; 128],
    pub endpoint: [u16; 64],
    pub options: [u16; 64],
    pub object_uuid: UUID,
    pub lpc_port_index: u32,
    pub auth_level: u32,
    pub auth_svc: u32,
    pub auth_identity: *mut core::ffi::c_void,
    pub authz_svc: u32,
    pub ref_count: u32,
}

impl RpcBindingInternal {
    pub const fn new() -> Self {
        Self {
            protseq: [0u16; 16],
            network_addr: [0u16; 128],
            endpoint: [0u16; 64],
            options: [0u16; 64],
            object_uuid: UUID {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            lpc_port_index: 0,
            auth_level: RPC_C_AUTHN_LEVEL_NONE,
            auth_svc: RPC_C_AUTHN_NONE,
            auth_identity: null_mut(),
            authz_svc: RPC_C_AUTHZ_NONE,
            ref_count: 1,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RpcServerInterface {
    pub if_spec: RpcIfHandle,
    pub mgr_type_uuid: UUID,
    pub mgr_epv: *mut core::ffi::c_void,
    pub flags: u32,
    pub max_calls: u32,
    pub max_rpc_size: u32,
    pub if_callback: *mut core::ffi::c_void,
    pub registered: bool,
}

impl RpcServerInterface {
    pub const fn new() -> Self {
        Self {
            if_spec: null_mut(),
            mgr_type_uuid: UUID {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            mgr_epv: null_mut(),
            flags: 0,
            max_calls: 0,
            max_rpc_size: 0,
            if_callback: null_mut(),
            registered: false,
        }
    }
}

pub const MAX_SERVER_INTERFACES: usize = 32;

pub const MAX_PROTSEQS: usize = 8;

pub const MAX_BINDINGS: usize = 64;
