//! RPC security and authentication
//!
//! Implements authentication, authorization, and impersonation operations.

use super::types::*;
use core::ptr::null_mut;

static mut CURRENT_IMPERSONATION_CONTEXT: *mut core::ffi::c_void = null_mut();

#[no_mangle]
pub unsafe extern "C" fn RpcBindingSetAuthInfoW(
    binding: RpcBindingHandle,
    server_princ_name: *const u16,
    authn_level: u32,
    authn_svc: u32,
    auth_identity: *mut core::ffi::c_void,
    authz_svc: u32,
) -> RpcStatus {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    match authn_level {
        RPC_C_AUTHN_LEVEL_DEFAULT
        | RPC_C_AUTHN_LEVEL_NONE
        | RPC_C_AUTHN_LEVEL_CONNECT
        | RPC_C_AUTHN_LEVEL_CALL
        | RPC_C_AUTHN_LEVEL_PKT
        | RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
        | RPC_C_AUTHN_LEVEL_PKT_PRIVACY => {}
        _ => return RPC_S_UNKNOWN_AUTHN_LEVEL,
    }

    match authn_svc {
        RPC_C_AUTHN_NONE
        | RPC_C_AUTHN_DCE_PRIVATE
        | RPC_C_AUTHN_DCE_PUBLIC
        | RPC_C_AUTHN_DEC_PUBLIC
        | RPC_C_AUTHN_WINNT
        | RPC_C_AUTHN_GSS_NEGOTIATE
        | RPC_C_AUTHN_GSS_KERBEROS
        | RPC_C_AUTHN_DEFAULT => {}
        _ => return RPC_S_UNKNOWN_AUTHN_SERVICE,
    }

    match authz_svc {
        RPC_C_AUTHZ_NONE | RPC_C_AUTHZ_NAME | RPC_C_AUTHZ_DCE | RPC_C_AUTHZ_DEFAULT => {}
        _ => return RPC_S_UNKNOWN_AUTHZ_SERVICE,
    }

    (*bind_internal).auth_level = authn_level;
    (*bind_internal).auth_svc = authn_svc;
    (*bind_internal).auth_identity = auth_identity;
    (*bind_internal).authz_svc = authz_svc;

    // Server principal name is stored but not used in this implementation
    let _ = server_princ_name;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingSetAuthInfoExW(
    binding: RpcBindingHandle,
    server_princ_name: *const u16,
    authn_level: u32,
    authn_svc: u32,
    auth_identity: *mut core::ffi::c_void,
    authz_svc: u32,
    security_qos: *mut core::ffi::c_void,
) -> RpcStatus {
    let _ = security_qos;

    RpcBindingSetAuthInfoW(
        binding,
        server_princ_name,
        authn_level,
        authn_svc,
        auth_identity,
        authz_svc,
    )
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqAuthInfoW(
    binding: RpcBindingHandle,
    server_princ_name: *mut *mut u16,
    authn_level: *mut u32,
    authn_svc: *mut u32,
    auth_identity: *mut *mut core::ffi::c_void,
    authz_svc: *mut u32,
) -> RpcStatus {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    if !authn_level.is_null() {
        *authn_level = (*bind_internal).auth_level;
    }

    if !authn_svc.is_null() {
        *authn_svc = (*bind_internal).auth_svc;
    }

    if !auth_identity.is_null() {
        *auth_identity = (*bind_internal).auth_identity;
    }

    if !authz_svc.is_null() {
        *authz_svc = (*bind_internal).authz_svc;
    }

    if !server_princ_name.is_null() {
        let buffer = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, 2) as *mut u16;

        if buffer.is_null() {
            return RPC_S_OUT_OF_MEMORY;
        }

        *buffer = 0;
        *server_princ_name = buffer;
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqAuthInfoExW(
    binding: RpcBindingHandle,
    server_princ_name: *mut *mut u16,
    authn_level: *mut u32,
    authn_svc: *mut u32,
    auth_identity: *mut *mut core::ffi::c_void,
    authz_svc: *mut u32,
    rpc_qos_version: u32,
    security_qos: *mut core::ffi::c_void,
) -> RpcStatus {
    let _ = rpc_qos_version;
    let _ = security_qos;

    RpcBindingInqAuthInfoW(
        binding,
        server_princ_name,
        authn_level,
        authn_svc,
        auth_identity,
        authz_svc,
    )
}

#[no_mangle]
pub unsafe extern "C" fn RpcImpersonateClient(binding_handle: RpcBindingHandle) -> RpcStatus {
    if !binding_handle.is_null() {
        CURRENT_IMPERSONATION_CONTEXT = binding_handle as *mut core::ffi::c_void;
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcRevertToSelf() -> RpcStatus {
    CURRENT_IMPERSONATION_CONTEXT = null_mut();
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcRevertToSelfEx(binding_handle: RpcBindingHandle) -> RpcStatus {
    if !binding_handle.is_null() {
        if CURRENT_IMPERSONATION_CONTEXT == binding_handle as *mut core::ffi::c_void {
            CURRENT_IMPERSONATION_CONTEXT = null_mut();
        }
    }
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqAuthClientW(
    client_binding: RpcBindingHandle,
    privs: *mut *mut core::ffi::c_void,
    server_princ_name: *mut *mut u16,
    authn_level: *mut u32,
    authn_svc: *mut u32,
    authz_svc: *mut u32,
) -> RpcStatus {
    if client_binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = client_binding as *mut RpcBindingInternal;

    if !authn_level.is_null() {
        *authn_level = (*bind_internal).auth_level;
    }

    if !authn_svc.is_null() {
        *authn_svc = (*bind_internal).auth_svc;
    }

    if !authz_svc.is_null() {
        *authz_svc = (*bind_internal).authz_svc;
    }

    if !privs.is_null() {
        *privs = (*bind_internal).auth_identity;
    }

    if !server_princ_name.is_null() {
        let buffer = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, 2) as *mut u16;

        if buffer.is_null() {
            return RPC_S_OUT_OF_MEMORY;
        }

        *buffer = 0;
        *server_princ_name = buffer;
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqAuthClientExW(
    client_binding: RpcBindingHandle,
    privs: *mut *mut core::ffi::c_void,
    server_princ_name: *mut *mut u16,
    authn_level: *mut u32,
    authn_svc: *mut u32,
    authz_svc: *mut u32,
    flags: u32,
) -> RpcStatus {
    let _ = flags; // flags ignored

    RpcBindingInqAuthClientW(
        client_binding,
        privs,
        server_princ_name,
        authn_level,
        authn_svc,
        authz_svc,
    )
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingSetOption(
    binding: RpcBindingHandle,
    option: u32,
    option_value: usize,
) -> RpcStatus {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = option;
    let _ = option_value;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqOption(
    binding: RpcBindingHandle,
    option: u32,
    option_value: *mut usize,
) -> RpcStatus {
    if binding.is_null() || option_value.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = option;
    *option_value = 0;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerRegisterAuthInfoW(
    server_princ_name: *const u16,
    authn_svc: u32,
    get_key_fn: *mut core::ffi::c_void,
    arg: *mut core::ffi::c_void,
) -> RpcStatus {
    match authn_svc {
        RPC_C_AUTHN_NONE
        | RPC_C_AUTHN_DCE_PRIVATE
        | RPC_C_AUTHN_DCE_PUBLIC
        | RPC_C_AUTHN_DEC_PUBLIC
        | RPC_C_AUTHN_WINNT
        | RPC_C_AUTHN_GSS_NEGOTIATE
        | RPC_C_AUTHN_GSS_KERBEROS
        | RPC_C_AUTHN_DEFAULT => {}
        _ => return RPC_S_UNKNOWN_AUTHN_SERVICE,
    }

    let _ = server_princ_name;
    let _ = get_key_fn;
    let _ = arg;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcServerInqDefaultPrincNameW(
    authn_svc: u32,
    princ_name: *mut *mut u16,
) -> RpcStatus {
    if princ_name.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = authn_svc;

    let buffer = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, 2) as *mut u16;

    if buffer.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    *buffer = 0;
    *princ_name = buffer;

    RPC_S_OK
}

pub type RpcIfCallbackFn = unsafe extern "C" fn(
    interface_uuid: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> RpcStatus;

#[no_mangle]
pub unsafe extern "C" fn RpcServerRegisterIfCallback(
    if_spec: RpcIfHandle,
    callback_fn: RpcIfCallbackFn,
) -> RpcStatus {
    if if_spec.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = callback_fn;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcGetAuthorizationContextForClient(
    client_binding: RpcBindingHandle,
    impersonation_on_return: i32,
    reserved1: *mut core::ffi::c_void,
    expiration_time: *mut i64,
    reserved2: *mut core::ffi::c_void,
    reserved3: u32,
    reserved4: *mut *mut core::ffi::c_void,
    authz_context_handle: *mut *mut core::ffi::c_void,
) -> RpcStatus {
    if client_binding.is_null() || authz_context_handle.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let _ = impersonation_on_return;
    let _ = reserved1;
    let _ = expiration_time;
    let _ = reserved2;
    let _ = reserved3;
    let _ = reserved4;

    *authz_context_handle = null_mut();

    RPC_S_CANNOT_SUPPORT
}
