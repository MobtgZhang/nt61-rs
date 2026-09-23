//! RPC binding handle management
//!
//! Implements binding handle creation, manipulation, and destruction.

use super::types::*;
use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

static BINDING_REGISTRY: Spinlock<BindingRegistry> = Spinlock::new(BindingRegistry::new());

pub struct BindingRegistry {
    bindings: [Option<*mut RpcBindingInternal>; MAX_BINDINGS],
    count: usize,
}

impl BindingRegistry {
    const fn new() -> Self {
        Self {
            bindings: [None; MAX_BINDINGS],
            count: 0,
        }
    }

    fn allocate_binding(&mut self) -> Option<usize> {
        if self.count >= MAX_BINDINGS {
            return None;
        }

        for i in 0..MAX_BINDINGS {
            if self.bindings[i].is_none() {
                return Some(i);
            }
        }
        None
    }

    fn add_binding(&mut self, binding: *mut RpcBindingInternal) -> Option<usize> {
        let idx = self.allocate_binding()?;
        self.bindings[idx] = Some(binding);
        self.count += 1;
        Some(idx)
    }

    fn remove_binding(&mut self, binding: *mut RpcBindingInternal) -> bool {
        for i in 0..MAX_BINDINGS {
            if let Some(b) = self.bindings[i] {
                if b == binding {
                    self.bindings[i] = None;
                    self.count -= 1;
                    return true;
                }
            }
        }
        false
    }

    fn find_binding(&self, binding: *mut RpcBindingInternal) -> bool {
        for i in 0..MAX_BINDINGS {
            if let Some(b) = self.bindings[i] {
                if b == binding {
                    return true;
                }
            }
        }
        false
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

unsafe fn wstrcpy(dst: *mut u16, src: *const u16, max_len: usize) -> usize {
    let mut len = 0;
    while len < max_len - 1 {
        let c = *src.add(len);
        *dst.add(len) = c;
        if c == 0 {
            break;
        }
        len += 1;
    }
    *dst.add(len) = 0;
    len
}

unsafe fn wstrlen(s: *const u16) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn RpcStringBindingComposeW(
    obj_uuid: *const u16,
    protseq: *const u16,
    network_addr: *const u16,
    endpoint: *const u16,
    options: *const u16,
    string_binding: *mut *mut u16,
) -> RPC_STATUS {
    if string_binding.is_null() {
        return RPC_S_INVALID_STRING_BINDING;
    }

    let mut total_len = 0usize;

    if !obj_uuid.is_null() {
        total_len += wstrlen(obj_uuid) + 1; // +1 for '@'
    }
    if !protseq.is_null() {
        total_len += wstrlen(protseq) + 1; // +1 for ':'
    }
    if !network_addr.is_null() {
        total_len += wstrlen(network_addr);
    }
    if !endpoint.is_null() {
        total_len += wstrlen(endpoint) + 1; // +1 for '['
    }
    if !options.is_null() {
        total_len += wstrlen(options) + 1; // +1 for ','
    }
    if !endpoint.is_null() || !options.is_null() {
        total_len += 1; // +1 for ']'
    }
    total_len += 1; // null terminator

    let buffer = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        total_len * 2,
    ) as *mut u16;

    if buffer.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    let mut pos = 0;

    if !obj_uuid.is_null() {
        let len = wstrlen(obj_uuid);
        for i in 0..len {
            *buffer.add(pos) = *obj_uuid.add(i);
            pos += 1;
        }
        *buffer.add(pos) = b'@' as u16;
        pos += 1;
    }

    if !protseq.is_null() {
        let len = wstrlen(protseq);
        for i in 0..len {
            *buffer.add(pos) = *protseq.add(i);
            pos += 1;
        }
        *buffer.add(pos) = b':' as u16;
        pos += 1;
    }

    if !network_addr.is_null() {
        let len = wstrlen(network_addr);
        for i in 0..len {
            *buffer.add(pos) = *network_addr.add(i);
            pos += 1;
        }
    }

    if !endpoint.is_null() || !options.is_null() {
        *buffer.add(pos) = b'[' as u16;
        pos += 1;

        if !endpoint.is_null() {
            let len = wstrlen(endpoint);
            for i in 0..len {
                *buffer.add(pos) = *endpoint.add(i);
                pos += 1;
            }
        }

        if !options.is_null() {
            *buffer.add(pos) = b',' as u16;
            pos += 1;
            let len = wstrlen(options);
            for i in 0..len {
                *buffer.add(pos) = *options.add(i);
                pos += 1;
            }
        }

        *buffer.add(pos) = b']' as u16;
        pos += 1;
    }

    *buffer.add(pos) = 0; // null terminator
    *string_binding = buffer;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingFromStringBindingW(
    string_binding: *const u16,
    binding: *mut RPC_BINDING_HANDLE,
) -> RPC_STATUS {
    if string_binding.is_null() || binding.is_null() {
        return RPC_S_INVALID_STRING_BINDING;
    }

    let bind_internal = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<RpcBindingInternal>(),
    ) as *mut RpcBindingInternal;

    if bind_internal.is_null() {
        return RPC_S_OUT_OF_MEMORY;
    }

    *bind_internal = RpcBindingInternal::new();

    let mut pos = 0;
    let len = wstrlen(string_binding);

    let mut at_pos = None;
    for i in 0..len {
        if *string_binding.add(i) == b'@' as u16 {
            at_pos = Some(i);
            break;
        }
    }

    if let Some(at) = at_pos {
        pos = at + 1;
    }

    let mut colon_pos = None;
    for i in pos..len {
        if *string_binding.add(i) == b':' as u16 {
            colon_pos = Some(i);
            break;
        }
    }

    if colon_pos.is_none() {
        crate::mm::pool::free(bind_internal as *mut u8);
        return RPC_S_INVALID_STRING_BINDING;
    }

    let colon = colon_pos.unwrap();

    let protseq_len = colon - pos;
    if protseq_len >= 16 {
        crate::mm::pool::free(bind_internal as *mut u8);
        return RPC_S_STRING_TOO_LONG;
    }
    for i in 0..protseq_len {
        (*bind_internal).protseq[i] = *string_binding.add(pos + i);
    }
    (*bind_internal).protseq[protseq_len] = 0;

    pos = colon + 1;

    let mut bracket_pos = None;
    for i in pos..len {
        if *string_binding.add(i) == b'[' as u16 {
            bracket_pos = Some(i);
            break;
        }
    }

    let network_end = bracket_pos.unwrap_or(len);

    let network_len = network_end - pos;
    if network_len >= 128 {
        crate::mm::pool::free(bind_internal as *mut u8);
        return RPC_S_STRING_TOO_LONG;
    }
    for i in 0..network_len {
        (*bind_internal).network_addr[i] = *string_binding.add(pos + i);
    }
    (*bind_internal).network_addr[network_len] = 0;

    if let Some(bracket) = bracket_pos {
        pos = bracket + 1;

        let mut comma_pos = None;
        let mut close_bracket_pos = None;
        for i in pos..len {
            if *string_binding.add(i) == b',' as u16 && comma_pos.is_none() {
                comma_pos = Some(i);
            }
            if *string_binding.add(i) == b']' as u16 {
                close_bracket_pos = Some(i);
                break;
            }
        }

        if close_bracket_pos.is_none() {
            crate::mm::pool::free(bind_internal as *mut u8);
            return RPC_S_INVALID_STRING_BINDING;
        }

        let endpoint_end = comma_pos.unwrap_or(close_bracket_pos.unwrap());

        let endpoint_len = endpoint_end - pos;
        if endpoint_len >= 64 {
            crate::mm::pool::free(bind_internal as *mut u8);
            return RPC_S_STRING_TOO_LONG;
        }
        for i in 0..endpoint_len {
            (*bind_internal).endpoint[i] = *string_binding.add(pos + i);
        }
        (*bind_internal).endpoint[endpoint_len] = 0;

        if let Some(comma) = comma_pos {
            pos = comma + 1;
            let options_end = close_bracket_pos.unwrap();
            let options_len = options_end - pos;
            if options_len >= 64 {
                crate::mm::pool::free(bind_internal as *mut u8);
                return RPC_S_STRING_TOO_LONG;
            }
            for i in 0..options_len {
                (*bind_internal).options[i] = *string_binding.add(pos + i);
            }
            (*bind_internal).options[options_len] = 0;
        }
    }

    let mut registry = BINDING_REGISTRY.lock();
    if registry.add_binding(bind_internal).is_none() {
        crate::mm::pool::free(bind_internal as *mut u8);
        return RPC_S_OUT_OF_RESOURCES;
    }

    *binding = bind_internal as RPC_BINDING_HANDLE;
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingToStringBindingW(
    binding: RPC_BINDING_HANDLE,
    string_binding: *mut *mut u16,
) -> RPC_STATUS {
    if binding.is_null() || string_binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    let registry = BINDING_REGISTRY.lock();
    if !registry.find_binding(bind_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    RpcStringBindingComposeW(
        null_mut(),
        (*bind_internal).protseq.as_ptr(),
        (*bind_internal).network_addr.as_ptr(),
        (*bind_internal).endpoint.as_ptr(),
        (*bind_internal).options.as_ptr(),
        string_binding,
    )
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingFree(binding: *mut RPC_BINDING_HANDLE) -> RPC_STATUS {
    if binding.is_null() || (*binding).is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = *binding as *mut RpcBindingInternal;

    let mut registry = BINDING_REGISTRY.lock();
    if !registry.remove_binding(bind_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    (*bind_internal).ref_count -= 1;
    if (*bind_internal).ref_count == 0 {
        crate::mm::pool::free(bind_internal as *mut u8);
    }

    *binding = null_mut();
    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingCopy(
    source_binding: RPC_BINDING_HANDLE,
    dest_binding: *mut RPC_BINDING_HANDLE,
) -> RPC_STATUS {
    if source_binding.is_null() || dest_binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let src_internal = source_binding as *mut RpcBindingInternal;

    let registry = BINDING_REGISTRY.lock();
    if !registry.find_binding(src_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    (*src_internal).ref_count += 1;
    *dest_binding = source_binding;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingReset(binding: RPC_BINDING_HANDLE) -> RPC_STATUS {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    let registry = BINDING_REGISTRY.lock();
    if !registry.find_binding(bind_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    (*bind_internal).lpc_port_index = 0;

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingSetObject(
    binding: RPC_BINDING_HANDLE,
    object_uuid: *const UUID,
) -> RPC_STATUS {
    if binding.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    let registry = BINDING_REGISTRY.lock();
    if !registry.find_binding(bind_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    if !object_uuid.is_null() {
        (*bind_internal).object_uuid = *object_uuid;
    } else {
        (*bind_internal).object_uuid = UUID::default();
    }

    RPC_S_OK
}

#[no_mangle]
pub unsafe extern "C" fn RpcBindingInqObject(
    binding: RPC_BINDING_HANDLE,
    object_uuid: *mut UUID,
) -> RPC_STATUS {
    if binding.is_null() || object_uuid.is_null() {
        return RPC_S_INVALID_BINDING;
    }

    let bind_internal = binding as *mut RpcBindingInternal;

    let registry = BINDING_REGISTRY.lock();
    if !registry.find_binding(bind_internal) {
        return RPC_S_INVALID_BINDING;
    }
    drop(registry);

    *object_uuid = (*bind_internal).object_uuid;
    RPC_S_OK
}
