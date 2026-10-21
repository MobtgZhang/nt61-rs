//! kernel32 — Additional synchronization primitives
//
//! Extended synchronization: timers, interlocked operations, barriers.

use super::error::set_last_error;
use super::types::{BOOL, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::libs::ntdll::status::STATUS_SUCCESS;
use crate::libs::ntdll::sync as ntdll_sync;
use crate::libs::ntdll::timer as ntdll_timer;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

pub unsafe extern "C" fn create_waitable_timer_w(
    _security_attributes: *const u8,
    manual_reset: BOOL,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let mut h: HANDLE = ptr::null_mut();
    let timer_type = if manual_reset != 0 { 0 } else { 1 };
    let status = ntdll_sync::nt_create_timer(&mut h, 0, &mut oa, timer_type);
    if status != STATUS_SUCCESS {
        set_last_error(8);
        return ptr::null_mut();
    }
    h
}

pub unsafe extern "C" fn set_waitable_timer(
    timer: HANDLE,
    due_time: *const i64,
    period: i32,
    completion_routine: *const (),
    arg_to_completion_routine: *const (),
    resume: BOOL,
) -> BOOL {
    if timer.is_null() || due_time.is_null() {
        set_last_error(6);
        return FALSE;
    }

    let _ = (completion_routine, arg_to_completion_routine);
    let status = ntdll_timer::nt_set_timer(
        timer,
        due_time as *const crate::libs::ntdll::types::LargeInteger,
        ptr::null_mut(),
        ptr::null_mut(),
        resume as u8,
        period,
        ptr::null_mut(),
    );

    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(6);
        FALSE
    }
}

pub unsafe extern "C" fn cancel_waitable_timer(timer: HANDLE) -> BOOL {
    if timer.is_null() {
        set_last_error(6);
        return FALSE;
    }

    let status = ntdll_sync::nt_cancel_timer(timer, ptr::null_mut());
    if status == STATUS_SUCCESS {
        TRUE
    } else {
        set_last_error(6);
        FALSE
    }
}

pub unsafe extern "C" fn interlocked_increment(addend: *mut i32) -> i32 {
    if addend.is_null() {
        return 0;
    }
    let atomic = &*(addend as *const AtomicI32);
    atomic.fetch_add(1, Ordering::SeqCst) + 1
}

pub unsafe extern "C" fn interlocked_decrement(addend: *mut i32) -> i32 {
    if addend.is_null() {
        return 0;
    }
    let atomic = &*(addend as *const AtomicI32);
    atomic.fetch_sub(1, Ordering::SeqCst) - 1
}

pub unsafe extern "C" fn interlocked_exchange(target: *mut i32, value: i32) -> i32 {
    if target.is_null() {
        return 0;
    }
    let atomic = &*(target as *const AtomicI32);
    atomic.swap(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_exchange_add(addend: *mut i32, value: i32) -> i32 {
    if addend.is_null() {
        return 0;
    }
    let atomic = &*(addend as *const AtomicI32);
    atomic.fetch_add(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_compare_exchange(
    destination: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    if destination.is_null() {
        return 0;
    }
    let atomic = &*(destination as *const AtomicI32);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(old) => old,
        Err(old) => old,
    }
}

pub unsafe extern "C" fn interlocked_exchange_pointer(
    target: *mut *mut core::ffi::c_void,
    value: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if target.is_null() {
        return ptr::null_mut();
    }
    let atomic = &*(target as *const core::sync::atomic::AtomicPtr<core::ffi::c_void>);
    atomic.swap(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_compare_exchange_pointer(
    destination: *mut *mut core::ffi::c_void,
    exchange: *mut core::ffi::c_void,
    comparand: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if destination.is_null() {
        return ptr::null_mut();
    }
    let atomic = &*(destination as *const core::sync::atomic::AtomicPtr<core::ffi::c_void>);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(old) => old,
        Err(old) => old,
    }
}

pub unsafe extern "C" fn interlocked_increment64(addend: *mut i64) -> i64 {
    if addend.is_null() {
        return 0;
    }
    let atomic = &*(addend as *const AtomicI64);
    atomic.fetch_add(1, Ordering::SeqCst) + 1
}

pub unsafe extern "C" fn interlocked_decrement64(addend: *mut i64) -> i64 {
    if addend.is_null() {
        return 0;
    }
    let atomic = &*(addend as *const AtomicI64);
    atomic.fetch_sub(1, Ordering::SeqCst) - 1
}

pub unsafe extern "C" fn interlocked_exchange64(target: *mut i64, value: i64) -> i64 {
    if target.is_null() {
        return 0;
    }
    let atomic = &*(target as *const AtomicI64);
    atomic.swap(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_compare_exchange64(
    destination: *mut i64,
    exchange: i64,
    comparand: i64,
) -> i64 {
    if destination.is_null() {
        return 0;
    }
    let atomic = &*(destination as *const AtomicI64);
    match atomic.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(old) => old,
        Err(old) => old,
    }
}

pub unsafe extern "C" fn interlocked_and(destination: *mut i32, value: i32) -> i32 {
    if destination.is_null() {
        return 0;
    }
    let atomic = &*(destination as *const AtomicI32);
    atomic.fetch_and(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_or(destination: *mut i32, value: i32) -> i32 {
    if destination.is_null() {
        return 0;
    }
    let atomic = &*(destination as *const AtomicI32);
    atomic.fetch_or(value, Ordering::SeqCst)
}

pub unsafe extern "C" fn interlocked_xor(destination: *mut i32, value: i32) -> i32 {
    if destination.is_null() {
        return 0;
    }
    let atomic = &*(destination as *const AtomicI32);
    atomic.fetch_xor(value, Ordering::SeqCst)
}

#[inline(always)]
pub extern "C" fn memory_barrier() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

#[inline(always)]
pub extern "C" fn yield_processor() {
    core::hint::spin_loop();
}

#[inline(always)]
pub extern "C" fn read_write_barrier() {
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
