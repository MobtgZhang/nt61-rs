//! kernel32 — synchronisation primitives
//
//! `wait_for_single_object`, `wait_for_multiple_objects`,
//! `create_event_w`, `set_event`, `reset_event`, `pulse_event`,
//! `create_mutex_w`, `release_mutex`, `create_semaphore_w`,
//! `release_semaphore`, `initialize_critical_section`,
//! `enter_critical_section`, `leave_critical_section`,
//! `delete_critical_section`. The user-mode side of this
//! kernel is never executed, so we accept the calls and
//! forward to ntdll.

use super::error::set_last_error;
use super::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::ke::sync::Spinlock;
use crate::libs::ntdll::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use crate::libs::ntdll::sync as ntdll_sync;
use core::ptr;
use core::sync::atomic::AtomicU32;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `create_event_w`.
pub unsafe extern "C" fn create_event_w(
    _security_attributes: *const u8,
    manual_reset: BOOL,
    initial_state: BOOL,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let event_type = if manual_reset != 0 { 0 } else { 1 };
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::nt_create_event(&mut h, 0, &mut oa, event_type, initial_state as u8);
    if status != STATUS_SUCCESS {
        set_last_error(8);
        return ptr::null_mut();
    }
    h
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `set_event` / `reset_event` / `pulse_event`.
pub unsafe extern "C" fn set_event(event: HANDLE) -> BOOL {
    if ntdll_sync::nt_set_event(event, ptr::null_mut()) == STATUS_SUCCESS {
        TRUE
    } else {
        FALSE
    }
}
/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn reset_event(event: HANDLE) -> BOOL {
    if ntdll_sync::nt_reset_event(event, ptr::null_mut()) == STATUS_SUCCESS {
        TRUE
    } else {
        FALSE
    }
}
/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn pulse_event(event: HANDLE) -> BOOL {
    if ntdll_sync::nt_pulse_event(event, ptr::null_mut()) == STATUS_SUCCESS {
        TRUE
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// Mutexes
// ---------------------------------------------------------------------------

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `create_mutex_w`.
pub unsafe extern "C" fn create_mutex_w(
    _security: *const u8,
    initial_owner: BOOL,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::nt_create_mutant(&mut h, 0, &mut oa, initial_owner as u8);
    if status != STATUS_SUCCESS {
        set_last_error(8);
        return ptr::null_mut();
    }
    h
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `release_mutex`.
pub unsafe extern "C" fn release_mutex(mutex: HANDLE) -> BOOL {
    if ntdll_sync::nt_release_mutant(mutex, ptr::null_mut()) == STATUS_SUCCESS {
        TRUE
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// Semaphores
// ---------------------------------------------------------------------------

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `create_semaphore_w`.
pub unsafe extern "C" fn create_semaphore_w(
    _security: *const u8,
    initial_count: DWORD,
    maximum_count: DWORD,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::nt_create_semaphore(&mut h, 0, &mut oa, initial_count, maximum_count);
    if status != STATUS_SUCCESS {
        set_last_error(8);
        return ptr::null_mut();
    }
    h
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `release_semaphore`.
pub unsafe extern "C" fn release_semaphore(
    semaphore: HANDLE,
    release_count: DWORD,
    previous_count: *mut DWORD,
) -> BOOL {
    if ntdll_sync::nt_release_semaphore(semaphore, release_count, previous_count) == STATUS_SUCCESS
    {
        TRUE
    } else {
        FALSE
    }
}

// ---------------------------------------------------------------------------
// Wait
// ---------------------------------------------------------------------------

const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_ABANDONED: DWORD = 0x80;
const WAIT_TIMEOUT: DWORD = 0x102;
const WAIT_FAILED: DWORD = 0xFFFF_FFFF;
pub const INFINITE: DWORD = 0xFFFF_FFFF;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `wait_for_single_object`.
pub unsafe extern "C" fn wait_for_single_object(handle: HANDLE, _milliseconds: DWORD) -> DWORD {
    if handle.is_null() {
        set_last_error(6);
        return WAIT_FAILED;
    }
    let status = ntdll_sync::nt_wait_for_single_object_kernel(handle, 0, None);
    if status == STATUS_SUCCESS {
        WAIT_OBJECT_0
    } else if status == STATUS_INVALID_HANDLE {
        set_last_error(6);
        WAIT_FAILED
    } else {
        WAIT_TIMEOUT
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `wait_for_multiple_objects`.
pub unsafe extern "C" fn wait_for_multiple_objects(
    count: DWORD,
    handles: *const HANDLE,
    wait_all: BOOL,
    _milliseconds: DWORD,
) -> DWORD {
    if count == 0 || count > 64 || handles.is_null() {
        set_last_error(87);
        return WAIT_FAILED;
    }
    let wait_type = if wait_all != 0 { 0 } else { 1 };
    let status = ntdll_sync::nt_wait_for_multiple_objects_kernel(
        count,
        unsafe { core::slice::from_raw_parts(handles, count as usize) },
        wait_type,
        0,
        None,
    );
    if status == STATUS_SUCCESS {
        WAIT_OBJECT_0
    } else {
        WAIT_TIMEOUT
    }
}

// ---------------------------------------------------------------------------
// Critical section (user-mode spinlock wrapper)
// ---------------------------------------------------------------------------

const CRITICAL_SECTION_MAGIC: u32 = 0xDEAD_C0DE;

/// `CRITICAL_SECTION` (RTL_CRITICAL_SECTION in user mode).
#[repr(C)]
pub struct CriticalSection {
    pub lock: AtomicU32,
    pub recursion_count: u32,
    pub owning_thread: u32,
    pub magic: u32,
    pub spin: Spinlock<()>,
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `initialize_critical_section`.
pub unsafe extern "C" fn initialize_critical_section(cs: *mut CriticalSection) {
    if cs.is_null() {
        return;
    }
    (*cs).lock = AtomicU32::new(0);
    (*cs).recursion_count = 0;
    (*cs).owning_thread = 0;
    (*cs).magic = CRITICAL_SECTION_MAGIC;
    (*cs).spin = Spinlock::new(());
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `enter_critical_section`.
pub unsafe extern "C" fn enter_critical_section(cs: *mut CriticalSection) {
    if cs.is_null() {
        return;
    }
    let _g = (*cs).spin.lock();
    (*cs).recursion_count += 1;
    (*cs).owning_thread = 1;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `leave_critical_section`.
pub unsafe extern "C" fn leave_critical_section(cs: *mut CriticalSection) {
    if cs.is_null() {
        return;
    }
    if (*cs).recursion_count > 0 {
        (*cs).recursion_count -= 1;
    }
    if (*cs).recursion_count == 0 {
        (*cs).owning_thread = 0;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `delete_critical_section`.
pub unsafe extern "C" fn delete_critical_section(cs: *mut CriticalSection) {
    if cs.is_null() {
        return;
    }
    (*cs).magic = 0;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `initialize_critical_section_and_spin_count` / `set_critical_section_spin_count`.
pub unsafe extern "C" fn initialize_critical_section_and_spin_count(
    cs: *mut CriticalSection,
    _spins: DWORD,
) -> BOOL {
    initialize_critical_section(cs);
    TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe extern "C" fn set_critical_section_spin_count(
    _cs: *mut CriticalSection,
    _spins: DWORD,
) -> DWORD {
    0
}
