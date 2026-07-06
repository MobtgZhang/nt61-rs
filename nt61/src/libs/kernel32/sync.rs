//! kernel32 — synchronisation primitives
//
//! `WaitForSingleObject`, `WaitForMultipleObjects`,
//! `CreateEventW`, `SetEvent`, `ResetEvent`, `PulseEvent`,
//! `CreateMutexW`, `ReleaseMutex`, `CreateSemaphoreW`,
//! `ReleaseSemaphore`, `InitializeCriticalSection`,
//! `EnterCriticalSection`, `LeaveCriticalSection`,
//! `DeleteCriticalSection`. The user-mode side of this
//! kernel is never executed, so we accept the calls and
//! forward to ntdll.

use super::error::{GetLastError, SetLastError};
use super::types::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, TRUE};
use crate::ke::sync::Spinlock;
use crate::libs::ntdll::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use crate::libs::ntdll::sync as ntdll_sync;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// `CreateEventW`.
pub unsafe extern "C" fn CreateEventW(
    _security_attributes: *const u8,
    manual_reset: BOOL,
    initial_state: BOOL,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let event_type = if manual_reset != 0 { 0 } else { 1 };
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::NtCreateEvent(&mut h, 0, &mut oa, event_type, initial_state as u8);
    if status != STATUS_SUCCESS {
        SetLastError(8);
        return ptr::null_mut();
    }
    h
}

/// `SetEvent` / `ResetEvent` / `PulseEvent`.
pub unsafe extern "C" fn SetEvent(event: HANDLE) -> BOOL {
    if ntdll_sync::NtSetEvent(event, ptr::null_mut()) == STATUS_SUCCESS { TRUE } else { FALSE }
}
pub unsafe extern "C" fn ResetEvent(event: HANDLE) -> BOOL {
    if ntdll_sync::NtResetEvent(event, ptr::null_mut()) == STATUS_SUCCESS { TRUE } else { FALSE }
}
pub unsafe extern "C" fn PulseEvent(event: HANDLE) -> BOOL {
    if ntdll_sync::NtPulseEvent(event, ptr::null_mut()) == STATUS_SUCCESS { TRUE } else { FALSE }
}

// ---------------------------------------------------------------------------
// Mutexes
// ---------------------------------------------------------------------------

/// `CreateMutexW`.
pub unsafe extern "C" fn CreateMutexW(
    _security: *const u8,
    initial_owner: BOOL,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::NtCreateMutant(&mut h, 0, &mut oa, initial_owner as u8);
    if status != STATUS_SUCCESS {
        SetLastError(8);
        return ptr::null_mut();
    }
    h
}

/// `ReleaseMutex`.
pub unsafe extern "C" fn ReleaseMutex(mutex: HANDLE) -> BOOL {
    if ntdll_sync::NtReleaseMutant(mutex, ptr::null_mut()) == STATUS_SUCCESS { TRUE } else { FALSE }
}

// ---------------------------------------------------------------------------
// Semaphores
// ---------------------------------------------------------------------------

/// `CreateSemaphoreW`.
pub unsafe extern "C" fn CreateSemaphoreW(
    _security: *const u8,
    initial_count: DWORD,
    maximum_count: DWORD,
    _name: LPCWSTR,
) -> HANDLE {
    let mut oa = crate::libs::ntdll::types::ObjectAttributes::new();
    let mut h: HANDLE = ptr::null_mut();
    let status = ntdll_sync::NtCreateSemaphore(&mut h, 0, &mut oa, initial_count, maximum_count);
    if status != STATUS_SUCCESS {
        SetLastError(8);
        return ptr::null_mut();
    }
    h
}

/// `ReleaseSemaphore`.
pub unsafe extern "C" fn ReleaseSemaphore(
    semaphore: HANDLE,
    release_count: DWORD,
    previous_count: *mut DWORD,
) -> BOOL {
    if ntdll_sync::NtReleaseSemaphore(semaphore, release_count, previous_count) == STATUS_SUCCESS {
        TRUE
    } else { FALSE }
}

// ---------------------------------------------------------------------------
// Wait
// ---------------------------------------------------------------------------

const WAIT_OBJECT_0: DWORD = 0;
const WAIT_ABANDONED: DWORD = 0x80;
const WAIT_TIMEOUT: DWORD = 0x102;
const WAIT_FAILED: DWORD = 0xFFFF_FFFF;
const INFINITE: DWORD = 0xFFFF_FFFF;

/// `WaitForSingleObject`.
pub unsafe extern "C" fn WaitForSingleObject(handle: HANDLE, _milliseconds: DWORD) -> DWORD {
    if handle.is_null() { SetLastError(6); return WAIT_FAILED; }
    let status = ntdll_sync::NtWaitForSingleObject(handle, 0, ptr::null_mut());
    if status == STATUS_SUCCESS { WAIT_OBJECT_0 }
    else if status == STATUS_INVALID_HANDLE { SetLastError(6); WAIT_FAILED }
    else { WAIT_TIMEOUT }
}

/// `WaitForMultipleObjects`.
pub unsafe extern "C" fn WaitForMultipleObjects(
    count: DWORD,
    handles: *const HANDLE,
    wait_all: BOOL,
    _milliseconds: DWORD,
) -> DWORD {
    if count == 0 || count > 64 || handles.is_null() {
        SetLastError(87);
        return WAIT_FAILED;
    }
    let wait_type = if wait_all != 0 { 0 } else { 1 };
    let status = ntdll_sync::NtWaitForMultipleObjects(count, handles as *mut _, wait_type, 0, ptr::null_mut());
    if status == STATUS_SUCCESS { WAIT_OBJECT_0 }
    else { WAIT_TIMEOUT }
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

/// `InitializeCriticalSection`.
pub unsafe extern "C" fn InitializeCriticalSection(cs: *mut CriticalSection) {
    if cs.is_null() { return; }
    (*cs).lock = AtomicU32::new(0);
    (*cs).recursion_count = 0;
    (*cs).owning_thread = 0;
    (*cs).magic = CRITICAL_SECTION_MAGIC;
    (*cs).spin = Spinlock::new(());
}

/// `EnterCriticalSection`.
pub unsafe extern "C" fn EnterCriticalSection(cs: *mut CriticalSection) {
    if cs.is_null() { return; }
    let _g = (*cs).spin.lock();
    (*cs).recursion_count += 1;
    (*cs).owning_thread = 1;
}

/// `LeaveCriticalSection`.
pub unsafe extern "C" fn LeaveCriticalSection(cs: *mut CriticalSection) {
    if cs.is_null() { return; }
    if (*cs).recursion_count > 0 { (*cs).recursion_count -= 1; }
    if (*cs).recursion_count == 0 { (*cs).owning_thread = 0; }
}

/// `DeleteCriticalSection`.
pub unsafe extern "C" fn DeleteCriticalSection(cs: *mut CriticalSection) {
    if cs.is_null() { return; }
    (*cs).magic = 0;
}

/// `InitializeCriticalSectionAndSpinCount` / `SetCriticalSectionSpinCount`.
pub unsafe extern "C" fn InitializeCriticalSectionAndSpinCount(cs: *mut CriticalSection, _spins: DWORD) -> BOOL {
    InitializeCriticalSection(cs);
    TRUE
}

pub unsafe extern "C" fn SetCriticalSectionSpinCount(_cs: *mut CriticalSection, _spins: DWORD) -> DWORD {
    0
}
