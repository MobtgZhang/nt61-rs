//! ntdll — RTL critical section operations
//
//! Implements the `Rtl*CriticalSection` family used for user-mode
//! synchronization. Critical sections are lightweight in-process
//! locks that use atomic operations for the fast path and fall
//! back to kernel events for contention.
//
//! References: MSDN Library "Windows 7" — RTL_CRITICAL_SECTION.

use super::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use super::sync::{NtCreateEvent, NtSetEvent, NtWaitForSingleObject};
use super::types::{HANDLE, NTSTATUS, ObjectAttributes, RtlCriticalSection};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

pub unsafe extern "C" fn RtlInitializeCriticalSection(
    critical_section: *mut RtlCriticalSection,
) -> NTSTATUS {
    if critical_section.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let cs = &mut *critical_section;
    cs.debug_info = ptr::null_mut();
    cs.lock_count = -1;
    cs.recursion_count = 0;
    cs.owning_thread = ptr::null_mut();
    cs.lock_semaphore = ptr::null_mut();
    cs.spin_count = 0;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlInitializeCriticalSectionAndSpinCount(
    critical_section: *mut RtlCriticalSection,
    spin_count: u32,
) -> NTSTATUS {
    let status = RtlInitializeCriticalSection(critical_section);
    if status == STATUS_SUCCESS {
        (*critical_section).spin_count = spin_count as usize;
    }
    status
}

pub unsafe extern "C" fn RtlEnterCriticalSection(
    critical_section: *mut RtlCriticalSection,
) -> NTSTATUS {
    if critical_section.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let cs = &mut *critical_section;
    let current_thread = get_current_thread_handle();

    let lock_ptr = &cs.lock_count as *const i32 as *mut AtomicI32;
    let old_count = (*lock_ptr).fetch_add(1, Ordering::Acquire);

    if old_count == -1 {
        cs.owning_thread = current_thread;
        cs.recursion_count = 1;
        return STATUS_SUCCESS;
    }

    if cs.owning_thread == current_thread {
        cs.recursion_count += 1;
        return STATUS_SUCCESS;
    }

    if cs.lock_semaphore.is_null() {
        let mut oa = ObjectAttributes::new();
        let mut event: HANDLE = ptr::null_mut();
        NtCreateEvent(&mut event, 0, &mut oa, 1, 0);
        cs.lock_semaphore = event;
    }

    if !cs.lock_semaphore.is_null() {
        NtWaitForSingleObject(cs.lock_semaphore, 0, ptr::null_mut());
    }

    cs.owning_thread = current_thread;
    cs.recursion_count = 1;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlTryEnterCriticalSection(
    critical_section: *mut RtlCriticalSection,
) -> u32 {
    if critical_section.is_null() {
        return 0;
    }
    let cs = &mut *critical_section;
    let current_thread = get_current_thread_handle();

    if cs.owning_thread == current_thread {
        let lock_ptr = &cs.lock_count as *const i32 as *mut AtomicI32;
        (*lock_ptr).fetch_add(1, Ordering::Acquire);
        cs.recursion_count += 1;
        return 1;
    }

    let lock_ptr = &cs.lock_count as *const i32 as *mut AtomicI32;
    if (*lock_ptr).compare_exchange(-1, 0, Ordering::Acquire, Ordering::Relaxed).is_ok() {
        cs.owning_thread = current_thread;
        cs.recursion_count = 1;
        1
    } else {
        0
    }
}

pub unsafe extern "C" fn RtlLeaveCriticalSection(
    critical_section: *mut RtlCriticalSection,
) -> NTSTATUS {
    if critical_section.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let cs = &mut *critical_section;

    cs.recursion_count -= 1;
    if cs.recursion_count > 0 {
        let lock_ptr = &cs.lock_count as *const i32 as *mut AtomicI32;
        (*lock_ptr).fetch_sub(1, Ordering::Release);
        return STATUS_SUCCESS;
    }

    cs.owning_thread = ptr::null_mut();
    let lock_ptr = &cs.lock_count as *const i32 as *mut AtomicI32;
    let old_count = (*lock_ptr).fetch_sub(1, Ordering::Release);

    if old_count > 0 && !cs.lock_semaphore.is_null() {
        NtSetEvent(cs.lock_semaphore, ptr::null_mut());
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlDeleteCriticalSection(
    critical_section: *mut RtlCriticalSection,
) -> NTSTATUS {
    if critical_section.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let cs = &mut *critical_section;

    if !cs.lock_semaphore.is_null() {
        cs.lock_semaphore = ptr::null_mut();
    }

    cs.lock_count = -1;
    cs.recursion_count = 0;
    cs.owning_thread = ptr::null_mut();
    cs.debug_info = ptr::null_mut();
    STATUS_SUCCESS
}

pub unsafe extern "C" fn RtlSetCriticalSectionSpinCount(
    critical_section: *mut RtlCriticalSection,
    spin_count: u32,
) -> u32 {
    if critical_section.is_null() {
        return 0;
    }
    let cs = &mut *critical_section;
    let old = cs.spin_count as u32;
    cs.spin_count = spin_count as usize;
    old
}

fn get_current_thread_handle() -> HANDLE {
    let ethread = crate::ps::thread::get_current_ethread();
    if ethread.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (*ethread).client_id.unique_thread as HANDLE }
    }
}
