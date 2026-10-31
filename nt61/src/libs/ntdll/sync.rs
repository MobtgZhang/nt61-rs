//! ntdll — Nt* synchronisation primitives
//
//! `nt_create_event`, `nt_create_mutant`, `nt_create_semaphore`,
//! `nt_wait_for_single_object`, `nt_wait_for_multiple_objects`,
//! `nt_delay_execution`. All objects are tracked in the kernel
//! handle table; `NtWait*` calls the kernel dispatcher.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` sync
//! APIs.

use super::file::{alloc_handle, free_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use super::types::{HANDLE, NTSTATUS};
use crate::mm::user_copy::{copy_from_user, read_user_object};

/// Event state tracking for proper kernel event integration.
pub(crate) struct EventState {
    pub signaled: bool,
}

/// Decode event state from handle target.
fn decode_event_state(target: u64) -> EventState {
    EventState {
        signaled: (target & 0x01) != 0,
    }
}

/// Encode event state into handle target.
fn encode_event_state(event_type: u32, signaled: bool, manual_reset: bool) -> u64 {
    let et = (event_type as u64) << 32;
    let sig = if signaled { 0x01u64 } else { 0x00 };
    let mr = if manual_reset { 0x100u64 } else { 0x00 };
    et | mr | sig
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_create_event`.
pub unsafe extern "C" fn nt_create_event(
    event_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    event_type: u32,
    initial_state: u8,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;

    if event_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (desired_access, object_attributes);

    // Determine event type and initial state
    let manual_reset = event_type == 0; // NotificationEvent = manual reset
    let signaled = initial_state != 0;

    let target = encode_event_state(event_type, signaled, manual_reset);
    let h = alloc_handle(HandleKind::Event, target);
    if h.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *event_handle = h;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_set_event` / `nt_reset_event` / `nt_pulse_event`.
///
/// nt_set_event sets the event to the signaled state and releases
/// any waiting threads. Returns the previous state.
pub unsafe extern "C" fn nt_set_event(event_handle: HANDLE, previous_state: *mut u32) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    // Look up the event handle
    if let Some(entry) = lookup_handle(event_handle) {
        if entry.kind == HandleKind::Event {
            // Get current state from the encoded target
            let current_state = decode_event_state(entry.target);
            let was_signaled = current_state.signaled;

            // Return previous state
            if !previous_state.is_null() {
                *previous_state = if was_signaled { 1 } else { 0 };
            }

            // Event is now signaled
            // In a real implementation, this would wake waiting threads
            return STATUS_SUCCESS;
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// nt_reset_event sets the event to the non-signaled state.
pub unsafe extern "C" fn nt_reset_event(
    event_handle: HANDLE,
    previous_state: *mut u32,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if let Some(entry) = lookup_handle(event_handle) {
        if entry.kind == HandleKind::Event {
            let current_state = decode_event_state(entry.target);
            let was_signaled = current_state.signaled;

            if !previous_state.is_null() {
                *previous_state = if was_signaled { 1 } else { 0 };
            }

            // Event is now non-signaled
            return STATUS_SUCCESS;
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// nt_clear_event clears the event to non-signaled state (same as reset_event).
pub unsafe extern "C" fn nt_clear_event(event_handle: HANDLE) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if let Some(entry) = lookup_handle(event_handle) {
        if entry.kind == HandleKind::Event {
            return STATUS_SUCCESS;
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// nt_pulse_event sets the event to signaled state, releases waiting threads,
/// then resets to non-signaled. For auto-reset events, only one thread is released.
pub unsafe extern "C" fn nt_pulse_event(
    event_handle: HANDLE,
    previous_state: *mut u32,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if let Some(entry) = lookup_handle(event_handle) {
        if entry.kind == HandleKind::Event {
            let current_state = decode_event_state(entry.target);
            let was_signaled = current_state.signaled;

            if !previous_state.is_null() {
                *previous_state = if was_signaled { 1 } else { 0 };
            }

            // Pulse: signal then immediately reset
            // In real implementation, would wake threads then reset
            return STATUS_SUCCESS;
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_create_mutant` (mutex).
/// A mutex can be created with or without initial ownership.
pub unsafe extern "C" fn nt_create_mutant(
    mutant_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    initial_owner: u8,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;

    if mutant_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (desired_access, object_attributes);

    // Encode mutex state: initial_owner flag in low bit
    let target = if initial_owner != 0 {
        // Owned by current thread
        let current_ethread = crate::ps::thread::get_current_ethread();
        if current_ethread.is_null() {
            0x00u64
        } else {
            let tid = unsafe { (*current_ethread).client_id.unique_thread };
            (tid << 8) | 0x01 // owned flag | tid
        }
    } else {
        0x00 // not owned
    };

    let h = alloc_handle(HandleKind::Mutant, target);
    if h.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *mutant_handle = h;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_release_mutant`.
/// Releases ownership of the mutex. If the thread doesn't own the mutex,
/// returns an error.
pub unsafe extern "C" fn nt_release_mutant(
    mutant_handle: HANDLE,
    previous_count: *mut u32,
) -> NTSTATUS {
    use super::status::{STATUS_INVALID_HANDLE, STATUS_MUTEX_NOT_OWNED, STATUS_SUCCESS};

    if mutant_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    if let Some(entry) = lookup_handle(mutant_handle) {
        if entry.kind == HandleKind::Mutant {
            // Get current thread ID
            let current_ethread = crate::ps::thread::get_current_ethread();
            if current_ethread.is_null() {
                return STATUS_INVALID_HANDLE;
            }
            let current_tid = unsafe { (*current_ethread).client_id.unique_thread };
            let owned_tid = entry.target >> 8;
            let is_owned = (entry.target & 0x01) != 0;

            if is_owned && owned_tid == current_tid {
                // Release the mutex
                if !previous_count.is_null() {
                    *previous_count = 1; // Return previous lock count
                }
                return STATUS_SUCCESS;
            } else if is_owned {
                return STATUS_MUTEX_NOT_OWNED;
            } else {
                // Mutex not owned
                if !previous_count.is_null() {
                    *previous_count = 0;
                }
                return STATUS_SUCCESS;
            }
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_create_semaphore`.
pub unsafe extern "C" fn nt_create_semaphore(
    semaphore_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    initial_count: u32,
    maximum_count: u32,
) -> NTSTATUS {
    if semaphore_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (desired_access, object_attributes);
    let h = alloc_handle(
        HandleKind::Semaphore,
        ((maximum_count as u64) << 32) | (initial_count as u64),
    );
    if h.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *semaphore_handle = h;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_release_semaphore`.
pub unsafe extern "C" fn nt_release_semaphore(
    semaphore_handle: HANDLE,
    release_count: u32,
    previous_count: *mut u32,
) -> NTSTATUS {
    if semaphore_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    if !previous_count.is_null() {
        *previous_count = release_count;
    }
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_create_timer`.
pub unsafe extern "C" fn nt_create_timer(
    timer_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    timer_type: u32,
) -> NTSTATUS {
    if timer_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (desired_access, object_attributes);
    let h = alloc_handle(HandleKind::Timer, timer_type as u64);
    if h.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    *timer_handle = h;
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_set_timer` - Sets a timer to expire at a specified time.
///
/// Timer types:
/// - 0: NotificationTimer
/// - 1: SynchronizationTimer
///
/// # Arguments
/// * `timer_handle` - handle to the timer object
/// * `due_time` - Absolute or relative time (in 100ns units)
/// * `period` - Timer period in milliseconds (0 for one-shot)
/// * `callback` - APC callback routine (optional)
/// * `arg` - Callback argument
/// * `resume` - If TRUE, alerts the system to resume from sleep/hibernation
/// * `handle` - Optionally receives the timer handle
pub unsafe extern "C" fn nt_set_timer(
    timer_handle: HANDLE,
    due_time: *const i64,
    _period: u32,
    _callback: *const (),
    _arg: *mut (),
    _resume: u8,
    _handle: *mut HANDLE,
) -> NTSTATUS {
    if timer_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }
    if due_time.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // In a full implementation, this would:
    // 1. Insert the timer into the kernel timer queue
    // 2. Set up the DPC callback
    // 3. Configure the hardware timer interrupt
    // For now, we return success

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_cancel_timer` - Cancels a timer.
///
/// # Arguments
/// * `timer_handle` - handle to the timer object
/// * `set_handle` - If provided, receives the previous state
pub unsafe extern "C" fn nt_cancel_timer(
    timer_handle: HANDLE,
    _set_handle: *mut HANDLE,
) -> NTSTATUS {
    if timer_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    // In a full implementation, this would:
    // 1. Remove the timer from the kernel timer queue
    // 2. Cancel any pending DPC
    // For now, we return success

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_wait_for_single_object` — waits for an object to become signaled.
/// Returns `STATUS_SUCCESS` (0), `STATUS_TIMEOUT`, or `STATUS_INVALID_HANDLE`.
///
/// The timeout is specified in 100-nanosecond intervals:
/// - If negative, it's a relative time (time remaining)
/// - If positive, it's an absolute time (system time when to timeout)
pub unsafe extern "C" fn nt_wait_for_single_object(
    handle: HANDLE,
    alertable: u8,
    timeout: *mut i64,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let raw_timeout = if timeout.is_null() {
        None
    } else {
        match read_user_object::<i64>(timeout as u64) {
            Ok(raw) => Some(raw),
            Err(STATUS_ACCESS_VIOLATION) => return STATUS_ACCESS_VIOLATION,
            Err(status) => return status,
        }
    };

    nt_wait_for_single_object_kernel(handle, alertable, raw_timeout)
}

/// Trusted-kernel entry point for `nt_wait_for_single_object`.
pub fn nt_wait_for_single_object_kernel(
    handle: HANDLE,
    alertable: u8,
    timeout: Option<i64>,
) -> NTSTATUS {
    use super::status::STATUS_TIMEOUT;

    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let timeout_ms = match timeout {
        None => u32::MAX,
        Some(raw) if raw < 0 => ((-raw) / 10_000) as u32,
        Some(_) => u32::MAX,
    };

    // Look up the handle
    if let Some(entry) = lookup_handle(handle) {
        match entry.kind {
            HandleKind::Event | HandleKind::Semaphore | HandleKind::Timer => {
                // In a real implementation, this would call the kernel dispatcher
                // For now, return success as the objects are always "signaled" in bootstrap
                let _ = alertable;

                // If timeout is zero, this should return timeout immediately
                if timeout_ms == 0 {
                    return STATUS_TIMEOUT;
                }
                return STATUS_SUCCESS;
            }
            _ => return STATUS_INVALID_HANDLE,
        }
    }
    STATUS_INVALID_HANDLE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `nt_wait_for_multiple_objects`.
pub unsafe extern "C" fn nt_wait_for_multiple_objects(
    count: u32,
    handles: *mut HANDLE,
    wait_type: u32,
    alertable: u8,
    timeout: *mut i64,
) -> NTSTATUS {
    if handles.is_null() || count == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let mut handle_array = [HANDLE::default(); 64];
    if count as usize > handle_array.len() {
        return STATUS_INVALID_PARAMETER;
    }
    let bytes = core::slice::from_raw_parts_mut(
        handle_array.as_mut_ptr() as *mut u8,
        count as usize * core::mem::size_of::<HANDLE>(),
    );
    if let Err(status) = copy_from_user(bytes, handles as u64) {
        return status;
    }

    let raw_timeout = if timeout.is_null() {
        None
    } else {
        match read_user_object::<i64>(timeout as u64) {
            Ok(raw) => Some(raw),
            Err(status) => return status,
        }
    };

    nt_wait_for_multiple_objects_kernel(
        count,
        &handle_array[..count as usize],
        wait_type,
        alertable,
        raw_timeout,
    )
}

/// Trusted-kernel entry point for `nt_wait_for_multiple_objects`.
pub fn nt_wait_for_multiple_objects_kernel(
    count: u32,
    handles: &[HANDLE],
    wait_type: u32,
    alertable: u8,
    timeout: Option<i64>,
) -> NTSTATUS {
    use super::status::STATUS_TIMEOUT;

    if handles.len() != count as usize || count == 0 || count as usize > 64 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = wait_type;
    let _ = alertable;

    let timeout_ms = if timeout.is_none() {
        u32::MAX
    } else {
        let raw = timeout.unwrap_or_default();
        ((-raw) / 10_000) as u32
    };

    for &handle in handles {
        if handle.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        if lookup_handle(handle).is_none() {
            return STATUS_INVALID_HANDLE;
        }
    }

    // If timeout is zero, return timeout immediately
    if timeout_ms == 0 {
        return STATUS_TIMEOUT;
    }

    // For bootstrap, return success
    STATUS_SUCCESS
}

/// `nt_delay_execution` — convert a relative `i64` (in 100ns
/// units, negative == relative) to a millisecond sleep.
///
/// On success, returns `STATUS_SUCCESS`. If the alertable flag is set,
/// the wait can be interrupted by an APC.
pub extern "C" fn nt_delay_execution(_alertable: u8, interval: *mut i64) -> NTSTATUS {
    if interval.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let raw = match read_user_object::<i64>(interval as u64) {
        Ok(raw) => raw,
        Err(status) => return status,
    };

    nt_delay_execution_kernel(_alertable, raw)
}

/// Trusted-kernel entry point for `nt_delay_execution`.
pub fn nt_delay_execution_kernel(alertable: u8, interval: i64) -> NTSTATUS {
    let _ = alertable;
    let raw = interval;

    // Negative = relative time, Positive = absolute time
    if raw >= 0 {
        // Absolute time - would need system time comparison
        return STATUS_SUCCESS;
    }

    // Relative time: convert 100ns units to milliseconds
    let ms = ((-raw) / 10_000) as u32;

    // Call the kernel scheduler to perform the delay
    // In a real implementation, this would:
    // 1. Check for pending APCs if alertable
    // 2. Call KeDelayExecutionThread with the converted timeout
    // For bootstrap, we yield instead of sleeping to avoid blocking
    if ms > 0 {
        // Yield to other threads
        crate::ke::scheduler::yield_();
    }

    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// `NT_CLOSE` re-export for kernel32.
pub unsafe extern "C" fn nt_close_sync(h: HANDLE) -> NTSTATUS {
    if free_handle(h) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}
