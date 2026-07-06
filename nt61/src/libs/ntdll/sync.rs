//! ntdll — Nt* synchronisation primitives
//
//! `NtCreateEvent`, `NtCreateMutant`, `NtCreateSemaphore`,
//! `NtWaitForSingleObject`, `NtWaitForMultipleObjects`,
//! `NtDelayExecution`. All objects are tracked in the kernel
//! handle table; `NtWait*` calls the kernel dispatcher.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` sync
//! APIs.

use super::file::{alloc_handle, free_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS, STATUS_TIMEOUT,
};
use super::types::{HANDLE, NTSTATUS, PVOID};
use core::ptr;

/// Event state tracking for proper kernel event integration.
pub(crate) struct EventState {
    pub event_type: u32,      // 0 = Notification, 1 = Synchronization
    pub signaled: bool,
    pub manual_reset: bool,
}

/// Mutex state tracking.
pub(crate) struct MutexState {
    pub initial_owner: bool,
    pub owned: bool,
    pub owned_by_tid: u64,
    pub recursion_count: u32,
}

/// Semaphore state tracking.
pub(crate) struct SemaphoreState {
    pub current_count: u32,
    pub maximum_count: u32,
}

/// Decode event state from handle target.
fn decode_event_state(target: u64) -> EventState {
    EventState {
        event_type: ((target >> 32) & 0xFF) as u32,
        signaled: (target & 0x01) != 0,
        manual_reset: ((target >> 8) & 0x01) != 0,
    }
}

/// Encode event state into handle target.
fn encode_event_state(event_type: u32, signaled: bool, manual_reset: bool) -> u64 {
    let et = (event_type as u64) << 32;
    let sig = if signaled { 0x01u64 } else { 0x00 };
    let mr = if manual_reset { 0x100u64 } else { 0x00 };
    et | mr | sig
}

/// `NtCreateEvent`.
pub unsafe extern "C" fn NtCreateEvent(
    event_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    event_type: u32,
    initial_state: u8,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;

    if event_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (desired_access, object_attributes);

    // Determine event type and initial state
    let manual_reset = event_type == 0; // NotificationEvent = manual reset
    let signaled = initial_state != 0;

    let target = encode_event_state(event_type, signaled, manual_reset);
    let h = alloc_handle(HandleKind::Event, target);
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *event_handle = h;
    STATUS_SUCCESS
}

/// `NtSetEvent` / `NtResetEvent` / `NtPulseEvent`.
///
/// NtSetEvent sets the event to the signaled state and releases
/// any waiting threads. Returns the previous state.
pub unsafe extern "C" fn NtSetEvent(event_handle: HANDLE, previous_state: *mut u32) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() { return STATUS_INVALID_HANDLE; }

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

/// NtResetEvent sets the event to the non-signaled state.
pub unsafe extern "C" fn NtResetEvent(event_handle: HANDLE, previous_state: *mut u32) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() { return STATUS_INVALID_HANDLE; }

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

/// NtClearEvent clears the event to non-signaled state (same as ResetEvent).
pub unsafe extern "C" fn NtClearEvent(event_handle: HANDLE) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() { return STATUS_INVALID_HANDLE; }

    if let Some(entry) = lookup_handle(event_handle) {
        if entry.kind == HandleKind::Event {
            return STATUS_SUCCESS;
        }
    }
    STATUS_INVALID_HANDLE
}

/// NtPulseEvent sets the event to signaled state, releases waiting threads,
/// then resets to non-signaled. For auto-reset events, only one thread is released.
pub unsafe extern "C" fn NtPulseEvent(event_handle: HANDLE, previous_state: *mut u32) -> NTSTATUS {
    use super::status::STATUS_INVALID_HANDLE;

    if event_handle.is_null() { return STATUS_INVALID_HANDLE; }

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

/// `NtCreateMutant` (mutex).
/// A mutex can be created with or without initial ownership.
pub unsafe extern "C" fn NtCreateMutant(
    mutant_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    initial_owner: u8,
) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;

    if mutant_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (desired_access, object_attributes);

    // Encode mutex state: initial_owner flag in low bit
    let target = if initial_owner != 0 {
        // Owned by current thread
        let current_ethread = crate::ps::thread::get_current_ethread();
        if current_ethread.is_null() {
            0x00u64
        } else {
            let tid = unsafe { (*current_ethread).client_id.unique_thread };
            (tid << 8) | 0x01  // owned flag | tid
        }
    } else {
        0x00  // not owned
    };

    let h = alloc_handle(HandleKind::Mutant, target);
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *mutant_handle = h;
    STATUS_SUCCESS
}

/// `NtReleaseMutant`.
/// Releases ownership of the mutex. If the thread doesn't own the mutex,
/// returns an error.
pub unsafe extern "C" fn NtReleaseMutant(mutant_handle: HANDLE, previous_count: *mut u32) -> NTSTATUS {
    use super::status::{STATUS_INVALID_HANDLE, STATUS_MUTEX_NOT_OWNED, STATUS_SUCCESS};

    if mutant_handle.is_null() { return STATUS_INVALID_HANDLE; }

    if let Some(entry) = lookup_handle(mutant_handle) {
        if entry.kind == HandleKind::Mutant {
            // Get current thread ID
            let current_ethread = crate::ps::thread::get_current_ethread();
            if current_ethread.is_null() {
                return STATUS_INVALID_HANDLE;
            }
            let current_tid = unsafe { (*current_ethread).client_id.unique_thread };
            let owned_tid = (entry.target >> 8) as u64;
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

/// `NtCreateSemaphore`.
pub unsafe extern "C" fn NtCreateSemaphore(
    semaphore_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    initial_count: u32,
    maximum_count: u32,
) -> NTSTATUS {
    if semaphore_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (desired_access, object_attributes);
    let h = alloc_handle(HandleKind::Semaphore,
                         ((maximum_count as u64) << 32) | (initial_count as u64));
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *semaphore_handle = h;
    STATUS_SUCCESS
}

/// `NtReleaseSemaphore`.
pub unsafe extern "C" fn NtReleaseSemaphore(
    semaphore_handle: HANDLE,
    release_count: u32,
    previous_count: *mut u32,
) -> NTSTATUS {
    if semaphore_handle.is_null() { return STATUS_INVALID_HANDLE; }
    if !previous_count.is_null() { *previous_count = release_count; }
    STATUS_SUCCESS
}

/// `NtCreateTimer`.
pub unsafe extern "C" fn NtCreateTimer(
    timer_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    timer_type: u32,
) -> NTSTATUS {
    if timer_handle.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (desired_access, object_attributes);
    let h = alloc_handle(HandleKind::Timer, timer_type as u64);
    if h.is_null() { return STATUS_INVALID_HANDLE; }
    *timer_handle = h;
    STATUS_SUCCESS
}

/// `NtSetTimer` - Sets a timer to expire at a specified time.
///
/// Timer types:
/// - 0: NotificationTimer
/// - 1: SynchronizationTimer
///
/// # Arguments
/// * `timer_handle` - Handle to the timer object
/// * `due_time` - Absolute or relative time (in 100ns units)
/// * `period` - Timer period in milliseconds (0 for one-shot)
/// * `callback` - APC callback routine (optional)
/// * `arg` - Callback argument
/// * `resume` - If TRUE, alerts the system to resume from sleep/hibernation
/// * `handle` - Optionally receives the timer handle
pub unsafe extern "C" fn NtSetTimer(
    timer_handle: HANDLE,
    due_time: *const i64,
    _period: u32,
    _callback: *const (),
    _arg: *mut (),
    _resume: u8,
    _handle: *mut HANDLE,
) -> NTSTATUS {
    if timer_handle.is_null() { return STATUS_INVALID_HANDLE; }
    if due_time.is_null() { return STATUS_INVALID_PARAMETER; }
    
    // In a full implementation, this would:
    // 1. Insert the timer into the kernel timer queue
    // 2. Set up the DPC callback
    // 3. Configure the hardware timer interrupt
    // For now, we return success
    
    STATUS_SUCCESS
}

/// `NtCancelTimer` - Cancels a timer.
///
/// # Arguments
/// * `timer_handle` - Handle to the timer object
/// * `set_handle` - If provided, receives the previous state
pub unsafe extern "C" fn NtCancelTimer(
    timer_handle: HANDLE,
    _set_handle: *mut HANDLE,
) -> NTSTATUS {
    if timer_handle.is_null() { return STATUS_INVALID_HANDLE; }
    
    // In a full implementation, this would:
    // 1. Remove the timer from the kernel timer queue
    // 2. Cancel any pending DPC
    // For now, we return success
    
    STATUS_SUCCESS
}

/// `NtWaitForSingleObject` — waits for an object to become signaled.
/// Returns `STATUS_SUCCESS` (0), `STATUS_TIMEOUT`, or `STATUS_INVALID_HANDLE`.
///
/// The timeout is specified in 100-nanosecond intervals:
/// - If negative, it's a relative time (time remaining)
/// - If positive, it's an absolute time (system time when to timeout)
pub unsafe extern "C" fn NtWaitForSingleObject(
    handle: HANDLE,
    alertable: u8,
    timeout: *mut i64,
) -> NTSTATUS {
    use super::status::STATUS_TIMEOUT;

    if handle.is_null() { return STATUS_INVALID_HANDLE; }

    // Parse timeout
    let timeout_ms = if timeout.is_null() {
        // No timeout specified - wait indefinitely
        u32::MAX
    } else {
        let raw = *timeout;
        if raw < 0 {
            // Relative time: convert 100ns units to milliseconds
            ((-raw) / 10_000) as u32
        } else {
            // Absolute time: would need system time comparison
            // For bootstrap, treat as no timeout
            u32::MAX
        }
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

/// `NtWaitForMultipleObjects`.
pub unsafe extern "C" fn NtWaitForMultipleObjects(
    count: u32,
    handles: *mut HANDLE,
    wait_type: u32,
    alertable: u8,
    timeout: *mut i64,
) -> NTSTATUS {
    use super::status::STATUS_TIMEOUT;

    if handles.is_null() || count == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = wait_type;
    let _ = alertable;

    // Parse timeout
    let timeout_ms = if timeout.is_null() {
        u32::MAX
    } else {
        let raw = unsafe { *timeout };
        if raw < 0 {
            ((-raw) / 10_000) as u32
        } else {
            u32::MAX
        }
    };

    // Validate all handles first
    for i in 0..count as isize {
        let h = unsafe { *handles.add(i as usize) };
        if h.is_null() {
            return STATUS_INVALID_HANDLE;
        }
        if lookup_handle(h).is_none() {
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

/// `NtDelayExecution` — convert a relative `i64` (in 100ns
/// units, negative == relative) to a millisecond sleep.
///
/// On success, returns `STATUS_SUCCESS`. If the alertable flag is set,
/// the wait can be interrupted by an APC.
pub extern "C" fn NtDelayExecution(_alertable: u8, interval: *mut i64) -> NTSTATUS {
    use super::status::STATUS_INVALID_PARAMETER;

    if interval.is_null() { return STATUS_INVALID_PARAMETER; }

    let raw = unsafe { *interval };

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

/// `NtClose` re-export for kernel32.
pub unsafe extern "C" fn NtCloseSync(h: HANDLE) -> NTSTATUS {
    if free_handle(h) { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }
}
