//! ntdll — Timer Objects (NT 6.1.7601)
//!
//! Waitable timer objects for scheduled execution and delays.
//! Timers can be manual-reset or synchronization (auto-reset).
//!
//! References:
//!   * MSDN Library "Windows 7" — Timer Objects
//!   * Windows Internals 7th Ed. - Chapter 8

use super::file::{alloc_handle, lookup_handle, HandleKind};
use super::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_TIMER_NOT_CANCELED,
};
use super::types::{HANDLE, NTSTATUS, PVOID, LARGE_INTEGER, LargeInteger};
use crate::ke::sync::Spinlock;
use core::ptr;


#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    NotificationTimer = 0, // Manual-reset
    SynchronizationTimer = 1, // Auto-reset
}

#[derive(Clone, Copy)]
struct TimerState {
    timer_type: u32,
    due_time: LargeInteger,  // Changed from i64 to LargeInteger
    period: i32, // Milliseconds (0 = one-shot)
    signaled: bool,
    apc_routine: PVOID,
    apc_context: PVOID,
}

impl TimerState {
    const fn new() -> Self {
        Self {
            timer_type: 0,
            due_time: LargeInteger { quad_part: 0 },
            period: 0,
            signaled: false,
            apc_routine: ptr::null_mut(),
            apc_context: ptr::null_mut(),
        }
    }
}

const MAX_TIMERS: usize = 64;
static TIMER_STATES: Spinlock<[Option<TimerState>; MAX_TIMERS]> =
    Spinlock::new([None; MAX_TIMERS]);


pub unsafe extern "C" fn NtCreateTimer(
    timer_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    timer_type: u32,
) -> NTSTATUS {
    if timer_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if timer_type > 1 {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = (desired_access, object_attributes);

    let mut states = TIMER_STATES.lock();
    let timer_id = match states.iter().position(|s| s.is_none()) {
        Some(idx) => idx,
        None => return STATUS_INVALID_HANDLE,
    };

    let mut state = TimerState::new();
    state.timer_type = timer_type;
    states[timer_id] = Some(state);
    drop(states);

    let h = alloc_handle(HandleKind::Timer, timer_id as u64);
    if h.is_null() {
        let mut states = TIMER_STATES.lock();
        states[timer_id] = None;
        return STATUS_INVALID_HANDLE;
    }

    *timer_handle = h;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtOpenTimer(
    timer_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
) -> NTSTATUS {
    if timer_handle.is_null() || object_attributes.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = desired_access;

    STATUS_INVALID_PARAMETER
}


pub type TimerApcRoutine = unsafe extern "C" fn(
    timer_context: PVOID,
    timer_low_value: u32,
    timer_high_value: i32,
);

pub unsafe extern "C" fn NtSetTimer(
    timer_handle: HANDLE,
    due_time: *const LARGE_INTEGER,
    timer_apc_routine: PVOID,
    timer_context: PVOID,
    resume: u8,
    period: i32,
    previous_state: *mut u8,
) -> NTSTATUS {
    if timer_handle.is_null() || due_time.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let entry = match lookup_handle(timer_handle) {
        Some(e) if e.kind == HandleKind::Timer => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let timer_id = entry.target as usize;
    if timer_id >= MAX_TIMERS {
        return STATUS_INVALID_HANDLE;
    }

    let _ = resume;

    let mut states = TIMER_STATES.lock();
    let state = match &mut states[timer_id] {
        Some(s) => s,
        None => return STATUS_INVALID_HANDLE,
    };

    if !previous_state.is_null() {
        *previous_state = if state.signaled { 1 } else { 0 };
    }

    state.due_time = *due_time;
    state.period = period;
    state.signaled = false;
    state.apc_routine = timer_apc_routine;
    state.apc_context = timer_context;


    STATUS_SUCCESS
}


pub unsafe extern "C" fn NtCancelTimer(
    timer_handle: HANDLE,
    current_state: *mut u8,
) -> NTSTATUS {
    if timer_handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    let entry = match lookup_handle(timer_handle) {
        Some(e) if e.kind == HandleKind::Timer => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let timer_id = entry.target as usize;
    if timer_id >= MAX_TIMERS {
        return STATUS_INVALID_HANDLE;
    }

    let mut states = TIMER_STATES.lock();
    let state = match &mut states[timer_id] {
        Some(s) => s,
        None => return STATUS_INVALID_HANDLE,
    };

    if !current_state.is_null() {
        *current_state = if state.signaled { 1 } else { 0 };
    }

    state.due_time = LargeInteger { quad_part: 0 };
    state.period = 0;
    state.signaled = false;


    STATUS_SUCCESS
}


#[repr(u32)]
pub enum TimerInformationClass {
    TimerBasicInformation = 0,
}

#[repr(C)]
pub struct TimerBasicInformation {
    pub remaining_time: LARGE_INTEGER,
    pub timer_state: u8,
}

pub unsafe extern "C" fn NtQueryTimer(
    timer_handle: HANDLE,
    timer_information_class: u32,
    timer_information: PVOID,
    timer_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if timer_handle.is_null() || timer_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let entry = match lookup_handle(timer_handle) {
        Some(e) if e.kind == HandleKind::Timer => e,
        _ => return STATUS_INVALID_HANDLE,
    };

    let timer_id = entry.target as usize;
    if timer_id >= MAX_TIMERS {
        return STATUS_INVALID_HANDLE;
    }

    if timer_information_class != TimerInformationClass::TimerBasicInformation as u32 {
        return STATUS_INVALID_PARAMETER;
    }

    if timer_information_length < core::mem::size_of::<TimerBasicInformation>() as u32 {
        return super::status::STATUS_BUFFER_TOO_SMALL;
    }

    let states = TIMER_STATES.lock();
    let state = match &states[timer_id] {
        Some(s) => s,
        None => return STATUS_INVALID_HANDLE,
    };

    let info = timer_information as *mut TimerBasicInformation;
    (*info).remaining_time = state.due_time;
    (*info).timer_state = if state.signaled { 1 } else { 0 };

    if !return_length.is_null() {
        *return_length = core::mem::size_of::<TimerBasicInformation>() as u32;
    }

    STATUS_SUCCESS
}
