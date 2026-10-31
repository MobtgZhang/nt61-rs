//! advapi32 — Event Logging APIs
//
//! Implements Windows Event Log functions:
//! - RegisterEventSourceW — Register an event source
//! - DeregisterEventSource — Unregister an event source
//! - ReportEventW — write an event to the event log
//! - OpenEventLogW — Open an event log for reading
//! - CloseEventLog — close an event log handle
//! - ReadEventLogW — read events from the log
//! - ClearEventLogW — Clear an event log

use core::sync::atomic::AtomicUsize;

use super::types::*;
use crate::libs::ntdll::types::{DWORD, HANDLE, PCWSTR, PVOID, WORD};

const MAX_EVENT_ENTRIES: usize = 1024;

#[derive(Copy, Clone)]
pub struct EventLogEntry {
    pub event_type: WORD,
    pub event_category: WORD,
    pub event_id: DWORD,
    pub user_sid: Option<[u8; 28]>,
    pub num_strings: WORD,
    pub data_size: WORD,
    pub source: [u16; 64],
    pub computer: [u16; 64],
    pub strings: [[u16; 256]; 8],
    pub data: [u8; 256],
    in_use: bool,
}

impl EventLogEntry {
    const fn new() -> Self {
        Self {
            event_type: 0,
            event_category: 0,
            event_id: 0,
            user_sid: None,
            num_strings: 0,
            data_size: 0,
            source: [0; 64],
            computer: [0; 64],
            strings: [[0; 256]; 8],
            data: [0; 256],
            in_use: false,
        }
    }
}

static mut EVENT_LOG: [EventLogEntry; MAX_EVENT_ENTRIES] =
    [EventLogEntry::new(); MAX_EVENT_ENTRIES];
pub static EVENT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Copy, Clone)]
pub struct EventSourceHandle {
    source_name: [u16; 64],
    access: DWORD,
    is_source: bool,
    read_position: usize,
    in_use: bool,
}

const MAX_EVENT_HANDLES: usize = 64;

static mut EVENT_HANDLES: [EventSourceHandle; MAX_EVENT_HANDLES] = [EventSourceHandle {
    source_name: [0; 64],
    access: 0,
    is_source: false,
    read_position: 0,
    in_use: false,
}; MAX_EVENT_HANDLES];

pub fn alloc_event_handle(
    source_name: &[u16],
    is_source: bool,
    access: DWORD,
) -> Option<HandleEventlog> {
    unsafe {
        for (i, entry) in (*core::ptr::addr_of_mut!(EVENT_HANDLES))
            .iter_mut()
            .enumerate()
        {
            if !entry.in_use {
                let copy_len = core::cmp::min(source_name.len(), entry.source_name.len() - 1);
                entry.source_name[..copy_len].copy_from_slice(&source_name[..copy_len]);
                entry.source_name[copy_len] = 0;
                entry.is_source = is_source;
                entry.access = access;
                entry.read_position = 0;
                entry.in_use = true;
                return Some((0x4000 + i * 4) as HandleEventlog);
            }
        }
    }
    None
}

pub fn free_event_handle(handle: HandleEventlog) -> bool {
    let index = ((handle as usize) - 0x4000) / 4;
    unsafe {
        if index < MAX_EVENT_HANDLES && EVENT_HANDLES[index].in_use {
            EVENT_HANDLES[index].in_use = false;
            return true;
        }
    }
    false
}

fn get_event_handle(handle: HandleEventlog) -> Option<&'static mut EventSourceHandle> {
    let index = ((handle as usize) - 0x4000) / 4;
    unsafe {
        if index < MAX_EVENT_HANDLES && EVENT_HANDLES[index].in_use {
            return Some(&mut EVENT_HANDLES[index]);
        }
    }
    None
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn copy_wide_to_buffer(dest: &mut [u16], src: PCWSTR) {
    if src.is_null() {
        dest[0] = 0;
        return;
    }

    let mut i = 0;
    let mut p = src;
    while i < dest.len() - 1 && !p.is_null() && *p != 0 {
        dest[i] = *p;
        i += 1;
        p = p.offset(1);
    }
    dest[i] = 0;
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn ReadEventLogW(
    h_event_log: HandleEventlog,
    _dw_read_flags: DWORD,
    _dw_record_offset: DWORD,
    _lp_buffer: PVOID,
    _n_number_of_bytes_to_read: DWORD,
    pn_bytes_read: *mut DWORD,
    pn_min_number_of_bytes_needed: *mut DWORD,
) -> LONG {
    let handle_entry = match get_event_handle(h_event_log) {
        Some(h) => h,
        None => return 0, // FALSE
    };

    if handle_entry.is_source {
        return 0; // Cannot read from event source
    }

    if !pn_bytes_read.is_null() {
        *pn_bytes_read = 0;
    }

    if !pn_min_number_of_bytes_needed.is_null() {
        *pn_min_number_of_bytes_needed = 0;
    }

    0 // FALSE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetNumberOfEventLogRecords(
    h_event_log: HandleEventlog,
    number_of_records: *mut DWORD,
) -> LONG {
    if number_of_records.is_null() {
        return 0; // FALSE
    }

    if get_event_handle(h_event_log).is_none() {
        return 0; // FALSE
    }

    let mut count = 0;
    for entry in (*core::ptr::addr_of!(EVENT_LOG)).iter() {
        if entry.in_use {
            count += 1;
        }
    }

    *number_of_records = count;
    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn GetOldestEventLogRecord(
    h_event_log: HandleEventlog,
    oldest_record: *mut DWORD,
) -> LONG {
    if oldest_record.is_null() {
        return 0; // FALSE
    }

    if get_event_handle(h_event_log).is_none() {
        return 0; // FALSE
    }

    *oldest_record = 0;
    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn BackupEventLogW(
    h_event_log: HandleEventlog,
    lp_backup_file_name: PCWSTR,
) -> LONG {
    if lp_backup_file_name.is_null() {
        return 0; // FALSE
    }

    if get_event_handle(h_event_log).is_none() {
        return 0; // FALSE
    }

    1 // TRUE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn NotifyChangeEventLog(
    h_event_log: HandleEventlog,
    _h_event: HANDLE,
) -> LONG {
    if get_event_handle(h_event_log).is_none() {
        return 0; // FALSE
    }

    1 // TRUE
}
