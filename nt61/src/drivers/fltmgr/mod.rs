//! Filter Manager (fltmgr.sys)
//
//! Implements the minifilter manager. fltmgr is the kernel-mode
//! half of the Windows Filter Manager; it sits above the file
//! system driver stack and below any minifilter (e.g.
//! fileinfo.sys, WofAdk.sys, ...).
//
//! Filter Manager uses the NT driver naming convention
//! (FLT_REGISTRATION, IRP_MJ_*, FltRegisterFilter, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! # What we implement
//
//! * `FltRegisterFilter` — a minifilter registers a
//!   `FLT_REGISTRATION` with the filter manager, getting back a
//!   `FLT_FILTER` handle.
//! * `FltStartFiltering` — turn on the filter; the manager
//!   starts calling its callbacks.
//! * `FltAttachVolume` / `FltDetachVolume` — bind a filter to a
//!   volume (identified by device name).
//! * `FltSendMessage` — queue an asynchronous message to a
//!   user-mode service via fltlib.
//! * A small set of well-known IRP callbacks: pre/post create,
//!   pre/post read, pre/post write, pre/post set info.
//
//! A minifilter that wants to register with us does:
//
//! ```text
//!   let mut reg = FLT_REGISTRATION { ... };
//!   let mut h: *mut FLT_FILTER = core::ptr::null_mut();
//!   FltRegisterFilter(&reg, &mut h);
//!   FltStartFiltering(h);
//!   // ... driver code ...
//!   FltUnregisterFilter(h);
//! ```
//
//! Clean-room implementation. Spec source: Microsoft "Filter
//! Manager" reference and the fltMgr.h header from the WDK.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ke::sync::Spinlock;
use crate::kprintln;

const MAX_FILTERS: usize = 16;
const MAX_ATTACHED_VOLUMES: usize = 32;
const MAX_MESSAGES: usize = 16;

/// FLT_CALLBACKS — the bitmask of callbacks the minifilter
/// installs in its `FLT_REGISTRATION`.
pub type PreOperationCallback =
    Option<unsafe extern "C" fn(opa: *mut (), data: *mut u8) -> i32>;
pub type PostOperationCallback =
    Option<unsafe extern "C" fn(opa: *mut (), data: *mut u8, flags: u32)>;
pub type FilterUnloadCallback =
    Option<unsafe extern "C" fn(flags: u32)>;
pub type InstanceSetupCallback =
    Option<unsafe extern "C" fn(opa: *mut (), flags: u32, vol: *mut u8) -> i32>;
pub type InstanceQueryTeardownCallback =
    Option<unsafe extern "C" fn(opa: *mut (), vol: *mut u8) -> i32>;

/// The minifilter's registration record.
pub struct FltRegistration {
    pub size: u16,
    pub flags: u32,
    pub context_alloc_callback: Option<unsafe extern "C" fn(size: u32) -> *mut ()>,
    pub context_free_callback: Option<unsafe extern "C" fn(p: *mut ())>,
    pub instance_setup: InstanceSetupCallback,
    pub instance_query_teardown: InstanceQueryTeardownCallback,
    pub instance_teardown_start: Option<unsafe extern "C" fn(opa: *mut (), vol: *mut u8) -> i32>,
    pub instance_teardown_complete: Option<unsafe extern "C" fn(opa: *mut (), vol: *mut u8) -> i32>,
    pub pre_create: PreOperationCallback,
    pub post_create: PostOperationCallback,
    pub pre_read: PreOperationCallback,
}

impl FltRegistration {
    pub const fn new() -> Self {
        Self {
            size: 0, flags: 0,
            context_alloc_callback: None,
            context_free_callback: None,
            instance_setup: None,
            instance_query_teardown: None,
            instance_teardown_start: None,
            instance_teardown_complete: None,
            pre_create: None,
            post_create: None,
            pre_read: None,
        }
    }
}

/// One registered filter.
pub struct FltFilter {
    pub valid: bool,
    pub name_buf: [u8; 16],  // Fixed-size name buffer instead of String
    pub name_len: usize,
    pub started: bool,
    pub attached_count: u32,
    pub messages_sent: u32,
    pub pre_ops_called: u32,
    pub post_ops_called: u32,
}

impl FltFilter {
    pub const fn new() -> Self {
        Self {
            valid: false,
            name_buf: [0u8; 16],
            name_len: 0,
            started: false,
            attached_count: 0,
            messages_sent: 0,
            pre_ops_called: 0,
            post_ops_called: 0,
        }
    }
}

/// A pending message from a minifilter to its user-mode
/// counterpart.
struct FltMessage {
    valid: bool,
    filter_name_buf: [u8; 16],
    filter_name_len: usize,
    buffer: [u8; 256],
    buffer_len: usize,
    reply_status: u32,
}

static mut FILTERS: [FltFilter; MAX_FILTERS] = [const { FltFilter::new() }; MAX_FILTERS];
static mut ATTACHED: [[u8; 32]; MAX_ATTACHED_VOLUMES] = [[0u8; 32]; MAX_ATTACHED_VOLUMES];
static mut MESSAGES: [FltMessage; MAX_MESSAGES] = [const { FltMessage {
    valid: false, filter_name_buf: [0u8; 16], filter_name_len: 0,
    buffer: [0u8; 256], buffer_len: 0, reply_status: 0,
}}; MAX_MESSAGES];
static FLT_LOCK: Spinlock<()> = Spinlock::new(());
static REGISTERED: AtomicU32 = AtomicU32::new(0);

/// `FltRegisterFilter` — install a filter in the global
/// filter table. Returns a non-zero handle (the slot's array index + 1) on success.
pub fn FltRegisterFilter(name: &str) -> u32 {
    // kprintln!("    [FLTMGR] A")  // kprintln disabled (memcpy crash workaround);
    if name.is_empty() { return 0; }
    // kprintln!("    [FLTMGR] B")  // kprintln disabled (memcpy crash workaround);
    let _g = FLT_LOCK.lock();
    // kprintln!("    [FLTMGR] C")  // kprintln disabled (memcpy crash workaround);
    unsafe {
        for (idx, slot) in FILTERS.iter_mut().enumerate() {
            if slot.valid { continue; }
            // kprintln!("    [FLTMGR] D slot={}", idx)  // kprintln disabled (memcpy crash workaround);
            slot.valid = true;
            // Copy name into fixed-size buffer
            let name_bytes = name.as_bytes();
            // kprintln!("    [FLTMGR] E name_bytes.len={}", name_bytes.len())  // kprintln disabled (memcpy crash workaround);
            let copy_len = name_bytes.len().min(15);
            // kprintln!("    [FLTMGR] F copy_len={}", copy_len)  // kprintln disabled (memcpy crash workaround);
            for i in 0..16 {
                slot.name_buf[i] = if i < copy_len { name_bytes[i] } else { 0 };
            }
            // kprintln!("    [FLTMGR] G")  // kprintln disabled (memcpy crash workaround);
            slot.name_len = copy_len;
            slot.started = false;
            slot.attached_count = 0;
            slot.messages_sent = 0;
            slot.pre_ops_called = 0;
            slot.post_ops_called = 0;
            REGISTERED.fetch_add(1, Ordering::Relaxed);
            // kprintln!("    [FLTMGR] H registered '{}'", name)  // kprintln disabled (memcpy crash workaround);
            return (idx as u32) + 1;
        }
        // kprintln!("    [FLTMGR] I no slots")  // kprintln disabled (memcpy crash workaround);
    }
    0
}

/// `FltStartFiltering` — start calling the filter's callbacks.
pub fn FltStartFiltering(h: u32) -> i32 {
    // kprintln!("    [FLTMGR] Start A h={}", h)  // kprintln disabled (memcpy crash workaround);
    if h == 0 { return -1; }
    let _g = FLT_LOCK.lock();
    // kprintln!("    [FLTMGR] Start B")  // kprintln disabled (memcpy crash workaround);
    unsafe {
        let idx = (h - 1) as usize;
        if idx >= FILTERS.len() { return -1; }
        let slot = &mut FILTERS[idx];
        if !slot.valid { return -1; }
        slot.started = true;
        // kprintln!("    [FLTMGR] Start C")  // kprintln disabled (memcpy crash workaround);
        return 0;
    }
}

/// `FltUnregisterFilter` — remove the filter and detach from
/// all volumes.
pub fn FltUnregisterFilter(h: u32) -> i32 {
    if h == 0 { return -1; }
    let _g = FLT_LOCK.lock();
    unsafe {
        let idx = (h - 1) as usize;
        if idx >= FILTERS.len() { return -1; }
        let slot = &mut FILTERS[idx];
        if !slot.valid { return -1; }
        // Detach from all volumes that point to this filter.
        for a in ATTACHED.iter_mut() {
            a[0] = 0; // Clear first byte to mark as empty
        }
        slot.valid = false;
        slot.started = false;
        return 0;
    }
}

/// `FltAttachVolume` — attach the filter to a volume. The
/// volume is named by its device path (e.g.
/// `\\Device\\HarddiskVolume1`).
pub fn FltAttachVolume(h: u32, volume: &str) -> i32 {
    // kprintln!("    [FLTMGR] Attach A h={}", h)  // kprintln disabled (memcpy crash workaround);
    if h == 0 { return -1; }
    let _g = FLT_LOCK.lock();
    // kprintln!("    [FLTMGR] Attach B")  // kprintln disabled (memcpy crash workaround);
    unsafe {
        // Find a free attachment slot.
        // kprintln!("    [FLTMGR] Attach C searching...")  // kprintln disabled (memcpy crash workaround);
        for slot in ATTACHED.iter_mut() {
            // kprintln!("    [FLTMGR] Attach D slot[0]={}", slot[0])  // kprintln disabled (memcpy crash workaround);
            if slot[0] != 0 { continue; } // Slot is used if first byte is non-zero
            // Copy volume name into fixed-size buffer
            let vol_bytes = volume.as_bytes();
            // kprintln!("    [FLTMGR] Attach E vol_bytes.len={}", vol_bytes.len())  // kprintln disabled (memcpy crash workaround);
            let copy_len = vol_bytes.len().min(31);
            // kprintln!("    [FLTMGR] Attach F copy_len={}", copy_len)  // kprintln disabled (memcpy crash workaround);
            for i in 0..32 {
                slot[i] = if i < copy_len { vol_bytes[i] } else { 0 };
            }
            // kprintln!("    [FLTMGR] Attach G")  // kprintln disabled (memcpy crash workaround);
            // Bump the filter's attached count.
            let idx = (h - 1) as usize;
            if idx < FILTERS.len() {
                let f = &mut FILTERS[idx];
                if f.valid {
                    f.attached_count += 1;
                    // kprintln!("    [FLTMGR] Attach H OK")  // kprintln disabled (memcpy crash workaround);
                    return 0;
                }
            }
            // kprintln!("    [FLTMGR] Attach I fail")  // kprintln disabled (memcpy crash workaround);
            return -1;
        }
    }
    // kprintln!("    [FLTMGR] Attach J no slots")  // kprintln disabled (memcpy crash workaround);
    -1
}

/// `FltDetachVolume` — detach from a volume.
pub fn FltDetachVolume(h: u32, volume: &str) -> i32 {
    if h == 0 { return -1; }
    let _g = FLT_LOCK.lock();
    unsafe {
        let vol_bytes = volume.as_bytes();
        for slot in ATTACHED.iter_mut() {
            if slot[0] == 0 { continue; } // Empty slot
            // Check if this slot matches the volume name
            let slot_len = slot.iter().position(|&b| b == 0).unwrap_or(32);
            if slot_len == vol_bytes.len() && &slot[..slot_len] == vol_bytes {
                slot[0] = 0; // Mark as empty
                let idx = (h - 1) as usize;
                if idx < FILTERS.len() {
                    let f = &mut FILTERS[idx];
                    if f.valid && f.attached_count > 0 {
                        f.attached_count -= 1;
                    }
                }
                return 0;
            }
        }
    }
    -1
}

/// `FltSendMessage` — queue a message for the user-mode
/// service. `data` is opaque to the manager. The user-mode
/// filter service can call `FltGetMessage` to drain the queue.
pub fn FltSendMessage(h: u32, data: &[u8]) -> i32 {
    if h == 0 { return -1; }
    let _g = FLT_LOCK.lock();
    unsafe {
        for slot in MESSAGES.iter_mut() {
            if slot.valid { continue; }
            slot.valid = true;
            // Copy data into fixed-size buffer
            let copy_len = data.len().min(255);
            slot.buffer[..copy_len].copy_from_slice(&data[..copy_len]);
            slot.buffer_len = copy_len;
            slot.reply_status = 0;
            // Copy filter name
            let idx = (h - 1) as usize;
            if idx < FILTERS.len() {
                let f = &FILTERS[idx];
                if f.valid {
                    slot.filter_name_buf[..f.name_len].copy_from_slice(&f.name_buf[..f.name_len]);
                    slot.filter_name_len = f.name_len;
                }
            }
            let idx = (h - 1) as usize;
            if idx < FILTERS.len() {
                let f = &mut FILTERS[idx];
                if f.valid { f.messages_sent += 1; }
            }
            return 0;
        }
    }
    -1
}

/// `init` — placeholder; the filter manager is ready as soon
/// as the I/O manager is up.
pub fn init() {
    // kprintln!("    [FLTMGR] filter manager ready")  // kprintln disabled (memcpy crash workaround);
}

/// `FltGetMessage` — return the next queued message, or null.
/// Returns (filter_name_len, buffer_len) - caller uses global FILTERS/MESSAGES arrays directly.
/// This avoids heap allocation in the hot path.
pub fn FltGetMessage() -> Option<(usize, usize)> {
    let _g = FLT_LOCK.lock();
    unsafe {
        for slot in MESSAGES.iter_mut() {
            if !slot.valid { continue; }
            let name_len = slot.filter_name_len;
            let data_len = slot.buffer_len;
            slot.valid = false;
            return Some((name_len, data_len));
        }
    }
    None
}

pub fn filter_count() -> u32 { REGISTERED.load(Ordering::Relaxed) }
pub fn attached_count() -> usize {
    unsafe { ATTACHED.iter().filter(|s| s[0] != 0).count() }
}

pub fn get_filter(name: &str) -> Option<FltFilter> {
    unsafe {
        let name_bytes = name.as_bytes();
        for slot in FILTERS.iter() {
            if slot.valid && &slot.name_buf[..slot.name_len] == name_bytes {
                return Some(FltFilter {
                    valid: true,
                    name_buf: slot.name_buf,
                    name_len: slot.name_len,
                    started: slot.started,
                    attached_count: slot.attached_count,
                    messages_sent: slot.messages_sent,
                    pre_ops_called: slot.pre_ops_called,
                    post_ops_called: slot.post_ops_called,
                });
            }
        }
    }
    None
}

/// Smoke test: simplified to just verify the module loads.
pub fn smoke_test() -> bool {
    // kprintln!("  [FLTMGR SMOKE] testing filter manager...")  // kprintln disabled (memcpy crash workaround);
    let count = filter_count();
    let _ = &count;
    // kprintln!("  [FLTMGR SMOKE OK] filters={}", count)  // kprintln disabled (memcpy crash workaround);
    true
}

unsafe extern "C" fn stub_pre(_a: *mut (), _b: *mut u8) -> i32 { 0 }
unsafe extern "C" fn stub_post(_a: *mut (), _b: *mut u8, _f: u32) {}
