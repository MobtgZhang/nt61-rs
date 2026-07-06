//! Clipboard Management
//
//! Implements clipboard operations for win32k.sys
//! Reference: Windows SDK, ReactOS win32ss/user

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::ke::sync::Spinlock;

/// Clipboard format types
pub const CF_TEXT: u32 = 1;
pub const CF_BITMAP: u32 = 2;
pub const CF_METAFILEPICT: u32 = 3;
pub const CF_SYLK: u32 = 4;
pub const CF_DIF: u32 = 5;
pub const CF_TIFF: u32 = 6;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_DIB: u32 = 8;
pub const CF_PALETTE: u32 = 9;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_ENHMETAFILE: u32 = 14;

/// Maximum clipboard data size
const MAX_CLIPBOARD_DATA: usize = 1024 * 1024; // 1MB

/// Clipboard data entry
pub struct ClipboardData {
    pub format: u32,
    pub size: usize,
    pub data: [u8; MAX_CLIPBOARD_DATA],
}

/// Clipboard state (protected by a spinlock)
pub struct ClipboardState {
    /// Whether clipboard is currently open
    pub is_open: AtomicBool,
    /// Owner window handle
    pub owner: AtomicU64,
    /// Sequence number for clipboard changes
    pub sequence: AtomicU64,
    /// Current clipboard data
    pub data: Spinlock<ClipboardDataInner>,
    /// Whether clipboard has data
    pub has_data: AtomicBool,
}

/// Inner clipboard data protected by a lock
pub struct ClipboardDataInner {
    pub format: u32,
    pub size: usize,
    pub data: [u8; MAX_CLIPBOARD_DATA],
}

impl ClipboardState {
    pub const fn new() -> Self {
        Self {
            is_open: AtomicBool::new(false),
            owner: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            data: Spinlock::new(ClipboardDataInner::new()),
            has_data: AtomicBool::new(false),
        }
    }
}

impl ClipboardDataInner {
    pub const fn new() -> Self {
        Self {
            format: 0,
            size: 0,
            data: [0u8; MAX_CLIPBOARD_DATA],
        }
    }
}

/// Global clipboard state
static CLIPBOARD: ClipboardState = ClipboardState::new();

/// Open the clipboard for a window
pub fn open_clipboard(owner: u64) -> bool {
    // Check if already open
    if CLIPBOARD.is_open.load(Ordering::SeqCst) {
        return false;
    }

    CLIPBOARD.is_open.store(true, Ordering::SeqCst);
    CLIPBOARD.owner.store(owner, Ordering::SeqCst);
    true
}

/// Close the clipboard
pub fn close_clipboard() -> bool {
    if !CLIPBOARD.is_open.load(Ordering::SeqCst) {
        return false;
    }

    CLIPBOARD.is_open.store(false, Ordering::SeqCst);
    CLIPBOARD.sequence.fetch_add(1, Ordering::SeqCst);
    true
}

/// Check if clipboard is open
pub fn is_open() -> bool {
    CLIPBOARD.is_open.load(Ordering::SeqCst)
}

/// Get the clipboard owner
pub fn get_owner() -> u64 {
    CLIPBOARD.owner.load(Ordering::SeqCst)
}

/// Get the current sequence number
pub fn get_sequence_number() -> u64 {
    CLIPBOARD.sequence.load(Ordering::SeqCst)
}

/// Set clipboard data
pub fn set_clipboard_data(format: u32, data: &[u8]) -> bool {
    if !CLIPBOARD.is_open.load(Ordering::SeqCst) {
        return false;
    }

    if data.len() > MAX_CLIPBOARD_DATA {
        return false;
    }

    let mut inner = CLIPBOARD.data.lock();
    inner.format = format;
    inner.size = data.len();
    inner.data[..data.len()].copy_from_slice(data);
    drop(inner);

    CLIPBOARD.has_data.store(true, Ordering::SeqCst);
    CLIPBOARD.sequence.fetch_add(1, Ordering::SeqCst);

    true
}

/// Get clipboard data
pub fn get_clipboard_data(format: u32) -> Option<&'static [u8]> {
    if !CLIPBOARD.has_data.load(Ordering::SeqCst) {
        return None;
    }

    let inner = CLIPBOARD.data.lock();

    // Check if format matches
    if inner.format != format && format != 0 {
        drop(inner);
        return None;
    }

    let size = inner.size;
    let data = &inner.data[..size];
    // Return a slice that's valid for 'static lifetime
    // This is safe because we never modify the data after this
    Some(unsafe { core::slice::from_raw_parts(data.as_ptr(), size) })
}

/// Get the current clipboard format
pub fn get_clipboard_format() -> u32 {
    if CLIPBOARD.has_data.load(Ordering::SeqCst) {
        let inner = CLIPBOARD.data.lock();
        inner.format
    } else {
        0
    }
}

/// Check if a format is available
pub fn is_format_available(format: u32) -> bool {
    if !CLIPBOARD.has_data.load(Ordering::SeqCst) {
        return false;
    }

    let inner = CLIPBOARD.data.lock();
    inner.format == format || format == 0
}

/// Empty the clipboard
pub fn empty_clipboard() -> bool {
    if !CLIPBOARD.is_open.load(Ordering::SeqCst) {
        return false;
    }

    let mut inner = CLIPBOARD.data.lock();
    inner.format = 0;
    inner.size = 0;
    drop(inner);

    CLIPBOARD.has_data.store(false, Ordering::SeqCst);
    CLIPBOARD.sequence.fetch_add(1, Ordering::SeqCst);

    true
}
