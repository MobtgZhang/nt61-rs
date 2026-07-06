//! CLFS File Control Block (FCB)
//
//! The FCB represents one open handle to a CLFS log. Multiple FCBs can
//! reference the same VCB. The FCB holds per-handle state such as the
//! client's current position in the log.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::context::ClfsClientContext;
use super::record::ClfsLsn;
use super::vcb::ClfsVcb;

// ============================================================================
// Open Mode
// ============================================================================

/// How the log was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClfsOpenMode {
    /// Open for reading only.
    Readonly,
    /// Open for writing only.
    Writeonly,
    /// Open for both reading and writing.
    ReadWrite,
    /// Open for appending (new records only).
    Append,
}

impl Default for ClfsOpenMode {
    fn default() -> Self {
        Self::ReadWrite
    }
}

// ============================================================================
// FCB Structure
// ============================================================================

/// File Control Block — represents one open handle to a CLFS log.
///
/// Each call to `ClfsCreateLogFile` or `ClfsOpenLogFile` creates one FCB.
/// Multiple FCBs can reference the same VCB (shared log).
///
/// The FCB holds:
/// - A reference to the VCB (the actual log)
/// - The client context for this handle
/// - Current read/write positions (LSNs)
/// - Handle-specific flags
pub struct ClfsFcb {
    /// Pointer to the VCB (the underlying log).
    /// This is a raw pointer because we need interior mutability.
    vcb: *mut ClfsVcb,

    /// Client ID for this handle (if registered as a client).
    client_id: u32,

    /// Client context for this handle.
    client_context: Option<ClfsClientContext>,

    /// Current read LSN — the LSN of the next record to read.
    read_lsn: ClfsLsn,

    /// Current write LSN — the LSN of the last written record.
    write_lsn: ClfsLsn,

    /// How the log was opened.
    open_mode: ClfsOpenMode,

    /// Handle flags.
    flags: u32,

    /// Sequence number for this handle (for debugging).
    handle_seq: u32,
}

impl ClfsFcb {
    /// Create a new FCB for a newly opened log.
    pub fn new(vcb: *mut ClfsVcb, client_id: u32, mode: ClfsOpenMode) -> Self {
        static HANDLE_SEQ: AtomicU32 = AtomicU32::new(0);

        Self {
            vcb,
            client_id,
            client_context: None,
            read_lsn: ClfsLsn::NULL,
            write_lsn: ClfsLsn::NULL,
            open_mode: mode,
            flags: 0,
            handle_seq: HANDLE_SEQ.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Get the VCB (the underlying log).
    ///
    /// # Safety
    /// The VCB pointer must still be valid. The FCB does not
    /// own the VCB — the VCB is freed when the last FCB is closed.
    pub unsafe fn vcb(&self) -> &ClfsVcb {
        &*self.vcb
    }

    /// Get a mutable reference to the VCB.
    ///
    /// # Safety
    /// The caller must ensure no other references to the VCB are
    /// held while this reference is used.
    pub unsafe fn vcb_mut(&mut self) -> &mut ClfsVcb {
        &mut *self.vcb
    }

    /// Get the client ID.
    #[inline]
    pub fn client_id(&self) -> u32 {
        self.client_id
    }

    /// Get the current read LSN.
    #[inline]
    pub fn read_lsn(&self) -> ClfsLsn {
        self.read_lsn
    }

    /// Set the current read LSN.
    #[inline]
    pub fn set_read_lsn(&mut self, lsn: ClfsLsn) {
        self.read_lsn = lsn;
    }

    /// Advance the read LSN to the next record.
    #[inline]
    pub fn advance_read_lsn(&mut self) {
        self.read_lsn = self.read_lsn.next();
    }

    /// Get the current write LSN.
    #[inline]
    pub fn write_lsn(&self) -> ClfsLsn {
        self.write_lsn
    }

    /// Set the current write LSN.
    #[inline]
    pub fn set_write_lsn(&mut self, lsn: ClfsLsn) {
        self.write_lsn = lsn;
    }

    /// Get the open mode.
    #[inline]
    pub fn open_mode(&self) -> ClfsOpenMode {
        self.open_mode
    }

    /// Check if this handle allows reading.
    #[inline]
    pub fn can_read(&self) -> bool {
        matches!(self.open_mode, ClfsOpenMode::Readonly | ClfsOpenMode::ReadWrite)
    }

    /// Check if this handle allows writing.
    #[inline]
    pub fn can_write(&self) -> bool {
        matches!(self.open_mode, ClfsOpenMode::Writeonly | ClfsOpenMode::ReadWrite | ClfsOpenMode::Append)
    }

    /// Get the handle sequence number.
    #[inline]
    pub fn handle_seq(&self) -> u32 {
        self.handle_seq
    }

    /// Check if this handle is valid for the given VCB.
    pub fn is_valid_for(&self, vcb_ptr: *const ClfsVcb) -> bool {
        self.vcb as *const _ == vcb_ptr
    }
}

impl Default for ClfsFcb {
    fn default() -> Self {
        Self {
            vcb: core::ptr::null_mut(),
            client_id: 0,
            client_context: None,
            read_lsn: ClfsLsn::NULL,
            write_lsn: ClfsLsn::NULL,
            open_mode: ClfsOpenMode::default(),
            flags: 0,
            handle_seq: 0,
        }
    }
}
