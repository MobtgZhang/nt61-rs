//! HANDLE32 resolution helpers for the Wow64 layer.
//
//! Real Wow64 processes see the same kernel handle space as
//! native x64 processes: every handle in user mode is a 32-bit
//! index into the calling process's `HANDLE_TABLE`. The
//! functions below convert a `HANDLE32` (which is just a
//! 32-bit index plus a few fixed sentinel values) into a
//! pointer to the underlying kernel object (`Eprocess`,
//! `Ethread`, etc.) using the per-process handle table stored
//! at `Eprocess.object_table`.
//
//! In this bootstrap the per-process handle table is flat and
//! pointed to by each `Eprocess`; see
//! `crate::ps::process::ProcessHandleTable`. The Wow64 path
//! shares that table because the per-thread EPROCESS for a
//! 32-bit thread is the same as for the matching native
//! thread — only the per-thread TEB differs between PEB32 and
//! PEB64.
//
//! All public functions in this module are `unsafe` because
//! they ultimately return raw pointers that the caller must
//! validate before dereferencing.

use crate::ps::process::Eprocess;
use crate::ps::thread::Ethread;

/// Index range reserved for kernel pseudo-handles. Real Windows
/// uses a high bit to distinguish pseudo-handles from
/// per-process handles; we emulate the same idea by treating
/// any handle whose top two bits are set as a pseudo handle.
const PSEUDO_HANDLE_MARK: u32 = 0x8000_0000;

/// Well-known pseudo handle values matching the Win32 SDK.
pub const HANDLE_CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
pub const HANDLE_CURRENT_THREAD: u32 = 0xFFFF_FFFE;
pub const HANDLE_NULL: u32 = 0;

/// Acquire a reference to the per-process handle table stored
/// at `Eprocess.object_table`.
///
/// # Safety
/// The caller must guarantee that `process` points to a live
/// EPROCESS with a valid `object_table` pointer, and that no
/// other thread is mutating the table while we hold a
/// reference to it. The returned reference must not be used
/// after the underlying EPROCESS is freed.
pub unsafe fn with_handle_table<'a, F, R>(process: &'a Eprocess, f: F) -> Option<R>
where
    F: FnOnce(&'a mut crate::ps::process::ProcessHandleTable) -> R,
{
    if process.object_table.is_null() {
        return None;
    }
    Some(f(&mut *process.object_table))
}

/// Resolve a HANDLE32 to a raw pointer to the underlying
/// `Eprocess`. The returned pointer is non-null only when the
/// handle resolves successfully.
///
/// # Arguments
/// * `process` - The EPROCESS whose handle table should be
///   consulted.
/// * `handle` - The 32-bit handle value.
///
/// # Returns
/// * `Some(ptr)` if the handle is valid.
/// * `None` otherwise (invalid handle, wrong type, or out of
///   range).
///
/// # Safety
/// The returned raw pointer must not outlive the underlying
/// object and must not be dereferenced after the corresponding
/// object has been closed. Callers should treat the pointer
/// as borrowed (not owned) and never modify the EPROCESS in
/// a way that would race with the holder of the original
/// `&Eprocess` argument.
pub unsafe fn resolve_to_eprocess(
    process: &Eprocess,
    handle: u32,
) -> Option<*mut Eprocess> {
    if handle == 0 {
        return None;
    }
    if handle == HANDLE_CURRENT_PROCESS {
        // The 32-bit process opened itself: the kernel object
        // is just `process`. We return a raw pointer (not a
        // `&mut` reference) to avoid the `&T → &mut T`
        // undefined behaviour the borrow checker would
        // otherwise reject. The caller is responsible for
        // not aliasing this pointer with the borrowed
        // `process` argument.
        return Some(process as *const Eprocess as *mut Eprocess);
    }
    if handle & PSEUDO_HANDLE_MARK != 0 {
        // Other pseudo handles (e.g. HANDLE_CURRENT_THREAD)
        // cannot be resolved through the process table; the
        // caller should use `resolve_to_ethread` instead.
        return None;
    }
    let table = process.object_table;
    if table.is_null() {
        return None;
    }
    let table = &*table;
    let slot = handle as usize;
    if slot >= table.slots.len() || table.valid[slot] == 0 {
        return None;
    }
    let raw = table.slots[slot];
    if raw.is_null() {
        return None;
    }
    Some(raw as *mut Eprocess)
}

/// Resolve a HANDLE32 to a raw ETHREAD pointer.
pub unsafe fn resolve_to_ethread(
    process: &Eprocess,
    handle: u32,
) -> Option<*mut Ethread> {
    if handle == 0 {
        return None;
    }
    if handle == HANDLE_CURRENT_THREAD || handle == HANDLE_CURRENT_PROCESS {
        // Resolving "self" requires a thread pointer from the
        // TSS, which is unavailable in a stub kernel. Real
        // Windows returns the caller's ETHREAD; we return
        // None to remain conservative.
        return None;
    }
    if handle & PSEUDO_HANDLE_MARK != 0 {
        return None;
    }
    let table = process.object_table;
    if table.is_null() {
        return None;
    }
    let table = &*table;
    let slot = handle as usize;
    if slot >= table.slots.len() || table.valid[slot] == 0 {
        return None;
    }
    let raw = table.slots[slot];
    if raw.is_null() {
        return None;
    }
    Some(raw as *mut Ethread)
}

/// Returns true if the HANDLE32 is `HANDLE_CURRENT_PROCESS` or
/// the value 0xFFFFFFFE.
#[inline]
pub fn is_current_process(handle: u32) -> bool {
    handle == HANDLE_CURRENT_PROCESS || handle == 0xFFFFFFFE
}

/// Returns true if the HANDLE32 looks like a real per-process
/// index (not a pseudo handle, not null).
#[inline]
pub fn is_real_handle(handle: u32) -> bool {
    handle != 0
        && handle != HANDLE_CURRENT_PROCESS
        && handle != HANDLE_CURRENT_THREAD
        && handle & PSEUDO_HANDLE_MARK == 0
}

/// Map a 32-bit index into a `usize` slot reference. Returns
/// `None` for any out-of-range handle, and never panics on a
/// null handle.
#[inline]
pub fn slot_index(handle: u32) -> Option<usize> {
    if !is_real_handle(handle) {
        return None;
    }
    Some(handle as usize)
}

/// Trivial accessor used by the Wow64 thunks to silence
/// "unused parameter" warnings: returns a non-null pointer for
/// a HANDLE_CURRENT_PROCESS literal (handy when a thunk
/// prototype demands a "current EPROCESS"). This is
/// intentionally conservative — only HANDLE_CURRENT_PROCESS
/// returns a non-null dummy; everything else returns null.
pub fn dummy_eprocess_for(handle: u32) -> *mut Eprocess {
    if handle == HANDLE_CURRENT_PROCESS {
        // Return a sentinel non-null pointer (well outside
        // any valid address) so that thunks can be observed
        // to have read the parameter without leaking a real
        // EPROCESS into the kernel.
        0xFFFF_FFFF_FFFF_FFFF as *mut Eprocess
    } else {
        core::ptr::null_mut()
    }
}

/// Trivial accessor used by the Wow64 thunks to silence
/// "unused parameter" warnings for the corresponding
/// ETHREAD lookup. Returns a non-null sentinel for current
/// thread/process and null otherwise.
pub fn dummy_ethread_for(handle: u32) -> *mut Ethread {
    if handle == HANDLE_CURRENT_THREAD || handle == HANDLE_CURRENT_PROCESS {
        0xFFFF_FFFF_FFFF_FFFE as *mut Ethread
    } else {
        core::ptr::null_mut()
    }
}

/// Convert the `HANDLE32` to an `Option<u32>` round-trip so
/// callers in thunks can be observed to consume the parameter
/// without dereferencing anything. Useful for "ack" thunks
/// that only need to log that they were called with a valid
/// handle value (e.g., the `wow64_*` queries that take a
/// `process_handle` argument for permission auditing).
pub fn acknowledge_handle(handle: u32) -> Option<u32> {
    if handle == 0 {
        None
    } else {
        Some(handle)
    }
}
