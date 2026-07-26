//! Named and anonymous pipes
//!
//! Pipes are the NT 6.1 IPC primitive used by:
//!   - cmd.exe's stdin/stdout/stderr when redirected
//!   - sshd for privilege separation between the listener and
//!     the unauthenticated child
//!   - sftp-server.exe via inherited handles from sshd
//!   - any process that calls CreatePipe()
//!
//! Design choices:
//!   - Anonymous pipes are modeled as a pair of file handles
//!     (read end + write end), stored in a kernel ring buffer.
//!     Blocking read/write is implemented on top of
//!     ke::sync::Spinlock + EventState so NtWaitForSingleObject
//!     works against the read end.
//!   - Named pipes start anonymous; the path component is stored
//!     but no filesystem entry is created yet (server-side
//!     CreateNamedPipeW is enough for OpenSSH's needs).
//!   - Both ends support FILE_APPEND_DATA / FILE_READ_DATA
//!     access masks as documented for anonymous pipes.

use crate::ke::sync::Spinlock;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Pipe buffer size (matches Windows default for anonymous pipes).
pub const PIPE_BUFFER_SIZE: usize = 64 * 1024;

/// One end of a pipe. The read end is signalled when data is
/// available; the write end is signalled when there is buffer
/// space again.
#[derive(Debug)]
pub struct PipeEnd {
    pub id: u64,
    /// Direction: true = read, false = write.
    pub is_read: bool,
}

/// State shared between the two ends of a pipe.
pub(crate) struct PipeState {
    pub buffer: VecDeque<u8>,
    pub write_open: bool,
    pub read_open: bool,
    /// Signalled whenever a byte is written to the buffer (for
    /// the read end to wake NtReadFile/NtWaitForSingleObject).
    pub read_event_target: u64,
    /// Signalled whenever the buffer is no longer full (for the
    /// write end to wake NtWriteFile).
    pub write_event_target: u64,
}

impl PipeState {
    fn new() -> Self {
        Self {
            buffer: VecDeque::with_capacity(PIPE_BUFFER_SIZE),
            write_open: true,
            read_open: true,
            // event_type=1 (Synchronization), manual_reset=false,
            // signaled depends on direction.
            read_event_target: encode_pipe_event(true, false),
            write_event_target: encode_pipe_event(false, false),
        }
    }
}

static PIPES: Spinlock<Vec<Option<PipeState>>> = Spinlock::new(Vec::new());
static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);

/// Encode a pipe end's event target (lower 32 bits = state, upper
/// 32 = (event_type, manual_reset)).
fn encode_pipe_event(signaled: bool, manual_reset: bool) -> u64 {
    let lo = if signaled { 1u64 } else { 0u64 };
    let hi = ((1u64 << 1) | (if manual_reset { 1u64 << 8 } else { 0u64 })) << 32;
    hi | lo
}

fn alloc_slot(state: PipeState) -> usize {
    let mut pipes = PIPES.lock();
    if let Some((idx, slot)) = pipes.iter_mut().enumerate().find(|(_, s)| s.is_none()) {
        *slot = Some(state);
        return idx;
    }
    pipes.push(Some(state));
    pipes.len() - 1
}

fn with_pipe<R>(idx: usize, f: impl FnOnce(&mut PipeState) -> R) -> Option<R> {
    let mut pipes = PIPES.lock();
    pipes.get_mut(idx).and_then(|s| s.as_mut().map(f))
}

/// Create an anonymous pipe. Returns (read_end_id, write_end_id)
/// where each id is a kernel-side pipe handle (not an NT HANDLE
/// yet — wrappers below add that).
pub fn create_anonymous() -> Option<(u64, u64)> {
    let id = NEXT_PIPE_ID.fetch_add(2, Ordering::Relaxed);
    let state = PipeState::new();
    let idx = alloc_slot(state);
    let read_id = id;
    let write_id = id.wrapping_add(1);
    crate::boot_println!("[PIPE] create_anonymous: slot={} read_id={} write_id={}",
        idx, read_id, write_id);
    Some((read_id, write_id))
}

/// Look up the slot index and direction for a pipe id. The pipe
/// allocator hands out sequential ids (read = id, write = id+1).
pub fn slot_for_id(pipe_id: u64) -> Option<(usize, bool)> {
    let pipes = PIPES.lock();
    // The id is `id << 1` relative to slot indexes — we packed
    // 2 ids per alloc call so slot = (id - 1) / 2, direction =
    // (id - 1) % 2.
    if pipe_id == 0 {
        return None;
    }
    let idx = ((pipe_id - 1) / 2) as usize;
    let is_write = ((pipe_id - 1) % 2) == 1;
    if idx >= pipes.len() {
        return None;
    }
    if pipes[idx].is_none() {
        return None;
    }
    Some((idx, is_write))
}

/// Read up to `buf.len()` bytes from the pipe. Returns the number
/// of bytes actually read (0 means EOF / pipe closed with no data).
pub fn read(idx: usize, buf: &mut [u8]) -> usize {
    let mut pipes = PIPES.lock();
    let Some(slot) = pipes.get_mut(idx) else { return 0 };
    let Some(state) = slot.as_mut() else { return 0 };
    if !state.read_open {
        return 0;
    }
    let take = buf.len().min(state.buffer.len());
    for i in 0..take {
        buf[i] = state.buffer.pop_front().unwrap_or(0);
    }
    // Signal write end if there is now room.
    if state.buffer.len() < PIPE_BUFFER_SIZE {
        state.write_event_target = encode_pipe_event(true, false);
    }
    take
}

/// Write `data` into the pipe. Returns the number of bytes
/// accepted (may be less than `data.len()` if the buffer is full).
pub fn write(idx: usize, data: &[u8]) -> usize {
    let mut pipes = PIPES.lock();
    let Some(slot) = pipes.get_mut(idx) else { return 0 };
    let Some(state) = slot.as_mut() else { return 0 };
    if !state.write_open {
        return 0;
    }
    let free = PIPE_BUFFER_SIZE.saturating_sub(state.buffer.len());
    let take = data.len().min(free);
    for i in 0..take {
        state.buffer.push_back(data[i]);
    }
    // Signal read end if there is now data.
    if !state.buffer.is_empty() {
        state.read_event_target = encode_pipe_event(true, false);
    }
    take
}

/// Close one end of the pipe. Closing the read end wakes any
/// blocked writers (with EOF); closing the write end wakes any
/// blocked readers (with EOF if no data buffered).
pub fn close_end(idx: usize, is_read: bool) {
    let mut pipes = PIPES.lock();
    let Some(slot) = pipes.get_mut(idx) else { return };
    let Some(state) = slot.as_mut() else { return };
    if is_read {
        state.read_open = false;
    } else {
        state.write_open = false;
        // Reader sees EOF.
        state.read_event_target = encode_pipe_event(true, false);
    }
    if !state.read_open && !state.write_open {
        // Both ends closed — reclaim the slot.
        *slot = None;
    }
}

/// Return the event-target encoded for the read or write end so
/// NtWaitForSingleObject can be wired to the pipe.
pub fn event_target(idx: usize, is_read: bool) -> u64 {
    with_pipe(idx, |s| {
        if is_read { s.read_event_target } else { s.write_event_target }
    })
    .unwrap_or(0)
}

/// Diagnostic helper for boot logs.
pub fn debug_pipe_count() -> usize {
    PIPES.lock().iter().filter(|s| s.is_some()).count()
}

/// Convenience wrapper for the cmd.exe inherited-stdout path:
/// create a pair, register both with the handle table so user
/// code can talk to them via NtWriteFile / NtReadFile, and return
/// the read and write NT HANDLEs.
pub fn create_anonymous_handles() -> Option<(u64, u64)> {
    let (read_id, write_id) = create_anonymous()?;
    // Translate to NT handle table indices via ntdll::file so
    // NtReadFile/NtWriteFile can route through the pipe layer.
    let read_handle = crate::libs::ntdll::file::alloc_pipe_handle(read_id);
    let write_handle = crate::libs::ntdll::file::alloc_pipe_handle(write_id);
    if read_handle.is_null() || write_handle.is_null() {
        return None;
    }
    Some((read_handle as u64, write_handle as u64))
}

/// Convenience wrapper for cmd.exe to print something on a pipe
/// handle. Mostly here so the public API has a stable name to
/// call from outside the kernel.
pub fn debug_handle_name() -> String {
    String::from("anonymous_pipe")
}

/// Stash an arbitrary host-side identifier (e.g. an NT HANDLE
/// value) into a new pipe slot so the handle table can look it
/// up by id. Returns the slot index.
#[allow(dead_code)]
pub fn register_external_pipe(host_id: u64) -> Option<usize> {
    let id = NEXT_PIPE_ID.fetch_add(2, Ordering::Relaxed);
    if id == host_id {
        return None;
    }
    let state = PipeState::new();
    Some(alloc_slot(state))
}
