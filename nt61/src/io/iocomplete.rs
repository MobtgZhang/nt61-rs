//! I/O Completion Ports — NT-style `Nt*` compatibility wrapper.
//!
//! This module is a thin delegation layer over the single IOCP
//! implementation in [`crate::io::iocp`]. It previously maintained a
//! second, independent port table, which meant packets posted through
//! `nt_set_io_completion` were invisible to completions delivered by
//! `io_complete_request` and vice versa. The duplicate table is gone:
//! both API surfaces now operate on the same port objects and queues, so
//! there is one completion-notification model.
//!
//! # Key API
//!
//! - `io_create_completion_port` / `io_close_completion_port` — port
//!   lifecycle. Handles are IOCP port ids (never 0).
//! - `nt_set_io_completion` — insert a completion packet into a port.
//! - `nt_remove_io_completion` — wait for and dequeue a packet.
//! - `io_bind_io_completion` — associate a file key with a port.
//!
//! # Key Types
//!
//! - `IoCompletionResult` — packet payload returned to the waiter.

use crate::io::iocp;

// ---------------------------------------------------------------------------
// Kernel API (Nt* and Io* functions)
// ---------------------------------------------------------------------------

/// create a new I/O Completion Port.
///
/// `key` is recorded as the port's default completion key and can be
/// retrieved with `port_default_key`.
///
/// Returns the port handle (an IOCP port id), or `None` if the port
/// table is exhausted.
pub fn io_create_completion_port(key: usize) -> Option<usize> {
    let port_id = iocp::create_io_completion_port_with_key(0, key as u64).ok()?;
    Some(port_id as usize)
}

/// Whether a completion port handle is valid.
pub fn port_exists(handle: usize) -> bool {
    iocp::port_exists(handle as u64)
}

/// Default completion key a port was created with.
pub fn port_default_key(handle: usize) -> Option<u64> {
    iocp::get_port_default_key(handle as u64)
}

/// close a completion port.
pub fn io_close_completion_port(handle: usize) -> bool {
    iocp::close_io_completion_port(handle as u64) == iocp::STATUS_SUCCESS
}

/// `nt_set_io_completion` — insert a completion packet into a port.
/// This is called by drivers when an asynchronous I/O operation
/// completes.
///
/// # Arguments
/// * `port_handle` — handle returned by `io_create_completion_port`
/// * `completion_key` — identifies the file/handle that completed
/// * `status` — NTSTATUS of the operation
/// * `information` — byte count for read/write, or 0
///
/// # Returns
/// * `0` — success
/// * otherwise — the underlying IOCP NTSTATUS (`STATUS_INVALID_HANDLE`
///   for an unknown port, `STATUS_INSUFFICIENT_RESOURCES` when the
///   queue is full).
pub fn nt_set_io_completion(
    port_handle: usize,
    completion_key: usize,
    status: u32,
    information: usize,
) -> u32 {
    iocp::post_completion_status(
        port_handle as u64,
        information as u64,
        completion_key as u64,
        0,
        status,
    )
}

/// Result payload returned to a waiter by `nt_remove_io_completion`.
#[derive(Debug)]
pub struct IoCompletionResult {
    pub status: u32,
    pub information: usize,
    pub completion_key: usize,
    pub apc_context: *mut (),
}

/// `nt_remove_io_completion` — wait for and remove a completion packet.
/// This is called by threads that want to process completed I/O.
///
/// # Arguments
/// * `port_handle` — handle returned by `io_create_completion_port`
/// * `timeout_ms` — timeout in milliseconds (0 = no wait)
///
/// # Returns
/// The dequeued packet, or `None` if the operation timed out or the
/// handle is unknown. While waiting, the thread cooperatively
/// reschedules (see `iocp::IoCompletionPort::get_completion`).
pub fn nt_remove_io_completion(port_handle: usize, timeout_ms: u32) -> Option<IoCompletionResult> {
    let packet = iocp::get_queued_completion_status(port_handle as u64, timeout_ms).ok()?;

    Some(IoCompletionResult {
        status: packet.status,
        information: packet.bytes_transferred as usize,
        completion_key: packet.completion_key as usize,
        apc_context: packet.overlapped as *mut (),
    })
}

/// Bind a file object to a completion port.
///
/// The file key is registered in the port's handle association table, so
/// completions posted with that key belong to this port.
pub fn io_bind_io_completion(port_handle: usize, file_key: usize) -> bool {
    iocp::associate_handle_with_iocp(port_handle as u64, file_key as u64, file_key as u64)
        == iocp::STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Smoke test the IOCP subsystem.
pub fn smoke_test() -> bool {
    let port_handle = match io_create_completion_port(0xDEADBEEF) {
        Some(handle) => handle,
        None => return false,
    };
    if !port_exists(port_handle) {
        return false;
    }

    if nt_set_io_completion(port_handle, 0x1111, 0, 512) != 0 {
        return false;
    }
    if nt_set_io_completion(port_handle, 0x2222, 0, 256) != 0 {
        return false;
    }

    let first = match nt_remove_io_completion(port_handle, 0) {
        Some(result) => result,
        None => return false,
    };
    if first.completion_key != 0x1111 || first.information != 512 {
        return false;
    }

    let second = match nt_remove_io_completion(port_handle, 0) {
        Some(result) => result,
        None => return false,
    };
    if second.completion_key != 0x2222 || second.information != 256 {
        return false;
    }

    if nt_remove_io_completion(port_handle, 0).is_some() {
        return false;
    }

    io_close_completion_port(port_handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_packet_round_trip_preserves_status_and_key() {
        let handle = io_create_completion_port(0x1234).expect("no free completion port slot");
        assert!(port_exists(handle));
        assert_eq!(port_default_key(handle), Some(0x1234));

        assert_eq!(nt_set_io_completion(handle, 0x1111, 0, 512), 0);
        assert_eq!(nt_set_io_completion(handle, 0x2222, 0xC000_0022, 7), 0);

        let first = nt_remove_io_completion(handle, 0).expect("packet 1");
        assert_eq!(first.completion_key, 0x1111);
        assert_eq!(first.status, 0);
        assert_eq!(first.information, 512);

        let second = nt_remove_io_completion(handle, 0).expect("packet 2");
        assert_eq!(second.completion_key, 0x2222);
        assert_eq!(second.status, 0xC000_0022);
        assert_eq!(second.information, 7);

        // Queue is drained.
        assert!(nt_remove_io_completion(handle, 0).is_none());

        assert!(io_close_completion_port(handle));
        assert!(!port_exists(handle));
        assert!(nt_remove_io_completion(handle, 0).is_none());
        assert_eq!(
            nt_set_io_completion(handle, 1, 0, 0),
            iocp::STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn unknown_handle_has_no_port() {
        assert!(!port_exists(usize::MAX));
        assert_eq!(port_default_key(usize::MAX), None);
        assert!(nt_remove_io_completion(usize::MAX, 0).is_none());
        assert!(!io_close_completion_port(usize::MAX));
    }

    #[test]
    fn bind_routes_file_key_to_the_port() {
        let handle = io_create_completion_port(0x9).expect("no free completion port slot");
        assert!(io_bind_io_completion(handle, 0x77));
        // The same file key cannot be associated twice.
        assert!(!io_bind_io_completion(handle, 0x77));
        assert!(!io_bind_io_completion(usize::MAX, 0x77));
        io_close_completion_port(handle);
    }
}
