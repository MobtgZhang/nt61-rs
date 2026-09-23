//! I/O Completion Ports (IOCP) Implementation
//!
//! # Task 6: I/O Completion Port (IOCP)
//!
//! IOCP provides high-performance asynchronous I/O for Windows applications.
//! It allows multiple I/O operations to be queued and processed by a pool
//! of worker threads efficiently.
//!
//! ## Architecture
//!
//! 1. **Completion Queue**: FIFO queue of completed I/O operations
//! 2. **Worker Thread Pool**: Threads waiting for completed I/O
//! 3. **Associated File Handles**: Files/sockets bound to the IOCP
//! 4. **Overlapped I/O**: Async operations with OVERLAPPED structure

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use crate::ke::sync::Spinlock;

/// Maximum number of I/O completion ports
pub const MAX_IOCP: usize = 256;

/// Maximum completion entries per port
pub const MAX_COMPLETION_ENTRIES: usize = 4096;

/// NTSTATUS codes
pub const STATUS_SUCCESS: u32 = 0x00000000;
pub const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000009A;
pub const STATUS_TIMEOUT: u32 = 0x00000102;
pub const STATUS_PENDING: u32 = 0x00000103;

/// I/O Completion Packet
///
/// Represents a single completed I/O operation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoCompletionPacket {
    /// Number of bytes transferred
    pub bytes_transferred: u64,

    /// Completion key (user-defined per file handle)
    pub completion_key: u64,

    /// Pointer to OVERLAPPED structure
    pub overlapped: u64,

    /// I/O status (NTSTATUS)

    pub status: u32,
}

impl IoCompletionPacket {
    pub const fn new() -> Self {
        Self {
            bytes_transferred: 0,
            completion_key: 0,
            overlapped: 0,
            status: STATUS_SUCCESS,
        }
    }
}

/// I/O Completion Port Structure
pub struct IoCompletionPort {
    /// Port ID
    port_id: u64,

    /// Completion queue
    queue: Spinlock<VecDeque<IoCompletionPacket>>,

    /// Maximum concurrent threads (0 = number of processors)
    max_concurrent_threads: u32,

    /// Currently active threads
    active_threads: AtomicU32,

    /// Total packets posted
    packets_posted: AtomicU64,

    /// Total packets retrieved
    packets_retrieved: AtomicU64,

    /// Associated file handles
    associated_handles: Spinlock<Vec<(u64, u64)>>, // (handle, completion_key)
}

impl IoCompletionPort {
    /// Create a new I/O Completion Port
    ///
    /// # Task 6.2: IOCP creation
    pub fn new(port_id: u64, max_concurrent_threads: u32) -> Self {
        Self {
            port_id,
            queue: Spinlock::new(VecDeque::new()),
            max_concurrent_threads,
            active_threads: AtomicU32::new(0),
            packets_posted: AtomicU64::new(0),
            packets_retrieved: AtomicU64::new(0),
            associated_handles: Spinlock::new(Vec::new()),
        }
    }

    /// Associate a file handle with this IOCP
    ///
    /// # Task 6.7: Integration with I/O manager
    pub fn associate_handle(&self, handle: u64, completion_key: u64) -> u32 {
        let mut handles = self.associated_handles.lock();

        // Check if already associated
        if handles.iter().any(|(h, _)| *h == handle) {
            return STATUS_INVALID_HANDLE;
        }

        handles.push((handle, completion_key));
        STATUS_SUCCESS
    }

    /// Post a completion packet to the queue
    ///
    /// # Task 6.6: PostQueuedCompletionStatus
    pub fn post_completion(&self, packet: IoCompletionPacket) -> u32 {
        let mut queue = self.queue.lock();

        if queue.len() >= MAX_COMPLETION_ENTRIES {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        queue.push_back(packet);
        self.packets_posted.fetch_add(1, Ordering::Relaxed);

        // TODO: Wake up waiting threads
        STATUS_SUCCESS
    }

    /// Get a completion packet from the queue
    ///
    /// # Task 6.5: GetQueuedCompletionStatus
    ///
    /// # Safety
    /// This function blocks if no packets are available
    pub fn get_completion(&self, timeout_ms: u32) -> Result<IoCompletionPacket, u32> {
        // Increment active threads
        let active = self.active_threads.fetch_add(1, Ordering::Relaxed);

        // Check concurrency limit
        if self.max_concurrent_threads > 0 && active >= self.max_concurrent_threads {
            self.active_threads.fetch_sub(1, Ordering::Relaxed);
            // TODO: Wait until a thread becomes available
        }

        // Try to get a packet
        let result = {
            let mut queue = self.queue.lock();
            queue.pop_front()
        };

        // Decrement active threads
        self.active_threads.fetch_sub(1, Ordering::Relaxed);

        if let Some(packet) = result {
            self.packets_retrieved.fetch_add(1, Ordering::Relaxed);
            Ok(packet)
        } else {
            // No packet available
            if timeout_ms == 0 {
                Err(STATUS_TIMEOUT)
            } else {
                // TODO: Wait for timeout_ms or until a packet arrives
                Err(STATUS_TIMEOUT)
            }
        }
    }

    /// Get port statistics
    pub fn get_stats(&self) -> (u64, u64, u32, usize) {
        let posted = self.packets_posted.load(Ordering::Relaxed);
        let retrieved = self.packets_retrieved.load(Ordering::Relaxed);
        let active = self.active_threads.load(Ordering::Relaxed);
        let queue_len = self.queue.lock().len();

        (posted, retrieved, active, queue_len)
    }

    /// Get port ID
    pub fn port_id(&self) -> u64 {
        self.port_id
    }
}

/// Global IOCP table
static IOCP_TABLE: Spinlock<Vec<Option<IoCompletionPort>>> = Spinlock::new(Vec::new());
static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(1);

/// Initialize IOCP subsystem
pub fn init() {
    let mut table = IOCP_TABLE.lock();
    // Pre-allocate space for MAX_IOCP ports
    for _ in 0..MAX_IOCP {
        table.push(None);
    }

    crate::hal::serial::write_string("[IOCP] I/O Completion Ports initialized\r\n");
}

/// Create a new I/O Completion Port
///
/// # Task 6.2: IOCP creation
pub fn create_io_completion_port(max_concurrent_threads: u32) -> Result<u64, u32> {
    let port_id = NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed);
    let port = IoCompletionPort::new(port_id, max_concurrent_threads);

    let mut table = IOCP_TABLE.lock();

    // Find empty slot
    for slot in table.iter_mut() {
        if slot.is_none() {
            *slot = Some(port);
            return Ok(port_id);
        }
    }

    Err(STATUS_INSUFFICIENT_RESOURCES)
}

/// Close an I/O Completion Port
///
/// # Task 6.2: IOCP destruction
pub fn close_io_completion_port(port_id: u64) -> u32 {
    let mut table = IOCP_TABLE.lock();

    for slot in table.iter_mut() {
        if let Some(port) = slot {
            if port.port_id() == port_id {
                *slot = None;
                return STATUS_SUCCESS;
            }
        }
    }

    STATUS_INVALID_HANDLE
}

/// Associate a file handle with an IOCP
pub fn associate_handle_with_iocp(
    port_id: u64,
    handle: u64,
    completion_key: u64,
) -> u32 {
    let table = IOCP_TABLE.lock();

    for slot in table.iter() {
        if let Some(port) = slot {
            if port.port_id() == port_id {
                return port.associate_handle(handle, completion_key);
            }
        }
    }

    STATUS_INVALID_HANDLE
}

/// Post a completion packet to an IOCP
///
/// # Task 6.6: PostQueuedCompletionStatus implementation
pub fn post_queued_completion_status(
    port_id: u64,
    bytes_transferred: u64,
    completion_key: u64,
    overlapped: u64,
) -> u32 {
    let table = IOCP_TABLE.lock();

    for slot in table.iter() {
        if let Some(port) = slot {
            if port.port_id() == port_id {
                let packet = IoCompletionPacket {
                    bytes_transferred,
                    completion_key,
                    overlapped,
                    status: STATUS_SUCCESS,
                };
                return port.post_completion(packet);
            }
        }
    }

    STATUS_INVALID_HANDLE
}

/// Get a completion packet from an IOCP
///
/// # Task 6.5: GetQueuedCompletionStatus implementation
pub fn get_queued_completion_status(
    port_id: u64,
    timeout_ms: u32,
) -> Result<IoCompletionPacket, u32> {
    // First, find the port and clone necessary data
    let port_exists = {
        let table = IOCP_TABLE.lock();
        table.iter().any(|slot| {
            if let Some(port) = slot {
                port.port_id() == port_id
            } else {
                false
            }
        })
    };

    if !port_exists {
        return Err(STATUS_INVALID_HANDLE);
    }

    // Now access the port without holding the table lock
    let table = IOCP_TABLE.lock();
    for slot in table.iter() {
        if let Some(port) = slot {
            if port.port_id() == port_id {
                // We need to call get_completion, but we can't drop table here
                // because port is borrowed from it. Instead, we'll restructure.
                return port.get_completion(timeout_ms);
            }
        }
    }

    Err(STATUS_INVALID_HANDLE)
}

/// Get IOCP statistics
pub fn get_iocp_stats(port_id: u64) -> Option<(u64, u64, u32, usize)> {
    let table = IOCP_TABLE.lock();

    for slot in table.iter() {
        if let Some(port) = slot {
            if port.port_id() == port_id {
                return Some(port.get_stats());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iocp_creation() {
        init();
        let port_id = create_io_completion_port(0).unwrap();
        assert!(port_id > 0);

        let result = close_io_completion_port(port_id);
        assert_eq!(result, STATUS_SUCCESS);
    }

    #[test]
    fn test_post_and_get_completion() {
        init();
        let port_id = create_io_completion_port(0).unwrap();

        // Post a packet
        let result = post_queued_completion_status(port_id, 1024, 0x1234, 0xABCD);
        assert_eq!(result, STATUS_SUCCESS);

        // Get the packet
        let packet = get_queued_completion_status(port_id, 0).unwrap();
        assert_eq!(packet.bytes_transferred, 1024);
        assert_eq!(packet.completion_key, 0x1234);
        assert_eq!(packet.overlapped, 0xABCD);

        close_io_completion_port(port_id);
    }

    #[test]
    fn test_handle_association() {
        init();
        let port_id = create_io_completion_port(0).unwrap();

        let result = associate_handle_with_iocp(port_id, 0x1000, 0x5678);
        assert_eq!(result, STATUS_SUCCESS);

        // Try to associate same handle again
        let result = associate_handle_with_iocp(port_id, 0x1000, 0x9999);
        assert_eq!(result, STATUS_INVALID_HANDLE);

        close_io_completion_port(port_id);
    }
}
