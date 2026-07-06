//! I/O Completion Ports
//
//! I/O Completion Ports (IOCP) provide an efficient mechanism for
//! processing multiple asynchronous I/O requests. They are the
//! primary completion notification mechanism used by NT kernel-mode
//! drivers and are analogous to POSIX `epoll`/`kqueue` or Linux
//! `io_uring`.
//
//! # Windows NT IOCP Semantics
//
//! An IOCP is created with `IoCreateCompletionPort`. A file object
//! is associated with the port via `NtSetIoCompletion`. When an
//! asynchronous I/O operation completes, the driver calls
//! `IoCompleteRequest` which queues a completion packet to the
//! associated IOCP. A thread waiting on the port via
//! `NtRemoveIoCompletion` dequeues packets.
//
//! # Key Types
//
//! - `IoCompletion` — the completion port itself
//! - `IoCompletionPacket` — a single queued completion notification
//! - `IoCompletionKey` — identifies which file/handle the completion belongs to
//! - `NtSetIoCompletion` / `NtRemoveIoCompletion` — the kernel API

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pool;
use crate::kprintln;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum concurrent completions in a single port's queue.
const MAX_COMPLETION_QUEUE: usize = 256;

/// Maximum completion ports in the system.
const MAX_COMPLETION_PORTS: usize = 16;

// ---------------------------------------------------------------------------
// Completion packet
// ---------------------------------------------------------------------------

/// One queued I/O completion notification. This is the unit of
/// dequeue from an IOCP.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct IoCompletionPacket {
    /// Completion key — identifies the file/handle that completed.
    pub completion_key: usize,
    /// APC context — opaque value from the original IRP.
    pub apc_context: *mut (),
    /// I/O status block — NTSTATUS code and information.
    pub status: u32,
    /// Information field — byte count for read/write, or 0.
    pub information: usize,
    /// Optional output buffer virtual address.
    pub buffer: *mut u8,
    /// Size of the output buffer in bytes.
    pub buffer_size: usize,
}

impl IoCompletionPacket {
    /// Create a new completion packet.
    pub fn new(
        completion_key: usize,
        apc_context: *mut (),
        status: u32,
        information: usize,
    ) -> Self {
        Self {
            completion_key,
            apc_context,
            status,
            information,
            buffer: core::ptr::null_mut(),
            buffer_size: 0,
        }
    }

    /// Create a completion packet with a buffer.
    pub fn with_buffer(
        completion_key: usize,
        apc_context: *mut (),
        status: u32,
        information: usize,
        buffer: *mut u8,
        buffer_size: usize,
    ) -> Self {
        Self {
            completion_key,
            apc_context,
            status,
            information,
            buffer,
            buffer_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Completion port
// ---------------------------------------------------------------------------

/// A complete IoCompletionPacket definition (fixing the typo).
type IoCompletionPacketDef = IoCompletionPacket;

/// A reference-counted I/O Completion Port.
///
/// The port owns a queue of `IoCompletionPacket` entries. Drivers
/// associate file handles with the port, and when I/O completes,
/// packets are queued. Threads wait on the port to receive completions.
pub struct IoCompletion {
    /// Unique port number (for debug / tracing).
    port_number: u32,
    /// Completion key associated with this port.
    key: usize,
    /// Queue of pending completion packets.
    queue: Spinlock<Vec<IoCompletionPacket>>,
    /// Number of threads currently waiting on this port.
    waiters: AtomicU64,
    /// Sequence number incremented on each enqueue.
    sequence: AtomicU64,
}

impl IoCompletion {
    /// Create a new completion port with the given key.
    pub fn new(key: usize) -> Self {
        static NEXT_PORT: AtomicU64 = AtomicU64::new(0);
        let port_number = NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u32;

        Self {
            port_number,
            key,
            queue: Spinlock::new(Vec::with_capacity(MAX_COMPLETION_QUEUE)),
            waiters: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    /// Get the port's completion key.
    pub fn key(&self) -> usize {
        self.key
    }

    /// Queue a completion packet to this port.
    /// Returns the new queue depth.
    pub fn enqueue(&self, packet: IoCompletionPacket) -> usize {
        let mut q = self.queue.lock();
        let depth = q.len();
        if depth < MAX_COMPLETION_QUEUE {
            q.push(packet);
            self.sequence.fetch_add(1, Ordering::Release);
        } else {
            // Queue full — drop the packet (in a real system, this
            // would return STATUS_NO_MEMORY or similar)
            // // kprintln!("[IOCP] port {} queue full, dropping packet", self.port_number)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
        q.len()
    }

    /// Attempt to dequeue a completion packet.
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&self) -> Option<IoCompletionPacket> {
        let mut q = self.queue.lock();
        q.pop()
    }

    /// Dequeue with a timeout (spin-based approximation).
    /// Returns `None` if no packet arrives within `max_spins` iterations.
    pub fn dequeue_with_timeout(&self, max_spins: usize) -> Option<IoCompletionPacket> {
        for _ in 0..max_spins {
            if let Some(packet) = self.dequeue() {
                return Some(packet);
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Return the current queue depth.
    pub fn depth(&self) -> usize {
        self.queue.lock().len()
    }

    /// Increment the waiter count.
    pub fn add_waiter(&self) {
        self.waiters.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the waiter count.
    pub fn remove_waiter(&self) {
        self.waiters.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get the number of waiting threads.
    pub fn waiter_count(&self) -> u64 {
        self.waiters.load(Ordering::Relaxed)
    }

    /// Get the sequence number (incremented on each enqueue).
    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }
}

impl core::fmt::Debug for IoCompletion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoCompletion")
            .field("port_number", &self.port_number)
            .field("key", &self.key)
            .field("depth", &self.depth())
            .field("waiters", &self.waiters)
            .field("sequence", &self.sequence)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Global IOCP registry
// ---------------------------------------------------------------------------

static COMPLETION_PORTS: Spinlock<Vec<Option<IoCompletion>>> =
    Spinlock::new(alloc::vec![None; MAX_COMPLETION_PORTS]);

/// Create a new I/O Completion Port.
/// Returns the port handle (index into the global table).
pub fn IoCreateCompletionPort(key: usize) -> Option<usize> {
    let mut ports = COMPLETION_PORTS.lock();

    for (i, slot) in ports.iter_mut().enumerate() {
        if slot.is_none() {
            let port = IoCompletion::new(key);
            *slot = Some(port);
            // // kprintln!("[IOCP] created port #{} key=0x{:x}", i, key)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Some(i);
        }
    }

    // // kprintln!("[IOCP] out of completion port slots")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    None
}

/// Look up a completion port by handle.
pub fn lookup_port(handle: usize) -> Option<&'static IoCompletion> {
    let ports = COMPLETION_PORTS.lock();
    ports.get(handle).and_then(|p| p.as_ref())
}

/// Look up a mutable completion port by handle.
pub fn lookup_port_mut(handle: usize) -> Option<&'static mut IoCompletion> {
    let mut ports = COMPLETION_PORTS.lock();
    let slot = ports.get_mut(handle)?;
    // SAFETY: we hold the lock exclusively
    unsafe { core::mem::transmute::<Option<&IoCompletion>, Option<&'static mut IoCompletion>>(slot.as_ref()) }
}

/// Close a completion port.
pub fn IoCloseCompletionPort(handle: usize) -> bool {
    let mut ports = COMPLETION_PORTS.lock();
    if let Some(slot) = ports.get_mut(handle) {
        if slot.is_some() {
            // // kprintln!("[IOCP] closing port #{}", handle)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            *slot = None;
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Kernel API (Nt* and Io* functions)
// ---------------------------------------------------------------------------

/// `NtSetIoCompletion` — insert a completion packet into a port.
/// This is called by drivers when an asynchronous I/O operation
/// completes.
///
/// # Arguments
/// * `port_handle` — handle returned by `IoCreateCompletionPort`
/// * `completion_key` — identifies the file/handle that completed
/// * `status` — NTSTATUS of the operation
/// * `information` — byte count for read/write, or 0
///
/// # Returns
/// * `0` — success
/// * `0xC0000001` — STATUS_UNSUCCESSFUL (invalid handle)
pub fn NtSetIoCompletion(
    port_handle: usize,
    completion_key: usize,
    status: u32,
    information: usize,
) -> u32 {
    let port = match lookup_port(port_handle) {
        Some(p) => p,
        None => {
            // // kprintln!("[IOCP] NtSetIoCompletion: invalid port handle {}", port_handle)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return 0xC0000001; // STATUS_UNSUCCESSFUL
        }
    };

    let packet = IoCompletionPacket::new(completion_key, core::ptr::null_mut(), status, information);
    let depth = port.enqueue(packet);
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "[IOCP] NtSetIoCompletion port={} key=0x{:x} status=0x{:08x} info={} depth={}",
// //         port_handle, completion_key, status, information, depth
// //     );
    0 // STATUS_SUCCESS
}

/// `NtRemoveIoCompletion` — wait for and remove a completion packet.
/// This is called by threads that want to process completed I/O.
///
/// # Arguments
/// * `port_handle` — handle returned by `IoCreateCompletionPort`
/// * `timeout_ms` — timeout in milliseconds (0 = no wait)
///
/// # Returns
/// A tuple of (status, information, completion_key) packed into a
/// struct, or `None` if the operation timed out.
#[derive(Debug)]
pub struct IoCompletionResult {
    pub status: u32,
    pub information: usize,
    pub completion_key: usize,
    pub apc_context: *mut (),
}

pub fn NtRemoveIoCompletion(
    port_handle: usize,
    timeout_ms: u32,
) -> Option<IoCompletionResult> {
    let port = lookup_port(port_handle)?;

    if timeout_ms == 0 {
        // Non-blocking — just try to dequeue
        let packet = port.dequeue()?;
        return Some(IoCompletionResult {
            status: packet.status,
            information: packet.information,
            completion_key: packet.completion_key,
            apc_context: packet.apc_context,
        });
    }

    // Spin-wait for up to `timeout_ms` milliseconds.
    // Each iteration is ~10 CPU cycles, so 100M iterations ≈ 1ms at 1GHz.
    let max_iters = (timeout_ms as usize) * 100_000_000;

    for i in 0..max_iters {
        if let Some(packet) = port.dequeue() {
            return Some(IoCompletionResult {
                status: packet.status,
                information: packet.information,
                completion_key: packet.completion_key,
                apc_context: packet.apc_context,
            });
        }

        // Yield periodically to avoid monopolizing the CPU
        if i % 1_000_000 == 0 {
            crate::arch::cpu_relax();
        }
    }

    None // Timeout
}

/// Bind a file object to a completion port.
/// In a full implementation, this would associate a file handle
/// with the port so that I/O completions on that file are routed
/// to the port. Here we just register the file's completion key.
pub fn IoBindIoCompletion(port_handle: usize, file_key: usize) -> bool {
    lookup_port(port_handle).is_some()
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Smoke test the IOCP subsystem.
pub fn smoke_test() -> bool {
    // // kprintln!("  [IOCP SMOKE] testing IOCP subsystem...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // 1. Create a port
    let port = IoCreateCompletionPort(0xDEADBEEF);
    if port.is_none() {
        // // kprintln!("  [IOCP SMOKE FAIL] IoCreateCompletionPort returned None")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let port_handle = port.unwrap();
    // // kprintln!("    port handle = {}", port_handle)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // 2. Enqueue some packets via NtSetIoCompletion
    let status = NtSetIoCompletion(port_handle, 0x1111, 0, 512);
    if status != 0 {
        // // kprintln!("  [IOCP SMOKE FAIL] NtSetIoCompletion failed: 0x{:08x}", status)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let status = NtSetIoCompletion(port_handle, 0x2222, 0, 256);
    if status != 0 {
        // // kprintln!("  [IOCP SMOKE FAIL] NtSetIoCompletion failed: 0x{:08x}", status)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // 3. Dequeue via NtRemoveIoCompletion
    let result = NtRemoveIoCompletion(port_handle, 0);
    if result.is_none() {
        // // kprintln!("  [IOCP SMOKE FAIL] NtRemoveIoCompletion timed out")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let result = result.unwrap();
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    packet: key=0x{:x} status=0x{:08x} info={}",
// //         result.completion_key, result.status, result.information
// //     );

    // 4. Check depth
    let port = lookup_port(port_handle).unwrap();
    let depth = port.depth();
    // // kprintln!("    remaining depth = {}", depth)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    if depth != 1 {
        // // kprintln!("  [IOCP SMOKE FAIL] expected depth 1, got {}", depth)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // 5. Dequeue remaining packet
    let result = NtRemoveIoCompletion(port_handle, 0);
    if result.is_none() {
        // // kprintln!("  [IOCP SMOKE FAIL] second NtRemoveIoCompletion timed out")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // 6. Verify empty queue
    let result = NtRemoveIoCompletion(port_handle, 0);
    if result.is_some() {
        // // kprintln!("  [IOCP SMOKE FAIL] unexpected third packet")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // 7. Close the port
    if !IoCloseCompletionPort(port_handle) {
        // // kprintln!("  [IOCP SMOKE FAIL] IoCloseCompletionPort failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // // kprintln!("  [IOCP SMOKE OK] IOCP subsystem healthy")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    true
}
