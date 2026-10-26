//! NDIS Miniport Send Queue Management
//
//! Handles the send queue for NET_BUFFER_LISTs. The send queue
//! buffers packets when the NIC is busy.
//
//! Clean-room implementation based on NDIS 6.0 specification.

use crate::drivers::net::{self, NicType};
use crate::drivers::net::ndis::nbl::{NetBufferList, NetBuffer};
use crate::drivers::net::ndis::miniport_adapter::MiniportAdapterContext;
use crate::ke::sync::Spinlock;
use crate::mm::pool::{self, PoolType};
use alloc::vec::Vec;
use core::ptr;

/// Pool tags
mod tags {
    use crate::mm::pool::make_tag;
    pub const SNDBUF: u32 = make_tag(b'S', b'N', b'D', b'B');
}

/// Send queue entry
struct SendQueueEntry {
    nbl: *mut NetBufferList,
    data: Vec<u8>,
}

/// Send queue for buffering packets.
///
/// A fixed-capacity ring buffer: all slots are allocated once at
/// construction, so enqueue never allocates while the caller holds the
/// queue spinlock, and dequeue is O(1) instead of the O(n) shift of a
/// Vec::remove(0).
pub struct SendQueue {
    slots: Vec<SendQueueEntry>,
    head: usize,
    tail: usize,
    count: usize,
    max_depth: usize,
}

impl SendQueue {
    /// create a new send queue
    pub fn new(max_depth: usize) -> Self {
        let slots: Vec<SendQueueEntry> = (0..max_depth)
            .map(|_| SendQueueEntry {
                nbl: ptr::null_mut(),
                data: Vec::new(),
            })
            .collect();
        Self {
            slots,
            head: 0,
            tail: 0,
            count: 0,
            max_depth,
        }
    }

    /// Add a packet to the queue
    pub fn enqueue(&mut self, nbl: *mut NetBufferList, data: Vec<u8>) -> bool {
        if self.count >= self.max_depth {
            return false;
        }
        self.slots[self.tail] = SendQueueEntry { nbl, data };
        self.tail = (self.tail + 1) % self.max_depth;
        self.count += 1;
        true
    }

    /// Get the next packet from the queue
    pub fn dequeue(&mut self) -> Option<(*mut NetBufferList, Vec<u8>)> {
        if self.count == 0 {
            return None;
        }
        // Hand the slot contents out and reset the slot in place so the
        // preallocated storage is reused without reallocation.
        let entry = core::mem::replace(
            &mut self.slots[self.head],
            SendQueueEntry {
                nbl: ptr::null_mut(),
                data: Vec::new(),
            },
        );
        self.head = (self.head + 1) % self.max_depth;
        self.count -= 1;
        Some((entry.nbl, entry.data))
    }

    /// Peek at the next packet without removing
    pub fn peek(&self) -> Option<*mut NetBufferList> {
        if self.count == 0 {
            None
        } else {
            Some(self.slots[self.head].nbl)
        }
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.count >= self.max_depth
    }

    /// Get queue depth
    pub fn len(&self) -> usize {
        self.count
    }
}

/// Send queue with lock
pub struct SendQueueManager {
    queue: Spinlock<SendQueue>,
}

impl SendQueueManager {
    /// create a new send queue manager
    pub fn new(max_depth: usize) -> Self {
        Self {
            queue: Spinlock::new(SendQueue::new(max_depth)),
        }
    }

    /// Enqueue a packet for sending
    pub fn enqueue(&self, nbl: *mut NetBufferList, data: Vec<u8>) -> bool {
        let mut queue = self.queue.lock();
        queue.enqueue(nbl, data)
    }

    /// Dequeue a packet for sending
    pub fn dequeue(&self) -> Option<(*mut NetBufferList, Vec<u8>)> {
        let mut queue = self.queue.lock();
        queue.dequeue()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        let queue = self.queue.lock();
        queue.is_empty()
    }

    /// Get queue length
    pub fn len(&self) -> usize {
        let queue = self.queue.lock();
        queue.len()
    }
}

/// NDIS send flags
pub mod send_flags {
    pub const NDIS_SEND_FLAGS_DISPATCH_LEVEL: u32 = 0x01;
    pub const NDIS_SEND_FLAGS_SW_ENCRYPT: u32 = 0x02;
    pub const NDIS_SEND_FLAGS_SW_SECURITY: u32 = 0x04;
    pub const NDIS_SEND_FLAGS_PER_PACKET_INFO: u32 = 0x08;
    pub const NDIS_SEND_FLAGS_SINGLE_QUEUE: u32 = 0x10;
    pub const NDIS_SEND_FLAGS_SHORTCUT: u32 = 0x20;
    pub const NDIS_SEND_FLAGS_DONT_LOOK_BEHIND: u32 = 0x40;
}

/// Process a NET_BUFFER_LIST for sending
pub fn process_send_nbl(
    adapter: *mut MiniportAdapterContext,
    nbl: *mut NetBufferList,
    _send_flags: u32,
) -> i32 {
    if adapter.is_null() || nbl.is_null() {
        return ndis_status::FAILURE;
    }

    unsafe {
        // Get the first NB
        let nb = (*nbl).first_nb();
        if nb.is_null() {
            return ndis_status::FAILURE;
        }

        // Get data from NB
        let data_ptr = (*nb).get_data();
        let data_len = (*nb).get_length() as usize;

        if let Some(data) = data_ptr {
            // The NIC send below is synchronous, so the NB data can be
            // passed straight through - no per-packet heap copy is needed
            // on this hot path.
            let data_slice = core::slice::from_raw_parts(data, data_len);

            // Get NIC type and index
            let nic_type = (*adapter).nic_type;
            let nic_index = (*adapter).nic_index;

            // Try to send directly
            if net::send_to_nic(nic_type, nic_index, data_slice) {
                // Update statistics
                (*adapter).tx_packet(data_len);
                (*nbl).set_status(ndis_status::SUCCESS);
                return ndis_status::SUCCESS;
            }

            // Send failed, mark NBL as having an error
            (*nbl).set_status(ndis_status::FAILURE);
            (*adapter).tx_error();
        } else {
            (*nbl).set_status(ndis_status::FAILURE);
        }
    }

    ndis_status::FAILURE
}

/// Return NBLs to the protocol driver
pub fn return_nbls(
    _adapter: *mut MiniportAdapterContext,
    nbl: *mut NetBufferList,
    _return_flags: u32,
) {
    // Walk the NBL chain and free each one
    let mut current = nbl;
    while !current.is_null() {
        let next = unsafe { (*current).next };
        unsafe {
            NetBufferList::free(current);
        }
        current = next;
    }
}

/// NDIS status codes
pub mod ndis_status {
    pub const SUCCESS: i32 = 0x00000000;
    pub const PENDING: i32 = 0x00000103;
    pub const FAILURE: i32 = 0xC0000001;
    pub const RESOURCES: i32 = 0xC000009A;
    pub const HARDWARE_ERRORS: i32 = 0xC0000185;
    pub const MEDIA_DISCONNECTED: i32 = 0x4000000B;
    pub const MEDIA_CONNECTED: i32 = 0x4000000A;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Under libtest the kernel heap is never initialised; configure a test
    // region so the queue slot allocation works.
    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }
        const TEST_HEAP_LEN: usize = 4 * 1024 * 1024;
        static mut TEST_HEAP: [u8; TEST_HEAP_LEN] = [0u8; TEST_HEAP_LEN];
        let base = core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8;
        crate::mm::heap::KERNEL_HEAP.configure(base, TEST_HEAP_LEN);
    }

    #[test]
    fn queue_preserves_fifo_order_and_wraps() {
        ensure_test_heap();
        let mut queue = SendQueue::new(3);

        // Wrap past capacity with interleaved enqueue/dequeue cycles.
        for round in 0..7u64 {
            let nbl = round as *mut NetBufferList;
            assert!(queue.enqueue(nbl, alloc::vec![round as u8]));
            let (nbl_out, data) = queue.dequeue().unwrap();
            assert_eq!(nbl_out, nbl);
            assert_eq!(data, alloc::vec![round as u8]);
        }
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_rejects_overdepth_and_recovers() {
        ensure_test_heap();
        let mut queue = SendQueue::new(2);

        assert!(queue.enqueue(ptr::null_mut(), alloc::vec![1u8]));
        assert!(queue.enqueue(ptr::null_mut(), alloc::vec![2u8]));
        assert!(queue.is_full());
        assert!(!queue.enqueue(ptr::null_mut(), alloc::vec![3u8]));
        assert_eq!(queue.len(), 2);

        let (_, data) = queue.dequeue().unwrap();
        assert_eq!(data, alloc::vec![1u8]);
        assert!(queue.enqueue(ptr::null_mut(), alloc::vec![3u8]));
        assert_eq!(queue.len(), 2);
        let (_, data) = queue.dequeue().unwrap();
        assert_eq!(data, alloc::vec![2u8]);
        let (_, data) = queue.dequeue().unwrap();
        assert_eq!(data, alloc::vec![3u8]);
        assert!(queue.dequeue().is_none());
    }

    #[test]
    fn zero_depth_queue_never_panics() {
        ensure_test_heap();
        let mut queue = SendQueue::new(0);
        assert!(!queue.enqueue(ptr::null_mut(), Vec::new()));
        assert!(queue.dequeue().is_none());
        assert!(queue.is_empty() && queue.is_full());
    }
}
