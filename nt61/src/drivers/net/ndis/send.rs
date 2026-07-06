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

/// Send queue for buffering packets
pub struct SendQueue {
    entries: Vec<SendQueueEntry>,
    max_depth: usize,
}

impl SendQueue {
    /// Create a new send queue
    pub fn new(max_depth: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_depth,
        }
    }

    /// Add a packet to the queue
    pub fn enqueue(&mut self, nbl: *mut NetBufferList, data: Vec<u8>) -> bool {
        if self.entries.len() >= self.max_depth {
            return false;
        }
        self.entries.push(SendQueueEntry { nbl, data });
        true
    }

    /// Get the next packet from the queue
    pub fn dequeue(&mut self) -> Option<(*mut NetBufferList, Vec<u8>)> {
        if self.entries.is_empty() {
            return None;
        }
        let entry = self.entries.remove(0);
        Some((entry.nbl, entry.data))
    }

    /// Peek at the next packet without removing
    pub fn peek(&self) -> Option<*mut NetBufferList> {
        self.entries.first().map(|e| e.nbl)
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if queue is full
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_depth
    }

    /// Get queue depth
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Send queue with lock
pub struct SendQueueManager {
    queue: Spinlock<SendQueue>,
}

impl SendQueueManager {
    /// Create a new send queue manager
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
            // Copy data
            let mut data_vec = vec![0u8; data_len];
            core::ptr::copy_nonoverlapping(data, data_vec.as_mut_ptr(), data_len);

            // Get NIC type and index
            let nic_type = (*adapter).nic_type;
            let nic_index = (*adapter).nic_index;

            // Try to send directly
            if net::send_to_nic(nic_type, nic_index, &data_vec) {
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
