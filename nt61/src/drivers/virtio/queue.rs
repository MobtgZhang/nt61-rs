//! Split virtqueue (virtio spec 2.4; Linux include/uapi/linux/virtio_ring.h).
//!
//! One contiguous allocation holds the descriptor table, the available
//! ring and the used ring, laid out with the alignment the legacy
//! transport requires. All buffers are described to the device by
//! physical address; the kernel identity-maps its pool memory on every
//! supported target, so virtual-to-physical translation is performed
//! through mm::virt_to_phys.

use alloc::vec::Vec;
use core::alloc::Layout;

use crate::mm::virt_to_phys;

// Descriptor flag bits (virtio_ring.h VRING_DESC_F_*).
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// Ring flag bits.
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
pub const VRING_USED_F_NO_NOTIFY: u16 = 1;

/// Alignment of the whole virtqueue region (legacy transport contract).
pub const QUEUE_ALIGNMENT: usize = 16;

/// One split-virtqueue descriptor table entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// One used-ring entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UsedElement {
    pub id: u32,
    pub len: u32,
}

/// A buffer in a descriptor chain: data pointer, length and whether
/// the device writes into it (device-writable) or reads from it.
#[derive(Clone, Copy)]
pub struct QueueBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub device_writable: bool,
}

impl QueueBuffer {
    pub fn new(data: *mut u8, len: usize, device_writable: bool) -> Self {
        Self {
            data,
            len,
            device_writable,
        }
    }
}

/// A configured split virtqueue: descriptor table + avail/used rings.
pub struct QueueLayout {
    num: u16,
    mem: *mut u8,
    mem_len: usize,
    desc: *mut Descriptor,
    avail_base: *mut u8,
    used_base: *mut u8,
    free_head: u16,
    free_count: u16,
    avail_index: u16,
    last_used: u16,
}

impl QueueLayout {
    /// Allocate and initialise a queue of num descriptors.
    /// Layout: desc table, avail ring (flags + idx + ring + event),
    /// used ring (flags + idx + ring + event), each 16-byte aligned
    /// and the whole region 4 KiB aligned for the legacy PFN path.
    pub fn allocate(num: u16) -> Option<QueueLayout> {
        crate::hal::serial::write_string_always("[QUEUE] allocate enter\r\n");
        if num == 0 || (num & (num - 1)) != 0 {
            return None;
        }
        let desc_len = num as usize * core::mem::size_of::<Descriptor>();
        let avail_len = 4 + num as usize * 2 + 2;
        let used_len = 4 + num as usize * core::mem::size_of::<UsedElement>() + 2;
        let align = 16;
        let avail_off = (desc_len + align - 1) & !(align - 1);
        let used_off = (avail_off + avail_len + align - 1) & !(align - 1);
        let mem_len = used_off + used_len;

        let _layout = match Layout::from_size_align(mem_len, QUEUE_ALIGNMENT) {
            Ok(layout) => layout,
            Err(_) => return None,
        };
        crate::hal::serial::write_string_always("[QUEUE] layout ok\r\n");
        let stack_probe = 0u8;
        let stack_addr = (&stack_probe as *const u8) as u64;
        crate::hal::serial::write_string_always("[QUEUE] sp=0x");
        crate::hal::serial::write_hex_u64_always(stack_addr);
        crate::hal::serial::write_string_always(" size=0x");
        crate::hal::serial::write_hex_u64_always(mem_len as u64);
        crate::hal::serial::write_string_always("\r\n");
        let page_count = mem_len.div_ceil(4096) as u64;
        let mem_phys = crate::mm::allocate_pages(page_count)?;
        let map_base = mem_phys & !0x1F_FFFF;
        if !crate::arch::identity_map_region(map_base, 0x20_0000) {
            crate::mm::free_pages(mem_phys, page_count);
            return None;
        }
        let mem = mem_phys as *mut u8;
        if mem.is_null() {
            return None;
        }
        unsafe {
            core::ptr::write_bytes(mem, 0, mem_len);
            let desc = mem as *mut Descriptor;
            let avail_base = mem.add(avail_off);
            let used_base = mem.add(used_off);

            // Free list: every descriptor chained through next.
            for i in 0..num as usize {
                let d = desc.add(i);
                (*d).next = ((i + 1) % num as usize) as u16;
                (*d).flags = 0;
                (*d).len = 0;
                (*d).addr = 0;
            }

            Some(QueueLayout {
                num,
                mem,
                mem_len,
                desc,
                avail_base,
                used_base,
                free_head: 0,
                free_count: num,
                avail_index: 0,
                last_used: 0,
            })
        }
    }

    pub fn num(&self) -> u16 {
        self.num
    }

    pub fn free_count(&self) -> u16 {
        self.free_count
    }

    /// Physical address of the descriptor table (for the transport).
    pub fn desc_physical(&self) -> Option<u64> {
        virt_to_phys(self.desc as u64)
    }

    pub fn avail_physical(&self) -> Option<u64> {
        virt_to_phys(self.avail_base as u64)
    }

    pub fn used_physical(&self) -> Option<u64> {
        virt_to_phys(self.used_base as u64)
    }

    /// Append one descriptor chain built from buffers and return the
    /// chain head index that will appear in the used ring on completion.
    pub fn add_chain(&mut self, buffers: &[QueueBuffer]) -> Option<u16> {
        if buffers.is_empty() || self.free_count < buffers.len() as u16 {
            return None;
        }
        unsafe {
            let head = self.free_head;
            let mut current = head;
            let next_head = ((head as usize + buffers.len()) % self.num as usize) as u16;
            for (i, buffer) in buffers.iter().enumerate() {
                let phys = virt_to_phys(buffer.data as u64)?;
                let d = self.desc.add(current as usize);
                (*d).addr = phys;
                (*d).len = buffer.len as u32;
                let mut flags = 0;
                if buffer.device_writable {
                    flags |= VRING_DESC_F_WRITE;
                }
                if i + 1 < buffers.len() {
                    flags |= VRING_DESC_F_NEXT;
                    (*d).next = ((current as usize + 1) % self.num as usize) as u16;
                    current = (*d).next;
                } else {
                    (*d).next = 0;
                }
                (*d).flags = flags;
            }
            self.free_head = next_head;
            self.free_count -= buffers.len() as u16;

            // Push head into the available ring and bump the index.
            let avail_idx = self.avail_base as *mut u16;
            let ring = self.avail_base.add(4) as *mut u16;
            let slot = (self.avail_index as usize) % self.num as usize;
            core::ptr::write_volatile(ring.add(slot), head);
            // Publish the ring entry before the index update.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_idx.add(1), self.avail_index.wrapping_add(1));
            self.avail_index = self.avail_index.wrapping_add(1);
            Some(head)
        }
    }

    /// Pop one completed chain from the used ring:
    /// (head index as passed to add_chain, total written bytes).
    /// Returns None when the device has not completed anything yet.
    pub fn pop_used(&mut self) -> Option<(u16, usize)> {
        unsafe {
            let used_idx_ptr = self.used_base.add(2) as *mut u16;
            let used_idx = core::ptr::read_volatile(used_idx_ptr);
            if used_idx == self.last_used {
                return None;
            }

            let elem_size = core::mem::size_of::<UsedElement>();
            let ring = self.used_base.add(4);
            let slot = (self.last_used as usize) % self.num as usize;
            let elem = ring.add(slot * elem_size) as *mut UsedElement;
            let id = core::ptr::read_volatile(&(*elem).id);
            let len = core::ptr::read_volatile(&(*elem).len) as usize;

            // Return the whole chain to the free list.
            let mut cursor = id as u16;
            let mut chain_len = 0u16;
            loop {
                let d = self.desc.add(cursor as usize);
                chain_len += 1;
                let has_next = (*d).flags & VRING_DESC_F_NEXT != 0;
                if has_next {
                    cursor = (*d).next;
                } else {
                    // Chain tail becomes the new free head.
                    (*d).next = self.free_head;
                    break;
                }
            }
            self.free_head = id as u16;
            self.free_count += chain_len;
            self.last_used = self.last_used.wrapping_add(1);
            Some((id as u16, len))
        }
    }

    /// Drain every completed chain (used when tearing down or flushing).
    pub fn drain_used(&mut self) -> Vec<(u16, usize)> {
        let mut out = Vec::new();
        while let Some(entry) = self.pop_used() {
            out.push(entry);
        }
        out
    }
}

impl Drop for QueueLayout {
    fn drop(&mut self) {
        if !self.mem.is_null() {
            let page_count = self.mem_len.div_ceil(4096) as u64;
            crate::mm::free_pages(self.mem as u64, page_count);
            self.mem = core::ptr::null_mut();
        }
    }
}
