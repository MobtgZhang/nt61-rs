//! virtio-blk block device driver (virtio spec 4.1; Linux
//! include/uapi/linux/virtio_blk.h).
//!
//! One request virtqueue carries (header, data, status) descriptor
//! chains. The header carries the operation type (IN/OUT/FLUSH), a
//! priority (always zero) and the starting sector (512-byte units).

use alloc::vec::Vec;

use super::{queue::QueueBuffer, status, Transport, FEATURE_VERSION_1};

// virtio_blk.h feature bits.
pub const F_SIZE_MAX: u64 = 1;
pub const F_SEG_MAX: u64 = 2;
pub const F_BLK_SIZE: u64 = 6;
pub const F_FLUSH: u64 = 9;

// virtio_blk.h operation types (VIRTIO_BLK_T_*).
pub const TYPE_IN: u32 = 0;
pub const TYPE_OUT: u32 = 1;
pub const TYPE_FLUSH: u32 = 4;

// virtio_blk.h S_OK / S_IOERR status bytes.
pub const S_OK: u8 = 0;
pub const S_IOERR: u8 = 2;

// Device-specific configuration offsets (virtio_blk.h virtio_blk_config).
pub const CFG_CAPACITY: u64 = 0;
pub const CFG_SIZE_MAX: u64 = 8;
pub const CFG_SEG_MAX: u64 = 12;
pub const CFG_BLK_SIZE: u64 = 16;

/// Standard 512-byte logical sector.
pub const SECTOR_SIZE: u32 = 512;

/// Maximum number of virtio-blk devices tracked by the dispatch layer.
pub const MAX_DISPATCH_DEVICES: usize = 8;

/// virtio_blk_req_header: one request descriptor's header.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RequestHeader {
    pub req_type: u32,
    pub ioprio: u32,
    pub sector: u64,
}

/// One configured virtio-blk device.
pub struct VirtioBlk {
    transport_index: usize,
    queue: super::queue::QueueLayout,
    capacity_sectors: u64,
    /// Set of feature bits negotiated with the device.
    features: u64,
}

impl VirtioBlk {
    /// Bring up a virtio-blk device over the given transport.
    /// Performs the standard status negotiation sequence
    /// (ACKNOWLEDGE -> DRIVER -> FEATURES_OK -> DRIVER_OK).
    pub unsafe fn probe(
        transport_index: usize,
        transport: &mut dyn Transport,
    ) -> Option<VirtioBlk> {
        transport.reset();
        transport.write_status(status::ACKNOWLEDGE);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

        let device_features = transport.read_device_features();
        // Negotiate the base spec version plus the features the driver
        // understands. Only F_FLUSH and F_BLK_SIZE influence our I/O
        // path; everything else is optional and left unset.
        let features =
            FEATURE_VERSION_1 | (device_features & F_FLUSH) | (device_features & F_BLK_SIZE);
        transport.write_driver_features(features);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        let current = transport.read_status();
        if current & status::FAILED != 0 {
            return None;
        }

        let max = transport.max_queue_size(0);
        let queue = super::queue::QueueLayout::allocate(max as u16)?;
        if !transport.setup_queue(0, &queue) {
            return None;
        }

        transport.write_status(
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );

        let capacity = transport.config_read_u64(CFG_CAPACITY);
        Some(VirtioBlk {
            transport_index,
            queue,
            capacity_sectors: capacity,
            features,
        })
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub fn has_flush(&self) -> bool {
        self.features & F_FLUSH != 0
    }

    pub fn has_blk_size(&self) -> bool {
        self.features & F_BLK_SIZE != 0
    }

    /// Read one or more 512-byte sectors into buffer.
    pub unsafe fn read_sectors(
        &mut self,
        transport: &mut dyn Transport,
        lba: u64,
        buffer: &mut [u8],
    ) -> bool {
        self.submit(transport, TYPE_IN, lba, buffer).is_some()
    }

    /// Write one or more 512-byte sectors from buffer.
    pub unsafe fn write_sectors(
        &mut self,
        transport: &mut dyn Transport,
        lba: u64,
        buffer: &[u8],
    ) -> bool {
        self.submit_write(transport, TYPE_OUT, lba, buffer)
            .is_some()
    }

    /// Flush the device cache.
    pub unsafe fn flush(&mut self, transport: &mut dyn Transport) -> bool {
        self.submit_flush(transport).is_some()
    }

    /// Build and submit one request chain, then wait for completion.
    fn submit(
        &mut self,
        transport: &mut dyn Transport,
        req_type: u32,
        lba: u64,
        buffer: &mut [u8],
    ) -> Option<usize> {
        let mut header = RequestHeader {
            req_type,
            ioprio: 0,
            sector: lba,
        };
        let status_byte: u8 = S_IOERR;

        let mut buffers = Vec::new();
        buffers.push(QueueBuffer::new(
            &mut header as *mut RequestHeader as *mut u8,
            core::mem::size_of::<RequestHeader>(),
            false,
        ));
        buffers.push(QueueBuffer::new(
            buffer.as_mut_ptr(),
            buffer.len(),
            req_type == TYPE_IN,
        ));
        buffers.push(QueueBuffer::new(
            &status_byte as *const u8 as *mut u8,
            1,
            true,
        ));

        let head = self.queue.add_chain(&buffers)?;
        unsafe { transport.notify(0) };

        // Busy-wait for completion (single-threaded boot path).
        loop {
            let used = self.queue.pop_used();
            if let Some((head_idx, _)) = used {
                if head_idx == head && status_byte == S_OK {
                    return Some(buffer.len());
                }
                if head_idx == head {
                    return None;
                }
            }
        }
    }

    /// Build and submit one write request chain from a read-only buffer.
    fn submit_write(
        &mut self,
        transport: &mut dyn Transport,
        req_type: u32,
        lba: u64,
        buffer: &[u8],
    ) -> Option<usize> {
        let mut header = RequestHeader {
            req_type,
            ioprio: 0,
            sector: lba,
        };
        let status_byte: u8 = S_IOERR;
        let mut buffers = Vec::new();
        buffers.push(QueueBuffer::new(
            &mut header as *mut RequestHeader as *mut u8,
            core::mem::size_of::<RequestHeader>(),
            false,
        ));
        buffers.push(QueueBuffer::new(
            buffer.as_ptr() as *mut u8,
            buffer.len(),
            false,
        ));
        buffers.push(QueueBuffer::new(
            &status_byte as *const u8 as *mut u8,
            1,
            true,
        ));
        let head = self.queue.add_chain(&buffers)?;
        unsafe { transport.notify(0) };
        loop {
            if let Some((head_idx, _)) = self.queue.pop_used() {
                if head_idx == head && status_byte == S_OK {
                    return Some(buffer.len());
                }
                if head_idx == head {
                    return None;
                }
            }
        }
    }

    /// Build and submit one flush chain (header + status, no data).
    fn submit_flush(&mut self, transport: &mut dyn Transport) -> Option<usize> {
        let mut header = RequestHeader {
            req_type: TYPE_FLUSH,
            ioprio: 0,
            sector: 0,
        };
        let status_byte: u8 = S_IOERR;

        let mut buffers = Vec::new();
        buffers.push(QueueBuffer::new(
            &mut header as *mut RequestHeader as *mut u8,
            core::mem::size_of::<RequestHeader>(),
            false,
        ));
        buffers.push(QueueBuffer::new(
            &status_byte as *const u8 as *mut u8,
            1,
            true,
        ));

        let head = self.queue.add_chain(&buffers)?;
        unsafe { transport.notify(0) };

        loop {
            let used = self.queue.pop_used();
            if let Some((head_idx, _)) = used {
                if head_idx == head && status_byte == S_OK {
                    return Some(0);
                }
                if head_idx == head {
                    return None;
                }
            }
        }
    }

    pub fn transport_index(&self) -> usize {
        self.transport_index
    }
}
