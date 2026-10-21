//! virtio-net NIC driver (virtio spec 4.3; Linux
//! include/uapi/linux/virtio_net.h).
//!
//! Two virtqueues: receive (index 0) and transmit (index 1). Every
//! packet is prefixed with a 10-12 byte header; the num_buffers field
//! is only present when VIRTIO_NET_F_MRG_RXBUF is negotiated.

use super::{queue::QueueBuffer, status, Transport, FEATURE_VERSION_1};

// virtio_net.h feature bits.
pub const F_CSUM: u64 = 0;
pub const F_GUEST_CSUM: u64 = 1;
pub const F_MAC: u64 = 5;
pub const F_MRG_RXBUF: u64 = 15;
pub const F_STATUS: u64 = 16;

// GSO type values (virtio_net.h).
pub const GSO_NONE: u8 = 0;

// Device configuration offsets (virtio_net.h virtio_net_config).
pub const CFG_MAC: u64 = 0;

/// virtio_net_hdr / virtio_net_hdr_size: 10-byte base + 2-byte
/// num_buffers tail (present with F_MRG_RXBUF, zero-padded without).
pub const HDR_LEN: usize = 12;

/// Standard Ethernet MTU (no VLAN tag).
pub const ETH_MTU: usize = 1500;
pub const ETH_HEADER_SIZE: usize = 14;

/// One configured virtio-net device.
pub struct VirtioNet {
    transport_index: usize,
    rx_queue: super::queue::QueueLayout,
    tx_queue: super::queue::QueueLayout,
    mac: [u8; 6],
}

impl VirtioNet {
    /// Bring up a virtio-net device over the given transport.
    pub unsafe fn probe(
        transport_index: usize,
        transport: &mut dyn Transport,
    ) -> Option<VirtioNet> {
        transport.reset();
        transport.write_status(status::ACKNOWLEDGE);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

        let device_features = transport.read_device_features();
        // We need the MAC address feature; the rest are optional.
        let features = FEATURE_VERSION_1 | (device_features & F_MAC);
        transport.write_driver_features(features);
        transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        if transport.read_status() & status::FAILED != 0 {
            return None;
        }

        let rx_max = transport.max_queue_size(0);
        let tx_max = transport.max_queue_size(1);
        let rx_queue = super::queue::QueueLayout::allocate(rx_max as u16)?;
        let tx_queue = super::queue::QueueLayout::allocate(tx_max as u16)?;
        if !transport.setup_queue(0, &rx_queue) || !transport.setup_queue(1, &tx_queue) {
            return None;
        }

        transport.write_status(
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );

        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = transport.config_read_u8(CFG_MAC + i as u64);
        }

        Some(VirtioNet {
            transport_index,
            rx_queue,
            tx_queue,
            mac,
        })
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// Read one received frame into buffer (without the virtio header).
    /// Returns the frame length in bytes, or None when no packet is
    /// pending.
    pub unsafe fn receive(
        &mut self,
        transport: &mut dyn Transport,
        buffer: &mut [u8],
    ) -> Option<usize> {
        let mut header = NetHeader::zeroed();

        // The device writes: header, frame data, num_buffers.
        let head = match self.rx_queue.add_chain(&[
            QueueBuffer::new(&mut header as *mut NetHeader as *mut u8, HDR_LEN, true),
            QueueBuffer::new(buffer.as_mut_ptr(), ETH_MTU + ETH_HEADER_SIZE, true),
        ]) {
            Some(h) => h,
            None => return None,
        };
        unsafe { transport.notify(0) };

        // Busy-wait for the device to deliver the frame.
        loop {
            if let Some((head_idx, written)) = self.rx_queue.pop_used() {
                if head_idx == head {
                    if written < HDR_LEN {
                        return None;
                    }
                    return Some(written - HDR_LEN);
                }
            }
        }
    }

    /// Transmit one frame from buffer.
    pub unsafe fn transmit(&mut self, transport: &mut dyn Transport, buffer: &[u8]) -> bool {
        let mut header = NetHeader::zeroed();
        header.hdr_len = HDR_LEN as u16;

        let head = match self.tx_queue.add_chain(&[
            QueueBuffer::new(&mut header as *mut NetHeader as *mut u8, HDR_LEN, false),
            QueueBuffer::new(buffer.as_ptr() as *mut u8, buffer.len(), false),
        ]) {
            Some(h) => h,
            None => return false,
        };
        unsafe { transport.notify(1) };

        loop {
            if let Some((head_idx, _)) = self.tx_queue.pop_used() {
                if head_idx == head {
                    return true;
                }
            }
        }
    }

    pub fn transport_index(&self) -> usize {
        self.transport_index
    }
}

/// virtio_net_hdr (10 bytes) + num_buffers (2 bytes) = 12 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl NetHeader {
    pub const fn zeroed() -> Self {
        Self {
            flags: 0,
            gso_type: GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        }
    }
}
