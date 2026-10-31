//! virtio device drivers shared by every target architecture.
//!
//! The transport layer (virtio-mmio and modern virtio-pci) plus the split
//! virtqueue live here; per-architecture modules only discover devices and
//! wire them into the I/O dispatch stack. Register offsets and layout
//! constants follow the virtio specification and Linux UAPI headers
//! (include/uapi/linux/virtio_mmio.h, virtio_ring.h, virtio_blk.h,
//! virtio_net.h, virtio_gpu.h, virtio_pci.h); machine MMIO windows come
//! from the QEMU machine sources (hw/arm/virt.c, hw/riscv/virt.c,
//! hw/loongarch/virt.c).

extern crate alloc;

pub mod blk;
pub mod gpu;
pub mod mmio;
pub mod net;
pub mod pci;
pub mod queue;

/// Device type identifiers (Linux include/uapi/linux/virtio_ids.h).
pub mod device_id {
    pub const NET: u32 = 1;
    pub const BLOCK: u32 = 2;
    pub const CONSOLE: u32 = 3;
    pub const RNG: u32 = 4;
    pub const GPU: u32 = 16;
    pub const INPUT: u32 = 18;
}

/// Device status bits (virtio spec 2.1 "Device Status Field").
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Feature bit that every device exposes to identify the spec version
/// (virtio spec 2.2 "Feature Bits": VIRTIO_F_VERSION_1).
pub const FEATURE_VERSION_1: u64 = 1 << 32;

use mmio::MmioTransport;
use pci::PciTransport;
use queue::QueueLayout;

/// Transport abstraction shared by virtio-mmio and modern virtio-pci.
/// Device drivers (blk, net, gpu) operate through this trait so the
/// per-architecture code only has to discover and hand over a
/// transport instance.
pub trait Transport {
    /// Device type identifier (virtio_ids.h values).
    fn device_id(&self) -> u32;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read the full 64-bit device feature set.
    unsafe fn read_device_features(&mut self) -> u64;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Write the negotiated driver feature set.
    unsafe fn write_driver_features(&mut self, features: u64);

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Program a virtqueue whose memory has already been laid out.
    unsafe fn setup_queue(&mut self, index: u16, queue: &QueueLayout) -> bool;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Maximum number of descriptors the device supports for a queue.
    unsafe fn max_queue_size(&mut self, index: u16) -> u32;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Kick the device to process the queue's pending descriptors.
    unsafe fn notify(&mut self, index: u16);

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read and acknowledge the interrupt status register.
    unsafe fn read_isr(&mut self) -> u32;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read the device status byte.
    unsafe fn read_status(&mut self) -> u8;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Write the device status byte (status negotiation sequence).
    unsafe fn write_status(&mut self, status: u8);

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Reset the device to the initial state.
    unsafe fn reset(&mut self);

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read one byte from the device-specific configuration space.
    unsafe fn config_read_u8(&self, offset: u64) -> u8;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read one 16-bit word from the device-specific configuration space.
    unsafe fn config_read_u16(&self, offset: u64) -> u16;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read one 32-bit word from the device-specific configuration space.
    unsafe fn config_read_u32(&self, offset: u64) -> u32;

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read one 64-bit word from the device-specific configuration space.
    unsafe fn config_read_u64(&self, offset: u64) -> u64;
}

impl Transport for MmioTransport {
    fn device_id(&self) -> u32 {
        self.device_id()
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_device_features(&mut self) -> u64 {
        MmioTransport::read_device_features(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn write_driver_features(&mut self, features: u64) {
        MmioTransport::write_driver_features(self, features)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn setup_queue(&mut self, index: u16, queue: &QueueLayout) -> bool {
        MmioTransport::setup_queue(self, index, queue)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn max_queue_size(&mut self, index: u16) -> u32 {
        MmioTransport::max_queue_size(self, index)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn notify(&mut self, index: u16) {
        MmioTransport::notify(self, index)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_isr(&mut self) -> u32 {
        MmioTransport::read_isr(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_status(&mut self) -> u8 {
        MmioTransport::read_status(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn write_status(&mut self, status: u8) {
        MmioTransport::write_status(self, status)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn reset(&mut self) {
        MmioTransport::reset(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u8(&self, offset: u64) -> u8 {
        MmioTransport::config_read_u8(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u16(&self, offset: u64) -> u16 {
        MmioTransport::config_read_u16(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u32(&self, offset: u64) -> u32 {
        MmioTransport::config_read_u32(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u64(&self, offset: u64) -> u64 {
        MmioTransport::config_read_u64(self, offset)
    }
}

impl Transport for PciTransport {
    fn device_id(&self) -> u32 {
        self.device_id()
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_device_features(&mut self) -> u64 {
        PciTransport::read_device_features(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn write_driver_features(&mut self, features: u64) {
        PciTransport::write_driver_features(self, features)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn setup_queue(&mut self, index: u16, queue: &QueueLayout) -> bool {
        PciTransport::setup_queue(self, index, queue)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn max_queue_size(&mut self, index: u16) -> u32 {
        PciTransport::max_queue_size(self, index)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn notify(&mut self, index: u16) {
        PciTransport::notify(self, index)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_isr(&mut self) -> u32 {
        PciTransport::read_isr(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn read_status(&mut self) -> u8 {
        PciTransport::read_status(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn write_status(&mut self, status: u8) {
        PciTransport::write_status(self, status)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn reset(&mut self) {
        PciTransport::reset(self)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u8(&self, offset: u64) -> u8 {
        PciTransport::config_read_u8(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u16(&self, offset: u64) -> u16 {
        PciTransport::config_read_u16(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u32(&self, offset: u64) -> u32 {
        PciTransport::config_read_u32(self, offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    unsafe fn config_read_u64(&self, offset: u64) -> u64 {
        PciTransport::config_read_u64(self, offset)
    }
}
