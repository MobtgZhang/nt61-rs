//! virtio-mmio transport (virtio spec 4.2 "MMIO Device").
//!
//! Register offsets are the Linux UAPI virtio_mmio.h layout. Legacy
//! (version 1) devices use the page-frame-number queue interface with
//! 32-bit features; modern (version 2) devices use the 64-bit queue
//! address interface. QEMU defaults virtio-mmio to legacy
//! (hw/virtio/virtio-mmio.c, force-legacy property), so both layouts
//! are supported and selected at probe time.

use super::queue::QueueLayout;

/// MagicValue register content: ASCII "virt".
pub const MAGIC_VALUE: u32 = 0x7472_6976;
pub const VERSION_LEGACY: u32 = 1;
pub const VERSION_MODERN: u32 = 2;

/// Queue page-frame unit for the legacy PFN interface (4 KiB).
pub const PFN_PAGE_SIZE: u64 = 4096;

// Register offsets (Linux include/uapi/linux/virtio_mmio.h).
pub const REG_MAGIC_VALUE: u64 = 0x000;
pub const REG_VERSION: u64 = 0x004;
pub const REG_DEVICE_ID: u64 = 0x008;
pub const REG_VENDOR_ID: u64 = 0x00c;
pub const REG_DEVICE_FEATURES: u64 = 0x010;
pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const REG_DRIVER_FEATURES: u64 = 0x020;
pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const REG_GUEST_PAGE_SIZE: u64 = 0x028;
pub const REG_QUEUE_SEL: u64 = 0x030;
pub const REG_QUEUE_NUM_MAX: u64 = 0x034;
pub const REG_QUEUE_NUM: u64 = 0x038;
pub const REG_QUEUE_ALIGN: u64 = 0x03c;
pub const REG_QUEUE_PFN: u64 = 0x040;
pub const REG_QUEUE_READY: u64 = 0x044;
pub const REG_QUEUE_NOTIFY: u64 = 0x050;
pub const REG_INTERRUPT_STATUS: u64 = 0x060;
pub const REG_INTERRUPT_ACK: u64 = 0x064;
pub const REG_STATUS: u64 = 0x070;
pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
pub const REG_QUEUE_AVAIL_LOW: u64 = 0x090;
pub const REG_QUEUE_AVAIL_HIGH: u64 = 0x094;
pub const REG_QUEUE_USED_LOW: u64 = 0x0a0;
pub const REG_QUEUE_USED_HIGH: u64 = 0x0a4;
pub const REG_CONFIG_GENERATION: u64 = 0x0fc;
pub const REG_CONFIG: u64 = 0x100;

// Interrupt status bits (Linux virtio_mmio.h).
pub const INT_VRING: u32 = 1 << 0;
pub const INT_CONFIG: u32 = 1 << 1;

/// One live virtio-mmio device slot.
pub struct MmioTransport {
    base: u64,
    device_id: u32,
    is_modern: bool,
}

impl MmioTransport {
    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Probe an MMIO window; returns the transport when the slot holds a
    /// live virtio-mmio device (magic "virt", known protocol version).
    pub unsafe fn probe(base: u64) -> Option<MmioTransport> {
        if read_u32(base + REG_MAGIC_VALUE) != MAGIC_VALUE {
            return None;
        }
        let version = read_u32(base + REG_VERSION);
        if version != VERSION_LEGACY && version != VERSION_MODERN {
            return None;
        }
        Some(MmioTransport {
            base,
            device_id: read_u32(base + REG_DEVICE_ID),
            is_modern: version == VERSION_MODERN,
        })
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read the full 64-bit device feature set (legacy devices only
    /// expose the low 32 bits; the high word reads as zero).
    pub unsafe fn read_device_features(&mut self) -> u64 {
        if self.is_modern {
            write_u32(self.base + REG_DEVICE_FEATURES_SEL, 1);
            let high = read_u32(self.base + REG_DEVICE_FEATURES) as u64;
            write_u32(self.base + REG_DEVICE_FEATURES_SEL, 0);
            let low = read_u32(self.base + REG_DEVICE_FEATURES) as u64;
            (high << 32) | low
        } else {
            read_u32(self.base + REG_DEVICE_FEATURES) as u64
        }
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn write_driver_features(&mut self, features: u64) {
        if self.is_modern {
            write_u32(self.base + REG_DRIVER_FEATURES_SEL, 1);
            write_u32(self.base + REG_DRIVER_FEATURES, (features >> 32) as u32);
            write_u32(self.base + REG_DRIVER_FEATURES_SEL, 0);
            write_u32(self.base + REG_DRIVER_FEATURES, features as u32);
        } else {
            write_u32(self.base + REG_DRIVER_FEATURES, features as u32);
        }
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Program the transport for a virtqueue whose memory layout has
    /// already been initialised.
    pub unsafe fn setup_queue(&mut self, index: u16, queue: &QueueLayout) -> bool {
        write_u32(self.base + REG_QUEUE_SEL, index as u32);
        if !self.is_modern {
            // Legacy: page-aligned PFN of the descriptor table.
            let desc_phys = match queue.desc_physical() {
                Some(addr) => addr,
                None => return false,
            };
            write_u32(self.base + REG_QUEUE_NUM, queue.num() as u32);
            write_u32(self.base + REG_QUEUE_ALIGN, PFN_PAGE_SIZE as u32);
            let pfn = desc_phys / PFN_PAGE_SIZE;
            write_u32(self.base + REG_QUEUE_PFN, pfn as u32);
            read_u32(self.base + REG_QUEUE_PFN) == pfn as u32
        } else {
            // Modern: 64-bit queue region addresses plus QUEUE_READY.
            let (desc, avail, used) = match (
                queue.desc_physical(),
                queue.avail_physical(),
                queue.used_physical(),
            ) {
                (Some(d), Some(a), Some(u)) => (d, a, u),
                _ => return false,
            };
            write_u32(self.base + REG_QUEUE_NUM, queue.num() as u32);
            write_u32(self.base + REG_QUEUE_DESC_LOW, desc as u32);
            write_u32(self.base + REG_QUEUE_DESC_HIGH, (desc >> 32) as u32);
            write_u32(self.base + REG_QUEUE_AVAIL_LOW, avail as u32);
            write_u32(self.base + REG_QUEUE_AVAIL_HIGH, (avail >> 32) as u32);
            write_u32(self.base + REG_QUEUE_USED_LOW, used as u32);
            write_u32(self.base + REG_QUEUE_USED_HIGH, (used >> 32) as u32);
            write_u32(self.base + REG_QUEUE_READY, 1);
            read_u32(self.base + REG_QUEUE_READY) == 1
        }
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn max_queue_size(&mut self, index: u16) -> u32 {
        write_u32(self.base + REG_QUEUE_SEL, index as u32);
        read_u32(self.base + REG_QUEUE_NUM_MAX)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn notify(&mut self, index: u16) {
        write_u32(self.base + REG_QUEUE_NOTIFY, index as u32);
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Read and acknowledge the ISR status register.
    pub unsafe fn read_isr(&mut self) -> u32 {
        let isr = read_u32(self.base + REG_INTERRUPT_STATUS);
        write_u32(self.base + REG_INTERRUPT_ACK, isr);
        isr
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn read_status(&mut self) -> u8 {
        read_u32(self.base + REG_STATUS) as u8
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn write_status(&mut self, status: u8) {
        write_u32(self.base + REG_STATUS, status as u32);
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn reset(&mut self) {
        write_u32(self.base + REG_STATUS, 0);
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Device-specific configuration space starts at REG_CONFIG.
    pub unsafe fn config_read_u8(&self, offset: u64) -> u8 {
        read_u8(self.base + REG_CONFIG + offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn config_read_u16(&self, offset: u64) -> u16 {
        read_u16(self.base + REG_CONFIG + offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn config_read_u32(&self, offset: u64) -> u32 {
        read_u32(self.base + REG_CONFIG + offset)
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    pub unsafe fn config_read_u64(&self, offset: u64) -> u64 {
        let low = self.config_read_u32(offset) as u64;
        let high = self.config_read_u32(offset + 4) as u64;
        (high << 32) | low
    }
}

// ---------------------------------------------------------------------------
// Volatile MMIO accessors
// ---------------------------------------------------------------------------

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn read_u8(addr: u64) -> u8 {
    core::ptr::read_volatile(addr as *const u8)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn read_u16(addr: u64) -> u16 {
    core::ptr::read_volatile(addr as *const u16)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn read_u32(addr: u64) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn write_u32(addr: u64, value: u32) {
    core::ptr::write_volatile(addr as *mut u32, value);
}
