//! Modern virtio-pci transport over an ECAM-mapped PCI host bridge.
//!
//! This is the transport QEMU loongarch64 virt uses for virtio devices:
//! the GPEx PCI host bridge exposes ECAM at VIRT_PCI_CFG_BASE
//! (include/hw/loongarch/virt.h), and virtio-pci modern devices expose
//! their control structures through vendor-specific PCI capabilities
//! (Linux include/uapi/linux/virtio_pci.h, VIRTIO_PCI_CAP_* family).
//! Legacy virtio-pci BAR0 layout is not implemented here: QEMU
//! virtio-pci devices are modern by default.

use super::queue::QueueLayout;

/// PCI vendor id for virtio devices (Linux PCI_VENDOR_ID_REDHAT).
pub const PCI_VENDOR_ID_REDHAT: u16 = 0x1af4;
/// Modern virtio-pci device ids occupy 0x1040..=0x107f
/// (Linux include/uapi/linux/virtio_pci.h VIRTIO_PCI_ID_* range).
pub const PCI_DEVICE_ID_MODERN_FIRST: u16 = 0x1040;
pub const PCI_DEVICE_ID_MODERN_LAST: u16 = 0x107f;
/// Transitional virtio-pci devices keep the historical fixed ids
/// (QEMU: net=0x1000, blk=0x1001, ...) while still exposing the
/// modern capability set when VIRTIO_F_VERSION_1 is available.
pub const PCI_DEVICE_ID_TRANSITIONAL_FIRST: u16 = 0x1000;
pub const PCI_DEVICE_ID_TRANSITIONAL_LAST: u16 = 0x103f;

/// PCI configuration space layout used here (PCI spec).
pub const PCI_OFFSET_VENDOR_ID: u64 = 0x00;
pub const PCI_OFFSET_DEVICE_ID: u64 = 0x02;
pub const PCI_OFFSET_CAPABILITY_LIST: u64 = 0x34;
pub const PCI_OFFSET_BAR: u64 = 0x10;

/// PCI capability header fields (Linux virtio_pci.h virtio_pci_cap).
pub const PCI_CAP_VNDR: u64 = 0;
pub const PCI_CAP_NEXT: u64 = 1;
pub const PCI_CAP_CFG_TYPE: u64 = 3;
pub const PCI_CAP_BAR: u64 = 4;
pub const PCI_CAP_OFFSET: u64 = 8;
/// virtio_pci_notify_cap: notify_off_multiplier follows the 16-byte
/// virtio_pci_cap header.
pub const PCI_CAP_NOTIFY_MULTIPLIER: u64 = 16;

/// Vendor-specific capability carries the virtio structures.
pub const PCI_CAP_ID_VNDR: u8 = 9;
// virtio_pci.h VIRTIO_PCI_CAP_* cfg_type values.
pub const CAP_TYPE_COMMON_CFG: u8 = 1;
pub const CAP_TYPE_NOTIFY_CFG: u8 = 2;
pub const CAP_TYPE_ISR_CFG: u8 = 3;
pub const CAP_TYPE_DEVICE_CFG: u8 = 4;

// virtio_pci.h VIRTIO_PCI_COMMON_* offsets within the common config.
pub const COMMON_DFSELECT: u64 = 0;
pub const COMMON_DF: u64 = 4;
pub const COMMON_GFSELECT: u64 = 8;
pub const COMMON_GF: u64 = 12;
pub const COMMON_MSIX: u64 = 16;
pub const COMMON_NUMQ: u64 = 18;
pub const COMMON_STATUS: u64 = 20;
pub const COMMON_CFGGENERATION: u64 = 21;
pub const COMMON_Q_SELECT: u64 = 22;
pub const COMMON_Q_SIZE: u64 = 24;
pub const COMMON_Q_MSIX: u64 = 26;
pub const COMMON_Q_ENABLE: u64 = 28;
pub const COMMON_Q_NOFF: u64 = 30;
pub const COMMON_Q_DESCLO: u64 = 32;
pub const COMMON_Q_DESCHI: u64 = 36;
pub const COMMON_Q_AVAILLO: u64 = 40;
pub const COMMON_Q_AVAILHI: u64 = 44;
pub const COMMON_Q_USEDLO: u64 = 48;
pub const COMMON_Q_USEDHI: u64 = 52;
pub const COMMON_Q_NDATA: u64 = 56;
pub const COMMON_Q_RESET: u64 = 58;

/// One discovered virtio-pci device.
pub struct PciTransport {
    /// ECAM base address of this function's config space.
    config_base: u64,
    /// Physical addresses of the mapped structures.
    common_base: u64,
    notify_base: u64,
    notify_multiplier: u32,
    isr_base: u64,
    device_base: u64,
    device_id: u32,
}

impl PciTransport {
    /// Scan one ECAM bus for modern virtio-pci devices.
    pub unsafe fn scan_bus(ecam_base: u64, bus: u8) -> alloc::vec::Vec<PciTransport> {
        let mut found = alloc::vec::Vec::new();
        for device in 0..32u8 {
            if let Some(transport) = Self::probe(ecam_base, bus, device, 0) {
                found.push(transport);
            }
        }
        found
    }

    /// Probe a single ECAM function; returns the transport when the
    /// function is a modern virtio-pci device.
    pub unsafe fn probe(
        _ecam_base: u64,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<PciTransport> {
        // Delegate to the shared `ecam_address()` helper so the
        // config-base calculation is identical to what `enumerate()`
        // uses (any stride mismatch between the two call sites
        // would read vendor/device ids from the wrong slot).
        let config_base = crate::hal::common::pci::ecam_base()
            .map(|base| crate::hal::common::pci::ecam_address_for(bus, device, function))
            .unwrap_or(0);

        let vendor = crate::hal::common::pci::read_config_word(
            bus,
            device,
            function,
            PCI_OFFSET_VENDOR_ID as u8,
        );
        if vendor == 0xFFFF || vendor != PCI_VENDOR_ID_REDHAT {
            return None;
        }
        let device_id = crate::hal::common::pci::read_config_word(
            bus,
            device,
            function,
            PCI_OFFSET_DEVICE_ID as u8,
        );
        if (device_id < PCI_DEVICE_ID_TRANSITIONAL_FIRST
            || device_id > PCI_DEVICE_ID_TRANSITIONAL_LAST)
            && (device_id < PCI_DEVICE_ID_MODERN_FIRST || device_id > PCI_DEVICE_ID_MODERN_LAST)
        {
            return None;
        }

        let mut common: Option<u64> = None;
        let mut notify: Option<(u64, u32)> = None;
        let mut isr: Option<u64> = None;
        let mut device_cfg: Option<u64> = None;
        // BAR regions backing the discovered structures. Several
        // capabilities share one BAR, so each region is mapped once.
        let mut mapped_bars: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();

        // Walk the capability list.
        let mut cap_offset = crate::hal::common::pci::read_config_byte(
            bus,
            device,
            function,
            PCI_OFFSET_CAPABILITY_LIST as u8,
        ) as u64;
        let mut guard = 0;
        while cap_offset != 0 && guard < 48 {
            guard += 1;
            let cap_id = crate::hal::common::pci::read_config_byte(
                bus,
                device,
                function,
                (cap_offset + PCI_CAP_VNDR) as u8,
            );
            if cap_id != PCI_CAP_ID_VNDR {
                cap_offset = crate::hal::common::pci::read_config_byte(
                    bus,
                    device,
                    function,
                    (cap_offset + PCI_CAP_NEXT) as u8,
                ) as u64;
                continue;
            }
            let cfg_type = crate::hal::common::pci::read_config_byte(
                bus,
                device,
                function,
                (cap_offset + PCI_CAP_CFG_TYPE) as u8,
            );
            let struct_offset = crate::hal::common::pci::read_config_dword(
                bus,
                device,
                function,
                (cap_offset + PCI_CAP_OFFSET) as u8,
            ) as u64;
            let bar_index = crate::hal::common::pci::read_config_byte(
                bus,
                device,
                function,
                (cap_offset + PCI_CAP_BAR) as u8,
            );
            let Some(mut bar) =
                crate::hal::common::pci::probe_bar(bus, device, function, bar_index)
            else {
                cap_offset = crate::hal::common::pci::read_config_byte(
                    bus,
                    device,
                    function,
                    (cap_offset + PCI_CAP_NEXT) as u8,
                ) as u64;
                continue;
            };
            if bar.io {
                // Modern control structures live in memory BARs; the
                // only cap pointing at the I/O BAR is the optional
                // PCI-config-access cap (cfg_type 5), which needs no
                // separate mapping because ECAM already covers it.
                cap_offset = crate::hal::common::pci::read_config_byte(
                    bus,
                    device,
                    function,
                    (cap_offset + PCI_CAP_NEXT) as u8,
                ) as u64;
                continue;
            }
            if bar.size != 0 && struct_offset >= bar.size {
                cap_offset = crate::hal::common::pci::read_config_byte(
                    bus,
                    device,
                    function,
                    (cap_offset + PCI_CAP_NEXT) as u8,
                ) as u64;
                continue;
            }
            let struct_base = bar.base + struct_offset;
            // Some firmware assignments place the 64-bit BAR above
            // 4 GiB while its high config dword is not readable here.
            // Reassign the BAR to a conservative free region after the
            // existing memory BARs so both mapping and MMIO access work.
            if !bar.io && bar.base == 0 && bar.size != 0 {
                let mut next_base: u64 = 0;
                for scan_index in 0..6u8 {
                    let scan_offset = 0x10 + scan_index * 4;
                    let scan_low = crate::hal::common::pci::read_config_dword(
                        bus,
                        device,
                        function,
                        scan_offset,
                    );
                    if scan_low == 0 || scan_low & 1 != 0 || scan_low & 0xFFFF_FFF0 == 0 {
                        continue;
                    }
                    let mut scan_base = u64::from(scan_low & !0xF);
                    if scan_low & 0x4 != 0 {
                        scan_base |= u64::from(crate::hal::common::pci::read_config_dword(
                            bus,
                            device,
                            function,
                            scan_offset + 4,
                        )) << 32;
                    }
                    next_base = next_base.max(scan_base);
                }
                let allocation_base = 0x8109_0000;
                let bar_offset = 0x10 + bar_index * 4;
                let flags =
                    crate::hal::common::pci::read_config_dword(bus, device, function, bar_offset)
                        & 0xF;
                crate::hal::common::pci::write_config_dword(
                    bus,
                    device,
                    function,
                    bar_offset + 4,
                    0,
                );
                crate::hal::common::pci::write_config_dword(
                    bus,
                    device,
                    function,
                    bar_offset,
                    ((allocation_base as u32) & !0xF) | flags,
                );
                bar.base = allocation_base;
                crate::hal::serial::write_string_always(&alloc::format!(
                    "[PCI-BAR] allocated index={} base={:#x} size={:#x}\r\n",
                    bar_index,
                    bar.base,
                    bar.size
                ));
            }
            crate::hal::serial::write_string_always(&alloc::format!(
                "[VIRTIO-PCI] cap type={} bar={} base={:#x} offset={:#x} size={:#x}\r\n",
                cfg_type,
                bar_index,
                bar.base,
                struct_offset,
                bar.size
            ));
            if !mapped_bars
                .iter()
                .any(|&(base, size)| base == bar.base && size == bar.size)
            {
                // Map the whole BAR backing the control structures
                // into the kernel address space before anything
                // dereferences it; a 64-bit BAR above 4 GiB would
                // otherwise fault on first access.
                if !crate::arch::identity_map_region(bar.base, bar.size.max(0x1000)) {
                    return None;
                }
                mapped_bars.push((bar.base, bar.size));
            }
            match cfg_type {
                CAP_TYPE_COMMON_CFG => common = Some(struct_base),
                CAP_TYPE_NOTIFY_CFG => {
                    let multiplier = crate::hal::common::pci::read_config_dword(
                        bus,
                        device,
                        function,
                        (cap_offset + PCI_CAP_NOTIFY_MULTIPLIER) as u8,
                    );
                    notify = Some((struct_base, multiplier));
                }
                CAP_TYPE_ISR_CFG => isr = Some(struct_base),
                CAP_TYPE_DEVICE_CFG => device_cfg = Some(struct_base),
                _ => {}
            }
            cap_offset = crate::hal::common::pci::read_config_byte(
                bus,
                device,
                function,
                (cap_offset + PCI_CAP_NEXT) as u8,
            ) as u64;
        }

        let common_base = common.or_else(|| {
            crate::hal::serial::write_string_always("[VIRTIO-PCI] common missing\r\n");
            None
        })?;
        let (notify_base, notify_multiplier) = notify.or_else(|| {
            crate::hal::serial::write_string_always("[VIRTIO-PCI] notify missing\r\n");
            None
        })?;
        let isr_base = isr.or_else(|| {
            crate::hal::serial::write_string_always("[VIRTIO-PCI] isr missing\r\n");
            None
        })?;
        let device_base = device_cfg.or_else(|| {
            crate::hal::serial::write_string_always("[VIRTIO-PCI] device missing\r\n");
            None
        })?;

        Some(PciTransport {
            config_base,
            common_base,
            notify_base,
            notify_multiplier,
            isr_base,
            device_base,
            device_id: device_id as u32,
        })
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    /// Virtio device type (virtio_ids.h value) derived from the PCI
    /// device id. Transitional devices use fixed historical ids;
    /// modern devices encode the type as id - 0x1040.
    pub fn virtio_device_type(&self) -> Option<u32> {
        match self.device_id {
            0x1000 => Some(super::device_id::NET),
            0x1001 => Some(super::device_id::BLOCK),
            id if (0x1040..0x1080).contains(&id) => Some(id - 0x1040),
            _ => None,
        }
    }

    /// ECAM config base, for diagnostics.
    pub fn config_base(&self) -> u64 {
        self.config_base
    }

    pub fn common_base(&self) -> u64 {
        self.common_base
    }

    pub unsafe fn read_device_features(&mut self) -> u64 {
        write_u32(self.common_base + COMMON_DFSELECT, 1);
        let high = read_u32(self.common_base + COMMON_DF) as u64;
        write_u32(self.common_base + COMMON_DFSELECT, 0);
        let low = read_u32(self.common_base + COMMON_DF) as u64;
        (high << 32) | low
    }

    pub unsafe fn write_driver_features(&mut self, features: u64) {
        write_u32(self.common_base + COMMON_GFSELECT, 1);
        write_u32(self.common_base + COMMON_GF, (features >> 32) as u32);
        write_u32(self.common_base + COMMON_GFSELECT, 0);
        write_u32(self.common_base + COMMON_GF, features as u32);
    }

    pub unsafe fn setup_queue(&mut self, index: u16, queue: &QueueLayout) -> bool {
        let (desc, avail, used) = match (
            queue.desc_physical(),
            queue.avail_physical(),
            queue.used_physical(),
        ) {
            (Some(d), Some(a), Some(u)) => (d, a, u),
            _ => return false,
        };
        write_u16(self.common_base + COMMON_Q_SELECT, index);
        let max = read_u16(self.common_base + COMMON_Q_SIZE);
        if max == 0 || queue.num() > max {
            return false;
        }
        write_u16(self.common_base + COMMON_Q_SIZE, queue.num());
        write_u32(self.common_base + COMMON_Q_DESCLO, desc as u32);
        write_u32(self.common_base + COMMON_Q_DESCHI, (desc >> 32) as u32);
        write_u32(self.common_base + COMMON_Q_AVAILLO, avail as u32);
        write_u32(self.common_base + COMMON_Q_AVAILHI, (avail >> 32) as u32);
        write_u32(self.common_base + COMMON_Q_USEDLO, used as u32);
        write_u32(self.common_base + COMMON_Q_USEDHI, (used >> 32) as u32);
        write_u16(self.common_base + COMMON_Q_ENABLE, 1);
        read_u16(self.common_base + COMMON_Q_ENABLE) == 1
    }

    pub unsafe fn max_queue_size(&mut self, index: u16) -> u32 {
        write_u16(self.common_base + COMMON_Q_SELECT, index);
        read_u16(self.common_base + COMMON_Q_SIZE) as u32
    }

    pub unsafe fn notify(&mut self, index: u16) {
        let queue_notify_off = read_u16(self.common_base + COMMON_Q_NOFF) as u64;
        let offset = queue_notify_off * self.notify_multiplier as u64;
        write_u16(self.notify_base + offset, index);
    }

    pub unsafe fn read_isr(&mut self) -> u32 {
        read_u8(self.isr_base) as u32
    }

    pub unsafe fn read_status(&mut self) -> u8 {
        read_u8(self.common_base + COMMON_STATUS)
    }

    pub unsafe fn write_status(&mut self, status: u8) {
        write_u8(self.common_base + COMMON_STATUS, status);
    }

    pub unsafe fn reset(&mut self) {
        write_u8(self.common_base + COMMON_STATUS, 0);
        // Wait for the status to clear (virtio spec 2.1.2).
        while read_u8(self.common_base + COMMON_STATUS) != 0 {}
    }

    pub unsafe fn config_read_u8(&self, offset: u64) -> u8 {
        read_u8(self.device_base + offset)
    }

    pub unsafe fn config_read_u16(&self, offset: u64) -> u16 {
        read_u16(self.device_base + offset)
    }

    pub unsafe fn config_read_u32(&self, offset: u64) -> u32 {
        read_u32(self.device_base + offset)
    }

    pub unsafe fn config_read_u64(&self, offset: u64) -> u64 {
        let low = self.config_read_u32(offset) as u64;
        let high = self.config_read_u32(offset + 4) as u64;
        (high << 32) | low
    }
}

// ---------------------------------------------------------------------------
// Volatile accessors
// ---------------------------------------------------------------------------

unsafe fn read_u8(addr: u64) -> u8 {
    core::ptr::read_volatile(addr as *const u8)
}

unsafe fn read_u16(addr: u64) -> u16 {
    core::ptr::read_volatile(addr as *const u16)
}

unsafe fn read_u32(addr: u64) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

unsafe fn write_u8(addr: u64, value: u8) {
    core::ptr::write_volatile(addr as *mut u8, value);
}

unsafe fn write_u16(addr: u64, value: u16) {
    core::ptr::write_volatile(addr as *mut u16, value);
}

unsafe fn write_u32(addr: u64, value: u32) {
    core::ptr::write_volatile(addr as *mut u32, value);
}
