//! PCI Bus Driver
//
//! Walks the PCI hierarchy and registers every populated device
//! as a PnP node. Also decodes the BARs and caches the result for
//! the functional drivers. The implementation is modelled on the
//! PCI Local Bus Specification 3.0, sections 6 (configuration
//! space) and 7 (BIOS / OS initialisation).
//
//! Clean-room implementation. No code is copied from any
//! Microsoft or ReactOS source file.

use super::pnp;
use crate::hal::common::pci::{self, PciDevice};
use crate::kprintln;

/// Maximum number of BARs the bus driver tracks per device. The
/// PCI spec allows 6 BARs (0..5).
pub const MAX_BARS: usize = 6;

/// One BAR's decoded information.
#[derive(Debug, Clone, Copy, Default)]
pub struct BarInfo {
    pub phys: u64,
    pub size: u64,
    pub is_io: bool,
    pub is_64: bool,
    pub prefetchable: bool,
}

/// A fully decoded PCI device.
#[derive(Debug, Clone, Copy)]
pub struct PciDeviceInfo {
    pub pci: PciDevice,
    pub bars: [BarInfo; MAX_BARS],
    pub irq: u8,
    pub bus_master: bool,
    pub memory_space: bool,
    pub io_space: bool,
}

impl Default for PciDeviceInfo {
    fn default() -> Self {
        Self {
            pci: PciDevice {
                bus: 0, device: 0, function: 0,
                vendor_id: 0, device_id: 0,
                class_code: 0, subclass: 0, prog_if: 0,
                header_type: 0, irq: 0, revision: 0,
            },
            bars: [BarInfo::default(); MAX_BARS],
            irq: 0,
            bus_master: false,
            memory_space: false,
            io_space: false,
        }
    }
}

static mut PCI_DEVICES: [PciDeviceInfo; 16] = [PciDeviceInfo {
    pci: PciDevice {
        bus: 0, device: 0, function: 0,
        vendor_id: 0, device_id: 0,
        class_code: 0, subclass: 0, prog_if: 0,
        header_type: 0, irq: 0, revision: 0,
    },
    bars: [BarInfo {
        phys: 0, size: 0, is_io: false, is_64: false, prefetchable: false,
    }; MAX_BARS],
    irq: 0, bus_master: false, memory_space: false, io_space: false,
}; 16];
static mut PCI_COUNT: usize = 0;

fn push_pci_info(info: PciDeviceInfo) {
    unsafe {
        if PCI_COUNT < PCI_DEVICES.len() {
            PCI_DEVICES[PCI_COUNT] = info;
            PCI_COUNT += 1;
        }
    }
}

/// Look up the cached `PciDeviceInfo` for a given bus address.
pub fn find_pci(bus: u8, device: u8, function: u8) -> Option<PciDeviceInfo> {
    unsafe {
        for info in PCI_DEVICES.iter().take(PCI_COUNT) {
            if info.pci.bus == bus
                && info.pci.device == device
                && info.pci.function == function
            {
                return Some(*info);
            }
        }
    }
    None
}

/// Number of PCI devices the bus driver has registered.
pub fn pci_count() -> usize { unsafe { PCI_COUNT } }

/// Walk PCI, register every device, and decode the BARs.
pub fn init() {
    // kprintln!("      [PCI] pci_bus::init() called")  // kprintln disabled (memcpy crash workaround);
    let devices = pci::enumerate();
    for dev in devices {
        let _ = pnp::register_pci_device(dev);
        let info = decode_device(&dev);
        push_pci_info(info);
    }
    // kprintln!("      PCI bus: enumerated {} devices", devices.len())  // kprintln disabled (memcpy crash workaround);
}

fn decode_device(dev: &PciDevice) -> PciDeviceInfo {
    let mut info = PciDeviceInfo {
        pci: *dev,
        ..Default::default()
    };
    let cmd = pci::read_config_word(dev.bus, dev.device, dev.function, 0x04);
    info.bus_master = (cmd & 0x04) != 0;
    info.memory_space = (cmd & 0x02) != 0;
    info.io_space = (cmd & 0x01) != 0;
    info.irq = dev.irq;
    for i in 0..MAX_BARS {
        info.bars[i] = decode_bar(dev, i as u8);
    }
    info
}

fn decode_bar(dev: &PciDevice, index: u8) -> BarInfo {
    if index >= 6 { return BarInfo::default(); }
    let off: u8 = 0x10 + index * 4;
    let raw = pci::read_config_dword(dev.bus, dev.device, dev.function, off);
    if raw == 0 {
        return BarInfo::default();
    }
    let is_io = (raw & 0x01) != 0;
    if is_io {
        return BarInfo {
            phys: (raw & !0x03) as u64,
            size: 0,
            is_io: true,
            is_64: false,
            prefetchable: false,
        };
    }
    let is_64 = (raw & 0x04) != 0;
    let prefetch = (raw & 0x08) != 0;
    let phys = (raw & !0x0F) as u64;
    // For now, skip the size-probe dance (write-0xFFFFFFFF-then-read).
    // On QEMU q35 the legacy CF8/CFC write to the BAR can confuse the
    // host bridge; we just record the raw address and zero the size.
    // Functional drivers that need size can probe at runtime.
    BarInfo { phys, size: 0, is_io: false, is_64, prefetchable: prefetch }
}
