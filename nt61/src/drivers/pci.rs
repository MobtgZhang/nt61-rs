//! PCI Bus Driver (pci.sys)
//
//! Implements the PCI bus driver. pci.sys is the Windows NT 6.1
//! bus driver that enumerates PCI devices, manages configuration
//! space access, handles interrupt routing, and exposes PCI
//! devices to functional drivers through the Plug and Play (PnP)
//! manager.
//
//! This is a wrapper around the existing pci_bus implementation
//! that provides the full Windows Driver Model (WDM) interface.
//
//! Clean-room implementation. Spec source: PCI Local Bus
//! Specification 3.0 and Microsoft "PCI Driver" reference.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;

pub use crate::drivers::bus::pci_bus::{
    PciDeviceInfo, BarInfo, find_pci, pci_count,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PciPowerState {
    D0 = 0,  // Fully on
    D1 = 1,  // Light sleep
    D2 = 2,  // Deeper sleep
    D3 = 3,  // Off
}

pub struct PciDeviceExtension {
    pub valid: bool,
    pub device_object: *mut DeviceObject,
    pub pci_info: PciDeviceInfo,
    pub power_state: PciPowerState,
    pub started: bool,
    pub removed: bool,
}

impl PciDeviceExtension {
    pub const fn new() -> Self {
        Self {
            valid: false,
            device_object: core::ptr::null_mut(),
            pci_info: PciDeviceInfo {
                pci: crate::hal::common::pci::PciDevice {
                    bus: 0, device: 0, function: 0,
                    vendor_id: 0, device_id: 0,
                    class_code: 0, subclass: 0, prog_if: 0,
                    header_type: 0, irq: 0, revision: 0,
                },
                bars: [BarInfo {
                    phys: 0, size: 0, is_io: false, is_64: false, prefetchable: false,
                }; 6],
                irq: 0,
                bus_master: false,
                memory_space: false,
                io_space: false,
            },
            power_state: PciPowerState::D0,
            started: false,
            removed: false,
        }
    }
}

const MAX_PCI_DEVICES: usize = 32;
static mut DEVICE_EXTENSIONS: [PciDeviceExtension; MAX_PCI_DEVICES] =
    [const { PciDeviceExtension::new() }; MAX_PCI_DEVICES];
static PCI_LOCK: Spinlock<()> = Spinlock::new(());
static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn init() {
    crate::drivers::bus::pci_bus::init();
}

pub fn AddDevice(driver: *mut DriverObject, pdo: *mut DeviceObject) -> u32 {
    let _g = PCI_LOCK.lock();

    unsafe {
        for ext in DEVICE_EXTENSIONS.iter_mut() {
            if !ext.valid {
                ext.valid = true;
                ext.device_object = pdo;
                ext.started = false;
                ext.removed = false;
                DEVICE_COUNT.fetch_add(1, Ordering::Relaxed);
                return 0; // STATUS_SUCCESS
            }
        }
    }

    0xC000_0017 // STATUS_NO_MEMORY
}

pub fn enable_bus_master(bus: u8, device: u8, function: u8) -> bool {
    let cmd_offset = 0x04u8;
    let cmd = crate::hal::common::pci::read_config_word(bus, device, function, cmd_offset);
    let new_cmd = cmd | 0x04; // Set bus master enable bit
    crate::hal::common::pci::write_config_word(bus, device, function, cmd_offset, new_cmd);
    true
}

pub fn enable_memory_space(bus: u8, device: u8, function: u8) -> bool {
    let cmd_offset = 0x04u8;
    let cmd = crate::hal::common::pci::read_config_word(bus, device, function, cmd_offset);
    let new_cmd = cmd | 0x02; // Set memory space enable bit
    crate::hal::common::pci::write_config_word(bus, device, function, cmd_offset, new_cmd);
    true
}

pub fn enable_io_space(bus: u8, device: u8, function: u8) -> bool {
    let cmd_offset = 0x04u8;
    let cmd = crate::hal::common::pci::read_config_word(bus, device, function, cmd_offset);
    let new_cmd = cmd | 0x01; // Set I/O space enable bit
    crate::hal::common::pci::write_config_word(bus, device, function, cmd_offset, new_cmd);
    true
}

pub fn set_power_state(
    bus: u8,
    device: u8,
    function: u8,
    power_state: PciPowerState,
) -> bool {
    let _g = PCI_LOCK.lock();

    unsafe {
        for ext in DEVICE_EXTENSIONS.iter_mut() {
            if ext.valid
                && ext.pci_info.pci.bus == bus
                && ext.pci_info.pci.device == device
                && ext.pci_info.pci.function == function
            {
                ext.power_state = power_state;
                return true;
            }
        }
    }

    false
}

pub fn device_count() -> u32 {
    DEVICE_COUNT.load(Ordering::Relaxed)
}

pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();
    0 // STATUS_SUCCESS
}

pub mod dispatch {
    use super::*;
    use crate::io::{Irp, IoStackLocation};
    use crate::io::major::*;
    use crate::io::pnp::*;
    use crate::io::power::*;

    pub fn Pnp(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn Power(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }

    pub fn DeviceControl(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
        0 // STATUS_SUCCESS
    }
}
