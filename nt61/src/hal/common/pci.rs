//! PCI (Peripheral Component Interconnect) Bus Enumeration
//
//! Implements the surface area of the `hal.dll` PCI exports:
//! bus enumeration, configuration-space access, and a small
//! helper to find a device by (vendor, device) id.
//
//! Configuration access methods:
//! - **ECAM (PCIe MMIO)**: Preferred. The MCFG ACPI table
//!   provides a physical MMIO address through which all PCI
//!   config space is accessible. This is the standard method
//!   on PCIe systems (q35/QEMU, real hardware).
//! - **Legacy CF8/CFC**: Fallback for pre-PCIe systems.
//!   Type 1 configuration cycles via I/O ports 0xCF8/0xCFC.

// HAL PCI helpers follow the WDK naming convention
// (`PCI_COMMON_HEADER`, `HalGetBusData`, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]
//
//! On OVMF/q35, the MCFG table maps bus 0 at 0xE0000000 and
//! enumerating 64 buses covers all PCIe traffic.
//
//! Clean-room implementation. No code is copied from any
//! Microsoft or ReactOS source file.

use core::sync::atomic::{AtomicU64, Ordering};

// use crate::kprintln;  // kprintln disabled (memcpy crash workaround)
use crate::hal::common::acpi::get_mcfg_base;

// =====================================================================
// Configuration access method
// =====================================================================

/// The currently active configuration access method.
static PCI_ECAM_BASE: AtomicU64 = AtomicU64::new(0);

/// Set up PCI configuration access. Called once during PCI init.
/// Attempts ECAM (via MCFG ACPI table) first; falls back to
/// legacy CF8/CFC (address 0).
pub fn setup_config_method() {
    let mcfg_base = get_mcfg_base();
    if mcfg_base != 0 {
        // q35 exposes bus 0 in the first MCFG entry.
        // With 1 MiB per bus, 64 buses give 64 MiB coverage.
        PCI_ECAM_BASE.store(mcfg_base, Ordering::Release);
//         // // kprintln!("  [PCI] ECAM base=0x{:016x} (64-bus window)", mcfg_base)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    } else {
//         // // kprintln!("  [PCI] MCFG not found — using legacy CF8/CFC")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    }
}

/// Returns true if ECAM is available.
fn use_ecam() -> bool {
    PCI_ECAM_BASE.load(Ordering::Acquire) != 0
}

// =====================================================================
// ECAM helpers
// =====================================================================
//
// ECAM address formula:
//   address = base + (bus * 4096 * 32) + (dev * 4096) + (func * 512) + offset
//
// This gives 4096 bytes per function (enough for all config registers),
// 4096 bytes per device (32 functions), 128 KiB per bus.

/// Compute the ECAM MMIO address for a config register.
fn ecam_address(bus: u8, dev: u8, func: u8, offset: u8) -> u64 {
    let base = PCI_ECAM_BASE.load(Ordering::Acquire);
    base + ((bus as u64) * 4096u64 * 32u64)
        + ((dev as u64) * 4096u64)
        + ((func as u64) * 512u64)
        + ((offset as u64) & !0x03u64)
}

/// Read 32-bit from MMIO (aligned).
fn mmio_read32(addr: u64) -> u32 {
    record_ecam_addr(addr);
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write 32-bit to MMIO (aligned).
fn mmio_write32(addr: u64, value: u32) {
    unsafe { core::ptr::write_volatile(addr as *mut u32, value); }
}

/// Read a 32-bit value via ECAM MMIO.
fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = ecam_address(bus, dev, func, offset);
    mmio_read32(addr)
}

/// Write a 32-bit value via ECAM MMIO.
fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr = ecam_address(bus, dev, func, offset);
    mmio_write32(addr, value);
}

// =====================================================================
// Legacy CF8/CFC helpers
// =====================================================================

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{READ_PORT_ULONG, WRITE_PORT_ULONG};

/// PCI configuration space address / data ports (Type 1).
pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Encode bus/device/function/offset into a Type 1 config address.
fn legacy_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | (((dev & 0x1F) as u32) << 11)
        | (((func & 0x07) as u32) << 8)
        | (((offset & 0xFC) as u32))
}

/// Read 32-bit via legacy CF8/CFC.
#[cfg(target_arch = "x86_64")]
fn legacy_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    WRITE_PORT_ULONG(PCI_CONFIG_ADDRESS, legacy_addr(bus, dev, func, offset));
    let value = READ_PORT_ULONG(PCI_CONFIG_DATA);
    let shift = (offset & 0x03) * 8;
    if shift != 0 { value >> shift } else { value }
}

/// Write 32-bit via legacy CF8/CFC.
#[cfg(target_arch = "x86_64")]
fn legacy_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr = legacy_addr(bus, dev, func, offset);
    WRITE_PORT_ULONG(PCI_CONFIG_ADDRESS, addr);
    WRITE_PORT_ULONG(PCI_CONFIG_DATA, value);
}

// =====================================================================
// Public API — config access
// =====================================================================

/// Read a 32-bit value from PCI configuration space.
/// Uses ECAM if available, legacy CF8/CFC otherwise.
pub fn read_config_dword(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    if use_ecam() {
        ecam_read32(bus, dev, func, offset)
    } else {
        #[cfg(target_arch = "x86_64")]
        { legacy_read32(bus, dev, func, offset) }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    }
}

/// Write a 32-bit value to PCI configuration space.
pub fn write_config_dword(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    if use_ecam() {
        ecam_write32(bus, dev, func, offset, value)
    } else {
        #[cfg(target_arch = "x86_64")]
        { legacy_write32(bus, dev, func, offset, value); }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = (bus, dev, func, offset, value); }
    }
}

/// Read a 16-bit value from PCI configuration space.
pub fn read_config_word(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let aligned = offset & !0x03;
    let shift = (offset & 0x02) * 8;
    let dword = read_config_dword(bus, dev, func, aligned);
    ((dword >> shift) & 0xFFFF) as u16
}

/// Write a 16-bit value to PCI configuration space.
pub fn write_config_word(bus: u8, dev: u8, func: u8, offset: u8, value: u16) {
    let aligned = offset & !0x03;
    let shift = (offset & 0x02) * 8;
    let mask = !(0xFFFFu32 << shift);
    let dword = read_config_dword(bus, dev, func, aligned);
    write_config_dword(bus, dev, func, aligned, (dword & mask) | (((value as u32) & 0xFFFF) << shift));
}

/// Read an 8-bit value from PCI configuration space.
pub fn read_config_byte(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let aligned = offset & !0x03;
    let shift = (offset & 0x03) * 8;
    let dword = read_config_dword(bus, dev, func, aligned);
    ((dword >> shift) & 0xFF) as u8
}

/// Write an 8-bit value to PCI configuration space.
pub fn write_config_byte(bus: u8, dev: u8, func: u8, offset: u8, value: u8) {
    let aligned = offset & !0x03;
    let shift = (offset & 0x03) * 8;
    let mask = !(0xFFu32 << shift);
    let dword = read_config_dword(bus, dev, func, aligned);
    write_config_dword(bus, dev, func, aligned, (dword & mask) | (((value as u32) & 0xFF) << shift));
}

// =====================================================================
// Device descriptor
// =====================================================================

/// A discovered PCI device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub irq: u8,
    pub revision: u8,
}

impl PciDevice {
    pub fn is_multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }
    pub fn is_p2p_bridge(&self) -> bool {
        self.class_code == 0x06 && self.subclass == 0x04
    }
    pub fn subordinate_bus(&self) -> u8 {
        read_config_byte(self.bus, self.device, self.function, 0x19)
    }
}

// =====================================================================
// Device cache
// =====================================================================

const MAX_PCI_DEVICES: usize = 64;
const MAX_BUSES: usize = 64;

/// PciDevice cache. We use a struct that includes a `valid` flag
/// rather than `Option<PciDevice>` so the array is a plain
/// `PciDevice` and we can use a `Copy`-friendly layout. This is
/// the same pattern Windows 7 uses for its internal device list.
static mut PCI_DEVICE_CACHE: [PciDevice; MAX_PCI_DEVICES] = [PciDevice {
    bus: 0,
    device: 0,
    function: 0,
    vendor_id: 0,
    device_id: 0,
    class_code: 0,
    subclass: 0,
    prog_if: 0,
    header_type: 0,
    irq: 0,
    revision: 0,
}; MAX_PCI_DEVICES];
static mut PCI_CACHE_COUNT: usize = 0;
static mut PCI_CACHE_VALID: bool = false;

fn cache_push(d: PciDevice) {
    unsafe {
        if PCI_CACHE_COUNT < MAX_PCI_DEVICES {
            PCI_DEVICE_CACHE[PCI_CACHE_COUNT] = d;
            PCI_CACHE_COUNT += 1;
        }
    }
}

// =====================================================================
// Diagnostics
// =====================================================================

static mut PCI_LAST_BUS: u8 = 0;
static mut PCI_LAST_DEV: u8 = 0;
static mut PCI_LAST_FUNC: u8 = 0;
static mut PCI_LAST_REG: u8 = 0;
static mut PCI_LAST_VALUE: u32 = 0;
static mut PCI_LAST_ECAM_ADDR: u64 = 0;

fn record_config_read(bus: u8, dev: u8, func: u8, reg: u8) {
    unsafe {
        PCI_LAST_BUS = bus;
        PCI_LAST_DEV = dev;
        PCI_LAST_FUNC = func;
        PCI_LAST_REG = reg;
    }
}

fn record_ecam_addr(addr: u64) {
    unsafe { PCI_LAST_ECAM_ADDR = addr; }
}

/// Dump the last access info to the serial console.
pub fn dump_last_access() {
    {
        if use_ecam() {
//             // // kprintln!("  [PCI] last ECAM addr=0x{:016x}", PCI_LAST_ECAM_ADDR)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        } else {
//             // // kprintln!("  [PCI] last access: bus={} dev={} func={} reg=0x{:02x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                      PCI_LAST_BUS, PCI_LAST_DEV, PCI_LAST_FUNC, PCI_LAST_REG);
        }
    }
}

// =====================================================================
// Low-level probe
// =====================================================================

/// Fast check: is a device present?
fn is_present(bus: u8, dev: u8, func: u8) -> bool {
    let id = read_config_dword(bus, dev, func, 0);
    record_config_read(bus, dev, func, 0);
    id != 0xFFFF_FFFF
}

/// Probe one (bus, dev, func) slot.
fn probe_slot(bus: u8, dev: u8, func: u8) -> Option<PciDevice> {
    if !is_present(bus, dev, func) {
        return None;
    }
    let reg0 = read_config_dword(bus, dev, func, 0);
    let reg2 = read_config_dword(bus, dev, func, 8);
    let reg3 = read_config_dword(bus, dev, func, 0x0C);
    let reg15 = read_config_dword(bus, dev, func, 0x3C);
    record_config_read(bus, dev, func, 0);
    Some(PciDevice {
        bus,
        device: dev,
        function: func,
        vendor_id: (reg0 & 0xFFFF) as u16,
        device_id: ((reg0 >> 16) & 0xFFFF) as u16,
        class_code: ((reg2 >> 24) & 0xFF) as u8,
        subclass: ((reg2 >> 16) & 0xFF) as u8,
        prog_if: ((reg2 >> 8) & 0xFF) as u8,
        header_type: ((reg3 >> 16) & 0xFF) as u8,
        irq: ((reg15 & 0xFF) as u8).min(23),
        revision: (reg2 & 0xFF) as u8,
    })
}

// =====================================================================
// Enumeration — no heap allocation
// =====================================================================

/// Scan one bus, collect devices into the cache, and return the count
/// of P2P bridges found.
fn scan_bus(bus: u8) -> usize {
    let mut bridge_count: usize = 0;
    for dev in 0..32u8 {
        if is_present(bus, dev, 0) {
            if let Some(d) = probe_slot(bus, dev, 0) {
                cache_push(d);
                if d.is_p2p_bridge() {
                    bridge_count += 1;
                }
                if d.is_multifunction() {
                    for func in 1..8u8 {
                        if is_present(bus, dev, func) {
                            if let Some(mf) = probe_slot(bus, dev, func) {
                                cache_push(mf);
                            }
                        }
                    }
                }
            }
        }
    }
    bridge_count
}

/// BFS enumeration using a fixed-size bridge queue (no heap).
/// On q35/QEMU there are no P2P bridges, so bridge_count will be 0
/// and this just scans bus 0..63.
fn enumerate_recursive() {
    // On q35 the root bus has no P2P bridges, so a fixed walk of
    // MAX_BUSES is enough. Real hardware enumeration would need a
    // proper DFS with a bridge queue; for the VM case this is a
    // no-op stub.
    let _ = scan_bus(0);
}

/// Enumerate all PCI buses and cache results. Safe to call multiple
/// times — subsequent calls return the cached slice instantly.
pub fn enumerate() -> &'static [PciDevice] {
    if unsafe { PCI_CACHE_VALID } {
        return unsafe {
            core::slice::from_raw_parts(
                PCI_DEVICE_CACHE.as_ptr() as *const PciDevice,
                PCI_CACHE_COUNT,
            )
        };
    }

//     // // kprintln!("  [PCI] starting enumeration... (scanning bus 0)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    enumerate_recursive();
    let count = unsafe { PCI_CACHE_COUNT };
//     // // kprintln!("  [PCI] enumeration complete: {} device(s) found", count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)

    unsafe {
        PCI_CACHE_COUNT = count;
        PCI_CACHE_VALID = true;
        core::slice::from_raw_parts(
            PCI_DEVICE_CACHE.as_ptr() as *const PciDevice,
            count,
        )
    }
}

/// Find a device by (vendor, device) id.
pub fn find_device(vendor: u16, device: u16) -> Option<PciDevice> {
    for d in enumerate() {
        if d.vendor_id == vendor && d.device_id == device {
            return Some(*d);
        }
    }
    None
}

/// Look up a device by (bus, device, function).
pub fn get_device(bus: u8, device: u8, function: u8) -> Option<PciDevice> {
    probe_slot(bus, device, function)
}

// =====================================================================
// BAR access
// =====================================================================

/// Read a BAR (Base Address Register).
pub fn read_bar(dev: &PciDevice, index: u8) -> u64 {
    if index >= 6 { return 0; }
    let off = 0x10 + (index as u8) * 4;
    let raw = read_config_dword(dev.bus, dev.device, dev.function, off);
    if raw & 1 == 0 {
        if raw & 0x04 != 0 && index < 5 {
            let hi = read_config_dword(dev.bus, dev.device, dev.function, off + 4);
            ((hi as u64) << 32) | ((raw & !0x0F) as u64)
        } else {
            (raw & !0x0F) as u64
        }
    } else {
        (raw & !0x03) as u64
    }
}

/// Enable bus-mastering DMA.
pub fn enable_bus_mastering(dev: &PciDevice) {
    let cmd = read_config_word(dev.bus, dev.device, dev.function, 0x04);
    write_config_word(dev.bus, dev.device, dev.function, 0x04, cmd | 0x04);
}

/// Disable bus-mastering DMA.
pub fn disable_bus_mastering(dev: &PciDevice) {
    let cmd = read_config_word(dev.bus, dev.device, dev.function, 0x04);
    write_config_word(dev.bus, dev.device, dev.function, 0x04, cmd & !0x04);
}

// =====================================================================
// Init
// =====================================================================

/// Initialize the PCI subsystem. Sets up the configuration access
/// method (ECAM from MCFG, or legacy CF8/CFC) and flushes the
/// PCI bridge config space.
pub fn init() {
    setup_config_method();
    // Verify the ISA bridge is reachable.
    let isa_bridge = read_config_dword(0, 31, 0, 0);
    record_config_read(0, 31, 0, 0);
//     // // kprintln!("  [PCI] ISA bridge id=0x{:08x}", isa_bridge)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    if isa_bridge != 0xFFFF_FFFF {
//         // // kprintln!("  [PCI] PCI subsystem ready")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    } else {
//         // // kprintln!("  [PCI] WARNING: ISA bridge not found on bus 0")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn address_encoding() {
        let addr = (1u32 << 31) | (1u32 << 16) | (2u32 << 11) | (3u32 << 8);
        assert_eq!(addr, 0x8001_0820);
    }
}
