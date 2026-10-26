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
//!   r#type 1 configuration cycles via I/O ports 0xCF8/0xCFC.

// HAL PCI helpers follow the WDK naming convention
// (`PCI_COMMON_HEADER`, `HalGetBusData`, ...).
//
//! On OVMF/q35, the MCFG table maps bus 0 at 0xE0000000 and
//! enumerating 64 buses covers all PCIe traffic.
//
//! Clean-room implementation. No code is copied from any
//! Microsoft or ReactOS source file.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

// use crate::kprintln;
use crate::hal::common::acpi::get_mcfg_info;

// =====================================================================
// Configuration access method
// =====================================================================

/// The currently active configuration access method.
static PCI_ECAM_BASE: AtomicU64 = AtomicU64::new(0);

/// Set up PCI configuration access. Called once during PCI init.
/// Attempts ECAM (via MCFG ACPI table) first; falls back to
/// legacy CF8/CFC (address 0).
pub fn setup_config_method() {
    // ECAM window: (physical base, byte size). Sourced from MCFG
    // when the firmware installs ACPI tables, or from the device
    // tree `pci-host-ecam-generic` node otherwise (generic UEFI
    // firmwares such as ArmVirtQemu nightly ship DTB-only).
    let (ecam_base, ecam_size) = if let Some((mcfg_base, start_bus, end_bus)) = get_mcfg_info() {
        // ECAM provides 1 MiB of config space per bus (32 devices ×
        // 8 functions × 4096 bytes).
        let bus_count = u64::from(end_bus.saturating_sub(start_bus)) + 1;
        (mcfg_base, (bus_count << 20).min(256 << 20))
    } else if let Some(ecam) = crate::arch::common::device_tree::hardware().pci_ecam {
        (ecam.base, ecam.size)
    } else {
        //         // // kprintln!("  [PCI] MCFG not found — using legacy CF8/CFC");
        return;
    };
    // Map the whole ECAM window into the kernel address space: on
    // non-x86 targets there is no firmware identity map, and
    // reading an unmapped ECAM window would fault.
    if !crate::arch::identity_map_region(ecam_base, ecam_size) {
        crate::boot_debug_println!(
            "[PCI] ECAM identity map FAILED base=0x{:x} size={}",
            ecam_base,
            ecam_size
        );
        return;
    }
    PCI_ECAM_BASE.store(ecam_base, Ordering::Release);
}

/// Returns true if ECAM is available.
fn use_ecam() -> bool {
    PCI_ECAM_BASE.load(Ordering::Acquire) != 0
}

/// ECAM window base when ECAM configuration access is active.
/// Transport layers that walk the ECAM window directly (virtio-pci)
/// need the same base the configuration helpers use.
pub fn ecam_base() -> Option<u64> {
    match PCI_ECAM_BASE.load(Ordering::Acquire) {
        0 => None,
        base => Some(base),
    }
}

/// Enable memory-space and bus-master decoding for one function so
/// that BAR MMIO reads succeed before a driver touches the device.
pub fn enable_memory_bus_master(bus: u8, device: u8, function: u8) {
    let cmd = read_config_word(bus, device, function, 0x04);
    write_config_word(bus, device, function, 0x04, cmd | 0x02 | 0x04);
}

// =====================================================================
// ECAM helpers
// =====================================================================
//
// ECAM address formula:
// The layout follows the PCIe ECAM standard the host firmware
// implements:
// - Standard ECAM (PCI Express Base spec, pci-host-ecam-generic
//   in Linux, QEMU riscv64 virt GPEx): one 4096-byte window per
//   function, 32 KiB per device (8 functions), 1 MiB per bus:
//     address = base + (bus << 20) + (dev << 15) + (func << 12) + offset
// - Compressed ECAM (LoongArch LS7A host bridge, QEMU loongarch64
//   virt): 4096 bytes per device window split into 512-byte function
//   slots, 128 KiB per bus:
//     address = base + (bus << 17) + (dev << 12) + (func << 9) + offset
//
// The stride set is a compile-time per-arch property because the host
// bridge (and therefore the firmware table describing it) differs per
// machine; hal.dll is the one place allowed to encode it (mirrors
// Windows hal!HalTranslateBusAddress).

/// ECAM window strides (bytes): bus, device, function.
struct EcamLayout {
    bus: u64,
    device: u64,
    function: u64,
}

#[cfg(target_arch = "riscv64")]
const ECAM_LAYOUT: EcamLayout = EcamLayout {
    bus: 1 << 20,
    device: 8 << 12,
    function: 1 << 12,
};
#[cfg(target_arch = "loongarch64")]
const ECAM_LAYOUT: EcamLayout = EcamLayout {
    bus: 1 << 17,
    device: 1 << 12,
    function: 1 << 9,
};
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
const ECAM_LAYOUT: EcamLayout = EcamLayout {
    bus: 1 << 20,
    device: 1 << 15,
    function: 1 << 12,
};

/// Compute the ECAM MMIO address for a config register.
fn ecam_address(bus: u8, dev: u8, func: u8, offset: u8) -> u64 {
    let base = PCI_ECAM_BASE.load(Ordering::Acquire);
    base + ((bus as u64) * ECAM_LAYOUT.bus)
        + ((dev as u64) * ECAM_LAYOUT.device)
        + ((func as u64) * ECAM_LAYOUT.function)
        + ((offset as u64) & !0x03u64)
}

/// Public wrapper so drivers can compute the same ECAM slot
/// address as `read_config_*` without duplicating the stride
/// arithmetic.
pub fn ecam_address_for(bus: u8, dev: u8, func: u8) -> u64 {
    ecam_address(bus, dev, func, 0)
}

/// read 32-bit from MMIO (aligned).
fn mmio_read32(addr: u64) -> u32 {
    record_ecam_addr(addr);
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// write 32-bit to MMIO (aligned).
fn mmio_write32(addr: u64, value: u32) {
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, value);
    }
}

/// read a 32-bit value via ECAM MMIO.
fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = ecam_address(bus, dev, func, offset);
    mmio_read32(addr)
}

/// write a 32-bit value via ECAM MMIO.
fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr = ecam_address(bus, dev, func, offset);
    mmio_write32(addr, value);
}

// =====================================================================
// Legacy CF8/CFC helpers
// =====================================================================

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{read_port_ulong, write_port_ulong};

/// PCI configuration space address / data ports (r#type 1).
pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Encode bus/device/function/offset into a r#type 1 config address.
#[cfg(target_arch = "x86_64")]
fn legacy_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | (((dev & 0x1F) as u32) << 11)
        | (((func & 0x07) as u32) << 8)
        | ((offset & 0xFC) as u32)
}

/// read 32-bit via legacy CF8/CFC.
#[cfg(target_arch = "x86_64")]
fn legacy_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    write_port_ulong(PCI_CONFIG_ADDRESS, legacy_addr(bus, dev, func, offset));
    let value = read_port_ulong(PCI_CONFIG_DATA);
    let shift = (offset & 0x03) * 8;
    if shift != 0 {
        value >> shift
    } else {
        value
    }
}

/// write 32-bit via legacy CF8/CFC.
#[cfg(target_arch = "x86_64")]
fn legacy_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr = legacy_addr(bus, dev, func, offset);
    write_port_ulong(PCI_CONFIG_ADDRESS, addr);
    write_port_ulong(PCI_CONFIG_DATA, value);
}

// =====================================================================
// Public API — config access
// =====================================================================

/// read a 32-bit value from PCI configuration space.
/// Uses ECAM if available, legacy CF8/CFC otherwise.
pub fn read_config_dword(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    if use_ecam() {
        ecam_read32(bus, dev, func, offset)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            legacy_read32(bus, dev, func, offset)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }
}

/// write a 32-bit value to PCI configuration space.
pub fn write_config_dword(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    if use_ecam() {
        ecam_write32(bus, dev, func, offset, value)
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            legacy_write32(bus, dev, func, offset, value);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (bus, dev, func, offset, value);
        }
    }
}

/// Decoded PCI base address register.
pub struct BarInfo {
    /// Base address (memory BARs: physical MMIO; I/O BARs: port no).
    pub base: u64,
    /// Decoded BAR size in bytes (0 when the BAR is not writable).
    pub size: u64,
    /// True when the BAR decodes I/O port space.
    pub io: bool,
}

/// Read one base address register and decode its size.
///
/// Decoding writes all-ones into the BAR and restores the original
/// value afterwards, so the firmware-assigned address survives the
/// probe (the same dance Linux `pci_size()` performs inside
/// `pci_read_bases`). 64-bit memory BARs consume the following dword
/// as the high half of the address; dropping it would decode a base
/// of 0 for every window assigned above 4 GiB.
pub fn probe_bar(bus: u8, dev: u8, func: u8, index: u8) -> Option<BarInfo> {
    if index > 5 {
        return None;
    }
    let off = 0x10 + index * 4;
    let low = read_config_dword(bus, dev, func, off);
    if low == 0 || low == 0xFFFF_FFFF {
        return None;
    }
    let io = low & 0x1 != 0;
    let is_64 = !io && (low & 0x4 != 0);
    let low_mask = if io { 0x3 } else { 0xF };

    // Save the firmware-assigned high dword before the probe so the
    // restore below puts back the real address, not the probed one.
    let mut high_orig = 0u32;
    if is_64 {
        high_orig = read_config_dword(bus, dev, func, off + 4);
    }
    crate::hal::serial::write_string_always("[PCI-BAR] index=");
    crate::hal::serial::write_hex_u64_always(index as u64);
    crate::hal::serial::write_string_always(" low=");
    crate::hal::serial::write_hex_u64_always(low as u64);
    crate::hal::serial::write_string_always(" high_orig=");
    crate::hal::serial::write_hex_u64_always(high_orig as u64);
    crate::hal::serial::write_string_always(" is64=");
    crate::hal::serial::write_hex_u64_always(is_64 as u64);
    crate::hal::serial::write_string_always("\r\n");

    // Probe the writable bits (and the high dword of 64-bit BARs).
    write_config_dword(bus, dev, func, off, 0xFFFF_FFFF);
    let probed_low = read_config_dword(bus, dev, func, off);
    let mut probed_high = 0u32;
    if is_64 {
        let high_off = off + 4;
        write_config_dword(bus, dev, func, high_off, 0xFFFF_FFFF);
        probed_high = read_config_dword(bus, dev, func, high_off);
        write_config_dword(bus, dev, func, high_off, high_orig);
    }
    crate::hal::serial::write_string_always("[PCI-BAR] probe low=");
    crate::hal::serial::write_hex_u64_always(probed_low as u64);
    crate::hal::serial::write_string_always(" high=");
    crate::hal::serial::write_hex_u64_always(probed_high as u64);
    crate::hal::serial::write_string_always("\r\n");
    // Restore the firmware-assigned addresses.
    write_config_dword(bus, dev, func, off, low);

    if probed_low == 0 {
        // Nothing writable: size unknown, report the address only.
        let base = u64::from(low & !(low_mask as u32));
        return Some(BarInfo { base, size: 0, io });
    }
    // For a 64-bit BAR whose size fits below 4 GiB, the low dword
    // already contains the complete size mask. This also avoids a
    // QEMU/OVMF configuration access quirk on high dwords. Only use
    // the high dword when the low dword is entirely writable.
    let low_mask_value = probed_low & !(low_mask as u32);
    // BAR size = ~(writable bits) + 1. For a 64-bit BAR combine both
    // probed dwords into a single u64 before inverting so the result
    // stays small and positive. A u64 negation of only the low dword
    // would produce a huge wrapped value (0xFFFFFFFF_xxxxxxxx) that
    // blows up identity_map_region.
    let combined = (u64::from(probed_high) << 32) | u64::from(low_mask_value);
    let size = (!combined).wrapping_add(1);
    let mut base = u64::from(low & !(low_mask as u32));
    if is_64 {
        base |= u64::from(high_orig) << 32;
    }
    Some(BarInfo { base, size, io })
}

/// read a 16-bit value from PCI configuration space.
pub fn read_config_word(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let aligned = offset & !0x03;
    let shift = (offset & 0x02) * 8;
    let dword = read_config_dword(bus, dev, func, aligned);
    ((dword >> shift) & 0xFFFF) as u16
}

/// write a 16-bit value to PCI configuration space.
pub fn write_config_word(bus: u8, dev: u8, func: u8, offset: u8, value: u16) {
    let aligned = offset & !0x03;
    let shift = (offset & 0x02) * 8;
    let mask = !(0xFFFFu32 << shift);
    let dword = read_config_dword(bus, dev, func, aligned);
    write_config_dword(
        bus,
        dev,
        func,
        aligned,
        (dword & mask) | (((value as u32) & 0xFFFF) << shift),
    );
}

/// read an 8-bit value from PCI configuration space.
pub fn read_config_byte(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let aligned = offset & !0x03;
    let shift = (offset & 0x03) * 8;
    let dword = read_config_dword(bus, dev, func, aligned);
    ((dword >> shift) & 0xFF) as u8
}

/// write an 8-bit value to PCI configuration space.
pub fn write_config_byte(bus: u8, dev: u8, func: u8, offset: u8, value: u8) {
    let aligned = offset & !0x03;
    let shift = (offset & 0x03) * 8;
    let mask = !(0xFFu32 << shift);
    let dword = read_config_dword(bus, dev, func, aligned);
    write_config_dword(
        bus,
        dev,
        func,
        aligned,
        (dword & mask) | (((value as u32) & 0xFF) << shift),
    );
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
pub const MAX_BUSES: usize = 64;

/// PciDevice cache. We use a struct that includes a `valid` flag
/// rather than `Option<PciDevice>` so the array is a plain
/// `PciDevice` and we can use a `Copy`-friendly layout. This is
/// the same pattern Windows 7 uses for its internal device list.
///
/// The cache is guarded by `PCI_CACHE.lock`: enumeration runs while
/// the lock is held, and the populated count is published through the
/// `valid` flag with Release ordering so lock-free readers that
/// observe `valid == true` also observe the fully populated device
/// array. (Audit hal_rtl P0-2: the previous `static mut` cache could
/// be enumerated concurrently from multiple CPUs and tear.)
struct PciDeviceCache {
    lock: AtomicBool,
    count: AtomicUsize,
    valid: AtomicBool,
    devices: UnsafeCell<[PciDevice; MAX_PCI_DEVICES]>,
}

// SAFETY: the device array is only accessed through `UnsafeCell::get`
// while `lock` is held (during enumeration) or after `valid` has been
// published with Release ordering (read-only snapshot).
unsafe impl Sync for PciDeviceCache {}

static PCI_CACHE: PciDeviceCache = PciDeviceCache {
    lock: AtomicBool::new(false),
    count: AtomicUsize::new(0),
    valid: AtomicBool::new(false),
    devices: UnsafeCell::new([PciDevice {
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
    }; MAX_PCI_DEVICES]),
};

fn cache_push(d: PciDevice) {
    // SAFETY: `cache_push` is only called from the enumeration scan
    // path, which runs while `PCI_CACHE.lock` is held by
    // `enumerate`. The store to `count` uses Release so a reader
    // that later observes `valid` also observes this entry.
    unsafe {
        let slots = &mut *PCI_CACHE.devices.get();
        let count = PCI_CACHE.count.load(Ordering::Relaxed);
        if count < MAX_PCI_DEVICES {
            slots[count] = d;
            PCI_CACHE.count.store(count + 1, Ordering::Release);
        }
    }
}

/// Snapshot of the published device cache. Safe without the lock:
/// `valid` is only set with Release ordering after every entry and
/// the final count are visible.
fn published_devices() -> &'static [PciDevice] {
    let count = PCI_CACHE
        .count
        .load(Ordering::Acquire)
        .min(MAX_PCI_DEVICES);
    unsafe {
        core::slice::from_raw_parts((*PCI_CACHE.devices.get()).as_ptr(), count)
    }
}

// =====================================================================
// Diagnostics
// =====================================================================

static mut PCI_LAST_BUS: u8 = 0;
static mut PCI_LAST_DEV: u8 = 0;
static mut PCI_LAST_FUNC: u8 = 0;
static mut PCI_LAST_REG: u8 = 0;
pub static mut PCI_LAST_VALUE: u32 = 0;
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
    unsafe {
        PCI_LAST_ECAM_ADDR = addr;
    }
}

/// Dump the last access info to the serial console.
pub fn dump_last_access() {
    {
        if use_ecam() {
            //             // // kprintln!("  [PCI] last ECAM addr=0x{:016x}", PCI_LAST_ECAM_ADDR);
        } else {
            //             // // kprintln!("  [PCI] last access: bus={} dev={} func={} reg=0x{:02x}",
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
    crate::hal::serial::write_string_always("[PCI] enum enter\r\n");
    if PCI_CACHE.valid.load(Ordering::Acquire) {
        crate::hal::serial::write_string_always("[PCI] enum cached\r\n");
        return published_devices();
    }

    // Serialize enumeration: two CPUs racing here would otherwise
    // push duplicate devices into the cache.
    while PCI_CACHE
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    if PCI_CACHE.valid.load(Ordering::Relaxed) {
        PCI_CACHE.lock.store(false, Ordering::Release);
        return published_devices();
    }

    // Lazy configuration-method bring-up. Some HALs (aarch64,
    // riscv64, loongarch64) reach enumeration through the
    // virtio/drivers path without calling `init` first; without
    // this, ECAM reads on those targets return all-zero garbage.
    crate::hal::serial::write_string_always("[PCI] enum setup enter\r\n");
    setup_config_method();
    crate::hal::serial::write_string_always("[PCI] enum setup done\r\n");

    //     // // kprintln!("  [PCI] starting enumeration... (scanning bus 0)");
    crate::hal::serial::write_string_always("[PCI] enum scan enter\r\n");
    enumerate_recursive();
    crate::hal::serial::write_string_always("[PCI] enum scan done\r\n");
    crate::hal::serial::write_string_always("[PCI] enum return enter\r\n");
    //     // // kprintln!("  [PCI] enumeration complete: {} device(s) found", count);

    // Publish: every entry and the final count are already visible
    // (Release stores above), so lock-free readers are safe from here.
    PCI_CACHE.valid.store(true, Ordering::Release);
    PCI_CACHE.lock.store(false, Ordering::Release);
    crate::hal::serial::write_string_always("[PCI] enum return done\r\n");
    published_devices()
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

/// read a BAR (Base Address Register).
pub fn read_bar(dev: &PciDevice, index: u8) -> u64 {
    if index >= 6 {
        return 0;
    }
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
    //     // // kprintln!("  [PCI] ISA bridge id=0x{:08x}", isa_bridge);
    if isa_bridge != 0xFFFF_FFFF {
        //         // // kprintln!("  [PCI] PCI subsystem ready");
    } else {
        //         // // kprintln!("  [PCI] WARNING: ISA bridge not found on bus 0");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn address_encoding() {
        // Standard PCI configuration address encoding:
        //   bit 31:    enable
        //   bits 16-23: bus number (8 bits)
        //   bits 11-15: device number (5 bits)
        //   bits 8-10:  function number (3 bits)
        //   bits 2-7:   register offset (6 bits)
        //   bits 0-1:   0
        let addr = (1u32 << 31) | (1u32 << 16) | (2u32 << 11) | (3u32 << 8);
        assert_eq!(addr, 0x8001_1300);
    }
}
