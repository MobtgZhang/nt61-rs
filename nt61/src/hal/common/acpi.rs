//! ACPI (Advanced Configuration and Power Interface) Table Support
//
//! Provides the surface area of the `hal.dll` ACPI exports:
//! parsing the RSDP, walking the XSDT, looking up tables by
//! signature, and validating the ACPI table checksum.
//
//! The RSDP pointer is normally handed to the kernel by the
//! firmware (UEFI configuration table on modern systems, BIOS
//! real-mode interrupt on legacy). We accept a physical address
//! as the entry point and assume the kernel has mapped it.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::READ_PORT_UCHAR;
// use crate::kprintln;  // kprintln disabled (memcpy crash workaround)

/// Standard ACPI RSDP signature (the 8-byte string "RSD PTR ").
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// ACPI description table header (the first 36 bytes of every
/// standard ACPI table).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct AcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// RSDP (revision 1, 20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct Rsdp1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// RSDP (revision 2+, 36 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct Rsdp2 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
}

/// The physical address of the RSDP as supplied by the firmware.
/// The kernel sets this from the BootInfo during Phase 5.
static RSDP_PHYS: AtomicU64 = AtomicU64::new(0);

/// Initialise the ACPI subsystem. `rsdp_phys` is the physical
/// address of the RSDP structure; 0 disables ACPI table access.
pub fn init() {
    RSDP_PHYS.store(0, Ordering::Release);
}

pub fn set_rsdp(rsdp_phys: u64) {
    RSDP_PHYS.store(rsdp_phys, Ordering::Release);
}

/// ACPI debug logging. Only enabled in debug builds to avoid
/// spamming the serial port in production.
#[cfg(debug_assertions)]
macro_rules! acpi_debug {
    ($($arg:tt)*) => {
//         // // crate::kprintln!($($arg)*)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    };
}
#[cfg(not(debug_assertions))]
macro_rules! acpi_debug {
    ($($arg:tt)*) => {};
}

/// Map a physical address for ACPI table access. Uses the
/// recursive kernel page-table self-map (if present); falls
/// back to the identity-mapped address on the BSP.
fn map_acpi(phys: u64) -> Option<u64> {
    acpi_debug!("    [acpi] map_acpi: mapping phys=0x{:016x}", phys);
    let result = crate::mm::syspte::map_io_space(phys, 1);
    if result.is_some() {
        acpi_debug!("    [acpi] map_acpi: mapped to {:?}", result);
    } else {
        acpi_debug!("    [acpi] map_acpi: mapping failed");
    }
    result
}

/// Sum the bytes of `buf` modulo 256. A valid ACPI table sums
/// to zero.
fn checksum(buf: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for b in buf {
        sum = sum.wrapping_add(*b);
    }
    sum
}

/// Find an ACPI table by its 4-byte signature. The search walks
/// the XSDT (preferred) or RSDT (fallback), depending on the
/// RSDP revision.
pub fn find_table(signature: &[u8; 4]) -> Option<*const AcpiTableHeader> {
    if signature.len() != 4 { return None; }
    let rsdp_phys = RSDP_PHYS.load(Ordering::Acquire);
    if rsdp_phys == 0 { return None; }
    acpi_debug!("    [acpi] find_table: searching for {:?}", core::str::from_utf8(signature).unwrap_or("???"));
    let rsdp_va = map_acpi(rsdp_phys)? as *const u8;
    unsafe {
        // Read signature (8 bytes).
        let mut sig = [0u8; 8];
        for i in 0..8 {
            sig[i] = ptr::read_volatile(rsdp_va.add(i));
        }
        if &sig != RSDP_SIGNATURE {
            // Some QEMU configurations forget the trailing
            // space; accept "RSDP" too.
            if &sig[..4] != b"RSDP" {
                acpi_debug!("    [acpi] find_table: RSDP signature mismatch");
                return None;
            }
        }
        // Read revision.
        let revision = ptr::read_volatile(rsdp_va.add(15));
        acpi_debug!("    [acpi] find_table: RSDP revision={}", revision);
        if revision >= 2 {
            // XSDT path.
            let xsdt_lo = read_u32(rsdp_va.add(24));
            let xsdt_hi = read_u32(rsdp_va.add(28));
            let xsdt_phys = ((xsdt_hi as u64) << 32) | (xsdt_lo as u64);
            acpi_debug!("    [acpi] find_table: using XSDT at phys=0x{:016x}", xsdt_phys);
            find_in_xsdt(xsdt_phys, signature)
        } else {
            // RSDT path.
            let rsdt_phys = read_u32(rsdp_va.add(16)) as u64;
            acpi_debug!("    [acpi] find_table: using RSDT at phys=0x{:016x}", rsdt_phys);
            find_in_rsdt(rsdt_phys, signature)
        }
    }
}

unsafe fn read_u32(p: *const u8) -> u32 {
    let b0 = ptr::read_volatile(p) as u32;
    let b1 = ptr::read_volatile(p.add(1)) as u32;
    let b2 = ptr::read_volatile(p.add(2)) as u32;
    let b3 = ptr::read_volatile(p.add(3)) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

#[allow(dead_code)]
unsafe fn read_u64(p: *const u8) -> u64 {
    (read_u32(p.add(4)) as u64) << 32 | (read_u32(p) as u64)
}

#[allow(dead_code)]
fn find_in_xsdt(xsdt_phys: u64, signature: &[u8; 4]) -> Option<*const AcpiTableHeader> {
    acpi_debug!("    [acpi] find_in_xsdt: xsdt_phys=0x{:016x}", xsdt_phys);
    let va = map_acpi(xsdt_phys)? as *const u8;
    unsafe {
        let length = read_u32(va.add(4));
        let n_entries = (length.saturating_sub(36)) / 8;
        acpi_debug!("    [acpi] find_in_xsdt: XSDT length={} entries={}", length, n_entries);
        for i in 0..n_entries as isize {
            let entry_lo = read_u32(va.add(36 + (i * 8) as usize));
            let entry_hi = read_u32(va.add(40 + (i * 8) as usize));
            let table_phys = ((entry_hi as u64) << 32) | (entry_lo as u64);
            if let Some(p) = find_in_table(table_phys, signature) {
                acpi_debug!("    [acpi] find_in_xsdt: found at phys=0x{:016x}", table_phys);
                return Some(p);
            }
        }
    }
    acpi_debug!("    [acpi] find_in_xsdt: table not found");
    None
}

fn find_in_rsdt(rsdt_phys: u64, signature: &[u8; 4]) -> Option<*const AcpiTableHeader> {
    let va = map_acpi(rsdt_phys)? as *const u8;
    unsafe {
        let length = read_u32(va.add(4));
        let n_entries = (length.saturating_sub(36)) / 4;
        for i in 0..n_entries as isize {
            let entry = read_u32(va.add(36 + (i * 4) as usize));
            if let Some(p) = find_in_table(entry as u64, signature) {
                return Some(p);
            }
        }
    }
    None
}

fn find_in_table(phys: u64, signature: &[u8; 4]) -> Option<*const AcpiTableHeader> {
    let va = map_acpi(phys)? as *const u8;
    unsafe {
        let mut sig = [0u8; 4];
        for i in 0..4 {
            sig[i] = ptr::read_volatile(va.add(i));
        }
        if &sig == signature {
            return Some(va as *const AcpiTableHeader);
        }
    }
    None
}

/// Return a `Vec` of every ACPI table the firmware reported.
/// Useful for diagnostics and for drivers that need to find a
/// non-standard table.
pub fn enumerate_tables() -> Vec<(*const AcpiTableHeader, [u8; 4])> {
    let mut out = Vec::new();
    let rsdp_phys = RSDP_PHYS.load(Ordering::Acquire);
    if rsdp_phys == 0 { return out; }
    let rsdp_va = match map_acpi(rsdp_phys) {
        Some(v) => v as *const u8,
        None => return out,
    };
    unsafe {
        let revision = ptr::read_volatile(rsdp_va.add(15));
        if revision >= 2 {
            let xsdt_lo = read_u32(rsdp_va.add(24));
            let xsdt_hi = read_u32(rsdp_va.add(28));
            let xsdt_phys = ((xsdt_hi as u64) << 32) | (xsdt_lo as u64);
            collect_xsdt(xsdt_phys, &mut out);
        } else {
            let rsdt_phys = read_u32(rsdp_va.add(16)) as u64;
            collect_rsdt(rsdt_phys, &mut out);
        }
    }
    out
}

fn collect_xsdt(xsdt_phys: u64, out: &mut Vec<(*const AcpiTableHeader, [u8; 4])>) {
    let Some(va) = map_acpi(xsdt_phys) else { return; };
    let va = va as *const u8;
    unsafe {
        let length = read_u32(va.add(4));
        let n = (length.saturating_sub(36)) / 8;
        for i in 0..n as isize {
            let lo = read_u32(va.add(36 + (i * 8) as usize));
            let hi = read_u32(va.add(40 + (i * 8) as usize));
            let phys = ((hi as u64) << 32) | (lo as u64);
            if let Some(p) = push_table(phys) {
                out.push(p);
            }
        }
    }
}

fn collect_rsdt(rsdt_phys: u64, out: &mut Vec<(*const AcpiTableHeader, [u8; 4])>) {
    let Some(va) = map_acpi(rsdt_phys) else { return; };
    let va = va as *const u8;
    unsafe {
        let length = read_u32(va.add(4));
        let n = (length.saturating_sub(36)) / 4;
        for i in 0..n as isize {
            let entry = read_u32(va.add(36 + (i * 4) as usize));
            if let Some(p) = push_table(entry as u64) {
                out.push(p);
            }
        }
    }
}

fn push_table(phys: u64) -> Option<(*const AcpiTableHeader, [u8; 4])> {
    let va = map_acpi(phys)? as *const u8;
    unsafe {
        let mut sig = [0u8; 4];
        for i in 0..4 {
            sig[i] = ptr::read_volatile(va.add(i));
        }
        let p = va as *const AcpiTableHeader;
        // Validate checksum: sum of header bytes must be zero.
        let length = read_u32(va.add(4));
        if length < 36 { return None; }
        let bytes = core::slice::from_raw_parts(va, length as usize);
        if checksum(bytes) != 0 {
            return None;
        }
        Some((p, sig))
    }
}

/// Validate the RSDP checksum. Reads the bytes at `rsdp_phys`
/// and returns `true` if they sum to zero.
pub fn validate_rsdp(rsdp_phys: u64) -> bool {
    let Some(va) = map_acpi(rsdp_phys) else { return false; };
    let va = va as *const u8;
    unsafe {
        let length = read_u32(va.add(20));
        let n = if length == 0 { 20 } else { length as usize };
        if n > 36 { return false; }
        let bytes = core::slice::from_raw_parts(va, n);
        checksum(bytes) == 0
    }
}

/// Read a CMOS byte. Re-exported here so callers don't have to
/// pull in the `hal::x86_64::cmos` module.
/// Read a byte from the CMOS register file. Stub on non-x86_64 —
/// LoongArch / ARM64 / RISC-V64 use ACPI for time-keeping instead.
#[cfg(target_arch = "x86_64")]
pub fn read_cmos(reg: u8) -> u8 {
    let addr = 0x70u16;
    let data = 0x71u16;
    crate::hal::x86_64::io_port::WRITE_PORT_UCHAR(addr, 0x80 | (reg & 0x7F));
    let v = READ_PORT_UCHAR(data);
    crate::hal::x86_64::io_port::WRITE_PORT_UCHAR(addr, reg & 0x7F);
    v
}

/// Read a byte from the CMOS register file. Non-x86_64 stub returning 0.
#[cfg(not(target_arch = "x86_64"))]
pub fn read_cmos(_reg: u8) -> u8 {
    0
}

// ---------------------------------------------------------------------------
// MCFG — PCI Express Enhanced Configuration Access Method
// ---------------------------------------------------------------------------
//
// The MCFG table describes the MMIO region used for PCIe ECAM
// (Enhanced Configuration Access Method). On q35/QEMU, this
// region covers all PCIe devices including theisa bridge's
// integrated devices.
//
// Reference: ACPI 6.0, Section 5.2.7.

/// MCFG structure: one entry describing one PCI segment / host bridge.
/// Offset 44 + i*16 in the MCFG table body.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    pub reserved: u32,
}

/// Returns the base MMIO address of the PCIe ECAM region from the
/// MCFG table. Returns 0 if MCFG is not available.
pub fn get_mcfg_base() -> u64 {
    let sig: [u8; 4] = *b"MCFG";
    let hdr = match find_table(&sig) {
        Some(h) => h,
        None => return 0,
    };
    unsafe {
        // MCFG header (44 bytes) + variable entries (16 bytes each).
        let len = read_u32((hdr as *const u8).add(4));
        if len < 44 {
            return 0;
        }
        // First entry is always at offset 44 (after AcpiTableHeader + 8 reserved bytes).
        let entry_ptr = (hdr as *const u8).add(44) as *const McfgEntry;
        core::ptr::read_unaligned(entry_ptr).base_address
    }
}

// ---------------------------------------------------------------------------
// MADT (Multiple APIC Description Table) parsing
// ---------------------------------------------------------------------------
//
// The MADT is the source of truth for the LAPIC ID of every
// CPU in the system and for the I/O APIC base. NT 6.1's
// `HalpGetNextProcessor` and `HalpGetIoApic` ultimately call
// into this table; we expose the same data here.
//
// Reference: ACPI 6.0, Section 5.2.12.

/// MADT table header (the part common with all ACPI tables).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MadtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// MADT-specific fields that follow the standard header.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MadtBody {
    pub local_apic_address: u32,
    pub flags: u32,
}

/// MADT entry sub-types.
pub const MADT_ENTRY_LOCAL_APIC: u8 = 0;
pub const MADT_ENTRY_IO_APIC: u8 = 1;
pub const MADT_ENTRY_INTERRUPT_OVERRIDE: u8 = 2;
pub const MADT_ENTRY_LOCAL_APIC_NMI: u8 = 4;
pub const MADT_ENTRY_LOCAL_X2APIC: u8 = 9;

/// A LAPIC entry from the MADT (type 0).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MadtLocalApic {
    pub entry_type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

/// An I/O APIC entry from the MADT (type 1).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MadtIoApic {
    pub entry_type: u8,
    pub length: u8,
    pub io_apic_id: u8,
    pub _reserved: u8,
    pub io_apic_address: u32,
    pub global_system_interrupt_base: u32,
}

/// An interrupt override entry from the MADT (type 2).
/// Used to remap ISA interrupts to the I/O APIC.
#[repr(C, packed)]
pub struct MadtIntOverride {
    pub entry_type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub global_system_interrupt: u32,
    pub flags: u16,
}

impl Default for MadtIntOverride {
    fn default() -> Self {
        // SAFETY: All zeros is a valid representation for this packed struct.
        unsafe { core::mem::zeroed() }
    }
}

impl Clone for MadtIntOverride {
    fn clone(&self) -> Self {
        // SAFETY: Copying the bytes is safe for this packed struct.
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// A local APIC NMI entry from the MADT (type 4).
#[repr(C, packed)]
pub struct MadtLocalApicNmi {
    pub entry_type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub flags: u16,
    pub local_apic_lint: u8,
}

impl Default for MadtLocalApicNmi {
    fn default() -> Self {
        // SAFETY: All zeros is a valid representation for this packed struct.
        unsafe { core::mem::zeroed() }
    }
}

impl Clone for MadtLocalApicNmi {
    fn clone(&self) -> Self {
        // SAFETY: Copying the bytes is safe for this packed struct.
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// Maximum number of interrupt overrides we can store.
pub const MAX_INT_OVERRIDES: usize = 16;

/// Maximum number of NMI sources we can store.
pub const MAX_NMI_SOURCES: usize = 16;

/// Decoded MADT — the result of `parse_madt`. Holds the LAPIC
/// address, the I/O APIC base, and a list of the LAPIC IDs of
/// every CPU. Static (not heap) to keep the bootstrap path
/// allocation-free.
pub const MAX_MADT_LAPICS: usize = 256;

#[derive(Clone)]
pub struct MadtInfo {
    pub local_apic_address: u64,
    pub flags: u32,
    pub lapic_ids: [u8; MAX_MADT_LAPICS],
    pub lapic_count: u8,
    pub io_apic_id: u8,
    pub io_apic_address: u64,
    pub io_apic_gsi_base: u32,
    pub has_io_apic: bool,
    /// Interrupt override entries (ISA interrupt remapping)
    pub int_overrides: [MadtIntOverride; MAX_INT_OVERRIDES],
    pub int_override_count: usize,
    /// NMI source entries
    pub nmi_sources: [MadtLocalApicNmi; MAX_NMI_SOURCES],
    pub nmi_source_count: usize,
}

impl Default for MadtInfo {
    fn default() -> Self {
        // SAFETY: All zeros is a valid representation.
        unsafe { core::mem::zeroed() }
    }
}

// SAFETY: All fields are zero-initialized which is a valid representation
// for MadtInfo (and its nested types MadtIntOverride and MadtLocalApicNmi).
static mut MADT_INFO: MadtInfo = unsafe { core::mem::zeroed() };

/// Parse the MADT and cache the result. Returns `true` on
/// success. The cached info is exposed by `madt_info()`.
pub fn parse_madt() -> bool {
    let madt_sig: [u8; 4] = *b"APIC";
    let header = match find_table(&madt_sig) {
        Some(p) => p,
        None => {
//             // // kprintln!("    [acpi] MADT not found")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
            return false;
        }
    };
    unsafe {
        let table_va = header as *const u8;
        let length = read_u32(table_va.add(4));
        let body_va = table_va.add(core::mem::size_of::<MadtHeader>());
        let body = core::ptr::read_unaligned(body_va as *const MadtBody);

        // Initialize MADT_INFO directly
        MADT_INFO.local_apic_address = body.local_apic_address as u64;
        MADT_INFO.flags = body.flags;
        MADT_INFO.lapic_count = 0;
        MADT_INFO.io_apic_id = 0;
        MADT_INFO.io_apic_address = 0;
        MADT_INFO.io_apic_gsi_base = 0;
        MADT_INFO.has_io_apic = false;
        MADT_INFO.int_override_count = 0;
        MADT_INFO.nmi_source_count = 0;

        // Walk the variable-length entries that follow the body.
        let mut offset = core::mem::size_of::<MadtHeader>() + core::mem::size_of::<MadtBody>();
        while offset + 2 <= length as usize {
            let entry_va = table_va.add(offset);
            let entry_type = ptr::read_volatile(entry_va);
            let entry_len = ptr::read_volatile(entry_va.add(1));
            if entry_len < 2 || offset + entry_len as usize > length as usize {
                break;
            }
            match entry_type {
                MADT_ENTRY_LOCAL_APIC => {
                    if MADT_INFO.lapic_count as usize >= MAX_MADT_LAPICS { break; }
                    let e: MadtLocalApic =
                        core::ptr::read_unaligned(entry_va as *const MadtLocalApic);
                    // bit 0 of flags = "enabled"
                    if e.flags & 1 != 0 {
                        MADT_INFO.lapic_ids[MADT_INFO.lapic_count as usize] = e.apic_id;
                        MADT_INFO.lapic_count += 1;
                        acpi_debug!("    [acpi] MADT: found LAPIC id={} proc_id={} enabled=true",
                                   e.apic_id, e.processor_id);
                    }
                }
                MADT_ENTRY_IO_APIC => {
                    if !MADT_INFO.has_io_apic {
                        let e: MadtIoApic =
                            core::ptr::read_unaligned(entry_va as *const MadtIoApic);
                        MADT_INFO.io_apic_id = e.io_apic_id;
                        MADT_INFO.io_apic_address = e.io_apic_address as u64;
                        MADT_INFO.io_apic_gsi_base = e.global_system_interrupt_base;
                        MADT_INFO.has_io_apic = true;
                        let _io_apic_id = e.io_apic_id;
                        let _io_apic_addr = e.io_apic_address;
                        let _gsi_base = e.global_system_interrupt_base;
                        acpi_debug!("    [acpi] MADT: found I/O APIC id={} addr=0x{:x} gsi_base={}",
                                   _io_apic_id, _io_apic_addr, _gsi_base);
                    }
                }
                MADT_ENTRY_INTERRUPT_OVERRIDE => {
                    if MADT_INFO.int_override_count < MAX_INT_OVERRIDES {
                        let e: MadtIntOverride =
                            core::ptr::read_unaligned(entry_va as *const MadtIntOverride);
                        // Copy fields before moving the struct
                        let _bus = e.bus;
                        let _source = e.source;
                        let _gsi = e.global_system_interrupt;
                        let _flags = e.flags;
                        MADT_INFO.int_overrides[MADT_INFO.int_override_count] = e;
                        MADT_INFO.int_override_count += 1;
                        acpi_debug!("    [acpi] MADT: interrupt override: bus={} src={} gsi={} flags=0x{:x}",
                                   _bus, _source, _gsi, _flags);
                    }
                }
                MADT_ENTRY_LOCAL_APIC_NMI => {
                    if MADT_INFO.nmi_source_count < MAX_NMI_SOURCES {
                        let e: MadtLocalApicNmi =
                            core::ptr::read_unaligned(entry_va as *const MadtLocalApicNmi);
                        // Copy fields before moving the struct
                        let _proc_id = e.processor_id;
                        let _lint = e.local_apic_lint;
                        let _flags = e.flags;
                        MADT_INFO.nmi_sources[MADT_INFO.nmi_source_count] = e;
                        MADT_INFO.nmi_source_count += 1;
                        acpi_debug!("    [acpi] MADT: local APIC NMI: proc={} lint={} flags=0x{:x}",
                                   _proc_id, _lint, _flags);
                    }
                }
                _ => {
                    acpi_debug!("    [acpi] MADT: unknown entry type {}", entry_type);
                }
            }
            offset += entry_len as usize;
        }
//         // // kprintln!("    [acpi] MADT: lapic_base=0x{:x} flags=0x{:x} cpus={} ioapic={} int_overrides={} nmi_sources={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                   MADT_INFO.local_apic_address, MADT_INFO.flags, MADT_INFO.lapic_count, MADT_INFO.has_io_apic,
// //                   MADT_INFO.int_override_count, MADT_INFO.nmi_source_count);
    }
    true
}

/// Return a reference to the cached MADT info (or default if parse failed).
/// Returns a reference to avoid needing Copy trait on MadtInfo.
pub fn madt_info() -> &'static MadtInfo {
    unsafe { &MADT_INFO }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zero() {
        let data = [0x00u8, 0x00, 0x00, 0x00];
        assert_eq!(checksum(&data), 0);
        let data = [0x01u8, 0xFF, 0xFE, 0x02];
        assert_eq!(checksum(&data), 0);
    }

    #[test]
    fn read_cmos_does_not_panic() {
        // The function reads CMOS register 0x00; on systems
        // without a CMOS the read just returns whatever the
        // host gives us. We only check that the call completes.
        let _ = read_cmos(0);
    }
}
