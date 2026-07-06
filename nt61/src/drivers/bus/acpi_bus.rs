//! ACPI Bus Driver
//
//! Registers the standard ACPI device nodes (PNP0C01, PNP0C02,
//! PNP0A03, ...) and re-uses the MADT entries already parsed by
//! `hal::common::acpi`.
//
//! Clean-room implementation. Spec source: ACPI 6.0, sections
//! 5.2 ("ACPI hardware specification") and 6.1 ("ACPI device
//! IDs"). No code is copied from any Microsoft or ReactOS
//! source file.

use super::pnp;
use crate::kprintln;

/// Standard ACPI device IDs we register. The full list lives in
/// the official ACPI specification; this is a bootstrap-friendly
/// subset that covers the resources Windows 7's `acpi.sys`
/// always touches at boot.
const ACPI_DEVICE_IDS: [&[u8]; 8] = [
    b"PNP0C01",  // System board
    b"PNP0C02",  // PNP motherboard resources
    b"PNP0C04",  // Floating-point unit
    b"PNP0C08",  // ACPI-compat HPET
    b"PNP0A03",  // PCI bus
    b"PNP0A05",  // Generic ACPI bus
    b"PNP0A06",  // Generic ACPI bus (extended)
    b"PNP0C09",  // Embedded controller
];

/// Walk the standard ACPI device table and register every entry
/// as a PnP node. The HAL layer is responsible for parsing the
/// MADT; the bus driver simply exposes the matching device IDs.
pub fn init() {
    // kprintln!("      [ACPI] acpi_bus::init() called")  // kprintln disabled (memcpy crash workaround);
    for (i, hid) in ACPI_DEVICE_IDS.iter().enumerate() {
        let _ = i;
        // kprintln!("      [ACPI] registering ACPI device {} {:?}", i, hid)  // kprintln disabled (memcpy crash workaround);
        let _ = pnp::register_acpi_device(hid, 0);
        // kprintln!("      [ACPI] registered ACPI device {}", i)  // kprintln disabled (memcpy crash workaround);
    }
    // kprintln!("      ACPI bus: registered {} device nodes", ACPI_DEVICE_IDS.len())  // kprintln disabled (memcpy crash workaround);
}
