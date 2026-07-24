//! Bus Drivers (PCI, ACPI, USB root hubs)
//
//! Each bus driver walks its respective bus and registers every
//! populated device as a PnP node. The PCI bus driver also
//! decodes the BARs and caches the result for the functional
//! drivers.
//
//! Clean-room implementation. The spec source is the PCI Local
//! Bus Specification 3.0, the ACPI 6.0 specification, and the
//! USB 2.0 / 3.0 specifications. No code is copied from any
//! Microsoft or ReactOS source file.

extern crate alloc;

pub mod pnp;
pub mod pci_bus;
pub mod acpi_bus;
pub mod usb_bus;

use crate::kprintln;

/// Initialise the bus drivers. Walks PCI, ACPI, and the USB root
/// hubs and registers every populated device.
///
/// PCI and the USB root hub are cross-arch (the ECAM and XHCI
/// drivers live in `hal/common/pci` and `hal/common/usb`). ACPI is
/// arch-specific (only x86_64 has an `acpi` device-table parser that
/// understands RSDP/XSDT); on aarch64 / riscv64 / loongarch64 we
/// rely on FDT/DTB discovery instead, which is handled in
/// `arch::<arch>::paging::init` via the `identity_map_region` calls
/// the kernel makes before reaching this function.
pub fn init() {
    crate::hal::serial::write_string("D:pci_start\r\n");
    pci_bus::init();
    crate::hal::serial::write_string("D:pci_done\r\n");
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::serial::write_string("D:acpi_start\r\n");
        acpi_bus::init();
        crate::hal::serial::write_string("D:acpi_done\r\n");
        crate::hal::serial::write_string("D:usb_bus_start\r\n");
        usb_bus::init();
        crate::hal::serial::write_string("D:usb_bus_done\r\n");
    }
}

/// Smoke test for the bus drivers. Re-enumerates PCI and asserts
/// the host bridge ID is stable across two reads.
pub fn smoke_test() -> bool {
    // kprintln!("  [BUS SMOKE] running bus driver smoke test...")  // kprintln disabled (memcpy crash workaround);

    let devs = crate::hal::common::pci::enumerate();
    if devs.is_empty() {
        // kprintln!("  [BUS SMOKE FAIL] PCI enumeration returned zero devices")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // kprintln!("  [BUS SMOKE] PCI: {} devices", devs.len())  // kprintln disabled (memcpy crash workaround);

    let id0 = crate::hal::common::pci::read_config_dword(0, 0, 0, 0);
    let id1 = crate::hal::common::pci::read_config_dword(0, 0, 0, 0);
    if id0 != id1 {
        // kprintln!("  [BUS SMOKE FAIL] host bridge ID is not stable across reads")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // kprintln!("  [BUS SMOKE] host bridge stable ID 0x{:08x}", id0)  // kprintln disabled (memcpy crash workaround);

    if devs.len() > 1 {
        if pci_bus::find_pci(devs[1].bus, devs[1].device, devs[1].function).is_none() {
            // kprintln!("  [BUS SMOKE FAIL] cached PCI info missing for 0:1:0")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    }

    // kprintln!("  [BUS SMOKE OK] bus drivers healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
