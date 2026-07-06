//! USB Bus Driver
//
//! Walks the USB host controllers (UHCI / EHCI / xHCI) and
//! registers each as a PnP node. The actual enumeration of
//! devices behind a hub is performed by the `hub` driver in
//! `drivers::usb` once the host controller driver is up.
//
//! Clean-room implementation. Spec source: USB 2.0 specification
//! (chapter 10, hub specification) and USB 3.0 specification
//! (chapter 11, hub specification). No code is copied from any
//! Microsoft or ReactOS source file.

use super::pnp;
use crate::hal::common::pci;
use crate::kprintln;

/// USB host controller PCI class codes (subclass 0x03, prog-if
/// varies by controller generation).
const UHCI_PCI_CLASS: (u8, u8, u8) = (0x0C, 0x03, 0x00);
const EHCI_PCI_CLASS: (u8, u8, u8) = (0x0C, 0x03, 0x20);
const XHCI_PCI_CLASS: (u8, u8, u8) = (0x0C, 0x03, 0x30);

/// Walk PCI, find every USB host controller, and register it.
pub fn init() {
    let mut hc_count = 0u32;
    for dev in pci::enumerate() {
        if (dev.class_code, dev.subclass, dev.prog_if) == UHCI_PCI_CLASS
            || (dev.class_code, dev.subclass, dev.prog_if) == EHCI_PCI_CLASS
            || (dev.class_code, dev.subclass, dev.prog_if) == XHCI_PCI_CLASS
        {
            if pnp::register_pci_device(dev).is_some() {
                hc_count += 1;
                let _ = hc_count; // increment semantics preserved; not yet reported
            }
        }
    }
    // kprintln!("      USB bus: {} host controller(s) discovered", hc_count)  // kprintln disabled (memcpy crash workaround);
}
