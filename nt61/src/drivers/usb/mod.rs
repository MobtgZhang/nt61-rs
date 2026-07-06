//! USB Driver Stack
//
//! Contains the three USB host controller drivers (UHCI / EHCI /
//! xHCI), the USB hub class driver, and the USB HID class driver.
//! On a QEMU `-machine q35` system the controller is xHCI; on
//! older VMs the controller is EHCI (USB 2) plus companion UHCI
//! (USB 1.1) controllers. The hub driver walks the port status
//! registers to discover connected devices; the HID driver
//! accepts the boot keyboard / mouse subclasses.
//
//! Clean-room implementation. Spec source: USB 2.0 specification
//! (chapters 5 / 8 / 10 / 11), USB 3.0 specification (chapters
//! 7 / 8), and the xHCI specification 1.2. No code is copied
//! from any Microsoft or ReactOS source file.

extern crate alloc;

pub mod uhci;
pub mod ehci;
pub mod xhci;
pub mod hub;
pub mod hid;

pub mod smoke;

use crate::kprintln;

/// Initialise the USB stack. Each host controller driver
/// registers itself with the bus layer; the hub and HID drivers
/// then bind to whichever devices the controllers discover.
pub fn init() {
    // kprintln!("    USB drivers: UHCI, EHCI, xHCI, hub, HID")  // kprintln disabled (memcpy crash workaround);
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:before_uhci\r\n");
    uhci::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:after_uhci\r\n");
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:before_ehci\r\n");
    ehci::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:after_ehci\r\n");
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:before_xhci\r\n");
    xhci::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:after_xhci\r\n");
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:before_hub\r\n");
    hub::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:after_hub\r\n");
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:before_hid\r\n");
    hid::init();
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:after_hid\r\n");
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("USB:done\r\n");
    // kprintln!("    USB stack ready")  // kprintln disabled (memcpy crash workaround);
}

/// Smoke test for the USB driver stack. Re-runs each driver's
/// self-check and aggregates.
pub fn smoke_test() -> bool { smoke::smoke_test() }

/// Poll all USB host controllers and feed any pending HID
/// boot-keyboard reports into the shared keyboard ring buffer.
///
/// On QEMU with the `-device usb-kbd` flag this picks up keys
/// pressed on the QEMU window via the emulated xHCI controller.
/// On bare hardware it depends on the host controller driver
/// being able to issue an interrupt-in transfer to the HID
/// endpoint — currently only the xHCI driver has enough MMIO
/// scaffolding to attempt that, and even there the polling path
/// is a placeholder until the transfer-ring infrastructure
/// lands.
///
/// Safe to call from any context, including with IF=0 — the
/// function does no sleeping and uses no heap allocation.
pub fn poll_keyboards() {
    hid::poll_keyboards();
}

/// Register a freshly-discovered USB HID boot-protocol keyboard
/// in the HID driver so subsequent `poll_keyboards` calls
/// process its reports.
pub fn register_usb_keyboard() -> Option<usize> {
    hid::register_keyboard()
}

/// Submit a single BootKeyboardReport for a registered slot.
pub fn submit_usb_keyboard_report(slot: usize, report: hid::BootKeyboardReport) {
    hid::submit_report(slot, report);
}

/// True when at least one USB HID keyboard has been registered.
pub fn usb_keyboard_available() -> bool {
    hid::has_keyboards()
}
