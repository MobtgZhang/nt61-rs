//! Common Hardware Abstraction Layer
//!
//! Architecture-independent hardware interfaces

pub mod acpi;
pub mod cmos;
pub mod console;
pub mod dma;
pub mod framebuffer;
pub mod framebuffer_impl;
pub mod interrupts;
pub mod io_port;
pub mod keyboard_input;
// Unified keyboard ring: x86_64 has its own PS/2 + USB-HID
// implementation at hal::x86_64::keyboard_unified, so this
// module only compiles on the other three architectures.
#[cfg(not(target_arch = "x86_64"))]
pub mod keyboard_unified;
pub mod pci;
pub mod pit;
pub mod power;
pub mod serial;
pub mod serial_disable;
pub mod system_info;
pub mod text_console;
pub mod timer;

/// Initialize all hardware (common part)
pub fn init() {
    acpi::init();
    pci::init();
}

/// Shutdown hardware
pub fn shutdown() {
    // Clean up hardware
}
