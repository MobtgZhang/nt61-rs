//! Common Hardware Abstraction Layer
//!
//! Architecture-independent hardware interfaces

pub mod acpi;
pub mod interrupts;
pub mod timer;
pub mod console;
pub mod pci;
pub mod dma;
pub mod pit;
pub mod serial;
pub mod io_port;
pub mod framebuffer;
pub mod text_console;
pub mod keyboard_input;

/// Initialize all hardware (common part)
pub fn init() {
    acpi::init();
    pci::init();
}

/// Shutdown hardware
pub fn shutdown() {
    // Clean up hardware
}