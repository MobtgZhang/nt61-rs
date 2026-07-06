//! aarch64 (ARMv8/ARMv9) Hardware Abstraction Layer
//!
//! ARM64 HAL. Contains the PL011 UART driver for QEMU 'virt', a GIC
//! interrupt controller driver (v2 and v3), an ARM Generic Timer
//! driver, and the SoC descriptor wiring that publishes the kernel's
//! view of the platform.

pub mod apic;
pub mod gic;
pub mod serial;
pub mod timer;

pub use apic as gic_legacy;
pub use timer as arch_timer;

/// Initialize the HAL - serial port + SoC detection + interrupt
/// controllers + timers.
pub fn init() {
    crate::hal::serial::write_string("hal_init:serial\r\n");
    serial::init();
    crate::hal::serial::write_string("hal_init:soc\r\n");
    crate::arch::aarch64::soc::init_soc();
    crate::hal::serial::write_string("hal_init:soc_done\r\n");
    crate::hal::serial::write_string("hal_init:apic\r\n");
    apic::init(0x0800_0000, 0x0801_0000);
    crate::hal::serial::write_string("hal_init:timer_init\r\n");
    timer::init(1000);
    crate::hal::serial::write_string("hal_init:timer_mark\r\n");
    timer::mark_boot();
    crate::hal::serial::write_string("hal_init:done\r\n");
}

/// Print the SoC info on the serial console (used by smoke tests and
/// by `kernel_main` once the page-fault handler is ready).
pub fn dump_soc_info() {
    let info = crate::arch::aarch64::soc::current_soc();
    serial::write_string("AArch64 SoC: ");
    serial::write_string(info.name);
    serial::write_string("\r\n");
}
