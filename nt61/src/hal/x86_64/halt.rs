//! Firmware Return / Reboot / Shutdown
//
//! Implements the `hal.dll` `HalReturnToFirmware` export plus a
//! hand-rolled `bugcheck_screen` helper that draws the NT-style
//! blue screen of death on whatever display the framebuffer
//! module was initialised with.
//
//! The reboot and shutdown paths follow the canonical x86
//! sequences: keyboard controller 0x64 warm-boot, ACPI PM1a
//! SLP_TYP/SLP_EN, and finally the triple-fault last resort.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::framebuffer;
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{WRITE_PORT_UCHAR, WRITE_PORT_USHORT};

/// Firmware action codes. The values match those defined in the
/// WDK `FIRMWARE_REENTRY` enumeration.
pub mod firmware_action {
    pub const HAL_HALT: u8 = 0;
    pub const HAL_REBOOT: u8 = 1;
    pub const HAL_SHUTDOWN: u8 = 2;
}

/// Conventional 8042 keyboard controller command byte. Writing
/// 0xFE triggers a CPU reset on real hardware.
const KBD_RESET_CPU: u8 = 0xFE;
const KBD_STATUS_PORT: u16 = 0x64;
const ACPI_PM1A_CNT: u16 = 0x604; // fallback if no FADT
const ACPI_PM1A_CNT_LEGACY: u16 = 0xB004; // legacy QEMU / Bochs PM port
const ACPI_SLP_TYP_S5: u16 = 5 << 10;
const ACPI_SLP_EN: u16 = 1 << 13;
#[allow(dead_code)]
const RESET_VECTOR_IO_PORT: u16 = 0x64;
const PCI_RESET_PORT: u16 = 0xCF9;
const PCI_RESET_VALUE: u8 = 0x06; // reset CPU + system

/// The physical address of the FADT-derived PM1a control
/// register. Defaults to 0x604 (a QEMU-emulated value) if the
/// real FADT is not available.
static PM1A_CNT: AtomicU64 = AtomicU64::new(ACPI_PM1A_CNT as u64);

/// Set the ACPI PM1a control register address. Called by
/// `HalInitSystem` after parsing the FADT.
pub fn set_pm1a_cnt(phys: u64) {
    PM1A_CNT.store(phys, Ordering::Release);
}

/// Write a 16-bit value to the ACPI PM1a control register. On
/// x86 the fixed PM1a_CNT (0x604) is an I/O port, not a
/// memory-mapped register, so the write must use `out dx, ax`.
fn pm1a_write(value: u16) {
    let phys = PM1A_CNT.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    WRITE_PORT_USHORT(phys as u16, value);
}

/// Reboot the system via the keyboard controller.
pub fn reboot_via_kbc() -> ! {
    WRITE_PORT_UCHAR(KBD_STATUS_PORT, KBD_RESET_CPU);
    // If the KBC did not cooperate, fall through to PCI reset.
    reboot_via_pci()
}

/// Reboot the system via the PCI reset port (0xCF9). Available
/// on most modern motherboards.
pub fn reboot_via_pci() -> ! {
    WRITE_PORT_UCHAR(PCI_RESET_PORT, PCI_RESET_VALUE);
    // Last resort: triple fault. Force #DF by setting the IDT
    // pointer to a NULL/0 limit, then `int 0`.
    unsafe {
        let idt_ptr: u64 = 0;
        asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack));
        asm!("int 3", options(nostack));
    }
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

/// Shutdown via ACPI S5 (soft-off). The spec-correct write uses
/// the \_S5 SLP_TYP value, but some firmware stacks (including
/// common QEMU machine models) only power off when the register
/// is written with SLP_EN and SLP_TYP = 0, or via the legacy
/// 0xB004 port. Each write either powers the machine off (and
/// never returns) or is ignored, so the attempts can be chained.
pub fn shutdown_via_acpi() -> ! {
    pm1a_write(ACPI_SLP_TYP_S5 | ACPI_SLP_EN);
    pm1a_write(ACPI_SLP_EN);
    WRITE_PORT_USHORT(ACPI_PM1A_CNT_LEGACY, ACPI_SLP_EN);
    // On real hardware the system powers off here. If the
    // firmware does not honour any of the requests we still want
    // to halt the kernel without taking the system down further.
    halt()
}

/// Halt the processor. Matches the `HAL_HALT` action.
pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("cli; hlt", options(nostack, preserves_flags));
        }
    }
}

/// Top-level `HalReturnToFirmware` entry. The argument is one of
/// the `firmware_action` constants; other values are coerced to
/// `HAL_HALT`.
pub fn HalReturnToFirmware(action: u32) -> ! {
    match action as u8 {
        firmware_action::HAL_REBOOT => reboot_via_kbc(),
        firmware_action::HAL_SHUTDOWN => shutdown_via_acpi(),
        _ => halt(),
    }
}

/// Display a blue-screen style bugcheck message. Used by
/// `ke::bugcheck` and the panic handler.
pub fn bugcheck_screen(code: u32, message: &str) {
    // Force the framebuffer into a known state.
    let fb = framebuffer::init(None);
    let _ = fb;

    let mut buf = [0u8; 32];
    let prefix = b"*** STOP: 0x";
    for (i, b) in prefix.iter().enumerate() {
        buf[i] = *b;
    }
    let hex_chars = b"0123456789ABCDEF";
    for i in 0..8 {
        let shift = (7 - i) * 4;
        let nibble = ((code >> shift) & 0xF) as usize;
        buf[prefix.len() + i] = hex_chars[nibble];
    }
    let title = match core::str::from_utf8(&buf[..prefix.len() + 8]) {
        Ok(s) => s,
        Err(_) => "*** STOP",
    };
    framebuffer::bugcheck_screen(title, message);
    halt();
}
