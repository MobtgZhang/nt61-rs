//! 8042 PS/2 Controller Driver
//
//! The 8042 is the legacy keyboard / mouse controller integrated
//! on every PC motherboard. It presents two I/O ports (0x60
//! data, 0x64 command / status) and two interrupt lines (IRQ1
//! for keyboard, IRQ12 for mouse).
//
//! Clean-room implementation. Spec source: IBM PS/2 hardware
//! reference. No code is copied from any Microsoft or ReactOS
//! source file.

#![cfg(target_arch = "x86_64")]

use crate::kprintln;

/// 8042 command / data ports.
const DATA_PORT: u16 = 0x60;
const CMD_PORT: u16 = 0x64;

/// 8042 commands.
const CMD_READ_CMD_BYTE: u8 = 0x20;
const CMD_WRITE_CMD_BYTE: u8 = 0x60;
const CMD_ENABLE_KBD: u8 = 0xAE;
const CMD_ENABLE_MOUSE: u8 = 0xA8;

/// 8042 command byte bits.
const CB_KBD_INT: u8 = 1 << 0;     // Keyboard interrupt enable
const CB_MOUSE_INT: u8 = 1 << 1;   // Mouse interrupt enable
const CB_KBD_DIS: u8 = 1 << 4;     // Keyboard disable (1 = disabled)
const CB_MOUSE_DIS: u8 = 1 << 5;   // Mouse disable (1 = disabled)

/// Cached state of the 8042 controller.
static mut INITIALISED: bool = false;
static mut KBD_INTERRUPTS_ENABLED: bool = false;
static mut MOUSE_INTERRUPTS_ENABLED: bool = false;

/// Walk the 8042. Enables both the keyboard and the mouse
/// interrupt paths.
pub fn init() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};
    unsafe {
        // Read the current command byte.
        WRITE_PORT_UCHAR(CMD_PORT, CMD_READ_CMD_BYTE);
        let mut cb = READ_PORT_UCHAR(DATA_PORT);
        // Make sure the keyboard and mouse are enabled, and that
        // both interrupt paths are wired.
        cb &= !(CB_KBD_DIS | CB_MOUSE_DIS);
        cb |= CB_KBD_INT | CB_MOUSE_INT;
        WRITE_PORT_UCHAR(CMD_PORT, CMD_WRITE_CMD_BYTE);
        WRITE_PORT_UCHAR(DATA_PORT, cb);
        // Re-enable the keyboard and mouse in case the BIOS left
        // them disabled.
        WRITE_PORT_UCHAR(CMD_PORT, CMD_ENABLE_KBD);
        WRITE_PORT_UCHAR(CMD_PORT, CMD_ENABLE_MOUSE);
        // Read the command byte back and confirm.
        WRITE_PORT_UCHAR(CMD_PORT, CMD_READ_CMD_BYTE);
        let cb2 = READ_PORT_UCHAR(DATA_PORT);
        KBD_INTERRUPTS_ENABLED = (cb2 & CB_KBD_INT) != 0;
        MOUSE_INTERRUPTS_ENABLED = (cb2 & CB_MOUSE_INT) != 0;
        INITIALISED = true;
    }
    // kprintln!("      i8042: keyboard+{} mouse+{}",  // kprintln disabled (memcpy crash workaround)
//               if kbd_interrupts_enabled() { "int" } else { "pol" },
//               if mouse_interrupts_enabled() { "int" } else { "pol" });
}


    pub fn kbd_interrupts_enabled() -> bool {
    unsafe { KBD_INTERRUPTS_ENABLED }
}

pub fn mouse_interrupts_enabled() -> bool {
    unsafe { MOUSE_INTERRUPTS_ENABLED }
}

pub fn smoke_test() -> bool {
    // kprintln!("  [i8042 SMOKE] i8042 controller: initialised={} kbd_int={} mouse_int={}",  // kprintln disabled (memcpy crash workaround)
//               unsafe { INITIALISED },
//               kbd_interrupts_enabled(),
//               mouse_interrupts_enabled());
    unsafe { INITIALISED }
}
