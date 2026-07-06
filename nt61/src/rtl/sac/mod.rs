//! EMS/SAC - Emergency Management Services / Special Administration Console
//
//! Implements Windows Emergency Management Services (EMS) and the Special
//! Administration Console (SAC) for serial console access to Windows 7.

#![allow(dead_code)]

pub mod channel;
// cmd_handler was removed — its previous implementation was a placeholder
// that did not match the rest of the codebase; SAC command processing is
// intentionally left for a future, properly designed implementation.

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether EMS/SAC is enabled
static EMS_ENABLED: AtomicBool = AtomicBool::new(false);
/// Whether SAC is initialized
static SAC_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Whether we are in SAC command mode
static IN_SAC_MODE: AtomicBool = AtomicBool::new(false);

pub fn enable() { EMS_ENABLED.store(true, Ordering::Release); }
pub fn disable() { EMS_ENABLED.store(false, Ordering::Release); }
pub fn is_enabled() -> bool { EMS_ENABLED.load(Ordering::Acquire) }
pub fn init() {
    if !is_enabled() { return; }
    SAC_INITIALIZED.store(true, Ordering::Release);
}
pub fn is_initialized() -> bool { SAC_INITIALIZED.load(Ordering::Acquire) }
pub fn is_in_sac_mode() -> bool { IN_SAC_MODE.load(Ordering::Acquire) }

pub fn stop_sac_loop() {
    IN_SAC_MODE.store(false, Ordering::Release);
}

/// Start SAC command loop
///
/// The command interpreter was removed in this build; SAC now presents its
/// banner, accepts a single Enter to acknowledge, and exits. A real command
/// table will be re-introduced only after the rest of the event-log/SAC
/// stack is verified end-to-end.
pub fn start_sac_loop() {
    if !is_enabled() || !is_initialized() {
        return;
    }
    IN_SAC_MODE.store(true, Ordering::Release);

    print_sac_banner();

    // SAC interactive console is only implemented on x86_64 and
    // loongarch64. On other architectures we simply fall through
    // and exit the loop.
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
    {
        use crate::hal::serial;
        let mut line_buf = [0u8; 256];
        let mut line_len: usize = 0;
        loop {
            if let Some(c) = serial::read_char() {
                match c {
                    b'\r' | b'\n' => {
                        serial::write_string("\r\n");
                        if line_len > 0 {
                            // Echo what was typed; command dispatch removed.
                            serial::write_string("\r\n(no command interpreter in this build)\r\n");
                            line_len = 0;
                        }
                        serial::write_string("SAC>");
                    }
                    0x08 | 0x7F => {
                        if line_len > 0 {
                            line_len -= 1;
                            line_buf[line_len] = 0;
                            serial::write_string("\x08 \x08");
                        }
                    }
                    0x20..=0x7E => {
                        if line_len < 255 {
                            line_buf[line_len] = c;
                            line_len += 1;
                            serial::write_char(c);
                        }
                    }
                    _ => {}
                }
            } else {
                core::hint::spin_loop();
            }
            if !is_in_sac_mode() { break; }
        }
    }
    IN_SAC_MODE.store(false, Ordering::Release);
}

fn print_sac_banner() {
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
    {
        use crate::hal::serial;
        serial::write_string("\r\nComputer is booting, SAC started and initialized.\r\n");
        serial::write_string("\r\nUse the \"ch -?\" command for information about using channels.\r\n");
        serial::write_string("\r\nSAC>");
    }
}

pub fn write(s: &str) {
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
    {
        use crate::hal::serial;
        serial::write_string(s);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "loongarch64")))]
    {
        let _ = s;
    }
}

pub fn write_line(s: &str) {
    write(s);
    write("\r\n");
}
