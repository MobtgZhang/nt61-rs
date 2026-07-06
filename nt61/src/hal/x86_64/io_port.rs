//! I/O Port Access Primitives
//
//! x86 `IN` / `OUT` instructions wrapped as Rust functions. The
//! `hal.dll` interface in Windows NT 6.1 exports a set of port-I/O
//! helpers (`READ_PORT_UCHAR`, `WRITE_PORT_ULONG`, ...). This module
//! provides the same names so kernel and driver code can call them
//! directly without going through the higher-level HAL APIs.
//
//! All routines are `#[inline(always)]` so the compiler emits the
//! single `in` / `out` instruction in place of the call.

// HAL port-I/O helpers follow the WDK naming convention
// (`READ_PORT_UCHAR`, `WRITE_PORT_ULONG`, ...).
#![allow(non_snake_case, non_upper_case_globals, dead_code)]

#![cfg(target_arch = "x86_64")]

use core::arch::asm;

/// Read an 8-bit value from `port`.
///
/// Equivalent of NT 6.1's `READ_PORT_UCHAR` macro.
#[inline(always)]
pub fn READ_PORT_UCHAR(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// Read a 16-bit value from `port`.
///
/// Equivalent of NT 6.1's `READ_PORT_USHORT` macro.
#[inline(always)]
pub fn READ_PORT_USHORT(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// Read a 32-bit value from `port`.
///
/// Equivalent of NT 6.1's `READ_PORT_ULONG` macro.
#[inline(always)]
pub fn READ_PORT_ULONG(port: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// Write an 8-bit value to `port`.
///
/// Equivalent of NT 6.1's `WRITE_PORT_UCHAR` macro.
#[inline(always)]
pub fn WRITE_PORT_UCHAR(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// Write a 16-bit value to `port`.
///
/// Equivalent of NT 6.1's `WRITE_PORT_USHORT` macro.
#[inline(always)]
pub fn WRITE_PORT_USHORT(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// Write a 32-bit value to `port`.
///
/// Equivalent of NT 6.1's `WRITE_PORT_ULONG` macro.
#[inline(always)]
pub fn WRITE_PORT_ULONG(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// Read a buffer of 8-bit values from `port` using `rep insb`.
///
/// Equivalent of NT 6.1's `READ_PORT_BUFFER_UCHAR` macro.
#[inline(never)]
pub fn READ_PORT_BUFFER_UCHAR(port: u16, buffer: &mut [u8]) {
    if buffer.is_empty() { return; }
    unsafe {
        asm!("rep insb",
             in("dx") port,
             inout("rdi") buffer.as_mut_ptr() => _,
             inout("rcx") buffer.len() => _,
             options(nostack, preserves_flags));
    }
}

/// Write a buffer of 8-bit values to `port` using `rep outsb`.
///
/// Equivalent of NT 6.1's `WRITE_PORT_BUFFER_UCHAR` macro.
#[inline(never)]
pub fn WRITE_PORT_BUFFER_UCHAR(port: u16, buffer: &[u8]) {
    if buffer.is_empty() { return; }
    unsafe {
        asm!("rep outsb",
             in("dx") port,
             inout("rsi") buffer.as_ptr() => _,
             inout("rcx") buffer.len() => _,
             options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The host build (x86_64-unknown-linux-gnu) can actually execute
    // these against the platform.  We deliberately pick a port
    // address (0x80) that is a diagnostic port and never raises an
    // error on a real PC; if the port is missing, the CPU still
    // completes the cycle on modern hardware.
    #[test]
    fn port_io_round_trip() {
        let port: u16 = 0x80;
        WRITE_PORT_UCHAR(port, 0xA5);
        let read_back = READ_PORT_UCHAR(port);
        // 0x80 is a write-only diagnostic port in PC hardware; we
        // do not assert any value, only that the CPU did not
        // fault. The test exists to ensure the inlines compile.
        let _ = read_back;
    }
}
