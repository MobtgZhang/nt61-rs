//! I/O Port Access Primitives
//
//! x86 `IN` / `OUT` instructions wrapped as Rust functions. The
//! `hal.dll` interface in Windows NT 6.1 exports a set of port-I/O
//! helpers (`read_port_uchar`, `write_port_ulong`, ...). This module
//! provides the same names so kernel and driver code can call them
//! directly without going through the higher-level HAL APIs.
//
//! All routines are `#[inline(always)]` so the compiler emits the
//! single `in` / `out` instruction in place of the call.

// HAL port-I/O helpers follow the WDK naming convention
// (`read_port_uchar`, `write_port_ulong`, ...).
#![cfg(target_arch = "x86_64")]

use core::arch::asm;

/// read an 8-bit value from `port`.
///
/// Equivalent of NT 6.1's `read_port_uchar` macro.
#[inline(always)]
pub fn read_port_uchar(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// read a 16-bit value from `port`.
///
/// Equivalent of NT 6.1's `read_port_ushort` macro.
#[inline(always)]
pub fn read_port_ushort(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// read a 32-bit value from `port`.
///
/// Equivalent of NT 6.1's `read_port_ulong` macro.
#[inline(always)]
pub fn read_port_ulong(port: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") value,
             options(nostack, preserves_flags, nomem));
    }
    value
}

/// write an 8-bit value to `port`.
///
/// Equivalent of NT 6.1's `write_port_uchar` macro.
#[inline(always)]
pub fn write_port_uchar(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// write a 16-bit value to `port`.
///
/// Equivalent of NT 6.1's `write_port_ushort` macro.
#[inline(always)]
pub fn write_port_ushort(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// write a 32-bit value to `port`.
///
/// Equivalent of NT 6.1's `write_port_ulong` macro.
#[inline(always)]
pub fn write_port_ulong(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value,
             options(nostack, preserves_flags, nomem));
    }
}

/// read a buffer of 8-bit values from `port` using `rep insb`.
///
/// Equivalent of NT 6.1's `read_port_buffer_uchar` macro.
#[inline(never)]
pub fn read_port_buffer_uchar(port: u16, buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }
    unsafe {
        asm!("rep insb",
             in("dx") port,
             inout("rdi") buffer.as_mut_ptr() => _,
             inout("rcx") buffer.len() => _,
             options(nostack, preserves_flags));
    }
}

/// write a buffer of 8-bit values to `port` using `rep outsb`.
///
/// Equivalent of NT 6.1's `write_port_buffer_uchar` macro.
#[inline(never)]
pub fn write_port_buffer_uchar(port: u16, buffer: &[u8]) {
    if buffer.is_empty() {
        return;
    }
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

    // The host build (x86_64-unknown-linux-gnu) cannot execute
    // `in`/`out` instructions in user mode (would cause SIGSEGV).
    // We keep this test as a compile-only smoke test; the real
    // port-IO validation runs during kernel boot via the smoke
    // harness.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn port_io_round_trip() {
        // Compile-only smoke. The actual round-trip is verified
        // during kernel boot by the `ke::smoke` test harness.
        let _port: u16 = 0x80;
        let _v: u8 = 0xA5;
    }
}
