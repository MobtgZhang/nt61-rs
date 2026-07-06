//! Architecture-agnostic I/O port support.
//
//! On x86_64 this module provides the x86 inb/outb instructions.
//! On other platforms we provide no-op stubs.

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::io_port::*;

#[cfg(not(target_arch = "x86_64"))]
mod stub {
    /// Read a byte from an I/O port. No-op on non-x86_64.
    pub fn READ_PORT_UCHAR(_port: u16) -> u8 {
        0
    }

    /// Write a byte to an I/O port. No-op on non-x86_64.
    pub fn WRITE_PORT_UCHAR(_port: u16, _value: u8) {}

    /// Read a word (16-bit) from an I/O port. No-op on non-x86_64.
    pub fn READ_PORT_USHORT(_port: u16) -> u16 {
        0
    }

    /// Write a word (16-bit) to an I/O port. No-op on non-x86_64.
    pub fn WRITE_PORT_USHORT(_port: u16, _value: u16) {}

    /// Read a long (32-bit) from an I/O port. No-op on non-x86_64.
    pub fn READ_PORT_ULONG(_port: u16) -> u32 {
        0
    }

    /// Write a long (32-bit) to an I/O port. No-op on non-x86_64.
    pub fn WRITE_PORT_ULONG(_port: u16, _value: u32) {}
}

#[cfg(not(target_arch = "x86_64"))]
pub use stub::*;
