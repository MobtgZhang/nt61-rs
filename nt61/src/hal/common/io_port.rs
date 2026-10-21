//! Architecture-agnostic I/O port support.
//
//! On x86_64 this module provides the x86 inb/outb instructions.
//! On other platforms we provide no-op stubs.

#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::io_port::*;

#[cfg(not(target_arch = "x86_64"))]
mod stub {
    /// read a byte from an I/O port. No-op on non-x86_64.
    pub fn read_port_uchar(_port: u16) -> u8 {
        0
    }

    /// write a byte to an I/O port. No-op on non-x86_64.
    pub fn write_port_uchar(_port: u16, _value: u8) {}

    /// read a word (16-bit) from an I/O port. No-op on non-x86_64.
    pub fn read_port_ushort(_port: u16) -> u16 {
        0
    }

    /// write a word (16-bit) to an I/O port. No-op on non-x86_64.
    pub fn write_port_ushort(_port: u16, _value: u16) {}

    /// read a long (32-bit) from an I/O port. No-op on non-x86_64.
    pub fn read_port_ulong(_port: u16) -> u32 {
        0
    }

    /// write a long (32-bit) to an I/O port. No-op on non-x86_64.
    pub fn write_port_ulong(_port: u16, _value: u32) {}
}

#[cfg(not(target_arch = "x86_64"))]
pub use stub::*;
