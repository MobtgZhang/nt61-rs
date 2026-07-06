//! BTL — system instruction translation (CPUID, RDTSC, IN/OUT).
//!
//! These are mostly trapped into the kernel: the translator emits a
//! call to a helper in the host kernel that handles the exception
//! and returns the appropriate x86-shaped value.

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

pub fn translate(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    let hi = (dec.opcode >> 8) & 0xFF;
    let lo = dec.opcode & 0xFF;
    if hi == 0x0F {
        match lo {
            0xA2 => return cpuid(buf, dec),
            0x31 => return rdtsc(buf, dec),
            0x05 => return syscall(buf, dec),
            _ => return Ok(()),
        }
    }
    match lo {
        0xEC | 0xEE => io_port(buf, dec),
        _ => Ok(()),
    }
}

fn cpuid(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn rdtsc(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn io_port(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn syscall(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
