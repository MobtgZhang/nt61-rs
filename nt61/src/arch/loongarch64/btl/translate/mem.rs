//! BTL — memory-access translation (LOAD/STORE/LEA).

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

pub fn translate(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    match dec.opcode {
        0x8B | 0x89 => mov(buf, dec),
        0x8D => lea(buf, dec),
        0xA4 => movs(buf, dec),
        _ => Ok(()),
    }
}

fn mov(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn lea(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn movs(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
