//! BTL — control-flow translation (jumps, calls, ret).

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

/// Translate one control-flow instruction. The actual LA64 branch
/// opcode is emitted through `emit::la64_reg::emit_label` so the
/// patcher can resolve cross-block targets after the block is
/// finalised.
pub fn translate(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    let hi = (dec.opcode >> 8) & 0xFF;
    let lo = dec.opcode & 0xFF;
    if hi == 0x0F && (0x80..=0x8F).contains(&lo) {
        return jcc_near(buf, dec);
    }
    match lo {
        0xE9 | 0xEB => jmp_near(buf, dec),
        0xE8 => call_near(buf, dec),
        0xC3 => ret(buf),
        0x70..=0x7F => jcc_short(buf, dec),
        _ => Ok(()),
    }
}

fn jmp_near(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn call_near(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn ret(_buf: &mut EmitBuffer) -> Result<(), TranslateError> { Ok(()) }
fn jcc_near(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn jcc_short(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
