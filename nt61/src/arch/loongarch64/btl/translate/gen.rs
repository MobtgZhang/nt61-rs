//! BTL — general-purpose (ALU + data-movement) instruction translation.

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

/// Translate one general-purpose instruction. The caller has
/// already verified that `dec.opcode` falls in the ALU/MOV group.
pub fn translate(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    match dec.opcode {
        0x90..=0x97 => xchg(buf, dec),
        0x89 => mov_rm_r(buf, dec),
        0xB0..=0xB7 => mov_r_imm8(buf, dec),
        0xB8..=0xBF => mov_r_imm(buf, dec),
        0x01 | 0x29 | 0x09 | 0x31 => alu_rm_r(buf, dec), // ADD/OR/ADC/SUB
        0x03 | 0x0B | 0x33 => alu_r_rm(buf, dec),
        0xC1 | 0xC9 => shift(buf, dec),
        0x38 | 0x39 => cmp(buf, dec),
        _ => {
            // Fall-back: emit a single `nop`-equivalent placeholder
            // so that translation does not stall. The Phase-5 follow-up
            // rules add coverage for the long tail.
            buf.push_insn(0x0340_0000);
            Ok(())
        }
    }
}

fn xchg(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn mov_rm_r(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn mov_r_imm8(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn mov_r_imm(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn alu_rm_r(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn alu_r_rm(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn shift(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
fn cmp(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
