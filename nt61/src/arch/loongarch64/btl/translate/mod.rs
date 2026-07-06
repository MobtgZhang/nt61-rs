//! BTL — translation rules (x86 → LA64).
//!
//! Each `translate_*` function takes a `Decoded` instruction plus the
//! current emit buffer and writes LoongArch instructions. The full
//! translation strategy mirrors WoW64's approach of keeping a fast
//! path for the 50-or-so most-frequent opcodes and falling back to a
//! microcoded helper for the long tail.
//!
//! Submodules:
//!   * `gen`     — ALU/MOV data movement
//!   * `ctrl`    — control flow (jmp / jcc / call / ret)
//!   * `mem`     — LOAD/STORE/LEA
//!   * `simd`    — SSE/AVX → LSX/LASX
//!   * `system`  — CPUID/RDTSC/SYSCALL/IN/OUT
//!   * `fpu`     — x87 FPU translation

#![cfg(target_arch = "loongarch64")]

pub mod ctrl;
pub mod fpu;
pub mod gen;
pub mod mem;
pub mod simd;
pub mod system;

use crate::arch::loongarch64::btl::decoder::Decoded;
use crate::arch::loongarch64::btl::emit::EmitBuffer;

#[derive(Copy, Clone, Debug)]
pub enum TranslateError {
    DecoderError,
    Oom,
}

/// Dispatch a single instruction to the right translator based on
/// the leading byte(s) of the opcode. The match chain here mirrors
/// Intel's opcode-table groupings rather than decoding the full
/// ModR/M (the per-group modules take it from there).
pub fn translate_instruction(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    let hi = (dec.opcode >> 8) & 0xFF;
    let lo = dec.opcode & 0xFF;
    if hi == 0x0F {
        // Two-byte opcode escape.
        if (0x10..=0x1F).contains(&lo) {
            return simd::translate_lsx(buf, dec).or(simd::translate_lasx(buf, dec));
        }
        if (0x20..=0x2F).contains(&lo) {
            return simd::translate_lsx(buf, dec).or(simd::translate_lasx(buf, dec));
        }
        return system::translate(buf, dec);
    }
    match lo {
        0x00..=0x3F => gen::translate(buf, dec),
        0x40..=0x7F => ctrl::translate(buf, dec).or(gen::translate(buf, dec)),
        0x80..=0xBF => mem::translate(buf, dec).or(gen::translate(buf, dec)),
        0xC0..=0xFF => gen::translate(buf, dec),
        _ => Ok(()),
    }
}

/// Translate an entire basic block starting at `code_base + offset`.
/// Stops at the first control-flow instruction (jmp/ret/intr/etc).
pub fn translate_block(code: &[u8], mut offset: usize, buf: &mut EmitBuffer) -> Result<usize, TranslateError> {
    while offset < code.len() {
        let (decoded, consumed) = match crate::arch::loongarch64::btl::decoder::decode_one(code, offset) {
            Ok((d, c)) => (d, c),
            Err(_) => break,
        };
        translate_instruction(buf, &decoded)?;
        offset = consumed;
        if matches!(decoded.opcode, 0xE9 | 0xEB | 0xC3 | 0xE8 | 0xCC | 0xCD) {
            break;
        }
        if offset - (offset - consumed) > 4096 {
            // Hard cap — block too long, force translation to retire.
            break;
        }
    }
    Ok(offset)
}
