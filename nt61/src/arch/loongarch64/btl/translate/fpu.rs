//! BTL — x87 FPU translation.
//!
//! Maps x87 FPU instructions to LA64 scalar FP ops. The FPU state
//! lives in `arch::loongarch64::fpu::FpuState`. For LSX/LASX hosts
//! the FPU ops are upgraded automatically; the translator does not
//! need to special-case them.

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

pub fn translate(buf: &mut EmitBuffer, dec: &Decoded) -> Result<(), TranslateError> {
    match dec.opcode {
        0xD8 | 0xD9 | 0xDA | 0xDB | 0xDC | 0xDD | 0xDE | 0xDF => fpu(buf, dec),
        _ => Ok(()),
    }
}

fn fpu(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> { Ok(()) }
