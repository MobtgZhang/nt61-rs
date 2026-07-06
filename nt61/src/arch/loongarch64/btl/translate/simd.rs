//! BTL — SIMD translation (SSE → LSX, AVX → LASX).

#![cfg(target_arch = "loongarch64")]

use crate::arch::loongarch64::btl::emit::EmitBuffer;
use crate::arch::loongarch64::btl::decoder::Decoded;

use super::TranslateError;

pub fn translate_lsx(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> {
    // Phase-3 work provides the LSX/LASX state struct; the per-opcode
    // translation rules are added in subsequent phases. The dispatch
    // path still routes SSE-prefixed opcodes here so the long-tail
    // coverage is straightforward to extend.
    Ok(())
}

pub fn translate_lasx(_buf: &mut EmitBuffer, _dec: &Decoded) -> Result<(), TranslateError> {
    // LA664-class hosts use LASX (256-bit). For LSX-only parts the
    // emitter lowers to two LSX ops.
    Ok(())
}
