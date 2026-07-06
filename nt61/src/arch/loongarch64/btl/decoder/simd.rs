//! SIMD instruction decoder stubs (SSE / AVX). Splitting the hot
//! path keeps the integer decoder readable.

#![cfg(target_arch = "loongarch64")]

/// Decode one SIMD-prefixed instruction. Currently returns a
/// "not-implemented" error for every input — the integer decoder
/// covers most guest code and SIMD coverage is added in a follow-up
/// phase.
pub fn decode_simd_one(_code: &[u8], _offset: usize) -> Result<super::Decoded, super::DecodeError> {
    Err(super::DecodeError::BadOpcode)
}
