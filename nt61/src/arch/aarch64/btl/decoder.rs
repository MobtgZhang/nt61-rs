//! BTL x86_64/AArch32 instruction decoder.
//!
//! Currently a stub. A full implementation will decode instructions
//! one at a time, returning a stream of [`super::DecodedInstr`]
//! that the IR builder consumes.
//!
//! ## Decoding strategy (planned)
//!
//! The decoder is partitioned by guest architecture:
//!
//! * `x86_64.rs` — x86/x86_64 instruction decoder (variable-length
//!   1-15 byte instructions, prefixes, immediate/displacement
//!   encoding).
//! * `x86_32.rs` — subset of the x86 decoder for 32-bit guest code.
//! * `arm32.rs` — fixed-width 32-bit ARM/Thumb decoder.
//!
//! All three modules export a single `decode_one(byte)` entry point
//! that consumes a single instruction and returns a
//! `DecodedInstr`.

use crate::arch::aarch64::btl::BtlError;

/// Decoded instruction placeholder.
#[derive(Debug, Clone, Copy)]
pub struct DecodedInstr {
    pub pc: u64,
    pub length: u8,
    pub kind: InstrKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrKind {
    Nop,
    MovImm { dst: u8, imm: i64 },
    Add { dst: u8, src: u8, imm: i32 },
    Jump { target: u64, is_indirect: bool },
    Call { target: u64, is_indirect: bool },
    Ret,
    Syscall,
    Unreachable,
    Other,
}

/// Decode one x86_64 instruction. Returns `Err(OutOfBounds)` if the
/// buffer is exhausted or `Err(InvalidInstruction)` if the bytes
/// don't form a recognised encoding.
pub fn decode_x86_64_one(bytes: &[u8]) -> Result<DecodedInstr, BtlError> {
    let _ = bytes;
    Err(BtlError::Disabled)
}

/// Decode one ARM32 instruction.
pub fn decode_arm32_one(_bytes: &[u8]) -> Result<DecodedInstr, BtlError> {
    Err(BtlError::Disabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_disabled() {
        let r = decode_x86_64_one(&[0x90]);
        assert_eq!(r, Err(BtlError::Disabled));
    }
}
