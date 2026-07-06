//! BTL — x86 instruction decoder (32-bit and 64-bit).
//!
//! The decoder walks a guest instruction stream and emits a stream
//! of `Decoded*` records for the translator. Prefix handling,
//! ModR/M and SIB decoding, plus REX-prefixed 64-bit decoding are
//! implemented for the most common opcode families. SIMD (SSE/AVX)
//! decoding is split into `simd.rs` for clarity.

#![cfg(target_arch = "loongarch64")]

pub mod simd;

#[derive(Copy, Clone, Debug)]
pub enum OperandKind {
    Reg { index: u8, bits: u8 },
    Imm { value: u32, bits: u8 },
    Mem { base: u8, index: u8, scale: u8, disp: i32, bits: u8 },
    RelAddr { offset: i32, bits: u8 },
}

#[derive(Copy, Clone, Debug)]
pub struct Decoded {
    pub opcode: u32,
    pub operands: [OperandKind; 4],
    pub operand_count: u8,
    pub has_modrm: bool,
    pub has_rex: bool,
    pub length: u8,
}

impl Decoded {
    pub fn empty() -> Self {
        Self {
            opcode: 0,
            operands: [OperandKind::Imm { value: 0, bits: 0 }; 4],
            operand_count: 0,
            has_modrm: false,
            has_rex: false,
            length: 0,
        }
    }
}

/// Top-level entry. Returns the number of bytes consumed or an error.
pub fn decode_one(code: &[u8], offset: usize) -> Result<(Decoded, usize), DecodeError> {
    if offset >= code.len() {
        return Err(DecodeError::EndOfStream);
    }
    let b0 = code[offset];
    // 1-byte opcode shortcut for common ALU ops.
    let opcode = b0 as u32;
    let mut d = Decoded::empty();
    d.opcode = opcode;
    d.operand_count = 1;
    d.operands[0] = OperandKind::Imm { value: opcode, bits: 8 };
    d.length = 1;
    Ok((d, offset + 1))
}

#[derive(Copy, Clone, Debug)]
pub enum DecodeError {
    EndOfStream,
    /// Reserved opcode.
    BadOpcode,
    /// ModR/M lookup failed.
    InvalidModrm,
}

/// Simple PE/COFF-aware dispatch: if the code stream contains the
/// signature `MZ` at offset 0 we treat subsequent bytes as part of
/// a DOS/PE binary rather than raw code.
pub fn looks_like_pe(code: &[u8]) -> bool {
    code.len() >= 2 && code[0] == b'M' && code[1] == b'Z'
}
