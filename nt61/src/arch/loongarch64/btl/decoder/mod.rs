//! BTL — x86 instruction decoder (thin wrapper around shared decoder).

#![cfg(target_arch = "loongarch64")]

pub use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};
pub use crate::arch::common::btl::x86_decoder::{
    decode_block as decode_block_shared, decode_one as decode_one_shared, MAX_BLOCK_BYTES,
    MAX_DECODED_INSTS,
};

/// Compatibility type for the existing loongarch64 code.
#[derive(Copy, Clone, Debug)]
pub struct Decoded {
    pub opcode: u32,
    pub length: u8,
    pub ir: Option<IrInst>,
}

impl Decoded {
    pub fn empty() -> Self {
        Self {
            opcode: 0,
            length: 0,
            ir: None,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum DecodeError {
    EndOfStream,
    BadOpcode,
    InvalidModrm,
}

/// Top-level entry. Returns (Decoded, bytes_consumed) or an error.
/// Uses the shared decoder and adapts the output.
pub fn decode_one(code: &[u8], offset: usize) -> Result<(Decoded, usize), DecodeError> {
    if offset >= code.len() {
        return Err(DecodeError::EndOfStream);
    }
    let va = 0x1000u64; // arbitrary base for VA calculation
    match decode_one_shared(&code[offset..], va) {
        Some((ir, len)) => {
            let opcode = match &ir.op {
                IROp::Nop => 0x90,
                IROp::Ret => 0xC3,
                IROp::Jmp { .. } => 0xE9,
                IROp::Call { .. } => 0xE8,
                IROp::Syscall => 0x0F05,
                IROp::MovImm { .. } => 0xB8,
                IROp::MovReg { .. } => 0x89,
                IROp::Load { .. } => 0x8B,
                IROp::Store { .. } => 0x89,
                IROp::AluReg { op, .. } => match op {
                    AluOp::Add => 0x01,
                    AluOp::Sub => 0x29,
                    AluOp::And => 0x21,
                    AluOp::Or => 0x09,
                    AluOp::Xor => 0x31,
                    AluOp::Cmp => 0x39,
                    AluOp::Test => 0x85,
                },
                IROp::AluImm { .. } => 0x83,
                IROp::AluMem { .. } => 0x83,
                IROp::Lea { .. } => 0x8D,
                IROp::Push { .. } => 0x50,
                IROp::Pop { .. } => 0x58,
                IROp::Jcc { .. } => 0x74,
                IROp::SimdMov { .. } | IROp::SimdStore { .. } | IROp::SimdArith { .. } => 0x0F,
                IROp::Unsupported => 0x0F,
            };
            Ok((
                Decoded {
                    opcode,
                    length: ir.guest_len,
                    ir: Some(ir),
                },
                len,
            ))
        }
        None => Err(DecodeError::BadOpcode),
    }
}

/// Simple PE/COFF-aware dispatch.
pub fn looks_like_pe(code: &[u8]) -> bool {
    code.len() >= 2 && code[0] == b'M' && code[1] == b'Z'
}
