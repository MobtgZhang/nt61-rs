//! x86_64 instruction decoder for the RISC-V BTL.
//!
//! Thin wrapper around the shared decoder in
//! crate::arch::common::btl::x86_decoder. Maintains the riscv64-specific
//! public API (DecMode, X86Inst) while delegating the actual decoding
//! to the shared implementation.

#![cfg(feature = "btl")]

pub use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};
pub use crate::arch::common::btl::x86_decoder::{
    decode_one as decode_one_shared, MAX_BLOCK_BYTES, MAX_DECODED_INSTS,
};

/// Decoder mode retained for API compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecMode {
    Mode32,
    Mode64,
}

/// Compatibility type — the shared decoder produces IrInst directly.
/// This struct is retained so that runtime.rs and mem.rs compile.
#[derive(Clone, Copy, Debug)]
pub struct X86Inst {
    pub raw_off: u32,
    pub raw_len: u16,
    pub width: u8,
}

impl X86Inst {
    pub const fn empty() -> Self {
        Self {
            raw_off: 0,
            raw_len: 0,
            width: 0,
        }
    }
}

/// Decode a basic block using the shared decoder. Adapts the shared
/// API to the riscv64-specific signature.
pub fn decode_block(bytes: &[u8], base_va: u64, _mode: DecMode, out: &mut [IrInst]) -> usize {
    crate::arch::common::btl::x86_decoder::decode_block(bytes, base_va, out)
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let mut out = [IrInst::empty(); 8];
    let bytes: [u8; 4] = [0x90, 0xC3, 0x48, 0xB8];
    let n = decode_block(&bytes, 0x1000, DecMode::Mode64, &mut out);
    n >= 2 && out[0].op == IROp::Nop && out[1].op == IROp::Ret
}
