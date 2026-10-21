//! x86 to RV64 IR and lowering.
//!
//! Thin wrapper around the shared IR. The riscv64 codegen consumes
//! shared IrInst directly.

#![cfg(feature = "btl")]

pub use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};

use super::decoder::DecMode;

/// Lower a decoded x86 instruction to IR (already done by the shared
/// decoder; this is retained for API compatibility).
pub fn lower(inst: &IrInst, _mode: DecMode, _base_va: u64) -> IrInst {
    *inst
}

/// Translate a complete basic block. The shared decoder already
/// produces IR, so this simply copies the input.
pub fn translate_block(block: &[IrInst], _mode: DecMode, out: &mut [IrInst]) -> usize {
    let n = block.len().min(out.len());
    out[..n].copy_from_slice(&block[..n]);
    n
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let ir = [IrInst::empty()];
    let mut out = [IrInst::empty(); 4];
    translate_block(&ir, DecMode::Mode64, &mut out) == 1
}
