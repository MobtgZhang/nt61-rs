//! Shared BTL infrastructure for all non-x86 architectures.
//!
//! Provides the x86_64 decoder and IR that each target-specific
//! code generator consumes.

pub mod ir;
pub mod x86_decoder;

pub use ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};
pub use x86_decoder::{decode_block, decode_one, MAX_BLOCK_BYTES, MAX_DECODED_INSTS};
