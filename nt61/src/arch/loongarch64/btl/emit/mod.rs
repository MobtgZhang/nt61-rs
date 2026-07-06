//! BTL — LoongArch instruction emitter.
//!
//! Builds a `Vec<u32>` of 32-bit instructions for the host. Each
//! LA64 fixed-length instruction is 32 bits; branch / jump offsets
//! are emitted via temporary branch-fixup placeholders that
//! `emit::resolve_branches` walks at the end of translation.

#![cfg(target_arch = "loongarch64")]

pub mod la64_reg;

pub use la64_reg::{La64Reg, Operand, emit_label};

#[derive(Copy, Clone, Debug)]
pub struct PendingBranch {
    pub offset_insn: usize,
    pub target: u32,
    pub kind: BranchKind,
}

#[derive(Copy, Clone, Debug)]
pub enum BranchKind {
    /// B/Cond branch — PC-relative.
    B { cond: u8, imm_bits: u32 },
    /// JIRL indirect jump through a register.
    Jirl { rd: u8, rj: u8 },
    /// BL unconditional call — patched at end of block.
    Bl,
}

/// Emit buffer that collects translated instructions and patch sites.
#[derive(Default)]
pub struct EmitBuffer {
    pub code: alloc::vec::Vec<u32>,
    pub pending: alloc::vec::Vec<PendingBranch>,
}

impl EmitBuffer {
    pub fn new() -> Self {
        Self {
            code: alloc::vec::Vec::new(),
            pending: alloc::vec::Vec::new(),
        }
    }
    pub fn push_insn(&mut self, raw: u32) { self.code.push(raw); }
    pub fn mark(&mut self, pc: u32) { /* branch targets stored as offsets */ let _ = pc; }
    pub fn len(&self) -> usize { self.code.len() }
    pub fn is_empty(&self) -> bool { self.code.is_empty() }
}

// Re-export the allocation API needed by emit-buffer callers.
extern crate alloc;
