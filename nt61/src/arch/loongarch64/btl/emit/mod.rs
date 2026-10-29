//! BTL — LoongArch instruction emitter.
//!
//! Builds a `Vec<u32>` of 32-bit instructions for the host. Each
//! LA64 fixed-length instruction is 32 bits; branch / jump offsets
//! are emitted via temporary branch-fixup placeholders that
//! `emit::resolve_branches` walks at the end of translation.

#![cfg(target_arch = "loongarch64")]

pub mod la64_reg;

pub use la64_reg::{emit_label, La64Reg, Operand};

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
    pub labels: alloc::vec::Vec<(u32, usize)>,
}

impl EmitBuffer {
    pub fn new() -> Self {
        Self {
            code: alloc::vec::Vec::new(),
            pending: alloc::vec::Vec::new(),
            labels: alloc::vec::Vec::new(),
        }
    }
    pub fn push_insn(&mut self, raw: u32) {
        self.code.push(raw);
    }
    pub fn mark(&mut self, pc: u32) {
        self.labels.push((pc, self.code.len()));
    }
    pub fn len(&self) -> usize {
        self.code.len()
    }
    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }
    /// Resolve all pending branches against the recorded label
    /// positions. Each branch is patched in-place with a PC-relative
    /// offset measured in 4-byte instruction units.
    pub fn resolve_branches(&mut self) {
        let labels = self.labels.clone();
        for branch in &self.pending {
            let Some(&(_pc, target_idx)) = labels
                .iter()
                .find(|&&(target_pc, _)| target_pc == branch.target)
            else {
                continue;
            };
            let rel = target_idx as isize - branch.offset_insn as isize;
            if !(-32768..=32767).contains(&rel) {
                continue;
            }
            let imm16 = (rel as u16) as u32;
            match branch.kind {
                BranchKind::B { cond, imm_bits } => {
                    let raw = self.code[branch.offset_insn];
                    // Preserve the opcode + cond bits, clear and
                    // refill the 16-bit immediate field.
                    let mask = !(0xFFFFu32);
                    let base = raw & (mask | (cond as u32) << 16);
                    self.code[branch.offset_insn] = base | imm16 | (imm_bits << 16);
                }
                BranchKind::Jirl { rd, rj } => {
                    // JIRL: bits [31:10] rd, [9:4] rj, [3:0] func
                    // (zero for return). The 16-bit offset occupies
                    // bits [31:16].
                    let raw = self.code[branch.offset_insn];
                    let base = raw & !(0xFFFFu32 << 16);
                    self.code[branch.offset_insn] =
                        base | (imm16 << 16) | ((rd as u32) << 10) | ((rj as u32) << 4);
                }
                BranchKind::Bl => {
                    // BL: 26-bit signed offset in bits [25:0].
                    let imm26 = (rel as u32) & 0x03FF_FFFF;
                    let raw = self.code[branch.offset_insn];
                    let base = raw & !(0x03FF_FFFFu32);
                    self.code[branch.offset_insn] = base | imm26;
                }
            }
        }
        self.pending.clear();
    }
}

// Re-export the allocation API needed by emit-buffer callers.
extern crate alloc;
