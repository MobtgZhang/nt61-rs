//! AArch64 code generator for the shared BTL IR.
//!
//! Lowers shared IR operations into real AArch64 (ARMv8-A) instruction
//! encodings. All instructions are fixed 4 bytes wide, little-endian.
//!
//! ## Register mapping
//!
//! x86_64 GPRs map to AArch64 x0..x15 (caller-saved scratch). The
//! stack pointer maps to x28 (a callee-saved scratch), and the guest
//! RIP is tracked in x29. A64 x30 (LR) and x31 (SP/ZR) are reserved
//! for the host ABI.
//!
//! ## Encoding conventions
//!
//! A64 instruction fields (for this generator):
//!   * SF (bit 31) = 1 for 64-bit ops
//!   * Rd, Rn, Rm are 5-bit register fields
//!   * Imm12 for ADD/SUB immediate (bits 10..21)

use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};

/// Maximum code bytes per translated block.
pub const MAX_CODE_BYTES: usize = 4096;

/// AArch64 NOP encoding (hint).
const A64_NOP: u32 = 0xD503_201F;

/// AArch64 branch condition codes (B.cond / CSEL).
/// Maps IR BranchCond to the ARM condition field (cond:4).
fn a64_cond(cond: BranchCond) -> u32 {
    match cond {
        BranchCond::Always => 0xE,       // AL
        BranchCond::Overflow => 0x0,     // VS
        BranchCond::NotOverflow => 0x1,  // VC
        BranchCond::Below => 0x3,        // UL (unsigned <)
        BranchCond::AboveOrEqual => 0x2, // HS (unsigned >=)
        BranchCond::Equal => 0x0 | 0x0,  // EQ
        BranchCond::NotEqual => 0x1,     // NE
        BranchCond::BelowOrEqual => 0x9, // LS
        BranchCond::Above => 0x8,        // HI
        BranchCond::Sign => 0x4,         // MI (negative)
        BranchCond::NotSign => 0x5,      // PL (non-negative)
        BranchCond::Parity => 0x6,       // PS
        BranchCond::NotParity => 0x7,    // PO
        BranchCond::Less => 0xB,         // LT
        BranchCond::GreaterOrEqual => 0xA, // GE
        BranchCond::LessOrEqual => 0xD,  // LE
        BranchCond::Greater => 0xC,      // GT
    }
}

/// Compiled AArch64 code block.
#[derive(Clone, Debug)]
pub struct CodeBlock {
    pub words: alloc::vec::Vec<u32>,
    pub guest_start: u64,
}

impl CodeBlock {
    pub fn new(guest_start: u64) -> Self {
        Self {
            words: alloc::vec::Vec::new(),
            guest_start,
        }
    }

    pub fn as_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::with_capacity(self.words.len() * 4);
        for w in &self.words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        bytes
    }
}

/// AArch64 code emitter.
pub struct A64Emitter {
    /// Encoded instruction words.
    pub code: alloc::vec::Vec<u32>,
    /// Branch fixup sites: (code_offset_in_words, branch_kind).
    fixups: alloc::vec::Vec<BranchFixup>,
}

/// A pending branch that needs its PC-relative offset patched.
struct BranchFixup {
    /// Index into the code array (the branch instruction itself).
    site: usize,
    /// Target kind.
    kind: FixupKind,
}

enum FixupKind {
    /// A B.cond with a given condition code.
    Cond(u32),
    /// Unconditional B.
    B,
    /// BL (call).
    Bl,
}

impl A64Emitter {
    pub fn new() -> Self {
        Self {
            code: alloc::vec::Vec::new(),
            fixups: alloc::vec::Vec::new(),
        }
    }

    /// Push one raw instruction word.
    pub fn push(&mut self, word: u32) {
        self.code.push(word);
    }

    /// Current code offset in words (for branch fixups).
    pub fn offset(&self) -> usize {
        self.code.len()
    }

    /// Patch a branch instruction at site with a PC-relative offset.
    /// The offset is in instruction words from the branch itself.
    pub fn fix_branch(&self, site: usize, kind: &FixupKind, rel_words: i32) -> u32 {
        let _ = site;
        let imm26 = (rel_words & 0x03FF_FFFF) as u32;
        match kind {
            FixupKind::Cond(cond) => {
                // B.cond: 0101_0100 | imm19 | 0 | cond
                // imm19 is the offset in words (rel_words already is).
                let imm19 = (rel_words & 0x7_FFFF) as u32;
                0x5400_0000 | (imm19 << 5) | cond
            }
            FixupKind::B => {
                // B: 000101 | imm26
                0x1400_0000 | imm26
            }
            FixupKind::Bl => {
                // BL: 100101 | imm26
                0x9400_0000 | imm26
            }
        }
    }

    /// Resolve all pending fixups using the current code length.
    pub fn resolve(&mut self) {
        let code_len = self.code.len();
        let fixups: alloc::vec::Vec<(usize, FixupKind)> = self
            .fixups
            .drain(..)
            .map(|f| (f.site, f.kind))
            .collect();
        for (site, kind) in fixups {
            let rel = (code_len - site) as i32;
            let patched = self.fix_branch(site, &kind, rel);
            self.code[site] = patched;
        }
    }

    /// Encode ADD Xd, Xn, #imm12 (64-bit).
    pub fn emit_add_imm(&mut self, rd: u8, rn: u8, imm12: u32) {
        // ADD (immediate): SF=1, op=0, S=0, 100010 | shift=0 | imm12 | Rn | Rd
        let word: u32 = 0x9100_0000 | (imm12 & 0xFFF) << 10
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode SUB Xd, Xn, #imm12 (64-bit).
    pub fn emit_sub_imm(&mut self, rd: u8, rn: u8, imm12: u32) {
        let word: u32 = 0xD100_0000 | (imm12 & 0xFFF) << 10
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode ADD Xd, Xn, Xm (64-bit register).
    pub fn emit_add_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0x8B00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode SUB Xd, Xn, Xm (64-bit register).
    pub fn emit_sub_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0xCB00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode SUBS Xd, Xn, Xm (64-bit, sets flags).
    pub fn emit_subs_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0xEB00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode AND Xd, Xn, Xm (64-bit).
    pub fn emit_and_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0x8A00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode ORR Xd, Xn, Xm (64-bit).
    pub fn emit_orr_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0xAA00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode EOR Xd, Xn, Xm (64-bit).
    pub fn emit_eor_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0xCA00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode ANDS Xd, Xn, Xm (64-bit, sets flags).
    pub fn emit_ands_reg(&mut self, rd: u8, rn: u8, rm: u8) {
        let word: u32 = 0xEA00_0000 | (rm as u32) << 16
            | (rn as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode MOV Xd, Xn (ORR Xd, XZR, Xn).
    pub fn emit_mov_reg(&mut self, rd: u8, rn: u8) {
        self.emit_orr_reg(rd, 31, rn);
    }

    /// Encode LDR Xt, [Xn, #imm12] (64-bit unsigned offset).
    pub fn emit_ldr(&mut self, rt: u8, rn: u8, imm12: u32) {
        let word: u32 = 0xF940_0000 | ((imm12 / 8) & 0xFFF) << 10
            | (rn as u32) << 5
            | rt as u32;
        self.push(word);
    }

    /// Encode STR Xt, [Xn, #imm12] (64-bit unsigned offset).
    pub fn emit_str(&mut self, rt: u8, rn: u8, imm12: u32) {
        let word: u32 = 0xF900_0000 | ((imm12 / 8) & 0xFFF) << 10
            | (rn as u32) << 5
            | rt as u32;
        self.push(word);
    }

    /// Encode MOVZ Xd, #imm16, LSL #shift (64-bit).
    pub fn emit_movz(&mut self, rd: u8, imm16: u16, shift: u32) {
        let hw = (shift / 16) as u32;
        let word: u32 = 0xD280_0000 | hw << 21
            | (imm16 as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode MOVK Xd, #imm16, LSL #shift (64-bit).
    pub fn emit_movk(&mut self, rd: u8, imm16: u16, shift: u32) {
        let hw = (shift / 16) as u32;
        let word: u32 = 0xF280_0000 | hw << 21
            | (imm16 as u32) << 5
            | rd as u32;
        self.push(word);
    }

    /// Encode a 64-bit immediate into Rd using MOVZ + MOVK sequence.
    pub fn emit_mov_imm64(&mut self, rd: u8, imm: u64) {
        let lo16 = (imm & 0xFFFF) as u16;
        let hi16 = ((imm >> 16) & 0xFFFF) as u16;
        let hi32 = ((imm >> 32) & 0xFFFF) as u16;
        let hi48 = ((imm >> 48) & 0xFFFF) as u16;
        self.emit_movz(rd, lo16, 0);
        if hi16 != 0 {
            self.emit_movk(rd, hi16, 16);
        }
        if hi32 != 0 {
            self.emit_movk(rd, hi32, 32);
        }
        if hi48 != 0 {
            self.emit_movk(rd, hi48, 48);
        }
    }

    /// Encode B (unconditional branch) with a pending fixup.
    pub fn emit_b(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup { site, kind: FixupKind::B });
        self.push(0); // placeholder, patched in resolve()
    }

    /// Encode BL (branch with link) with a pending fixup.
    pub fn emit_bl(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup { site, kind: FixupKind::Bl });
        self.push(0);
    }

    /// Encode B.cond with a pending fixup.
    pub fn emit_bcond(&mut self, cond: u32) {
        let site = self.code.len();
        self.fixups.push(BranchFixup { site, kind: FixupKind::Cond(cond) });
        self.push(0);
    }

    /// Encode BR Xn (branch register).
    pub fn emit_br(&mut self, rn: u8) {
        let word: u32 = 0xD61F_0000 | (rn as u32) << 5;
        self.push(word);
    }

    /// Encode BLR Xn (branch with link register).
    pub fn emit_blr(&mut self, rn: u8) {
        let word: u32 = 0xD63F_0000 | (rn as u32) << 5;
        self.push(word);
    }

    /// Encode RET Xn (default X30).
    pub fn emit_ret(&mut self, rn: u8) {
        let word: u32 = 0xD65F_0000 | (rn as u32) << 5;
        self.push(word);
    }

    /// Encode STR Xt, [SP, #-imm9]! (pre-indexed decrement).
    pub fn emit_str_pre_sp(&mut self, rt: u8, imm9: i32) {
        // STR (register, pre-index): 1 x 11 1000 000 | 0 | Rn | 1 1 1 1 1 1 1 1 1 | 0 0 | imm9 | Rn | Rt
        // Correct encoding: 0xF81F_0C00 pattern
        // str x2, [sp, #-8]! = 0xF81F8FE2
        // Format: size[31:30]=11, V=0, o[29:27]=000, L=0, 0/1 [26:24]=0000,
        // S [23]=1, 1 [22]=1, 1 [21]=1, Rn [20:16], Rm/imm [15:0]
        // For pre-index: 0b111_11000_010_1_1_111_Rn(31)_imm9_11_Rt
        let imm = (imm9 & 0x1FF) as u32;
        let word: u32 = 0xF81F_0000
            | (imm & 0x1FF) << 12
            | 31 << 5
            | rt as u32;
        self.push(word);
    }

    /// Encode LDR Xt, [SP], #imm9 (post-indexed increment).
    pub fn emit_ldr_post_sp(&mut self, rt: u8, imm9: i32) {
        // LDR (register, post-index): post-index has bit11=1, bit10=0
        // ldr x3, [sp], #8 = 0xF84087E3
        let imm = (imm9 & 0x1FF) as u32;
        let word: u32 = 0xF840_0000
            | (imm & 0x1FF) << 12
            | 31 << 5
            | rt as u32;
        self.push(word);
    }

    /// Encode a load from a memory operand into Rt.
    pub fn emit_load_mem(&mut self, rt: u8, mem: &MemOperand) {
        match mem.base {
            Some(base_reg) => {
                let rn = map_reg(base_reg);
                let disp = mem.disp;
                if disp >= 0 && (disp as u32) < 0x8000 {
                    // Unsigned offset LDR
                    self.emit_ldr(rt, rn, disp as u32);
                } else {
                    // Load address into a scratch (x16), then LDR.
                    self.emit_add_imm(16, rn, (disp & 0xFFF) as u32);
                    self.emit_ldr(rt, 16, 0);
                }
            }
            None => {
                // Absolute address: build it in x16, then LDR.
                let addr = mem.disp as u64 as u64;
                self.emit_mov_imm64(16, addr);
                self.emit_ldr(rt, 16, 0);
            }
        }
    }

    /// Encode a store from Rt to a memory operand.
    pub fn emit_store_mem(&mut self, rt: u8, mem: &MemOperand) {
        match mem.base {
            Some(base_reg) => {
                let rn = map_reg(base_reg);
                let disp = mem.disp;
                if disp >= 0 && (disp as u32) < 0x8000 {
                    self.emit_str(rt, rn, disp as u32);
                } else {
                    self.emit_add_imm(16, rn, (disp & 0xFFF) as u32);
                    self.emit_str(rt, 16, 0);
                }
            }
            None => {
                let addr = mem.disp as u64 as u64;
                self.emit_mov_imm64(16, addr);
                self.emit_str(rt, 16, 0);
            }
        }
    }

    /// Encode a LEA: compute the effective address into Rd.
    pub fn emit_lea(&mut self, rd: u8, mem: &MemOperand) {
        match (mem.base, mem.index) {
            (Some(base), Some(index)) => {
                let rb = map_reg(base);
                let ri = map_reg(index);
                // LSL X17, Xi, #log2(scale)
                let shift_amt = match mem.scale {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => 3,
                };
                if shift_amt > 0 {
                    self.emit_mov_reg(17, ri);
                    // LSL X17, X17, #shift_amt
                    // LSL is an alias of UBFM Xd, Xn, #(64-shift), #(63-shift)
                    let immr = ((64 - shift_amt) & 0x3F) as u32;
                    let imms = ((63 - shift_amt) & 0x3F) as u32;
                    let lsl_word: u32 = 0xD340_0000
                        | immr << 16
                        | imms << 10
                        | (17 as u32) << 5
                        | 17;
                    self.push(lsl_word);
                } else {
                    self.emit_mov_reg(17, ri);
                }
                // ADD Rd, Rb, X17
                self.emit_add_reg(rd, rb, 17);
            }
            (Some(base), None) => {
                let rb = map_reg(base);
                let disp = mem.disp;
                if disp == 0 {
                    self.emit_mov_reg(rd, rb);
                } else if disp > 0 && disp < 4096 {
                    self.emit_add_imm(rd, rb, disp as u32);
                } else if disp < 0 && disp > -4096 {
                    self.emit_sub_imm(rd, rb, ((-disp) as u32) & 0xFFF);
                } else {
                    self.emit_mov_reg(16, rb);
                    self.emit_add_imm(16, 16, (disp & 0xFFF) as u32);
                    self.emit_mov_reg(rd, 16);
                }
            }
            (None, Some(index)) => {
                let ri = map_reg(index);
                let shift_amt = match mem.scale {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => 3,
                };
                self.emit_mov_reg(17, ri);
                if shift_amt > 0 {
                    let immr = ((64 - shift_amt) & 0x3F) as u32;
                    let imms = ((63 - shift_amt) & 0x3F) as u32;
                    let lsl_word: u32 = 0xD340_0000
                        | immr << 16
                        | imms << 10
                        | (17 as u32) << 5
                        | 17;
                    self.push(lsl_word);
                }
                // MOV Rd, X17 (then add disp if needed)
                self.emit_mov_reg(rd, 17);
                if mem.disp != 0 {
                    self.emit_add_imm(rd, rd, (mem.disp & 0xFFF) as u32);
                }
            }
            (None, None) => {
                self.emit_mov_imm64(rd, mem.disp as u64 as u64);
            }
        }
    }
}

/// Map an x86_64 register to its AArch64 register number.
pub fn map_reg(r: X86Reg) -> u8 {
    match r {
        X86Reg::Rax => 0,
        X86Reg::Rcx => 1,
        X86Reg::Rdx => 2,
        X86Reg::Rbx => 3,
        X86Reg::Rsp => 28, // use x28 (scratch) for guest SP
        X86Reg::Rbp => 4,
        X86Reg::Rsi => 5,
        X86Reg::Rdi => 6,
        X86Reg::R8 => 7,
        X86Reg::R9 => 8,
        X86Reg::R10 => 9,
        X86Reg::R11 => 10,
        X86Reg::R12 => 11,
        X86Reg::R13 => 12,
        X86Reg::R14 => 13,
        X86Reg::R15 => 14,
        X86Reg::Rip => 29, // x29 for guest RIP
    }
}

/// Lower an IR block to AArch64 machine code.
pub fn encode_block(ir: &[IrInst], guest_start: u64) -> CodeBlock {
    let mut em = A64Emitter::new();
    for inst in ir {
        match &inst.op {
            IROp::Nop => {
                em.push(A64_NOP);
            }
            IROp::MovImm { dst, imm } => {
                let rd = map_reg(*dst);
                em.emit_mov_imm64(rd, *imm as u64);
            }
            IROp::MovReg { dst, src } => {
                let rd = map_reg(*dst);
                let rs = map_reg(*src);
                em.emit_mov_reg(rd, rs);
            }
            IROp::Load { dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_load_mem(rd, mem);
            }
            IROp::Store { mem, src } => {
                let rs = map_reg(*src);
                em.emit_store_mem(rs, mem);
            }
            IROp::AluReg { op, dst, src } => {
                let rd = map_reg(*dst);
                let rs = map_reg(*src);
                match op {
                    AluOp::Add => em.emit_add_reg(rd, rd, rs),
                    AluOp::Sub => em.emit_sub_reg(rd, rd, rs),
                    AluOp::And => em.emit_and_reg(rd, rd, rs),
                    AluOp::Or => em.emit_orr_reg(rd, rd, rs),
                    AluOp::Xor => em.emit_eor_reg(rd, rd, rs),
                    AluOp::Cmp => em.emit_subs_reg(31, rd, rs),
                    AluOp::Test => em.emit_ands_reg(31, rd, rs),
                }
            }
            IROp::AluImm { op, dst, imm } => {
                let rd = map_reg(*dst);
                let imm_val = *imm as i64;
                if imm_val >= 0 && imm_val < 4096 {
                    let imm12 = imm_val as u32;
                    match op {
                        AluOp::Add => em.emit_add_imm(rd, rd, imm12),
                        AluOp::Sub => em.emit_sub_imm(rd, rd, imm12),
                        AluOp::Cmp => em.emit_sub_imm(31, rd, imm12),
                        _ => {
                            em.emit_mov_imm64(16, imm_val as u64);
                            match op {
                                AluOp::And => em.emit_and_reg(rd, rd, 16),
                                AluOp::Or => em.emit_orr_reg(rd, rd, 16),
                                AluOp::Xor => em.emit_eor_reg(rd, rd, 16),
                                AluOp::Test => em.emit_ands_reg(31, rd, 16),
                                _ => em.push(A64_NOP),
                            }
                        }
                    }
                } else {
                    em.emit_mov_imm64(16, imm_val as u64);
                    match op {
                        AluOp::Add => em.emit_add_reg(rd, rd, 16),
                        AluOp::Sub => em.emit_sub_reg(rd, rd, 16),
                        AluOp::And => em.emit_and_reg(rd, rd, 16),
                        AluOp::Or => em.emit_orr_reg(rd, rd, 16),
                        AluOp::Xor => em.emit_eor_reg(rd, rd, 16),
                        AluOp::Cmp => em.emit_subs_reg(31, rd, 16),
                        AluOp::Test => em.emit_ands_reg(31, rd, 16),
                    }
                }
            }
            IROp::AluMem { op, dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_load_mem(15, mem); // load into x15
                match op {
                    AluOp::Add => em.emit_add_reg(rd, rd, 15),
                    AluOp::Sub => em.emit_sub_reg(rd, rd, 15),
                    AluOp::And => em.emit_and_reg(rd, rd, 15),
                    AluOp::Or => em.emit_orr_reg(rd, rd, 15),
                    AluOp::Xor => em.emit_eor_reg(rd, rd, 15),
                    AluOp::Cmp => em.emit_subs_reg(31, rd, 15),
                    AluOp::Test => em.emit_ands_reg(31, rd, 15),
                }
            }
            IROp::Lea { dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_lea(rd, mem);
            }
            IROp::Push { src } => {
                let rs = map_reg(*src);
                em.emit_str_pre_sp(rs, -8);
            }
            IROp::Pop { dst } => {
                let rd = map_reg(*dst);
                em.emit_ldr_post_sp(rd, 8);
            }
            IROp::Jmp { .. } => {
                em.emit_b();
            }
            IROp::Jcc { cond, .. } => {
                em.emit_bcond(a64_cond(*cond));
            }
            IROp::Call { .. } => {
                em.emit_bl();
            }
            IROp::Ret => {
                em.emit_ret(30);
            }
            IROp::Syscall => {
                // Emit HVC #0 to trap into the host kernel.
                let word: u32 = 0xD400_0000 | 0x0020_0000;
                em.push(word);
            }
            IROp::Unsupported => {
                // Emit BRK #0 to signal an unsupported instruction.
                let word: u32 = 0xD420_0000;
                em.push(word);
            }
            IROp::SimdMov { .. } | IROp::SimdStore { .. } | IROp::SimdArith { .. } => {
                // SIMD operations are not yet supported by the A64
                // emitter. Emit BRK #0 so that a trap handler can
                // fall back to interpretation rather than executing
                // garbage.
                let word: u32 = 0xD420_0000;
                em.push(word);
            }
        }
    }
    em.resolve();
    CodeBlock {
        words: em.code,
        guest_start,
    }
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let ir = [
        IrInst {
            op: IROp::Nop,
            guest_va: 0x1000,
            guest_len: 1,
        },
        IrInst {
            op: IROp::MovImm {
                dst: X86Reg::Rax,
                imm: 42,
            },
            guest_va: 0x1001,
            guest_len: 5,
        },
        IrInst {
            op: IROp::Ret,
            guest_va: 0x1006,
            guest_len: 1,
        },
    ];
    let block = encode_block(&ir, 0x1000);
    // NOP = 0xD503201F
    assert_eq!(block.words[0], 0xD503_201F);
    // MOVZ x0, #42 = 0xD2800000 | (42 << 5) | 0 = 0xD2800540
    assert_eq!(block.words[1], 0xD280_0540);
    // RET x30 = 0xD65F03C0
    assert_eq!(block.words[2], 0xD65F_03C0);
    true
}

