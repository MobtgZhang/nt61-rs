//! BTL — LA64 code generator for the shared BTL IR.
//!
//! Emits real LoongArch64 instruction encodings (fixed 4-byte width,
//! little-endian). Covers the shared IR operations: MOV, LOAD/STORE,
//! ALU, LEA, PUSH/POP, JMP/Jcc, CALL, RET, SYSCALL.
//!
//! ## Register mapping
//!
//! x86_64 GPRs map to LA64 integer registers:
//!   RAX->r4($a0), RCX->r5($a1), RDX->r6($a2), RBX->r7($a3),
//!   RSP->r3($sp), RBP->r23($s0), RSI->r24($s1), RDI->r25($s2),
//!   R8..R15 -> r26..r31 ($s3..$s8), RIP->r12($t0).

#![cfg(target_arch = "loongarch64")]

use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};

// LA64 instruction opcodes (top 6 bits + func fields).
const OPCODE_ADD_D: u32 = 0x0011_0000;
const OPCODE_SUB_D: u32 = 0x0011_1000;
const OPCODE_AND: u32 = 0x0011_0C00;
const OPCODE_OR: u32 = 0x0011_0800;
const OPCODE_XOR: u32 = 0x0011_0400;
const OPCODE_ADDI_D: u32 = 0x02C0_0000;
const OPCODE_ADDI_W: u32 = 0x0280_0000;
const OPCODE_ANDI: u32 = 0x0340_0000;
const OPCODE_ORI: u32 = 0x0380_0000;
const OPCODE_XORI: u32 = 0x03C0_0000;
const OPCODE_LU12I_W: u32 = 0x0140_0000;
const OPCODE_LD_D: u32 = 0x2840_0000;
const OPCODE_ST_D: u32 = 0x29C0_0000;
const OPCODE_LD_W: u32 = 0x2880_0000;
const OPCODE_ST_W: u32 = 0x28C0_0000;
const OPCODE_BEQ: u32 = 0x6400_0000;
const OPCODE_BNE: u32 = 0x6800_0000;
const OPCODE_BLT: u32 = 0x6C00_0000;
const OPCODE_BGE: u32 = 0x7400_0000;
const OPCODE_B: u32 = 0x5000_0000;
const OPCODE_BL: u32 = 0x5400_0000;
const OPCODE_JIRL: u32 = 0x4C00_0000;
const OPCODE_SLT: u32 = 0x0011_2000;

/// LA64 NOP encoding: ANDI r0, r0, 0.
pub const LA64_NOP: u32 = 0x0340_0000;

/// Map an x86_64 register to its LA64 register number.
pub fn map_reg(r: X86Reg) -> u32 {
    match r {
        X86Reg::Rax => 4,  // $a0
        X86Reg::Rcx => 5,  // $a1
        X86Reg::Rdx => 6,  // $a2
        X86Reg::Rbx => 7,  // $a3
        X86Reg::Rsp => 3,  // $sp
        X86Reg::Rbp => 23, // $s0
        X86Reg::Rsi => 24, // $s1
        X86Reg::Rdi => 25, // $s2
        X86Reg::R8 => 26,  // $s3
        X86Reg::R9 => 27,  // $s4
        X86Reg::R10 => 28, // $s5
        X86Reg::R11 => 29, // $s6
        X86Reg::R12 => 30, // $s7
        X86Reg::R13 => 31, // $s8
        X86Reg::R14 => 12, // $t0
        X86Reg::R15 => 13, // $t1
        X86Reg::Rip => 14, // $t2
    }
}

/// LA64 register for $zero (r0).
const LA_ZERO: u32 = 0;
/// LA64 register for $ra (r1).
const LA_RA: u32 = 1;
/// LA64 scratch register ($t3, r15).
const LA_SCRATCH: u32 = 15;
/// LA64 scratch register ($t4, r16).
const LA_SCRATCH2: u32 = 16;

/// Pending branch fixup.
struct BranchFixup {
    site: usize,
    kind: FixupKind,
}

enum FixupKind {
    B,
    Bl,
    Jcc(BranchCond),
}

/// LA64 code emitter.
pub struct La64Emitter {
    pub code: alloc::vec::Vec<u32>,
    fixups: alloc::vec::Vec<BranchFixup>,
}

impl La64Emitter {
    pub fn new() -> Self {
        Self {
            code: alloc::vec::Vec::new(),
            fixups: alloc::vec::Vec::new(),
        }
    }

    pub fn push(&mut self, word: u32) {
        self.code.push(word);
    }

    pub fn offset(&self) -> usize {
        self.code.len()
    }

    /// Encode 3-register ALU: rd = fn(rd, rj, rk).
    /// LA64 R-type: opcode[6:0] | rk[4:0] << 10 | rj[4:0] << 5 | rd[4:0]
    fn emit_r(&mut self, opcode: u32, rj: u32, rk: u32, rd: u32) {
        let word = opcode | (rk << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ADD.D rd, rj, rk.
    pub fn emit_add_d(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_ADD_D, rj, rk, rd);
    }

    /// Encode SUB.D rd, rj, rk.
    pub fn emit_sub_d(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_SUB_D, rj, rk, rd);
    }

    /// Encode AND rd, rj, rk.
    pub fn emit_and(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_AND, rj, rk, rd);
    }

    /// Encode OR rd, rj, rk.
    pub fn emit_or(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_OR, rj, rk, rd);
    }

    /// Encode XOR rd, rj, rk.
    pub fn emit_xor(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_XOR, rj, rk, rd);
    }

    /// Encode ADDI.D rd, rj, imm12 (sign-extended).
    pub fn emit_addi_d(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_ADDI_D | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ADDI.W rd, rj, imm12.
    pub fn emit_addi_w(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_ADDI_W | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ANDI rd, rj, imm12 (zero-extended).
    pub fn emit_andi(&mut self, rd: u32, rj: u32, imm12: u32) {
        let word = OPCODE_ANDI | ((imm12 & 0xFFF) << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ORI rd, rj, imm12.
    pub fn emit_ori(&mut self, rd: u32, rj: u32, imm12: u32) {
        let word = OPCODE_ORI | ((imm12 & 0xFFF) << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode XORI rd, rj, imm12.
    pub fn emit_xori(&mut self, rd: u32, rj: u32, imm12: u32) {
        let word = OPCODE_XORI | ((imm12 & 0xFFF) << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode LU12I.W rd, imm20 (loads a 20-bit immediate into the
    /// lower 32 bits, zero-extends to 64).
    pub fn emit_lu12i_w(&mut self, rd: u32, imm20: u32) {
        let word = OPCODE_LU12I_W | ((imm20 & 0xFFFFF) << 5) | rd;
        self.push(word);
    }

    /// Encode LD.D rd, rj, imm12 (signed offset, 64-bit load).
    pub fn emit_ld_d(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_LD_D | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ST.D rd, rj, imm12 (signed offset, 64-bit store).
    pub fn emit_st_d(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_ST_D | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode LD.W rd, rj, imm12 (signed offset, 32-bit load).
    pub fn emit_ld_w(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_LD_W | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode ST.W rd, rj, imm12 (signed offset, 32-bit store).
    pub fn emit_st_w(&mut self, rd: u32, rj: u32, imm12: i32) {
        let imm = (imm12 & 0xFFF) as u32;
        let word = OPCODE_ST_W | (imm << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode a 64-bit immediate into rd using LU12I.W + ORI sequence.
    pub fn emit_li(&mut self, rd: u32, imm: i64) {
        if imm >= -2048 && imm <= 2047 {
            self.emit_addi_d(rd, LA_ZERO, imm as i32);
        } else if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
            let lo12 = (imm & 0xFFF) as u32;
            let hi20 = ((imm >> 12) & 0xFFFFF) as u32;
            self.emit_lu12i_w(rd, hi20);
            if lo12 != 0 {
                self.emit_ori(rd, rd, lo12);
            }
        } else {
            let lo20 = (imm & 0xFFFFF) as u32;
            let hi20 = ((imm >> 20) & 0xFFFFF) as u32;
            let hi40 = ((imm >> 40) & 0xFFFFF) as u32;
            // Build the low 32 bits first.
            self.emit_lu12i_w(rd, lo20);
            // Build the high 32 bits in the scratch.
            self.emit_lu12i_w(LA_SCRATCH, hi20);
            self.emit_ori(LA_SCRATCH, LA_SCRATCH, hi40);
            // Shift scratch left by 32 and OR into rd.
            // For simplicity, we use a 2-step approach.
            self.emit_lu12i_w(LA_SCRATCH2, hi40 >> 8);
            self.emit_ori(LA_SCRATCH2, LA_SCRATCH2, hi40 & 0xFF);
            // OR the pieces.
            self.emit_or(rd, rd, LA_SCRATCH);
        }
    }

    /// Encode BEQ rj, rd, offset16.
    pub fn emit_beq(&mut self, rj: u32, rd: u32, offset: i32) {
        let off = (offset & 0xFFFF) as u32;
        let word = OPCODE_BEQ | (off << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode BNE rj, rd, offset16.
    pub fn emit_bne(&mut self, rj: u32, rd: u32, offset: i32) {
        let off = (offset & 0xFFFF) as u32;
        let word = OPCODE_BNE | (off << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode BLT rj, rd, offset16 (signed less than).
    pub fn emit_blt(&mut self, rj: u32, rd: u32, offset: i32) {
        let off = (offset & 0xFFFF) as u32;
        let word = OPCODE_BLT | (off << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode BGE rj, rd, offset16 (signed >=).
    pub fn emit_bge(&mut self, rj: u32, rd: u32, offset: i32) {
        let off = (offset & 0xFFFF) as u32;
        let word = OPCODE_BGE | (off << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Encode B (unconditional branch, offset in halfwords).
    pub fn emit_b(&mut self, offset: i32) {
        let off = (offset & 0xFFFFF) as u32;
        let word = OPCODE_B | (off << 10);
        self.push(word);
    }

    /// Encode BL (branch with link, offset in halfwords).
    pub fn emit_bl(&mut self, offset: i32) {
        let off = (offset & 0xFFFFF) as u32;
        let word = OPCODE_BL | (off << 10);
        self.push(word);
    }

    /// Encode JIRL rd, rj, offset16 (indirect jump and link).
    pub fn emit_jirl(&mut self, rd: u32, rj: u32, offset: i32) {
        let off = (offset & 0xFFFF) as u32;
        let word = OPCODE_JIRL | (off << 10) | (rj << 5) | rd;
        self.push(word);
    }

    /// Emit a pending unconditional branch fixup.
    pub fn emit_jmp(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::B,
        });
        self.push(0);
    }

    /// Emit a pending conditional branch fixup.
    pub fn emit_jcc(&mut self, cond: BranchCond) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::Jcc(cond),
        });
        self.push(0);
    }

    /// Emit a pending call fixup.
    pub fn emit_call(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::Bl,
        });
        self.push(0);
    }

    /// Resolve all pending branch fixups.
    pub fn resolve(&mut self) {
        let code_len = self.code.len();
        let fixups: alloc::vec::Vec<(usize, FixupKind)> =
            self.fixups.drain(..).map(|f| (f.site, f.kind)).collect();
        for (site, kind) in fixups {
            let rel = (code_len - site) as i32;
            match kind {
                FixupKind::B => {
                    let off = (rel & 0xFFFFF) as u32;
                    self.code[site] = OPCODE_B | (off << 10);
                }
                FixupKind::Bl => {
                    let off = (rel & 0xFFFFF) as u32;
                    self.code[site] = OPCODE_BL | (off << 10);
                }
                FixupKind::Jcc(cond) => {
                    let (opcode, rj, rd) = self.jcc_encoding(cond);
                    let off = (rel & 0xFFFF) as u32;
                    self.code[site] = opcode | (off << 10) | (rj << 5) | rd;
                }
            }
        }
    }

    fn jcc_encoding(&self, cond: BranchCond) -> (u32, u32, u32) {
        // For Jcc, compare against $zero (r0).
        match cond {
            BranchCond::Equal => (OPCODE_BEQ, LA_ZERO, LA_ZERO),
            BranchCond::NotEqual => (OPCODE_BNE, LA_ZERO, LA_ZERO),
            BranchCond::Below => (OPCODE_BLT, LA_ZERO, LA_ZERO),
            BranchCond::AboveOrEqual => (OPCODE_BGE, LA_ZERO, LA_ZERO),
            BranchCond::BelowOrEqual => (OPCODE_BNE, LA_ZERO, LA_ZERO),
            BranchCond::Above => (OPCODE_BLT, LA_ZERO, LA_ZERO),
            BranchCond::Less => (OPCODE_BLT, LA_ZERO, LA_ZERO),
            BranchCond::GreaterOrEqual => (OPCODE_BGE, LA_ZERO, LA_ZERO),
            BranchCond::LessOrEqual => (OPCODE_BNE, LA_ZERO, LA_ZERO),
            BranchCond::Greater => (OPCODE_BLT, LA_ZERO, LA_ZERO),
            BranchCond::Always => (OPCODE_B, 0, 0),
            _ => (OPCODE_BEQ, LA_ZERO, LA_ZERO),
        }
    }

    /// Load a memory operand into rd.
    pub fn emit_load_mem(&mut self, rd: u32, mem: &MemOperand) {
        let (base, disp) = match mem.base {
            Some(b) => (map_reg(b), mem.disp),
            None => (LA_ZERO, mem.disp),
        };
        if disp >= -2048 && disp <= 2047 {
            self.emit_ld_d(rd, base, disp);
        } else {
            self.emit_li(LA_SCRATCH, disp as i64);
            self.emit_add_d(LA_SCRATCH, base, LA_SCRATCH);
            self.emit_ld_d(rd, LA_SCRATCH, 0);
        }
    }

    /// Store rd to a memory operand.
    pub fn emit_store_mem(&mut self, rd: u32, mem: &MemOperand) {
        let (base, disp) = match mem.base {
            Some(b) => (map_reg(b), mem.disp),
            None => (LA_ZERO, mem.disp),
        };
        if disp >= -2048 && disp <= 2047 {
            self.emit_st_d(rd, base, disp);
        } else {
            self.emit_li(LA_SCRATCH, disp as i64);
            self.emit_add_d(LA_SCRATCH, base, LA_SCRATCH);
            self.emit_st_d(rd, LA_SCRATCH, 0);
        }
    }

    /// Encode LEA: compute effective address into rd.
    pub fn emit_lea(&mut self, rd: u32, mem: &MemOperand) {
        match (mem.base, mem.index) {
            (Some(base), Some(index)) => {
                let rb = map_reg(base);
                let ri = map_reg(index);
                let shift_amt = match mem.scale {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => 3,
                };
                // Scale the index: slli.w scratch, ri, shift_amt
                // Actually: LA64 uses SLL.D rd, rj, rk (register shift).
                // For a constant shift, we can use ANDI to clear, but
                // simpler: just do ADD and skip the scale for now.
                self.emit_mov_d(LA_SCRATCH, ri);
                // SLL.D scratch, scratch, shift_reg
                // For constant shift, load the shift amount into a reg.
                if shift_amt > 0 {
                    self.emit_addi_d(LA_SCRATCH2, LA_ZERO, shift_amt as i32);
                    self.emit_sll_d(LA_SCRATCH, LA_SCRATCH, LA_SCRATCH2);
                }
                self.emit_add_d(rd, rb, LA_SCRATCH);
                if mem.disp != 0 {
                    self.emit_addi_d(rd, rd, mem.disp);
                }
            }
            (Some(base), None) => {
                let rb = map_reg(base);
                let disp = mem.disp;
                if disp >= -2048 && disp <= 2047 {
                    self.emit_addi_d(rd, rb, disp);
                } else {
                    self.emit_li(LA_SCRATCH, disp as i64);
                    self.emit_add_d(rd, rb, LA_SCRATCH);
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
                self.emit_mov_d(rd, ri);
                if shift_amt > 0 {
                    self.emit_addi_d(LA_SCRATCH2, LA_ZERO, shift_amt as i32);
                    self.emit_sll_d(rd, rd, LA_SCRATCH2);
                }
                if mem.disp != 0 {
                    self.emit_addi_d(rd, rd, mem.disp);
                }
            }
            (None, None) => {
                self.emit_li(rd, mem.disp as i64);
            }
        }
    }

    /// MOV rd, rj (ADDI.D rd, rj, 0).
    pub fn emit_mov_d(&mut self, rd: u32, rj: u32) {
        self.emit_addi_d(rd, rj, 0);
    }

    /// SLL.D rd, rj, rk (shift left logical).
    pub fn emit_sll_d(&mut self, rd: u32, rj: u32, rk: u32) {
        self.emit_r(OPCODE_SLT | 0x400, rj, rk, rd);
    }
}

/// Translate an IR block into LA64 machine code.
pub fn encode_block(ir: &[IrInst], guest_start: u64) -> alloc::vec::Vec<u8> {
    let mut em = La64Emitter::new();
    for inst in ir {
        match &inst.op {
            IROp::Nop => em.push(LA64_NOP),
            IROp::MovImm { dst, imm } => {
                let rd = map_reg(*dst);
                em.emit_li(rd, *imm);
            }
            IROp::MovReg { dst, src } => {
                let rd = map_reg(*dst);
                let rs = map_reg(*src);
                em.emit_mov_d(rd, rs);
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
                    AluOp::Add => em.emit_add_d(rd, rd, rs),
                    AluOp::Sub => em.emit_sub_d(rd, rd, rs),
                    AluOp::And => em.emit_and(rd, rd, rs),
                    AluOp::Or => em.emit_or(rd, rd, rs),
                    AluOp::Xor => em.emit_xor(rd, rd, rs),
                    AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, rs),
                    AluOp::Test => em.emit_and(LA_SCRATCH, rd, rs),
                }
            }
            IROp::AluImm { op, dst, imm } => {
                let rd = map_reg(*dst);
                if *imm >= -2048 && *imm <= 2047 {
                    let imm12 = *imm as i32;
                    match op {
                        AluOp::Add => em.emit_addi_d(rd, rd, imm12),
                        AluOp::Sub => em.emit_addi_d(rd, rd, -imm12),
                        AluOp::Cmp => em.emit_addi_d(LA_SCRATCH, rd, -imm12),
                        _ => {
                            em.emit_li(LA_SCRATCH, *imm);
                            match op {
                                AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                                AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                                AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                                AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
                                _ => em.push(LA64_NOP),
                            }
                        }
                    }
                } else {
                    em.emit_li(LA_SCRATCH, *imm);
                    match op {
                        AluOp::Add => em.emit_add_d(rd, rd, LA_SCRATCH),
                        AluOp::Sub => em.emit_sub_d(rd, rd, LA_SCRATCH),
                        AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                        AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                        AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                        AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, LA_SCRATCH),
                        AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
                    }
                }
            }
            IROp::AluMem { op, dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_load_mem(LA_SCRATCH, mem);
                match op {
                    AluOp::Add => em.emit_add_d(rd, rd, LA_SCRATCH),
                    AluOp::Sub => em.emit_sub_d(rd, rd, LA_SCRATCH),
                    AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                    AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                    AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                    AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, LA_SCRATCH),
                    AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
                }
            }
            IROp::Lea { dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_lea(rd, mem);
            }
            IROp::Push { src } => {
                let rs = map_reg(*src);
                // addi.d sp, sp, -8
                em.emit_addi_d(3, 3, -8);
                // st.d rs, sp, 0
                em.emit_st_d(rs, 3, 0);
            }
            IROp::Pop { dst } => {
                let rd = map_reg(*dst);
                // ld.d rd, sp, 0
                em.emit_ld_d(rd, 3, 0);
                // addi.d sp, sp, 8
                em.emit_addi_d(3, 3, 8);
            }
            IROp::Jmp { .. } => em.emit_jmp(),
            IROp::Jcc { cond, .. } => em.emit_jcc(*cond),
            IROp::Call { .. } => em.emit_call(),
            IROp::Ret => {
                // ret = jirl $zero, $ra, 0
                em.emit_jirl(LA_ZERO, LA_RA, 0);
            }
            IROp::Syscall => {
                // syscall (breakpoint trap in LA64)
                em.push(0x002B_0000); // syscall encoding
            }
            IROp::Unsupported => {
                // break 0
                em.push(0x002A_0000);
            }
            IROp::SimdMov { .. } | IROp::SimdStore { .. } | IROp::SimdArith { .. } => {
                // LA64 backend has no vector support: break 0
                em.push(0x002A_0000);
            }
        }
    }
    em.resolve();

    let mut bytes = alloc::vec::Vec::with_capacity(em.code.len() * 4);
    for w in &em.code {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let _ = guest_start;
    bytes
}

/// Translate a single decoded x86_64 instruction to LA64.
///
/// Extracts the shared IR from `Decoded`, lowers it through the
/// `La64Emitter`, and appends the resulting instruction words to
/// `buf`. Returns an error if the instruction has no IR (i.e. the
/// shared decoder could not decode it) so that the dispatch chain in
/// `translate/mod.rs` can try another submodule.
pub fn translate(
    buf: &mut crate::arch::loongarch64::btl::emit::EmitBuffer,
    dec: &crate::arch::loongarch64::btl::decoder::Decoded,
) -> Result<(), super::TranslateError> {
    let ir = match &dec.ir {
        Some(inst) => inst,
        None => return Err(super::TranslateError::DecoderError),
    };
    let mut em = La64Emitter::new();
    let _ = ir.guest_va;
    match &ir.op {
        IROp::Nop => em.push(LA64_NOP),
        IROp::MovImm { dst, imm } => em.emit_li(map_reg(*dst), *imm),
        IROp::MovReg { dst, src } => {
            em.emit_mov_d(map_reg(*dst), map_reg(*src));
        }
        IROp::Load { dst, mem } => em.emit_load_mem(map_reg(*dst), mem),
        IROp::Store { mem, src } => em.emit_store_mem(map_reg(*src), mem),
        IROp::AluReg { op, dst, src } => {
            let rd = map_reg(*dst);
            let rs = map_reg(*src);
            match op {
                AluOp::Add => em.emit_add_d(rd, rd, rs),
                AluOp::Sub => em.emit_sub_d(rd, rd, rs),
                AluOp::And => em.emit_and(rd, rd, rs),
                AluOp::Or => em.emit_or(rd, rd, rs),
                AluOp::Xor => em.emit_xor(rd, rd, rs),
                AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, rs),
                AluOp::Test => em.emit_and(LA_SCRATCH, rd, rs),
            }
        }
        IROp::AluImm { op, dst, imm } => {
            let rd = map_reg(*dst);
            if (-2048..=2047).contains(imm) {
                let imm12 = *imm as i32;
                match op {
                    AluOp::Add => em.emit_addi_d(rd, rd, imm12),
                    AluOp::Sub => em.emit_addi_d(rd, rd, -imm12),
                    AluOp::Cmp => em.emit_addi_d(LA_SCRATCH, rd, -imm12),
                    _ => {
                        em.emit_li(LA_SCRATCH, *imm);
                        match op {
                            AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                            AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                            AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                            AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
                            _ => em.push(LA64_NOP),
                        }
                    }
                }
            } else {
                em.emit_li(LA_SCRATCH, *imm);
                match op {
                    AluOp::Add => em.emit_add_d(rd, rd, LA_SCRATCH),
                    AluOp::Sub => em.emit_sub_d(rd, rd, LA_SCRATCH),
                    AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                    AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                    AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                    AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, LA_SCRATCH),
                    AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
                }
            }
        }
        IROp::AluMem { op, dst, mem } => {
            let rd = map_reg(*dst);
            em.emit_load_mem(LA_SCRATCH, mem);
            match op {
                AluOp::Add => em.emit_add_d(rd, rd, LA_SCRATCH),
                AluOp::Sub => em.emit_sub_d(rd, rd, LA_SCRATCH),
                AluOp::And => em.emit_and(rd, rd, LA_SCRATCH),
                AluOp::Or => em.emit_or(rd, rd, LA_SCRATCH),
                AluOp::Xor => em.emit_xor(rd, rd, LA_SCRATCH),
                AluOp::Cmp => em.emit_sub_d(LA_SCRATCH, rd, LA_SCRATCH),
                AluOp::Test => em.emit_and(LA_SCRATCH, rd, LA_SCRATCH),
            }
        }
        IROp::Lea { dst, mem } => em.emit_lea(map_reg(*dst), mem),
        IROp::Push { src } => {
            let rs = map_reg(*src);
            em.emit_addi_d(3, 3, -8);
            em.emit_st_d(rs, 3, 0);
        }
        IROp::Pop { dst } => {
            let rd = map_reg(*dst);
            em.emit_ld_d(rd, 3, 0);
            em.emit_addi_d(3, 3, 8);
        }
        IROp::Jmp { .. } => em.emit_jmp(),
        IROp::Jcc { cond, .. } => em.emit_jcc(*cond),
        IROp::Call { .. } => em.emit_call(),
        IROp::Ret => em.emit_jirl(LA_ZERO, LA_RA, 0),
        IROp::Syscall => em.push(LA64_SYSCALL),
        IROp::Unsupported => em.push(LA64_BREAK),
        IROp::SimdMov { .. } | IROp::SimdStore { .. } | IROp::SimdArith { .. } => {
            em.push(LA64_BREAK)
        }
    }
    em.resolve();
    for word in &em.code {
        buf.push_insn(*word);
    }
    Ok(())
}

/// LA64 syscall instruction encoding.
const LA64_SYSCALL: u32 = 0x002B_0000;
/// LA64 break 0 instruction encoding.
const LA64_BREAK: u32 = 0x002A_0000;

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
    let bytes = encode_block(&ir, 0x1000);
    // NOP = ANDI r0, r0, 0 = 0x03400000
    assert_eq!(&bytes[0..4], &0x0340_0000u32.to_le_bytes());
    // li $a0, 42 = LU12I.W r4, 0 | ORI r4, r4, 42
    // LU12I.W r4, 0 = 0x01400000 | (0 << 5) | 4 = 0x01400004
    assert_eq!(&bytes[4..8], &0x0140_0004u32.to_le_bytes());
    // ret = JIRL r0, r1, 0 = 0x4C000000 | (0 << 10) | (1 << 5) | 0 = 0x4C000020
    assert_eq!(&bytes[8..12], &0x4C00_0020u32.to_le_bytes());
    true
}
