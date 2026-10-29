//! RISC-V RV64GC code generator for the shared BTL IR.
//!
//! Emits real RV64 instruction encodings. All instructions are
//! 4 bytes wide (no compressed instructions for simplicity).
//!
//! ## Register mapping
//!
//! x86_64 GPRs map to RV64 integer registers.

use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};

pub const MAX_CODE_BYTES: usize = 4096;

const OPCODE_OP: u32 = 0x33;
const OPCODE_OP_IMM: u32 = 0x13;
const OPCODE_LOAD: u32 = 0x03;
const OPCODE_STORE: u32 = 0x23;
const OPCODE_LUI: u32 = 0x37;
const OPCODE_JAL: u32 = 0x6F;
const OPCODE_JALR: u32 = 0x67;
const OPCODE_BRANCH: u32 = 0x63;
const OPCODE_ECALL: u32 = 0x73;

const FUNCT3_ADD_SUB: u32 = 0x0;
const FUNCT3_AND: u32 = 0x7;
const FUNCT3_OR: u32 = 0x6;
const FUNCT3_XOR: u32 = 0x4;
const FUNCT3_LD: u32 = 0x3;
const FUNCT3_SD: u32 = 0x3;
const FUNCT3_BEQ: u32 = 0x0;
const FUNCT3_BNE: u32 = 0x1;
const FUNCT3_BLT: u32 = 0x4;
const FUNCT3_BGE: u32 = 0x5;

const FUNCT7_SUB: u32 = 0x20;

pub fn map_reg(r: X86Reg) -> u32 {
    match r {
        X86Reg::Rax => 10,
        X86Reg::Rcx => 11,
        X86Reg::Rdx => 12,
        X86Reg::Rbx => 13,
        X86Reg::Rsp => 2,
        X86Reg::Rbp => 8,
        X86Reg::Rsi => 14,
        X86Reg::Rdi => 15,
        X86Reg::R8 => 16,
        X86Reg::R9 => 17,
        X86Reg::R10 => 18,
        X86Reg::R11 => 19,
        X86Reg::R12 => 20,
        X86Reg::R13 => 21,
        X86Reg::R14 => 22,
        X86Reg::R15 => 23,
        X86Reg::Rip => 5,
    }
}

const RV_ZERO: u32 = 0;

#[derive(Clone, Debug)]
pub struct CodeBlock {
    pub bytes: [u8; MAX_CODE_BYTES],
    pub len: usize,
    pub raw_va: u64,
}

impl CodeBlock {
    pub const fn empty() -> Self {
        Self {
            bytes: [0x13; MAX_CODE_BYTES],
            len: 0,
            raw_va: 0,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len.min(MAX_CODE_BYTES)]
    }
}

pub struct Rv64Emitter {
    pub code: alloc::vec::Vec<u32>,
    fixups: alloc::vec::Vec<BranchFixup>,
}

enum FixupKind {
    Jmp,
    Jcc(BranchCond),
    Call,
}

struct BranchFixup {
    site: usize,
    kind: FixupKind,
}

impl Rv64Emitter {
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
    fn emit_r(&mut self, f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32) {
        let w = (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | OPCODE_OP;
        self.push(w);
    }
    fn emit_i(&mut self, imm: u32, rs1: u32, f3: u32, rd: u32, op: u32) {
        let w = (imm << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
        self.push(w);
    }
    pub fn emit_add(&mut self, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(0x00, rs2, rs1, FUNCT3_ADD_SUB, rd);
    }
    pub fn emit_sub(&mut self, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(FUNCT7_SUB, rs2, rs1, FUNCT3_ADD_SUB, rd);
    }
    pub fn emit_and(&mut self, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(0x00, rs2, rs1, FUNCT3_AND, rd);
    }
    pub fn emit_or(&mut self, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(0x00, rs2, rs1, FUNCT3_OR, rd);
    }
    pub fn emit_xor(&mut self, rd: u32, rs1: u32, rs2: u32) {
        self.emit_r(0x00, rs2, rs1, FUNCT3_XOR, rd);
    }
    pub fn emit_addi(&mut self, rd: u32, rs1: u32, imm: i32) {
        self.emit_i((imm & 0xFFF) as u32, rs1, FUNCT3_ADD_SUB, rd, OPCODE_OP_IMM);
    }
    pub fn emit_andi(&mut self, rd: u32, rs1: u32, imm: i32) {
        self.emit_i((imm & 0xFFF) as u32, rs1, FUNCT3_AND, rd, OPCODE_OP_IMM);
    }
    pub fn emit_ori(&mut self, rd: u32, rs1: u32, imm: i32) {
        self.emit_i((imm & 0xFFF) as u32, rs1, FUNCT3_OR, rd, OPCODE_OP_IMM);
    }
    pub fn emit_xori(&mut self, rd: u32, rs1: u32, imm: i32) {
        self.emit_i((imm & 0xFFF) as u32, rs1, FUNCT3_XOR, rd, OPCODE_OP_IMM);
    }
    pub fn emit_ld(&mut self, rd: u32, rs1: u32, off: i32) {
        self.emit_i((off & 0xFFF) as u32, rs1, FUNCT3_LD, rd, OPCODE_LOAD);
    }
    pub fn emit_sd(&mut self, rs2: u32, rs1: u32, off: i32) {
        let hi = ((off >> 5) & 0x7F) as u32;
        let lo = (off & 0x1F) as u32;
        let w =
            (hi << 25) | (rs2 << 20) | (rs1 << 15) | (FUNCT3_SD << 12) | (lo << 7) | OPCODE_STORE;
        self.push(w);
    }
    pub fn emit_lui(&mut self, rd: u32, imm20: u32) {
        self.push((imm20 << 12) | (rd << 7) | OPCODE_LUI);
    }
    pub fn emit_li(&mut self, rd: u32, imm: i64) {
        if imm >= -2048 && imm <= 2047 {
            self.emit_addi(rd, RV_ZERO, imm as i32);
        } else if imm >= i32::MIN as i64 && imm <= i32::MAX as i64 {
            let lo = (imm & 0xFFF) as i32;
            let hi = ((imm >> 12) & 0xFFFFF) as u32;
            self.emit_lui(rd, hi);
            if lo != 0 {
                self.emit_addi(rd, rd, lo);
            }
        } else {
            self.emit_addi(rd, RV_ZERO, (imm & 0xFFF) as i32);
            self.emit_addi(rd, rd, ((imm >> 12) & 0xFFF) as i32);
            self.emit_addi(rd, rd, (((imm >> 24) & 0xFFF) as i32) << 4);
        }
    }
    pub fn emit_jalr(&mut self, rd: u32, rs1: u32, imm: i32) {
        self.emit_i((imm & 0xFFF) as u32, rs1, FUNCT3_ADD_SUB, rd, OPCODE_JALR);
    }
    pub fn emit_ecall(&mut self) {
        self.push(OPCODE_ECALL);
    }
    pub fn emit_jmp(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::Jmp,
        });
        self.push(0);
    }
    pub fn emit_jcc(&mut self, cond: BranchCond) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::Jcc(cond),
        });
        self.push(0);
    }
    pub fn emit_call(&mut self) {
        let site = self.code.len();
        self.fixups.push(BranchFixup {
            site,
            kind: FixupKind::Call,
        });
        self.push(0);
    }
    pub fn resolve(&mut self) {
        let cl = self.code.len();
        let fups: alloc::vec::Vec<(usize, FixupKind)> =
            self.fixups.drain(..).map(|f| (f.site, f.kind)).collect();
        for (site, kind) in fups {
            let rel = (cl - site) as i32;
            match kind {
                FixupKind::Jmp => {
                    self.code[site] = self.jal_word(RV_ZERO, rel);
                }
                FixupKind::Jcc(cond) => {
                    let f3 = rv_cond_funct3(cond);
                    self.code[site] = self.b_word(f3, RV_ZERO, 0, rel);
                }
                FixupKind::Call => {
                    self.code[site] = self.jal_word(1, rel);
                }
            }
        }
    }
    fn jal_word(&self, rd: u32, off: i32) -> u32 {
        let imm = off & 0x1FFFFF;
        let i20 = ((imm >> 20) & 0x1) as u32;
        let i10_1 = ((imm >> 1) & 0x3FF) as u32;
        let i11 = ((imm >> 11) & 0x1) as u32;
        let i19_12 = ((imm >> 12) & 0xFF) as u32;
        (i20 << 31) | (i10_1 << 21) | (i11 << 20) | (i19_12 << 12) | (rd << 7) | OPCODE_JAL
    }
    fn b_word(&self, f3: u32, rs1: u32, rs2: u32, off: i32) -> u32 {
        let imm = off & 0x1FFF;
        let i12 = ((imm >> 12) & 0x1) as u32;
        let i10_5 = ((imm >> 5) & 0x3F) as u32;
        let i4_1 = ((imm >> 1) & 0xF) as u32;
        let i11 = ((imm >> 11) & 0x1) as u32;
        (i12 << 31)
            | (i10_5 << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (f3 << 12)
            | (i4_1 << 8)
            | (i11 << 7)
            | OPCODE_BRANCH
    }
    pub fn emit_load_mem(&mut self, rd: u32, mem: &MemOperand) {
        let (base, disp) = match mem.base {
            Some(b) => (map_reg(b), mem.disp),
            None => (RV_ZERO, mem.disp),
        };
        if disp >= -2048 && disp <= 2047 {
            self.emit_ld(rd, base, disp);
        } else {
            self.emit_li(6, disp as i64);
            self.emit_add(6, base, 6);
            self.emit_ld(rd, 6, 0);
        }
    }
    pub fn emit_store_mem(&mut self, rs2: u32, mem: &MemOperand) {
        let (base, disp) = match mem.base {
            Some(b) => (map_reg(b), mem.disp),
            None => (RV_ZERO, mem.disp),
        };
        if disp >= -2048 && disp <= 2047 {
            self.emit_sd(rs2, base, disp);
        } else {
            self.emit_li(6, disp as i64);
            self.emit_add(6, base, 6);
            self.emit_sd(rs2, 6, 0);
        }
    }
    pub fn emit_lea(&mut self, rd: u32, mem: &MemOperand) {
        match (mem.base, mem.index) {
            (Some(base), Some(index)) => {
                let rb = map_reg(base);
                let ri = map_reg(index);
                let shift = match mem.scale {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => 3,
                };
                if shift > 0 {
                    let slli = ((shift as u32) << 20)
                        | (ri << 15)
                        | (FUNCT3_ADD_SUB << 12)
                        | (6 << 7)
                        | OPCODE_OP_IMM;
                    self.push(slli);
                }
                self.emit_add(rd, rb, 6);
                if mem.disp != 0 {
                    self.emit_addi(rd, rd, mem.disp);
                }
            }
            (Some(base), None) => {
                let rb = map_reg(base);
                if mem.disp >= -2048 && mem.disp <= 2047 {
                    self.emit_addi(rd, rb, mem.disp);
                } else {
                    self.emit_li(6, mem.disp as i64);
                    self.emit_add(rd, rb, 6);
                }
            }
            (None, Some(index)) => {
                let ri = map_reg(index);
                let shift = match mem.scale {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => 3,
                };
                if shift > 0 {
                    let slli = ((shift as u32) << 20)
                        | (ri << 15)
                        | (FUNCT3_ADD_SUB << 12)
                        | (6 << 7)
                        | OPCODE_OP_IMM;
                    self.push(slli);
                    self.emit_mov_reg(rd, 6);
                } else {
                    self.emit_mov_reg(rd, ri);
                }
                if mem.disp != 0 {
                    self.emit_addi(rd, rd, mem.disp);
                }
            }
            (None, None) => {
                self.emit_li(rd, mem.disp as i64);
            }
        }
    }
    pub fn emit_mov_reg(&mut self, rd: u32, rs1: u32) {
        self.emit_addi(rd, rs1, 0);
    }
}

fn rv_cond_funct3(cond: BranchCond) -> u32 {
    match cond {
        BranchCond::Always => 0x0,
        BranchCond::Equal => FUNCT3_BEQ,
        BranchCond::NotEqual => FUNCT3_BNE,
        BranchCond::Below => FUNCT3_BLT,
        BranchCond::AboveOrEqual => FUNCT3_BGE,
        BranchCond::BelowOrEqual => FUNCT3_BNE,
        BranchCond::Above => FUNCT3_BLT,
        BranchCond::Less => FUNCT3_BLT,
        BranchCond::GreaterOrEqual => FUNCT3_BGE,
        BranchCond::LessOrEqual => FUNCT3_BNE,
        BranchCond::Greater => FUNCT3_BLT,
        BranchCond::Overflow => FUNCT3_BEQ,
        BranchCond::NotOverflow => FUNCT3_BNE,
        BranchCond::Sign => FUNCT3_BLT,
        BranchCond::NotSign => FUNCT3_BGE,
        BranchCond::Parity => FUNCT3_BEQ,
        BranchCond::NotParity => FUNCT3_BNE,
    }
}

pub fn encode_block(ir: &[IrInst], raw_va: u64) -> CodeBlock {
    let mut em = Rv64Emitter::new();
    for inst in ir {
        match &inst.op {
            IROp::Nop => em.push(0x0000_0013),
            IROp::MovImm { dst, imm } => {
                let rd = map_reg(*dst);
                em.emit_li(rd, *imm);
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
                    AluOp::Add => em.emit_add(rd, rd, rs),
                    AluOp::Sub => em.emit_sub(rd, rd, rs),
                    AluOp::And => em.emit_and(rd, rd, rs),
                    AluOp::Or => em.emit_or(rd, rd, rs),
                    AluOp::Xor => em.emit_xor(rd, rd, rs),
                    AluOp::Cmp => em.emit_sub(6, rd, rs),
                    AluOp::Test => em.emit_and(6, rd, rs),
                }
            }
            IROp::AluImm { op, dst, imm } => {
                let rd = map_reg(*dst);
                if *imm >= -2048 && *imm <= 2047 {
                    let imm12 = *imm as i32;
                    match op {
                        AluOp::Add => em.emit_addi(rd, rd, imm12),
                        AluOp::Sub => em.emit_addi(rd, rd, -imm12),
                        AluOp::And => em.emit_andi(rd, rd, imm12),
                        AluOp::Or => em.emit_ori(rd, rd, imm12),
                        AluOp::Xor => em.emit_xori(rd, rd, imm12),
                        AluOp::Cmp => em.emit_addi(6, rd, -imm12),
                        AluOp::Test => em.emit_andi(6, rd, imm12),
                    }
                } else {
                    em.emit_li(6, *imm);
                    match op {
                        AluOp::Add => em.emit_add(rd, rd, 6),
                        AluOp::Sub => em.emit_sub(rd, rd, 6),
                        AluOp::And => em.emit_and(rd, rd, 6),
                        AluOp::Or => em.emit_or(rd, rd, 6),
                        AluOp::Xor => em.emit_xor(rd, rd, 6),
                        AluOp::Cmp => em.emit_sub(6, rd, 6),
                        AluOp::Test => em.emit_and(6, rd, 6),
                    }
                }
            }
            IROp::AluMem { op, dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_load_mem(7, mem);
                match op {
                    AluOp::Add => em.emit_add(rd, rd, 7),
                    AluOp::Sub => em.emit_sub(rd, rd, 7),
                    AluOp::And => em.emit_and(rd, rd, 7),
                    AluOp::Or => em.emit_or(rd, rd, 7),
                    AluOp::Xor => em.emit_xor(rd, rd, 7),
                    AluOp::Cmp => em.emit_sub(6, rd, 7),
                    AluOp::Test => em.emit_and(6, rd, 7),
                }
            }
            IROp::Lea { dst, mem } => {
                let rd = map_reg(*dst);
                em.emit_lea(rd, mem);
            }
            IROp::Push { src } => {
                let rs = map_reg(*src);
                em.emit_addi(2, 2, -8);
                em.emit_sd(rs, 2, 0);
            }
            IROp::Pop { dst } => {
                let rd = map_reg(*dst);
                em.emit_ld(rd, 2, 0);
                em.emit_addi(2, 2, 8);
            }
            IROp::Jmp { .. } => em.emit_jmp(),
            IROp::Jcc { cond, .. } => em.emit_jcc(*cond),
            IROp::Call { .. } => em.emit_call(),
            IROp::Ret => em.emit_jalr(RV_ZERO, 1, 0),
            IROp::Syscall => em.emit_ecall(),
            IROp::Unsupported => em.push(0x0010_0073),
            IROp::SimdMov { .. } | IROp::SimdStore { .. } | IROp::SimdArith { .. } => {
                em.push(0x0010_0073)
            }
        }
    }
    em.resolve();
    let mut cb = CodeBlock::empty();
    cb.raw_va = raw_va;
    for (i, w) in em.code.iter().enumerate() {
        let off = i * 4;
        if off + 4 <= MAX_CODE_BYTES {
            cb.bytes[off..off + 4].copy_from_slice(&w.to_le_bytes());
            cb.len = off + 4;
        }
    }
    cb
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
    assert_eq!(&block.bytes[0..4], &0x0000_0013u32.to_le_bytes());
    assert_eq!(&block.bytes[4..8], &0x02A0_0513u32.to_le_bytes());
    assert_eq!(&block.bytes[8..12], &0x0000_8067u32.to_le_bytes());
    true
}
#[cfg(test)]
mod tests {
    use crate::arch::common::btl::exec::test_support::{decode, flat_memory, run_mov_imm_add_imm};
    use crate::arch::common::btl::memory::GuestMemory;

    use super::*;

    #[test]
    fn interprets_x86_64_mov_imm_add_imm() {
        let mut backing = [0u8; 0x1000];
        let mut memory = flat_memory(&mut backing);
        let (outcome, rax) = run_mov_imm_add_imm(&mut memory);
        assert!(matches!(outcome, crate::arch::common::btl::exec::ExecOutcome::Retired { .. }));
        assert_eq!(rax, 50);
    }
}
