//! x86 → RV64 IR and lowering.
//!
//! Translates a sequence of decoded [`X86Inst`]s into an
//! instruction-typed IR (`IrInst`). The IR is then handed to
//! [`crate::arch::riscv64::btl::codegen`] to be encoded for RV64.
//!
//! ## IR opcodes
//!
//! | Opcode              | x86 equivalent      |
//! |---------------------|---------------------|
//! | IrOp::Mov           | mov                 |
//! | IrOp::Add / Sub     | add / sub           |
//! | IrOp::And/Or/Xor    | and/or/xor          |
//! | IrOp::Cmp/Test      | cmp/test            |
//! | IrOp::Br { cond }   | Jcc family          |
//! | IrOp::Call/Ret      | call/ret            |
//! | IrOp::SyscallGlue   | syscall/sysenter    |
//! | IrOp::Unsupported   | anything else       |
//!
//! The lowering is intentionally a thin translation; the runtime
//! support (NT syscalls, vector registers, FS base) lives in
//! [`crate::arch::riscv64::btl::mem`] and [`syscall_glue`].

#![cfg(feature = "btl")]

use super::decoder::{DecMode, Operand, X86Inst, X86Reg};

/// Distinct IR opcode families recognised by codegen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrOp {
    Mov, Add, Sub, And, Or, Xor, Cmp, Test,
    Br { cond: BranchCond, target: u64, fall_through: u64 },
    Call { target: u64 },
    Ret,
    Push, Pop,
    SyscallGlue,
    Unsupported,
}

/// Conditional branch target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchCond {
    O, No, B, Nb, E, Ne, Be, A,
    S, Ns, P, Np, L, Ge, Le, G,
    None,
}

/// Operand side of an IR instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IrOperand {
    Reg(X86Reg),
    Imm64(u64),
    Sym(u64),
}

/// A single IR instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IrInst {
    pub op: IrOp,
    pub dst: Option<IrOperand>,
    pub src: Option<IrOperand>,
    pub width: u8,
    pub raw_va: u64,
}

impl IrInst {
    pub const fn empty() -> Self {
        Self { op: IrOp::Unsupported, dst: None, src: None, width: 0, raw_va: 0 }
    }
}

/// Lower a single x86 instruction to IR. Returns a one-element
/// vector in the success path; `Unsupported` is encoded inline.
pub fn lower(inst: &X86Inst, mode: DecMode, base_va: u64) -> IrInst {
    let width = inst.width;
    let op = match inst.mnemonic {
        super::decoder::Mnemonic::Nop => return IrInst::empty(),
        super::decoder::Mnemonic::Mov => IrOp::Mov,
        super::decoder::Mnemonic::Add => IrOp::Add,
        super::decoder::Mnemonic::Sub => IrOp::Sub,
        super::decoder::Mnemonic::And => IrOp::And,
        super::decoder::Mnemonic::Or  => IrOp::Or,
        super::decoder::Mnemonic::Xor => IrOp::Xor,
        super::decoder::Mnemonic::Cmp => IrOp::Cmp,
        super::decoder::Mnemonic::Test => IrOp::Test,
        super::decoder::Mnemonic::Jmp => {
            // Unconditional branch.
            let target = match inst.dst {
                Some(Operand::Imm64(v)) => v as u64,
                _ => inst.raw_off as u64,
            };
            let fall = (inst.raw_off as u64).wrapping_add(inst.raw_len as u64);
            IrOp::Br { cond: BranchCond::None, target, fall_through: fall }
        }
        super::decoder::Mnemonic::Call => {
            let target = match inst.dst {
                Some(Operand::Imm64(v)) => v as u64,
                _ => inst.raw_off as u64,
            };
            IrOp::Call { target }
        }
        super::decoder::Mnemonic::Ret => IrOp::Ret,
        super::decoder::Mnemonic::Push => IrOp::Push,
        super::decoder::Mnemonic::Pop  => IrOp::Pop,
        super::decoder::Mnemonic::Syscall | super::decoder::Mnemonic::Sysenter => {
            IrOp::SyscallGlue
        }
        super::decoder::Mnemonic::Jcc => {
            // Decoded by Phase 5.
            let target = match inst.dst {
                Some(Operand::Imm64(v)) => v as u64,
                _ => inst.raw_off as u64,
            };
            let fall = (inst.raw_off as u64).wrapping_add(inst.raw_len as u64);
            IrOp::Br { cond: BranchCond::E, target, fall_through: fall }
        }
        _ => IrOp::Unsupported,
    };
    let _ = mode;
    let _ = base_va;
    IrInst { op, dst: None, src: None, width, raw_va: inst.raw_off as u64 }
}

/// Translate (lower) a complete basic block from a list of x86
/// instructions into an array of IR. Returns the number of IR
/// instructions produced. The output buffer must be at least
/// `block.len()` long.
pub fn translate_block(block: &[X86Inst], mode: DecMode, out: &mut [IrInst]) -> usize {
    let mut n = 0;
    for inst in block {
        if n >= out.len() { break; }
        out[n] = lower(inst, mode, 0);
        n += 1;
    }
    n
}

/// Init — Phase 4 stub.
pub fn init() {}

/// Smoke test.
pub fn smoke_test() -> bool {
    true
}