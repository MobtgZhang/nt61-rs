//! Shared BTL Intermediate Representation (IR).
//!
//! All non-x86 BTL backends (AArch64, RISC-V, LoongArch) consume this
//! IR. It is produced by the shared x86_64 decoder and consumed by the
//! per-architecture code generators.

/// x86_64 general-purpose register identifiers (64-bit view).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    Rip = 16,
}

/// x86_64 SIMD register identifiers (XMM0–XMM31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum X86Xmm {
    Xmm0 = 0,
    Xmm1 = 1,
    Xmm2 = 2,
    Xmm3 = 3,
    Xmm4 = 4,
    Xmm5 = 5,
    Xmm6 = 6,
    Xmm7 = 7,
    Xmm8 = 8,
    Xmm9 = 9,
    Xmm10 = 10,
    Xmm11 = 11,
    Xmm12 = 12,
    Xmm13 = 13,
    Xmm14 = 14,
    Xmm15 = 15,
    Xmm16 = 16,
    Xmm17 = 17,
    Xmm18 = 18,
    Xmm19 = 19,
    Xmm20 = 20,
    Xmm21 = 21,
    Xmm22 = 22,
    Xmm23 = 23,
    Xmm24 = 24,
    Xmm25 = 25,
    Xmm26 = 26,
    Xmm27 = 27,
    Xmm28 = 28,
    Xmm29 = 29,
    Xmm30 = 30,
    Xmm31 = 31,
}

impl X86Xmm {
    /// All 32 XMM registers in x86 encoding order.
    pub const XMMS: [X86Xmm; 32] = [
        X86Xmm::Xmm0,
        X86Xmm::Xmm1,
        X86Xmm::Xmm2,
        X86Xmm::Xmm3,
        X86Xmm::Xmm4,
        X86Xmm::Xmm5,
        X86Xmm::Xmm6,
        X86Xmm::Xmm7,
        X86Xmm::Xmm8,
        X86Xmm::Xmm9,
        X86Xmm::Xmm10,
        X86Xmm::Xmm11,
        X86Xmm::Xmm12,
        X86Xmm::Xmm13,
        X86Xmm::Xmm14,
        X86Xmm::Xmm15,
        X86Xmm::Xmm16,
        X86Xmm::Xmm17,
        X86Xmm::Xmm18,
        X86Xmm::Xmm19,
        X86Xmm::Xmm20,
        X86Xmm::Xmm21,
        X86Xmm::Xmm22,
        X86Xmm::Xmm23,
        X86Xmm::Xmm24,
        X86Xmm::Xmm25,
        X86Xmm::Xmm26,
        X86Xmm::Xmm27,
        X86Xmm::Xmm28,
        X86Xmm::Xmm29,
        X86Xmm::Xmm30,
        X86Xmm::Xmm31,
    ];

    /// Convert a 3-bit (legacy) or 4-bit (VEX.R/VEX.B) register index.
    pub const fn from_modrm(index: u8, vex_b: bool) -> Self {
        let full = if vex_b { index | 0x08 } else { index & 0x07 };
        Self::XMMS[full as usize]
    }

    /// Convert a 4-bit index with EVEX R' extension to a full 5-bit XMM index.
    pub const fn from_evex(index: u8, reg_ext_hi: bool, reg_ext_lo: bool) -> Self {
        let full = ((index & 0x07) as usize)
            | (((reg_ext_hi as usize) & 1) << 4)
            | (((reg_ext_lo as usize) & 1) << 3);
        Self::XMMS[full & 31]
    }
}

/// SIMD element width for a vector operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdWidth {
    /// 128-bit single-precision floats (packed 4×f32).
    PackedF32,
    /// 128-bit double-precision floats (packed 2×f64).
    PackedF64,
    /// Scalar single-precision (lower f32).
    ScalarF32,
    /// Scalar double-precision (lower f64).
    ScalarF64,
    /// 128-bit integer (packed i8/i16/i32/i64 lanes).
    PackedI128,
}

/// SIMD arithmetic / data-movement operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdOp {
    Mov,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Compare,
}

impl X86Reg {
    /// All 16 GPRs in x86 encoding order.
    pub const GPRS: [X86Reg; 16] = [
        X86Reg::Rax,
        X86Reg::Rcx,
        X86Reg::Rdx,
        X86Reg::Rbx,
        X86Reg::Rsp,
        X86Reg::Rbp,
        X86Reg::Rsi,
        X86Reg::Rdi,
        X86Reg::R8,
        X86Reg::R9,
        X86Reg::R10,
        X86Reg::R11,
        X86Reg::R12,
        X86Reg::R13,
        X86Reg::R14,
        X86Reg::R15,
    ];

    /// Convert a raw 3-bit or 4-bit ModR/M register field.
    pub const fn from_modrm(index: u8, rex_b: bool) -> Self {
        let full = if rex_b { index | 0x08 } else { index & 0x07 };
        Self::GPRS[full as usize]
    }
}

/// Memory operand: base + index * scale + disp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOperand {
    pub base: Option<X86Reg>,
    pub index: Option<X86Reg>,
    pub scale: u8,
    pub disp: i32,
    pub width: u8,
}

/// Arithmetic / logic operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Cmp,
    Test,
}

/// Conditional branch predicate mapping x86 condition codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchCond {
    Always,
    Overflow,
    NotOverflow,
    Below,
    AboveOrEqual,
    Equal,
    NotEqual,
    BelowOrEqual,
    Above,
    Sign,
    NotSign,
    Parity,
    NotParity,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
}

impl BranchCond {
    /// Map an x86 condition code low nibble to the IR predicate.
    pub const fn from_x86_cc(cc: u8) -> Self {
        match cc & 0x0F {
            0x0 => BranchCond::Overflow,
            0x1 => BranchCond::NotOverflow,
            0x2 => BranchCond::Below,
            0x3 => BranchCond::AboveOrEqual,
            0x4 => BranchCond::Equal,
            0x5 => BranchCond::NotEqual,
            0x6 => BranchCond::BelowOrEqual,
            0x7 => BranchCond::Above,
            0x8 => BranchCond::Sign,
            0x9 => BranchCond::NotSign,
            0xA => BranchCond::Parity,
            0xB => BranchCond::NotParity,
            0xC => BranchCond::Less,
            0xD => BranchCond::GreaterOrEqual,
            0xE => BranchCond::LessOrEqual,
            _ => BranchCond::Greater,
        }
    }
}

/// A single IR operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IROp {
    Nop,
    MovImm {
        dst: X86Reg,
        imm: i64,
    },
    MovReg {
        dst: X86Reg,
        src: X86Reg,
    },
    Load {
        dst: X86Reg,
        mem: MemOperand,
    },
    Store {
        mem: MemOperand,
        src: X86Reg,
    },
    AluReg {
        op: AluOp,
        dst: X86Reg,
        src: X86Reg,
    },
    AluImm {
        op: AluOp,
        dst: X86Reg,
        imm: i64,
    },
    AluMem {
        op: AluOp,
        dst: X86Reg,
        mem: MemOperand,
    },
    Lea {
        dst: X86Reg,
        mem: MemOperand,
    },
    Push {
        src: X86Reg,
    },
    Pop {
        dst: X86Reg,
    },
    Jmp {
        target: u64,
    },
    Jcc {
        cond: BranchCond,
        target: u64,
    },
    Call {
        target: u64,
    },
    Ret,
    Syscall,
    /// SIMD move: dst_xmm = src (reg or memory).
    SimdMov {
        dst: X86Xmm,
        src: SimdSrc,
        width: SimdWidth,
    },
    /// SIMD store: mem = src_xmm.
    SimdStore {
        mem: MemOperand,
        src: X86Xmm,
        width: SimdWidth,
    },
    /// SIMD arithmetic: dst_xmm = dst_xmm <op> src.
    SimdArith {
        op: SimdOp,
        dst: X86Xmm,
        src: SimdSrc,
        width: SimdWidth,
    },
    Unsupported,
}

/// Source operand for a SIMD instruction (register or memory).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdSrc {
    Xmm(X86Xmm),
    Mem(MemOperand),
}

/// One lowered IR instruction with its guest VA and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrInst {
    pub op: IROp,
    pub guest_va: u64,
    pub guest_len: u8,
}

impl IrInst {
    pub const fn empty() -> Self {
        Self {
            op: IROp::Nop,
            guest_va: 0,
            guest_len: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modrm_register_mapping() {
        assert_eq!(X86Reg::from_modrm(0, false), X86Reg::Rax);
        assert_eq!(X86Reg::from_modrm(7, false), X86Reg::Rdi);
        assert_eq!(X86Reg::from_modrm(0, true), X86Reg::R8);
        assert_eq!(X86Reg::from_modrm(7, true), X86Reg::R15);
    }

    #[test]
    fn condition_code_mapping() {
        assert_eq!(BranchCond::from_x86_cc(0x74), BranchCond::Equal);
        assert_eq!(BranchCond::from_x86_cc(0x75), BranchCond::NotEqual);
        assert_eq!(BranchCond::from_x86_cc(0x0E), BranchCond::LessOrEqual);
    }
}
