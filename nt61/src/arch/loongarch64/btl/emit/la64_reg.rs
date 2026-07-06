//! LoongArch register encoding helpers used by the BTL emitter.

#![cfg(target_arch = "loongarch64")]

/// Common registers used during translation. The numeric values
/// match the LA64 ABI encoding for `$r0`-`$r31`.
#[derive(Copy, Clone, Debug)]
pub enum La64Reg {
    Zero = 0, Ra = 1, Sp = 3, Tp = 2,
    A0 = 4, A1 = 5, A2 = 6, A3 = 7,
    A4 = 8, A5 = 9, A6 = 10, A7 = 11,
    T0 = 12, T1 = 13, T2 = 14, T3 = 15,
    T4 = 16, T5 = 17, T6 = 18, T7 = 19,
    T8 = 20, T9 = 21, S0 = 23, S1 = 24,
    S2 = 25, S3 = 26, S4 = 27, S5 = 28,
    S6 = 29, S7 = 30, S8 = 31,
}

impl La64Reg {
    pub fn from_index(n: u8) -> Self {
        match n {
            1 => La64Reg::Ra,
            3 => La64Reg::Sp,
            5 => La64Reg::A1,
            6 => La64Reg::A2,
            7 => La64Reg::A3,
            23 => La64Reg::S0,
            _ => La64Reg::T0,
        }
    }
}

/// Operand wrappers for the emitter. Today only register operands
/// are needed; memory operands are synthesised by `translate::*`
/// into `ldptr`/`stptr` equivalents.
#[derive(Copy, Clone, Debug)]
pub enum Operand {
    Reg(La64Reg),
    Imm(u32),
    /// Reserved placeholder for future use (e.g. label refs).
    Label(u32),
}

/// Emit a label-defining `nop` placeholder that the patcher can use
/// to record a translation-target address.
pub fn emit_label(buf: &mut super::EmitBuffer, _id: u32) {
    // `addi.d $zero, $zero, 0` — single-instruction, well-defined
    // encoding. The patcher later rewrites a branch to point here
    // when the label is referenced.
    buf.push_insn(0x0340_0000);
}
