//! BTL Intermediate Representation (IR).
//!
//! Currently a stub. The IR is a simple, RISC-like instruction set
//! that the codegen lowers into AArch64. This module will be
//! expanded incrementally:
//!
//! 1. Define the IR ops (e.g. `IRMov`, `IRAdd`, `IRBranch`, ...).
//! 2. Define a builder API that emits IR while consuming a stream
//!    of [`super::DecodedInstr`] from the decoder.
//! 3. Provide a peephole optimiser that runs after decoding.
//!
//! ## Why an IR?
//!
//! A minimal IR between decoder and codegen lets us:
//!
//! * Run architecture-independent optimisations (constant folding,
//!   dead code elimination).
//! * Share code generation across x86_64, x86_32 and ARM32 since
//!   the source opcodes are normalised into a common format.
//! * Make the code generator easy to retarget (an IR backend for
//!   a new target architecture only has to consume IR).

use crate::arch::aarch64::btl::decoder::DecodedInstr;

/// IR op placeholder.
#[derive(Debug, Clone, Copy)]
pub enum IROp {
    Nop,
    Mov { dst: u8, src: u8 },
    Add { dst: u8, src: u8, imm: i32 },
    Branch { target: u64, cond: u8 },
    Call { target: u64 },
    Ret,
    Syscall,
}

pub fn build_ir(_decoded: &[DecodedInstr]) -> Vec<IROp> {
    // Stub: real impl walks the DecodedInstr stream and emits IR.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_ir() {
        let v = build_ir(&[]);
        assert!(v.is_empty());
    }
}
