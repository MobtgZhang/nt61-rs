//! BTL Intermediate Representation — re-exports the shared IR.

pub use crate::arch::common::btl::ir::{AluOp, BranchCond, IROp, IrInst, MemOperand, X86Reg};

pub fn build_ir(decoded: &[IrInst]) -> alloc::vec::Vec<IrInst> {
    decoded.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_roundtrip() {
        let ir: alloc::vec::Vec<IrInst> = alloc::vec![IrInst {
            op: IROp::Nop,
            guest_va: 0x1000,
            guest_len: 1,
        }];
        let result = build_ir(&ir);
        assert_eq!(result.len(), 1);
    }
}
