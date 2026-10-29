//! BTL x86_64 instruction decoder — thin wrapper around the shared
//! decoder in crate::arch::common::btl::x86_decoder.

use crate::arch::common::btl::ir::{IROp, IrInst, X86Reg};
use crate::arch::common::btl::x86_decoder as shared;

pub use shared::{decode_block, decode_one, MAX_BLOCK_BYTES, MAX_DECODED_INSTS};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_nop_via_shared() {
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&[0x90], 0x1000, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].op, IROp::Nop);
    }

    #[test]
    fn decode_ret_via_shared() {
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&[0xC3], 0x1000, &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].op, IROp::Ret);
    }

    #[test]
    fn decode_mov_via_shared() {
        // mov rax, 42 (48 C7 C0 2A 00 00 00)
        let bytes = [0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00];
        let mut out = [IrInst::empty(); 4];
        let n = decode_block(&bytes, 0x1000, &mut out);
        assert_eq!(n, 1);
        match out[0].op {
            IROp::MovImm { dst, imm } => {
                assert_eq!(dst, X86Reg::Rax);
                assert_eq!(imm, 42);
            }
            _ => panic!("expected MovImm"),
        }
    }
}
