//! RISC-V code generator for the IR produced by
//! [`crate::arch::riscv64::btl::translator`].
//!
//! Phase 4 ships a minimal encodable stub that emits 4-byte NOP
//! per IR instruction. Phase 5 wires concrete RV64 encodings for
//! the IR op set; Phase 6 adds vector / V-extension support for
//! the x86 SSE/AVX subset.

#![cfg(feature = "btl")]

use super::translator::IrInst;

/// Maximum code-buffer size per basic block. We set this to 4 KiB
/// — for x86 blocks <= 1024 bytes the worst-case RV64 expansion is
/// roughly 4x and we want to be safe.
pub const MAX_CODE_BYTES: usize = 4096;

/// A compiled basic-block.
#[derive(Clone, Debug)]
pub struct CodeBlock {
    pub bytes: [u8; MAX_CODE_BYTES],
    pub len: usize,
    pub raw_va: u64,
}

impl CodeBlock {
    pub const fn empty() -> Self {
        Self { bytes: [0x13; MAX_CODE_BYTES], len: 0, raw_va: 0 }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len.min(MAX_CODE_BYTES)]
    }
}

fn encode_nop() -> [u8; 4] {
    // c.nop (compact NOP, expanded to 'addi x0, x0, 0' = 0x13 0x00 0x00 0x00).
    [0x13, 0x00, 0x00, 0x00]
}

/// Encode an entire IR list into a [`CodeBlock`].
///
/// Phase 4 emits a NOP per IR instruction; the real RV64 lowering
/// is wired in Phase 5.
pub fn encode_block(ir: &[IrInst], raw_va: u64) -> CodeBlock {
    let mut cb = CodeBlock::empty();
    cb.raw_va = raw_va;
    let mut off = 0;
    for inst in ir {
        let nop = encode_nop();
        if off + 4 > MAX_CODE_BYTES { break; }
        cb.bytes[off..off+4].copy_from_slice(&nop);
        off += 4;
        let _ = inst;
    }
    cb.len = off;
    cb
}

pub fn init() {}

pub fn smoke_test() -> bool {
    let ir: [IrInst; 0] = [];
    let cb = encode_block(&ir, 0);
    cb.len == 0
}