//! BTL AArch64 code generator.
//!
//! Currently a stub. The code generator lowers an [`IROp`] stream
//! into AArch64 instructions, allocating registers and emitting the
//! resulting bytes into the code cache slot reserved by
//! [`super::TranslationManager`].
//!
//! ## Register allocation
//!
//! * First pass: per-block liveness analysis.
//! * Second pass: linear scan allocation using
//!   `x0..x18` (caller-saved on AAPCS64), spilling to a private
//!   stack in the BTL slot if necessary.
//!
//! ## Code emitter
//!
//! The emitter outputs 4-byte AArch64 instructions in little-endian
//! order. Each emitter helper accepts the AArch64 fixed encoding
//! and writes it via volatile stores. Conditional branches are
//! resolved during emission; the IR already carries the
//! `cond` value.

use crate::arch::aarch64::btl::ir::IROp;

/// Emit AArch64 bytes for an `IROp` stream into `dst`. Returns the
/// number of bytes written or an error on failure.
pub fn emit(ir: &[IROp], dst: &mut [u8]) -> Result<usize, ()> {
    let mut off = 0;
    for op in ir {
        let bytes = match op {
            IROp::Nop => [0xD503_201F_u32.to_le_bytes(); 1].concat(),
            _ => [0xD503_201F_u32.to_le_bytes(); 1].concat(),
        };
        if off + bytes.len() > dst.len() {
            return Err(());
        }
        dst[off..off + bytes.len()].copy_from_slice(&bytes);
        off += bytes.len();
    }
    Ok(off)
}
