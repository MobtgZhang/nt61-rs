//! RISC-V 64 `stvec` and exception handling.
//!
//! The `stvec_trap` assembler below is the entry point installed
//! into the `stvec` CSR by [`init`]. It:
//!
//!   1. Swaps `sp` with `sscratch` (which holds the per-CPU
//!      kernel-stack pointer set up by [`super::user_entry`]) so
//!      we have a valid kernel stack to spill registers onto.
//!   2. Saves the general-purpose register file plus `sepc`,
//!      `sstatus`, `stval`, `scause` onto the new stack.
//!   3. Calls [`super::trap::riscv64_trap_dispatch`], which
//!      decodes the cause and dispatches to the right handler.
//!   4. Restores the registers, swaps `sp` back, and `sret`s to
//!      the saved `sepc`.
//!
//! `TrapFrame` itself lives in [`super::trap`]; this module keeps
//! only the assembler stub and the `init()` glue.

use core::arch::asm;
use core::arch::global_asm;

global_asm!(
    ".align 4",
    ".global stvec_trap",
    "stvec_trap:",
    // 1. Swap sp and sscratch to land on the per-CPU kernel stack.
    "  csrrw sp, sscratch, sp",
    // 2. Spill the GPR file plus the four trap CSRs.
    "  sd    ra,   0(sp)",
    "  sd    t0,   8(sp)",
    "  sd    t1,   16(sp)",
    "  sd    t2,   24(sp)",
    "  sd    s0,   32(sp)",
    "  sd    s1,   40(sp)",
    "  sd    a0,   48(sp)",
    "  sd    a1,   56(sp)",
    "  sd    a2,   64(sp)",
    "  sd    a3,   72(sp)",
    "  sd    a4,   80(sp)",
    "  sd    a5,   88(sp)",
    "  sd    a6,   96(sp)",
    "  sd    a7,   104(sp)",
    "  sd    s2,   112(sp)",
    "  sd    s3,   120(sp)",
    "  sd    s4,   128(sp)",
    "  sd    s5,   136(sp)",
    "  sd    s6,   144(sp)",
    "  sd    s7,   152(sp)",
    "  sd    s8,   160(sp)",
    "  sd    s9,   168(sp)",
    "  sd    s10,  176(sp)",
    "  sd    s11,  184(sp)",
    "  sd    gp,   192(sp)",
    "  sd    tp,   200(sp)",
    "  csrr  t0,   sepc",
    "  sd    t0,   208(sp)",
    "  csrr  t0,   sstatus",
    "  sd    t0,   216(sp)",
    "  csrr  t0,   stval",
    "  sd    t0,   224(sp)",
    "  csrr  t0,   scause",
    "  sd    t0,   232(sp)",
    // 3. Hand off to the Rust dispatcher. a0 = pointer to trap
    //    frame (live on the kernel stack).
    "  mv    a0,   sp",
    "  call  riscv64_trap_dispatch",
    // 4. Restore state. We reload the trap CSRs first so that any
    //    change the dispatcher made (e.g. sepc advance) takes
    //    effect.
    "  ld    t0,   232(sp)",
    "  csrw  scause, t0",
    "  ld    t0,   224(sp)",
    "  csrw  stval,  t0",
    "  ld    t0,   216(sp)",
    "  csrw  sstatus, t0",
    "  ld    t0,   208(sp)",
    "  csrw  sepc,   t0",
    "  ld    ra,   0(sp)",
    "  ld    t0,   8(sp)",
    "  ld    t1,   16(sp)",
    "  ld    t2,   24(sp)",
    "  ld    s0,   32(sp)",
    "  ld    s1,   40(sp)",
    "  ld    a0,   48(sp)",
    "  ld    a1,   56(sp)",
    "  ld    a2,   64(sp)",
    "  ld    a3,   72(sp)",
    "  ld    a4,   80(sp)",
    "  ld    a5,   88(sp)",
    "  ld    a6,   96(sp)",
    "  ld    a7,   104(sp)",
    "  ld    s2,   112(sp)",
    "  ld    s3,   120(sp)",
    "  ld    s4,   128(sp)",
    "  ld    s5,   136(sp)",
    "  ld    s6,   144(sp)",
    "  ld    s7,   152(sp)",
    "  ld    s8,   160(sp)",
    "  ld    s9,   168(sp)",
    "  ld    s10,  176(sp)",
    "  ld    s11,  184(sp)",
    "  ld    gp,   192(sp)",
    "  ld    tp,   200(sp)",
    // 5. Swap sp and sscratch back so user mode resumes on its own
    //    stack pointer.
    "  csrrw sp, sscratch, sp",
    "  sret"
);

extern "C" {
    fn stvec_trap();
}

/// Install the `stvec` handler.
pub fn init() {
    unsafe {
        let v = stvec_trap as *const () as u64;
        asm!("csrw stvec, {}", in(reg) v, options(nostack));
    }
}

/// `TrapFrame` is defined in [`super::trap`]. Re-export here for
/// callers that historically imported it from this module.
pub use super::trap::TrapFrame;