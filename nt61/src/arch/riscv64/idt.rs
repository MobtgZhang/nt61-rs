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
    // `sscratch` holds the current kernel-stack top. Swap it with `sp`
    // before touching memory: user traps land on the kernel stack while
    // the user sp moves to `sscratch`; kernel traps land on the saved
    // kernel-stack top. The only special case is the very first kernel
    // trap before `sscratch` has been primed.
    "  csrrw sp,   sscratch, sp",
    "  bnez  sp,   1f",
    // First kernel trap: `sscratch` was still zero, so the interrupted
    // supervisor stack is in `sscratch`.
    "  csrr  sp,   sscratch",
    "  addi  sp,   sp,   -256",
    "  sd    t0,   8(sp)",
    "  csrr  t0,   sscratch",
    "  sd    t0,   240(sp)",
    "  addi  t0,   sp,   256",
    "  csrw  sscratch, t0",
    "  j     3f",
    "1:",
    // User trap or a nested kernel trap: `sp` is now the saved kernel
    // stack top and `sscratch` is the interrupted sp. Allocate the frame
    // below that top, save the interrupted sp, and republish the new top
    // for nested traps.
    "  addi  sp,   sp,   -256",
    "  sd    t0,   8(sp)",
    "  csrr  t0,   sscratch",
    "  sd    t0,   240(sp)",
    "  addi  t0,   sp,   256",
    "  csrw  sscratch, t0",
    "3:",
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
    //    effect. sstatus is loaded into a caller-saved register and
    //    restored after the stack switch so SUM tracks the original
    //    privilege mode.
    "  ld    t0,   232(sp)",
    "  csrw  scause, t0",
    "  ld    t0,   224(sp)",
    "  csrw  stval,  t0",
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
    // The CSR restore block uses `t0` as a scratch register; reload the
    // saved value before returning to user mode.
    "  ld    t3,   216(sp)",
    "  bnez  t3,   4f",
    "  ld    t5,   8(sp)",
    "  addi  t0,   sp,   256",
    "  csrw  sscratch, t0",
    "  ld    sp,   240(sp)",
    "  mv    t0,   t5",
    "  j     5f",
    "4:",
    "  ld    t5,   8(sp)",
    "  addi  t0,   sp,   256",
    "  csrw  sscratch, t0",
    "  ld    sp,   240(sp)",
    "  mv    t0,   t5",
    "5:",
    "  csrw  sstatus, t3",
    "  sret"
);

extern "C" {
    fn stvec_trap();
}

/// Runtime address of the trap entry, for low-level diagnostics.
pub fn trap_entry_addr() -> u64 {
    stvec_trap as *const () as u64
}

/// Install the `stvec` handler.
pub fn init() {
    unsafe {
        let v = stvec_trap as *const () as u64;
        asm!("csrw stvec, {}", in(reg) v, options(nostack));
        let stack_top: u64;
        asm!("mv {}, sp", out(reg) stack_top, options(nostack));
        asm!("csrw sscratch, {}", in(reg) stack_top, options(nostack));
    }
}

/// `TrapFrame` is defined in [`super::trap`]. Re-export here for
/// callers that historically imported it from this module.
pub use super::trap::TrapFrame;
