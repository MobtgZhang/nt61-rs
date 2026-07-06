//! RISC-V 64-bit OS Loader trampoline.
//!
//! On RISC-V the loader and kernel use the same LP64D ABI:
//! `a0` carries the first integer argument, `a1` the second, etc.
//! `kernel_main` (declared `extern "C" fn kernel_main(&BootInfo)`)
//! therefore expects `a0` to hold the BootInfo pointer — and the
//! C-style Rust `call` already does that for us.
//!
//! The trampoline's only jobs are therefore:
//!   * Install the kernel stack (`sp <- stack_top`).
//!   * Branch into `kernel_main` via `jalr ra, .+0`.
//!
//! Pre-conditions the kernel assumes but does *not* re-establish:
//!   * `sstatus.SIE = 0` (interrupts masked).
//!   * `sstatus.SUM = 0` (no S-mode access to U-mode pages).
//!   * `satp` is whatever the firmware left it — the kernel
//!     re-installs its page table early in `paging::init`.

use nt61::kernel_main::kernel_main;

/// Switch to the kernel stack and jump to `kernel_main`. Never
/// returns.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main(stack_top: u64, bi_ptr: u64) -> ! {
    core::arch::asm!(
        // 1. Install the kernel stack *before* we touch `a0`.
        "mv sp, {sp}",
        // 2. Place the BootInfo pointer in `a0` (RISC-V LP64D
        //    first integer argument register).
        "mv a0, {bi}",
        // 3. Branch to the kernel symbol and link so the
        //    kernel's RA is the trampoline return PC. The
        //    kernel is `-> !`, so RA is unused, but having
        //    it set correctly aids any debug trace path that
        //    walks the call stack.
        //
        //    RISC-V `jalr rs1, imm(rs2)` is *two*-operand
        //    syntax (GAS binutils form: `jalr rs1, rs2` is
        //    `jalr rd, rs1`); the GNU RISC-V assembler does
        //    not accept the three-operand `jalr rd, sym, 0`
        //    form. We therefore use the `(sym)` addressing
        //    form which GAS expands to `auipc + jalr` for
        //    symbols outside the ±2 KiB range.
        "jalr ra, {km}",
        sp = in(reg) stack_top,
        bi = in(reg) bi_ptr,
        km = in(reg) kernel_main as *const () as usize,
        options(noreturn),
    );
}
