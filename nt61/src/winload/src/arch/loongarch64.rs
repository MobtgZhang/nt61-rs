//! LoongArch64 OS Loader trampoline.
//!
//! On LoongArch64 the loader and kernel use the same LP64 ABI:
//! `a0` carries the first integer argument, `a1` the second, etc.
//! `kernel_main` (declared `extern "C" fn kernel_main(&BootInfo)`)
//! therefore expects `a0` to hold the BootInfo pointer — and the
//! C-style Rust `call` already places the first argument in `a0`.
//!
//! The trampoline's only jobs are therefore:
//!   * Disable firmware paging (CRMD.PG = 0) so that MMIO is reachable
//!     before the kernel installs its own page tables.
//!   * Install the kernel stack (`sp <- stack_top`).
//!   * Branch into `kernel_main` via `jirl ra, .+0`.
//!
//! Pre-conditions the kernel assumes but does *not* re-establish:
//!   * `CRMD.IE = 0` (interrupts masked).
//!   * `CRMD.PG = 0` (paging disabled — we cleared it here).
//!   * `PGD` / `PGDH` left in whatever state the firmware set;
//!     paging is off so they are irrelevant.

use nt61::kernel_main::kernel_main;

/// Switch to the kernel stack and jump to `kernel_main`. Never
/// returns.
#[cfg(target_arch = "loongarch64")]
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main(stack_top: u64, bi_ptr: u64) -> ! {
    // LoongArch64 QEMU/EDK2 firmware leaves paging enabled with
    // page tables that only map the kernel image range above
    // `0x80000000`. The LS7A MMIO region around `0x1FE0_0000`
    // (where the 8250/16550 UART lives) is NOT reachable through
    // `PGDH`, so the very first serial write in `kernel_main`
    // would fault with an "Address error exception" (`#ADE`,
    // Ecode `0x08`).
    //
    // We clear `CRMD.PG` here — *before* the kernel stack
    // pointer is installed and before any other code runs —
    // so paging is disabled when `kernel_main` makes its first
    // MMIO access. The kernel re-enables paging itself once it
    // has installed a fresh page table (`arch::paging::
    // load_page_root`).
    //
    // This asm runs at the trampoline level (not inside
    // `kernel_main`) so the LTO/DCE in `release` builds cannot
    // eliminate it: the trampoline is the only thing the loader
    // calls into and the asm is on the call graph's hot path.
    //
    // Register layout: the LP64 ABI places the first two integer
    // args in `$a0` and `$a1`. We must move them out of `$a0`
    // **before** issuing the CRMD `csrrd` (which clobbers `$a0`),
    // otherwise `move $sp, $a0` would install CRMD as the stack
    // pointer. We stash `stack_top` in the callee-saved `$s0`
    // register so paging can be disabled freely, then restore it
    // into `$sp`. `bi_ptr` stays in `$a1` (the kernel ABI second
    // argument, unused on entry — `kernel_main` only takes one).
    core::arch::asm!(
        "move  $s0, $a0",               // save stack_top in $s0
        "csrrd $a0, 0x0",               // read CRMD
        "bstrins.d $a0, $zero, 0x4, 0x4", // clear PG bit
        "csrwr $a0, 0x0",               // write CRMD (PG=0)
        "move  $sp, $s0",               // $sp = stack_top
        "move  $a0, $a1",               // $a0 = bi_ptr (kernel 1st arg)
        // Tail-call `kernel_main` via a register indirection so
        // the call graph reaches the kernel entry. We pass the
        // function pointer through a register because LLVM's
        // loongarch assembler rejects `jirl $ra, <sym>, 0` when
        // the function pointer is bound to a function item
        // directly.
        "jirl  $ra, $a2, 0",
        // Operand bindings. `$a2` is chosen for `kernel_main`
        // because it is caller-saved and not used by the prologue
        // above.
        in("$a0") stack_top,
        in("$a1") bi_ptr,
        in("$a2") kernel_main as *const () as u64,
        options(noreturn),
    );
}