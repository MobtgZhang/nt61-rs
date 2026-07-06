//! AArch64 OS Loader trampoline.
//!
//! On AArch64 the loader and kernel use the same AAPCS64 ABI, so
//! `kernel_main` (declared `extern "C" fn kernel_main(&BootInfo)`)
//! expects `x0` to hold the BootInfo pointer. The C-style Rust
//! `call` already places the first argument in `x0` per AAPCS64,
//! so the only thing the trampoline has to do is install the
//! kernel stack and jump to the kernel symbol.
//!
//! Convention notes:
//!   * `sp` is the stack pointer. AAPCS64 says the *callee* owns
//!     the stack below `sp`, so the kernel can write its first
//!     frame at `[sp]` without SPINC.
//!   * `x0` is the first integer argument / return value register.
//!     We pass `bi_ptr` in `x0`; the kernel returns `!`.
//!   * The kernel assumes interrupts are masked (`DAIF.I = 1`)
//!     and that the page-table state is "boot-strapped"; the
//!     firmware normally leaves the MMU on, so we do not touch
//!     `sctlr_el1` here.
//!
//! Inline assembly uses `sym` to take the address of
//! `kernel_main`; the linker resolves it during final link.

use nt61::kernel_main::kernel_main;

/// Switch to the kernel stack and jump to `kernel_main`. Never
/// returns.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main(stack_top: u64, bi_ptr: u64) -> ! {
    // We invoke `kernel_main` as a normal C-ABI call by storing
    // its address in a function pointer and using `blr` through
    // a register. The `sym` operand is not directly usable inside
    // a `blr` instruction, and COFF does not support the
    // `movw`-style symbol relocation. Using a function pointer
    // keeps both the assembler and the linker happy.
    //
    // We declare a thin shim with the same C-ABI signature as the
    // real kernel entry (`fn(u64) -> !`) and have the shim call
    // `kernel_main` with the supplied pointer cast to `&BootInfo`.
    // That gives us a `fn(u64) -> !` value we can pass to the
    // inline asm without needing to take the address of a
    // function item.
    extern "C" fn km_shim(bi_ptr: u64) -> ! {
        // SAFETY: the caller of `call_kernel_main_from_loader`
        // passes a valid `&BootInfo` pointer.
        unsafe { kernel_main(&*(bi_ptr as *const nt61::kernel_main::BootInfo)) }
    }
    let km_addr: u64 = km_shim as usize as u64;
    core::arch::asm!(
        // 1. Install the kernel stack *before* we touch `x0` so an
        //    incoming IRQ cannot observe a half-converted state.
        "mov sp, {sp}",
        // 2. Place the BootInfo pointer in `x0` (AAPCS64 first
        //    integer argument register).
        "mov x0, {bi}",
        // 3. Branch to the kernel. The function pointer is loaded
        //    into a register so `blr` has a register operand (the
        //    only addressing mode AArch64 supports here).
        "mov x16, {km}",
        "blr x16",
        sp = in(reg) stack_top,
        bi = in(reg) bi_ptr,
        km = in(reg) km_addr,
        options(noreturn),
    );
}
