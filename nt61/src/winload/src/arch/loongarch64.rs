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

const CRMD_DA: u64 = 1 << 3;
const CRMD_PG: u64 = 1 << 4;

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Switch to the kernel stack and jump to `kernel_main`. Never
/// returns.
#[cfg(target_arch = "loongarch64")]
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main(stack_top: u64, bi_ptr: u64) -> ! {
    write_com1_marker(b"[TRAMPOLINE-LOONGARCH]\r\n");
    // The firmware page table does not cover every physical page used by
    // the kernel's early allocator. Turn translation off before handing
    // control to the kernel; the kernel installs its own PGDH-rooted
    // tables and enables paging only after mapping the bootstrap memory.
    let mut crmd: u64;
    core::arch::asm!(
        "csrrd {0}, 0x0",
        out(reg) crmd,
        options(nostack)
    );
    crmd &= !CRMD_PG;
    crmd |= CRMD_DA;
    core::arch::asm!(
        "csrwr {0}, 0x0",
        in(reg) crmd,
        options(nostack)
    );
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
        "nop",
        // Operand bindings. `$a2` is chosen for `kernel_main`
        // because it is caller-saved and not used by the prologue
        // above.
        in("$a0") stack_top,
        in("$a1") bi_ptr,
        in("$a2") kernel_main as *const () as u64,
    );

    core::arch::asm!(
        "move  $sp, $s0",               // $sp = stack_top
        "move  $a0, $a1",               // $a0 = bi_ptr (kernel 1st arg)
        "jirl  $ra, $a2, 0",
        in("$s0") stack_top,
        in("$a1") bi_ptr,
        in("$a2") kernel_main as *const () as u64,
        options(noreturn),
    );
}

pub fn install_kernel_handoff() -> u64 {
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn launch_kernel(stack_top: u64, bi_ptr: u64, _ntoskrnl_base: u64) -> ! {
    call_kernel_main(stack_top, bi_ptr)
}

pub fn write_debug_marker(_bytes: &[u8]) {}

const UART0_BASE: u64 = 0x1FE0_01E0;
const UART_THR: u64 = 0;
const UART_LSR: u64 = 5;
const UART_LSR_THR_EMPTY: u8 = 0x20;

pub fn write_com1_marker(bytes: &[u8]) {
    for byte in bytes {
        unsafe {
            while core::ptr::read_volatile((UART0_BASE + UART_LSR) as *const u8)
                & UART_LSR_THR_EMPTY
                == 0
            {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile((UART0_BASE + UART_THR) as *mut u8, *byte);
        }
    }
}
