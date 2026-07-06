//! AArch64 Exception Vector Table
//!
//! Provides the 2 KiB exception vector table required by ARMv8-A. Each
//! entry is exactly 128 bytes wide and the table itself must be aligned
//! to 2 KiB (i.e. aligned to 11 bits). On exception entry the CPU jumps
//! to the entry based on the exception class:
//!
//!   * Sync / IRQ / FIQ / SError
//!   * Current EL with SP0 (using SP_EL0) vs SPx (using SP_ELx)
//!   * Lower EL (EL0) executing in AArch64 vs AArch32
//!
//! For the bootstrap we install all 16 entries as stubs that save the
//! general-purpose registers onto a per-CPU kernel stack, call the Rust
//! dispatcher in `arch::aarch64::trap`, and then `eret` back to the
//! caller. The detailed handlers (sync / IRQ / FIQ / SError) live in
//! Rust and dispatch by `ESR_EL1.EC` for synchronous exceptions.
//!
//! Implementation note: the assembly is embedded as a `global_asm!`
//! blob so that no external `.S` file is required (matches the
//! convention used by the rest of the architecture layer in this
//! crate — see `x86_64/idt_stubs.rs` and `riscv64/idt.rs`).

use core::arch::global_asm;

global_asm!(
    // Vector table: 16 entries of 128 bytes each = 2048 bytes total.
    // The table must be aligned to 2 KiB; we use .align 11 (2^11 = 2048).
    ".align 11",
    ".global exception_vector",
    "exception_vector:",

    // ============================================================
    //   Current EL with SP0 — kernel saved on its own stack
    // ============================================================
    ".align 7",
    "current_el_sp0_sync:",
    "  b current_el_sp0_sync_stub",

    ".align 7",
    "current_el_sp0_irq:",
    "  b current_el_sp0_irq_stub",

    ".align 7",
    "current_el_sp0_fiq:",
    "  b current_el_sp0_fiq_stub",

    ".align 7",
    "current_el_sp0_serror:",
    "  b current_el_sp0_serror_stub",

    // ============================================================
    //   Current EL with SPx — kernel using current SP
    // ============================================================
    ".align 7",
    "current_el_spx_sync:",
    "  b current_el_spx_sync_stub",

    ".align 7",
    "current_el_spx_irq:",
    "  b current_el_spx_irq_stub",

    ".align 7",
    "current_el_spx_fiq:",
    "  b current_el_spx_fiq_stub",

    ".align 7",
    "current_el_spx_serror:",
    "  b current_el_spx_serror_stub",

    // ============================================================
    //   Lower EL using AArch64 (EL0 / 64-bit) — user-mode exceptions
    // ============================================================
    ".align 7",
    "lower_el_aarch64_sync:",
    "  b lower_el_aarch64_sync_stub",

    ".align 7",
    "lower_el_aarch64_irq:",
    "  b lower_el_aarch64_irq_stub",

    ".align 7",
    "lower_el_aarch64_fiq:",
    "  b lower_el_aarch64_fiq_stub",

    ".align 7",
    "lower_el_aarch64_serror:",
    "  b lower_el_aarch64_serror_stub",

    // ============================================================
    //   Lower EL using AArch32 — not supported, loop forever
    // ============================================================
    ".align 7",
    "lower_el_aarch32_sync:",
    "  b .",

    ".align 7",
    "lower_el_aarch32_irq:",
    "  b .",

    ".align 7",
    "lower_el_aarch32_fiq:",
    "  b .",

    ".align 7",
    "lower_el_aarch32_serror:",
    "  b .",

    // ============================================================
    //   Stubs — saved-context layout
    // ============================================================
    //. The trap frame layout must match `arch::aarch64::trap::TrapFrame`.
    //. Each stub allocates one stack frame, saves x0..x30, plus pc/pstate,
    //. calls the Rust dispatcher, then restores the registers and erets.
    //
    //. Offsets (matches struct TrapFrame field order):
    //.   [sp, #0x000]  x0
    //.   [sp, #0x008]  x1
    //.   ...
    //.   [sp, #0x0F0]  x30
    //.   [sp, #0x0F8]  sp (the original SP)
    //.   [sp, #0x100]  elr_el1 (PC)
    //.   [sp, #0x108]  spsr_el1 (PSTATE)
    //.   [sp, #0x110]  esr_el1
    //.   [sp, #0x118]  far_el1
    //.   [sp, #0x120]  exception_class
    //.   [sp, #0x128]  reserved

    ".macro save_context kind",
    "  sub  sp, sp, #0x130",
    "  stp  x0, x1, [sp, #0x000]",
    "  stp  x2, x3, [sp, #0x010]",
    "  stp  x4, x5, [sp, #0x020]",
    "  stp  x6, x7, [sp, #0x030]",
    "  stp  x8, x9, [sp, #0x040]",
    "  stp  x10, x11, [sp, #0x050]",
    "  stp  x12, x13, [sp, #0x060]",
    "  stp  x14, x15, [sp, #0x070]",
    "  stp  x16, x17, [sp, #0x080]",
    "  stp  x18, x19, [sp, #0x090]",
    "  stp  x20, x21, [sp, #0x0A0]",
    "  stp  x22, x23, [sp, #0x0B0]",
    "  stp  x24, x25, [sp, #0x0C0]",
    "  stp  x26, x27, [sp, #0x0D0]",
    "  stp  x28, x29, [sp, #0x0E0]",
    "  str  x30, [sp, #0x0F0]",
    "  add  x9, sp, #0x130",
    "  str  x9, [sp, #0x0F8]",
    "  mrs  x10, elr_el1",
    "  mrs  x11, spsr_el1",
    "  mrs  x12, esr_el1",
    "  mrs  x13, far_el1",
    "  stp  x10, x11, [sp, #0x100]",
    "  stp  x12, x13, [sp, #0x110]",
    "  mov  x0, #\\kind",
    "  mov  x1, sp",
    ".endm",

    ".macro restore_context",
    "  ldp  x0, x1, [sp, #0x000]",
    "  ldp  x2, x3, [sp, #0x010]",
    "  ldp  x4, x5, [sp, #0x020]",
    "  ldp  x6, x7, [sp, #0x030]",
    "  ldp  x8, x9, [sp, #0x040]",
    "  ldp  x10, x11, [sp, #0x050]",
    "  ldp  x12, x13, [sp, #0x060]",
    "  ldp  x14, x15, [sp, #0x070]",
    "  ldp  x16, x17, [sp, #0x080]",
    "  ldp  x18, x19, [sp, #0x090]",
    "  ldp  x20, x21, [sp, #0x0A0]",
    "  ldp  x22, x23, [sp, #0x0B0]",
    "  ldp  x24, x25, [sp, #0x0C0]",
    "  ldp  x26, x27, [sp, #0x0D0]",
    "  ldp  x28, x29, [sp, #0x0E0]",
    "  ldr  x30, [sp, #0x0F0]",
    "  add  sp, sp, #0x130",
    ".endm",

    // ============================================================
    //   Stub bodies — each calls into `arch_aarch64_trap_dispatch`
    // ============================================================
    ".global current_el_sp0_sync_stub",
    "current_el_sp0_sync_stub:",
    "  save_context 0",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_sp0_irq_stub",
    "current_el_sp0_irq_stub:",
    "  save_context 1",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_sp0_fiq_stub",
    "current_el_sp0_fiq_stub:",
    "  save_context 2",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_sp0_serror_stub",
    "current_el_sp0_serror_stub:",
    "  save_context 3",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_spx_sync_stub",
    "current_el_spx_sync_stub:",
    "  save_context 4",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_spx_irq_stub",
    "current_el_spx_irq_stub:",
    "  save_context 5",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_spx_fiq_stub",
    "current_el_spx_fiq_stub:",
    "  save_context 6",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global current_el_spx_serror_stub",
    "current_el_spx_serror_stub:",
    "  save_context 7",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global lower_el_aarch64_sync_stub",
    "lower_el_aarch64_sync_stub:",
    "  save_context 8",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global lower_el_aarch64_irq_stub",
    "lower_el_aarch64_irq_stub:",
    "  save_context 9",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global lower_el_aarch64_fiq_stub",
    "lower_el_aarch64_fiq_stub:",
    "  save_context 10",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",

    ".global lower_el_aarch64_serror_stub",
    "lower_el_aarch64_serror_stub:",
    "  save_context 11",
    "  bl   arch_aarch64_trap_dispatch",
    "  restore_context",
    "  eret",
);

extern "C" {
    /// The 2 KiB exception vector table. The CPU loads this address
    /// into `VBAR_EL1` during `init()`.
    fn exception_vector();
}

/// Install the exception vector table at EL1.
pub fn init() {
    unsafe {
        let v: u64 = exception_vector as u64;
        core::arch::asm!("msr VBAR_EL1, {}", in(reg) v, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
}
