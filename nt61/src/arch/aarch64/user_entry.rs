//! AArch64 user-entry implementation.
//
//! Uses `eret` with SPSR_EL1 and ELR_EL1 to transition from EL1 (kernel)
//! to EL0 (user mode). The kernel stack is stored in the per-CPU area
//! via TPIDR_EL1; the user stack is set in SP_EL0.
//
//! ## Registers used
//
//! | Register | Purpose |
//! |----------|---------|
//! | SP_EL0  | User stack pointer (user_rsp) |
//! | ELR_EL1 | Exception return address (user_rip) |
//! | SPSR_EL1 | Processor state on return to EL0 |
//
//! ## SPSR_EL1 value
//
//! `0x3C5` encodes:
//!   - M[4:0] = 0x05 = AArch64, EL1h, SP0 (exception from EL1, return to EL0)
//!   - D, A, I, F = 1 = all interrupts masked (IDT not ready yet)

use crate::arch::common::percpu::PerCpuArea;

/// Per-CPU area TPIDR_EL1 access (matches percpu_impl.rs layout).
const PER_CPU_TPIDR_EL1_OFFSET_KERNEL_SP: usize = 1; // u64 at offset 0x08

/// AArch64 EL0 code segment selector (placeholder — AArch64 uses ESR to
/// determine the target exception level, not a segment selector).
const AARCH64_USER_CS: u16 = 0x11;

/// AArch64 EL0 data segment selector (placeholder).
const AARCH64_USER_SS: u16 = 0x13;

/// User entry point virtual address.
const AARCH64_USER_ENTRY_RIP: u64 = crate::mm::constants::USER_ENTRY_RIP;

/// User stack base address.
const AARCH64_USER_STACK_BASE: u64 = crate::mm::constants::USER_STACK_BASE;

/// User stack top address.
const AARCH64_USER_STACK_TOP: u64 = crate::mm::constants::USER_STACK_TOP;

/// SPSR_EL1 value for return to EL0 with all interrupts masked.
/// M = 0x05 (AArch64, EL1h → EL0), DAIF = 0xF (all masked).
const AARCH64_SPSR_EL1: u64 = 0x3C5;

// =====================================================================
// Per-CPU area helpers
// =====================================================================

/// Read TPIDR_EL1 (per-CPU area base).
#[inline(always)]
fn get_tpidr_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) val, options(nostack));
    }
    val
}

// =====================================================================
// extern "Rust" implementations (required by arch/common/user_entry.rs)
// =====================================================================

/// Return the user code segment selector.
#[no_mangle]
pub fn __user_entry_user_cs() -> u16 {
    AARCH64_USER_CS
}

/// Return the user stack segment selector.
#[no_mangle]
pub fn __user_entry_user_ss() -> u16 {
    AARCH64_USER_SS
}

/// Return the user entry point virtual address.
#[no_mangle]
pub fn __user_entry_user_entry_rip() -> u64 {
    AARCH64_USER_ENTRY_RIP
}

/// Return the user stack base address.
#[no_mangle]
pub fn __user_entry_user_stack_base() -> u64 {
    AARCH64_USER_STACK_BASE
}

/// Return the user stack top address.
#[no_mangle]
pub fn __user_entry_user_stack_top() -> u64 {
    AARCH64_USER_STACK_TOP
}

/// Return the RFLAGS / PSTATE value for user mode (interrupts disabled).
#[no_mangle]
pub fn __user_entry_user_rflags() -> u64 {
    AARCH64_SPSR_EL1
}

/// Transfer control to EL0. Never returns.
#[no_mangle]
pub unsafe fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> ! {
    // Force rustc to allocate fresh registers for the operands.
    let rip_v = core::hint::black_box(user_rip);
    let rsp_v = core::hint::black_box(user_rsp);
    unsafe {
        core::arch::asm!(
            // Set SP_EL0 (user stack) and ELR_EL1 (entry point).
            // SPSR_EL1 is set via the const operand below.
            "mov sp, {rsp}",
            "msr elr_el1, {rip}",
            "eret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            in("x0") AARCH64_SPSR_EL1,
            options(noreturn),
        );
    }
    // Suppress unreachable-code warning.
    #[allow(unreachable_code)]
    loop {
        crate::arch::halt();
    }
}

/// Store the kernel stack pointer in the per-CPU area.
#[no_mangle]
pub fn __user_entry_set_kernel_stack(sp: u64) {
    let base = get_tpidr_el1();
    if base == 0 {
        return;
    }
    unsafe {
        let ptr = (base as *mut u64).add(PER_CPU_TPIDR_EL1_OFFSET_KERNEL_SP);
        ptr.write(sp);
    }
}

/// Read the kernel stack pointer from the per-CPU area.
#[no_mangle]
pub fn __user_entry_get_kernel_stack() -> u64 {
    let base = get_tpidr_el1();
    if base == 0 {
        return 0;
    }
    unsafe {
        let ptr = (base as *const u64).add(PER_CPU_TPIDR_EL1_OFFSET_KERNEL_SP);
        ptr.read()
    }
}

// =====================================================================
// enter_first_user_thread — end-to-end first user entry
// =====================================================================

/// Enter the first user thread end-to-end.
///
/// ## Pre-conditions
///
/// The kernel enters this function in EL1 with:
///   - TPIDR_EL1 pointing at the per-CPU area
///   - MMU enabled with kernel page table active
///   - Interrupts disabled
///
/// ## Post-conditions
///
/// Control is transferred to EL0 at `user_rip` with `user_rsp` as the
/// stack pointer. The function does not return.
#[inline(never)]
pub fn enter_first_user_thread(pml4_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    // 0. Publish the kernel stack so that any exception taken from EL0
    //    (syscall, page fault) can find a valid stack.
    let kernel_sp: u64;
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) kernel_sp, options(nostack, preserves_flags));
    }
    crate::arch::common::percpu::set_kernel_stack(kernel_sp);

    // 1. Switch to the user page table.
    //    On aarch64 we use TTBR0_EL1 for the user address space.
    crate::mm::vas::attach_process(pml4_phys);

    // 2. Transfer to EL0. The eret instruction restores SPSR_EL1
    //    (interrupts remain masked) and jumps to ELR_EL1.
    unsafe {
        let rip_v = core::hint::black_box(user_rip);
        let rsp_v = core::hint::black_box(user_rsp);
        core::arch::asm!(
            "mov sp, {rsp}",
            "msr elr_el1, {rip}",
            // SPSR_EL1: M=EL0, all interrupts masked
            "msr spsr_el1, {spsr}",
            "eret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            spsr = in(reg) AARCH64_SPSR_EL1,
            options(noreturn),
        );
    }
    #[allow(unreachable_code)]
    loop {
        crate::arch::halt();
    }
}
