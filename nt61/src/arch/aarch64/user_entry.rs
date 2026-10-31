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

/// Per-CPU area TPIDR_EL1 access (matches percpu_impl.rs layout).
const PER_CPU_TPIDR_EL1_OFFSET_KERNEL_SP: usize = 1; // u64 at offset 0x08

/// AArch64 EL0 code segment selector (placeholder — AArch64 uses ESR to
/// determine the target exception level, not a segment selector).
///
/// AArch64 has no segment selectors at all: the privilege level is
/// encoded in `SPSR_EL1` and selected by `eret`, and user/kernel code
/// share one flat address space per TTBR. These constants are opaque
/// placeholder tokens kept only so the arch-generic entry layer can
/// fill its `u16` selector slots; they MUST NOT be compared against
/// x86 selector values or used to decide privilege — use
/// `AARCH64_SPSR_EL0T` for that.
const AARCH64_USER_CS_PLACEHOLDER: u16 = 0x11;

/// AArch64 EL0 data segment selector (placeholder).
///
/// See `AARCH64_USER_CS_PLACEHOLDER`: same caveat applies.
const AARCH64_USER_SS_PLACEHOLDER: u16 = 0x13;

/// User entry point virtual address.
const AARCH64_USER_ENTRY_RIP: u64 = crate::mm::constants::USER_ENTRY_RIP;

/// User stack base address.
const AARCH64_USER_STACK_BASE: u64 = crate::mm::constants::USER_STACK_BASE;

/// User stack top address.
const AARCH64_USER_STACK_TOP: u64 = crate::mm::constants::USER_STACK_TOP;

/// SPSR_EL1 value for return to EL0t.
/// M[4:0] = 0b00000 (EL0t, AArch64); DAIF bits 9:6 all set (masked)
/// because the GIC is not yet ready when user mode is entered and
/// unmasked pseudo-interrupts would be taken immediately.
const AARCH64_SPSR_EL0T: u64 = 0x3C0;

// =====================================================================
// Per-CPU area helpers
// =====================================================================

/// read TPIDR_EL1 (per-CPU area base).
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
    AARCH64_USER_CS_PLACEHOLDER
}

/// Return the user stack segment selector.
#[no_mangle]
pub fn __user_entry_user_ss() -> u16 {
    AARCH64_USER_SS_PLACEHOLDER
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
    AARCH64_SPSR_EL0T
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Transfer control to EL0. Never returns.
#[no_mangle]
pub unsafe fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> ! {
    // Force rustc to allocate fresh registers for the operands.
    let rip_v = core::hint::black_box(user_rip);
    let rsp_v = core::hint::black_box(user_rsp);
    unsafe {
        core::arch::asm!(
            // Set SP_EL0 (user stack), SPSR_EL1 and ELR_EL1.
            //
            // NOTE: we deliberately do not write SP_EL1 here. On this
            // QEMU build (10.2.1, cortex-a57) the valid encoding of
            // "msr sp_el1, <Xt>" executed at EL1 raises a synchronous
            // exception (EC=0, ISS=0, FAR=0). The write was redundant
            // anyway: the kernel runs at EL1h, so the current SP is
            // already SP_EL1 and already holds this thread's kernel
            // stack, which is what EL0 exceptions must land on.
            "msr sp_el0, {rsp}",
            "msr spsr_el1, {spsr}",
            "msr elr_el1, {rip}",
            "isb",
            "eret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            spsr = in(reg) AARCH64_SPSR_EL0T,
            options(noreturn),
        );
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

/// read the kernel stack pointer from the per-CPU area.
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
/// control is transferred to EL0 at `user_rip` with `user_rsp` as the
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
    // NOTE: do not write SP_EL1 here. This QEMU raises a synchronous
    // exception (EC=0, ISS=0) on "msr sp_el1" executed at EL1, and the
    // write is redundant: the kernel runs at EL1h, so the current SP
    // already is SP_EL1 and already holds this thread's kernel stack.

    // 1. Switch to the user page table.
    //    On aarch64 we use TTBR0_EL1 for the user address space.
    crate::mm::vas::attach_process(pml4_phys);

    // 2. Transfer to EL0. The eret instruction restores SPSR_EL1
    //    (interrupts remain masked) and jumps to ELR_EL1.
    unsafe {
        let rip_v = core::hint::black_box(user_rip);
        let rsp_v = core::hint::black_box(user_rsp);
        core::arch::asm!(
            "msr sp_el0, {rsp}",
            "msr elr_el1, {rip}",
            // SPSR_EL1: M=EL0t, DAIF all masked (GIC not ready)
            "msr spsr_el1, {spsr}",
            "isb",
            "eret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            spsr = in(reg) AARCH64_SPSR_EL0T,
            options(noreturn),
        );
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn __user_entry_enter_first(root_table_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    enter_first_user_thread(root_table_phys, user_rip, user_rsp)
}
