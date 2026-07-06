//! LoongArch64 user-entry implementation.
//
//! Uses `ertn` (Exception Return) with ERA and CRMD to transition from
//! kernel mode (PPL=1) to user mode (PPL=0). The per-CPU area pointer
//! is stored in CSR tp (0x13).
//
//! ## CRMD register (CSR 0x0) layout
//
//! | Bits | Field | Description |
//! |-------|-------|-------------|
//! | 0    | DA    | Direct-mapped address space (0=kernel,1=user) |
//! | 1    | PG    | Paging enable (0=off, 1=on) |
//! | 2    | IE    | Interrupt enable (0=off) |
//! | 3:2  | PPL   | Previous privilege level (0=User, 1=Kernel) |
//
//! ## ERA register (CSR 0x6)
//
//! Holds the PC to return to after an exception/ERTN.
//
//! ## PGDL register (CSR 0x19)
//
//! Page table base address for direct-mapped low address region.
//! Write the user PGD physical address here to switch address spaces.

/// LoongArch64 user code segment (placeholder — no segment selectors on LA64).
const LOONGARCH_USER_CS: u16 = 0;

/// LoongArch64 user data segment (placeholder).
const LOONGARCH_USER_SS: u16 = 0;

/// User entry point virtual address.
const LOONGARCH_USER_ENTRY_RIP: u64 = crate::mm::constants::USER_ENTRY_RIP;

/// User stack base address.
const LOONGARCH_USER_STACK_BASE: u64 = crate::mm::constants::USER_STACK_BASE;

/// User stack top address.
const LOONGARCH_USER_STACK_TOP: u64 = crate::mm::constants::USER_STACK_TOP;

/// CRMD value for return to user mode.
/// PPL=0 (user), PG=0 (paging controlled by PGDL), IE=0 (interrupts disabled).
/// DA=0 means direct-mapped (not used when paging is on).
const LOONGARCH_CRMD_USER: u64 = 0x0;

/// CSR 0x0 — CRMD (Current Mode).
const CSR_CRMD: u64 = 0x0;

/// CSR 0x6 — ERA (Exception Return Address).
const CSR_ERA: u64 = 0x6;

/// CSR 0x19 — PGDL (Page Table Base, Direct-map Low).
const CSR_PGDL: u64 = 0x19;

/// CSR 0x13 — TP (Thread Pointer, per-CPU area).
const CSR_TP: u64 = 0x13;

// =====================================================================
// Per-CPU area helpers (tp CSR access)
// =====================================================================

/// Read the tp CSR.
#[inline(always)]
fn get_tp() -> u64 {
    let val: u64;
    unsafe {
        // CSR_TP (0x13) is encoded directly in the asm template.
        core::arch::asm!("csrrd {}, 0x13", out(reg) val, options(nostack));
    }
    val
}

// =====================================================================
// extern "Rust" implementations (required by arch/common/user_entry.rs)
// =====================================================================

/// Return the user code segment selector.
#[no_mangle]
pub fn __user_entry_user_cs() -> u16 {
    LOONGARCH_USER_CS
}

/// Return the user stack segment selector.
#[no_mangle]
pub fn __user_entry_user_ss() -> u16 {
    LOONGARCH_USER_SS
}

/// Return the user entry point virtual address.
#[no_mangle]
pub fn __user_entry_user_entry_rip() -> u64 {
    LOONGARCH_USER_ENTRY_RIP
}

/// Return the user stack base address.
#[no_mangle]
pub fn __user_entry_user_stack_base() -> u64 {
    LOONGARCH_USER_STACK_BASE
}

/// Return the user stack top address.
#[no_mangle]
pub fn __user_entry_user_stack_top() -> u64 {
    LOONGARCH_USER_STACK_TOP
}

/// Return the RFLAGS / CRMD value for user mode (interrupts disabled).
#[no_mangle]
pub fn __user_entry_user_rflags() -> u64 {
    LOONGARCH_CRMD_USER
}

/// Transfer control to user mode. Never returns.
#[no_mangle]
pub unsafe fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> ! {
    let rip_v = core::hint::black_box(user_rip);
    let rsp_v = core::hint::black_box(user_rsp);
    unsafe {
        // CSR immediate operands must be inlined into the asm template;
        // using operand placeholders makes the assembler think they are
        // general-purpose registers. The CSR numbers below (0x0 = CRMD,
        // 0x6 = ERA) are constants and therefore safe to embed.
        core::arch::asm!(
            // Set user stack pointer (SP is alias for R3)
            "move $sp, {rsp}",
            // Set ERA = user entry point
            "csrwr {rip}, 0x6",
            // Set CRMD = 0 (PPL=0=user, IE=0=interrupts off) via $zero.
            "csrwr $r0, 0x0",
            // Return to user mode
            "ertn",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            options(noreturn),
        );
    }
    #[allow(unreachable_code)]
    loop {
        crate::arch::halt();
    }
}

/// Store the kernel stack pointer in the per-CPU area.
#[no_mangle]
pub fn __user_entry_set_kernel_stack(sp: u64) {
    let base = get_tp();
    if base == 0 {
        return;
    }
    // kernel_rsp is at offset 0x08 in PerCpuArea.
    unsafe {
        let ptr = (base as *mut u64).add(1);
        ptr.write(sp);
    }
}

/// Read the kernel stack pointer from the per-CPU area.
#[no_mangle]
pub fn __user_entry_get_kernel_stack() -> u64 {
    let base = get_tp();
    if base == 0 {
        return 0;
    }
    unsafe {
        let ptr = (base as *const u64).add(1);
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
/// The kernel enters this function in kernel mode (PPL=1) with:
///   - tp CSR pointing at the per-CPU area
///   - MMU enabled with kernel page table active
///   - Interrupts disabled
///
/// ## Post-conditions
///
/// Control is transferred to user mode at `user_rip` with `user_rsp` as the
/// stack pointer. The function does not return.
#[inline(never)]
pub fn enter_first_user_thread(pgd_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    // 0. Publish the kernel stack so that any exception taken from user mode
    //    (syscall, page fault) can find a valid stack.
    let kernel_sp: u64;
    unsafe {
        core::arch::asm!("move {}, $sp", out(reg) kernel_sp, options(nostack, preserves_flags));
    }
    crate::arch::common::percpu::set_kernel_stack(kernel_sp);

    // 1. Load the user page table base into PGDL.
    //    The user address space must be set up in the page table at pgd_phys.
    unsafe {
        // CSR_PGDL = 0x19; the operand must be a literal in the asm
        // template, not an inlined register.
        core::arch::asm!(
            "csrwr {pgd}, 0x19",
            pgd = in(reg) pgd_phys,
            options(nostack),
        );
        // TLB invalidation: flush all entries since we switched page tables.
        core::arch::asm!("invtlb 0, $r0, $r0", options(nostack));
    }

    // 2. Transfer to user mode. ERA = entry point, CRMD.PPL=0 = user.
    unsafe {
        let rip_v = core::hint::black_box(user_rip);
        let rsp_v = core::hint::black_box(user_rsp);
        core::arch::asm!(
            // Set user stack
            "move $sp, {rsp}",
            // Set ERA = user entry point
            "csrwr {rip}, 0x6",
            // Set CRMD = 0 (PPL=0=user, IE=0=interrupts off) via $zero.
            "csrwr $r0, 0x0",
            // Return to user mode
            "ertn",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            options(noreturn),
        );
    }
    #[allow(unreachable_code)]
    loop {
        crate::arch::halt();
    }
}
