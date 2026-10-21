//! RISC-V 64-bit user-entry implementation.
//
//! Uses `sret` with `sepc` and `sstatus` to transition from S-mode (kernel)
//! to U-mode (user mode). The kernel stack pointer is stored in the per-CPU
//! area via the `tp` register.
//
//! ## Registers used
//
//! | Register | Purpose |
//! |----------|---------|
//! | tp (x4) | Per-CPU area pointer (set by percpu_impl) |
//! | sepc    | Supervisor exception PC (user entry point) |
//! | sstatus | Supervisor status (SPIE=1, SPP=0, SIE=0) |
//
//! ## sstatus value
//
//! `RISCV_SSTATUS` is assembled from the named constants in
//! `csr::sstatus` and encodes:
//!   - SPP = 0   → previous mode was U-mode
//!   - SPIE = 1  → interrupts enabled on return
//!   - SIE = 0   → interrupts disabled in user mode itself
//!   - UXL = 2   → U-mode executes with XLEN = 64
//!   - FS = 2    → floating-point state clean (FPU usable)
//!   - XS = 0    → no user extensions active
//!   - SUM = 0   → S-mode cannot access U-mode pages
//
//! ## satp mode
//
//! For Sv39/Sv48, satp[63:60] = 8 (mode = 8 = Sv39) or 9 (Sv48).
//! The actual page table root is in satp[43:0].

/// RISC-V U-mode code segment selector (placeholder — RISC-V uses
/// the privilege mode, not segment selectors, to determine execution level).
const RISCV_USER_CS: u16 = 0;

/// RISC-V U-mode data segment selector (placeholder).
const RISCV_USER_SS: u16 = 0;

/// User entry point virtual address.
const RISCV_USER_ENTRY_RIP: u64 = crate::mm::constants::USER_ENTRY_RIP;

/// User stack base address.
const RISCV_USER_STACK_BASE: u64 = crate::mm::constants::USER_STACK_BASE;

/// User stack top address.
const RISCV_USER_STACK_TOP: u64 = crate::mm::constants::USER_STACK_TOP;

/// sstatus value for return to U-mode.
/// SPP=0 (previous mode was U), SPIE=1, SIE=0 (interrupts disabled),
/// UXL=2 (U-mode XLEN=64), FS=clean (FPU usable). The previous
/// hand-computed value placed no UXL field at all and set stray
/// reserved bits, which made every Ring-3 thread run as RV32 under
/// QEMU and fault immediately.
const RISCV_SSTATUS: u64 = crate::arch::riscv64::csr::sstatus::UXL_64
    | crate::arch::riscv64::csr::sstatus::SPIE
    | (0b10 << 13);

// =====================================================================
// Per-CPU area helpers (tp register access)
// =====================================================================

/// read the `tp` (thread pointer) CSR.
#[inline(always)]
fn get_tp() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) val, options(nostack));
    }
    val
}

// =====================================================================
// extern "Rust" implementations (required by arch/common/user_entry.rs)
// =====================================================================

/// Return the user code segment selector.
#[no_mangle]
pub fn __user_entry_user_cs() -> u16 {
    RISCV_USER_CS
}

/// Return the user stack segment selector.
#[no_mangle]
pub fn __user_entry_user_ss() -> u16 {
    RISCV_USER_SS
}

/// Return the user entry point virtual address.
#[no_mangle]
pub fn __user_entry_user_entry_rip() -> u64 {
    RISCV_USER_ENTRY_RIP
}

/// Return the user stack base address.
#[no_mangle]
pub fn __user_entry_user_stack_base() -> u64 {
    RISCV_USER_STACK_BASE
}

/// Return the user stack top address.
#[no_mangle]
pub fn __user_entry_user_stack_top() -> u64 {
    RISCV_USER_STACK_TOP
}

/// Return the RFLAGS / sstatus value for user mode.
#[no_mangle]
pub fn __user_entry_user_rflags() -> u64 {
    RISCV_SSTATUS
}

/// Transfer control to U-mode. Never returns.
#[no_mangle]
pub unsafe fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> ! {
    let rip_v = core::hint::black_box(user_rip);
    let rsp_v = core::hint::black_box(user_rsp);
    unsafe {
        core::arch::asm!(
            // Set sepc = user entry point
            "csrw sepc, {rip}",
            // Set sstatus: SPP=0 (return to U-mode), SPIE=1, SIE=0
            "csrw sstatus, {sstatus}",
            // Set sp = user stack
            "mv sp, {rsp}",
            // Return to U-mode
            "sret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            sstatus = in(reg) RISCV_SSTATUS,
            options(noreturn),
        );
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

/// read the kernel stack pointer from the per-CPU area.
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
/// The kernel enters this function in S-mode with:
///   - `tp` register pointing at the per-CPU area
///   - MMU enabled with kernel page table active
///   - Interrupts disabled
///
/// ## Post-conditions
///
/// control is transferred to U-mode at `user_rip` with `user_rsp` as the
/// stack pointer. The function does not return.
#[inline(never)]
pub fn enter_first_user_thread(satp_root: u64, user_rip: u64, user_rsp: u64) -> ! {
    // 0. Publish the kernel stack so that any exception taken from U-mode
    //    (syscall, page fault) can find a valid stack.
    let kernel_sp: u64;
    unsafe {
        core::arch::asm!("mv {}, sp", out(reg) kernel_sp, options(nostack, preserves_flags));
    }
    crate::arch::common::percpu::set_kernel_stack(kernel_sp);

    // 0.5 Publish the kernel stack into sscratch so that the first
    //     trap from user mode can swap sp with a valid kernel stack.
    //     Without this, stvec_trap would read sscratch = 0 and the
    //     CPU would fault with a zero stack pointer.
    unsafe {
        core::arch::asm!(
            "csrw sscratch, {val}",
            val = in(reg) kernel_sp,
            options(nostack),
        );
    }

    // 1. Switch to the user address space via the shared vas layer.
    //    attach_process() encodes the Sv39 satp value (MODE=8, PPN
    //    = satp_root >> 12), issues the sfence.vma barrier, and
    //    publishes the per-CPU root-table bookkeeping -- exactly
    //    what the aarch64 TTBR0 path does via its own
    //    load_page_root(). Writing a raw physical address directly
    //    into satp would leave MODE = 0 (bare mode), disabling the
    //    MMU and faulting on the first U-mode instruction fetch.
    crate::mm::vas::attach_process(satp_root);

    // 2. Transfer to U-mode. sret jumps to sepc with sstatus applied.
    unsafe {
        let rip_v = core::hint::black_box(user_rip);
        let rsp_v = core::hint::black_box(user_rsp);
        core::arch::asm!(
            "csrw sepc, {rip}",
            "csrw sstatus, {sstatus}",
            "mv sp, {rsp}",
            "sret",
            rip = in(reg) rip_v,
            rsp = in(reg) rsp_v,
            sstatus = in(reg) RISCV_SSTATUS,
            options(noreturn),
        );
    }
}

pub unsafe fn __user_entry_enter_first(root_table_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    enter_first_user_thread(root_table_phys, user_rip, user_rsp)
}
