//! Architecture-common user-entry trait and public API.
//
//! This module defines the `UserEntryArch` trait that each architecture
//! must implement for Ring-0 → Ring-3 transitions. It also provides the
//! `extern "Rust"` declarations that each arch's `user_entry.rs` must
//! provide, and the public API functions that callers use.
//
//! ## Design
//
//! Each architecture needs to:
//! 1. Define constants for user-mode segments and addresses
//! 2. Implement the `enter_user_mode` function using the platform's
//!    return-from-exception instruction (e.g. `iretq`, `eret`, `sret`, `ertn`)
//! 3. Provide `set_kernel_stack` / `get_kernel_stack` to manage the
//!    kernel stack stored in the per-CPU area
//
//! ## Boot flow
//
//! `enter_first_user_thread()` in the arch-specific `user_entry.rs`:
//!   1. Publishes the kernel stack into the per-CPU area
//!   2. Switches to the user page table (CR3 / TTBR0_EL1 / satp / Direct mapping)
//!   3. Calls `enter_user_mode(user_rip, user_rsp)` which does the actual
//!      privilege switch and never returns

// =====================================================================
// Trait definition
// =====================================================================

/// Trait that each architecture must implement to support Ring-0 → Ring-3
/// transitions.
pub trait UserEntryArch {
    /// User code segment selector.
    const USER_CS: u16;

    /// User stack segment selector.
    /// On some architectures (e.g. AArch64) this is implicit and may be 0.
    const USER_SS: u16;

    /// User-mode entry point virtual address.
    const USER_ENTRY_RIP: u64;

    /// User stack region base virtual address.
    const USER_STACK_BASE: u64;

    /// User stack region top (inclusive guard page below this).
    const USER_STACK_TOP: u64;

    /// RFLAGS / PSTATE / status register value for user mode.
    /// Interrupts are disabled on entry to give the kernel time to
    /// bring up the IDT before delivering IRQs to Ring 3.
    const USER_RFLAGS: u64 = 0x002;

    /// Transfer control to a user-mode thread. Never returns.
    ///
    /// ## Arguments
    /// * `user_rip` — user-mode entry point virtual address
    /// * `user_rsp` — user-mode stack pointer (typically `USER_STACK_TOP`)
    ///
    /// ## Preconditions
    /// * The per-CPU kernel stack must have been set via `set_kernel_stack`
    /// * The user page table must be active
    /// * Interrupts must be disabled
    unsafe fn enter_user_mode(user_rip: u64, user_rsp: u64) -> !;

    /// Store a kernel stack pointer in the current CPU's per-CPU area.
    /// This value is loaded on entry from user mode to handle syscalls.
    fn set_kernel_stack(sp: u64);

    /// Read the kernel stack pointer from the current CPU's per-CPU area.
    fn get_kernel_stack() -> u64;
}

// =====================================================================
// extern "Rust" declarations — provided by each arch's user_entry.rs
// =====================================================================

unsafe extern "Rust" {
    /// Return the user code segment selector.
    fn __user_entry_user_cs() -> u16;

    /// Return the user stack segment selector.
    fn __user_entry_user_ss() -> u16;

    /// Return the user entry point virtual address.
    fn __user_entry_user_entry_rip() -> u64;

    /// Return the user stack base address.
    fn __user_entry_user_stack_base() -> u64;

    /// Return the user stack top address.
    fn __user_entry_user_stack_top() -> u64;

    /// Return the RFLAGS / PSTATE value for user mode (interrupts disabled).
    fn __user_entry_user_rflags() -> u64;

    /// Transfer control to a user-mode thread. Never returns.
    fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> !;

    /// Store the kernel stack pointer in the per-CPU area.
    fn __user_entry_set_kernel_stack(sp: u64);

    /// Read the kernel stack pointer from the per-CPU area.
    fn __user_entry_get_kernel_stack() -> u64;
}

// =====================================================================
// Public API — delegates to arch-specific implementations
// =====================================================================

/// Return the user code segment selector.
#[inline(always)]
pub fn user_cs() -> u16 {
    unsafe { __user_entry_user_cs() }
}

/// Return the user stack segment selector.
#[inline(always)]
pub fn user_ss() -> u16 {
    unsafe { __user_entry_user_ss() }
}

/// Return the user entry point virtual address.
#[inline(always)]
pub fn user_entry_rip() -> u64 {
    unsafe { __user_entry_user_entry_rip() }
}

/// Return the user stack base address.
#[inline(always)]
pub fn user_stack_base() -> u64 {
    unsafe { __user_entry_user_stack_base() }
}

/// Return the user stack top address.
#[inline(always)]
pub fn user_stack_top() -> u64 {
    unsafe { __user_entry_user_stack_top() }
}

/// Return the RFLAGS / PSTATE value for user mode.
#[inline(always)]
pub fn user_rflags() -> u64 {
    unsafe { __user_entry_user_rflags() }
}

/// Transfer control to a user-mode thread. Never returns.
#[inline(always)]
pub unsafe fn enter_user_mode(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { __user_entry_enter(user_rip, user_rsp) }
}

/// Store the kernel stack pointer in the per-CPU area.
#[inline(always)]
pub fn set_kernel_stack(sp: u64) {
    unsafe { __user_entry_set_kernel_stack(sp) }
}

/// Read the kernel stack pointer from the per-CPU area.
#[inline(always)]
pub fn get_kernel_stack() -> u64 {
    unsafe { __user_entry_get_kernel_stack() }
}
