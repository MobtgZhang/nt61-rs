//! LoongArch64 exception stack.
//!
//! Phase 1 of the LA64 plan needs an exception stack so the kernel
//! can take traps before any thread stack is set up. We define a
//! dedicated 64 KiB region and publish the top-of-stack symbol that
//! `arch/loongarch64/idt.rs` (`loongarch64_exception`) references
//! via the `la $sp, _exception_stack_top` instruction.
//!
//! Phase 2 will replace this with a per-CPU stack allocated out of
//! the kernel pool.

/// Size of the dedicated exception stack.
pub const EXCEPTION_STACK_SIZE: usize = 64 * 1026;

/// Backing storage for the BSP exception stack.
// `#[no_mangle]` on a struct (rather than a function or static) has
// always been a no-op; the linker cannot use it to demangle a
// layout. rustc 1.71+ now warns and intends to make it a hard error,
// so the attribute is dropped here. The public symbol exported for
// `arch/loongarch64/idt.rs` (`_exception_stack_top`) is `pub static`,
// which keeps its identity across builds.
#[repr(C, align(16))]
pub struct ExceptionStack {
    pub data: [u8; EXCEPTION_STACK_SIZE],
}

#[no_mangle]
pub static mut EXCEPTION_STACK: ExceptionStack = ExceptionStack {
    data: [0u8; EXCEPTION_STACK_SIZE],
};

/// Top-of-stack pointer (one past the end of `EXCEPTION_STACK`).
///
/// `arch/loongarch64/idt.rs` references this symbol via
/// `la $sp, _exception_stack_top`.
#[no_mangle]
#[link_section = ".data"]
pub static mut _exception_stack_top: u64 = 0;

/// Initialise the exception stack pointer at boot.
pub fn init() {
    unsafe {
        let bottom = core::ptr::addr_of_mut!(EXCEPTION_STACK) as *mut u8 as u64;
        let top = bottom + EXCEPTION_STACK_SIZE as u64;
        _exception_stack_top = top;
    }
}

/// Read the current top-of-stack value.
pub fn top() -> u64 {
    unsafe { _exception_stack_top }
}