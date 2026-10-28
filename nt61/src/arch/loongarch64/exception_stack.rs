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
pub const EXCEPTION_STACK_SIZE: usize = 64 * 1024;

/// Interior-mutable backing storage for the BSP exception stack. The trap
/// vector writes through the fixed symbol; Rust code only computes and reads
/// its top pointer, so this cell removes `static mut` while preserving the
/// linker-visible address and layout.
struct ExceptionStackCell(core::cell::UnsafeCell<ExceptionStack>);

// SAFETY: The trap vector owns this storage after boot initialization and
// only one CPU enters the BSP exception vector at a time.
unsafe impl Sync for ExceptionStackCell {}

#[repr(C, align(16))]
pub struct ExceptionStack {
    pub data: [u8; EXCEPTION_STACK_SIZE],
}

static EXCEPTION_STACK: ExceptionStackCell = ExceptionStackCell(core::cell::UnsafeCell::new(
    ExceptionStack {
        data: [0u8; EXCEPTION_STACK_SIZE],
    },
));

/// Top-of-stack pointer (one past the end of `EXCEPTION_STACK`).
///
/// `arch/loongarch64/idt.rs` references this symbol via
/// `la $sp, _exception_stack_top`.
#[no_mangle]
#[link_section = ".data"]
pub static _exception_stack_top: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Initialise the exception stack pointer at boot.
pub fn init() {
    unsafe {
        let bottom = (*EXCEPTION_STACK.0.get()).data.as_ptr() as *mut u8 as u64;
        let top = bottom + EXCEPTION_STACK_SIZE as u64;
        _exception_stack_top.store(top, core::sync::atomic::Ordering::Release);
    }
}

/// read the current top-of-stack value.
pub fn top() -> u64 {
    _exception_stack_top.load(core::sync::atomic::Ordering::Acquire)
}
