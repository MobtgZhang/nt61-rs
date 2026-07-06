//! AArch64 context switch implementation.
//!
//! Provides two flavours of [`swap_context`]:
//!
//! * **rsp-based** (callable from `ke::scheduler`): the conventional
//!   AArch64 syscall-vendor style where each thread saves its
//!   callee-saved set onto its kernel stack.
//! * **CpuContext-based** ([`swap_context_full`]): used by tools and
//!   tests that want to swap the entire register file (e.g. debuggers
//!   or stub-using callers).
//!
//! The on-stack register layout matches [`ContextFrame`] below, which
//! is what the kernel allocates in every `ETHREAD.kthread.context`.

use core::arch::asm;

/// Minimal context frame stored at the top of each kernel stack when
/// the thread is not running. The field offsets MUST match the
/// `save_callee` / `restore_callee` macros in
/// [`swap_context_rsp`].
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ContextFrame {
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64, // FP
    pub x30: u64, // LR — for `ret` to land at the saved PC
}

impl ContextFrame {
    /// Size of the frame (in bytes).
    pub const SIZE: usize = 12 * 8;
}

/// RSP-based swap context — the everyday kernel call.
///
/// On entry:
///
///   - `out_rsp = x0` points at a `u64` location; we store the
///     callee-saved set of the outgoing thread onto the *kernel
///     stack* of the outgoing thread and write the resulting `sp`
///     to `*out_rsp` so the scheduler can pick it up later.
///   - `new_rsp = x1` is the kernel stack pointer of the incoming
///     thread.
///
/// The incoming thread's stack MUST already have a [`ContextFrame`]
/// at its top (see [`seed_thread_frame`]). After restoring the
/// callee-saved registers we `ret` into the saved `x30` (LR) so
/// control transfers to the incoming thread "from" the kernel.
///
/// # Safety
///
/// - Both stacks must be valid and large enough to hold a
///   [`ContextFrame`].
/// - Interrupts must be disabled.
#[no_mangle]
pub unsafe extern "C" fn swap_context(out_rsp: *mut u64, new_rsp: u64) {
    unsafe {
        asm!(
            // Save callee-saved registers onto the outgoing kernel
            // stack, then drop into a fresh context frame. The
            // first dpc ("downward push") will land *above* the
            // current SP; we then update SP to point below the
            // frame.
            //
            // We don't have a separate push because the dispatcher
            // allocates the frame lazily through `seed_thread_frame`.

            "sub  sp, sp, #96",          // 12 * 8
            "stp  x19, x20, [sp, #0x00]",
            "stp  x21, x22, [sp, #0x10]",
            "stp  x23, x24, [sp, #0x20]",
            "stp  x25, x26, [sp, #0x30]",
            "stp  x27, x28, [sp, #0x40]",
            "stp  x29, x30, [sp, #0x50]",
            "mov  x4, sp",
            "str  x4, [x0]",             // *out_rsp = sp

            // Restore the incoming frame and `ret` into it.
            "mov  sp, x1",
            "ldp  x19, x20, [sp, #0x00]",
            "ldp  x21, x22, [sp, #0x10]",
            "ldp  x23, x24, [sp, #0x20]",
            "ldp  x25, x26, [sp, #0x30]",
            "ldp  x27, x28, [sp, #0x40]",
            "ldp  x29, x30, [sp, #0x50]",
            "add  sp, sp, #96",
            "ret",

            // We never return through Rust ABI; the `ret` jumps
            // into the saved LR of the incoming thread.
            options(noreturn),
        );
    }
}

/// Seed a brand-new thread's kernel stack with a [`ContextFrame`]
/// that will run `entry(arg)`.  The frame is placed at `*stack_top`
/// (which is then advanced downward by [`ContextFrame::SIZE`]) so
/// the next `swap_context` to that thread will switch into
/// `entry(arg)`.
///
/// # Safety
///
/// `stack_top` must point at writable memory holding at least
/// [`ContextFrame::SIZE`] bytes of stack space.
#[no_mangle]
pub unsafe extern "C" fn seed_thread_frame(
    stack_top: *mut u64,
    entry: u64,
    arg: u64,
) -> u64 {
    unsafe {
        // The kernel pushes the frame "downward" by the asm above
        // (sub sp). The frame's top-of-stack address is therefore
        // the address `stack_top - ContextFrame::SIZE`. We
        // pre-populate so that the asm `ldp`/`ret` reads valid
        // values.
        let frame_addr = stack_top as u64 - ContextFrame::SIZE as u64;
        // The frame layout (matching the asm above, low-to-high):
        //   [0]  x19, [1]  x20, ...
        //   [10] x29, [11] x30  (LR — must point at `entry`)
        // We pass `arg` in x19 which is where the entry expects it.
        let frame = frame_addr as *mut u64;
        frame.add(0).write(0);  // x19
        frame.add(1).write(0);  // x20
        frame.add(2).write(0);  // x21
        frame.add(3).write(0);  // x22
        frame.add(4).write(0);  // x23
        frame.add(5).write(0);  // x24
        frame.add(6).write(0);  // x25
        frame.add(7).write(0);  // x26
        frame.add(8).write(0);  // x27
        frame.add(9).write(0);  // x28
        frame.add(10).write(0); // x29 (FP)
        frame.add(11).write(entry); // x30 (LR) -> entry
        // Patch x19 in the frame to `arg` after the writes are
        // committed. x19 is the first callee-saved arg register
        // for an `extern "C" fn(u64)` per AAPCS.
        frame.add(0).write(arg); // x19 = arg
        frame_addr
    }
}

/// Full context swap (used by tools / tests).
///
/// Operates on a [`CpuContext`](super::context::CpuContext) of
/// `CACHE_LINE` size — the saved register file of the outgoing
/// thread, plus the CpuContext of the incoming thread.
///
/// # Safety
///
/// The pointers must satisfy the same requirements as
/// [`swap_context`].
#[no_mangle]
pub unsafe extern "C" fn swap_context_full(
    old_ctx: *mut super::context::CpuContext,
    new_ctx: *const super::context::CpuContext,
) {
    unsafe {
        asm!(
            "mov x19, x0",
            "stp x0,  x1,  [x19, #0x000]",
            "stp x2,  x3,  [x19, #0x010]",
            "stp x4,  x5,  [x19, #0x020]",
            "stp x6,  x7,  [x19, #0x030]",
            "stp x8,  x9,  [x19, #0x040]",
            "stp x10, x11, [x19, #0x050]",
            "stp x12, x13, [x19, #0x060]",
            "stp x14, x15, [x19, #0x070]",
            "stp x16, x17, [x19, #0x080]",
            "str x18,      [x19, #0x090]",
            "stp x20, x21, [x19, #0x098]",
            "stp x22, x23, [x19, #0x0A8]",
            "stp x24, x25, [x19, #0x0B8]",
            "stp x26, x27, [x19, #0x0C8]",
            "stp x28, x29, [x19, #0x0D8]",
            "str x30,      [x19, #0x0E8]",
            "mov  x2, sp",
            "str  x2,     [x19, #0x0F0]",
            "mov  x20, x1",
            "ldp  x0,  x1,  [x20, #0x000]",
            "ldp  x2,  x3,  [x20, #0x010]",
            "ldp  x4,  x5,  [x20, #0x020]",
            "ldp  x6,  x7,  [x20, #0x030]",
            "ldp  x8,  x9,  [x20, #0x040]",
            "ldp  x10, x11, [x20, #0x050]",
            "ldp  x12, x13, [x20, #0x060]",
            "ldp  x14, x15, [x20, #0x070]",
            "ldp  x16, x17, [x20, #0x080]",
            "ldr  x18,     [x20, #0x090]",
            "ldp  x22, x23, [x20, #0x0A8]",
            "ldp  x24, x25, [x20, #0x0B8]",
            "ldp  x26, x27, [x20, #0x0C8]",
            "ldp  x28, x29, [x20, #0x0D8]",
            "ldr  x30,     [x20, #0x0E8]",
            "ldr  x2,      [x20, #0x0F0]",
            "mov  sp, x2",
            "ret",
            options(noreturn),
        );
    }
}

/// Smoke test: verify the symbol resolves.
pub fn smoke_test() -> bool {
    let p: *const () = swap_context as *const ();
    !p.is_null()
}
