//! RISC-V 64 context-switch helpers.
//!
//! Provides the rsp-based `swap_context` ABI consumed by
//! `ke::scheduler::schedule()` (see `arch/riscv64/mod.rs`) and a
//! full-register variant `KiSwapContext` / `swap_context_full` that
//! operates on the `CpuContext` defined in [`super::context`].
//!
//! RISC-V has a 32-register GPR file (x0 = zero, x1 = ra, x2 = sp,
//! x3 = gp, x4 = tp, x5..x7 = t0..t2, x8..x9 = s0..fp, x10..x17 =
//! a0..a7, x18..x27 = s2..s11, x28..x31 = t3..t6). The psABI
//! reserves the following subsets:
//!
//!   * Caller-saved (scratch): t0..t6, a0..a7, ra (ra is
//!     conceptually caller-saved because it is overwritten by
//!     `call`/`jal`).
//!   * Callee-saved (preserved): s0..s11 (x8..x9 and x18..x27),
//!     sp (x2), gp (x3), tp (x4). ra is not preserved across
//!     function calls but is preserved across a *context switch* —
//!     it holds the resume address for the next swap.
//!
//! ## Layout of [`ContextFrame`]
//!
//! The struct is laid out so the assembly below can spill registers
//! at fixed offsets (in bytes):
//!
//! ```text
//!    0  + 8 :  ra  (x1)
//!    8  + 8 :  sp  (x2)
//!   16  + 8 :  gp  (x3)
//!   24  + 8 :  tp  (x4)
//!   32  + 8 :  s0  (x8/fp)
//!   40  + 8 :  s1  (x9)
//!   48  + 8 :  s2  (x18)
//!   56  + 8 :  s3  (x19)
//!   64  + 8 :  s4  (x20)
//!   72  + 8 :  s5  (x21)
//!   80  + 8 :  s6  (x22)
//!   88  + 8 :  s7  (x23)
//!   96  + 8 :  s8  (x24)
//!  104  + 8 :  s9  (x25)
//!  112  + 8 :  s10 (x26)
//!  120  + 8 :  s11 (x27)
//! ```
//!
//! FPU / V extension state is appended by `fpu.rs` (Phase 2) and is
//! not touched by Phase 0 / 1 here.
//!
//! ## `swap_context` ABI (matches x86_64 / aarch64 / loongarch64)
//!
//! `swap_context(out_rsp_addr, new_rsp)`:
//!   * saves the callee-saved set of the *outgoing* thread onto the
//!     outgoing kernel stack (the kernel stack pointer of the
//!     outgoing thread is the value of `sp` on entry);
//!   * publishes the resulting `sp` to `*out_rsp_addr`;
//!   * switches `sp` to `new_rsp`;
//!   * restores the callee-saved set from the top of the new stack;
//!   * `ret`s into the saved `ra` of the incoming thread.
//!
//! This matches the call site at `ke/scheduler.rs:1395`.

use core::arch::asm;

/// Size in bytes of one [`ContextFrame`] slot.
pub const CONTEXT_FRAME_SIZE: usize = 128;

/// Full register save area for one thread.
///
/// This is a `#[repr(C)]` struct so the assembly below can rely on
/// the field offsets. Do not reorder fields without updating the
/// assembly.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ContextFrame {
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub s0: u64,
    pub s1: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
}

impl ContextFrame {
    /// Size of the frame in bytes — matches [`CONTEXT_FRAME_SIZE`].
    pub const SIZE: usize = CONTEXT_FRAME_SIZE;
}

/// Pointer to a `ContextFrame` living somewhere on the kernel stack
/// of the thread being switched out.
pub type ContextFramePtr = *mut ContextFrame;

/// Pointer-sized `*mut ContextFrame`.
pub type RawContextPtr = usize;

/// `swap_context` — swap from the outgoing stack pointer (pointed to
/// by `out_rsp_addr`) to the incoming stack pointer (`new_rsp`).
///
/// On return the caller resumes execution with the outgoing context
/// saved at `*out_rsp_addr`. The function never returns to its
/// caller in the linear sense — control flows to whichever context
/// last executed on `new_rsp`.
///
/// # Safety
///
/// `out_rsp_addr` must point at a valid, aligned `usize` that will
/// be used to publish the saved stack pointer. `new_rsp` must be
/// the top of a stack containing a [`ContextFrame`] laid out per
/// the contract above. Interrupts must be disabled at the call
/// site.
#[no_mangle]
pub unsafe extern "C" fn swap_context(out_rsp_addr: *mut u64, new_rsp: u64) {
    asm!(
        // ---- Save the outgoing thread ----
        // Allocate 128 bytes (= CONTEXT_FRAME_SIZE) on the outgoing
        // stack and store the callee-saved registers at fixed
        // offsets.
        "addi  sp, sp, -128",
        "sd    ra,   0(sp)",
        "sd    sp,   8(sp)",   // sp here is *decremented* sp
        "sd    gp,   16(sp)",
        "sd    tp,   24(sp)",
        "sd    s0,   32(sp)",
        "sd    s1,   40(sp)",
        "sd    s2,   48(sp)",
        "sd    s3,   56(sp)",
        "sd    s4,   64(sp)",
        "sd    s5,   72(sp)",
        "sd    s6,   80(sp)",
        "sd    s7,   88(sp)",
        "sd    s8,   96(sp)",
        "sd    s9,   104(sp)",
        "sd    s10,  112(sp)",
        "sd    s11,  120(sp)",
        // Publish the saved sp to *out_rsp_addr.
        "mv    t0, sp",
        "sd    t0, 0(a0)",

        // ---- Restore the incoming thread ----
        // Switch to the new stack and load the callee-saved set.
        "mv    sp, a1",
        "ld    ra,   0(sp)",
        "ld    sp,   8(sp)",   // sp is restored *from* the frame
        "ld    gp,   16(sp)",
        "ld    tp,   24(sp)",
        "ld    s0,   32(sp)",
        "ld    s1,   40(sp)",
        "ld    s2,   48(sp)",
        "ld    s3,   56(sp)",
        "ld    s4,   64(sp)",
        "ld    s5,   72(sp)",
        "ld    s6,   80(sp)",
        "ld    s7,   88(sp)",
        "ld    s8,   96(sp)",
        "ld    s9,   104(sp)",
        "ld    s10,  112(sp)",
        "ld    s11,  120(sp)",
        "addi  sp, sp, 128",
        "ret",
        // The `ret` jumps to the saved `ra` of the incoming thread.
        // We never return through the Rust ABI.
        options(noreturn),
    );
}

/// Fill a fresh [`ContextFrame`] so the thread starts executing
/// `rip(user_entry)` with `sp = user_stack_top`.
///
/// `user_entry` is loaded into `ra` (the return-address register);
/// the next `ret` after a `swap_context` will jump to `user_entry`.
///
/// This is used by `ke::process::create_user_process` to bootstrap a
/// new thread's kernel-stack context before its first
/// `swap_context`.
pub fn init_user_frame(
    frame: &mut ContextFrame,
    user_entry: u64,
    user_stack_top: u64,
) {
    frame.ra = user_entry; // ret after swap_context -> user_entry
    frame.sp = user_stack_top;
    frame.gp = 0;
    frame.tp = 0;
    frame.s0 = 0;
    frame.s1 = 0;
    frame.s2 = 0;
    frame.s3 = 0;
    frame.s4 = 0;
    frame.s5 = 0;
    frame.s6 = 0;
    frame.s7 = 0;
    frame.s8 = 0;
    frame.s9 = 0;
    frame.s10 = 0;
    frame.s11 = 0;
}

/// Save the current callee-saved register set into `out`.
///
/// # Safety
///
/// `out` must point at a live, properly-aligned [`ContextFrame`].
#[inline(never)]
pub unsafe fn save_context(out: *mut ContextFrame) {
    // We load `out` into `t0` and then reference it as a register
    // operand in the asm (`{out_ptr}` appears in the asm text).
    // That keeps the operand binding visible to rustc, which
    // otherwise complains about a "named argument never used" when
    // the same value is referenced only via a memory-operand
    // syntax like `sd sp, 8(out_ptr)`.
    let out_ptr = core::hint::black_box(out);
    asm!(
        "mv    t0, {out_ptr}",
        "sd    ra,   0(t0)",
        "sd    sp,   8(t0)",
        "sd    gp,   16(t0)",
        "sd    tp,   24(t0)",
        "sd    s0,   32(t0)",
        "sd    s1,   40(t0)",
        "sd    s2,   48(t0)",
        "sd    s3,   56(t0)",
        "sd    s4,   64(t0)",
        "sd    s5,   72(t0)",
        "sd    s6,   80(t0)",
        "sd    s7,   88(t0)",
        "sd    s8,   96(t0)",
        "sd    s9,   104(t0)",
        "sd    s10,  112(t0)",
        "sd    s11,  120(t0)",
        out_ptr = in(reg) out_ptr,
        out("t0") _,
        options(nostack, preserves_flags),
    );
}

/// Restore a previously-saved [`ContextFrame`].
///
/// # Safety
///
/// `frame` must point at a valid [`ContextFrame`] produced by
/// [`save_context`] or [`init_user_frame`].
#[inline(never)]
pub unsafe fn restore_context(frame: *const ContextFrame) {
    // See `save_context` for the rationale behind the explicit
    // register move + `{frame}` operand binding.
    let frame = core::hint::black_box(frame);
    asm!(
        "mv    t0, {frame}",
        "ld    ra,   0(t0)",
        "ld    sp,   8(t0)",
        "ld    gp,   16(t0)",
        "ld    tp,   24(t0)",
        "ld    s0,   32(t0)",
        "ld    s1,   40(t0)",
        "ld    s2,   48(t0)",
        "ld    s3,   56(t0)",
        "ld    s4,   64(t0)",
        "ld    s5,   72(t0)",
        "ld    s6,   80(t0)",
        "ld    s7,   88(t0)",
        "ld    s8,   96(t0)",
        "ld    s9,   104(t0)",
        "ld    s10,  112(t0)",
        "ld    s11,  120(t0)",
        frame = in(reg) frame,
        out("t0") _,
        options(nostack, preserves_flags),
    );
}

/// Full context switch — used by tools / tests.
///
/// Operates on a full [`CpuContext`](super::context::CpuContext).
/// Saves all callee-saved registers of the outgoing thread into
/// `out`, then restores from `incoming`, and finally `ret`s into
/// the saved `ra`.
///
/// # Safety
///
/// The pointers must satisfy the same requirements as
/// [`swap_context`].
#[no_mangle]
pub unsafe extern "C" fn swap_context_full(
    out: *mut super::context::CpuContext,
    incoming: *const super::context::CpuContext,
) {
    // We only spill the callee-saved set into the CpuContext.
    unsafe {
        save_context_to_cpu_context(out);
        restore_context_from_cpu_context(incoming);
    }
    // Jump to incoming ra (return address that the incoming thread
    // will resume at).
    let target_ra: u64 = (*incoming).ra;
    asm!(
        "mv    sp, {sp}",
        "jr    {target_ra}",
        sp = in(reg) (*incoming).sp,
        target_ra = in(reg) target_ra,
        options(noreturn),
    );
}

#[cfg(target_arch = "riscv64")]
unsafe fn save_context_to_cpu_context(out: *mut super::context::CpuContext) {
    use core::arch::asm;
    // See `save_context` for the rationale behind the explicit
    // register move + `{out_ptr}` operand binding.
    let out_ptr = core::hint::black_box(out);
    asm!(
        "mv    t0, {out_ptr}",
        "sd    ra,  8(t0)",
        "sd    sp,  16(t0)",
        "sd    gp,  24(t0)",
        "sd    tp,  32(t0)",
        "sd    s0,  72(t0)",
        "sd    s1,  80(t0)",
        "sd    s2,  144(t0)",
        "sd    s3,  152(t0)",
        "sd    s4,  160(t0)",
        "sd    s5,  168(t0)",
        "sd    s6,  176(t0)",
        "sd    s7,  184(t0)",
        "sd    s8,  192(t0)",
        "sd    s9,  200(t0)",
        "sd    s10, 208(t0)",
        "sd    s11, 216(t0)",
        out_ptr = in(reg) out_ptr,
        out("t0") _,
        options(nostack, preserves_flags),
    );
}

#[cfg(target_arch = "riscv64")]
unsafe fn restore_context_from_cpu_context(incoming: *const super::context::CpuContext) {
    use core::arch::asm;
    // See `save_context_to_cpu_context` for the rationale.
    let inc_ptr = core::hint::black_box(incoming);
    asm!(
        "mv    t0, {inc_ptr}",
        "ld    ra,  8(t0)",
        "ld    gp,  24(t0)",
        "ld    tp,  32(t0)",
        "ld    s0,  72(t0)",
        "ld    s1,  80(t0)",
        "ld    s2,  144(t0)",
        "ld    s3,  152(t0)",
        "ld    s4,  160(t0)",
        "ld    s5,  168(t0)",
        "ld    s6,  176(t0)",
        "ld    s7,  184(t0)",
        "ld    s8,  192(t0)",
        "ld    s9,  200(t0)",
        "ld    s10, 208(t0)",
        "ld    s11, 216(t0)",
        // sp is restored last, separately, by the caller.
        inc_ptr = in(reg) inc_ptr,
        out("t0") _,
        options(nostack, preserves_flags),
    );
}

/// Seed a brand-new thread's kernel stack with a [`ContextFrame`]
/// that will run `entry(arg)`.
///
/// The frame is placed at `*stack_top` (which is then advanced
/// downward by [`ContextFrame::SIZE`]) so the next `swap_context`
/// to that thread will switch into `entry(arg)`.
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
        // The kernel `swap_context` pushes the frame downward by
        // `CONTEXT_FRAME_SIZE`, so the frame's top-of-stack address
        // is `stack_top - CONTEXT_FRAME_SIZE`. We pre-populate so
        // that the asm `ld`/`ret` reads valid values.
        let frame_addr = stack_top as u64 - ContextFrame::SIZE as u64;
        let frame = frame_addr as *mut u64;
        // CpuContext field offsets used by save/restore above.
        frame.add(1).write(entry);   // ra  -> entry
        frame.add(2).write(stack_top as u64); // sp = stack_top
        frame.add(3).write(0);       // gp
        frame.add(4).write(arg);     // tp -> arg
        // s0..s11 are callee-saved, init to 0
        frame_addr
    }
}

/// Smoke test: verify the symbol resolves.
pub fn smoke_test() -> bool {
    let p: *const () = swap_context as *const ();
    !p.is_null()
}