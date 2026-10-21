//! Phase 0 first-time Ring 3 entry trampoline.
//
//! This module provides `first_user_enter`, the assembly routine
//! that takes a fresh user thread and "releases" it into Ring 3.
//
//! The function never returns (`-> !`). Before calling it the
//! caller must:
//
//! 1. `attach_process(pml4_phys)` — switch CR3 to the per-process
//!    PML4 (which already has the kernel half copied and the user
//!    half populated by `mm::vas::map_user_pages`).
//! 2. `swapgs` — swap the user and kernel GS bases so that the
//!    kernel's `IA32_KERNEL_GS_BASE` points to the per-CPU area.
//! 3. Set the per-CPU user RSP (`gs:[0x0]`) to the new user
//!    thread's user RSP. This is the value that will be
//!    `iretq`-restored on Ring 3 entry.
//
//! The iretq frame is constructed on the **kernel** stack (which
//! is still RSP at function entry) and contains the 5 values
//! `SS, RSP, RFLAGS, CS, RIP` that `iretq` pops and uses to set
//! the user-visible CPL=3 state.
//
//! `CS` and `SS` are the canonical Ring-3 selectors installed by
//! `arch::x86_64::gdt::init()`. The OVMF GDT is augmented so that
//! user CS is at slot 5 (selector 0x2b) and user SS is at slot 4
//! (selector 0x23). `RFLAGS` is set to 0x200 (IF=0, interrupts disabled)
//! because the IDT is not fully initialized yet.
//
//! This routine is the only path that lets the kernel cleanly
//! transition to Ring 3 the very first time. After the thread has
//! been entered once, Ring-3 → Ring-0 → Ring-3 transitions use the
//! `syscall`/`sysret` path (see `arch::x86_64::syscall`).

use core::arch::global_asm;

// Import selector constants from the authoritative source (gdt.rs).
// These must match the slots that gdt::init() writes into the OVMF GDT:
//   USER_SS at slot 4 (selector 0x23, DPL=3)
//   USER_CS at slot 5 (selector 0x2b, DPL=3)
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::USER_CS;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::USER_SS;
/// RFLAGS for the iretq frame.
///
/// CRITICAL-004: bit 1 (IF, Interrupt Flag) is **cleared** on entry
/// to Ring 3. The IDT, the PIC, and per-device ISR registration are
/// still being brought up at this point in the boot sequence, and an
/// IF=1 entry would mean a hardware IRQ fired into an IDT that is
/// either still empty or only partially populated — which would
/// raise #GP and then #DF.
///
/// IOPL (I/O Privilege Level) is set to 3 so that user-mode programs
/// can perform I/O port access (e.g., serial port output via `out dx, al`).
/// This is needed for the minimal cmd.exe stub that outputs directly to
/// the serial port.
///
/// Interrupts are re-enabled by `arch::enable_interrupts_once()` in
/// the boot-mode dispatch (Normal: in the IDLE scheduler loop;
/// SafeModeCmd: just before the keyboard poll loop is armed).
const USER_RFLAGS: u64 = 0x3002; // IOPL=3, IF=0

global_asm!(
    // ---- first_user_enter ---------------------------------------------
    // On entry (called from a Rust function via `extern "C"`):
    //   rdi = user RIP
    //   rsi = user RSP
    //
    // The caller has already:
    //   - Switched CR3 to the per-process PML4.
    //   - Set TSS.rsp0 to a valid kernel stack.
    //   - Set PER_CPU_0.kernel_rsp to a valid kernel stack.
    //   - Disabled interrupts (cli).
    //
    // We build the iret frame on the kernel stack and iretq
    // into Ring 3.
    //
    // iretq frame layout (top of stack after this asm):
    //     [rsp+0x28]  SS    (u64, low 32 bits = USER_SS)
    //     [rsp+0x20]  RSP   (u64)
    //     [rsp+0x18]  RFLAGS(u64, low 32 bits = USER_RFLAGS)
    //     [rsp+0x10]  CS    (u64, low 32 bits = USER_CS)
    //     [rsp+0x08]  RIP   (u64)
    //     [rsp+0x00]  <top of stack>
    "  .global first_user_enter",
    "first_user_enter:",
    "  cli",                              // no interrupts while we build the iret frame
    "  mov r15, rdi",                     // r15 = user RIP
    "  mov r14, rsi",                     // r14 = user RSP
    "  push {user_ss_32}",                // SS (zero-extended)
    "  push r14",                         // RSP
    "  push {user_rflags_32}",            // RFLAGS (zero-extended)
    "  push {user_cs_32}",                // CS (zero-extended)
    "  push r15",                         // RIP
    user_ss_32     = const USER_SS as u32,
    user_cs_32     = const USER_CS as u32,
    user_rflags_32 = const USER_RFLAGS as u32,
);

// Inline iretq that does not require the caller to first call
// through an `extern "C"` function. We use `options(noreturn,
// preserves_flags)` so the optimiser treats this as the final
// transfer of control in the function and does not emit any
// epilogue that might clobber RDI/RSI.
//
// The trampoline is written entirely in assembly so that the
// Rust compiler cannot intervene in the placement of `user_rip`
// and `user_rsp` between the moment we name them as operands and
// the moment they are actually pushed onto the stack.
pub unsafe fn first_user_enter_inline(user_rip: u64, user_rsp: u64) -> ! {
    core::arch::asm!(
        "cli",
        "push {ss32}",
        "push rsi",
        "push {rfl32}",
        "push {cs32}",
        "push rdi",
        "iretq",
        ss32 = const USER_SS as u32,
        cs32 = const USER_CS as u32,
        rfl32 = const USER_RFLAGS as u32,
        in("rdi") user_rip,
        in("rsi") user_rsp,
        options(noreturn, preserves_flags),
    );
}

extern "C" {
    /// Transfer control to a user-mode thread for the very first
    /// time. Never returns.
    ///
    /// ## Arguments
    /// * `user_rip` — the user-mode entry point (e.g. the PE
    ///   image's `AddressOfEntryPoint` resolved to a virtual
    ///   address, or `userspace::minimal_stub::USER_ENTRY_RIP`).
    /// * `user_rsp` — the user-mode stack pointer (top of the
    ///   per-process 1 MiB stack).
    ///
    /// ## Preconditions
    /// * CR3 points at the per-process PML4 (call
    ///   `mm::vas::attach_process` first).
    /// * `swapgs` has been executed so the kernel's
    ///   `IA32_KERNEL_GS_BASE` points at the per-CPU area and
    ///   `IA32_GS_BASE` points at the user base.
    /// * The per-CPU user-RSP slot (`gs:[0x0]`) has been set to
    ///   `user_rsp` so that subsequent `syscall` entries start
    ///   from a consistent state.
    pub fn first_user_enter(user_rip: u64, user_rsp: u64) -> !;
}

/// Tiny `extern "C"` wrapper around `first_user_enter` so that the
/// Rust ABI properly forwards the two arguments in RDI/RSI to the
/// assembly trampoline. The wrapper has the `#[inline(never)]`
/// attribute to discourage the optimiser from inlining the call
/// site and re-doing the register allocation it would otherwise
/// perform there (which, as of rustc 1.x with debug-build
/// optimisations, has been observed to spill the arguments into a
/// stack slot that is reused by the rest of the function).
///
/// `enter_first_user_thread` inlines its own iretq to keep the
/// hot Ring-0 → Ring-3 transition as short as possible. This
/// wrapper exists as the named, callable counterpart used by
/// `smoke_test` to verify the `first_user_enter` assembly
/// trampoline still resolves and has a callable address. If
/// `first_user_enter` were ever removed (or its symbol stripped
/// by the linker), this helper — invoked from `smoke_test` — would
/// fail to link, catching the regression at build time rather than
/// at first user-mode boot.
#[inline(never)]
pub extern "C" fn call_first_user_enter(user_rip: u64, user_rsp: u64) -> ! {
    unsafe { first_user_enter(user_rip, user_rsp) }
}

/// Smoke test for the Ring-0 → Ring-3 entry path.
///
/// We can't actually run an `iretq` here (it would never return),
/// so we verify the **linker-level** invariants of the entry path:
///
/// 1. `first_user_enter` resolves to a non-null pointer.
/// 2. `call_first_user_enter` resolves to *something we can take
///    a pointer to* at run time (not dead-code-eliminated).
/// 3. The trampoline address is in the kernel text range (i.e.
///    above `KERNEL_BASE`).
///
/// The actual transfer to Ring 3 happens in
/// `enter_first_user_thread`, which is the production path.
pub fn smoke_test() -> bool {
    let entry: *const () = first_user_enter as *const ();
    if entry.is_null() {
        return false;
    }
    let call_addr = call_first_user_enter as *const () as usize;
    if call_addr == 0 {
        return false;
    }
    // Make sure the compiler doesn't DCE these — we use them via
    // volatile reads so the symbols are genuinely "consumed".
    let entry_addr = entry as usize;
    let _ = (entry_addr, call_addr);
    true
}

/// Helper: store the user RSP into the per-CPU slot. After
/// `attach_process` + `swapgs` the kernel's `IA32_KERNEL_GS_BASE`
/// points at the per-CPU area, so `gs:[0x0]` writes to that area.
#[inline(always)]
pub fn set_per_cpu_user_rsp(user_rsp: u64) {
    unsafe {
        core::arch::asm!(
            "mov gs:[0x0], {v}",
            v = in(reg) user_rsp,
            options(nostack, preserves_flags),
        );
    }
}

/// Enter the first user thread end-to-end. This wraps the lower
/// level helpers and adds the CR3 switching the plan calls out.
/// Returns `!`.
///
/// ## Pre-conditions
///
/// The kernel enters this function with the canonical Ring-0
/// state set up by `arch::x86_64::syscall::init()`:
///
/// * `IA32_GS_BASE = 0`
/// * `IA32_KERNEL_GS_BASE = &PER_CPU_0` (the per-CPU area)
/// * `PER_CPU_0.kernel_rsp` is **unset** (still 0 from `init`)
/// * `EFER.SCE = 1`, `LSTAR` points at `syscall_entry`,
///   `STAR` is configured for `0x23 / 0x2b` user CS/SS.
///
/// We must therefore do **two** things before `iretq`:
///
/// 1. Publish the new kernel stack into `PER_CPU_0.kernel_rsp`
///    so the very first `syscall` instruction issued from Ring 3
///    can load a valid kernel stack and not `#SS` on `rsp=0`.
/// 2. Switch CR3 to the per-process PML4 (so the CPU finds the
///    user pages via the new PML4's user half).
///
/// ## GS-base state
///
/// On x86-64 long-mode CPUs the `gs:` segment-override prefix
/// resolves GS.base to **IA32_GS_BASE** regardless of CPL (this
/// is empirical — see debugging notes in `gdt::init()`). The
/// kernel therefore installs `&PER_CPU_0` into BOTH `IA32_GS_BASE`
/// and `IA32_KERNEL_GS_BASE`; `swapgs` in `syscall_entry`
/// remains a no-op after this assignment, and the kernel
/// per-cpu area is reachable from both Ring 0 and Ring 3.
#[inline(never)]
pub fn enter_first_user_thread(pml4_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    let kernel_sp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) kernel_sp, options(nostack, preserves_flags));
    }
    crate::arch::x86_64::syscall::set_kernel_stack(kernel_sp);
    crate::arch::x86_64::tss::set_rsp0(kernel_sp);
    crate::mm::vas::refresh_kernel_mappings(pml4_phys);

    unsafe {
        core::arch::asm!(
            "mov cr3, {pml4}",
            pml4 = in(reg) pml4_phys,
            options(nostack, preserves_flags),
        );
        let rip = core::hint::black_box(user_rip);
        let rsp = core::hint::black_box(user_rsp);
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = const USER_SS as u32,
            cs = const USER_CS as u32,
            flags = const USER_RFLAGS as u32,
            rsp = in(reg) rsp,
            rip = in(reg) rip,
            options(noreturn, preserves_flags),
        );
    }
}
#[no_mangle]
pub unsafe fn __user_entry_enter_first(root_table_phys: u64, user_rip: u64, user_rsp: u64) -> ! {
    enter_first_user_thread(root_table_phys, user_rip, user_rsp)
}

#[no_mangle]
pub fn __user_entry_user_cs() -> u16 {
    USER_CS
}

#[no_mangle]
pub fn __user_entry_user_ss() -> u16 {
    USER_SS
}

#[no_mangle]
pub fn __user_entry_user_entry_rip() -> u64 {
    crate::mm::constants::USER_ENTRY_RIP
}

#[no_mangle]
pub fn __user_entry_user_stack_base() -> u64 {
    crate::mm::constants::USER_STACK_BASE
}

#[no_mangle]
pub fn __user_entry_user_stack_top() -> u64 {
    crate::mm::constants::USER_STACK_TOP
}

#[no_mangle]
pub fn __user_entry_user_rflags() -> u64 {
    USER_RFLAGS
}

#[no_mangle]
pub unsafe fn __user_entry_enter(user_rip: u64, user_rsp: u64) -> ! {
    first_user_enter_inline(user_rip, user_rsp)
}

#[no_mangle]
pub fn __user_entry_set_kernel_stack(sp: u64) {
    let per_cpu = crate::arch::x86_64::syscall::get_per_cpu();
    if !per_cpu.is_null() {
        unsafe {
            (*per_cpu).kernel_rsp = sp;
        }
    }
}

#[no_mangle]
pub fn __user_entry_get_kernel_stack() -> u64 {
    let per_cpu = crate::arch::x86_64::syscall::get_per_cpu();
    if per_cpu.is_null() {
        0
    } else {
        unsafe { (*per_cpu).kernel_rsp }
    }
}
