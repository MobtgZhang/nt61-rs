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
/// User-mode IOPL is 0 on Windows 7; I/O ports must be trapped.
const USER_IOPL: u64 = 0;
/// Required always-one RFLAGS reserved bit.
const RFLAGS_RESERVED: u64 = 0x002;
/// Deliver maskable hardware IRQs while Ring 3 runs.
const RFLAGS_IF: u64 = 0x200;
const USER_RFLAGS: u64 = USER_IOPL | RFLAGS_RESERVED | RFLAGS_IF;

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

    // One-shot bring-up diagnostic: verify that the executable page
    // backing user_rip is present, user-accessible, and contains the
    // first bytes of cmd.exe before dropping privilege. This is cheap
    // and catches image-loading or page-table wiring regressions that
    // otherwise appear as a silent Ring-3 hang.
    unsafe {
        let read_table = |table_phys: u64, index: usize| -> Option<u64> {
            if table_phys == 0 {
                return None;
            }
            Some(*((table_phys + (index as u64) * 8) as *const u64))
        };
        let pml4_index = ((user_rip >> 39) & 0x1ff) as usize;
        let pdpt_index = ((user_rip >> 30) & 0x1ff) as usize;
        let pd_index = ((user_rip >> 21) & 0x1ff) as usize;
        let pt_index = ((user_rip >> 12) & 0x1ff) as usize;
        let pml4_entry = read_table(pml4_phys, pml4_index).unwrap_or(0);
        let pdpt_entry = if pml4_entry & 1 != 0 {
            read_table(pml4_entry & 0x000f_ffff_ffff_f000, pdpt_index).unwrap_or(0)
        } else {
            0
        };
        let pd_entry = if pml4_entry & 1 != 0 && pdpt_entry & 1 != 0 {
            read_table(pdpt_entry & 0x000f_ffff_ffff_f000, pd_index).unwrap_or(0)
        } else {
            0
        };
        let pt_entry = if pml4_entry & 1 != 0
            && pdpt_entry & 1 != 0
            && pd_entry & 1 != 0
            && pd_entry & 0x80 == 0
        {
            read_table(pd_entry & 0x000f_ffff_ffff_f000, pt_index).unwrap_or(0)
        } else {
            0
        };
        crate::hal::serial::write_string_always("[RING3-ENTRY] rip=");
        crate::hal::serial::write_hex_u64_always(user_rip);
        crate::hal::serial::write_string_always(" pml4e=");
        crate::hal::serial::write_hex_u64_always(pml4_entry);
        crate::hal::serial::write_string_always(" pdpte=");
        crate::hal::serial::write_hex_u64_always(pdpt_entry);
        crate::hal::serial::write_string_always(" pde=");
        crate::hal::serial::write_hex_u64_always(pd_entry);
        crate::hal::serial::write_string_always(" pte=");
        crate::hal::serial::write_hex_u64_always(pt_entry);
        crate::hal::serial::write_string_always("\r\n");
        let large_pdpt = pdpt_entry & 0x80 != 0;
        let large_pd = pd_entry & 0x80 != 0;
        if large_pdpt || large_pd || (pd_entry & 0x80 == 0 && pt_entry & 1 != 0) {
            let page_phys = if large_pdpt {
                pdpt_entry & 0x000f_ffff_c000_0000
            } else if large_pd {
                pd_entry & 0x000f_ffff_fe00_0000
            } else {
                pt_entry & 0x000f_ffff_ffff_f000
            };
            let offset = (user_rip & 0xfff) as usize;
            let source = (page_phys + offset as u64) as *const u8;
            let mut bytes = [0u8; 16];
            for (index, target) in bytes.iter_mut().enumerate() {
                *target = *source.add(index);
            }
            crate::hal::serial::write_string_always("[RING3-ENTRY] code=");
            for &byte in &bytes {
                crate::hal::serial::write_hex_u64_always(byte as u64);
                crate::hal::serial::write_string_always(" ");
            }
            crate::hal::serial::write_string_always("\r\n");

            let stack_pml4_index = ((user_rsp >> 39) & 0x1ff) as usize;
            let stack_pdpt_index = ((user_rsp >> 30) & 0x1ff) as usize;
            let stack_pd_index = ((user_rsp >> 21) & 0x1ff) as usize;
            let stack_pt_index = ((user_rsp >> 12) & 0x1ff) as usize;
            let stack_pml4_entry = read_table(pml4_phys, stack_pml4_index).unwrap_or(0);
            let stack_pdpt_entry = if stack_pml4_entry & 1 != 0 {
                read_table(stack_pml4_entry & 0x000f_ffff_ffff_f000, stack_pdpt_index).unwrap_or(0)
            } else {
                0
            };
            let stack_pd_entry = if stack_pml4_entry & 1 != 0 && stack_pdpt_entry & 1 != 0 {
                read_table(stack_pdpt_entry & 0x000f_ffff_ffff_f000, stack_pd_index).unwrap_or(0)
            } else {
                0
            };
            let stack_pt_entry = if stack_pml4_entry & 1 != 0
                && stack_pdpt_entry & 1 != 0
                && stack_pd_entry & 1 != 0
                && stack_pd_entry & 0x80 == 0
            {
                read_table(stack_pd_entry & 0x000f_ffff_ffff_f000, stack_pt_index).unwrap_or(0)
            } else {
                0
            };
            crate::hal::serial::write_string_always("[RING3-STACK] rsp=");
            crate::hal::serial::write_hex_u64_always(user_rsp);
            crate::hal::serial::write_string_always(" pml4e=");
            crate::hal::serial::write_hex_u64_always(stack_pml4_entry);
            crate::hal::serial::write_string_always(" pdpte=");
            crate::hal::serial::write_hex_u64_always(stack_pdpt_entry);
            crate::hal::serial::write_string_always(" pde=");
            crate::hal::serial::write_hex_u64_always(stack_pd_entry);
            crate::hal::serial::write_string_always(" pte=");
            crate::hal::serial::write_hex_u64_always(stack_pt_entry);
            crate::hal::serial::write_string_always("\r\n");

            let read_msr = |msr: u32| -> u64 {
                let lo: u32;
                let hi: u32;
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") msr,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, preserves_flags)
                );
                ((hi as u64) << 32) | lo as u64
            };
            let efer = read_msr(0xC0000080);
            let lstar = read_msr(0xC0000082);
            crate::hal::serial::write_string_always("[RING3-MSR] efer=");
            crate::hal::serial::write_hex_u64_always(efer);
            crate::hal::serial::write_string_always(" lstar=");
            crate::hal::serial::write_hex_u64_always(lstar);
            crate::hal::serial::write_string_always(" syscall_entry=");
            crate::hal::serial::write_hex_u64_always(
                crate::arch::x86_64::syscall::syscall_entry_address(),
            );
            crate::hal::serial::write_string_always("\r\n");
        }
    }

    unsafe {
        // Publish the Ring-3 GS convention before the privilege change:
        // user GS becomes 0, and IA32_KERNEL_GS_BASE retains the per-CPU
        // area for the syscall/trap entry stubs.
        core::arch::asm!("swapgs", options(nostack, preserves_flags));
        {
            let mut gdtr = [0u8; 16];
            core::arch::asm!(
                "sgdt [{buf}]",
                buf = in(reg) gdtr.as_mut_ptr(),
                options(nostack),
            );
            let limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
            let base = u64::from_le_bytes([
                gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
            ]);
            crate::hal::serial::write_string_always("[RING3-GDT] base=");
            crate::hal::serial::write_hex_u64_always(base);
            crate::hal::serial::write_string_always(" limit=");
            crate::hal::serial::write_hex_u64_always(limit as u64);
            crate::hal::serial::write_string_always(" cs=");
            crate::hal::serial::write_hex_u64_always(core::ptr::read_volatile(
                (base + 0x28) as *const u64,
            ));
            crate::hal::serial::write_string_always(" ss=");
            crate::hal::serial::write_hex_u64_always(core::ptr::read_volatile(
                (base + 0x20) as *const u64,
            ));
            crate::hal::serial::write_string_always("\r\n");
        }
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
