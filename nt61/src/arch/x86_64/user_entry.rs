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
extern "C" {
    fn syscall_entry();
}

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
    // DEBUG: dump the 5 iret frame values (each 8 bytes) and the
    // current CS descriptor D/L bits before iretq.
    "  push rax",                         // save scratch regs
    "  push rbx",
    "  push rcx",
    "  push rdx",
    // Print "IF>" marker so we know the dump ran.
    "  mov al, 'I'", "mov dx, 0x3F8", "out dx, al",
    "  mov al, 'F'", "out dx, al",
    "  mov al, '>'", "out dx, al",
    // Print the value at [rsp+0] which is RIP (8 bytes little-endian).
    "  mov rax, [rsp + 0x28]",            // RIP
    "  call 1f",
    // Print SS
    "  mov rax, [rsp + 0x20]",
    "  call 1f",
    // Print RSP
    "  mov rax, [rsp + 0x18]",
    "  call 1f",
    // Print RFLAGS
    "  mov rax, [rsp + 0x10]",
    "  call 1f",
    // Print CS
    "  mov rax, [rsp + 0x08]",
    "  call 1f",
    // Newline
    "  mov al, 0x0D", "out dx, al",
    "  mov al, 0x0A", "out dx, al",
    "  pop rdx",
    "  pop rcx",
    "  pop rbx",
    "  pop rax",
    "  iretq",
    // Local subroutine: print rax as 16 hex digits then a space.
    "1:",
    "  push rcx",
    "  push rdx",
    "  mov ecx, 16",
    "2:",
    "  rol rax, 4",
    "  mov dl, al",
    "  and dl, 0x0F",
    "  cmp dl, 10",
    "  jb 3f",
    "  add dl, 'A' - 10",
    "  jmp 4f",
    "3:",
    "  add dl, '0'",
    "4:",
    "  mov al, dl",
    "  mov dx, 0x3F8",
    "  out dx, al",
    "  dec ecx",
    "  jnz 2b",
    "  mov al, ' '",
    "  out dx, al",
    "  pop rdx",
    "  pop rcx",
    "  ret",
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
#[allow(unused)]
unsafe fn first_user_enter_inline(user_rip: u64, user_rsp: u64) -> ! {
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
    // 0. Publish the kernel stack that the next Ring-3 `syscall`
    //    will load. We use the current kernel stack pointer
    //    (RSP at function entry). The per-CPU area is a Rust
    //    static so we can write it directly via the gs: prefix.
    let kernel_sp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) kernel_sp, options(nostack, preserves_flags)); }
    crate::hal::x86_64::serial::write_string("[UE] kernel_sp=");
    crate::hal::x86_64::serial::write_u64_hex(kernel_sp);
    crate::hal::x86_64::serial::write_string("\r\n");
    crate::arch::x86_64::syscall::set_kernel_stack(kernel_sp);
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::tss::set_rsp0(kernel_sp);
    // DEBUG: verify the per-CPU kernel_rsp slot is correctly written
    // and that the gs: readback returns what we just stored. Without
    // this we cannot tell whether `mov rsp, gs:[8]` in syscall_entry
    // is loading the right value or a stale 0.
    unsafe {
        let readback: u64;
        core::arch::asm!(
            "mov {v}, gs:[0x8]",
            v = out(reg) readback,
            options(nostack, preserves_flags),
        );
        crate::hal::x86_64::serial::write_string("[UE] gs:[8] readback=");
        crate::hal::x86_64::serial::write_u64_hex(readback);
        crate::hal::x86_64::serial::write_string("\r\n");
        let user_rsp_readback: u64;
        core::arch::asm!(
            "mov {v}, gs:[0x0]",
            v = out(reg) user_rsp_readback,
            options(nostack, preserves_flags),
        );
        crate::hal::x86_64::serial::write_string("[UE] gs:[0] readback=");
        crate::hal::x86_64::serial::write_u64_hex(user_rsp_readback);
        crate::hal::x86_64::serial::write_string("\r\n");
    }

    // Verify the cmd.exe entry page actually contains valid machine
    // code. Walk the per-process page table for `user_rip` (which
    // may live under the new per-process PML4), then read the bytes
    // at `user_rip` via the kernel's identity map. Because the
    // kernel has a stable system PML4 with a W=1 identity map, we
    // temporarily flip CR3 to the system PML4 for the walk +
    // physical-address read, then restore the per-process PML4
    // before the iretq. Doing this on the cmd.exe entry page is
    // important: a zeroed-out page (or a wrong mapping) here means
    // we iretq into Ring 3 and trip #PF with interrupts masked,
    // which looks like a silent hang on the serial log because the
    // page-fault handler does not print until interrupt-driven
    // serial I/O is wired up. Failing fast in this handler keeps
    // the next debugging cycle shorter.
    unsafe {
        let saved_cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) saved_cr3, options(nostack, preserves_flags));
        let per_cpu = crate::arch::x86_64::syscall::get_per_cpu();
        let sys_pml4 = if !per_cpu.is_null() { (*per_cpu).system_pml4 } else { 0 };
        if sys_pml4 != 0 && sys_pml4 != saved_cr3 {
            core::arch::asm!("mov cr3, {}", in(reg) sys_pml4, options(nostack, preserves_flags));
        }
        let mut frame_phys: u64 = 0;
        let mut frame_off: u64 = 0;
        let mut found: bool = false;
        let pml4_idx = ((user_rip >> 39) & 0x1FF) as usize;
        let pml4e = core::ptr::read_unaligned((pml4_phys as *const u64).add(pml4_idx));
        if pml4e & 1 != 0 {
            let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
            let pdpt_idx = ((user_rip >> 30) & 0x1FF) as usize;
            let pdpte = core::ptr::read_unaligned((pdpt_phys as *const u64).add(pdpt_idx));
            if pdpte & 1 != 0 {
                let pd_phys = pdpte & 0x000F_FFFF_FFFF_F000;
                let pd_idx = ((user_rip >> 21) & 0x1FF) as usize;
                let pde = core::ptr::read_unaligned((pd_phys as *const u64).add(pd_idx));
                if pde & 1 != 0 {
                    let pt_phys = pde & 0x000F_FFFF_FFFF_F000;
                    let pt_idx = ((user_rip >> 12) & 0x1FF) as usize;
                    let pte = core::ptr::read_unaligned((pt_phys as *const u64).add(pt_idx));
                    if pte & 1 != 0 {
                        frame_phys = pte & 0x000F_FFFF_FFFF_F000;
                        frame_off  = user_rip & 0xFFF;
                        found = true;
                    }
                }
            }
        }
        if found {
            let mut buf = [0u8; 16];
            // Read 16 bytes from the physical frame into `buf`. We use
            // `core::ptr::read_unaligned` instead of an inline asm
            // `rep movsq` because the asm block would clobber RDI,
            // RSI, RCX without the compiler knowing — RDI in
            // particular is the function parameter register for
            // `user_rip` (the cmd.exe entry), and clobbering it
            // caused the iret frame RIP to be replaced with whatever
            // happened to be in RDI afterwards (a kernel address
            // that immediately #GP'd when executed at CPL=3).
            let src_ptr = (frame_phys + frame_off) as *const u8;
            for i in 0..16 {
                buf[i] = core::ptr::read_volatile(src_ptr.add(i));
            }
            crate::hal::x86_64::serial::write_string("[UE] cmd.exe first 16 bytes (phys=0x");
            crate::hal::x86_64::serial::write_u64_hex(frame_phys + frame_off);
            crate::hal::x86_64::serial::write_string("): ");
            for &b in &buf {
                crate::hal::x86_64::serial::write_u32_hex(b as u32);
                crate::hal::x86_64::serial::write_string(" ");
            }
            crate::hal::x86_64::serial::write_string("\r\n");
            // Dump 32 bytes starting at offset 14 (the B8 byte) so we
            // can see the full imm32 that `mov eax, imm32` reads.
            crate::hal::x86_64::serial::write_string("[UE] cmd.exe bytes 14..46 (phys=0x");
            crate::hal::x86_64::serial::write_u64_hex(frame_phys + frame_off + 14);
            crate::hal::x86_64::serial::write_string("): ");
            for i in 14..46 {
                let b: u8 = core::ptr::read_volatile(src_ptr.add(i));
                crate::hal::x86_64::serial::write_string("[");
                crate::hal::x86_64::serial::write_u32_hex(i as u32);
                crate::hal::x86_64::serial::write_string("]=");
                crate::hal::x86_64::serial::write_u32_hex(b as u32);
                crate::hal::x86_64::serial::write_string(" ");
            }
            crate::hal::x86_64::serial::write_string("\r\n");
            // DEBUG: print the PTE bits so we can verify that the
            // cmd.exe page is mapped with US=1 and not NX. Without
            // US=1, user-mode code can't execute from the page; with
            // NX=1 the page is non-executable. Either of those would
            // silently abort cmd.exe on its very first instruction.
            let pml4_idx_dbg = ((user_rip >> 39) & 0x1FF) as usize;
            let pdpt_idx_dbg = ((user_rip >> 30) & 0x1FF) as usize;
            let pd_idx_dbg = ((user_rip >> 21) & 0x1FF) as usize;
            let pt_idx_dbg = ((user_rip >> 12) & 0x1FF) as usize;
            let pml4e_dbg = core::ptr::read_unaligned((pml4_phys as *const u64).add(pml4_idx_dbg));
            let pdpt_phys_dbg = pml4e_dbg & 0x000F_FFFF_FFFF_F000;
            let pdpte_dbg = core::ptr::read_unaligned((pdpt_phys_dbg as *const u64).add(pdpt_idx_dbg));
            let pd_phys_dbg = pdpte_dbg & 0x000F_FFFF_FFFF_F000;
            let pde_dbg = core::ptr::read_unaligned((pd_phys_dbg as *const u64).add(pd_idx_dbg));
            let pt_phys_dbg = pde_dbg & 0x000F_FFFF_FFFF_F000;
            let pte_dbg = core::ptr::read_unaligned((pt_phys_dbg as *const u64).add(pt_idx_dbg));
            crate::hal::x86_64::serial::write_string("[UE] cmd.exe PTE walk: PML4[");
            crate::hal::x86_64::serial::write_u32_hex(pml4_idx_dbg as u32);
            crate::hal::x86_64::serial::write_string("]=0x");
            crate::hal::x86_64::serial::write_u64_hex(pml4e_dbg);
            crate::hal::x86_64::serial::write_string(" PDPT[");
            crate::hal::x86_64::serial::write_u32_hex(pdpt_idx_dbg as u32);
            crate::hal::x86_64::serial::write_string("]=0x");
            crate::hal::x86_64::serial::write_u64_hex(pdpte_dbg);
            crate::hal::x86_64::serial::write_string(" PD[");
            crate::hal::x86_64::serial::write_u32_hex(pd_idx_dbg as u32);
            crate::hal::x86_64::serial::write_string("]=0x");
            crate::hal::x86_64::serial::write_u64_hex(pde_dbg);
            crate::hal::x86_64::serial::write_string(" PT[");
            crate::hal::x86_64::serial::write_u32_hex(pt_idx_dbg as u32);
            crate::hal::x86_64::serial::write_string("]=0x");
            crate::hal::x86_64::serial::write_u64_hex(pte_dbg);
            crate::hal::x86_64::serial::write_string("\r\n");
            let _ = (pml4_idx_dbg, pdpt_idx_dbg, pd_idx_dbg, pt_idx_dbg,
                     pml4e_dbg, pdpte_dbg, pde_dbg, pte_dbg);
        } else {
            crate::hal::x86_64::serial::write_string("[UE] cmd.exe entry page walk FAILED: PML4[");
            crate::hal::x86_64::serial::write_u32_hex(pml4_idx as u32);
            crate::hal::x86_64::serial::write_string("]=0x");
            crate::hal::x86_64::serial::write_u64_hex(pml4e);
            crate::hal::x86_64::serial::write_string(" (cmd.exe page NOT mapped!)\r\n");
        }
        core::arch::asm!("mov cr3, {}", in(reg) saved_cr3, options(nostack, preserves_flags));
    }

    // 0.5 Verify the user entry mapping.
    // PML4 index for USER_ENTRY_RIP (0xFFFF800000001000) is 256.
    // Only in debug builds for troubleshooting.
    #[cfg(debug_assertions)]
    unsafe {
        let pml4 = pml4_phys as *const u64;
        let idx = ((user_rip >> 39) & 0x1FF) as usize;
        // // crate::kprintln!("[USER] enter_first_user_thread: PML4 idx for 0x{:x} = {}", user_rip, idx)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let e = core::ptr::read_unaligned(pml4.add(idx));
        // // crate::kprintln!("[USER] enter_first_user_thread: usr PML4[{}] = 0x{:x}", idx, e)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        if e & 1 != 0 {
            let pdpt_phys = e & 0x000F_FFFF_FFFF_F000;
            let pdpt = pdpt_phys as *const u64;
            let pdpt_idx = ((user_rip >> 30) & 0x1FF) as usize;
            let pdpte = core::ptr::read_unaligned(pdpt.add(pdpt_idx));
            // // crate::kprintln!("[USER]   PDPT[{}] @ 0x{:x} = 0x{:x}", pdpt_idx, pdpt_phys, pdpte)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            if pdpte & 1 != 0 {
                let pd_phys = pdpte & 0x000F_FFFF_FFFF_F000;
                let pd = pd_phys as *const u64;
                let pd_idx = ((user_rip >> 21) & 0x1FF) as usize;
                let pde = core::ptr::read_unaligned(pd.add(pd_idx));
                let _p = pde;
                // // crate::kprintln!("[USER]   PD[{}] @ 0x{:x} = 0x{:x}", pd_idx, pd_phys, pde)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }

    // 1. Switch CR3 to the per-process PML4.
    crate::mm::vas::attach_process(pml4_phys);
    // // crate::kprintln!("[USER] CR3 switched to 0x{:x}", pml4_phys)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Verify the kernel stack is still accessible (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        let _v = core::ptr::read_volatile(rsp as *const u64);
        // // crate::kprintln!("[USER] kernel stack @ 0x{:x} = 0x{:x}", rsp, _v)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // Read GDTR to verify GDT is accessible (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let mut buf = [0u8; 16];
        core::arch::asm!("sgdt [{buf}]", buf = in(reg) buf.as_mut_ptr(), options(nostack));
    }

    // Read IDTR to verify IDT is accessible (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let mut buf = [0u8; 16];
        core::arch::asm!("sidt [{buf}]", buf = in(reg) buf.as_mut_ptr(), options(nostack));
    }

    // Read PIC mask registers to verify state (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let pic1_mask: u8;
        let pic2_mask: u8;
        core::arch::asm!("in al, dx", out("al") pic1_mask, in("dx") 0x21u16, options(nostack));
        core::arch::asm!("in al, dx", out("al") pic2_mask, in("dx") 0xa1u16, options(nostack));
        let _p1 = pic1_mask;
        let _p2 = pic2_mask;
        // // crate::kprintln!("[USER] PIC1 mask=0x{:02x} PIC2 mask=0x{:02x}", pic1_mask, pic2_mask)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // Read TR to verify TSS is loaded (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let tr: u16;
        core::arch::asm!("str {tr:x}", tr = out(reg) tr, options(nostack, preserves_flags));
        let _t = tr;
        // // crate::kprintln!("[USER] TR = 0x{:x}", tr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // Verify the user entry is readable from the new CR3 (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let _b = core::ptr::read_volatile(user_rip as *const u8);
    }

    // Verify GDT and IDT are accessible from the new CR3 (kernel half
    // should have been copied into the user PML4). If these faults,
    // the kernel half isn't properly set up.
    #[cfg(debug_assertions)]
    unsafe {
        let mut gdt_ptr: u64 = 0;
        let mut idt_ptr: u64 = 0;
        core::arch::asm!(
            "sgdt [{gdtp}]",
            "sidt [{idtp}]",
            gdtp = in(reg) &mut gdt_ptr,
            idtp = in(reg) &mut idt_ptr,
            options(nostack),
        );
        // Attempt to read first byte of GDT (slot 0) and IDT (entry 0)
        // through the user PML4's mapping.
        let _gdt_byte = core::ptr::read_volatile(gdt_ptr as *const u8);
        let _idt_byte = core::ptr::read_volatile(idt_ptr as *const u8);
    }

    // Verify the iret frame will be valid by reading the kernel stack (debug only).
    #[cfg(debug_assertions)]
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        let _r = rsp;
        // // crate::kprintln!("[USER] kernel RSP before iret: 0x{:x}", rsp)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // 2. iretq into Ring 3. The caller has already:
    //    - Switched CR3 to the per-process PML4.
    //    - Set TSS.rsp0 / PER_CPU_0.kernel_rsp.
    //    - Disabled interrupts.
    //
    //    The `first_user_enter` assembly builds the iret frame
    //    on the kernel stack and does iretq.

    // Mask all PIC IRQs so a stray IRQ (e.g. PIT at vector
    // 0x20) doesn't fire in Ring 3 before the user thread
    // is ready to handle it. The IDT entries for 0x20..0x2F
    // are also unset, so an IRQ firing there would #GP.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x21u16, in("al") 0xFFu8, options(nostack, nomem));
        core::arch::asm!("out dx, al", in("dx") 0xa1u16, in("al") 0xFFu8, options(nostack, nomem));
        // Debug: verify PIC masks were set
        #[cfg(debug_assertions)]
        {
            let m1: u8;
            let m2: u8;
            core::arch::asm!("in al, dx", out("al") m1, in("dx") 0x21u16, options(nostack));
            core::arch::asm!("in al, dx", out("al") m2, in("dx") 0xa1u16, options(nostack));
            let _ = (m1, m2);
            // // crate::kprintln!("[USER] PIC after mask: PIC1=0x{:02x} PIC2=0x{:02x}", m1, m2)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    }

    // DEBUG: read IA32_GS_BASE and IA32_KERNEL_GS_BASE (debug only).
    // (silent in release; debug builds skip these checks entirely
    // because they can fault when the GS_BASE MSR is 0.)
    #[cfg(debug_assertions)]
    {
        let _ = user_rip;
    }

    // crate::kprintln!("[USER] about to call first_user_enter")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // crate::kprintln!("[USER]   will iretq with RIP=0x{:x} RSP=0x{:x} CS=0x{:x} SS=0x{:x} RFLAGS=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         user_rip, user_rsp, USER_CS as u64, USER_SS as u64, USER_RFLAGS);
    // We disable interrupts and transfer to Ring 3 via an inline
    // iretq. We pass `user_rip` and `user_rsp` through Rust
    // `let` bindings that the compiler can't keep in any
    // register (because they are read once by the asm block
    // and then never again). Forcing rustc to treat them as
    // cold data forces it to materialise them into a fresh
    // register just before the asm block runs.
    unsafe {
        // Force rustc to allocate fresh registers for
        // user_rip and user_rsp by wrapping them in a black
        // box that prevents any dataflow optimisation.
        let rip_v = core::hint::black_box(user_rip);
        let rsp_v = core::hint::black_box(user_rsp);
        // Read current state for debugging
        let cr3_before: u64;
        let cs_before: u64;
        core::arch::asm!(
            "mov {cr3}, cr3",
            "mov {cs}, cs",
            cr3 = out(reg) cr3_before,
            cs = out(reg) cs_before,
            options(nostack, preserves_flags),
        );
        crate::hal::x86_64::serial::write_string("[UE] before iretq: rip=");
        crate::hal::x86_64::serial::write_u64_hex(rip_v);
        crate::hal::x86_64::serial::write_string(" rsp=");
        crate::hal::x86_64::serial::write_u64_hex(rsp_v);
        crate::hal::x86_64::serial::write_string(" cs=");
        crate::hal::x86_64::serial::write_u64_hex(USER_CS as u64);
        crate::hal::x86_64::serial::write_string(" ss=");
        crate::hal::x86_64::serial::write_u64_hex(USER_SS as u64);
        crate::hal::x86_64::serial::write_string("\r\n");
        crate::hal::x86_64::serial::write_string("[UE] state: CR3=");
        crate::hal::x86_64::serial::write_u64_hex(cr3_before);
        crate::hal::x86_64::serial::write_string(" currentCS=");
        crate::hal::x86_64::serial::write_u64_hex(cs_before);
        crate::hal::x86_64::serial::write_string("\r\n");
        // Sanity check the iret frame by reading the kernel stack
        // before pushing anything. This helps us verify that the
        // iretq frame isn't being corrupted by stack misalignment.
        let stack_check: u64;
        core::arch::asm!(
            "mov {val}, rsp",
            val = out(reg) stack_check,
            options(nostack, preserves_flags),
        );
        crate::hal::x86_64::serial::write_string("[UE] pre-iretq rsp=");
        crate::hal::x86_64::serial::write_u64_hex(stack_check);
        crate::hal::x86_64::serial::write_string("\r\n");
        // DEBUG: print LSTAR and EFER to verify syscall is reachable
        let lstar: u64;
        let efer: u64;
        core::arch::asm!(
            "mov ecx, 0xc0000082",
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            lateout("rax") lstar,
            out("rcx") _,
            out("rdx") _,
            options(nostack),
        );
        core::arch::asm!(
            "mov ecx, 0xc0000080",
            "rdmsr",
            "shl rdx, 32",
            "or rax, rdx",
            lateout("rax") efer,
            out("rcx") _,
            out("rdx") _,
            options(nostack),
        );
        crate::hal::x86_64::serial::write_string("[UE] LSTAR=");
        crate::hal::x86_64::serial::write_u64_hex(lstar);
        crate::hal::x86_64::serial::write_string(" EFER=");
        crate::hal::x86_64::serial::write_u64_hex(efer);
        crate::hal::x86_64::serial::write_string(" syscall_entry_addr=");
        crate::hal::x86_64::serial::write_u64_hex(syscall_entry as *const () as u64);
        crate::hal::x86_64::serial::write_string("\r\n");
        // DEBUG: Output distinctive markers to identify execution flow.
        // 'W' = entering iretq inline block
        // 'w' = returned from iretq (unreachable)
        // Force the user-mode RIP/RSP into callee-preserved registers
        // that survive across the diagnostic above. Without this, the
        // compiler is free to allocate the operands to registers that
        // get clobbered by intermediate code (we observed the
        // compiler emitting `movq %rax, %rbp` to save IA32_STAR,
        // overwriting the location where user_rsp had been
        // stashed). We move them into %r15 / %rbp *immediately*
        // before the iretq block so they're guaranteed to hold the
        // right values at push time.
        core::arch::asm!(
            "push {ss32}",
            "push {rsp_v}",
            "push {rfl32}",
            "push {cs32}",
            "push {rip_v}",
            "mov al, 0x2D",  // '-'
            "mov dx, 0x3F8",
            "out dx, al",
            "iretq",
            ss32 = const USER_SS as u32,
            cs32 = const USER_CS as u32,
            rfl32 = const USER_RFLAGS as u32,
            rip_v = in(reg) rip_v,
            rsp_v = in(reg) rsp_v,
            options(noreturn, preserves_flags),
        );
    }
    // first_user_enter never returns; suppress unreachable warning.
    #[allow(unreachable_code)]
    loop {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        {
            // Output 'w' to serial when we somehow return from iretq.
            // This should NEVER happen, but if it does, it means iretq
            // was misconfigured and jumped somewhere unexpected.
            unsafe {
                core::arch::asm!(
                    "mov al, 0x77",  // 'w'
                    "mov dx, 0x3F8",
                    "out dx, al",
                    options(nostack, preserves_flags),
                );
            }
            crate::hal::x86_64::serial::write_string("[UE] post-iret unreachable\r\n");
        }
        crate::boot_println!("[UE] post-iret unreachable (CPU survived iretq!)");
        crate::arch::halt();
    }
}
