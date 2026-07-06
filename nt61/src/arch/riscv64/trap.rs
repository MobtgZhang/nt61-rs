//! RISC-V 64 trap / exception dispatch.
//!
//! Provides the high-level dispatch routine that runs after
//! `stvec_trap` (in `idt.rs`) has saved the trap frame. We map the
//! RISC-V `scause` register onto a `TrapKind` enum and dispatch:
//!
//! * `EnvironmentCallFromUMode` — branch into `syscall::dispatch_syscall`.
//! * `LoadPageFault` / `StorePageFault` /
//!   `InstructionPageFault` — currently a panic; Phase 2 will wire
//!   these into the page-fault handler in `mm::vas`.
//! * `IllegalInstruction`,
//!   `InstructionAddressMisaligned`,
//!   `Breakpoint`,
//!   ... — panic with diagnostic info.
//!
//! The trap frame layout must match the order in which `stvec_trap`
//! saves registers (see `arch::riscv64::idt`).
//!
//! ## References
//!
//! * RISC-V ISA Specification Volume II — "Trap Cause" (`scause`)
//!   register layout.
//! * RISC-V Privileged Specification §3.1.8/§3.1.9 — `sepc`,
//!   `sstatus`, `stval`.

use core::arch::asm;

/// Exception cause values from the RISC-V `scause` register.
///
/// The high bit of `scause` distinguishes interrupts (1) from
/// exceptions (0). We mask off that bit before classifying, so the
/// enum below covers only the exception codes.
///
/// Reference: RISC-V Privileged Spec §3.1.8.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    InstructionAddressMisaligned = 0,
    InstructionAccessFault = 1,
    IllegalInstruction = 2,
    Breakpoint = 3,
    LoadAddressMisaligned = 4,
    LoadAccessFault = 5,
    StoreAddressMisaligned = 6,
    StoreAccessFault = 7,
    EnvironmentCallFromUMode = 8,
    EnvironmentCallFromSMode = 9,
    EnvironmentCallFromMMode = 11,
    InstructionPageFault = 12,
    LoadPageFault = 13,
    StorePageFault = 15,
    SoftwareCheck = 18,
    HardwareError = 19,
    Other(u64),
}

impl TrapKind {
    /// Mask off the interrupt bit (`scause[63]`) and convert the
    /// remaining exception code into a [`TrapKind`].
    pub fn from_scause(scause: u64) -> Self {
        // Interrupt bit is bit 63; the exception code lives in
        // bits [62:0].
        let code = scause & 0x7FFF_FFFF_FFFF_FFFF;
        match code {
            0 => TrapKind::InstructionAddressMisaligned,
            1 => TrapKind::InstructionAccessFault,
            2 => TrapKind::IllegalInstruction,
            3 => TrapKind::Breakpoint,
            4 => TrapKind::LoadAddressMisaligned,
            5 => TrapKind::LoadAccessFault,
            6 => TrapKind::StoreAddressMisaligned,
            7 => TrapKind::StoreAccessFault,
            8 => TrapKind::EnvironmentCallFromUMode,
            9 => TrapKind::EnvironmentCallFromSMode,
            11 => TrapKind::EnvironmentCallFromMMode,
            12 => TrapKind::InstructionPageFault,
            13 => TrapKind::LoadPageFault,
            15 => TrapKind::StorePageFault,
            18 => TrapKind::SoftwareCheck,
            19 => TrapKind::HardwareError,
            other => TrapKind::Other(other),
        }
    }
}

/// Trap frame pushed by `stvec_trap`. The layout mirrors the order
/// of `sd` instructions in `idt.rs` (offsets relative to `sp` after
/// `csrrw sp, sscratch, sp`).
///
/// | Offset  | Field        | Source      |
/// |---------|--------------|-------------|
/// | 0x00    | ra           | x1          |
/// | 0x08    | t0           | x5          |
/// | 0x10    | t1           | x6          |
/// | 0x18    | t2           | x7          |
/// | 0x20    | s0           | x8          |
/// | 0x28    | s1           | x9          |
/// | 0x30    | a0           | x10         |
/// | 0x38    | a1           | x11         |
/// | 0x40    | a2           | x12         |
/// | 0x48    | a3           | x13         |
/// | 0x50    | a4           | x14         |
/// | 0x58    | a5           | x15         |
/// | 0x60    | a6           | x16         |
/// | 0x68    | a7           | x17         |
/// | 0x70    | s2           | x18         |
/// | 0x78    | s3           | x19         |
/// | 0x80    | s4           | x20         |
/// | 0x88    | s5           | x21         |
/// | 0x90    | s6           | x22         |
/// | 0x98    | s7           | x23         |
/// | 0xA0    | s8           | x24         |
/// | 0xA8    | s9           | x25         |
/// | 0xB0    | s10          | x26         |
/// | 0xB8    | s11          | x27         |
/// | 0xC0    | gp           | x3          |
/// | 0xC8    | tp           | x4          |
/// | 0xD0    | sepc         | CSR 0x141   |
/// | 0xD8    | sstatus      | CSR 0x100   |
/// | 0xE0    | stval        | CSR 0x143   |
/// | 0xE8    | scause       | CSR 0x142   |
///
/// The base layout is shared with `idt::TrapFrame`; here we extend
/// it with `stval` and `scause` so the dispatcher can read both
/// without re-issuing CSR reads.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapFrame {
    pub ra: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub s0: u64,
    pub s1: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
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
    pub gp: u64,
    pub tp: u64,
    pub sepc: u64,
    pub sstatus: u64,
    pub stval: u64,
    pub scause: u64,
}

/// Address / page-fault information extracted from `stval` and the
/// `scause` register.
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    pub badv: u64,
    pub is_write: bool,
    pub is_instruction: bool,
    pub is_user: bool,
}

/// Read `scause` CSR (0x142).
#[inline(always)]
pub fn read_scause() -> u64 {
    let v: u64;
    unsafe { asm!("csrr {}, 0x142", out(reg) v, options(nostack)); }
    v
}

/// Read `sepc` CSR (0x141).
#[inline(always)]
pub fn read_sepc() -> u64 {
    let v: u64;
    unsafe { asm!("csrr {}, 0x141", out(reg) v, options(nostack)); }
    v
}

/// Read `stval` CSR (0x143).
#[inline(always)]
pub fn read_stval() -> u64 {
    let v: u64;
    unsafe { asm!("csrr {}, 0x143", out(reg) v, options(nostack)); }
    v
}

/// Read `sstatus` CSR (0x100).
#[inline(always)]
pub fn read_sstatus() -> u64 {
    let v: u64;
    unsafe { asm!("csrr {}, 0x100", out(reg) v, options(nostack)); }
    v
}

/// Write `sepc` CSR.
#[inline(always)]
pub fn write_sepc(v: u64) {
    unsafe { asm!("csrw 0x141, {}", in(reg) v, options(nostack)); }
}

/// Top-level trap dispatcher invoked from `handle_trap` in
/// `arch::riscv64::idt`.
///
/// We read `scause` from the trap frame (the assembler saved it on
/// entry) to determine the cause, branch accordingly, and advance
/// `sepc` by 4 for synchronous exceptions so the offending
/// instruction is not re-executed.
///
/// For Phase 0 / Phase 1, only [`TrapKind::EnvironmentCallFromUMode`]
/// is meaningfully routed; the rest either panic or print a
/// diagnostic via the (disabled) `kprintln!` to keep the build
/// small.
#[no_mangle]
pub extern "C" fn riscv64_trap_dispatch(frame: *mut TrapFrame) {
    // Safety: `frame` is the live trap frame saved by `stvec_trap`.
    let scause = unsafe { (*frame).scause };
    let sepc = unsafe { (*frame).sepc };
    let stval = unsafe { (*frame).stval };
    let sstatus = unsafe { (*frame).sstatus };
    // SPP (bit 8 of sstatus): 0 = U-mode, 1 = S-mode.
    let is_user = (sstatus & (1 << 8)) == 0;

    let kind = TrapKind::from_scause(scause);
    let is_interrupt = (scause >> 63) != 0;

    // For interrupts we deliver via the ke::interrupt path; for
    // synchronous exceptions we route by kind. For Phase 1 we only
    // service U-mode `ecall` and acknowledge everything else.
    if !is_interrupt {
        match kind {
            TrapKind::EnvironmentCallFromUMode => {
                // Syscall numbers arrive in $a7 (per Linux RISC-V
                // convention); arguments in $a0..$a5. We hand them
                // off to the syscall module which fills in $a0
                // with the return value and patches sepc so it
                // advances past the `ecall` instruction (we
                // re-execute it as an `ecall` only by accident —
                // advance by 4 to be safe).
                unsafe { crate::arch::riscv64::syscall::dispatch_syscall(frame); }
                // Advance sepc past the ecall (4 bytes on RV64).
                unsafe {
                    let new_sepc = sepc.wrapping_add(4);
                    (*frame).sepc = new_sepc;
                    write_sepc(new_sepc);
                }
            }
            TrapKind::EnvironmentCallFromSMode => {
                // Should not happen for kernel code unless an SBI
                // trampoline is involved. We pass through without
                // advancing sepc (the caller knows what to do).
                // Phase 1: nothing to do.
            }
            TrapKind::Breakpoint => {
                // Treat as no-op; advance past the `ebreak` so we
                // don't re-trigger. Real debugger support lands
                // later.
                unsafe {
                    let new_sepc = sepc.wrapping_add(
                        if is_compressed_at(sepc) { 2 } else { 4 }
                    );
                    (*frame).sepc = new_sepc;
                    write_sepc(new_sepc);
                }
            }
            TrapKind::LoadPageFault
            | TrapKind::StorePageFault
            | TrapKind::InstructionPageFault => {
                // Phase 1: not implemented yet — Phase 2 will plug
                // in the mm::vas page-fault handler. For now we
                // panic with diagnostic info so we can iterate.
                let is_write = matches!(kind, TrapKind::StorePageFault);
                let is_inst = matches!(kind, TrapKind::InstructionPageFault);
                panic!(
                    "RV64 page fault @ {:#x} (kind={:?}, write={}, inst={}, user={})",
                    stval, kind, is_write, is_inst, is_user
                );
            }
            TrapKind::IllegalInstruction => {
                panic!(
                    "RV64 illegal instruction @ sepc={:#x} (kind={:?})",
                    sepc, kind
                );
            }
            _ => {
                panic!(
                    "RV64 unhandled trap: {:?} (scause={:#x}) @ sepc={:#x}",
                    kind, scause, sepc
                );
            }
        }
    } else {
        // Interrupts: route through the PLIC/CLINT. We don't try
        // to classify the kind further — the apic module owns the
        // claim/complete logic.
        let hart = crate::arch::riscv64::smp::current_hart_id();
        let _ = hart;
        crate::arch::riscv64::apic::handle_irq();
        // sip.STIP / sip.SEIP / sip.SSIP are cleared by the
        // matching device-side EOI (PLIC complete or CLINT MSIP=0).
    }
}

/// Decide whether the instruction at `addr` is RVC (2-byte) or
/// base 4-byte. We probe by reading the lowest two bits — if they
/// are not `11`, the encoding is compressed.
///
/// # Safety
///
/// `addr` must point at a valid, executable page. The deref is
/// safe in that we only inspect bits; we don't rely on the value
/// beyond that.
#[inline]
fn is_compressed_at(addr: u64) -> bool {
    let insn: u16 = unsafe { *(addr as *const u16) };
    (insn & 0b11) != 0b11
}

/// Acknowledge an external interrupt (PLIC) for the current hart.
///
/// This is exposed as a helper for kernel code that wants to
/// poll for IRQs without going through the trap path (e.g. the
/// dispatcher in [`crate::ke::interrupt`]). The trap dispatcher
/// itself calls [`crate::arch::riscv64::apic::handle_irq`]
/// directly.
pub fn interrupt_ack_external() -> u32 {
    crate::arch::riscv64::apic::handle_irq()
}

/// Init hook for the trap subsystem. Currently empty — the
/// exception vector is installed by [`super::idt::init`]. Phase 2
/// will set up the timer interrupt enable bits.
pub fn init() {
    // Enable supervisor external interrupts at the `sie` level
    // and clear the `sip` pending bits.
    let sie = crate::arch::riscv64::csr::sie::read();
    let _ = sie;
    crate::arch::riscv64::csr::sie::set(
        crate::arch::riscv64::csr::sie::SEIE
        | crate::arch::riscv64::csr::sie::STIE
        | crate::arch::riscv64::csr::sie::SSIE,
    );
    // Init the CLINT and PLIC.
    crate::arch::riscv64::clint::init(0x2000000);
    crate::arch::riscv64::apic::init();
}

/// Smoke test: verify that the dispatcher symbol is reachable.
pub fn smoke_test() -> bool {
    let p: *const () = riscv64_trap_dispatch as *const ();
    !p.is_null()
}