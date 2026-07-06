//! LoongArch64 trap / exception dispatch.
//!
//! Phase 1 of the LA64 plan introduces the high-level dispatch
//! routine that runs after `loongarch64_exception` (in `idt.rs`)
//! has saved the trap frame. We map the LoongArch `ESTAT.ExcCode`
//! field onto a `TrapKind` enum and dispatch:
//!
//! * `Syscall`     — branch into `syscall::dispatch_syscall`.
//! * `PageFault`   — currently a panic; Phase 2 will wire this into
//!                    the page-fault handler in `mm::vas`.
//! * `IllegalInst`,
//!   `AddressError`,
//!   `Breakpoint`,
//!   `Other`       — panic with diagnostic info.
//!
//! The trap frame layout must match the order in which
//! `loongarch64_exception` saves registers. See `arch::loongarch64::idt`
//! for the layout.

use core::arch::asm;

/// Exception code values from the LoongArch `ESTAT` register.
///
/// Reference: LoongArch Reference Manual, Volume 1, §7.4
/// ("Exception Status Register"). Only the subset used by this
/// kernel is enumerated.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapKind {
    Int = 0,         // External interrupt
    PIl = 1,         // Reserved / pending interrupt
    PIS = 2,         // Same
    PME = 3,         // Performance monitor
    PpiHvi = 4,      // Same family
    Syscall = 5,     // `syscall` instruction (user mode)
    Breakpoint = 6,  // `break`
    InstNonAligned = 7,
    InstAccessFault = 8,
    InstPageFault = 9,   // PIF
    InstPageNonPresentFault = 10,
    InstPageWriteFault = 11,
    LoadPageFault = 12,
    StorePageFault = 13,
    LoadAddrError = 14,
    StoreAddrError = 15,
    InstIllegal = 16,
    MisalignedAtomic = 17, // not on all models
    Other(u32),
}

impl From<u32> for TrapKind {
    fn from(code: u32) -> Self {
        match code {
            0 => TrapKind::Int,
            5 => TrapKind::Syscall,
            6 => TrapKind::Breakpoint,
            9 => TrapKind::InstPageFault,
            12 => TrapKind::LoadPageFault,
            13 => TrapKind::StorePageFault,
            14 => TrapKind::LoadAddrError,
            15 => TrapKind::StoreAddrError,
            16 => TrapKind::InstIllegal,
            other => TrapKind::Other(other),
        }
    }
}

/// Trap frame pushed by `loongarch64_exception`. The layout mirrors
/// the order of `st.d` instructions in `idt.rs`.
///
/// | Offset | Field | Source |
/// |--------|-------|--------|
/// | 0x00   | ra    |        |
/// | 0x08   | tp    |        |
/// | 0x10   | s0..s8 |       |
/// | 0x60   | fp    |        |
/// | 0x68   | a0..a7 |       |
/// | 0xA8   | t0..t7 |       |
///
/// Phase 1 only uses a0..a7 for syscall argument parsing; we expose
/// the full layout for forward compatibility.
#[repr(C)]
#[derive(Debug, Default)]
pub struct TrapFrame {
    pub ra: u64,
    pub tp: u64,
    pub s: [u64; 9],   // s0..s8
    pub fp: u64,
    pub a: [u64; 8],   // a0..a7
    pub t: [u64; 8],   // t0..t7
}

/// Address-error / page-fault information extracted from the
/// `BADV` (Bad Virtual Address) CSR.
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    pub badv: u64,
    pub is_write: bool,
    pub is_instruction: bool,
}

/// Read ESTAT (Exception Status) CSR (0x9).
#[inline(always)]
pub fn read_estat() -> u32 {
    let v: u32;
    unsafe { asm!("csrrd {0}, 0x9", out(reg) v, options(nostack)); }
    v
}

/// Read ERA (Exception Return Address) CSR (0x6).
#[inline(always)]
pub fn read_era() -> u64 {
    let v: u64;
    unsafe { asm!("csrrd {0}, 0x6", out(reg) v, options(nostack)); }
    v
}

/// Read BADV (Bad Virtual Address) CSR (0x7).
#[inline(always)]
pub fn read_badv() -> u64 {
    let v: u64;
    unsafe { asm!("csrrd {0}, 0x7", out(reg) v, options(nostack)); }
    v
}

/// Read PRMD (Previous Mode) CSR (0x1) — bit 0 = PIE, bit 1 = PPL.
#[inline(always)]
pub fn read_prmd() -> u32 {
    let v: u32;
    unsafe { asm!("csrrd {0}, 0x1", out(reg) v, options(nostack)); }
    v
}

/// Top-level trap dispatcher invoked from `handle_trap` in
/// `arch::loongarch64::idt`. We read ESTAT to determine the cause,
/// branch accordingly, and return whether the trap was handled.
///
/// For Phase 1, only `TrapKind::Syscall` is meaningfully routed;
/// the rest either panic or print a diagnostic via the (disabled)
/// `kprintln!` to keep the build small.
#[no_mangle]
pub extern "C" fn trap_dispatch(frame: *mut TrapFrame) {
    let estat = read_estat();
    let exc_code = estat & 0x3F;
    let kind: TrapKind = exc_code.into();

    match kind {
        TrapKind::Syscall => {
            // Syscall numbers arrive in $a7 (per Linux/LA convention);
            // arguments in $a0..$a5. We hand them off to the syscall
            // module which fills in $a0 with the return value and
            // patches the trap frame so the saved ERA advances past
            // the syscall instruction (we don't actually replay it).
            unsafe { crate::arch::loongarch64::syscall::dispatch_syscall(frame); }
        }
        TrapKind::InstPageFault
        | TrapKind::LoadPageFault
        | TrapKind::StorePageFault => {
            // Phase 1: not implemented yet — Phase 2 will plug in the
            // mm::vas page-fault handler.
            let badv = read_badv();
            let is_write = matches!(kind, TrapKind::StorePageFault);
            let is_inst = matches!(kind, TrapKind::InstPageFault);
            panic!(
                "LA64 page fault @ {:#x} (write={}, inst={})",
                badv, is_write, is_inst
            );
        }
        TrapKind::InstIllegal => {
            let era = read_era();
            panic!("LA64 illegal instruction @ ERA={:#x}", era);
        }
        TrapKind::Breakpoint => {
            let era = read_era();
            // Treat as no-op; advance past the `break` so we don't
            // re-trigger. Real debugger support lands in Phase 2.
            unsafe {
                asm!(
                    "csrwr {era}, 0x6",  // ERA = next instruction
                    era = in(reg) era + 4,
                    options(nostack),
                );
            }
        }
        _ => {
            let era = read_era();
            panic!("LA64 unhandled trap: {:?} (ESTAT={:#x}) @ ERA={:#x}",
                   kind, estat, era);
        }
    }
}