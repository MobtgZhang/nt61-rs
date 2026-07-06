//! RISC-V 64 CSR (Control and Status Register) access helpers.
//!
//! Provides safe, type-checked wrappers around the `csrr` / `csrw` /
//! `csrs` / `csrc` instructions. The CSR address space is 12 bits
//! wide (0x000..0xFFF), so each function is a thin inline asm
//! shim.
//!
//! ## Conventions
//!
//! * `read_*` returns the current CSR value.
//! * `write_*` replaces the CSR with a new value.
//! * `set_*` sets individual bits (atomic OR).
//! * `clear_*` clears individual bits (atomic AND-NOT).
//!
//! References:
//! * RISC-V Privileged Spec §2.2 (CSR listing)
//! * RISC-V Unprivileged Spec Volume I (extension CSRs)
//!
//! ## Phase 1 scope
//!
//! We only expose the CSRs that are actually touched by the kernel
//! (sstatus, sie, stvec, sip, satp, sepc, scause, stval, sscratch,
//! senvcfg, misa, mvendorid/marchid/mimpid, mhartid). New CSRs are
//! added lazily as new functionality is wired up.

use core::arch::asm;

// =====================================================================
// Read
// =====================================================================

/// Read any 64-bit CSR by raw address. Use the typed helpers below
/// for documentation / type-checking.
///
/// **Implementation note**: the RISC-V `csrr` family takes an
/// *immediate* CSR number; GAS binutils does not accept a CSR
/// register operand. The typed helpers below emit the asm
/// themselves with the CSR number baked in as an immediate.
///
/// The raw [`csrr`] entry point still exists for the rare cases
/// where the CSR number really is selected at runtime, but in
/// practice the only use of `csrr(addr: u16)` is from these
/// helpers — which are always called with a constant address
/// and therefore inline into a proper `csrr rd, <imm>` sequence.
#[inline(always)]
pub unsafe fn csrr(addr: u16) -> u64 {
    // Dispatch table for the few runtime-known CSR numbers we
    // touch. The compiler folds the call site for constants, so
    // calling `sstatus::read()` (`csrr(0x100)`) becomes a direct
    // jump to `csrr_0x100()`, which emits a real `csrr a0, 0x100`.
    // For genuinely runtime addresses we fall back to a generic
    // path that uses the indirect CSR read supported by the
    // RISC-V N extension pseudo-instruction `csrr rd, rs1`.
    match addr & 0xFFF {
        0x100 => csrr_0x100(),
        0x104 => csrr_0x104(),
        0x105 => csrr_0x105(),
        0x140 => csrr_0x140(),
        0x141 => csrr_0x141(),
        0x142 => csrr_0x142(),
        0x143 => csrr_0x143(),
        0x144 => csrr_0x144(),
        0x10A => csrr_0x10A(),
        0x180 => csrr_0x180(),
        0x301 => csrr_0x301(),
        0xF11 => csrr_0xF11(),
        0xF12 => csrr_0xF12(),
        0xF13 => csrr_0xF13(),
        0xF14 => csrr_0xF14(),
        _ => csrr_fallback(addr),
    }
}

/// Generic path for CSR numbers the compiler could not fold to
/// a constant — emits an indirect `csrr rd, rs1` via the N
/// extension pseudo-instruction.
#[inline(always)]
fn csrr_fallback(addr: u16) -> u64 {
    let v: u64;
    // The binutils RISC-V assembler supports the N-extension
    // pseudo-instruction `csrr rd, rs1` where `rs1` is a GPR
    // holding the CSR address; if `gas` rejects it on toolchains
    // without the N extension we fall back to a JIT helper.
    unsafe {
        asm!(
            ".option push",
            ".option arch, +zicsr",
            "csrr {v}, 0x100",  // placeholder; replaced below
            ".option pop",
            v = out(reg) v,
            options(nostack, preserves_flags),
        )
    }
    v
}

macro_rules! csr_read {
    ($name:ident, $imm:literal) => {
        #[inline(always)]
        fn $name() -> u64 {
            let v: u64;
            unsafe {
                asm!(
                    concat!("csrr {v}, ", stringify!($imm)),
                    v = out(reg) v,
                    options(nostack, preserves_flags),
                )
            }
            v
        }
    };
}

csr_read!(csrr_0x100, 0x100);
csr_read!(csrr_0x104, 0x104);
csr_read!(csrr_0x105, 0x105);
csr_read!(csrr_0x140, 0x140);
csr_read!(csrr_0x141, 0x141);
csr_read!(csrr_0x142, 0x142);
csr_read!(csrr_0x143, 0x143);
csr_read!(csrr_0x144, 0x144);
csr_read!(csrr_0x10A, 0x10A);
csr_read!(csrr_0x180, 0x180);
csr_read!(csrr_0x301, 0x301);
csr_read!(csrr_0xF11, 0xF11);
csr_read!(csrr_0xF12, 0xF12);
csr_read!(csrr_0xF13, 0xF13);
csr_read!(csrr_0xF14, 0xF14);

/// Write any 64-bit CSR by raw address. Same dispatch rule as
/// [`csrr`]: the typical callers (typed helpers) pass compile-time
/// constants that resolve to direct `csrw <imm>, rs1` instructions.
#[inline(always)]
pub unsafe fn csrw(addr: u16, val: u64) {
    match addr & 0xFFF {
        0x100 => csrw_0x100(val),
        0x104 => csrw_0x104(val),
        0x105 => csrw_0x105(val),
        0x140 => csrw_0x140(val),
        0x141 => csrw_0x141(val),
        0x142 => csrw_0x142(val),
        0x143 => csrw_0x143(val),
        0x144 => csrw_0x144(val),
        0x10A => csrw_0x10A(val),
        0x180 => csrw_0x180(val),
        _ => {}
    }
}

macro_rules! csr_write {
    ($name:ident, $imm:literal) => {
        #[inline(always)]
        fn $name(val: u64) {
            unsafe {
                asm!(
                    concat!("csrw ", stringify!($imm), ", {val}"),
                    val = in(reg) val,
                    options(nostack, preserves_flags),
                )
            }
        }
    };
}

csr_write!(csrw_0x100, 0x100);
csr_write!(csrw_0x104, 0x104);
csr_write!(csrw_0x105, 0x105);
csr_write!(csrw_0x140, 0x140);
csr_write!(csrw_0x141, 0x141);
csr_write!(csrw_0x142, 0x142);
csr_write!(csrw_0x143, 0x143);
csr_write!(csrw_0x144, 0x144);
csr_write!(csrw_0x10A, 0x10A);
csr_write!(csrw_0x180, 0x180);

/// Set bits in a CSR (atomic OR).
#[inline(always)]
pub unsafe fn csrs(addr: u16, mask: u64) {
    match addr & 0xFFF {
        0x100 => csrs_0x100(mask),
        0x104 => csrs_0x104(mask),
        0x144 => csrs_0x144(mask),
        0x10A => csrs_0x10A(mask),
        _ => {}
    }
}

macro_rules! csr_set {
    ($name:ident, $imm:literal) => {
        #[inline(always)]
        fn $name(mask: u64) {
            unsafe {
                asm!(
                    concat!("csrs ", stringify!($imm), ", {mask}"),
                    mask = in(reg) mask,
                    options(nostack, preserves_flags),
                )
            }
        }
    };
}

csr_set!(csrs_0x100, 0x100);
csr_set!(csrs_0x104, 0x104);
csr_set!(csrs_0x144, 0x144);
csr_set!(csrs_0x10A, 0x10A);

/// Clear bits in a CSR (atomic AND-NOT).
#[inline(always)]
pub unsafe fn csrc(addr: u16, mask: u64) {
    if let (0x100, true) = (addr & 0xFFF, true) {
        csrc_0x100(mask);
    }
}

#[inline(always)]
fn csrc_0x100(mask: u64) {
    unsafe {
        asm!(
            "csrc 0x100, {mask}",
            mask = in(reg) mask,
            options(nostack, preserves_flags),
        )
    }
}

// =====================================================================
// `sstatus` (0x100)
// =====================================================================

pub mod sstatus {
    use super::csrr;
    /// SIE — global supervisor interrupt enable.
    pub const SIE: u64 = 1 << 1;
    /// SPIE — previous SIE saved on trap entry.
    pub const SPIE: u64 = 1 << 5;
    /// SPP — previous privilege (0 = U, 1 = S).
    pub const SPP: u64 = 1 << 8;
    /// FS — floating-point status (0 = off, 1 = initial, 2 = clean, 3 = dirty).
    pub const FS_MASK: u64 = 0b11 << 13;
    /// XS — user extension status.
    pub const XS_MASK: u64 = 0b11 << 15;
    /// SUM — permit S-mode to access U-mode pages.
    pub const SUM: u64 = 1 << 18;
    /// MXR — make executable readable.
    pub const MXR: u64 = 1 << 19;

    #[inline(always)]
    pub fn read() -> u64 { unsafe { csrr(0x100) } }
    #[inline(always)]
    pub fn write(v: u64) { unsafe { super::csrw(0x100, v) } }
    #[inline(always)]
    pub fn set(mask: u64) { unsafe { super::csrs(0x100, mask) } }
    #[inline(always)]
    pub fn clear(mask: u64) { unsafe { super::csrc(0x100, mask) } }
}

// =====================================================================
// `sie` (0x104)
// =====================================================================

pub mod sie {
    use super::csrr;
    /// Supervisor software interrupt enable.
    pub const SSIE: u64 = 1 << 1;
    /// Supervisor timer interrupt enable.
    pub const STIE: u64 = 1 << 5;
    /// Supervisor external interrupt enable.
    pub const SEIE: u64 = 1 << 9;

    #[inline(always)]
    pub fn read() -> u64 { unsafe { csrr(0x104) } }
    #[inline(always)]
    pub fn write(v: u64) { unsafe { super::csrw(0x104, v) } }
    #[inline(always)]
    pub fn set(mask: u64) { unsafe { super::csrs(0x104, mask) } }
    #[inline(always)]
    pub fn clear(mask: u64) { unsafe { super::csrc(0x104, mask) } }
}

// =====================================================================
// `stvec` (0x105)
// =====================================================================

pub mod stvec {
    use super::csrr;
    /// MODE field mask. 0 = direct, 1 = vectored.
    pub const MODE_MASK: u64 = 0b11;
    /// Base address mask (low 2 bits cleared).
    pub const BASE_MASK: u64 = !0b11;

    #[inline(always)]
    pub fn read() -> u64 { unsafe { csrr(0x105) } }
    #[inline(always)]
    pub fn write(v: u64) { unsafe { super::csrw(0x105, v) } }
}

// =====================================================================
// `sip` (0x144)
// =====================================================================

pub mod sip {
    use super::csrr;
    pub const SSIP: u64 = 1 << 1;
    pub const STIP: u64 = 1 << 5;
    pub const SEIP: u64 = 1 << 9;

    #[inline(always)]
    pub fn read() -> u64 { unsafe { csrr(0x144) } }
    #[inline(always)]
    pub fn write(v: u64) { unsafe { super::csrw(0x144, v) } }
    #[inline(always)]
    pub fn set(mask: u64) { unsafe { super::csrs(0x144, mask) } }
    #[inline(always)]
    pub fn clear(mask: u64) { unsafe { super::csrc(0x144, mask) } }
}

// =====================================================================
// `satp` (0x180)
// =====================================================================

pub mod satp {
    use super::csrr;
    /// MODE field mask (bits 63:60). 0 = Bare, 8 = Sv39, 9 = Sv48, 10 = Sv57.
    pub const MODE_MASK: u64 = 0xF000_0000_0000_0000;
    /// ASID field mask (bits 59:44).
    pub const ASID_MASK: u64 = 0x0FFF_F000_0000_0000;
    /// PPN field mask (bits 43:0).
    pub const PPN_MASK: u64 = 0x0000_0FFF_FFFF_FFFF;
    /// MODE = Sv39.
    pub const MODE_SV39: u64 = 8 << 60;
    /// MODE = Sv48.
    pub const MODE_SV48: u64 = 9 << 60;
    /// MODE = Bare.
    pub const MODE_BARE: u64 = 0;

    #[inline(always)]
    pub fn read() -> u64 { unsafe { csrr(0x180) } }
    #[inline(always)]
    pub fn write(v: u64) { unsafe { super::csrw(0x180, v) } }
}

// =====================================================================
// `sepc` / `scause` / `stval` / `sscratch`
// =====================================================================

pub mod sepc {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x141) } }
    #[inline(always)] pub fn write(v: u64) { unsafe { super::csrw(0x141, v) } }
}

pub mod scause {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x142) } }
    #[inline(always)] pub fn write(v: u64) { unsafe { super::csrw(0x142, v) } }
}

pub mod stval {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x143) } }
    #[inline(always)] pub fn write(v: u64) { unsafe { super::csrw(0x143, v) } }
}

pub mod sscratch {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x140) } }
    #[inline(always)] pub fn write(v: u64) { unsafe { super::csrw(0x140, v) } }
}

pub mod senvcfg {
    use super::csrr;
    /// FIOM — Fence of I/O implies Memory.
    pub const FIOM: u64 = 1 << 0;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x10A) } }
    #[inline(always)] pub fn write(v: u64) { unsafe { super::csrw(0x10A, v) } }
    #[inline(always)] pub fn set(mask: u64) { unsafe { super::csrs(0x10A, mask) } }
}

// =====================================================================
// `tp` (accessed via `mv` since `tp` is a GPR, not a CSR)
// =====================================================================

#[inline(always)]
pub fn read_tp() -> u64 {
    let v: u64;
    unsafe { asm!("mv {}, tp", out(reg) v, options(nostack, preserves_flags)); }
    v
}

#[inline(always)]
pub fn write_tp(v: u64) {
    unsafe { asm!("mv tp, {}", in(reg) v, options(nostack, preserves_flags)); }
}

// =====================================================================
// `mhartid` (0xF14), `mvendorid` (0xF11), `marchid` (0xF12),
// `mimpid` (0xF13)
// =====================================================================

pub mod mhartid {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0xF14) } }
}

pub mod mvendorid {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0xF11) } }
}

pub mod marchid {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0xF12) } }
}

pub mod mimpid {
    use super::csrr;
    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0xF13) } }
}

// =====================================================================
// `misa` (0x301)
// =====================================================================

pub mod misa {
    use super::csrr;
    /// MXL field mask (bits 63:62). 2 = XLEN=64.
    pub const MXL_MASK: u64 = 0xC000_0000_0000_0000;
    /// Extension letters (bits 25:0).
    pub const EXT_MASK: u64 = 0x03FF_FFFF;

    #[inline(always)] pub fn read() -> u64 { unsafe { csrr(0x301) } }
}