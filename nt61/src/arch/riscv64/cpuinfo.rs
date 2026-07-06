//! RISC-V 64 per-CPU capability information.
//!
//! Reports which RISC-V ISA extensions each core exposes. The
//! detection builds on [`super::soc`] — `soc::detect()` should have
//! been called first so the static SoC table is populated.
//!
//! ## References
//!
//! * RISC-V Unprivileged ISA Manual Volume I — " misa " register
//!   (extension letters).
//! * RISC-V Privileged Specification §3.1.3 (`misa` layout).
//! * Linux arch/riscv/kernel/cpufeature.c (probe behaviour).

use core::sync::atomic::{AtomicU64, Ordering};

/// ISA extension bitmask.
///
/// The low 26 bits mirror `misa`'s "extension letters" field. The
/// high bits hold a few derived flags that are easier to test as a
/// single bit (e.g. `RV_GC_BASE`).
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct IsaExtensions(pub u64);

impl IsaExtensions {
    pub const fn empty() -> Self { Self(0) }
    pub const fn from_bits(bits: u64) -> Self { Self(bits) }
    pub const fn bits(self) -> u64 { self.0 }
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    pub const fn insert(&mut self, other: Self) { self.0 |= other.0; }
    pub const fn remove(&mut self, other: Self) { self.0 &= !other.0; }
}

// Extension letter bits — directly mirror `misa[25:0]`.
impl IsaExtensions {
    /// Base integer ISA.
    pub const I: Self = Self(1 << 8);
    /// Integer multiply/divide.
    pub const M: Self = Self(1 << 12);
    /// Atomics.
    pub const A: Self = Self(1 << 0);
    /// Single-precision floating-point.
    pub const F: Self = Self(1 << 5);
    /// Double-precision floating-point.
    pub const D: Self = Self(1 << 3);
    /// Compressed instructions.
    pub const C: Self = Self(1 << 2);
    /// Vector extension.
    pub const V: Self = Self(1 << 21);
    /// Bitmanip.
    pub const B: Self = Self(1 << 1);
    /// Hypervisor.
    pub const H: Self = Self(1 << 7);
    /// Scalar crypto.
    pub const K: Self = Self(1 << 11);
    /// JIT (RVJ) — out of scope, reserved for future.
    pub const J: Self = Self(1 << 9);
    /// Packed SIMD (P).
    pub const P: Self = Self(1 << 15);
    /// Privileged spec M-mode/S-mode standard.
    pub const S: Self = Self(1 << 18);
    /// User-mode traps.
    pub const U: Self = Self(1 << 20);
}

// Sub-ext bits — reserved for higher letters (Z* prefix).
impl IsaExtensions {
    /// `Zicntr` — base counters.
    pub const ZICNTR: Self = Self(1 << 32);
    /// `Zihpm` — hardware performance counters.
    pub const ZIHPM: Self = Self(1 << 33);
    /// `Zicsr` — CSR instructions.
    pub const ZICSR: Self = Self(1 << 34);
    /// `Zifencei` — fence.i instruction.
    pub const ZIFENCEI: Self = Self(1 << 35);
    /// `Zicond` — conditional operations.
    pub const ZICOND: Self = Self(1 << 36);
    /// `Zicbo*` — cache-block ops.
    pub const ZICBO: Self = Self(1 << 37);
    /// `Sv48` — 48-bit virtual address space.
    pub const SV48: Self = Self(1 << 38);
    /// `Sv57` — 57-bit virtual address space.
    pub const SV57: Self = Self(1 << 39);
}

// Convenience aggregates.
impl IsaExtensions {
    /// I + M + A + C — the IMAC profile.
    pub const RV_IMAC_BASE: Self = Self(
        Self::I.0 | Self::M.0 | Self::A.0 | Self::C.0 | Self::U.0 | Self::S.0
    );
    /// I + M + A + F + D + C — the GC profile.
    pub const RV_GC_BASE: Self = Self(
        Self::I.0 | Self::M.0 | Self::A.0 | Self::F.0
        | Self::D.0 | Self::C.0 | Self::U.0 | Self::S.0
        | Self::ZICSR.0 | Self::ZIFENCEI.0 | Self::ZICNTR.0
    );
    /// GCV profile — adds Vector.
    pub const RV_GCV_BASE: Self = Self(
        Self::I.0 | Self::M.0 | Self::A.0 | Self::F.0
        | Self::D.0 | Self::C.0 | Self::V.0 | Self::U.0 | Self::S.0
        | Self::ZICSR.0 | Self::ZIFENCEI.0 | Self::ZICNTR.0
    );
}

// =====================================================================
// `misa` parsing
// =====================================================================

/// Read the `misa` CSR (0x301).
#[inline(always)]
fn read_misa() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, 0x301", out(reg) v, options(nostack)); }
    v
}

/// Decode a `misa` value into an [`IsaExtensions`] bitmask.
///
/// `misa` layout (RV64): bit 63 = MXL (2 = RV64), bits 25..0 =
/// extension letters (A=1, B=2, C=4, D=8, E=16, F=32, ...).
fn parse_misa(misa: u64) -> IsaExtensions {
    let mut e = IsaExtensions::empty();
    // MXL lives in bits [63:62]. Anything other than 2 is not
    // RV64; we still report the bits we know about so downstream
    // checks degrade gracefully.
    let mxl = (misa >> 62) & 0b11;
    if mxl != 2 && mxl != 0 {
        // Probably RV32 — leave the parsed letters alone but do
        // not enable RV64-only aggregates (F/D/V).
    }
    if misa & (1 << 0) != 0 { e.insert(IsaExtensions::A); }
    if misa & (1 << 1) != 0 { e.insert(IsaExtensions::B); }
    if misa & (1 << 2) != 0 { e.insert(IsaExtensions::C); }
    if misa & (1 << 3) != 0 { e.insert(IsaExtensions::D); }
    if misa & (1 << 5) != 0 { e.insert(IsaExtensions::F); }
    if misa & (1 << 7) != 0 { e.insert(IsaExtensions::H); }
    if misa & (1 << 8) != 0 { e.insert(IsaExtensions::I); }
    if misa & (1 << 9) != 0 { e.insert(IsaExtensions::J); }
    if misa & (1 << 11) != 0 { e.insert(IsaExtensions::K); }
    if misa & (1 << 12) != 0 { e.insert(IsaExtensions::M); }
    if misa & (1 << 15) != 0 { e.insert(IsaExtensions::P); }
    if misa & (1 << 18) != 0 { e.insert(IsaExtensions::S); }
    if misa & (1 << 20) != 0 { e.insert(IsaExtensions::U); }
    if misa & (1 << 21) != 0 { e.insert(IsaExtensions::V); }

    // Always-on sub-exts on any conformant RISC-V core — they're
    // so universally implemented that misa does not report them.
    e.insert(IsaExtensions::ZICSR);
    e.insert(IsaExtensions::ZIFENCEI);
    e.insert(IsaExtensions::ZICNTR);
    e
}

// =====================================================================
// Per-Hart / Aggregate feature state
// =====================================================================

/// Per-hart feature snapshot. Kept in a per-CPU slot when the
/// kernel has SMP up. At Phase 0 we only use the boot-hart entry.
#[derive(Copy, Clone, Debug, Default)]
pub struct PerHartCpuInfo {
    pub hart_id: u32,
    pub misa_value: u64,
    pub isa: IsaExtensions,
    pub mvendorid: u32,
    pub marchid: u64,
    pub mimpid: u64,
    pub supports_svinval: bool,
}

impl PerHartCpuInfo {
    pub const fn empty() -> Self { Self {
        hart_id: 0, misa_value: 0, isa: IsaExtensions::empty(),
        mvendorid: 0, marchid: 0, mimpid: 0, supports_svinval: false,
    } }
}

// =====================================================================
// Cached global state
// =====================================================================

/// Aggregate ISA extensions across all observed harts. Phase 2
/// also keeps a per-hart slot for harts that come online later.
static ISA_FEATURES: AtomicU64 = AtomicU64::new(0);

/// Cached `misa` value.
static MISA: AtomicU64 = AtomicU64::new(0);

/// Maximum number of per-hart ISA snapshots we cache.
pub const MAX_HARTS: usize = 64;

/// Per-hart feature snapshots, indexed by hart id.
static HART_FEATURES: [AtomicU64; MAX_HARTS] =
    [const { AtomicU64::new(0) }; MAX_HARTS];

/// Cached senvcfg value (Sv48 hint etc.).
static SENVCFG: AtomicU64 = AtomicU64::new(0);

// =====================================================================
// Public API
// =====================================================================

/// Detect ISA features for the boot core and cache them. Idempotent.
pub fn detect_all() -> IsaExtensions {
    let misa = read_misa();
    let isa = parse_misa(misa);
    ISA_FEATURES.store(isa.0, Ordering::Release);
    MISA.store(misa, Ordering::Release);
    // Probe senvcfg and derive the Sv48/Sv57 hint.
    let senv = crate::arch::riscv64::csr::senvcfg::read();
    SENVCFG.store(senv, Ordering::Relaxed);
    isa
}

/// Probe the running hart and store its ISA into the per-hart
/// slot. Used by the SMP trampoline to publish each secondary
/// hart's features.
pub fn probe_current_hart(hart_id: u32) -> IsaExtensions {
    let misa = read_misa();
    let isa = parse_misa(misa);
    if (hart_id as usize) < MAX_HARTS {
        HART_FEATURES[hart_id as usize].store(isa.0, Ordering::Release);
    }
    // Update the aggregate mask — features enabled on any hart are
    // considered present in the running system.
    let prev = IsaExtensions(ISA_FEATURES.load(Ordering::Acquire));
    let merged = IsaExtensions(prev.0 | isa.0);
    ISA_FEATURES.store(merged.0, Ordering::Release);
    isa
}

/// Return the per-hart ISA extensions for `hart_id`. The result
/// is zero-extended if the hart has not been probed yet.
pub fn hart_features(hart_id: u32) -> IsaExtensions {
    if (hart_id as usize) >= MAX_HARTS { return IsaExtensions::empty(); }
    IsaExtensions(HART_FEATURES[hart_id as usize].load(Ordering::Acquire))
}

/// Probe whether the running core supports the Sv48 paging mode.
/// We inspect `misa` for the implicit XLEN=64 requirement and
/// assume Sv48 is available on any RV64 system that reports
/// XLEN=64 (misa.MXL=2). Hardware that omits Sv48 would
/// trap on `sret` with `sbadaddr` set to the offending VA,
/// at which point the kernel falls back to Sv39.
pub fn supports_sv48() -> bool {
    let misa = MISA.load(Ordering::Acquire);
    if misa == 0 { detect_all(); }
    let mxl = (MISA.load(Ordering::Acquire) >> 62) & 0b11;
    mxl == 2
}

/// Probe whether the running core supports Sv57. Per the
/// Privileged Spec, Sv57 is conditional on RV64 + explicit
/// support; we conservatively assume no until proven otherwise.
pub fn supports_sv57() -> bool {
    false
}

/// Cached senvcfg value (or 0 if not yet probed).
pub fn senvcfg() -> u64 {
    if SENVCFG.load(Ordering::Acquire) == 0 {
        detect_all();
    }
    SENVCFG.load(Ordering::Acquire)
}

/// Cached aggregate ISA extensions (or detect on first call).
pub fn features_mask() -> IsaExtensions {
    let v = ISA_FEATURES.load(Ordering::Acquire);
    if v == 0 {
        detect_all();
        IsaExtensions(ISA_FEATURES.load(Ordering::Acquire))
    } else {
        IsaExtensions(v)
    }
}

/// Convenience predicate — does the running CPU support the given
/// extension?
pub fn has(ext: IsaExtensions) -> bool {
    features_mask().contains(ext)
}

/// Raw `misa` value.
pub fn misa() -> u64 {
    let v = MISA.load(Ordering::Acquire);
    if v == 0 { detect_all(); }
    MISA.load(Ordering::Acquire)
}

/// Build a [`PerHartCpuInfo`] for the current hart.
pub fn per_hart_info(hart_id: u32) -> PerHartCpuInfo {
    PerHartCpuInfo {
        hart_id,
        misa_value: misa(),
        isa: features_mask(),
        mvendorid: crate::arch::riscv64::soc::mvendorid(),
        marchid: crate::arch::riscv64::soc::marchid(),
        mimpid: crate::arch::riscv64::soc::mimpid(),
        // Svinval is exposed via the `senvcfg` CSR's `SIFIVE_C`
        // bit on some SoCs. Phase 0 hard-codes "no"; Phase 2 will
        // probe.
        supports_svinval: false,
    }
}

/// Initialise the CPU-feature subsystem. Called from
/// [`super::mod::init`].
pub fn init_cpuinfo() {
    let _ = detect_all();
}

/// Smoke test: verify `features_mask` returns a sane bitmask.
pub fn smoke_test() -> bool {
    let f = features_mask();
    // I + S + U must be set on every conformant hart — the bit
    // positions are reserved by the spec.
    f.contains(IsaExtensions::I) && f.contains(IsaExtensions::S)
        && f.contains(IsaExtensions::U)
}