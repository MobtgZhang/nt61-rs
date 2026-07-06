//! Per-CPU capability information.
//!
//! Reports which LoongArch CPU features each core exposes (LSX / LASX /
//! LBT / LVZ / SMT). The detection builds on `arch::loongarch64::soc`,
//! so `soc::detect()` should have been called first.
//!
//! References:
//!   * LoongArch Reference Manual — CPUCFG feature words 0x11/0x12
//   * Linux arch/loongarch/kernel/cpu-probe.c (probe_level())

#![cfg(target_arch = "loongarch64")]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::loongarch64::soc;

/// Cached aggregate of feature bits exposed across all CPU cores.
///
/// We also expose per-core feature words where the hardware differs
/// (rare on a single SoC, but visible on heterogeneous boards).
#[derive(Copy, Clone, Default)]
pub struct CpuFeatures {
    /// Raw 64-bit value of CPUCFG word 0x11 (CPU feature bits 1).
    bits_word11: u64,
    /// Raw 64-bit value of CPUCFG word 0x12 (CPU feature bits 2).
    bits_word12: u64,
}

/// Set by `cpuinfo::detect_all` once during early boot.
static FEATURES: AtomicU64 = AtomicU64::new(0);

/// Stable feature flags derived from CPUCFG.
pub mod feature {
    /// LSX 128-bit SIMD (SIMD-128 on top of LA64).
    pub const LSX: u64 = 1 << 0;
    /// LASX 256-bit SIMD (LA664 only).
    pub const LASX: u64 = 1 << 1;
    /// LBT — Branch Target identification.
    pub const LBT: u64 = 1 << 2;
    /// LVZ — Virtualization (hypervisor) extension.
    pub const LVZ: u64 = 1 << 3;
    /// LAM — Linear Address Mask.
    pub const LAM: u64 = 1 << 4;
    /// Hardware SMT (HT) — derived from SoC microarchitecture.
    pub const SMT: u64 = 1 << 5;
}

impl CpuFeatures {
    pub const fn empty() -> Self {
        Self { bits_word11: 0, bits_word12: 0 }
    }

    /// Construct from raw CPUCFG words.
    pub const fn from_raw(w11: u64, w12: u64) -> Self {
        Self { bits_word11: w11, bits_word12: w12 }
    }

    /// True if the named feature is present.
    pub fn has(&self, flag: u64) -> bool {
        // First consult derived flags (which may incorporate SoC info
        // like SMT, or aggregate bits 5/6 of word 0x11 for SIMD).
        match flag {
            feature::LSX => (self.bits_word11 & (1 << 6)) != 0 || soc::is_lsx_capable(),
            feature::LASX => (self.bits_word11 & (1 << 5)) != 0 || soc::is_lasx_capable(),
            feature::LBT => (self.bits_word11 & (1 << 8)) != 0,
            feature::LVZ => (self.bits_word11 & (1 << 9)) != 0,
            feature::LAM => (self.bits_word11 & (1 << 10)) != 0,
            feature::SMT => soc::is_smt_capable(),
            _ => false,
        }
    }
}

/// Read CPUCFG word 0x11 (CPU feature flags 1).
fn read_word_11() -> u64 {
    unsafe { soc::cpucfg_read(0x11) }
}

/// Read CPUCFG word 0x12 (CPU feature flags 2).
fn read_word_12() -> u64 {
    unsafe { soc::cpucfg_read(0x12) }
}

/// Detect all CPU features for the boot core and cache them.
/// Idempotent.
pub fn detect_all() -> CpuFeatures {
    let feat = CpuFeatures::from_raw(read_word_11(), read_word_12());
    let mut bits: u64 = 0;
    if feat.has(feature::LSX) { bits |= feature::LSX; }
    if feat.has(feature::LASX) { bits |= feature::LASX; }
    if feat.has(feature::LBT) { bits |= feature::LBT; }
    if feat.has(feature::LVZ) { bits |= feature::LVZ; }
    if feat.has(feature::LAM) { bits |= feature::LAM; }
    if feat.has(feature::SMT) { bits |= feature::SMT; }
    FEATURES.store(bits, Ordering::Release);
    feat
}

/// Return the cached feature bitmask (or detect on the first call).
pub fn features_mask() -> u64 {
    let v = FEATURES.load(Ordering::Acquire);
    if v == 0 {
        let _ = detect_all();
        FEATURES.load(Ordering::Acquire)
    } else {
        v
    }
}

/// Convenience predicate — does the running CPU support `flag`?
pub fn has(flag: u64) -> bool {
    features_mask() & flag != 0
}
