//! AArch64 CPU feature detection.
//!
//! Uses `ID_AA64*` system registers exposed by ARMv8-A compliant
//! cores. The cached copy in [`CpuInfo`] is filled by [`init`] and
//! consulted by every other subsystem that needs to know whether a
//! feature is available (NEON, AES, virtualization, 16K pages, …).
//!
//! The implementation deliberately keeps the interface small and
//! `const`-friendly so other `init` paths can call into it without
//! pulling in the full HAL.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// Number of logical CPUs currently considered online.
static LOGICAL_CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// CPU feature flags extracted from `ID_AA64*` registers.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    /// Floating-point unit.
    pub fp: bool,
    /// SIMD/NEON (Advanced SIMD).
    pub asimd: bool,
    /// AES extension (ID_AA64ISAR0_EL1.AES).
    pub aes: bool,
    /// SHA-256/SHA-512 extension (ID_AA64ISAR0_EL1.SHA2).
    pub sha2: bool,
    /// CRC32 instructions (ID_AA64ISAR0_EL1.CRC32).
    pub crc32: bool,
    /// Atomic instructions (ID_AA64ISAR0_EL1.LSE).
    pub atomic: bool,
    /// 16-bit FP (FP16) — ID_AA64PFR0_EL1.FP bits == 0b01.
    pub fp16: bool,
    /// SVE present (ID_AA64PFR0_EL1.SVE != 0).
    pub sve: bool,
    /// EL2 — virtualisation supported.
    pub el2: bool,
    /// EL3 — secure monitor supported.
    pub el3: bool,
    /// 16 KiB granule supported by the MMU (TCR_ELx.IOS).
    pub granule_16k: bool,
    /// 64 KiB granule supported.
    pub granule_64k: bool,
}

impl CpuFeatures {
    /// Construct zeroed features.
    pub const fn empty() -> Self {
        Self {
            fp: false,
            asimd: false,
            aes: false,
            sha2: false,
            crc32: false,
            atomic: false,
            fp16: false,
            sve: false,
            el2: false,
            el3: false,
            granule_16k: false,
            granule_64k: false,
        }
    }
}

/// Cached CPU info, populated by [`init`].
static mut CPU_FEATURES: CpuFeatures = CpuFeatures::empty();

/// Read `ID_AA64PFR0_EL1` (Processor Feature Register 0).
#[inline(always)]
fn id_aa64pfr0_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64pfr0_el1", out(reg) v, options(nostack)) };
    v
}

/// Read `ID_AA64PFR1_EL1`.
#[inline(always)]
fn id_aa64pfr1_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nostack)) };
    v
}

/// Read `ID_AA64ISAR0_EL1` (Instruction Set Attribute Register 0).
#[inline(always)]
fn id_aa64isar0_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) v, options(nostack)) };
    v
}

/// Read `ID_AA64ISAR1_EL1`.
#[inline(always)]
fn id_aa64isar1_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64isar1_el1", out(reg) v, options(nostack)) };
    v
}

/// Read `ID_AA64MMFR0_EL1` (Memory Model Feature Register 0).
#[inline(always)]
fn id_aa64mmfr0_el1() -> u64 {
    let v: u64;
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nostack)) };
    v
}

/// Initialise the CPU feature cache. Called from `arch::aarch64::init()`.
pub fn init() {
    let pfr0 = id_aa64pfr0_el1();
    let pfr1 = id_aa64pfr1_el1();
    let isar0 = id_aa64isar0_el1();
    let isar1 = id_aa64isar1_el1();
    let mmfr0 = id_aa64mmfr0_el1();

    let mut feat = CpuFeatures::empty();

    // FP: PFR0[19:16] != 0 means FP is supported.
    feat.fp = (pfr0 >> 16) & 0xF != 0;
    // ASIMD: PFR0[23:20] != 0
    feat.asimd = (pfr0 >> 20) & 0xF != 0;
    // SVE: PFR0[35:32] != 0
    feat.sve = (pfr0 >> 32) & 0xF != 0;
    // FP16: PFR0[43:40] != 0
    feat.fp16 = (pfr0 >> 40) & 0xF != 0;
    // EL2: PFR0[15:12] != 0
    feat.el2 = (pfr0 >> 12) & 0xF != 0;
    // EL3: PFR0[11:8] != 0
    feat.el3 = (pfr0 >> 8) & 0xF != 0;

    // AES: ISAR0[7:4] != 0
    feat.aes = (isar0 >> 4) & 0xF != 0;
    // SHA2: ISAR0[15:12] != 0
    feat.sha2 = (isar0 >> 12) & 0xF != 0;
    // CRC32: ISAR0[23:20] != 0
    feat.crc32 = (isar0 >> 20) & 0xF != 0;
    // Atomic (LSE): ISAR0[23:20] for LSE == 0b0010
    let lse = (isar0 >> 20) & 0xF;
    feat.atomic = lse == 0x2;

    // 16 KiB granule: MMFR0[23:20] != 0
    feat.granule_16k = (mmfr0 >> 20) & 0xF != 0;
    // 64 KiB granule: MMFR0[27:24] != 0
    feat.granule_64k = (mmfr0 >> 24) & 0xF != 0;

    // Suppress unused-variable warnings for registers we read but
    // don't currently expose.
    let _ = pfr1;
    let _ = isar1;

    // Cache the feature set for later readers.
    unsafe {
        CPU_FEATURES = feat;
    }
}

/// Return the cached CPU features.
pub fn features() -> CpuFeatures {
    // Reading a static mut is safe because we never write to
    // `CPU_FEATURES` after init() completes (init() runs on each CPU
    // but writes the same content — the read is non-atomic and may
    // catch a half-update, which is benign because every reader
    // only ever looks at idempotent feature bits).
    unsafe { CPU_FEATURES }
}

/// Logical CPU count. Updated by the SMP bring-up path.
pub fn set_logical_cpu_count(n: u32) {
    LOGICAL_CPU_COUNT.store(n, Ordering::Release);
}

/// Return the cached logical CPU count.
pub fn logical_cpu_count() -> u32 {
    LOGICAL_CPU_COUNT.load(Ordering::Acquire)
}

/// Smoke test: verify `init()` populated the cache and that the FEAT
/// flags look plausible.
pub fn smoke_test() -> bool {
    let f = features();
    if !f.fp || !f.asimd {
        return false;
    }
    true
}
