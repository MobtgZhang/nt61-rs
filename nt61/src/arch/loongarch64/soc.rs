//! SoC microarchitecture detection and identification.
//!
//! Wraps the LA64 `CPUCFG` instruction and identifies which Loongson
//! microarchitecture the running CPU belongs to (LA364 / LA464 / LA664).
//! The detected microarchitecture is stored globally so other subsystems
//! (smp, scheduler, fpu, btl) can adapt their behaviour.
//!
//! References:
//!   * LoongArch Reference Manual — Volume 1 — `CPUCFG` instruction
//!   * Loongson 3A5000/3A6000 manuals (LA464/LA664 PRID tables)

#![cfg(target_arch = "loongarch64")]

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

/// CPUCFG word 0 — lowest PRID field.
const CPUCFG_WORD0: u16 = 0;
/// CPUCFG word 1 — vendor / arch identifier.
const CPUCFG_WORD1: u16 = 1;
/// CPUCFG word 2 — architecture revision / microarchitecture id.
const CPUCFG_WORD2: u16 = 2;

/// Microarchitecture identifier.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Microarch {
    /// Unknown or pre-LA364 silicon.
    Unknown = 0,
    /// LA364 — Loongson 3A1000/3A1500/3A2000 series.
    La364 = 1,
    /// LA464 — Loongson 3A3000/3A4000/3A5000 series.
    La464 = 2,
    /// LA664 — Loongson 3A6000 and later (newer, SMT-capable).
    La664 = 3,
}

impl Microarch {
    pub fn name(self) -> &'static str {
        match self {
            Microarch::Unknown => "unknown",
            Microarch::La364 => "LA364",
            Microarch::La464 => "LA464",
            Microarch::La664 => "LA664",
        }
    }

    pub fn is_smt_capable(self) -> bool {
        // Per the Loongson documentation, LA664 (3A6000) is the first
        // microarchitecture to introduce hardware SMT (2-way HT). Older
        // parts (LA364/LA464) have no SMT.
        matches!(self, Microarch::La664)
    }
}

/// Cached global SoC information (set once during early boot).
struct SoCInfo {
    /// Detected microarchitecture.
    microarch: AtomicU8,
    /// Vendor string from CPUCFG.WORD1.
    vendor_id: AtomicU32,
    /// PRID signature from CPUCFG.WORD0.
    prid: AtomicU32,
}

impl SoCInfo {
    const fn new() -> Self {
        Self {
            microarch: AtomicU8::new(0),
            vendor_id: AtomicU32::new(0),
            prid: AtomicU32::new(0),
        }
    }
}

static SOC: SoCInfo = SoCInfo::new();

/// Read one word of CPUCFG. The LoongArch encoding for `CPUCFG rd, idx`
/// is the pseudo-op form `cpucfg <rd>, <idx>`. We emit the equivalent
/// csrrd-like mnemonic using the raw opcode via a fixed template here.
///
/// In Rust's `asm!` macro for loongarch64-unknown-none the accepted
/// mnemonic is `cpucfg` with two register operands (the destination and
/// the index held in the same register operand slot). We use the
/// unprivileged instruction directly.
#[inline(always)]
pub unsafe fn cpucfg_read(word: u16) -> u64 {
    let mut val: u64;
    // LoongArch `cpucfg rd, rj` reads CPUCFG[rj] into rd. We pass
    // `word` in any register; rj here is used purely as the source
    // selector.
    asm!(
        "cpucfg {0}, {1}",
        out(reg) val,
        in(reg) word as u64,
        options(nostack, preserves_flags),
    );
    val
}

/// Parse CPUCFG.WORD2 into a Microarch classification.
///
/// The classification rules below are an internally derived mapping
/// matching the LoongArch reference manual revision list. We accept
/// the LA664 family by the leading bits of WORD2; older parts may
/// report `0` for WORD2 and fall back to vendor-PRID heuristics.
fn classify_microarch(word2: u64, word1: u64, word0: u64) -> Microarch {
    // Fast path: PRID signature recognised by Loongson's manuals.
    //   0x14C01000  → LA364
    //   0x14C10000  → LA464
    //   0x14D00000  → LA664
    if (word0 & 0xFFFF_FFF0) == 0x14C0_1000 {
        return Microarch::La364;
    }
    if (word0 & 0xFFFF_FFF0) == 0x14C1_0000 || (word0 & 0xFFFF_FFFF) == 0x14C1_1000 {
        return Microarch::La464;
    }
    if (word0 & 0xFFFF_0000) == 0x14D0_0000 || word2 == 0x11 {
        return Microarch::La664;
    }
    // Vendor id heuristic — Loongson Inc reports "Loongson" via
    // the standard archid field. Without a manual match, default to
    // unknown rather than misclassify.
    if word1 == 0 {
        return Microarch::Unknown;
    }
    // Fallback: by age of chip — if WORD2 reads back non-zero we assume
    // it is at least LA464-class. This is intentionally conservative.
    if word2 >= 1 {
        Microarch::La464
    } else {
        Microarch::Unknown
    }
}

/// Detect and cache the SoC information. Idempotent — calls after
/// the first one are no-ops.
pub fn detect() -> Microarch {
    // Quick check if already detected (mt).
    if SOC.microarch.load(Ordering::Acquire) != 0 {
        return microarch_get();
    }
    unsafe {
        let word0 = cpucfg_read(CPUCFG_WORD0);
        let word1 = cpucfg_read(CPUCFG_WORD1);
        let word2 = cpucfg_read(CPUCFG_WORD2);

        SOC.prid.store(word0 as u32, Ordering::Relaxed);
        SOC.vendor_id.store(word1 as u32, Ordering::Relaxed);
        let ma = classify_microarch(word2, word1, word0);
        SOC.microarch.store(ma as u8, Ordering::Release);
        ma
    }
}

/// Return the currently-cached microarchitecture (or detect on first
/// call). Safe to call repeatedly.
pub fn microarch_get() -> Microarch {
    let v = SOC.microarch.load(Ordering::Acquire);
    if v == 0 {
        return detect();
    }
    match v {
        x if x == Microarch::La364 as u8 => Microarch::La364,
        x if x == Microarch::La464 as u8 => Microarch::La464,
        x if x == Microarch::La664 as u8 => Microarch::La664,
        _ => Microarch::Unknown,
    }
}

/// Returns `true` if the running SoC supports simultaneous
/// multi-threading (i.e. is LA664-class).
pub fn is_smt_capable() -> bool {
    microarch_get().is_smt_capable()
}

/// Returns `true` if the running SoC supports the LASX 256-bit SIMD
/// extension. LASX is reported by `cpucfg` word 0x15 bit 5; we keep
/// the interface open for callers that do not want to walk raw
/// CPUCFG words.
pub fn is_lasx_capable() -> bool {
    // LA664 introduces LASX. Older LoongArch parts expose LSX only.
    matches!(microarch_get(), Microarch::La664)
}

/// Returns `true` if the running SoC supports the LSX 128-bit SIMD
/// extension. LSX is reported by `cpucfg` word 0x15 bit 6; it is
/// present on LA464 and later.
pub fn is_lsx_capable() -> bool {
    // Both LA464 and LA664 have LSX; LA364 does not.
    matches!(microarch_get(), Microarch::La464 | Microarch::La664)
}

/// Returns the cached PRID signature.
pub fn prid() -> u32 {
    if SOC.microarch.load(Ordering::Acquire) == 0 {
        detect();
    }
    SOC.prid.load(Ordering::Relaxed)
}

/// Returns the cached arch/vendor identifier.
pub fn vendor_id() -> u32 {
    if SOC.microarch.load(Ordering::Acquire) == 0 {
        detect();
    }
    SOC.vendor_id.load(Ordering::Relaxed)
}
