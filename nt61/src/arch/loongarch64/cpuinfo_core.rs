//! Per-CPU capability metadata used by the scheduler and FPU subsystem.
//!
//! Each logical CPU holds a `PerCpuCapability` record describing which
//! features it exposes (SMT sibling id, LSX/LASX ownership, etc.). The
//! boot core populates its own record during `arch::init`; secondary
//! cores update theirs as they come up.
//!
//! References:
//!   * Linux arch/loongarch/kernel/smp.c
//!   * Windows 7 KE_PROCESSOR_CHANGE / KiProcessorProfile

#![cfg(target_arch = "loongarch64")]

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::arch::loongarch64::soc;

/// Maximum CPUs we track — must match MAX_CPUS in mod.rs.
const MAX_CPUS: usize = 64;

/// SMT sibling identification. A logical CPU id is encoded as
/// `(physical_id << 1) | thread_id` (LA664-style 2-way HT).
#[derive(Copy, Clone, Default)]
pub struct PerCpuCapability {
    /// The physical core id (shared between SMT siblings).
    pub physical_id: u8,
    /// The hardware thread within the physical core (0..smt_threads-1).
    pub thread_id: u8,
    /// Number of SMT siblings (1 if SMT is off; 2 for LA664 default).
    pub smt_threads: u8,
    /// True if this CPU is the first thread of its physical core.
    pub is_primary_thread: bool,
    /// Cached microarchitecture id.
    pub microarch: u8,
    /// Cached feature bitmask (LSX/LASX/SMT/etc.).
    pub features: u32,
}

impl PerCpuCapability {
    pub const fn empty() -> Self {
        Self {
            physical_id: 0,
            thread_id: 0,
            smt_threads: 1,
            is_primary_thread: true,
            microarch: 0,
            features: 0,
        }
    }
}

/// Storage for per-CPU capability records. Indexed by logical CPU id
/// (0..MAX_CPUS). Entries are populated lazily.
static CAPS: [AtomicU32; MAX_CPUS] = {
    // Initialize all zeros via a const helper.
    [const { AtomicU32::new(0) }; MAX_CPUS]
};
static CAPS_EXT: [AtomicU32; MAX_CPUS] = {
    [const { AtomicU32::new(0) }; MAX_CPUS]
};

fn encode_primary(cap: &PerCpuCapability) -> u32 {
    // Bits 0..=7 physical_id, bits 8..=15 thread_id, bits 16..=23 smt_threads,
    // bits 24..=31 microarch.
    (cap.physical_id as u32)
        | ((cap.thread_id as u32) << 8)
        | ((cap.smt_threads as u32) << 16)
        | ((cap.microarch as u32) << 24)
}

fn encode_ext(cap: &PerCpuCapability) -> u32 {
    let mut v = cap.features;
    if cap.is_primary_thread { v |= 1 << 31; }
    v
}

fn decode(idx: usize) -> PerCpuCapability {
    let p = CAPS[idx].load(Ordering::Relaxed);
    let e = CAPS_EXT[idx].load(Ordering::Relaxed);
    PerCpuCapability {
        physical_id: (p & 0xFF) as u8,
        thread_id: ((p >> 8) & 0xFF) as u8,
        smt_threads: ((p >> 16) & 0xFF) as u8,
        microarch: ((p >> 24) & 0xFF) as u8,
        features: e & 0x7FFF_FFFF,
        is_primary_thread: (e & (1 << 31)) != 0,
    }
}

/// Populate `cpu_id`'s capability record from the SoC/cpuinfo state.
/// Designed to be called once during boot for each logical CPU.
pub fn set_for_cpu(cpu_id: usize, physical_id: u8, thread_id: u8) {
    if cpu_id >= MAX_CPUS { return; }
    let smt_threads = if soc::is_smt_capable() { 2 } else { 1 };
    let microarch = soc::microarch_get() as u8;
    let features = crate::arch::loongarch64::cpuinfo::features_mask() as u32;
    let cap = PerCpuCapability {
        physical_id,
        thread_id,
        smt_threads,
        is_primary_thread: thread_id == 0,
        microarch,
        features,
    };
    CAPS[cpu_id].store(encode_primary(&cap), Ordering::Release);
    CAPS_EXT[cpu_id].store(encode_ext(&cap), Ordering::Release);
}

/// Retrieve the capability record for `cpu_id`.
pub fn get(cpu_id: usize) -> PerCpuCapability {
    if cpu_id >= MAX_CPUS {
        return PerCpuCapability::empty();
    }
    decode(cpu_id)
}

/// Initial capability of the boot CPU (logical id 0).
pub fn init_boot_cpu() {
    let smt = if soc::is_smt_capable() { 2 } else { 1 };
    let cap = PerCpuCapability {
        physical_id: 0,
        thread_id: 0,
        smt_threads: smt,
        is_primary_thread: true,
        microarch: soc::microarch_get() as u8,
        features: crate::arch::loongarch64::cpuinfo::features_mask() as u32,
    };
    CAPS[0].store(encode_primary(&cap), Ordering::Release);
    CAPS_EXT[0].store(encode_ext(&cap), Ordering::Release);
}

// Silence the unused-import lint when `AtomicU8` is reduced away by
// future refactors (kept around for the moment because the encoder
// relies on `u8` fields above).
#[allow(dead_code)]
static _PROBE_ATOMICU8: AtomicU8 = AtomicU8::new(0);
