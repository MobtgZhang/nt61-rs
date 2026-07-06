//! BTL performance counters.
//!
//! Tracks block-level statistics used to drive Phase 6
//! optimisations:
//!
//! * Hot-block detection — reorder the cache so frequently
//!   translated blocks sit at the front of the probe sequence.
//! * Translation cache effectiveness — `hits / (hits+misses)`.
//! * Per-mnemonic cost — used by the codegen to bias tight loops
//!   towards the most efficient opcodes (e.g. compare-and-branch
//!   on the K3 / M1 cores which prefer narrow branches).
//!
//! Backed by a 16-slot histogram indexed by
//! [`crate::arch::riscv64::btl::translator::IrOp`] tag. Reads are
//! non-atomic to keep the instrumentation path cheap; the kernel
//! reads the counters at trace-time (`stdio` from kdcom) and is
//! tolerant to skew.

#![cfg(feature = "btl")]

use core::sync::atomic::{AtomicU64, Ordering};

/// 16 counters indexed by IrOp tag. TheIrOp size follows the
/// tree in `translator.rs`.
static HIST: [AtomicU64; 16] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

/// Bump the counter for the IR tag at slot `idx`.
pub fn record(idx: usize) {
    if idx >= HIST.len() { return; }
    HIST[idx].fetch_add(1, Ordering::Relaxed);
}

/// Read out the entire histogram.
pub fn histogram() -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, c) in HIST.iter().enumerate() {
        out[i] = c.load(Ordering::Relaxed);
    }
    out
}

/// Reset all counters. Called when the user starts a new profiling
/// session (`casperf` equivalent).
pub fn reset() {
    for c in HIST.iter() {
        c.store(0, Ordering::Relaxed);
    }
}

/// Total counter.
pub fn total() -> u64 {
    HIST.iter().fold(0u64, |acc, c| {
        acc.wrapping_add(c.load(Ordering::Relaxed))
    })
}

pub fn init() {}

/// Validate that `record(0)` is observable in `histogram()`.
pub fn smoke_test() -> bool {
    reset();
    record(0);
    record(0);
    record(1);
    let h = histogram();
    h[0] == 2 && h[1] == 1 && total() == 3
}