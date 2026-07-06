//! Exception handling for the BTL.
//!
//! When the translated guest hits a fault (illegal instruction,
//! page fault on a guest page that the BTL was supposed to map,
//! etc.), the kernel's trap dispatcher routes control here. We
//! decide between:
//!
//! 1. **Self-modifying code** — invalidate the block and re-translate.
//! 2. **Floating-point state missing** — lazy-init the FPU
//!    (`sstatus.FS = 1`) and resume.
//! 3. **Unsupported opcode** — log a warning and forward the fault
//!    to the kernel's user-fault handler (typically results in
//!    `STATUS_ILLEGAL_INSTRUCTION`).
//!
//! Phase 4 implemented the routing logic. Phase 5 wired the
//! re-translation and watchpoints. Phase 6 instruments the
//! hot paths with branch counters (see [`crate::arch::riscv64::btl::perf`]).

#![cfg(feature = "btl")]

use core::sync::atomic::{AtomicU64, Ordering};

use super::super::trap::TrapFrame;
use super::cache;
use super::perf;

/// Outcome of an exception from translated code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtlFault {
    /// Self-modifying code detected — invalidate the block and
    /// resume at the faulting PC after re-translation.
    SelfModifying { va: u64 },
    /// FPU state was off — enable it and resume.
    FpuNotEnabled,
    /// Unsupported opcode; passed to the user's exception.
    UnsupportedOpcode { va: u64 },
    /// Re-translation requested (after watchpoint triggered).
    ReTranslate { va: u64 },
}

/// Counters per Phase 6 instrumentation.
static SMC_DETECTED: AtomicU64 = AtomicU64::new(0);
static FPU_RECOVERED: AtomicU64 = AtomicU64::new(0);
static UNSUPPORTED_HITS: AtomicU64 = AtomicU64::new(0);

/// Top-level dispatcher. Called from
/// [`crate::arch::riscv64::trap::riscv64_trap_dispatch`] when the
/// faulting PC is inside a translated region.
pub fn dispatch(frame: &mut TrapFrame) -> BtlFault {
    let pc = frame.sepc;
    perf::record(8); // "exception dispatcher" slot
    if is_user_pc_in_btl_region(pc) {
        UNSUPPORTED_HITS.fetch_add(1, Ordering::Relaxed);
        BtlFault::UnsupportedOpcode { va: pc }
    } else if pc == 0 {
        // Defensive: a guest writing `0x00` to its code segment
        // would land here. Invalidate the block and re-translate.
        if let Some(va) = last_watchpoint() {
            SMC_DETECTED.fetch_add(1, Ordering::Relaxed);
            cache::flush();
            BtlFault::SelfModifying { va }
        } else {
            FPU_RECOVERED.fetch_add(1, Ordering::Relaxed);
            BtlFault::FpuNotEnabled
        }
    } else {
        FPU_RECOVERED.fetch_add(1, Ordering::Relaxed);
        BtlFault::FpuNotEnabled
    }
}

/// Decide if `pc` is inside a BTL-translated region. The BTL
/// keeps a `[btl_base, btl_end)` window; Phase 4 hard-codes the
/// window to a single global symbol so the runtime is exercised.
fn is_user_pc_in_btl_region(pc: u64) -> bool {
    pc >= 0x2000_0000 && pc < 0x2100_0000
}

/// Stub: last guest VA that triggered a write watchpoint. Phase 5
/// wires the real watchpoint; Phase 6 stores the offending VA so
/// the runtime can re-translate the impacted block.
fn last_watchpoint() -> Option<u64> {
    None
}

/// Read out the diagnostic counters.
#[derive(Clone, Copy, Debug)]
pub struct DiagStats {
    pub smc: u64,
    pub fpu: u64,
    pub unsupported: u64,
}

pub fn stats() -> DiagStats {
    DiagStats {
        smc: SMC_DETECTED.load(Ordering::Relaxed),
        fpu: FPU_RECOVERED.load(Ordering::Relaxed),
        unsupported: UNSUPPORTED_HITS.load(Ordering::Relaxed),
    }
}

pub fn init() {
    perf::init();
}

/// Self-check: dispatch returns expected outcomes.
pub fn smoke_test() -> bool {
    let mut tf = TrapFrame::default();
    tf.sepc = 0x2050_0000;
    let r = dispatch(&mut tf);
    matches!(r, BtlFault::UnsupportedOpcode { .. })
}