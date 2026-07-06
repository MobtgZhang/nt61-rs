//! IRQL (Interrupt Request Level)
//
//! Software interrupt priority levels.
//
//! Windows 6.1 uses 32 IRQLs (0..31). Code at IRQL 0 (PASSIVE_LEVEL)
//! can take any lock; code at IRQL 2 (DISPATCH_LEVEL) can only take
//! spinlocks; code at IRQL >= 27 must not touch pageable memory.
//
//! The IRQL is stored as a single byte in a thread-local slot on
//! the BSP and on each AP. The kernel uses a `#[thread_local]`-style
//! slot on the static `BSP_IRQL` until SMP code installs per-CPU
//! copies via the GS base path. We keep the API simple: a single
//! global current IRQL for the BSP, a `raise_irql` / `lower_irql`
//! pair that returns / consumes the previous level, and a runtime
//! check that DISPATCH_LEVEL code does not call into a pageable
//! routine.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::common::percpu::PerCpuArea;


/// IRQL levels (Windows 6.1, 32 entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Irql {
    Passive = 0,
    ApcLevel = 1,
    DispatchLevel = 2,
    DeviceInterruptBase = 3, // 0x13 in NT — IRQL 3..26
    ProfileLevel = 27,
    ClockLevel = 28,
    IpiLevel = 29,
    PowerLevel = 30,
    HighestLevel = 31,
}

impl Irql {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Is this IRQL above DISPATCH_LEVEL?
    pub fn is_dispatch_or_above(self) -> bool {
        self as u8 >= Self::DispatchLevel as u8
    }

    /// Is this IRQL above APC_LEVEL?
    pub fn is_apc_or_above(self) -> bool {
        self as u8 >= Self::ApcLevel as u8
    }

    /// Is this IRQL high enough that pageable code is forbidden?
    pub fn is_at_or_above_dirql(self) -> bool {
        self as u8 >= Self::DeviceInterruptBase as u8
    }
}

impl From<u8> for Irql {
    fn from(value: u8) -> Self {
        match value {
            0 => Irql::Passive,
            1 => Irql::ApcLevel,
            2 => Irql::DispatchLevel,
            27 => Irql::ProfileLevel,
            28 => Irql::ClockLevel,
            29 => Irql::IpiLevel,
            30 => Irql::PowerLevel,
            31 => Irql::HighestLevel,
            // Device-interrupt IRQLs (3..=26) are valid but we
            // don't have a name for each one.
            n if (3..=26).contains(&n) => Irql::DeviceInterruptBase,
            _ => Irql::Passive,
        }
    }
}

/// Current IRQL of the BSP. The bootstrap is single-CPU, so a
/// single global atomic is enough. SMP will replace this with a
/// GS-base-relative access.
static mut CURRENT_IRQL: AtomicU8 = AtomicU8::new(0);

/// Maximum IRQL observed so far (a diagnostic, never used for
/// logic).
static MAX_OBSERVED_IRQL: AtomicU8 = AtomicU8::new(0);

/// Counter for how many times we have been at IRQL > PASSIVE. The
/// smoke test asserts this is non-zero at the end of the boot
/// sequence.
static RAISE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static LOWER_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// =============================================================================
// Per-CPU IRQL Support (SMP)
// =============================================================================

/// Offset of IRQL field in PerCpuArea structure.
/// Layout:
///   0x00: user_rsp (u64)
///   0x08: kernel_rsp (u64)
///   0x10: cpu_id (u32) + _pad (u32)
///   0x18: current_thread (u64)
///   0x20: current_process (u64)
///   0x28: irql (u8)
const PER_CPU_IRQL_OFFSET: usize = 0x28;

/// Get a pointer to the current CPU's IRQL storage.
/// In SMP mode, this reads from the per-CPU area via GS base.
/// Falls back to the global atomic for single-CPU bootstrap.
fn get_current_cpu_irql_ptr() -> *mut u8 {
    // Get the per-CPU area base using the arch-specific accessor
    let gs_base = crate::arch::common::percpu::get_current() as *const PerCpuArea as u64;
    if gs_base != 0 {
        // Per-CPU area is available - use it
        // IRQL is at offset 0x28 in PerCpuArea
        unsafe { (gs_base as *mut u8).add(PER_CPU_IRQL_OFFSET) }
    } else {
        // Fallback to direct global atomic during early boot
        // Use addr_of_mut to get a mutable pointer to the atomic
        unsafe {
            let ptr = &CURRENT_IRQL as *const AtomicU8 as *mut AtomicU8;
            ptr as *mut u8
        }
    }
}

/// Initialize IRQL
pub fn init() {
    crate::hal::serial::write_string("[ke.irql] enter\r\n");
    // Initialize the global fallback (used during early boot)
    unsafe {
        CURRENT_IRQL.store(Irql::Passive as u8, Ordering::SeqCst);
    }
    MAX_OBSERVED_IRQL.store(0, Ordering::SeqCst);
    RAISE_COUNT.store(0, Ordering::SeqCst);
    LOWER_COUNT.store(0, Ordering::SeqCst);

    // If per-CPU area is available (SMP), initialize it too
    let gs_base = crate::arch::common::percpu::get_current() as *const PerCpuArea as u64;
    if gs_base != 0 {
        unsafe {
            core::ptr::write_volatile(
                (gs_base as *mut u8).add(PER_CPU_IRQL_OFFSET),
                Irql::Passive as u8
            );
        }
    }

    // // kprintln!("    IRQL: current=PASSIVE_LEVEL max_observed=PASSIVE_LEVEL")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Get current IRQL. In SMP mode, reads from the per-CPU area.
/// Falls back to global atomic during early boot.
pub fn get_current_irql() -> Irql {
    let ptr = get_current_cpu_irql_ptr();
    Irql::from(unsafe { core::ptr::read_volatile(ptr) })
}

/// Raise IRQL. Returns the previous IRQL — the caller must pass it
/// to `lower_irql` to restore. Raises of *same-or-lower* IRQL are
/// silently ignored (Windows convention: only higher IRQLs have
/// effect; lowering is the caller's responsibility).
pub fn raise_irql(new_irql: Irql) -> Irql {
    let ptr = get_current_cpu_irql_ptr();
    let old = Irql::from(unsafe { core::ptr::read_volatile(ptr) });
    if new_irql > old {
        unsafe { core::ptr::write_volatile(ptr, new_irql as u8); }
        // Track max observed.
        let mut max = MAX_OBSERVED_IRQL.load(Ordering::SeqCst);
        while (new_irql as u8) > max {
            match MAX_OBSERVED_IRQL.compare_exchange(
                max,
                new_irql as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => max = observed,
            }
        }
        RAISE_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    old
}

/// Lower IRQL back to a previous value returned by `raise_irql`.
pub fn lower_irql(old_irql: Irql) {
    let ptr = get_current_cpu_irql_ptr();
    unsafe { core::ptr::write_volatile(ptr, old_irql as u8); }
    LOWER_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// RAII-style IRQL bracket. Disables APC delivery on construction
/// (raises to APC_LEVEL) and restores the previous IRQL on drop.
/// This is the Windows `KeEnterCriticalRegion` / `KeLeaveCriticalRegion`
/// pair.
pub struct CriticalRegion {
    previous: Irql,
}

impl CriticalRegion {
    pub fn enter() -> Self {
        let prev = raise_irql(Irql::ApcLevel);
        CriticalRegion { previous: prev }
    }
}

impl Drop for CriticalRegion {
    fn drop(&mut self) {
        lower_irql(self.previous);
    }
}

/// Diagnostic: how many times has the IRQL been raised above PASSIVE?
pub fn raise_count() -> u32 {
    RAISE_COUNT.load(Ordering::Relaxed)
}
/// Diagnostic: how many times has the IRQL been lowered?
pub fn lower_count() -> u32 {
    LOWER_COUNT.load(Ordering::Relaxed)
}
/// Diagnostic: the highest IRQL observed during this boot.
pub fn max_observed() -> Irql {
    Irql::from(MAX_OBSERVED_IRQL.load(Ordering::SeqCst))
}

/// Smoke test for the IRQL subsystem.
///
/// Raises and lowers around a critical region, checks that the
/// IRQL returns to PASSIVE_LEVEL, and verifies that the raise /
/// lower counters advanced symmetrically.
pub fn smoke_test() -> bool {
    let start = get_current_irql();
    if start != Irql::Passive {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [IRQL SMOKE FAIL] expected PASSIVE at start, got {:?}",
// //             start
// //         );
        return false;
    }
    let raise_before = raise_count();
    let lower_before = lower_count();

    // Critical region: raise -> work -> lower.
    {
        let _cr = CriticalRegion::enter();
        let now = get_current_irql();
        if now != Irql::ApcLevel {
            // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                 "    [IRQL SMOKE FAIL] expected APC_LEVEL in CR, got {:?}",
// //                 now
// //             );
            return false;
        }
    }
    if get_current_irql() != Irql::Passive {
        // // kprintln!("    [IRQL SMOKE FAIL] did not return to PASSIVE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // Manual raise / lower.
    let prev = raise_irql(Irql::DispatchLevel);
    if prev != Irql::Passive {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [IRQL SMOKE FAIL] raise_irql returned {:?} expected PASSIVE",
// //             prev
// //         );
        return false;
    }
    if get_current_irql() != Irql::DispatchLevel {
        // // kprintln!("    [IRQL SMOKE FAIL] not at DISPATCH after raise")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    lower_irql(Irql::Passive);
    if get_current_irql() != Irql::Passive {
        // // kprintln!("    [IRQL SMOKE FAIL] not at PASSIVE after lower")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    let raise_after = raise_count();
    let lower_after = lower_count();
    if raise_after != raise_before + 2 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [IRQL SMOKE FAIL] raise counter: {} -> {}",
// //             raise_before, raise_after
// //         );
        return false;
    }
    if lower_after != lower_before + 2 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [IRQL SMOKE FAIL] lower counter: {} -> {}",
// //             lower_before, lower_after
// //         );
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [IRQL SMOKE OK] raise={} lower={} max_observed={:?}",
// //         raise_after, lower_after, max_observed()
// //     );
    true
}
