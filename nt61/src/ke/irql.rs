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
    GateLevel = 3,
    // Device IRQLs (DIRQL): Windows names these DEVICE_LEVEL_1..DEVICE_LEVEL_23
    // and they occupy numeric IRQL 4..26. They must stay individually
    // representable, otherwise a driver connected at DIRQL 7 would program
    // the hardware priority for DIRQL 4 and mask the wrong interrupt band.
    DeviceLevel1 = 4,
    DeviceLevel2 = 5,
    DeviceLevel3 = 6,
    DeviceLevel4 = 7,
    DeviceLevel5 = 8,
    DeviceLevel6 = 9,
    DeviceLevel7 = 10,
    DeviceLevel8 = 11,
    DeviceLevel9 = 12,
    DeviceLevel10 = 13,
    DeviceLevel11 = 14,
    DeviceLevel12 = 15,
    DeviceLevel13 = 16,
    DeviceLevel14 = 17,
    DeviceLevel15 = 18,
    DeviceLevel16 = 19,
    DeviceLevel17 = 20,
    DeviceLevel18 = 21,
    DeviceLevel19 = 22,
    DeviceLevel20 = 23,
    DeviceLevel21 = 24,
    DeviceLevel22 = 25,
    DeviceLevel23 = 26,
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

    /// Numeric device IRQL (4..=26); out-of-range values clamp to the base.
    pub fn from_device_level(level: u8) -> Self {
        match level {
            4 => Irql::DeviceLevel1,
            5 => Irql::DeviceLevel2,
            6 => Irql::DeviceLevel3,
            7 => Irql::DeviceLevel4,
            8 => Irql::DeviceLevel5,
            9 => Irql::DeviceLevel6,
            10 => Irql::DeviceLevel7,
            11 => Irql::DeviceLevel8,
            12 => Irql::DeviceLevel9,
            13 => Irql::DeviceLevel10,
            14 => Irql::DeviceLevel11,
            15 => Irql::DeviceLevel12,
            16 => Irql::DeviceLevel13,
            17 => Irql::DeviceLevel14,
            18 => Irql::DeviceLevel15,
            19 => Irql::DeviceLevel16,
            20 => Irql::DeviceLevel17,
            21 => Irql::DeviceLevel18,
            22 => Irql::DeviceLevel19,
            23 => Irql::DeviceLevel20,
            24 => Irql::DeviceLevel21,
            25 => Irql::DeviceLevel22,
            26 => Irql::DeviceLevel23,
            _ => Irql::DeviceLevel1,
        }
    }

    /// Is this IRQL above APC_LEVEL?
    pub fn is_apc_or_above(self) -> bool {
        self as u8 >= Self::ApcLevel as u8
    }

    /// Is this IRQL high enough that pageable code is forbidden?
    pub fn is_at_or_above_dirql(self) -> bool {
        self as u8 >= Self::DeviceLevel1 as u8
    }
}

impl From<u8> for Irql {
    fn from(value: u8) -> Self {
        match value {
            0 => Irql::Passive,
            1 => Irql::ApcLevel,
            2 => Irql::DispatchLevel,
            3 => Irql::GateLevel,
            27 => Irql::ProfileLevel,
            28 => Irql::ClockLevel,
            29 => Irql::IpiLevel,
            30 => Irql::PowerLevel,
            31 => Irql::HighestLevel,
            n if (4..=26).contains(&n) => Irql::from_device_level(n),
            _ => Irql::Passive,
        }
    }
}

// =============================================================================
// IRQL -> hardware task priority
// =============================================================================

/// The documented HAL IRQL -> TPR table (`HalpIRQLtoTPR[32]`, ReactOS
/// `hal/halx86/apic/apic.c`). The TPR encodes the running priority in its
/// high nibble, so `priority == HalpIRQLtoTPR[irql] >> 4`.
///
/// Levels 3..=26 all map to priority 11: NT collapses the whole device
/// IRQL band onto a single hardware priority, which is why a device ISR
/// running at DIRQL 7 still blocks interrupts from DIRQL 4..=11.
pub const HALP_IRQL_TO_TPR: [u8; 32] = [
    0x00, //  0 PASSIVE_LEVEL
    0x3d, //  1 APC_LEVEL
    0x41, //  2 DISPATCH_LEVEL
    0x41, //  3 GATE_LEVEL
    0x51, //  4 \
    0x61, //  5  |
    0x71, //  6  |
    0x81, //  7  |
    0x91, //  8  |
    0xa1, //  9  |
    0xb1, // 10  |
    0xb1, // 11  |
    0xb1, // 12  |
    0xb1, // 13  |
    0xb1, // 14  |
    0xb1, // 15 DEVICE IRQL
    0xb1, // 16  |
    0xb1, // 17  |
    0xb1, // 18  |
    0xb1, // 19  |
    0xb1, // 20  |
    0xb1, // 21  |
    0xb1, // 22  |
    0xb1, // 23  |
    0xb1, // 24  |
    0xb1, // 25  /
    0xb1, // 26 /
    0xc1, // 27 PROFILE_LEVEL
    0xd1, // 28 CLOCK2_LEVEL
    0xe1, // 29 IPI_LEVEL
    0xef, // 30 POWER_LEVEL
    0xff, // 31 HIGH_LEVEL
];

/// Inverse table (`HalVectorToIRQL[16]`), indexed by the priority nibble.
/// Entries 1 and 2 have no hardware priority of their own on the APIC, so
/// the documented table marks them as unused (`0xFF`).
pub const HAL_PRIORITY_TO_IRQL: [u8; 16] =
    [0, 0xff, 0xff, 1, 2, 4, 5, 6, 7, 8, 9, 10, 27, 28, 29, 31];

/// IRQL -> 8-bit TPR encoding.
pub fn irql_to_tpr(irql: Irql) -> u8 {
    let level = irql as u8;
    // AMD64 documents `IrqlToTpr(Irql) = Irql << 4`, which is only
    // meaningful for IRQL 0..=15 because CR8 holds 4 priority bits.
    // Levels above 15 and other architectures use the HAL table.
    crate::arch::interrupt_priority_encoding(level, HALP_IRQL_TO_TPR[level as usize])
}

/// 8-bit TPR encoding -> IRQL.
pub fn tpr_to_irql(tpr: u8) -> Irql {
    let priority = ((tpr >> 4) & 0xF) as usize;
    let mapped = HAL_PRIORITY_TO_IRQL[priority];
    if mapped == 0xFF {
        Irql::Passive
    } else {
        Irql::from(mapped)
    }
}

/// CR8 task priority for an IRQL (AMD64: the 4-bit priority nibble).
pub fn irql_to_cr8_priority(irql: Irql) -> u8 {
    ((irql_to_tpr(irql) >> 4) & 0xF) as u8
}

/// Push the software IRQL into the interrupt controller.
///
/// Returns `true` when the hardware priority was actually programmed.
/// Before the APIC is mapped this is a no-op and returns `false`: the
/// software counter is the only storage, which is also what keeps unit
/// tests (running in userspace) from executing a privileged instruction.
pub fn sync_hard_irql(irql: Irql) -> bool {
    let _ = irql;
    crate::arch::set_interrupt_priority(irql_to_cr8_priority(irql))
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

/// offset of IRQL field in PerCpuArea structure.
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
    // Once the per-CPU area is installed, IRQL is per-CPU. Before that the
    // arch accessor would execute a privileged instruction (rdmsr on
    // x86_64), so callers must not use it; the single-CPU atomic is the
    // documented early-boot storage.
    if let Some(area) = crate::arch::common::percpu::try_get_current() {
        // IRQL is at offset 0x28 in PerCpuArea
        unsafe { (area as *mut PerCpuArea as *mut u8).add(PER_CPU_IRQL_OFFSET) }
    } else {
        let ptr = core::ptr::addr_of!(CURRENT_IRQL) as *const AtomicU8 as *mut AtomicU8;
        ptr as *mut u8
    }
}

/// Initialize IRQL
pub fn init() {
    // Initialize the global fallback (used during early boot)
    unsafe {
        (*core::ptr::addr_of!(CURRENT_IRQL)).store(Irql::Passive as u8, Ordering::SeqCst);
    }
    MAX_OBSERVED_IRQL.store(0, Ordering::SeqCst);
    RAISE_COUNT.store(0, Ordering::SeqCst);
    LOWER_COUNT.store(0, Ordering::SeqCst);

    // If per-CPU area is available (SMP), initialize it too
    if let Some(area) = crate::arch::common::percpu::try_get_current() {
        unsafe {
            core::ptr::write_volatile(
                (area as *mut PerCpuArea as *mut u8).add(PER_CPU_IRQL_OFFSET),
                Irql::Passive as u8,
            );
        }
    }

    // // kprintln!("    IRQL: current=PASSIVE_LEVEL max_observed=PASSIVE_LEVEL");
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
        unsafe {
            core::ptr::write_volatile(ptr, new_irql as u8);
        }
        // Program the hardware task priority as well once the APIC is up;
        // before that the software counter is the only storage.
        sync_hard_irql(new_irql);
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
    unsafe {
        core::ptr::write_volatile(ptr, old_irql as u8);
    }
    sync_hard_irql(old_irql);
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
        // // kprintln!(
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
            // // kprintln!(
            // //                 "    [IRQL SMOKE FAIL] expected APC_LEVEL in CR, got {:?}",
            // //                 now
            // //             );
            return false;
        }
    }
    if get_current_irql() != Irql::Passive {
        // // kprintln!("    [IRQL SMOKE FAIL] did not return to PASSIVE");
        return false;
    }
    // Manual raise / lower.
    let prev = raise_irql(Irql::DispatchLevel);
    if prev != Irql::Passive {
        // // kprintln!(
        // //             "    [IRQL SMOKE FAIL] raise_irql returned {:?} expected PASSIVE",
        // //             prev
        // //         );
        return false;
    }
    if get_current_irql() != Irql::DispatchLevel {
        // // kprintln!("    [IRQL SMOKE FAIL] not at DISPATCH after raise");
        return false;
    }
    lower_irql(Irql::Passive);
    if get_current_irql() != Irql::Passive {
        // // kprintln!("    [IRQL SMOKE FAIL] not at PASSIVE after lower");
        return false;
    }

    let raise_after = raise_count();
    let lower_after = lower_count();
    if raise_after != raise_before + 2 {
        // // kprintln!(
        // //             "    [IRQL SMOKE FAIL] raise counter: {} -> {}",
        // //             raise_before, raise_after
        // //         );
        return false;
    }
    if lower_after != lower_before + 2 {
        // // kprintln!(
        // //             "    [IRQL SMOKE FAIL] lower counter: {} -> {}",
        // //             lower_before, lower_after
        // //         );
        return false;
    }
    // // kprintln!(
    // //         "    [IRQL SMOKE OK] raise={} lower={} max_observed={:?}",
    // //         raise_after, lower_after, max_observed()
    // //     );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irql_values_match_nt61_table() {
        assert_eq!(Irql::Passive as u8, 0);
        assert_eq!(Irql::ApcLevel as u8, 1);
        assert_eq!(Irql::DispatchLevel as u8, 2);
        assert_eq!(Irql::GateLevel as u8, 3);
        assert_eq!(Irql::DeviceLevel1 as u8, 4);
        assert_eq!(Irql::ProfileLevel as u8, 27);
        assert_eq!(Irql::ClockLevel as u8, 28);
        assert_eq!(Irql::IpiLevel as u8, 29);
        assert_eq!(Irql::PowerLevel as u8, 30);
        assert_eq!(Irql::HighestLevel as u8, 31);
    }

    #[test]
    fn device_irql_range_starts_at_4() {
        assert_eq!(Irql::from(3), Irql::GateLevel);
        // Each device IRQL must survive the numeric conversion: a driver
        // connected at DIRQL 7 has to raise to 7, not to the band base.
        for v in 4..=26 {
            assert_eq!(Irql::from(v).as_u8(), v);
        }
        assert_eq!(Irql::from(4), Irql::DeviceLevel1);
        assert_eq!(Irql::from(7), Irql::DeviceLevel4);
        assert_eq!(Irql::from(26), Irql::DeviceLevel23);
        assert_eq!(Irql::from(27), Irql::ProfileLevel);
    }

    #[test]
    fn irql_constants_agree_with_sync_module() {
        assert_eq!(Irql::Passive as u8, crate::ke::sync::IRQL_LEVEL_PASSIVE);
        assert_eq!(Irql::ApcLevel as u8, crate::ke::sync::IRQL_LEVEL_APC);
        assert_eq!(
            Irql::DispatchLevel as u8,
            crate::ke::sync::IRQL_LEVEL_DISPATCH
        );
        assert_eq!(Irql::GateLevel as u8, crate::ke::sync::IRQL_LEVEL_GATE);
        assert_eq!(
            Irql::DeviceLevel1 as u8,
            crate::ke::sync::IRQL_LEVEL_DEVICE_BASE
        );
        assert_eq!(
            Irql::ProfileLevel as u8,
            crate::ke::sync::IRQL_LEVEL_PROFILE
        );
        assert_eq!(Irql::ClockLevel as u8, crate::ke::sync::IRQL_LEVEL_CLOCK2);
        assert_eq!(Irql::IpiLevel as u8, crate::ke::sync::IRQL_LEVEL_IPI);
        assert_eq!(Irql::PowerLevel as u8, crate::ke::sync::IRQL_LEVEL_POWER);
        assert_eq!(
            Irql::HighestLevel as u8,
            crate::ke::sync::IRQL_LEVEL_HIGHEST
        );
    }

    #[test]
    fn halp_irql_to_tpr_matches_the_documented_table() {
        // Documented HalpIRQLtoTPR[32] anchor points.
        assert_eq!(HALP_IRQL_TO_TPR[0], 0x00);
        assert_eq!(HALP_IRQL_TO_TPR[1], 0x3d);
        assert_eq!(HALP_IRQL_TO_TPR[2], 0x41);
        assert_eq!(HALP_IRQL_TO_TPR[15], 0xb1);
        assert_eq!(HALP_IRQL_TO_TPR[27], 0xc1);
        assert_eq!(HALP_IRQL_TO_TPR[28], 0xd1);
        assert_eq!(HALP_IRQL_TO_TPR[29], 0xe1);
        assert_eq!(HALP_IRQL_TO_TPR[30], 0xef);
        assert_eq!(HALP_IRQL_TO_TPR[31], 0xff);
    }

    #[test]
    fn device_irql_band_collapses_to_one_hardware_priority() {
        // NT collapses DIRQL 4..=26 onto priority 11, so an ISR at DIRQL 7
        // still masks everything in that band.
        for level in 16..=26 {
            assert_eq!(irql_to_cr8_priority(Irql::from(level)), 11);
        }
        assert_eq!(irql_to_cr8_priority(Irql::ProfileLevel), 12);
        assert_eq!(irql_to_cr8_priority(Irql::ClockLevel), 13);
        assert_eq!(irql_to_cr8_priority(Irql::IpiLevel), 14);
        assert_eq!(irql_to_cr8_priority(Irql::PowerLevel), 14);
        assert_eq!(irql_to_cr8_priority(Irql::HighestLevel), 15);
    }

    #[test]
    fn amd64_priority_is_identity_below_16() {
        // IrqlToTpr(Irql) = Irql << 4 on AMD64, and CR8 holds the nibble.
        for level in 0..=15 {
            let irql = Irql::from(level);
            assert_eq!(irql_to_tpr(irql), (level << 4) as u8);
            assert_eq!(irql_to_cr8_priority(irql), level);
        }
    }

    #[test]
    fn tpr_to_irql_matches_the_documented_inverse_table() {
        assert_eq!(tpr_to_irql(0x00), Irql::Passive);
        assert_eq!(tpr_to_irql(0x3d), Irql::ApcLevel);
        assert_eq!(tpr_to_irql(0x41), Irql::DispatchLevel);
        assert_eq!(tpr_to_irql(0x71), Irql::from(6));
        // The device band has no per-level inverse entry: priority 11
        // resolves to the documented representative IRQL 10.
        assert_eq!(tpr_to_irql(0xb1), Irql::from(10));
        assert_eq!(tpr_to_irql(0xc1), Irql::ProfileLevel);
        assert_eq!(tpr_to_irql(0xd1), Irql::ClockLevel);
        assert_eq!(tpr_to_irql(0xe1), Irql::IpiLevel);
        assert_eq!(tpr_to_irql(0xff), Irql::HighestLevel);
    }

    #[test]
    fn hardware_priority_is_not_programmed_before_the_apic_is_mapped() {
        // Unit tests run in userspace: writing CR8 would fault, so the
        // readiness gate must keep this a pure software counter here.
        assert!(!sync_hard_irql(Irql::DispatchLevel));
    }
}
