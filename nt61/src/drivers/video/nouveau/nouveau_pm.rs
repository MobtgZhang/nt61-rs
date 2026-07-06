//! NVIDIA Nouveau Power Management
//
//! This module implements power management for NVIDIA GPUs.
//
//! Clean-room implementation based on public specifications.

use core::sync::atomic::{AtomicU32, Ordering};

/// Power states
#[derive(Debug, Clone, Copy)]
pub enum NouveauPowerState {
    /// Full power state
    D0,
    /// Low power state
    D1,
    /// Standby state
    D2,
    /// Hot standby
    D3,
}

/// Counter for `nouveau_pm_init` invocations.
static PM_INIT_CALLS: AtomicU32 = AtomicU32::new(0);
/// Counter for `nouveau_set_power_state` invocations.
static PM_SET_CALLS: AtomicU32 = AtomicU32::new(0);
/// Counter for `nouveau_get_power_state` invocations.
static PM_GET_CALLS: AtomicU32 = AtomicU32::new(0);
/// Counter for clock-gating toggles.
static PM_CLOCK_GATES: AtomicU32 = AtomicU32::new(0);
/// Last power state requested.
static PM_LAST_STATE: AtomicU32 = AtomicU32::new(0);

/// Initialize power management
pub fn nouveau_pm_init(device: &super::NouveauDevice) -> Result<(), ()> {
    // Enable power management
    device.write_reg(0x0010A0, 0x1);
    PM_INIT_CALLS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Set power state
pub fn nouveau_set_power_state(device: &super::NouveauDevice, state: NouveauPowerState) {
    let state_val = match state {
        NouveauPowerState::D0 => 0,
        NouveauPowerState::D1 => 1,
        NouveauPowerState::D2 => 2,
        NouveauPowerState::D3 => 3,
    };
    device.write_reg(0x0010A8, state_val);
    PM_SET_CALLS.fetch_add(1, Ordering::Relaxed);
    PM_LAST_STATE.store(state_val, Ordering::Relaxed);
}

/// Get power state
pub fn nouveau_get_power_state(device: &super::NouveauDevice) -> NouveauPowerState {
    let state = device.read_reg(0x0010A8);
    PM_GET_CALLS.fetch_add(1, Ordering::Relaxed);
    match state {
        0 => NouveauPowerState::D0,
        1 => NouveauPowerState::D1,
        2 => NouveauPowerState::D2,
        _ => NouveauPowerState::D3,
    }
}

/// Enable clock gating
pub fn nouveau_enable_clock_gating(device: &super::NouveauDevice) {
    device.write_reg(0x001200, 0x1);
    PM_CLOCK_GATES.fetch_add(1, Ordering::Relaxed);
}

/// Disable clock gating
pub fn nouveau_disable_clock_gating(device: &super::NouveauDevice) {
    device.write_reg(0x001200, 0x0);
    PM_CLOCK_GATES.fetch_add(1, Ordering::Relaxed);
}

/// Return aggregate counts for power-management operations.
pub fn pm_counts() -> (u32, u32, u32, u32, u32) {
    (
        PM_INIT_CALLS.load(Ordering::Relaxed),
        PM_SET_CALLS.load(Ordering::Relaxed),
        PM_GET_CALLS.load(Ordering::Relaxed),
        PM_CLOCK_GATES.load(Ordering::Relaxed),
        PM_LAST_STATE.load(Ordering::Relaxed),
    )
}