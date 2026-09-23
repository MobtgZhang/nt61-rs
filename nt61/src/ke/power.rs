//! Kernel Power Management
//!
//! This module implements system-level power management including:
//! - System power states (S0-S5)
//! - CPU power states (C-states, P-states)
//! - Power policy management
//! - Sleep/Hibernate transitions

use crate::kprintln;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::io::{SystemPowerState, PowerActionType};

/// CPU C-states (power states)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuCState {
    /// C0: Active/Running
    C0 = 0,
    /// C1: Halt (MWAIT or HLT)
    C1 = 1,
    /// C2: Stop-Clock
    C2 = 2,
    /// C3: Sleep (Deep Sleep)
    C3 = 3,
}

/// CPU P-states (performance states)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuPState {
    /// Frequency in MHz
    pub frequency: u32,
    /// Voltage in mV
    pub voltage: u32,
    /// Power consumption in mW
    pub power: u32,
    /// Transition latency in microseconds

    pub latency: u32,
}

impl Default for CpuPState {
    fn default() -> Self {
        Self {
            frequency: 2000,
            voltage: 1000,
            power: 15000,
            latency: 10,
        }
    }
}

/// Maximum number of P-states per CPU
pub const MAX_P_STATES: usize = 16;

/// CPU power information
#[derive(Debug, Clone, Copy)]
pub struct CpuPowerInfo {
    /// Current C-state
    pub current_c_state: CpuCState,
    /// Current P-state index

    pub current_p_state: u8,
    /// Available P-states
    pub p_states: [CpuPState; MAX_P_STATES],
    /// Number of available P-states
    pub p_state_count: u8,
    /// C1 support
    pub c1_supported: bool,
    /// C2 support
    pub c2_supported: bool,
    /// C3 support

    pub c3_supported: bool,
}

impl Default for CpuPowerInfo {
    fn default() -> Self {
        let mut p_states = [CpuPState::default(); MAX_P_STATES];

        // Default P-states (example: 2.0 GHz, 1.5 GHz, 1.0 GHz, 0.8 GHz)
        p_states[0] = CpuPState {
            frequency: 2000,
            voltage: 1000,
            power: 15000,
            latency: 10,
        };
        p_states[1] = CpuPState {
            frequency: 1500,
            voltage: 900,
            power: 10000,
            latency: 10,
        };
        p_states[2] = CpuPState {
            frequency: 1000,
            voltage: 800,
            power: 6000,
            latency: 10,
        };
        p_states[3] = CpuPState {
            frequency: 800,
            voltage: 750,
            power: 4000,
            latency: 10,
        };

        Self {
            current_c_state: CpuCState::C0,
            current_p_state: 0,
            p_states,
            p_state_count: 4,
            c1_supported: true,
            c2_supported: false,
            c3_supported: false,
        }
    }
}

/// System power policy
#[derive(Debug, Clone, Copy)]
pub struct SystemPowerPolicy {
    /// Idle timeout in seconds
    pub idle_timeout: u32,
    /// Maximum sleep state
    pub max_sleep_state: SystemPowerState,
    /// Minimum sleep state
    pub min_sleep_state: SystemPowerState,
    /// Hibernate enabled
    pub hibernate_enabled: bool,
    /// Reduced latency sleep enabled
    pub reduced_latency_sleep: bool,
    /// Minimum throttle percentage
    pub min_throttle: u8,
    /// Dynamic throttle enabled
    pub dynamic_throttle: bool,
}

impl Default for SystemPowerPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: 300,
            max_sleep_state: SystemPowerState::S4,
            min_sleep_state: SystemPowerState::S1,
            hibernate_enabled: true,
            reduced_latency_sleep: false,
            min_throttle: 50,
            dynamic_throttle: true,
        }
    }
}

/// Power transition context
#[derive(Debug, Clone, Copy)]
pub struct PowerTransitionContext {
    /// Target system state
    pub target_state: SystemPowerState,
    /// Power action
    pub action: PowerActionType,
    /// Transition start time
    pub start_time: u64,
    /// Flags
    pub flags: u32,
}

/// Global system power state
static SYSTEM_POWER_STATE: AtomicU32 = AtomicU32::new(SystemPowerState::S0 as u32);

/// Global power statistics
static POWER_TRANSITIONS: AtomicU64 = AtomicU64::new(0);

/// Current system power policy
static mut SYSTEM_POWER_POLICY: SystemPowerPolicy = SystemPowerPolicy {
    idle_timeout: 300,
    max_sleep_state: SystemPowerState::S4,
    min_sleep_state: SystemPowerState::S1,
    hibernate_enabled: true,
    reduced_latency_sleep: false,
    min_throttle: 50,
    dynamic_throttle: true,
};

/// CPU power information (per-CPU, simplified to single CPU for now)
static mut CPU_POWER_INFO: CpuPowerInfo = CpuPowerInfo {
    current_c_state: CpuCState::C0,
    current_p_state: 0,
    p_states: [CpuPState {
        frequency: 2000,
        voltage: 1000,
        power: 15000,
        latency: 10,
    }; MAX_P_STATES],
    p_state_count: 4,
    c1_supported: true,
    c2_supported: false,
    c3_supported: false,
};

/// Initialize kernel power management
pub fn init() {
    kprintln!("[KE-POWER] Initializing kernel power management...");

    SYSTEM_POWER_STATE.store(SystemPowerState::S0 as u32, Ordering::SeqCst);
    POWER_TRANSITIONS.store(0, Ordering::SeqCst);

    // Initialize CPU power management
    init_cpu_power_management();

    // Query ACPI for power capabilities
    query_acpi_power_capabilities();

    kprintln!("[KE-POWER] Kernel power management initialized");
    kprintln!("[KE-POWER] System state: S0 (Working)");
}

/// Initialize CPU power management
fn init_cpu_power_management() {
    unsafe {
        // Query CPU capabilities
        CPU_POWER_INFO = query_cpu_power_capabilities();

        kprintln!("[KE-POWER] CPU power: {} P-states, C1={} C2={} C3={}", CPU_POWER_INFO.p_state_count, CPU_POWER_INFO.c1_supported, CPU_POWER_INFO.c2_supported, CPU_POWER_INFO.c3_supported);

    }
}

/// Query CPU power capabilities
fn query_cpu_power_capabilities() -> CpuPowerInfo {
    // Real implementation would use CPUID and ACPI
    // For now, return default capabilities
    CpuPowerInfo::default()
}

/// Query ACPI power capabilities
fn query_acpi_power_capabilities() {
    // Query FADT for power management support
    if let Some(fadt) = crate::hal::common::acpi::parse_fadt() {
        kprintln!("[KE-POWER] ACPI FADT found");

        // Copy values from packed struct to avoid unaligned references
        let pm1a_evt = fadt.pm1a_evt_blk;
        let pm1a_cnt = fadt.pm1a_cnt_blk;
        let pm_tmr = fadt.pm_tmr_blk;
        let flags = fadt.flags;

        kprintln!("  PM1a Event Block: 0x{:x}", pm1a_evt);
        kprintln!("  PM1a Control Block: 0x{:x}", pm1a_cnt);
        kprintln!("  PM Timer Block: 0x{:x}", pm_tmr);
        kprintln!("  Flags: 0x{:x}", flags);

        unsafe {
            // Update policy based on ACPI capabilities
            if flags & crate::hal::common::acpi::fadt_flags::CPU_SW_SLP != 0 {
                SYSTEM_POWER_POLICY.max_sleep_state = SystemPowerState::S3;
            }
        }
    } else {
        kprintln!("[KE-POWER] ACPI FADT not found, using defaults");
    }
}

/// Get current system power state
pub fn get_system_power_state() -> SystemPowerState {
    let state = SYSTEM_POWER_STATE.load(Ordering::Acquire);
    match state {
        0 => SystemPowerState::S0,
        1 => SystemPowerState::S1,
        2 => SystemPowerState::S2,
        3 => SystemPowerState::S3,
        4 => SystemPowerState::S4,
        5 => SystemPowerState::S5,
        _ => SystemPowerState::S0,
    }
}

/// Request system power state transition
pub fn request_power_state_transition(
    target_state: SystemPowerState,
    action: PowerActionType,
) -> bool {
    let current_state = get_system_power_state();

    kprintln!("[KE-POWER] Requesting power transition: {:?} -> {:?} (action={:?})", current_state, target_state, action);


    // Validate transition
    if !is_valid_power_transition(current_state, target_state) {
        kprintln!("[KE-POWER] Invalid power transition");
        return false;
    }

    // Create transition context
    let context = PowerTransitionContext {
        target_state,
        action,
        start_time: 0,
        flags: 0,
    };

    // Perform the transition
    perform_power_transition(context)
}

/// Check if a power transition is valid
fn is_valid_power_transition(
    current: SystemPowerState,
    target: SystemPowerState,
) -> bool {
    use SystemPowerState::*;

    match (current, target) {
        // Can always go to working state
        (_, S0) => true,
        // Can go to sleep/hibernate from working
        (S0, S1) | (S0, S2) | (S0, S3) | (S0, S4) | (S0, S5) => true,
        // Cannot transition between sleep states directly
        (S1, _) | (S2, _) | (S3, _) | (S4, _) | (S5, _) => false,
    }
}

/// Perform power state transition
fn perform_power_transition(context: PowerTransitionContext) -> bool {
    let target = context.target_state;

    // Execute ACPI _PTS method (Prepare To Sleep)
    if target != SystemPowerState::S0 {
        let _ = crate::hal::common::acpi::execute_acpi_method(
            "_PTS",
            &[target as u64],
        );
    }

    // Perform state-specific actions
    let result = match target {
        SystemPowerState::S0 => resume_from_sleep(context),
        SystemPowerState::S1 => enter_s1_sleep(),
        SystemPowerState::S2 => enter_s2_sleep(),
        SystemPowerState::S3 => enter_s3_sleep(),
        SystemPowerState::S4 => enter_s4_hibernate(),
        SystemPowerState::S5 => enter_s5_shutdown(),
    };

    if result {
        // Update state
        SYSTEM_POWER_STATE.store(target as u32, Ordering::Release);

        // Update statistics
        let transitions = POWER_TRANSITIONS.load(Ordering::Relaxed);
        POWER_TRANSITIONS.store(transitions + 1, Ordering::Relaxed);

        // Execute ACPI _SST method (System Status)
        let _ = crate::hal::common::acpi::execute_acpi_method("_SST", &[target as u64]);
    }

    result
}

/// Resume from sleep state
fn resume_from_sleep(_context: PowerTransitionContext) -> bool {
    kprintln!("[KE-POWER] Resuming from sleep...");

    // Execute ACPI _WAK method (Wake)
    let _ = crate::hal::common::acpi::execute_acpi_method("_WAK", &[0]);

    // Restore CPU state
    restore_cpu_state();

    // Restore devices
    restore_device_power();

    kprintln!("[KE-POWER] Resume complete");
    true
}

/// Enter S1 sleep state (CPU stopped, RAM refreshed)
fn enter_s1_sleep() -> bool {
    kprintln!("[KE-POWER] Entering S1 sleep (CPU halt)...");

    // Save minimal CPU state
    save_cpu_state();

    // Notify devices
    notify_devices_power_change(SystemPowerState::S1);

    // Execute HLT instruction
    // Real implementation would execute HLT in a loop
    kprintln!("[KE-POWER] Would execute HLT instruction here");

    true
}

/// Enter S2 sleep state (CPU powered off)
fn enter_s2_sleep() -> bool {
    kprintln!("[KE-POWER] Entering S2 sleep (CPU power off)...");

    // Save CPU state
    save_cpu_state();

    // Notify devices
    notify_devices_power_change(SystemPowerState::S2);

    // Power off CPU
    kprintln!("[KE-POWER] Would power off CPU here");

    true
}

/// Enter S3 sleep state (Suspend to RAM)
fn enter_s3_sleep() -> bool {
    kprintln!("[KE-POWER] Entering S3 sleep (Suspend to RAM)...");

    // Call hibernate subsystem
    crate::mm::hiber::save_s3_state()
}

/// Enter S4 hibernate state
fn enter_s4_hibernate() -> bool {
    kprintln!("[KE-POWER] Entering S4 hibernate...");

    // Call hibernate subsystem
    crate::mm::hiber::save_s4_state()
}

/// Enter S5 shutdown state
fn enter_s5_shutdown() -> bool {
    kprintln!("[KE-POWER] Entering S5 shutdown...");

    // Notify all drivers
    notify_devices_power_change(SystemPowerState::S5);

    // Call ACPI shutdown
    acpi_shutdown();

    true
}

/// Save CPU state
fn save_cpu_state() {
    // Real implementation would save:
    // - General purpose registers
    // - Control registers
    // - FPU/SSE state
    // - MSRs
    kprintln!("[KE-POWER] Saving CPU state");
}

/// Restore CPU state
fn restore_cpu_state() {
    // Real implementation would restore saved state
    kprintln!("[KE-POWER] Restoring CPU state");
}

/// Notify devices of power change
fn notify_devices_power_change(state: SystemPowerState) {
    kprintln!("[KE-POWER] Notifying devices of power state {:?}", state);
    // Real implementation would send power IRPs to all devices);;
}

/// Restore device power
fn restore_device_power() {
    kprintln!("[KE-POWER] Restoring device power");
    // Real implementation would send power IRPs to restore devices);;
}

/// ACPI shutdown
fn acpi_shutdown() {
    kprintln!("[KE-POWER] ACPI shutdown");
    // Real implementation would:, 1. Write to PM1a/PM1b control registers, 2. Execute ACPI _PTS(5) and _S5 methods);;
}

/// Enter CPU C-state
pub fn enter_cpu_c_state(state: CpuCState) -> bool {
    unsafe {
        if CPU_POWER_INFO.current_c_state == state {
            return true;
        }

        let supported = match state {
            CpuCState::C0 => true,
            CpuCState::C1 => CPU_POWER_INFO.c1_supported,
            CpuCState::C2 => CPU_POWER_INFO.c2_supported,
            CpuCState::C3 => CPU_POWER_INFO.c3_supported,
        };

        if !supported {
            return false;
        }

        // Transition to C-state
        match state {
            CpuCState::C0 => {
                // Already active
            }
            CpuCState::C1 => {
                // Execute HLT or MWAIT
                #[cfg(target_arch = "x86_64")]
                core::arch::x86_64::_mm_pause();
            }
            CpuCState::C2 | CpuCState::C3 => {
                // Would execute deeper sleep instructions
            }
        }

        CPU_POWER_INFO.current_c_state = state;
        true
    }
}

/// Set CPU P-state (performance state)
pub fn set_cpu_p_state(p_state_index: u8) -> bool {
    unsafe {
        if p_state_index >= CPU_POWER_INFO.p_state_count {
            return false;
        }

        let p_state = CPU_POWER_INFO.p_states[p_state_index as usize];

        kprintln!("[KE-POWER] Setting CPU P-state {}: {} MHz, {} mV", p_state_index, p_state.frequency, p_state.voltage);


        // Real implementation would:
        // 1. Write to MSRs (x86) or ACPI registers
        // 2. Wait for transition
        // 3. Verify new frequency

        CPU_POWER_INFO.current_p_state = p_state_index;
        true
    }
}

/// Get current CPU P-state
pub fn get_cpu_p_state() -> u8 {
    unsafe { CPU_POWER_INFO.current_p_state }
}

/// Get CPU power info
pub fn get_cpu_power_info() -> CpuPowerInfo {
    unsafe { CPU_POWER_INFO }
}

/// Set system power policy
pub fn set_system_power_policy(policy: SystemPowerPolicy) {
    unsafe {
        SYSTEM_POWER_POLICY = policy;
    }
    kprintln!("[KE-POWER] System power policy updated");
}

/// Get system power policy
pub fn get_system_power_policy() -> SystemPowerPolicy {
    unsafe { SYSTEM_POWER_POLICY }
}

/// Get power transition count
pub fn get_power_transition_count() -> u64 {
    POWER_TRANSITIONS.load(Ordering::Relaxed)
}

/// Idle CPU (enter lowest available C-state)
pub fn idle_cpu() {
    unsafe {
        if CPU_POWER_INFO.c3_supported {
            let _ = enter_cpu_c_state(CpuCState::C3);
        } else if CPU_POWER_INFO.c2_supported {
            let _ = enter_cpu_c_state(CpuCState::C2);
        } else if CPU_POWER_INFO.c1_supported {
            let _ = enter_cpu_c_state(CpuCState::C1);
        }
    }
}
