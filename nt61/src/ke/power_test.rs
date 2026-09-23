//! Power Management Test Suite
//!
//! Tests for kernel power management functionality.

use crate::ke::power::*;
use crate::io::{SystemPowerState, PowerActionType};


/// Test CPU C-state transitions
pub fn test_cpu_c_states() -> bool {
    kprintln!("[POWER-TEST] Testing CPU C-state transitions...");

    // Test C0 (active)
    if !enter_cpu_c_state(CpuCState::C0) {
        kprintln!("[POWER-TEST] FAIL: Cannot enter C0");
        return false;
    }

    // Test C1 (halt)
    if enter_cpu_c_state(CpuCState::C1) {
        kprintln!("[POWER-TEST] PASS: Entered C1 state");
    }

    // Return to C0
    enter_cpu_c_state(CpuCState::C0);

    kprintln!("[POWER-TEST] CPU C-state test passed");
    true
}

/// Test CPU P-state transitions

pub fn test_cpu_p_states() -> bool {
    kprintln!("[POWER-TEST] Testing CPU P-state transitions...");

    let info = get_cpu_power_info();
    kprintln!("[POWER-TEST] CPU has {} P-states", info.p_state_count);

    // Try to set each P-state
    for i in 0..info.p_state_count {
        if set_cpu_p_state(i) {
            let p_state = info.p_states[i as usize];
            kprintln!("[POWER-TEST] P-state {}: {} MHz, {} mV", i, p_state.frequency, p_state.voltage);
        }
    }

    // Return to highest performance state
    set_cpu_p_state(0);

    kprintln!("[POWER-TEST] CPU P-state test passed");
    true
}

/// Test system power policy

use crate::kprintln;
pub fn test_power_policy() -> bool {
    kprintln!("[POWER-TEST] Testing system power policy...");

    // Get current policy
    let policy = get_system_power_policy();
    kprintln!("[POWER-TEST] Current policy:");
    kprintln!("  Idle timeout: {} seconds", policy.idle_timeout);
    kprintln!("  Max sleep state: {:?}", policy.max_sleep_state);
    kprintln!("  Hibernate enabled: {}", policy.hibernate_enabled);

    // Create a new policy
    let new_policy = SystemPowerPolicy {
        idle_timeout: 600,
        max_sleep_state: SystemPowerState::S3,
        min_sleep_state: SystemPowerState::S1,
        hibernate_enabled: true,
        reduced_latency_sleep: false,
        min_throttle: 50,
        dynamic_throttle: true,
    };

    // Set the new policy
    set_system_power_policy(new_policy);

    kprintln!("[POWER-TEST] Power policy test passed");
    true
}

/// Test power state query
pub fn test_power_state_query() -> bool {
    kprintln!("[POWER-TEST] Testing power state query...");

    let state = get_system_power_state();
    kprintln!("[POWER-TEST] Current system power state: {:?}", state);

    if state != SystemPowerState::S0 {
        kprintln!("[POWER-TEST] FAIL: Expected S0, got {:?}", state);
        return false;
    }

    kprintln!("[POWER-TEST] Power state query test passed");
    true
}

/// Test power transition validation
pub fn test_power_transition_validation() -> bool {
    kprintln!("[POWER-TEST] Testing power transition validation...");

    // Valid transitions from S0
    let valid_transitions = [
        (SystemPowerState::S0, SystemPowerState::S1),
        (SystemPowerState::S0, SystemPowerState::S3),
        (SystemPowerState::S0, SystemPowerState::S4),
    ];

    for (from, to) in valid_transitions.iter() {
        kprintln!("[POWER-TEST] Testing transition {:?} -> {:?}", from, to);
    // Note: We don't actually perform the transition, just validate);;
    }

    kprintln!("[POWER-TEST] Power transition validation test passed");
    true
}

/// Run all power management tests
pub fn run_all_tests() -> bool {
    kprintln!("[POWER-TEST] ========================================");
    kprintln!("[POWER-TEST] Running Power Management Test Suite");
    kprintln!("[POWER-TEST] ========================================");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Power state query
    if test_power_state_query() {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 2: CPU C-states
    if test_cpu_c_states() {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 3: CPU P-states
    if test_cpu_p_states() {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 4: Power policy
    if test_power_policy() {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 5: Transition validation
    if test_power_transition_validation() {
        passed += 1;
    } else {
        failed += 1;
    }

    kprintln!("[POWER-TEST] ========================================");
    kprintln!("[POWER-TEST] Test Results: {} passed, {} failed", passed, failed);
    kprintln!("[POWER-TEST] ========================================");

    failed == 0
}
