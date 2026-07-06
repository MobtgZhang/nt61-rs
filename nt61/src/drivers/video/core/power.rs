//! GPU Power Management
//
//! Provides power management infrastructure for GPU drivers,
//! including power states, clock management, and thermal throttling.
//
//! Clean-room implementation based on industry standards.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// =====================================================================
// Power States (ACPI D-States)
// =====================================================================

/// GPU power states (ACPI D-states)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuPowerState {
    /// D0: Fully on
    D0,
    /// D1: Light sleep
    D1,
    /// D2: Deep sleep
    D2,
    /// D3: Hot standby / Off
    D3,
}

impl GpuPowerState {
    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            GpuPowerState::D0 => "D0 (Fully On)",
            GpuPowerState::D1 => "D1 (Light Sleep)",
            GpuPowerState::D2 => "D2 (Deep Sleep)",
            GpuPowerState::D3 => "D3 (Hot Standby)",
        }
    }

    /// Get power consumption estimate (as percentage of max)
    pub fn power_percent(&self) -> u32 {
        match self {
            GpuPowerState::D0 => 100,
            GpuPowerState::D1 => 50,
            GpuPowerState::D2 => 20,
            GpuPowerState::D3 => 5,
        }
    }

    /// Transition latency in microseconds
    pub fn transition_latency_us(&self, target: GpuPowerState) -> u32 {
        match (*self as u8, target as u8) {
            (0, 1) => 100,
            (0, 2) => 500,
            (0, 3) => 1000,
            (1, 0) => 200,
            (1, 2) => 200,
            (1, 3) => 500,
            (2, 0) => 500,
            (2, 1) => 300,
            (2, 3) => 500,
            (3, 0) => 2000,
            (3, 1) => 1500,
            (3, 2) => 1000,
            _ => 0,
        }
    }
}

// =====================================================================
// Performance States (P-States)
// =====================================================================

/// GPU performance states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuPerformanceState {
    /// Turbo / Boost state
    Turbo,
    /// High performance
    High,
    /// Balanced
    Balanced,
    /// Low power
    Low,
    /// Idle
    Idle,
}

impl GpuPerformanceState {
    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            GpuPerformanceState::Turbo => "Turbo",
            GpuPerformanceState::High => "High Performance",
            GpuPerformanceState::Balanced => "Balanced",
            GpuPerformanceState::Low => "Low Power",
            GpuPerformanceState::Idle => "Idle",
        }
    }
}

// =====================================================================
// Clock Domains
// =====================================================================

/// GPU clock domains
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockDomain {
    /// Core clock
    Core,
    /// Memory clock
    Memory,
    /// Display clock
    Display,
    /// Uniphy clock (for DisplayPort)
    Uniphy,
    /// Timestamp clock
    Timestamp,
}

impl ClockDomain {
    /// Get domain name
    pub fn name(&self) -> &'static str {
        match self {
            ClockDomain::Core => "Core",
            ClockDomain::Memory => "Memory",
            ClockDomain::Display => "Display",
            ClockDomain::Uniphy => "Uniphy",
            ClockDomain::Timestamp => "Timestamp",
        }
    }
}

/// Clock frequency
#[derive(Debug, Clone, Copy)]
pub struct ClockFrequency {
    /// Frequency in Hz
    pub hz: u64,
    /// Voltage in millivolts
    pub voltage_mv: u32,
}

impl ClockFrequency {
    /// Create a new clock frequency
    pub fn new(hz: u64, voltage_mv: u32) -> Self {
        Self { hz, voltage_mv }
    }

    /// Get frequency in MHz
    pub fn mhz(&self) -> u64 {
        self.hz / 1_000_000
    }

    /// Get frequency in KHz
    pub fn khz(&self) -> u64 {
        self.hz / 1_000
    }
}

/// Clock state
#[derive(Debug, Clone, Copy)]
pub struct ClockState {
    /// Domain
    pub domain: ClockDomain,
    /// Current frequency
    pub current: ClockFrequency,
    /// Minimum frequency
    pub min: ClockFrequency,
    /// Maximum frequency
    pub max: ClockFrequency,
    /// Is enabled
    pub enabled: bool,
}

impl ClockState {
    /// Create a new clock state
    pub fn new(domain: ClockDomain) -> Self {
        Self {
            domain,
            current: ClockFrequency::new(0, 0),
            min: ClockFrequency::new(0, 0),
            max: ClockFrequency::new(0, 0),
            enabled: false,
        }
    }

    /// Check if clock can transition to target frequency
    pub fn can_transition_to(&self, target: &ClockFrequency) -> bool {
        target.hz >= self.min.hz && target.hz <= self.max.hz
    }
}

// =====================================================================
// Thermal Management
// =====================================================================

/// Thermal zone
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalZone {
    /// GPU core
    Core,
    /// Memory
    Memory,
    /// VRM (Voltage Regulator Module)
    Vrm,
    /// Ambient
    Ambient,
}

impl ThermalZone {
    /// Get zone name
    pub fn name(&self) -> &'static str {
        match self {
            ThermalZone::Core => "GPU Core",
            ThermalZone::Memory => "Memory",
            ThermalZone::Vrm => "VRM",
            ThermalZone::Ambient => "Ambient",
        }
    }
}

/// Thermal trip point
#[derive(Debug, Clone, Copy)]
pub struct ThermalTripPoint {
    /// Temperature in millidegrees Celsius
    pub temperature_mc: i32,
    /// Trip type
    pub trip_type: ThermalTripType,
}

impl ThermalTripPoint {
    /// Create a new trip point
    pub fn new(temperature_mc: i32, trip_type: ThermalTripType) -> Self {
        Self {
            temperature_mc,
            trip_type,
        }
    }
}

/// Thermal trip type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalTripType {
    /// Active cooling (fan)
    Active,
    /// Passive cooling (throttling)
    Passive,
    /// Hot
    Hot,
    /// Critical (emergency shutdown)
    Critical,
}

impl ThermalTripType {
    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            ThermalTripType::Active => "Active (Fan)",
            ThermalTripType::Passive => "Passive (Throttling)",
            ThermalTripType::Hot => "Hot",
            ThermalTripType::Critical => "Critical",
        }
    }
}

/// Thermal status
#[derive(Debug, Clone, Copy)]
pub struct ThermalStatus {
    /// Zone
    pub zone: ThermalZone,
    /// Current temperature in millidegrees Celsius
    pub temperature_mc: i32,
    /// Trip point currently active
    pub active_trip: Option<ThermalTripType>,
    /// Thermal throttling active
    pub throttling: bool,
}

impl Default for ThermalStatus {
    fn default() -> Self {
        Self {
            zone: ThermalZone::Core,
            temperature_mc: 0,
            active_trip: None,
            throttling: false,
        }
    }
}

// =====================================================================
// Power Management Controller
// =====================================================================

/// GPU power management controller
pub struct GpuPowerManager {
    /// Current power state
    current_state: AtomicU32,
    /// Target power state
    target_state: AtomicU32,
    /// Power state valid
    state_valid: AtomicBool,
    /// Clocks enabled
    clocks_enabled: AtomicBool,
    /// Interrupts enabled
    interrupts_enabled: AtomicBool,
    /// Thermal status
    thermal_status: ThermalStatus,
    /// Clock states
    clock_states: [ClockState; 5],
    /// Thermal trip points
    trip_points: Vec<ThermalTripPoint>,
    /// Performance state
    perf_state: AtomicU32,
}

impl GpuPowerManager {
    /// Create a new power manager
    pub fn new() -> Self {
        Self {
            current_state: AtomicU32::new(GpuPowerState::D0 as u32),
            target_state: AtomicU32::new(GpuPowerState::D0 as u32),
            state_valid: AtomicBool::new(true),
            clocks_enabled: AtomicBool::new(true),
            interrupts_enabled: AtomicBool::new(true),
            thermal_status: ThermalStatus::default(),
            clock_states: [
                ClockState::new(ClockDomain::Core),
                ClockState::new(ClockDomain::Memory),
                ClockState::new(ClockDomain::Display),
                ClockState::new(ClockDomain::Uniphy),
                ClockState::new(ClockDomain::Timestamp),
            ],
            trip_points: Vec::new(),
            perf_state: AtomicU32::new(GpuPerformanceState::Balanced as u32),
        }
    }

    /// Get current power state
    pub fn current_power_state(&self) -> GpuPowerState {
        let state = self.current_state.load(Ordering::Acquire);
        unsafe { core::mem::transmute(state as u8) }
    }

    /// Get target power state
    pub fn target_power_state(&self) -> GpuPowerState {
        let state = self.target_state.load(Ordering::Acquire);
        unsafe { core::mem::transmute(state as u8) }
    }

    /// Set target power state
    pub fn set_target_state(&self, state: GpuPowerState) {
        self.target_state
            .store(state as u32, Ordering::Release);
    }

    /// Transition to target power state
    ///
    /// Returns true if transition was successful.
    pub fn transition(&mut self) -> bool {
        let target = self.target_power_state();
        let current = self.current_power_state();

        if target == current {
            return true;
        }

        // Perform transition sequence
        match target {
            GpuPowerState::D0 => { self.power_up(); true }
            GpuPowerState::D3 => { self.power_down(); true }
            _ => { self.enter_state(target) }
        }
    }

    /// Power up (D0)
    fn power_up(&mut self) -> bool {
        // Enable clocks
        self.enable_clocks();

        // Enable interrupts
        self.enable_interrupts();

        // Enable power rails
        self.state_valid.store(true, Ordering::Release);
        self.current_state
            .store(GpuPowerState::D0 as u32, Ordering::Release);

        true
    }

    /// Power down (D3)
    fn power_down(&mut self) {
        // Disable interrupts
        self.disable_interrupts();

        // Disable clocks
        self.disable_clocks();

        // Disable power rails
        self.state_valid.store(false, Ordering::Release);
        self.current_state
            .store(GpuPowerState::D3 as u32, Ordering::Release);
    }

    /// Enter specific state
    fn enter_state(&mut self, state: GpuPowerState) -> bool {
        // Handle intermediate states (D1, D2)
        // These vary by GPU, but typically:
        // D1: Reduce clock frequency, keep some power
        // D2: Further reduce clocks, reduce power

        self.current_state
            .store(state as u32, Ordering::Release);
        true
    }

    /// Enable all clocks
    pub fn enable_clocks(&self) {
        self.clocks_enabled.store(true, Ordering::Release);
    }

    /// Disable all clocks
    pub fn disable_clocks(&self) {
        self.clocks_enabled.store(false, Ordering::Release);
    }

    /// Check if clocks are enabled
    pub fn clocks_enabled(&self) -> bool {
        self.clocks_enabled.load(Ordering::Acquire)
    }

    /// Enable interrupts
    pub fn enable_interrupts(&self) {
        self.interrupts_enabled.store(true, Ordering::Release);
    }

    /// Disable interrupts
    pub fn disable_interrupts(&self) {
        self.interrupts_enabled.store(false, Ordering::Release);
    }

    /// Check if interrupts are enabled
    pub fn interrupts_enabled(&self) -> bool {
        self.interrupts_enabled.load(Ordering::Acquire)
    }

    /// Set clock frequency for a domain
    pub fn set_clock(&mut self, domain: ClockDomain, freq: &ClockFrequency) -> bool {
        let idx = domain as usize;
        if idx >= self.clock_states.len() {
            return false;
        }

        let state = &mut self.clock_states[idx];

        // Check if transition is possible
        if !state.can_transition_to(freq) {
            return false;
        }

        // Set new frequency
        state.current = *freq;
        true
    }

    /// Get clock state for a domain
    pub fn get_clock_state(&self, domain: ClockDomain) -> Option<ClockState> {
        let idx = domain as usize;
        if idx >= self.clock_states.len() {
            return None;
        }
        Some(self.clock_states[idx])
    }

    /// Set performance state
    pub fn set_performance_state(&self, state: GpuPerformanceState) {
        self.perf_state.store(state as u32, Ordering::Release);
    }

    /// Get performance state
    pub fn performance_state(&self) -> GpuPerformanceState {
        let state = self.perf_state.load(Ordering::Acquire);
        unsafe { core::mem::transmute(state as u8) }
    }

    /// Update thermal status
    pub fn update_thermal(&mut self, zone: ThermalZone, temp_mc: i32) {
        self.thermal_status.zone = zone;
        self.thermal_status.temperature_mc = temp_mc;

        // Check trip points
        let mut throttling = false;
        let mut active_trip = None;

        for trip in &self.trip_points {
            if temp_mc >= trip.temperature_mc {
                throttling = true;
                active_trip = Some(trip.trip_type);
                break;
            }
        }

        self.thermal_status.throttling = throttling;
        self.thermal_status.active_trip = active_trip;
    }

    /// Get thermal status
    pub fn thermal_status(&self) -> ThermalStatus {
        self.thermal_status
    }

    /// Add thermal trip point
    pub fn add_trip_point(&mut self, trip: ThermalTripPoint) {
        self.trip_points.push(trip);
        // Sort by temperature (ascending)
        self.trip_points.sort_by_key(|t| t.temperature_mc);
    }

    /// Check if thermal throttling is active
    pub fn is_throttling(&self) -> bool {
        self.thermal_status.throttling
    }
}

impl Default for GpuPowerManager {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Dynamic Frequency Scaling (DFS)
// =====================================================================

/// DFS policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsPolicy {
    /// Performance oriented
    Performance,
    /// Balanced (default)
    Balanced,
    /// Power saving
    PowerSave,
}

impl Default for DfsPolicy {
    fn default() -> Self {
        Self::Balanced
    }
}

/// DFS controller
pub struct DfsController {
    /// Policy
    pub policy: DfsPolicy,
    /// Target utilization percentage
    pub target_utilization: u32,
    /// Up threshold percentage
    pub up_threshold: u32,
    /// Down threshold percentage
    pub down_threshold: u32,
    /// Sample interval in milliseconds
    pub sample_interval_ms: u32,
    /// Last sample time
    pub last_sample_ns: AtomicU64,
}

impl DfsController {
    /// Create a new DFS controller
    pub fn new() -> Self {
        Self {
            policy: DfsPolicy::Balanced,
            target_utilization: 80,
            up_threshold: 90,
            down_threshold: 50,
            sample_interval_ms: 50,
            last_sample_ns: AtomicU64::new(0),
        }
    }

    /// Set policy
    pub fn set_policy(&mut self, policy: DfsPolicy) {
        self.policy = policy;

        // Adjust thresholds based on policy
        match policy {
            DfsPolicy::Performance => {
                self.up_threshold = 95;
                self.down_threshold = 70;
            }
            DfsPolicy::Balanced => {
                self.up_threshold = 90;
                self.down_threshold = 50;
            }
            DfsPolicy::PowerSave => {
                self.up_threshold = 80;
                self.down_threshold = 30;
            }
        }
    }

    /// Evaluate utilization and determine if frequency should change
    ///
    /// Returns the frequency adjustment factor (1.0 = no change)
    pub fn evaluate(&self, utilization: u32) -> f64 {
        if utilization >= self.up_threshold {
            // Scale up
            1.2
        } else if utilization <= self.down_threshold {
            // Scale down
            0.8
        } else {
            // No change
            1.0
        }
    }

    /// Get target utilization
    pub fn target_utilization(&self) -> u32 {
        self.target_utilization
    }

    /// Set target utilization
    pub fn set_target_utilization(&mut self, utilization: u32) {
        self.target_utilization = utilization.clamp(50, 100);
    }
}

impl Default for DfsController {
    fn default() -> Self {
        Self::new()
    }
}
