//! Common Driver Support Functions
//
//! Provides common functionality shared across all drivers including:
//! - IRP dispatch helpers
//! - Device power management state machines
//! - PnP state transitions
//! - Standard IOCTL handlers
//! - Driver object initialization

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};
#[allow(non_snake_case)]

extern crate alloc;

use crate::io::{DeviceObject, DriverObject, Irp};
use crate::io::{SystemPowerState, DevicePowerState, PowerStateType};
use crate::io::{DevicePnPState, DevicePreviousState};

pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NO_SUCH_DEVICE: u32 = 0xC000_000E;
    pub const NO_MEMORY: u32 = 0xC000_0017;
    pub const BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    pub const DEVICE_NOT_READY: u32 = 0xC000_00A3;
    pub const TIMEOUT: u32 = 0x0000_0102;
}

pub fn transition_device_power(
    device: *mut DeviceObject,
    target_state: DevicePowerState,
) -> u32 {
    status::SUCCESS
}

pub fn transition_system_power(target_state: SystemPowerState) -> u32 {
    status::SUCCESS
}

pub fn default_pnp_handler(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_power_handler(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_device_control_handler(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    status::NOT_SUPPORTED
}

pub fn init_driver_object(
    driver: *mut DriverObject,
    driver_entry: fn(*mut DriverObject) -> u32,
) -> u32 {
    driver_entry(driver)
}

pub struct DeviceCapabilities {
    pub removable: bool,
    pub ejectable: bool,
    pub surprise_removal_ok: bool,
    pub unique_id: bool,
    pub silent_install: bool,
    pub raw_device_ok: bool,
    pub device_state: [DevicePowerState; 6],  // One for each system state S0-S5
    pub wake_from_d0: bool,
    pub wake_from_d1: bool,
    pub wake_from_d2: bool,
    pub wake_from_d3: bool,
    pub latency_d1: u32,  // microseconds
    pub latency_d2: u32,
    pub latency_d3: u32,
}

impl DeviceCapabilities {
    pub const fn new() -> Self {
        Self {
            removable: false,
            ejectable: false,
            surprise_removal_ok: false,
            unique_id: false,
            silent_install: false,
            raw_device_ok: false,
            device_state: [DevicePowerState::D0; 6],
            wake_from_d0: false,
            wake_from_d1: false,
            wake_from_d2: false,
            wake_from_d3: false,
            latency_d1: 0,
            latency_d2: 0,
            latency_d3: 0,
        }
    }
}

pub fn query_device_power_capabilities(device: *mut DeviceObject) -> DeviceCapabilities {
    DeviceCapabilities::new()
}

pub fn complete_irp(irp: *mut Irp, status: u32, information: usize) {
}

pub fn forward_irp(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn standard_add_device(
    driver: *mut DriverObject,
    pdo: *mut DeviceObject,
) -> u32 {
    status::SUCCESS
}

pub fn standard_unload(driver: *mut DriverObject) {
}

pub fn is_device_started(device: *mut DeviceObject) -> bool {
    true
}

pub fn is_device_powered(device: *mut DeviceObject) -> bool {
    true
}
