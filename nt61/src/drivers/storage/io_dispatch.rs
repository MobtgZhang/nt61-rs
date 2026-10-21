//! Storage device-to-IRP-dispatcher bridge.
//!
//! Maps the storage layer's numeric device IDs onto DeviceObjects
//! with DriverObject dispatch tables. Every sector read/write goes
//! through io::dispatch::dispatch_storage_request.

use crate::io::{DeviceObject, DriverObject};
use crate::ke::sync::Spinlock;

pub const MAX_DISPATCH_DEVICES: usize = 8;

struct DispatchRegistry {
    devices: [Option<*mut DeviceObject>; MAX_DISPATCH_DEVICES],
}

impl DispatchRegistry {
    const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DISPATCH_DEVICES],
        }
    }
}

static REGISTRY: Spinlock<DispatchRegistry> = Spinlock::new(DispatchRegistry::new());

pub fn register_device(device_id: usize, device: *mut DeviceObject) -> bool {
    if device_id >= MAX_DISPATCH_DEVICES || device.is_null() {
        return false;
    }
    let mut registry = REGISTRY.lock();
    if registry.devices[device_id].is_some() {
        return false;
    }
    registry.devices[device_id] = Some(device);
    true
}

pub fn get_device(device_id: usize) -> Option<*mut DeviceObject> {
    if device_id >= MAX_DISPATCH_DEVICES {
        return None;
    }
    let registry = REGISTRY.lock();
    registry.devices[device_id]
}

pub unsafe fn dispatch_read(device_id: usize, byte_offset: u64, buffer: &mut [u8]) -> bool {
    let device = match get_device(device_id) {
        Some(d) => d,
        None => return false,
    };
    let status = crate::io::dispatch::dispatch_storage_request(
        device,
        false,
        byte_offset,
        buffer.len() as u32,
        buffer.as_mut_ptr(),
    );
    status >= 0
}

pub unsafe fn dispatch_write(device_id: usize, byte_offset: u64, buffer: &[u8]) -> bool {
    let device = match get_device(device_id) {
        Some(d) => d,
        None => return false,
    };
    let status = crate::io::dispatch::dispatch_storage_request(
        device,
        true,
        byte_offset,
        buffer.len() as u32,
        buffer.as_ptr() as *mut u8,
    );
    status >= 0
}

pub unsafe fn create_driver_object(driver_name: &[u8]) -> *mut DriverObject {
    crate::io::allocate_driver(driver_name)
}
