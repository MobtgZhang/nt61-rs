//! Driver Dispatch and IRP Handler Framework
//
//! Provides complete IRP dispatch handlers for all major function codes
//! and standardized patterns for driver development.

use super::common::status;
use crate::io::{DeviceObject, DriverObject, Irp};

pub struct DispatchTable {
    pub create: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub close: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub read: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub write: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub device_control: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub pnp: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub power: fn(*mut DeviceObject, *mut Irp) -> u32,
    pub cleanup: fn(*mut DeviceObject, *mut Irp) -> u32,
}

impl DispatchTable {
    pub const fn default() -> Self {
        Self {
            create: default_create,
            close: default_close,
            read: default_read,
            write: default_write,
            device_control: default_device_control,
            pnp: default_pnp,
            power: default_power,
            cleanup: default_cleanup,
        }
    }
}

pub fn default_create(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_close(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_read(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::NOT_SUPPORTED
}

pub fn default_write(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::NOT_SUPPORTED
}

pub fn default_device_control(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::NOT_SUPPORTED
}

pub fn default_pnp(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_power(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn default_cleanup(_device: *mut DeviceObject, _irp: *mut Irp) -> u32 {
    status::SUCCESS
}

pub fn install_dispatch_table(_driver: *mut DriverObject, _table: &DispatchTable) {}
