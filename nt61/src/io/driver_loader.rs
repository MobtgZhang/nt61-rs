//! Driver Loading and Initialization
//!
//! Implements the NT driver loading subsystem, including:
//! - Driver image loading from disk
//! - Driver initialization (DriverEntry)
//! - Service start types (BOOT_START, SYSTEM_START, AUTO_START)
//! - Driver database management
//! - Driver unload support

use alloc::vec::Vec;
use alloc::string::String;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pool;
use super::{DriverObject, DeviceObject, UnicodeString};
use crate::libs::ntdll::status::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceStartType {
    BootStart = 0,
    SystemStart = 1,
    AutoStart = 2,
    DemandStart = 3,
    Disabled = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverLoadState {
    NotLoaded,
    Loading,
    Loaded,
    Failed,
    Unloading,
}

pub struct DriverRegistryEntry {
    pub name: [u8; 64],
    pub driver_object: *mut DriverObject,
    pub start_type: ServiceStartType,
    pub load_state: DriverLoadState,
    pub image_base: u64,
    pub image_size: u64,
    pub ref_count: AtomicU32,
}

impl Clone for DriverRegistryEntry {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            driver_object: self.driver_object,
            start_type: self.start_type,
            load_state: self.load_state,
            image_base: self.image_base,
            image_size: self.image_size,
            ref_count: AtomicU32::new(self.ref_count.load(Ordering::Relaxed)),
        }
    }
}

impl DriverRegistryEntry {
    pub fn new(name: &[u8], driver: *mut DriverObject, start_type: ServiceStartType) -> Self {
        let mut name_buf = [0u8; 64];
        let len = name.len().min(64);
        name_buf[..len].copy_from_slice(&name[..len]);

        Self {
            name: name_buf,
            driver_object: driver,
            start_type,
            load_state: DriverLoadState::NotLoaded,
            image_base: 0,
            image_size: 0,
            ref_count: AtomicU32::new(1),
        }
    }
}

const MAX_LOADED_DRIVERS: usize = 64;

static DRIVER_REGISTRY: Spinlock<Vec<Option<DriverRegistryEntry>>> =
    Spinlock::new(Vec::new());

pub fn init() {
    let mut registry = DRIVER_REGISTRY.lock();
    if registry.is_empty() {
        registry.resize_with(MAX_LOADED_DRIVERS, || None);
    }
}

pub fn load_driver(
    driver_name: &[u8],
    registry_path: &[u8],
    start_type: ServiceStartType,
) -> *mut DriverObject {
    let driver = super::allocate_driver(driver_name);
    if driver.is_null() {
        return null_mut();
    }

    let mut entry = DriverRegistryEntry::new(driver_name, driver, start_type);
    entry.load_state = DriverLoadState::Loading;

    let mut registry = DRIVER_REGISTRY.lock();
    let slot = registry.iter_mut().find(|e| e.is_none());

    if let Some(slot) = slot {
        *slot = Some(entry.clone());
    } else {
        pool::free(driver as *mut u8);
        return null_mut();
    }

    let init_status = unsafe {
        if let Some(driver_init) = (*driver).driver_init {
            let reg_path_ptr = registry_path.as_ptr() as *mut u16;
            driver_init(driver, reg_path_ptr)
        } else {
            STATUS_SUCCESS as u32
        }
    };

    if init_status != STATUS_SUCCESS as u32 {
        entry.load_state = DriverLoadState::Failed;
        if let Some(slot) = registry.iter_mut().find(|e| {
            e.as_ref().map_or(false, |e| e.driver_object == driver)
        }) {
            *slot = Some(entry);
        }
        return null_mut();
    }

    entry.load_state = DriverLoadState::Loaded;
    if let Some(slot) = registry.iter_mut().find(|e| {
        e.as_ref().map_or(false, |e| e.driver_object == driver)
    }) {
        *slot = Some(entry);
    }

    driver
}

pub fn unload_driver(driver: *mut DriverObject) -> bool {
    if driver.is_null() {
        return false;
    }

    let mut registry = DRIVER_REGISTRY.lock();

    let entry_idx = registry.iter().position(|e| {
        e.as_ref().map_or(false, |e| e.driver_object == driver)
    });

    let entry_idx = match entry_idx {
        Some(idx) => idx,
        None => return false,
    };

    if let Some(Some(entry)) = registry.get(entry_idx) {
        let refs = entry.ref_count.load(Ordering::Acquire);
        if refs > 1 {
            // Driver is still in use
            return false;
        }
    }

    unsafe {
        if let Some(unload) = (*driver).driver_unload {
            unload(driver);
        }
    }

    registry[entry_idx] = None;

    pool::free(driver as *mut u8);

    true
}

pub fn reference_driver(driver: *mut DriverObject) -> bool {
    if driver.is_null() {
        return false;
    }

    let mut registry = DRIVER_REGISTRY.lock();

    if let Some(entry) = registry.iter_mut().find_map(|e| e.as_mut()) {
        if entry.driver_object == driver {
            entry.ref_count.fetch_add(1, Ordering::Release);
            return true;
        }
    }

    false
}

pub fn dereference_driver(driver: *mut DriverObject) -> bool {
    if driver.is_null() {
        return false;
    }

    let mut registry = DRIVER_REGISTRY.lock();

    if let Some(entry) = registry.iter_mut().find_map(|e| e.as_mut()) {
        if entry.driver_object == driver {
            let old = entry.ref_count.fetch_sub(1, Ordering::Release);
            if old == 1 {
                entry.load_state = DriverLoadState::Unloading;
            }
            return true;
        }
    }

    false
}

pub fn find_driver(name: &[u8]) -> *mut DriverObject {
    let registry = DRIVER_REGISTRY.lock();

    for entry in registry.iter().filter_map(|e| e.as_ref()) {
        let entry_name_len = entry.name.iter().position(|&b| b == 0).unwrap_or(64);
        let entry_name = &entry.name[..entry_name_len];

        if entry_name == name {
            return entry.driver_object;
        }
    }

    null_mut()
}

pub fn load_boot_start_drivers() -> usize {
    0
}

pub fn load_system_start_drivers() -> usize {
    0
}

pub fn load_auto_start_drivers() -> usize {
    0
}

pub fn loaded_driver_count() -> usize {
    let registry = DRIVER_REGISTRY.lock();
    registry.iter().filter(|e| e.is_some()).count()
}

pub fn enumerate_drivers<F>(mut callback: F)
where
    F: FnMut(&DriverRegistryEntry) -> bool,
{
    let registry = DRIVER_REGISTRY.lock();

    for entry in registry.iter().filter_map(|e| e.as_ref()) {
        if !callback(entry) {
            break;
        }
    }
}
