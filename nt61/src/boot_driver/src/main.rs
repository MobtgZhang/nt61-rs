#![no_std]
#![no_main]

use nt61_driver::{dispatch_success, register_driver, unload_driver};

#[unsafe(no_mangle)]
pub extern "efiapi" fn DriverEntry(driver_object: *mut u8, _registry_path: *const u16) -> i32 {
    register_driver(
        driver_object,
        || {},
        dispatch_success,
        unload_driver,
    )
}
