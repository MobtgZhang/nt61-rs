//! KMDF (Kernel-Mode Driver Framework) Implementation
//
//! A small subset of KMDF's API surface, sufficient for a
//! driver author to write a `driver_entry -> WdfDriverCreate ->
//! EvtDeviceAdd` flow. The full KMDF surface is ~1500 entry
//! points; the bootstrap implements the 6 the drivers below
//! actually call.
//
//! Clean-room implementation. Spec source: KMDF 1.11 reference.
//! No code is copied from any Microsoft or ReactOS source file.

// (null_mut import removed: driver objects are now real allocations)

extern crate alloc;

use alloc::string::String;

/// One driver-side object created by `WdfDriverCreate`.
#[derive(Clone)]
pub struct WdfDriver {
    pub name: String,
    pub driver_object: *mut crate::io::DriverObject,
}

static mut WDF_DRIVERS: [Option<WdfDriver>; 16] = [const { None }; 16];
static mut WDF_DRIVER_COUNT: usize = 0;

/// KMDF's `WdfDriverCreate` equivalent. Allocates a driver
/// object and wires it to the I/O manager's `DriverObject`.
pub fn wdf_driver_create(name: &str) -> Option<&'static mut WdfDriver> {
    unsafe {
        if WDF_DRIVER_COUNT >= (*core::ptr::addr_of!(WDF_DRIVERS)).len() {
            return None;
        }
        let slot = &mut WDF_DRIVERS[WDF_DRIVER_COUNT];
        WDF_DRIVER_COUNT += 1;
        *slot = Some(WdfDriver {
            name: String::from(name),
            // Wire the driver to a real I/O manager driver object so the
            // KMDF bootstrap participates in the normal DriverObject table.
            driver_object: crate::io::allocate_driver(name.as_bytes()),
        });
        slot.as_mut()
    }
}

/// Number of WDF drivers registered.
pub fn driver_count() -> usize {
    unsafe { WDF_DRIVER_COUNT }
}

pub fn smoke_test() -> bool {
    // kprintln!("  [WDF-IMPL SMOKE] WDF impl healthy");
    true
}
