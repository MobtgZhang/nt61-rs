//! I/O System smoke test
//
//! End-to-end exercise of the kernel I/O manager. Verifies:
//! 1. A driver object can be allocated and registered.
//! 2. Two device objects can be created on top of the driver.
//! 3. The upper device can be attached above the lower one.
//! 4. An IRP can be allocated, written, and completed.
//! 5. The I/O stats counters advance as expected.

use crate::rtl::logging::subsystem::IO;

use super::{
    allocate_driver, allocate_irp, attach_device, complete_irp, create_device,
    io_stats, register_driver, DeviceType, IO_STATS,
};
use super::major;

/// Run the I/O system smoke test.
pub fn smoke_test() -> bool {
    crate::kprintln_info!("IO", "    [IO SMOKE] step 1: allocate driver object");
    let driver = allocate_driver(b"SmokeDriver");
    if driver.is_null() {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] allocate_driver returned null");
        return false;
    }

    crate::kprintln_info!("IO", "    [IO SMOKE] step 2: register driver");
    if !register_driver(driver) {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] register_driver returned false");
        return false;
    }

    crate::kprintln_info!("IO", "    [IO SMOKE] step 3: create devices (upper + lower)");
    let upper = create_device(driver, DeviceType::Disk, b"Upper");
    let lower = create_device(driver, DeviceType::Disk, b"Lower");
    if upper.is_null() || lower.is_null() {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] create_device returned null");
        return false;
    }

    crate::kprintln_info!("IO", "    [IO SMOKE] step 4: attach upper above lower");
    attach_device(upper, lower);
    unsafe {
        if (*upper).attached_device != lower {
            crate::kprintln_info!("IO", "    [IO SMOKE FAIL] attach_device: wrong attached_device");
            return false;
        }
        if (*lower).attached_to != Some(upper) {
            crate::kprintln_info!("IO", "    [IO SMOKE FAIL] attach_device: wrong attached_to");
            return false;
        }
    }

    let irps_before = IO_STATS.lock().irps_allocated;
    crate::kprintln_info!("IO", "    [IO SMOKE] step 5: allocate IRP (stack_locations=1)");
    let irp = allocate_irp(1);
    if irp.is_null() {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] allocate_irp returned null");
        return false;
    }

    // Write a stack location into the IRP's current stack.
    unsafe {
        let sl = (*irp).current_stack;
        if !sl.is_null() {
            (*sl).major_function = major::IRP_MJ_READ;
            (*sl).device_object = upper;
        }
        (*irp).io_status.status = 0xC0000001;
        (*irp).io_status.information = 0;
    }

    crate::kprintln_info!("IO", "    [IO SMOKE] step 6: complete IRP with STATUS_SUCCESS");
    complete_irp(irp, 0, 512);
    let irps_completed = IO_STATS.lock().irps_completed;
    if irps_completed < irps_before + 1 {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] irps_completed counter did not advance");
        return false;
    }

    let stats = io_stats();
    if stats.irps_allocated < 1 {
        crate::kprintln_info!("IO", "    [IO SMOKE FAIL] irps_allocated counter is 0");
        return false;
    }
    crate::kprintln_info!("IO", "    [IO SMOKE OK] driver registered, 2 devices chained, irp alloc={} complete={} cancel={}",
        stats.irps_allocated, stats.irps_completed, stats.irps_cancelled
    );
    true
}
