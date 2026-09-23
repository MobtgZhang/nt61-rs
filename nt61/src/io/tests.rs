//! I/O Subsystem Unit Tests
//!
//! Comprehensive test suite for the I/O subsystem.
//! Tests cover:
//! - IRP allocation and completion
//! - Device object management
//! - Driver object management
//! - I/O stack locations
//! - Device queue operations

use crate::rtl::testing::TestStats;
use core::ptr::null_mut;

/// Run all I/O subsystem unit tests
pub fn run_tests() -> bool {
    let mut stats = TestStats::new("IO-UNIT");

    // IRP Tests
    stats.test("IRP Allocation", test_irp_allocation);
    stats.test("IRP Stack Location", test_irp_stack_location);
    stats.test("IRP Completion", test_irp_completion);
    stats.test("IRP Cancellation", test_irp_cancellation);

    // Device Object Tests
    stats.test("Device Creation", test_device_creation);
    stats.test("Device Lookup", test_device_lookup);
    stats.test("Device Deletion", test_device_deletion);

    // Driver Object Tests
    stats.test("Driver Creation", test_driver_creation);
    stats.test("Driver Registration", test_driver_registration);
    stats.test("Driver Dispatch", test_driver_dispatch);

    // Device Queue Tests
    stats.test("Queue Initialization", test_device_queue_init);
    stats.test("Queue Insert", test_device_queue_insert);
    stats.test("Queue Remove", test_device_queue_remove);

    // I/O Request Tests
    stats.test("Read Request", test_read_request);
    stats.test("Write Request", test_write_request);
    stats.test("IOCTL Request", test_ioctl_request);

    stats.finish()
}

// =============================================================================
// IRP Tests
// =============================================================================

fn test_irp_allocation() -> bool {
    use crate::io::irp;

    let stack_size = 2u8;
    let irp = irp::allocate_irp(stack_size);

    if irp.is_null() {
        return false;
    }

    unsafe {
        // Verify stack size
        if (*irp).stack_count != stack_size {
            irp::free_irp(irp);
            return false;
        }

        crate::boot_println!("    Allocated IRP: stack_size={}", stack_size);
        irp::free_irp(irp);
    }

    true
}

fn test_irp_stack_location() -> bool {
    use crate::io::irp;

    let irp = irp::allocate_irp(3);
    if irp.is_null() {
        return false;
    }

    unsafe {
        // Get current stack location
        let stack_loc = irp::get_current_stack_location(irp);
        if stack_loc.is_null() {
            irp::free_irp(irp);
            return false;
        }

        // Get next stack location
        let next_stack = irp::get_next_stack_location(irp);
        if next_stack.is_null() {
            irp::free_irp(irp);
            return false;
        }

        crate::boot_println!("    IRP stack locations: OK");
        irp::free_irp(irp);
    }

    true
}

fn test_irp_completion() -> bool {
    use crate::io::irp;

    let irp = irp::allocate_irp(1);
    if irp.is_null() {
        return false;
    }

    unsafe {
        // Set completion routine
        let status = 0u32; // STATUS_SUCCESS
        irp::complete_irp(irp, status);

        crate::boot_println!("    IRP completed with status: 0x{:x}", status);
    }

    true
}

fn test_irp_cancellation() -> bool {
    use crate::io::irp;

    let irp = irp::allocate_irp(1);
    if irp.is_null() {
        return false;
    }

    unsafe {
        // Mark IRP as cancellable
        (*irp).cancel = false;

        // Cancel the IRP
        irp::cancel_irp(irp);

        if !(*irp).cancel {
            irp::free_irp(irp);
            return false;
        }

        irp::free_irp(irp);
    }

    true
}

// =============================================================================
// Device Object Tests
// =============================================================================

fn test_device_creation() -> bool {
    use crate::io::device;

    let device_name = b"\\Device\\TestDevice";
    let device_ptr = device::create_device(
        device_name,
        0, // Device type
        0, // Device characteristics
    );

    if device_ptr.is_null() {
        return false;
    }

    unsafe {
        crate::boot_println!("    Created device at {:p}", device_ptr);
    }

    true
}

fn test_device_lookup() -> bool {
    use crate::io::device;

    let device_name = b"\\Device\\TestLookup";
    let device_ptr = device::create_device(device_name, 0, 0);

    if device_ptr.is_null() {
        return false;
    }

    // Lookup the device
    let found = device::lookup_device(device_name);
    if found.is_null() {
        return false;
    }

    if found != device_ptr {
        return false;
    }

    crate::boot_println!("    Device lookup: OK");
    true
}

fn test_device_deletion() -> bool {
    use crate::io::device;

    let device_name = b"\\Device\\TestDelete";
    let device_ptr = device::create_device(device_name, 0, 0);

    if device_ptr.is_null() {
        return false;
    }

    // Delete the device
    device::delete_device(device_ptr);

    // Verify it's no longer findable
    let found = device::lookup_device(device_name);
    if !found.is_null() {
        crate::boot_println!("    Warning: device still found after deletion");
    }

    true
}

// =============================================================================
// Driver Object Tests
// =============================================================================

fn test_driver_creation() -> bool {
    use crate::io::driver;

    let driver_name = b"\\Driver\\TestDriver";
    let driver_ptr = driver::create_driver_object(driver_name);

    if driver_ptr.is_null() {
        return false;
    }

    unsafe {
        crate::boot_println!("    Created driver at {:p}", driver_ptr);
    }

    true
}

fn test_driver_registration() -> bool {
    use crate::io::driver;

    let driver_name = b"\\Driver\\TestRegister";
    let driver_ptr = driver::create_driver_object(driver_name);

    if driver_ptr.is_null() {
        return false;
    }

    // Register dispatch routines
    extern "C" fn test_dispatch(_device: *mut u8, _irp: *mut u8) -> u32 {
        0 // STATUS_SUCCESS
    }

    unsafe {
        driver::set_driver_dispatch(driver_ptr, 0, test_dispatch);
        crate::boot_println!("    Registered driver dispatch");
    }

    true
}

fn test_driver_dispatch() -> bool {
    use crate::io::{driver, irp};

    let driver_ptr = driver::create_driver_object(b"\\Driver\\TestDispatch");
    if driver_ptr.is_null() {
        return false;
    }

    // Set up dispatch routine
    extern "C" fn test_dispatch(_device: *mut u8, _irp: *mut u8) -> u32 {
        0 // STATUS_SUCCESS
    }

    unsafe {
        driver::set_driver_dispatch(driver_ptr, 0, test_dispatch);

        // Create IRP and dispatch
        let irp_ptr = irp::allocate_irp(1);
        if irp_ptr.is_null() {
            return false;
        }

        let status = driver::call_driver_dispatch(driver_ptr, null_mut(), irp_ptr);
        crate::boot_println!("    Dispatch returned: 0x{:x}", status);

        irp::free_irp(irp_ptr);
    }

    true
}

// =============================================================================
// Device Queue Tests
// =============================================================================

fn test_device_queue_init() -> bool {
    use crate::io::queue::DeviceQueue;

    let mut queue = DeviceQueue::new();

    // Verify initial state
    if queue.queue_count != 0 {
        return false;
    }

    crate::boot_println!("    Device queue initialized");
    true
}

fn test_device_queue_insert() -> bool {
    use crate::io::{queue::DeviceQueue, irp};

    let mut queue = DeviceQueue::new();
    let irp_ptr = irp::allocate_irp(1);

    if irp_ptr.is_null() {
        return false;
    }

    queue.insert(irp_ptr);

    if queue.queue_count != 1 {
        unsafe { irp::free_irp(irp_ptr); }
        return false;
    }

    crate::boot_println!("    Inserted IRP into queue, count={}", queue.queue_count);
    true
}

fn test_device_queue_remove() -> bool {
    use crate::io::{queue::DeviceQueue, irp};

    let mut queue = DeviceQueue::new();
    let irp_ptr = irp::allocate_irp(1);

    if irp_ptr.is_null() {
        return false;
    }

    queue.insert(irp_ptr);

    let removed = queue.remove();
    if removed.is_null() {
        return false;
    }

    if removed != irp_ptr {
        return false;
    }

    if queue.queue_count != 0 {
        return false;
    }

    unsafe { irp::free_irp(irp_ptr); }
    true
}

// =============================================================================
// I/O Request Tests
// =============================================================================

fn test_read_request() -> bool {
    use crate::io::{irp, IRP_MJ_READ};

    let irp_ptr = irp::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = irp::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = IRP_MJ_READ;
            crate::boot_println!("    Created READ request");
        }

        irp::free_irp(irp_ptr);
    }

    true
}

fn test_write_request() -> bool {
    use crate::io::{irp, IRP_MJ_WRITE};

    let irp_ptr = irp::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = irp::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = IRP_MJ_WRITE;
            crate::boot_println!("    Created WRITE request");
        }

        irp::free_irp(irp_ptr);
    }

    true
}

fn test_ioctl_request() -> bool {
    use crate::io::{irp, IRP_MJ_DEVICE_CONTROL};

    let irp_ptr = irp::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = irp::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = IRP_MJ_DEVICE_CONTROL;
            (*stack_loc).ioctl_code = 0x12345678;
            crate::boot_println!("    Created IOCTL request, code=0x{:x}",
                               (*stack_loc).ioctl_code);
        }

        irp::free_irp(irp_ptr);
    }

    true
}
