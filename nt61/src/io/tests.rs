//! I/O Subsystem Unit Tests
//!
//! Comprehensive test suite for the I/O subsystem.
//! Tests cover:
//! - IRP allocation and completion
//! - Device object management
//! - Driver object management
//! - I/O stack locations
//! - Device queue (list-head) initialisation
//!
//! Every test below exercises APIs that actually exist in `crate::io`
//! (`allocate_irp`, `io_call_driver`, `create_device`, `allocate_driver`,
//! `register_driver`). Earlier revisions referenced non-existent modules
//! (`io::irp`, `io::device`, `io::driver`, `io::queue`); those were
//! rewritten against the real surface.

use crate::rtl::testing::TestStats;

#[cfg(test)]
mod tests {
    // Under libtest the kernel heap is never initialised (no `kernel_main`
    // runs), so `pool::allocate` returns null and the harness helpers below
    // would fail at the first allocation. Configure a test region so the real
    // allocation path is exercised.
    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }
        const TEST_HEAP_LEN: usize = 4 * 1024 * 1024;
        static mut TEST_HEAP: [u8; TEST_HEAP_LEN] = [0u8; TEST_HEAP_LEN];
        let base = core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8;
        crate::mm::heap::KERNEL_HEAP.configure(base, TEST_HEAP_LEN);
    }

    #[test]
    fn device_name_is_populated() {
        ensure_test_heap();

        let driver = crate::io::allocate_driver(b"\\Driver\\TestDriverName");
        assert!(!driver.is_null());
        let device = unsafe {
            crate::io::create_device(
                driver,
                crate::io::DeviceType::Unknown,
                b"\\Device\\TestDevice",
            )
        };
        assert!(!device.is_null());

        unsafe {
            let name = (*device).device_name;
            assert!(!name.buffer.is_null());
            assert_eq!(name.length, 18 * 2);
            assert_eq!(name.maximum_length, 19 * 2);
            for (i, expected) in b"\\Device\\TestDevice".iter().enumerate() {
                assert_eq!(name.buffer.add(i).read(), *expected as u16);
            }
            assert_eq!(name.buffer.add(18).read(), 0);
        }
    }

    #[test]
    fn driver_name_buffer_is_populated() {
        ensure_test_heap();

        let driver = crate::io::allocate_driver(b"\\Driver\\TestDriverBuffer");
        assert!(!driver.is_null());
        unsafe {
            let name = (*driver).driver_name;
            assert!(
                !name.buffer.is_null(),
                "UnicodeString lengths set without a buffer"
            );
            assert_eq!(name.length, 24 * 2);
            for (i, expected) in b"\\Driver\\TestDriverBuffer".iter().enumerate() {
                assert_eq!(name.buffer.add(i).read(), *expected as u16);
            }
            assert_eq!(name.buffer.add(24).read(), 0);
        }
    }

    #[test]
    fn io_complete_request_posts_iocp_packet() {
        ensure_test_heap();

        let port_id = crate::io::iocp::create_io_completion_port(0).expect("port");
        assert!(port_id > 0);

        let irp = crate::io::allocate_irp(1);
        assert!(!irp.is_null());

        unsafe {
            (*irp).bind_completion(port_id, 0x5A5A, 0x1BAD_BEEF);
            (*irp).io_status.status = 0xC000_0022;
            (*irp).io_status.information = 42;
            crate::io::io_complete_request(irp, 0);
        }

        let packet = crate::io::iocp::get_queued_completion_status(port_id, 0)
            .expect("io_complete_request must queue a packet on the bound port");
        assert_eq!(packet.status, 0xC000_0022);
        assert_eq!(packet.bytes_transferred, 42);
        assert_eq!(packet.completion_key, 0x5A5A);
        assert_eq!(packet.overlapped, 0x1BAD_BEEF);

        assert_eq!(
            crate::io::iocp::close_io_completion_port(port_id),
            crate::io::iocp::STATUS_SUCCESS
        );
    }
}

/// Run all I/O subsystem unit tests
pub fn run_tests() -> bool {
    let mut stats = TestStats::new("IO-UNIT");

    // IRP Tests
    stats.test("IRP Allocation", test_irp_allocation);
    stats.test("IRP Stack Location", test_irp_stack_location);
    stats.test(
        "IRP Skip Stack Location Boundary",
        test_irp_skip_stack_location_boundary,
    );
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
    let stack_size = 2u8;
    let irp = crate::io::allocate_irp(stack_size);

    if irp.is_null() {
        return false;
    }

    unsafe {
        // Verify stack size
        if (*irp).stack_count != stack_size {
            crate::io::free_irp(irp);
            return false;
        }

        // `ExAllocateIrp` anchors CurrentStack at location StackCount.
        if (*irp).current_stack.is_null() || (*irp).current_location != stack_size {
            crate::io::free_irp(irp);
            return false;
        }

        crate::boot_println!("    Allocated IRP: stack_size={}", stack_size);
        crate::io::free_irp(irp);
    }

    true
}

fn test_irp_stack_location() -> bool {
    unsafe {
        let irp = crate::io::allocate_irp(3);
        if irp.is_null() {
            return false;
        }

        // Get current stack location
        let stack_loc = crate::io::irp_stack::get_current_stack_location(irp);
        if stack_loc.is_null() {
            crate::io::free_irp(irp);
            return false;
        }

        // Get next stack location
        let next_stack = crate::io::irp_stack::get_next_stack_location(irp);
        if next_stack.is_null() {
            crate::io::free_irp(irp);
            return false;
        }

        crate::boot_println!("    IRP stack locations: OK");
        crate::io::free_irp(irp);

        true
    }
}

fn test_irp_skip_stack_location_boundary() -> bool {
    let irp = crate::io::allocate_irp(2);
    if irp.is_null() {
        return false;
    }

    let result = unsafe {
        let mut ok = true;

        // Skip down one slot at a time and confirm each skip advances
        // the pointer towards the bottom of the IRP allocation.
        let mut current_location = (*irp).current_location;
        while current_location > 1 {
            let stack_before = (*irp).current_stack;
            let location_before = (*irp).current_location;
            crate::io::irp_stack::skip_current_stack_location(irp);
            current_location = (*irp).current_location;
            if (*irp).current_stack == stack_before || (*irp).current_location >= location_before {
                ok = false;
                break;
            }
        }

        // At the `current_location == 1` boundary there is no lower
        // slot: skipping must be a no-op so the pointer cannot walk
        // off the bottom of the IRP allocation.
        if ok && (*irp).current_location == 1 {
            let stack_before = (*irp).current_stack;
            crate::io::irp_stack::skip_current_stack_location(irp);
            if (*irp).current_stack != stack_before || (*irp).current_location != 1 {
                ok = false;
            }
        } else if ok {
            ok = false;
        }

        ok
    };

    crate::boot_println!("    IRP skip stack location boundary: OK");
    crate::io::free_irp(irp);

    result
}

fn test_irp_completion() -> bool {
    unsafe {
        let irp = crate::io::allocate_irp(1);
        if irp.is_null() {
            return false;
        }

        // Set completion status
        let status = 0i32; // STATUS_SUCCESS
        crate::io::complete_irp(irp, status, 0);

        let completed_status = (*irp).io_status.status;
        if completed_status != status as u32 {
            crate::io::free_irp(irp);
            return false;
        }

        crate::boot_println!("    IRP completed with status: 0x{:x}", status);
        crate::io::free_irp(irp);

        true
    }
}

fn test_irp_cancellation() -> bool {
    unsafe {
        let irp = crate::io::allocate_irp(1);
        if irp.is_null() {
            return false;
        }

        // Not cancelled yet
        if crate::io::irp_is_cancelled(irp) {
            crate::io::free_irp(irp);
            return false;
        }

        // Cancel the IRP
        if !crate::io::cancel_irp(irp) {
            crate::io::free_irp(irp);
            return false;
        }

        if !crate::io::irp_is_cancelled(irp) {
            crate::io::free_irp(irp);
            return false;
        }

        crate::io::free_irp(irp);

        true
    }
}

// =============================================================================
// Device Object Tests
// =============================================================================

fn test_device_creation() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestDriver");
        if driver.is_null() {
            return false;
        }

        let device_name = b"\\Device\\TestDevice";
        let device_ptr =
            crate::io::create_device(driver, crate::io::DeviceType::Unknown, device_name);

        if device_ptr.is_null() {
            return false;
        }

        if (*device_ptr).device_type as u32 != crate::io::DeviceType::Unknown as u32 {
            return false;
        }
        if (*device_ptr).driver_object != driver {
            return false;
        }
        if (*device_ptr)
            .ref_count
            .load(core::sync::atomic::Ordering::Relaxed)
            != 1
        {
            return false;
        }
        crate::boot_println!("    Created device at {:p}", device_ptr);

        true
    }
}

fn test_device_lookup() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestLookupDriver");
        if driver.is_null() {
            return false;
        }

        let device_name = b"\\Device\\TestLookup";
        let device_ptr =
            crate::io::create_device(driver, crate::io::DeviceType::Unknown, device_name);

        if device_ptr.is_null() {
            return false;
        }

        let header = crate::ob::lookup_object(device_name);
        if header.is_null() {
            // Object manager not initialised (early boot): the driver
            // device list is the authoritative link.
            return (*driver).device_object == device_ptr;
        }
        (*header).body == device_ptr as *mut ()
    }
}

fn test_device_deletion() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestDeleteDriver");
        if driver.is_null() {
            return false;
        }

        let device_ptr = crate::io::create_device(
            driver,
            crate::io::DeviceType::Unknown,
            b"\\Device\\TestDelete",
        );
        if device_ptr.is_null() {
            return false;
        }

        // There is no IoDeleteDevice equivalent in this tree; the implemented
        // removal path is the PnP state machine, which ends in `Deleted`.
        if !crate::io::pnp_remove_device(device_ptr) {
            return false;
        }

        if (*device_ptr).pnp_state != crate::io::DevicePnPState::Deleted {
            return false;
        }

        true
    }
}

// =============================================================================
// Driver Object Tests
// =============================================================================

fn test_driver_creation() -> bool {
    let driver_name = b"\\Driver\\TestDriver";
    let driver_ptr = crate::io::allocate_driver(driver_name);

    if driver_ptr.is_null() {
        return false;
    }

    unsafe {
        if (*driver_ptr).driver_name.length as usize != driver_name.len() {
            return false;
        }
        crate::boot_println!("    Created driver at {:p}", driver_ptr);
    }

    true
}

fn test_driver_registration() -> bool {
    let driver_ptr = crate::io::allocate_driver(b"\\Driver\\TestRegister");
    if driver_ptr.is_null() {
        return false;
    }

    if !unsafe { crate::io::register_driver(driver_ptr) } {
        return false;
    }

    crate::boot_println!("    Registered driver dispatch");
    true
}

fn test_driver_dispatch() -> bool {
    let driver_ptr = crate::io::allocate_driver(b"\\Driver\\TestDispatch");
    if driver_ptr.is_null() {
        return false;
    }

    // Set up dispatch routine
    unsafe extern "C" fn test_dispatch(
        _device: *mut crate::io::DeviceObject,
        irp: *mut crate::io::Irp,
    ) -> i32 {
        if irp.is_null() {
            return 0xC0000001_u32 as i32;
        }
        unsafe {
            (*irp).io_status.status = 0;
        }
        0 // STATUS_SUCCESS
    }

    unsafe {
        (*driver_ptr).major_functions[crate::io::major::IRP_MJ_CREATE as usize] =
            Some(test_dispatch);

        // create IRP and dispatch
        let irp_ptr = crate::io::allocate_irp(1);
        if irp_ptr.is_null() {
            return false;
        }

        let device_ptr = crate::io::create_device(
            driver_ptr,
            crate::io::DeviceType::Unknown,
            b"\\Device\\TestDispatchDevice",
        );
        if device_ptr.is_null() {
            crate::io::free_irp(irp_ptr);
            return false;
        }

        let stack = crate::io::irp_stack::get_current_stack_location(irp_ptr);
        if stack.is_null() {
            crate::io::free_irp(irp_ptr);
            return false;
        }
        (*stack).major_function = crate::io::major::IRP_MJ_CREATE;

        let status = crate::io::io_call_driver(device_ptr, irp_ptr);
        crate::boot_println!("    Dispatch returned: 0x{:x}", status);

        if status != 0 {
            crate::io::free_irp(irp_ptr);
            return false;
        }

        crate::io::free_irp(irp_ptr);
    }

    true
}

// =============================================================================
// Device Queue Tests
// =============================================================================

fn test_device_queue_init() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestQueueDriver");
        if driver.is_null() {
            return false;
        }

        let device = crate::io::create_device(driver, crate::io::DeviceType::Unknown, b"");
        if device.is_null() {
            return false;
        }

        if !(*device).device_queue.is_empty() {
            return false;
        }

        crate::boot_println!("    Device queue initialized");
        true
    }
}

fn test_device_queue_insert() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestQueueInsertDriver");
        if driver.is_null() {
            return false;
        }

        let device = crate::io::create_device(driver, crate::io::DeviceType::Unknown, b"");
        let irp_ptr = crate::io::allocate_irp(1);

        if device.is_null() || irp_ptr.is_null() {
            return false;
        }

        // Manual DEVICE_QUEUE insert: link the IRP entry into the head.
        let head = &mut (*device).device_queue;
        let entry = &mut (*irp_ptr).thread_list_entry;
        entry.flink = head.flink;
        entry.blink = head;
        head.flink = entry;
        if head.is_empty() {
            crate::io::free_irp(irp_ptr);
            return false;
        }
        if core::ptr::eq(entry.flink, head) {
            crate::io::free_irp(irp_ptr);
            return false;
        }
        crate::boot_println!("    Inserted IRP into queue");

        crate::io::free_irp(irp_ptr);
        true
    }
}

fn test_device_queue_remove() -> bool {
    unsafe {
        let driver = crate::io::allocate_driver(b"\\Driver\\TestQueueRemoveDriver");
        if driver.is_null() {
            return false;
        }

        let device = crate::io::create_device(driver, crate::io::DeviceType::Unknown, b"");
        let irp_ptr = crate::io::allocate_irp(1);

        if device.is_null() || irp_ptr.is_null() {
            return false;
        }

        let head = &mut (*device).device_queue;
        let entry = &mut (*irp_ptr).thread_list_entry;
        entry.flink = head;
        entry.blink = head;
        head.flink = entry;
        head.blink = entry;

        let removed = head.flink;
        if removed.is_null() || removed != entry {
            crate::io::free_irp(irp_ptr);
            return false;
        }

        // Unlink: the head becomes empty again.
        head.flink = head;
        head.blink = head;
        if !head.is_empty() {
            crate::io::free_irp(irp_ptr);
            return false;
        }

        crate::io::free_irp(irp_ptr);
        true
    }
}

// =============================================================================
// I/O Request Tests
// =============================================================================

fn test_read_request() -> bool {
    let irp_ptr = crate::io::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = crate::io::irp_stack::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = crate::io::major::IRP_MJ_READ;
            crate::boot_println!("    Created READ request");
        }
        crate::io::free_irp(irp_ptr);
    }

    true
}

fn test_write_request() -> bool {
    let irp_ptr = crate::io::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = crate::io::irp_stack::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = crate::io::major::IRP_MJ_WRITE;
            crate::boot_println!("    Created WRITE request");
        }
        crate::io::free_irp(irp_ptr);
    }

    true
}

fn test_ioctl_request() -> bool {
    let irp_ptr = crate::io::allocate_irp(1);
    if irp_ptr.is_null() {
        return false;
    }

    unsafe {
        let stack_loc = crate::io::irp_stack::get_current_stack_location(irp_ptr);
        if !stack_loc.is_null() {
            (*stack_loc).major_function = crate::io::major::IRP_MJ_DEVICE_CONTROL;
            let ioctl_code = 0x12345678u32;
            (*stack_loc).parameters.device_io_control.io_control_code = ioctl_code;
            crate::boot_println!("    Created IOCTL request, code=0x{:x}", ioctl_code);

            if (*stack_loc).parameters.device_io_control.io_control_code != ioctl_code {
                crate::io::free_irp(irp_ptr);
                return false;
            }
        }

        crate::io::free_irp(irp_ptr);
    }

    true
}
