#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const STATUS_SUCCESS: i32 = 0;

fn dispatch(_device_object: *mut u8, _irp: *mut u8) -> i32 {
    STATUS_SUCCESS
}

fn unload(_driver_object: *mut u8) {}

#[unsafe(no_mangle)]
pub extern "efiapi" fn DriverEntry(driver_object: *mut u8, _registry_path: *const u16) -> i32 {
    if driver_object.is_null() {
        return -1;
    }

    unsafe {
        let dispatch_ptr = dispatch as *const () as usize;
        let unload_ptr = unload as *const () as usize;
        let object = driver_object.cast::<usize>();
        core::ptr::write_volatile(object.add(12), dispatch_ptr);
        core::ptr::write_volatile(object.add(11), unload_ptr);
    }

    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(driver_object: *mut u8, registry_path: *const u16) -> i32 {
    DriverEntry(driver_object, registry_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry() -> ! {
    let _ = efi_main(core::ptr::null_mut(), core::ptr::null());
    loop {
        core::hint::spin_loop();
    }
}
