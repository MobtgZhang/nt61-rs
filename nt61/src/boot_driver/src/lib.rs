#![no_std]

extern crate alloc;

#[global_allocator]
static ALLOCATOR: nt61::mm::heap::KernelHeapAllocator = nt61::mm::heap::KernelHeapAllocator;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_INVALID_PARAMETER: i32 = -1;

type InitFn = fn();
type DispatchFn = unsafe extern "efiapi" fn(*mut u8, *mut u8) -> i32;
type UnloadFn = unsafe extern "efiapi" fn(*mut u8);

pub fn register_driver(
    driver_object: *mut u8,
    init: InitFn,
    dispatch: DispatchFn,
    unload: UnloadFn,
) -> i32 {
    if driver_object.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    init();

    unsafe {
        let object = driver_object.cast::<usize>();
        core::ptr::write_volatile(object.add(12), dispatch as *const () as usize);
        core::ptr::write_volatile(object.add(11), unload as *const () as usize);
    }

    STATUS_SUCCESS
}

pub unsafe extern "efiapi" fn dispatch_success(
    _device_object: *mut u8,
    _irp: *mut u8,
) -> i32 {
    STATUS_SUCCESS
}

pub unsafe extern "efiapi" fn unload_driver(_driver_object: *mut u8) {}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(driver_object: *mut u8, registry_path: *const u16) -> i32 {
    unsafe extern "efiapi" {
        fn DriverEntry(driver_object: *mut u8, registry_path: *const u16) -> i32;
    }

    unsafe { DriverEntry(driver_object, registry_path) }
}
