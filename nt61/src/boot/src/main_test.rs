//! NT6.1.7601 UEFI Boot Manager - Minimal Test Version

#![no_std]
#![no_main]

extern crate uefi;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "efiapi" fn efi_main(image: uefi::Handle, table: *const core::ffi::c_void) -> uefi::Status {
    // Basic setup
    unsafe {
        uefi::boot::set_image_handle(image);
        uefi::table::set_system_table(table as *const _);
    }
    
    // Get stdout
    if let Ok(mut stdout) = uefi::boot::text_output() {
        let _ = stdout.reset(false);
        let _ = stdout.clear();
        
        // Try using the system function like in the original
        uefi::system::with_stdout(|s| {
            let _ = s.clear();
            let _ = s.reset(false);
            
            // Print a simple message
            let msg: &[u16] = &[
                0x0048, 0x0045, 0x004C, 0x004C, 0x004F, // HELLO
                0x0020,
                0x004E, 0x0054, 0x0036, 0x002E, 0x0031, // NT6.1
                0x0021, 0x000A, 0x0000
            ];
            let _ = s.output_string(msg);
        });
    }
    
    loop {}
}
