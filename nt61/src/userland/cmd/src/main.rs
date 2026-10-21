#![no_std]
#![no_main]
#![deny(warnings)]

mod arch;
mod shell;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        arch::halt()
    }
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> ! {
    shell::run()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry() -> ! {
    efi_main(0, 0)
}
