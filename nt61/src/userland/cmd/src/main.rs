#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![deny(warnings)]
#![cfg_attr(test, allow(dead_code, unused_imports))]

mod arch;
mod shell;

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
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
