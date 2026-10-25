#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use nt61::hal;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: nt61::mm::heap::KernelHeap = nt61::mm::heap::KernelHeap::new();

#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry() -> ! {
    efi_main(0, 0)
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    kernel_entry()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> ! {
    hal::init();
    loop {
        nt61::arch::halt();
    }
}
