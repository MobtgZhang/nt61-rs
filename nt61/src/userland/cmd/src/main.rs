#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![deny(warnings)]
#![cfg_attr(test, allow(dead_code, unused_imports))]

mod arch;
mod shell;

#[cfg(not(test))]
use core::panic::PanicInfo;

// Panic path for the kernel-launched command host. The kernel that
// started this process is still running when a Ring-3 thread panics,
// so the console syscall stays usable: emit the panic message and
// location on the machine console before requesting firmware shutdown,
// instead of spinning silently with no diagnostics.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;

    struct Console;

    impl Write for Console {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            for &byte in text.as_bytes() {
                arch::put_char(byte);
            }
            Ok(())
        }
    }

    let mut console = Console;
    let _ = write!(console, "\r\nnt61-cmd panic: {}\r\n", info);
    arch::halt()
}

/// Entry point of the command host.
///
/// The binary is started by the kernel's process loader through
/// 'kernel_entry', not handed control by UEFI firmware, so the image
/// handle and system-table pointers carried by the 'efiapi' signature
/// have no consumer here. The signature is kept so the same binary can
/// be launched from firmware later; such a launcher would have to
/// consume those arguments explicitly.
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> ! {
    shell::run()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry() -> ! {
    efi_main(0, 0)
}
