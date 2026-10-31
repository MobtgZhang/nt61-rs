//! NT6.1.7601 Kernel Entry Point
//
//! The real init sequence lives in `nt61::kernel_main` so that the
//! UEFI boot path and the multiboot boot path can share it without
//! any duplicated code.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use nt61::kernel_main::kernel_main;

// Global allocator forwarding to the single kernel heap instance.
#[global_allocator]
static ALLOCATOR: nt61::mm::heap::KernelHeapAllocator = nt61::mm::heap::KernelHeapAllocator;

/// Bare-metal ELF entry.
///
/// The loader-visible symbol is named `kernel_entry` so it can be
/// selected independently from the host C runtime entry point.
///
/// `bi_ptr` carries the boot-loader-provided `BootInfo` pointer; winload
/// passes it in both RCX (Win7 `KiSystemStartup` convention) and RDI
/// (System V first argument), so either ABI reaches the same value.
/// Passing 0 selects the built-in defaults.
#[no_mangle]
pub extern "C" fn kernel_entry(bi_ptr: usize) -> ! {
    nt61::arch::boot::kernel_entry(bi_ptr)
}

/// ELF linker entry. Keeping this symbol explicit means bare-metal
/// linking works even when external RUSTFLAGS override the Cargo
/// config's `link-arg=-e kernel_entry`.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    kernel_entry(0)
}

/// UEFI/PE entry point used when the kernel itself is emitted as
/// `ntoskrnl.exe`.  This is the same initialization path as the
/// bare-metal ELF, so winload can load and run the image without a
/// synthetic handoff trampoline.
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(boot_info_ptr: usize, _system_table: usize) -> ! {
    if boot_info_ptr == 0 {
        nt61::arch::boot::kernel_entry(0)
    }

    let boot_info = unsafe { &*(boot_info_ptr as *const nt61::boot_types::BootInfo) };
    kernel_main(boot_info)
}

/// Keep the PE entry alive when the image is linked as a bare-metal
/// ELF: --gc-sections drops no_mangle functions that nothing
/// references, and the UEFI entry must survive the ELF-to-PE
/// conversion so winload can also boot the image through efi_main
/// directly.
#[used]
pub static EFI_MAIN_LINK_KEEP: unsafe extern "efiapi" fn(usize, usize) -> ! = efi_main;

// Re-export `kernel_main` so it appears in the symbol table of the
// bare-metal ELF as well — the UEFI winload never references it
// directly, but the linker keeps it for debugging / inspection.
#[used]
static KERNEL_MAIN_LINK_KEEP: extern "C" fn(&nt61::kernel_main::BootInfo) -> ! = kernel_main;

// `core::slice::cmp::SlicePartialEq::equal_same_length` and
// `core::str::PartialEq::eq` lower to a call to libc's
// `memcmp` when the compiler does not constant-fold the
// comparison. The kernel is freestanding and cannot link
// against libc, so `memcmp` is provided by the CRT module
// (`crate::libs::msvcrt::string::memcmp`, exported with `no_mangle`).
//
// Defining a second global `memcmp` here produced a duplicate-symbol
// error when the kernel binary was linked, so this entry stub no longer
// carries its own copy.

/// `memmove` — copy `n` bytes from `src` to `dst`. The
/// regions may overlap. Signature uses `core::ffi::c_void` to match
/// the standard C ABI and avoid conflicts with any libc symbols.
//
// Safety: The pointers must be valid for `n` bytes.
/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
#[no_mangle]
pub unsafe extern "C" fn memmove(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: usize,
) -> *mut core::ffi::c_void {
    let dst = dst as *mut u8;
    let src = src as *const u8;
    // Forward copying corrupts the destination when the regions overlap and
    // `dst` is after `src`: each byte written overwrites a byte still to be
    // read. Copy backwards in that case.
    if n == 0 || (dst as usize) == (src as usize) {
        return dst as *mut core::ffi::c_void;
    }
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dst.add(i) = *src.add(i);
        }
    }
    dst as *mut core::ffi::c_void
}

/// `_Unwind_Resume` — called by the panic handler when unwinding.
/// We provide a stub since the kernel never actually unwinds.
//
/// Reaching this symbol means an unwind was attempted in a
/// `panic=abort` kernel: the panic already happened, and spinning here
/// turns a diagnosable crash into a silent hang. Report it and take the
/// same bugcheck path as the panic handler.
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    nt61::hal::serial::write_string_always("KERNEL PANIC: unwind attempted in kernel\r\n");
    nt61::drivers::bootvid::bugcheck_screen(0x000000E2, "unwind attempted in kernel");
    loop {
        nt61::arch::halt();
    }
}

/// `_Unwind_Resume_or_Rethrow` — alternative entry point for unwinding.
#[no_mangle]
pub extern "C" fn _Unwind_Resume_or_Rethrow(_exc: *mut ()) -> ! {
    _Unwind_Resume()
}
