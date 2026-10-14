//! NT6.1.7601 Kernel Entry Point (bare-metal ELF / grub multiboot)
//
//! `nt61-kernel` is the standalone ELF that grub loads via multiboot.
//! It is the *same* `kernel_main` that the UEFI winload invokes, but
//! reached through the bare-metal stub that grub expects.
//
//! The real init sequence lives in `nt61::kernel_main` so that the
//! UEFI boot path and the multiboot boot path can share it without
//! any duplicated code.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

extern crate alloc;

use nt61::kernel_main::{kernel_main, BootInfo};

// Global allocator — the kernel library uses the standard heap APIs
// (`Vec`, `String`, etc.) from `alloc`, so any binary that exercises
// the kernel needs a `#[global_allocator]` to back those allocations.
// The multiboot `kernel_entry` path uses the same bump allocator the
// UEFI path uses.
#[global_allocator]
static ALLOCATOR: nt61::mm::heap::KernelHeap = nt61::mm::heap::KernelHeap::new();

/// Fixed-buffer formatter used by the panic handler.
//
/// `PanicInfo` renders as "panicked at <file>:<line>: <message>",
/// which is the only thing that makes a kernel panic diagnosable. The
/// handler previously threw the `PanicInfo` away and printed a fixed
/// string, so a panic left no indication of which check fired.
struct PanicFormatter {
    buf: [u8; 256],
    len: usize,
}

impl PanicFormatter {
    const fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("kernel panic")
    }
}

impl core::fmt::Write for PanicFormatter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = byte;
                self.len += 1;
            }
        }
        Ok(())
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    let mut formatter = PanicFormatter::new();
    let _ =
        core::fmt::Write::write_fmt(&mut formatter, core::format_args!("KERNEL PANIC: {}", info));
    let rendered = formatter.as_str();
    nt61::hal::x86_64::serial::write_string(rendered);
    nt61::hal::x86_64::serial::write_string("\r\n");
    nt61::drivers::bootvid::bugcheck_screen(0x000000E2, rendered);
    loop {
        nt61::arch::halt();
    }
}

/// Bare-metal ELF entry. Grub multiboot invokes this with `eax =
/// 0x2BADB002` and `ebx = &multiboot_info`. We ignore those and
/// hand a default `BootInfo` to the real `kernel_main`.
///
/// We name this `kernel_entry` (not `_start`) so the host `cc`
/// linker wrapper does not conflict with the libc `_start` it
/// would otherwise pull in from `Scrt1.o`. The real entry point
/// is registered via the linker option `-e kernel_entry` set in
/// `build.rs`.
#[no_mangle]
pub extern "C" fn kernel_entry() -> ! {
    kernel_main(&BootInfo::defaults())
}

// Re-export `kernel_main` so it appears in the symbol table of the
// bare-metal ELF as well — the UEFI winload never references it
// directly, but the linker keeps it for debugging / inspection.
#[allow(dead_code)]
fn _re_export() {
    kernel_main(&BootInfo::zeroed());
}

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
    nt61::hal::x86_64::serial::write_string("KERNEL PANIC: unwind attempted in kernel\r\n");
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
