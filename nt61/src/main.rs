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

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    nt61::hal::x86_64::serial::write_string("KERNEL PANIC\r\n");
    nt61::drivers::bootvid::bugcheck_screen(0x000000E1, "kernel panic");
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
// against libc, so we provide our own `memcmp` here.
//
// The signature matches the C ABI on x86_64: returns an
// `i32` (<0, 0, >0) and never panics.
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

/// `memmove` — copy `n` bytes from `src` to `dst`. The
/// regions may overlap. Signature matches the C ABI.
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    dst
}

/// `_Unwind_Resume` — called by the panic handler when unwinding.
/// We provide a no-op stub since the kernel never actually unwinds.
#[no_mangle]
pub extern "C" fn _Unwind_Resume() {
    loop { core::hint::spin_loop(); }
}

/// `_Unwind_Resume_or_Rethrow` — alternative entry point for unwinding.
#[no_mangle]
pub extern "C" fn _Unwind_Resume_or_Rethrow(_exc: *mut ()) {
    loop { core::hint::spin_loop(); }
}
