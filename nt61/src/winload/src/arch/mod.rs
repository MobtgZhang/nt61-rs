//! Cross-architecture support for the NT6.1.7601 OS Loader.
//!
//! Windows 7 boots `ntoskrnl.exe` through a chain
//! `firmware -> bootmgfw.efi -> winload.efi -> ntoskrnl.exe`. The
//! loader (`winload.efi`) is the only piece that varies per target
//! architecture: the UEFI calling convention, the page-table
//! format, the ring-0 entry mechanism, and the kernel-jump
//! trampoline are all architecture specific.
//!
//! This module dispatches the small amount of architecture-specific
//! glue to the per-arch submodules. Everything else (PE loading,
//! memory-map collection, BCD parsing, hive loading, GOP capture) is
//! arch-independent and lives in `super::*`.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

/// Architecture-independent call to the kernel.
///
/// After `ExitBootServices` the loader is no longer running under
/// UEFI and may no longer use the boot-services allocator, the
/// firmware console, or the GOP framebuffer (the GOP framebuffer is
/// still present, but the protocol handle is gone). The kernel
/// expects:
///
///   * The platform-ABI first argument register
///       - `rdi` on x86_64
///       - `x0` on aarch64
///       - `a0` on riscv64 / loongarch64
///     to hold `bi_ptr` (pointer to the `BootInfo` struct).
///   * `rsp` / `sp` to point at a kernel stack (boot-services-data
///     or runtime-services-data memory that survives
///     `ExitBootServices`).
///   * All other CPU state "boot-strapped": interrupts masked,
///     paging state in whatever mode the firmware left it.
///
/// On x86_64 the loader ABI is the Microsoft x64 ABI (rcx/rdx for
/// the first two parameters), but `kernel_main` is declared
/// `extern "C"` and therefore expects the System V AMD64 ABI where
/// `rdi` is the first parameter. The x86_64-specific trampoline
/// (`x86_64::call_kernel_main`) reconciles the two by moving the
/// args and then `call`-ing `kernel_main`.
///
/// On aarch64 / riscv64 / loongarch64 the platform ABI and the
/// `extern "C"` ABI coincide, so no register-shuffling is required:
/// the Rust-generated call sequence already places `bi_ptr` in
/// `x0`/`a0`. The trampolines for those architectures only have to
/// switch the stack and `branch` to `kernel_main`.
///
/// This entry-point is invoked exactly once at the very end of
/// `os_loader_run`. It must not return — the kernel will not call
/// back into the loader.
#[inline(never)]
pub unsafe extern "C" fn call_kernel_main_from_loader(stack_top: u64, bi_ptr: u64) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::call_kernel_main(stack_top, bi_ptr)
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::call_kernel_main(stack_top, bi_ptr)
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::call_kernel_main(stack_top, bi_ptr)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::call_kernel_main(stack_top, bi_ptr)
    }
}
