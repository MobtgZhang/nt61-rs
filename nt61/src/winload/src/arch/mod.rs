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

#[cfg(target_arch = "riscv64")]
#[path = "riscv64.rs"]
pub mod current;

#[cfg(target_arch = "loongarch64")]
#[path = "loongarch64.rs"]
pub mod current;

/// Architecture dispatch surface used by the loader body.
#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
pub mod current;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
pub mod current;

/// Return the target architecture tag used by boot diagnostics.
pub const fn architecture_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64"
    }
    #[cfg(target_arch = "loongarch64")]
    {
        "loongarch64"
    }
}
