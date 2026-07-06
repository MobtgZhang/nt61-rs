//! NT6.1.7601 Winload Logging Utilities
//
//! Provides unified logging format for winload.efi
//! Format: [SUBSYSTEM] Message

/// Boot phase header
#[macro_export]
macro_rules! boot_phase_header {
    ($phase:expr, $name:expr) => {
        uefi::println!("");
        uefi::println!("===============================================");
        uefi::println!("  BOOT PHASE {}: {}", $phase, $name);
        uefi::println!("===============================================");
    };
}

/// Boot loader header
///
/// The architecture tag is selected at build time via `cfg(target_arch)` so
/// `x86_64`, `aarch64`, `riscv64`, and `loongarch64` each emit their own
/// banner. There is no hard-coded `x86_64` string in the macro body — see
/// the per-arch branches below.
#[macro_export]
macro_rules! boot_loader_header {
    () => {
        uefi::println!("");
        uefi::println!("===============================================");
        uefi::println!("  Windows OS Loader  (winload.efi)");
        uefi::println!("  Build:  6.1.7601  (NT 6.1)");
        uefi::println!(
            "  Arch:   {}",
            $crate::logging::arch_label_str()
        );
        uefi::println!("===============================================");
        uefi::println!("");
    };
}

/// Return the architecture tag for boot banners.
///
/// Equivalent to `cfg!(target_arch = "...")`, but evaluated inside
/// `winload.efi`'s own crate so the boot banner is always correct
/// regardless of the build target. Using `cfg!` inside the macro
/// above would also work, but exposing a runtime-callable helper
/// keeps the dependency direction clean (the macro calls into the
/// crate's public API rather than into the `cfg` machinery
/// directly).
#[inline]
pub fn arch_label_str() -> &'static str {
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

/// Kernel transfer header
#[macro_export]
macro_rules! kernel_transfer_header {
    ($stack_base:expr, $stack_top:expr, $bi_phys:expr) => {
        uefi::println!("");
        uefi::println!("===============================================");
        uefi::println!("  Transferring control to ntoskrnl.exe ...");
        uefi::println!("  Entry: KiSystemStartup");
        uefi::println!("  Stack: 0x{:016x} - 0x{:016x}", $stack_base, $stack_top);
        uefi::println!("  BootInfo PA: {:016x}", $bi_phys);
        uefi::println!("===============================================");
        uefi::println!("");
    };
}
