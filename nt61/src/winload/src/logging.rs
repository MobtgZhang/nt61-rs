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
/// The architecture tag comes from the loader architecture facade so the
/// banner remains correct without embedding target selection in this module.
#[macro_export]
macro_rules! boot_loader_header {
    () => {
        uefi::println!("");
        uefi::println!("===============================================");
        uefi::println!("  Windows OS Loader  (winload.efi)");
        uefi::println!("  Build:  6.1.7601  (NT 6.1)");
        uefi::println!("  Arch:   {}", $crate::logging::arch_label_str());
        uefi::println!("===============================================");
        uefi::println!("");
    };
}

/// Return the architecture tag for boot banners.
///
/// Thin alias retained for the boot-header macro.
#[inline]
pub fn arch_label_str() -> &'static str {
    crate::arch::architecture_name()
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
