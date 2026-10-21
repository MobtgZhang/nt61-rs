//! Kernel debugger transport and platform capability queries.

/// Initialise the platform's kernel debugger transport. On x86_64
/// we drive the legacy 8250 COM1 kdcom stub; on the other
/// architectures the kernel-side `kd>` shell in `servers::cmd`
/// is the equivalent debug surface. Returns `true` if a debugger
/// is actually attached on COM1 (x86_64 only).
pub fn init_kernel_debugger() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::drivers::arch::kdcom::kd_init_system();
        let connected = crate::drivers::arch::kdcom::kd_is_connected();
        if !connected {
            crate::boot_println!("No debugger connected, enabling SAC...");
            crate::rtl::sac::enable();
            crate::rtl::sac::start_sac_loop();
        } else {
            crate::boot_println!("Kernel debugger connected on COM1");
            crate::boot_println!("Type 'g' in WinDbg to continue boot...");
        }
        #[cfg(target_arch = "x86_64")]
        {
            crate::rtl::ntbtlog::end_boot_sequence();
        }
        connected
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::boot_println!("No kdcom transport on this arch, using kernel-side kd> shell");
        // SAC is not wired up on the non-x86_64 arches yet; the
        // shell in servers::cmd is the equivalent debug surface.
        false
    }
}

/// True if the platform has a legacy COM1 8250 port that can be
/// used as a kdcom transport. The kernel debugger stack is only
/// built on x86_64 today.
pub const fn has_kdcom_transport() -> bool {
    cfg!(target_arch = "x86_64")
}

/// True if the platform supports a user-mode `cmd.exe` style
/// handover (Ring 0 → Ring 3 + `iretq`-style). Only x86_64 has a
/// working user-mode ring transition today; the other arches
/// fall back to the kernel-side CMD shell.
pub const fn has_user_mode_hand_off() -> bool {
    cfg!(target_arch = "x86_64")
}

/// Human-readable architecture / QEMU machine name printed in
/// the Safe-Mode shell title pane.
///
/// Lives in `arch::boot` because every architecture has the same
/// representation (the same string the operator types into QEMU's
/// `-machine` flag), and the kernel-side shell wants to display
/// it without an architecture-specific `cfg` block.
pub const fn arch_name_line() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "  x86_64  (QEMU: -machine pc)"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "  aarch64  (QEMU: -machine virt)"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "  riscv64  (QEMU: -machine virt)"
    }
    #[cfg(target_arch = "loongarch64")]
    {
        "  loongarch64 (QEMU: -machine virt)"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    )))]
    {
        "  unknown architecture"
    }
}

/// True if the platform exposes a linear framebuffer that bootvid
/// can drive for boot progress. After the cross-arch framebuffer
/// unification the LFB is wired on every architecture provided the
/// firmware (UEFI GOP, `-device ramfb`, BOCHS) publishes a valid
/// `BootInfo.framebuffer_*` mailbox; if it doesn't, bootvid falls
/// back to its legacy VGA path on x86_64 and is a no-op on the
/// other architectures.
///
/// The const is true on x86_64 because the VGA text buffer at
/// 0xB8000 is always present even when the firmware never sets up
/// a GOP, and on the other architectures it's true because the LFB
/// is now wired by `adopt_bootinfo_framebuffer` whenever
/// `BootInfo.framebuffer_base != 0`.
pub const fn has_vga_text_console() -> bool {
    cfg!(target_arch = "x86_64")
}
