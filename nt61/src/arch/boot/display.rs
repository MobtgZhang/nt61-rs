//! Boot-time display-mode selection, IRQ masking and boot animation.

use crate::boot_types::BootMode;

/// Bring up the platform's text console (VGA mirror on x86_64,
/// log-ring on the other architectures). Idempotent across
/// re-entry.
pub fn init_text_console() {
    #[cfg(target_arch = "x86_64")]
    {
        // gui_log is the VGA mirror; it's only defined on x86_64.
        crate::hal::x86_64::text_console::init();
    }
    // The unified log-ring lives in hal::common; harmless to call
    // on every arch.
    crate::hal::common::text_console::init();
}

/// Initialise the platform serial port. Idempotent.
pub fn init_serial() {
    crate::hal::serial::init();
}

/// Mask every legacy 8259 IRQ line. On x86_64 this writes the
/// OCW1 mask to the master/slave pair; on every other
/// architecture the legacy PIC is absent and the per-arch
/// interrupt controller is handled inside `arch::init_hardware()`,
/// so this is a no-op.
pub fn mask_legacy_pic_irqs() {
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::init_and_mask_all();
}

/// Belt-and-braces mask used by the Safe-Mode polling shell:
/// every maskable IRQ is dropped at the controller so the
/// PIT/IRQ keyboard cannot fire while the shell owns the CPU.
///
/// On x86_64 we mask the legacy 8259 with the OCW1 mask
/// `0xFF/0xFF` (all 16 lines). The other architectures mask at
/// the platform controller inside `arch::init_hardware()` already;
/// we still call into the per-arch helper to leave room for
/// future per-arch masks.
pub fn mask_all_irqs_for_polled_io() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::x86_64::pic::write_mask(0xFFFF);
    }
    // The other architectures have already masked their
    // respective controllers in `arch::init_hardware()`, so no
    // additional action is needed here.
}

/// Configure the boot-time display mode (logo, SOS, ...).
///
/// `Desktop` / `Cmd`  -> Windows 7 logo + animation, no log output.
/// `DebugCmd`         -> SOS mode (verbose log) + ntbtlog.
/// `SafeMode`         -> SOS mode, distinct Safe Mode banner.
pub fn configure_boot_display(mode: BootMode) {
    use crate::drivers::bootvid::{set_boot_mode, BootDisplayMode};

    // Gate the boot log on the selected mode. Desktop and Cmd modes
    // show only the animation; DebugCmd and SafeMode show the full
    // verbose boot trace.
    crate::rtl::klog::set_boot_log_visible(!mode.suppress_boot_log());

    match mode {
        BootMode::Desktop | BootMode::Cmd => {
            set_boot_mode(BootDisplayMode::Normal);
            crate::drivers::bootvid::paint_progress_bar(0);
        }
        BootMode::DebugCmd => {
            set_boot_mode(BootDisplayMode::Sos);
            crate::rtl::ntbtlog::enable_boot_log();
            crate::rtl::ntbtlog::begin_boot_sequence();
            crate::rtl::ntbtlog::log_ntoskrnl();
        }
        BootMode::SafeMode => {
            set_boot_mode(BootDisplayMode::Sos);
            crate::rtl::ntbtlog::enable_boot_log();
            crate::rtl::ntbtlog::begin_boot_sequence();
            crate::rtl::ntbtlog::log_ntoskrnl();
            crate::boot_println!("Starting in Safe Mode");
        }
    }
}

/// Run the Windows 7 boot animation for Desktop / Cmd modes.
///
/// Animates the progress bar from 0% to 100% over a short busy-wait
/// period (~2 seconds), then clears the screen so Ring 3 cmd.exe
/// starts on a clean display.
pub fn run_boot_animation() {
    use crate::drivers::bootvid::{paint_progress_bar, vid_clean_up};

    const ANIMATION_STEPS: u32 = 20;
    for step in 0..ANIMATION_STEPS {
        let percent = (step + 1) * 100 / ANIMATION_STEPS;
        paint_progress_bar(percent);
        boot_delay_ms(100);
    }

    vid_clean_up();
}

fn boot_delay_ms(milliseconds: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let start = crate::hal::x86_64::pit::get_system_time_us();
        let target = start.saturating_add(milliseconds.saturating_mul(1_000));
        while crate::hal::x86_64::pit::get_system_time_us() < target {
            core::hint::spin_loop();
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let start = crate::hal::aarch64::timer::time_ms();
        let target = start.saturating_add(milliseconds);
        while crate::hal::aarch64::timer::time_ms() < target {
            core::hint::spin_loop();
        }
    }

    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::pit::{time, TIMER_TICKS_PER_MS};
        let start = time();
        let target = start.wrapping_add(milliseconds.saturating_mul(TIMER_TICKS_PER_MS));
        while time().wrapping_sub(start) < milliseconds.saturating_mul(TIMER_TICKS_PER_MS) {
            core::hint::spin_loop();
        }
        let _ = target;
    }

    #[cfg(target_arch = "loongarch64")]
    {
        // QEMU `virt` exposes the stable counter at CSR 0x20. The
        // emulated platform uses 100 MHz, which gives the same 2 s
        // animation cadence as x86_64 and AArch64.
        const COUNTER_HZ: u64 = 100_000_000;
        let mut counter: u64;
        unsafe { core::arch::asm!("csrrd {}, 0x20", out(reg) counter) };
        let start = counter;
        let delta = milliseconds.saturating_mul(COUNTER_HZ / 1000);
        loop {
            unsafe { core::arch::asm!("csrrd {}, 0x20", out(reg) counter) };
            if counter.wrapping_sub(start) >= delta {
                break;
            }
            core::hint::spin_loop();
        }
    }
}
