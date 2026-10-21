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
    const SPIN_PER_STEP: u64 = 8_000_000;
    for step in 0..ANIMATION_STEPS {
        let percent = (step + 1) * 100 / ANIMATION_STEPS;
        paint_progress_bar(percent);
        let mut spin: u64 = 0;
        while spin < SPIN_PER_STEP {
            core::hint::spin_loop();
            spin += 1;
        }
    }

    vid_clean_up();
}
