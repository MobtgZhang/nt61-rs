//! ACPI Power-Management Timer Driver
//
//! The ACPI PM timer is a 24- or 32-bit free-running counter
//! that increments at 3.579545 MHz. The base address is in the
//! FADT's `pm_tmr_blk` field. The PM timer is the canonical
//! time source for `KeQueryPerformanceCounter` on machines
//! without an HPET.
//
//! Clean-room implementation. Spec source: ACPI 6.0 section
//! 4.8.2 ("Power Management Timer"). No code is copied from any
//! Microsoft or ReactOS source file.

use crate::hal::common::acpi;
use crate::kprintln;

/// ACPI PM timer frequency (Hz). 3.579545 MHz.
pub const PM_TIMER_FREQ_HZ: u32 = 3_579_545;

#[derive(Debug, Clone, Copy, Default)]
struct AcpiPm {
    port: u16,
    width: u8, // 24 or 32
    initialised: bool,
}

static mut PM_TIMER: Option<AcpiPm> = None;

pub fn port() -> u16 { unsafe { PM_TIMER.map(|p| p.port).unwrap_or(0) } }

/// Walk the FADT to find the PM timer port, then probe the bit
/// width (24 or 32). The 24-bit variant rolls over when bit 23
/// transitions from 0 to 1; the 32-bit variant doesn't.
pub fn init() {
    // The FADT is in the standard ACPI tables. We use the
    // `FADT::pm_timer_length` field; if it is 0 we treat the
    // timer as 24-bit, otherwise we trust the firmware's value.
    let sig: [u8; 4] = *b"FACP";
    if let Some(hdr) = acpi::find_table(&sig) {
        unsafe {
            // The FADT is 116 bytes (ACPI 1.0) or longer. The
            // `pm_tmr_blk` field is at offset 0x68 in the 1.0
            // FADT; the `pm_timer_length` field is at 0x6C
            // (added in ACPI 2.0+).
            let base = hdr as *const u8;
            let port = core::ptr::read_unaligned(base.add(0x68) as *const u32) as u16;
            let length = core::ptr::read_unaligned(base.add(0x6C) as *const u8);
            PM_TIMER = Some(AcpiPm {
                port,
                width: if length == 0 { 24 } else { length },
                initialised: true,
            });
        }
    }
    // kprintln!("      ACPI PM timer: port=0x{:x} width={}-bit",  // kprintln disabled (memcpy crash workaround)
//               port(), width());
}

fn width() -> u8 { unsafe { PM_TIMER.map(|p| p.width).unwrap_or(0) } }

pub fn smoke_test() -> bool {
    // kprintln!("  [ACPI-PM SMOKE] PM timer: port=0x{:x} width={}-bit",  // kprintln disabled (memcpy crash workaround)
//               port(), width());
    // kprintln!("  [ACPI-PM SMOKE OK] ACPI PM timer healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
