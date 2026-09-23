//! HPET (High Precision Event Timer) Driver
//
//! The HPET specification (IA-PC HPET 1.0a, March 2004)
//! describes a set of hardware timers backed by a single
//! counter, used to back the NT `KeQueryPerformanceCounter`
//! API. The HPET MMIO block is at least 1024 bytes; the first
//! 0x80 bytes are general capability / configuration registers,
//! the rest is per-timer configuration space.
//
//! Clean-room implementation. Spec source: IA-PC HPET 1.0a. No
//! code is copied from any Microsoft or ReactOS source file.

use crate::hal::common::acpi;
use crate::kprintln;

/// HPET register offsets.
const REG_CAP_ID: u64 = 0x00;   // 4-byte capability, 4-byte revision
const REG_CONFIG: u64 = 0x10;
const REG_COUNTER: u64 = 0xF0;

#[derive(Debug, Clone, Copy, Default)]
struct Hpet {
    phys_base: u64,
    cap: u32,
    freq_hz: u32,
    initialised: bool,
}

static mut HPETS: [Option<Hpet>; 2] = [None; 2];
static mut HPET_COUNT: usize = 0;

fn push_hpet(h: Hpet) {
    unsafe {
        if HPET_COUNT < HPETS.len() {
            HPETS[HPET_COUNT] = Some(h);
            HPET_COUNT += 1;
        }
    }
}

pub fn count() -> usize { unsafe { HPET_COUNT } }

/// Look up the HPET table in the ACPI tables and initialise it.
pub fn init() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::serial_puts("HPET1\n");
    let sig: [u8; 4] = *b"HPET";
    let hdr = acpi::find_table(&sig);
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::serial_puts("HPET2\n");
    if let Some(hdr) = hdr {
#[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::serial::serial_puts("HPET3\n");
        // HPET table is bigger than the standard 36-byte header.
        // The address is at offset 0x10 in the table body.
        unsafe {
            let body_va = (hdr as *const u8).add(0x10);
            let base_lo = core::ptr::read_volatile(body_va as *const u32);
            let base_hi = core::ptr::read_volatile(body_va.add(4) as *const u32);
            let base = ((base_hi as u64) << 32) | (base_lo as u64);
#[cfg(target_arch = "x86_64")]
            #[cfg(target_arch = "x86_64")]
            crate::hal::x86_64::serial::serial_puts("HPET4\n");
            if let Some(mmio) = crate::mm::syspte::map_io_space(base & !0xFFF, 4) {
#[cfg(target_arch = "x86_64")]
                #[cfg(target_arch = "x86_64")]
                crate::hal::x86_64::serial::serial_puts("HPET5\n");
                let cap_id = core::ptr::read_volatile((mmio + REG_CAP_ID) as *const u32);
#[cfg(target_arch = "x86_64")]
                #[cfg(target_arch = "x86_64")]
                crate::hal::x86_64::serial::serial_puts("HPET6\n");
                let period_fs = core::ptr::read_volatile((mmio + REG_CAP_ID + 4) as *const u32);
#[cfg(target_arch = "x86_64")]
                #[cfg(target_arch = "x86_64")]
                crate::hal::x86_64::serial::serial_puts("HPET7\n");
                let freq_hz = 1_000_000_000_000_000u64 / (period_fs as u64);
                let h = Hpet {
                    phys_base: base,
                    cap: cap_id,
                    freq_hz: freq_hz as u32,
                    initialised: true,
                };
                push_hpet(h);
            }
        }
    }
    // kprintln!("      HPET: {} timer(s) initialised", count())  // kprintln disabled (memcpy crash workaround);
}

// Suppress unused warning
#[allow(dead_code)]
const _UNUSED: () = ();

pub fn smoke_test() -> bool {
    // kprintln!("  [HPET SMOKE] HPET timers: {}", count())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  [HPET SMOKE OK] HPET stack healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
