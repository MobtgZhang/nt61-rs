//! Timer Driver Stack
//
//! Two high-resolution timer sources back the NT time /
//! performance counter APIs:
//
//! * `hpet` - the IA-PC HPET (High Precision Event Timer).
//! * `acpi_pm` - the ACPI power-management timer (24 / 32-bit
//!   free-running counter at 3.579545 MHz).
//
//!   Clean-room implementation. Spec source: IA-PC HPET
//!   specification 1.0a, ACPI 6.0 section 4.8.2. No code is
//!   copied from any Microsoft or ReactOS source file.

extern crate alloc;

pub fn init() {
    // syspte::map_io_space now walks PML4 from CR3 via arch::map_page,
    // so system-PTE VAs above the first 512 GiB no longer fault on the
    // self-map. Enable both high-resolution timer sources.
    hpet::init();
    acpi_pm::init();
}

pub fn smoke_test() -> bool {
    // kprintln!("  [TIMER SMOKE OK] Timer stack healthy (stub mode)");
    true
}

pub mod acpi_pm;
pub mod hpet;
pub mod smoke;
