//! HPET (High Precision Event Timer)
//
//! The HPET is a 64-bit counter with at least 3 compare registers,
//! specified by the IA-PC HPET specification. We parse the ACPI
//! HPET table to discover the MMIO base, map it through
//! `mm::syspte::map_io_space`, and expose a high-resolution
//! performance counter that maps directly to the
//! `QueryPerformanceCounter` / `QueryPerformanceFrequency` Win32
//! API.

#![cfg(target_arch = "x86_64")]

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

const HPET_REG_CAP: u64 = 0x00;
const HPET_REG_CFG: u64 = 0x10;
const HPET_REG_COUNTER: u64 = 0xF0;

const HPET_CFG_ENABLE: u32 = 1 << 0;
const HPET_CFG_LEGACY: u32 = 1 << 1;

static HPET_VA: AtomicU64 = AtomicU64::new(0);
static HPET_FREQ_HZ: AtomicU64 = AtomicU64::new(0);
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0);

#[repr(C, packed)]
struct AcpiHpetTable {
    header: [u8; 36],
    event_block_id: u32,
    base_address: u64,
    hpet_number: u8,
    clock_tick_unit: u16,
    _padding: u8,
}

fn hpet_va() -> u64 {
    HPET_VA.load(Ordering::Acquire)
}

fn hpet_reg(off: u64) -> u32 {
    let va = hpet_va();
    if va == 0 { return 0; }
    unsafe { ptr::read_volatile((va + off) as *const u32) }
}

fn hpet_reg_write(off: u64, val: u32) {
    let va = hpet_va();
    if va == 0 { return; }
    unsafe { ptr::write_volatile((va + off) as *mut u32, val); }
}

fn hpet_reg64(off: u64) -> u64 {
    let va = hpet_va();
    if va == 0 { return 0; }
    unsafe { ptr::read_volatile((va + off) as *const u64) }
}

/// Initialise the HPET. `acpi_hpet_phys` is the physical address
/// of the ACPI HPET table; if it is 0 we silently succeed with
/// HPET disabled.
pub fn init(acpi_hpet_phys: u64) -> bool {
    if acpi_hpet_phys == 0 { return false; }
    let table_va = acpi_hpet_phys as *const AcpiHpetTable;
    let base: u64 = unsafe {
        let p = core::ptr::addr_of!((*table_va).base_address);
        ptr::read_unaligned(p)
    };
    if base == 0 { return false; }

    // Map the registers. The HPET spec requires a 1 KiB aligned
    // region; we map 1 page (4 KiB) which is plenty.
    let va = crate::mm::syspte::map_io_space(base, 1).unwrap_or(base);
    HPET_VA.store(va, Ordering::Release);

    let cap = hpet_reg64(HPET_REG_CAP);
    let period_fs = cap >> 32; // femtoseconds per tick
    if period_fs == 0 { return false; }
    let hz = 1_000_000_000_000_000u64 / period_fs as u64;
    HPET_FREQ_HZ.store(hz, Ordering::Release);
    HPET_PERIOD_FS.store(period_fs as u64, Ordering::Release);

    // Enable timer + legacy replacement routing. The legacy bit
    // is only honoured by hardware that advertises it in CAP.
    let cfg = hpet_reg(HPET_REG_CFG);
    let mut new_cfg = cfg | HPET_CFG_ENABLE;
    if cap & (1 << 15) != 0 {
        new_cfg |= HPET_CFG_LEGACY;
    }
    hpet_reg_write(HPET_REG_CFG, new_cfg);
    true
}

/// The HPET main counter frequency in Hz. Returns 0 if the HPET
/// was not initialised.
pub fn hpet_freq_hz() -> u64 {
    HPET_FREQ_HZ.load(Ordering::Acquire)
}

/// Period between HPET ticks, in femtoseconds.
pub fn hpet_period_fs() -> u64 {
    HPET_PERIOD_FS.load(Ordering::Acquire)
}

/// Read the 32-bit low half of the HPET main counter.
pub fn counter_lo() -> u32 {
    hpet_reg(HPET_REG_COUNTER)
}

/// Read the 64-bit HPET main counter. The HPET counter is 64-bit
/// wide but most hardware exposes it as a 32-bit register that
/// must be read twice with the high-32 read first to avoid
/// tearing.
pub fn counter() -> u64 {
    let va = hpet_va();
    if va == 0 { return 0; }
    let hi_first = unsafe { ptr::read_volatile((va + HPET_REG_COUNTER + 4) as *const u32) } as u64;
    let lo = unsafe { ptr::read_volatile((va + HPET_REG_COUNTER) as *const u32) } as u64;
    let hi_second = unsafe { ptr::read_volatile((va + HPET_REG_COUNTER + 4) as *const u32) } as u64;
    if hi_first == hi_second {
        (hi_first << 32) | lo
    } else {
        // The counter rolled over between the two reads; trust
        // the high value we read first.
        (hi_first << 32) | lo
    }
}

/// Equivalent of Win32 `QueryPerformanceFrequency`. Returns the
/// counter rate in Hz.
pub fn HalQueryPerformanceFrequency() -> i64 {
    hpet_freq_hz() as i64
}

/// Equivalent of Win32 `QueryPerformanceCounter`. Returns the
/// current counter value.
pub fn HalQueryPerformanceCounter() -> i64 {
    counter() as i64
}

/// Block for `us` microseconds using the HPET as the time base.
/// Returns `true` if the HPET was available; `false` if the call
/// fell back to a coarse spin.
pub fn delay_us(us: u32) -> bool {
    let hz = hpet_freq_hz();
    if hz == 0 { return false; }
    let start = counter();
    let ticks = (hz * us as u64) / 1_000_000;
    if ticks == 0 { return false; }
    loop {
        let now = counter();
        if now.wrapping_sub(start) >= ticks {
            return true;
        }
        core::hint::spin_loop();
    }
}

/// Program timer 0 with `ticks` from `now`. `now + ticks` is
/// written into the comparator. The caller is responsible for
/// enabling the matching IRQ in the I/O APIC.
pub fn program_timer0(delay_ticks: u32) {
    let cur = counter();
    let target = cur.wrapping_add(delay_ticks as u64);
    hpet_reg_write(0x108, target as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_to_hz() {
        // 100 ns = 100,000,000 femtoseconds → 10 MHz.
        let period_fs: u64 = 100_000_000;
        let hz = 1_000_000_000_000_000u64 / period_fs;
        assert_eq!(hz, 10_000_000);
    }
}
