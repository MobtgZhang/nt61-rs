//! CMOS / RTC (Real-Time Clock) Driver
//
//! The PC's CMOS memory bank is the legacy location of the wall-clock
//! time, configuration data, and a small non-volatile storage area.
//! Windows 6.1's `hal.dll` exports `HalQueryRealTimeClock` and
//! `HalSetRealTimeClock`; this module provides those, plus helpers to
//! read and write raw CMOS registers.
//
//! # Programming model
//
//! The CMOS is accessed through two I/O ports: 0x70 (index) and
//! 0x71 (data). Bit 7 of the index byte is the NMI mask (1 = NMI
//! disabled); we set it to 1 around every access and restore it to
//! 0 (NMI enabled) afterwards. The RTC owns registers 0x00..0x0D;
//! the rest of the 64-byte bank is general non-volatile storage.
//
//! # Time format
//
//! The RTC stores time either in BCD or in binary, and either in
//! 12-hour or 24-hour mode. We auto-detect both from the Status
//! Register B and convert to the in-kernel `TimeFields` struct.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};

/// I/O ports used to access the CMOS/RTC bank.
const CMOS_INDEX_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

/// The NMI-disable bit in the CMOS index port.
const NMI_DISABLE_BIT: u8 = 0x80;

/// Standard RTC register addresses.
pub mod reg {
    pub const SECONDS: u8 = 0x00;
    pub const MINUTES: u8 = 0x02;
    pub const HOURS: u8 = 0x04;
    pub const WEEKDAY: u8 = 0x06;
    pub const DAY: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const STATUS_A: u8 = 0x0A;
    pub const STATUS_B: u8 = 0x0B;
    pub const STATUS_C: u8 = 0x0C;
    pub const STATUS_D: u8 = 0x0D;
}

/// Status Register B bits (selected ones).
mod status_b {
    pub const HOUR_FORMAT_24: u8 = 0x02;
    pub const BINARY_MODE: u8 = 0x04;
    #[allow(dead_code)]
    pub const UPDATE_IN_PROGRESS: u8 = 0x80;
}

/// Status Register A bit 7 — "update in progress" (UIP).
mod status_a {
    pub const UPDATE_IN_PROGRESS: u8 = 0x80;
}

/// Wall-clock fields. Matches the fields `hal.dll` reads from / writes
/// to the RTC. Year is the full four-digit year (e.g. 2024), not the
/// two-digit year stored in CMOS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeFields {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    second: u8,
    pub weekday: u8,
}

impl TimeFields {
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, weekday: u8) -> Self {
        Self { year, month, day, hour, minute, second, weekday }
    }
    pub fn second(&self) -> u8 { self.second }
    pub fn get_second(&self) -> u8 { self.second }
}

/// A latch that prevents re-entering the CMOS access paths while a
/// previous call is in flight. The hardware has no concept of
/// interrupts-disabled critical sections for port 0x70/0x71; we
/// just spin here for the duration of a few-port access.
static CMOS_LOCK: AtomicBool = AtomicBool::new(false);

/// Acquire the CMOS spinlock. Returns `false` if already held.
fn try_lock() -> bool {
    CMOS_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

fn unlock() {
    CMOS_LOCK.store(false, Ordering::Release);
}

/// Wait until the RTC is no longer in the middle of an update cycle
/// (status A bit 7). Per the datasheet the update takes up to 2 ms.
fn wait_for_update_complete() {
    for _ in 0..1024 {
        let a = read_register_raw(reg::STATUS_A);
        if a & status_a::UPDATE_IN_PROGRESS == 0 {
            return;
        }
        // Tiny spin delay — at 4 GHz this is 256 ns per iteration,
        // so 1024 iterations ≈ 256 µs.
        for _ in 0..32 {
            core::hint::spin_loop();
        }
    }
}

fn read_register_raw(reg: u8) -> u8 {
    WRITE_PORT_UCHAR(CMOS_INDEX_PORT, NMI_DISABLE_BIT | (reg & 0x7F));
    let value = READ_PORT_UCHAR(CMOS_DATA_PORT);
    WRITE_PORT_UCHAR(CMOS_INDEX_PORT, reg & 0x7F); // re-enable NMI
    value
}

fn write_register_raw(reg: u8, value: u8) {
    WRITE_PORT_UCHAR(CMOS_INDEX_PORT, NMI_DISABLE_BIT | (reg & 0x7F));
    WRITE_PORT_UCHAR(CMOS_DATA_PORT, value);
    WRITE_PORT_UCHAR(CMOS_INDEX_PORT, reg & 0x7F); // re-enable NMI
}

/// Convert a BCD-encoded value to binary. The high nibble is tens,
/// the low nibble is ones.
fn bcd_to_bin(b: u8) -> u8 {
    ((b >> 4) & 0x0F) * 10 + (b & 0x0F)
}

/// Convert a binary value (0..99) to BCD.
fn bin_to_bcd(b: u8) -> u8 {
    ((b / 10) << 4) | (b % 10)
}

/// Read a CMOS register with the spinlock held. `reg` must be 0..0x7F.
pub fn read_register(reg: u8) -> u8 {
    if !try_lock() { return 0xFF; }
    let v = read_register_raw(reg);
    unlock();
    v
}

/// Write a CMOS register with the spinlock held.
pub fn write_register(reg: u8, value: u8) {
    if !try_lock() { return; }
    write_register_raw(reg, value);
    unlock();
}

/// Read the current wall-clock time. Returns `None` if the CMOS is
/// inaccessible (boot-time probe failure).
pub fn HalQueryRealTimeClock() -> Option<TimeFields> {
    if !try_lock() { return None; }

    // Wait for any in-progress update to complete so we read a
    // consistent snapshot.
    wait_for_update_complete();

    let status_b = read_register_raw(reg::STATUS_B);
    let binary_mode = (status_b & status_b::BINARY_MODE) != 0;
    let hour_24 = (status_b & status_b::HOUR_FORMAT_24) != 0;

    // Read each field. Status B is read once before the read loop.
    let mut second = read_register_raw(reg::SECONDS);
    let mut minute = read_register_raw(reg::MINUTES);
    let mut hour = read_register_raw(reg::HOURS);
    let weekday = read_register_raw(reg::WEEKDAY);
    let mut day = read_register_raw(reg::DAY);
    let mut month = read_register_raw(reg::MONTH);
    let mut year = read_register_raw(reg::YEAR) as u16;

    // On RTCs that have an UIP race we re-read the time; the IBM PC
    // technical reference suggests re-reading if Status A UIP is
    // set after the read loop.
    if read_register_raw(reg::STATUS_A) & status_a::UPDATE_IN_PROGRESS != 0 {
        second = read_register_raw(reg::SECONDS);
        minute = read_register_raw(reg::MINUTES);
        hour = read_register_raw(reg::HOURS);
        let _ = read_register_raw(reg::WEEKDAY);
        day = read_register_raw(reg::DAY);
        month = read_register_raw(reg::MONTH);
        year = read_register_raw(reg::YEAR) as u16;
    }

    unlock();

    if !binary_mode {
        second = bcd_to_bin(second);
        minute = bcd_to_bin(minute);
        hour = bcd_to_bin(hour & 0x7F);
        day = bcd_to_bin(day);
        month = bcd_to_bin(month);
        year = bcd_to_bin(year as u8) as u16;
    }

    // 12-hour mode: bit 7 of the hour byte is the PM flag.
    if !hour_24 && (hour & 0x80) != 0 {
        hour = ((hour & 0x7F) + 12) % 24;
    }

    // CMOS stores a two-digit year. The conventional pivot is
    // 1980 — anything below 80 maps to 2000+, anything >= 80 to
    // 1900+.  We apply the pivot unconditionally; BIOS and UEFI
    // both follow the same convention.
    let full_year = if year < 80 { 2000 + year } else { 1900 + year };

    Some(TimeFields {
        year: full_year,
        month,
        day,
        hour,
        minute,
        second,
        weekday,
    })
}

/// Program the CMOS RTC with the supplied wall-clock time. The
/// caller is expected to provide a valid 4-digit year; values
/// outside 0..99 are folded into the BCD register range.
///
/// This routine disables the RTC update cycle in Status B, writes
/// the new fields, and re-enables updates. It also performs a
/// pre-write read of Status B to keep the other bits intact.
pub fn HalSetRealTimeClock(time: &TimeFields) -> bool {
    if !try_lock() { return false; }

    // Pause the RTC update cycle.
    let prev_status_b = read_register_raw(reg::STATUS_B);
    write_register_raw(reg::STATUS_B, prev_status_b & !0x80);

    let binary_mode = (prev_status_b & status_b::BINARY_MODE) != 0;
    let hour_24 = (prev_status_b & status_b::HOUR_FORMAT_24) != 0;

    let mut year2 = (time.year % 100) as u8;
    let mut month = time.month;
    let mut day = time.day;
    let mut hour = time.hour;
    let mut minute = time.minute;
    let mut second = time.second;
    let weekday = time.weekday & 0x07;

    if !binary_mode {
        year2 = bin_to_bcd(year2);
        month = bin_to_bcd(month);
        day = bin_to_bcd(day);
        minute = bin_to_bcd(minute);
        second = bin_to_bcd(second);
        hour = bin_to_bcd(if hour_24 {
            hour
        } else {
            // 12-hour wrap.
            let mut h12 = hour % 12;
            if hour >= 12 { h12 |= 0x80; }
            h12
        });
    } else if !hour_24 {
        let mut h12 = hour % 12;
        if hour >= 12 { h12 |= 0x80; }
        hour = h12;
    }

    write_register_raw(reg::SECONDS, second);
    write_register_raw(reg::MINUTES, minute);
    write_register_raw(reg::HOURS, hour);
    write_register_raw(reg::WEEKDAY, weekday);
    write_register_raw(reg::DAY, day);
    write_register_raw(reg::MONTH, month);
    write_register_raw(reg::YEAR, year2);

    // Resume updates.
    write_register_raw(reg::STATUS_B, prev_status_b);

    unlock();
    true
}

/// Days-from-1601 helper. Used by callers that need to convert
/// `TimeFields` into a Windows-style 100-ns FILETIME.
///
/// The algorithm: count days in completed years since 1601, plus
/// days in completed months of the current year, plus the current
/// day-of-month. Leap years follow the Gregorian rule (every 4,
/// not every 100, but every 400).
pub fn days_from_1601(time: &TimeFields) -> u64 {
    fn is_leap(y: u16) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    let mut days: u64 = 0;
    for y in 1601..time.year {
        days += if is_leap(y) { 366 } else { 365 };
    }

    let month_days = if is_leap(time.year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let m = (time.month as usize).saturating_sub(1).min(11);
    for d in &month_days[..m] {
        days += *d as u64;
    }
    days += (time.day as u64).saturating_sub(1);
    days
}

/// Convert `TimeFields` into a 100-ns-since-1601 count (Windows
/// `SYSTEMTIME` / `FILETIME` compatible).
pub fn time_fields_to_100ns(time: &TimeFields) -> u64 {
    let days = days_from_1601(time);
    let secs = (time.hour as u64) * 3600
             + (time.minute as u64) * 60
             + (time.second as u64);
    // 1 second = 10_000_000 100-ns intervals.
    days * 86_400 * 10_000_000 + secs * 10_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_round_trip() {
        for v in 0u8..100 {
            assert_eq!(bcd_to_bin(bin_to_bcd(v)), v);
        }
    }

    #[test]
    fn days_from_1601_jan_1_1970() {
        // Unix epoch is 1970-01-01, which is 134774 days after
        // 1601-01-01.
        let t = TimeFields::new(1970, 1, 1, 0, 0, 0, 4);
        assert_eq!(days_from_1601(&t), 134774);
    }
}
