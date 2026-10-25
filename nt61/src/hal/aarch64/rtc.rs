//! PL031 RTC driver for the QEMU `virt` machine.

use core::ptr::read_volatile;

const RTC_BASE: u64 = 0x0901_0000;
const RTC_DR: usize = 0x000;

#[inline]
fn reg(offset: usize) -> *mut u32 {
    (RTC_BASE as usize + offset) as *mut u32
}

pub fn query_real_time_clock() -> Option<crate::hal::common::cmos::TimeFields> {
    let timestamp = unsafe { read_volatile(reg(RTC_DR)) as u64 } as i64;
    let days = (timestamp / 86_400) as i32;
    let mut seconds_of_day = timestamp % 86_400;
    let hour = (seconds_of_day / 3600) as u8;
    seconds_of_day %= 3600;
    let minute = (seconds_of_day / 60) as u8;
    let second = (seconds_of_day % 60) as u8;

    let days_since_epoch = days as i64;
    let mut year = 1970;
    let mut remaining = days_since_epoch;
    while remaining >= if leap_year(year) { 366 } else { 365 } {
        remaining -= if leap_year(year) { 366 } else { 365 };
        year += 1;
    }
    let month_days = if leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0usize;
    while remaining >= month_days[month] {
        remaining -= month_days[month];
        month += 1;
    }
    Some(crate::hal::common::cmos::TimeFields::new(
        year as u16,
        (month + 1) as u8,
        (remaining + 1) as u8,
        hour,
        minute,
        second,
        ((days_since_epoch + 4).rem_euclid(7) + 1) as u8,
    ))
}

const fn leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
