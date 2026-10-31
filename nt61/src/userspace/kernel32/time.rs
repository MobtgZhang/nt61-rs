//! User-mode time helpers backed by the HAL RTC and kernel tick counters.

use crate::libs::ntdll::types::LargeInteger;
use crate::libs::ntdll::types::NTSTATUS;

const STATUS_INVALID_PARAMETER: NTSTATUS = -0x0FFF_FFF9i32 as NTSTATUS;
const FILETIME_TICKS_PER_SECOND: i64 = 10_000_000;
const UNIX_TO_FILETIME_SECONDS: i64 = 11_644_473_600;

pub fn get_tick_count() -> u32 {
    crate::ke::time::get_tick_count()
}

pub fn get_tick_count64() -> u64 {
    crate::ke::time::get_tick_count() as u64
}

pub fn get_system_time(system_time: &mut SystemTime) -> Result<(), NTSTATUS> {
    let Some(clock) = crate::hal::common::cmos::query_real_time_clock() else {
        return Err(STATUS_INVALID_PARAMETER);
    };

    system_time.w_year = clock.year;
    system_time.w_month = u16::from(clock.month);
    system_time.w_day = u16::from(clock.day);
    system_time.w_hour = u16::from(clock.hour);
    system_time.w_minute = u16::from(clock.minute);
    system_time.w_second = u16::from(clock.second());
    system_time.w_milliseconds = 0;
    system_time.w_day_of_week = weekday(clock.year, u16::from(clock.month), u16::from(clock.day));
    Ok(())
}

pub fn get_local_time(system_time: &mut SystemTime) -> Result<(), NTSTATUS> {
    get_system_time(system_time)
}

pub fn file_time_to_system_time(
    file_time: &LargeInteger,
    system_time: &mut SystemTime,
) -> Result<(), NTSTATUS> {
    let ticks = file_time.quad_part;
    if ticks < 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let seconds = ticks / FILETIME_TICKS_PER_SECOND;
    let remainder = ticks % FILETIME_TICKS_PER_SECOND;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let unix_days = days - UNIX_TO_FILETIME_SECONDS / 86_400;
    let (year, month, day) = civil_from_days(unix_days);

    system_time.w_year = year as u16;
    system_time.w_month = month as u16;
    system_time.w_day = day as u16;
    system_time.w_hour = (seconds_of_day / 3_600) as u16;
    system_time.w_minute = ((seconds_of_day % 3_600) / 60) as u16;
    system_time.w_second = (seconds_of_day % 60) as u16;
    system_time.w_milliseconds = (remainder / 10_000) as u16;
    system_time.w_day_of_week = (unix_days.rem_euclid(7) + 1) as u16;
    Ok(())
}

pub fn system_time_to_file_time(
    system_time: &SystemTime,
    file_time: &mut LargeInteger,
) -> Result<(), NTSTATUS> {
    let year = system_time.w_year as i64;
    let month = system_time.w_month as i64;
    let day = system_time.w_day as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let unix_days = days_from_unix_epoch(year, month, day);
    let seconds = unix_days * 86_400
        + UNIX_TO_FILETIME_SECONDS
        + (system_time.w_hour as i64 * 3_600)
        + (system_time.w_minute as i64 * 60)
        + system_time.w_second as i64;
    file_time.quad_part =
        seconds * FILETIME_TICKS_PER_SECOND + system_time.w_milliseconds as i64 * 10_000;
    Ok(())
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTime {
    pub w_year: u16,
    pub w_month: u16,
    pub w_day_of_week: u16,
    pub w_day: u16,
    pub w_hour: u16,
    pub w_minute: u16,
    pub w_second: u16,
    pub w_milliseconds: u16,
}

fn weekday(year: u16, month: u16, day: u16) -> u16 {
    let unix_days = days_from_unix_epoch(i64::from(year), i64::from(month), i64::from(day));
    (unix_days.rem_euclid(7) + 1) as u16
}

fn days_from_unix_epoch(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 146_096
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + year_of_era / 400 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let mut year_of_era = 0i64;
    while year_of_era < 399 {
        let next_year_start = (year_of_era + 1) * 365 + (year_of_era + 1) / 4
            - (year_of_era + 1) / 100
            + (year_of_era + 1) / 400;
        if next_year_start > day_of_era {
            break;
        }
        year_of_era += 1;
    }
    let year_start = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + year_of_era / 400;
    let day_of_year = day_of_era - year_start;
    let year = era * 400 + year_of_era;
    let adjusted_month = (5 * day_of_year + 2) / 153;
    let month = adjusted_month + if adjusted_month < 10 { 3 } else { -9 };
    let day = day_of_year - (153 * adjusted_month + 2) / 5 + 1;
    (year + if month <= 2 { 1 } else { 0 }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_time_round_trip_is_exact() {
        let mut file_time = LargeInteger::new(0);
        let system_time = SystemTime {
            w_year: 2024,
            w_month: 2,
            w_day_of_week: 4,
            w_day: 29,
            w_hour: 12,
            w_minute: 34,
            w_second: 56,
            w_milliseconds: 789,
        };

        system_time_to_file_time(&system_time, &mut file_time).unwrap();
        let mut decoded = SystemTime::default();
        file_time_to_system_time(&file_time, &mut decoded).unwrap();

        assert_eq!(decoded.w_year, system_time.w_year);
        assert_eq!(decoded.w_month, system_time.w_month);
        assert_eq!(decoded.w_day, system_time.w_day);
        assert_eq!(decoded.w_hour, system_time.w_hour);
        assert_eq!(decoded.w_minute, system_time.w_minute);
        assert_eq!(decoded.w_second, system_time.w_second);
        assert_eq!(decoded.w_milliseconds, system_time.w_milliseconds);
    }
}
