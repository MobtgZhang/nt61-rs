use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use super::types::*;
use super::string::*;
use core::ptr;

const SECONDS_PER_MINUTE: i64 = 60;
const SECONDS_PER_HOUR: i64 = 3600;
const SECONDS_PER_DAY: i64 = 86400;
const DAYS_PER_YEAR: i64 = 365;
const DAYS_IN_4_YEARS: i64 = 1461; // Including 1 leap year
const SECONDS_FROM_1970_TO_1601: i64 = 11644473600;

const DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
];

const DAY_NAMES: [&str; 7] = [
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
];

pub const CLOCKS_PER_SEC: clock_t = 1000;

static mut TM_BUFFER: tm = tm::new();
static mut TM_BUFFER2: tm = tm::new();
static ASCTIME_BUFFER: Lazy<Mutex<[c_char; 26]>> = Lazy::new(|| Mutex::new([0; 26]));
static mut TIMEZONE_OFFSET: i32 = 0; // Seconds west of UTC
static mut DAYLIGHT: i32 = 0; // DST flag

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(month: i32, year: i32) -> i32 {
    if month == 1 && is_leap_year(year) {
        29
    } else {
        DAYS_IN_MONTH[month as usize]
    }
}

fn days_in_year(year: i32) -> i32 {
    if is_leap_year(year) { 366 } else { 365 }
}

fn day_of_week(year: i32, month: i32, day: i32) -> i32 {
    let mut y = year;
    let mut m = month + 1;

    if m < 3 {
        m += 12;
        y -= 1;
    }

    let q = day;
    let k = y % 100;
    let j = y / 100;

    let h = (q + ((13 * (m + 1)) / 5) + k + (k / 4) + (j / 4) - (2 * j)) % 7;

    (h + 6) % 7
}

#[no_mangle]
pub unsafe extern "C" fn time(timer: *mut time_t) -> time_t {
    let timestamp = super::hal_stubs::read_rtc_timestamp();

    if !timer.is_null() {
        *timer = timestamp;
    }

    timestamp
}

#[no_mangle]
pub unsafe extern "C" fn clock() -> clock_t {
    let tsc = super::hal_stubs::rdtsc();
    let tsc_freq = super::hal_stubs::tsc_frequency();

    if tsc_freq > 0 {
        ((tsc * 1000) / tsc_freq) as clock_t
    } else {
        // Fallback: use a simple counter
        static mut CLOCK_TICKS: clock_t = 0;
        CLOCK_TICKS = CLOCK_TICKS.wrapping_add(1);
        CLOCK_TICKS
    }
}

unsafe fn time_to_tm(timer: time_t, utc: bool) -> *mut tm {
    let mut t = timer;

    if !utc {
        t -= TIMEZONE_OFFSET as i64;
    }

    let mut year = 1970;
    loop {
        let days_this_year = days_in_year(year);
        let seconds_this_year = days_this_year as i64 * SECONDS_PER_DAY;

        if t < seconds_this_year {
            break;
        }

        t -= seconds_this_year;
        year += 1;
    }

    let days_since_jan1 = (t / SECONDS_PER_DAY) as i32;
    t %= SECONDS_PER_DAY;

    let mut month = 0;
    let mut day = days_since_jan1;

    for m in 0..12 {
        let days = days_in_month(m, year);
        if day < days {
            month = m;
            break;
        }
        day -= days;
    }

    let hour = (t / SECONDS_PER_HOUR) as i32;
    t %= SECONDS_PER_HOUR;
    let min = (t / SECONDS_PER_MINUTE) as i32;
    let sec = (t % SECONDS_PER_MINUTE) as i32;

    let wday = day_of_week(year, month, day + 1);

    TM_BUFFER.tm_sec = sec;
    TM_BUFFER.tm_min = min;
    TM_BUFFER.tm_hour = hour;
    TM_BUFFER.tm_mday = day + 1;
    TM_BUFFER.tm_mon = month;
    TM_BUFFER.tm_year = year - 1900;
    TM_BUFFER.tm_wday = wday;
    TM_BUFFER.tm_yday = days_since_jan1;
    TM_BUFFER.tm_isdst = if !utc && DAYLIGHT != 0 { 1 } else { 0 };

    &mut TM_BUFFER as *mut tm
}

#[no_mangle]
pub unsafe extern "C" fn localtime(timer: *const time_t) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }

    time_to_tm(*timer, false)
}

#[no_mangle]
pub unsafe extern "C" fn gmtime(timer: *const time_t) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }

    time_to_tm(*timer, true)
}

#[no_mangle]
pub unsafe extern "C" fn localtime_s(result: *mut tm, timer: *const time_t) -> errno_t {
    if result.is_null() || timer.is_null() {
        return EINVAL;
    }

    let tm_ptr = time_to_tm(*timer, false);
    *result = *tm_ptr;
    0
}

#[no_mangle]
pub unsafe extern "C" fn gmtime_s(result: *mut tm, timer: *const time_t) -> errno_t {
    if result.is_null() || timer.is_null() {
        return EINVAL;
    }

    let tm_ptr = time_to_tm(*timer, true);
    *result = *tm_ptr;
    0
}

#[no_mangle]
pub unsafe extern "C" fn mktime(timeptr: *mut tm) -> time_t {
    if timeptr.is_null() {
        return -1;
    }

    let t = &mut *timeptr;

    let mut year = t.tm_year + 1900;
    let mut month = t.tm_mon;
    let day = t.tm_mday;

    while month < 0 {
        month += 12;
        year -= 1;
    }
    while month >= 12 {
        month -= 12;
        year += 1;
    }

    let mut days = 0i64;

    for y in 1970..year {
        days += days_in_year(y) as i64;
    }

    for m in 0..month {
        days += days_in_month(m, year) as i64;
    }

    days += (day - 1) as i64;

    let mut seconds = days * SECONDS_PER_DAY;
    seconds += t.tm_hour as i64 * SECONDS_PER_HOUR;
    seconds += t.tm_min as i64 * SECONDS_PER_MINUTE;
    seconds += t.tm_sec as i64;

    seconds += TIMEZONE_OFFSET as i64;

    t.tm_wday = day_of_week(year, month, day);

    let mut yday = 0;
    for m in 0..month {
        yday += days_in_month(m, year);
    }
    yday += day - 1;
    t.tm_yday = yday;

    seconds
}

#[no_mangle]
pub extern "C" fn difftime(time1: time_t, time0: time_t) -> c_double {
    (time1 - time0) as c_double
}

#[no_mangle]
pub unsafe extern "C" fn strftime(
    s: *mut c_char,
    maxsize: size_t,
    format: *const c_char,
    timeptr: *const tm,
) -> size_t {
    if s.is_null() || format.is_null() || timeptr.is_null() || maxsize == 0 {
        return 0;
    }

    let t = &*timeptr;
    let mut output_pos = 0;
    let mut format_pos = 0;

    loop {
        if output_pos >= maxsize - 1 {
            break;
        }

        let ch = *format.add(format_pos);
        if ch == 0 {
            break;
        }

        if ch != b'%' as c_char {
            *s.add(output_pos) = ch;
            output_pos += 1;
            format_pos += 1;
            continue;
        }

        format_pos += 1;
        let spec = *format.add(format_pos) as u8;

        let mut buf = [0u8; 64];
        let text: &[u8] = match spec {
            b'a' => DAY_NAMES[t.tm_wday as usize].as_bytes(),
            b'A' => DAY_NAMES[t.tm_wday as usize].as_bytes(),
            b'b' | b'h' => MONTH_NAMES[t.tm_mon as usize].as_bytes(),
            b'B' => MONTH_NAMES[t.tm_mon as usize].as_bytes(),
            b'd' => {
                let len = super::convert::itoa(t.tm_mday, buf.as_mut_ptr() as *mut c_char, 10);
                if t.tm_mday < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + t.tm_mday as u8;
                    &buf[0..2]
                } else {
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'H' => {
                if t.tm_hour < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + t.tm_hour as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(t.tm_hour, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'I' => {
                let hour12 = if t.tm_hour == 0 { 12 } else if t.tm_hour > 12 { t.tm_hour - 12 } else { t.tm_hour };
                if hour12 < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + hour12 as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(hour12, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'j' => {
                super::convert::itoa(t.tm_yday + 1, buf.as_mut_ptr() as *mut c_char, 10);
                core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
            }
            b'm' => {
                let mon = t.tm_mon + 1;
                if mon < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + mon as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(mon, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'M' => {
                if t.tm_min < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + t.tm_min as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(t.tm_min, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'p' => if t.tm_hour < 12 { b"AM" } else { b"PM" },
            b'S' => {
                if t.tm_sec < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + t.tm_sec as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(t.tm_sec, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'U' | b'W' => {
                let week = t.tm_yday / 7;
                super::convert::itoa(week, buf.as_mut_ptr() as *mut c_char, 10);
                core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
            }
            b'w' => {
                buf[0] = b'0' + t.tm_wday as u8;
                &buf[0..1]
            }
            b'y' => {
                let year = t.tm_year % 100;
                if year < 10 {
                    buf[0] = b'0';
                    buf[1] = b'0' + year as u8;
                    &buf[0..2]
                } else {
                    super::convert::itoa(year, buf.as_mut_ptr() as *mut c_char, 10);
                    core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
                }
            }
            b'Y' => {
                let year = t.tm_year + 1900;
                super::convert::itoa(year, buf.as_mut_ptr() as *mut c_char, 10);
                core::slice::from_raw_parts(buf.as_ptr(), strlen(buf.as_ptr() as *const c_char))
            }
            b'%' => b"%",
            _ => {
                *s.add(output_pos) = b'%' as c_char;
                output_pos += 1;
                if output_pos < maxsize - 1 {
                    *s.add(output_pos) = spec as c_char;
                    output_pos += 1;
                }
                format_pos += 1;
                continue;
            }
        };

        for &byte in text {
            if output_pos >= maxsize - 1 {
                break;
            }
            *s.add(output_pos) = byte as c_char;
            output_pos += 1;
        }

        format_pos += 1;
    }

    *s.add(output_pos) = 0;
    output_pos
}

#[no_mangle]
pub unsafe extern "C" fn asctime(timeptr: *const tm) -> *mut c_char {
    if timeptr.is_null() {
        return ptr::null_mut();
    }

    let t = &*timeptr;

    let day_name = DAY_NAMES[t.tm_wday as usize].as_bytes();
    let mon_name = MONTH_NAMES[t.tm_mon as usize].as_bytes();

    let mut pos = 0;

    for &b in day_name {
        ASCTIME_BUFFER[pos] = b as c_char;
        pos += 1;
    }
    ASCTIME_BUFFER[pos] = b' ' as c_char;
    pos += 1;

    for &b in mon_name {
        ASCTIME_BUFFER[pos] = b as c_char;
        pos += 1;
    }
    ASCTIME_BUFFER[pos] = b' ' as c_char;
    pos += 1;

    if t.tm_mday < 10 {
        ASCTIME_BUFFER[pos] = b' ' as c_char;
        pos += 1;
        ASCTIME_BUFFER[pos] = (b'0' + t.tm_mday as u8) as c_char;
        pos += 1;
    } else {
        ASCTIME_BUFFER[pos] = (b'0' + (t.tm_mday / 10) as u8) as c_char;
        pos += 1;
        ASCTIME_BUFFER[pos] = (b'0' + (t.tm_mday % 10) as u8) as c_char;
        pos += 1;
    }
    ASCTIME_BUFFER[pos] = b' ' as c_char;
    pos += 1;

    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_hour / 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_hour % 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = b':' as c_char;
    pos += 1;

    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_min / 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_min % 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = b':' as c_char;
    pos += 1;

    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_sec / 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + (t.tm_sec % 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = b' ' as c_char;
    pos += 1;

    let year = t.tm_year + 1900;
    ASCTIME_BUFFER[pos] = (b'0' + (year / 1000) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + ((year / 100) % 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + ((year / 10) % 10) as u8) as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = (b'0' + (year % 10) as u8) as c_char;
    pos += 1;

    ASCTIME_BUFFER[pos] = b'\n' as c_char;
    pos += 1;
    ASCTIME_BUFFER[pos] = 0;

    ASCTIME_BUFFER.as_mut_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ctime(timer: *const time_t) -> *mut c_char {
    if timer.is_null() {
        return ptr::null_mut();
    }

    let tm_ptr = localtime(timer);
    asctime(tm_ptr)
}

#[no_mangle]
pub unsafe extern "C" fn asctime_s(buf: *mut c_char, bufsz: size_t, timeptr: *const tm) -> errno_t {
    if buf.is_null() || timeptr.is_null() || bufsz < 26 {
        return EINVAL;
    }

    let result = asctime(timeptr);
    if result.is_null() {
        return EINVAL;
    }

    strcpy(buf, result);
    0
}

#[no_mangle]
pub unsafe extern "C" fn ctime_s(buf: *mut c_char, bufsz: size_t, timer: *const time_t) -> errno_t {
    if buf.is_null() || timer.is_null() || bufsz < 26 {
        return EINVAL;
    }

    let result = ctime(timer);
    if result.is_null() {
        return EINVAL;
    }

    strcpy(buf, result);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _tzset() {
    // For now, use UTC (offset = 0)
    TIMEZONE_OFFSET = 0;
    DAYLIGHT = 0;
}

#[no_mangle]
pub static mut tzname: [*const c_char; 2] = [
    b"UTC\0".as_ptr() as *const c_char,
    b"UTC\0".as_ptr() as *const c_char,
];

#[no_mangle]
pub static mut timezone: c_long = 0;

#[no_mangle]
pub static mut daylight: c_int = 0;
