use core::sync::atomic::Ordering;
use spin::{Lazy, Mutex};

use core::sync::atomic::{AtomicI32, AtomicI64};

use super::types::*;
use core::ptr;

pub struct TimeBuffers {
    tm_buffer: tm,
    pub tm_buffer2: tm,
    asctime_buffer: [CChar; 26],
}

impl TimeBuffers {
    const fn new() -> Self {
        Self {
            tm_buffer: tm::new(),
            tm_buffer2: tm::new(),
            asctime_buffer: [0; 26],
        }
    }
}

static TIME_BUFFERS: Lazy<Mutex<TimeBuffers>> = Lazy::new(|| Mutex::new(TimeBuffers::new()));

static TIMEZONE_OFFSET: AtomicI32 = AtomicI32::new(0);
pub static DAYLIGHT: AtomicI32 = AtomicI32::new(0);
static TIMEZONE_GLOBAL: AtomicI64 = AtomicI64::new(0);
static DAYLIGHT_GLOBAL: AtomicI32 = AtomicI32::new(0);

static CLOCK_TICKS: AtomicI64 = AtomicI64::new(0);

const TZNAME_STD: &[u8] = b"UTC\0";
const TZNAME_DST: &[u8] = b"UTC\0";

#[export_name = "tzname"]
pub static mut TZNAME: [*const CChar; 2] = [
    TZNAME_STD.as_ptr() as *const CChar,
    TZNAME_DST.as_ptr() as *const CChar,
];

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _get_timezone(tz: *mut CLong) -> ErrnoT {
    if tz.is_null() {
        return EINVAL;
    }
    *tz = TIMEZONE_GLOBAL.load(Ordering::Relaxed) as CLong;
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _get_daylight(dl: *mut CInt) -> ErrnoT {
    if dl.is_null() {
        return EINVAL;
    }
    *dl = DAYLIGHT_GLOBAL.load(Ordering::Relaxed);
    0
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _set_timezone(tz: CLong) {
    TIMEZONE_GLOBAL.store(tz as i64, Ordering::Relaxed);
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn _set_daylight(dl: CInt) {
    DAYLIGHT_GLOBAL.store(dl, Ordering::Relaxed);
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn clock() -> ClockT {
    CLOCK_TICKS.fetch_add(1, Ordering::Relaxed) as ClockT
}

unsafe fn get_tm_buffer() -> *mut tm {
    let mut buffers = TIME_BUFFERS.lock();
    &mut buffers.tm_buffer as *mut tm
}

pub unsafe fn get_tm_buffer2() -> *mut tm {
    let mut buffers = TIME_BUFFERS.lock();
    &mut buffers.tm_buffer2 as *mut tm
}

unsafe fn get_asctime_buffer() -> *mut CChar {
    let mut buffers = TIME_BUFFERS.lock();
    buffers.asctime_buffer.as_mut_ptr()
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn localtime(timer: *const TimeT) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }
    localtime_r(timer, get_tm_buffer())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn gmtime(timer: *const TimeT) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }
    gmtime_r(timer, get_tm_buffer())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn localtime_r(timer: *const TimeT, result: *mut tm) -> *mut tm {
    if timer.is_null() || result.is_null() {
        return ptr::null_mut();
    }

    let t = *timer;
    let offset = TIMEZONE_OFFSET.load(Ordering::Relaxed) as i64;
    let adjusted_time = t + offset;

    time_to_tm(adjusted_time, result);
    result
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn gmtime_r(timer: *const TimeT, result: *mut tm) -> *mut tm {
    if timer.is_null() || result.is_null() {
        return ptr::null_mut();
    }

    time_to_tm(*timer, result);
    result
}

unsafe fn time_to_tm(t: TimeT, result: *mut tm) {
    const SECONDS_PER_MINUTE: i64 = 60;
    const SECONDS_PER_HOUR: i64 = 3600;
    const SECONDS_PER_DAY: i64 = 86400;

    let mut days = t / SECONDS_PER_DAY;
    let mut rem = t % SECONDS_PER_DAY;

    (*result).tm_hour = (rem / SECONDS_PER_HOUR) as CInt;
    rem %= SECONDS_PER_HOUR;
    (*result).tm_min = (rem / SECONDS_PER_MINUTE) as CInt;
    (*result).tm_sec = (rem % SECONDS_PER_MINUTE) as CInt;

    (*result).tm_wday = ((days + 4) % 7) as CInt;

    let mut year = 1970;
    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }

    (*result).tm_year = year - 1900;
    (*result).tm_yday = days as CInt;

    let month_days = if is_leap_year(year) {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    for &mdays in month_days {
        if days < mdays {
            break;
        }
        days -= mdays;
        month += 1;
    }

    (*result).tm_mon = month;
    (*result).tm_mday = (days + 1) as CInt;
    (*result).tm_isdst = 0;
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn asctime(timeptr: *const tm) -> *mut CChar {
    if timeptr.is_null() {
        return ptr::null_mut();
    }
    asctime_r(timeptr, get_asctime_buffer())
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn asctime_r(timeptr: *const tm, buf: *mut CChar) -> *mut CChar {
    if timeptr.is_null() || buf.is_null() {
        return ptr::null_mut();
    }

    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let tm = &*timeptr;
    let day = DAYS[tm.tm_wday as usize % 7];
    let month = MONTHS[tm.tm_mon as usize % 12];

    let formatted = alloc::format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}\n",
        day,
        month,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tm.tm_year + 1900
    );

    for (i, &byte) in formatted.as_bytes().iter().enumerate() {
        if i >= 25 {
            break;
        }
        *buf.add(i) = byte as CChar;
    }
    *buf.add(formatted.len().min(25)) = 0;

    buf
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn time(timer: *mut TimeT) -> TimeT {
    let uptime_ms = crate::hal::common::pit::get_system_time_ms();
    let current_time = (uptime_ms / 1000) as i64;

    if !timer.is_null() {
        *timer = current_time;
    }

    current_time
}
