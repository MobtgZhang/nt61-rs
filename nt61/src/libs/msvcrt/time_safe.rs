use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, AtomicI32, AtomicI64, AtomicPtr, Ordering};

use super::types::*;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

struct TimeBuffers {
    tm_buffer: tm,
    tm_buffer2: tm,
    asctime_buffer: [c_char; 26],
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

static TIME_BUFFERS: Lazy<Mutex<TimeBuffers>> = Lazy::new(|| {
    Mutex::new(TimeBuffers::new())
});

static TIMEZONE_OFFSET: AtomicI32 = AtomicI32::new(0);
static DAYLIGHT: AtomicI32 = AtomicI32::new(0);
static TIMEZONE_GLOBAL: AtomicI64 = AtomicI64::new(0);
static DAYLIGHT_GLOBAL: AtomicI32 = AtomicI32::new(0);

static CLOCK_TICKS: AtomicI64 = AtomicI64::new(0);

const TZNAME_STD: &[u8] = b"UTC\0";
const TZNAME_DST: &[u8] = b"UTC\0";

#[no_mangle]
pub static mut tzname: [*const c_char; 2] = [
    TZNAME_STD.as_ptr() as *const c_char,
    TZNAME_DST.as_ptr() as *const c_char,
];

#[no_mangle]
pub unsafe extern "C" fn _get_timezone(tz: *mut c_long) -> errno_t {
    if tz.is_null() {
        return super::EINVAL;
    }
    *tz = TIMEZONE_GLOBAL.load(Ordering::Relaxed) as c_long;
    0
}

#[no_mangle]
pub unsafe extern "C" fn _get_daylight(dl: *mut c_int) -> errno_t {
    if dl.is_null() {
        return super::EINVAL;
    }
    *dl = DAYLIGHT_GLOBAL.load(Ordering::Relaxed);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _set_timezone(tz: c_long) {
    TIMEZONE_GLOBAL.store(tz as i64, Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn _set_daylight(dl: c_int) {
    DAYLIGHT_GLOBAL.store(dl, Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn clock() -> clock_t {
    CLOCK_TICKS.fetch_add(1, Ordering::Relaxed) as clock_t
}

unsafe fn get_tm_buffer() -> *mut tm {
    let mut buffers = TIME_BUFFERS.lock();
    &mut buffers.tm_buffer as *mut tm
}

unsafe fn get_tm_buffer2() -> *mut tm {
    let mut buffers = TIME_BUFFERS.lock();
    &mut buffers.tm_buffer2 as *mut tm
}

unsafe fn get_asctime_buffer() -> *mut c_char {
    let mut buffers = TIME_BUFFERS.lock();
    buffers.asctime_buffer.as_mut_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn localtime(timer: *const time_t) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }
    localtime_r(timer, get_tm_buffer())
}

#[no_mangle]
pub unsafe extern "C" fn gmtime(timer: *const time_t) -> *mut tm {
    if timer.is_null() {
        return ptr::null_mut();
    }
    gmtime_r(timer, get_tm_buffer())
}

#[no_mangle]
pub unsafe extern "C" fn localtime_r(timer: *const time_t, result: *mut tm) -> *mut tm {
    if timer.is_null() || result.is_null() {
        return ptr::null_mut();
    }

    let t = *timer;
    let offset = TIMEZONE_OFFSET.load(Ordering::Relaxed) as i64;
    let adjusted_time = t + offset;

    time_to_tm(adjusted_time, result);
    result
}

#[no_mangle]
pub unsafe extern "C" fn gmtime_r(timer: *const time_t, result: *mut tm) -> *mut tm {
    if timer.is_null() || result.is_null() {
        return ptr::null_mut();
    }

    time_to_tm(*timer, result);
    result
}

unsafe fn time_to_tm(t: time_t, result: *mut tm) {
    const SECONDS_PER_MINUTE: i64 = 60;
    const SECONDS_PER_HOUR: i64 = 3600;
    const SECONDS_PER_DAY: i64 = 86400;

    let mut days = t / SECONDS_PER_DAY;
    let mut rem = t % SECONDS_PER_DAY;

    (*result).tm_hour = (rem / SECONDS_PER_HOUR) as c_int;
    rem %= SECONDS_PER_HOUR;
    (*result).tm_min = (rem / SECONDS_PER_MINUTE) as c_int;
    (*result).tm_sec = (rem % SECONDS_PER_MINUTE) as c_int;

    (*result).tm_wday = ((days + 4) % 7) as c_int;

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
    (*result).tm_yday = days as c_int;

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
    (*result).tm_mday = (days + 1) as c_int;
    (*result).tm_isdst = 0;
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[no_mangle]
pub unsafe extern "C" fn asctime(timeptr: *const tm) -> *mut c_char {
    if timeptr.is_null() {
        return ptr::null_mut();
    }
    asctime_r(timeptr, get_asctime_buffer())
}

#[no_mangle]
pub unsafe extern "C" fn asctime_r(timeptr: *const tm, buf: *mut c_char) -> *mut c_char {
    if timeptr.is_null() || buf.is_null() {
        return ptr::null_mut();
    }

    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    let tm = &*timeptr;
    let day = DAYS[tm.tm_wday as usize % 7];
    let month = MONTHS[tm.tm_mon as usize % 12];

    let formatted = alloc::format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}\n",
        day, month, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_year + 1900
    );

    for (i, &byte) in formatted.as_bytes().iter().enumerate() {
        if i >= 25 {
            break;
        }
        *buf.add(i) = byte as c_char;
    }
    *buf.add(formatted.len().min(25)) = 0;

    buf
}

#[no_mangle]
pub unsafe extern "C" fn time(timer: *mut time_t) -> time_t {
    let current_time = 0i64; // TODO: implement real time source

    if !timer.is_null() {
        *timer = current_time;
    }

    current_time
}
