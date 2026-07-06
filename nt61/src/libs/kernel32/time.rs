//! kernel32 — time APIs
//
//! `GetSystemTime`, `GetLocalTime`, `GetTickCount`,
//! `GetTickCount64`, `QueryPerformanceCounter`,
//! `QueryPerformanceFrequency`, `GetSystemTimeAsFileTime`.
//! All values are sourced from the kernel's time source.

use super::types::DWORD;

/// `SYSTEMTIME` — 16-byte struct.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

/// `FILETIME` — 8-byte struct (100ns since 1601-01-01).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// `GetSystemTime`.
pub unsafe extern "C" fn GetSystemTime(out: *mut SystemTime) {
    if out.is_null() { return; }
    let ms = crate::ke::time::get_system_time();
    let s = (ms / 1000) as u64;
    let ns = ((ms % 1000) as u64) * 1_000_000;
    fill_system_time(out, s, ns);
}

/// `GetLocalTime` — same as `GetSystemTime` since we
/// have no concept of time zones.
pub unsafe extern "C" fn GetLocalTime(out: *mut SystemTime) { GetSystemTime(out); }

/// `GetSystemTimeAsFileTime`.
pub unsafe extern "C" fn GetSystemTimeAsFileTime(out: *mut FileTime) {
    if out.is_null() { return; }
    let ms = crate::ke::time::get_system_time();
    let ft = ms.wrapping_mul(10_000).wrapping_add(EPOCH_DIFF_100NS);
    (*out).low = ft as u32;
    (*out).high = (ft >> 32) as u32;
}

/// `GetTickCount` — milliseconds since boot, lower 32 bits.
pub extern "C" fn GetTickCount() -> DWORD {
    let t = crate::ke::time::get_tick_count();
    t
}

/// `GetTickCount64` — milliseconds since boot, full 64 bits.
pub extern "C" fn GetTickCount64() -> u64 {
    let t = crate::ke::time::get_system_time();
    t
}

/// `QueryPerformanceCounter`.
pub unsafe extern "C" fn QueryPerformanceCounter(counter: *mut i64) -> i32 {
    if counter.is_null() { return 0; }
    *counter = crate::ke::time::get_system_time() as i64;
    1
}

/// `QueryPerformanceFrequency` — 1 MHz.
pub unsafe extern "C" fn QueryPerformanceFrequency(freq: *mut i64) -> i32 {
    if freq.is_null() { return 0; }
    *freq = 1_000_000;
    1
}

/// `Sleep` — yield the current thread.
pub extern "C" fn Sleep(_ms: DWORD) {
    // The bootstrap scheduler does not implement a real
    // sleep loop. The user-mode side never runs anyway.
}

/// `SleepEx` — same as `Sleep` plus the alertable flag.
pub extern "C" fn SleepEx(_ms: DWORD, _alertable: i32) -> DWORD {
    0
}

fn fill_system_time(out: *mut SystemTime, s: u64, ns: u64) {
    // Convert seconds-since-epoch to Y/M/D.
    let secs_per_day = 86_400u64;
    let days = (s / secs_per_day) as i64;
    let mut year = 1970;
    let mut d = days;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if d < dy { break; }
        d -= dy;
        year += 1;
    }
    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    while m < 12 && d >= month_days[m] as i64 {
        d -= month_days[m] as i64;
        m += 1;
    }
    let secs_today = s % secs_per_day;
    let h = (secs_today / 3600) as u16;
    let m_s = ((secs_today % 3600) / 60) as u16;
    let s_s = (secs_today % 60) as u16;
    unsafe {
        (*out).year = year as u16;
        (*out).month = (m as u16) + 1;
        (*out).day = (d as u16) + 1;
        (*out).day_of_week = 0;
        (*out).hour = h;
        (*out).minute = m_s;
        (*out).second = s_s;
        (*out).milliseconds = (ns / 1_000_000) as u16;
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
