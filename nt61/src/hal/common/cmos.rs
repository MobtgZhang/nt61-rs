//! Architecture-agnostic real-time clock interface.
//!
//! Kernel subsystems should call [`query_real_time_clock`] instead of
//! reaching into a platform-specific CMOS driver. Platforms without an
//! RTC report `None`, which callers must treat as "time unavailable"
//! rather than substituting a fake system time.

/// Wall-clock fields returned by [`query_real_time_clock`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        weekday: u8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            weekday,
        }
    }

    pub const fn second(&self) -> u8 {
        self.second
    }

    pub const fn get_second(&self) -> u8 {
        self.second
    }
}

/// Read the platform clock. Returns `None` when no RTC is available.
pub fn query_real_time_clock() -> Option<TimeFields> {
    backend::query_real_time_clock()
}

mod backend {
    #[cfg(target_arch = "x86_64")]
    pub fn query_real_time_clock() -> Option<super::TimeFields> {
        crate::hal::x86_64::cmos::hal_query_real_time_clock().map(|time| super::TimeFields {
            year: time.year,
            month: time.month,
            day: time.day,
            hour: time.hour,
            minute: time.minute,
            second: time.second(),
            weekday: time.weekday,
        })
    }

    #[cfg(target_arch = "aarch64")]
    pub fn query_real_time_clock() -> Option<super::TimeFields> {
        crate::hal::aarch64::rtc::query_real_time_clock()
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn query_real_time_clock() -> Option<super::TimeFields> {
        None
    }
}
