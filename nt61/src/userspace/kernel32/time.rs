//! Time / TickCount (kernel32).

#![allow(dead_code)]

use crate::libs::ntdll::types::{NTSTATUS};
use crate::libs::ntdll::types::LARGE_INTEGER;

pub fn get_tick_count() -> u32 { 0 }
pub fn get_tick_count64() -> u64 { 0 }

pub fn get_system_time(_st: &mut SystemTime) -> Result<(), NTSTATUS> { Ok(()) }
pub fn get_local_time(_st: &mut SystemTime) -> Result<(), NTSTATUS> { Ok(()) }

pub fn file_time_to_system_time(_ft: &LARGE_INTEGER, _st: &mut SystemTime) -> Result<(), NTSTATUS> { Ok(()) }
pub fn system_time_to_file_time(_st: &SystemTime, _ft: &mut LARGE_INTEGER) -> Result<(), NTSTATUS> { Ok(()) }

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
