//! Environment block accessors (kernel32).

#![allow(dead_code)]

pub fn get_environment_strings_w() -> *mut u16 { core::ptr::null_mut() }
pub fn get_environment_variable_w(_name: &[u16], _buf: &mut [u16]) -> u32 { 0 }
pub fn set_environment_variable_w(_name: &[u16], _value: Option<&[u16]>) -> i32 { 0 }
pub fn get_current_directory_w(_buf: &mut [u16]) -> u32 { 0 }
pub fn set_current_directory_w(_dir: &[u16]) -> i32 { 0 }
