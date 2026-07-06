//! BTL — system-call bridge directory.

#![cfg(target_arch = "loongarch64")]

pub mod nt;
pub mod win32;

pub fn init() {}
