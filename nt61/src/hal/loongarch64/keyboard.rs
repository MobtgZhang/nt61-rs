//! LoongArch64 keyboard HAL — thin re-export of the common
//! unified keyboard buffer so `hal::loongarch64::keyboard` is the
//! same API used on the other architectures.

pub use crate::hal::common::keyboard_unified::*;
