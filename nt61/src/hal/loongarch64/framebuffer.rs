//! LoongArch64 framebuffer HAL — thin re-export of the common
//! framebuffer implementation so `hal::loongarch64::framebuffer`
//! is the same API used on the other architectures.

pub use crate::hal::common::framebuffer::*;
