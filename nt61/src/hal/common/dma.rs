//! Architecture-agnostic DMA support.
//!
//! On x86_64 this module re-exports the full PCI DMA implementation.
//! On other platforms we provide stub types so portable code can compile.

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::dma::{HalAllocateCommonBuffer, HalFreeCommonBuffer, AdapterInfo};

#[cfg(not(target_arch = "x86_64"))]
pub struct AdapterInfo;

#[cfg(not(target_arch = "x86_64"))]
pub fn HalAllocateCommonBuffer(_adapter: &AdapterInfo, _size: usize) -> Option<(*mut u8, u64)> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn HalFreeCommonBuffer(_adapter: &AdapterInfo, _size: usize, _phys: u64, _virt: *mut u8) {}
