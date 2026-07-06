//! Canonical paging operations.
//
//! Provides a unified `PageFlags` type and `PagingArch` trait for
//! virtual memory operations across all supported architectures.
//
//! Each architecture provides its trait implementation in its own
//! `arch/*/paging_impl.rs`.

// =====================================================================
// Page flags
// =====================================================================

/// Page mapping flags used across all architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct PageFlags(u64);

impl PageFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const USER: Self = Self(1 << 3);
    pub const GLOBAL: Self = Self(1 << 4);
    pub const WRITE_THROUGH: Self = Self(1 << 5);
    pub const CACHE_DISABLE: Self = Self(1 << 6);
    pub const ACCESSED: Self = Self(1 << 7);
    pub const DIRTY: Self = Self(1 << 8);
    pub const NO_EXECUTE: Self = Self(1 << 63);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    pub const fn bits(self) -> u64 { self.0 }
    pub const fn from_bits(bits: u64) -> Self { Self(bits) }
    pub const fn with(self, flag: Self) -> Self { Self(self.0 | flag.0) }
}

impl core::ops::BitOr for PageFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

// =====================================================================
// PagingArch trait
// =====================================================================

/// Paging operations that differ per architecture.
/// Implementations live in `arch/*/paging_impl.rs`.
pub trait PagingArch {
    fn map_page(va: u64, pa: u64, flags: PageFlags) -> bool;
    fn unmap_page(va: u64) -> Option<u64>;
    fn translate_virt(va: u64) -> Option<u64>;
    fn invalidate_tlb(va: u64);
    fn flush_tlb();
    unsafe fn load_page_root(root_pfn: u64);
    fn read_page_root_pfn() -> u64;
    const PAGE_SIZE: u64 = 4096;
    const PAGE_SHIFT: u64 = 12;
}
