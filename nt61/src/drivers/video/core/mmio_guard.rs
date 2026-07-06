//! MMIO Guard with Bounds Checking and Synchronization
//
//! Provides a safe wrapper around GPU MMIO register access.
//! Every `read_reg`/`write_reg` call is:
//! 1. Range-checked against the known MMIO size for this device
//! 2. Serialized with a spinlock to prevent SMP races
//
//! Clean-room implementation.

use crate::ke::sync::Spinlock;

/// Maximum MMIO size for known GPU devices (64 MB).
/// This is a safe upper bound for all known discrete and integrated GPUs.
pub const MAX_MMIO_SIZE: u64 = 64 * 1024 * 1024;

/// A MMIO range definition with base address and size.
#[derive(Debug, Clone, Copy)]
pub struct MmioRange {
    /// Physical/MMIO base address.
    pub base: u64,
    /// Size of the MMIO region in bytes.
    pub size: u64,
}

impl MmioRange {
    /// Create a new MMIO range.
    pub const fn new(base: u64, size: u64) -> Self {
        Self { base, size }
    }

    /// Check if a given offset is within this MMIO range.
    #[inline]
    pub fn contains_offset(&self, offset: u32) -> bool {
        let offset_u64 = offset as u64;
        offset_u64 < self.size
    }

    /// Get the absolute MMIO address for a register offset.
    #[inline]
    pub fn address(&self, offset: u32) -> u64 {
        self.base + offset as u64
    }

    /// Check if a value is a valid MMIO address (within range).
    #[inline]
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.wrapping_add(self.size)
    }
}

/// MMIO accessor with bounds checking and per-device spinlock.
///
/// All MMIO operations on a GPU device should go through this guard
/// to ensure safe concurrent access and prevent out-of-range accesses.
pub struct MmioGuard {
    /// The MMIO range for this device.
    range: MmioRange,
    /// Spinlock to serialize MMIO accesses on SMP systems.
    lock: Spinlock<()>,
}

impl MmioGuard {
    /// Create a new MMIO guard.
    ///
    /// # Arguments
    /// * `base` - MMIO base address from PCI BAR0 or known hardware mapping
    /// * `size` - Size of the MMIO region. If 0, a safe maximum is used.
    ///
    /// # Safety
    /// The caller must ensure that `base..base+size` maps to the
    /// correct MMIO registers and is mapped in the kernel page tables.
    pub const fn new(base: u64, size: u64) -> Self {
        let actual_size = if size == 0 { MAX_MMIO_SIZE } else { size };
        Self {
            range: MmioRange::new(base, actual_size),
            lock: Spinlock::new(()),
        }
    }

    /// Create a new MMIO guard from a PCI BAR value.
    /// The BAR value has low bits masked off (they encode flags).
    ///
    /// # Arguments
    /// * `bar` - The raw PCI BAR value (low flags bits masked off by caller)
    /// * `bar_size_hint` - The known size for this BAR, or 0 for default
    pub const fn from_pci_bar(bar: u64, bar_size_hint: u64) -> Self {
        // PCI BARs are already masked (low 4 bits cleared).
        Self::new(bar, bar_size_hint)
    }

    /// Read a 32-bit MMIO register.
    ///
    /// Returns `0xDEADBEEFu32` if the offset is out of range.
    /// (This is a distinctive sentinel value for debugging.)
    #[inline]
    pub fn read_reg(&self, offset: u32) -> u32 {
        if !self.range.contains_offset(offset) {
            // Out-of-range access — log and return sentinel.
            // This prevents silent data corruption but still allows
            // the system to continue running.
            return 0xDEAD_BEEFu32;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Read a 32-bit MMIO register, returning None if out of range.
    #[inline]
    pub fn read_reg_opt(&self, offset: u32) -> Option<u32> {
        if !self.range.contains_offset(offset) {
            return None;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *const u32;
        Some(unsafe { core::ptr::read_volatile(addr) })
    }

    /// Write a 32-bit MMIO register.
    ///
    /// Returns `false` if the offset is out of range.
    #[inline]
    pub fn write_reg(&self, offset: u32, value: u32) -> bool {
        if !self.range.contains_offset(offset) {
            return false;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *mut u32;
        unsafe { core::ptr::write_volatile(addr, value) };
        true
    }

    /// Read a 16-bit MMIO register.
    #[inline]
    pub fn read_reg16(&self, offset: u32) -> u16 {
        if !self.range.contains_offset(offset) {
            return 0xDEADu16;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *const u16;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write a 16-bit MMIO register.
    #[inline]
    pub fn write_reg16(&self, offset: u32, value: u16) -> bool {
        if !self.range.contains_offset(offset) {
            return false;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *mut u16;
        unsafe { core::ptr::write_volatile(addr, value) };
        true
    }

    /// Read an 8-bit MMIO register.
    #[inline]
    pub fn read_reg8(&self, offset: u32) -> u8 {
        if !self.range.contains_offset(offset) {
            return 0xDEu8;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *const u8;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write an 8-bit MMIO register.
    #[inline]
    pub fn write_reg8(&self, offset: u32, value: u8) -> bool {
        if !self.range.contains_offset(offset) {
            return false;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *mut u8;
        unsafe { core::ptr::write_volatile(addr, value) };
        true
    }

    /// Read a 64-bit MMIO register (two consecutive 32-bit reads).
    #[inline]
    pub fn read_reg64(&self, offset: u32) -> u64 {
        if !self.range.contains_offset(offset) {
            return 0xDEAD_DEAD_DEAD_DEADu64;
        }
        let _guard = self.lock.lock();
        let addr = self.range.address(offset) as *const u32;
        // Read low 32 bits first (little-endian).
        let low = unsafe { core::ptr::read_volatile(addr) };
        let high = unsafe { core::ptr::read_volatile(addr.add(1)) };
        ((high as u64) << 32) | (low as u64)
    }

    /// Get the MMIO base address.
    #[inline]
    pub const fn base(&self) -> u64 {
        self.range.base
    }

    /// Get the MMIO region size.
    #[inline]
    pub const fn size(&self) -> u64 {
        self.range.size
    }

    /// Get a raw pointer to the MMIO region.
    /// # Safety: caller must ensure the offset is within range.
    #[inline]
    pub unsafe fn as_ptr(&self, offset: u32) -> *const u32 {
        self.range.address(offset) as *const u32
    }

    /// Get a raw mutable pointer to the MMIO region.
    /// # Safety: caller must ensure the offset is within range and
    /// that no other accesses are happening concurrently.
    #[inline]
    pub unsafe fn as_mut_ptr(&self, offset: u32) -> *mut u32 {
        self.range.address(offset) as *mut u32
    }
}

/// Sentinel value returned when an MMIO read is out of bounds.
pub const MMIO_OUT_OF_RANGE: u32 = 0xDEAD_BEEFu32;

impl core::fmt::Debug for MmioGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmioGuard")
            .field("base", &format_args!("0x{:016X}", self.range.base))
            .field("size", &format_args!("0x{:X}", self.range.size))
            .finish()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmio_range_contains_offset() {
        let range = MmioRange::new(0x1000, 0x1000);
        assert!(range.contains_offset(0));
        assert!(range.contains_offset(0xFFF));
        assert!(!range.contains_offset(0x1000));
        assert!(!range.contains_offset(0x2000));
    }

    #[test]
    fn test_mmio_range_address() {
        let range = MmioRange::new(0xE000_0000, 0x1000);
        assert_eq!(range.address(0), 0xE000_0000);
        assert_eq!(range.address(0x100), 0xE000_0100);
        assert_eq!(range.address(0xFFF), 0xE000_0FFF);
    }

    #[test]
    fn test_mmio_range_contains_address() {
        let range = MmioRange::new(0x1000, 0x1000);
        assert!(range.contains_address(0x1000));
        assert!(range.contains_address(0x1FFF));
        assert!(!range.contains_address(0x0FFF));
        assert!(!range.contains_address(0x2000));
    }

    #[test]
    fn test_mmio_guard_new() {
        let guard = MmioGuard::new(0x1000, 0x100);
        assert_eq!(guard.base(), 0x1000);
        assert_eq!(guard.size(), 0x100);
    }

    #[test]
    fn test_mmio_guard_new_default_size() {
        // Size 0 should use max size
        let guard = MmioGuard::new(0x1000, 0);
        assert_eq!(guard.size(), MAX_MMIO_SIZE);
    }

    #[test]
    fn test_mmio_guard_from_pci_bar() {
        let guard = MmioGuard::from_pci_bar(0xFED9_0000, 0x1000);
        assert_eq!(guard.base(), 0xFED9_0000);
        assert_eq!(guard.size(), 0x1000);
    }

    #[test]
    fn test_mmio_out_of_range_sentinel() {
        // Verify the sentinel value constant
        assert_eq!(MMIO_OUT_OF_RANGE, 0xDEAD_BEEFu32);
    }

    #[test]
    fn test_max_mmio_size() {
        // Verify max MMIO size is 64MB
        assert_eq!(MAX_MMIO_SIZE, 64 * 1024 * 1024);
    }

    #[test]
    fn test_mmio_guard_debug() {
        let guard = MmioGuard::new(0xE000_0000, 0x1000);
        let debug_str = alloc::format!("{:?}", guard);
        assert!(debug_str.contains("0xE0000000"));
        assert!(debug_str.contains("MmioGuard"));
    }

    #[test]
    fn test_mmio_range_new_const() {
        // Verify MmioRange::new is const
        const RANGE: MmioRange = MmioRange::new(0x1000, 0x200);
        assert_eq!(RANGE.base, 0x1000);
        assert_eq!(RANGE.size, 0x200);
    }

    #[test]
    fn test_mmio_range_size_zero() {
        // Edge case: size 0 should still work
        let range = MmioRange::new(0x1000, 0);
        // No offsets should be valid
        assert!(!range.contains_offset(0));
        assert!(!range.contains_address(0x1000));
    }

    #[test]
    fn test_mmio_guard_16bit_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        // Read out of range should return sentinel
        let val = guard.read_reg16(0x200);
        assert_eq!(val, 0xDEAD);
    }

    #[test]
    fn test_mmio_guard_8bit_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        // Read out of range should return sentinel
        let val = guard.read_reg8(0x200);
        assert_eq!(val, 0xDE);
    }

    #[test]
    fn test_mmio_guard_64bit_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        // Read out of range should return sentinel
        let val = guard.read_reg64(0x200);
        assert_eq!(val, 0xDEAD_DEAD_DEAD_DEADu64);
    }

    #[test]
    fn test_mmio_guard_write_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        // Write out of range should return false
        let result = guard.write_reg(0x200, 0x1234);
        assert!(!result);
    }

    #[test]
    fn test_mmio_guard_write16_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        let result = guard.write_reg16(0x200, 0x1234);
        assert!(!result);
    }

    #[test]
    fn test_mmio_guard_write8_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        let result = guard.write_reg8(0x200, 0x12);
        assert!(!result);
    }

    #[test]
    fn test_mmio_guard_read_reg_opt_out_of_range() {
        let guard = MmioGuard::new(0x1000, 0x100);
        // Out of range should return None
        let result = guard.read_reg_opt(0x200);
        assert!(result.is_none());
    }
}
