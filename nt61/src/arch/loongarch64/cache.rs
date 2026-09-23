//! LoongArch64 Cache Management
//!
//! Comprehensive cache operations:
//! - Data cache clean/invalidate/flush
//! - Instruction cache invalidate
//! - Cache line operations
//! - Prefetch hints

use core::arch::asm;

/// Cache line size (typically 64 bytes)
pub const CACHE_LINE_SIZE: usize = 64;

/// Cache operation codes
mod op {
    pub const DCACHE_IBAR: u8 = 0x00;
    pub const DCACHE_WBAR: u8 = 0x01;
    pub const DCACHE_HIT_INV: u8 = 0x08;
    pub const DCACHE_HIT_WB: u8 = 0x09;
    pub const DCACHE_HIT_WBINV: u8 = 0x0A;
    pub const ICACHE_INV: u8 = 0x10;
}

/// Clean (writeback) data cache line by virtual address
#[inline]
pub fn clean_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "cacop 0x9, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Invalidate data cache line by virtual address
#[inline]
pub fn invalidate_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "cacop 0x8, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Flush (clean + invalidate) data cache line by virtual address
#[inline]
pub fn flush_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "cacop 0xA, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Clean data cache range by virtual address
#[inline]
pub fn clean_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    while addr < end {
        clean_dcache_line(addr);
        addr += CACHE_LINE_SIZE as u64;
    }

    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

/// Invalidate data cache range by virtual address
#[inline]
pub fn invalidate_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    while addr < end {
        invalidate_dcache_line(addr);
        addr += CACHE_LINE_SIZE as u64;
    }

    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

/// Flush data cache range by virtual address
#[inline]
pub fn flush_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    while addr < end {
        flush_dcache_line(addr);
        addr += CACHE_LINE_SIZE as u64;
    }

    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

/// Invalidate instruction cache line
#[inline]
pub fn invalidate_icache_line(vaddr: u64) {
    unsafe {
        asm!(
            "cacop 0x10, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Invalidate instruction cache range
#[inline]
pub fn invalidate_icache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    while addr < end {
        invalidate_icache_line(addr);
        addr += CACHE_LINE_SIZE as u64;
    }

    unsafe {
        asm!("ibar 0", options(nostack));
    }
}

/// Synchronize instruction and data for a code region
#[inline]
pub fn sync_icache_range(start: u64, size: usize) {
    // Clean data cache to memory
    clean_dcache_range(start, size);

    // Invalidate instruction cache
    invalidate_icache_range(start, size);
}

/// Data barrier - ensure all loads/stores complete
#[inline]
pub fn dbar() {
    unsafe {
        asm!("dbar 0", options(nostack));
    }
}

/// Instruction barrier - synchronize instruction fetch
#[inline]
pub fn ibar() {
    unsafe {
        asm!("ibar 0", options(nostack));
    }
}

/// Full memory barrier
#[inline]
pub fn memory_barrier() {
    unsafe {
        asm!("dbar 0", options(nostack));
        asm!("ibar 0", options(nostack));
    }
}

/// Clean entire data cache (all levels)
#[inline]
pub fn clean_dcache_all() {
    unsafe {
        // Index-based cache operations for entire cache
        // This is simplified - full implementation would walk cache sets
        for level in 0..3 {
            for set in 0..256 {
                for way in 0..16 {
                    let index = (level << 16) | (set << 6) | way;
                    asm!(
                        "cacop 0x9, $zero, {}",
                        in(reg) index,
                        options(nostack)
                    );
                }
            }
        }
        asm!("dbar 0", options(nostack));
    }
}

/// Invalidate entire data cache
#[inline]
pub fn invalidate_dcache_all() {
    unsafe {
        for level in 0..3 {
            for set in 0..256 {
                for way in 0..16 {
                    let index = (level << 16) | (set << 6) | way;
                    asm!(
                        "cacop 0x8, $zero, {}",
                        in(reg) index,
                        options(nostack)
                    );
                }
            }
        }
        asm!("dbar 0", options(nostack));
    }
}

/// Flush entire data cache
#[inline]
pub fn flush_dcache_all() {
    unsafe {
        for level in 0..3 {
            for set in 0..256 {
                for way in 0..16 {
                    let index = (level << 16) | (set << 6) | way;
                    asm!(
                        "cacop 0xA, $zero, {}",
                        in(reg) index,
                        options(nostack)
                    );
                }
            }
        }
        asm!("dbar 0", options(nostack));
    }
}

/// Invalidate entire instruction cache
#[inline]
pub fn invalidate_icache_all() {
    unsafe {
        for level in 0..3 {
            for set in 0..256 {
                for way in 0..16 {
                    let index = (level << 16) | (set << 6) | way;
                    asm!(
                        "cacop 0x10, $zero, {}",
                        in(reg) index,
                        options(nostack)
                    );
                }
            }
        }
        asm!("ibar 0", options(nostack));
    }
}

/// Prefetch data for read
#[inline]
pub fn prefetch_read(vaddr: u64) {
    unsafe {
        asm!(
            "preld 0, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Prefetch data for write
#[inline]
pub fn prefetch_write(vaddr: u64) {
    unsafe {
        asm!(
            "preld 8, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Prefetch instruction
#[inline]
pub fn prefetch_instruction(vaddr: u64) {
    unsafe {
        asm!(
            "preld 0, {addr}, 0",
            addr = in(reg) vaddr,
            options(nostack)
        );
    }
}
