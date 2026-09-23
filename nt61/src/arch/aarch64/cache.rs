//! AArch64 Cache Management
//!
//! Comprehensive cache operations including:
//! - Data cache clean/invalidate/flush
//! - Instruction cache invalidate
//! - Cache line operations
//! - Point of Coherency (PoC) and Point of Unification (PoU) operations

use core::arch::asm;

/// Cache line size (typically 64 bytes on AArch64)
pub const CACHE_LINE_SIZE: usize = 64;

/// Clean entire data cache to Point of Coherency
#[inline]
pub fn clean_dcache_all() {
    unsafe {
        asm!(
            "dsb sy",
            "mrs x0, clidr_el1",
            "and x1, x0, #0x7000000",
            "lsr x1, x1, #23",
            "cbz x1, 2f",
            "mov x2, #0",
            "1:",
            "add x3, x2, x2, lsr #1",
            "lsr x3, x0, x3",
            "and x3, x3, #7",
            "cmp x3, #2",
            "b.lt 3f",
            "msr csselr_el1, x2",
            "isb",
            "mrs x3, ccsidr_el1",
            "and x4, x3, #7",
            "add x4, x4, #4",
            "ubfx x5, x3, #3, #10",
            "clz w6, w5",
            "mov x7, #0x7fff",
            "and x8, x7, x3, lsr #13",
            "4:",
            "mov x9, x5",
            "5:",
            "lsl x7, x2, #1",
            "orr x10, x7, x9, lsl x4",
            "orr x10, x10, x8, lsl x6",
            "dc csw, x10",
            "subs x9, x9, #1",
            "b.ge 5b",
            "subs x8, x8, #1",
            "b.ge 4b",
            "3:",
            "add x2, x2, #2",
            "cmp x1, x2",
            "b.gt 1b",
            "2:",
            "dsb sy",
            "isb",
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            out("x4") _,
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            options(nostack)
        );
    }
}

/// Invalidate entire data cache
#[inline]
pub fn invalidate_dcache_all() {
    unsafe {
        asm!(
            "dsb sy",
            "mrs x0, clidr_el1",
            "and x1, x0, #0x7000000",
            "lsr x1, x1, #23",
            "cbz x1, 2f",
            "mov x2, #0",
            "1:",
            "add x3, x2, x2, lsr #1",
            "lsr x3, x0, x3",
            "and x3, x3, #7",
            "cmp x3, #2",
            "b.lt 3f",
            "msr csselr_el1, x2",
            "isb",
            "mrs x3, ccsidr_el1",
            "and x4, x3, #7",
            "add x4, x4, #4",
            "ubfx x5, x3, #3, #10",
            "clz w6, w5",
            "mov x7, #0x7fff",
            "and x8, x7, x3, lsr #13",
            "4:",
            "mov x9, x5",
            "5:",
            "lsl x7, x2, #1",
            "orr x10, x7, x9, lsl x4",
            "orr x10, x10, x8, lsl x6",
            "dc isw, x10",
            "subs x9, x9, #1",
            "b.ge 5b",
            "subs x8, x8, #1",
            "b.ge 4b",
            "3:",
            "add x2, x2, #2",
            "cmp x1, x2",
            "b.gt 1b",
            "2:",
            "dsb sy",
            "isb",
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            out("x4") _,
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            options(nostack)
        );
    }
}

/// Flush (clean + invalidate) entire data cache
#[inline]
pub fn flush_dcache_all() {
    clean_dcache_all();
    invalidate_dcache_all();
}

/// Clean data cache line by virtual address to PoC
#[inline]
pub fn clean_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "dc cvac, {}",
            "dsb sy",
            in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Invalidate data cache line by virtual address to PoC
#[inline]
pub fn invalidate_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "dc ivac, {}",
            "dsb sy",
            in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Flush (clean + invalidate) data cache line by virtual address
#[inline]
pub fn flush_dcache_line(vaddr: u64) {
    unsafe {
        asm!(
            "dc civac, {}",
            "dsb sy",
            in(reg) vaddr,
            options(nostack)
        );
    }
}

/// Clean data cache range by virtual address
#[inline]
pub fn clean_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    unsafe {
        while addr < end {
            asm!(
                "dc cvac, {}",
                in(reg) addr,
                options(nostack)
            );
            addr += CACHE_LINE_SIZE as u64;
        }
        asm!("dsb sy", options(nostack));
    }
}

/// Invalidate data cache range by virtual address
#[inline]
pub fn invalidate_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    unsafe {
        while addr < end {
            asm!(
                "dc ivac, {}",
                in(reg) addr,
                options(nostack)
            );
            addr += CACHE_LINE_SIZE as u64;
        }
        asm!("dsb sy", options(nostack));
    }
}

/// Flush data cache range by virtual address
#[inline]
pub fn flush_dcache_range(start: u64, size: usize) {
    let end = start + size as u64;
    let mut addr = start & !(CACHE_LINE_SIZE as u64 - 1);

    unsafe {
        while addr < end {
            asm!(
                "dc civac, {}",
                in(reg) addr,
                options(nostack)
            );
            addr += CACHE_LINE_SIZE as u64;
        }
        asm!("dsb sy", options(nostack));
    }
}

/// Invalidate entire instruction cache to Point of Unification
#[inline]
pub fn invalidate_icache_all() {
    unsafe {
        asm!(
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// Invalidate instruction cache range
#[inline]
pub fn invalidate_icache_range(start: u64, size: usize) {
    // First clean data cache for the range
    clean_dcache_range(start, size);

    // Then invalidate instruction cache
    unsafe {
        asm!(
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// Synchronize instruction and data for a code region
/// Use this after writing executable code
#[inline]
pub fn sync_icache_range(start: u64, size: usize) {
    // Clean data cache to PoU
    clean_dcache_range(start, size);

    // Invalidate instruction cache
    invalidate_icache_all();
}

/// Data Synchronization Barrier
#[inline]
pub fn dsb() {
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

/// Data Synchronization Barrier (Inner Shareable)
#[inline]
pub fn dsb_ish() {
    unsafe {
        asm!("dsb ish", options(nostack));
    }
}

/// Data Memory Barrier
#[inline]
pub fn dmb() {
    unsafe {
        asm!("dmb sy", options(nostack));
    }
}

/// Data Memory Barrier (Inner Shareable)
#[inline]
pub fn dmb_ish() {
    unsafe {
        asm!("dmb ish", options(nostack));
    }
}

/// Instruction Synchronization Barrier
#[inline]
pub fn isb() {
    unsafe {
        asm!("isb", options(nostack));
    }
}

/// Full memory barrier (DSB + ISB)
#[inline]
pub fn memory_barrier() {
    unsafe {
        asm!(
            "dsb sy",
            "isb",
            options(nostack)
        );
    }
}
