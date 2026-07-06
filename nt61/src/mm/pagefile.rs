//! Page file
//
//! Maps a `page_file_no` (0..15) and `offset` (in pages) onto a
//! physical PFN. In NT 6.1 each paging file is a normal file on the
//! boot partition; we reserve 16-bit PFNs from the page file
//! bitmap. The full system supports up to 16 paging files.
//
//! This module supports both RAM-backed and disk-backed paging files:
//! - **RAM-backed**: Uses PFN reserved regions (bootstrap mode)
//! - **Disk-backed**: Uses `pagefile.sys` on FAT32 or NTFS volumes
//
//! ## Disk-Backed Pagefile Architecture
//
//! When disk I/O is available, the pagefile transitions to disk-backed mode:
//! 1. FAT32: `pagefile.sys` is created as a contiguous file
//! 2. NTFS: `pagefile.sys` is created with dynamic cluster allocation
//! 3. Both: Use block layer for sector-level I/O

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU64, Ordering};
use core::fmt;

use crate::mm::pfn;
use crate::mm::pte::pfn_to_phys;
use crate::kprintln_info;
use crate::fs::FileSystemType;

const MAX_PAGING_FILES: usize = 16;
const PAGES_PER_FILE: u64 = 4096;
const BITS_PER_WORD: usize = 64;
const BITMAP_WORDS: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct PageFileHandle {
    pub handle: u64,
    pub device_id: usize,
    pub fs_type: FileSystemType,
    pub start_sector: u64,
    pub size_pages: u64,
    pub valid: bool,
}

impl Default for PageFileHandle {
    fn default() -> Self {
        Self {
            handle: 0,
            device_id: 0,
            fs_type: FileSystemType::Unknown,
            start_sector: 0,
            size_pages: 0,
            valid: false,
        }
    }
}

impl fmt::Display for PageFileHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageFileHandle(handle={}, device={}, fs={:?}, sectors={}, pages={})",
               self.handle, self.device_id, self.fs_type, self.start_sector, self.size_pages)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DiskPageFileMeta {
    pub fs_type: FileSystemType,
    pub device_id: usize,
    pub start_sector: u64,
    pub size_bytes: u64,
}

/// PagingFile - represents a paging file in the system
/// 
/// A paging file is used to store pages of memory that are not currently in use.
/// Windows uses one or more paging files to supplement physical RAM.
pub struct PagingFile {
    pub enabled: bool,
    pub base_pfn: u64,
    pub page_count: u64,
    pub used_count: u64,
    pub bitmap_words: usize,
    pub max_size: AtomicU64,
    pub current_size: AtomicU64,
    pub filename: [u8; 260],
    pub disk_handle: PageFileHandle,
    pub is_disk_backed: bool,
    pub disk_meta: DiskPageFileMeta,
}

impl Default for PagingFile {
    fn default() -> Self {
        Self {
            enabled: false,
            base_pfn: 0,
            page_count: 0,
            used_count: 0,
            bitmap_words: 0,
            max_size: AtomicU64::new(0),
            current_size: AtomicU64::new(0),
            filename: [0u8; 260],
            disk_handle: PageFileHandle::default(),
            is_disk_backed: false,
            disk_meta: DiskPageFileMeta {
                fs_type: FileSystemType::Unknown,
                device_id: 0,
                start_sector: 0,
                size_bytes: 0,
            },
        }
    }
}

static mut PAGE_FILE_ALLOCATED: [[u64; BITMAP_WORDS]; MAX_PAGING_FILES] =
    [[0u64; BITMAP_WORDS]; MAX_PAGING_FILES];

/// Default `PagingFile` instance used to initialize the static array.
/// Uses explicit field initialization (not `zeroed()`) because
/// `PagingFile.max_size` and `PagingFile.current_size` are `AtomicU64`,
/// which produces an invalid bit pattern when zeroed.
const DEFAULT_PAGING_FILE: PagingFile = PagingFile {
    enabled: false,
    base_pfn: 0,
    page_count: 0,
    used_count: 0,
    bitmap_words: 0,
    max_size: core::sync::atomic::AtomicU64::new(0),
    current_size: core::sync::atomic::AtomicU64::new(0),
    filename: [0u8; 260],
    disk_handle: PageFileHandle {
        handle: 0,
        device_id: 0,
        fs_type: FileSystemType::Unknown,
        start_sector: 0,
        size_pages: 0,
        valid: false,
    },
    is_disk_backed: false,
    disk_meta: DiskPageFileMeta {
        fs_type: FileSystemType::Unknown,
        device_id: 0,
        start_sector: 0,
        size_bytes: 0,
    },
};

static mut PAGE_FILES: [PagingFile; MAX_PAGING_FILES] = [DEFAULT_PAGING_FILE; MAX_PAGING_FILES];

static mut PAGEFILE_INITIALIZED: bool = false;

fn init_paging_file(paging_file: &mut PagingFile, page_count: u64) {
    *paging_file = PagingFile {
        enabled: false,
        base_pfn: 0,
        page_count,
        used_count: 0,
        bitmap_words: 0,
        max_size: AtomicU64::new(page_count),
        current_size: AtomicU64::new(0),
        filename: [0u8; 260],
        disk_handle: PageFileHandle::default(),
        is_disk_backed: false,
        disk_meta: DiskPageFileMeta {
            fs_type: FileSystemType::Unknown,
            device_id: 0,
            start_sector: 0,
            size_bytes: 0,
        },
    };
}

fn find_first_zero(word: u64) -> Option<usize> {
    let zeros = !word;
    if zeros != 0 {
        Some(zeros.trailing_zeros() as usize)
    } else {
        None
    }
}

fn init_bitmap(page_file_idx: usize, page_count: u64) {
    let bitmap_words_needed = ((page_count as usize) + BITS_PER_WORD - 1) / BITS_PER_WORD;
    unsafe {
        for i in 0..BITMAP_WORDS {
            PAGE_FILE_ALLOCATED[page_file_idx][i] = 0;
        }
        PAGE_FILES[page_file_idx].bitmap_words = bitmap_words_needed;
    }
}

fn bitmap_alloc(page_file_idx: usize) -> Option<u32> {
    unsafe {
        let pf = &mut PAGE_FILES[page_file_idx];
        if !pf.enabled {
            return None;
        }
        let bitmap_words = pf.bitmap_words;
        if bitmap_words == 0 {
            return None;
        }
        for word_idx in 0..bitmap_words {
            let word = &mut PAGE_FILE_ALLOCATED[page_file_idx][word_idx];
            if let Some(bit_pos) = find_first_zero(*word) {
                *word |= 1u64 << bit_pos;
                let offset = ((word_idx * BITS_PER_WORD) + bit_pos) as u32;
                if (offset as u64) < pf.page_count {
                    pf.used_count += 1;
                    return Some(offset);
                } else {
                    *word &= !(1u64 << bit_pos);
                    return None;
                }
            }
        }
        None
    }
}

fn bitmap_free(page_file_idx: usize, offset: u32) {
    unsafe {
        let pf = &mut PAGE_FILES[page_file_idx];
        if !pf.enabled {
            return;
        }
        if (offset as u64) >= pf.page_count {
            return;
        }
        let word_idx = (offset as usize) / BITS_PER_WORD;
        let bit_pos = (offset as usize) % BITS_PER_WORD;
        if word_idx < pf.bitmap_words {
            PAGE_FILE_ALLOCATED[page_file_idx][word_idx] &= !(1u64 << bit_pos);
            pf.used_count = pf.used_count.saturating_sub(1);
        }
    }
}

pub fn init() {
    unsafe {
        for i in 0..MAX_PAGING_FILES {
            init_paging_file(&mut PAGE_FILES[i], PAGES_PER_FILE);
        }
        init_bitmap(0, PAGES_PER_FILE);
        let base_pfn = match crate::mm::frame::allocate_pages(PAGES_PER_FILE) {
            Some(p) => p / 4096,
            None => {
                // [DISABLED] // // kprintln!("    [mm] pagefile: dynamic alloc failed, pagefile disabled")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                0
            }
        };
        init_paging_file(&mut PAGE_FILES[0], PAGES_PER_FILE);
        PAGE_FILES[0].enabled = base_pfn != 0;
        PAGE_FILES[0].base_pfn = base_pfn;
        // [DISABLED] // // kprintln!("    [mm] pagefile: {} pages available ({} MiB)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]             PAGES_PER_FILE, PAGES_PER_FILE * 4096 / (1024 * 1024));
    }
}

pub fn read_page(page_file_no: u32, offset: u32) -> Option<u64> {
    if page_file_no as usize >= MAX_PAGING_FILES { return None; }
    unsafe {
        let pf = &PAGE_FILES[page_file_no as usize];
        if !pf.enabled { return None; }
        if (offset as u64) >= pf.page_count { return None; }
        let dst_pfn = pfn::allocate_pfn()?;
        let dst_pa = pfn_to_phys(dst_pfn);
        let src_pa = pfn_to_phys(pf.base_pfn + offset as u64);
        let src = src_pa as *const u64;
        let dst = dst_pa as *mut u64;
        for i in 0..512usize {
            let v = core::ptr::read_volatile(src.add(i));
            core::ptr::write_volatile(dst.add(i), v);
        }
        Some(dst_pfn)
    }
}

pub fn write_modified_page(pfn_no: u64) {
    let db = pfn::PFN_DB.lock();
    let entry = match db.entry(pfn_no) { Some(e) => e, None => return };
    unsafe {
        let pf_no = ((*entry).u3.flags.paging_file as u32) as usize;
        if pf_no >= MAX_PAGING_FILES { return; }
        let pf = &mut PAGE_FILES[pf_no];
        if !pf.enabled { return; }
        let offset = (*entry).u3.flags.paging_file_offset;
        if (offset as u64) >= pf.page_count { return; }
        let dst_pa = pfn_to_phys(pf.base_pfn + offset as u64);
        let src_pa = pfn_to_phys(pfn_no);
        let src = src_pa as *const u64;
        let dst = dst_pa as *mut u64;
        for i in 0..512usize {
            let v = core::ptr::read_volatile(src.add(i));
            core::ptr::write_volatile(dst.add(i), v);
        }
    }
}

pub fn reserve_slot() -> Option<(u32, u32)> {
    if let Some(offset) = bitmap_alloc(0) {
        return Some((0, offset));
    }
    for i in 1..MAX_PAGING_FILES {
        if let Some(offset) = bitmap_alloc(i) {
            return Some((i as u32, offset));
        }
    }
    None
}

pub fn reserve_slot_in_file(page_file_no: u32) -> Option<(u32, u32)> {
    if page_file_no as usize >= MAX_PAGING_FILES {
        return None;
    }
    bitmap_alloc(page_file_no as usize).map(|offset| (page_file_no, offset))
}

pub fn release_slot(page_file_no: u32, offset: u32) {
    if page_file_no as usize >= MAX_PAGING_FILES {
        return;
    }
    bitmap_free(page_file_no as usize, offset);
}

pub fn set_paging_file(page_file_no: u32, base_pfn: u64, page_count: u64) {
    if page_file_no as usize >= MAX_PAGING_FILES {
        return;
    }
    unsafe {
        init_paging_file(&mut PAGE_FILES[page_file_no as usize], page_count);
        PAGE_FILES[page_file_no as usize].base_pfn = base_pfn;
        PAGE_FILES[page_file_no as usize].enabled = base_pfn != 0;
        init_bitmap(page_file_no as usize, page_count);
    }
}

pub fn grow_pagefile(page_file_no: u32, new_size: u64) -> bool {
    if page_file_no as usize >= MAX_PAGING_FILES { return false; }
    unsafe {
        let pf = &mut PAGE_FILES[page_file_no as usize];
        if !pf.enabled { return false; }
        if new_size <= pf.page_count { return false; }
        let _old_size = pf.page_count;
        pf.page_count = new_size;
        pf.max_size.store(new_size, Ordering::SeqCst);
        let new_bitmap_words = ((new_size as usize) + BITS_PER_WORD - 1) / BITS_PER_WORD;
        for i in pf.bitmap_words..new_bitmap_words.min(BITMAP_WORDS) {
            PAGE_FILE_ALLOCATED[page_file_no as usize][i] = 0;
        }
        pf.bitmap_words = new_bitmap_words;
        // _old_size is intentionally unused - reserved for future logging
        // [DISABLED] // // kprintln!("[pagefile] grow_pagefile #{}: {} -> {} pages", page_file_no, _old_size, new_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        true
    }
}

pub fn get_total_pagefile_pages() -> u64 {
    let mut total = 0u64;
    unsafe {
        for i in 0..MAX_PAGING_FILES {
            if PAGE_FILES[i].enabled {
                total += PAGE_FILES[i].page_count;
            }
        }
    }
    total
}

pub fn get_total_free_pagefile_pages() -> u64 {
    let mut free = 0u64;
    unsafe {
        for i in 0..MAX_PAGING_FILES {
            if PAGE_FILES[i].enabled {
                free += PAGE_FILES[i].page_count.saturating_sub(PAGE_FILES[i].used_count);
            }
        }
    }
    free
}

pub fn is_pagefile_enabled(page_file_no: u32) -> bool {
    if page_file_no as usize >= MAX_PAGING_FILES { return false; }
    unsafe { PAGE_FILES[page_file_no as usize].enabled }
}

pub const DEFAULT_PAGEFILE_SIZE_MB: u64 = 512;
pub const MIN_PAGEFILE_SIZE_MB: u64 = 2;
pub const MAX_PAGEFILE_SIZE_MB: u64 = 4096;
pub const PAGEFILE_SIZE_GRANULARITY_MB: u64 = 4;

pub fn is_initialized() -> bool {
    unsafe { PAGEFILE_INITIALIZED }
}

pub fn set_disk_pagefile(
    page_file_no: u32,
    fs_type: FileSystemType,
    device_id: usize,
    start_sector: u64,
    size_pages: u64,
) -> bool {
    if page_file_no as usize >= MAX_PAGING_FILES { return false; }
    let pagefile_size_mb = size_pages * 4096 / (1024 * 1024);
    unsafe {
        init_paging_file(&mut PAGE_FILES[page_file_no as usize], size_pages);
        let pf = &mut PAGE_FILES[page_file_no as usize];
        pf.is_disk_backed = true;
        pf.disk_handle = PageFileHandle {
            handle: page_file_no as u64,
            device_id,
            fs_type,
            start_sector,
            size_pages,
            valid: true,
        };
        pf.disk_meta = DiskPageFileMeta {
            fs_type,
            device_id,
            start_sector,
            size_bytes: size_pages * 4096,
        };
        pf.enabled = true;
        pf.page_count = size_pages;
        pf.max_size = AtomicU64::new(size_pages);
        pf.current_size = AtomicU64::new(size_pages);
        init_bitmap(page_file_no as usize, size_pages);
        kprintln_info!("MEMORY",
            "Disk-backed pagefile #{} enabled: {} pages ({} MB)",
            page_file_no, size_pages, pagefile_size_mb);
        true
    }
}

pub fn set_initialized() {
    unsafe {
        PAGEFILE_INITIALIZED = true;
    }
    kprintln_info!("MEMORY", "Pagefile subsystem initialization complete");
}

// =============================================================================
// Page I/O Functions
// =============================================================================

/// Write a page to the pagefile.
///
/// This function writes a physical page frame to the specified
/// pagefile at the given offset. Used by the modified page writer.
pub fn write_page_to_disk(pfn: u64, pagefile_no: u32, offset: u32) -> bool {
    if !is_initialized() {
        return false;
    }

    if pagefile_no >= MAX_PAGING_FILES as u32 {
        return false;
    }

    let pf = unsafe { &PAGE_FILES[pagefile_no as usize] };
    if !pf.enabled {
        return false;
    }

    let phys_addr = pfn * 4096;

    // Check if this is a disk-backed pagefile
    if pf.is_disk_backed {
        let sector_offset = (offset * 8) as u64; // Convert to u64 for addition
        let start_sector = pf.disk_meta.start_sector + sector_offset;

        kprintln_info!("MEMORY",
            "write_page_to_disk: PFN {} -> disk pagefile {} offset {} (sector {})",
            pfn, pagefile_no, offset, start_sector);

        // Write 8 sectors (4096 bytes) to disk
        let mut buffer = [0u8; 512];
        let mut success = true;

        for i in 0..8 {
            // Copy 512 bytes from physical memory
            // SAFETY: We have exclusive access to the source page
            let src = (phys_addr + (i as u64) * 512) as *const u8;
            unsafe {
                for j in 0..512 {
                    buffer[j] = core::ptr::read_volatile(src.add(j));
                }
            }

            // Write to disk via block device
            if !crate::drivers::storage::block::write_block(
                pf.disk_meta.device_id,
                start_sector + (i as u64),
                &buffer
            ) {
                success = false;
                // [DISABLED] // // kprintln!("[pagefile] write_page_to_disk: failed at sector {}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]                           start_sector + (i as u64));
                break;
            }
        }

        if success {
            kprintln_info!("MEMORY",
                "write_page_to_disk: PFN {} written to disk (pagefile {}, offset {})",
                pfn, pagefile_no, offset);
        }
        return success;
    } else {
        // RAM-backed pagefile: memory-to-memory copy
        let dst_pa = pfn_to_phys(pf.base_pfn + offset as u64);
        let src_pa = pfn_to_phys(pfn);
        let src = src_pa as *const u64;
        let dst = dst_pa as *mut u64;

        // SAFETY: We have exclusive access to both pages
        unsafe {
            for i in 0..512usize {
                let v = core::ptr::read_volatile(src.add(i));
                core::ptr::write_volatile(dst.add(i), v);
            }
        }

        kprintln_info!("MEMORY",
            "write_page_to_disk: PFN {} -> RAM pagefile {} offset {}",
            pfn, pagefile_no, offset);
        return true;
    }
}

/// Read a page from the pagefile.
///
/// This function reads a page from the specified pagefile at
/// the given offset and returns the PFN of the page containing
/// the data.
pub fn read_page_from_disk(pagefile_no: u32, offset: u32) -> Option<u64> {
    if !is_initialized() {
        return None;
    }

    if pagefile_no >= MAX_PAGING_FILES as u32 {
        return None;
    }

    let pf = unsafe { &PAGE_FILES[pagefile_no as usize] };
    if !pf.enabled {
        return None;
    }

    // Allocate a new PFN for the page
    let new_pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => {
            kprintln_info!("MEMORY",
                "read_page_from_disk: Failed to allocate PFN");
            return None;
        }
    };

    let phys_addr = new_pfn * 4096;

    // Check if this is a disk-backed pagefile
    if pf.is_disk_backed {
        let sector_offset = (offset * 8) as u64; // Convert to u64 for addition
        let start_sector = pf.disk_meta.start_sector + sector_offset;

        kprintln_info!("MEMORY",
            "read_page_from_disk: pagefile {} offset {} -> PFN {} (sector {})",
            pagefile_no, offset, new_pfn, start_sector);

        // Read 8 sectors (4096 bytes) from disk
        let mut buffer = [0u8; 512];
        let mut success = true;

        for i in 0..8 {
            // Read from disk via block device
            if !crate::drivers::storage::block::read_block(
                pf.disk_meta.device_id,
                start_sector + (i as u64),
                &mut buffer
            ) {
                success = false;
                // [DISABLED] // // kprintln!("[pagefile] read_page_from_disk: failed at sector {}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]                           start_sector + (i as u64));
                break;
            }

            // Copy 512 bytes to physical memory
            // SAFETY: We have exclusive access to the destination page
            let dst = (phys_addr + (i as u64) * 512) as *mut u8;
            unsafe {
                for j in 0..512 {
                    core::ptr::write_volatile(dst.add(j), buffer[j]);
                }
            }
        }

        if !success {
            pfn::free_pfn(new_pfn);
            return None;
        }

        kprintln_info!("MEMORY",
            "read_page_from_disk: page {} read from disk (pagefile {}, offset {})",
            new_pfn, pagefile_no, offset);
    } else {
        // RAM-backed pagefile: memory-to-memory copy
        let src_pa = pfn_to_phys(pf.base_pfn + offset as u64);
        let dst_pa = pfn_to_phys(new_pfn);
        let src = src_pa as *const u64;
        let dst = dst_pa as *mut u64;

        // SAFETY: We have exclusive access to both pages
        unsafe {
            for i in 0..512usize {
                let v = core::ptr::read_volatile(src.add(i));
                core::ptr::write_volatile(dst.add(i), v);
            }
        }

        kprintln_info!("MEMORY",
            "read_page_from_disk: pagefile {} offset {} -> PFN {}",
            pagefile_no, offset, new_pfn);
    }

    Some(new_pfn)
}

/// Get pagefile information.
#[derive(Debug, Clone)]
pub struct PagefileInfo {
    pub pagefile_no: u32,
    pub total_pages: u64,
    pub free_pages: u64,
    pub enabled: bool,
}

impl PagefileInfo {
    pub fn new() -> Self {
        Self {
            pagefile_no: 0,
            total_pages: 0,
            free_pages: 0,
            enabled: false,
        }
    }
}

/// Get information about a pagefile.
pub fn get_pagefile_info(pagefile_no: u32) -> Option<PagefileInfo> {
    if pagefile_no >= MAX_PAGING_FILES as u32 {
        return None;
    }

    // SAFETY: PAGE_FILES is protected by PAGEFILE_INIT_LOCK
    let pf = unsafe { &PAGE_FILES[pagefile_no as usize] };

    if !pf.enabled {
        return None;
    }

    let total = get_total_pagefile_pages();
    let free = get_total_free_pagefile_pages();

    Some(PagefileInfo {
        pagefile_no,
        total_pages: total,
        free_pages: free,
        enabled: true,
    })
}
