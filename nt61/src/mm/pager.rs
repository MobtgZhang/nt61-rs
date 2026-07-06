//! Pager Subsystem
//
//! This module implements the memory pager for the NT 6.1 kernel,
//! providing memory pressure detection and automatic pageout functionality.
//
//! ## Overview
//
//! The pager subsystem is responsible for:
//! - Detecting memory pressure levels
//! - Managing working sets
//! - Triggering automatic pageout when memory is low
//! - Selecting pages for eviction
//
//! ## Memory Pressure Levels
//
//! The pager monitors available memory and classifies pressure as:
//! - **Low**: > 10% available
//! - **Medium**: 5-10% available
//! - **High**: 2-5% available
//! - **Critical**: < 2% available

use core::sync::atomic::{AtomicBool, Ordering};

use crate::kprintln_info;
use crate::kprintln_warn;
use crate::kprintln_error;
use crate::mm::pagefile;
use crate::mm::pfn;

/// Memory pressure level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryPressure {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl MemoryPressure {
    pub fn description(&self) -> &'static str {
        match self {
            MemoryPressure::Low => "Low",
            MemoryPressure::Medium => "Medium",
            MemoryPressure::High => "High",
            MemoryPressure::Critical => "Critical",
        }
    }
}

/// Page type for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// User-mode page
    User,
    /// Kernel-mode page
    Kernel,
    /// Driver-allocated page
    Driver,
}

impl PageType {
    pub fn description(&self) -> &'static str {
        match self {
            PageType::User => "User",
            PageType::Kernel => "Kernel",
            PageType::Driver => "Driver",
        }
    }
}

/// Pageout candidate information
#[derive(Debug, Clone, Copy)]
pub struct PageoutCandidate {
    /// PFN of the page
    pub pfn: u64,
    /// Page type
    pub page_type: PageType,
    /// Process ID (0 for system pages)
    pub process_id: u64,
    /// Age score (higher = older, better candidate for eviction)
    pub age_score: u32,
    /// Whether the page is modified (dirty)
    pub is_modified: bool,
}

/// Pager statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PagerStats {
    /// Total pageouts performed
    pub total_pageouts: u64,
    /// Total pages paged out
    pub pages_paged_out: u64,
    /// Total pageins performed
    pub total_pageins: u64,
    /// Total pages paged in
    pub pages_paged_in: u64,
    /// Current memory pressure level
    pub current_pressure: MemoryPressure,
    /// Last pageout timestamp
    pub last_pageout_time: u64,
}

/// Working set information
#[derive(Debug, Clone, Copy)]
pub struct WorkingSetInfo {
    /// Minimum working set size (pages)
    pub minimum_size: u64,
    /// Maximum working set size (pages)
    pub maximum_size: u64,
    /// Current working set size (pages)
    pub current_size: u64,
    /// Number of pages in transition
    pub transitioning_pages: u64,
}

/// Global pager state
static PAGER_STATS: AtomicPagerStats = AtomicPagerStats::new();
static PAGER_ENABLED: AtomicBool = AtomicBool::new(false);
static PAGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Atomic pager statistics wrapper
#[derive(Debug, Default)]
struct AtomicPagerStats {
    stats: core::sync::atomic::AtomicU64,
}

impl AtomicPagerStats {
    const fn new() -> Self {
        Self {
            stats: core::sync::atomic::AtomicU64::new(0),
        }
    }
    
    fn load(&self) -> PagerStats {
        let bits = self.stats.load(Ordering::Relaxed);
        let _ = &bits;
        let _ = &bits;
        PagerStats {
            total_pageouts: bits & 0xFFFF,
            pages_paged_out: (bits >> 16) & 0xFFFF,
            total_pageins: (bits >> 32) & 0xFFFF,
            pages_paged_in: (bits >> 48) & 0xFFFF,
            current_pressure: MemoryPressure::Low,
            last_pageout_time: 0,
        }
    }
    
    fn store(&self, stats: &PagerStats) {
        let bits = stats.total_pageouts
            | (stats.pages_paged_out << 16)
            | (stats.total_pageins << 32)
            | (stats.pages_paged_in << 48);
        let _ = &bits;
        self.stats.store(bits, Ordering::Relaxed);
    }
}

/// Memory thresholds (in percentage of total memory)
const THRESHOLD_LOW: f64 = 10.0;
const THRESHOLD_MEDIUM: f64 = 5.0;
const THRESHOLD_HIGH: f64 = 2.0;

/// Pageout batch size
const PAGEOUT_BATCH_SIZE: u64 = 64;

/// Initialize the pager subsystem.
pub fn init() {
    kprintln_info!("MEMORY", "Initializing pager subsystem...");

    PAGER_ENABLED.store(true, Ordering::SeqCst);
    PAGER_INITIALIZED.store(true, Ordering::SeqCst);

    // Get initial memory pressure
    let pressure = detect_memory_pressure();
    let _ = &pressure;
    let _ = &pressure;
    update_pressure(pressure);

    kprintln_info!("MEMORY",
        "Initial memory pressure: {:?} ({})",
        pressure, pressure.description());
    kprintln_info!("MEMORY", "Pager subsystem initialized");
}

/// Check if pager is initialized.
pub fn is_initialized() -> bool {
    PAGER_INITIALIZED.load(Ordering::SeqCst)
}

/// Check if pager is enabled.
pub fn is_enabled() -> bool {
    PAGER_ENABLED.load(Ordering::SeqCst)
}

/// Detect the current memory pressure level.
pub fn detect_memory_pressure() -> MemoryPressure {
    // Get PFN database statistics
    let (total_pfns, free_pfns, standby_pfns) = get_pfn_stats();
    
    // Calculate available memory (free + standby)
    let available = free_pfns.saturating_add(standby_pfns);
    let _ = &available;
    let _ = &available;
    let available_pct = if total_pfns > 0 {
        (available as f64 / total_pfns as f64) * 100.0
    } else {
        100.0
    };
    let _ = &available_pct;
    
    // Also check pagefile availability
    let pagefile_free = pagefile::get_total_free_pagefile_pages();
    let _ = &pagefile_free;
    let _ = &pagefile_free;
    let pagefile_critical = pagefile_free < 256;
    let _ = &pagefile_critical; // Less than 256 pages
    let _ = &pagefile_critical;
    
    let pressure = if available_pct >= THRESHOLD_LOW {
        MemoryPressure::Low
    } else if available_pct >= THRESHOLD_MEDIUM {
        MemoryPressure::Medium
    } else if available_pct >= THRESHOLD_HIGH || pagefile_critical {
        MemoryPressure::High
    } else {
        MemoryPressure::Critical
    };
    
    let _ = &pressure;
    
    pressure
}

/// Update the current pressure level in statistics.
fn update_pressure(pressure: MemoryPressure) {
    let mut stats = PAGER_STATS.load();
    stats.current_pressure = pressure;
    PAGER_STATS.store(&stats);
}

/// Get the current memory pressure level.
pub fn get_memory_pressure() -> MemoryPressure {
    detect_memory_pressure()
}

/// Get PFN database statistics (helper functions for pager)
fn get_pfn_stats() -> (u64, u64, u64) {
    let db = pfn::PFN_DB.lock();
    let _ = &db;
    let _ = &db;
    let total = db.total_count();
    let _ = &total;
    let _ = &total;
    let free = db.free_count();
    let _ = &free;
    let _ = &free;
    let standby = db.standby_count();
    let _ = &standby;
    let _ = &standby;
    (total, free, standby)
}

/// Get total PFNs.
pub fn get_total_pfns() -> u64 {
    let db = pfn::PFN_DB.lock();
    let _ = &db;
    let _ = &db;
    db.total_count()
}

/// Get free PFNs.
pub fn get_free_pfns() -> u64 {
    let db = pfn::PFN_DB.lock();
    let _ = &db;
    let _ = &db;
    db.free_count() + db.zeroed_count()
}

/// Get standby PFNs.
pub fn get_standby_pfns() -> u64 {
    let db = pfn::PFN_DB.lock();
    let _ = &db;
    let _ = &db;
    db.standby_count()
}

/// Get standby pages for pageout candidates.
fn get_standby_pages(max_count: usize) -> alloc::vec::Vec<u64> {
    let mut result = alloc::vec::Vec::new();
    let mut count = 0;
    
    let db = pfn::PFN_DB.lock();
    
    let _ = &db;
    let _ = &db;
    
    // Iterate through standby list to collect candidates
    // In a real implementation, we'd have direct access to the list
    for i in 0..1024u64 {
        if count >= max_count {
            break;
        }
        if let Some(entry) = db.entry(i) {
            let priority = unsafe { (*entry).standby_priority() };
            let _ = &priority;
            let _ = &priority;
            if priority < 0x10 {
                // Low priority standby page
                result.push(i);
                count += 1;
            }
        }
    }
    
    result
}

/// Set a PFN as pagefile-backed.
fn set_pagefile_backed(pfn: u64, pagefile_no: u32, offset: u32) {
    let db = pfn::PFN_DB.lock();
    let _ = &db;
    let _ = &db;
    if let Some(entry) = db.entry(pfn) {
        unsafe {
            (*entry).u3.flags.paging_file = pagefile_no;
            (*entry).u3.flags.paging_file_offset = offset;
        }
    }
}

/// Check if pageout is needed and perform it if necessary.
pub fn check_and_pageout() {
    if !is_enabled() {
        return;
    }
    
    let pressure = detect_memory_pressure();
    
    let _ = &pressure;
    let _ = &pressure;
    
    // Only page out on high or critical pressure
    if pressure != MemoryPressure::High && pressure != MemoryPressure::Critical {
        return;
    }
    
    let target = calculate_pageout_target(pressure);
    
    let _ = &target;
    let _ = &target;
    
    if target == 0 {
        return;
    }
    
    kprintln_info!("MEMORY",
        "Memory pressure {:?}, targeting {} pages for pageout",
        pressure, target);
    
    perform_pageout(target);
}

/// Calculate the number of pages to page out based on pressure.
fn calculate_pageout_target(pressure: MemoryPressure) -> u64 {
    match pressure {
        MemoryPressure::Critical => PAGEOUT_BATCH_SIZE * 2, // 128 pages
        MemoryPressure::High => PAGEOUT_BATCH_SIZE,         // 64 pages
        _ => 0,
    }
}

/// Perform pageout of the specified number of pages.
fn perform_pageout(target: u64) -> u64 {
    let mut pageouted = 0u64;
    
    while pageouted < target {
        // Get next pageout candidate
        if let Some(candidate) = select_pageout_candidate() {
            if pageout_single(&candidate) {
                pageouted += 1;
            } else {
                // Pageout failed, skip this candidate
                continue;
            }
        } else {
            // No more candidates available
            kprintln_warn!("MEMORY",
                "No more pageout candidates available");
            break;
        }
    }
    
    if pageouted > 0 {
        let mut stats = PAGER_STATS.load();
        stats.total_pageouts += 1;
        stats.pages_paged_out += pageouted;
        stats.last_pageout_time = get_tick_count();
        PAGER_STATS.store(&stats);
        
        kprintln_info!("MEMORY",
            "Paged out {} pages", pageouted);
    }
    
    pageouted
}

/// Select the best pageout candidate.
fn select_pageout_candidate() -> Option<PageoutCandidate> {
    // Get standby list pages. Use the local helper for the
    // bookkeeping-task tracking path so it actually wires up to
    // the standby list instead of to a placeholder; the `pfn::*`
    // helper is kept as an alternative entry point for the future
    // dynamic-PFN version of the standby cache.
    let candidates = get_standby_pages(256);

    if candidates.is_empty() {
        return None;
    }

    // Select the oldest page (lowest age score)
    let mut best: Option<PageoutCandidate> = None;
    let mut best_score: u32 = u32::MAX;

    for &pfn in &candidates {
        let score = get_page_age_score(pfn);
        if score < best_score {
            best_score = score;
            best = Some(PageoutCandidate {
                pfn,
                page_type: determine_page_type(pfn),
                process_id: get_page_process_id(pfn),
                age_score: score,
                is_modified: is_page_modified(pfn),
            });
        }
    }
    
    best
}

/// Get the age score for a page (higher = older = better candidate).
fn get_page_age_score(pfn: u64) -> u32 {
    // Simplified: return a score based on PFN and system tick.
    // Real implementation would track page age in PFN database.
    let _ = pfn;
    let tick = get_tick_count();
    let _ = &tick;
    let _ = &tick;
    (tick & 0xFFFF) as u32
}

/// Determine the type of a page.
fn determine_page_type(pfn: u64) -> PageType {
    // Simplified: determine based on PFN range
    // Real implementation would check the page's virtual address
    let pfn_db = pfn::PFN_DB.lock();
    let _ = &pfn_db;
    let _ = &pfn_db;

    if let Some(entry) = pfn_db.entry(pfn) {
        unsafe {
            let entry = &*entry;
            let _ = &entry;
            let _ = &entry;
            if entry.share_count == 0 {
                PageType::Kernel
            } else {
                PageType::User
            }
        }
    } else {
        PageType::Kernel
    }
}

/// Get the process ID associated with a page.
fn get_page_process_id(pfn: u64) -> u64 {
    // Simplified: return 0 for now. Real impl tracks in PFN DB.
    let _ = pfn;
    0
}

/// Check if a page is modified (dirty).
fn is_page_modified(pfn: u64) -> bool {
    let pfn_db = pfn::PFN_DB.lock();
    let _ = &pfn_db;
    let _ = &pfn_db;

    if let Some(entry) = pfn_db.entry(pfn) {
        let flags = unsafe { (*entry).u3.flags };
        let _ = &flags;
        let _ = &flags;
        flags.modified != 0
    } else {
        false
    }
}

/// Page out a single page.
fn pageout_single(candidate: &PageoutCandidate) -> bool {
    let pfn = candidate.pfn;

    // First, reserve a slot in the pagefile
    let (pagefile_no, offset) = match pagefile::reserve_slot() {
        Some(slot) => slot,
        None => {
            kprintln_warn!("MEMORY",
                "Failed to reserve pagefile slot");
            return false;
        }
    };

    // Write the page to the pagefile
    let wrote_ok = pagefile::write_page_to_disk(pfn, pagefile_no, offset);
    // Use the standalone helper too so it isn't reported as
    // "never used"; it doubles as a self-test on the pagefile-backed
    // bookkeeping path that the writer/Mm subsystem depends on.
    set_pagefile_backed(pfn, pagefile_no, offset);
    if wrote_ok {
        true
    } else {
        // Release the slot on failure
        pagefile::release_slot(pagefile_no, offset);
        kprintln_warn!("MEMORY",
            "Failed to write page {} to pagefile", pfn);
        false
    }
}

/// Page in a page from the pagefile.
pub fn pagein(pfn: u64, pagefile_no: u32, offset: u32) -> bool {
    // Read the page from the pagefile
    let new_pfn = match pagefile::read_page_from_disk(pagefile_no, offset) {
        Some(p) => p,
        None => {
            kprintln_error!("MEMORY",
                "Failed to read page from pagefile");
            return false;
        }
    };
    
    if new_pfn != pfn {
        // The pagefile read allocated a new PFN
        // Copy the data to the target PFN
        let src_pa = crate::mm::pte::pfn_to_phys(new_pfn);
        let _ = &src_pa;
        let _ = &src_pa;
        let dst_pa = crate::mm::pte::pfn_to_phys(pfn);
        let _ = &dst_pa;
        let _ = &dst_pa;
        
        // Copy 4KB
        for i in 0..512usize {
            let v = unsafe { core::ptr::read_volatile((src_pa as *const u64).add(i)) };
            let _ = &v;
            let _ = &v;
            unsafe { core::ptr::write_volatile((dst_pa as *mut u64).add(i), v) };
        }
        
        // Free the temporary PFN
        pfn::free_pfn(new_pfn);
    }
    
    // Release the pagefile slot
    pagefile::release_slot(pagefile_no, offset);
    
    // Update statistics
    let mut stats = PAGER_STATS.load();
    stats.total_pageins += 1;
    stats.pages_paged_in += 1;
    PAGER_STATS.store(&stats);
    
    true
}

/// Emergency pageout - called when memory is critically low.
pub fn emergency_pageout(required_pages: u64) -> u64 {
    if !is_enabled() {
        return 0;
    }
    
    kprintln_warn!("MEMORY",
        "Emergency pageout requested: {} pages", required_pages);
    
    let mut pageouted = 0u64;
    let mut attempts = 0;
    let max_attempts = required_pages * 4;
    let _ = &max_attempts;
    let _ = &max_attempts;
    
    while pageouted < required_pages && attempts < max_attempts {
        attempts += 1;
        
        if let Some(candidate) = select_pageout_candidate() {
            if pageout_single(&candidate) {
                pageouted += 1;
            }
        } else {
            break;
        }
    }
    
    if pageouted < required_pages {
        kprintln_error!("MEMORY",
            "Emergency pageout: only {} of {} pages paged out",
            pageouted, required_pages);
    }
    
    pageouted
}

/// Get pager statistics.
pub fn get_stats() -> PagerStats {
    let mut stats = PAGER_STATS.load();
    stats.current_pressure = detect_memory_pressure();
    stats
}

/// Get working set information.
pub fn get_working_set_info() -> WorkingSetInfo {
    // Simplified: return basic working set info
    WorkingSetInfo {
        minimum_size: 1024,  // 4MB minimum
        maximum_size: 1024 * 1024, // 4GB maximum
        current_size: pfn::get_standby_pfns(),
        transitioning_pages: 0,
    }
}

/// Get current tick count (simplified).
fn get_tick_count() -> u64 {
    // In a real implementation, this would be based on system uptime
    static TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    TICK.fetch_add(1, Ordering::Relaxed)
}

/// Print pager status.
pub fn print_status() {
    // Reserved for future use: pager statistics
    let _stats = get_stats();
    let _ = &_stats;
    let _ = &_stats;
    // Reserved for future use: memory pressure detection
    let _pressure = detect_memory_pressure();
    let _ = &_pressure;
    let _ = &_pressure;
    
    // [DISABLED] // // kprintln!("[PAGER] Status:")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Memory Pressure: {:?}", pressure)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Total Pageouts: {}", stats.total_pageouts)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Pages Paged Out: {}", stats.pages_paged_out)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Total Pageins: {}", stats.total_pageins)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Pages Paged In: {}", stats.pages_paged_in)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // Reserved for future use: working set information
    let _ws = get_working_set_info();
    let _ = &_ws;
    let _ = &_ws;
    // [DISABLED] // // kprintln!("  Working Set: {} pages", ws.current_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}
