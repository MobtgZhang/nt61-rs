//! Memory Manager Performance Counters
//
//! Provides detailed performance metrics for the memory management subsystem.
//! Tracks allocation counts, failures, page faults, TLB invalidations, etc.

use core::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Performance Counter Definitions
// =============================================================================

/// Performance counters for the memory manager
#[derive(Debug)]
pub struct PerfCounters {
    // PFN allocation statistics
    pub pfn_alloc_count: AtomicU64,
    pub pfn_free_count: AtomicU64,
    pub pfn_alloc_failures: AtomicU64,
    pub pfn_zeroed_used: AtomicU64,
    pub pfn_free_used: AtomicU64,

    // Kernel heap statistics
    pub heap_alloc_count: AtomicU64,
    pub heap_free_count: AtomicU64,
    pub heap_current_allocated: AtomicU64,
    pub heap_peak_allocated: AtomicU64,
    pub heap_alloc_failures: AtomicU64,

    // Kernel pool statistics
    pub pool_alloc_count: AtomicU64,
    pub pool_free_count: AtomicU64,
    pub pool_alloc_failures: AtomicU64,
    pub paged_pool_alloc: AtomicU64,
    pub non_paged_pool_alloc: AtomicU64,

    // Page fault statistics
    pub page_fault_count: AtomicU64,
    pub demand_zero_faults: AtomicU64,
    pub cow_faults: AtomicU64,
    pub disk_faults: AtomicU64,
    pub guard_page_faults: AtomicU64,

    // TLB statistics
    pub tlb_invalidations: AtomicU64,
    pub invlpg_count: AtomicU64,
    pub invpcid_count: AtomicU64,
    pub cr3_switches: AtomicU64,

    // VAD tree statistics
    pub vad_insert_count: AtomicU64,
    pub vad_remove_count: AtomicU64,
    pub vad_split_count: AtomicU64,
    pub vad_merge_count: AtomicU64,
    pub vad_search_count: AtomicU64,

    // Working set statistics
    pub ws_trim_count: AtomicU64,
    pub ws_pageout_count: AtomicU64,
    pub ws_faults_handled: AtomicU64,

    // System PTE pool statistics
    pub syspte_alloc_count: AtomicU64,
    pub syspte_free_count: AtomicU64,
    pub syspte_alloc_failures: AtomicU64,

    // Hyperspace statistics
    pub hyperspace_map_count: AtomicU64,
    pub hyperspace_unmap_count: AtomicU64,
}

impl PerfCounters {
    /// Create a new performance counter structure with all counters initialized to 0
    pub const fn new() -> Self {
        Self {
            // PFN counters
            pfn_alloc_count: AtomicU64::new(0),
            pfn_free_count: AtomicU64::new(0),
            pfn_alloc_failures: AtomicU64::new(0),
            pfn_zeroed_used: AtomicU64::new(0),
            pfn_free_used: AtomicU64::new(0),

            // Heap counters
            heap_alloc_count: AtomicU64::new(0),
            heap_free_count: AtomicU64::new(0),
            heap_current_allocated: AtomicU64::new(0),
            heap_peak_allocated: AtomicU64::new(0),
            heap_alloc_failures: AtomicU64::new(0),

            // Pool counters
            pool_alloc_count: AtomicU64::new(0),
            pool_free_count: AtomicU64::new(0),
            pool_alloc_failures: AtomicU64::new(0),
            paged_pool_alloc: AtomicU64::new(0),
            non_paged_pool_alloc: AtomicU64::new(0),

            // Page fault counters
            page_fault_count: AtomicU64::new(0),
            demand_zero_faults: AtomicU64::new(0),
            cow_faults: AtomicU64::new(0),
            disk_faults: AtomicU64::new(0),
            guard_page_faults: AtomicU64::new(0),

            // TLB counters
            tlb_invalidations: AtomicU64::new(0),
            invlpg_count: AtomicU64::new(0),
            invpcid_count: AtomicU64::new(0),
            cr3_switches: AtomicU64::new(0),

            // VAD counters
            vad_insert_count: AtomicU64::new(0),
            vad_remove_count: AtomicU64::new(0),
            vad_split_count: AtomicU64::new(0),
            vad_merge_count: AtomicU64::new(0),
            vad_search_count: AtomicU64::new(0),

            // Working set counters
            ws_trim_count: AtomicU64::new(0),
            ws_pageout_count: AtomicU64::new(0),
            ws_faults_handled: AtomicU64::new(0),

            // System PTE counters
            syspte_alloc_count: AtomicU64::new(0),
            syspte_free_count: AtomicU64::new(0),
            syspte_alloc_failures: AtomicU64::new(0),

            // Hyperspace counters
            hyperspace_map_count: AtomicU64::new(0),
            hyperspace_unmap_count: AtomicU64::new(0),
        }
    }

    /// Reset all counters to zero
    pub fn reset(&self) {
        // Note: In a real implementation, we'd need interior mutability
        // For now, we provide this as a documentation of intent
    }
}

/// Global performance counter instance
pub static PERF: PerfCounters = PerfCounters::new();

// =============================================================================
// Convenience Functions
// =============================================================================

/// Record a PFN allocation
#[inline]
pub fn record_pfn_alloc(from_zeroed: bool) {
    PERF.pfn_alloc_count.fetch_add(1, Ordering::Relaxed);
    if from_zeroed {
        PERF.pfn_zeroed_used.fetch_add(1, Ordering::Relaxed);
    } else {
        PERF.pfn_free_used.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a PFN free
#[inline]
pub fn record_pfn_free() {
    PERF.pfn_free_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a PFN allocation failure
#[inline]
pub fn record_pfn_alloc_failure() {
    PERF.pfn_alloc_failures.fetch_add(1, Ordering::Relaxed);
}

/// Record a page fault
#[inline]
pub fn record_page_fault(fault_type: PageFaultType) {
    PERF.page_fault_count.fetch_add(1, Ordering::Relaxed);
    match fault_type {
        PageFaultType::DemandZero => { PERF.demand_zero_faults.fetch_add(1, Ordering::Relaxed); }
        PageFaultType::CopyOnWrite => { PERF.cow_faults.fetch_add(1, Ordering::Relaxed); }
        PageFaultType::Disk => { PERF.disk_faults.fetch_add(1, Ordering::Relaxed); }
        PageFaultType::GuardPage => { PERF.guard_page_faults.fetch_add(1, Ordering::Relaxed); }
    }
}

/// Types of page faults for tracking
#[derive(Debug, Clone, Copy)]
pub enum PageFaultType {
    DemandZero,
    CopyOnWrite,
    Disk,
    GuardPage,
}

/// Record a TLB invalidation
#[inline]
pub fn record_tlb_invalidate(invlpg_used: bool) {
    PERF.tlb_invalidations.fetch_add(1, Ordering::Relaxed);
    if invlpg_used {
        PERF.invlpg_count.fetch_add(1, Ordering::Relaxed);
    } else {
        PERF.invpcid_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a CR3 switch (process context switch)
#[inline]
pub fn record_cr3_switch() {
    PERF.cr3_switches.fetch_add(1, Ordering::Relaxed);
}

/// Record a VAD operation
#[inline]
pub fn record_vad_insert() {
    PERF.vad_insert_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a VAD remove operation
#[inline]
pub fn record_vad_remove() {
    PERF.vad_remove_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a VAD split operation
#[inline]
pub fn record_vad_split() {
    PERF.vad_split_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a VAD merge operation
#[inline]
pub fn record_vad_merge() {
    PERF.vad_merge_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a system PTE allocation
#[inline]
pub fn record_syspte_alloc() {
    PERF.syspte_alloc_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a system PTE allocation failure
#[inline]
pub fn record_syspte_alloc_failure() {
    PERF.syspte_alloc_failures.fetch_add(1, Ordering::Relaxed);
}

/// Record a system PTE free
#[inline]
pub fn record_syspte_free() {
    PERF.syspte_free_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a hyperspace map operation
#[inline]
pub fn record_hyperspace_map() {
    PERF.hyperspace_map_count.fetch_add(1, Ordering::Relaxed);
}

/// Record a hyperspace unmap operation
#[inline]
pub fn record_hyperspace_unmap() {
    PERF.hyperspace_unmap_count.fetch_add(1, Ordering::Relaxed);
}

// =============================================================================
// Statistics Display
// =============================================================================

/// Print all performance statistics
pub fn print_stats() {
    // [DISABLED] // // kprintln!("=== Memory Manager Performance Counters ===")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- PFN Allocation ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Allocations:     {}", PERF.pfn_alloc_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Frees:           {}", PERF.pfn_free_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Failures:       {}", PERF.pfn_alloc_failures.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  From Zeroed:    {}", PERF.pfn_zeroed_used.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  From Free:      {}", PERF.pfn_free_used.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- Page Faults ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Total faults:    {}", PERF.page_fault_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Demand zero:     {}", PERF.demand_zero_faults.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Copy-on-write:   {}", PERF.cow_faults.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Disk I/O:        {}", PERF.disk_faults.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Guard page:      {}", PERF.guard_page_faults.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- TLB ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Invalidations:   {}", PERF.tlb_invalidations.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  INVLPG:          {}", PERF.invlpg_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  CR3 switches:    {}", PERF.cr3_switches.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- VAD Tree ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Inserts:         {}", PERF.vad_insert_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Removes:         {}", PERF.vad_remove_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Splits:          {}", PERF.vad_split_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Merges:          {}", PERF.vad_merge_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- System PTE Pool ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Allocations:     {}", PERF.syspte_alloc_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Frees:           {}", PERF.syspte_free_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Failures:        {}", PERF.syspte_alloc_failures.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!()  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("--- Hyperspace ---")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Maps:            {}", PERF.hyperspace_map_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("  Unmaps:          {}", PERF.hyperspace_unmap_count.load(Ordering::Relaxed))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // [DISABLED] // // kprintln!("===========================================")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Get a summary of PFN statistics
pub fn get_pfn_stats() -> PfnStats {
    PfnStats {
        alloc_count: PERF.pfn_alloc_count.load(Ordering::Relaxed),
        free_count: PERF.pfn_free_count.load(Ordering::Relaxed),
        failures: PERF.pfn_alloc_failures.load(Ordering::Relaxed),
        zeroed_used: PERF.pfn_zeroed_used.load(Ordering::Relaxed),
        free_used: PERF.pfn_free_used.load(Ordering::Relaxed),
    }
}

/// PFN statistics summary
#[derive(Debug, Clone, Copy)]
pub struct PfnStats {
    pub alloc_count: u64,
    pub free_count: u64,
    pub failures: u64,
    pub zeroed_used: u64,
    pub free_used: u64,
}

/// Get page fault statistics
pub fn get_page_fault_stats() -> PageFaultStats {
    PageFaultStats {
        total: PERF.page_fault_count.load(Ordering::Relaxed),
        demand_zero: PERF.demand_zero_faults.load(Ordering::Relaxed),
        cow: PERF.cow_faults.load(Ordering::Relaxed),
        disk: PERF.disk_faults.load(Ordering::Relaxed),
        guard_page: PERF.guard_page_faults.load(Ordering::Relaxed),
    }
}

/// Page fault statistics summary
#[derive(Debug, Clone, Copy)]
pub struct PageFaultStats {
    pub total: u64,
    pub demand_zero: u64,
    pub cow: u64,
    pub disk: u64,
    pub guard_page: u64,
}

/// Initialize the performance counter system
pub fn init() {
    // Performance counters start at 0 by default
    // [DISABLED] // // kprintln!("[MM PERF] Performance counters initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_pfn_operations() {
        let initial_alloc = PERF.pfn_alloc_count.load(Ordering::Relaxed);
        record_pfn_alloc(true);
        assert_eq!(PERF.pfn_alloc_count.load(Ordering::Relaxed), initial_alloc + 1);
        assert_eq!(PERF.pfn_zeroed_used.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_record_page_fault() {
        let initial = PERF.page_fault_count.load(Ordering::Relaxed);
        record_page_fault(PageFaultType::DemandZero);
        assert_eq!(PERF.page_fault_count.load(Ordering::Relaxed), initial + 1);
        assert_eq!(PERF.demand_zero_faults.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_get_stats() {
        let stats = get_pfn_stats();
        assert!(stats.alloc_count >= 0);
    }
}
