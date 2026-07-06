//! Memory Diagnostic Commands
//
//! Provides command-line interface for memory testing in Safe Mode.

/// Print memory status
pub fn cmd_memory_status() {
    use crate::mm;
    
    // // crate::kprintln!("[INFO]   [MEMORY]   0  ")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [MEMORY]   0  === Memory Status ===")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [MEMORY]   0  ")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // Get memory info from PFN database
    let free_count = mm::pfn::get_free_pfns();
    let _ = &free_count;
    let total_count = mm::pfn::get_database_count();
    let _ = &total_count;
    
    // // crate::kprintln!("[INFO]   [MEMORY]   0  Physical Memory:")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [MEMORY]   0    Total Pages: {}", total_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [MEMORY]   0    Free Pages:  {}", free_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [MEMORY]   0    Used Pages:  {}", total_count.saturating_sub(free_count))  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Run memory test
pub fn cmd_memory_test() {
    use crate::mm::memtest;
    
    // // crate::kprintln!("[INFO]   [DIAG]     0  ")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [DIAG]     0  Running memory test...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[DEBUG]  [DIAG]     0    Patterns: {}", memtest::TestPatterns::PATTERNS.len())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // Get test range from available memory
    let test_start = 0x100_000;  // 1MB
    let test_end = 0x100_000 + (64 * 1024 * 1024); // 64MB test range
    
    // // crate::kprintln!("[DEBUG]  [DIAG]     0    Range: 0x{:016X} - 0x{:016X}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               test_start, test_end);
    
    // Run tests using quick_test
    let passed = memtest::quick_test(test_start, test_end);
    
    if passed {
        // // crate::kprintln!("[INFO]   [DIAG]     0  Memory test PASSED")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // // crate::kprintln!("[INFO]   [DIAG]     0  {} KB tested, 0 errors", (test_end - test_start) / 1024)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // // crate::kprintln!("[ERROR]  [DIAG]     0  Memory test FAILED")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // // crate::kprintln!("[ERROR]  [DIAG]     0  Errors detected in test range")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Dump PFN database state
pub fn cmd_pfn_dump() {
    
    // // crate::kprintln!("[INFO]   [PFN]      0  ")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [PFN]      0  === PFN Database Dump ===")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [PFN]      0  ")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [PFN]      0    Total Pages: {}", pfn::get_database_count())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [PFN]      0    Free PFNs:  {}", pfn::get_free_pfns())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("[INFO]   [PFN]      0    Database Base: 0x{:016X}", pfn::get_database_base())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}
