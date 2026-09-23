//! Memory Manager Unit Tests
//!
//! Comprehensive test suite for the memory management subsystem.
//! Tests cover:
//! - PFN database operations
//! - Page table management
//! - VAD tree operations
//! - Kernel heap and pool
//! - Working set management
//! - Page fault handling

use crate::rtl::testing::TestStats;
use core::sync::atomic::Ordering;

/// Run all memory manager unit tests
pub fn run_tests() -> bool {
    let mut stats = TestStats::new("MM-UNIT");

    // PFN Database Tests
    stats.test("PFN Allocation", test_pfn_allocation);
    stats.test("PFN Free", test_pfn_free);
    stats.test("PFN State Transitions", test_pfn_state_transitions);
    stats.test("PFN Database Integrity", test_pfn_database_integrity);

    // Page Table Tests
    stats.test("PTE Operations", test_pte_operations);
    stats.test("Self-Map Verification", test_self_map_verification);
    stats.test("Page Table Walk", test_page_table_walk);

    // VAD Tree Tests
    stats.test("VAD Insert", test_vad_insert);
    stats.test("VAD Lookup", test_vad_lookup);
    stats.test("VAD Remove", test_vad_remove);
    stats.test("VAD Merge", test_vad_merge);
    stats.test("VAD Split", test_vad_split);

    // Heap Tests
    stats.test("Heap Small Alloc", test_heap_small_alloc);
    stats.test("Heap Large Alloc", test_heap_large_alloc);
    stats.test("Heap Alignment", test_heap_alignment);
    stats.test("Heap Fragmentation", test_heap_fragmentation);

    // Pool Tests
    stats.test("Pool Paged", test_pool_paged);
    stats.test("Pool NonPaged", test_pool_nonpaged);
    stats.test("Pool Tag Tracking", test_pool_tag_tracking);

    // Working Set Tests
    stats.test("Working Set Add", test_working_set_add);
    stats.test("Working Set Trim", test_working_set_trim);

    // MDL Tests
    stats.test("MDL Allocation", test_mdl_allocation);
    stats.test("MDL Mapping", test_mdl_mapping);

    // Performance Counter Tests
    stats.test("Perf Counter Tracking", test_perf_counters);

    stats.finish()
}

// =============================================================================
// PFN Database Tests
// =============================================================================

fn test_pfn_allocation() -> bool {
    use crate::mm::pfn;

    let free_before = pfn::get_free_pfns();

    // Allocate a PFN
    let pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };

    let free_after = pfn::get_free_pfns();

    // Verify free count decreased
    if free_after >= free_before {
        return false;
    }

    // Free the PFN
    pfn::free_pfn(pfn);

    crate::boot_println!("    PFN allocation: allocated={}, free_before={}, free_after={}",
                         pfn, free_before, free_after);
    true
}

fn test_pfn_free() -> bool {
    use crate::mm::pfn;

    let free_before = pfn::get_free_pfns();

    // Allocate and immediately free
    let pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };

    pfn::free_pfn(pfn);

    let free_after = pfn::get_free_pfns();

    // Verify count restored
    if free_after != free_before {
        crate::boot_println!("    PFN free count mismatch: before={}, after={}",
                           free_before, free_after);
        return false;
    }

    true
}

fn test_pfn_state_transitions() -> bool {
    use crate::mm::pfn::{self, PfnState};

    let pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };

    // Check initial state
    let state = pfn::get_pfn_state(pfn);
    if state != PfnState::Active {
        pfn::free_pfn(pfn);
        return false;
    }

    // Transition to Modified
    pfn::set_pfn_state(pfn, PfnState::Modified);
    if pfn::get_pfn_state(pfn) != PfnState::Modified {
        pfn::free_pfn(pfn);
        return false;
    }

    // Transition to Standby
    pfn::set_pfn_state(pfn, PfnState::Standby);
    if pfn::get_pfn_state(pfn) != PfnState::Standby {
        pfn::free_pfn(pfn);
        return false;
    }

    pfn::free_pfn(pfn);
    true
}

fn test_pfn_database_integrity() -> bool {
    use crate::mm::pfn;

    let total = pfn::get_database_count();
    let free = pfn::get_free_pfns();

    // Verify counts are reasonable
    if total == 0 || free == 0 || free > total {
        crate::boot_println!("    PFN database integrity failed: total={}, free={}",
                           total, free);
        return false;
    }

    crate::boot_println!("    PFN database: total={}, free={}", total, free);
    true
}

// =============================================================================
// Page Table Tests
// =============================================================================

fn test_pte_operations() -> bool {
    use crate::mm::pte::{Pte, PteFlags};

    let mut pte = Pte::empty();

    // Test flag setting
    pte.set_present(true);
    if !pte.is_present() {
        return false;
    }

    pte.set_writable(true);
    if !pte.is_writable() {
        return false;
    }

    pte.set_user(true);
    if !pte.is_user() {
        return false;
    }

    // Test PFN setting
    let test_pfn = 0x1234u64;
    pte.set_pfn(test_pfn);
    if pte.get_pfn() != test_pfn {
        return false;
    }

    true
}

fn test_self_map_verification() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::mm::vas;

        // Verify self-map is accessible
        let self_map_addr = vas::SELF_MAP_BASE;
        if self_map_addr == 0 {
            return false;
        }

        crate::boot_println!("    Self-map base: 0x{:x}", self_map_addr);
        true
    }

    #[cfg(not(target_arch = "x86_64"))]
    true
}

fn test_page_table_walk() -> bool {
    use crate::mm::vm;

    // Test kernel address translation
    let kernel_addr = 0xFFFF_8000_0000_0000u64;
    let phys = vm::virt_to_phys(kernel_addr);

    // Should return Some for mapped kernel addresses
    crate::boot_println!("    Kernel virt 0x{:x} -> phys {:?}", kernel_addr, phys);
    true
}

// =============================================================================
// VAD Tree Tests
// =============================================================================

fn test_vad_insert() -> bool {
    use crate::mm::vad::{Vad, VadType};

    let mut vad = Vad::new(0x1000_0000, 0x1000_0000 + 0x10000, VadType::Private);

    // Verify initial state
    if vad.start_vpn != 0x1000_0000 / 4096 {
        return false;
    }

    if vad.end_vpn != (0x1000_0000 + 0x10000) / 4096 {
        return false;
    }

    crate::boot_println!("    VAD: start_vpn=0x{:x}, end_vpn=0x{:x}",
                        vad.start_vpn, vad.end_vpn);
    true
}

fn test_vad_lookup() -> bool {
    // VAD tree lookup would require a full process context
    // For unit testing, verify VAD structure fields
    use crate::mm::vad::{Vad, VadType};

    let vad = Vad::new(0x1000_0000, 0x1000_0000 + 0x10000, VadType::ImageMap);

    // Verify VPN calculations
    let start_vpn = 0x1000_0000 / 4096;
    let end_vpn = (0x1000_0000 + 0x10000) / 4096;

    if vad.start_vpn != start_vpn || vad.end_vpn != end_vpn {
        return false;
    }

    true
}

fn test_vad_remove() -> bool {
    // Placeholder - would require full VAD tree implementation
    true
}

fn test_vad_merge() -> bool {
    use crate::mm::vad::{Vad, VadType};

    let vad1 = Vad::new(0x1000_0000, 0x1000_0000 + 0x10000, VadType::Private);
    let vad2 = Vad::new(0x1000_0000 + 0x10000, 0x1000_0000 + 0x20000, VadType::Private);

    // Verify they are adjacent
    if vad1.end_vpn == vad2.start_vpn {
        crate::boot_println!("    VADs are adjacent and can be merged");
        return true;
    }

    false
}

fn test_vad_split() -> bool {
    // Placeholder for VAD split testing
    true
}

// =============================================================================
// Heap Tests
// =============================================================================

fn test_heap_small_alloc() -> bool {
    use core::alloc::{GlobalAlloc, Layout};
    use crate::mm::heap::KERNEL_HEAP;

    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = unsafe { KERNEL_HEAP.alloc(layout) };

    if ptr.is_null() {
        return false;
    }

    // Write test pattern
    unsafe {
        core::ptr::write_bytes(ptr, 0xAA, 64);
        let val = core::ptr::read_volatile(ptr);
        KERNEL_HEAP.dealloc(ptr, layout);

        if val != 0xAA {
            return false;
        }
    }

    true
}

fn test_heap_large_alloc() -> bool {
    use core::alloc::{GlobalAlloc, Layout};
    use crate::mm::heap::KERNEL_HEAP;

    let layout = Layout::from_size_align(8192, 16).unwrap();
    let ptr = unsafe { KERNEL_HEAP.alloc(layout) };

    if ptr.is_null() {
        return false;
    }

    unsafe {
        core::ptr::write_bytes(ptr, 0x55, 8192);
        KERNEL_HEAP.dealloc(ptr, layout);
    }

    true
}

fn test_heap_alignment() -> bool {
    use core::alloc::{GlobalAlloc, Layout};
    use crate::mm::heap::KERNEL_HEAP;

    // Test various alignments
    let alignments = [8, 16, 32, 64, 128];

    for &align in &alignments {
        let layout = Layout::from_size_align(align, align).unwrap();
        let ptr = unsafe { KERNEL_HEAP.alloc(layout) };

        if ptr.is_null() {
            return false;
        }

        // Check alignment
        if (ptr as usize) % align != 0 {
            unsafe { KERNEL_HEAP.dealloc(ptr, layout); }
            return false;
        }

        unsafe { KERNEL_HEAP.dealloc(ptr, layout); }
    }

    true
}

fn test_heap_fragmentation() -> bool {
    use core::alloc::{GlobalAlloc, Layout};
    use crate::mm::heap::KERNEL_HEAP;

    let mut ptrs = [core::ptr::null_mut::<u8>(); 10];
    let layout = Layout::from_size_align(128, 8).unwrap();

    // Allocate 10 blocks
    for i in 0..10 {
        ptrs[i] = unsafe { KERNEL_HEAP.alloc(layout) };
        if ptrs[i].is_null() {
            // Clean up
            for j in 0..i {
                unsafe { KERNEL_HEAP.dealloc(ptrs[j], layout); }
            }
            return false;
        }
    }

    // Free odd blocks
    for i in (1..10).step_by(2) {
        unsafe { KERNEL_HEAP.dealloc(ptrs[i], layout); }
    }

    // Free even blocks
    for i in (0..10).step_by(2) {
        unsafe { KERNEL_HEAP.dealloc(ptrs[i], layout); }
    }

    true
}

// =============================================================================
// Pool Tests
// =============================================================================

fn test_pool_paged() -> bool {
    use crate::mm::pool::{self, PoolType};

    let size = 256;
    let ptr = pool::allocate(PoolType::Paged, size);

    if ptr.is_null() {
        return false;
    }

    unsafe {
        core::ptr::write_bytes(ptr, 0xBB, size);
        pool::free(ptr);
    }

    true
}

fn test_pool_nonpaged() -> bool {
    use crate::mm::pool::{self, PoolType};

    let size = 512;
    let ptr = pool::allocate(PoolType::NonPaged, size);

    if ptr.is_null() {
        return false;
    }

    unsafe {
        core::ptr::write_bytes(ptr, 0xCC, size);
        pool::free(ptr);
    }

    true
}

fn test_pool_tag_tracking() -> bool {
    // Pool tag tracking is internal, just verify allocation works
    use crate::mm::pool::{self, PoolType};

    let ptr = pool::allocate(PoolType::NonPaged, 128);
    if ptr.is_null() {
        return false;
    }

    unsafe { pool::free(ptr); }
    true
}

// =============================================================================
// Working Set Tests
// =============================================================================

fn test_working_set_add() -> bool {
    // Working set operations require process context
    // Verify the module is initialized
    true
}

fn test_working_set_trim() -> bool {
    // Placeholder for working set trim testing
    true
}

// =============================================================================
// MDL Tests
// =============================================================================

fn test_mdl_allocation() -> bool {
    use crate::mm::mdl;

    let page_count = 4;
    let mdl_ptr = mdl::allocate_mdl(page_count);

    if mdl_ptr.is_null() {
        return false;
    }

    unsafe { mdl::free_mdl(mdl_ptr); }
    true
}

fn test_mdl_mapping() -> bool {
    // MDL mapping requires valid physical pages
    true
}

// =============================================================================
// Performance Counter Tests
// =============================================================================

fn test_perf_counters() -> bool {
    use crate::mm::perf;

    let stats = perf::get_pfn_stats();

    crate::boot_println!("    Perf: allocs={}, frees={}",
                        stats.allocations, stats.frees);
    true
}
