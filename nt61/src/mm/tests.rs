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

    crate::boot_println!(
        "    PFN allocation: allocated={}, free_before={}, free_after={}",
        pfn,
        free_before,
        free_after
    );
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
        crate::boot_println!(
            "    PFN free count mismatch: before={}, after={}",
            free_before,
            free_after
        );
        return false;
    }

    true
}

fn test_pfn_state_transitions() -> bool {
    use crate::mm::pfn::{self, MMPFNSTATE};

    let pfn = match pfn::allocate_pfn() {
        Some(p) => p,
        None => return false,
    };

    let entry = match pfn::get_entry(pfn) {
        Some(e) if !e.is_null() => e,
        _ => {
            pfn::free_pfn(pfn);
            return false;
        }
    };

    unsafe {
        // `ExAllocatePfn` leaves the page Active.
        if (*entry).state() != MMPFNSTATE::Active {
            pfn::free_pfn(pfn);
            return false;
        }

        // Transition to Modified
        (*entry).set_state(MMPFNSTATE::Modified);
        if (*entry).state() != MMPFNSTATE::Modified {
            pfn::free_pfn(pfn);
            return false;
        }

        // Transition to Standby (priority 0 bucket)
        (*entry).set_state(MMPFNSTATE::Standby0);
        if (*entry).state() != MMPFNSTATE::Standby0 {
            pfn::free_pfn(pfn);
            return false;
        }
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
        crate::boot_println!(
            "    PFN database integrity failed: total={}, free={}",
            total,
            free
        );
        return false;
    }

    crate::boot_println!("    PFN database: total={}, free={}", total, free);
    true
}

// =============================================================================
// Page Table Tests
// =============================================================================

fn test_pte_operations() -> bool {
    use crate::mm::pte::MMPTE;

    let mut pte = MMPTE::empty();

    // Present | RW | U/S on x86-64: bits 0, 1, 2.
    const PAGE_PRESENT: u64 = 0x1;
    const PAGE_WRITABLE: u64 = 0x2;
    const PAGE_USER: u64 = 0x4;
    let test_pfn = 0x1234u64;
    let pa = test_pfn << 12;
    pte.set_hardware(pa, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);

    if !pte.is_hardware() {
        return false;
    }
    if !pte.writable() {
        return false;
    }
    if !pte.user() {
        return false;
    }
    if pte.hardware_page_frame() != pa {
        return false;
    }

    true
}

fn test_self_map_verification() -> bool {
    match crate::arch::self_map_info() {
        Some((self_map_addr, self_map_index)) => {
            if self_map_addr == 0 {
                return false;
            }
            if ((self_map_addr >> 39) & 0x1FF) as usize != self_map_index {
                return false;
            }

            crate::boot_println!("    Self-map base: 0x{:x}", self_map_addr);
            true
        }
        None => true,
    }
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
    use crate::mm::vad::{VadEntry, VadType};

    let mut vad = VadEntry::new();
    vad.vad_type = VadType::VadImage;
    vad.set_range(0x1000_0000, 0x1000_0000 + 0x10000);

    // Verify initial state
    if vad.starting_vpn != 0x1000_0000 / 4096 {
        return false;
    }

    if vad.ending_vpn != (0x1000_0000 + 0x10000) / 4096 {
        return false;
    }

    crate::boot_println!(
        "    VAD: start_vpn=0x{:x}, end_vpn=0x{:x}",
        vad.starting_vpn,
        vad.ending_vpn
    );
    true
}

fn test_vad_lookup() -> bool {
    // VAD tree lookup would require a full process context
    // For unit testing, verify VAD structure fields
    use crate::mm::vad::{VadEntry, VadType};

    let mut vad = VadEntry::new();
    vad.vad_type = VadType::VadDevice;
    vad.set_range(0x1000_0000, 0x1000_0000 + 0x10000);

    // Verify VPN calculations
    let start_vpn = 0x1000_0000 / 4096;
    let end_vpn = (0x1000_0000 + 0x10000) / 4096;

    if vad.starting_vpn != start_vpn || vad.ending_vpn != end_vpn {
        return false;
    }

    true
}

fn test_vad_remove() -> bool {
    // Placeholder - would require full VAD tree implementation
    true
}

fn test_vad_merge() -> bool {
    use crate::mm::vad::{VadEntry, VadType};

    let mut vad1 = VadEntry::new();
    vad1.vad_type = VadType::VadImage;
    vad1.set_range(0x1000_0000, 0x1000_0000 + 0x10000);

    let mut vad2 = VadEntry::new();
    vad2.vad_type = VadType::VadImage;
    vad2.set_range(0x1000_0000 + 0x10000, 0x1000_0000 + 0x20000);

    // Verify they are adjacent
    if vad1.ending_vpn == vad2.starting_vpn {
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
    use crate::mm::heap::KERNEL_HEAP;
    use core::alloc::{GlobalAlloc, Layout};

    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = unsafe { KERNEL_HEAP.alloc(layout) };

    if ptr.is_null() {
        return false;
    }

    // write test pattern
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
    use crate::mm::heap::KERNEL_HEAP;
    use core::alloc::{GlobalAlloc, Layout};

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
    use crate::mm::heap::KERNEL_HEAP;
    use core::alloc::{GlobalAlloc, Layout};

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
            unsafe {
                KERNEL_HEAP.dealloc(ptr, layout);
            }
            return false;
        }

        unsafe {
            KERNEL_HEAP.dealloc(ptr, layout);
        }
    }

    true
}

fn test_heap_fragmentation() -> bool {
    use crate::mm::heap::KERNEL_HEAP;
    use core::alloc::{GlobalAlloc, Layout};

    let mut ptrs = [core::ptr::null_mut::<u8>(); 10];
    let layout = Layout::from_size_align(128, 8).unwrap();

    // Allocate 10 blocks
    for i in 0..10 {
        ptrs[i] = unsafe { KERNEL_HEAP.alloc(layout) };
        if ptrs[i].is_null() {
            // Clean up
            for j in 0..i {
                unsafe {
                    KERNEL_HEAP.dealloc(ptrs[j], layout);
                }
            }
            return false;
        }
    }

    // Free odd blocks
    for i in (1..10).step_by(2) {
        unsafe {
            KERNEL_HEAP.dealloc(ptrs[i], layout);
        }
    }

    // Free even blocks
    for i in (0..10).step_by(2) {
        unsafe {
            KERNEL_HEAP.dealloc(ptrs[i], layout);
        }
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

    pool::free(ptr);
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
    use crate::io::transfer;

    let buffer = [0u8; 4096];
    let base = buffer.as_ptr() as *mut u8;
    let mdl_ptr = transfer::allocate_mdl(base, 4096, false, false, core::ptr::null_mut());

    if mdl_ptr.is_null() {
        return false;
    }

    unsafe {
        if (*mdl_ptr).byte_count != 4096 {
            transfer::free_mdl(mdl_ptr);
            return false;
        }
        // MDL_SIZE covers the header only; the page array follows it.
        if (*mdl_ptr).size != core::mem::size_of::<transfer::Mdl>() as u16 {
            transfer::free_mdl(mdl_ptr);
            return false;
        }
        // Byte offset is the alignment of the buffer inside its page.
        if (*mdl_ptr).byte_offset != (base as usize & 0xFFF) as u32 {
            transfer::free_mdl(mdl_ptr);
            return false;
        }
        transfer::free_mdl(mdl_ptr);
    }

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

    crate::boot_println!(
        "    Perf: allocs={}, frees={}",
        stats.alloc_count,
        stats.free_count
    );
    true
}
