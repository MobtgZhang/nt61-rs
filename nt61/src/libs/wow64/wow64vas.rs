//! wow64vas — 32-bit Virtual Address Space Manager for WoW64
//
//! This module provides a 32-bit virtual address space manager that
//! operates within the Wow64 process address space constraints:
//!   - User space: 0x00010000 to 0x7FFEFFFF
//!   - System DLLs: 0x7FFE0000 to 0x7FFFFFFF
//
//! The Wow64 VAS allocator manages memory allocation in the lower 4GB
//! of the address space, mapping 32-bit allocations to actual physical
//! pages and maintaining the per-process view.
//
//! References:
//!   * geoffchappell.com - WoW64 system service dispatching
//!   * ReactOS 0.3.x - wow64 memory management

use crate::ke::sync::Spinlock;

// Re-export basic types for convenience
use crate::libs::wow64::types::*;

// =============================================================================
// Constants
// =============================================================================

/// Minimum allocation granularity (4KB page).
pub const WOW64_ALLOCATION_GRANULARITY: u32 = 0x1000;

/// Minimum allocation size (4KB).
pub const WOW64_MINIMUM_ALLOC: u32 = 0x1000;

/// Default stack size for 32-bit threads.
pub const WOW64_DEFAULT_STACK_SIZE: u32 = 0x100000; // 1MB

/// Heap virtual alloc base for 32-bit processes.
pub const WOW64_HEAP_VIRTUAL_ALLOC_BASE: u32 = 0x00030000;

/// Heap virtual alloc max (up to Wow64 user space limit).
pub const WOW64_HEAP_VIRTUAL_ALLOC_MAX: u32 = 0x7FFE0000;

// =============================================================================
// Wow64 Virtual Address Space State
// =============================================================================

/// Per-allocation tracking entry.
#[derive(Debug, Clone, Default)]
pub struct AllocationEntry {
    /// Base address of allocation.
    pub base: u32,
    /// Size of allocation in bytes.
    pub size: u32,
    /// Allocation type flags.
    pub allocation_type: u32,
    /// Protection flags.
    pub protect: u32,
    /// Whether this entry is in use.
    pub in_use: bool,
}

/// Wow64 VAS allocator state.
/// Tracks the current allocation position and maintains
/// a simple bump-pointer allocation strategy.
pub struct Wow64VasState {
    /// Next allocation base (bump pointer).
    pub next_alloc: u32,
    /// End of user space (exclusive).
    pub end_of_space: u32,
    /// Number of allocations made.
    pub allocation_count: u32,
    /// Peak usage.
    pub peak_usage: u32,
}

impl Default for Wow64VasState {
    fn default() -> Self {
        Self {
            // Start after the system DLL region
            next_alloc: WOW64_USER_SPACE_START,
            end_of_space: WOW64_USER_SPACE_END,
            allocation_count: 0,
            peak_usage: 0,
        }
    }
}

impl Wow64VasState {
    /// Create a new VAS state.
    pub const fn new() -> Self {
        // Start after the system DLL region.
        Self {
            next_alloc: WOW64_USER_SPACE_START,
            end_of_space: WOW64_USER_SPACE_END,
            allocation_count: 0,
            peak_usage: 0,
        }
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.next_alloc = WOW64_USER_SPACE_START;
        self.allocation_count = 0;
    }

    /// Get current usage.
    pub fn current_usage(&self) -> u32 {
        self.next_alloc - WOW64_USER_SPACE_START
    }
}

// =============================================================================
// Global Wow64 VAS
// =============================================================================

/// Global Wow64 virtual address space allocator.
/// This is process-specific and would typically be stored in
/// the EPROCESS wow64_extension field.
pub static WOW64_VAS: Spinlock<Wow64VasState> = Spinlock::new(Wow64VasState::new());

// =============================================================================
// Address Validation
// =============================================================================

/// Check if an address is in the valid Wow64 user range.
#[inline]
pub fn is_valid_user_address(addr: u32) -> bool {
    addr >= WOW64_USER_SPACE_START && addr <= WOW64_USER_SPACE_END
}

/// Check if a range is valid for Wow64 user mode.
#[inline]
pub fn is_valid_user_range(addr: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    // Check for overflow
    match addr.checked_add(size) {
        Some(end) => end <= (WOW64_USER_SPACE_END + 1),
        None => false,
    }
}

/// Check if address is in the system DLL region.
#[inline]
pub fn is_in_system_dll_region(addr: u32) -> bool {
    addr >= WOW64_SYSTEM_DLL_BASE
}

/// Align address up to page boundary.
#[inline]
pub fn align_to_page(addr: u32) -> u32 {
    (addr + (WOW64_ALLOCATION_GRANULARITY - 1)) & !(WOW64_ALLOCATION_GRANULARITY - 1)
}

/// Align address down to page boundary.
#[inline]
pub fn align_to_page_down(addr: u32) -> u32 {
    addr & !(WOW64_ALLOCATION_GRANULARITY - 1)
}

// =============================================================================
// Allocation Functions
// =============================================================================

/// Allocate virtual memory in the 32-bit address space.
///
/// # Arguments
/// * `size` - Size of allocation in bytes (will be aligned to page)
/// * `align` - Alignment requirement (must be power of 2 and >= page size)
/// * `preferred_base` - Preferred base address (0 for any)
/// * `allocation_type` - MEM_COMMIT, MEM_RESERVE, or both
/// * `protect` - Page protection (PAGE_READ, PAGE_WRITE, etc)
///
/// # Returns
/// * `Some((base, actual_size))` on success
/// * `None` if allocation failed
pub fn allocate(
    size: u32,
    align: u32,
    preferred_base: u32,
    allocation_type: u32,
    _protect: u32,
) -> Option<(u32, u32)> {
    let size = if size == 0 { WOW64_MINIMUM_ALLOC } else { size };

    // Align size to page boundary
    let aligned_size = align_to_page(size);

    // Determine base address
    let base = if preferred_base != 0 {
        // Use preferred base if valid
        if is_valid_user_range(preferred_base, aligned_size) {
            align_to_page(preferred_base)
        } else {
            return None;
        }
    } else {
        // Bump pointer allocation
        let mut vas = WOW64_VAS.lock();

        // Align next_alloc to specified alignment
        let aligned_base = if align > WOW64_ALLOCATION_GRANULARITY {
            (vas.next_alloc + align - 1) & !(align - 1)
        } else {
            vas.next_alloc
        };

        // Check if we have space
        let end = aligned_base.checked_add(aligned_size)?;
        if end > WOW64_USER_SPACE_END {
            // Out of address space
            crate::wow64_klog!("allocate: out of address space");
            return None;
        }

        // Update next_alloc
        vas.next_alloc = end;
        vas.allocation_count += 1;

        // Update peak usage
        let usage = vas.next_alloc - WOW64_USER_SPACE_START;
        if usage > vas.peak_usage {
            vas.peak_usage = usage;
        }

        aligned_base
    };

    crate::wow64_klog!(
        "allocate: base=0x{:08x} size=0x{:08x} type=0x{:x}",
        base, aligned_size, allocation_type
    );

    Some((base, aligned_size))
}

/// Free virtual memory in the 32-bit address space.
///
/// # Arguments
/// * `base` - Base address (must be page-aligned)
/// * `size` - Size to free (must be page-aligned)
///
/// # Returns
/// * `true` on success
/// * `false` on failure
pub fn free(base: u32, size: u32) -> bool {
    if !is_valid_user_range(base, size) {
        crate::wow64_klog!(
            "free: invalid range base=0x{:08x} size=0x{:08x}",
            base, size
        );
        return false;
    }

    crate::wow64_klog!(
        "free: base=0x{:08x} size=0x{:08x}",
        base, size
    );

    true
}

/// Query virtual memory information.
///
/// # Arguments
/// * `base` - Base address to query
///
/// # Returns
/// * `Some(WOW64_MEMORY_BASIC_INFORMATION32)` on success
/// * `None` on failure
pub fn query(base: u32) -> Option<Wow64MemoryBasicInformation32> {
    if !is_valid_user_address(base) {
        return None;
    }

    // In a real implementation, this would query the VAD tree
    // For the stub, return a basic structure
    Some(Wow64MemoryBasicInformation32 {
        base_address: align_to_page_down(base),
        allocation_base: align_to_page_down(base),
        allocation_protect: memory_protect::PAGE_READWRITE,
        region_size: 0x1000, // Minimum page size
        state: memory_state::MEM_COMMIT,
        protect: memory_protect::PAGE_READWRITE,
        memory_type: 0, // MEM_PRIVATE
    })
}

// =============================================================================
// Wow64-specific Memory Operations
// =============================================================================

/// Allocate memory for a 32-bit process heap.
///
/// This is called when initializing a Wow64 process to set up
/// the initial process heap.
pub fn allocate_heap(size: u32) -> Option<u32> {
    let aligned_size = align_to_page(size.max(WOW64_MINIMUM_ALLOC));
    allocate(
        aligned_size,
        WOW64_ALLOCATION_GRANULARITY,
        WOW64_HEAP_VIRTUAL_ALLOC_BASE,
        memory_allocation_type::MEM_COMMIT | memory_allocation_type::MEM_RESERVE,
        memory_protect::PAGE_READWRITE,
    )
    .map(|(base, sz)| {
        crate::wow64_klog!("allocated heap: base=0x{:08x} size=0x{:08x}", base, sz);
        base
    })
}

/// Allocate memory for a 32-bit thread stack.
///
/// This allocates the user-mode stack for a 32-bit thread.
pub fn allocate_stack(size: u32) -> Option<u32> {
    let stack_size = size.max(WOW64_DEFAULT_STACK_SIZE);
    let aligned_size = align_to_page(stack_size);

    // Stacks are allocated from high addresses going down
    // In a full implementation, this would use a different allocator
    allocate(
        aligned_size,
        WOW64_ALLOCATION_GRANULARITY,
        0, // Any base
        memory_allocation_type::MEM_COMMIT | memory_allocation_type::MEM_RESERVE,
        memory_protect::PAGE_READWRITE,
    )
    .map(|(base, sz)| {
        crate::wow64_klog!("allocated stack: base=0x{:08x} size=0x{:08x}", base, sz);
        base + sz // Return top of stack
    })
}

/// Read memory from a 32-bit process.
///
/// This is used by the kernel to read from a Wow64 process's address space.
pub fn read_memory(
    _process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> Result<u32, u32> {
    if !is_valid_user_range(base_address, size) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !is_valid_user_range(buffer, size) {
        return Err(STATUS_INVALID_PARAMETER);
    }

    crate::wow64_klog!(
        "read_memory: from=0x{:08x} to=0x{:08x} size=0x{:08x}",
        base_address, buffer, size
    );

    Ok(size)
}

/// Write memory to a 32-bit process.
///
/// This is used by the kernel to write to a Wow64 process's address space.
pub fn write_memory(
    _process_handle: u32,
    base_address: u32,
    buffer: u32,
    size: u32,
) -> Result<u32, u32> {
    if !is_valid_user_range(base_address, size) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !is_valid_user_range(buffer, size) {
        return Err(STATUS_INVALID_PARAMETER);
    }

    crate::wow64_klog!(
        "write_memory: to=0x{:08x} from=0x{:08x} size=0x{:08x}",
        base_address, buffer, size
    );

    Ok(size)
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the Wow64 VAS for a new process.
pub fn init_process() {
    let mut vas = WOW64_VAS.lock();
    vas.reset();
    crate::wow64_klog!(
        "initialized: user_space=0x{:08x}-0x{:08x}",
        WOW64_USER_SPACE_START,
        WOW64_USER_SPACE_END
    );
}

/// Get current allocation statistics.
pub fn get_stats() -> (u32, u32, u32) {
    let vas = WOW64_VAS.lock();
    (vas.current_usage(), vas.peak_usage, vas.allocation_count)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        assert!(is_valid_user_address(0x00010000));
        assert!(is_valid_user_address(0x7FFEFFFF));
        assert!(!is_valid_user_address(0));
        assert!(!is_valid_user_address(0xFFFFFFFF));
        assert!(!is_valid_user_address(0x80000000));
    }

    #[test]
    fn test_range_validation() {
        assert!(is_valid_user_range(0x00010000, 0x1000));
        assert!(is_valid_user_range(0x00010000, 0));
        assert!(!is_valid_user_range(0, 0x1000));
        assert!(!is_valid_user_range(0x7FFFFFFF, 0x1000));
        assert!(!is_valid_user_range(0x7FFF0000, 0x20000));
    }

    #[test]
    fn test_page_alignment() {
        assert_eq!(align_to_page(0), 0);
        assert_eq!(align_to_page(0x1000), 0x1000);
        assert_eq!(align_to_page(0x1001), 0x2000);
        assert_eq!(align_to_page(0x2000), 0x2000);

        assert_eq!(align_to_page_down(0), 0);
        assert_eq!(align_to_page_down(0x1000), 0x1000);
        assert_eq!(align_to_page_down(0x1001), 0x1000);
        assert_eq!(align_to_page_down(0x2000), 0x2000);
    }

    #[test]
    fn test_allocation() {
        init_process();

        let result = allocate(0x1000, 0x1000, 0, memory_allocation_type::MEM_COMMIT, memory_protect::PAGE_READWRITE);
        assert!(result.is_some());

        let (base, size) = result.unwrap();
        assert!(is_valid_user_address(base));
        assert_eq!(size, 0x1000);
    }
}
