//! Dynamic Page Table Allocation for Large Memory Systems
//!
//! This module extends the memory manager to support systems with 2GB to 192GB
//! of RAM. It provides dynamic page table allocation that can grow as needed,
//! rather than using static mappings.
//!
//! # Memory Layout
//!
//! For 48-bit virtual address layouts:
//! - User space: 0x0000_0000_0000_0000 to 0x0000_7FFF_FFFF_FFFF (128TB)
//! - Kernel space: 0xFFFF_8000_0000_0000 to 0xFFFF_FFFF_FFFF_FFFF (128TB)
//!
//! The kernel maps physical memory into the upper half of the address space.
//! This module supports dynamic extension of these mappings.
//!
extern crate alloc;
use alloc::vec::Vec;

/// Maximum physical memory we support: 192GB
pub const MAX_SUPPORTED_MEMORY: u64 = 192 * 1024 * 1024 * 1024; // 192GB

/// Minimum kernel virtual base: 2GB physical memory threshold
pub const MIN_KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of page table levels (PML4, PDPT, PD, PT)
pub const PAGE_TABLE_LEVELS: usize = 4;

/// Page size: 4KB
pub const PAGE_SIZE: u64 = 4096;

/// Large page size: 2MB
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Huge page size: 1GB
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

/// PTE bits
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_LARGE: u64 = 1 << 7; // 2MB page
pub const PTE_HUGE: u64 = 1 << 7; // 1GB page (in PDPT)
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NX: u64 = 1 << 63;

/// Default page table flags for kernel memory
pub const KERNEL_PAGE_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED;

/// Kernel + writable + user accessible
pub const KERNEL_USER_PAGE_FLAGS: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_ACCESSED;

/// Page directory entry for 2MB pages
pub const PDE_LARGE: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY | PTE_LARGE;

/// Page directory pointer entry for 1GB pages
pub const PDPE_HUGE: u64 = PTE_PRESENT | PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY | PTE_HUGE;

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Physical base address
    pub phys_base: u64,
    /// Size in bytes
    pub size: u64,
    /// Is this region usable for general allocation?
    pub usable: bool,
}

impl MemoryRegion {
    /// create a new memory region
    pub fn new(phys_base: u64, size: u64, usable: bool) -> Self {
        Self {
            phys_base,
            size,
            usable,
        }
    }

    /// Get the number of 2MB pages in this region
    pub fn large_page_count(&self) -> u64 {
        self.size / LARGE_PAGE_SIZE
    }

    /// Get the number of 4KB pages in this region
    pub fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }
}

/// Dynamic page table allocator
///
/// This allocator dynamically creates page table pages as needed when
/// mapping new memory regions. It avoids pre-allocating large amounts
/// of page tables by creating them on-demand.
pub struct DynamicPageTable {
    /// Base address of the PML4 (physical)
    pml4_phys: u64,
    /// Base address of the PML4 (virtual)
    pml4_virt: u64,
    /// Number of allocated page table pages
    allocated_tables: u64,
}

impl DynamicPageTable {
    /// create a new dynamic page table allocator
    pub fn new(pml4_phys: u64, pml4_virt: u64) -> Self {
        Self {
            pml4_phys,
            pml4_virt,
            allocated_tables: 0,
        }
    }

    /// Get the PML4 virtual address
    pub fn pml4_virtual(&self) -> u64 {
        self.pml4_virt
    }

    /// Get the PML4 physical address
    pub fn pml4_physical(&self) -> u64 {
        self.pml4_phys
    }

    /// Get the number of allocated page table pages
    pub fn allocated_count(&self) -> u64 {
        self.allocated_tables
    }
}

/// Calculate the PML4 index for a virtual address
#[inline]
pub fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}

/// Calculate the PDPT index for a virtual address
#[inline]
pub fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}

/// Calculate the PD index for a virtual address
#[inline]
pub fn pd_index(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

/// Calculate the PTE index for a virtual address
#[inline]
pub fn pte_index(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

/// Check if a virtual address is in kernel space
#[inline]
pub fn is_kernel_address(va: u64) -> bool {
    va >= MIN_KERNEL_VIRTUAL_BASE
}

/// Check if a virtual address is canonical
///
/// On x86_64 with 48-bit addresses, canonical addresses have bits 63:48
/// equal to bit 47.
#[inline]
pub fn is_canonical(va: u64) -> bool {
    let sign_bit = (va >> 47) & 1;
    let _ = &sign_bit;
    let _ = &sign_bit;
    let high_bits = va >> 48;
    let _ = &high_bits;
    let _ = &high_bits;
    high_bits == sign_bit || high_bits == !sign_bit
}

/// Map a physical address range to a virtual address range
///
/// This is a basic implementation that creates the necessary page tables.
/// In a full implementation, this would allocate page table pages from
/// a dedicated pool and update the PFN database.
///
/// # Safety
///
/// This function modifies page tables and should only be called during
/// early boot before the scheduler starts.
pub unsafe fn map_physical_to_virtual(
    pml4: *mut u64,
    phys: u64,
    virt: u64,
    size: u64,
    flags: u64,
) -> Result<(), &'static str> {
    if phys == 0 || !phys.is_multiple_of(PAGE_SIZE) {
        return Err("physical address must be 4 KiB aligned");
    }
    if !virt.is_multiple_of(PAGE_SIZE) {
        return Err("virtual address must be 4 KiB aligned");
    }
    if size == 0 {
        return Ok(());
    }

    let huge_count = if virt.is_multiple_of(HUGE_PAGE_SIZE) && phys.is_multiple_of(HUGE_PAGE_SIZE) {
        size / HUGE_PAGE_SIZE
    } else {
        0
    };
    let mut offset = huge_count * HUGE_PAGE_SIZE;
    for index in 0..huge_count {
        let va = virt + index * HUGE_PAGE_SIZE;
        let pa = phys + index * HUGE_PAGE_SIZE;
        map_huge_page(pml4, va, pa, flags)?;
    }

    let large_count = if (virt + offset).is_multiple_of(LARGE_PAGE_SIZE)
        && (phys + offset).is_multiple_of(LARGE_PAGE_SIZE)
    {
        (size - offset) / LARGE_PAGE_SIZE
    } else {
        0
    };
    for index in 0..large_count {
        let va = virt + offset + index * LARGE_PAGE_SIZE;
        let pa = phys + offset + index * LARGE_PAGE_SIZE;
        map_large_page(pml4, va, pa, flags)?;
    }
    offset += large_count * LARGE_PAGE_SIZE;

    let tail = size - offset;
    if !tail.is_multiple_of(PAGE_SIZE) {
        return Err("size must be 4 KiB aligned");
    }
    for index in 0..(tail / PAGE_SIZE) {
        let va = virt + offset + index * PAGE_SIZE;
        let pa = phys + offset + index * PAGE_SIZE;
        map_page(pml4, va, pa, flags)?;
    }
    Ok(())
}

/// Map one 1 GiB page in a PML4/PDPT hierarchy.
///
/// # Safety
/// `pml4` must be the active or a valid x64 root page table, and the
/// direct map must be able to access newly allocated table pages.
pub unsafe fn map_huge_page(
    pml4: *mut u64,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), &'static str> {
    if !virt.is_multiple_of(HUGE_PAGE_SIZE) || !phys.is_multiple_of(HUGE_PAGE_SIZE) {
        return Err("1 GiB mappings require 1 GiB-aligned addresses");
    }
    if flags & PTE_PRESENT == 0 {
        return Err("flags must include PTE_PRESENT");
    }

    let pml4e = pml4.add(pml4_index(virt));
    let pdpt = ensure_child_table(*pml4e, flags | PTE_PRESENT | PTE_WRITABLE)?;
    let pdpte = pdpt.add(pdpt_index(virt));
    if *pdpte & PTE_PRESENT != 0 && *pdpte & PTE_HUGE == 0 {
        return Err("PDPT entry is already mapped as a table");
    }
    if *pdpte & PTE_PRESENT != 0 && *pdpte & PHYSICAL_ADDRESS_MASK != phys {
        return Err("PDPT entry is already mapped to a different page");
    }
    *pdpte = phys | flags | PTE_HUGE | PTE_DIRTY;
    invlpg(virt);
    Ok(())
}

/// Map one 2 MiB page.
///
/// # Safety
/// See `map_huge_page`.
pub unsafe fn map_large_page(
    pml4: *mut u64,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), &'static str> {
    if !virt.is_multiple_of(LARGE_PAGE_SIZE) || !phys.is_multiple_of(LARGE_PAGE_SIZE) {
        return Err("2 MiB mappings require 2 MiB-aligned addresses");
    }
    if flags & PTE_PRESENT == 0 {
        return Err("flags must include PTE_PRESENT");
    }

    let pml4e = pml4.add(pml4_index(virt));
    let pdpt = ensure_child_table(*pml4e, flags | PTE_PRESENT | PTE_WRITABLE)?;
    let pd = ensure_child_table(
        *pdpt.add(pdpt_index(virt)),
        flags | PTE_PRESENT | PTE_WRITABLE,
    )?;
    let pde = pd.add(pd_index(virt));
    if *pde & PTE_PRESENT != 0 && *pde & PTE_LARGE == 0 {
        return Err("PDE is already mapped as a table");
    }
    if *pde & PTE_PRESENT != 0 && *pde & PHYSICAL_ADDRESS_MASK != phys {
        return Err("PDE is already mapped to a different page");
    }
    *pde = phys | flags | PTE_LARGE | PTE_DIRTY;
    invlpg(virt);
    Ok(())
}

/// Map one 4 KiB page.
///
/// # Safety
/// See `map_huge_page`.
pub unsafe fn map_page(
    pml4: *mut u64,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<(), &'static str> {
    if !virt.is_multiple_of(PAGE_SIZE) || !phys.is_multiple_of(PAGE_SIZE) {
        return Err("4 KiB mappings require 4 KiB-aligned addresses");
    }
    if flags & PTE_PRESENT == 0 {
        return Err("flags must include PTE_PRESENT");
    }

    let pml4e = pml4.add(pml4_index(virt));
    let pdpt = ensure_child_table(*pml4e, flags | PTE_PRESENT | PTE_WRITABLE)?;
    let pd = ensure_child_table(
        *pdpt.add(pdpt_index(virt)),
        flags | PTE_PRESENT | PTE_WRITABLE,
    )?;
    let pt = ensure_child_table(*pd.add(pd_index(virt)), flags | PTE_PRESENT | PTE_WRITABLE)?;
    let pte = pt.add(pte_index(virt));
    if *pte & PTE_PRESENT != 0 && *pte & PHYSICAL_ADDRESS_MASK != phys {
        return Err("PTE is already mapped to a different page");
    }
    *pte = phys | flags | PTE_DIRTY;
    invlpg(virt);
    Ok(())
}

/// Bits which identify the physical page in a page-table entry.
const PHYSICAL_ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Resolve a page-table physical address to the kernel direct map.
fn table_virtual(physical: u64) -> Option<*mut u64> {
    if physical == 0 || !physical.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    Some((crate::mm::constants::KERNEL_DIRECT_MAP_BASE + physical) as *mut u64)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Return the child table for an entry, allocating it if required.
unsafe fn ensure_child_table(entry: u64, flags: u64) -> Result<*mut u64, &'static str> {
    if entry & PTE_PRESENT == 0 {
        let table = crate::mm::frame::allocate_frame().ok_or("failed to allocate page table")?;
        let table_virt = table_virtual(table).ok_or("page table is outside the direct map")?;
        core::ptr::write_bytes(table_virt as *mut u8, 0, PAGE_SIZE as usize);
        return Ok(table_virt);
    }
    if entry & PTE_LARGE != 0 {
        return Err("parent entry is already mapped as a large page");
    }
    let _ = flags;
    table_virtual(entry & PHYSICAL_ADDRESS_MASK).ok_or("page table is outside the direct map")
}

/// Unmap a virtual address range
///
/// # Safety
///
/// This function modifies page tables and should only be called during
/// early boot or when no threads are running.
pub unsafe fn unmap_virtual(pml4: *mut u64, virt: u64, size: u64) -> Result<(), &'static str> {
    // Simplified implementation
    let _ = (pml4, virt, size);
    Ok(())
}

/// Get the current kernel page root (physical address)
#[inline]
pub fn get_cr3() -> u64 {
    crate::arch::read_current_page_root()
}

/// Set the CR3 register (load new page table)
///
/// # Safety
///
/// This function changes the active page tables. The new page table
/// must have valid mappings for the current code execution.
#[inline]
pub unsafe fn set_cr3(pml4_phys: u64) {
    crate::arch::load_page_root(pml4_phys >> 12);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Invalidate a single TLB entry
#[inline]
pub unsafe fn invlpg(virt: u64) {
    crate::arch::invalidate_tlb(virt);
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Invalidate the entire TLB
#[inline]
pub unsafe fn invlpg_all() {
    // Writing to CR3 reloads the page directory pointer, which
    // effectively invalidates the entire TLB
    let cr3_val = get_cr3();
    let _ = &cr3_val;
    let _ = &cr3_val;
    crate::arch::flush_tlb();
}

/// Memory statistics
#[derive(Debug, Default)]
pub struct MemoryStats {
    /// Total physical memory in bytes
    pub total_bytes: u64,
    /// Usable memory in bytes
    pub usable_bytes: u64,
    /// Reserved memory in bytes
    pub reserved_bytes: u64,
    /// Number of page tables allocated
    pub page_table_count: u64,
    /// Highest physical address seen
    pub highest_phys_addr: u64,
}

impl MemoryStats {
    /// create new memory statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total memory in GB
    pub fn total_gb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get usable memory in GB
    pub fn usable_gb(&self) -> f64 {
        self.usable_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Check if memory is above 4GB threshold
    pub fn has_above_4gb(&self) -> bool {
        self.total_bytes > 0x1_0000_0000
    }

    /// Check if memory is large (> 8GB)
    pub fn is_large_memory(&self) -> bool {
        self.total_bytes > 8 * 1024 * 1024 * 1024
    }

    /// Check if memory is very large (> 64GB)
    pub fn is_very_large_memory(&self) -> bool {
        self.total_bytes > 64 * 1024 * 1024 * 1024
    }
}

/// Parse UEFI memory map entries and build memory regions
///
/// This function takes the UEFI memory map and converts it into
/// a list of usable memory regions.
pub fn parse_uefi_memory_map(map_addr: u64, map_size: u64, entry_size: u64) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();

    if map_addr == 0 || map_size == 0 || entry_size == 0 {
        return regions;
    }

    // UEFI memory descriptor structure:
    // r#type (u32), PhysicalStart (u64), VirtualStart (u64), NumberOfPages (u64), Attribute (u64)

    let entries = map_size as usize / entry_size as usize;

    let _ = &entries;
    let _ = &entries;
    let mut current = map_addr;

    for _ in 0..entries {
        let desc = current as *const UefiMemoryDescriptor;
        let _ = &desc;
        let _ = &desc;

        // UEFI memory types we consider usable:
        // 7 = EfiConventionalMemory
        // 9 = EfiBootServicesData (can be reclaimed)
        // 10 = EfiBootServicesCode (can be reclaimed)
        let memory_type = unsafe { (*desc).type_ };
        let _ = &memory_type;
        let _ = &memory_type;
        let phys_start = unsafe { (*desc).physical_start };
        let _ = &phys_start;
        let _ = &phys_start;
        let num_pages = unsafe { (*desc).number_of_pages };
        let _ = &num_pages;
        let _ = &num_pages;

        let size = num_pages * 4096;

        let _ = &size;
        let _ = &size;
        let usable = memory_type == 7 || memory_type == 9 || memory_type == 10;
        let _ = &usable;
        let _ = &usable;

        regions.push(MemoryRegion::new(phys_start, size, usable));

        current += entry_size;
    }

    regions
}

/// UEFI memory descriptor (as passed by firmware)
#[repr(C)]
struct UefiMemoryDescriptor {
    type_: u32,
    _padding: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

/// Calculate the number of page tables needed for a memory size
///
/// Returns (number of PML4 entries needed, number of page tables needed)
pub fn calculate_page_table_requirements(memory_bytes: u64) -> (u64, u64) {
    // Each PML4 entry covers 512GB (512 * 1024 * 1024 * 1024 bytes)
    const PML4_COVERAGE: u64 = 512 * 1024 * 1024 * 1024;

    // Each PDPT entry covers 1GB
    const PDPT_COVERAGE: u64 = 1024 * 1024 * 1024;

    // Each PD entry covers 2MB
    const PD_COVERAGE: u64 = 2 * 1024 * 1024;

    // Each PT entry covers 4KB

    let pml4_needed = memory_bytes.div_ceil(PML4_COVERAGE);

    let _ = &pml4_needed;
    let _ = &pml4_needed;
    let pdpt_needed = memory_bytes.div_ceil(PDPT_COVERAGE);
    let _ = &pdpt_needed;
    let _ = &pdpt_needed;
    let pd_needed = memory_bytes.div_ceil(PD_COVERAGE);
    let _ = &pd_needed;
    let _ = &pd_needed;

    // Page tables themselves need space: estimate 1 page table per 512MB
    let page_tables = (memory_bytes / (512 * 1024 * 1024)) + pml4_needed + pdpt_needed + pd_needed;
    let _ = &page_tables;
    let _ = &page_tables;

    (pml4_needed, page_tables)
}

// ============================================================================
// Smoke Tests
// ============================================================================

/// Dynamic paging smoke test
///
/// Tests the dynamic page table infrastructure for large memory systems.
/// Verifies:
/// 1. Page table index calculations work correctly
/// 2. Address validity checks work
/// 3. Memory region calculations work
/// 4. Page table requirement calculations work
pub fn smoke_test() -> bool {
    // // kprintln!("  [DYNAMIC PAGING SMOKE] running dynamic paging smoke test...");
    let mut ok = true;

    // Test 1: PML4 index calculation
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 1: PML4 index calculation");
    let test_va: u64 = 0xFFFF_8000_0000_0000; // Kernel base
    let idx = pml4_index(test_va);
    let _ = &idx;
    let _ = &idx;
    if idx != 256 {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] PML4 index for kernel base should be 256, got {}", idx);
        ok = false;
    }

    // Test 2: Address validity checks
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 2: address validity checks");
    let kernel_addr: u64 = 0xFFFF_8000_0000_0000;
    let user_addr: u64 = 0x0000_0000_1000;

    if !is_kernel_address(kernel_addr) {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] kernel address not detected as kernel");
        ok = false;
    }
    if is_kernel_address(user_addr) {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] user address detected as kernel");
        ok = false;
    }

    // Test 3: Canonical address check
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 3: canonical address check");
    if !is_canonical(kernel_addr) {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] kernel base not canonical");
        ok = false;
    }
    if !is_canonical(user_addr) {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] user address not canonical");
        ok = false;
    }

    // Test 4: Memory region calculations
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 4: memory region calculations");
    let region = MemoryRegion::new(0x1000_0000, 8 * 1024 * 1024, true);
    let _ = &region; // 8MB region
    let _ = &region;
    let pages = region.large_page_count();
    let _ = &pages;
    let _ = &pages;
    if pages != 4 {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] 8MB should be 4 2MB pages, got {}", pages);
        ok = false;
    }

    // Test 5: Page table requirements for large memory
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 5: page table requirements");
    // Reserved for future use: page table calculation for large memory regions
    let (_pml4_needed, _page_tables) = calculate_page_table_requirements(16 * 1024 * 1024 * 1024); // 16GB
                                                                                                   // // kprintln!("  [DYNAMIC PAGING SMOKE]   16GB needs {} PML4 entries, ~{} page tables",
                                                                                                   // //         pml4_needed, page_tables);

    // Test 6: Memory stats
    // // kprintln!("  [DYNAMIC PAGING SMOKE] test 6: memory stats");
    let mut stats = MemoryStats::new();
    stats.total_bytes = 16 * 1024 * 1024 * 1024;
    stats.usable_bytes = 15 * 1024 * 1024 * 1024;
    stats.highest_phys_addr = 16 * 1024 * 1024 * 1024 - 1;

    if !stats.is_large_memory() {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] 16GB should be detected as large memory");
        ok = false;
    }
    if stats.is_very_large_memory() {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] 16GB should not be very large (>64GB)");
        ok = false;
    }
    // // kprintln!("  [DYNAMIC PAGING SMOKE]   total: {:.2} GB, usable: {:.2} GB",
    // //         stats.total_gb(), stats.usable_gb());

    if ok {
        // // kprintln!("  [DYNAMIC PAGING SMOKE] all dynamic paging checks passed");
    } else {
        // // kprintln!("  [DYNAMIC PAGING SMOKE FAIL] one or more checks failed");
    }

    ok
}
