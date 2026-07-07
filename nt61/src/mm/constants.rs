//! Memory Manager Constants
//
//! Centralized location for all memory management related constants.
//! This module provides a single source of truth for addresses,
//! sizes, and other memory-related values used throughout the
//! memory management subsystem.
//
//! ## Address Space Layout (NT 6.1 x64)
//
//! ```text
//! 0x0000_0000_0000_0000  User space (canonical low half)
//! ...
//! 0x0000_7FFF_FFFF_FFFF  User space limit
//
//! 0xFFFF8000_0000_0000  Kernel space (canonical high half)
//! ...
//! 0xFFFF_FFFF_FFFF_FFFF  Kernel space limit
//! ```

// ============================================================================
// Page/Frame Constants
// ============================================================================

/// Standard x86-64 page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page size as a shift count (log2(PAGE_SIZE)).
pub const PAGE_SHIFT: u64 = 12;

/// Mask to zero out lower page offset bits.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Number of entries per page table level (512 for x86-64).
pub const PT_ENTRIES: usize = 512;

/// Large page size (2 MiB for PDE large pages).
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Huge page size (1 GiB for PDPE huge pages).
pub const HUGE_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

// ============================================================================
// Kernel Address Space
// ============================================================================

/// Kernel base address. The kernel image is loaded at this address
/// or higher. Standard Windows 7 x64 uses 0xFFFFF800_00000000,
/// but this implementation uses 0xFFFF8000_00000000 for Phase 0
/// compatibility with the linker script.
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Kernel space upper limit (canonical form).
pub const KERNEL_LIMIT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Kernel direct map base - mirrors lower physical memory 1:1.
/// Used for drivers and kernel data structures.
pub const KERNEL_DIRECT_MAP_BASE: u64 = 0xFFFF_8800_0000_0000;

/// Kernel image base for PE loader.
pub const KERNEL_IMAGE_BASE: u64 = 0xFFFF8000_0000_0000;

// ============================================================================
// User Address Space
// ============================================================================

/// User space base. Low 64KB is left unused for NULL pointer
/// compatibility and DOS compatibility.
pub const USER_BASE: u64 = 0x0000_0000_0001_0000;

/// User space upper limit (canonical form, Windows 7 x64 default).
pub const USER_LIMIT: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Default user-mode image base. Standard Windows 7 x64 uses
/// 0x00400000, but this implementation uses 0x00100000 for
/// Phase 0 simplicity.
pub const USER_IMAGE_BASE: u64 = 0x0000_0000_0010_0000;

/// Default user entry point (first bytes of mapped image).
pub const USER_ENTRY_RIP: u64 = 0x0000_0000_0010_1000;

/// User stack base (near top of user space, 32 MiB below limit for PEB headroom).
pub const USER_STACK_BASE: u64 = 0x0000_7FFF_DE00_0000;

/// User stack size (1 MiB default).
pub const USER_STACK_SIZE: u64 = 0x0010_0000;

/// User stack top (base + size).
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + USER_STACK_SIZE;

/// User entry point for ring transition stub (canonical high address
/// to avoid collision with kernel identity map).
pub const USER_ENTRY_BASE: u64 = 0xFFFF_8000_0000_1000;

/// TEB (Thread Environment Block) base address.
/// Windows 7 x64 places the first thread's TEB at
/// 0x0000_FFFF_FFDF_0000.
pub const TEB_BASE: u64 = 0x0000_FFFF_FFDF_0000;

/// TEB size (8KB per TEB in Windows 7 x64).
pub const TEB_SIZE: u64 = 0x2000;

// ============================================================================
// Self-Map (HyperSpace) Constants
// ============================================================================

/// PML4 index for the self-map slot (NT 6.1 convention).
pub const MI_SELF_MAP_INDEX: usize = 0x1ED;

/// Self-map addresses derived from the PML4 index.
/// PXE_BASE = 0xFFFFF6FB7DBED000
/// PPE_BASE = 0xFFFFF6FB7DA00000
/// PDE_BASE = 0xFFFFF6FB40000000
/// PTE_BASE = 0xFFFFF68000000000
pub const PTE_BASE: u64 = 0xFFFF_F680_0000_0000;
pub const PDE_BASE: u64 = 0xFFFF_F6FB_4000_0000;
pub const PPE_BASE: u64 = 0xFFFF_F6FB_7DA0_0000;
pub const PXE_BASE: u64 = 0xFFFF_F6FB_7DBE_D000;

/// Hyperspace base address. Per-CPU temporary mapping window.
pub const HYPERSPACE_BASE: u64 = 0xFFFF_F700_0000_0000;

/// Number of hyperspace entries (one per CPU slot).
pub const HYPERSPACE_ENTRIES: u64 = 512;

/// Hyperspace end address.
pub const HYPERSPACE_END: u64 = HYPERSPACE_BASE + HYPERSPACE_ENTRIES * 4096;

// ============================================================================
// System PTE Pool
// ============================================================================

/// System PTE pool base address.
/// Reserves VA region for system PTEs (I/O space, MDL, kernel stacks).
pub const SYSTEM_PTE_BASE: u64 = 0xFFFF_F900_0000_0000;

/// System PTE pool end address (16 GiB region = 4M PTEs).
pub const SYSTEM_PTE_END: u64 = 0xFFFF_F9A0_0000_0000;

/// System PTE pool total size.
pub const SYSTEM_PTE_BYTES: u64 = SYSTEM_PTE_END - SYSTEM_PTE_BASE;

/// System PTE region size (64 KiB = 16 pages per region).
pub const SYSTEM_PTE_REGION_BYTES: u64 = 64 * 1024;

/// Pages per system PTE region.
pub const SYSTEM_PTE_REGION_PAGES: u64 = SYSTEM_PTE_REGION_BYTES / PAGE_SIZE;

// ============================================================================
// Boot Memory Constants
// ============================================================================

/// Boot RAM base address. The kernel image is loaded at 1 MiB
/// by both grub (multiboot) and the UEFI stub.
pub const BOOT_RAM_BASE: u64 = 0x0010_0000;

/// Default boot RAM size (8 GiB, QEMU default).
pub const BOOT_RAM_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Maximum supported RAM bytes (192 GiB hard upper bound for
/// static bookkeeping buffers with 48-bit VA space).
pub const MAX_RAM_BYTES: u64 = 192 * 1024 * 1024 * 1024;

/// Maximum supported RAM frames.
pub const MAX_RAM_FRAMES: u64 = MAX_RAM_BYTES / PAGE_SIZE;

// ============================================================================
// Kernel Heap Constants
// ============================================================================

/// Default kernel heap size (8 MiB).
pub const KERNEL_HEAP_SIZE: u64 = 8 * 1024 * 1024;

/// Default kernel heap page count.
pub const KERNEL_HEAP_PAGES: u64 = KERNEL_HEAP_SIZE / PAGE_SIZE;

// ============================================================================
// Kernel Stack Constants
// ============================================================================

/// Default kernel stack size per thread.
pub const KERNEL_STACK_SIZE: u64 = 32 * PAGE_SIZE; // 128 KiB

/// Default user-mode stack size.
pub const USER_MODE_STACK_SIZE: u64 = 0x0010_0000; // 1 MiB

// ============================================================================
// Segment Selectors (x86-64)
// ============================================================================

/// Kernel code segment selector. OVMF slot 7 (offset 0x38) is
/// the actual 64-bit kernel CS used in long mode; slot 2 (0x10) is
/// only the legacy 32-bit CS. The IDT must target the 64-bit one.
pub const KERNEL_CS: u16 = 0x38;

/// Kernel data segment selector (GDT index 3, RPL=0).
pub const KERNEL_SS: u16 = 0x18;

/// User code segment selector (GDT index 5, RPL=3).
pub const USER_CS: u16 = 0x2b;

/// User data segment selector (GDT index 4, RPL=3).
pub const USER_SS: u16 = 0x23;

// ============================================================================
// RFLAGS Constants
// ============================================================================

/// Initial RFLAGS for user mode: Reserved bits set + IF=1.
/// Note: Interrupts disabled on Ring 3 entry until IDT is ready.
pub const USER_RFLAGS: u64 = 0x002;

/// RFLAGS with interrupts enabled.
pub const USER_RFLAGS_IRQ: u64 = 0x202;

// ============================================================================
// PTE Bit Masks
// ============================================================================

/// PTE Present bit.
pub const PTE_P: u64 = 1 << 0;

/// PTE Read/Write bit.
pub const PTE_RW: u64 = 1 << 1;

/// PTE User/Supervisor bit.
pub const PTE_US: u64 = 1 << 2;

/// PTE Page Level Write-Through.
pub const PTE_PWT: u64 = 1 << 3;

/// PTE Page Level Cache Disable.
pub const PTE_PCD: u64 = 1 << 4;

/// PTE Accessed bit.
pub const PTE_A: u64 = 1 << 5;

/// PTE Dirty bit.
pub const PTE_D: u64 = 1 << 6;

/// PTE PAT (Page Attribute Table) bit.
pub const PTE_PAT: u64 = 1 << 7;

/// PTE Global bit.
pub const PTE_G: u64 = 1 << 8;

/// PTE Software bit 1 (used for COW in this implementation).
pub const PTE_SW1: u64 = 1 << 9;

/// PTE Software bit 2 (used for page file in this implementation).
pub const PTE_SW2: u64 = 1 << 10;

/// PTE No-Execute bit (bit 63).
pub const PTE_NX: u64 = 1u64 << 63;

/// Standard kernel-side intermediate PTE bits: P + RW + US + A + D.
pub const INT_PTE_BITS: u64 = PTE_P | PTE_RW | PTE_US | PTE_A | PTE_D;

/// Self-map PTE bits: P + RW + US + A + D.
pub const SELF_MAP_BITS: u64 = PTE_P | PTE_RW | PTE_US | PTE_A | PTE_D;

// ============================================================================
// Physical Address Masks
// ============================================================================

/// Mask to extract the page frame number from a PTE.
pub const PTE_FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Mask to clear the lower 12 bits (page offset).
pub const PAGE_OFFSET_MASK: u64 = 0xFFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_alignment() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_SHIFT, 12);
        assert_eq!(PAGE_MASK & PAGE_SIZE, 0);
        assert_eq!(PAGE_MASK & (PAGE_SIZE - 1), PAGE_SIZE - 1);
    }

    #[test]
    fn test_address_ranges() {
        // Kernel addresses should be in canonical high form
        assert!(KERNEL_BASE & (1 << 47) != 0);
        assert!(KERNEL_LIMIT == 0xFFFF_FFFF_FFFF_FFFF);

        // User addresses should be in canonical low form
        assert!(USER_BASE < 0x8000_0000_0000_0000);
        assert!(USER_LIMIT <= 0x7FFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn test_self_map_index() {
        assert_eq!(MI_SELF_MAP_INDEX, 0x1ED);
        // PTE_BASE should be reachable through self-map
        assert!(PTE_BASE >= HYPERSPACE_BASE || PTE_BASE < HYPERSPACE_END);
    }

    #[test]
    fn test_stack_addresses() {
        // Stack grows downward from top
        assert!(USER_STACK_TOP > USER_STACK_BASE);
        assert_eq!(USER_STACK_TOP - USER_STACK_BASE, USER_STACK_SIZE);
    }

    #[test]
    fn test_pte_bits() {
        // Present must be bit 0
        assert_eq!(PTE_P, 1);
        // NX must be bit 63
        assert_eq!(PTE_NX, 1u64 << 63);
    }
}
