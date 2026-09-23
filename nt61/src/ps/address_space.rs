//! Process Address Space Management
//!
//! Implements user-mode address space initialization for NT processes.
//! Handles PEB/TEB mapping, user stack creation, and VAD tree management.

use crate::mm::vad::{VadTree, VadType, VadEntry, VadProtection, VadFlags};
use crate::mm::pfn;
use crate::mm::vas;
use crate::mm::pool;
use core::ptr::null_mut;

/// User stack base address (Windows 7 x64 layout)
pub const USER_STACK_BASE: u64 = 0x0000_0030_0000_0000;
pub const USER_STACK_SIZE: u64 = 0x100000; // 1MB default stack

/// PEB base address (Windows 7 x64 layout)
pub const PEB_BASE: u64 = 0x0000_007F_FFFF_0000;

/// TEB base address (Windows 7 x64 layout)
pub const TEB_BASE: u64 = 0x0000_007F_FFFD_F000;

/// Process address space structure
pub struct ProcessAddressSpace {
    /// Physical address of PML4 page table
    pub pml4_phys: u64,

    /// VAD tree for tracking virtual address regions
    pub vad_tree: VadTree,

    /// User stack base address
    pub user_stack_base: u64,

    /// User stack size in bytes
    pub user_stack_size: u64,

    /// PEB virtual address
    pub peb_address: u64,

    /// TEB virtual address
    pub teb_address: u64,

    /// Image base address (PE load address)
    pub image_base: u64,

    /// Image size in bytes
    pub image_size: u64,
}

impl ProcessAddressSpace {
    /// Create a new process address space
    pub fn new() -> Option<Self> {
        // 1. Allocate a new PML4 for the user process
        let pml4_phys = vas::create_user_address_space()?;

        Some(Self {
            pml4_phys,
            vad_tree: VadTree::new(),
            user_stack_base: USER_STACK_BASE,
            user_stack_size: USER_STACK_SIZE,
            peb_address: PEB_BASE,
            teb_address: TEB_BASE,
            image_base: 0,
            image_size: 0,
        })
    }

    /// Map the user stack
    pub fn map_user_stack(&mut self) -> Result<(), ()> {
        // Map user stack with RW permissions
        if vas::map_user_pages(
            self.pml4_phys,
            self.user_stack_base,
            self.user_stack_size,
            vas::PTE_RW | vas::PTE_US, // User, Read/Write
        ) != vas::MmStatus::Ok {
            return Err(());
        }

        // Allocate and insert VAD entry for stack
        let vad = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<VadEntry>()) as *mut VadEntry;
        if vad.is_null() {
            return Err(());
        }

        unsafe {
            core::ptr::write(vad, VadEntry::new());
            (*vad).starting_vpn = self.user_stack_base >> 12;
            (*vad).ending_vpn = (self.user_stack_base + self.user_stack_size - 1) >> 12;
            (*vad).vad_type = VadType::VadNone; // Stack uses VadNone type
            (*vad).protection = VadProtection::READWRITE;
            (*vad).flags = VadFlags::SEC_COMMIT;
        }

        let _ = self.vad_tree.insert(unsafe { &mut *vad });

        Ok(())
    }

    /// Map the PEB (Process Environment Block)
    pub fn map_peb(&mut self) -> Result<(), ()> {
        // Map PEB with RW permissions
        if vas::map_user_pages(
            self.pml4_phys,
            self.peb_address,
            0x1000,
            vas::PTE_RW | vas::PTE_US,
        ) != vas::MmStatus::Ok {
            return Err(());
        }

        // Allocate and insert VAD entry for PEB
        let vad = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<VadEntry>()) as *mut VadEntry;
        if vad.is_null() {
            return Err(());
        }

        unsafe {
            core::ptr::write(vad, VadEntry::new());
            (*vad).starting_vpn = self.peb_address >> 12;
            (*vad).ending_vpn = (self.peb_address + 0x1000 - 1) >> 12;
            (*vad).vad_type = VadType::VadNone;
            (*vad).protection = VadProtection::READWRITE;
            (*vad).flags = VadFlags::SEC_COMMIT;
        }

        let _ = self.vad_tree.insert(unsafe { &mut *vad });

        Ok(())
    }

    /// Map the TEB (Thread Environment Block)
    pub fn map_teb(&mut self) -> Result<(), ()> {
        // Map TEB with RW permissions
        if vas::map_user_pages(
            self.pml4_phys,
            self.teb_address,
            0x1000,
            vas::PTE_RW | vas::PTE_US,
        ) != vas::MmStatus::Ok {
            return Err(());
        }

        // Allocate and insert VAD entry for TEB
        let vad = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<VadEntry>()) as *mut VadEntry;
        if vad.is_null() {
            return Err(());
        }

        unsafe {
            core::ptr::write(vad, VadEntry::new());
            (*vad).starting_vpn = self.teb_address >> 12;
            (*vad).ending_vpn = (self.teb_address + 0x1000 - 1) >> 12;
            (*vad).vad_type = VadType::VadNone;
            (*vad).protection = VadProtection::READWRITE;
            (*vad).flags = VadFlags::SEC_COMMIT;
        }

        let _ = self.vad_tree.insert(unsafe { &mut *vad });

        Ok(())
    }

    /// Map a memory region for the PE image
    pub fn map_image(&mut self, base: u64, size: u64) -> Result<(), ()> {
        // Align size to page boundary
        let aligned_size = (size + 0xFFF) & !0xFFF;

        // Map image region with RW permissions (will set execute later per-section)
        if vas::map_user_pages(
            self.pml4_phys,
            base,
            aligned_size,
            vas::PTE_RW | vas::PTE_US,
        ) != vas::MmStatus::Ok {
            return Err(());
        }

        // Allocate and insert VAD entry for image
        let vad = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<VadEntry>()) as *mut VadEntry;
        if vad.is_null() {
            return Err(());
        }

        unsafe {
            core::ptr::write(vad, VadEntry::new());
            (*vad).starting_vpn = base >> 12;
            (*vad).ending_vpn = (base + aligned_size - 1) >> 12;
            (*vad).vad_type = VadType::VadImage;
            (*vad).protection = VadProtection::EXECUTE_READWRITE;
            (*vad).flags = VadFlags::SEC_COMMIT;
        }

        let _ = self.vad_tree.insert(unsafe { &mut *vad });

        // Record image base and size
        self.image_base = base;
        self.image_size = aligned_size;

        Ok(())
    }

    /// Get stack top (initial RSP)
    pub fn get_stack_top(&self) -> u64 {
        self.user_stack_base + self.user_stack_size
    }

    /// Clean up the address space (called on process termination)
    pub fn cleanup(&mut self) {
        // Unmap user stack
        let _ = vas::unmap_user_pages(
            self.pml4_phys,
            self.user_stack_base,
            self.user_stack_size,
        );

        // Unmap PEB
        let _ = vas::unmap_user_pages(
            self.pml4_phys,
            self.peb_address,
            0x1000,
        );

        // Unmap TEB
        let _ = vas::unmap_user_pages(
            self.pml4_phys,
            self.teb_address,
            0x1000,
        );

        // Unmap image
        if self.image_base != 0 && self.image_size != 0 {
            let _ = vas::unmap_user_pages(
                self.pml4_phys,
                self.image_base,
                self.image_size,
            );
        }

        // Free the PML4
        pfn::free_pfn(self.pml4_phys >> 12);
    }
}

impl Drop for ProcessAddressSpace {
    fn drop(&mut self) {
        self.cleanup();
    }
}
