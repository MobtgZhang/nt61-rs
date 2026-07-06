//! Virtual Memory Management
//
//! Virtual address space management and page mapping.
//
//! Implements an NT-style virtual memory manager with a global
//! `VmState` describing the kernel/user address space layout. The
//! actual hardware page table is managed by `arch::paging` - this
//! file only deals with the policy (where to allocate from, what
//! protection bits to use) and the bookkeeping that user-mode address
//! ranges need.
//
//! Address space layout (matches the Windows 7 default):
//
//! ```text
//!   0x0000_0000_0000_0000  User space (canonical low half)
//!   ...
//!   0x0000_7FFF_FFFF_FFFF  User space limit
//
//!   0xFFFF_8000_0000_0000  Kernel space (canonical high half)
//!   ...
//!   0xFFFF_FFFF_FFFF_FFFF  Kernel space limit
//! ```
//
//! The kernel has a 4 MiB "direct map" region that mirrors the low
//! 4 GiB of physical memory 1:1 (useful for drivers), and a
//! separately-allocated region for the kernel image itself, the
//! kernel heap, and the kernel stack per CPU.

// Architecture-specific paging helpers live in the per-arch submodules.
// We do a cfg-gated re-export so call-sites do not have to repeat the
// cfg attribute everywhere.
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging as paging_impl;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::paging as paging_impl;

#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::paging as paging_impl;

#[cfg(target_arch = "loongarch64")]
use crate::arch::loongarch64::paging as paging_impl;

use crate::ke::sync::Spinlock;

pub use self::MemFlags as PageFlags;

// Import memory management constants from single source of truth.
pub use crate::mm::constants::{PAGE_SIZE, PAGE_SHIFT, PAGE_MASK, KERNEL_BASE, USER_BASE, USER_LIMIT, KERNEL_LIMIT};

/// Memory protection flags - matches Windows 7's `PAGE_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemFlags(u32);

impl core::ops::BitOr for MemFlags {
    type Output = MemFlags;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl MemFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    /// Raw bit value. Useful for handing the protection bits to the
    /// architecture-specific `paging::map_page` helper.
    pub const fn bits(self) -> u32 { self.0 }
    pub const EXECUTE: Self = Self(1 << 2);
    pub const USER: Self = Self(1 << 3);
    pub const GUARD: Self = Self(1 << 4);
    pub const NO_CACHE: Self = Self(1 << 5);
    pub const WRITE_COMBINE: Self = Self(1 << 6);
    pub const LARGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    pub fn as_u32(&self) -> u32 {
        self.0
    }
    pub fn from_u32(val: u32) -> Self {
        Self(val)
    }
    pub fn with_read(&self) -> Self {
        Self(self.0 | Self::READ.0)
    }
    pub fn with_write(&self) -> Self {
        Self(self.0 | Self::WRITE.0)
    }
    pub fn with_execute(&self) -> Self {
        Self(self.0 | Self::EXECUTE.0)
    }
    pub fn with_user(&self) -> Self {
        Self(self.0 | Self::USER.0)
    }
}

/// Memory allocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationType {
    Commit = 0x1000,
    Reserve = 0x2000,
    Decommit = 0x4000,
    Release = 0x8000,
    Free = 0x10000,
    Reset = 0x80000,
    TopDown = 0x100000,
    Physical = 0x400000,
}

/// Memory region info.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub region_size: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
}

pub mod state {
    pub const MEM_FREE: u32 = 0x10000;
    pub const MEM_RESERVED: u32 = 0x20000;
    pub const MEM_COMMIT: u32 = 0x1000;
}

pub mod mem_type {
    pub const MEM_PRIVATE: u32 = 0x20000;
    pub const MEM_MAPPED: u32 = 0x40000;
    pub const MEM_IMAGE: u32 = 0x1000000;
}

/// Kernel address space layout.
pub struct VmState {
    pub kernel_base: u64,
    pub user_base: u64,
    pub user_limit: u64,
    pub kernel_limit: u64,
    /// Next free kernel virtual address for `allocate_virtual`.
    pub next_alloc_base: u64,
    /// Direct-map base (mirrors the lower 4 GiB of physical memory).
    pub direct_map_base: u64,
    /// Next free direct-map address.
    pub direct_map_next: u64,
}

impl VmState {
    pub const fn new() -> Self {
        Self {
            kernel_base: KERNEL_BASE,
            user_base: USER_BASE,
            user_limit: USER_LIMIT,
            kernel_limit: KERNEL_LIMIT,
            next_alloc_base: 0xFFFF_8000_0040_0000,
            direct_map_base: 0xFFFF_8800_0000_0000,
            direct_map_next: 0xFFFF_8800_0000_0000,
        }
    }
}

pub(crate) static VM_STATE: Spinlock<VmState> = Spinlock::new(VmState::new());

/// Initialise VM subsystem.
pub fn init() {
    // // kprintln!("    Virtual memory manager initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      Kernel base: 0xFFFF800000000000")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      User base:   0x0000000000000000")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // The low-level paging bring-up is per-arch; today only x86_64
    // exposes a callable `init()`. Other targets do their paging
    // setup in `arch::<arch>::init_hardware()` before this point.
    #[cfg(target_arch = "x86_64")]
    unsafe { paging_impl::init() };
}

/// Allocate a region of virtual address space. Returns the base
/// address on success.
pub fn allocate_virtual(base: u64, size: u64, alloc_type: AllocationType, flags: MemFlags) -> Result<u64, ()> {
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let mut state = VM_STATE.lock();
    let mut addr = if base == 0 {
        state.next_alloc_base
    } else {
        base
    };
    addr = (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    match alloc_type {
        AllocationType::Commit | AllocationType::Reserve => {
            if addr.checked_add(aligned_size).is_none() || addr + aligned_size > state.kernel_limit {
                return Err(());
            }
            state.next_alloc_base = addr + aligned_size;
            // // kprintln!("      Allocated VA region 0x{:x} + 0x{:x}", addr, aligned_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            Ok(addr)
        }
        _ => {
            // Decommit / Free / Reset - would walk the VAD tree.
            let _ = flags;
            Ok(addr)
        }
    }
}

/// Reserve virtual memory (no physical backing).
pub fn reserve(base: u64, size: u64) -> Result<u64, ()> {
    allocate_virtual(base, size, AllocationType::Reserve, MemFlags::NONE)
}

/// Commit virtual memory (allocate physical pages and map them in).
pub fn commit(base: u64, size: u64) -> Result<u64, ()> {
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = aligned_size / PAGE_SIZE;

    for i in 0..page_count {
        let va = base + i * PAGE_SIZE;
        // Allocate one PFN per page and map it. This goes through
        // the new PFN database, not the legacy buddy.
        let pfn_no = match crate::mm::pfn::allocate_pfn() {
            Some(p) => p,
            None => return Err(()),
        };
        let pa = crate::mm::pte::pfn_to_phys(pfn_no);
        let bits: u64 = (MemFlags::READ | MemFlags::WRITE).bits() as u64;
        paging_impl::map_page(va, pa, bits);
    }
    Ok(base)
}

/// Free virtual memory (unmap and release physical pages).
pub fn free(base: u64, size: u64) -> Result<(), ()> {
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    for i in 0..(aligned_size / PAGE_SIZE) {
        let va = base + i * PAGE_SIZE;
        if let Some(phys) = paging_impl::unmap_page(va) {
            crate::mm::pfn::free_pfn(crate::mm::pfn::phys_to_pfn(phys));
        }
    }
    Ok(())
}

/// Decommit virtual memory (unmap but keep the VA reservation).
pub fn decommit(base: u64, size: u64) -> Result<(), ()> {
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    for i in 0..(aligned_size / PAGE_SIZE) {
        let va = base + i * PAGE_SIZE;
        paging_impl::unmap_page(va);
    }
    Ok(())
}

/// Query information about a VA range.
pub fn query(base: u64) -> Option<MemoryRegion> {
    Some(MemoryRegion {
        base_address: base,
        region_size: PAGE_SIZE,
        allocation_base: base,
        allocation_protect: (MemFlags::READ | MemFlags::WRITE).as_u32(),
        state: state::MEM_COMMIT,
        protect: (MemFlags::READ | MemFlags::WRITE).as_u32(),
        type_: mem_type::MEM_PRIVATE,
    })
}

/// Map a single page.
pub fn map_page(va: u64, pa: u64, flags: MemFlags) {
    paging_impl::map_page(va, pa, flags.bits() as u64);
}

/// Unmap a single page.
pub fn unmap_page(va: u64) -> Option<u64> {
    paging_impl::unmap_page(va)
}

/// Translate a virtual address to a physical one.
pub fn virt_to_phys(virt: u64) -> Option<u64> {
    paging_impl::translate_virt(virt)
}

/// Get kernel virtual base.
pub fn get_kernel_base() -> u64 {
    VM_STATE.lock().kernel_base
}

/// Get user space base.
pub fn get_user_base() -> u64 {
    VM_STATE.lock().user_base
}

/// Map a physical address into the direct-map region.
pub fn direct_map_phys(phys: u64, size: u64) -> Result<u64, ()> {
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = aligned_size / PAGE_SIZE;
    // Use the system PTE pool for the direct map so we don't burn
    // our kernel virtual space.
    let va = crate::mm::syspte::map_io_space(phys, page_count).ok_or(())?;
    Ok(va)
}
