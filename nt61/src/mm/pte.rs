//! Page Table Entry (PTE) types and operations
//
//! NT-style `_MMPTE` union. The same 8-byte slot is interpreted in
//! different ways depending on which bits are set:
//
//! 1. **Hardware** (`P=1`) — A real mapping. The hardware walks this
//!    PTE and produces a physical address. The valid bits and
//!    protection bits are exactly what the architecture defines.
//! 2. **Transition** (`P=0, T=1`) — The page is not present but its
//!    physical content is still in memory, parked on a standby or
//!    modified list. A subsequent access triggers a transition fault
//!    and the PTE is promoted back to `Hardware` with no I/O.
//! 3. **Software** (`P=0, T=0, proto=0`) — A demand-zero PTE (no
//!    information) or a PTE whose content has been paged out to a
//!    page file.
//! 4. **Prototype** (`P=0, proto=1`) — Indirect through a prototype
//!    PTE. Used for shared mappings (sections, mapped files).
//! 5. **Subsection** — A pointer to a subsection structure inside a
//!    section object.
//
//! Each interpretation lives in its own struct (or a packed union),
//! and helpers translate between them.

#![allow(non_snake_case)]

use core::ptr;

/// A page table entry — 8 bytes, matches the on-disk / in-memory
/// layout of a PML4E/PDPTE/PDE/PTE.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
pub struct MMPTE {
    pub u_long: u64,
}

impl MMPTE {
    pub const fn empty() -> Self { Self { u_long: 0 } }
    pub const fn from_raw(v: u64) -> Self { Self { u_long: v } }
    pub const fn raw(&self) -> u64 { self.u_long }

    // -----------------------------------------------------------------
    // Hardware interpretation
    // -----------------------------------------------------------------
    pub fn is_hardware(&self) -> bool {
        (self.u_long & 1) != 0
    }
    pub fn is_transition(&self) -> bool {
        (self.u_long & 0x800) != 0
    }
    pub fn is_prototype(&self) -> bool {
        (self.u_long & 0x400) != 0
    }
    pub fn is_software(&self) -> bool {
        !self.is_hardware() && !self.is_transition() && !self.is_prototype()
    }
    pub fn set_hardware(&mut self, pa: u64, pte_flags: u64) {
        self.u_long = (pa & !0xFFF) | (pte_flags & 0xFFF);
    }
    pub fn hardware_page_frame(&self) -> u64 {
        self.u_long & !0xFFF
    }
    pub fn hardware_flags(&self) -> u64 {
        self.u_long & 0xFFF
    }
    pub fn writable(&self) -> bool {
        (self.u_long & 2) != 0
    }
    pub fn user(&self) -> bool {
        (self.u_long & 4) != 0
    }
    pub fn accessed(&self) -> bool {
        (self.u_long & 0x20) != 0
    }
    pub fn dirty(&self) -> bool {
        (self.u_long & 0x40) != 0
    }
    pub fn large(&self) -> bool {
        (self.u_long & 0x80) != 0
    }
    pub fn global(&self) -> bool {
        (self.u_long & 0x100) != 0
    }
    pub fn no_execute(&self) -> bool {
        (self.u_long & (1u64 << 63)) != 0
    }

    pub fn set_writable(&mut self, v: bool) {
        if v { self.u_long |= 2; } else { self.u_long &= !2; }
    }
    pub fn set_user(&mut self, v: bool) {
        if v { self.u_long |= 4; } else { self.u_long &= !4; }
    }
    pub fn set_accessed(&mut self, v: bool) {
        if v { self.u_long |= 0x20; } else { self.u_long &= !0x20; }
    }
    pub fn set_dirty(&mut self, v: bool) {
        if v { self.u_long |= 0x40; } else { self.u_long &= !0x40; }
    }
    pub fn set_large(&mut self, v: bool) {
        if v { self.u_long |= 0x80; } else { self.u_long &= !0x80; }
    }
    pub fn set_global(&mut self, v: bool) {
        if v { self.u_long |= 0x100; } else { self.u_long &= !0x100; }
    }
    pub fn set_no_execute(&mut self, v: bool) {
        if v { self.u_long |= 1u64 << 63; } else { self.u_long &= !(1u64 << 63); }
    }
    pub fn clear(&mut self) {
        self.u_long = 0;
    }

    // -----------------------------------------------------------------
    // Transition interpretation
    // -----------------------------------------------------------------
    pub fn set_transition(&mut self, pfn: u64, protection: u32) {
        // P=0, T=1, protection in bits 5..9, pfn in upper bits
        self.u_long = ((pfn << 12) & 0x000F_FFFF_FFFF_F000)
            | (1u64 << 11)
            | ((protection as u64) & 0x1F) << 5;
    }
    pub fn transition_pfn(&self) -> u64 {
        (self.u_long >> 12) & 0x000F_FFFF
    }
    pub fn transition_protection(&self) -> u32 {
        ((self.u_long >> 5) & 0x1F) as u32
    }

    // -----------------------------------------------------------------
    // Software (page file / demand zero) interpretation
    // -----------------------------------------------------------------
    pub fn set_software_pagefile(&mut self, page_file: u32, offset: u32, protection: u32) {
        // Bit 9 = page file on (1)
        // Bits 1..5 = protection
        // Bits 12..31 = page file number (4 bits)
        // Bits 32..63 = offset
        self.u_long = ((page_file as u64) & 0xF) << 12
            | (1u64 << 9)
            | ((protection as u64) & 0x1F) << 5
            | ((offset as u64) & 0xFFFF_FFFF) << 32;
    }
    pub fn set_demand_zero(&mut self, protection: u32) {
        self.u_long = ((protection as u64) & 0x1F) << 5;
    }
    pub fn software_page_file(&self) -> u32 {
        ((self.u_long >> 12) & 0xF) as u32
    }
    pub fn software_offset(&self) -> u32 {
        ((self.u_long >> 32) & 0xFFFF_FFFF) as u32
    }
    pub fn software_protection(&self) -> u32 {
        ((self.u_long >> 5) & 0x1F) as u32
    }

    // -----------------------------------------------------------------
    // Prototype (shared mapping) interpretation
    // -----------------------------------------------------------------
    pub fn set_prototype(&mut self, pte_addr: *const MMPTE, protection: u32) {
        // P=0, proto=1 (bit 10), protection in bits 5..9
        // PteAddress occupies bits 12..59 (must be 16-byte aligned)
        self.u_long = ((pte_addr as u64) & 0x000F_FFFF_FFFF_F000)
            | (1u64 << 10)
            | ((protection as u64) & 0x1F) << 5;
    }
    pub fn prototype_address(&self) -> *const MMPTE {
        (self.u_long & 0x000F_FFFF_FFFF_F000) as *const MMPTE
    }
    pub fn prototype_protection(&self) -> u32 {
        ((self.u_long >> 5) & 0x1F) as u32
    }

    // -----------------------------------------------------------------
    // Copy-on-Write helper
    // -----------------------------------------------------------------
    pub fn set_copy_on_write(&mut self) {
        // Use software bit 9 to flag this hardware PTE as COW.
        // We keep P=1 so the page is present, but R/W=0.
        self.u_long |= 1u64 << 9;
    }
    pub fn clear_copy_on_write(&mut self) {
        self.u_long &= !(1u64 << 9);
    }
    pub fn is_copy_on_write(&self) -> bool {
        (self.u_long & 0x200) != 0
    }

    // -----------------------------------------------------------------
    // Subsubsection
    // -----------------------------------------------------------------
    pub fn set_subsection(&mut self, subsection: u32, protection: u32) {
        // P=0, proto=1 (bit 10), protection in bits 5..9
        // Subsection address is in bits 12..59
        self.u_long = ((subsection as u64) & 0x000F_FFFF_FFFF_F000)
            | (1u64 << 10)
            | ((protection as u64) & 0x1F) << 5;
    }
}

// ---------------------------------------------------------------------------
// NT protection codes (5 bits stored in the software/prototype/transition
// PTE fields). Values follow ntdef.h / nt!MM_PROTECTION.
// ---------------------------------------------------------------------------
pub mod protect {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
    pub const PAGE_WRITECOMBINE: u32 = 0x400;

    // The 5-bit forms stored in PTE
    pub const MM_READONLY: u32 = 0x0;
    pub const MM_EXECUTE: u32 = 0x1;
    pub const MM_READWRITE: u32 = 0x2;
    pub const MM_WRITECOPY: u32 = 0x3;
    pub const MM_EXECUTE_READ: u32 = 0x4;
    pub const MM_EXECUTE_READWRITE: u32 = 0x5;
    pub const MM_EXECUTE_WRITECOPY: u32 = 0x6;
    pub const MM_NOACCESS: u32 = 0x18;
    pub const MM_GUARD_PAGE: u32 = 0x19;
}

/// Translate a Win32 protection code to the 5-bit MM protection code
/// stored in the software/prototype PTE.
pub fn win32_protect_to_mm(code: u32) -> u32 {
    use protect::*;
    let rwx = code & 0xFF;
    match rwx {
        PAGE_NOACCESS => MM_NOACCESS,
        PAGE_READONLY => MM_READONLY,
        PAGE_READWRITE => MM_READWRITE,
        PAGE_WRITECOPY => MM_WRITECOPY,
        PAGE_EXECUTE => MM_EXECUTE,
        PAGE_EXECUTE_READ => MM_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE => MM_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY => MM_EXECUTE_WRITECOPY,
        _ => MM_NOACCESS,
    }
}

/// Translate a 5-bit MM protection code back to Win32 (without caching
/// flags).
pub fn mm_protect_to_win32(code: u32) -> u32 {
    use protect::*;
    match code {
        MM_NOACCESS => PAGE_NOACCESS,
        MM_READONLY => PAGE_READONLY,
        MM_READWRITE => PAGE_READWRITE,
        MM_WRITECOPY => PAGE_WRITECOPY,
        MM_EXECUTE => PAGE_EXECUTE,
        MM_EXECUTE_READ => PAGE_EXECUTE_READ,
        MM_EXECUTE_READWRITE => PAGE_EXECUTE_READWRITE,
        MM_EXECUTE_WRITECOPY => PAGE_EXECUTE_WRITECOPY,
        MM_GUARD_PAGE => PAGE_GUARD,
        _ => PAGE_NOACCESS,
    }
}

/// Translate Win32 protection to the low 12 hardware PTE bits for the
/// current architecture. We assume the architecture is x86_64-like
/// (P/RW/U/A/D/G/XD/PAT bits in the canonical positions); other
/// architectures have equivalent fields and just need a re-encoding
/// at the point of writing the actual hardware register.
pub fn mm_protect_to_pte_bits(code: u32, user: bool) -> u64 {
    use protect::*;
    let rwx = code & 0xFF;
    // R/W
    let rw = match rwx {
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY => 1u64 << 1,
        _ => 0,
    };
    // U/S
    let us = if user { 1u64 << 2 } else { 0 };
    // XD (NX)
    let xd = match rwx {
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY => 1u64 << 63,
        _ => 0,
    };
    // PCD / PWT / PAT
    let pwt = if code & PAGE_NOCACHE != 0 { 1u64 << 3 } else { 0 };
    let pcd = if code & PAGE_NOCACHE != 0 { 1u64 << 4 } else { 0 };
    1 | rw | us | pwt | pcd | xd
}

// ---------------------------------------------------------------------------
// Page frame number
// ---------------------------------------------------------------------------
/// Page frame number type alias
pub type PfnNumber = u64;

/// Convert a physical address to a PFN.
#[inline]
pub fn pfn_from_phys(pa: u64) -> PfnNumber { pa >> 12 }
/// Convert a PFN to a physical address.
#[inline]
pub fn pfn_to_phys(pfn: PfnNumber) -> u64 { pfn << 12 }

// ---------------------------------------------------------------------------
// List head for a PTE/PFN linked list — minimal flat intrusive list with
// next pointer only. PTE lists are forward-only; PFN lists are doubly
// linked. The two encodings coexist on a single 8-byte PTE through the
// `List` variant.
// ---------------------------------------------------------------------------
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PTE_LIST {
    pub next: *mut MMPTE,
    pub _padding: u32,
    pub _entry_type: u32,
}

impl PTE_LIST {
    pub fn empty() -> Self { Self { next: ptr::null_mut(), _padding: 0, _entry_type: 0 } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protect::*;

    #[test]
    fn demand_zero_roundtrip() {
        let mut p = MMPTE::empty();
        p.set_demand_zero(MM_READWRITE);
        assert!(p.is_software());
        assert!(!p.is_hardware());
        assert_eq!(p.software_protection(), MM_READWRITE);
    }

    #[test]
    fn transition_roundtrip() {
        let mut p = MMPTE::empty();
        p.set_transition(0x12345, MM_READONLY);
        assert!(p.is_transition());
        assert_eq!(p.transition_pfn(), 0x12345);
        assert_eq!(p.transition_protection(), MM_READONLY);
    }

    #[test]
    fn hardware_roundtrip() {
        let mut p = MMPTE::empty();
        p.set_hardware(0x1000, mm_protect_to_pte_bits(PAGE_READWRITE, true));
        assert!(p.is_hardware());
        assert_eq!(p.hardware_page_frame(), 0x1000);
        assert!(p.writable());
        assert!(p.user());
    }

    #[test]
    fn pagefile_roundtrip() {
        let mut p = MMPTE::empty();
        p.set_software_pagefile(1, 0xCAFE, MM_READWRITE);
        assert!(p.is_software());
        assert_eq!(p.software_page_file(), 1);
        assert_eq!(p.software_offset(), 0xCAFE);
    }

    #[test]
    fn cow_flag() {
        let mut p = MMPTE::empty();
        p.set_hardware(0x2000, mm_protect_to_pte_bits(PAGE_READONLY, true));
        p.set_copy_on_write();
        assert!(p.is_copy_on_write());
        assert!(p.is_hardware());
        p.clear_copy_on_write();
        assert!(!p.is_copy_on_write());
    }

    #[test]
    fn prototype_roundtrip() {
        let target = MMPTE::empty();
        let target_ptr: *const MMPTE = &target;
        let mut p = MMPTE::empty();
        p.set_prototype(target_ptr, MM_READONLY);
        assert!(p.is_prototype());
        assert_eq!(p.prototype_protection(), MM_READONLY);
    }
}

// ---------------------------------------------------------------------------
// Raw hardware PTE bit flags (x86_64 page table entry layout).
//
// These are the standard IA-32e PTE bits defined by the AMD64 / Intel 64
// architecture. They are independent of the NT-specific MMPTE structure
// above and are used by the simple page-table mapper (mm::vas) and the
// user-space PE loader. The values are architecture-specific; on non-x86
// targets, callers should use the arch-specific equivalents in
// arch/<target>/paging.rs.
// ---------------------------------------------------------------------------
pub mod hw {
    /// Present — page is resident in physical memory.
    pub const PTE_P: u64 = 1 << 0;
    /// Read/Write — page is writable (cleared = read-only).
    pub const PTE_RW: u64 = 1 << 1;
    /// User/Supervisor — page accessible from Ring 3 (cleared = Ring 0).
    pub const PTE_US: u64 = 1 << 2;
    /// Page-level Write-Through.
    pub const PTE_PWT: u64 = 1 << 3;
    /// Page-level Cache Disable.
    pub const PTE_PCD: u64 = 1 << 4;
    /// Accessed — set by the CPU on first access.
    pub const PTE_A: u64 = 1 << 5;
    /// Dirty — set by the CPU on first write (only for PTE leaf entries).
    pub const PTE_D: u64 = 1 << 6;
    /// Page Attribute Table — selects MAIR attribute index.
    pub const PTE_PAT: u64 = 1 << 7;
    /// Global — page is not flushed on CR3 writes (requires CR4.PGE).
    pub const PTE_G: u64 = 1 << 8;
    /// NX (No-Execute) — execute disabled (requires EFER.NXE).
    pub const PTE_NX: u64 = 1 << 63;
}

// Re-export the hardware flags at the module root for callers that use
// `crate::mm::pte::PTE_P` style imports (matches x86 conventions).
pub use hw::{PTE_A, PTE_D, PTE_G, PTE_NX, PTE_P, PTE_PAT, PTE_PCD, PTE_PWT, PTE_RW, PTE_US};
