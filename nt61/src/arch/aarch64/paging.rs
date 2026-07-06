//! aarch64 paging
//
//! AArch64 4-KiB granule 4-level page table (L0..L3). The L0 table
//! is the root pointed at by `TTBR1_EL1` for the kernel half and
//! `TTBR0_EL1` for the user half.
//
//! # Table walk
//!
//! The original implementation obtained the L0..L3 entries via the
//! NT 6.1 self-map windows (`PXE_BASE`, `PPE_BASE`, …) defined in
//! `mm::vas`. That works on x86_64 because `MmSystemAddressSpace::init`
//! installs a recursive self-map into `PML4[0x1ED]`. The aarch64
//! equivalent (a 4-level recursive walk that ends at the page-root
//! page itself) is *not* installed: `mm::vas::init` is a no-op on
//! non-x86_64 architectures, and `PXE_BASE`/`PPE_BASE`/... therefore
//! resolve to high kernel VAs that have no translation tables
//! behind them. Dereferencing them from `map_page` causes a
//! synchronous data abort (ESR=0x25 / "Translation fault, zeroth
//! level") at the FAR value `0xFFFFF6FB7DBED000` — exactly the
//! `PXE_BASE + 0x1ED * 8`.
//
//! To get around this, `map_page` / `unmap_page` / `translate_virt`
//! here walk the kernel's translation tables by *physical address* —
//! they read the page root PA from `TTBR1_EL1` (which is always a
//! valid physical address; the root page is identity-mapped at PA by
//! the boot stub) and follow each intermediate table PA through the
//! descriptor bits. The leaf write/install still uses the
//! `arch::aarch64::paging::PTE` layout so the format is identical
//! to x86_64's.
//!
//! `load_page_root` writes the supplied PFN to `TTBR1_EL1`.

#![allow(non_snake_case)]

use core::arch::asm;
use core::ptr;

use crate::mm::pfn;
use crate::mm::pte::pfn_to_phys;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

pub type VirtAddr = u64;
pub type PhysAddr = u64;

pub struct PageTableEntry {
    pub value: u64,
}
impl PageTableEntry {
    pub const fn empty() -> Self { Self { value: 0 } }
    pub fn present(&self) -> bool { (self.value & 1) != 0 }
    pub fn writable(&self) -> bool { (self.value & 2) != 0 }
    pub fn user(&self) -> bool { (self.value & 4) != 0 }
    pub fn frame(&self) -> u64 { self.value & 0x000F_FFFF_FFFF_F000 }
    pub fn set(&mut self, addr: u64, flags: u64) {
        self.value = (addr & 0x000F_FFFF_FFFF_F000) | (flags & 0xFFF);
    }
}

/// AArch64 L0..L3 table descriptor / page descriptor encoding.
///
/// * Page descriptor: bits[1:0] = 0b11, bits[54:2] = physical address.
/// * Table descriptor: bits[1:0] = 0b11, bits[47:12] = next table
///   address (a block descriptor is 0b01 for 4 KiB pages).
fn make_page_desc(pa: u64, pte_flags: u64) -> u64 {
    // aarch64 with 4 KiB granule: block/page descriptors occupy
    // bits [47:12] for the address.
    //
    // bit 10 = AF (Access Flag) MUST be 1; if the hardware has
    // Access Flag checking enabled (TCR_EL1.HA or per-page) and
    // AF=0 on the leaf, the first write triggers an Access Flag
    // Fault (DFSC=0x10 + level).
    //
    // bit 54 = UXN, bit 53 = PXN — both 0 (RW, executable) for
    // kernel data pages; we never execute from the heap/pool.
    (pa & 0x0000_FFFF_FFFF_F000) | (pte_flags & 0xFFF) | 0x3 | (1u64 << 10)
}
fn make_table_desc(pa: u64) -> u64 {
    // Same AF caveat as above applies to table descriptors when
    // Access Flag checking is enabled — set bit 10 to be safe.
    (pa & 0x0000_FFFF_FFFF_F000) | 0x3 | (1u64 << 10)
}
fn is_valid_table(e: u64) -> bool { (e & 0x3) == 0x3 }
fn is_valid_page(e: u64) -> bool { (e & 0x3) == 0x1 || (e & 0x3) == 0x3 }

/// Address (PA) of the page table that backs L0 of the kernel
/// half of the address space. The page root itself is left
/// identity-mapped by the boot stub (the L0 page is allocated from
/// physical memory whose PA == VA mapping is preserved across
/// `ExitBootServices`), so we can dereference it directly without
/// going through any translation.
///
/// On EDK2 / QEMU virt the boot stub typically installs a single
/// page table into TTBR0_EL1 and zeroes TTBR1_EL1 (the kernel
/// half). We honour whichever one is non-zero.
#[inline]
fn current_l0_phys() -> u64 {
    let ttbr1: u64;
    let ttbr0: u64;
    unsafe {
        asm!("mrs {}, TTBR1_EL1", out(reg) ttbr1, options(nostack));
        asm!("mrs {}, TTBR0_EL1", out(reg) ttbr0, options(nostack));
    }
    let chosen = if (ttbr1 & 0x0000_FFFF_FFFF_F000) != 0 { ttbr1 } else { ttbr0 };
    chosen & 0x0000_FFFF_FFFF_F000
}

#[allow(dead_code)]
unsafe fn dump_l0_for(va: u64) {
    let l0_phys = current_l0_phys();
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    crate::hal::serial::write_string("[dump] l0_idx=");
    crate::hal::serial::write_hex_u64(l0_idx as u64);
    crate::hal::serial::write_string(" l0_phys=");
    crate::hal::serial::write_hex_u64(l0_phys);
    crate::hal::serial::write_string(" l0e=");
    crate::hal::serial::write_hex_u64(l0e);
    crate::hal::serial::write_string("\r\n");

    let l1_phys = l0e & 0x0000_FFFF_FFFF_F000;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    crate::hal::serial::write_string("[dump]   l1_idx=");
    crate::hal::serial::write_hex_u64(l1_idx as u64);
    crate::hal::serial::write_string(" l1_phys=");
    crate::hal::serial::write_hex_u64(l1_phys);
    crate::hal::serial::write_string(" l1e=");
    crate::hal::serial::write_hex_u64(l1e);
    crate::hal::serial::write_string("\r\n");

    let l2_phys = l1e & 0x0000_FFFF_FFFF_F000;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;
    let l2 = l2_phys as *mut u64;
    let l2e = core::ptr::read_volatile(l2.add(l2_idx));
    crate::hal::serial::write_string("[dump]     l2_idx=");
    crate::hal::serial::write_hex_u64(l2_idx as u64);
    crate::hal::serial::write_string(" l2_phys=");
    crate::hal::serial::write_hex_u64(l2_phys);
    crate::hal::serial::write_string(" l2e=");
    crate::hal::serial::write_hex_u64(l2e);
    crate::hal::serial::write_string("\r\n");

    let l3_phys = l2e & 0x0000_FFFF_FFFF_F000;
    let l3_idx = ((va >> 12) & 0x1FF) as usize;
    let l3 = l3_phys as *mut u64;
    let l3e = core::ptr::read_volatile(l3.add(l3_idx));
    crate::hal::serial::write_string("[dump]       l3_idx=");
    crate::hal::serial::write_hex_u64(l3_idx as u64);
    crate::hal::serial::write_string(" l3_phys=");
    crate::hal::serial::write_hex_u64(l3_phys);
    crate::hal::serial::write_string(" l3e=");
    crate::hal::serial::write_hex_u64(l3e);
    crate::hal::serial::write_string("\r\n");
}

/// Compute the AArch64 descriptor bits that point an intermediate
/// table at `pa`. Returns the raw 8-byte descriptor value.
#[inline]
fn table_desc_at(pa: u64) -> u64 {
    (pa & 0x0000_FFFF_FFFF_F000) | 0x3 | (1u64 << 10)
}

/// Walk the kernel page tables and return a writable pointer to
/// the leaf PTE that maps `va`. Allocates any missing
/// intermediates along the way. The caller writes the leaf PTE
/// (this function intentionally does NOT touch the leaf, only the
/// chain leading up to it). On allocation failure returns a null
/// pointer.
unsafe fn leaf_pte_ptr_for(va: u64) -> *mut u64 {
    let l0_phys = current_l0_phys();
    let l0_idx = ((va >> 39) & 0x1FF) as usize;
    let l1_idx = ((va >> 30) & 0x1FF) as usize;
    let l2_idx = ((va >> 21) & 0x1FF) as usize;
    let l3_idx = ((va >> 12) & 0x1FF) as usize;

    let l0 = l0_phys as *mut u64;
    let l0e = core::ptr::read_volatile(l0.add(l0_idx));
    let l1_phys = if (l0e & 0x3) == 0x3 {
        l0e & 0x0000_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = table_desc_at(new_phys);
        core::ptr::write_volatile(l0.add(l0_idx), new_desc);
        new_phys
    };

    let l1 = l1_phys as *mut u64;
    let l1e = core::ptr::read_volatile(l1.add(l1_idx));
    let l2_phys = if (l1e & 0x3) == 0x3 {
        l1e & 0x0000_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = table_desc_at(new_phys);
        core::ptr::write_volatile(l1.add(l1_idx), new_desc);
        new_phys
    };

    let l2 = l2_phys as *mut u64;
    let l2e = core::ptr::read_volatile(l2.add(l2_idx));
    let l3_phys = if (l2e & 0x3) == 0x3 {
        l2e & 0x0000_FFFF_FFFF_F000
    } else {
        let pfn = match pfn::allocate_pfn() {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let new_phys = pfn_to_phys(pfn);
        crate::hal::serial::write_string("[leaf] new-l3 pfn=");
        crate::hal::serial::write_hex_u64(pfn);
        crate::hal::serial::write_string(" phys=");
        crate::hal::serial::write_hex_u64(new_phys);
        crate::hal::serial::write_string(" for-va=");
        crate::hal::serial::write_hex_u64(va);
        crate::hal::serial::write_string("\r\n");
        ptr::write_bytes(new_phys as *mut u8, 0, 4096);
        let new_desc = table_desc_at(new_phys);
        core::ptr::write_volatile(l2.add(l2_idx), new_desc);
        new_phys
    };

    let l3 = l3_phys as *mut u64;
    l3.add(l3_idx)
}

pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    let l3_pte = unsafe { leaf_pte_ptr_for(va) };
    if l3_pte.is_null() { return false; }
    // Write the leaf as an AArch64 page descriptor (bits[1:0] = 0b11).
    let desc = make_page_desc(pa, flags);
    unsafe {
        core::ptr::write_volatile(l3_pte, desc);
        // Order PTE writes before subsequent translations.
        asm!("dsb ishst", options(nostack));
        // Verify the write actually landed — read it back. On
        // systems where the L3 page itself is in unmapped memory,
        // the write itself faults and we never reach this read.
        let verify = core::ptr::read_volatile(l3_pte);
        if verify != desc {
            crate::hal::serial::write_string("[map_page] verify-fail va=");
            crate::hal::serial::write_hex_u64(va);
            crate::hal::serial::write_string(" wrote=");
            crate::hal::serial::write_hex_u64(desc);
            crate::hal::serial::write_string(" read=");
            crate::hal::serial::write_hex_u64(verify);
            crate::hal::serial::write_string("\r\n");
        }
    }
    true
}

pub fn unmap_page(va: u64) -> Option<u64> {
    let l3_pte = unsafe { leaf_pte_ptr_for(va) };
    if l3_pte.is_null() { return None; }
    unsafe {
        let pte = core::ptr::read_volatile(l3_pte);
        if !is_valid_page(pte) { return None; }
        let pa = pte & 0x0000_FFFF_FFFF_F000;
        core::ptr::write_volatile(l3_pte, 0);
        asm!("tlbi VAE1, {}", in(reg) va >> 12, options(nostack));
        asm!("dsb nsh", options(nostack));
        asm!("isb", options(nostack));
        Some(pa)
    }
}

pub fn translate_virt(va: u64) -> Option<u64> {
    unsafe {
        let l0_phys = current_l0_phys();
        let l0_idx = ((va >> 39) & 0x1FF) as usize;
        let l1_idx = ((va >> 30) & 0x1FF) as usize;
        let l2_idx = ((va >> 21) & 0x1FF) as usize;
        let l3_idx = ((va >> 12) & 0x1FF) as usize;
        let l0 = l0_phys as *const u64;
        let l0e = core::ptr::read_volatile(l0.add(l0_idx));
        if (l0e & 0x3) != 0x3 { return None; }
        let l1_phys = l0e & 0x0000_FFFF_FFFF_F000;
        let l1 = l1_phys as *const u64;
        let l1e = core::ptr::read_volatile(l1.add(l1_idx));
        if (l1e & 0x3) != 0x3 { return None; }
        let l2_phys = l1e & 0x0000_FFFF_FFFF_F000;
        let l2 = l2_phys as *const u64;
        let l2e = core::ptr::read_volatile(l2.add(l2_idx));
        if (l2e & 0x3) != 0x3 { return None; }
        let l3_phys = l2e & 0x0000_FFFF_FFFF_F000;
        let l3 = l3_phys as *const u64;
        let l3e = core::ptr::read_volatile(l3.add(l3_idx));
        if !is_valid_page(l3e) { return None; }
        Some((l3e & 0x0000_FFFF_FFFF_F000) | (va & 0xFFF))
    }
}

pub unsafe fn load_page_root(pml4_pfn: u64) {
    let pa = pfn_to_phys(pml4_pfn);
    asm!("msr TTBR1_EL1, {}", in(reg) pa, options(nostack));
    asm!("dsb nsh", options(nostack));
    asm!("isb", options(nostack));
}

pub fn read_page_root_pfn() -> u64 {
    let pa: u64;
    unsafe { asm!("mrs {}, TTBR1_EL1", out(reg) pa, options(nostack)); }
    pa >> 12
}

/// Invalidate a single TLB entry for the given virtual address.
pub fn invalidate_tlb(va: u64) {
    unsafe {
        asm!("tlbi VAE1, {}", in(reg) va >> 12, options(nostack));
        asm!("dsb nsh", options(nostack));
        asm!("isb", options(nostack));
    }
}

/// Flush the entire TLB (all entries).
pub fn flush_tlb() {
    unsafe {
        // VMALLE1 invalidates all stage-1 TLB entries for EL1.
        asm!("tlbi vmalle1", options(nostack));
        asm!("dsb nsh", options(nostack));
        asm!("isb", options(nostack));
    }
}

/// Identity-map `[pa, pa + size)` into the kernel's translation
/// tables, so that virtual address `pa` resolves to physical
/// address `pa`.
///
/// This is required on aarch64 / riscv64 because the firmware
/// does not always leave the entire RAM region 1:1-mapped after
/// `ExitBootServices` (especially on the QEMU `virt` machine
/// where all RAM is above 4 GiB). The kernel's buddy allocator
/// hands out pages at physical addresses above the bootloader's
/// initial identity-map range, and `mm::heap::init` uses one of
/// those pages as the kernel heap. The first pool allocation then
/// dereferences a pointer that is not in the kernel's TTBR1_EL1
/// translation tables, raising a synchronous data-abort.
///
/// We work around that by walking the page table once for every
/// page in the heap region and installing an identity mapping
/// (VA == PA) at the same attributes the kernel heap expects
/// (read-write, inner-shareable, writeback).
///
/// `pa` must be page-aligned and `size` is rounded up to the next
/// page boundary. Returns `true` on success, `false` if any
/// `map_page` call in the range failed (for example because the
/// pfn allocator is exhausted — in that case the caller should
/// fall back to its existing fast-path).
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    const PAGE_SIZE: u64 = 4096;
    // Access Flag (AF, bit 10) MUST be set on every descriptor we
    // install, otherwise the MMU raises an Access Flag Fault on
    // first access. Our trap handler does not service Access Flag
    // Faults (it only handles translation faults by parking the
    // CPU), so any page we map must arrive with AF=1.
    //
    // Bit breakdown:
    //   bits [4:2] = 011 = AttrIndx = 3 (matches firmware's RAM
    //                 descriptors; see MAIR_EL1 init in
    //                 `arch::aarch64::init`).
    //   bit 10  = AF (required to avoid Access Flag Fault).
    //   bits [1:0] are overridden to 0b11 by make_page_desc.
    //   AP[2:0] = 001 → RW at EL1, no access at EL0.
    //   SH[1:0] = 00 → non-shareable.
    //   UXN/PXN live in bits [54:53], not in the 12-bit flags word.
    const HEAP_FLAGS: u64 = 0x40C;

    let pa_aligned = pa & !(PAGE_SIZE - 1);
    let end = pa.saturating_add(size);
    let mut cur = pa_aligned;
    let mut count: u64 = 0;
    let mut skipped: u64 = 0;

    unsafe {
        let l0_phys = current_l0_phys();
        let l0 = l0_phys as *mut u64;

        while cur < end {
            let l0_idx = ((cur >> 39) & 0x1FF) as usize;
            let l1_idx = ((cur >> 30) & 0x1FF) as usize;
            let l2_idx = ((cur >> 21) & 0x1FF) as usize;
            let l3_idx = ((cur >> 12) & 0x1FF) as usize;

            // Walk L0 → L1 → L2 ourselves. If the firmware has
            // already installed a 2 MiB block descriptor at L2
            // covering this 2 MiB region (very common — EDK2's
            // RAM map typically installs one block per region),
            // the page is already RW and we don't have to touch
            // anything. Touching L2 just to install a table+page
            // descriptor on top would (a) waste memory and (b)
            // replace a working block mapping with a broken
            // sub-mapping.
            let l0e = core::ptr::read_volatile(l0.add(l0_idx));
            if (l0e & 0x3) != 0x3 {
                // L0 missing — install a fresh L1.
                if !map_page(cur, cur, HEAP_FLAGS) { return false; }
                count += 1;
                cur = cur.saturating_add(PAGE_SIZE);
                continue;
            }
            let l1_phys = l0e & 0x0000_FFFF_FFFF_F000;
            let l1 = l1_phys as *mut u64;
            let l1e = core::ptr::read_volatile(l1.add(l1_idx));
            if (l1e & 0x3) != 0x3 {
                if !map_page(cur, cur, HEAP_FLAGS) { return false; }
                count += 1;
                cur = cur.saturating_add(PAGE_SIZE);
                continue;
            }
            let l2_phys = l1e & 0x0000_FFFF_FFFF_F000;
            let l2 = l2_phys as *mut u64;
            let l2e = core::ptr::read_volatile(l2.add(l2_idx));

            // If L2 already has a 2 MiB block descriptor for this
            // address and the whole 2 MiB region we need falls
            // inside it, the page is already mapped — skip.
            if (l2e & 0x3) == 0x1 {
                let block_base = l2e & 0xFFFF_FFFF_E000_0000;
                let block_end = block_base.saturating_add(2 * 1024 * 1024);
                // Advance `cur` to the next 2 MiB boundary (or `end`)
                let next_2mb = (cur & !((2u64 * 1024 * 1024) - 1))
                    .saturating_add(2 * 1024 * 1024);
                let advance = next_2mb.min(end).min(block_end);
                let pages_in_block = (advance - cur) / PAGE_SIZE;
                skipped += pages_in_block;
                cur = advance;
                continue;
            }

            // L2 has no block descriptor — install a 4 KiB page
            // mapping via the existing leaf_pte_ptr_for path.
            if !map_page(cur, cur, HEAP_FLAGS) { return false; }
            count += 1;
            cur = cur.saturating_add(PAGE_SIZE);
        }
    }

    flush_tlb();
    crate::hal::serial::write_string("[idmap] mapped ");
    crate::hal::serial::write_hex_u64(count);
    crate::hal::serial::write_string(" pages, skipped ");
    crate::hal::serial::write_hex_u64(skipped);
    crate::hal::serial::write_string(" (already block-mapped)\r\n");
    true
}
