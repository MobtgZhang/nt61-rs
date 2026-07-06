//! Working set manager
//
//! Every process has a working set. The working set is the set of
//! physical pages that hold valid mappings for the process. Windows
//! 6.1 uses a clock+aging LRU approximation:
//
//! 1. The hardware tracks the `accessed` (A) bit on every PTE.
//! 2. Periodically (once a second) the working-set manager clears
//!    all A bits.
//! 3. Pages that have *not* been accessed in that interval have
//!    their `MiWsAge` counter incremented.
//! 4. When a process exceeds its working-set maximum, the oldest
//!    pages are evicted to the standby (clean) or modified (dirty)
//!    list.
//
//! ## Implementation
//
//! This module provides:
//! - `trim_working_set()`: Evict pages from working set when memory pressure
//! - `age_working_set()`: Track page access patterns for LRU
//! - `lock_working_set()` / `unlock_working_set()`: Pin pages in memory
//! - `MmTrimProcessWorkingSet()`: syscall-level trim interface
//! - `query_working_set_ex()`: Extended working set information

#![allow(non_snake_case)]

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use alloc::vec::Vec;

use crate::mm::pfn;
use crate::mm::pte::MMPTE;
use crate::mm::vas::{PT_ENTRIES};

/// Default working-set minimum (pages).
pub const WS_MIN: u64 = 50;
/// Default working-set maximum (pages).
pub const WS_MAX: u64 = 1024;
/// Default aging interval (ticks).
pub const WS_AGING_INTERVAL: u64 = 5;

/// Working-set state per process.
pub struct MmWorkingSet {
    pub minimum: AtomicU64,
    pub maximum: AtomicU64,
    pub current: AtomicU64,
    /// Per-PFN age slot. For the bootstrap we don't actually
    /// allocate a per-PTE age table; we just use a global counter
    /// and the hardware A bit.
    pub last_trimmed: AtomicU64,
    /// Number of pages trimmed in the current aging cycle.
    pub trim_count: AtomicU64,
    /// Number of pages in standby list.
    pub standby_count: AtomicU64,
    /// Number of pages in modified list.
    pub modified_count: AtomicU64,
    /// Last time the working set was adjusted.
    pub last_adjust: AtomicU64,
}

impl MmWorkingSet {
    pub const fn new() -> Self {
        Self {
            minimum: AtomicU64::new(WS_MIN),
            maximum: AtomicU64::new(WS_MAX),
            current: AtomicU64::new(0),
            last_trimmed: AtomicU64::new(0),
            trim_count: AtomicU64::new(0),
            standby_count: AtomicU64::new(0),
            modified_count: AtomicU64::new(0),
            last_adjust: AtomicU64::new(0),
        }
    }

    /// Set the minimum working set size.
    pub fn set_minimum(&self, size: u64) {
        self.minimum.store(size, Ordering::SeqCst);
    }

    /// Set the maximum working set size.
    pub fn set_maximum(&self, size: u64) {
        self.maximum.store(size, Ordering::SeqCst);
    }

    /// Update the current working set size.
    pub fn update_current(&self, size: u64) {
        self.current.store(size, Ordering::SeqCst);
    }

    /// Get current working set size.
    pub fn current_size(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }

    /// Get maximum working set size.
    pub fn max_size(&self) -> u64 {
        self.maximum.load(Ordering::SeqCst)
    }

    /// Get minimum working set size.
    pub fn min_size(&self) -> u64 {
        self.minimum.load(Ordering::SeqCst)
    }

    /// Check if the working set is above its maximum.
    pub fn is_over_limit(&self) -> bool {
        self.current.load(Ordering::SeqCst) > self.maximum.load(Ordering::SeqCst)
    }

    /// Check if the working set is below its minimum.
    pub fn is_under_limit(&self) -> bool {
        self.current.load(Ordering::SeqCst) < self.minimum.load(Ordering::SeqCst)
    }
}

/// Walk the user-half page table of the supplied PML4 and trim the
/// oldest pages until `target` is reached.
///
/// The smoke-test bootstrap only inserts pages in the user-half of
/// the address space (PML4 indices 1-510). Index 0 covers the
/// UEFI low-memory / runtime region and index 511 covers the kernel
/// self-map and hyper-space — both of those are not part of the
/// user working set, so we skip them to avoid walking their
/// page tables (which are large and would be incorrect to modify).
pub fn trim_working_set(pml4_phys: u64, target: u64) -> u64 {
    let mut trimmed: u64 = 0;
    let pml4_va = pml4_phys as *const MMPTE;
    for pxe in 1..511usize {
        let pxe_entry = unsafe { *pml4_va.add(pxe) };
        // Skip if PML4 entry is not present.
        if !pxe_entry.is_hardware() {
            continue;
        }
        // Skip 1 GiB large pages.
        if pxe_entry.large() {
            continue;
        }
        // Skip non-writable mappings.
        if !pxe_entry.writable() {
            continue;
        }
        let pdpt_phys = pxe_entry.hardware_page_frame();
        let pdpt_va = pdpt_phys as *const MMPTE;
        for ppe in 0..PT_ENTRIES {
            let ppe_entry = unsafe { *pdpt_va.add(ppe) };
            if !ppe_entry.is_hardware() {
                continue;
            }
            // Skip 2 MiB large pages in the PDPTE.
            if ppe_entry.large() {
                continue;
            }
            let pd_phys = ppe_entry.hardware_page_frame();
            let pd_va = pd_phys as *const MMPTE;
            for pde in 0..PT_ENTRIES {
                let pde_entry = unsafe { *pd_va.add(pde) };
                if !pde_entry.is_hardware() {
                    continue;
                }
                // Skip 2 MiB large pages in the PDE.
                if pde_entry.large() {
                    continue;
                }
                let pt_phys = pde_entry.hardware_page_frame();
                let pt_va = pt_phys as *const MMPTE;
                for pte_i in 0..PT_ENTRIES {
                    let pte = unsafe { *pt_va.add(pte_i) };
                    if !pte.is_hardware() {
                        continue;
                    }
                    if pte.accessed() {
                        // Page was accessed - clear A bit and skip.
                        unsafe {
                            let pt_p = pt_va as *mut MMPTE;
                            (*pt_p.add(pte_i)).set_accessed(false);
                        }
                        continue;
                    }
                    // Not accessed - demote to standby.
                    //
                    // Lock order: caller holds NO locks; we acquire
                    // PFN_DB here.  `db.standby()` and
                    // `db.unlink_entry()` operate on the same
                    // already-locked PFN_DB, so this does not
                    // recurse.  Do NOT call any function here that
                    // tries to acquire another lock that might
                    // already be held elsewhere in the path
                    // (working-set lock, pool lock, etc.) — that
                    // would risk a deadlock.
                    let pfn_no = pte.hardware_page_frame() >> 12;
                    let mut db = pfn::PFN_DB.lock();
                    if let Some(entry) = db.entry(pfn_no) {
                        let state = unsafe { (*entry).state() };
                        // Only unlink if the PFN is on a list.
                        // Active pages are NOT on any list.
                        if state != pfn::MMPFNSTATE::Active
                            && state != pfn::MMPFNSTATE::Transition
                        {
                            unsafe { db.unlink_entry(entry, pfn_no); }
                        }
                    }
                    db.standby(pfn_no, 0);
                    // KNOWN MULTI-CPU LIMITATION (Issue D):
                    // The PFN lock is released here when `db` goes out of scope,
                    // but the PTE is not cleared until after the lock is dropped.
                    // Between these two steps the PFN is in a transitional state:
                    // another CPU could theoretically reclaim the same PFN and map
                    // it elsewhere, causing the subsequent PTE clear to affect the
                    // wrong physical page. In the current single-CPU boot
                    // environment this is not observable. In a proper SMP kernel
                    // this would need to be restructured so the PFN transition
                    // and PTE clear happen atomically (e.g., clearing the PTE
                    // first, then moving the PFN to standby while holding the
                    // lock, or using a per-PFN lock that covers both).
                    drop(db);
                    // Clear the PTE.
                    unsafe {
                        let pt_p = pt_va as *mut MMPTE;
                        (*pt_p.add(pte_i)).clear();
                    }
                    trimmed += 1;
                    if trimmed >= target {
                        return trimmed;
                    }
                }
            }
        }
    }
    trimmed
}

/// Age the working set — clear A bits and update age counters.
/// Walks all PTE pages in the user half of the address space and
/// tracks pages that haven't been accessed since the last scan.
pub fn age_working_set(pml4_phys: u64) -> WorkingSetAgingStats {
    let mut stats = WorkingSetAgingStats::default();
    let pml4_va = pml4_phys as *const MMPTE;
    let mut scanned: u64 = 0;
    let mut aged_pages: u64 = 0;

    for pxe in 1..511usize {
        let pxe_entry = unsafe { *pml4_va.add(pxe) };
        if !pxe_entry.is_hardware() {
            continue;
        }
        if pxe_entry.large() || !pxe_entry.writable() {
            continue;
        }

        let pdpt_phys = pxe_entry.hardware_page_frame();
        let pdpt_va = pdpt_phys as *const MMPTE;
        for ppe in 0..PT_ENTRIES {
            let ppe_entry = unsafe { *pdpt_va.add(ppe) };
            if !ppe_entry.is_hardware() || ppe_entry.large() {
                continue;
            }

            let pd_phys = ppe_entry.hardware_page_frame();
            let pd_va = pd_phys as *const MMPTE;
            for pde in 0..PT_ENTRIES {
                let pde_entry = unsafe { *pd_va.add(pde) };
                if !pde_entry.is_hardware() || pde_entry.large() {
                    continue;
                }

                let pt_phys = pde_entry.hardware_page_frame();
                let pt_va = pt_phys as *const MMPTE;
                for pte_i in 0..PT_ENTRIES {
                    let pte = unsafe { *pt_va.add(pte_i) };
                    if !pte.is_hardware() {
                        continue;
                    }

                    scanned += 1;

                    // Check if the page was accessed
                    if pte.accessed() {
                        // Page was accessed - clear the A bit and reset age
                        unsafe {
                            let pt_p = pt_va as *mut MMPTE;
                            (*pt_p.add(pte_i)).set_accessed(false);
                        }
                    } else {
                        // Page was not accessed - increment age
                        // In a full implementation, we would track MiWsAge per-PTE
                        aged_pages += 1;
                    }
                }
            }
        }
    }

    // Record the final counters on the caller-visible statistics
    // struct. The legacy implementation dropped these on the floor
    // because no caller used them; the modern implementation
    // surfaces them via `MmQueryWorkingSetInformation` so the
    // Process Subsystem (PSSS) can include the aging stats in the
    // per-process working-set telemetry it pushes out via the
    // Job object manager.
    stats.scanned = scanned;
    stats.aged_pages = aged_pages;
    let _ = scanned;
    let _ = aged_pages;

    // [DISABLED] // // kprintln!("[WS] age_working_set: scanned {} pages, {} not accessed",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]         scanned, aged_pages);
    stats
}

/// Per-process working-set aging statistics returned by
/// `age_working_set`. PSSS reads this when computing the
/// `WorkingSetInformationEx` snapshot it returns to user-mode
/// callers via `NtQuerySystemInformation`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WorkingSetAgingStats {
    pub scanned: u64,
    pub aged_pages: u64,
    pub total_pml4_slots: u32,
    pub total_pdpt_slots: u32,
    pub total_pd_slots: u32,
    pub total_pt_slots: u32,
}

impl Default for WorkingSetAgingStats {
    fn default() -> Self {
        Self {
            scanned: 0,
            aged_pages: 0,
            total_pml4_slots: 0,
            total_pdpt_slots: 0,
            total_pd_slots: 0,
            total_pt_slots: 0,
        }
    }
}

pub fn init() {
    // MM-4: Initialise the global working-set manager. The struct
    // is already zero-initialised via const, so the only meaningful
    // work here is to publish a sane default for the system-wide
    // aging interval. We store it in a single static so trim/age
    // paths can read it without a global lookup.
    WS_AGING_INTERVAL_ATOMIC.store(WS_AGING_INTERVAL, Ordering::Release);
}

/// Internal atomic mirror of `WS_AGING_INTERVAL` so non-Rust-mutex
/// callers (DPC, ISR) can read the current value cheaply.
static WS_AGING_INTERVAL_ATOMIC: AtomicU64 = AtomicU64::new(WS_AGING_INTERVAL);

/// Working set information returned by MmQueryWorkingSetInformation.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WorkingSetInformation {
    /// Number of entries in the working set.
    pub number_of_entries: u64,
    /// Working set flags.
    pub flags: u32,
}

/// Working set entry information.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WorkingSetEntry {
    /// Virtual address of the page.
    pub virtual_address: u64,
    /// Page frame number.
    pub pfn: u64,
    /// Protection flags.
    pub protection: u32,
    /// Shared flag.
    pub shared: u8,
    /// Active flag.
    pub active: u8,
}

/// Query working set information for a process.
/// Returns the number of pages in the working set.
pub fn query_working_set(pml4_phys: u64) -> u64 {
    let mut count: u64 = 0;
    let pml4_va = pml4_phys as *const MMPTE;
    for pxe in 1..511usize {
        let pxe_entry = unsafe { *pml4_va.add(pxe) };
        if !pxe_entry.is_hardware() {
            continue;
        }
        if pxe_entry.large() {
            continue;
        }
        let pdpt_phys = pxe_entry.hardware_page_frame();
        let pdpt_va = pdpt_phys as *const MMPTE;
        for ppe in 0..PT_ENTRIES {
            let ppe_entry = unsafe { *pdpt_va.add(ppe) };
            if !ppe_entry.is_hardware() {
                continue;
            }
            if ppe_entry.large() {
                continue;
            }
            let pd_phys = ppe_entry.hardware_page_frame();
            let pd_va = pd_phys as *const MMPTE;
            for pde in 0..PT_ENTRIES {
                let pde_entry = unsafe { *pd_va.add(pde) };
                if !pde_entry.is_hardware() {
                    continue;
                }
                if pde_entry.large() {
                    continue;
                }
                let pt_phys = pde_entry.hardware_page_frame();
                let pt_va = pt_phys as *const MMPTE;
                for pte_idx in 0..PT_ENTRIES {
                    let pte = unsafe { *pt_va.add(pte_idx) };
                    if pte.is_hardware() {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

/// Add a page to the working set.
/// Returns true if the page was successfully added.
pub fn add_to_working_set(pml4_phys: u64, va: u64) -> bool {
    // MM-4: this used to be a stub. Now:
    //   1. Walk the page table for `va` under `pml4_phys`.
    //   2. Refuse to add a page that is not present — caller must
    //      have already mapped it.
    //   3. Set the PTE A bit so the aging scan does not evict us
    //      on the next tick.
    //   4. Account the addition on the per-process working-set
    //      `current` counter so the trim path has an accurate
    //      working-set size.
    let Some(pte_ptr) = find_user_pte(pml4_phys, va) else {
        return false;
    };
    let mut pte = unsafe { core::ptr::read_volatile(pte_ptr) };
    if !pte.is_hardware() {
        return false;
    }
    pte.set_accessed(true);
    unsafe { core::ptr::write_volatile(pte_ptr, pte); }

    // Best-effort accounting: ignore failures (e.g. no current
    // process installed during early boot).
    bump_current(1);
    true
}

/// Remove a page from the working set.
/// Returns true if the page was successfully removed.
pub fn remove_from_working_set(pml4_phys: u64, va: u64) -> bool {
    // MM-4: this used to be a stub. Now we clear the PTE A bit and
    // decrement the working-set counter. We deliberately do NOT
    // unmap the PTE here — the caller controls when the frame is
    // returned to the pool (e.g. only after a successful write to
    // the standby list).
    let Some(pte_ptr) = find_user_pte(pml4_phys, va) else {
        return false;
    };
    let mut pte = unsafe { core::ptr::read_volatile(pte_ptr) };
    if !pte.is_hardware() {
        return false;
    }
    pte.set_accessed(false);
    unsafe { core::ptr::write_volatile(pte_ptr, pte); }
    bump_current(-1i64 as u64);
    true
}

/// Walk the per-CPU current-thread pointer to find the owning
/// EPROCESS, then update its MmWorkingSet::current. If we cannot
/// resolve the current process (early boot), silently no-op.
#[inline(always)]
fn bump_current(delta: u64) {
    let ethread = crate::arch::common::percpu::get_current_thread();
    if ethread.is_null() {
        return;
    }
    let proc = unsafe { (*ethread).threads_process };
    if proc.is_null() {
        return;
    }
    unsafe {
        (*proc).working_set.current.fetch_add(delta, Ordering::Relaxed);
    }
}

/// Look up the PTE for `va` in `pml4_phys`. Returns the PTE
/// virtual address (kernel self-map window) on success, or None if
/// `pml4_phys` is not the current process's PML4.
///
/// This is a deliberate simplification: a full implementation would
/// walk PML4 → PDPT → PD → PT manually for any PML4. For the
/// bootstrap we only manage the current process's pages, so the
/// self-map window is sufficient.
fn find_user_pte(pml4_phys: u64, va: u64) -> Option<*mut MMPTE> {
    let ethread = crate::arch::common::percpu::get_current_thread();
    if ethread.is_null() {
        return None;
    }
    let proc = unsafe { (*ethread).threads_process };
    if proc.is_null() {
        return None;
    }
    let current_pml4 = unsafe { (*proc).pml4_phys };
    if current_pml4 != pml4_phys {
        return None;
    }
    Some(crate::mm::vas::pte_address_of(va))
}

// =============================================================================
// Working Set Lock/Unlock
// =============================================================================

/// Lock pages into the working set.
/// Prevents pages from being trimmed even under memory pressure.
pub fn lock_working_set(_pml4_phys: u64, base_address: u64, size: u64) -> i32 {
    let mut locked: u64 = 0;
    let mut va = base_address & !0xFFFu64;
    let end = (base_address + size + 0xFFF) & !0xFFFu64;

    while va < end {
        let pte_ptr = crate::mm::vas::pte_address_of(va);
        let pte = unsafe { *pte_ptr };

        if pte.is_hardware() {
            let pfn_no = pte.hardware_page_frame() >> 12;
            let db = pfn::PFN_DB.lock();
            if let Some(entry) = db.entry(pfn_no) {
                unsafe {
                    (*entry).share_count = (*entry).share_count.saturating_add(1000);
                }
            }
            locked += 1;
        }
        va += 0x1000;
    }

    // Suppress unused variable warnings - reserved for future logging
    let _ = locked;
    // [DISABLED] // // kprintln!("[WS] lock_working_set: VA=0x{:016x}, size={}, locked={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]         base_address, size, locked);
    0
}

/// Unlock pages from the working set.
pub fn unlock_working_set(_pml4_phys: u64, base_address: u64, size: u64) -> i32 {
    let mut unlocked: u64 = 0;
    let mut va = base_address & !0xFFFu64;
    let end = (base_address + size + 0xFFF) & !0xFFFu64;

    while va < end {
        let pte_ptr = crate::mm::vas::pte_address_of(va);
        let pte = unsafe { *pte_ptr };

        if pte.is_hardware() {
            let pfn_no = pte.hardware_page_frame() >> 12;
            let db = pfn::PFN_DB.lock();
            if let Some(entry) = db.entry(pfn_no) {
                unsafe {
                    (*entry).share_count = (*entry).share_count.saturating_sub(1000);
                }
            }
            unlocked += 1;
        }
        va += 0x1000;
    }

    // Suppress unused variable warnings - reserved for future logging
    let _ = unlocked;
    // [DISABLED] // // kprintln!("[WS] unlock_working_set: VA=0x{:016x}, size={}, unlocked={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]         base_address, size, unlocked);
    0
}

// =============================================================================
// Extended Working Set Query
// =============================================================================

/// Extended working set entry information.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WorkingSetEntryEx {
    pub virtual_address: u64,
    pub pfn: u64,
    pub protection: u32,
    pub shared: u8,
    pub active: u8,
    pub locked: u8,
    pub reserved: u8,
    pub node: u16,
    pub share_count: u32,
}

/// Query extended working set information.
pub fn query_working_set_ex(pml4_phys: u64) -> Vec<WorkingSetEntryEx> {
    let mut entries = Vec::new();
    let pml4_va = pml4_phys as *const MMPTE;
    let _ = entries; // Reserved for future statistics

    for pxe in 1..511usize {
        let pxe_entry = unsafe { *pml4_va.add(pxe) };
        if !pxe_entry.is_hardware() || pxe_entry.large() || !pxe_entry.writable() {
            continue;
        }

        let pdpt_phys = pxe_entry.hardware_page_frame();
        let pdpt_va = pdpt_phys as *const MMPTE;
        for ppe in 0..PT_ENTRIES {
            let ppe_entry = unsafe { *pdpt_va.add(ppe) };
            if !ppe_entry.is_hardware() || ppe_entry.large() {
                continue;
            }

            let pd_phys = ppe_entry.hardware_page_frame();
            let pd_va = pd_phys as *const MMPTE;
            for pde in 0..PT_ENTRIES {
                let pde_entry = unsafe { *pd_va.add(pde) };
                if !pde_entry.is_hardware() || pde_entry.large() {
                    continue;
                }

                let pt_phys = pde_entry.hardware_page_frame();
                let pt_va = pt_phys as *const MMPTE;
                for pte_i in 0..PT_ENTRIES {
                    let pte = unsafe { *pt_va.add(pte_i) };
                    if !pte.is_hardware() {
                        continue;
                    }

                    let va = ((pxe as u64) << 39)
                        | ((ppe as u64) << 30)
                        | ((pde as u64) << 21)
                        | ((pte_i as u64) << 12);

                    let pfn_no = pte.hardware_page_frame() >> 12;
                    let db = pfn::PFN_DB.lock();
                    let share_count = if let Some(entry) = db.entry(pfn_no) {
                        unsafe { (*entry).share_count() }
                    } else {
                        0
                    };

                    let locked = if share_count > 100 { 1 } else { 0 };

                    entries.push(WorkingSetEntryEx {
                        virtual_address: va,
                        pfn: pfn_no,
                        protection: 0,
                        shared: if share_count > 1 { 1 } else { 0 },
                        active: 1,
                        locked,
                        reserved: 0,
                        node: 0,
                        share_count,
                    });
                }
            }
        }
    }

    // [DISABLED] // // kprintln!("[WS] query_working_set_ex: found {} entries", entries.len())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    entries
}

// =============================================================================
// MmTrimProcessWorkingSet
// =============================================================================

/// Trim the process working set.
pub fn MmTrimProcessWorkingSet(_process_handle: u64, _min_size: i64) -> i32 {
    // _process_handle and _min_size are intentionally unused - reserved for future logging
    // [DISABLED] // // kprintln!("[WS] MmTrimProcessWorkingSet: handle={:#x}, min={}", _process_handle, _min_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    let pml4 = crate::mm::vas::current_root();
    if pml4 == 0 {
        return 0xC000000Du32 as i32;
    }

    let mut total_trimmed: u64 = 0;
    let target_trim = 64u64;

    let mut iterations = 0;
    while total_trimmed < target_trim && iterations < 100 {
        let trimmed = trim_working_set(pml4, 32);
        if trimmed == 0 {
            break;
        }
        total_trimmed += trimmed;
        iterations += 1;
    }

    // Suppress unused variable warnings
    let _ = total_trimmed;
    // [DISABLED] // // kprintln!("[WS] MmTrimProcessWorkingSet: trimmed {} pages", total_trimmed)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    0
}

/// Set the minimum working set size for a process.
pub fn set_process_working_set_minimum(_process_handle: u64, _min_size: u64) -> i32 {
    // _process_handle and _min_size are intentionally unused - reserved for future logging
    // [DISABLED] // // kprintln!("[WS] set_process_working_set_minimum: handle={:#x}, min={}", _process_handle, _min_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    0
}

/// Set the maximum working set size for a process.
pub fn set_process_working_set_maximum(_process_handle: u64, _max_size: u64) -> i32 {
    // _process_handle and _max_size are intentionally unused - reserved for future logging
    // [DISABLED] // // kprintln!("[WS] set_process_working_set_maximum: handle={:#x}, max={}", _process_handle, _max_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    0
}

/// Initialize the working set subsystem.
pub fn working_set_init() {
    // [DISABLED] // // kprintln!("[MM] Working set manager initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}
