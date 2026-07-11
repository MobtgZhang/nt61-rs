//! PFN (Page Frame Number) database
//
//! `_MMPFN` is a metadata record for every physical 4 KiB page frame in
//! the system. The fields mirror the structure used by Windows 7
//! (around 0x30 bytes per entry) but compressed to the subset that
//! the kernel actually inspects on the hot path:
//
//! * `u1` / `u2` / `u3` / `u4` are 32-bit overlay unions whose meaning
//!   depends on the current state of the page. The most useful ones
//!   are:
//!   - `u1.ListEntry` — the linked-list node when the page is on a
//!     free / standby / modified / zeroed list.
//!   - `u2.ShortFlags` — state + reference count bits.
//!   - `u3.PteAddress` — for resident pages, the PTE that points at
//!     this PFN; for prototype/transition PTE work, the PTE being
//!     examined.
//!   - `u4.OriginalPte` — for section / pagefile pages, the PTE value
//!     that was demoted.
//! * `share_count` — number of PTEs that share the page (mapping count
//!   beyond the owning PTE).
//! * `pfn_database_index` — index back into this database (used to
//!   recover the PFN from a pointer to an `_MMPFN`).
//
//! Pages are bucketed into state lists:
//
//! * Active (valid) — not on any list, the owning PTE points to us.
//! * Standby 0..7 — 8 priority buckets for clean-but-evicted pages.
//! * Modified — clean-from-disk-dirty pages that still need to be
//!   written out.
//! * ModifiedNoWrite — pages that are dirty but pinned (won't be
//!   written out — used for the pagefile backing of large pages).
//! * Free — pages that have not been zeroed.
//! * Zeroed — pages that have been zeroed and are ready to hand out.
//! * Bad — pages the firmware reported as broken.
//
//! The free / zeroed / standby / modified lists are protected by
//! `PFN_LOCK` (the outermost lock in the system per NT conventions).

#![allow(non_snake_case)]

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pte::{pfn_to_phys, pfn_from_phys, PfnNumber, MMPTE};

/// Page frame state — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MMPFNSTATE {
    Active = 0,
    Transition = 1,
    /// Standby 0..7 — encoded in the lowest 3 bits of the value.
    Standby0 = 2,
    Standby1 = 3,
    Standby2 = 4,
    Standby3 = 5,
    Standby4 = 6,
    Standby5 = 7,
    Standby6 = 8,
    Standby7 = 9,
    Modified = 10,
    ModifiedNoWrite = 11,
    Free = 12,
    Zeroed = 13,
    Bad = 14,
    Rom = 15,
}

impl MMPFNSTATE {
    pub fn from_bits(b: u32) -> Self {
        match b {
            0 => MMPFNSTATE::Active,
            1 => MMPFNSTATE::Transition,
            2 => MMPFNSTATE::Standby0,
            3 => MMPFNSTATE::Standby1,
            4 => MMPFNSTATE::Standby2,
            5 => MMPFNSTATE::Standby3,
            6 => MMPFNSTATE::Standby4,
            7 => MMPFNSTATE::Standby5,
            8 => MMPFNSTATE::Standby6,
            9 => MMPFNSTATE::Standby7,
            10 => MMPFNSTATE::Modified,
            11 => MMPFNSTATE::ModifiedNoWrite,
            12 => MMPFNSTATE::Free,
            13 => MMPFNSTATE::Zeroed,
            14 => MMPFNSTATE::Bad,
            15 => MMPFNSTATE::Rom,
            _ => MMPFNSTATE::Active,
        }
    }
    pub fn as_u32(self) -> u32 {
        self as u32
    }
    pub fn is_standby(self) -> bool {
        matches!(self,
            MMPFNSTATE::Standby0 | MMPFNSTATE::Standby1 | MMPFNSTATE::Standby2
            | MMPFNSTATE::Standby3 | MMPFNSTATE::Standby4 | MMPFNSTATE::Standby5
            | MMPFNSTATE::Standby6 | MMPFNSTATE::Standby7)
    }
    pub fn standby_priority(self) -> u8 {
        match self {
            MMPFNSTATE::Standby0 => 0,
            MMPFNSTATE::Standby1 => 1,
            MMPFNSTATE::Standby2 => 2,
            MMPFNSTATE::Standby3 => 3,
            MMPFNSTATE::Standby4 => 4,
            MMPFNSTATE::Standby5 => 5,
            MMPFNSTATE::Standby6 => 6,
            MMPFNSTATE::Standby7 => 7,
            _ => 0,
        }
    }
}

/// Doubly-linked list node stored in the PFN entry.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct LIST_ENTRY {
    pub flink: PfnNumber,
    pub blink: PfnNumber,
}

/// `_MMPFN` — one per physical 4 KiB page.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MMPFN {
    pub u1: LIST_ENTRY,
    pub u2: PfnShortFlags,
    /// Owner PTE or related PTE depending on state.
    pub u3: PfnU3,
    /// Original PTE (saved when a Hardware PTE is demoted to
    /// prototype / software / transition).
    pub u4: OriginalPteUnion,
    pub pte_address: *mut MMPTE,
    pub share_count: u32,
    /// Standby priority (0..7) or page-file number etc. depending on
    /// state. The lowest 3 bits are the priority for standby pages.
    pub pfn_priority: u8,
    pub pfn_database_index: u32,
    pub reference_count: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union PfnShortFlags {
    pub raw: u32,
    pub bits: PfnShortFlagsBits,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PfnShortFlagsBits {
    /// 4 bits: state
    pub state: u32,
    /// 4 bits: priority
    pub priority: u32,
    /// 1 bit: modified (in modified list)
    pub modified: u32,
    /// 1 bit: read in progress
    pub read_in_progress: u32,
    /// 1 bit: write in progress
    pub write_in_progress: u32,
    /// 16 bits: reference count (when packed)
    pub reference_count: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union PfnU3 {
    pub flags: PfnU3Flags,
    pub pte_address: *mut MMPTE,
    /// For prototype PTE chains, the pointer to the prototype PTE
    /// describing the page.
    pub proto_pte_address: *mut MMPTE,
    pub raw: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct PfnU3Flags {
    pub modified: u32,
    pub read_in_progress: u32,
    pub write_in_progress: u32,
    /// 25 bits: offset in paging file, low bits
    pub paging_file_offset: u32,
    /// 4 bits: page file number
    pub paging_file: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union OriginalPteUnion {
    pub pte: MMPTE,
    pub pfn_link: PfnNumber,
    pub raw: u64,
}

impl Default for OriginalPteUnion {
    fn default() -> Self { Self { raw: 0 } }
}

impl MMPFN {
    pub const fn empty() -> Self {
        Self {
            u1: LIST_ENTRY { flink: 0, blink: 0 },
            u2: PfnShortFlags { raw: 0 },
            u3: PfnU3 { raw: 0 },
            u4: OriginalPteUnion { raw: 0 },
            pte_address: ptr::null_mut(),
            share_count: 0,
            pfn_priority: 0,
            pfn_database_index: 0,
            reference_count: 0,
        }
    }

    pub fn state(&self) -> MMPFNSTATE {
        let raw = unsafe { self.u2.raw };
        MMPFNSTATE::from_bits(raw & 0xF)
    }
    pub fn set_state(&mut self, s: MMPFNSTATE) {
        // Pack the 4-bit state in the low 4 bits of `u2.raw`.
        let raw = unsafe { self.u2.raw };
        let new = (raw & !0xF) | (s as u32 & 0xF);
        self.u2 = PfnShortFlags { raw: new };
    }
    pub fn standby_priority(&self) -> u8 {
        let raw = unsafe { self.u2.raw };
        ((raw >> 4) & 0x7) as u8
    }
    pub fn set_standby_priority(&mut self, p: u8) {
        let raw = unsafe { self.u2.raw };
        self.u2 = PfnShortFlags { raw: (raw & !0x70) | (((p as u32) & 0x7) << 4) };
    }
    pub fn set_share_count(&mut self, c: u32) { self.share_count = c; }
    pub fn share_count(&self) -> u32 { self.share_count }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const PFN_LIST_MAX: usize = 16;

/// All the lists the PFN state machine knows about.
const PFNL_FREE: usize = 0;
const PFNL_ZEROED: usize = 1;
const PFNL_STANDBY0: usize = 2;
const PFNL_STANDBY7: usize = 9;
const PFNL_MODIFIED: usize = 10;
const PFNL_MODIFIED_NW: usize = 11;
const PFNL_BAD: usize = 12;
const PFNL_TRANSITION: usize = 13;
const PFNL_LIST_COUNT: usize = 14;

#[derive(Clone, Copy, Default)]
struct ListHead {
    head: PfnNumber,
    count: u64,
}

/// Global PFN database state.
pub struct PfnDatabase {
    pub pfn_array: *mut MMPFN,
    pub pfn_count: u64,
    pub lowest_pfn: u64,
    pub highest_pfn: u64,
    pub initialized: bool,
    lists: [ListHead; PFNL_LIST_COUNT],
    /// Total number of pages per state — diagnostic counters.
    pub state_counts: [AtomicU64; 16],
    /// Free-page count.
    pub total_free: AtomicU64,
    /// Zeroed-page count.
    pub total_zeroed: AtomicU64,
    /// Standby count.
    pub total_standby: AtomicU64,
    /// Modified count.
    pub total_modified: AtomicU64,
}

unsafe impl Send for PfnDatabase {}
unsafe impl Sync for PfnDatabase {}

impl PfnDatabase {
    pub const fn new() -> Self {
        Self {
            pfn_array: ptr::null_mut(),
            pfn_count: 0,
            lowest_pfn: 0,
            highest_pfn: 0,
            initialized: false,
            lists: [ListHead { head: 0, count: 0 }; PFNL_LIST_COUNT],
            state_counts: [const { AtomicU64::new(0) }; 16],
            total_free: AtomicU64::new(0),
            total_zeroed: AtomicU64::new(0),
            total_standby: AtomicU64::new(0),
            total_modified: AtomicU64::new(0),
        }
    }

    /// Initialise the database with a contiguous storage region
    /// (`storage` of `storage_entries * core::mem::size_of::<MMPFN>()`)
    /// covering PFNs `[base_pfn, base_pfn + pfn_count)`.
    ///
    /// All PFNs start in the Active state with the supplied `state`
    /// for the first pass. `mark_active` puts a page in the free
    /// list; `mark_zeroed` puts it in the zeroed list.
    pub fn init(&mut self, storage: *mut u8, storage_bytes: usize, base_pfn: PfnNumber, pfn_count: PfnNumber) {
        let bytes_needed = (pfn_count as usize) * core::mem::size_of::<MMPFN>();
        // If storage is smaller than what the full pfn_count would
        // need, truncate pfn_count to whatever storage can hold.
        // This is the "memory-map lies, buddy is tight" fallback
        // path; the kernel still boots, just with fewer tracked
        // PFNs than physical RAM has.
        let usable_pfns = if bytes_needed > storage_bytes {
            storage_bytes / core::mem::size_of::<MMPFN>()
        } else {
            pfn_count as usize
        };
        let usable_bytes = usable_pfns * core::mem::size_of::<MMPFN>();
        // Zero the storage so the list state is consistent.
        unsafe { ptr::write_bytes(storage, 0, usable_bytes); }
        self.pfn_array = storage as *mut MMPFN;
        self.pfn_count = usable_pfns as u64;
        self.lowest_pfn = base_pfn;
        self.highest_pfn = base_pfn + usable_pfns as u64;
        self.initialized = true;
    }

    /// Convert a PFN to the address of its database entry.
    /// Returns `None` for out-of-range PFNs.
    #[inline]
    pub fn entry(&self, pfn: PfnNumber) -> Option<*mut MMPFN> {
        if !self.initialized { return None; }
        if pfn < self.lowest_pfn || pfn >= self.highest_pfn {
            return None;
        }
        let idx = (pfn - self.lowest_pfn) as usize;
        unsafe { Some(self.pfn_array.add(idx)) }
    }

    /// Convert a PFN to the address of its database entry without
    /// bounds checking.
    /// # Safety
    /// Caller must guarantee the PFN is in range.
    #[inline]
    pub unsafe fn entry_unchecked(&self, pfn: PfnNumber) -> *mut MMPFN {
        let idx = (pfn - self.lowest_pfn) as usize;
        self.pfn_array.add(idx)
    }

    /// Convert a PFN database entry pointer back to its PFN.
    #[inline]
    pub fn pfn_of(&self, entry: *mut MMPFN) -> Option<PfnNumber> {
        if !self.initialized || self.pfn_array.is_null() { return None; }
        let off = (entry as usize) - (self.pfn_array as usize);
        if off % core::mem::size_of::<MMPFN>() != 0 { return None; }
        let idx = off / core::mem::size_of::<MMPFN>();
        if idx as u64 >= self.pfn_count { return None; }
        Some(self.lowest_pfn + idx as u64)
    }

    // -- List operations ------------------------------------------------

    fn list_index_for(state: MMPFNSTATE, _priority: u8) -> usize {
        match state {
            MMPFNSTATE::Free => PFNL_FREE,
            MMPFNSTATE::Zeroed => PFNL_ZEROED,
            MMPFNSTATE::Bad => PFNL_BAD,
            MMPFNSTATE::Modified => PFNL_MODIFIED,
            MMPFNSTATE::ModifiedNoWrite => PFNL_MODIFIED_NW,
            MMPFNSTATE::Transition => PFNL_TRANSITION,
            s if s.is_standby() => PFNL_STANDBY0 + s.standby_priority() as usize,
            _ => PFNL_FREE,
        }
    }

    /// Insert a PFN at the head of the list for its current state.
    pub fn insert_head(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe { self.insert_head_entry(entry, pfn); }
    }

    unsafe fn insert_head_entry(&mut self, entry: *mut MMPFN, pfn: PfnNumber) {
        let state = (*entry).state();
        let list_idx = Self::list_index_for(state, (*entry).standby_priority());
        // We mutate `self.lists` and access self.entry, so we must
        // not hold a `&mut self.lists` reference while calling
        // `self.entry`. Work on a raw pointer instead.
        let head = self.lists[list_idx].head;
        (*entry).u1.flink = head;
        (*entry).u1.blink = 0;
        if head != 0 {
            let old = self.entry(head).expect("pfn in range");
            (*old).u1.blink = pfn;
        }
        self.lists[list_idx].head = pfn;
        self.lists[list_idx].count += 1;
        // Index in.
        (*entry).pfn_database_index = (pfn - self.lowest_pfn) as u32;
        self.bump_state_count(state, 1);
    }

    /// Remove a PFN from the list it is currently on. The PFN must be
    /// in a list-bearing state.
    pub fn unlink(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe { self.unlink_entry(entry, pfn); }
    }

    pub unsafe fn unlink_entry(&mut self, entry: *mut MMPFN, _pfn: PfnNumber) {
        let state = (*entry).state();
        let list_idx = Self::list_index_for(state, (*entry).standby_priority());
        let flink = (*entry).u1.flink;
        let blink = (*entry).u1.blink;
        if blink != 0 {
            let prev = self.entry(blink).expect("pfn in range");
            (*prev).u1.flink = flink;
        } else {
            self.lists[list_idx].head = flink;
        }
        if flink != 0 {
            let next = self.entry(flink).expect("pfn in range");
            (*next).u1.blink = blink;
        }
        self.lists[list_idx].count = self.lists[list_idx].count.saturating_sub(1);
        (*entry).u1.flink = 0;
        (*entry).u1.blink = 0;
        self.bump_state_count(state, -1);
    }

    fn bump_state_count(&self, state: MMPFNSTATE, delta: i64) {
        if (state.as_u32() as usize) < self.state_counts.len() {
            // Use SeqCst for cross-core visibility in multi-core environment
            self.state_counts[state.as_u32() as usize]
                .fetch_add(delta as u64, Ordering::SeqCst);
        }
        match state {
            MMPFNSTATE::Free => { self.total_free.fetch_add(delta as u64, Ordering::SeqCst); }
            MMPFNSTATE::Zeroed => { self.total_zeroed.fetch_add(delta as u64, Ordering::SeqCst); }
            s if s.is_standby() => { self.total_standby.fetch_add(delta as u64, Ordering::SeqCst); }
            MMPFNSTATE::Modified | MMPFNSTATE::ModifiedNoWrite => {
                self.total_modified.fetch_add(delta as u64, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    /// Pop the head of the free list, or None if empty.
    pub fn pop_free(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_FREE].head == 0 { return None; }
        let pfn = self.lists[PFNL_FREE].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe { self.unlink_entry(entry, pfn); }
        Some(pfn)
    }

    /// Pop the head of the zeroed list.
    pub fn pop_zeroed(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_ZEROED].head == 0 { return None; }
        let pfn = self.lists[PFNL_ZEROED].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe { self.unlink_entry(entry, pfn); }
        Some(pfn)
    }

    /// Pop the head of the modified list.
    pub fn pop_modified(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_MODIFIED].head == 0 { return None; }
        let pfn = self.lists[PFNL_MODIFIED].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe { self.unlink_entry(entry, pfn); }
        Some(pfn)
    }

    /// Pop the head of the no-write modified list.
    pub fn pop_modified_no_write(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_MODIFIED_NW].head == 0 { return None; }
        let pfn = self.lists[PFNL_MODIFIED_NW].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe { self.unlink_entry(entry, pfn); }
        Some(pfn)
    }

    /// Pop the head of the highest-priority standby list (7 first).
    pub fn pop_standby(&mut self) -> Option<PfnNumber> {
        // Iterate from highest to lowest priority.
        for i in (PFNL_STANDBY0..=PFNL_STANDBY7).rev() {
            if self.lists[i].head != 0 {
                let pfn = self.lists[i].head;
                let entry = self.entry(pfn).expect("pfn in range");
                unsafe { self.unlink_entry(entry, pfn); }
                return Some(pfn);
            }
        }
        None
    }

    /// True if all the per-state lists are empty.
    pub fn lists_is_empty(&self) -> bool {
        self.lists[PFNL_MODIFIED].head == 0 && self.lists[PFNL_FREE].head == 0
    }

    /// Iterator over a list starting at `head`.
    pub unsafe fn iter_list(&self, head: PfnNumber, mut cb: impl FnMut(PfnNumber)) {
        let mut current = head;
        let mut steps = 0u64;
        while current != 0 && steps < self.pfn_count {
            cb(current);
            let entry = self.entry(current).expect("pfn in range");
            current = (*entry).u1.flink;
            steps += 1;
        }
    }

    /// Add a range of PFNs to the free list.
    pub fn seed_free(&mut self, base: PfnNumber, count: PfnNumber) {
        for i in 0..count {
            let pfn = base + i;
            let entry = self.entry(pfn).expect("pfn in range");
            unsafe {
                (*entry).set_state(MMPFNSTATE::Free);
                (*entry).set_standby_priority(0);
                (*entry).reference_count = 0;
                (*entry).share_count = 0;
                (*entry).pte_address = ptr::null_mut();
                (*entry).u3.raw = 0;
                (*entry).u4.raw = 0;
                self.insert_head_entry(entry, pfn);
            }
        }
    }

    /// Add a single PFN to the free list.
    pub fn add_to_free(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe {
            (*entry).set_state(MMPFNSTATE::Free);
            (*entry).set_standby_priority(0);
            (*entry).reference_count = 0;
            (*entry).share_count = 0;
            self.insert_head_entry(entry, pfn);
        }
    }

    /// Mark a PFN as active (allocated).
    ///
    /// The free-list-population functions (`pop_free`, `pop_zeroed`,
    /// `pop_modified`, ...) already remove the entry from its current
    /// list before returning the PFN to the caller, so this function
    /// does NOT re-unlink. It only flips the state to `Active` and
    /// initialises the reference / share counts.
    ///
    /// Historical bug: an earlier version of this function called
    /// `unlink_entry` a second time when the state was still `Free` /
    /// `Zeroed`, which (because `unlink_entry` does not change the
    /// state and runs unconditionally on the next list head it
    /// sees) corrupted the list head. We now rely on the pop
    /// functions to do the unlink.
    pub fn allocate_pfn(&mut self, pfn: PfnNumber) -> bool {
        let entry = match self.entry(pfn) { Some(e) => e, None => return false };
        unsafe {
            (*entry).set_state(MMPFNSTATE::Active);
            (*entry).reference_count = 1;
            (*entry).share_count = 1;
        }
        true
    }

    /// Move a PFN to the standby list at the given priority.
    pub fn standby(&mut self, pfn: PfnNumber, priority: u8) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe {
            if (*entry).state() == MMPFNSTATE::Active
                || (*entry).state() == MMPFNSTATE::Transition
            {
                // No list to unlink - these states are not on any list.
            } else {
                self.unlink_entry(entry, pfn);
            }
            // Select the correct standby state based on priority (0..7)
            let prio = priority & 0x7;
            let standby_state = match prio {
                0 => MMPFNSTATE::Standby0,
                1 => MMPFNSTATE::Standby1,
                2 => MMPFNSTATE::Standby2,
                3 => MMPFNSTATE::Standby3,
                4 => MMPFNSTATE::Standby4,
                5 => MMPFNSTATE::Standby5,
                6 => MMPFNSTATE::Standby6,
                7 => MMPFNSTATE::Standby7,
                _ => MMPFNSTATE::Standby0,
            };
            (*entry).set_state(standby_state);
            (*entry).set_standby_priority(prio);
            self.insert_head_entry(entry, pfn);
        }
    }

    /// Move a PFN to the modified list.
    pub fn modified(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe {
            if (*entry).state() == MMPFNSTATE::Active
                || (*entry).state() == MMPFNSTATE::Transition
            {
                // No list to unlink.
            } else {
                self.unlink_entry(entry, pfn);
            }
            (*entry).set_state(MMPFNSTATE::Modified);
            (*entry).set_standby_priority(0);
            self.insert_head_entry(entry, pfn);
        }
    }

    /// Move a PFN to the zeroed list (already zeroed).
    pub fn insert_zeroed(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) { Some(e) => e, None => return };
        unsafe {
            if (*entry).state() == MMPFNSTATE::Free
                || (*entry).state() == MMPFNSTATE::Zeroed
                || (*entry).state() == MMPFNSTATE::Active
            {
                if (*entry).state() != MMPFNSTATE::Active {
                    self.unlink_entry(entry, pfn);
                }
            } else {
                self.unlink_entry(entry, pfn);
            }
            (*entry).set_state(MMPFNSTATE::Zeroed);
            (*entry).set_standby_priority(0);
            self.insert_head_entry(entry, pfn);
        }
    }

    /// Translate a PFN to a physical address.
    pub fn phys(&self, pfn: PfnNumber) -> u64 { pfn_to_phys(pfn) }

    /// Translate a physical address to a PFN (no bounds check; for
    /// translating a PA to a database index the caller should have
    /// already done so).
    pub fn pfn_of_phys(&self, pa: u64) -> PfnNumber { pfn_from_phys(pa) }

    /// Diagnostics.
    pub fn free_count(&self) -> u64 { self.total_free.load(Ordering::Relaxed) }
    pub fn zeroed_count(&self) -> u64 { self.total_zeroed.load(Ordering::Relaxed) }
    pub fn standby_count(&self) -> u64 { self.total_standby.load(Ordering::Relaxed) }
    pub fn modified_count(&self) -> u64 { self.total_modified.load(Ordering::Relaxed) }
    pub fn total_count(&self) -> u64 { self.pfn_count }
}

// ---------------------------------------------------------------------------
// Global singleton and accessors
// ---------------------------------------------------------------------------

pub static PFN_DB: Spinlock<PfnDatabase> = Spinlock::new(PfnDatabase::new());

/// Static BSS storage used as a bootstrap fallback. Holds 128K PFNs
/// (~2 MiB), enough to track the first 512 MiB of RAM during early boot
/// when the buddy allocator hasn't been fully initialized yet.
static mut PFN_STORAGE_BOOTSTRAP: [u8; 2 * 1024 * 1024] = [0; 2 * 1024 * 1024];

/// Physical address of the dynamic PFN database storage (set by
/// `init`). Kept so the arch code can register it with the
/// self-map.
static mut PFN_STORAGE_PTR: *mut u8 = core::ptr::null_mut();
static mut PFN_STORAGE_PHYS: u64 = 0;
static mut PFN_STORAGE_USED: usize = 0;
static mut PFN_STORAGE_CAPACITY: usize = 0;

/// Total number of PFNs initialised.
static mut PFN_COUNT: PfnNumber = 0;

/// Initial base PFN (lowest free PFN available).
static mut PFN_BASE: PfnNumber = 0;

/// Boot-time initialisation. Allocates the PFN database storage
/// from the buddy allocator (which is already up because
/// `frame::init` runs before `pfn::init`), sized for the full
/// range of physical memory. The size scales from 2 GiB
/// (`~2 MiB` of metadata) to 192 GiB (`~384 MiB` of metadata).
pub fn init(base_pfn: PfnNumber, pfn_count: PfnNumber) {
    let bytes_needed = (pfn_count as usize) * core::mem::size_of::<MMPFN>();
    unsafe {
        PFN_COUNT = pfn_count;
        PFN_BASE = base_pfn;
        // Try to allocate the full-size storage from the buddy.
        let pages = (bytes_needed + 4095) / 4096;
        if let Some(phys) = crate::mm::frame::allocate_pages(pages as u64) {
            // The PFN DB storage lives in kernel-VA space via the
            // recursive self-map, so we can access it through its
            // physical address directly.
            PFN_STORAGE_PTR = phys as *mut u8;
            PFN_STORAGE_PHYS = phys;
            PFN_STORAGE_USED = pages * 4096;
            PFN_STORAGE_CAPACITY = pages * 4096;
            crate::hal::serial::write_string("[mm] pfn::init: dynamic storage OK\r\n");
        } else if bytes_needed <= PFN_STORAGE_BOOTSTRAP.len() {
            // Fall back to the static buffer (cap is 8K PFNs,
            // about 32 MiB of RAM). The buddy is so out of memory
            // that we can't even allocate the proper tables.
            crate::hal::serial::write_string("[mm] pfn::init: using static storage\r\n");
            PFN_STORAGE_PTR = PFN_STORAGE_BOOTSTRAP.as_mut_ptr();
            PFN_STORAGE_USED = bytes_needed;
            PFN_STORAGE_CAPACITY = PFN_STORAGE_BOOTSTRAP.len();
        } else {
            // CRITICAL ERROR: Cannot allocate PFN database storage.
            // Without full PFN tracking, memory management is compromised.
            // System cannot safely continue - trigger bugcheck.
            crate::hal::serial::write_string("[FATAL] pfn::init: no storage\r\n");
            // Trigger CRITICAL_DATA_TABLE_CORRUPTION bugcheck
            // This indicates critical memory management data structures are corrupted
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::DataInconsistencyLock,
                bytes_needed as u64,           // P1: bytes needed
                PFN_STORAGE_BOOTSTRAP.len() as u64,  // P2: bootstrap capacity
                pfn_count,                    // P3: requested PFN count
                core::mem::size_of::<MMPFN>() as u64, // P4: sizeof(MMPFN)
            );
            // NOTE: bugcheck_with() is ! (never returns), so no code after this
        }
        let mut db = PFN_DB.lock();
        db.init(PFN_STORAGE_PTR, PFN_STORAGE_CAPACITY, base_pfn, pfn_count);
        db.seed_free(base_pfn, pfn_count);
        crate::hal::serial::write_string("[mm] pfn::init: PFN_COUNT=0x");
        crate::hal::serial::write_hex_u64(pfn_count);
        crate::hal::serial::write_string(" highest_pfn=0x");
        crate::hal::serial::write_hex_u64(db.highest_pfn);
        crate::hal::serial::write_string("\r\n");
    }
}

/// Allocate one PFN (zeroed preferred, else free). Returns None if no
/// pages are available.
pub fn allocate_pfn() -> Option<PfnNumber> {
    let mut db = PFN_DB.lock();
    if let Some(pfn) = db.pop_zeroed() {
        db.allocate_pfn(pfn);
        return Some(pfn);
    }
    if let Some(pfn) = db.pop_free() {
        db.allocate_pfn(pfn);
        return Some(pfn);
    }
    // Self-heal: the free list head is 0 but the count claims there
    // are entries. Walk the database to find Free entries and rebuild
    // the list.
    let mut free_count = 0u64;
    for pfn in db.lowest_pfn..db.highest_pfn {
        if let Some(entry) = db.entry(pfn) {
            unsafe {
                if (*entry).state() == MMPFNSTATE::Free {
                    free_count += 1;
                }
            }
        }
    }
    crate::hal::serial::write_string("[PFN] OUT_OF_PFNS: self-heal free_in_db=0x");
    crate::hal::serial::write_hex_u64(free_count);
    crate::hal::serial::write_string(" free_list_count=0x");
    crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].count as u64);
    crate::hal::serial::write_string("\r\n");
    if free_count > 0 {
        // Try to repair the list by re-inserting all free entries.
        // First reset the list.
        db.lists[PFNL_FREE].head = 0;
        db.lists[PFNL_FREE].count = 0;
        for pfn in db.lowest_pfn..db.highest_pfn {
            if let Some(entry) = db.entry(pfn) {
                unsafe {
                    if (*entry).state() == MMPFNSTATE::Free {
                        (*entry).u1.flink = 0;
                        (*entry).u1.blink = 0;
                        db.insert_head_entry(entry, pfn);
                    }
                }
            }
        }
        crate::hal::serial::write_string("[PFN] self-heal: rebuilt free list, head=0x");
        crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].head);
        crate::hal::serial::write_string(" count=0x");
        crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].count as u64);
        crate::hal::serial::write_string("\r\n");
        // Retry the allocation.
        if let Some(pfn) = db.pop_free() {
            db.allocate_pfn(pfn);
            return Some(pfn);
        }
    }
    None
}

/// Allocate a contiguous range of `count` PFNs. Falls back to
/// non-contiguous if the contig run cannot be assembled.
pub fn allocate_pfn_range(count: PfnNumber) -> Option<PfnNumber> {
    if count == 0 { return None; }
    let mut db = PFN_DB.lock();
    if count == 1 {
        return allocate_pfn();
    }
    // Scan the free list for a contiguous run of `count` pages.
    let head = db.lists[PFNL_FREE].head;
    let mut current = head;
    let mut run_start: Option<PfnNumber> = None;
    let mut run_len: u64 = 0;
    let mut prev: PfnNumber = 0;
    // Walk up to 1M PFNs to keep the search bounded.
    let mut steps = 0u64;
    while current != 0 && steps < 1_000_000 {
        steps += 1;
        if prev != 0 && current == prev + 1 {
            run_len += 1;
            if run_start.is_none() {
                run_start = Some(prev);
            }
        } else {
            run_len = 1;
            run_start = Some(current);
        }
        if run_len >= count {
            // Unlink `count` consecutive PFNs.
            for i in 0..count {
                let p = run_start.unwrap() + i;
                db.unlink(p);
                db.allocate_pfn(p);
            }
            return run_start;
        }
        let entry = db.entry(current)?;
        unsafe {
            prev = current;
            current = (*entry).u1.flink;
        }
    }
    // Non-contiguous fallback: just return the first free page and
    // rely on the caller to handle a single page.
    if let Some(p) = db.pop_free() {
        db.allocate_pfn(p);
        return Some(p);
    }
    None
}

/// Return a PFN to the free list (zeroed, since we just released it
/// and the caller can clear it if they care).
pub fn free_pfn(pfn: PfnNumber) {
    let mut db = PFN_DB.lock();
    db.add_to_free(pfn);
}

/// Reserve a PFN so it will never be returned by `allocate_pfn` /
/// `pop_zeroed` / `pop_free`. This is the right primitive for
/// "I already own this page and the allocator must not hand it
/// out to anyone else" — typically the boot PML4, the PFN DB
/// metadata page, or any other in-use page that the kernel keeps
/// on its own.
///
/// The PFN must currently be on one of the allocator lists
/// (Free / Zeroed / Standby / Modified). The function unlinks it
/// from that list and flips its state to `Active` with refcount=1.
pub fn reserve_pfn(pfn: PfnNumber) -> bool {
    let mut db = PFN_DB.lock();
    let entry = match db.entry(pfn) { Some(e) => e, None => return false };
    unsafe {
        // If the PFN is on a list (Free/Zeroed/Standby/Modified)
        // unlink it. If it is already Active or Bad, leave the
        // refcount untouched.
        let s = (*entry).state();
        if s == MMPFNSTATE::Free
            || s == MMPFNSTATE::Zeroed
            || s.is_standby()
            || s == MMPFNSTATE::Modified
            || s == MMPFNSTATE::ModifiedNoWrite
            || s == MMPFNSTATE::Transition
        {
            db.unlink_entry(entry, pfn);
        }
        (*entry).set_state(MMPFNSTATE::Active);
        if (*entry).reference_count == 0 {
            (*entry).reference_count = 1;
        }
        if (*entry).share_count == 0 {
            (*entry).share_count = 1;
        }
    }
    true
}

/// Return a PFN to the zeroed list (use this when the caller just
/// cleared it).
pub fn release_zeroed(pfn: PfnNumber) {
    let mut db = PFN_DB.lock();
    db.insert_zeroed(pfn);
}

#[inline]
pub fn phys_to_pfn(pa: u64) -> PfnNumber { pfn_from_phys(pa) }
#[inline]
pub fn pfn_to_phys_va(pfn: PfnNumber) -> u64 { pfn_to_phys(pfn) }

pub fn get_database_phys() -> u64 {
    unsafe { PFN_STORAGE_PHYS }
}

pub fn get_database_bytes() -> usize {
    unsafe { PFN_STORAGE_USED }
}

pub fn get_database_count() -> PfnNumber {
    unsafe { PFN_COUNT }
}

pub fn get_database_base() -> PfnNumber {
    unsafe { PFN_BASE }
}

/// Get the count of free PFNs
pub fn get_free_pfns() -> u64 {
    let db = PFN_DB.lock();
    db.free_count()
}

/// Lookup a PFN entry pointer from a physical address.
pub fn get_entry(pfn: PfnNumber) -> Option<*mut MMPFN> {
    let db = PFN_DB.lock();
    db.entry(pfn)
}

/// Get standby pages for pageout candidates.
pub fn get_standby_pages(max_count: usize) -> alloc::vec::Vec<PfnNumber> {
    let mut result = alloc::vec::Vec::new();
    let db = PFN_DB.lock();

    // Iterate through the PFN database to find standby pages
    let count = db.total_count().min(1024) as usize;
    for i in 0..count {
        if result.len() >= max_count {
            break;
        }
        if let Some(entry_ptr) = db.entry(i as PfnNumber) {
            let entry = unsafe { &*entry_ptr };
            let state = entry.state();
            if state.is_standby() {
                result.push(i as PfnNumber);
            }
        }
    }
    result
}

/// Set a PFN as pagefile-backed.
pub fn set_pagefile_backed(pfn: PfnNumber, pagefile_no: u32, offset: u32) {
    if let Some(entry_ptr) = get_entry(pfn) {
        unsafe {
            let entry = &mut *entry_ptr;
            entry.u3.flags.paging_file = pagefile_no;
            entry.u3.flags.paging_file_offset = offset;
        }
    }
}

/// Get the number of standby PFNs.
pub fn get_standby_pfns() -> u64 {
    let db = PFN_DB.lock();
    db.standby_count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_db() -> PfnDatabase {
        let mut db = PfnDatabase::new();
        let mut storage = vec![0u8; 16 * 4096];
        db.init(storage.as_mut_ptr(), storage.len(), 1000, 1000);
        db.seed_free(1000, 1000);
        db
    }

    #[test]
    fn seed_and_pop() {
        let mut db = make_db();
        assert_eq!(db.free_count(), 1000);
        let pfn = db.pop_free().unwrap();
        assert!(pfn >= 1000 && pfn < 2000);
        assert_eq!(db.free_count(), 999);
    }

    #[test]
    fn allocate_pfn_changes_state() {
        let mut db = make_db();
        let pfn = 1500u64;
        db.allocate_pfn(pfn);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe { assert_eq!((*entry).state(), MMPFNSTATE::Active); }
    }

    #[test]
    fn standby_and_modified() {
        let mut db = make_db();
        let pfn = 1700u64;
        db.standby(pfn, 3);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Standby0);
            assert_eq!((*entry).standby_priority(), 3);
        }
        db.modified(pfn);
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Modified);
        }
    }

    #[test]
    fn test_all_standby_priorities() {
        let mut db = make_db();
        // After the from_bits fix, each raw priority value (2..=9) maps to
        // the corresponding Standby0..=Standby7 state.
        for priority in 0u8..8 {
            let pfn = 2000u64 + priority as u64;
            db.standby(pfn, priority);
            let entry = db.entry(pfn).expect("pfn in range");
            unsafe {
                // Verify the state is the correct StandbyN for this priority.
                let expected_state = match priority {
                    0 => MMPFNSTATE::Standby0,
                    1 => MMPFNSTATE::Standby1,
                    2 => MMPFNSTATE::Standby2,
                    3 => MMPFNSTATE::Standby3,
                    4 => MMPFNSTATE::Standby4,
                    5 => MMPFNSTATE::Standby5,
                    6 => MMPFNSTATE::Standby6,
                    7 => MMPFNSTATE::Standby7,
                    _ => MMPFNSTATE::Standby0,
                };
                assert_eq!((*entry).state(), expected_state);
                assert_eq!((*entry).standby_priority(), priority);
            }
        }
    }

    #[test]
    fn test_zeroed_list() {
        let mut db = make_db();
        let pfn = 2100u64;
        db.add_to_free(pfn);
        assert_eq!(db.free_count(), 1001);

        // Pop and mark as zeroed
        db.unlink(pfn);
        db.insert_zeroed(pfn);
        assert_eq!(db.zeroed_count(), 1);

        // Pop zeroed
        let popped = db.pop_zeroed();
        assert_eq!(popped, Some(pfn));
        assert_eq!(db.zeroed_count(), 0);
    }

    #[test]
    fn test_modified_list() {
        let mut db = make_db();
        let pfn = 2200u64;
        db.allocate_pfn(pfn);
        db.modified(pfn);
        assert!(db.modified_count() >= 1);

        let popped = db.pop_modified();
        assert_eq!(popped, Some(pfn));
    }

    #[test]
    fn test_pfn_entry_bounds_check() {
        let db = make_db();
        // Valid range
        assert!(db.entry(1000).is_some());
        assert!(db.entry(1999).is_some());
        // Invalid range
        assert!(db.entry(999).is_none());
        assert!(db.entry(2000).is_none());
    }

    #[test]
    fn test_state_transitions() {
        let mut db = make_db();
        let pfn = 2300u64;

        // Start: Free
        db.add_to_free(pfn);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Free);
        }

        // To Active
        db.unlink(pfn);
        db.allocate_pfn(pfn);
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Active);
        }

        // To Standby
        db.standby(pfn, 2);
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Standby0);
        }

        // To Modified
        db.modified(pfn);
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Modified);
        }
    }

    #[test]
    fn test_reference_count() {
        let mut db = make_db();
        let pfn = 2400u64;
        db.allocate_pfn(pfn);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe {
            assert_eq!((*entry).reference_count, 1);
            assert_eq!((*entry).share_count, 1);
        }
    }
}
