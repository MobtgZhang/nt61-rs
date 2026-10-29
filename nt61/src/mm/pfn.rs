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

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pte::{pfn_from_phys, pfn_to_phys, PfnNumber, MMPTE};

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
        matches!(
            self,
            MMPFNSTATE::Standby0
                | MMPFNSTATE::Standby1
                | MMPFNSTATE::Standby2
                | MMPFNSTATE::Standby3
                | MMPFNSTATE::Standby4
                | MMPFNSTATE::Standby5
                | MMPFNSTATE::Standby6
                | MMPFNSTATE::Standby7
        )
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
    /// owner PTE or related PTE depending on state.
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
    fn default() -> Self {
        Self { raw: 0 }
    }
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
        self.u2 = PfnShortFlags {
            raw: (raw & !0x70) | (((p as u32) & 0x7) << 4),
        };
    }
    pub fn set_share_count(&mut self, c: u32) {
        self.share_count = c;
    }
    pub fn share_count(&self) -> u32 {
        self.share_count
    }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

pub const PFN_LIST_MAX: usize = 16;

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
    pub fn init(
        &mut self,
        storage: *mut u8,
        storage_bytes: usize,
        base_pfn: PfnNumber,
        pfn_count: PfnNumber,
    ) {
        let bytes_needed = (pfn_count as usize) * core::mem::size_of::<MMPFN>();
        crate::hal::serial::write_string_always("[mm] PFNDB bytes_needed=");
        crate::mm::write_decimal_u64(bytes_needed as u64);
        crate::hal::serial::write_string_always(" storage=");
        crate::mm::write_decimal_u64(storage_bytes as u64);
        crate::hal::serial::write_string_always(" ptr=0x");
        crate::hal::serial::write_hex_u64_always(storage as u64);
        crate::hal::serial::write_string_always("\r\n");
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
        crate::hal::serial::write_string_always("[mm] PFNDB usable_pfns=");
        crate::mm::write_decimal_u64(usable_pfns as u64);
        crate::hal::serial::write_string_always(" usable_bytes=");
        crate::mm::write_decimal_u64(usable_bytes as u64);
        crate::hal::serial::write_string_always("\r\n");
        // Zero the storage so the list state is consistent.
        unsafe {
            for zero_base in (0..usable_bytes).step_by(32 * 1024) {
                let zero_end = core::cmp::min(zero_base + 32 * 1024, usable_bytes);
                ptr::write_bytes(storage.add(zero_base), 0, zero_end - zero_base);
                crate::hal::serial::write_string_always("[mm] PFNDB zero ");
                crate::mm::write_decimal_u64(zero_end as u64);
                crate::hal::serial::write_string_always("/");
                crate::mm::write_decimal_u64(usable_bytes as u64);
                crate::hal::serial::write_string_always("\r\n");
            }
        }
        crate::hal::serial::write_string_always("[mm] PFNDB zeroed\r\n");
        self.pfn_array = storage as *mut MMPFN;
        self.pfn_count = usable_pfns as u64;
        self.lowest_pfn = base_pfn;
        self.highest_pfn = base_pfn.checked_add(usable_pfns as u64).unwrap_or(u64::MAX);
        self.initialized = true;
        // Inline verification — read back immediately.
        crate::hal::serial::write_string_always("[mm] init verify: self=0x");
        crate::hal::serial::write_hex_u64_always(self as *const PfnDatabase as u64);
        crate::hal::serial::write_string_always(" lowest=");
        crate::mm::write_decimal_u64(self.lowest_pfn);
        crate::hal::serial::write_string_always(" count=");
        crate::mm::write_decimal_u64(self.pfn_count);
        crate::hal::serial::write_string_always("\r\n");
    }

    /// Convert a PFN to the address of its database entry.
    /// Returns `None` for out-of-range PFNs.
    #[inline]
    pub fn entry(&self, pfn: PfnNumber) -> Option<*mut MMPFN> {
        if !self.initialized {
            return None;
        }
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
        if !self.initialized || self.pfn_array.is_null() {
            return None;
        }
        let off = (entry as usize) - (self.pfn_array as usize);
        if off % core::mem::size_of::<MMPFN>() != 0 {
            return None;
        }
        let idx = off / core::mem::size_of::<MMPFN>();
        if idx as u64 >= self.pfn_count {
            return None;
        }
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
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
        unsafe {
            self.insert_head_entry(entry, pfn);
        }
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
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
        unsafe {
            self.unlink_entry(entry, pfn);
        }
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
        let apply = |counter: &AtomicU64| {
            let _ = counter.try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some((current as i64).saturating_add(delta).max(0) as u64)
            });
        };

        if (state.as_u32() as usize) < self.state_counts.len() {
            // Use SeqCst for cross-core visibility in multi-core environment.
            apply(&self.state_counts[state.as_u32() as usize]);
        }
        match state {
            MMPFNSTATE::Free => apply(&self.total_free),
            MMPFNSTATE::Zeroed => apply(&self.total_zeroed),
            s if s.is_standby() => apply(&self.total_standby),
            MMPFNSTATE::Modified | MMPFNSTATE::ModifiedNoWrite => apply(&self.total_modified),
            _ => {}
        }
    }

    /// Pop the head of the free list, or None if empty.
    pub fn pop_free(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_FREE].head == 0 {
            return None;
        }
        let pfn = self.lists[PFNL_FREE].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe {
            self.unlink_entry(entry, pfn);
            (*entry).set_state(MMPFNSTATE::Active);
        }
        Some(pfn)
    }

    /// Pop the head of the zeroed list.
    pub fn pop_zeroed(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_ZEROED].head == 0 {
            return None;
        }
        let pfn = self.lists[PFNL_ZEROED].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe {
            self.unlink_entry(entry, pfn);
            (*entry).set_state(MMPFNSTATE::Active);
        }
        Some(pfn)
    }

    /// Pop the head of the modified list.
    pub fn pop_modified(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_MODIFIED].head == 0 {
            return None;
        }
        let pfn = self.lists[PFNL_MODIFIED].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe {
            self.unlink_entry(entry, pfn);
            (*entry).set_state(MMPFNSTATE::Active);
        }
        Some(pfn)
    }

    /// Pop the head of the no-write modified list.
    pub fn pop_modified_no_write(&mut self) -> Option<PfnNumber> {
        if self.lists[PFNL_MODIFIED_NW].head == 0 {
            return None;
        }
        let pfn = self.lists[PFNL_MODIFIED_NW].head;
        let entry = self.entry(pfn).expect("pfn in range");
        unsafe {
            self.unlink_entry(entry, pfn);
            (*entry).set_state(MMPFNSTATE::Active);
        }
        Some(pfn)
    }

    /// Pop the head of the highest-priority standby list (7 first).
    pub fn pop_standby(&mut self) -> Option<PfnNumber> {
        // Iterate from highest to lowest priority.
        for i in (PFNL_STANDBY0..=PFNL_STANDBY7).rev() {
            if self.lists[i].head != 0 {
                let pfn = self.lists[i].head;
                let entry = self.entry(pfn).expect("pfn in range");
                unsafe {
                    self.unlink_entry(entry, pfn);
                    (*entry).set_state(MMPFNSTATE::Active);
                }
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
            let Some(pfn) = base.checked_add(i) else {
                panic!("PFN range [{}, +{}) overflows in seed_free", base, count);
            };
            let entry = match self.entry(pfn) {
                Some(e) => e,
                None => panic!(
                    "pfn={} not in range [{}, {}) in seed_free",
                    pfn, self.lowest_pfn, self.highest_pfn
                ),
            };
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
    ///
    /// If the PFN is still on one of the allocator lists (Free /
    /// Zeroed / Standby / Modified / ModifiedNoWrite / Transition),
    /// it is unlinked first. Inserting an entry that is already on a
    /// list would create a cycle / double ownership, so pop_free
    /// could hand the same page to two consumers.
    pub fn add_to_free(&mut self, pfn: PfnNumber) {
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
        unsafe {
            let state = (*entry).state();
            if state == MMPFNSTATE::Free
                || state == MMPFNSTATE::Zeroed
                || state.is_standby()
                || state == MMPFNSTATE::Modified
                || state == MMPFNSTATE::ModifiedNoWrite
                || state == MMPFNSTATE::Transition
            {
                self.unlink_entry(entry, pfn);
            }
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
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return false,
        };
        unsafe {
            (*entry).set_state(MMPFNSTATE::Active);
            (*entry).reference_count = 1;
            (*entry).share_count = 1;
        }
        true
    }

    /// Move a PFN to the standby list at the given priority.
    pub fn standby(&mut self, pfn: PfnNumber, priority: u8) {
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
        unsafe {
            if (*entry).state() == MMPFNSTATE::Active || (*entry).state() == MMPFNSTATE::Transition
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
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
        unsafe {
            if (*entry).state() == MMPFNSTATE::Active || (*entry).state() == MMPFNSTATE::Transition
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
        let entry = match self.entry(pfn) {
            Some(e) => e,
            None => return,
        };
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
    pub fn phys(&self, pfn: PfnNumber) -> u64 {
        pfn_to_phys(pfn)
    }

    /// Translate a physical address to a PFN (no bounds check; for
    /// translating a PA to a database index the caller should have
    /// already done so).
    pub fn pfn_of_phys(&self, pa: u64) -> PfnNumber {
        pfn_from_phys(pa)
    }

    /// Diagnostics.
    pub fn free_count(&self) -> u64 {
        self.total_free.load(Ordering::Relaxed)
    }
    pub fn zeroed_count(&self) -> u64 {
        self.total_zeroed.load(Ordering::Relaxed)
    }
    pub fn standby_count(&self) -> u64 {
        self.total_standby.load(Ordering::Relaxed)
    }
    pub fn modified_count(&self) -> u64 {
        self.total_modified.load(Ordering::Relaxed)
    }
    pub fn total_count(&self) -> u64 {
        self.pfn_count
    }
}

// ---------------------------------------------------------------------------
// Global singleton and accessors
// ---------------------------------------------------------------------------

pub static PFN_DB: Spinlock<PfnDatabase> = Spinlock::new(PfnDatabase::new());

/// Report whether the physical page allocator is ready.
pub fn is_initialized() -> bool {
    let db = PFN_DB.lock();
    db.initialized
}

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
        if cfg!(target_arch = "loongarch64") {
            crate::hal::serial::write_string("[mm] pfn::init: using bootstrap storage\r\n");
            PFN_STORAGE_PTR = (*core::ptr::addr_of_mut!(PFN_STORAGE_BOOTSTRAP)).as_mut_ptr();
            PFN_STORAGE_USED = (*core::ptr::addr_of!(PFN_STORAGE_BOOTSTRAP)).len();
            PFN_STORAGE_CAPACITY = (*core::ptr::addr_of!(PFN_STORAGE_BOOTSTRAP)).len();
        } else if let Some(phys) = crate::mm::frame::allocate_pages(pages as u64) {
            if !crate::arch::identity_map_region(phys, (pages * 4096) as u64) {
                crate::hal::serial::write_string_always(
                    "[FATAL] pfn::init: storage map failed\r\n",
                );
                crate::ke::bugcheck::bugcheck_with(
                    crate::ke::bugcheck::BugCheckCode::PfnListCorrupt,
                    bytes_needed as u64,
                    phys,
                    pfn_count,
                    core::mem::size_of::<MMPFN>() as u64,
                );
            }
            // The PFN DB storage lives in kernel-VA space via the
            // recursive self-map, so we can access it through its
            // physical address directly.
            PFN_STORAGE_PTR = phys as *mut u8;
            PFN_STORAGE_PHYS = phys;
            PFN_STORAGE_USED = pages * 4096;
            PFN_STORAGE_CAPACITY = pages * 4096;
            crate::hal::serial::write_string("[mm] pfn::init: dynamic storage OK\r\n");
        } else if bytes_needed <= (*core::ptr::addr_of!(PFN_STORAGE_BOOTSTRAP)).len() {
            // Fall back to the static buffer (cap is 8K PFNs,
            // about 32 MiB of RAM). The buddy is so out of memory
            // that we can't even allocate the proper tables.
            crate::hal::serial::write_string("[mm] pfn::init: using static storage\r\n");
            PFN_STORAGE_PTR = (*core::ptr::addr_of_mut!(PFN_STORAGE_BOOTSTRAP)).as_mut_ptr();
            PFN_STORAGE_USED = bytes_needed;
            PFN_STORAGE_CAPACITY = (*core::ptr::addr_of!(PFN_STORAGE_BOOTSTRAP)).len();
        } else {
            // CRITICAL ERROR: Cannot allocate PFN database storage.
            // Without full PFN tracking, memory management is compromised.
            // System cannot safely continue - trigger bugcheck.
            crate::hal::serial::write_string_always("[FATAL] pfn::init: no storage\r\n");
            // Trigger PFN_LIST_CORRUPT (bug check 0x4E).
            // This indicates critical memory management data structures are corrupted.
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::PfnListCorrupt,
                bytes_needed as u64, // P1: bytes needed
                (*core::ptr::addr_of!(PFN_STORAGE_BOOTSTRAP)).len() as u64, // P2: bootstrap capacity
                pfn_count,                            // P3: requested PFN count
                core::mem::size_of::<MMPFN>() as u64, // P4: sizeof(MMPFN)
            );
            // NOTE: bugcheck_with() is ! (never returns), so no code after this
        }
        crate::hal::serial::write_string_always("[mm] pfn::init: before db init\r\n");
        let mut db = PFN_DB.lock();
        crate::hal::serial::write_string_always("[mm] db_ptr=0x");
        crate::hal::serial::write_hex_u64_always(&mut *db as *mut PfnDatabase as u64);
        crate::hal::serial::write_string_always(" pfn_db_static=0x");
        crate::hal::serial::write_hex_u64_always(core::ptr::addr_of!(PFN_DB) as u64);
        crate::hal::serial::write_string_always("\r\n");
        // WORKAROUND: LoongArch64 `db.init()` via DerefMut passes self=0.
        // Write the fields directly through a raw pointer to bypass the
        // method-call overhead and any argument-passing issue.
        let db_raw = &mut *db as *mut PfnDatabase;
        crate::hal::serial::write_string_always("[mm] raw_init: db_raw=0x");
        crate::hal::serial::write_hex_u64_always(db_raw as u64);
        crate::hal::serial::write_string_always("\r\n");
        let usable_pfns = {
            let bytes_needed = (pfn_count as usize) * core::mem::size_of::<MMPFN>();
            crate::hal::serial::write_string_always("[mm] raw_init: bytes_needed=");
            crate::mm::write_decimal_u64(bytes_needed as u64);
            crate::hal::serial::write_string_always(" storage_cap=");
            crate::mm::write_decimal_u64(PFN_STORAGE_CAPACITY as u64);
            crate::hal::serial::write_string_always(" pfn_count=");
            crate::mm::write_decimal_u64(pfn_count);
            crate::hal::serial::write_string_always("\r\n");
            if bytes_needed > PFN_STORAGE_CAPACITY {
                PFN_STORAGE_CAPACITY / core::mem::size_of::<MMPFN>()
            } else {
                pfn_count as usize
            }
        };
        crate::hal::serial::write_string_always("[mm] raw_init: usable_pfns=");
        crate::mm::write_decimal_u64(usable_pfns as u64);
        crate::hal::serial::write_string_always(" storage_ptr=0x");
        crate::hal::serial::write_hex_u64_always(PFN_STORAGE_PTR as u64);
        crate::hal::serial::write_string_always("\r\n");
        let storage_local = PFN_STORAGE_PTR;
        crate::hal::serial::write_string_always("[mm] read_test: byte0=0x");
        crate::hal::serial::write_hex_u64_always(*storage_local as u64);
        crate::hal::serial::write_string_always("\r\n");
        crate::hal::serial::write_string_always("[mm] write_test...\r\n");
        *storage_local = 0;
        crate::hal::serial::write_string_always("[mm] write_test ok\r\n");
        // Zero the PFN storage (the part db.init() would have done).
        let usable_bytes = usable_pfns * core::mem::size_of::<MMPFN>();
        let mut zero_base: usize = 0;
        while zero_base < usable_bytes {
            storage_local.add(zero_base).write_volatile(0);
            zero_base += 1;
            if zero_base % (64 * 1024) == 0 {
                crate::hal::serial::write_string_always("[mm] zero@");
                crate::mm::write_decimal_u64(zero_base as u64);
                crate::hal::serial::write_string_always("\r\n");
            }
        }
        crate::hal::serial::write_string_always("[mm] PFNDB zeroed\r\n");
        (*db_raw).pfn_array = PFN_STORAGE_PTR as *mut MMPFN;
        (*db_raw).pfn_count = usable_pfns as u64;
        (*db_raw).lowest_pfn = base_pfn;
        (*db_raw).highest_pfn = base_pfn.checked_add(usable_pfns as u64).unwrap_or(u64::MAX);
        (*db_raw).initialized = true;
        crate::hal::serial::write_string_always("[mm] raw_init done\r\n");
        crate::hal::serial::write_string_always("[mm] pfn::init: db init done\r\n");
        // Diagnostic: verify the PfnDatabase fields were written.
        crate::hal::serial::write_string_always("[mm] PFNDB init check: lowest=");
        crate::mm::write_decimal_u64(db.lowest_pfn);
        crate::hal::serial::write_string_always(" highest=");
        crate::mm::write_decimal_u64(db.highest_pfn);
        crate::hal::serial::write_string_always(" count=");
        crate::mm::write_decimal_u64(db.pfn_count);
        crate::hal::serial::write_string_always(" init=");
        crate::mm::write_decimal_u64(db.initialized as u64);
        crate::hal::serial::write_string_always(" pfn_array=0x");
        crate::hal::serial::write_hex_u64_always(db.pfn_array as u64);
        crate::hal::serial::write_string_always("\r\n");
        db.seed_free(base_pfn, usable_pfns as u64);
        crate::hal::serial::write_string_always("[mm] pfn::init: seed done\r\n");
        crate::hal::serial::write_string_always("[mm] PFN_COUNT=");
        crate::mm::write_decimal_u64(pfn_count);
        crate::hal::serial::write_string_always(" FREE_AFTER_SEED=");
        crate::mm::write_decimal_u64(db.free_count());
        crate::hal::serial::write_string_always("\r\n");
    }

    // The heap was allocated from the buddy before this PFN database
    // was seeded. `seed_free` therefore marks those live pages free;
    // reserve them before any caller allocates PFN-backed page tables.
    if let Some((base, size)) = crate::mm::heap::KERNEL_HEAP.configured_region() {
        let heap_base_pfn = (base as u64).div_ceil(4096);
        let heap_end_pfn = (base as u64 + size as u64) / 4096;
        if heap_end_pfn > heap_base_pfn {
            if !crate::mm::pfn::reserve_pfn_range(heap_base_pfn, heap_end_pfn - heap_base_pfn) {
                crate::hal::serial::write_string_always("[mm] WARN: heap pfn reserve failed\r\n");
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::mm::vas::reserve_system_page_tables(crate::arch::read_current_page_root());
    }
}

/// Allocate one PFN (zeroed preferred, else free). Returns None if no
/// pages are available.
pub fn allocate_pfn() -> Option<PfnNumber> {
    let mut db = PFN_DB.lock();
    if let Some(pfn) = db.pop_zeroed() {
        db.allocate_pfn(pfn);
        #[cfg(target_arch = "loongarch64")]
        crate::arch::loongarch64::paging::watch_pfn_alloc(pfn);
        return Some(pfn);
    }
    if let Some(pfn) = db.pop_free() {
        db.allocate_pfn(pfn);
        #[cfg(target_arch = "loongarch64")]
        crate::arch::loongarch64::paging::watch_pfn_alloc(pfn);
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
    crate::hal::serial::write_string_always("[PFN] OUT_OF_PFNS: self-heal free_in_db=0x");
    crate::hal::serial::write_hex_u64(free_count);
    crate::hal::serial::write_string_always(" free_list_count=0x");
    crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].count as u64);
    crate::hal::serial::write_string_always("\r\n");
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
        crate::hal::serial::write_string_always("[PFN] self-heal: rebuilt free list, head=0x");
        crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].head);
        crate::hal::serial::write_string_always(" count=0x");
        crate::hal::serial::write_hex_u64(db.lists[PFNL_FREE].count as u64);
        crate::hal::serial::write_string_always("\r\n");
        // Retry the allocation.
        if let Some(pfn) = db.pop_free() {
            db.allocate_pfn(pfn);
            #[cfg(target_arch = "loongarch64")]
            crate::arch::loongarch64::paging::watch_pfn_alloc(pfn);
            return Some(pfn);
        }
    }
    None
}

/// Allocate a contiguous range of `count` PFNs. Falls back to
/// non-contiguous if the contig run cannot be assembled.
pub fn allocate_pfn_range(count: PfnNumber) -> Option<PfnNumber> {
    if count == 0 {
        return None;
    }
    let mut db = PFN_DB.lock();
    // The free list is populated in LIFO order, so it does not provide a
    // reliable contiguous-order view. Walk the PFN range and track physical
    // adjacency using the database state instead.
    let mut run_start: Option<PfnNumber> = None;
    let mut run_len: u64 = 0;
    let mut pfn = db.lowest_pfn;
    while pfn < db.highest_pfn {
        let free = db
            .entry(pfn)
            .map(|entry| unsafe { (*entry).state() == MMPFNSTATE::Free })
            .unwrap_or(false);

        if free {
            if run_start.is_none() {
                run_start = Some(pfn);
            }
            run_len += 1;
            if run_len == count {
                let start = run_start.unwrap();
                for i in 0..count {
                    let allocated = start + i;
                    db.unlink(allocated);
                    db.allocate_pfn(allocated);
                    #[cfg(target_arch = "loongarch64")]
                    crate::arch::loongarch64::paging::watch_pfn_alloc(allocated);
                }
                return Some(start);
            }
        } else {
            run_start = None;
            run_len = 0;
        }

        pfn = pfn.saturating_add(1);
    }

    // Non-contiguous fallback: return one page and let callers that require
    // contiguity reject the partial result.
    if let Some(p) = db.pop_free() {
        db.allocate_pfn(p);
        #[cfg(target_arch = "loongarch64")]
        crate::arch::loongarch64::paging::watch_pfn_alloc(p);
        return Some(p);
    }
    None
}

/// Return a PFN to the free list (zeroed, since we just released it
/// and the caller can clear it if they care).
pub fn free_pfn(pfn: PfnNumber) {
    crate::boot_println!("[PFN] free_pfn: pfn=0x{:x}", pfn);
    let mut db = PFN_DB.lock();
    db.add_to_free(pfn);
}

/// Shim for `frame::allocate_pages` / `frame::free_pages`: reports
/// whether the PFN database is online so the frame allocator knows
/// whether mirror reservations are meaningful.
#[doc(hidden)]
pub fn frame_sync_is_initialized() -> bool {
    is_initialized()
}

/// Shim for `frame::allocate_pages`: reserves a frame the buddy
/// allocator has just handed out so the PFN allocator will never
/// return it to a second consumer.
#[doc(hidden)]
pub fn frame_sync_reserve(pfn: PfnNumber) -> bool {
    reserve_pfn(pfn)
}

/// Shim for `frame::free_pages`: releases a frame back into the PFN
/// free list when the buddy allocator frees the block.
#[doc(hidden)]
pub fn frame_sync_release(pfn: PfnNumber) {
    let mut db = PFN_DB.lock();
    if db.entry(pfn).is_some() {
        db.add_to_free(pfn);
    }
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
    let entry = match db.entry(pfn) {
        Some(e) => e,
        None => return false,
    };
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

/// Reserve a contiguous PFN range with one lock acquisition.
pub fn reserve_pfn_range(base_pfn: PfnNumber, count: PfnNumber) -> bool {
    if count == 0 {
        return true;
    }
    // Take the PFN database lock like every other allocator entry
    // point (reserve_pfn, allocate_pfn, ...). The previous lock-free
    // path dereferenced the database through raw_data_ptr(), which is
    // UB as soon as any other CPU (or any caller after AP bring-up)
    // touches the database concurrently. PFN_DB.lock() is proven safe
    // here: the same lock is already taken during mm::init by
    // pfn::allocate_pfn (self-map page allocation) without hangs.
    let mut db = PFN_DB.lock();
    for index in 0..count {
        let Some(pfn) = base_pfn.checked_add(index) else {
            return false;
        };
        let entry = match db.entry(pfn) {
            Some(e) => e,
            None => return false,
        };
        unsafe {
            let state = (*entry).state();
            if state == MMPFNSTATE::Free
                || state == MMPFNSTATE::Zeroed
                || state.is_standby()
                || state == MMPFNSTATE::Modified
                || state == MMPFNSTATE::ModifiedNoWrite
                || state == MMPFNSTATE::Transition
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
    }
    true
}

/// Return a PFN to the zeroed list (use this when the caller just
/// cleared it).
pub fn release_zeroed(pfn: PfnNumber) {
    let mut db = PFN_DB.lock();
    db.insert_zeroed(pfn);
}

/// Increment the reference count of an active PFN (page sharing).
///
/// Returns `false` when the PFN is out of range or not `Active`:
/// only live allocations can be shared, and bumping the counter of a
/// free frame would silently resurrect a page the allocator may
/// already have handed out elsewhere.
pub fn reference_pfn(pfn: PfnNumber) -> bool {
    let db = PFN_DB.lock();
    let entry = match db.entry(pfn) {
        Some(e) => e,
        None => return false,
    };
    unsafe {
        if (*entry).state() != MMPFNSTATE::Active {
            return false;
        }
        let current = (*entry).reference_count;
        (*entry).reference_count = current.saturating_add(1);
    }
    true
}

/// Decrement the reference count of an active PFN.
///
/// Returns `true` when this call dropped the last reference (the
/// count reached zero) so the caller can return the frame to its
/// allocator. The frame is deliberately not freed here: the freeing
/// path differs per allocator (buddy `free_pages` vs PFN release)
/// and only the caller knows which one owns the page. Returns
/// `false` when the PFN is out of range, not `Active`, or still
/// shared.
pub fn dereference_pfn(pfn: PfnNumber) -> bool {
    let db = PFN_DB.lock();
    let entry = match db.entry(pfn) {
        Some(e) => e,
        None => return false,
    };
    unsafe {
        if (*entry).state() != MMPFNSTATE::Active {
            return false;
        }
        if (*entry).reference_count == 0 {
            return false;
        }
        (*entry).reference_count -= 1;
        (*entry).reference_count == 0
    }
}

#[inline]
pub fn phys_to_pfn(pa: u64) -> PfnNumber {
    pfn_from_phys(pa)
}
#[inline]
pub fn pfn_to_phys_va(pfn: PfnNumber) -> u64 {
    pfn_to_phys(pfn)
}

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

pub fn get_free_list_stats() -> (u64, u64) {
    let db = PFN_DB.lock();
    (db.lists[PFNL_FREE].head, db.lists[PFNL_FREE].count as u64)
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
    // PFN entries are addressed by absolute PFN: entry() subtracts
    // lowest_pfn internally, so the scan must start at db.lowest_pfn
    // (index 0 would look up a PFN below the database range and never
    // find any standby page).
    let max_scan = db.total_count().min(1024) as usize;
    let mut scanned = 0usize;
    for pfn in db.lowest_pfn..db.highest_pfn {
        if scanned >= max_scan || result.len() >= max_count {
            break;
        }
        if let Some(entry_ptr) = db.entry(pfn) {
            scanned += 1;
            let entry = unsafe { &*entry_ptr };
            let state = entry.state();
            if state.is_standby() {
                result.push(pfn);
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
        // Size storage generously: 16 pages * 16 pages = 256 pages
        // (~1 MiB), enough for any plausible `MMPFN` layout plus
        // headroom. The kernel never uses a PFN database this big.
        // Track 1500 PFNs (range 1000..2500) so that tests which
        // exercise PFNs beyond 2000 still find them in range.
        let storage = alloc::vec::Vec::leak(vec![0u8; 16 * 16 * 4096]);
        db.init(storage.as_mut_ptr(), storage.len(), 1000, 1500);
        db.seed_free(1000, 1500);
        db
    }

    #[test]
    fn seed_and_pop() {
        let mut db = make_db();
        assert_eq!(db.free_count(), 1500);
        let pfn = db.pop_free().unwrap();
        assert!(pfn >= 1000 && pfn < 2500);
        assert_eq!(db.free_count(), 1499);
    }

    #[test]
    fn allocate_pfn_changes_state() {
        let mut db = make_db();
        let pfn = 1500u64;
        db.allocate_pfn(pfn);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Active);
        }
    }

    #[test]
    fn standby_and_modified() {
        let mut db = make_db();
        let pfn = 1700u64;
        db.standby(pfn, 3);
        let entry = db.entry(pfn).expect("pfn in range");
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Standby3);
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
        let pfn = db.pop_free().expect("free page available");
        assert_eq!(db.free_count(), 1499);
        db.add_to_free(pfn);
        assert_eq!(db.free_count(), 1500);

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
        assert!(db.entry(2499).is_some());
        // Invalid range
        assert!(db.entry(999).is_none());
        assert!(db.entry(2500).is_none());
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

        // To Standby (priority 2 → Standby2)
        db.standby(pfn, 2);
        unsafe {
            assert_eq!((*entry).state(), MMPFNSTATE::Standby2);
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
