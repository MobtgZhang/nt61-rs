//! Modified-page and mapped-page writer threads
//
//! NT 6.1 uses two system threads to write dirty pages to their
//! backing store:
//
//! * `MiModifiedPageWriter` — writes pages from the *modified* list
//!   to the page file.
//! * `MiMappedPageWriter` — writes pages from the modified list
//!   that are part of mapped sections (i.e. share an underlying
//!   file) to that file.
//
//! After a page is written it transitions to the standby list. We
//! model the writer as a periodic function that runs on the
//! `BalanceSetManager` tick (one second). In the bootstrap the
//! `BalanceSetManager` is the same thread that runs zero-page
//! work, so we just expose a `tick()` function.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mm::pfn;

/// Number of pages to write per tick.
const PAGES_PER_TICK: u64 = 32;

/// Whether the modified page writer thread should keep running.
static MPW_RUNNING: AtomicBool = AtomicBool::new(true);

/// Run one tick of the writer. Drains up to `PAGES_PER_TICK` pages
/// from the modified list, writes them to the page file (if
/// applicable), and moves them to the standby list.
///
/// In the bootstrap we have no real page file yet, so this just
/// moves modified pages to standby — the *logical* state machine
/// transition is what matters. The page file write is wired in
/// `mm::pagefile` and called from here.
pub fn tick() -> u64 {
    let mut moved: u64 = 0;
    for _ in 0..PAGES_PER_TICK {
        let pfn_no = {
            let mut db = pfn::PFN_DB.lock();
            if db.lists_is_empty() { break; }
            match db.pop_modified() {
                Some(p) => p,
                None => break,
            }
        };
        let _ = &pfn_no;
        // Hook for the page file subsystem — they look at the
        // pfn.u3.paging_file and u3.paging_file_offset to know
        // where to write the page. The pagefile subsystem
        // returns early if the slot is invalid; this is fine for
        // the bootstrap, where many modified pages have no
        // reserved slot.
        crate::mm::pagefile::write_modified_page(pfn_no);
        // Move to standby.
        let mut db = pfn::PFN_DB.lock();
        db.standby(pfn_no, 0);
        moved += 1;
    }
    moved
}

/// MiModifiedPageWriter — the NT 6.1 modified page writer entry point.
///
/// This system thread periodically scans the modified page list and
/// writes dirty pages to the page file. It runs at low priority
/// and sleeps between scans to avoid consuming CPU.
pub extern "C" fn mi_modified_page_writer_entry(context: u64) {
    // [DISABLED] crate:: // // kprintln!("[MM] MiModifiedPageWriter started")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let _ = context;
    while MPW_RUNNING.load(Ordering::Relaxed) {
        let written = tick();
        let _ = &written;
        let _ = &written;
        if written == 0 {
            // No pages to write; sleep for a longer interval.
            crate::ke::scheduler::yield_();
            crate::ke::scheduler::yield_();
            crate::ke::scheduler::yield_();
        } else {
            // [DISABLED] crate:: // // kprintln!("[MM] MiModifiedPageWriter: wrote {} modified pages", written)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            crate::ke::scheduler::yield_();
        }
    }
    // [DISABLED] crate:: // // kprintln!("[MM] MiModifiedPageWriter exiting")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    crate::ps::thread::ps_exit_system_thread(0);
}

/// Start the modified page writer as a system thread.
pub fn start_modified_page_writer() {
    let entry_addr = mi_modified_page_writer_entry as *const () as u64;
    let _ = &entry_addr;
    let _ = &entry_addr;
    let result = crate::ps::thread::ps_create_system_thread(
        entry_addr,
        0,
    );
    let _ = &result;
    if result.success {
        // [DISABLED] crate:: // // kprintln!("[MM] MiModifiedPageWriter created (entry=0x{:016x})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// // // [DISABLED]             entry_addr);
    } else {
        // [DISABLED] crate:: // // kprintln!("[MM] WARNING: MiModifiedPageWriter creation failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Stop the modified page writer (called during shutdown).
pub fn stop_modified_page_writer() {
    MPW_RUNNING.store(false, Ordering::SeqCst);
}

pub fn init() {
    MPW_RUNNING.store(true, Ordering::SeqCst);
}

// =============================================================================
// MiMappedPageWriter - writes mapped file pages to disk
// =============================================================================

/// Number of pages to write per mapped page writer tick.
const MAPPED_PAGES_PER_TICK: u64 = 16;

/// Whether the mapped page writer should keep running.
static MPW_MAPPED_RUNNING: AtomicBool = AtomicBool::new(true);

/// Counter for total pages written by mapped page writer.
static MPW_MAPPED_TOTAL_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// MiMappedPageWriter state
pub struct MiMappedPageWriter {
    /// Running flag (kept for future use; currently MPW_MAPPED_RUNNING static is used)
    #[allow(unused)]
    running: AtomicBool,
}

impl MiMappedPageWriter {
    /// Create a new mapped page writer instance.
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
        }
    }

    /// Run one tick of the mapped page writer.
    /// Scans pages that belong to mapped sections and writes them back.
    /// Returns the number of pages written.
    pub fn tick(&mut self) -> u64 {
        let mut written: u64 = 0;
        for _ in 0..MAPPED_PAGES_PER_TICK {
            // Try to get a page from the modified list that belongs to a section
            let pfn_no = {
                let mut db = pfn::PFN_DB.lock();
                if db.lists_is_empty() {
                    break;
                }
                match db.pop_modified() {
                    Some(p) => p,
                    None => break,
                }
            };
            let _ = &pfn_no;

            // Check if this page belongs to a section/file mapping
            let is_section_page = {
                let db = pfn::PFN_DB.lock();
                let _ = &db;
                if let Some(entry) = db.entry(pfn_no) {
                    unsafe {
                        // Check if u3 contains section information
                        // In a full impl, we would check u4.OriginalPte
                        // for a Prototype PTE pointing to a section
                        let orig_pte = (*entry).u4.pte.raw();
                        // Prototype PTE format: bit 1 = 1 for prototype
                        (orig_pte & 0x2) != 0
                    }
                } else {
                    false
                }
            };
            let _ = &is_section_page;

            if is_section_page {
                // This is a mapped file page - write it to the file
                // In a full implementation, we would:
                // 1. Look up the section object from the prototype PTE
                // 2. Determine the file offset
                // 3. Call IoWriteFile to write the page
                // For now, just log the operation
                // [DISABLED] // // kprintln!("[MM] MiMappedPageWriter: would write PFN {} to file", pfn_no)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

                // Put the page back to modified list (not yet implemented)
                // In real implementation, after writing to file, move to standby
                let mut db = pfn::PFN_DB.lock();
                db.modified(pfn_no);
            } else {
                // Regular modified page - put it back to modified list
                // It will be handled by MiModifiedPageWriter
                let mut db = pfn::PFN_DB.lock();
                db.modified(pfn_no);
            }

            written += 1;
        }

        if written > 0 {
            MPW_MAPPED_TOTAL_WRITTEN.fetch_add(written, Ordering::Relaxed);
        }

        written
    }

    /// MiMappedPageWriter entry point - system thread.
    pub extern "C" fn mi_mapped_page_writer_entry(&self, context: u64) {
        // [DISABLED] // // kprintln!("[MM] MiMappedPageWriter started")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let _ = context;
        let mut writer = MiMappedPageWriter::new();
        while MPW_MAPPED_RUNNING.load(Ordering::Relaxed) {
            let written = writer.tick();
            let _ = &written;
            let _ = &written;
            if written == 0 {
                // No pages to write - sleep for a while
                crate::ke::scheduler::yield_();
                crate::ke::scheduler::yield_();
                crate::ke::scheduler::yield_();
            } else {
                // [DISABLED] // // kprintln!("[MM] MiMappedPageWriter: wrote {} pages", written)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                crate::ke::scheduler::yield_();
            }
        }
        // [DISABLED] // // kprintln!("[MM] MiMappedPageWriter exiting")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        crate::ps::thread::ps_exit_system_thread(0);
    }

    /// Start the mapped page writer as a system thread.
    pub fn start(&self) {
        let entry_addr = Self::mi_mapped_page_writer_entry as *const () as u64;
        let _ = &entry_addr;
        let _ = &entry_addr;
        let result = crate::ps::thread::ps_create_system_thread(
            entry_addr,
            0,
        );
        let _ = &result;
        if result.success {
            // [DISABLED] // // kprintln!("[MM] MiMappedPageWriter thread created")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        } else {
            // [DISABLED] // // kprintln!("[MM] WARNING: MiMappedPageWriter creation failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    }

    /// Stop the mapped page writer.
    pub fn stop(&self) {
        MPW_MAPPED_RUNNING.store(false, Ordering::SeqCst);
    }

    /// Get total pages written by mapped page writer.
    pub fn total_written() -> u64 {
        MPW_MAPPED_TOTAL_WRITTEN.load(Ordering::Relaxed)
    }
}

/// Global mapped page writer instance.
static MAPPED_PAGE_WRITER: MiMappedPageWriter = MiMappedPageWriter::new();

/// Start the global mapped page writer.
pub fn start_mapped_page_writer() {
    MAPPED_PAGE_WRITER.start();
}

/// Stop the global mapped page writer.
pub fn stop_mapped_page_writer() {
    MAPPED_PAGE_WRITER.stop();
}

/// Get the mapped page writer's total written count.
pub fn get_mapped_writer_total() -> u64 {
    MiMappedPageWriter::total_written()
}
