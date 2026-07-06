//! PSSS worker threads
//
//! NT 6.1 launches three system worker threads early in the
//! boot:
//
//!   - **BalanceSetManager** — wakes once per second to run
//!     the working-set trimmer and to refill the zeroed
//!     page list.
//!   - **MiZeroPageThread** — idles, popping free pages and
//!     pre-zeroing them. The demand-zero fault handler
//!     consumes from the zeroed list.
//!   - **MiModifiedPageWriter** — pops modified pages and
//!     writes them to the page file.
//
//! In the bootstrap these are not actual kernel threads
//! (creating a thread is expensive and the kernel doesn't
//! have a full scheduler yet).  Instead we expose a single
//! `psss_tick()` function that runs all three on the BSP
//! whenever the timer interrupt fires.

#![allow(non_snake_case)]

use crate::mm::{working_set, writer, zeropage};
use crate::ke::dispatch;

/// Run one tick of the PSSS workers. Called from the timer
/// ISR (or, in the bootstrap, by the BSP loop).
pub fn psss_tick() {
    // 1. Refill the zeroed list.
    let z = zeropage::tick();
    // 2. Drain the modified list to standby (writes to the
    // page file in the process).
    let w = writer::tick();
    // 3. Trim the working set of the current process.
    let current_pml4 = crate::mm::vas::current_root();
    if current_pml4 != 0 {
        working_set::age_working_set(current_pml4);
        let target = 32; // trim up to 32 pages per tick
        working_set::trim_working_set(current_pml4, target);
    }
    // 4. Walk the dispatcher wait list, time out expired waits.
    dispatch::tick_wait_list();
    if z + w > 0 {
        // Optional: log first time to confirm PSSS is alive.
        static mut FIRST: bool = true;
        unsafe {
            if FIRST {
                FIRST = false;
                // // kprintln!("    [psss] first tick: zeroed={} wrote={}", z, w)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }
}

pub fn init() {
    crate::hal::serial::write_string("[ke.psss] enter\r\n");
}
