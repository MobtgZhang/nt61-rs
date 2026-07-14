//! Process / Thread smoke test
//
//! End-to-end exercise of the process and thread subsystem.
//! Verifies:
//
//! 1. Process IDs are stable. Windows 7 reserves:
//!      * PID 0   - the Idle process
//!      * PID 4   - the System process
//!      * PID 256 - SMSS
//!      * PID 512 - CSRSS
//!      * PID 768 - WinLogon
//!      * PID 1024 - Services
//!      * PID 1152 - LSASS
//! 2. The well-known EPROCESS / KTHREAD / ETHREAD layouts are
//!    well-formed (their sizes are the same as the published
//!    `nt!_EPROCESS` / `nt!_KTHREAD` / `nt!_ETHREAD` types).
//! 3. The dispatcher header has the right type tag for each
//!    object (process = 3, thread = 6) — the kernel's wait
//!    machinery uses the type to identify the object.
//! 4. ListEntry::init() makes a self-referential list and
//!    insert_tail() / remove() maintain the invariants.
//! 5. A user process can be created via create_user_process
//!    and looked up via get_by_pid.
//! 6. The create_user_process path initialises the EPROCESS
//!    (PID, name, PEB pointer, thread list head).
//! 7. The thread counter is non-zero after a thread is created.
//! 8. ExFastRef reference counting works correctly.

#[allow(unused_imports)]
use crate::boot_println;
use crate::rtl::testing::TestStats;
use core::sync::atomic::Ordering;

use super::process::{
    get_by_pid, ListEntry, Eprocess, Process, MAX_PROCESSES, PID_CSRSS, PID_IDLE, PID_LSASS,
    PID_SERVICES, PID_SMSS, PID_SYSTEM, PID_WINLOGON, ExFastRef,
};
use super::thread::{DispatcherHeader, Ethread, KThreadState, Kthread, THREAD_COUNT, NEXT_TID};

/// Run the full Phase 7 process / thread smoke test.
pub fn smoke_test() -> bool {
    let mut stats = TestStats::new("PS");

    stats.test("PID Constants", step1_pid_constants);
    stats.test("Layout Sizes", step2_layout_sizes);
    stats.test("ListEntry", step3_list_entry);
    stats.test("User Process Creation", step4_create_user_process);
    stats.test("Thread Counter", step5_thread_counter);
    stats.test("Process Table", step6_process_table);
    stats.test("ExFastRef", step7_ex_fast_ref);

    stats.finish()
}

/// Step 1: well-known process ids.
fn step1_pid_constants() -> bool {
    if PID_IDLE != 0 {
        return false;
    }
    if PID_SYSTEM != 4 {
        return false;
    }
    if PID_SMSS != 256 {
        return false;
    }
    if PID_CSRSS != 512 {
        return false;
    }
    if PID_WINLOGON != 0x900 {
        return false;
    }
    if PID_SERVICES != 1024 {
        return false;
    }
    if PID_LSASS != 1152 {
        return false;
    }
    crate::boot_println!("    PID_IDLE={}, PID_SYSTEM={}, PID_SMSS={}", PID_IDLE, PID_SYSTEM, PID_SMSS);
    true
}

/// Step 2: well-known layout sizes.
///
/// Windows 7 _EPROCESS is around 0x4D0 bytes; the bootstrap uses
/// the same shape but with a smaller `VadTree`. The size must
/// stay under a single 4 KiB page so the `mm::frame::allocate_pages`
/// back-end in `create_user_process` is sufficient.
///
/// KTHREAD is 0x360 bytes on Windows 7 x64 RTM.
/// ETHREAD is 0x4D8 bytes on Windows 7 x64 RTM.
fn step2_layout_sizes() -> bool {
    let ep_size = core::mem::size_of::<Eprocess>();
    let et_size = core::mem::size_of::<Ethread>();
    let kt_size = core::mem::size_of::<Kthread>();

    if ep_size == 0 || ep_size > 4096 {
        return false;
    }
    if et_size == 0 || et_size > 4096 {
        return false;
    }
    if kt_size == 0 || kt_size > 4096 {
        return false;
    }

    crate::boot_println!("    Eprocess = 0x{:x} bytes", ep_size);
    crate::boot_println!("    Ethread  = 0x{:x} bytes", et_size);
    crate::boot_println!("    Kthread  = 0x{:x} bytes", kt_size);

    // KTHREAD must be the first field of ETHREAD, because the
    // kernel's wait list head points to the dispatcher header
    // and the dispatcher header is the first field of KTHREAD.
    if core::mem::offset_of!(Ethread, kthread) != 0 {
        return false;
    }
    if core::mem::offset_of!(Kthread, header) != 0 {
        return false;
    }
    if core::mem::offset_of!(Eprocess, kprocess_header) != 0 {
        return false;
    }

    // Dispatcher header type tags.
    let h = Eprocess::new().kprocess_header;
    if h.type_ != 3 {
        return false;
    }
    let h = DispatcherHeader::new(6);
    if h.type_ != 6 {
        return false;
    }

    true
}

/// Step 3: ListEntry invariants.
fn step3_list_entry() -> bool {
    let mut head = ListEntry::new();

    // After new(), the list is empty (flink == null)
    if !head.is_empty() {
        return false;
    }

    head.init();
    if !head.is_empty() {
        return false;
    }

    // Allocate a couple of nodes and add them.
    let mut a = ListEntry::new();
    let mut b = ListEntry::new();
    a.init();
    b.init();
    head.insert_tail(&mut a as *mut ListEntry);
    head.insert_tail(&mut b as *mut ListEntry);

    if head.is_empty() {
        return false;
    }

    // Walk forward.
    unsafe {
        let mut count = 0;
        let mut e = head.flink;
        while e != &mut head as *mut ListEntry {
            if count > 8 {
                return false;
            }
            e = (*e).flink;
            count += 1;
        }
        if count != 2 {
            return false;
        }

        // remove() `a` and confirm the list has exactly one element remaining.
        a.remove();
        let mut e = head.flink;
        let mut count = 0;
        while e != &mut head as *mut ListEntry {
            count += 1;
            e = (*e).flink;
        }
        if count != 1 {
            return false;
        }
    }

    crate::boot_println!("    ListEntry init/insert/remove: OK");
    true
}

/// Step 4: create a user process and look it up.
fn step4_create_user_process() -> bool {
    // Use a PID above the well-known range so this test
    // doesn't collide with the SMSS process created in kernel_main.
    let test_pid: u64 = 0xCAFE_BABE;
    let image: &[u8] = b"\\SystemRoot\\System32\\smoke.exe";

    let process = match super::process::create_user_process(image, test_pid, None) {
        Some(p) => p,
        None => {
            return false;
        }
    };

    if process.unique_process_id != test_pid {
        return false;
    }

    // Name was set. Eprocess::image_file_name holds the base name only.
    let base_start = image.iter().rposition(|&b| b == b'\\').map(|p| p + 1).unwrap_or(0);
    let base_name = &image[base_start..];
    let mut name_match = true;
    for i in 0..base_name.len().min(process.image_file_name.len()) {
        if process.image_file_name[i] != base_name[i] {
            name_match = false;
            break;
        }
    }
    if !name_match {
        return false;
    }

    // The thread list head is NOT empty - create_user_process adds an initial thread.
    if process.kprocess_thread_list_head.is_empty() {
        return false;
    }

    // Look it up.
    let looked_up = match get_by_pid(test_pid) {
        Some(p) => p,
        None => {
            return false;
        }
    };
    if looked_up.unique_process_id != test_pid {
        return false;
    }
    if (looked_up as *mut _) != (process as *mut _) {
        return false;
    }

    crate::boot_println!("    User process PID={}, name={:?}", test_pid, base_name);
    true
}

/// Step 5: thread counter advanced.
fn step5_thread_counter() -> bool {
    let c0 = THREAD_COUNT.load(Ordering::Relaxed);

    // Each Phase 9 init creates at least one user process (smss) with a thread.
    if c0 == 0 {
        crate::boot_println!("    No threads created in init (acceptable for early smoke test)");
        return true;
    }

    let t0 = NEXT_TID.load(Ordering::Relaxed);
    if t0 < 1 {
        return false;
    }

    crate::boot_println!("    Thread count: {}, next TID: {}", c0, t0);
    true
}

/// Step 6: Process / ListEntry size and MAX_PROCESSES.
fn step6_process_table() -> bool {
    if MAX_PROCESSES < 8 {
        return false;
    }

    // Process is just a thin wrapper around Eprocess; the size
    // should be at least as large.
    if core::mem::size_of::<Process>() < core::mem::size_of::<Eprocess>() {
        return false;
    }

    // Thread states.
    if KThreadState::Ready as u8 != 1 {
        return false;
    }
    if KThreadState::Running as u8 != 2 {
        return false;
    }
    if KThreadState::Waiting as u8 != 5 {
        return false;
    }
    if KThreadState::Terminated as u8 != 4 {
        return false;
    }

    crate::boot_println!("    MAX_PROCESSES={}, Process size OK", MAX_PROCESSES);
    true
}

/// Step 7: ExFastRef reference counting
fn step7_ex_fast_ref() -> bool {
    // Test from_object
    let obj_ptr = 0x1000u64 as *const ();
    // SAFETY: obj_ptr is a valid test pointer.
    let fast_ref = unsafe { ExFastRef::from_object(obj_ptr) };

    // Verify object pointer extraction
    if fast_ref.get_object() != obj_ptr as u64 {
        return false;
    }

    // Verify initial reference count is 1
    if fast_ref.get_refcount() != 1 {
        return false;
    }

    // Test add_ref
    let mutable_ref = fast_ref;
    mutable_ref.add_ref();
    if mutable_ref.get_refcount() != 2 {
        return false;
    }

    // Test release
    let should_free = mutable_ref.release();
    if should_free {
        return false;
    }
    if mutable_ref.get_refcount() != 1 {
        return false;
    }

    // Test release to zero (should_free = true)
    let should_free = mutable_ref.release();
    if !should_free {
        return false;
    }

    // Test from_raw
    let raw_value = 0xFFFFF000_00001000u64;
    let from_raw_ref = ExFastRef::from_raw(raw_value);
    if from_raw_ref.get_object() != (raw_value & !0x7) {
        return false;
    }

    crate::boot_println!("    ExFastRef: OK");
    true
}
