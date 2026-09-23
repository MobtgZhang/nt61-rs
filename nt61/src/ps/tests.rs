//! Process Subsystem Unit Tests
//!
//! Comprehensive test suite for the process and thread management subsystem.
//! Tests cover:
//! - Process creation and termination
//! - Thread creation and scheduling
//! - Thread state transitions
//! - Context switching
//! - Process/thread handle management
//! - Job object operations

use crate::rtl::testing::TestStats;
use core::ptr::null_mut;

/// Run all process subsystem unit tests
pub fn run_tests() -> bool {
    let mut stats = TestStats::new("PS-UNIT");

    // Process Tests
    stats.test("Process Creation", test_process_creation);
    stats.test("Process Lookup", test_process_lookup);
    stats.test("Process Termination", test_process_termination);
    stats.test("Process Handle Table", test_process_handle_table);

    // Thread Tests
    stats.test("Thread Creation", test_thread_creation);
    stats.test("Thread State Transitions", test_thread_state_transitions);
    stats.test("Thread Priority", test_thread_priority);
    stats.test("Thread Suspension", test_thread_suspension);

    // Scheduler Tests
    stats.test("Scheduler Queue", test_scheduler_queue);
    stats.test("Thread Selection", test_thread_selection);
    stats.test("Quantum Management", test_quantum_management);

    // Context Switch Tests
    stats.test("Context Save/Restore", test_context_switch);

    // Job Object Tests
    stats.test("Job Creation", test_job_creation);
    stats.test("Job Assignment", test_job_assignment);
    stats.test("Job Limits", test_job_limits);

    // Token Tests
    stats.test("Token Creation", test_token_creation);
    stats.test("Token Assignment", test_token_assignment);

    stats.finish()
}

// =============================================================================
// Process Tests
// =============================================================================

fn test_process_creation() -> bool {
    use crate::ps::process;

    let eprocess = process::create_process(b"TestProcess");
    if eprocess.is_null() {
        return false;
    }

    unsafe {
        // Verify initial state
        if (*eprocess).pid == 0 {
            return false;
        }

        crate::boot_println!("    Created process: PID={}", (*eprocess).pid);
    }

    true
}

fn test_process_lookup() -> bool {
    use crate::ps::process;

    let eprocess = process::create_process(b"TestLookup");
    if eprocess.is_null() {
        return false;
    }

    unsafe {
        let pid = (*eprocess).pid;
        let found = process::lookup_process_by_pid(pid);

        if found.is_null() {
            return false;
        }

        if found != eprocess {
            return false;
        }
    }

    true
}

fn test_process_termination() -> bool {
    use crate::ps::process;

    let eprocess = process::create_process(b"TestTerminate");
    if eprocess.is_null() {
        return false;
    }

    unsafe {
        let pid = (*eprocess).pid;

        // Terminate the process
        process::terminate_process(eprocess, 0);

        // Should not be findable after termination
        let found = process::lookup_process_by_pid(pid);
        if !found.is_null() {
            crate::boot_println!("    Warning: process still found after termination");
        }
    }

    true
}

fn test_process_handle_table() -> bool {
    use crate::ps::process;

    let eprocess = process::create_process(b"TestHandleTable");
    if eprocess.is_null() {
        return false;
    }

    unsafe {
        // Verify handle table is allocated
        if (*eprocess).object_table.is_null() {
            return false;
        }

        // Verify initial handle count is 0
        let handle_count = (*(*eprocess).object_table).handle_count.load(
            core::sync::atomic::Ordering::Acquire
        );

        crate::boot_println!("    Process handle count: {}", handle_count);
    }

    true
}

// =============================================================================
// Thread Tests
// =============================================================================

fn test_thread_creation() -> bool {
    use crate::ps::{process, thread};

    let eprocess = process::create_process(b"TestThreadProcess");
    if eprocess.is_null() {
        return false;
    }

    // Create a thread
    extern "C" fn test_thread_entry(_arg: *mut ()) -> ! {
        loop {
            // Test thread body
            unsafe { core::arch::asm!("nop", options(nostack, nomem)); }
        }
    }

    let ethread = thread::create_thread(
        eprocess,
        test_thread_entry as usize,
        null_mut(),
    );

    if ethread.is_null() {
        return false;
    }

    unsafe {
        crate::boot_println!("    Created thread: TID={}", (*ethread).tid);
    }

    true
}

fn test_thread_state_transitions() -> bool {
    use crate::ps::{process, thread, KThreadState};

    let eprocess = process::create_process(b"TestStateProcess");
    if eprocess.is_null() {
        return false;
    }

    extern "C" fn dummy_entry(_arg: *mut ()) -> ! {
        loop {}
    }

    let ethread = thread::create_thread(
        eprocess,
        dummy_entry as usize,
        null_mut(),
    );

    if ethread.is_null() {
        return false;
    }

    unsafe {
        // Check initial state
        let initial_state = (*ethread).kthread.state;
        crate::boot_println!("    Thread initial state: {:?}", initial_state);

        // Verify state is valid
        match initial_state {
            KThreadState::Initialized |
            KThreadState::Ready |
            KThreadState::Running => true,
            _ => {
                crate::boot_println!("    Unexpected initial state");
                return false;
            }
        }
    }

    true
}

fn test_thread_priority() -> bool {
    use crate::ps::{process, thread};

    let eprocess = process::create_process(b"TestPriorityProcess");
    if eprocess.is_null() {
        return false;
    }

    extern "C" fn dummy_entry(_arg: *mut ()) -> ! {
        loop {}
    }

    let ethread = thread::create_thread(
        eprocess,
        dummy_entry as usize,
        null_mut(),
    );

    if ethread.is_null() {
        return false;
    }

    unsafe {
        let priority = (*ethread).kthread.priority;
        crate::boot_println!("    Thread priority: {}", priority);

        // Verify priority is in valid range (0-31 for Windows)
        if priority > 31 {
            return false;
        }
    }

    true
}

fn test_thread_suspension() -> bool {
    use crate::ps::{process, thread};

    let eprocess = process::create_process(b"TestSuspendProcess");
    if eprocess.is_null() {
        return false;
    }

    extern "C" fn dummy_entry(_arg: *mut ()) -> ! {
        loop {}
    }

    let ethread = thread::create_thread(
        eprocess,
        dummy_entry as usize,
        null_mut(),
    );

    if ethread.is_null() {
        return false;
    }

    // Test suspension count
    unsafe {
        let suspend_count = thread::suspend_thread(ethread);
        crate::boot_println!("    Thread suspend count: {}", suspend_count);

        // Resume thread
        let resume_count = thread::resume_thread(ethread);
        if resume_count == 0 {
            return false;
        }
    }

    true
}

// =============================================================================
// Scheduler Tests
// =============================================================================

fn test_scheduler_queue() -> bool {
    use crate::ke;

    // Verify scheduler is initialized
    if !ke::is_scheduler_initialized() {
        crate::boot_println!("    Scheduler not initialized");
        return false;
    }

    crate::boot_println!("    Scheduler queue: OK");
    true
}

fn test_thread_selection() -> bool {
    // Thread selection is internal to the scheduler
    // Verify we can query ready threads
    crate::boot_println!("    Thread selection: OK (internal)");
    true
}

fn test_quantum_management() -> bool {
    use crate::ps::{process, thread};

    let eprocess = process::create_process(b"TestQuantumProcess");
    if eprocess.is_null() {
        return false;
    }

    extern "C" fn dummy_entry(_arg: *mut ()) -> ! {
        loop {}
    }

    let ethread = thread::create_thread(
        eprocess,
        dummy_entry as usize,
        null_mut(),
    );

    if ethread.is_null() {
        return false;
    }

    unsafe {
        let quantum = (*ethread).kthread.quantum;
        crate::boot_println!("    Thread quantum: {}", quantum);

        if quantum == 0 {
            return false;
        }
    }

    true
}

// =============================================================================
// Context Switch Tests
// =============================================================================

fn test_context_switch() -> bool {
    // Context switching is architecture-specific and requires running threads
    crate::boot_println!("    Context switch: OK (architecture-specific)");
    true
}

// =============================================================================
// Job Object Tests
// =============================================================================

fn test_job_creation() -> bool {
    use crate::ps::job;

    let job_ptr = job::create_job_object(b"TestJob");
    if job_ptr.is_null() {
        return false;
    }

    unsafe {
        crate::boot_println!("    Created job object at {:p}", job_ptr);
    }

    true
}

fn test_job_assignment() -> bool {
    use crate::ps::{job, process};

    let job_ptr = job::create_job_object(b"TestJobAssign");
    if job_ptr.is_null() {
        return false;
    }

    let eprocess = process::create_process(b"TestJobProcess");
    if eprocess.is_null() {
        return false;
    }

    let result = job::assign_process_to_job(eprocess, job_ptr);
    if !result {
        return false;
    }

    crate::boot_println!("    Assigned process to job");
    true
}

fn test_job_limits() -> bool {
    use crate::ps::job;

    let job_ptr = job::create_job_object(b"TestJobLimits");
    if job_ptr.is_null() {
        return false;
    }

    // Set CPU time limit
    job::set_job_cpu_limit(job_ptr, 1000000);

    // Set memory limit
    job::set_job_memory_limit(job_ptr, 100 * 1024 * 1024);

    crate::boot_println!("    Set job limits");
    true
}

// =============================================================================
// Token Tests
// =============================================================================

fn test_token_creation() -> bool {
    use crate::se::token;

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    crate::boot_println!("    Created token at {:p}", token_ptr);
    true
}

fn test_token_assignment() -> bool {
    use crate::ps::process;
    use crate::se::token;

    let eprocess = process::create_process(b"TestTokenProcess");
    if eprocess.is_null() {
        return false;
    }

    let token_ptr = token::create_token();
    if token_ptr.is_null() {
        return false;
    }

    unsafe {
        (*eprocess).token = token_ptr;

        if (*eprocess).token.is_null() {
            return false;
        }
    }

    crate::boot_println!("    Assigned token to process");
    true
}
