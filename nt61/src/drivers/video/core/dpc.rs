//! Deferred Procedure Call (DPC) Support
//
//! Provides DPC infrastructure for GPU drivers, allowing long-running
//! operations to be deferred to a lower priority execution context.
//
//! Clean-room implementation based on industry standards.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// =====================================================================
// DPC Types
// =====================================================================

/// DPC priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DpcPriority {
    /// High priority (dispatch level)
    High,
    /// Medium priority
    Medium,
    /// Low priority
    Low,
    /// Background (idle time)
    Background,
}

impl DpcPriority {
    /// Get scheduling weight
    pub fn weight(&self) -> u32 {
        match self {
            DpcPriority::High => 100,
            DpcPriority::Medium => 50,
            DpcPriority::Low => 25,
            DpcPriority::Background => 1,
        }
    }
}

/// DPC routine function type
pub type DpcRoutine = fn(arg: *mut core::ffi::c_void);

/// DPC (Deferred Procedure Call) object
#[derive(Debug)]
pub struct Dpc {
    /// DPC routine to execute
    routine: DpcRoutine,
    /// Argument to pass to routine
    arg: *mut core::ffi::c_void,
    /// Priority level
    priority: DpcPriority,
    /// Whether DPC is currently executing
    executing: AtomicBool,
    /// DPC queue link (for list insertion)
    pub queue_next: Option<*const Dpc>,
}

impl Dpc {
    /// Create a new DPC
    pub fn new(routine: DpcRoutine, arg: *mut core::ffi::c_void, priority: DpcPriority) -> Self {
        Self {
            routine,
            arg,
            priority,
            executing: AtomicBool::new(false),
            queue_next: None,
        }
    }

    /// Execute the DPC
    pub fn execute(&self) {
        // Prevent re-entrant execution
        if self.executing.swap(true, Ordering::AcqRel) {
            return;
        }

        // Call the routine
        (self.routine)(self.arg);

        self.executing.store(false, Ordering::Release);
    }

    /// Check if DPC is currently executing
    pub fn is_executing(&self) -> bool {
        self.executing.load(Ordering::Acquire)
    }

    /// Get priority
    pub fn priority(&self) -> DpcPriority {
        self.priority
    }
}

// =====================================================================
// DPC Queue
// =====================================================================

/// DPC queue implementation
pub struct DpcQueue {
    /// DPC count
    count: AtomicU32,
    /// Maximum DPCs in queue
    max_dpcs: usize,
    /// DPC array
    dpcs: [*const Dpc; 64],
    /// Head index
    head: AtomicU32,
    /// Tail index
    tail: AtomicU32,
    /// Queue is full
    full: AtomicBool,
    /// Queue is empty
    empty: AtomicBool,
}

impl DpcQueue {
    /// Create a new DPC queue
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            max_dpcs: 64,
            dpcs: [core::ptr::null(); 64],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            full: AtomicBool::new(false),
            empty: AtomicBool::new(true),
        }
    }

    /// Enqueue a DPC
    ///
    /// Returns true if the DPC was enqueued, false if the queue is full.
    pub fn enqueue(&mut self, dpc: *const Dpc) -> bool {
        if self.full.load(Ordering::Acquire) {
            return false;
        }

        // Get next tail position
        let tail = self.tail.load(Ordering::Acquire) as usize;
        self.dpcs[tail] = dpc;

        // Update tail
        let new_tail = ((tail + 1) % self.max_dpcs) as u32;
        self.tail.store(new_tail, Ordering::Release);

        // Update count
        self.count.fetch_add(1, Ordering::AcqRel);

        // Update flags
        self.empty.store(false, Ordering::Release);
        if new_tail == self.head.load(Ordering::Acquire) {
            self.full.store(true, Ordering::Release);
        }

        true
    }

    /// Dequeue a DPC
    ///
    /// Returns the next DPC, or None if the queue is empty.
    pub fn dequeue(&self) -> Option<*const Dpc> {
        if self.empty.load(Ordering::Acquire) {
            return None;
        }

        // Get head position
        let head = self.head.load(Ordering::Acquire) as usize;
        let dpc = self.dpcs[head];

        // Update head
        let new_head = ((head + 1) % self.max_dpcs) as u32;
        self.head.store(new_head, Ordering::Release);

        // Update count
        self.count.fetch_sub(1, Ordering::AcqRel);

        // Update flags
        self.full.store(false, Ordering::Release);
        if new_head == self.tail.load(Ordering::Acquire) {
            self.empty.store(true, Ordering::Release);
        }

        Some(dpc)
    }

    /// Peek at the next DPC without removing it
    pub fn peek(&self) -> Option<*const Dpc> {
        if self.empty.load(Ordering::Acquire) {
            return None;
        }
        let head = self.head.load(Ordering::Acquire) as usize;
        Some(self.dpcs[head])
    }

    /// Get the number of DPCs in the queue
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire) as usize
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.empty.load(Ordering::Acquire)
    }

    /// Check if the queue is full
    pub fn is_full(&self) -> bool {
        self.full.load(Ordering::Acquire)
    }

    /// Drain all DPCs from the queue
    ///
    /// Returns a vector of DPC pointers.
    pub fn drain(&self) -> Vec<*const Dpc> {
        let mut result = Vec::new();
        while let Some(dpc) = self.dequeue() {
            result.push(dpc);
        }
        result
    }
}

impl Default for DpcQueue {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// DPC Thread
// =====================================================================

/// DPC thread state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpcThreadState {
    /// Thread is idle
    Idle,
    /// Thread is processing DPCs
    Running,
    /// Thread is signaled to exit
    Exiting,
}

/// DPC thread
pub struct DpcThread {
    /// Thread state
    state: DpcThreadState,
    /// DPC queue
    queue: DpcQueue,
    /// Processed DPC count
    processed_count: AtomicU64,
    /// Last error
    last_error: AtomicU32,
}

impl DpcThread {
    /// Create a new DPC thread
    pub fn new() -> Self {
        Self {
            state: DpcThreadState::Idle,
            queue: DpcQueue::new(),
            processed_count: AtomicU64::new(0),
            last_error: AtomicU32::new(0),
        }
    }

    /// Queue a DPC for execution
    pub fn queue_dpc(&mut self, dpc: *const Dpc) -> bool {
        self.queue.enqueue(dpc)
    }

    /// Process DPCs in the queue
    ///
    /// This is typically called from a worker thread or at lowered IRQL.
    pub fn process_queue(&mut self) {
        while let Some(dpc_ptr) = self.queue.dequeue() {
            let dpc = unsafe { &*dpc_ptr };

            // Skip if already executing
            if dpc.is_executing() {
                // Re-queue for later
                self.queue.enqueue(dpc_ptr);
                break;
            }

            // Execute DPC
            dpc.execute();

            self.processed_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Get processed count
    pub fn processed_count(&self) -> u64 {
        self.processed_count.load(Ordering::Acquire)
    }

    /// Get state
    pub fn state(&self) -> DpcThreadState {
        self.state
    }

    /// Set state
    pub fn set_state(&mut self, state: DpcThreadState) {
        self.state = state;
    }

    /// Get last error
    pub fn last_error(&self) -> u32 {
        self.last_error.load(Ordering::Acquire)
    }

    /// Set last error
    pub fn set_last_error(&self, error: u32) {
        self.last_error.store(error, Ordering::Release);
    }
}

impl Default for DpcThread {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// DPC Manager
// =====================================================================

/// DPC manager for GPU operations
pub struct DpcManager {
    /// DPC threads (one per CPU)
    threads: Vec<DpcThread>,
    /// Default DPC queue
    default_queue: DpcQueue,
}

impl DpcManager {
    /// Create a new DPC manager
    pub fn new(num_cpus: usize) -> Self {
        let threads = (0..num_cpus).map(|_| DpcThread::new()).collect();

        Self {
            threads,
            default_queue: DpcQueue::new(),
        }
    }

    /// Queue a DPC to the default queue
    pub fn queue(&mut self, dpc: *const Dpc) -> bool {
        self.default_queue.enqueue(dpc)
    }

    /// Queue a DPC to a specific CPU
    pub fn queue_cpu(&mut self, cpu: usize, dpc: *const Dpc) -> bool {
        if cpu < self.threads.len() {
            self.threads[cpu].queue_dpc(dpc)
        } else {
            false
        }
    }

    /// Process DPCs on the current CPU
    pub fn process_current(&mut self) {
        if let Some(thread) = self.threads.first_mut() {
            thread.process_queue();
        }
        self.default_queue.drain().iter().for_each(|dpc| {
            let dpc = unsafe { &**dpc };
            dpc.execute();
        });
    }

    /// Get DPC count
    pub fn pending_count(&self) -> usize {
        let mut count = self.default_queue.len();
        for thread in &self.threads {
            count += thread.queue.len();
        }
        count
    }
}

impl Default for DpcManager {
    fn default() -> Self {
        Self::new(1)
    }
}
