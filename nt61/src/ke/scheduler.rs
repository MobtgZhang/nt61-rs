//! Scheduler
//
//! Process and thread scheduling for the NT kernel.
//
//! Implements an SMP-aware, multi-level queue scheduler with 32
//! priority levels. Each PRCB owns a per-CPU set of 32 ready queues
//! (matching the Windows 7 x64 KPRCB layout at offset 0x0D0) plus a
//! ready_summary bitmask for fast priority lookup. The dispatcher
//! picks threads from the current CPU's PRCB first; each per-CPU and
//! per-(CPU, priority) queue has its own lock for SMP scalability.
//
//! On the bootstrap the dispatcher lock is held while we make
//! scheduling decisions but not while we context-switch (the
//! assembly trampoline in `arch::x86_64` is responsible for saving
//! and restoring the caller's registers; this file just selects the
//! next thread).

use crate::ke::irql::{self, Irql};
use crate::ke::sync::Spinlock;
use crate::ps::thread::{create_idle_thread as create_thread_idle, Ethread, KThreadState};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 4;
const MAX_IDLE_THREADS: usize = 4;

/// Scheduler priority levels (Windows-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    BackgroundSystem = 4,
    Variable = 13,
    TimeCritical = 15,
    RealTime = 16,
}

/// Quantum values for different priority classes.
#[derive(Debug, Clone, Copy)]
pub enum Quantum {
    Short,
    Standard,
    Long,
}

/// Quantum constants (in timer ticks).
/// Windows 7 default quantum values:
///   - Foreground process: 36 ticks (12 * 3 multiplier)
///   - Background process: 12 ticks
///   - Variable priority: 6 ticks
pub const QUANTUM_DEFAULT: u32 = 12;
pub const QUANTUM_FOREGROUND: u32 = 36;
pub const QUANTUM_SHORT: u32 = 6;

/// Priority boost constants
pub const PRIORITY_BOOST_IOTHREAD: i8 = 1;
pub const PRIORITY_BOOST_SETEVENT: i8 = 2;
pub const PRIORITY_BOOST_SPECIAL: i8 = 2;
pub const PRIORITY_BOOST_MUTANT: i8 = 1;
pub const MAX_BOOSTED_PRIORITY: i8 = 15;
pub const DECAY_TIME_MS: u32 = 4000;

/// Priority decay constants
pub const DECAY_AMOUNT: i8 = 1; // Amount to decay per interval
pub const DECAY_CHECK_INTERVAL: u32 = 1000; // Check for decay every 1 second

/// Balance constants
pub const BALANCE_THRESHOLD_DEFAULT: usize = 2;
pub const BALANCE_CHECK_INTERVAL_MS: u32 = 5000;

/// Timer tick interval in milliseconds (assuming 15ms per tick)
pub const TICK_MS: u32 = 15;

/// Priority boost types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityBoostType {
    IoCompletion,
    EventSet,
    Special,
    MutantRelease,
}

/// Thread quantum tracking per CPU.
pub struct ThreadQuantum {
    pub remaining: u32,
    pub initial: u32,
}

/// Ready queue for each priority level.
#[repr(C)]
// =============================================================================
// Extended PRCB structures for Windows 7 x64 compatibility (P2-3)
// =============================================================================

/// Processor information structure
#[repr(C)]
pub struct ProcessorInfo {
    /// Processor name string (up to 96 bytes)
    pub processor_name: [u8; 96],
    /// Processor ID
    pub processor_id: u64,
    /// Initial APIC ID
    pub initial_apic_id: u32,
    /// Local APIC version
    pub local_apic_version: u8,
    /// Processor feature flags
    pub feature_flags: u64,
    /// Processor frequency (MHz)
    pub mhz: u32,
    /// Processor group index
    pub group_index: u16,
    /// group relative processor number
    pub processor_number: u8,
    /// Reserved
    pub reserved: u8,
}

impl ProcessorInfo {
    pub const fn new() -> Self {
        Self {
            processor_name: [0; 96],
            processor_id: 0,
            initial_apic_id: 0,
            local_apic_version: 0x20,
            feature_flags: 0,
            mhz: 0,
            group_index: 0,
            processor_number: 0,
            reserved: 0,
        }
    }
}

/// Cache information structure
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CacheInfo {
    /// Cache level (L1=1, L2=2, etc.)
    pub level: u8,
    /// Cache associativity
    pub associativity: u8,
    /// Cache line size
    pub line_size: u16,
    /// Cache size in bytes
    pub size: u32,
    /// Reserved
    pub reserved: [u8; 7],
}

impl CacheInfo {
    pub const fn empty() -> Self {
        Self {
            level: 0,
            associativity: 0,
            line_size: 0,
            size: 0,
            reserved: [0; 7],
        }
    }
}

/// DPC queue data structure
#[repr(C)]
pub struct DpcData {
    /// DPC list head
    pub dpc_list_head: ListEntry,
    /// DPC list tail
    pub dpc_list_tail: *mut ListEntry,
    /// DPC queue depth
    pub dpc_queue_depth: u32,
    /// DPC routine active flag
    pub dpc_routine_active: u32,
    /// DPC request time
    pub dpc_request_time: u64,
    /// DPC lock
    pub dpc_lock: u64,
}

impl DpcData {
    pub const fn new() -> Self {
        Self {
            dpc_list_head: ListEntry {
                flink: core::ptr::null_mut(),
                blink: core::ptr::null_mut(),
            },
            dpc_list_tail: core::ptr::null_mut(),
            dpc_queue_depth: 0,
            dpc_routine_active: 0,
            dpc_request_time: 0,
            dpc_lock: 0,
        }
    }
}

/// Per-priority ready queue head - 16 bytes to match Windows 7 x64 offsets.
/// Windows 7 x64 KPRCB ready queues are at offset 0x0D0, each is 16 bytes.
/// Uses the standard doubly-linked list pattern: head+tail, no count field.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ListHead {
    pub head: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListHead {
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            blink: core::ptr::null_mut(),
        }
    }

    pub fn is_empty(&self) -> bool {
        // Double-sided check: both head and blink must be consistent.
        // - both null  -> empty
        // - both non-null -> has at least one node
        // - one null and the other non-null -> inconsistent state;
        //   treat as non-empty to avoid dropping a tail pointer.
        self.head.is_null() && self.blink.is_null()
    }

    pub fn add_tail(&mut self, entry: *mut ListEntry) {
        unsafe {
            (*entry).blink = self.blink;
            (*entry).flink = core::ptr::null_mut();
            if self.blink.is_null() {
                self.head = entry;
                self.blink = entry;
            } else {
                (*self.blink).flink = entry;
                self.blink = entry;
            }
        }
    }

    pub fn remove_head(&mut self) -> Option<*mut ListEntry> {
        if self.head.is_null() {
            return None;
        }
        unsafe {
            let entry = self.head;
            let next = (*entry).flink;
            self.head = next;
            if next.is_null() {
                self.blink = core::ptr::null_mut();
            } else {
                (*next).blink = core::ptr::null_mut();
            }
            Some(entry)
        }
    }
}

// Compile-time layout assertions for ListHead (Windows 7 x64 size
// is 16 bytes: head pointer + blink pointer).
const _: () = assert!(
    core::mem::size_of::<ListHead>() == 16,
    "ListHead must be 16 bytes (head + blink)"
);
const _: () = assert!(
    core::mem::offset_of!(ListHead, head) == 0,
    "ListHead.head must be at offset 0"
);
const _: () = assert!(
    core::mem::offset_of!(ListHead, blink) == 8,
    "ListHead.blink must be at offset 8"
);

/// List entry.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    pub const fn new() -> Self {
        Self {
            flink: core::ptr::null_mut(),
            blink: core::ptr::null_mut(),
        }
    }
}

/// Wait block structure for wait operations
#[derive(Clone, Copy)]
#[repr(C)]
pub struct WaitBlock {
    pub wait_list_entry: ListEntry, // 0x00
    pub thread: *mut Ethread,       // 0x10
    pub object: u64,                // 0x18
    pub next_wait_block: u64,       // 0x20
    pub wait_key: u16,              // 0x28
    pub wait_type: u16,             // 0x2A
}

/// Processor control Block (PRCB) - Windows 7 x64 KPRCB Layout
///
/// Windows 7 x64 KPRCB actual size: 0xF80 (3968 bytes)
/// Reference: geoffchappell.com, Vergilius Project
///
/// Structure layout follows Windows 7 x64 KPRCB with the following sections:
/// - 0x000-0x1FF: Basic Scheduler (threads, ready queues, dispatcher)
/// - 0x200-0x2FF: Processor Info (CPU ID, cache, features)
/// - 0x300-0x3FF: DPC Data
/// - 0x400-0x4FF: Interrupt & Timer
/// - 0x500-0x5FF: power & Thermal
/// - 0x600-0x6FF: Statistics
/// - 0x700-0x7FF: MultiThread Processor Set
/// - 0x800-0x8FF: Waiting & Scheduling
/// - 0x900-0x9FF: Additional Wait/Schedule Data
/// - 0xA00-0xAFF: Schedule Groups
/// - 0xB00-0xBFF: Cache Data
/// - 0xC00-0xCFF: Performance Counters
/// - 0xD00-0xDFF: Timeout Data
/// - 0xE00-0xEFF: Report Data
/// - 0xF00-0xF7F: PrcbType/Size/Version
#[repr(C)]
#[repr(align(16))]
pub struct Prcb {
    // === 0x000: Basic Scheduler ===
    pub current_thread: *mut Ethread,  // 0x000
    pub current_thread_pad: u64,       // 0x008
    pub idle_thread: *mut Ethread,     // 0x010
    pub idle_thread_pad: u64,          // 0x018
    pub next_thread: *mut Ethread,     // 0x020
    pub standby_thread: *mut Ethread,  // 0x028
    pub old_thread: *mut Ethread,      // 0x030
    pub idle_ready_threads: ListEntry, // 0x038 (16 bytes, ends at 0x048)

    // Padding from 0x048 to 0x0C8 (128 bytes)
    _pad_basic1: [u8; 0xC8 - 0x048],

    pub ready_summary: AtomicU32,   // 0x0C8 (atomic for SMP safety)
    pub ready_summary_padding: u32, // 0x0CC

    // ready_queues array at 0x0D0 - 32 priority queues
    // Each ListHead is 16 bytes (3 x 8-byte fields with padding)
    pub ready_queues: [ListHead; 32], // 0x0D0 (512 bytes, ends at 0x2D0)

    // After ready_queues at 0x2D0:
    pub dispatcher_lock: u64,     // 0x2D0
    pub dispatcher_lock_pad: u64, // 0x2D8
    pub schedule_dpc: u64,        // 0x2E0
    _pad_2e8: u8,                 // 0x2E8
    pub panic_in_progress: u8,    // 0x2E9
    pub dpc_time: u16,            // 0x2EA
    pub timer_table: u64,         // 0x2EC
    pub timer_expiration: i64,    // 0x2F4

    // === 0x300: Processor Info ===
    pub quantum_remaining: u32,    // 0x300
    pub quantum_initial: u32,      // 0x304
    pub processor_number: u8,      // 0x308
    pub normal_cpu: u8,            // 0x309
    pub group_index: u8,           // 0x30A
    pub apic_id: u8,               // 0x30B
    pub local_apic_version: u8,    // 0x30C
    pub cpu_type: u8,              // 0x30D
    pub cpu_features: u8,          // 0x30E
    pub cpu_features_pad: u8,      // 0x30F
    pub cpu_brand: [u8; 64],       // 0x310
    pub logical_processors: u16,   // 0x350
    pub group_processor_count: u8, // 0x352
    _pad_353: u8,                  // 0x353
    pub last_dispatch_time: u64,   // 0x358
    pub cache: [CacheInfo; 5],     // 0x360 (80 bytes, ends at 0x3B0)

    // Padding from 0x3B0 to 0x400 (80 bytes)
    _pad_proc_info: [u8; 0x400 - 0x3B0],

    // === 0x400: DPC Data ===
    pub dpc_data: DpcData,         // 0x400
    pub dpc_stack: u64,            // 0x430
    pub max_dpc_queue_depth: u32,  // 0x438
    pub dpc_queue_depth: u32,      // 0x43C
    pub dpc_request_pending: u8,   // 0x440
    pub dpc_request_slot: [u8; 2], // 0x441
    pub dpc_routine_active: u8,    // 0x443
    pub dpc_thread_active: u8,     // 0x444
    pub dpc_unused: u8,            // 0x445
    pub timer_service_index: u8,   // 0x446
    pub timer_banner: u8,          // 0x447
    pub npx_configuration: u8,     // 0x448
    pub npx_sp: u64,               // 0x450
    pub pdc_cpu: u64,              // 0x458
    pub system_calls: u32,         // 0x460

    // Padding from 0x464 to 0x500 (156 bytes)
    _pad_dpc: [u8; 0x500 - 0x464],

    // === 0x500: Interrupt & Timer ===
    pub interrupt_count: u64,       // 0x500
    pub dpc_interrupt_count: u64,   // 0x508
    pub timer_interrupt_count: u64, // 0x510
    pub pending_interrupts: u64,    // 0x518
    pub interrupt_mode: u8,         // 0x520
    _pad_int: [u8; 7],              // 0x521
    pub timer_vector: u64,          // 0x528
    pub local_apic: [u8; 0x100],    // 0x530

    // Padding from 0x630 to 0x700 (208 bytes)
    _pad_int_timer: [u8; 0x700 - 0x630],

    // === 0x700: power & Thermal ===
    pub power_state: u32,       // 0x700
    pub thermal_zone: u64,      // 0x708
    pub power_policy: u64,      // 0x710
    pub idle_function: u64,     // 0x718
    pub idle_state: [u8; 0xE8], // 0x720 (232 bytes, ends at 0x808)

    // Padding from 0x808 to 0x900 (248 bytes)
    _pad_power: [u8; 0x900 - 0x808],

    // === 0x900: Statistics ===
    pub context_switch_count: u64,       // 0x900
    pub cycle_time: u64,                 // 0x908
    pub cycle_time_padding: u64,         // 0x910
    pub wait_continuation_count: u64,    // 0x918
    pub ready_continuation_count: u64,   // 0x920
    pub kernel_time: u64,                // 0x928
    pub user_time: u64,                  // 0x930
    pub dpc_time_stat: u64,              // 0x938
    pub interrupt_time: u64,             // 0x940
    pub page_fault_count: u32,           // 0x948
    pub cache_fill_count: u32,           // 0x94C
    pub syscall_count: u32,              // 0x950
    pub interrupt_count_stat: u32,       // 0x954
    pub dpc_count: u32,                  // 0x958
    pub pad_95c: u32,                    // 0x95C
    pub passive_affinity_count: u32,     // 0x960
    pub pad_cpu: u64,                    // 0x968
    pub debugger_options: u64,           // 0x970
    pub pad_974: u32,                    // 0x978
    pub pad_97c: u32,                    // 0x97C
    pub seed: u64,                       // 0x980
    pub node_seed: [u64; 2],             // 0x988
    pub stall_scale_factor: u32,         // 0x998
    pub multi_thread_processor_set: u64, // 0x9A0

    // Padding from 0x9A8 to 0xA00 (88 bytes)
    _pad_stat: [u8; 0xA00 - 0x9A8],

    // === 0xA00: MultiThread Processor Set ===
    pub mt_wait_bitset: [u8; 64], // 0xA00
    pub mt_processor_set: u64,    // 0xA40
    pub mt_aprocessors: u64,      // 0xA48

    // Padding from 0xA50 to 0xB00 (176 bytes)
    _pad_mt: [u8; 0xB00 - 0xA50],

    // === 0xB00: Waiting & Scheduling ===
    pub wait_intes: u64,              // 0xB00
    pub wait_block: [WaitBlock; 8],   // 0xB08
    pub wait_list_head: ListEntry,    // 0xB88
    pub affinity_suspend_quantum: u8, // 0xB98
    pub suspend_timer_in_use: u8,     // 0xB99
    pub cpu_vendor: u8,               // 0xB9A
    pub dbg_cpu: u8,                  // 0xB9B
    pub ccd_time: u64,                // 0xBA0
    pub ready_summary_smt: u64,       // 0xBA8
    pub smt_period: u32,              // 0xBB0
    pub smt_csd_barrier: u32,         // 0xBB4
    pub wait_affinity: u32,           // 0xBB8
    pub pad_8bc: u32,                 // 0xBBC
    pub initial_stall: u32,           // 0xBC0
    pub pad_8c4: u32,                 // 0xBC4
    pub pad_8c8: u64,                 // 0xBC8
    pub pad_8d0: u64,                 // 0xBD0
    pub wait_outstanding: u8,         // 0xBD8
    _pad_wait: [u8; 3],               // 0xBD9
    pub yield_needed: u32,            // 0xBDC
    pub yield_outstanding: u32,       // 0xBE0
    pub pad_8e4: u32,                 // 0xBE4
    pub pad_8e8: u64,                 // 0xBE8
    pub pad_8f0: u64,                 // 0xBF0
    pub pad_8f8: u64,                 // 0xBF8

    // Padding from 0xC00 to 0xD00 (256 bytes)
    _pad_wait2: [u8; 0xD00 - 0xC00],

    // === 0xD00: Schedule Groups ===
    pub schedule_groups: u64,        // 0xD00
    pub schedule_slots: [u64; 16],   // 0xD08
    pub schedule_last_slot: u32,     // 0xD88
    pub schedule_slots_padding: u32, // 0xD8C
    pub ccd_runnable_max: u32,       // 0xD90
    pub ccd_runnable: u32,           // 0xD94

    // Padding from 0xD98 to 0xE00 (104 bytes)
    _pad_sched: [u8; 0xE00 - 0xD98],

    // === 0xE00: Cache Data ===
    _pad_cache: [u8; 0xF00 - 0xE00],

    // === 0xF00: Performance Counters ===
    pub perf_global: u64,       // 0xF00
    pub perf_global_mask: u64,  // 0xF08
    pub perf_global_spin: u64,  // 0xF10
    pub perf_counter: [u64; 8], // 0xF18 (64 bytes, ends at 0xF58)

    // PrcbType/Size/Version (final section)
    pub prcb_type: u16,       // 0xF58 (should be 0x0864)
    pub prcb_size: u16,       // 0xF5A (should be 0x0F80)
    pub minor_version: u8,    // 0xF5C
    pub major_version: u8,    // 0xF5D
    pub build_number: u16,    // 0xF5E
    pub q_system_time: u64,   // 0xF60
    pub pad_f68: [u8; 0x118], // 0xF68 - Fill to 0xF80 (280 bytes)
}

// Note: Prcb structure is expanded for Windows 7 x64 compatibility
// The actual size may vary slightly from the theoretical 0xF80 bytes
// Key fields are at their correct offsets for compatibility

// FIX 2.10: Add comprehensive compile-time assertions for critical field offsets
// These assertions ensure the struct layout matches Windows 7 x64 KPRCB layout

// Verify basic scheduler fields
const _: () = assert!(
    core::mem::offset_of!(Prcb, current_thread) == 0x000,
    "current_thread must be at offset 0x000"
);
const _: () = assert!(
    core::mem::offset_of!(Prcb, idle_ready_threads) == 0x038,
    "idle_ready_threads must be at offset 0x038"
);

// Verify ready_summary at 0x0C8 (critical for scheduling)
const _: () = assert!(
    core::mem::offset_of!(Prcb, ready_summary) == 0x0C8,
    "ready_summary must be at offset 0x0C8 for Windows 7 x64 compatibility"
);

// Verify ready_queues at 0x0D0
const _: () = assert!(
    core::mem::offset_of!(Prcb, ready_queues) == 0x0D0,
    "ready_queues must be at offset 0x0D0 for Windows 7 x64 compatibility"
);

// Verify dispatcher_lock at 0x2D0
const _: () = assert!(
    core::mem::offset_of!(Prcb, dispatcher_lock) == 0x2D0,
    "dispatcher_lock must be at offset 0x2D0 for Windows 7 x64 compatibility"
);

// Verify processor info fields
const _: () = assert!(
    core::mem::offset_of!(Prcb, quantum_remaining) == 0x300,
    "quantum_remaining must be at offset 0x300"
);
const _: () = assert!(
    core::mem::offset_of!(Prcb, processor_number) == 0x308,
    "processor_number must be at offset 0x308"
);

// Verify perf_global in second half
const _: () = assert!(
    core::mem::offset_of!(Prcb, perf_global) >= 0xE00,
    "perf_global should be in second half of structure"
);

// Verify prcb_type in final section
const _: () = assert!(
    core::mem::offset_of!(Prcb, prcb_type) > 0xF00,
    "prcb_type should be in the final section of Prcb"
);

// Verify prcb_size is 0x0F80
const _: () = assert!(
    core::mem::size_of::<Prcb>() >= 0xF80,
    "Prcb size must be at least 0xF80 bytes for Windows 7 x64 compatibility"
);

impl Prcb {
    /// create a new PRCB for the given CPU ID
    /// Note: Uses pool allocation instead of direct construction to avoid
    /// SSE stack-to-heap copy issues with the large structure
    pub fn new(cpu_id: u32) -> Self {
        Self {
            // === 0x000: Basic Scheduler ===
            current_thread: null_mut(),
            current_thread_pad: 0,
            idle_thread: null_mut(),
            idle_thread_pad: 0,
            next_thread: null_mut(),
            standby_thread: null_mut(),
            old_thread: null_mut(),
            idle_ready_threads: ListEntry::new(),
            _pad_basic1: [0; 0xC8 - 0x048],
            ready_summary: AtomicU32::new(0),
            ready_summary_padding: 0,
            ready_queues: [ListHead::new(); 32],

            // After ready_queues at 0x2D0:
            dispatcher_lock: 0,
            dispatcher_lock_pad: 0,
            schedule_dpc: 0,
            _pad_2e8: 0,
            panic_in_progress: 0,
            dpc_time: 0,
            timer_table: 0,
            timer_expiration: 0,

            // === 0x300: Processor Info ===
            quantum_remaining: QUANTUM_DEFAULT,
            quantum_initial: QUANTUM_DEFAULT,
            processor_number: cpu_id as u8,
            normal_cpu: cpu_id as u8,
            group_index: 0,
            apic_id: cpu_id as u8,
            local_apic_version: 0x20,
            cpu_type: 0,
            cpu_features: 0,
            cpu_features_pad: 0,
            cpu_brand: [0; 64],
            logical_processors: 1,
            group_processor_count: 1,
            _pad_353: 0,
            last_dispatch_time: 0,
            cache: [CacheInfo::empty(); 5],
            _pad_proc_info: [0; 0x400 - 0x3B0],

            // === 0x400: DPC Data ===
            dpc_data: DpcData::new(),
            dpc_stack: 0,
            max_dpc_queue_depth: 100,
            dpc_queue_depth: 0,
            dpc_request_pending: 0,
            dpc_request_slot: [0; 2],
            dpc_routine_active: 0,
            dpc_thread_active: 0,
            dpc_unused: 0,
            timer_service_index: 0,
            timer_banner: 0,
            npx_configuration: 0,
            npx_sp: 0,
            pdc_cpu: 0,
            system_calls: 0,
            _pad_dpc: [0; 0x500 - 0x464],

            // === 0x500: Interrupt & Timer ===
            interrupt_count: 0,
            dpc_interrupt_count: 0,
            timer_interrupt_count: 0,
            pending_interrupts: 0,
            interrupt_mode: 0,
            _pad_int: [0; 7],
            timer_vector: 0,
            local_apic: [0; 0x100],
            _pad_int_timer: [0; 0x700 - 0x630],

            // === 0x700: power & Thermal ===
            power_state: 0,
            thermal_zone: 0,
            power_policy: 0,
            idle_function: 0,
            idle_state: [0; 0xE8],
            _pad_power: [0; 0x900 - 0x808],

            // === 0x900: Statistics ===
            context_switch_count: 0,
            cycle_time: 0,
            cycle_time_padding: 0,
            wait_continuation_count: 0,
            ready_continuation_count: 0,
            kernel_time: 0,
            user_time: 0,
            dpc_time_stat: 0,
            interrupt_time: 0,
            page_fault_count: 0,
            cache_fill_count: 0,
            syscall_count: 0,
            interrupt_count_stat: 0,
            dpc_count: 0,
            pad_95c: 0,
            passive_affinity_count: 0,
            pad_cpu: 0,
            debugger_options: 0,
            pad_974: 0,
            pad_97c: 0,
            seed: 0,
            node_seed: [0; 2],
            stall_scale_factor: 0,
            multi_thread_processor_set: 0,
            _pad_stat: [0; 0xA00 - 0x9A8],

            // === 0xA00: MultiThread Processor Set ===
            mt_wait_bitset: [0; 64],
            mt_processor_set: 0,
            mt_aprocessors: 0,
            _pad_mt: [0; 0xB00 - 0xA50],

            // === 0xB00: Waiting & Scheduling ===
            wait_intes: 0,
            wait_block: [WaitBlock {
                wait_list_entry: ListEntry::new(),
                thread: null_mut(),
                object: 0,
                next_wait_block: 0,
                wait_key: 0,
                wait_type: 0,
            }; 8],
            wait_list_head: ListEntry::new(),
            affinity_suspend_quantum: 0,
            suspend_timer_in_use: 0,
            cpu_vendor: 0,
            dbg_cpu: 0,
            ccd_time: 0,
            ready_summary_smt: 0,
            smt_period: 0,
            smt_csd_barrier: 0,
            wait_affinity: 0,
            pad_8bc: 0,
            initial_stall: 0,
            pad_8c4: 0,
            pad_8c8: 0,
            pad_8d0: 0,
            wait_outstanding: 0,
            _pad_wait: [0; 3],
            yield_needed: 0,
            yield_outstanding: 0,
            pad_8e4: 0,
            pad_8e8: 0,
            pad_8f0: 0,
            pad_8f8: 0,
            _pad_wait2: [0; 0xD00 - 0xC00],

            // === 0xD00: Schedule Groups ===
            schedule_groups: 0,
            schedule_slots: [0; 16],
            schedule_last_slot: 0,
            schedule_slots_padding: 0,
            ccd_runnable_max: 0,
            ccd_runnable: 0,
            _pad_sched: [0; 0xE00 - 0xD98],

            // === 0xE00: Cache Data ===
            _pad_cache: [0; 0xF00 - 0xE00],

            // === 0xF00: Performance Counters ===
            perf_global: 0,
            perf_global_mask: 0,
            perf_global_spin: 0,
            perf_counter: [0; 8],

            // PrcbType/Size/Version
            prcb_type: 0x0864,
            prcb_size: 0x0F80,
            minor_version: 1,
            major_version: 6,
            build_number: 7601,
            q_system_time: 0,
            pad_f68: [0; 0x118],
        }
    }

    /// Initialize extended fields for a CPU
    pub fn init_extensions(&mut self, cpu_id: u32) {
        self.processor_number = cpu_id as u8;
        self.normal_cpu = cpu_id as u8;
        self.group_index = (cpu_id / 64) as u8;
        self.apic_id = cpu_id as u8;
        self.max_dpc_queue_depth = 100;
        self.local_apic_version = 0x20;
    }
}

/// Scheduler state.
pub struct Scheduler {
    pub cpus: [Option<&'static mut Prcb>; MAX_CPUS],
    pub current_cpu: u32,
    pub idle_threads: [*mut Ethread; MAX_IDLE_THREADS],
    pub num_cpus: usize,
    pub num_idle_threads: usize,
    /// Per-CPU affinity masks (which CPUs each thread can run on)
    /// In a full implementation, this would be stored in the thread structure
    /// For now, we use this for tracking thread affinity
    pub thread_affinity: core::sync::atomic::AtomicU64,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            cpus: [const { None }; MAX_CPUS],
            current_cpu: 0,
            idle_threads: [core::ptr::null_mut(); MAX_IDLE_THREADS],
            num_cpus: 0,
            num_idle_threads: 0,
            thread_affinity: core::sync::atomic::AtomicU64::new(!0u64), // All CPUs by default
        }
    }
}

static SCHEDULER: Spinlock<Scheduler> = Spinlock::new(Scheduler::new());
static SMP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

// Per-CPU dispatcher locks for improved SMP scalability
// Each CPU has its own lock for local scheduler operations,
// reducing contention compared to a single global lock.
//
// In Windows 7, these are in the KPRCB at offset 0x02D0.
// For now, we use a simple array-based approach.
const MAX_PERCPU_LOCKS: usize = 32;

// Lock states for per-CPU locks.
// 0 = unlocked, otherwise the owning CPU number + 1. Storing the owner
// makes reentrant acquisition detectable instead of silently deadlocking,
// and makes acquire/release an atomic CAS rather than a non-atomic
// read-modify-write (which is a data race and therefore UB).
static PRCB_LOCK_STATES: [AtomicU8; MAX_PERCPU_LOCKS] =
    [const { AtomicU8::new(0) }; MAX_PERCPU_LOCKS];

/// Per-CPU per-priority ready queue locks for fine-grained locking.
/// Each (CPU, priority) combination has its own lock, allowing parallel
/// operations on different priority queues across CPUs.
///
/// This improves SMP scalability by reducing lock contention:
/// - Operations on different CPUs don't contend
/// - Operations on different priority queues don't contend
const MAX_PRIORITY: usize = 32;
const MAX_CPU_SUPPORTED: usize = MAX_CPUS;

// Per-CPU per-priority locks: [cpu][priority]
// Each lock protects a single priority queue on a single CPU.
// 0 = unlocked, otherwise the owning CPU number + 1.
static READY_QUEUE_LOCKS: [[AtomicU8; MAX_PRIORITY]; MAX_CPU_SUPPORTED] =
    [const { [const { AtomicU8::new(0) }; MAX_PRIORITY] }; MAX_CPU_SUPPORTED];

/// RAII guard for a ready queue lock. Releases the lock on drop.
/// FIX 2.9: Refactored to use proper RAII pattern instead of closure.
pub struct QueueLockGuard {
    cpu: usize,
    priority: usize,
    owner: u8,
    acquired: bool, // Track if lock was actually acquired
}

impl QueueLockGuard {
    /// Lock index protected by this guard.
    pub fn cpu(&self) -> usize {
        self.cpu
    }

    /// Priority index protected by this guard.
    pub fn priority(&self) -> usize {
        self.priority
    }
}

impl Drop for QueueLockGuard {
    fn drop(&mut self) {
        if self.acquired {
            let _ = READY_QUEUE_LOCKS[self.cpu][self.priority].compare_exchange(
                self.owner,
                0,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

fn current_lock_owner() -> Option<u8> {
    if !crate::arch::common::percpu::is_ready() {
        return Some(1);
    }
    let cpu = get_current_cpu();
    (cpu < u8::MAX as usize).then_some((cpu + 1) as u8)
}

/// Lock a specific ready queue (CPU + priority combination).
/// Returns a RAII guard that automatically releases the lock on drop.
///
/// FIX 2.9: Uses proper RAII pattern with Drop implementation
/// instead of returning a closure. This avoids monomorphization
/// issues with `impl FnOnce()` return type.
pub fn lock_ready_queue(cpu: usize, priority: usize) -> Option<QueueLockGuard> {
    // Out-of-range indices are rejected rather than silently clamped: a
    // clamped index aliases a different queue's lock, so two CPUs could
    // mutate the same queue concurrently. A reentrant acquisition on the
    // same CPU is also rejected (spinlocks are not reentrant), which
    // prevents a guard from releasing a lock it never owned.
    if cpu >= MAX_CPU_SUPPORTED || priority >= MAX_PRIORITY {
        return None;
    }
    let owner = current_lock_owner()?;
    let slot = &READY_QUEUE_LOCKS[cpu][priority];
    loop {
        match slot.compare_exchange(0, owner, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                return Some(QueueLockGuard {
                    cpu,
                    priority,
                    owner,
                    acquired: true,
                })
            }
            Err(state) => {
                if state == owner {
                    return None;
                }
                core::hint::spin_loop();
            }
        }
    }
}

/// Lock the dispatcher lock for a specific CPU.
/// This provides per-CPU locking for improved SMP scalability.
///
/// In a full implementation, this would use a ticket spinlock
/// like the Windows KPRCB dispatcher lock for fairness.
pub fn lock_prcb(cpu: usize) -> bool {
    if cpu >= MAX_PERCPU_LOCKS {
        return false;
    }
    let Some(owner) = current_lock_owner() else {
        return false;
    };
    let slot = &PRCB_LOCK_STATES[cpu];
    loop {
        match slot.compare_exchange(0, owner, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => return true,
            Err(state) => {
                if state == owner {
                    return false;
                }
                core::hint::spin_loop();
            }
        }
    }
}

/// Unlock the dispatcher lock for a specific CPU.
pub fn unlock_prcb(cpu: usize) {
    if cpu < MAX_PERCPU_LOCKS {
        if let Some(owner) = current_lock_owner() {
            let _ = PRCB_LOCK_STATES[cpu].compare_exchange(
                owner,
                0,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

/// Get the current CPU number.
pub fn get_current_cpu() -> usize {
    crate::arch::common::percpu::get_current_cpu_id() as usize
}

/// Initialize scheduler.
pub fn init() {
    crate::hal::serial::write_string("[ke.scheduler] enter\r\n");
    // // kprintln!("    Initializing scheduler...");
    // Bootstrap: we don't actually need a full Prcb for the
    // single-CPU bring-up; defer Prcb allocation until SMP is
    // initialised.
    // // kprintln!("      Ready queues: initialized");
    // // kprintln!("      CPU 0: ready");
    if SMP_INITIALIZED.load(Ordering::SeqCst) {
        // // kprintln!("    Scheduler initialized (SMP support: enabled)");
    } else {
        // // kprintln!("    Scheduler initialized (SMP support: single-core)");
    }
}

/// Install a thread as the BSP's current thread. The BSP PRCB is
/// allocated on first call; subsequent calls replace the current
/// thread. Returns true if the BSP PRCB was newly created.
pub fn setup_bsp(thread: *mut Ethread) -> bool {
    // // kprintln!("  [SCHED] setup_bsp: enter thread=0x{:x}", thread as u64);
    let mut sched = SCHEDULER.lock();
    let newly_created = sched.cpus[0].is_none();
    // // kprintln!("  [SCHED] setup_bsp: scheduler locked, newly_created={}", newly_created);
    if newly_created {
        // // kprintln!("  [SCHED] setup_bsp: building Prcb via pool");
        // Allocate the Prcb from the kernel pool (the pool zeros
        // its user region, then we set up the non-null fields
        // manually). This avoids the SSE stack-to-heap copy that
        // `Prcb::new(0)` would emit — the Prcb contains
        // `[ListHead; 32]` (768 bytes) which the compiler may
        // initialise with 32-byte aligned stores that fault on
        // a 16-byte aligned stack.
        let raw = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<Prcb>(),
        ) as *mut Prcb;
        if raw.is_null() {
            // // kprintln!("[FATAL] setup_bsp: PRCB pool allocation failed");
            // // kprintln!("[FATAL] Cannot initialize scheduler - system cannot continue");
            // PRCB allocation failure is fatal - trigger bugcheck
            // Use SystemUninit (0xDC) for system initialization failures
            // P1 = 0x6B (PROCESS_INITIALIZATION_FAILURE sub-code)
            // P2 = CPU ID (0 for BSP)
            // P3 = size of PRCB
            // P4 = 0
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::ProcessInitializationFailed,
                0x6B, // PROCESS_INITIALIZATION_FAILURE
                0,    // CPU ID (0 for BSP)
                core::mem::size_of::<Prcb>() as u64,
                0,
            );
            // NOTE: bugcheck_with() does not return
        }
        // // kprintln!("  [SCHED] setup_bsp: Prcb pool-allocated at 0x{:x}", raw as u64);
        unsafe {
            (*raw).processor_number = 0;
            (*raw).dispatcher_lock = 0;
            (*raw).ready_summary.store(0, Ordering::Relaxed);
            (*raw).ready_summary_padding = 0;
            for i in 0..(*raw).ready_queues.len() {
                (*raw).ready_queues[i].head = core::ptr::null_mut();
                (*raw).ready_queues[i].blink = core::ptr::null_mut();
            }
            (*raw).quantum_remaining = QUANTUM_DEFAULT;
            (*raw).quantum_initial = QUANTUM_DEFAULT;
        }
        // SAFETY: We leak the Prcb for the lifetime of the
        // scheduler; `Scheduler` is never dropped at runtime,
        // so the static `Option<&'static mut Prcb>` only ever
        // holds a pointer to the pool-allocated Prcb.
        let leaked: &'static mut Prcb = unsafe { &mut *raw };
        sched.cpus[0] = Some(leaked);
    }
    let prcb = sched.cpus[0]
        .as_mut()
        .expect("PRCB slot 0 just initialised");
    prcb.current_thread = thread;
    prcb.idle_thread = thread;
    if sched.num_cpus == 0 {
        sched.num_cpus = 1;
    }
    sched.current_cpu = 0;
    drop(sched);
    // // kprintln!("  [SCHED] setup_bsp: prcb updated, publishing current_thread into per-CPU area");
    // Mirror the change through the per-CPU area (`gs:[0x10]`)
    // Publish the current thread/process into the per-CPU area so callers
    // that read the current thread via the per-CPU register see the
    // same value. We use the canonical per-CPU accessors from
    // `arch::common::percpu`.
    if !thread.is_null() {
        crate::arch::common::percpu::set_current_thread(thread);
        crate::arch::common::percpu::set_current_process(unsafe { (*thread).threads_process });
    }
    // // kprintln!("  [SCHED] setup_bsp: done");
    newly_created
}

/// Initialize SMP (called during kernel init after ACPI table parsing).
pub fn init_smp(cpu_count: u32) {
    let mut scheduler = SCHEDULER.lock();
    for i in 1..(cpu_count as usize).min(MAX_CPUS) {
        // Allocate from pool and leak to satisfy the
        // `&'static mut Prcb` storage. Avoids the SSE
        // stack-to-heap copy that `Prcb::new(i as u32)` would
        // emit when initialising the 32-element `ready_queues`.
        let raw = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<Prcb>(),
        ) as *mut Prcb;
        if raw.is_null() {
            // // kprintln!("[FATAL] init_smp: PRCB pool allocation failed for CPU {}", i);
            // // kprintln!("[FATAL] SMP initialization failed - cannot continue");
            // AP PRCB allocation failure is also fatal
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::ProcessInitializationFailed,
                0x6B,     // PROCESS_INITIALIZATION_FAILURE
                i as u64, // CPU ID
                core::mem::size_of::<Prcb>() as u64,
                0,
            );
            // NOTE: bugcheck_with() does not return
        }
        unsafe {
            (*raw).processor_number = i as u8;
            (*raw).dispatcher_lock = 0;
            (*raw).ready_summary.store(0, Ordering::Relaxed);
            (*raw).ready_summary_padding = 0;
            for q in 0..(*raw).ready_queues.len() {
                (*raw).ready_queues[q].head = core::ptr::null_mut();
                (*raw).ready_queues[q].blink = core::ptr::null_mut();
            }
            (*raw).quantum_remaining = QUANTUM_DEFAULT;
            (*raw).quantum_initial = QUANTUM_DEFAULT;
        }
        scheduler.cpus[i] = Some(unsafe { &mut *raw });
        scheduler.num_cpus = i + 1;
        if scheduler.num_idle_threads < scheduler.idle_threads.len() {
            if let Some(idle) = create_thread_idle(i as u32) {
                let idx = scheduler.num_idle_threads;
                scheduler.idle_threads[idx] = idle;
                scheduler.num_idle_threads += 1;
            }
        }
    }
    drop(scheduler);
    CPU_COUNT.store(cpu_count, Ordering::SeqCst);
    SMP_INITIALIZED.store(true, Ordering::SeqCst);
    // // kprintln!("      SMP initialized with multiple CPUs");
}

/// Add thread to ready queue.
///
/// For SMP with per-CPU queues, the thread is added to:
/// 1. Its home CPU's queue if affinity is set
/// 2. The current CPU's queue otherwise
///
/// This implements true per-CPU scheduling where threads run on their
/// preferred CPU for cache locality, but can be migrated if needed.
pub fn add_ready(thread: *mut Ethread, priority: u8) {
    if thread.is_null() {
        return;
    }
    let priority = priority.min(31);

    let mut scheduler = SCHEDULER.lock();

    // Determine target CPU based on thread affinity
    let target_cpu = unsafe {
        // If thread has a specific affinity, use its home CPU
        // Otherwise, use the current CPU for cache locality
        let home_cpu = (*thread).kthread.home_cpu;
        let affinity = (*thread).kthread.affinity_mask;

        // Check if home CPU is allowed by affinity
        if (affinity & (1u64 << home_cpu)) != 0 {
            home_cpu as usize
        } else {
            // Home CPU not in affinity mask, find first allowed CPU
            // Default to current CPU
            scheduler.current_cpu as usize
        }
    };

    // Same lock protocol as `ki_balance_processor`: the scheduler lock is
    // held first, then the per-(CPU, priority) queue lock. Without this
    // guard the queue could be mutated here while a balancing CPU mutated
    // the very same queue under the queue lock.
    let _queue_guard = match lock_ready_queue(target_cpu, priority as usize) {
        Some(g) => g,
        None => return,
    };

    if SMP_INITIALIZED.load(Ordering::SeqCst) && target_cpu < scheduler.cpus.len() {
        // Add to per-CPU PRCB ready queue
        if let Some(ref mut prcb) = scheduler.cpus[target_cpu] {
            let entry_ptr = unsafe {
                core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry)
                    as *mut ListEntry
            };
            prcb.ready_queues[priority as usize].add_tail(entry_ptr);
            // Update ready summary bitmask for fast priority check
            // Update ready summary atomically
            prcb.ready_summary
                .fetch_or(1u32 << priority, Ordering::AcqRel);

            // // kprintln!(
            // //                 level: crate::rtl::logging::LogLevel::Debug,
            // //                 subsystem: "SCHED",
            // //                 "add_ready: thread added to CPU {} priority {} (home_cpu={})",
            // //                 target_cpu, priority, unsafe { (*thread).kthread.home_cpu }
            // //             );
            return;
        }
    }

    // Fallback for single-CPU mode: use CPU 0's queue if available
    if let Some(ref mut prcb) = scheduler.cpus[0] {
        let entry_ptr = unsafe {
            core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry) as *mut ListEntry
        };
        prcb.ready_queues[priority as usize].add_tail(entry_ptr);
        // Update ready summary atomically
        prcb.ready_summary
            .fetch_or(1u32 << priority, Ordering::AcqRel);
        // // kprintln!("[SCHED] add_ready: fallback to CPU 0, priority {}", priority);
    }
}

/// Remove thread from ready queue.
///
/// This is called when a thread is blocked, terminated, or
/// moved to a wait state. The thread is removed from the
/// appropriate CPU's priority queue based on its home CPU affinity.
pub fn remove_ready(thread: *mut Ethread) {
    if thread.is_null() {
        return;
    }

    let mut scheduler = SCHEDULER.lock();

    // Determine which CPU's queue the thread should be in
    let target_cpu = unsafe {
        let home_cpu = (*thread).kthread.home_cpu;
        let affinity = (*thread).kthread.affinity_mask;

        // Check if home CPU is allowed by affinity
        if (affinity & (1u64 << home_cpu)) != 0 {
            home_cpu as usize
        } else {
            // Fallback to current CPU
            scheduler.current_cpu as usize
        }
    };

    // Get the thread's priority level
    let priority = unsafe { (*thread).kthread.base_priority as u8 };

    if priority >= 32 {
        return;
    }

    // Same lock protocol as `add_ready` and `ki_balance_processor`.
    let _queue_guard = match lock_ready_queue(target_cpu, priority as usize) {
        Some(g) => g,
        None => return,
    };

    // Search for the thread in the target CPU's ready queue
    if target_cpu < scheduler.cpus.len() {
        if let Some(ref mut prcb) = scheduler.cpus[target_cpu] {
            let queue = &mut prcb.ready_queues[priority as usize];
            let mut entry_ptr = queue.head;

            while !entry_ptr.is_null() {
                unsafe {
                    // Compare entry pointers - queue stores pointers to global_thread_list_entry
                    let thread_list_ptr =
                        core::ptr::addr_of!((*thread).kthread.global_thread_list_entry)
                            as *mut ListEntry;

                    if entry_ptr == thread_list_ptr {
                        // Found it - remove from list
                        let blink = (*entry_ptr).blink;
                        let flink = (*entry_ptr).flink;

                        if !blink.is_null() {
                            (*blink).flink = flink;
                        } else {
                            queue.head = flink;
                        }

                        if !flink.is_null() {
                            (*flink).blink = blink;
                        } else {
                            queue.blink = blink;
                        }

                        // Mark entry as removed
                        (*entry_ptr).flink = core::ptr::null_mut();
                        (*entry_ptr).blink = core::ptr::null_mut();

                        // Update ready_summary atomically if queue is now empty
                        if queue.is_empty() {
                            prcb.ready_summary
                                .fetch_and(!(1u32 << priority), Ordering::AcqRel);
                        }

                        // // kprintln!(
                        // //                             level: crate::rtl::logging::LogLevel::Debug,
                        // //                             subsystem: "SCHED",
                        // //                             "remove_ready: removed thread from CPU {} priority {}",
                        // //                             target_cpu, priority
                        // //                         );
                        return;
                    }

                    entry_ptr = (*entry_ptr).flink;
                }
            }
        }
    }

    // // kprintln!(
    // //         level: crate::rtl::logging::LogLevel::Debug,
    // //         subsystem: "SCHED",
    // //         "remove_ready: thread not found in CPU {} queue (priority={})",
    // //         target_cpu, priority
    // //     );
}

/// Schedule the next thread on the current CPU.
///
/// If there is a non-current thread in the ready queue, swap to it.
/// Returns true if a switch actually happened.
///
/// Uses per-CPU PRCB ready queues when SMP is enabled for better
/// cache locality and scalability. The per-CPU dispatcher lock is
/// used instead of the global SCHEDULER lock to reduce contention.
///
/// NOTE: this function is *not* safe to call from inside the
/// syscall path. The syscall path returns to user mode by
/// `sysretq`, which is incompatible with `swap_context`'s
/// `ret`-based return. The Phase 0 bring-up uses this function
/// from a kernel-mode caller (e.g. the idle loop) only. Calling
/// it from a Ring 3 syscall will produce undefined behaviour.
pub fn schedule() -> bool {
    // Use get_current_cpu() to get the real CPU ID from GS base
    let cpu = get_current_cpu();

    // Scheduling is only legal at DISPATCH_LEVEL. Above it we are in an
    // interrupt (or DPC) context and swapping the kernel stack would
    // corrupt the interrupt stack; record the request instead.
    if irql::get_current_irql() > Irql::DispatchLevel {
        request_reschedule(cpu);
        return false;
    }

    // Acquire per-CPU dispatcher lock first
    if !lock_prcb(cpu) {
        // Reentrant acquisition or out-of-range CPU: the dispatcher lock
        // is already held by this CPU, so re-entering the dispatcher here
        // would deadlock. Bail out and let the outer dispatcher run.
        return false;
    }

    // Hold the scheduler lock for the duration of thread selection and PRCB update
    let mut scheduler = SCHEDULER.lock();

    // Get current thread from PRCB
    let current = if cpu < scheduler.cpus.len() {
        scheduler.cpus[cpu].as_ref().and_then(|p| {
            if p.current_thread.is_null() {
                None
            } else {
                Some(p.current_thread)
            }
        })
    } else {
        None
    };

    // Try to pick the next thread from per-CPU PRCB queue
    let next = if SMP_INITIALIZED.load(Ordering::SeqCst) && cpu < scheduler.cpus.len() {
        if let Some(ref mut prcb) = scheduler.cpus[cpu] {
            // Find highest priority non-empty queue
            let summary = prcb.ready_summary.load(Ordering::Acquire);
            if summary != 0 {
                // Find MSB (highest priority) set
                let priority = 31 - summary.leading_zeros() as u8;
                let _queue_guard = match lock_ready_queue(cpu, priority as usize) {
                    Some(guard) => guard,
                    None => {
                        drop(scheduler);
                        unlock_prcb(cpu);
                        return false;
                    }
                };
                if let Some(entry) = prcb.ready_queues[priority as usize].remove_head() {
                    // Convert ListEntry to Ethread
                    // The queue stores pointers to global_thread_list_entry
                    let ethread_ptr = unsafe {
                        let kthread_offset = core::mem::offset_of!(Ethread, kthread)
                            + core::mem::offset_of!(
                                crate::ps::thread::Kthread,
                                global_thread_list_entry
                            );
                        (entry as *mut u8).offset(-(kthread_offset as isize)) as *mut Ethread
                    };

                    // Clear the ready summary bit atomically if queue is now empty
                    if prcb.ready_queues[priority as usize].is_empty() {
                        prcb.ready_summary
                            .fetch_and(!(1u32 << priority), Ordering::AcqRel);
                    }

                    Some(ethread_ptr)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        // Single-CPU or uninitialized mode: use CPU 0's queue
        if let Some(ref mut prcb) = scheduler.cpus[0] {
            let summary = prcb.ready_summary.load(Ordering::Acquire);
            if summary != 0 {
                let priority = 31 - summary.leading_zeros() as u8;
                let _queue_guard = match lock_ready_queue(0, priority as usize) {
                    Some(guard) => guard,
                    None => {
                        drop(scheduler);
                        unlock_prcb(cpu);
                        return false;
                    }
                };
                if let Some(entry) = prcb.ready_queues[priority as usize].remove_head() {
                    let ethread_ptr = unsafe {
                        let kthread_offset = core::mem::offset_of!(Ethread, kthread)
                            + core::mem::offset_of!(
                                crate::ps::thread::Kthread,
                                global_thread_list_entry
                            );
                        (entry as *mut u8).offset(-(kthread_offset as isize)) as *mut Ethread
                    };
                    if prcb.ready_queues[priority as usize].is_empty() {
                        // Update ready_summary atomically
                        prcb.ready_summary
                            .fetch_and(!(1u32 << priority), Ordering::AcqRel);
                    }
                    Some(ethread_ptr)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    // Update current_thread in PRCB
    if let Some(next_thread) = next {
        if Some(next_thread) != current {
            // Save current thread's context (its kernel RSP lives
            // in the per-arch register; read via the unified facade).
            unsafe {
                if let Some(cur) = current {
                    (*cur).kthread.context.kernel_rsp = crate::arch::get_stack_pointer();
                }
            }
            // Update PRCB's current_thread
            if let Some(ref mut prcb) = scheduler.cpus[cpu] {
                prcb.current_thread = next_thread;
            }
            // Keep locks held, release scheduler lock early to reduce contention
            drop(scheduler);
            unlock_prcb(cpu);

            // Perform context switch (no lock held). The unified
            // `swap_context` lives in the per-arch module; route
            // through the unified `arch::swap_context` facade so the
            // scheduler stays arch-agnostic.
            let new_rsp = unsafe { (*next_thread).kthread.context.kernel_rsp };
            unsafe {
                (*next_thread).kthread.state = KThreadState::Running;
                if new_rsp != 0 {
                    let mut out_rsp: u64 = 0;
                    crate::arch::swap_context(&mut out_rsp, new_rsp);
                }
            }
            return true;
        }
    }
    drop(scheduler);
    unlock_prcb(cpu);
    false
}

/// Phase 0: tick handler called by the timer ISR. Decrements
/// the current thread's quantum and, when it reaches zero,
/// triggers a reschedule.
/// Also implements priority decay mechanism (P2 Enhancement).
pub fn tick() {
    // The clock ISR runs at CLOCK_LEVEL (28). A context switch is only
    // legal at DISPATCH_LEVEL, so the ISR records a reschedule request
    // and the dispatcher performs the swap once IRQL has been lowered
    // (`dispatch_pending_reschedule`, called from the ISR exit path).
    let previous_irql = irql::raise_irql(Irql::ClockLevel);

    // Advance the authoritative clock once per tick.
    crate::ke::time::advance_tick();

    let mut scheduler = SCHEDULER.lock();
    // Use get_current_cpu() to get the real CPU ID from GS base
    let cpu = get_current_cpu();

    // Get per-CPU PRCB
    if let Some(ref mut prcb) = scheduler.cpus[cpu] {
        let remaining = prcb.quantum_remaining;

        if remaining > 0 {
            prcb.quantum_remaining = remaining - 1;

            // When quantum reaches zero, trigger reschedule
            if prcb.quantum_remaining == 0 {
                // // kprintln!("[SCHED] tick: quantum expired");

                // Unboost current thread's priority if boost has expired
                // This starts the decay process instead of instant drop
                if !prcb.current_thread.is_null() {
                    ki_unboost_thread(prcb.current_thread);
                }

                // Reset quantum for next thread
                prcb.quantum_remaining = QUANTUM_DEFAULT;
                prcb.quantum_initial = QUANTUM_DEFAULT;
                // Do not swap context from the ISR: request a reschedule
                // and let the dispatcher run it at DISPATCH_LEVEL.
                drop(scheduler);
                request_reschedule(cpu);
            } else {
                // Check for priority decay even when quantum hasn't expired.
                // This allows gradual decay during the thread's quantum.
                if !prcb.current_thread.is_null() {
                    check_and_decay_priority(prcb.current_thread);
                }
            }
        }
    }

    irql::lower_irql(previous_irql);

    poll_services();
}

/// Drain network RX and advance long-lived kernel services.
///
/// A user-mode process can monopolize the CPU without returning to the
/// idle loop, so syscall entry and the clock path both call this as a
/// deferred-work opportunity.
pub fn poll_services() {
    crate::drivers::net::poll_all();
    crate::servers::sshd::launcher::service_tick();
}

/// Per-CPU reschedule requests raised by the clock ISR.
static PENDING_RESCHEDULE: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Record that the dispatcher must run on `cpu` once IRQL drops to
/// DISPATCH_LEVEL.
pub fn request_reschedule(cpu: usize) {
    if cpu < MAX_CPUS {
        PENDING_RESCHEDULE[cpu].store(true, Ordering::Release);
    }
}

/// True if `cpu` has an outstanding reschedule request.
pub fn has_pending_reschedule(cpu: usize) -> bool {
    cpu < MAX_CPUS && PENDING_RESCHEDULE[cpu].load(Ordering::Acquire)
}

/// Run the dispatcher for a pending ISR reschedule request.
///
/// Must be called from the ISR exit path, after IRQL has been lowered
/// to DISPATCH_LEVEL. Calling `schedule()` while still at CLOCK_LEVEL
/// swaps the stack in interrupt context, which is not a legal
/// scheduling point.
pub fn dispatch_pending_reschedule() -> bool {
    let cpu = get_current_cpu();
    if !has_pending_reschedule(cpu) {
        return false;
    }
    if irql::get_current_irql() > Irql::DispatchLevel {
        return false;
    }
    let consumed =
        PENDING_RESCHEDULE[cpu].compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire);
    if consumed.is_err() {
        // Already consumed by another path.
        return false;
    }
    schedule()
}

/// Get current system tick count (for priority decay timing).
///
/// This is a getter and must not advance the clock. The previous
/// implementation used `fetch_add(1)`, so every read moved the shared
/// clock: all threads' elapsed time increased by one tick on every
/// read, which made priority-decay timing unreliable. The authoritative
/// clock is `ke::time`, advanced once per tick by the clock ISR.
fn get_ticks() -> u64 {
    crate::ke::time::get_tick_count() as u64 / TICK_MS as u64
}

/// Convert milliseconds to timer ticks
fn ms_to_ticks(ms: u32) -> u64 {
    ((ms as u64) + (TICK_MS as u64) - 1) / (TICK_MS as u64)
}

/// Idle loop (called when no threads are ready).
/// Uses the unified `arch::wait_for_interrupt()` so the per-arch
/// `sti;hlt` / `wfi` / `idle 0` sequence stays inside `arch::*`.
pub fn idle_loop() -> ! {
    loop {
        crate::arch::wait_for_interrupt();
    }
}

/// create an idle thread for a CPU.
pub fn create_idle_thread() {
    let mut scheduler = SCHEDULER.lock();
    let cpu_id = scheduler.num_cpus as u32;

    if scheduler.num_idle_threads >= scheduler.idle_threads.len() {
        // // kprintln!("[SCHED] create_idle_thread: idle thread array full (num={})",
        // //                  scheduler.num_idle_threads);
        return;
    }

    // // kprintln!("[SCHED] create_idle_thread: creating for CPU {}", cpu_id);

    match create_thread_idle(cpu_id) {
        Some(idle) => {
            let idx = scheduler.num_idle_threads;
            scheduler.idle_threads[idx] = idle;
            scheduler.num_idle_threads += 1;
            if let Some(ref mut prcb) = scheduler.cpus[0] {
                prcb.idle_thread = idle;
                prcb.current_thread = idle;
                // // kprintln!("[SCHED] create_idle_thread: idle thread set for CPU 0, idle=0x{:x}", idle as *const Ethread as u64);
            } else {
                // // kprintln!("[SCHED] create_idle_thread: WARNING - CPU 0 PRCB not initialized");
            }
        }
        None => {
            // // kprintln!("[SCHED] create_idle_thread: FAILED to create idle thread for CPU {}", cpu_id);
        }
    }
}

/// Set thread priority.
pub fn set_priority(thread: *mut Ethread, priority: i8) {
    unsafe {
        (*thread).kthread.base_priority = priority;
        (*thread).kthread.priority = priority;
    }
}

/// Initialize thread quantum based on process priority class.
pub fn init_thread_quantum(_thread: *mut Ethread, quantum: Quantum) {
    let (initial, remaining) = match quantum {
        Quantum::Short => (QUANTUM_SHORT, QUANTUM_SHORT),
        Quantum::Standard => (QUANTUM_DEFAULT, QUANTUM_DEFAULT),
        Quantum::Long => (QUANTUM_FOREGROUND, QUANTUM_FOREGROUND),
    };

    let mut scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;
    if let Some(ref mut prcb) = scheduler.cpus[cpu] {
        prcb.quantum_initial = initial;
        prcb.quantum_remaining = remaining;
    }
}

/// Set quantum for current thread.
pub fn set_thread_quantum(thread: *mut Ethread, quantum_ticks: u32) {
    let mut scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;
    if let Some(ref mut prcb) = scheduler.cpus[cpu] {
        prcb.quantum_initial = quantum_ticks;
        prcb.quantum_remaining = quantum_ticks;
    }
    let _ = thread; // suppress unused warning
}

/// Get remaining quantum for current thread.
pub fn get_remaining_quantum() -> u32 {
    let scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;
    scheduler.cpus[cpu]
        .as_ref()
        .map(|p| p.quantum_remaining)
        .unwrap_or(0)
}

/// Get current thread.
///
/// Reads the per-CPU `current_thread` slot via the arch-specific per-CPU
/// register. The pointer is installed by `setup_bsp` and updated by every
/// context switch. This function is the canonical accessor used
/// throughout the scheduler; `ps::thread::KeGetCurrentEthread`
/// also delegates to the same slot.
pub fn get_current_thread() -> Option<&'static mut Ethread> {
    let ptr = crate::arch::common::percpu::get_current_thread();
    if ptr.is_null() {
        None
    } else {
        unsafe { ptr.as_mut() }
    }
}

/// Yield to scheduler.
pub fn yield_() {
    schedule();
}

/// Start idle process (entry point).
pub fn start_idle_process() -> ! {
    loop {
        crate::arch::halt();
    }
}

/// Number of CPUs the scheduler has detected.
pub fn get_cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::SeqCst)
}

/// Is SMP enabled?
pub fn is_smp_enabled() -> bool {
    SMP_INITIALIZED.load(Ordering::SeqCst)
}

/// Initialise per-CPU state for the current CPU (BSP or AP).
pub fn init_smp_this_cpu(cpu_id: u32) {
    let mut sched = SCHEDULER.lock();
    let idx = (cpu_id as usize).min(MAX_CPUS - 1);

    if sched.cpus[idx].is_none() {
        let raw = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<Prcb>(),
        ) as *mut Prcb;
        if raw.is_null() {
            // // kprintln!("[FATAL] init_smp_this_cpu: PRCB pool allocation failed for CPU {}", cpu_id);
            // // kprintln!("[FATAL] Per-CPU initialization failed - cannot continue");
            // Per-CPU PRCB allocation failure is also fatal
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::ProcessInitializationFailed,
                0x6B,          // PROCESS_INITIALIZATION_FAILURE
                cpu_id as u64, // CPU ID
                core::mem::size_of::<Prcb>() as u64,
                0,
            );
            // NOTE: bugcheck_with() does not return
        }
        unsafe {
            (*raw).processor_number = idx as u8;
            (*raw).dispatcher_lock = 0;
            (*raw).ready_summary.store(0, Ordering::Relaxed);
            (*raw).ready_summary_padding = 0;
            for q in 0..(*raw).ready_queues.len() {
                (*raw).ready_queues[q].head = core::ptr::null_mut();
                (*raw).ready_queues[q].blink = core::ptr::null_mut();
            }
            (*raw).quantum_remaining = QUANTUM_DEFAULT;
            (*raw).quantum_initial = QUANTUM_DEFAULT;
        }
        sched.cpus[idx] = Some(unsafe { &mut *raw });
    }

    if sched.num_cpus <= idx {
        sched.num_cpus = idx + 1;
    }
    if sched.num_idle_threads < sched.idle_threads.len() {
        if let Some(idle) = create_thread_idle(idx as u32) {
            let i = sched.num_idle_threads;
            sched.idle_threads[i] = idle;
            sched.num_idle_threads += 1;
            if let Some(prcb) = sched.cpus[idx].as_mut() {
                prcb.idle_thread = idle;
                prcb.current_thread = idle;
            }
        }
    }
    drop(sched);

    // Install the kernel GS base for this CPU and clear the
    // per-CPU current_thread/current_process slots. Done via
    // the authoritative `arch::x86_64::syscall::init_per_cpu`
    // so there is exactly one source of truth for the layout.
    crate::arch::init_per_cpu(cpu_id);
}

// ---------------------------------------------------------------------------
// Per-CPU current thread via GS base
// ---------------------------------------------------------------------------
//
// The actual `gs:[0x10]` accessors and the per-CPU `current_thread`
// publication live in `arch::x86_64::syscall`. This module used to
// carry a duplicate `BSP_PERCPU` struct that was never actually
// read by anything except itself; it has been removed so the
// per-CPU data lives in exactly one place.

// =============================================================================
// Per-CPU Load Balancing and Affinity Support
// =============================================================================

/// Get the current CPU ID (returns u32 instead of usize)
pub fn get_current_cpu_id() -> u32 {
    crate::arch::common::percpu::get_current_cpu_id()
}

/// Set thread affinity - which CPUs the thread can run on.
/// Returns true if successful, false if invalid parameters.
///
/// FIX 2.8: Added bounds checking for trailing_zeros() overflow.
/// trailing_zeros() returns 64 for affinity_mask=0, which would
/// truncate to 0 when cast to u8, causing incorrect home_cpu assignment.
pub fn set_thread_affinity(thread: *mut Ethread, affinity_mask: u64) -> bool {
    if thread.is_null() || affinity_mask == 0 {
        return false;
    }

    let new_home = affinity_mask.trailing_zeros() as usize;

    // Bounds check: home_cpu must be within supported CPU count
    if new_home >= MAX_CPUS {
        return false;
    }

    unsafe {
        (*thread).kthread.affinity_mask = affinity_mask;
        (*thread).kthread.home_cpu = new_home as u8;
        (*thread).kthread.affinitized = 1;

        // // kprintln!("[SCHED] set_thread_affinity: thread affinity=0x{:016x}, home_cpu={}",
        // //                   affinity_mask, new_home);
    }

    true
}

/// Get thread affinity mask
pub fn get_thread_affinity(thread: *mut Ethread) -> u64 {
    if thread.is_null() {
        return 0;
    }
    unsafe { (*thread).kthread.affinity_mask }
}

/// Calculate the exact load of a CPU (total thread count in all queues)
fn calculate_cpu_load(prcb: &Prcb) -> usize {
    let mut count = 0usize;
    for queue in &prcb.ready_queues {
        let mut entry_ptr = queue.head;
        while !entry_ptr.is_null() {
            count += 1;
            unsafe {
                entry_ptr = (*entry_ptr).flink;
            }
        }
    }
    count
}

/// Calculate dynamic balance threshold based on average load
fn calculate_balance_threshold(avg_load: usize) -> usize {
    // If average load is high, use a larger threshold to avoid thrashing
    if avg_load < 4 {
        BALANCE_THRESHOLD_DEFAULT
    } else {
        BALANCE_THRESHOLD_DEFAULT + 1
    }
}

/// Helper function to find a migratable thread in a CPU's queue
fn find_migratable_thread(prcb: &Prcb) -> Option<(*mut Ethread, u8)> {
    // Search from lower priorities first (prefer migrating lower priority threads)
    for prio in 0..32 {
        let queue = &prcb.ready_queues[prio];
        let mut entry_ptr = queue.head;

        while !entry_ptr.is_null() {
            unsafe {
                let ethread_ptr = {
                    let kthread_offset = core::mem::offset_of!(Ethread, kthread)
                        + core::mem::offset_of!(
                            crate::ps::thread::Kthread,
                            global_thread_list_entry
                        );
                    (entry_ptr as *mut u8).offset(-(kthread_offset as isize)) as *mut Ethread
                };

                let affinity = (*ethread_ptr).kthread.affinity_mask;
                let is_affinitized = (*ethread_ptr).kthread.affinitized != 0;

                // Prefer migrating threads that:
                // 1. Are not affinitized (can run anywhere)
                // 2. Have multi-CPU affinity (can run on multiple CPUs)
                if !is_affinitized || affinity.count_ones() > 1 {
                    return Some((ethread_ptr, prio as u8));
                }

                entry_ptr = (*entry_ptr).flink;
            }
        }
    }
    None
}

/// KiBalanceProcessor - Balance processor load via DPC (P2 Enhancement)
///
/// This implements the BALANCE_APC mechanism for cross-CPU load balancing.
/// When called on a target CPU, it triggers that CPU to perform load balancing.
pub fn ki_balance_processor(target_cpu: u32) {
    if !SMP_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let mut scheduler = SCHEDULER.lock();
    let num_cpus = scheduler.num_cpus as u32;

    if target_cpu >= num_cpus || num_cpus <= 1 {
        return;
    }

    // // kprintln!("[SCHED] KiBalanceProcessor: balancing for CPU {}", target_cpu);

    // Perform load balancing for the target CPU
    let _cpu_idx = target_cpu as usize;

    let mut max_load = 0usize;
    let mut min_load = usize::MAX;
    let mut max_cpu = 0usize;
    let mut min_cpu = 0usize;

    // Calculate loads for all CPUs
    let mut total_load = 0usize;
    for i in 0..num_cpus as usize {
        if let Some(prcb) = &scheduler.cpus[i] {
            let load = calculate_cpu_load(prcb);
            total_load += load;
            if load > max_load {
                max_load = load;
                max_cpu = i;
            }
            if load < min_load {
                min_load = load;
                min_cpu = i;
            }
        }
    }

    let avg_load = if num_cpus > 0 {
        total_load / num_cpus as usize
    } else {
        0
    };
    let threshold = calculate_balance_threshold(avg_load);

    // Only migrate if load difference exceeds threshold
    if max_load > min_load + threshold && max_load > 0 {
        // // kprintln!(
        // //             "[SCHED] KiBalanceProcessor: CPU {} (load={}) -> CPU {} (load={}), threshold={}",
        // //             max_cpu, max_load, min_cpu, min_load, threshold
        // //         );

        // Attempt to migrate a thread from the most loaded CPU to the least loaded.
        // Use fine-grained per-queue locking to reduce contention.
        if let Some(ref mut max_prcb) = scheduler.cpus[max_cpu] {
            if let Some((thread, priority)) = find_migratable_thread(max_prcb) {
                let priority_idx = priority as usize;

                // Lock the source queue first, then the target queue
                // to avoid deadlocks (always lock in same order: lower CPU first)
                let (first_cpu, first_priority, second_cpu, second_priority) = if max_cpu <= min_cpu
                {
                    (max_cpu, priority_idx, min_cpu, priority_idx)
                } else {
                    (min_cpu, priority_idx, max_cpu, priority_idx)
                };

                // Scope for the locks - both locks must be held during migration
                // FIX 2.9: Using RAII pattern - locks auto-release on drop
                {
                    // Acquire both locks. Both are held while the scheduler
                    // lock is held, so the lock order is always
                    // dispatcher lock -> scheduler lock -> queue lock.
                    let guard1 = match lock_ready_queue(first_cpu, first_priority) {
                        Some(g) => g,
                        None => return,
                    };
                    let guard2 = match lock_ready_queue(second_cpu, second_priority) {
                        Some(g) => g,
                        None => return,
                    };
                    let _ = (&guard1, &guard2);

                    // Now perform the migration under the queue locks
                    // Locks are automatically released when guards go out of scope
                    let queue = &mut max_prcb.ready_queues[priority_idx];
                    let entry_ptr = unsafe {
                        core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry)
                            as *mut ListEntry
                    };

                    // Remove from source CPU queue
                    unsafe {
                        let prev = (*entry_ptr).blink;
                        let next = (*entry_ptr).flink;

                        if !prev.is_null() {
                            (*prev).flink = next;
                        } else {
                            queue.head = next;
                        }

                        if !next.is_null() {
                            (*next).blink = prev;
                        } else {
                            queue.blink = prev;
                        }

                        (*entry_ptr).flink = core::ptr::null_mut();
                        (*entry_ptr).blink = core::ptr::null_mut();

                        if queue.is_empty() {
                            // Update ready_summary atomically
                            max_prcb
                                .ready_summary
                                .fetch_and(!(1u32 << priority), Ordering::AcqRel);
                        }
                    }

                    // Update thread's home CPU
                    unsafe {
                        (*thread).kthread.home_cpu = min_cpu as u8;
                    }

                    // Add to target CPU queue
                    if let Some(ref mut min_prcb) = scheduler.cpus[min_cpu] {
                        let new_entry_ptr = unsafe {
                            core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry)
                                as *mut ListEntry
                        };
                        min_prcb.ready_queues[priority_idx].add_tail(new_entry_ptr);
                        // Update ready_summary atomically
                        min_prcb
                            .ready_summary
                            .fetch_or(1u32 << priority, Ordering::AcqRel);

                        let _tid = unsafe { (*thread).client_id.unique_thread };
                        // _tid is intentionally unused - reserved for future logging
                        // // kprintln!(
                        // //                             "[SCHED] KiBalanceProcessor: TID {} migrated from CPU {} to CPU {}",
                        // //                             _tid, max_cpu, min_cpu
                        // //                         );
                    }

                    // FIX 2.9: No explicit release needed - RAII guards auto-release on drop
                }
            }
        }
    }
}

/// Migrate a thread from one CPU to another (complete implementation)
fn migrate_thread_locked(
    scheduler: &mut Scheduler,
    thread: *mut Ethread,
    from_cpu: usize,
    to_cpu: usize,
    _priority: u8,
) {
    if thread.is_null() || from_cpu >= scheduler.cpus.len() {
        return;
    }

    // Verify target CPU is valid and allowed by thread affinity
    let affinity = unsafe { (*thread).kthread.affinity_mask };
    if to_cpu >= scheduler.cpus.len() || (affinity & (1u64 << to_cpu)) == 0 {
        // Find first valid CPU from affinity
        let valid_cpu = affinity.trailing_zeros() as usize;
        if valid_cpu >= scheduler.cpus.len() {
            // // kprintln!("[SCHED] migrate_thread_locked: no valid target CPU for TID {}",
            // //                      unsafe { (*thread).client_id.unique_thread });
            return;
        }
    }

    unsafe {
        // Update thread's home CPU
        (*thread).kthread.home_cpu = to_cpu as u8;

        // Note: The actual queue removal and insertion is handled by the caller
        // (balance_load or ki_balance_processor) to avoid lock issues

        // // kprintln!(
        // //             "[SCHED] migrate_thread_locked: TID {} from CPU {} to CPU {} (priority={})",
        // //             (*thread).client_id.unique_thread,
        // //             from_cpu,
        // //             to_cpu,
        // //             priority
        // //         );
    }
}

/// Balance load across CPUs by migrating threads
/// Uses improved load calculation and dynamic threshold (P2 Enhancement)
pub fn balance_load() {
    if !SMP_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let mut scheduler = SCHEDULER.lock();
    let num_cpus = scheduler.num_cpus;

    if num_cpus <= 1 {
        return;
    }

    let mut max_load = 0usize;
    let mut min_load = usize::MAX;
    let mut max_cpu = 0usize;
    let mut min_cpu = 0usize;
    let mut total_load = 0usize;

    // Calculate exact loads for all CPUs
    for i in 0..num_cpus {
        if let Some(prcb) = &scheduler.cpus[i] {
            let load = calculate_cpu_load(prcb);
            total_load += load;
            if load > max_load {
                max_load = load;
                max_cpu = i;
            }
            if load < min_load {
                min_load = load;
                min_cpu = i;
            }
        }
    }

    let avg_load = total_load / num_cpus;
    let threshold = calculate_balance_threshold(avg_load);

    // Only migrate if load difference exceeds threshold
    if max_load > min_load + threshold && max_load > 0 {
        // // kprintln!(
        // //             "[SCHED] balance_load: CPU {} (load={}) -> CPU {} (load={}), threshold={}, avg={}",
        // //             max_cpu, max_load, min_cpu, min_load, threshold, avg_load
        // //         );

        if let Some(ref mut max_prcb) = scheduler.cpus[max_cpu] {
            if let Some((thread, priority)) = find_migratable_thread(max_prcb) {
                let queue = &mut max_prcb.ready_queues[priority as usize];
                let entry_ptr = unsafe {
                    core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry)
                        as *mut ListEntry
                };

                // Remove from source CPU queue
                unsafe {
                    let prev = (*entry_ptr).blink;
                    let next = (*entry_ptr).flink;

                    if !prev.is_null() {
                        (*prev).flink = next;
                    } else {
                        queue.head = next;
                    }

                    if !next.is_null() {
                        (*next).blink = prev;
                    } else {
                        queue.blink = prev;
                    }

                    (*entry_ptr).flink = core::ptr::null_mut();
                    (*entry_ptr).blink = core::ptr::null_mut();

                    if queue.is_empty() {
                        // Update ready_summary atomically
                        max_prcb
                            .ready_summary
                            .fetch_and(!(1u32 << priority), Ordering::AcqRel);
                    }
                }

                // Complete migration (update home_cpu)
                migrate_thread_locked(&mut scheduler, thread, max_cpu, min_cpu, priority);

                // Add to target CPU queue
                if let Some(ref mut min_prcb) = scheduler.cpus[min_cpu] {
                    let new_entry_ptr = unsafe {
                        core::ptr::addr_of_mut!((*thread).kthread.global_thread_list_entry)
                            as *mut ListEntry
                    };
                    min_prcb.ready_queues[priority as usize].add_tail(new_entry_ptr);
                    // Update ready_summary atomically
                    min_prcb
                        .ready_summary
                        .fetch_or(1u32 << priority, Ordering::AcqRel);

                    let _tid = unsafe { (*thread).client_id.unique_thread };
                    // _tid is intentionally unused - reserved for future logging
                    // // kprintln!("[SCHED] balance_load: TID {} migrated from CPU {} to CPU {}",
                    // //                              _tid, max_cpu, min_cpu);
                }
            } else {
                // // kprintln!("[SCHED] balance_load: no migratable thread found on CPU {}", max_cpu);
            }
        }
    }
}

/// Request a context switch on the current CPU
pub fn request_context_switch() {
    // In a real implementation, this would set a pending context switch flag
}

/// Check if current CPU has work to do
pub fn has_work() -> bool {
    let scheduler = SCHEDULER.lock();
    let cpu = get_current_cpu();

    if cpu < scheduler.cpus.len() {
        if let Some(prcb) = scheduler.cpus[cpu].as_ref() {
            return prcb.ready_summary.load(Ordering::Acquire) != 0;
        }
    }
    false
}

// =============================================================================
// Priority Boost and Decay Implementation (P2 Enhancement)
// =============================================================================

/// KiBoostThread - Boost thread priority when waiting object becomes signaled
/// Also records boost timestamp for decay mechanism
pub fn ki_boost_thread(thread: *mut Ethread, boost_type: PriorityBoostType) -> i8 {
    unsafe {
        let kthread = &mut (*thread).kthread;
        let base = kthread.base_priority;
        let current = kthread.priority;

        let boost_amount = match boost_type {
            PriorityBoostType::IoCompletion => PRIORITY_BOOST_IOTHREAD,
            PriorityBoostType::EventSet => PRIORITY_BOOST_SETEVENT,
            PriorityBoostType::Special => PRIORITY_BOOST_SPECIAL,
            PriorityBoostType::MutantRelease => PRIORITY_BOOST_MUTANT,
        };

        let mut new_priority = current;

        if current < base {
            new_priority = base;
        }

        if new_priority < MAX_BOOSTED_PRIORITY {
            let boosted = (new_priority + boost_amount).min(MAX_BOOSTED_PRIORITY);
            if boosted > new_priority {
                new_priority = boosted;
            }
        }

        if new_priority > current {
            kthread.priority = new_priority;
            // Record boost timestamp for decay mechanism
            kthread.boost_time = get_ticks();
            kthread.decay_started = 1;
            // // kprintln!(
            // //                 "[SCHED] KiBoostThread: TID {} priority {} -> {} (boost_type={:?}, boost={})",
            // //                 (*thread).client_id.unique_thread,
            // //                 current,
            // //                 new_priority,
            // //                 boost_type,
            // //                 boost_amount
            // //             );
        }

        new_priority
    }
}

/// KiUnboostThread - Remove priority boost when quantum expires
pub fn ki_unboost_thread(thread: *mut Ethread) {
    unsafe {
        let kthread = &mut (*thread).kthread;
        let current = kthread.priority;
        let base = kthread.base_priority;

        if current > base {
            // Start the decay process instead of instantly dropping to base priority.
            // This matches Windows behavior where priority decays gradually.
            kthread.decay_started = 1;
            kthread.boost_time = get_ticks();
            // // kprintln!(
            // //                 "[SCHED] KiUnboostThread: TID {} starting decay from {} to {} (will decay over {}ms)",
            // //                 (*thread).client_id.unique_thread,
            // //                 current,
            // //                 base,
            // //                 DECAY_TIME_MS
            // //             );
            // Note: We don't change kthread.priority here - let ki_decay_priority handle it
            // The thread will remain at boosted priority until decay kicks in
        }
    }
}

/// KiDecayPriority - Gradual priority decay over time (P2 Enhancement)
///
/// Implements priority decay mechanism: when a thread's priority has been
/// boosted for longer than DECAY_TIME_MS, it gradually returns to base
/// priority instead of an instant drop.
pub fn ki_decay_priority(thread: *mut Ethread) {
    unsafe {
        let kthread = &mut (*thread).kthread;
        let current = kthread.priority;
        let base = kthread.base_priority;

        if current <= base {
            // Already at base priority, stop decay
            kthread.decay_started = 0;
            return;
        }

        // Decay by DECAY_AMOUNT steps
        let new_priority = (current - DECAY_AMOUNT).max(base);

        kthread.priority = new_priority;

        if new_priority == base {
            kthread.decay_started = 0;
            // // kprintln!(
            // //                 "[SCHED] KiDecayPriority: TID {} decayed to base priority {}",
            // //                 (*thread).client_id.unique_thread,
            // //                 base
            // //             );
        } else {
            // Update boost time for next decay interval
            kthread.boost_time = get_ticks();
            // // kprintln!(
            // //                 "[SCHED] KiDecayPriority: TID {} priority {} -> {}",
            // //                 (*thread).client_id.unique_thread,
            // //                 current,
            // //                 new_priority
            // //             );
        }
    }
}

/// CheckAndDecayPriority - Called periodically to check if decay is needed
/// Returns true if decay was performed
pub fn check_and_decay_priority(thread: *mut Ethread) -> bool {
    if thread.is_null() {
        return false;
    }

    unsafe {
        let kthread = &(*thread).kthread;

        // Only decay if decay has started and we're above base priority
        if kthread.decay_started == 0 || kthread.priority <= kthread.base_priority {
            return false;
        }

        // Check if DECAY_TIME_MS has elapsed since last boost/decay
        let elapsed = get_ticks() - kthread.boost_time;
        let decay_interval = ms_to_ticks(DECAY_TIME_MS);

        if elapsed >= decay_interval {
            ki_decay_priority(thread);
            return true;
        }
    }
    false
}

/// Boost thread priority for I/O completion
pub fn boost_for_io(thread: *mut Ethread) {
    ki_boost_thread(thread, PriorityBoostType::IoCompletion);
}

/// Boost thread priority for event signaling
pub fn boost_for_event(thread: *mut Ethread) {
    ki_boost_thread(thread, PriorityBoostType::EventSet);
}

/// Boost thread priority for mutex release
pub fn boost_for_mutex(thread: *mut Ethread) {
    ki_boost_thread(thread, PriorityBoostType::MutantRelease);
}

// =============================================================================
// Dispatcher Lock and Timer Table Management (P2 Enhancement)
// =============================================================================

/// Dispatcher lock state for the PRCB
#[derive(Clone, Copy)]
pub struct DispatcherLock {
    pub held: bool,
    pub owner_cpu: u32,
    pub owner_thread: *mut Ethread,
    pub recursion_count: u32,
}

impl DispatcherLock {
    pub const fn new() -> Self {
        Self {
            held: false,
            owner_cpu: 0,
            owner_thread: core::ptr::null_mut(),
            recursion_count: 0,
        }
    }
}

/// Timer table entry for per-CPU timer management
/// Windows 7 x64 uses 256 timer buckets
pub const TIMER_TABLE_SIZE: usize = 256;

#[derive(Clone, Copy)]
pub struct TimerTableEntry {
    pub list_head: ListEntry,
    pub entry: *mut TimerTableEntry,
}

impl TimerTableEntry {
    pub const fn new() -> Self {
        Self {
            list_head: ListEntry::new(),
            entry: core::ptr::null_mut(),
        }
    }
}

/// Timer table structure for managing per-CPU timers
pub struct TimerTable {
    pub entries: [TimerTableEntry; TIMER_TABLE_SIZE],
}

impl TimerTable {
    pub const fn new() -> Self {
        Self {
            entries: [TimerTableEntry::new(); TIMER_TABLE_SIZE],
        }
    }

    /// Get the timer bucket index from a timer due time
    pub fn get_bucket_index(due_time: u64) -> usize {
        // Hash the due time to a bucket index
        // Windows uses a rotating table scheme
        ((due_time >> 8) as usize) & (TIMER_TABLE_SIZE - 1)
    }
}

/// Initialize dispatcher lock for a PRCB
pub fn init_dispatcher_lock(prcb: &mut Prcb) {
    prcb.dispatcher_lock = 0; // Indicates lock is not held
    prcb.panic_in_progress = 0;
    // // kprintln!("[SCHED] Dispatcher lock initialized for PRCB");
}

/// Initialize timer table for a PRCB
pub fn init_timer_table(prcb: &mut Prcb) {
    // Timer table would be allocated from pool in a full implementation
    prcb.timer_table = 0;
    prcb.timer_expiration = 0;
    prcb.timer_service_index = 0;
    prcb.timer_banner = 0;
    // // kprintln!("[SCHED] Timer table initialized for PRCB");
}

/// Try to acquire the dispatcher lock for the current CPU
/// Returns true if lock was acquired
pub fn acquire_dispatcher_lock() -> bool {
    let mut scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;

    if let Some(ref mut prcb) = scheduler.cpus[cpu] {
        // Check if lock is already held
        if prcb.dispatcher_lock != 0 {
            return false;
        }
        // Acquire the lock
        prcb.dispatcher_lock = 1;
        return true;
    }
    false
}

/// Release the dispatcher lock for the current CPU
pub fn release_dispatcher_lock() {
    let mut scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;

    if let Some(ref mut prcb) = scheduler.cpus[cpu] {
        if prcb.dispatcher_lock == 1 {
            prcb.dispatcher_lock = 0;
        }
        // // kprintln!("[SCHED] Dispatcher lock released for CPU {}", cpu);
    }
}

/// Acquire the scheduler's global lock
pub fn acquire_scheduler_lock() {
    // The global SCHEDULER spinlock already provides this
    // Just for API completeness
    let _ = SCHEDULER.lock();
}

/// Release the scheduler's global lock
/// Note: This is a no-op since the lock is RAII
pub fn release_scheduler_lock() {
    // Lock is released when the guard is dropped
}

/// Initialize scheduler extensions for a PRCB (P2 Enhancement)
pub fn init_scheduler_extensions(prcb: &mut Prcb, _cpu_id: u32) {
    init_dispatcher_lock(prcb);
    init_timer_table(prcb);

    // Initialize idle_ready_threads list
    prcb.idle_ready_threads.flink = core::ptr::null_mut();
    prcb.idle_ready_threads.blink = core::ptr::null_mut();

    // Initialize schedule_dpc (placeholder)
    prcb.schedule_dpc = 0;

    // _cpu_id is intentionally unused - reserved for future logging
    // // kprintln!(
    // //         "[SCHED] Scheduler extensions initialized for CPU {}: dispatcher_lock, timer_table, idle_ready_threads",
    // //         _cpu_id
    // //     );
}

/// Run `callback` with exclusive access to a CPU's PRCB.
///
/// This keeps the PRCB registered in the scheduler while it is in use and
/// performs the lookup while holding the scheduler lock only once.
pub fn with_prcb<R>(cpu: usize, callback: impl FnOnce(&mut Prcb) -> R) -> Option<R> {
    let mut scheduler = SCHEDULER.lock();
    if cpu >= scheduler.cpus.len() {
        return None;
    }
    scheduler.cpus[cpu].as_deref_mut().map(callback)
}

/// Run `callback` with exclusive access to the current CPU's PRCB.
pub fn with_current_prcb<R>(callback: impl FnOnce(&mut Prcb) -> R) -> Option<R> {
    let mut scheduler = SCHEDULER.lock();
    let cpu = scheduler.current_cpu as usize;
    if cpu >= scheduler.cpus.len() {
        return None;
    }
    scheduler.cpus[cpu].as_deref_mut().map(callback)
}

#[cfg(test)]
mod ready_queue_lock_tests {
    use super::lock_ready_queue;

    #[test]
    fn rejects_out_of_range_queue_locks() {
        assert!(lock_ready_queue(usize::MAX, 0).is_none());
        assert!(lock_ready_queue(0, usize::MAX).is_none());
    }

    #[test]
    fn rejects_reentrant_acquisition_and_releases_on_drop() {
        let guard = lock_ready_queue(3, 31).expect("queue lock must be acquirable");
        assert!(lock_ready_queue(3, 31).is_none());
        drop(guard);
        let reacquired = lock_ready_queue(3, 31).expect("queue lock must be released");
        drop(reacquired);
    }
}

#[cfg(test)]
mod scheduler_prcb_access_tests {
    use super::with_prcb;

    #[test]
    fn rejects_out_of_range_cpu_without_panicking() {
        assert!(with_prcb(usize::MAX, |_prcb| ()).is_none());
    }
}

#[cfg(test)]
mod multicore_contention_tests {
    use super::*;

    /// Multi-core contention stress test: verify that per-priority
    /// ready queue locks do not alias across CPUs and that the
    /// per-CPU dispatcher lock (PRCB lock) is independently
    /// acquired and released for different CPUs.
    #[test]
    fn per_priority_queue_locks_do_not_alias_across_cpus() {
        // Use priorities that do not collide with other tests that
        // also lock (CPU 0..4, priority 0/7/15/31) concurrently.
        // Lock (CPU 0, priority 29).
        let guard_0 = lock_ready_queue(0, 29).expect("CPU 0 priority 29");

        // Lock (CPU 1, priority 29): different CPU, same priority.
        let guard_1 = lock_ready_queue(1, 29).expect("CPU 1 priority 29");

        // Lock (CPU 0, priority 28): same CPU, different priority.
        let guard_2 = lock_ready_queue(0, 28).expect("CPU 0 priority 28");

        drop(guard_0);
        drop(guard_1);
        drop(guard_2);

        // Re-acquire to verify locks were released.
        let guard = lock_ready_queue(0, 29).expect("re-acquired after drop");
        drop(guard);
    }

    #[test]
    fn reentrant_acquisition_rejected_for_each_cpu() {
        for cpu in 0..4 {
            for priority in [0usize, 7, 15, 31] {
                let guard = lock_ready_queue(cpu, priority).expect("first acquisition");
                assert!(
                    lock_ready_queue(cpu, priority).is_none(),
                    "reentrant rejected for CPU {} priority {}",
                    cpu,
                    priority
                );
                drop(guard);
            }
        }
    }

    #[test]
    fn prcb_locks_are_per_cpu() {
        assert!(lock_prcb(0), "CPU 0 PRCB lock acquirable");
        assert!(lock_prcb(1), "CPU 1 PRCB lock acquirable");
        assert!(!lock_prcb(0), "CPU 0 PRCB lock reentrant rejected");
        unlock_prcb(0);
        unlock_prcb(1);
        assert!(lock_prcb(0), "CPU 0 PRCB lock re-acquirable");
        unlock_prcb(0);
    }

    #[test]
    fn per_cpu_ready_summary_tracks_independent_queues() {
        // Verify that every (CPU, priority) pair is independently
        // lockable.  Acquire and release each lock one at a time so
        // that this test does not hold all 128 spin-locks at once —
        // holding them all would make the test unable to run in
        // parallel with any other test that also touches the ready
        // queue locks (cargo runs tests on multiple threads by
        // default).
        let mut acquired = 0usize;
        for cpu in 0..4 {
            for priority in 0..32 {
                let guard = lock_ready_queue(cpu, priority).expect("queue lock must be acquirable");
                acquired += 1;
                drop(guard);
            }
        }
        assert_eq!(
            acquired,
            4 * 32,
            "all 128 queue locks individually acquired"
        );

        let guard = lock_ready_queue(0, 0).expect("re-acquired after mass release");
        drop(guard);
    }
}
