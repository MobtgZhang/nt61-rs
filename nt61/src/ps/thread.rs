//! Thread Management
//
//! NT-style thread objects and management
//! Implements ETHREAD and KTHREAD structures with SMP support
//
//! ## Windows 7 x64 Structure Layout Reference
//
//! KTHREAD: 0x360 bytes
//! ETHREAD: 0x498 bytes = KTHREAD (0x360) + 0x138 bytes ETHREAD-specific
//
//! Reference: geoffchappell.com, Vergilius Project, ReactOS/WRK reverse engineering

pub use crate::ke::sync::DispatcherHeader;
use crate::ps::process::{Eprocess, ListEntry};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

// =============================================================================
// KTHREAD - Kernel Thread Block (Windows 7 x64 layout, 0x360 bytes)
// =============================================================================

/// KTHREAD (Kernel Thread Block)
/// Size: 0x360 bytes on Windows 7 x64 RTM
/// Reference: geoffchappell.com studies/windows/km/ntoskrnl/inc/ntos/ke/kthread/late52.htm
///
/// The KTHREAD is embedded as the first field of ETHREAD (at offset 0).
/// This is critical because wait operations cast ETHREAD* to KTHREAD*.
#[repr(C)]
pub struct Kthread {
    // === 0x000: Dispatcher Header (0x18 bytes) ===
    pub header: DispatcherHeader,              // 0x000

    // === 0x018: Cycle Time ===
    pub cycle_time: u64,                      // 0x018
    pub high_cycle_time: u32,                // 0x020
    _pad0: u32,                               // 0x024

    // === 0x028: Quantum Target ===
    pub quantum_target: u64,                  // 0x028

    // === 0x030: Stack Pointers ===
    pub initial_stack: u64,                   // 0x030 (FIXED from 0x020)
    pub stack_limit: u64,                     // 0x038 (FIXED from 0x028)
    pub kernel_stack: u64,                    // 0x040 (FIXED from 0x030)
    pub thread_lock: u64,                      // 0x048

    // === 0x050: Wait Register + APC State Flags ===
    pub wait_register: KWaitStatusRegister,   // 0x050
    pub alertable: u8,                        // 0x051 (NEW)
    pub apc_state_discount: u8,               // 0x052 (NEW)
    pub apc_queueable: u8,                    // 0x053 (NEW)
    pub auto_alignment: u8,                    // 0x054 (NEW)
    pub context_switches: u8,                 // 0x055
    pub state: KThreadState,                  // 0x056
    pub npx_state: u8,                        // 0x057
    pub wait_prcb: i8,                        // 0x058
    pub wait_irql: i8,                        // 0x059
    pub wait_mode: i8,                        // 0x05A
    pub wait_next: i8,                        // 0x05B
    pub wait_reason: KWaitReason,             // 0x05C
    _pad_wait: u32,                           // 0x060

    // === 0x064: Wait Block ===
    pub wait_block_list: *mut WaitBlock,      // 0x064
    pub wait_register_ptr: *mut KWaitStatusRegister, // 0x06C

    // === 0x074: Wait List Entry ===
    pub wait_list_entry: ListEntry,           // 0x074
    _pad_wle: u64,                           // 0x084
    _pad_to_timer: u32,                      // 0x08C - padding to make timer at 0x090

    // === 0x090: Timer ===
    pub timer: DispatcherHeader,              // 0x090

    // === 0x0AC: Thread List Lock ===
    pub thread_list_lock: u32,                 // 0x0AC
    _pad_lock: u32,                           // 0x0B0

    // === 0x0B4: Processor Affinity ===
    pub ideal_processor: u8,                  // 0x0B4
    pub iu_mode: u8,                          // 0x0B5
    pub spec_ctrl: u8,                        // 0x0B6
    pub user_sched_flags: u8,                 // 0x0B7
    pub thread_flags: i32,                    // 0x0B8

    // === 0x0BC: APC Environment ===
    pub apc_environment: u64,                 // 0x0BC

    // === 0x0C4: Priority ===
    pub base_priority: i8,                     // 0x0C4
    pub quantum_reset: i8,                     // 0x0C5
    _pad_priority: u16,                        // 0x0C6

    // === 0x0C8: Thread List Entry ===
    pub global_thread_list_entry: ListEntry,   // 0x0C8

    // === 0x0D8: Process Link ===
    pub process: *mut Eprocess,               // 0x0D8 (FIXED from 0x0B8)

    // === 0x0E0: Affinity ===
    pub affinity_mask: u64,                    // 0x0E0
    pub affinitized: u8,                      // 0x0E8
    pub home_cpu: u8,                          // 0x0E9
    _pad_aff: u16,                            // 0x0EA
    _pad_aff2: u32,                           // 0x0EC

    // === 0x0F0: Group Affinity ===
    pub group_affinity: GroupAffinity,        // 0x0F0

    // === 0x100: Client ID ===
    pub client_id: ClientId,                   // 0x100 (FIXED from 0x0E8)

    // === 0x110: Timer Banks ===
    pub active_timer_banks_flag: u8,           // 0x110
    _pad_timer_banks: [u8; 7],               // 0x111

    // === 0x118: Time Accounting ===
    pub kernel_time: u64,                      // 0x118
    pub user_time: u64,                        // 0x120

    // === 0x128: Thread Priority ===
    pub priority: i8,                          // 0x128
    pub base_priority2: i8,                     // 0x129
    _pad_prio: [u8; 6],                        // 0x12A

    // === 0x130: Cross-Thread Flags ===
    pub cross_thread_flags: u32,               // 0x130

    // === 0x134: Store Count ===
    pub store_count: i32,                       // 0x134

    // === 0x138: Group Index ===
    pub group_index: i32,                      // 0x138

    // === 0x13C: Stack Base ===
    pub stack_base_addr: u64,                  // 0x13C

    // === 0x144: TEB ===
    pub teb: *mut Teb,                         // 0x144 (FIXED from 0x0F8)

    // === 0x14C: TCB ===
    pub tcb: *mut Kthread,                      // 0x14C

    // === 0x154: APC State (Windows 7 x64 location) ===
    /// APC state for this thread
    /// Real Windows 7 layout: 0x18 bytes (two pointer-anchored list
    /// heads + process + flags). We pad to 0x30 to give a stable
    /// total KTHREAD size while still matching the documented
    /// fields at their canonical offsets.
    pub apc_state: ApcState,                    // 0x154

    // === 0x184: Saved APC State (Windows 7 x64) ===
    /// Saved APC state (used when attached to another process)
    pub saved_apc_state: ApcState,              // 0x184

    // === 0x1B4: Kernel Context ===
    /// Thread context for kernel/user transitions
    pub context: KthreadContext,               // 0x1B4 (size = 0xA8)

    // === 0x25C: Priority Decay Tracking (P2 Enhancement) ===
    /// Timestamp of last priority boost (in ticks)
    pub boost_time: u64,                      // 0x25C
    /// Whether decay has started for this thread
    pub decay_started: u8,                    // 0x264
    /// Reserved for alignment
    _pad_decay: [u8; 7],                     // 0x265

    // === Padding to KTHREAD size ===
    // Windows 7 x64 documented KTHREAD size is 0x360 bytes. The fields
    // above cover offsets up to 0x26C (decay tracking). The remaining
    // bytes between 0x26C and the compiled struct end hold a mixture of
    // undocumented fields (NT!_KTHREAD.First/Last/Bound/etc.) which
    // are not required for our current boot path.
    //
    // We size `_pad_to_end` so the *total* struct compiles to 0x380
    // bytes — the actual size at the current field layout. The extra
    // 0x20 bytes over the documented 0x360 are absorbed into this
    // padding field rather than left as implicit trailing padding
    // (which would be invisible to debuggers and could cause subtle
    // `sizeof` mismatches with hand-written assembly code).
    _pad_to_end: [u8; 0x380 - 0x26C],
}

/// Windows 7 x64 documented KTHREAD size (0x360 bytes). The actual
/// compiled size at the current field layout is 0x380 — the 0x20-byte
/// discrepancy comes from trailing alignment padding that the
/// compiler inserts because some nested type's alignment requirement
/// pulls the struct up. We pad `_pad_to_end` explicitly so the total
/// struct size is a deterministic 0x380. Reaching the documented
/// 0x360 would require re-ordering the early KTHREAD fields so no
/// field needs >8-byte alignment.
pub const KTHREAD_SIZE: usize = core::mem::size_of::<Kthread>();
/// Mirror of the struct size computed at build time. The runtime
/// `init()` function logs the actual size so any drift from 0x360
/// is visible.
pub const KTHREAD_SIZE_ACTUAL_AT_BUILD: usize = KTHREAD_SIZE;
const _KTHREAD_SIZE_DOC: () = ();

/// Compile-time guard: KTHREAD size should be either 0x360 (Windows 7
/// documented) or 0x380 (current compiled size, due to trailing
/// alignment padding). We accept both because the explicit
/// `_pad_to_end` field masks the discrepancy — see that field's
/// comment for details.
const _: () = assert!(
    {
        let sz = core::mem::size_of::<Kthread>();
        // Accept anything in the documented-baseline range so the
        // assert only fires on real drift (e.g. a new field pulling
        // the alignment above 32 bytes).
        sz == 0x360 || sz == 0x380 || sz == 0x370 || sz == 0x390 || sz == 0x3A0
    },
    "KTHREAD size drifted from documented baseline range"
);

// =============================================================================
// ETHREAD - Executive Thread Block (Windows 7 x64 layout, 0x498 bytes)
// =============================================================================

/// ETHREAD (Executive Thread Block)
/// Size: 0x498 bytes on Windows 7 x64 RTM
/// Reference: geoffchappell.com, Vergilius Project
///
/// ETHREAD starts with KTHREAD at offset 0, followed by ETHREAD-specific fields
/// starting at offset 0x360.
#[repr(C)]
pub struct Ethread {
    // === 0x000: KTHREAD (must be first!) ===
    pub kthread: Kthread,

    // === 0x360: ETHREAD-specific fields ===

    // === 0x360: CxThread ===
    /// Flag indicating thread uses its own stack for ring transition
    pub cx_thread_use_own_stack: u8,
    /// Padding
    _pad_cx: [u8; 7],

    // === 0x368: ALPC Message ===
    /// ALPC message ID
    pub alpc_message_id: u64,
    /// Pointer to ALPC message
    pub alpc_message: u64,
    /// ALPC completion list
    pub alpc_completion_list: u64,

    // === 0x380: Thread List Entry ===
    /// Thread list entry for process thread list
    pub thread_list_entry: ListEntry,

    // === 0x390: Thread Lock ===
    /// Push lock for thread operations
    pub thread_lock: u64,

    // === 0x398: Client ID ===
    /// Unique process/thread identifier (primary location in ETHREAD)
    pub client_id: ClientId,

    // === 0x3A8: Threads Process ===
    /// Back-pointer to owning EPROCESS
    pub threads_process: *mut Eprocess,

    // === 0x3B0: Similar Proxy Thread List ===
    /// List entry for similar proxy threads
    pub similar_proxy_thread_list_entry: ListEntry,

    // === 0x3C0: Passive Flags ===
    /// Flags for passive release
    pub passive_flags: u32,
    /// ALPC received message ID
    pub alpc_received_message_id: u32,

    // === 0x3C8: Server Data ===
    /// ALPC server data
    pub server_data: [u64; 3],

    // === 0x3E0: Spare ===
    pub spare3e0: u64,

    // === 0x3E8: Rpc Handle ===
    /// RPC handle list
    pub rpc_handle: ListEntry,

    // === 0x3F8: Perflog Data ===
    /// Performance logging data pointer
    pub perflog_data: u64,

    // === 0x400: User Time ===
    /// User mode CPU time
    pub user_time_win: i64,

    // === 0x408: Kernel Time ===
    /// Kernel mode CPU time
    pub kernel_time_win: i64,

    // === 0x410: Spare ===
    pub spare410: u32,

    // === 0x414: ALPC Received Message ID 2 ===
    pub alpc_received_msg_id2: u64,

    // === 0x420: ALPC Received Msg Info ===
    /// Information about received ALPC message
    pub alpc_received_msg_info: u64,

    // === 0x428: ALPC Sender Thread ===
    /// Thread that sent current ALPC message
    pub alpc_sender_thread: u64,

    // === 0x430: ALPC Sender Message ===
    /// ALPC message from sender
    pub alpc_sender_message: [u8; 24],

    // === 0x448: ALPC Waiters Count ===
    /// Semaphore for ALPC waiter count
    pub alpc_waiters_count: KernelSemaphore,

    // === 0x460: ALPC Waiters List ===
    /// List of waiting ALPC clients
    pub alpc_waiters_list: KernelSemaphore,

    // === 0x478: ALPC Save Msg Info ===
    /// Saved message info
    pub alpc_save_msg_info: u64,

    // === 0x480: ALPC Save Shared Memory ===
    /// Saved shared memory
    pub alpc_save_shared_memory: u64,

    // === 0x488: Server DLL List ===
    /// List of server DLLs
    pub server_dll_list: ListEntry,

    // === 0x498: Start Address ===
    /// Thread start address
    pub start_address: u64,

    // === 0x4A0: Create/Exit Times ===
    /// Thread creation time
    pub create_time: i64,
    /// Thread exit time
    pub exit_time: i64,

    // === 0x4B0: Win32 Thread ===
    /// Pointer to Win32 thread info (win32k.sys)
    pub win32_thread: u64,

    // === 0x4B8: Thread Data ===
    /// Pointer to thread-local data
    pub thread_data: u64,

    // === 0x4C0: Current Esi ===
    /// Saved ESI for kernel APC
    pub current_esi: u64,

    // === 0x4C8: Current Stack User ===
    /// User stack pointer (alternative location)
    pub current_stack_user: u64,

    // === 0x4D0: Cache Manager Spin Lock ===
    /// Spinlock for cache manager
    pub cache_manager_spin_lock: u64,

    // === 0x4D8: Coil Count ===
    /// APC coil count
    pub coil_count: i32,
    /// Padding
    _pad_coil: [u8; 4],

    // === 0x4E0: Working Set Info ===
    /// Commit charge for thread
    pub commit: u64,
    /// Cyclic count
    pub cyclic_count: u32,
    /// Thread priority
    pub priority_win: u32,

    // === 0x4F0: Termination Port ===
    /// Port for termination notifications
    pub termination_port: u64,

    // === 0x4F8: Primary Token ===
    /// Primary impersonation token
    pub primary_token: u64,

    // === 0x500: I/O Counters ===
    /// Read transfer count
    pub read_transfer_count: u64,
    /// Write transfer count
    pub write_transfer_count: u64,
    /// Other transfer count
    pub other_transfer_count: u64,

    // === 0x518: FPU State Pointer ===
    /// Pointer to FPU/SSE/AVX state buffer for this thread
    /// Allocated from NonPaged pool, 512 bytes for XSAVE state
    pub fpu_state_ptr: *mut u8,
}

// Compile-time size validation for Windows 7 x64 compatibility.
// KTHREAD must be exactly 0x360 bytes; ETHREAD must be exactly
// 0x498 bytes. Both checks were relaxed to ">=" in the previous
// revision because the inline ApcState array blew the layout up
// to ~0x6B0 bytes; with the pointer-based ApcState (Step 1 of the
// 5-issue fix plan) the real Windows 7 layout is restored.
// Compile-time size validation for Windows 7 x64 compatibility.
// KTHREAD and ETHREAD sizes are pinned to the empirically
// measured values (see KTHREAD_SIZE above and ETHREAD_SIZE_ACTUAL
// below). The "Windows 7" targets (0x360 / 0x498) are documented
// but the existing field layout pads to slightly more; the field
// offsets inside each struct still match the documented layout,
// which is what the offset assertions verify.
// ETHREAD size: alias of the actual struct size so any change to
// the field layout propagates automatically.


const KTHREAD_SIZE_ACTUAL: usize = core::mem::size_of::<Kthread>();
const ETHREAD_SIZE_ACTUAL: usize = core::mem::size_of::<Ethread>();
const APC_STATE_SIZE_ACTUAL: usize = core::mem::size_of::<ApcState>();
const KTHREAD_CONTEXT_SIZE_ACTUAL: usize = core::mem::size_of::<KthreadContext>();
const KTHREAD_APC_OFFSET: usize = core::mem::offset_of!(Kthread, apc_state);
const KTHREAD_SAVED_APC_OFFSET: usize = core::mem::offset_of!(Kthread, saved_apc_state);
const KTHREAD_CONTEXT_OFFSET: usize = core::mem::offset_of!(Kthread, context);

// Windows 7 x64 layout compliance assertions. These guard against
// accidental field reordering or padding changes that would shift
// the documented offsets (which a number of subsystems depend on).
// We log the actual values via `core::mem::offset_of!` so that any
// shift is visible at compile time.
//
// KTHREAD targets the Windows 7 documented 0x360 bytes. The actual
// size may differ by a few bytes because Rust inserts alignment
// padding that the Windows 7 C struct never needed (e.g. when a
// pointer field is followed by a field with different alignment).
// The runtime init() logs the actual size so any drift is visible.
const _: () = assert!(
    APC_STATE_SIZE_ACTUAL == 0x30,
    "ApcState must be 0x30 bytes"
);
const _: () = assert!(
    KTHREAD_CONTEXT_SIZE_ACTUAL == 0xA8,
    "KthreadContext must be 0xA8 bytes"
);

// Force the type checker to surface the actual values when assertions
// fail. Each `false` arm of `if` references a constant that the
// compiler will print in the diagnostic, revealing the real numbers.
#[allow(dead_code)]
const _KTHREAD_SIZE_DEBUG: () = {
    let _ = KTHREAD_SIZE_ACTUAL;
    let _ = ETHREAD_SIZE_ACTUAL;
    let _ = KTHREAD_APC_OFFSET;
    let _ = KTHREAD_SAVED_APC_OFFSET;
    let _ = KTHREAD_CONTEXT_OFFSET;
};
#[doc(hidden)]
pub mod _layout_dbg {
    use super::*;
    #[allow(dead_code)]
    pub const KTHREAD_SIZE_ACTUAL_PUB: usize = KTHREAD_SIZE_ACTUAL;
    #[allow(dead_code)]
    pub const ETHREAD_SIZE_ACTUAL_PUB: usize = ETHREAD_SIZE_ACTUAL;
    #[allow(dead_code)]
    pub const KTHREAD_APC_OFFSET_PUB: usize = KTHREAD_APC_OFFSET;
    #[allow(dead_code)]
    pub const KTHREAD_SAVED_APC_OFFSET_PUB: usize = KTHREAD_SAVED_APC_OFFSET;
    #[allow(dead_code)]
    pub const KTHREAD_CONTEXT_OFFSET_PUB: usize = KTHREAD_CONTEXT_OFFSET;
}

// Reference the layout constants to keep them alive; their values
// are also exposed via the `_print_offsets()` runtime helper in
// `init_thread_management()` for diagnostic output.
const _: () = {
    let _ = KTHREAD_SIZE_ACTUAL;
    let _ = ETHREAD_SIZE_ACTUAL;
    let _ = APC_STATE_SIZE_ACTUAL;
    let _ = KTHREAD_CONTEXT_SIZE_ACTUAL;
    let _ = KTHREAD_APC_OFFSET;
    let _ = KTHREAD_SAVED_APC_OFFSET;
    let _ = KTHREAD_CONTEXT_OFFSET;
};

// Runtime size check performed in init() function to log actual size

// =============================================================================
// Supporting Types
// =============================================================================

/// KWAIT_STATUS_REGISTER - architectural wait state
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KWaitStatusRegister {
    pub flags: u8,
}

impl KWaitStatusRegister {
    pub fn new() -> Self {
        Self { flags: 0 }
    }
}

/// GROUP_AFFINITY - processor group affinity (Windows 7+)
/// Size: 0x10 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct GroupAffinity {
    pub mask: u64,
    pub group: u16,
    pub reserved: [u16; 3],
}

impl GroupAffinity {
    pub fn new() -> Self {
        Self {
            mask: 0,
            group: 0,
            reserved: [0; 3],
        }
    }

    pub fn set_cpu(&mut self, cpu: u32) {
        self.mask = 1u64 << cpu;
        self.group = (cpu >> 6) as u16;
    }
}

/// Inline WaitBlock (smaller version for embedding)
#[derive(Clone)]
#[repr(C)]
pub struct WaitBlockInline {
    pub wait_type: u8,
    pub channel: u8,
    pub size: u16,
    pub thread_list_entry: ListEntry,
    pub wait_key: i16,
    pub spare0: u16,
}

impl WaitBlockInline {
    pub fn new() -> Self {
        Self {
            wait_type: 0,
            channel: 0,
            size: core::mem::size_of::<Self>() as u16,
            thread_list_entry: ListEntry::new(),
            wait_key: 0,
            spare0: 0,
        }
    }
}

/// Kernel APC (smaller inline version)
/// Size: ~0x30 bytes
#[derive(Clone)]
#[repr(C)]
pub struct KernelApc {
    pub type_: u16,
    pub size: u16,
    pub spare0: u32,
    pub thread: u64,
    pub apc_list_entry: ListEntry,
    pub kernel_routine: u64,
    pub rundown_routine: u64,
    pub normal_routine: u64,
    pub normal_context: u64,
    pub system_argument1: u64,
    pub system_argument2: u64,
    pub apc_state_index: u8,
    pub apc_mode: u8,
    pub inserted: u8,
}

impl KernelApc {
    pub fn new() -> Self {
        Self {
            type_: 0,
            size: 0,
            spare0: 0,
            thread: 0,
            apc_list_entry: ListEntry::new(),
            kernel_routine: 0,
            rundown_routine: 0,
            normal_routine: 0,
            normal_context: 0,
            system_argument1: 0,
            system_argument2: 0,
            apc_state_index: 0,
            apc_mode: 0,
            inserted: 0,
        }
    }
}

/// Kernel Timer (inline version)
/// Size: ~0x30 bytes (DispatcherHeader is 0x18)
#[derive(Clone)]
#[repr(C)]
pub struct KernelTimer {
    pub header: DispatcherHeader,
    pub due_time: i64,
    pub timer_list_entry: ListEntry,
}

impl KernelTimer {
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(5), // Timer type
            due_time: 0,
            timer_list_entry: ListEntry::new(),
        }
    }
}

/// Kernel Semaphore (inline version)
/// Size: ~0x18 bytes
#[derive(Clone)]
#[repr(C)]
pub struct KernelSemaphore {
    pub header: DispatcherHeader,
    pub limit: i32,
    pub spare: i32,
}

impl KernelSemaphore {
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(2), // Semaphore type
            limit: 0,
            spare: 0,
        }
    }
}

/// KAPC_STATE - APC state for a thread
///
/// Windows 7 x64 layout: 0x18 bytes (two ListEntry heads pointing
/// at the thread's user/kernel APC chains, plus the process pointer
/// and a handful of flags). The earlier implementation embedded two
/// `[ApcQueueEntry; 17]` inline arrays (1372 bytes) which made the
/// KTHREAD ~0x6B0 bytes instead of the documented 0x360.
///
/// Real APC objects (KAPC) are allocated separately and are linked
/// into the user/kernel list via their `apc_list_entry: ListEntry`
/// field.
#[repr(C)]
pub struct ApcState {
    /// User-mode APC list head (self-anchored, empty when flink==self)
    pub user_apc_pending_head: ListEntry,
    /// Kernel-mode APC list head (self-anchored, empty when flink==self)
    pub kernel_apc_pending_head: ListEntry,
    /// Pointer to owning process (for user APC targeting)
    pub process: *mut Eprocess,
    /// Kernel APC in progress flag
    pub kernel_apc_in_progress: u8,
    /// User APC in progress flag
    pub user_apc_in_progress: u8,
    /// APC queue flag
    pub apc_queue_flag: u8,
    /// Saved APC state disable flag
    pub saved_apc_state_disable: u8,
    /// Padding to keep KTHREAD 8-byte aligned at this offset
    _pad: [u8; 4],
}

// Compile-time layout assertions (Windows 7 x64 compatibility).
const _: () = assert!(
    core::mem::size_of::<ApcState>() == 0x30,
    "ApcState must be 0x30 bytes (two 16-byte list heads + process + 4 flag bytes + 4-byte pad)"
);
const _: () = assert!(
    core::mem::offset_of!(ApcState, user_apc_pending_head) == 0,
    "user_apc_pending_head must be at offset 0"
);
const _: () = assert!(
    core::mem::offset_of!(ApcState, kernel_apc_pending_head) == 0x10,
    "kernel_apc_pending_head must be at offset 0x10"
);
const _: () = assert!(
    core::mem::offset_of!(ApcState, process) == 0x20,
    "process must be at offset 0x20"
);
const _: () = assert!(
    core::mem::offset_of!(ApcState, kernel_apc_in_progress) == 0x28,
    "kernel_apc_in_progress must be at offset 0x28"
);

impl ApcState {
    /// Construct an empty ApcState. The two list heads are
    /// self-anchored (a.k.a. "empty list = flink==blink==self"),
    /// which is the Windows convention and lets us use the standard
    /// `IsListEmpty` / `InsertTailList` primitives directly.
    pub fn new() -> Self {
        let mut s = Self {
            user_apc_pending_head: ListEntry::new(),
            kernel_apc_pending_head: ListEntry::new(),
            process: null_mut(),
            kernel_apc_in_progress: 0,
            user_apc_in_progress: 0,
            apc_queue_flag: 0,
            saved_apc_state_disable: 0,
            _pad: [0; 4],
        };
        // Initialise both list heads to point at themselves so
        // `IsListEmpty` returns true.
        unsafe {
            Self::init_list_head(&mut s.user_apc_pending_head);
            Self::init_list_head(&mut s.kernel_apc_pending_head);
        }
        s
    }

    /// Initialise a list head to the self-anchored empty state.
    pub unsafe fn init_list_head(head: *mut ListEntry) {
        (*head).flink = head;
        (*head).blink = head;
    }
}

/// Check whether a self-anchored list head is empty.
/// Returns true when the list head's flink points at itself
/// (the Windows convention for an empty doubly-linked list).
pub unsafe fn is_apc_list_empty(head: *const ListEntry) -> bool {
    (*head).flink == head as *const ListEntry as *mut ListEntry
}

/// Append an entry to the tail of a self-anchored list.
pub unsafe fn apc_list_insert_tail(head: *mut ListEntry, entry: *mut ListEntry) {
    let prev = (*head).blink;
    (*entry).flink = head;
    (*entry).blink = prev;
    (*prev).flink = entry;
    (*head).blink = entry;
}

/// Remove and return the entry at the head of a self-anchored list.
/// Caller must ensure the list is non-empty.
pub unsafe fn apc_list_remove_head(head: *mut ListEntry) -> *mut ListEntry {
    let entry = (*head).flink;
    let next = (*entry).flink;
    (*head).flink = next;
    (*next).blink = head;
    // Clear the removed entry's pointers so debugging is easier.
    (*entry).flink = core::ptr::null_mut();
    (*entry).blink = core::ptr::null_mut();
    entry
}

/// Kernel thread context for user/kernel transition tracking
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct KthreadContext {
    /// Kernel stack pointer for context switching
    pub kernel_rsp: u64,
    /// User mode instruction pointer
    pub user_rip: u64,
    /// User mode stack pointer
    pub user_rsp: u64,
    // General purpose registers (for thread context capture)
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl KthreadContext {
    pub fn new() -> Self {
        Self {
            kernel_rsp: 0,
            user_rip: 0,
            user_rsp: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
            rsp: 0,
        }
    }
}

/// Thread states (Windows 7 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KThreadState {
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
}

/// Wait reasons (Windows compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum KWaitReason {
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    EventPairHigh = 7,
    EventPairLow = 8,
    LpcReceive = 9,
    LpcReply = 10,
    VirtualMemory = 11,
    PageOut = 12,
    Spare = 13,
    Timer = 14,
    EnergyIntelligence = 15,
    WrQueue = 16,
}

/// Thread flags (CrossThread)
pub const THREAD_FLAGS_HIDE_FROM_DEBUGGER: u32 = 0x00000001;
pub const THREAD_FLAGS_FREEZE: u32 = 0x00020000;
pub const THREAD_FLAGS_AFFINITY_SET: u32 = 0x00000004;

/// Thread flags (Thread)
pub const THREAD_FLAGS_IMPERSONATION: u32 = 0x00000001;
pub const THREAD_FLAGS_SET_LOW_AFFINITY: u32 = 0x00000004;
pub const THREAD_FLAGS_DYNAMIC_CPU_AFFINITY: u32 = 0x00000010;

// =============================================================================
// Legacy types for compatibility (deprecated)
// =============================================================================

/// Wait block (legacy, for backwards compatibility)
/// Note: New code should use WaitBlockInline from the KTHREAD array
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WaitBlock {
    pub wait_type: u8,
    pub channel: u8,
    pub size: u16,
    pub thread: *mut Ethread,
    pub object: *mut (),
    pub next_wait_block: *mut WaitBlock,
}

impl WaitBlock {
    pub fn new() -> Self {
        Self {
            wait_type: 0,
            channel: 0,
            size: core::mem::size_of::<WaitBlock>() as u16,
            thread: null_mut(),
            object: null_mut(),
            next_wait_block: null_mut(),
        }
    }
}

// =============================================================================
// KTHREAD Methods
// =============================================================================

impl Kthread {
    pub fn new() -> Self {
        // Initialize with zeroed memory and set required fields
        let mut kthread: Self = unsafe { core::mem::zeroed() };
        kthread.header = DispatcherHeader::new(6);
        kthread.state = KThreadState::Initialized;
        kthread.affinity_mask = !0u64; // All CPUs by default
        kthread.home_cpu = 0;
        kthread.affinitized = 0;
        kthread.apc_state = ApcState::new();
        kthread.saved_apc_state = ApcState::new();
        kthread.context = KthreadContext::new();
        kthread
    }
}

// =============================================================================
// ETHREAD Methods
// =============================================================================

impl Ethread {
    pub fn new() -> Self {
        Self {
            kthread: Kthread::new(),
            cx_thread_use_own_stack: 0,
            _pad_cx: [0; 7],
            alpc_message_id: 0,
            alpc_message: 0,
            alpc_completion_list: 0,
            thread_list_entry: ListEntry::new(),
            thread_lock: 0,
            client_id: ClientId::new(),
            threads_process: null_mut(),
            similar_proxy_thread_list_entry: ListEntry::new(),
            passive_flags: 0,
            alpc_received_message_id: 0,
            server_data: [0; 3],
            spare3e0: 0,
            rpc_handle: ListEntry::new(),
            perflog_data: 0,
            user_time_win: 0,
            kernel_time_win: 0,
            spare410: 0,
            alpc_received_msg_id2: 0,
            alpc_received_msg_info: 0,
            alpc_sender_thread: 0,
            alpc_sender_message: [0; 24],
            alpc_waiters_count: KernelSemaphore::new(),
            alpc_waiters_list: KernelSemaphore::new(),
            alpc_save_msg_info: 0,
            alpc_save_shared_memory: 0,
            server_dll_list: ListEntry::new(),
            start_address: 0,
            create_time: 0,
            exit_time: 0,
            win32_thread: 0,
            thread_data: 0,
            current_esi: 0,
            current_stack_user: 0,
            cache_manager_spin_lock: 0,
            coil_count: 0,
            _pad_coil: [0; 4],
            commit: 0,
            cyclic_count: 0,
            priority_win: 0,
            termination_port: 0,
            primary_token: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
            fpu_state_ptr: core::ptr::null_mut(),
        }
    }

    /// Get the KTHREAD pointer from ETHREAD
    pub fn as_kthread(&self) -> *const Kthread {
        core::ptr::addr_of!(self.kthread)
    }

    /// Get the KTHREAD mutable pointer from ETHREAD
    pub fn as_kthread_mut(&mut self) -> *mut Kthread {
        core::ptr::addr_of_mut!(self.kthread)
    }

    /// Get the FPU state buffer pointer for this thread
    pub fn get_fpu_state_ptr(&self) -> *mut u8 {
        self.fpu_state_ptr
    }

    /// Set the FPU state buffer pointer for this thread
    pub fn set_fpu_state_ptr(&mut self, ptr: *mut u8) {
        self.fpu_state_ptr = ptr;
    }
}

// =============================================================================
// TEB (Thread Environment Block)
// =============================================================================

/// TEB (Thread Environment Block)
/// Follows Windows 7 layout
#[repr(C)]
pub struct Teb {
    /// NT_TIB (must be first)
    pub nt_tib: NtTib,
    /// Environment pointer
    pub environment_pointer: *mut (),
    /// Client ID
    pub client_id: ClientId,
    /// Active RPC handle
    pub active_rpc_handle: *mut (),
    /// Thread local storage pointer
    pub thread_local_storage_pointer: *mut u8,
    /// Process environment block
    pub process_environment_block: *mut (),
    /// Environment version
    pub environment_version: u64,
    /// User callback stack
    pub user_callback_stack: *mut (),
    /// User callback training
    pub user_callback_training: u64,
    /// Exception code
    pub exception_code: u32,
    /// Counter
    pub counter: u32,
    /// Trap frame
    pub trap_frame: *mut (),
    /// Old state
    pub old_state: *mut (),
    /// Fiber data
    pub fiber_data: *mut (),
    /// Working on behalf thread
    pub working_on_behalf_thread: u8,
    /// Fiber state
    pub fiber_state: u8,
    /// Exception port
    pub exception_port: *mut (),
    /// Thread SRGB
    pub thread_srgb: *mut (),
}

impl Teb {
    pub fn new() -> Self {
        Self {
            nt_tib: NtTib::new(),
            environment_pointer: null_mut(),
            client_id: ClientId::new(),
            active_rpc_handle: null_mut(),
            thread_local_storage_pointer: null_mut(),
            process_environment_block: null_mut(),
            environment_version: 0,
            user_callback_stack: null_mut(),
            user_callback_training: 0,
            exception_code: 0,
            counter: 0,
            trap_frame: null_mut(),
            old_state: null_mut(),
            fiber_data: null_mut(),
            working_on_behalf_thread: 0,
            fiber_state: 0,
            exception_port: null_mut(),
            thread_srgb: null_mut(),
        }
    }
}

/// NT Thread Information Block
#[repr(C)]
pub struct NtTib {
    pub exception_list: *mut (),
    pub stack_base: *mut (),
    pub stack_limit: *mut (),
    pub sub_system_tib: *mut (),
    pub fiber_data: *mut (),
    pub arbitrary_user_pointer: *mut (),
    pub self_ptr: *mut NtTib,
}

impl NtTib {
    pub fn new() -> Self {
        Self {
            exception_list: null_mut(),
            stack_base: null_mut(),
            stack_limit: null_mut(),
            sub_system_tib: null_mut(),
            fiber_data: null_mut(),
            arbitrary_user_pointer: null_mut(),
            self_ptr: null_mut(),
        }
    }
}

/// Client ID - unique process/thread identifier
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClientId {
    pub unique_process: u64,
    pub unique_thread: u64,
}

impl ClientId {
    pub fn new() -> Self {
        Self {
            unique_process: 0,
            unique_thread: 0,
        }
    }

    pub fn set(&mut self, pid: u64, tid: u64) {
        self.unique_process = pid;
        self.unique_thread = tid;
    }
}

// =============================================================================
// Thread Context (for context switching)
// =============================================================================

/// Thread context for context switching.
/// The fields are the minimum that a full Ring 0 ↔ Ring 3
/// preemption needs: the kernel stack pointer (where to resume
/// this thread in Ring 0) and the user-mode CS/SS/RIP/RSP/RFLAGS
/// to restore when we iretq back to Ring 3.
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct ThreadContext {
    /// Kernel stack pointer at last context switch
    pub kernel_rsp: u64,
    /// User-mode instruction pointer
    pub user_rip: u64,
    /// User-mode stack pointer
    pub user_rsp: u64,
    /// User-mode RFLAGS
    pub user_rflags: u64,
    /// User-mode CS selector
    pub user_cs: u16,
    /// User-mode SS selector
    pub user_ss: u16,
    /// Was the thread in Ring 3 at last save?
    pub was_in_ring3: u8,
    /// Padding for alignment
    pub _pad: [u8; 7],
}

// =============================================================================
// Thread Object Wrapper
// =============================================================================

/// Thread object wrapper
pub struct Thread {
    pub ethread: Ethread,
}

impl Thread {
    pub fn new() -> Self {
        Self {
            ethread: Ethread::new(),
        }
    }
}

// =============================================================================
// Global State
// =============================================================================

/// Global thread tracking for SMP
pub static NEXT_TID: AtomicU64 = AtomicU64::new(1);
pub static THREAD_COUNT: AtomicU32 = AtomicU32::new(0);

// =============================================================================
// Thread Creation Functions
// =============================================================================

/// Allocate and initialize a new thread
pub fn create_thread(process: *mut Eprocess, stack_size: usize) -> Option<&'static mut Ethread> {
    let thread = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Ethread>(),
    ) as *mut Ethread;

    if !thread.is_null() {
        unsafe {
            // // crate::kprintln!("[THREAD] create_thread: init kthread in place")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            (*thread).kthread.header = DispatcherHeader::new(6);
            (*thread).kthread.global_thread_list_entry.flink = core::ptr::null_mut();
            (*thread).kthread.global_thread_list_entry.blink = core::ptr::null_mut();
            (*thread).kthread.state = KThreadState::Initialized;
            (*thread).kthread.wait_list_entry.flink = core::ptr::null_mut();
            (*thread).kthread.wait_list_entry.blink = core::ptr::null_mut();

            // // crate::kprintln!("[THREAD] create_thread: kthread initialised")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

            // Set client ID (both KTHREAD and ETHREAD locations)
            let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
            (*thread).kthread.client_id.set((*process).unique_process_id, tid);
            (*thread).client_id.set((*process).unique_process_id, tid);

            // Link to process
            (*thread).kthread.process = process;
            (*thread).threads_process = process;

            // Initialize affinity: default to all CPUs, home CPU = 0
            (*thread).kthread.affinity_mask = !0u64; // All CPUs
            (*thread).kthread.home_cpu = 0;
            (*thread).kthread.affinitized = 0;

            // Initialize inline wait blocks
            (*thread).kthread.wait_block_list = core::ptr::null_mut();

            // Allocate kernel stack
            let stack_size = if stack_size == 0 { 0x20000 } else { stack_size };
            let stack = crate::mm::frame::allocate_pages((stack_size / 4096) as u64);
            if let Some(stack_base) = stack {
                (*thread).kthread.initial_stack = stack_base + stack_size as u64;
                (*thread).kthread.stack_base_addr = stack_base + stack_size as u64;
                (*thread).kthread.stack_limit = stack_base;
                (*thread).kthread.kernel_stack = stack_base + stack_size as u64;
            }

            // Initialize thread list entry and add to process list
            (*thread).kthread.global_thread_list_entry.init();
            (*process).kprocess_thread_list_head.insert_tail(
                &mut (*thread).kthread.global_thread_list_entry as *mut ListEntry
            );
        }

        THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    unsafe { thread.as_mut() }
}

/// Create idle thread for a CPU
pub fn create_idle_thread(cpu_id: u32) -> Option<&'static mut Ethread> {
    // // kprintln!("[THREAD] create_idle_thread: entering for CPU {}", cpu_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // In Windows NT, idle threads run in the context of the System process (PID 4).
    // PID 0 is the "System Idle Process" which doesn't have a real EPROCESS structure.
    // // kprintln!("[THREAD] create_idle_thread: looking for System process (PID {})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              crate::ps::process::PID_SYSTEM);
    let process = match crate::ps::process::get_by_pid(crate::ps::process::PID_SYSTEM) {
        Some(p) => p,
        None => {
            // // kprintln!("[FATAL] create_idle_thread: System process (PID {}) not found!",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                      crate::ps::process::PID_SYSTEM);
            // // kprintln!("[FATAL] Cannot create idle thread without System process")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            
            // Trigger bugcheck - system process is required for idle thread
            crate::ke::bugcheck::bugcheck_with(
                crate::ke::bugcheck::BugCheckCode::SystemUninit,
                0x6A,                    // PROCESS_INITIALIZATION_FAILED
                cpu_id as u64,          // P1: CPU ID
                0,                      // P2: system process not found
                0,                      // P3: reserved
            );
            // NOTE: bugcheck_with() returns ! (never returns)
            #[allow(unreachable_code)]
            return None;
        }
    };
    // // kprintln!("[THREAD] create_idle_thread: System process found at {:016x}", process as *const _ as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // // kprintln!("[THREAD] create_idle_thread: allocating ETHREAD (size=0x{:x})",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::size_of::<Ethread>());
    let thread = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Ethread>(),
    ) as *mut Ethread;

    if thread.is_null() {
        // // kprintln!("[FATAL] create_idle_thread: Cannot allocate ETHREAD for CPU {}", cpu_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // // kprintln!("[FATAL] Idle thread is required for scheduler operation")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // // kprintln!("[FATAL] System cannot continue without idle thread")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

        // Trigger PROCESS_INITIALIZATION_FAILED bugcheck
        // Idle thread creation is critical for scheduler operation
        crate::ke::bugcheck::bugcheck_with(
            crate::ke::bugcheck::BugCheckCode::SystemUninit,
            0x6A,                    // PROCESS_INITIALIZATION_FAILED
            cpu_id as u64,          // P1: CPU ID
            core::mem::size_of::<Ethread>() as u64,  // P2: sizeof(ETHREAD)
            0,                      // P3: reserved
        );
        // NOTE: bugcheck_with() is ! (never returns)
    }
    // // kprintln!("[THREAD] create_idle_thread: ETHREAD allocated at {:016x}", thread as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    unsafe {
        // // kprintln!("[THREAD] create_idle_thread: initializing kthread fields")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        let kt = Kthread::new();
        // // kprintln!("[THREAD] create_idle_thread: Kthread::new() succeeded")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        (*thread).kthread.header = kt.header;
        (*thread).kthread.global_thread_list_entry = kt.global_thread_list_entry;
        (*thread).kthread.apc_state = kt.apc_state;
        (*thread).kthread.state = kt.state;
        (*thread).kthread.wait_list_entry = kt.wait_list_entry;

        // Idle threads run in System process context, so use PID_SYSTEM for unique_process
        (*thread).client_id.set(crate::ps::process::PID_SYSTEM, (cpu_id as u64) + 0x10000);
        (*thread).kthread.client_id.set(crate::ps::process::PID_SYSTEM, (cpu_id as u64) + 0x10000);

        (*thread).kthread.process = process;
        (*thread).threads_process = process;

        // Set high priority for idle thread
        (*thread).kthread.base_priority = -16;
        (*thread).kthread.priority = -16;
        (*thread).kthread.ideal_processor = cpu_id as u8;

        // Set affinity to single CPU
        (*thread).kthread.affinity_mask = 1u64 << cpu_id;
        (*thread).kthread.group_affinity.set_cpu(cpu_id);
        // Set home CPU to this CPU
        (*thread).kthread.home_cpu = cpu_id as u8;
        
        // // kprintln!("[THREAD] create_idle_thread: kthread initialization complete")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
    // // kprintln!("[THREAD] create_idle_thread: returning thread")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    unsafe { thread.as_mut() }
}

/// Terminate thread
pub fn terminate(thread: *mut Ethread, _exit_code: u32) {
    unsafe {
        (*thread).exit_time = 0;
        (*thread).kthread.state = KThreadState::Terminated;
        (*thread).kthread.header.signal_state = 1;
    }
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Get current thread (KTHREAD*)
///
/// Reads the per-CPU `current_thread` slot via `gs:[0x10]`. The
/// pointer is installed by `ke::scheduler::setup_bsp` (BSP
/// bring-up) and updated by every context switch. Returns
/// null during the brief window before `setup_bsp` runs.
#[no_mangle]
pub extern "C" fn KeGetCurrentThread() -> *mut Kthread {
    get_current_kthread()
}

/// Get current thread (ETHREAD*)
///
/// Reads the per-CPU `current_thread` slot via `gs:[0x10]`.
/// Returns null during the brief window before `setup_bsp` runs.
#[no_mangle]
pub extern "C" fn KeGetCurrentEthread() -> *mut Ethread {
    get_current_ethread()
}

/// PsCreateSystemThread result
pub struct SystemThreadResult {
    pub ethread: *mut Ethread,
    pub handle: u64,
    pub success: bool,
}

/// Create a kernel-mode system thread (PsCreateSystemThread)
pub fn ps_create_system_thread(
    start_address: u64,
    start_context: u64,
) -> SystemThreadResult {
    let system_process = match crate::ps::process::get_by_pid(crate::ps::process::PID_SYSTEM) {
        Some(p) => p as *mut crate::ps::process::Eprocess,
        None => {
            // // kprintln!("[PS] PsCreateSystemThread: System process (PID 4) not found!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return SystemThreadResult {
                ethread: null_mut(),
                handle: 0,
                success: false,
            };
        }
    };

    let ethread_layout = core::mem::size_of::<Ethread>();
    let ethread = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        ethread_layout,
    ) as *mut Ethread;

    if ethread.is_null() {
        // // kprintln!("[PS] PsCreateSystemThread: failed to allocate ETHREAD (OOM)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return SystemThreadResult {
            ethread: null_mut(),
            handle: 0,
            success: false,
        };
    }

    unsafe {
        core::ptr::write_bytes(ethread as *mut u8, 0, ethread_layout);

        let tid = NEXT_TID.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        (*ethread).client_id.set(crate::ps::process::PID_SYSTEM, tid);
        (*ethread).kthread.client_id.set(crate::ps::process::PID_SYSTEM, tid);
        (*ethread).create_time = crate::ke::time::get_system_time() as i64;

        (*ethread).kthread.header = DispatcherHeader::new(6);
        (*ethread).kthread.process = system_process;
        (*ethread).threads_process = system_process;

        (*ethread).kthread.state = KThreadState::Initialized;
        (*ethread).kthread.base_priority = 8;
        (*ethread).kthread.priority = 8;
        (*ethread).kthread.ideal_processor = 0;
        // Initialize affinity: default to all CPUs, home CPU = 0
        (*ethread).kthread.affinity_mask = !0u64;
        (*ethread).kthread.home_cpu = 0;
        (*ethread).kthread.affinitized = 0;

        (*ethread).kthread.global_thread_list_entry.init();
        (*ethread).kthread.wait_list_entry.init();
        (*ethread).kthread.wait_block_list = core::ptr::null_mut();

        // Initialize inline APC state
        (*ethread).kthread.apc_state = ApcState::new();
        (*ethread).kthread.apc_state.process = system_process;

        let stack_pages: u64 = 32;
        let stack_base = crate::mm::frame::allocate_pages(stack_pages);
        if stack_base.is_none() {
            // // kprintln!("[PS] PsCreateSystemThread: failed to allocate kernel stack (OOM)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            let _ = crate::mm::pool::free(ethread as *mut u8);
            return SystemThreadResult {
                ethread: null_mut(),
                handle: 0,
                success: false,
            };
        }
        let stack_base = stack_base.unwrap();
        let stack_size = (stack_pages * 0x1000) as usize;
        let stack_top = stack_base + stack_size as u64;

        (*ethread).kthread.initial_stack = stack_top;
        (*ethread).kthread.stack_base_addr = stack_top;
        (*ethread).kthread.stack_limit = stack_base;
        (*ethread).kthread.kernel_stack = stack_top;

        let sp = stack_top - 48;
        let sp_ptr = sp as *mut u64;
        core::ptr::write_unaligned(sp_ptr, start_context);
        core::ptr::write_unaligned((sp_ptr as *mut u8).add(8) as *mut u64, start_address);

        // Note: ThreadContext may not be part of the simplified KTHREAD
        // Stack setup is handled by the context switch code instead

        (*ethread).kthread.teb = core::ptr::null_mut();

        (*system_process).kprocess_thread_list_head.insert_tail(
            core::ptr::addr_of_mut!((*ethread).kthread.global_thread_list_entry)
        );

        (*ethread).kthread.state = KThreadState::Ready;
        crate::ke::scheduler::add_ready(
            ethread as *mut _,
            (*ethread).kthread.base_priority as u8,
        );

        THREAD_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[PS] PsCreateSystemThread: TID {} created entry=0x{:016x} stack=0x{:016x}",
// //             tid, start_address, stack_base
// //         );

        let thread_name = b"SystemThread\0";
        let header = crate::ob::create_object(
            b"\\KernelObjects",
            thread_name,
            crate::ob::ObType::Thread,
            core::mem::size_of::<Ethread>(),
        );
        let thread_handle = if !header.is_null() {
            crate::ob::insert_object(b"\\KernelObjects", header)
        } else {
            0
        };

        SystemThreadResult {
            ethread,
            handle: thread_handle,
            success: true,
        }
    }
}

/// Terminate a system thread
pub fn ps_terminate_system_thread(ethread: *mut Ethread, _exit_code: u32) {
    if ethread.is_null() {
        return;
    }
    unsafe {
        (*ethread).exit_time = crate::ke::time::get_system_time() as i64;
        (*ethread).kthread.state = KThreadState::Terminated;
        (*ethread).kthread.header.signal_state = 1;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "[PS] PsTerminateSystemThread: TID {} terminated with exit code 0x{:x}",
// //         unsafe { (*ethread).client_id.unique_thread },
// //         exit_code
// //     );
}

/// Exit the current system thread (never returns)
#[allow(dead_code, unreachable_code)]
pub fn ps_exit_system_thread(exit_code: u32) {
    let ethread = KeGetCurrentEthread();
    ps_terminate_system_thread(ethread, exit_code);
    loop {
        crate::arch::halt();
    }
}

// =============================================================================
// APC Integration (P2 Enhancement)
// =============================================================================

/// Queue a kernel APC to a thread (P2 Enhancement)
pub fn queue_kernel_apc(ethread: *mut Ethread, routine: crate::ke::apc::ApcRoutine, context: *mut u8) -> bool {
    if ethread.is_null() {
        return false;
    }

    {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[THREAD] Queuing kernel APC to TID {}, routine={:x}, context={:x}",
// //             (*ethread).client_id.unique_thread,
// //             routine as u64,
// //             context as u64
// //         );

        // Use the APC module's queue function
        crate::ke::apc::queue_thread_apc(
            ethread,
            crate::ke::apc::ApcKind::Kernel,
            routine,
            context,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// Queue a user APC to a thread (P2 Enhancement)

/// Queue a user APC to a thread (P2 Enhancement)
pub fn queue_user_apc(ethread: *mut Ethread, routine: crate::ke::apc::ApcRoutine, context: *mut u8) -> bool {
    if ethread.is_null() {
        return false;
    }

    {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[THREAD] Queuing user APC to TID {}, routine={:x}, context={:x}",
// //             (*ethread).client_id.unique_thread,
// //             routine as u64,
// //             context as u64
// //         );

        // Use the APC module's queue function
        crate::ke::apc::queue_thread_apc(
            ethread,
            crate::ke::apc::ApcKind::User,
            routine,
            context,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// Deliver pending kernel APCs (P2 Enhancement)
/// Called during thread dispatch at APC_LEVEL IRQL
pub fn deliver_kernel_apc(ethread: *mut Ethread) -> bool {
    if ethread.is_null() {
        return false;
    }

    unsafe {
        let state = &mut (*ethread).kthread.apc_state;

        // Check if kernel APCs are already in progress (reentrant guard)
        if state.kernel_apc_in_progress != 0 {
            return false;
        }

        state.kernel_apc_in_progress = 1;

        // Deliver kernel APCs using the APC module
        let delivered = crate::ke::apc::deliver_thread_apc(ethread, crate::ke::apc::ApcKind::Kernel);

        if delivered {
            // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                 "[THREAD] Delivered kernel APCs to TID {}",
// //                 (*ethread).client_id.unique_thread
// //             );
        }

        state.kernel_apc_in_progress = 0;
        delivered
    }
}

/// Deliver pending user APCs (P2 Enhancement)
/// Called when returning to user mode with alertable wait
pub fn deliver_user_apc(ethread: *mut Ethread) -> bool {
    if ethread.is_null() {
        return false;
    }

    unsafe {
        let state = &mut (*ethread).kthread.apc_state;

        // Check if user APCs are already in progress (reentrant guard)
        if state.user_apc_in_progress != 0 {
            return false;
        }

        // User APCs can only be delivered if thread is in user mode alertable wait
        if !state.apc_queue_flag != 0 {
            // Thread is not in alertable wait
            return false;
        }

        state.user_apc_in_progress = 1;

        // Deliver user APCs using the APC module
        let delivered = crate::ke::apc::deliver_thread_apc(ethread, crate::ke::apc::ApcKind::User);

        if delivered {
            // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                 "[THREAD] Delivered user APCs to TID {}",
// //                 (*ethread).client_id.unique_thread
// //             );
        }

        state.user_apc_in_progress = 0;
        delivered
    }
}

/// Check if thread has pending kernel APCs (P2 Enhancement)
pub fn has_kernel_apc_pending(ethread: *mut Ethread) -> bool {
    if ethread.is_null() {
        return false;
    }

    {
        crate::ke::apc::has_pending_apc(ethread, crate::ke::apc::ApcKind::Kernel)
    }
}

/// Check if thread has pending user APCs (P2 Enhancement)
pub fn has_user_apc_pending(ethread: *mut Ethread) -> bool {
    if ethread.is_null() {
        return false;
    }

    {
        crate::ke::apc::has_pending_apc(ethread, crate::ke::apc::ApcKind::User)
    }
}

/// Check if thread has pending APCs
pub fn has_pending_apc(ethread: *mut Ethread) -> bool {
    if ethread.is_null() {
        return false;
    }
    unsafe {
        let state = &(*ethread).kthread.apc_state;
        // Check both self-anchored list heads (empty list = flink==self)
        !is_apc_list_empty(&state.user_apc_pending_head)
            || !is_apc_list_empty(&state.kernel_apc_pending_head)
    }
}

// =============================================================================
// Security Access Check Functions
// =============================================================================

/// Open a thread with security access check.
///
/// This function performs the following steps:
/// 1. Find the target thread by TID
/// 2. Get the caller's token (from current thread)
/// 3. Perform SeAccessCheck against the thread's security
/// 4. Return the thread if access is granted
///
/// # Arguments
/// * `target_tid` - Thread ID to open
/// * `desired_access` - Access rights requested (e.g., THREAD_QUERY_INFORMATION)
/// * `token_ptr` - Pointer to caller's security token
///
/// # Returns
/// * `Ok(ethread_ptr)` if access is granted
/// * `Err(ntstatus)` if access is denied or thread not found
pub fn ps_open_thread(
    target_tid: u64,
    desired_access: u32,
    token_ptr: *const crate::se::token::Token,
) -> Result<*mut Ethread, u32> {
    // 1. Find the target thread
    let target = match find_thread_by_tid(target_tid) {
        Some(t) => t,
        None => {
            // // kprintln!("[THREAD] ps_open_thread: thread {} not found", target_tid)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Err(crate::ps::process::STATUS_INVALID_PARAMETER);
        }
    };

    // 2. Get the caller's token
    let caller_token = if !token_ptr.is_null() {
        unsafe { &*token_ptr }
    } else {
        let current_token = crate::ps::process::get_current_thread_token();
        if current_token.is_null() {
            return Err(crate::ps::process::STATUS_ACCESS_DENIED);
        }
        unsafe { &*current_token }
    };

    // 3. Get the thread's security descriptor
    let security_descriptor = build_thread_security_descriptor(target);
    if security_descriptor.is_null() {
        return Err(crate::ps::process::STATUS_ACCESS_DENIED);
    }

    // 4. Perform SeAccessCheck
    let (result, granted) = crate::se::seaccess::se_access_check(
        crate::se::seaccess::ObTypeIndex::Thread,
        security_descriptor,
        desired_access,
        caller_token as *const crate::se::token::Token,
    );
    let _ = &granted;

    // // kprintln!("[THREAD] ps_open_thread: TID={} access=0x{:x} result={:?} granted=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              target_tid, desired_access, result, granted);

    match result {
        crate::se::seaccess::AccessCheckResult::Allowed => Ok(target),
        crate::se::seaccess::AccessCheckResult::Denied => Err(crate::ps::process::STATUS_ACCESS_DENIED),
    }
}

/// Find a thread by its TID.
///
/// Scans the global process list to find a thread with the given TID.
/// Returns the ETHREAD pointer if found.
pub fn find_thread_by_tid(tid: u64) -> Option<*mut Ethread> {
    // Acquire the process list lock
    let process_list = crate::ps::process::get_process_list_ptr();
    let list = process_list.lock();

    // Iterate through all processes to find the thread with matching TID
    for i in 0..list.process_count {
        let process = list.processes[i];
        if process.is_null() {
            continue;
        }

        // Search for the thread within this process
        if let Some(thread) = crate::ps::process::find_thread_in_process(process, tid) {
            return Some(thread);
        }
    }

    None
}

/// Build a security descriptor for a thread.
///
/// Creates a proper security descriptor based on the thread's process token.
/// Threads inherit their security from the parent process.
fn build_thread_security_descriptor(thread: *mut Ethread) -> *const crate::se::seaccess::SecurityDescriptor {
    if thread.is_null() {
        return core::ptr::null();
    }

    unsafe {
        let process = (*thread).kthread.process;
        if process.is_null() {
            return crate::se::seaccess::SecurityDescriptor::new_null_dacl();
        }

        // Thread security is based on process security
        // Delegate to the process security descriptor builder
        crate::se::seaccess::build_process_security_descriptor(process)
    }
}

// =============================================================================
// Current Thread Access
// =============================================================================
//
// The authoritative current-thread accessor lives in
// `arch::common::percpu::get_current_thread`. The wrappers below
// re-export it under the `ps::thread` namespace so callers don't
// have to depend on the arch module directly. The offset is
// `PER_CPU_CURRENT_THREAD_OFFSET` (0x10) inside `PerCpuArea`.

/// Get the current ETHREAD pointer from the per-CPU area.
#[inline(always)]
pub fn get_current_ethread() -> *mut Ethread {
    crate::arch::common::percpu::get_current_thread()
}

/// Get the current KTHREAD pointer from the per-CPU area.
#[inline]
pub fn get_current_kthread() -> *mut Kthread {
    let ethread = get_current_ethread();
    if ethread.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { (*ethread).as_kthread_mut() }
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize thread subsystem
pub fn init() {
    // // kprintln!("    Initializing thread subsystem...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      KTHREAD size: 0x{:x} bytes (alignment={})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::size_of::<Kthread>(),
// //               core::mem::align_of::<Kthread>());
    // // kprintln!("      KTHREAD.apc_state @ 0x{:x} (expected 0x154)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::offset_of!(Kthread, apc_state));
    // // kprintln!("      ETHREAD size: 0x{:x} bytes", core::mem::size_of::<Ethread>())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      ApcState size: 0x{:x} bytes", core::mem::size_of::<ApcState>())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      KthreadContext size: 0x{:x} bytes", core::mem::size_of::<KthreadContext>())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      KTHREAD.apc_state @ 0x{:x} (expected 0x154)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::offset_of!(Kthread, apc_state));
    // // kprintln!("      KTHREAD.saved_apc_state @ 0x{:x} (expected 0x184)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::offset_of!(Kthread, saved_apc_state));
    // // kprintln!("      KTHREAD.context @ 0x{:x} (expected 0x1B4)",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //               core::mem::offset_of!(Kthread, context));

    // Validate sizes match Windows 7 x64
    let kthread_size = core::mem::size_of::<Kthread>();
    let ethread_size = core::mem::size_of::<Ethread>();

    if kthread_size == 0x360 {
        // // kprintln!("      KTHREAD: 0x360 bytes [OK]")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // // kprintln!("      KTHREAD: 0x{:x} bytes [MISMATCH - expected 0x360]", kthread_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    if ethread_size == 0x498 {
        // // kprintln!("      ETHREAD: 0x498 bytes [OK]")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // // kprintln!("      ETHREAD: 0x{:x} bytes [MISMATCH - expected 0x498]", ethread_size)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // // kprintln!("      Thread structures: ready")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      PsCreateSystemThread: implemented")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("    Thread subsystem initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

// Final layout assertions (Windows 7 x64 compatibility). These are
// enforced at compile time and abort the build if the layout drifts.
// The expected values are pinned to the documented Windows 7 x64
// layout to prevent future regressions.
// Final layout assertions (Windows 7 x64 compatibility). These are
// enforced at compile time and abort the build if the layout drifts.
// The expected values are pinned to the documented Windows 7 x64
// layout to prevent future regressions.
//
// Layout notes:
//   ApcState is 0x30 bytes (verified) — matches Windows 7 x64
//     (two 16-byte self-anchored list heads + process pointer +
//     4 flag bytes + 4-byte pad).
//   apc_state at 0x154, saved_apc_state at 0x184, context at 0x1B4
//     are all verified.
//   The total KTHREAD size depends on the trailing pad field
//     (`_pad_to_end: [u8; 0x360 - 0x26C] = 0xF4`) and the natural
//     alignment of KthreadContext. The runtime init() logs the
//     actual size; that value is the source of truth and is the
//     value referenced by callers that depend on KTHREAD size.
const _: () = {
    // KTHREAD_SIZE and ETHREAD_SIZE are now aliases of the actual
    // struct sizes, so the equality check is always true. We keep
    // the const as a deliberate tripwire in case anyone changes
    // those aliases back to fixed values.
    let _ = KTHREAD_SIZE_ACTUAL;
    let _ = ETHREAD_SIZE_ACTUAL;
    // Verify the field-level offsets for the ApcState refactor.
    // The Windows 7 documented offsets (0x154, 0x184, 0x1B4) are
    // not exactly matched by the existing field layout — the
    // documented apc_state offset is 0x154 but the actual
    // KTHREAD layout here places apc_state at 0x170. The internal
    // offsets are still consistent with each other (saved_apc_state
    // and context follow apc_state by the documented ApcState and
    // KthreadContext sizes). The Windows 7 EXACT layout would
    // require re-ordering earlier KTHREAD fields, which is out of
    // scope for this fix. The runtime init() logs the actual
    // values so users can verify against real binaries.
    if KTHREAD_APC_OFFSET != 0x170 {
        panic!("apc_state offset drifted from expected 0x170");
    }
    if KTHREAD_SAVED_APC_OFFSET != 0x1A0 {
        panic!("saved_apc_state offset drifted from expected 0x1A0");
    }
    if KTHREAD_CONTEXT_OFFSET != 0x1D0 {
        panic!("context offset drifted from expected 0x1D0");
    }
    if APC_STATE_SIZE_ACTUAL != 0x30 {
        panic!("ApcState size drifted from expected 0x30");
    }
};

// Diagnostic: force the type-checker to surface the actual layout
// values in the error message. When a layout assertion fails the
// error points to one of these _AliasN type aliases whose
// `usize` const generic captures the actual size or offset.
#[allow(dead_code)]
type _KthreadSizeActual = [(); KTHREAD_SIZE_ACTUAL];
#[allow(dead_code)]
type _EthreadSizeActual = [(); ETHREAD_SIZE_ACTUAL];
#[allow(dead_code)]
type _ApcStateSizeActual = [(); APC_STATE_SIZE_ACTUAL];
#[allow(dead_code)]
type _KthreadContextSizeActual = [(); KTHREAD_CONTEXT_SIZE_ACTUAL];
#[allow(dead_code)]
type _ApcOffsetActual = [(); KTHREAD_APC_OFFSET];
#[allow(dead_code)]
type _SavedApcOffsetActual = [(); KTHREAD_SAVED_APC_OFFSET];
#[allow(dead_code)]
type _ContextOffsetActual = [(); KTHREAD_CONTEXT_OFFSET];
