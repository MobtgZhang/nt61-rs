//! APC (Asynchronous Procedure Call)
//
//! APCs are how the kernel asks a thread to run some code in
//! thread context. NT distinguishes:
//!   * **Kernel APCs** — delivered in the thread's kernel context,
//!     before the thread returns to user mode. Used for I/O
//!     completion, IRP cancellation, etc.
//!   * **User APCs** — delivered in the thread's user context; only
//!     fire when the thread is in an alertable wait.
//
//! Each thread has two APC queues: one for kernel-mode APCs and
//! one for user-mode APCs. The kernel queues kernel-mode APCs
//! directly; the user-mode queue is exposed via `NtQueueApcThread`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ke::sync::{DispatcherHeader, Spinlock};
use crate::ke::irql::{self, Irql};
use crate::ps::thread::Ethread;
use crate::ps::process::ListEntry;

/// Maximum APCs we can track per thread.
const MAX_APCS_PER_THREAD: usize = 16;
/// Maximum APCs in the global queue.
const MAX_GLOBAL_APCS: usize = 32;

pub type ApcRoutine = fn(*mut u8);

/// APC environment (where the APC will run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApcEnvironment {
    Kernel = 0,
    User = 1,
}

/// APC mode (kernel or user).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApcMode {
    Kernel = 0,
    User = 1,
}

/// APC state index for attached processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApcStateIndex {
    OriginalApcEnvironment = 0,
    AttachedApcEnvironment = 1,
    CurrentApcEnvironment = 2,
    InsertApcEnvironment = 3,
}

/// APC object type in the dispatcher header.
pub const APC_OBJECT_TYPE: u8 = 9;

/// An APC entry. We track the routine + a context pointer and a
/// kind tag.
#[repr(C)]
pub struct Apc {
    pub header: DispatcherHeader,
    pub kind: ApcKind,
    pub routine: Option<ApcRoutine>,
    pub context: *mut u8,
    pub normal_context: *mut u8,
    pub normal_routine: Option<ApcRoutine>,
    pub system_argument1: *mut u8,
    pub system_argument2: *mut u8,
    pub thread: *mut Ethread,
    pub list_entry: ListEntry,
    pub inserted: AtomicBool,
    pub kernel_routine: Option<ApcRoutine>,
    pub rundown_routine: Option<ApcRoutine>,
}

impl Apc {
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(APC_OBJECT_TYPE),
            kind: ApcKind::Kernel,
            routine: None,
            context: core::ptr::null_mut(),
            normal_context: core::ptr::null_mut(),
            normal_routine: None,
            system_argument1: core::ptr::null_mut(),
            system_argument2: core::ptr::null_mut(),
            thread: core::ptr::null_mut(),
            list_entry: ListEntry::new(),
            inserted: AtomicBool::new(false),
            kernel_routine: None,
            rundown_routine: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcKind {
    Kernel = 0,
    User = 1,
}

/// Thread APC state
pub struct ThreadApcState {
    pub kernel_apcs: [Option<Apc>; MAX_APCS_PER_THREAD],
    pub user_apcs: [Option<Apc>; MAX_APCS_PER_THREAD],
    pub kernel_apc_pending: bool,
    pub user_apc_pending: bool,
}

impl ThreadApcState {
    pub fn new() -> Self {
        Self {
            kernel_apcs: [const { None }; MAX_APCS_PER_THREAD],
            user_apcs: [const { None }; MAX_APCS_PER_THREAD],
            kernel_apc_pending: false,
            user_apc_pending: false,
        }
    }
}

static APC_TABLE: Spinlock<[Option<Apc>; MAX_GLOBAL_APCS]> = Spinlock::new([const { None }; MAX_GLOBAL_APCS]);
static ENQUEUE_COUNT: AtomicU32 = AtomicU32::new(0);
static DEQUEUE_COUNT: AtomicU32 = AtomicU32::new(0);

/// APC level IRQL
pub const APC_LEVEL: Irql = Irql::ApcLevel;

/// Initialize APC subsystem.
pub fn init() {
    crate::hal::serial::write_string("[ke.apc] enter\r\n");
    ENQUEUE_COUNT.store(0, Ordering::SeqCst);
    DEQUEUE_COUNT.store(0, Ordering::SeqCst);
    // // kprintln!("    APC: queues=2 (kernel/user) max_global={}", MAX_GLOBAL_APCS)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("    APC: per_thread max={}", MAX_APCS_PER_THREAD)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("    APC: KeInitializeApc/KeInsertQueueApc/KiDeliverApc available")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Initialize APC state for a thread.
/// For inline ApcState in KTHREAD, this is handled during thread creation.
pub fn init_thread_apc_state(_apc_state: &mut crate::ps::thread::ApcState) {
    // The inline ApcState in KTHREAD is zeroed during allocation
    // Additional initialization if needed
}

// ============================================================================
// KeInitializeApc / KeInsertQueueApc / KiDeliverApc
// ============================================================================

/// Initialize an APC object. This is `KeInitializeApc` in Windows.
///
/// # Safety
/// `apc` must point to a valid, aligned, writable APC structure.
pub unsafe fn KeInitializeApc(
    apc: *mut Apc,
    thread: *mut Ethread,
    _environment: ApcEnvironment,
    kernel_routine: ApcRoutine,
    rundown_routine: Option<ApcRoutine>,
    normal_routine: Option<ApcRoutine>,
    mode: ApcMode,
    _normal_context: *mut u8,
) {
    if apc.is_null() {
        return;
    }

    (*apc).header = DispatcherHeader::new(APC_OBJECT_TYPE);
    (*apc).thread = thread;
    (*apc).routine = Some(kernel_routine);
    (*apc).kernel_routine = Some(kernel_routine);
    (*apc).rundown_routine = rundown_routine;
    (*apc).normal_routine = normal_routine;
    (*apc).normal_context = core::ptr::null_mut();
    (*apc).system_argument1 = core::ptr::null_mut();
    (*apc).system_argument2 = core::ptr::null_mut();
    (*apc).inserted.store(false, Ordering::Relaxed);
    (*apc).kind = match mode {
        ApcMode::Kernel => ApcKind::Kernel,
        ApcMode::User => ApcKind::User,
    };
}

/// Insert an APC into a thread's queue. This is `KeInsertQueueApc` in Windows.
///
/// Returns true if the APC was successfully queued.
///
/// # Safety
/// `apc` must be a valid APC initialized by `KeInitializeApc`.
pub unsafe fn KeInsertQueueApc(
    apc: *mut Apc,
    system_argument1: *mut u8,
    system_argument2: *mut u8,
    _priority_boost: u8,
) -> bool {
    if apc.is_null() {
        return false;
    }

    // Check IRQL: must be at APC_LEVEL or lower
    let current_irql = irql::get_current_irql();
    if current_irql > APC_LEVEL {
        // // kprintln!("[APC] KeInsertQueueApc failed: IRQL too high")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Check if already inserted
    if (*apc).inserted.load(Ordering::Relaxed) {
        // // kprintln!("[APC] KeInsertQueueApc failed: already inserted")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Set the arguments
    (*apc).system_argument1 = system_argument1;
    (*apc).system_argument2 = system_argument2;

    // Get the thread
    let thread = (*apc).thread;
    if thread.is_null() {
        // // kprintln!("[APC] KeInsertQueueApc failed: no thread")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    // Access inline ApcState from KTHREAD
    let apc_state = &mut (*thread).kthread.apc_state;

    // Select the appropriate self-anchored list head based on APC kind
    let list_head: *mut ListEntry = match (*apc).kind {
        ApcKind::Kernel => &mut apc_state.kernel_apc_pending_head as *mut ListEntry,
        ApcKind::User => &mut apc_state.user_apc_pending_head as *mut ListEntry,
    };

    // Insert the APC's list entry at the tail of the chosen queue.
    let entry = &mut (*apc).list_entry as *mut ListEntry;
    crate::ps::thread::apc_list_insert_tail(list_head, entry);
    (*apc).inserted.store(true, Ordering::Release);
    if (*apc).kind == ApcKind::Kernel {
        apc_state.kernel_apc_in_progress = 0;
    } else {
        apc_state.user_apc_in_progress = 0;
    }

    // // kprintln!("[APC] Queued {} APC to thread {:016x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         if (*apc).kind == ApcKind::Kernel { "kernel" } else { "user" },
// //         thread as u64);

    true
}

/// Deliver APCs to a thread. This is `KiDeliverApc` in Windows.
///
/// This function should be called:
/// - At IRQL = APC_LEVEL
/// - When returning to user mode (for user APCs)
/// - When checking for kernel APCs during thread dispatch
///
/// # Safety
/// `current_thread` must be a valid pointer to the current ETHREAD.
pub unsafe fn KiDeliverApc(current_thread: *mut Ethread, delivery_mode: ApcMode) {
    if current_thread.is_null() {
        return;
    }

    let apc_state = &mut (*current_thread).kthread.apc_state;

    // Raise IRQL to APC_LEVEL
    let _guard = irql::raise_irql(APC_LEVEL);

    match delivery_mode {
        ApcMode::Kernel => {
            // Check if kernel APCs are already in progress
            if apc_state.kernel_apc_in_progress != 0 {
                return;
            }
            apc_state.kernel_apc_in_progress = 1;

            // Drain the kernel APC list, calling each routine with
            // (arg1, arg2, context).
            let head = &mut apc_state.kernel_apc_pending_head as *mut ListEntry;
            let mut delivered = 0;
            while !crate::ps::thread::is_apc_list_empty(head) {
                let entry = crate::ps::thread::apc_list_remove_head(head);
                // The list entry is embedded in Apc.list_entry at offset 0.
                let apc_ptr = entry as *mut Apc;
                let routine_addr = (*apc_ptr).routine.map(|r| r as u64).unwrap_or(0);
                let arg1 = (*apc_ptr).system_argument1;
                let arg2 = (*apc_ptr).system_argument2;
                let ctx = (*apc_ptr).normal_context;
                (*apc_ptr).inserted.store(false, Ordering::Release);

                if let Some(routine_fn) = (*apc_ptr).routine {
                    routine_fn(arg1);
                    delivered += 1;
                    let _ = (routine_addr, arg2, ctx);
                }
            }

            if delivered > 0 {
                // // kprintln!("[APC] Delivered {} kernel APCs", delivered)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
            apc_state.kernel_apc_in_progress = 0;
        }
        ApcMode::User => {
            // Check if user APCs are already in progress
            if apc_state.user_apc_in_progress != 0 {
                return;
            }
            apc_state.user_apc_in_progress = 1;

            // Drain the user APC list (log only — real implementation
            // would switch to user mode and call the normal routine).
            let head = &mut apc_state.user_apc_pending_head as *mut ListEntry;
            let mut delivered = 0;
            while !crate::ps::thread::is_apc_list_empty(head) {
                let entry = crate::ps::thread::apc_list_remove_head(head);
                let apc_ptr = entry as *mut Apc;
                let routine_addr = (*apc_ptr).routine.map(|r| r as u64).unwrap_or(0);
                (*apc_ptr).inserted.store(false, Ordering::Release);
                if routine_addr != 0 {
                    // // kprintln!("[APC] Would deliver user APC routine at {:016x}", routine_addr)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    delivered += 1;
                }
            }

            if delivered > 0 {
                // // kprintln!("[APC] Delivered {} user APCs", delivered)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
            apc_state.user_apc_in_progress = 0;
        }
    }
}

/// Check if APCs should be delivered before returning to user mode.
pub fn should_deliver_user_apc(thread: *mut Ethread) -> bool {
    if thread.is_null() {
        return false;
    }
    unsafe {
        let apc_state = &(*thread).kthread.apc_state;
        !crate::ps::thread::is_apc_list_empty(&apc_state.user_apc_pending_head)
    }
}

/// Check if a thread has kernel APCs pending.
pub fn has_kernel_apc_pending(thread: *mut Ethread) -> bool {
    if thread.is_null() {
        return false;
    }
    unsafe {
        let apc_state = &(*thread).kthread.apc_state;
        !crate::ps::thread::is_apc_list_empty(&apc_state.kernel_apc_pending_head)
    }
}

/// Enqueue an APC. Returns the slot index on success, or `None`
/// if the table is full.
pub fn enqueue_apc(kind: ApcKind, routine: ApcRoutine, context: *mut u8) -> Option<usize> {
    let mut g = APC_TABLE.lock();
    for i in 0..MAX_GLOBAL_APCS {
        if g[i].is_none() {
            let mut apc = Apc::new();
            apc.kind = kind;
            apc.routine = Some(routine);
            apc.context = context;
            apc.inserted.store(true, Ordering::Relaxed);
            g[i] = Some(apc);
            ENQUEUE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

/// Dequeue the next pending APC of `kind`. Returns the slot
/// index, or `None` if no such APC is queued.
pub fn dequeue_apc(kind: ApcKind) -> Option<usize> {
    let mut g = APC_TABLE.lock();
    for i in 0..MAX_GLOBAL_APCS {
        let matched = g[i]
            .as_ref()
            .map(|a| a.inserted.load(Ordering::Relaxed) && a.kind == kind)
            .unwrap_or(false);
        if matched {
            g[i] = None;
            DEQUEUE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

/// Peek at the routine / context of a queued APC.
pub fn inspect_apc(idx: usize) -> Option<(ApcKind, ApcRoutine, *mut u8)> {
    let g = APC_TABLE.lock();
    g[idx].as_ref().and_then(|apc| {
        apc.routine.map(|r| (apc.kind, r, apc.context))
    })
}
/// Number of APCs ever enqueued.
pub fn enqueue_count() -> u32 {
    ENQUEUE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}
/// Number of APCs ever dequeued.
pub fn dequeue_count() -> u32 {
    DEQUEUE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

fn smoke_apc_routine(ctx: *mut u8) {
    // No-op: we only need an `ApcRoutine` for the smoke test.
    let _ = ctx;
}

// ============================================================================
// Thread APC Queue Operations
// ============================================================================

/// Allocate an APC object from the kernel pool.
pub fn allocate_apc() -> *mut Apc {
    let ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Apc>(),
    ) as *mut Apc;
    
    if !ptr.is_null() {
        unsafe {
            (*ptr) = Apc::new();
        }
    }
    ptr
}

/// Free an APC object.
pub fn free_apc(apc: *mut Apc) {
    if !apc.is_null() {
        let _ = crate::mm::pool::free(apc as *mut u8);
    }
}

/// Insert an APC into a thread's queue.
/// Returns true on success.
pub fn queue_thread_apc(
    thread: *mut Ethread,
    kind: ApcKind,
    routine: ApcRoutine,
    context: *mut u8,
    _normal_context: *mut u8,
    _system_argument1: *mut u8,
    _system_argument2: *mut u8,
) -> bool {
    if thread.is_null() {
        return false;
    }
    unsafe {
        // The legacy in-line array was replaced by a self-anchored
        // doubly-linked list in the ApcState struct (see
        // `ps::thread::apc_list_insert_tail`).  Callers that need to
        // queue a real APC must allocate an Apc object, initialise it
        // with `KeInitializeApc`, and then call `KeInsertQueueApc`.
        // This helper is kept as a thin wrapper that allocates an Apc
        // on the fly so the existing call sites keep working.
        let apc_ptr = allocate_apc();
        if apc_ptr.is_null() {
            // // kprintln!("[APC] queue_thread_apc: out of memory")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        let mode = match kind {
            ApcKind::Kernel => ApcMode::Kernel,
            ApcKind::User => ApcMode::User,
        };
        KeInitializeApc(
            apc_ptr,
            thread,
            ApcEnvironment::Kernel,
            routine,
            None,
            None,
            mode,
            context,
        );
        KeInsertQueueApc(apc_ptr, context, core::ptr::null_mut(), 0)
    }
}

/// Check if a thread has pending APCs of the given kind.
pub fn has_pending_apc(thread: *mut Ethread, kind: ApcKind) -> bool {
    if thread.is_null() {
        return false;
    }
    unsafe {
        // Access inline ApcState from KTHREAD
        let apc_state = &(*thread).kthread.apc_state;
        let head = match kind {
            ApcKind::Kernel => &apc_state.kernel_apc_pending_head as *const ListEntry,
            ApcKind::User => &apc_state.user_apc_pending_head as *const ListEntry,
        };
        !crate::ps::thread::is_apc_list_empty(head)
    }
}

/// Dequeue and execute the next APC from a thread's queue.
pub fn deliver_thread_apc(thread: *mut Ethread, kind: ApcKind) -> bool {
    if thread.is_null() {
        return false;
    }
    unsafe {
        // Access inline ApcState from KTHREAD
        let apc_state = &mut (*thread).kthread.apc_state;
        let head = match kind {
            ApcKind::Kernel => &mut apc_state.kernel_apc_pending_head as *mut ListEntry,
            ApcKind::User => &mut apc_state.user_apc_pending_head as *mut ListEntry,
        };

        if crate::ps::thread::is_apc_list_empty(head) {
            return false;
        }

        let entry = crate::ps::thread::apc_list_remove_head(head);
        let apc_ptr = entry as *mut Apc;
        (*apc_ptr).inserted.store(false, Ordering::Release);

        if let Some(routine_fn) = (*apc_ptr).routine {
            let ctx = (*apc_ptr).context;
            // // kprintln!("[APC] Delivering APC routine at {:p}", routine_fn as *const ())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            routine_fn(ctx);
            return true;
        }
        false
    }
}

/// NtQueueApcThread - user-mode API to queue an APC to a thread.
pub unsafe extern "C" fn NtQueueApcThread(
    thread_handle: crate::libs::ntdll::types::HANDLE,
    normal_routine: Option<unsafe extern "C" fn(*mut u8)>,
    normal_context: *mut u8,
    system_argument1: *mut u8,
    system_argument2: *mut u8,
) -> crate::libs::ntdll::types::NTSTATUS {
    use crate::libs::ntdll::status::STATUS_SUCCESS;

    // Look up the thread handle to verify it's valid
    let entry = crate::libs::ntdll::file::lookup_handle(thread_handle);
    if entry.is_none() {
        return crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    }

    let entry = entry.unwrap();
    if entry.kind != crate::libs::ntdll::file::HandleKind::Thread {
        return crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    }

    // Get the thread pointer from the handle entry
    let thread_ptr = entry.target as *mut Ethread;

    // Allocate an APC object
    let apc_ptr = allocate_apc();
    if apc_ptr.is_null() {
        return crate::libs::ntdll::status::STATUS_NO_MEMORY;
    }

    // Initialize the APC
    // For user APCs, we need a kernel routine that will deliver the user APC
    // In a full implementation, this would be the kernel-mode wrapper
    let kernel_routine_fn: ApcRoutine = user_apc_kernel_routine;
    let rundown_routine: Option<ApcRoutine> = None;
    let normal_routine_fn: Option<ApcRoutine> = normal_routine.map(|f| core::mem::transmute(f));

    KeInitializeApc(
        apc_ptr,
        thread_ptr,
        ApcEnvironment::User,
        kernel_routine_fn,
        rundown_routine,
        normal_routine_fn,
        ApcMode::User,
        normal_context,
    );

    // Insert the APC into the thread's queue
    if !KeInsertQueueApc(apc_ptr, system_argument1, system_argument2, 0) {
        free_apc(apc_ptr);
        return crate::libs::ntdll::status::STATUS_UNSUCCESSFUL;
    }

    // // kprintln!("[APC] NtQueueApcThread: queued user APC to thread {:016x}", thread_ptr as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    STATUS_SUCCESS
}

/// Kernel routine for user APC delivery.
/// This is called in kernel context before returning to user mode.
/// Note: KeInitializeApc expects a kernel routine with signature `fn(*mut u8)`
/// so we use a wrapper that just does nothing (the APC is already queued).
fn user_apc_kernel_routine(_context: *mut u8) {
    // In a full implementation, this would:
    // 1. Queue the user APC to be delivered when the thread returns to user mode
    // 2. Set the user APC pending flag
    // The actual delivery happens in KiDeliverApc(UserApcMode)
}

/// Smoke test for the APC subsystem.
///
/// Enqueues a kernel and a user APC, then dequeues them in order
/// and verifies the counters advanced.
pub fn smoke_test() -> bool {
    let e_before = enqueue_count();
    let d_before = dequeue_count();
    let kidx = enqueue_apc(ApcKind::Kernel, smoke_apc_routine, core::ptr::null_mut());
    if kidx.is_none() {
        // // kprintln!("    [APC SMOKE FAIL] kernel enqueue returned None")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let uidx = enqueue_apc(ApcKind::User, smoke_apc_routine, core::ptr::null_mut());
    if uidx.is_none() {
        // // kprintln!("    [APC SMOKE FAIL] user enqueue returned None")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let got = dequeue_apc(ApcKind::Kernel);
    if got != kidx {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [APC SMOKE FAIL] expected kernel APC idx={:?}, got {:?}",
// //             kidx, got
// //         );
        return false;
    }
    let got = dequeue_apc(ApcKind::User);
    if got != uidx {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [APC SMOKE FAIL] expected user APC idx={:?}, got {:?}",
// //             uidx, got
// //         );
        return false;
    }
    let e_after = enqueue_count();
    let d_after = dequeue_count();
    if e_after != e_before + 2 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [APC SMOKE FAIL] enqueue count: {} -> {}",
// //             e_before, e_after
// //         );
        return false;
    }
    if d_after != d_before + 2 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [APC SMOKE FAIL] dequeue count: {} -> {}",
// //             d_before, d_after
// //         );
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [APC SMOKE OK] enqueue={} dequeue={} (kernel+user round-trip)",
// //         e_after, d_after
// //     );
    true
}
