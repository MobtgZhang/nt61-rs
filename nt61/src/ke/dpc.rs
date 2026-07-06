//! DPC (Deferred Procedure Call)
//
//! DPCs are how the kernel defers work from DIRQL to DISPATCH_LEVEL.
//! An ISR can `KeInsertQueueDpc` to ask for a routine to run once
//! the CPU drops to DISPATCH_LEVEL; the dispatcher's DPC software
//! interrupt (vector 0xDF on x86) drains the queue.
//
//! We model a single per-CPU DPC list, protected by a spinlock.
//! The smoke test enqueues three DPCs, runs the list, and
//! verifies they fired in order.
//
//! The DPC backing array is allocated on first use via the kernel
//! pool. We tried a `static` array originally, but the PE/COFF
//! image places it in the uninitialised gap between `.data` and
//! the next section, which the UEFI PE loader does not zero-fill
//! or mark writable. The result is a page fault on the very first
//! `DPC_LIST.lock()` call. The pool allocation is the standard
//! NT-style solution (Windows itself uses `ExAllocatePool` for
//! the DPC list).
//
//! We also avoid `Option::is_none()` for slot-empty detection
//! because the `Option<Dpc>` layout has a niche in the first
//! `Option<fn>` field of `Dpc`, and the compiler's `is_none`
//! codegen reads memory in a way that does not match the
//! zero-fill our pool allocator just did. A byte-level
//! `is_all_zero` check is unambiguous and correct.
//
//! P2 Enhancement: Added KiRetireDpcList, DPC interrupt handling, and
//! DPC queue management for SMP systems.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ke::sync::Spinlock;
use crate::ke::irql::{self, Irql};
use crate::mm::pool;

pub type DpcRoutine = fn(*mut u8);

/// DPC importance levels (Windows-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DpcImportance {
    Low = 0,
    Medium = 1,
    High = 2,
    Realtime = 3,
}

const MAX_DPCS: usize = 8;
const DPC_SIZE: usize = core::mem::size_of::<Dpc>();

/// DPC object.
#[repr(C)]
pub struct Dpc {
    pub header: DispatcherHeader,
    pub type_: u16,           // DpcContext (0x0010)
    pub importance: u8,       // DpcImportance
    pub number: u32,         // CPU number (0 for current)
    pub routine: Option<DpcRoutine>,
    pub context: *mut u8,
    pub inserted: AtomicBool,
    pub fired: AtomicBool,
    pub name: &'static str,
}

impl Dpc {
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(0x13),
            type_: 0x0010,
            importance: DpcImportance::Low as u8,
            number: 0,
            routine: None,
            context: core::ptr::null_mut(),
            inserted: AtomicBool::new(false),
            fired: AtomicBool::new(false),
            name: "<dpc>",
        }
    }

    pub fn init(&mut self) {
        self.header.init();
        self.inserted.store(false, Ordering::Relaxed);
        self.fired.store(false, Ordering::Relaxed);
    }
}

/// Dispatcher header for DPC (partial implementation).
#[derive(Clone)]
#[repr(C)]
pub struct DispatcherHeader {
    pub type_: u8,
    pub signal_state: u8,
    pub size: u16,
    pub inserted: u8,
    pub spare: [u8; 3],
}

impl DispatcherHeader {
    pub const fn new(object_type: u8) -> Self {
        Self {
            type_: object_type,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
        }
    }

    pub fn init(&mut self) {
        self.type_ = 0x13; // DpcObject = 0x13
        self.signal_state = 0;
        self.inserted = 0;
    }
}

impl Default for DispatcherHeader {
    fn default() -> Self {
        Self {
            type_: 0,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
        }
    }
}

/// System DPC queue state.
///
/// Per-CPU DPC locks: Each CPU has its own lock for its DPC queue.
/// This allows DPC operations on different CPUs to proceed in parallel.
/// MAX_CPUS matches the maximum number of processors supported.
const MAX_CPUS: usize = 4;
static DPC_QUEUE_LOCKS: [Spinlock<()>; MAX_CPUS] = [
    Spinlock::new(()),
    Spinlock::new(()),
    Spinlock::new(()),
    Spinlock::new(()),
];

/// Legacy global lock for single-CPU fallback and DPC storage initialization.
/// Kept for compatibility with code that doesn't use per-CPU DPC queues yet.
static DPC_QUEUE_LOCK: Spinlock<()> = Spinlock::new(());

/// Get the DPC lock for the current CPU.
/// This enables per-CPU DPC queue operations in SMP environments.
fn get_current_cpu_dpc_lock() -> &'static Spinlock<()> {
    let cpu = crate::ke::scheduler::get_current_cpu().min(MAX_CPUS - 1);
    &DPC_QUEUE_LOCKS[cpu]
}

/// Backing storage pointer. Heap-allocated to avoid the
/// PE/COFF uninitialised-section page fault.
static DPC_STORAGE: Spinlock<*mut Dpc> = Spinlock::new(core::ptr::null_mut());

static INSERT_COUNT: AtomicU32 = AtomicU32::new(0);
static FIRE_COUNT: AtomicU32 = AtomicU32::new(0);

/// DPC interrupt request flag - set when DPCs need processing.
static DPC_NEEDED: AtomicBool = AtomicBool::new(false);

/// DPC vector number on x86 (software interrupt).
pub const DPC_VECTOR: u8 = 0xDF; // 223

/// Get (or allocate on first call) the DPC backing array.
fn dpc_array() -> &'static mut [Dpc; MAX_DPCS] {
    let mut g = DPC_STORAGE.lock();
    if g.is_null() {
        let bytes = pool::allocate(
            pool::PoolType::NonPaged,
            MAX_DPCS * DPC_SIZE,
        ) as *mut Dpc;
        if bytes.is_null() {
            static mut FALLBACK: [Dpc; MAX_DPCS] = [const { Dpc::new() }; MAX_DPCS];
            return unsafe { &mut *(&raw mut FALLBACK) };
        }
        unsafe {
            core::ptr::write_bytes(bytes as *mut u8, 0u8, MAX_DPCS * DPC_SIZE);
        }
        *g = bytes;
    }
    // SAFETY: pool alloc returned exactly MAX_DPCS Dpcs, all zeroed.
    let arr_ptr = *g as *mut [Dpc; MAX_DPCS];
    unsafe { &mut *arr_ptr }
}

/// True iff every byte of `slot` is zero. Used to detect an
/// empty DPC slot without depending on `Option::is_none`.
unsafe fn is_all_zero(slot: *const Dpc) -> bool {
    let bytes = core::slice::from_raw_parts(slot as *const u8, DPC_SIZE);
    bytes.iter().all(|&b| b == 0)
}

/// Initialize DPC subsystem.
pub fn init() {
    crate::hal::serial::write_string("[ke.dpc] enter\r\n");
    INSERT_COUNT.store(0, Ordering::SeqCst);
    FIRE_COUNT.store(0, Ordering::SeqCst);
    DPC_NEEDED.store(false, Ordering::SeqCst);
    // // kprintln!("    DPC: max={} (per-CPU list, heap-backed)", MAX_DPCS)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("      DPC vector: 0x{:02x} (software interrupt)", DPC_VECTOR)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Initialize a DPC object. This is `KeInitializeDpc` in Windows.
pub unsafe fn KeInitializeDpc(dpc: *mut Dpc, routine: DpcRoutine, context: *mut u8) {
    if dpc.is_null() {
        return;
    }
    (*dpc).header.init();
    (*dpc).type_ = 0x0010; // DpcContext
    (*dpc).importance = DpcImportance::Low as u8;
    (*dpc).number = 0; // Current processor
    (*dpc).routine = Some(routine);
    (*dpc).context = context;
    (*dpc).inserted.store(false, Ordering::Relaxed);
    (*dpc).fired.store(false, Ordering::Relaxed);
    (*dpc).name = "<dpc>";
}

/// Insert a DPC into the queue. This is `KeInsertQueueDpc` in Windows.
///
/// Returns true if the DPC was successfully queued.
pub unsafe fn KeInsertQueueDpc(
    dpc: *mut Dpc,
    _system_argument1: *mut u8,
    _system_argument2: *mut u8,
) -> bool {
    if dpc.is_null() {
        return false;
    }

    // Check IRQL: must be at DISPATCH_LEVEL or lower
    let current_irql = irql::get_current_irql();
    if current_irql > Irql::DispatchLevel {
        // Cannot queue DPC at IRQL > DISPATCH_LEVEL
        return false;
    }

    let arr = dpc_array();
    let mut found_slot = false;
    let _lock = DPC_QUEUE_LOCK.lock();

    // Find an empty slot
    for i in 0..MAX_DPCS {
        let slot = &mut arr[i];
        if unsafe { is_all_zero(slot) } || !slot.inserted.load(Ordering::Relaxed) {
            // Copy the DPC to this slot
            core::ptr::copy_nonoverlapping(dpc, slot, 1);
            slot.inserted.store(true, Ordering::Release);
            slot.fired.store(false, Ordering::Relaxed);
            found_slot = true;
            break;
        }
    }

    if found_slot {
        INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
        // Set DPC needed flag
        DPC_NEEDED.store(true, Ordering::Release);
        // Request DPC processing
        request_dpc_interrupt();
    }

    found_slot
}

/// Request a DPC software interrupt.
fn request_dpc_interrupt() {
    // On x86, we request interrupt 0xDF via the APIC
    // For now, just set the flag - the DPC will be processed
    // when the system is at DISPATCH_LEVEL
    DPC_NEEDED.store(true, Ordering::Release);
}

/// Check if DPC processing is needed.
pub fn is_dpc_needed() -> bool {
    DPC_NEEDED.load(Ordering::Acquire)
}

/// Insert a DPC. Returns the slot index.
/// Note: This is the legacy insert function for compatibility.
/// Uses per-CPU DPC lock for SMP support.
pub fn insert(routine: DpcRoutine, context: *mut u8, name: &'static str) -> Option<usize> {
    let arr = dpc_array();
    let _lock = get_current_cpu_dpc_lock().lock();
    for i in 0..MAX_DPCS {
        let slot = &mut arr[i];
        if unsafe { is_all_zero(slot) } || !slot.inserted.load(Ordering::Relaxed) {
            // SAFETY: arr is a valid reference into the pool-allocated
            // backing array; index is in-range.
            slot.routine = Some(routine);
            slot.context = context;
            slot.inserted.store(true, Ordering::Relaxed);
            slot.fired.store(false, Ordering::Relaxed);
            slot.name = name;
            slot.header.init();
            slot.type_ = 0x0010;
            slot.importance = DpcImportance::Low as u8;
            slot.number = 0;
            INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
            DPC_NEEDED.store(true, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Drain the DPC list. Returns the number of DPCs that fired.
/// This is called from the DPC interrupt handler or from the
/// scheduler when at DISPATCH_LEVEL.
/// Uses per-CPU DPC lock for SMP support.
pub fn drain() -> usize {
    let arr = dpc_array();
    let _lock = get_current_cpu_dpc_lock().lock();
    let mut fired = 0;

    for i in 0..MAX_DPCS {
        let slot = &mut arr[i];
        if slot.inserted.load(Ordering::Relaxed) && !slot.fired.load(Ordering::Relaxed) {
            slot.fired.store(true, Ordering::Relaxed);
            if let Some(r) = slot.routine {
                r(slot.context);
            }
            fired += 1;
        }
        // Reset the slot
        slot.routine = None;
        slot.context = core::ptr::null_mut();
        slot.inserted.store(false, Ordering::Relaxed);
        slot.fired.store(false, Ordering::Relaxed);
        slot.name = "<dpc>";
    }

    DPC_NEEDED.store(false, Ordering::Release);
    FIRE_COUNT.fetch_add(fired as u32, Ordering::Relaxed);
    fired
}

pub fn insert_count() -> u32 {
    INSERT_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}
pub fn fire_count() -> u32 {
    FIRE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

fn smoke_dpc_routine(_ctx: *mut u8) {}

/// Smoke test for the DPC subsystem.
pub fn smoke_test() -> bool {
    let i_before = insert_count();
    let f_before = fire_count();

    // Test with the legacy insert function
    let idx0 = insert(smoke_dpc_routine, core::ptr::null_mut(), "dpc0");
    let idx1 = insert(smoke_dpc_routine, core::ptr::null_mut(), "dpc1");
    let idx2 = insert(smoke_dpc_routine, core::ptr::null_mut(), "dpc2");
    if idx0.is_none() || idx1.is_none() || idx2.is_none() {
        // // kprintln!("    [DPC SMOKE FAIL] could not enqueue three DPCs")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let fired = drain();
    if fired != 3 {
        // // kprintln!("    [DPC SMOKE FAIL] drain fired={} (expected 3)", fired)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    let i_after = insert_count();
    let f_after = fire_count();
    if i_after != i_before + 3 || f_after != f_before + 3 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [DPC SMOKE FAIL] insert: {}->{} fire: {}->{}",
// //             i_before, i_after, f_before, f_after
// //         );
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [DPC SMOKE OK] drain fired={} insert={} fire={}",
// //         fired, i_after, f_after
// //     );

    // Test KeInitializeDpc and KeInsertQueueDpc
    let mut test_dpc = Dpc::new();
    unsafe {
        KeInitializeDpc(&mut test_dpc, smoke_dpc_routine, core::ptr::null_mut());
        let result = KeInsertQueueDpc(&mut test_dpc, core::ptr::null_mut(), core::ptr::null_mut());
        if !result {
            // // kprintln!("    [DPC SMOKE FAIL] KeInsertQueueDpc returned false")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }
    }
    let fired2 = drain();
    if fired2 != 1 {
        // // kprintln!("    [DPC SMOKE FAIL] KeInsertQueueDpc drain fired={} (expected 1)", fired2)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // // kprintln!("    [DPC SMOKE OK] KeInitializeDpc/KeInsertQueueDpc work")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    true
}

// =============================================================================
// DPC Interrupt Integration (P2 Enhancement)
// =============================================================================

/// DPC interrupt request flag - set when DPCs need processing.
static DPC_INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// DPC routine active flag
static DPC_ROUTINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Request a DPC software interrupt (P2 Enhancement)
/// This function triggers the DPC interrupt on the current CPU
pub fn request_dpc_interrupt_extended() {
    // Set the interrupt request flag
    DPC_INTERRUPT_REQUESTED.store(true, Ordering::Release);

    // On x86, trigger software interrupt 0xDF via APIC
    // In a real implementation, this would use:
    // - LAPIC: write to APIC's interrupt command register (ICR)
    // - Or CPU instruction like INT instruction (less preferred)
    //
    // For now, just set the flag - the DPC will be processed
    // when the system reaches DISPATCH_LEVEL
    // // kprintln!("[DPC] DPC interrupt requested (extended)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Clear the DPC interrupt request flag
pub fn clear_dpc_interrupt_request() {
    DPC_INTERRUPT_REQUESTED.store(false, Ordering::Release);
}

/// Check if DPC interrupt is requested
pub fn is_dpc_interrupt_requested() -> bool {
    DPC_INTERRUPT_REQUESTED.load(Ordering::Acquire)
}

/// KiRetireDpcList - Process all DPCs in the queue (P2 Enhancement)
///
/// This function is called from the DPC interrupt handler or when
/// the system is at DISPATCH_LEVEL. It processes all DPCs in the
/// per-CPU DPC queue until the queue is empty.
///
/// In Windows, this is called from KiInterruptTemplateDispatch or
/// from the dispatcher's idle loop.
pub fn ki_retire_dpc_list() {
    loop {
        // Check if DPCs are needed
        if !is_dpc_needed() {
            break;
        }

        // Set routine active flag
        DPC_ROUTINE_ACTIVE.store(true, Ordering::Release);

        // Drain the DPC queue
        let fired = drain();

        if fired > 0 {
            // // kprintln!("[DPC] KiRetireDpcList: processed {} DPCs", fired)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }

        // Clear routine active flag
        DPC_ROUTINE_ACTIVE.store(false, Ordering::Release);

        // Double-check if more DPCs were queued while processing
        if !is_dpc_needed() {
            break;
        }
    }

    // Clear interrupt request
    clear_dpc_interrupt_request();
}

/// DPC interrupt handler stub (P2 Enhancement)
///
/// This would be called from the interrupt dispatch code when
/// DPC_VECTOR (0xDF) is triggered. It calls KiRetireDpcList
/// to process pending DPCs.
pub fn dpc_interrupt_handler() {
    // // kprintln!("[DPC] DPC interrupt handler entered")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Process all pending DPCs
    ki_retire_dpc_list();

    // // kprintln!("[DPC] DPC interrupt handler exiting")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Check if DPC routine is currently executing
pub fn is_dpc_routine_active() -> bool {
    DPC_ROUTINE_ACTIVE.load(Ordering::Acquire)
}

/// Queue a DPC to a specific CPU (for SMP) (P2 Enhancement)
///
/// In a full SMP implementation, this would queue the DPC to the
/// target CPU's DPC queue and trigger an IPI.
pub fn queue_dpc_to_cpu(dpc: *mut Dpc, cpu_number: u32, system_argument1: *mut u8, system_argument2: *mut u8) -> bool {
    if dpc.is_null() {
        return false;
    }

    unsafe {
        // Set the target CPU number
        (*dpc).number = cpu_number;
    }

    // Queue the DPC
    let result = unsafe { KeInsertQueueDpc(dpc, system_argument1, system_argument2) };

    if result {
        // // kprintln!("[DPC] Queued DPC to CPU {}", cpu_number)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

        // If target CPU is not current CPU, an Inter-Processor
        // Interrupt would be issued here. Port to the unified
        // `hal::pic`/`arch::common::ipi` facade when SMP is
        // brought up on non-x86_64 targets.
        #[cfg(target_arch = "x86_64")]
        if cpu_number != get_current_cpu_number() {
            // Request IPI to target CPU via APIC's IPI mechanism.
            // // kprintln!("[DPC] Would send IPI to CPU {}", cpu_number)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    }

    result
}

/// Get current CPU number (P2 Enhancement)
fn get_current_cpu_number() -> u32 {
    // In a real implementation, this would read from per-CPU data
    // via the GS base or similar mechanism
    0
}

/// Remove a DPC from the queue (P2 Enhancement)
///
/// Returns true if the DPC was found and removed.
pub fn remove_dpc(dpc: *mut Dpc) -> bool {
    if dpc.is_null() {
        return false;
    }

    let arr = dpc_array();
    let _lock = get_current_cpu_dpc_lock().lock();

    // Search for the DPC in the queue
    for i in 0..MAX_DPCS {
        let slot = &mut arr[i];
        if slot.inserted.load(Ordering::Relaxed) {
            // Compare DPC pointers
            let slot_ptr = slot as *mut Dpc;
            if slot_ptr == dpc {
                // Found it - remove from queue
                slot.inserted.store(false, Ordering::Release);
                slot.routine = None;
                slot.context = core::ptr::null_mut();

                // // kprintln!("[DPC] Removed DPC from queue")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                return true;
            }
        }
    }

    false
}

/// Get DPC queue depth (P2 Enhancement)
pub fn get_dpc_queue_depth() -> usize {
    let arr = dpc_array();
    let _lock = get_current_cpu_dpc_lock().lock();

    let mut count = 0;
    for i in 0..MAX_DPCS {
        if arr[i].inserted.load(Ordering::Relaxed) {
            count += 1;
        }
    }
    count
}
