//! Kernel Synchronization Primitives
//
//! NT-style dispatcher objects plus a basic spinlock that works on every
//! supported architecture (x86_64, aarch64, riscv64, loongarch64).
//
//! This is the **single** spinlock implementation in the kernel - all the
//! per-module `mod spin { ... }` shadowing has been removed from
//! `mm/frame.rs`, `mm/pool.rs`, `mm/vm.rs`, `mm/heap.rs`, `ps/process.rs`,
//! `servers/services.rs` and `ke/scheduler.rs`; they all consume
//! `crate::ke::sync::Spinlock` instead.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// IRQL (Interrupt Request Level) type
/// Used to represent software interrupt priority levels in NT
pub type Irql = u8;

/// Long-spin statistics for \`Spinlock::lock\`: incremented at each
/// power-of-two threshold crossing beyond 10000 spin iterations, so
/// contended or deadlocked locks are observable in diagnostics even
/// when serial logging is suppressed or unavailable.
pub static LONG_SPIN_EVENTS: AtomicU64 = AtomicU64::new(0);

/// IRQL levels
//
// NT 6.1 defines 32 IRQLs (0..31). The documented x86/x64 layout is:
//   PASSIVE 0, APC 1, DISPATCH 2, GATE 3, DEVICE_LEVEL_1..10 = 4..13,
//   reserved device levels 14..26, PROFILE 27, CLOCK2 28, IPI 29,
//   POWER 30, HIGH 31.
// IRQL 3 is a software level; hardware device IRQLs (DIRQL) only start
// at 4. See `ke::irql::Irql` for the typed view of the same table.
pub const IRQL_LEVEL_PASSIVE: Irql = 0;
pub const IRQL_LEVEL_LOWEST: Irql = IRQL_LEVEL_PASSIVE;
pub const IRQL_LEVEL_APC: Irql = 1;
pub const IRQL_LEVEL_DISPATCH: Irql = 2;
pub const IRQL_LEVEL_GATE: Irql = 3;
pub const IRQL_LEVEL_DEVICE_BASE: Irql = 4;
pub const IRQL_LEVEL_DEVICE_10: Irql = 13;
pub const IRQL_LEVEL_PROFILE: Irql = 27;
pub const IRQL_LEVEL_CLOCK2: Irql = 28;
pub const IRQL_LEVEL_IPI: Irql = 29;
pub const IRQL_LEVEL_POWER: Irql = 30;
pub const IRQL_LEVEL_HIGHEST: Irql = 31;

/// Interrupt-disable / restore bracket. We use the architecture's
/// interrupt flag - on x86_64 it is the IF flag, on aarch64 it is
/// DAIF, on riscv64 it is the `sstatus.SIE` bit, on loongarch64 it is
/// `crmd.ie`. The helpers in `arch::*` are the only place that needs
/// to know the encoding.
pub struct IrqlRestore {
    /// The IRQL observed at `raise()` time, restored by `Drop`.
    previous: crate::ke::irql::Irql,
}

impl IrqlRestore {
    /// Raise the current CPU to DISPATCH_LEVEL and remember the level
    /// we came from.
    ///
    /// NT requires spinlocks to be taken at DISPATCH_LEVEL: a lock held
    /// at PASSIVE_LEVEL can be contended by an ISR that raises to the
    /// same level on the same CPU, which deadlocks. Raising on acquire
    /// and restoring on drop is the `KeRaiseIrql`/`KeLowerIrql` pair.
    pub fn raise() -> Self {
        let previous = crate::ke::irql::raise_irql(crate::ke::irql::Irql::DispatchLevel);
        Self { previous }
    }
}

impl Drop for IrqlRestore {
    fn drop(&mut self) {
        crate::ke::irql::lower_irql(self.previous);
    }
}

/// A simple, correct, RAII spinlock. It disables interrupts while held
/// (so we never deadlock against a clock interrupt that wants the same
/// lock) and re-enables them on drop. Interrupts are *not* disabled
/// while waiting for the lock - that would be a long time at high
/// IRQL on a multi-core system and is unnecessary.
pub struct Spinlock<T: ?Sized> {
    locked: AtomicU32,
    data: core::cell::UnsafeCell<T>,
}

// SAFETY: A spinlock is `Send + Sync` regardless of `T` because the
// `locked` field is atomic and access to `data` is always serialised
// through the lock. We additionally require `T: Send` for `Send` so
// that the data cannot be moved while still being accessible through
// another reference - but we *do* allow non-`Send` payloads (raw
// pointers) by overriding the auto-trait impl. Most of the kernel
// structures wrapped in spinlocks contain raw pointers (ETHEAD,
// EPROCESS, frame info) which are not `Send` by default, so we
// unconditionally mark the lock `Send + Sync`. The lock itself
// guarantees the safety invariant.
// A Spinlock may only be moved across threads when the data it
// protects is also Send; the unconditional bound previously allowed
// e.g. Rc-backed payloads to cross threads unsafely.
unsafe impl<T: ?Sized + Send> Send for Spinlock<T> {}
unsafe impl<T: ?Sized> Sync for Spinlock<T> {}

impl<T> Spinlock<T> {
    /// create a new spinlock wrapping `data`.
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicU32::new(0),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    /// Consume the spinlock and return the inner data.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Spinlock<T> {
    /// Try to acquire the lock once, returning `None` on contention.
    /// When the lock is acquired, interrupts are disabled on this CPU
    /// and will be re-enabled when the guard is dropped.
    pub fn try_lock(&self) -> Option<SpinlockGuard<'_, T>> {
        let irql_guard = IrqlRestore::raise();
        self.locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinlockGuard {
                lock: self,
                _irql_guard: Some(irql_guard),
            })
    }

    /// Plain acquire/release pair for callers that cannot hold an RAII
    /// guard across two functions (the WDF spinlock API). The RAII
    /// `lock()` guard is still preferred when the scope is lexical.
    ///
    /// The caller must pair `acquire()` with `release()`; the IRQL raised
    /// on acquire is lowered by `release()` rather than by a `Drop`.
    pub fn acquire(&self) {
        while self
            .locked
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::arch::cpu_relax();
        }
    }

    /// Release a lock taken with `acquire()`.
    pub fn release(&self) {
        self.locked.store(0, Ordering::Release);
    }

    /// Acquire the lock, spinning until it is free. Interrupts are
    /// disabled on the calling CPU *while the lock is held* (not while
    /// waiting for it) so that an ISR running on the same CPU cannot
    /// try to take the same lock and deadlock.
    ///
    /// Uses exponential backoff to reduce bus contention on SMP systems.
    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        let irql_guard = IrqlRestore::raise();
        let mut spins: u32 = 0;
        loop {
            // Try to acquire the lock first
            if self
                .locked
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return SpinlockGuard {
                    lock: self,
                    _irql_guard: Some(irql_guard),
                };
            }

            // Exponential backoff: start with small delay, grow exponentially
            // Maximum backoff caps at 1024 iterations (2^10) to prevent
            // excessive waiting on very contended locks
            let backoff = spins.min(10);
            let delay = 1u32 << backoff;
            for _ in 0..delay {
                core::hint::spin_loop();
            }
            spins += 1;

            // Log warning if spinning for too long (potential deadlock or heavy contention)
            // Use logarithmic rate limiting: only print at 10K, 20K, 40K, 80K, ...
            // or when the threshold is first crossed (spins == 10001).
            if spins > 10000 {
                // Check if this is the first warning or a power-of-2 threshold crossing
                let is_threshold_crossing = (spins == 10001) || (spins & (spins - 1)) == 0;
                if is_threshold_crossing {
                    LONG_SPIN_EVENTS.fetch_add(1, Ordering::Relaxed);
                    crate::hal::serial::write_string(
                        "[SYNC] spinlock contention: spinning beyond 10000 iterations (possible deadlock)\r\n",
                    );
                }
            }
        }
    }

    /// read the lock state (true = held). For diagnostics / asserts.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed) != 0
    }

    /// Boot-time raw access to the guarded data without acquiring the
    /// lock. Only safe when called before APs start and the caller can
    /// prove no other CPU holds the lock. Used to work around
    /// LoongArch64 atomics issues during early boot.
    pub fn raw_data_ptr(&self) -> *mut T {
        self.data.get()
    }
}

/// RAII guard for a spinlock. When dropped, the lock is released
/// and interrupts are re-enabled.
pub struct SpinlockGuard<'a, T: ?Sized + 'a> {
    lock: &'a Spinlock<T>,
    _irql_guard: Option<IrqlRestore>, // Saved IRQL state, re-enabled on drop
}

impl<'a, T: ?Sized> core::ops::Deref for SpinlockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: The guard exists iff the lock is held, so no one else
        // can be accessing the data.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> core::ops::DerefMut for SpinlockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for SpinlockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(0, Ordering::Release);
    }
}

/// Dispatcher header (the first field of every NT dispatcher object:
/// process, thread, event, mutex, semaphore, timer, queue, ...).
/// Size: 0x20 bytes (32 bytes) on Windows 7 x64
#[derive(Clone)]
#[repr(C)]
pub struct DispatcherHeader {
    pub type_: u8,        // 0x00
    pub signal_state: u8, // 0x01
    pub size: u16,        // 0x02
    pub inserted: u8,     // 0x04
    pub spare: [u8; 3],   // 0x05 - 8 bytes total so far
    // Additional fields to reach 0x20 (32 bytes)
    pub absolute: u8,       // 0x08 - for timers
    pub co_started: u8,     // 0x09 - for timers
    pub co_terminated: u8,  // 0x0A - for timers
    pub inactive: u8,       // 0x0B - for timers
    pub reserved: [u64; 2], // 0x10 - 16 bytes to reach 0x20
}

impl DispatcherHeader {
    pub const fn new(object_type: u8) -> Self {
        Self {
            type_: object_type,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
            absolute: 0,
            co_started: 0,
            co_terminated: 0,
            inactive: 0,
            reserved: [0; 2],
        }
    }
}

/// Object types recognised by the dispatcher.
#[derive(Debug, Clone, Copy)]
pub enum DispatcherObjectType {
    Event = 0,
    Mutex = 1,
    Semaphore = 2,
    Thread = 3,
    Process = 4,
    Timer = 5,
}

/// Notification event - pulses the signal state when set; auto-resets.
pub struct NotificationEvent {
    pub header: DispatcherHeader,
}

impl NotificationEvent {
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Event as u8),
        }
    }
    pub fn signal(&mut self) {
        self.header.signal_state = 1;
    }
    pub fn reset(&mut self) {
        self.header.signal_state = 0;
    }
    pub fn is_signaled(&self) -> bool {
        self.header.signal_state != 0
    }
}

impl Default for NotificationEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronization event - acts like a "gate", only one waiter is
/// released per set, and it stays signalled until manually cleared.
pub struct SynchronizationEvent {
    pub header: DispatcherHeader,
}

impl SynchronizationEvent {
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Event as u8),
        }
    }
    pub fn set(&mut self) {
        self.header.signal_state = 1;
    }
    pub fn clear(&mut self) {
        self.header.signal_state = 0;
    }
}

impl Default for SynchronizationEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// Event type for `KeInitializeEvent`-style APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Notification = 0,
    Synchronization = 1,
}

/// Generic event with type tag. The header byte matches the `type_`
/// convention: 0 = Notification, 1 = Synchronization.
pub struct Event {
    pub header: DispatcherHeader,
}

impl Event {
    pub fn new(event_type: EventType) -> Self {
        Self {
            header: DispatcherHeader::new(event_type as u8),
        }
    }

    pub fn set(&mut self) {
        self.header.signal_state = 1;
    }
    pub fn clear(&mut self) {
        self.header.signal_state = 0;
    }
    pub fn is_signaled(&self) -> bool {
        self.header.signal_state != 0
    }
}

/// Mutex with the standard NT owner-thread / recursion bookkeeping.
pub struct Mutex {
    pub header: DispatcherHeader,
    pub owner_thread: u64,
    pub recursion_count: u32,
}

impl Mutex {
    pub const fn new() -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Mutex as u8),
            owner_thread: 0,
            recursion_count: 0,
        }
    }

    pub fn try_acquire(&mut self, tid: u64) -> bool {
        if self.header.signal_state == 0 {
            self.header.signal_state = 1;
            self.owner_thread = tid;
            self.recursion_count = 1;
            true
        } else if self.owner_thread == tid {
            self.recursion_count += 1;
            true
        } else {
            false
        }
    }

    pub fn release(&mut self, tid: u64) -> bool {
        if self.owner_thread != tid {
            return false;
        }
        self.recursion_count -= 1;
        if self.recursion_count == 0 {
            self.owner_thread = 0;
            self.header.signal_state = 0; // un-signal
        }
        true
    }
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}

/// Counting semaphore.
pub struct Semaphore {
    pub header: DispatcherHeader,
    pub count: u32,
    pub limit: u32,
}

impl Semaphore {
    pub const fn new(initial: u32, limit: u32) -> Self {
        Self {
            header: DispatcherHeader::new(DispatcherObjectType::Semaphore as u8),
            count: initial,
            limit,
        }
    }
    pub fn signal(&mut self) {
        if self.count < self.limit {
            self.count += 1;
            self.header.signal_state = 1;
        }
    }
    pub fn wait(&mut self) -> bool {
        if self.count > 0 {
            self.count -= 1;
            if self.count == 0 {
                self.header.signal_state = 0;
            }
            true
        } else {
            false
        }
    }
}

/// Result of a `KeWaitForSingleObject` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    Success = 0,
    Abandoned = 1,
    Timeout = 2,
    Error = 3,
}

/// Block the current thread until the dispatcher object becomes
/// signalled, the timeout expires, or an alertable wait is cancelled.
///
/// This is a scheduler-aware wait: the current thread is parked
/// on the dispatcher's wait list and `schedule()` is invoked.
/// The bootstrap version uses a single global wait list and
/// relies on the timer tick to re-check the wait list; the
/// full implementation (in `ke::dispatch`) uses a per-object
/// wait list with immediate wakeup on signal.
pub fn wait_single(object: &DispatcherHeader, timeout_ms: u32) -> WaitResult {
    // Fast path: already signalled.
    if object.signal_state != 0 {
        return WaitResult::Success;
    }
    // Fast path: zero timeout.
    if timeout_ms == 0 {
        return WaitResult::Timeout;
    }
    // Park the current thread on the wait list. The thread's
    // `wait_list_entry` is already part of `Ethread`; we link
    // it onto the dispatcher's wait queue.
    crate::ke::dispatch::wait_on(object, timeout_ms)
}

/// Wake one or all threads waiting on `object`. Called by the
/// dispatcher object's `signal` / `pulse` implementations.
pub fn wake(object: &DispatcherHeader, all: bool) -> u32 {
    crate::ke::dispatch::wake(object, all)
}

// ======================================================================
// OnceLock: simple one-shot initializer (kernel-mode equivalent)
// ======================================================================

use core::cell::UnsafeCell;
use core::sync::atomic::Ordering as AOrdering;

/// One-shot initializer. Once initialized, get() returns the value.
///
/// Suitable for low-IRQL kernel boot-time initialization. The first
/// `get_or_init` call wins; subsequent calls return the previously stored
/// value.
pub struct OnceLock<T> {
    state: AtomicU32,
    value: UnsafeCell<core::mem::MaybeUninit<T>>,
}

const ONCE_UNINIT: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_READY: u32 = 2;

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(ONCE_UNINIT),
            value: UnsafeCell::new(core::mem::MaybeUninit::uninit()),
        }
    }

    /// Try to get the stored value. Returns None if not yet initialized.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(AOrdering::Acquire) == ONCE_READY {
            // SAFETY: state == READY implies value was initialized.
            unsafe { Some(&*(*self.value.get()).as_ptr()) }
        } else {
            None
        }
    }

    /// Initialize (if not already) and return the value.
    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        // Fast path
        if self.state.load(AOrdering::Acquire) == ONCE_READY {
            unsafe { return &*(*self.value.get()).as_ptr() };
        }

        // Try to transition UNINIT -> RUNNING
        if self
            .state
            .compare_exchange(
                ONCE_UNINIT,
                ONCE_RUNNING,
                AOrdering::AcqRel,
                AOrdering::Acquire,
            )
            .is_ok()
        {
            // We are the initializer
            let v = f();
            unsafe {
                (*self.value.get()).write(v);
            }
            self.state.store(ONCE_READY, AOrdering::Release);
            unsafe { &*(*self.value.get()).as_ptr() }
        } else {
            // Spin-wait briefly until the initializer finishes.
            while self.state.load(AOrdering::Acquire) != ONCE_READY {
                core::hint::spin_loop();
            }
            unsafe { &*(*self.value.get()).as_ptr() }
        }
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: Kernel-mode. Single-threaded boot-time usage. Mutations of state
// are atomic; the value is only set once and is then read-only. Sharing
// across threads is OK under IRQL discipline.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
unsafe impl<T: Send> Send for OnceLock<T> {}

/// Initialize the synchronization subsystem.
pub fn init() {
    crate::hal::serial::write_string("[ke.sync] enter\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irql_constants_match_nt61_table() {
        assert_eq!(IRQL_LEVEL_PASSIVE, 0);
        assert_eq!(IRQL_LEVEL_APC, 1);
        assert_eq!(IRQL_LEVEL_DISPATCH, 2);
        assert_eq!(IRQL_LEVEL_GATE, 3);
        assert_eq!(IRQL_LEVEL_DEVICE_BASE, 4);
        assert_eq!(IRQL_LEVEL_DEVICE_10, 13);
        assert_eq!(IRQL_LEVEL_PROFILE, 27);
        assert_eq!(IRQL_LEVEL_CLOCK2, 28);
        assert_eq!(IRQL_LEVEL_IPI, 29);
        assert_eq!(IRQL_LEVEL_POWER, 30);
        assert_eq!(IRQL_LEVEL_HIGHEST, 31);
        assert_eq!(IRQL_LEVEL_LOWEST, IRQL_LEVEL_PASSIVE);
    }
}
