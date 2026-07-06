//! GPU Interrupt Handling
//
//! Provides interrupt handling infrastructure for GPU drivers,
//! including vblank interrupts, error handling, and deferred
//! procedure calls.
//
//! Clean-room implementation based on industry standards.

use alloc::vec::Vec;
use alloc::boxed::Box;
use crate::drivers::video::core::gpu_common::{GpuError, GpuInterrupt};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// =====================================================================
// Interrupt Types
// =====================================================================

/// Interrupt types handled by GPU drivers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuIrqType {
    /// Vertical blank interrupt
    VBlank,
    /// Horizontal blank interrupt
    HBlank,
    /// Page fault interrupt
    PageFault,
    /// Command completion
    CmdComplete,
    /// Flip completion
    FlipComplete,
    /// GPU error
    GpuError,
    /// Thermal interrupt
    Thermal,
    /// Display detect
    DisplayDetect,
}

/// Interrupt flags
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuIrqFlags {
    /// Interrupt is enabled
    pub enabled: bool,
    /// Interrupt is edge-triggered
    pub edge: bool,
    /// Interrupt is level-triggered
    pub level: bool,
    /// Interrupt is active high
    pub active_high: bool,
    /// Interrupt is active low
    pub active_low: bool,
}

impl GpuIrqFlags {
    /// Create default flags for vblank (level-triggered, active high)
    pub fn vblank() -> Self {
        Self {
            enabled: true,
            edge: false,
            level: true,
            active_high: true,
            active_low: false,
        }
    }
}

// =====================================================================
// Interrupt Status
// =====================================================================

/// Interrupt status for a single display head
#[derive(Debug, Clone, Copy)]
pub struct InterruptStatus {
    /// Vertical blank pending
    pub vblank_pending: bool,
    /// Horizontal blank pending
    pub hblank_pending: bool,
    /// Flip complete pending
    pub flip_pending: bool,
    /// Error pending
    pub error_pending: bool,
    /// Error code
    pub error_code: u32,
}

impl Default for InterruptStatus {
    fn default() -> Self {
        Self {
            vblank_pending: false,
            hblank_pending: false,
            flip_pending: false,
            error_pending: false,
            error_code: 0,
        }
    }
}

// =====================================================================
// VBlank Counter
// =====================================================================

/// Vertical blank counter
///
/// Tracks the number of vertical blanks for each display head,
/// useful for triple buffering and vsync.
pub struct VBlankCounter {
    /// Counter for each head (max 8 heads)
    counters: [AtomicU64; 8],
    /// Timestamp of last vblank
    last_vblank_ns: AtomicU64,
}

impl VBlankCounter {
    /// Create a new vblank counter
    pub fn new() -> Self {
        Self {
            counters: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            last_vblank_ns: AtomicU64::new(0),
        }
    }

    /// Increment vblank counter for a head
    pub fn increment(&self, head: u32) {
        if (head as usize) < self.counters.len() {
            self.counters[head as usize].fetch_add(1, Ordering::AcqRel);
            self.last_vblank_ns
                .store(Self::current_time_ns(), Ordering::Release);
        }
    }

    /// Get vblank count for a head
    pub fn get(&self, head: u32) -> u64 {
        if (head as usize) < self.counters.len() {
            self.counters[head as usize].load(Ordering::Acquire)
        } else {
            0
        }
    }

    /// Get timestamp of last vblank
    pub fn last_vblank_time(&self) -> u64 {
        self.last_vblank_ns.load(Ordering::Acquire)
    }

    /// Get current timestamp in nanoseconds
    fn current_time_ns() -> u64 {
        // Simplified - in real implementation, use a proper timer
        0
    }
}

impl Default for VBlankCounter {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Interrupt Handler Trait
// =====================================================================

/// Trait for GPU interrupt handlers
pub trait GpuIrqHandler: Send + Sync {
    /// Handle an interrupt
    ///
    /// Returns true if the interrupt was handled, false otherwise.
    fn handle_irq(&self, head: u32) -> bool;

    /// Get interrupt status
    fn get_status(&self) -> InterruptStatus;

    /// Enable a specific interrupt type
    fn enable(&self, irq_type: GpuIrqType, head: u32);

    /// Disable a specific interrupt type
    fn disable(&self, irq_type: GpuIrqType, head: u32);

    /// Check if interrupt is enabled
    fn is_enabled(&self, irq_type: GpuIrqType, head: u32) -> bool;
}

// =====================================================================
// VBlank Wait Queue
// =====================================================================

/// VBlank wait token
#[derive(Debug, Clone, Copy)]
pub struct VBlankWaitToken {
    /// Target vblank count
    target_count: u64,
    /// Current head
    head: u32,
    /// Whether the wait has completed
    completed: bool,
}

impl VBlankWaitToken {
    /// Create a new wait token
    pub fn new(head: u32, target_count: u64) -> Self {
        Self {
            target_count,
            head,
            completed: false,
        }
    }

    /// Check if wait is complete
    pub fn is_complete(&self, current_count: u64) -> bool {
        current_count >= self.target_count
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.completed = true;
    }

    /// Get head
    pub fn head(&self) -> u32 {
        self.head
    }
}

/// VBlank wait queue
pub struct VBlankWaitQueue {
    /// Waiting tokens
    waiters: alloc::vec::Vec<VBlankWaitToken>,
}

impl VBlankWaitQueue {
    /// Create a new wait queue
    pub fn new() -> Self {
        Self { waiters: Vec::new() }
    }

    /// Add a waiter
    pub fn add_waiter(&mut self, token: VBlankWaitToken) {
        self.waiters.push(token);
    }

    /// Process vblank for a head
    ///
    /// Returns the number of waiters that were completed.
    pub fn process_vblank(&mut self, head: u32, current_count: u64) -> usize {
        let mut completed = 0;
        let mut remaining = Vec::new();

        for mut waiter in self.waiters.drain(..) {
            if waiter.head() == head && waiter.is_complete(current_count) {
                waiter.complete();
                completed += 1;
            } else {
                remaining.push(waiter);
            }
        }

        self.waiters = remaining;
        completed
    }

    /// Get number of waiters
    pub fn len(&self) -> usize {
        self.waiters.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }
}

impl Default for VBlankWaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// GPU IRQ Controller
// =====================================================================

/// GPU interrupt controller
///
/// Central controller for GPU interrupts, managing multiple
/// interrupt handlers and dispatching to the appropriate driver.
pub struct GpuIrqController {
    /// IRQ number
    pub irq: AtomicU32,
    /// Enabled heads
    pub enabled_heads: u32,
    /// VBlank counter
    pub vblank_counter: VBlankCounter,
    /// VBlank wait queue — protected by spinlock for thread safety
    pub wait_queue: Spinlock<VBlankWaitQueue>,
    /// Registered handlers
    pub handlers: Vec<Box<dyn GpuIrqHandler>>,
    /// Interrupt status
    pub status: AtomicU32,
}

impl GpuIrqController {
    /// Create a new IRQ controller
    pub fn new(irq: u32) -> Self {
        Self {
            irq: AtomicU32::new(irq),
            enabled_heads: 0,
            vblank_counter: VBlankCounter::new(),
            wait_queue: Spinlock::new(VBlankWaitQueue::new()),
            handlers: Vec::new(),
            status: AtomicU32::new(0),
        }
    }

    /// Register an interrupt handler
    pub fn register_handler(&mut self, handler: Box<dyn GpuIrqHandler>) {
        self.handlers.push(handler);
    }

    /// Get IRQ number
    pub fn irq(&self) -> u32 {
        self.irq.load(Ordering::Acquire)
    }

    /// Set IRQ number
    pub fn set_irq(&self, irq: u32) {
        self.irq.store(irq, Ordering::Release);
    }

    /// Enable vblank for a head
    pub fn enable_vblank(&mut self, head: u32) {
        self.enabled_heads |= 1 << head;
    }

    /// Disable vblank for a head
    pub fn disable_vblank(&mut self, head: u32) {
        self.enabled_heads &= !(1 << head);
    }

    /// Handle an interrupt
    ///
    /// This should be called from the actual IRQ handler.
    pub fn handle_irq(&self) -> bool {
        let mut handled = false;

        for handler in &self.handlers {
            for head in 0..8u32 {
                if self.enabled_heads & (1 << head) != 0 {
                    if handler.handle_irq(head) {
                        handled = true;
                    }
                }
            }
        }

        // Update status
        self.status.store(0, Ordering::Release);

        handled
    }

    /// Notify vblank occurred
    pub fn notify_vblank(&self, head: u32) {
        self.vblank_counter.increment(head);

        // Process waiters with proper synchronization.
        // The lock is held only for the brief processing of waiters.
        let mut queue = self.wait_queue.lock();
        let current_count = self.vblank_counter.get(head);
        let _completed = queue.process_vblank(head, current_count);
        // In a full implementation, we would wake blocked threads here.
    }

    /// Get vblank count for a head
    pub fn get_vblank_count(&self, head: u32) -> u64 {
        self.vblank_counter.get(head)
    }

    /// Wait for vblank
    ///
    /// Returns true if vblank occurred before timeout.
    pub fn wait_vblank(&self, head: u32, timeout_ms: u32) -> bool {
        let start_count = self.vblank_counter.get(head);
        let target_count = start_count + 1;

        // Poll-based wait — each iteration pauses on a spin hint,
        // then reads the atomic counter. This is far more efficient
        // than a tight loop without any pause instruction.
        let max_iterations = timeout_ms * 100;
        for _ in 0..max_iterations {
            if self.vblank_counter.get(head) >= target_count {
                return true;
            }
            // Pause instruction: yields to sibling hyper-threads and
            // reduces power consumption during the busy wait.
            core::hint::spin_loop();
        }

        // Timeout — vblank did not fire within the window.
        // This can happen if the display is disabled or the IRQ
        // is not correctly routed.
        false
    }
}

impl Default for GpuIrqController {
    fn default() -> Self {
        Self::new(0)
    }
}

// =====================================================================
// Softirq (Bottom Half Processing)
// =====================================================================

/// Softirq types for GPU
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuSoftirq {
    /// VBlank deferred work
    VBlank(u32),
    /// Flip completed deferred work
    FlipComplete(u32),
    /// Error processing
    Error,
    /// Thermal throttling
    Thermal,
    /// Custom deferred work
    Custom(u8),
}

/// Softirq handler function type
type SoftirqHandler = fn(GpuSoftirq);

/// GPU softirq controller
///
/// Handles deferred interrupt processing (bottom half) for GPU events.
pub struct GpuSoftirqController {
    /// Pending softirqs (bitmap)
    pending: AtomicU64,
    /// Softirq handlers
    handlers: [Option<SoftirqHandler>; 16],
}

impl GpuSoftirqController {
    /// Create a new softirq controller
    pub fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            handlers: [
                None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None,
            ],
        }
    }

    /// Register a softirq handler
    pub fn register_handler(&mut self, softirq: GpuSoftirq, handler: SoftirqHandler) {
        let idx = softirq_to_index(softirq);
        if idx < self.handlers.len() {
            self.handlers[idx] = Some(handler);
        }
    }

    /// Raise a softirq
    pub fn raise(&self, softirq: GpuSoftirq) {
        let idx = softirq_to_index(softirq);
        self.pending.fetch_or(1u64 << idx, Ordering::AcqRel);
    }

    /// Process pending softirqs
    pub fn process_pending(&self) {
        let mut pending = self.pending.load(Ordering::Acquire);

        while pending != 0 {
            // Find lowest set bit
            let idx = (pending & !pending + 1).trailing_zeros() as usize;

            if idx < self.handlers.len() {
                if let Some(handler) = self.handlers[idx] {
                    let softirq = index_to_softirq(idx);
                    handler(softirq);
                }
            }

            // Clear the bit
            pending &= pending - 1;
            self.pending.store(pending, Ordering::Release);
        }
    }

    /// Check if any pending softirqs
    pub fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire) != 0
    }
}

impl Default for GpuSoftirqController {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert softirq to bitmap index
fn softirq_to_index(softirq: GpuSoftirq) -> usize {
    match softirq {
        GpuSoftirq::VBlank(_) => 0,
        GpuSoftirq::FlipComplete(_) => 1,
        GpuSoftirq::Error => 2,
        GpuSoftirq::Thermal => 3,
        GpuSoftirq::Custom(n) => (4 + n) as usize,
    }
}

/// Convert bitmap index to softirq
fn index_to_softirq(idx: usize) -> GpuSoftirq {
    match idx {
        0 => GpuSoftirq::VBlank(0),
        1 => GpuSoftirq::FlipComplete(0),
        2 => GpuSoftirq::Error,
        3 => GpuSoftirq::Thermal,
        _ => GpuSoftirq::Custom((idx - 4) as u8),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vblank_counter_new() {
        let counter = VBlankCounter::new();
        assert_eq!(counter.get(0), 0);
        assert_eq!(counter.get(7), 0);
    }

    #[test]
    fn test_vblank_counter_increment() {
        let counter = VBlankCounter::new();
        counter.increment(0);
        assert_eq!(counter.get(0), 1);
        counter.increment(0);
        assert_eq!(counter.get(0), 2);
    }

    #[test]
    fn test_vblank_counter_multiple_heads() {
        let counter = VBlankCounter::new();
        counter.increment(0);
        counter.increment(1);
        counter.increment(2);
        assert_eq!(counter.get(0), 1);
        assert_eq!(counter.get(1), 1);
        assert_eq!(counter.get(2), 1);
    }

    #[test]
    fn test_vblank_counter_out_of_bounds() {
        let counter = VBlankCounter::new();
        // Head 8+ should return 0
        assert_eq!(counter.get(8), 0);
        assert_eq!(counter.get(100), 0);
    }

    #[test]
    fn test_vblank_wait_token_new() {
        let token = VBlankWaitToken::new(0, 100);
        assert_eq!(token.head(), 0);
        assert!(!token.is_complete(99));
        assert!(token.is_complete(100));
        assert!(token.is_complete(200));
    }

    #[test]
    fn test_vblank_wait_token_complete() {
        let mut token = VBlankWaitToken::new(1, 50);
        assert!(!token.completed);
        token.complete();
        assert!(token.completed);
    }

    #[test]
    fn test_vblank_wait_queue_new() {
        let queue = VBlankWaitQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_vblank_wait_queue_add() {
        let mut queue = VBlankWaitQueue::new();
        queue.add_waiter(VBlankWaitToken::new(0, 10));
        queue.add_waiter(VBlankWaitToken::new(1, 20));
        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_vblank_wait_queue_process() {
        let mut queue = VBlankWaitQueue::new();
        queue.add_waiter(VBlankWaitToken::new(0, 5));
        queue.add_waiter(VBlankWaitToken::new(0, 10));
        queue.add_waiter(VBlankWaitToken::new(1, 5));

        // Process vblank for head 0 with count 5
        let completed = queue.process_vblank(0, 5);
        assert_eq!(completed, 1);
        assert_eq!(queue.len(), 2);

        // Process vblank for head 0 with count 10
        let completed = queue.process_vblank(0, 10);
        assert_eq!(completed, 1);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_vblank_wait_queue_all_complete() {
        let mut queue = VBlankWaitQueue::new();
        queue.add_waiter(VBlankWaitToken::new(0, 5));
        queue.add_waiter(VBlankWaitToken::new(0, 10));

        // High enough count to complete all
        let completed = queue.process_vblank(0, 100);
        assert_eq!(completed, 2);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_interrupt_status_default() {
        let status = InterruptStatus::default();
        assert!(!status.vblank_pending);
        assert!(!status.error_pending);
        assert_eq!(status.error_code, 0);
    }

    #[test]
    fn test_gpu_irq_flags_vblank() {
        let flags = GpuIrqFlags::vblank();
        assert!(flags.enabled);
        assert!(!flags.edge);
        assert!(flags.level);
        assert!(flags.active_high);
        assert!(!flags.active_low);
    }

    #[test]
    fn test_gpu_irq_type_values() {
        // Just verify enum variants exist
        let _ = GpuIrqType::VBlank;
        let _ = GpuIrqType::HBlank;
        let _ = GpuIrqType::PageFault;
        let _ = GpuIrqType::Thermal;
    }

    #[test]
    fn test_gpu_softirq_types() {
        let _ = GpuSoftirq::VBlank(0);
        let _ = GpuSoftirq::FlipComplete(1);
        let _ = GpuSoftirq::Error;
        let _ = GpuSoftirq::Thermal;
        let _ = GpuSoftirq::Custom(7);
    }

    #[test]
    fn test_softirq_to_index() {
        assert_eq!(softirq_to_index(GpuSoftirq::VBlank(0)), 0);
        assert_eq!(softirq_to_index(GpuSoftirq::FlipComplete(0)), 1);
        assert_eq!(softirq_to_index(GpuSoftirq::Error), 2);
        assert_eq!(softirq_to_index(GpuSoftirq::Thermal), 3);
        assert_eq!(softirq_to_index(GpuSoftirq::Custom(5)), 9);
    }

    #[test]
    fn test_index_to_softirq() {
        assert!(matches!(index_to_softirq(0), GpuSoftirq::VBlank(_)));
        assert!(matches!(index_to_softirq(1), GpuSoftirq::FlipComplete(_)));
        assert!(matches!(index_to_softirq(2), GpuSoftirq::Error));
        assert!(matches!(index_to_softirq(3), GpuSoftirq::Thermal));
        assert!(matches!(index_to_softirq(10), GpuSoftirq::Custom(6)));
    }

    #[test]
    fn test_gpu_softirq_controller_new() {
        let controller = GpuSoftirqController::new();
        assert!(!controller.has_pending());
    }

    #[test]
    fn test_gpu_softirq_controller_raise() {
        let controller = GpuSoftirqController::new();
        controller.raise(GpuSoftirq::VBlank(0));
        assert!(controller.has_pending());
    }

    #[test]
    fn test_gpu_softirq_controller_roundtrip() {
        // Verify softirq can be converted to index and back
        let original = GpuSoftirq::FlipComplete(3);
        let idx = softirq_to_index(original);
        let recovered = index_to_softirq(idx);
        assert!(matches!(recovered, GpuSoftirq::FlipComplete(_)));
    }
}
