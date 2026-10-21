//! Unified keyboard input ring (cross-architecture).
//!
//! On x86_64 the canonical implementation lives in
//! `crate::hal::x86_64::keyboard_unified` (PS/2 8042 + USB-HID).
//! This module is the equivalent facade for the other three
//! architectures — aarch64 (PL011), riscv64 (NS16550A) and
//! loongarch64 (8250/16550-compatible) — where the operator's
//! keyboard reaches the kernel through the UART and, when
//! present, a virtio-input device.
//!
//! # Data flow
//!
//! ```ignore
//! UART RX interrupt handler (arch/)  ──▶  serial_rx_irq()  ──┐
//! virtio-input device poll           ──▶  try_read_byte()  ◀┤ ring
//! polled serial fallback (SafeMode)  ──▶  try_read_byte()  ──┘
//! ```
//!
//! `inject_byte` feeds the ring programmatically (e.g. a USB-HID
//! stack once the non-x86 USB controllers are wired). Consumers
//! — the Ring-3 cmd.exe input loop, the SafeBootMode shell — all
//! call `try_read_byte`.
//!
//! # Interrupt wiring contract
//!
//! `enable_serial_rx_irq` arms the UART receive interrupt in the
//! peripheral only. The HAL deliberately does NOT enable the CPU
//! interrupt controller line: the GIC / PLIC / EXTIOI dispatch
//! code and the exception vector that calls `serial_rx_irq`
//! live in `arch/`, and arming hardware IRQs without a
//! registered handler would storm. `disable_serial_rx_irq`
//! masks the peripheral again.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Ring capacity in bytes. Deep enough to absorb a full UART
/// FIFO burst plus a fast typist between polls, matching the
/// x86_64 PS/2 ring's sizing.
const RING_CAPACITY: usize = 256;

/// Single-producer/multi-use byte ring guarded by a spin lock.
/// A lock is used instead of lock-free counters because both the
/// serial RX interrupt handler and the polling path can push
/// concurrently from different CPUs.
struct KeyboardRing {
    lock: AtomicBool,
    /// Read index; only `pop` advances it.
    head: AtomicUsize,
    /// Write index; every producer advances it under the lock.
    tail: AtomicUsize,
    buffer: core::cell::UnsafeCell<[u8; RING_CAPACITY]>,
    /// Bytes dropped because the ring was full.
    dropped: AtomicUsize,
}

static RING: KeyboardRing = KeyboardRing {
    lock: AtomicBool::new(false),
    head: AtomicUsize::new(0),
    tail: AtomicUsize::new(0),
    buffer: core::cell::UnsafeCell::new([0u8; RING_CAPACITY]),
    dropped: AtomicUsize::new(0),
};

// SAFETY: `RING.buffer` is only accessed through `UnsafeCell::get` under
// the spin lock (`RING.lock`), which serialises all reads and writes.
unsafe impl Sync for KeyboardRing {}

/// Acquire the ring's spin lock.
fn lock_ring() {
    while RING
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

/// Release the ring's spin lock.
fn unlock_ring() {
    RING.lock.store(false, Ordering::Release);
}

/// Push one byte into the ring. Drops (and counts) the byte when
/// the ring is full.
fn push_byte(c: u8) {
    lock_ring();
    let head = RING.head.load(Ordering::Relaxed);
    let tail = RING.tail.load(Ordering::Relaxed);
    if tail - head >= RING_CAPACITY {
        unlock_ring();
        RING.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    unsafe {
        let base = RING.buffer.get().cast::<u8>();
        let slot = base.add(tail % RING_CAPACITY);
        core::ptr::write_volatile(slot, c);
    }
    RING.tail.store(tail.wrapping_add(1), Ordering::Release);
    unlock_ring();
}

/// Pop one byte from the ring, or `None` when empty.
fn pop_byte() -> Option<u8> {
    lock_ring();
    let head = RING.head.load(Ordering::Relaxed);
    let tail = RING.tail.load(Ordering::Relaxed);
    if head == tail {
        unlock_ring();
        return None;
    }
    let byte = unsafe {
        let base = RING.buffer.get().cast::<u8>();
        let slot = base.add(head % RING_CAPACITY);
        core::ptr::read_volatile(slot)
    };
    RING.head.store(head.wrapping_add(1), Ordering::Release);
    unlock_ring();
    Some(byte)
}

/// Enqueue a decoded keyboard byte into the unified ring. The
/// x86_64 PS/2 / USB-HID path mirrors this through
/// `hal::x86_64::keyboard_unified::inject_byte`.
pub fn inject_byte(c: u8) {
    push_byte(c);
}

/// Try to read one byte without blocking. The ring (fed by the
/// serial RX interrupt or `inject_byte`) is drained first;
/// when it is empty the virtio-input device is polled, and as a
/// last resort the UART is polled directly (the SafeBootMode
/// shell runs before the interrupt controllers are wired, so
/// this fallback is the path that makes typing work there).
pub fn try_read_byte() -> Option<u8> {
    if let Some(b) = pop_byte() {
        return Some(b);
    }
    if let Some(b) = crate::drivers::input::virtio_input::try_read_byte() {
        return Some(b);
    }
    poll_serial_once()
}

/// Coarse "is input pending?" probe used by callers that want to
/// avoid spinning.
pub fn peek() -> bool {
    if ring_has_data() {
        return true;
    }
    crate::drivers::input::virtio_input::is_present() || serial_data_available()
}

/// True when the ring holds at least one unconsumed byte.
fn ring_has_data() -> bool {
    lock_ring();
    let head = RING.head.load(Ordering::Relaxed);
    let tail = RING.tail.load(Ordering::Relaxed);
    unlock_ring();
    head != tail
}

/// Poll the virtio-input device (aggregates its queue into the
/// ring when it produced bytes).
pub fn poll() {
    crate::drivers::input::virtio_input::poll();
}

/// Number of bytes dropped because the ring was full.
pub fn dropped_count() -> usize {
    RING.dropped.load(Ordering::Relaxed)
}

/// Serial RX interrupt drain hook. The per-architecture
/// exception handler calls this from the UART IRQ vector; it
/// drains the whole receive FIFO into the ring and then clears
/// the peripheral's latched interrupt so the line can fire
/// again.
pub fn serial_rx_irq() {
    drain_serial_fifo();
    serial_clear_rx_irq();
}

/// Arm the UART receive interrupt in the peripheral.
pub fn enable_serial_rx_irq() {
    serial_enable_rx_irq();
}

/// Mask the UART receive interrupt in the peripheral.
pub fn disable_serial_rx_irq() {
    serial_disable_rx_irq();
}

/// Drain the UART receive FIFO into the ring (one batch).
fn drain_serial_fifo() {
    while let Some(byte) = poll_serial_once() {
        push_byte(byte);
    }
}

/// True when the architecture's UART has a byte pending.
fn serial_data_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::serial::data_available()
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::hal::riscv64::serial::data_available()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::hal::loongarch64::serial::data_available()
    }
}

/// Non-blocking single-byte poll of the architecture's UART.
fn poll_serial_once() -> Option<u8> {
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::serial::try_get_char()
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::hal::riscv64::serial::try_get_char()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::hal::loongarch64::serial::try_get_char()
    }
}

/// Clear the peripheral's latched receive interrupt so the line
/// can fire again after a drain pass.
fn serial_clear_rx_irq() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::serial::clear_rx_irq();
    }
}

/// Arm the architecture's UART receive interrupt in the
/// peripheral.
fn serial_enable_rx_irq() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::serial::enable_rx_irq();
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::hal::riscv64::serial::enable_rx_irq();
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::hal::loongarch64::serial::enable_rx_irq();
    }
}

/// Mask the architecture's UART receive interrupt in the
/// peripheral.
fn serial_disable_rx_irq() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::serial::disable_rx_irq();
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::hal::riscv64::serial::disable_rx_irq();
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::hal::loongarch64::serial::disable_rx_irq();
    }
}
