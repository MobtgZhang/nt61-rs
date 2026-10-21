//! Interrupt Handling Support
//! The canonical IRQL table lives in `crate::ke::irql`: NT 6.1 defines 32
//! IRQLs (0..31), with device IRQLs starting at 4. This module used to
//! define a second, incompatible 15-level table, which meant the same
//! numeric IRQL could mean different things depending on which module a
//! caller imported. The duplicate is removed; this module re-exports the
//! canonical table and delegates to the single implementation.

use core::sync::atomic::{AtomicU32, Ordering};

pub use crate::ke::irql::Irql;

/// Counter of IRQs dispatched through the unified AP path
/// (instrumentation for smoke tests and the Safe-Mode shell).
static AP_IRQ_COUNT: AtomicU32 = AtomicU32::new(0);

/// CPU index of the most recent dispatch through the unified AP path
/// (single-writer instrumentation; the HAL facade is called with
/// interrupts masked).
static LAST_AP_CPU: AtomicU32 = AtomicU32::new(0);

/// Unified AP interrupt-dispatch entry for the secondary interrupt
/// controllers: GIC (aarch64), PLIC (riscv64), LoongArch EXTIOI
/// (loongarch64). The per-arch backends keep their own ack/eoi
/// conventions; this facade normalizes the call shape so kernel code
/// (SMP IPI handling, scheduler reschedule IPIs) never needs cfg
/// blocks outside the HAL.
pub fn dispatch_ap_irq(cpu: u32, irq: u64) {
    AP_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_AP_CPU.store(cpu, Ordering::Relaxed);
    #[cfg(target_arch = "x86_64")]
    {
        // The x86_64 AP path is driven by the IDT/APIC vector table;
        // there is no line-numbered dispatch to forward here.
        let _ = (cpu, irq);
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::aarch64::apic::dispatch_irq(irq);
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::apic::dispatch_irq(irq as u32);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        // The EXTIOI backend acknowledges (clears pending) so the
        // line can re-fire; routing was already programmed by
        // interrupt::set_route.
        crate::arch::loongarch64::interrupt::eoi(irq as u32);
    }
}

/// Number of IRQs dispatched through the unified AP dispatcher.
pub fn ap_irq_count() -> u32 {
    AP_IRQ_COUNT.load(Ordering::Relaxed)
}

/// Register an interrupt handler
pub fn register_handler(_vector: u8, _handler: fn()) {
    // Register interrupt handler
}

/// Raise IRQL to `level`, returning the previous level.
pub fn raise_irql(level: Irql) -> Irql {
    crate::ke::irql::raise_irql(level)
}

/// Lower IRQL back to a level previously returned by `raise_irql`.
pub fn lower_irql(level: Irql) {
    crate::ke::irql::lower_irql(level);
}
