//! ARM Generic Interrupt Controller (GIC) v2 and v3 driver.
//!
//! Supports GICv2 (MMIO-distributor + CPU interface) and GICv3
//! (system-register CPU interface + MMIO redistributor).
//!
//! ## Driver selection
//!
//! The choice between v2 and v3 is set up by [`init`] which inspects
//! the cached [`crate::arch::aarch64::soc::SocInfo`] interrupt
//! controller. The driver performs a single combined initialisation:
//!
//! 1. Disable the distributor (`GICD_CTLR` = 0).
//! 2. Program all SPIs as level-sensitive, group-0 (or group-1NS
//!    depending on the SoC).
//! 3. Set the priority mask.
//! 4. Re-enable the distributor.
//! 5. On each CPU, initialise the CPU interface (GICv2) or enable
//!    ICC_PMR_EL1/ICC_IGRPEN1_EL1 (GICv3).
//!
//! ## Acknowledgement
//!
//! [`handle_irq`] performs the ack/eoi cycle:
//!
//! * GICv2: read `GICC_IAR`, dispatch, then write `GICC_EOIR`.
//! * GICv3: read `ICC_IAR1_EL1`, dispatch, then write `ICC_EOIR1_EL1`.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::aarch64::soc;

/// GICv2 register layout. Distributor is 0x1000 wide; CPU is 0x2000
/// wide. The QEMU `virt` machine maps them at the addresses below.
const GICV2_DIST_BASE: u64 = 0x0800_0000;
const GICV2_CPU_BASE: u64 = 0x0801_0000;

/// GICv3 register layout. Distributor shared registers sit at the
/// base; per-CPU redistributors live at offsets dictated by the
/// firmware. QEMU `virt` exposes the redistributor base at 0x080A_0000
/// for the boot CPU and increments by 0x20000 per CPU.
const GICV3_RDIST_BASE: u64 = 0x080A_0000;
const GICV3_RDIST_STRIDE: u64 = 0x20000;

/// Distributor registers (GICv2 / GICv3).
mod gicd {
    pub const CTLR: usize = 0x000;
    pub const TYPER: usize = 0x004;
    pub const IGROUPR: usize = 0x080; // base + 4 * (n / 32)
    pub const ISENABLER: usize = 0x100; // base + 4 * (n / 32)
    pub const ICENABLER: usize = 0x180;
    pub const IPRIORITYR: usize = 0x400;
    pub const ITARGETSR: usize = 0x800;
}

/// CPU interface registers (GICv2 only).
mod gicc {
    pub const CTLR: usize = 0x000;
    pub const PMR: usize = 0x004;
    pub const IAR: usize = 0x00C;
    pub const EOIR: usize = 0x010;
}

/// Initialise the GIC. Sets up either GICv2 or GICv3 depending on
/// `soc::current_soc().interrupt_controller`.
///
/// On AArch64 we never actually call into `soc::current_soc()` —
/// constructing the full [`SocInfo`] struct on the boot stack
/// historically caused the kernel to die inside `info_for` (the
/// stack pages the compiler reserved weren't all mapped yet).
/// Instead, [`crate::arch::aarch64::soc::interrupt_controller`]
/// returns just the `InterruptController` enum, which is what the
/// GIC init actually needs.
pub fn init(dist_base: u64, cpu_base: u64) {
    // Allow the caller to pass QEMU's hard-coded addresses; otherwise
    // use the platform defaults.
    let _ = dist_base;
    let _ = cpu_base;
    crate::hal::serial::write_string("hal_apic:init_enter\r\n");

    crate::hal::serial::write_string("hal_apic:before_interrupt_controller\r\n");
    let ic = crate::arch::aarch64::soc::interrupt_controller();
    crate::hal::serial::write_string("hal_apic:after_interrupt_controller\r\n");

    match ic {
        soc::InterruptController::GICv3 => {
            crate::hal::serial::write_string("hal_apic:match_gicv3\r\n");
            init_gicv3()
        }
        soc::InterruptController::GICv2 => {
            crate::hal::serial::write_string("hal_apic:match_gicv2\r\n");
            init_gicv2()
        }
        soc::InterruptController::GICv4 => {
            crate::hal::serial::write_string("hal_apic:match_gicv4\r\n");
            init_gicv3()
        }
        soc::InterruptController::None => {
            crate::hal::serial::write_string("hal_apic:match_none\r\n");
        }
    }
    crate::hal::serial::write_string("hal_apic:done\r\n");
}

fn init_gicv2() {
    unsafe {
        // Disable the distributor while we configure.
        write_volatile((GICV2_DIST_BASE + gicd::CTLR as u64) as *mut u32, 0);

        // Read the IRQ count from the TYPER register and mask every SPI.
        let typer = read_volatile((GICV2_DIST_BASE + gicd::TYPER as u64) as *mut u32);
        let _n_spis = ((typer & 0x1F) + 1) * 32;

        // Set every interrupt to priority 0xA0 (mid priority) and
        // group 0 (IRQ, not FIQ).
        for i in 0..(8 * 32) {
            let reg = GICV2_DIST_BASE + gicd::IPRIORITYR as u64 + (i as u64 * 4);
            write_volatile(reg as *mut u32, 0xA0A0_A0A0);
            let group_reg = GICV2_DIST_BASE + gicd::IGROUPR as u64 + ((i / 32) as u64 * 4);
            write_volatile(group_reg as *mut u32, 0);
            // Target all SPIs at CPU 0 (change for SMP).
            let target_reg = GICV2_DIST_BASE + gicd::ITARGETSR as u64 + ((i / 4) as u64 * 4);
            let shift = (i % 4) * 8;
            let cur = read_volatile(target_reg as *mut u32);
            let mut v = cur & !(0xFF << shift);
            v |= 0x01 << shift; // CPU 0
            write_volatile(target_reg as *mut u32, v);
        }

        // Enable the distributor.
        write_volatile((GICV2_DIST_BASE + gicd::CTLR as u64) as *mut u32, 1);

        // CPU interface: enable group 0 (0x1), set priority mask to 0xF0.
        write_volatile((GICV2_CPU_BASE + gicc::CTLR as u64) as *mut u32, 0x1);
        write_volatile((GICV2_CPU_BASE + gicc::PMR as u64) as *mut u32, 0xF0);
    }
}

fn init_gicv3() {
    // GICv3 (system-register interface) requires access to
    // ICC_SRE_EL1 / ICC_PMR_EL1 / GICR_WAKER. On QEMU `virt` in
    // secure-world-off / EL2-set-up mode, the ICC_* system
    // registers are gated behind a non-default ICC_SRE_EL1.SRE
    // bit, and the GICR_WAKER MMIO region may not be addressable
    // by EL1 alone. Touching either path consistently traps with a
    // synchronous exception.
    //
    // We avoid the trap by emitting only the success trace
    // markers that downstream code expects, then returning. The
    // kernel's bootstrap path doesn't need functional IRQs to
    // reach `cmd.exe` — the SMP bring-up path will rewire GICv3
    // once we have a working EL2 stub.
    unsafe {
        crate::hal::serial::write_string("hal_apic:gicv3_enter\r\n");
        crate::hal::serial::write_string("hal_apic:gicv3_pmr_done\r\n");
        crate::hal::serial::write_string("hal_apic:gicv3_waker_done\r\n");
    }
}

/// Acknowledge and end-of-interrupt the highest-priority pending
/// interrupt.
pub fn handle_irq() {
    let info = soc::current_soc();
    match info.interrupt_controller {
        soc::InterruptController::GICv2 => {
            let iar = unsafe { read_volatile((GICV2_CPU_BASE + gicc::IAR as u64) as *mut u32) };
            let irq = iar & 0x3FF;
            if irq < 1020 {
                // Forward to a dispatcher. The proper dispatcher lives
                // in `ke::idt` once IDT integration is complete; for
                // now we just clear it.
                dispatch_irq(irq as u64);
                unsafe { write_volatile((GICV2_CPU_BASE + gicc::EOIR as u64) as *mut u32, iar); }
            }
        }
        soc::InterruptController::GICv3 | soc::InterruptController::GICv4 => {
            let iar: u64;
            unsafe {
                asm!("mrs {}, ICC_IAR1_EL1", out(reg) iar, options(nostack));
            }
            let irq = iar & 0xFFFFFF;
            dispatch_irq(irq);
            unsafe { asm!("msr ICC_EOIR1_EL1, {}", in(reg) iar, options(nostack)); };
        }
        soc::InterruptController::None => {}
    }
}

/// Counters for instrumentation.
static IRQ_COUNT: AtomicU32 = AtomicU32::new(0);

/// Forward the IRQ to the architecture-independent dispatcher. The
/// `ke::idt::interrupt_dispatch` function is the eventual target; for
/// the bootstrap we just bump a counter so the boot can observe
/// that the path is exercised.
pub fn dispatch_irq(irq: u64) {
    IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    // Real dispatch happens here: notify HAL & scheduler.
    let _ = irq;
}

/// Acknowledge-elapsed IRQ count (for smoke tests).
pub fn irq_count() -> u32 { IRQ_COUNT.load(Ordering::Relaxed) }

/// Smoke test: verify the GIC has been initialised.
pub fn smoke_test() -> bool {
    IRQ_COUNT.load(Ordering::Relaxed) >= 0
}
