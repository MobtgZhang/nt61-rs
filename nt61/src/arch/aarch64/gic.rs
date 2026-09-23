//! AArch64 GIC (Generic Interrupt Controller) driver - Enhanced
//!
//! Comprehensive GICv2/GICv3 implementation with:
//! - Full distributor and CPU interface management
//! - IPI (Inter-Processor Interrupt) support for SMP
//! - Priority and affinity configuration
//! - SGI, PPI, and SPI handling

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// GIC version detected at runtime
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    None,
    V2,
    V3,
    V4,
}

static GIC_VERSION: AtomicU64 = AtomicU64::new(0);
static GIC_DIST_BASE: AtomicU64 = AtomicU64::new(0x0800_0000);
static GIC_CPU_BASE: AtomicU64 = AtomicU64::new(0x0801_0000);
static GIC_RDIST_BASE: AtomicU64 = AtomicU64::new(0x080A_0000);
static GIC_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Interrupt types
pub const IRQ_TYPE_EDGE_RISING: u32 = 0x01;
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 0x04;

/// SGI (Software Generated Interrupt) range: 0-15
pub const SGI_BASE: u32 = 0;
pub const SGI_MAX: u32 = 15;

/// PPI (Private Peripheral Interrupt) range: 16-31
pub const PPI_BASE: u32 = 16;
pub const PPI_MAX: u32 = 31;

/// SPI (Shared Peripheral Interrupt) range: 32+
pub const SPI_BASE: u32 = 32;

/// GICv2 Distributor register offsets

mod gicd {
    pub const CTLR: usize = 0x000;
    pub const TYPER: usize = 0x004;
    pub const IIDR: usize = 0x008;
    pub const IGROUPR: usize = 0x080;
    pub const ISENABLER: usize = 0x100;
    pub const ICENABLER: usize = 0x180;
    pub const ISPENDR: usize = 0x200;
    pub const ICPENDR: usize = 0x280;
    pub const ISACTIVER: usize = 0x300;
    pub const ICACTIVER: usize = 0x380;
    pub const IPRIORITYR: usize = 0x400;
    pub const ITARGETSR: usize = 0x800;
    pub const ICFGR: usize = 0xC00;
    pub const SGIR: usize = 0xF00;
}

/// GICv2 CPU interface register offsets
mod gicc {
    pub const CTLR: usize = 0x000;
    pub const PMR: usize = 0x004;
    pub const BPR: usize = 0x008;
    pub const IAR: usize = 0x00C;
    pub const EOIR: usize = 0x010;
    pub const RPR: usize = 0x014;
    pub const HPPIR: usize = 0x018;
}

/// Initialize GIC with auto-detection
pub fn init(dist_base: u64, cpu_base: u64) {
    GIC_DIST_BASE.store(dist_base, Ordering::Release);
    GIC_CPU_BASE.store(cpu_base, Ordering::Release);

    // Detect GIC version by checking ID registers
    let version = detect_gic_version();
    GIC_VERSION.store(version as u64, Ordering::Release);

    match version {
        GicVersion::V2 => init_gicv2(),
        GicVersion::V3 | GicVersion::V4 => init_gicv3(),
        GicVersion::None => {}
    }

    GIC_INITIALIZED.store(true, Ordering::Release);
}

/// Detect GIC version from hardware
fn detect_gic_version() -> GicVersion {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);

    unsafe {
        // Try to read GICD_IIDR to determine version
        let iidr = read_volatile((dist_base + gicd::IIDR as u64) as *const u32);

        // Check for GICv3/v4 system register interface
        let mut icc_sre: u64;
        asm!("mrs {}, ICC_SRE_EL1", out(reg) icc_sre, options(nostack));

        if (icc_sre & 0x1) != 0 {
            // System register interface enabled - GICv3 or later
            if (iidr >> 16) & 0xF >= 4 {
                GicVersion::V4
            } else {
                GicVersion::V3
            }
        } else {
            // Memory-mapped interface - GICv2
            GicVersion::V2
        }
    }
}

/// Initialize GICv2
fn init_gicv2() {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let cpu_base = GIC_CPU_BASE.load(Ordering::Acquire);

    unsafe {
        // 1. Disable distributor
        write_volatile((dist_base + gicd::CTLR as u64) as *mut u32, 0);

        // 2. Read number of interrupt lines
        let typer = read_volatile((dist_base + gicd::TYPER as u64) as *const u32);
        let max_irqs = ((typer & 0x1F) + 1) * 32;

        // 3. Configure all interrupts
        for i in 0..max_irqs {
            let word_offset = (i / 32) as u64;
            let bit_offset = i % 32;

            // Disable interrupt
            let icenabler = dist_base + gicd::ICENABLER as u64 + word_offset * 4;
            write_volatile(icenabler as *mut u32, 1 << bit_offset);

            // Clear pending
            let icpendr = dist_base + gicd::ICPENDR as u64 + word_offset * 4;
            write_volatile(icpendr as *mut u32, 1 << bit_offset);

            // Set to Group 1 (non-secure)
            let igroupr = dist_base + gicd::IGROUPR as u64 + word_offset * 4;
            let group_val = read_volatile(igroupr as *const u32);
            write_volatile(igroupr as *mut u32, group_val | (1 << bit_offset));
        }

        // 4. Set priority for all interrupts (0xA0 = middle priority)
        for i in 0..(max_irqs / 4) {
            let ipriorityr = dist_base + gicd::IPRIORITYR as u64 + (i as u64) * 4;
            write_volatile(ipriorityr as *mut u32, 0xA0A0_A0A0);
        }

        // 5. Target all SPIs to CPU0
        for i in (SPI_BASE / 4)..(max_irqs / 4) {
            let itargetsr = dist_base + gicd::ITARGETSR as u64 + (i as u64) * 4;
            write_volatile(itargetsr as *mut u32, 0x0101_0101);
        }

        // 6. Configure all as level-sensitive (default)
        for i in 0..(max_irqs / 16) {
            let icfgr = dist_base + gicd::ICFGR as u64 + (i as u64) * 4;
            write_volatile(icfgr as *mut u32, 0);
        }

        // 7. Enable distributor
        write_volatile((dist_base + gicd::CTLR as u64) as *mut u32, 0x03); // Enable Group 0 and 1

        // 8. Initialize CPU interface
        // Set priority mask to allow all priorities
        write_volatile((cpu_base + gicc::PMR as u64) as *mut u32, 0xFF);

        // Set binary point to maximum preemption
        write_volatile((cpu_base + gicc::BPR as u64) as *mut u32, 0);

        // Enable CPU interface for both groups
        write_volatile((cpu_base + gicc::CTLR as u64) as *mut u32, 0x03);
    }
}

/// Initialize GICv3 with system registers
fn init_gicv3() {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);

    unsafe {
        // 1. Enable system register interface
        let mut icc_sre: u64;
        asm!("mrs {}, ICC_SRE_EL1", out(reg) icc_sre, options(nostack));
        icc_sre |= 0x7; // Enable SRE, disable IRQ/FIQ bypass
        asm!("msr ICC_SRE_EL1, {}", in(reg) icc_sre, options(nostack));
        asm!("isb", options(nostack));

        // 2. Disable distributor
        write_volatile((dist_base + gicd::CTLR as u64) as *mut u32, 0);

        // 3. Read number of interrupt lines
        let typer = read_volatile((dist_base + gicd::TYPER as u64) as *const u32);
        let max_irqs = ((typer & 0x1F) + 1) * 32;

        // 4. Configure SPIs in distributor
        for i in SPI_BASE..max_irqs {
            let word_offset = (i / 32) as u64;
            let bit_offset = i % 32;

            // Disable and clear pending
            let icenabler = dist_base + gicd::ICENABLER as u64 + word_offset * 4;
            write_volatile(icenabler as *mut u32, 1 << bit_offset);

            // Set to Group 1 non-secure
            let igroupr = dist_base + gicd::IGROUPR as u64 + word_offset * 4;
            let group_val = read_volatile(igroupr as *const u32);
            write_volatile(igroupr as *mut u32, group_val | (1 << bit_offset));
        }

        // 5. Enable distributor for Group 1 non-secure
        write_volatile((dist_base + gicd::CTLR as u64) as *mut u32, 0x02);

        // 6. Configure CPU interface via system registers
        // Set priority mask to allow all
        asm!("msr ICC_PMR_EL1, {}", in(reg) 0xFFu64, options(nostack));

        // Set binary point
        asm!("msr ICC_BPR1_EL1, {}", in(reg) 0u64, options(nostack));

        // Enable Group 1 interrupts
        asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) 1u64, options(nostack));

        asm!("isb", options(nostack));
    }
}

/// Enable a specific interrupt
pub fn enable_irq(irq: u32) {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let word_offset = (irq / 32) as u64;
    let bit_offset = irq % 32;

    unsafe {
        let isenabler = dist_base + gicd::ISENABLER as u64 + word_offset * 4;
        write_volatile(isenabler as *mut u32, 1 << bit_offset);
    }
}

/// Disable a specific interrupt
pub fn disable_irq(irq: u32) {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let word_offset = (irq / 32) as u64;
    let bit_offset = irq % 32;

    unsafe {
        let icenabler = dist_base + gicd::ICENABLER as u64 + word_offset * 4;
        write_volatile(icenabler as *mut u32, 1 << bit_offset);
    }
}

/// Set interrupt priority (0 = highest, 255 = lowest)
pub fn set_priority(irq: u32, priority: u8) {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let byte_offset = irq as u64;

    unsafe {
        let ipriorityr = (dist_base + gicd::IPRIORITYR as u64 + byte_offset) as *mut u8;
        write_volatile(ipriorityr, priority);
    }
}

/// Set interrupt target CPU (GICv2 only)
pub fn set_target(irq: u32, cpu_mask: u8) {
    if GIC_VERSION.load(Ordering::Acquire) != GicVersion::V2 as u64 {
        return;
    }

    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let byte_offset = irq as u64;

    unsafe {
        let itargetsr = (dist_base + gicd::ITARGETSR as u64 + byte_offset) as *mut u8;
        write_volatile(itargetsr, cpu_mask);
    }
}

/// Configure interrupt trigger type
pub fn set_trigger_type(irq: u32, trigger_type: u32) {
    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);
    let word_offset = (irq / 16) as u64;
    let bit_offset = (irq % 16) * 2;

    unsafe {
        let icfgr = dist_base + gicd::ICFGR as u64 + word_offset * 4;
        let mut val = read_volatile(icfgr as *const u32);

        // Clear existing configuration
        val &= !(0x3 << bit_offset);

        // Set new configuration (bit 1: 0=level, 1=edge)
        if trigger_type == IRQ_TYPE_EDGE_RISING {
            val |= 0x2 << bit_offset;
        }

        write_volatile(icfgr as *mut u32, val);
    }
}

/// Send IPI (Inter-Processor Interrupt) - GICv2
pub fn send_ipi_v2(target_cpus: u32, sgi_id: u32) {
    if sgi_id > SGI_MAX {
        return;
    }

    let dist_base = GIC_DIST_BASE.load(Ordering::Acquire);

    unsafe {
        // SGIR format: [31:26]=reserved, [25:24]=target_list_filter,
        // [23:16]=cpu_target_list, [15]=NSATT, [3:0]=INTID
        let sgir_val = ((target_cpus & 0xFF) << 16) | (sgi_id & 0xF);
        write_volatile((dist_base + gicd::SGIR as u64) as *mut u32, sgir_val);
    }
}

/// Send IPI - GICv3 uses system registers
pub fn send_ipi_v3(target_cpu: u64, sgi_id: u32) {
    if sgi_id > SGI_MAX {
        return;
    }

    unsafe {
        // ICC_SGI1R_EL1: [55:48]=Aff3, [39:32]=Aff2, [23:16]=Aff1,
        // [15:0]=target_list + INTID
        let sgi1r_val = (target_cpu << 16) | (sgi_id as u64);
        asm!("msr ICC_SGI1R_EL1, {}", in(reg) sgi1r_val, options(nostack));
        asm!("isb", options(nostack));
    }
}

/// Send IPI to specific CPU
pub fn send_ipi(target_cpu: u32, sgi_id: u32) {
    let version = GIC_VERSION.load(Ordering::Acquire);

    match version {
        v if v == GicVersion::V2 as u64 => {
            send_ipi_v2(1 << target_cpu, sgi_id);
        }
        v if v == GicVersion::V3 as u64 || v == GicVersion::V4 as u64 => {
            send_ipi_v3(target_cpu as u64, sgi_id);
        }
        _ => {}
    }
}

/// Acknowledge and handle interrupt
pub fn handle_irq() -> u32 {
    let version = GIC_VERSION.load(Ordering::Acquire);

    match version {
        v if v == GicVersion::V2 as u64 => handle_irq_v2(),
        v if v == GicVersion::V3 as u64 || v == GicVersion::V4 as u64 => handle_irq_v3(),
        _ => 1023, // Spurious interrupt
    }
}

fn handle_irq_v2() -> u32 {
    let cpu_base = GIC_CPU_BASE.load(Ordering::Acquire);

    unsafe {
        let iar = read_volatile((cpu_base + gicc::IAR as u64) as *const u32);
        let irq = iar & 0x3FF;

        if irq < 1020 {
            // Valid interrupt - will be handled by caller
            irq
        } else {
            1023 // Spurious
        }
    }
}

fn handle_irq_v3() -> u32 {
    unsafe {
        let iar: u64;
        asm!("mrs {}, ICC_IAR1_EL1", out(reg) iar, options(nostack));
        (iar & 0xFFFFFF) as u32
    }
}

/// End of interrupt
pub fn eoi(irq: u32) {
    let version = GIC_VERSION.load(Ordering::Acquire);

    match version {
        v if v == GicVersion::V2 as u64 => eoi_v2(irq),
        v if v == GicVersion::V3 as u64 || v == GicVersion::V4 as u64 => eoi_v3(irq),
        _ => {}
    }
}

fn eoi_v2(irq: u32) {
    let cpu_base = GIC_CPU_BASE.load(Ordering::Acquire);
    unsafe {
        write_volatile((cpu_base + gicc::EOIR as u64) as *mut u32, irq);
    }
}

fn eoi_v3(irq: u32) {
    unsafe {
        asm!("msr ICC_EOIR1_EL1, {}", in(reg) irq as u64, options(nostack));
    }
}

/// Check if GIC is initialized
pub fn is_initialized() -> bool {
    GIC_INITIALIZED.load(Ordering::Acquire)
}

/// Get GIC version
pub fn version() -> GicVersion {
    match GIC_VERSION.load(Ordering::Acquire) {
        0 => GicVersion::None,
        1 => GicVersion::V2,
        2 => GicVersion::V3,
        3 => GicVersion::V4,
        _ => GicVersion::None,
    }
}
