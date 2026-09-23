//! Per-CPU Data Structure
//
//! Each CPU has its own private data area stored via the GS base register.
//! This provides fast access to CPU-local state without requiring locks.
//
//! The Per-CPU area contains:
//! - CPU identification (CPU ID, APIC ID)
//! - Current thread and idle thread pointers
//! - Interrupt and IRQL state
//! - Scheduling statistics
//! - Memory management state (PML4, kernel stack)

use core::arch::asm;
use crate::ke::sync::Spinlock;

/// Per-CPU data structure (stored at GS:0)
#[repr(C)]
pub struct PerCpuData {
    /// Self-pointer (for validation)
    pub self_ptr: u64,

    /// CPU identification
    pub cpu_id: u32,
    pub apic_id: u32,

    /// Scheduling state
    pub current_thread: *mut crate::ps::thread::Ethread,
    pub idle_thread: *mut crate::ps::thread::Ethread,
    pub scheduler_lock: Spinlock<()>,
    pub need_reschedule: bool,

    /// Interrupt state
    pub interrupt_count: u32,
    pub irql: u8,
    pub in_interrupt: bool,
    pub interrupt_disable_count: u32,

    /// Timing
    pub ticks: u64,
    pub tsc_frequency: u64,
    pub last_schedule_tsc: u64,

    /// Memory management
    pub pml4_phys: u64,
    pub kernel_stack_top: u64,
    pub kernel_stack_size: u64,

    /// Statistics
    pub context_switches: u64,
    pub interrupts_processed: u64,
    pub ipi_count: u64,
    pub tlb_flushes: u64,
}

impl PerCpuData {
    /// Create a new Per-CPU data structure

    pub const fn new(cpu_id: u32, apic_id: u32) -> Self {
        Self {
            self_ptr: 0,
            cpu_id,
            apic_id,
            current_thread: core::ptr::null_mut(),
            idle_thread: core::ptr::null_mut(),
            scheduler_lock: Spinlock::new(()),
            need_reschedule: false,
            interrupt_count: 0,
            irql: 0,
            in_interrupt: false,
            interrupt_disable_count: 0,
            ticks: 0,
            tsc_frequency: 0,
            last_schedule_tsc: 0,
            pml4_phys: 0,
            kernel_stack_top: 0,
            kernel_stack_size: 0,
            context_switches: 0,
            interrupts_processed: 0,
            ipi_count: 0,
            tlb_flushes: 0,
        }
    }

    /// Get the current CPU's Per-CPU data
    ///
    /// SAFETY: Must be called after Per-CPU data has been initialized
    /// for this CPU. Returns a mutable reference with 'static lifetime
    /// because Per-CPU data lives in a static array.
    #[inline]
    pub fn current() -> &'static mut Self {
        unsafe {
            let ptr: u64;
            // Read GS:0 which contains the self-pointer
            asm!("mov {}, gs:0", out(reg) ptr, options(nostack, preserves_flags));
            &mut *(ptr as *mut Self)
        }
    }

    /// Try to get current CPU data (returns None if not initialized)
    #[inline]
    pub fn try_current() -> Option<&'static mut Self> {
        unsafe {
            let ptr: u64;
            asm!("mov {}, gs:0", out(reg) ptr, options(nostack, preserves_flags));
            if ptr == 0 {
                None
            } else {
                Some(&mut *(ptr as *mut Self))
            }
        }
    }

    /// Install this Per-CPU data as the current CPU's GS base
    pub fn install(&mut self) {
        // Set self-pointer for validation
        self.self_ptr = self as *mut _ as u64;

        unsafe {
            let addr = self as *mut _ as u64;

            // Write to IA32_GS_BASE MSR (0xC0000101)
            // This sets the base address for GS-relative addressing
            asm!(
                "wrmsr",
                in("ecx") 0xC0000101u32,
                in("eax") (addr & 0xFFFFFFFF) as u32,
                in("edx") (addr >> 32) as u32,
                options(nostack, preserves_flags)
            );

            // Also write to IA32_KERNEL_GS_BASE (0xC0000102)
            // This is used during SWAPGS in syscall entry
            asm!(
                "wrmsr",
                in("ecx") 0xC0000102u32,
                in("eax") (addr & 0xFFFFFFFF) as u32,
                in("edx") (addr >> 32) as u32,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Verify this Per-CPU data is valid
    pub fn validate(&self) -> bool {
        self.self_ptr == (self as *const _ as u64)
    }

    /// Get current CPU ID (fast path)
    #[inline]
    pub fn cpu_id_fast() -> u32 {
        unsafe {
            let id: u32;
            asm!(
                "mov {0:e}, gs:[{1}]",
                out(reg) id,
                const core::mem::offset_of!(PerCpuData, cpu_id),
                options(nostack, preserves_flags, readonly)
            );
            id
        }
    }

    /// Get current APIC ID (fast path)
    #[inline]
    pub fn apic_id_fast() -> u32 {
        unsafe {
            let id: u32;
            asm!(
                "mov {0:e}, gs:[{1}]",
                out(reg) id,
                const core::mem::offset_of!(PerCpuData, apic_id),
                options(nostack, preserves_flags, readonly)
            );
            id
        }
    }

    /// Mark that a reschedule is needed
    pub fn set_need_reschedule(&mut self) {
        self.need_reschedule = true;
    }

    /// Clear the reschedule flag
    pub fn clear_need_reschedule(&mut self) {
        self.need_reschedule = false;
    }

    /// Check if reschedule is needed
    pub fn should_reschedule(&self) -> bool {
        self.need_reschedule
    }
}

// Global Per-CPU data array (one entry per CPU)
// Maximum 256 CPUs supported
static mut PER_CPU_DATA: [PerCpuData; 256] = [const { PerCpuData::new(0, 0) }; 256];

/// Initialize BSP (Bootstrap Processor) Per-CPU data
pub fn init_bsp() {
    unsafe {
        PER_CPU_DATA[0].cpu_id = 0;
        PER_CPU_DATA[0].apic_id = 0; // BSP APIC ID is typically 0
        PER_CPU_DATA[0].install();
    }

    // Validate installation
    let percpu = PerCpuData::current();
    assert!(percpu.validate(), "BSP Per-CPU data validation failed");
}

/// Initialize AP (Application Processor) Per-CPU data
pub fn init_ap(cpu_id: u32, apic_id: u32) {
    unsafe {
        if (cpu_id as usize) >= PER_CPU_DATA.len() {
            panic!("CPU ID {} exceeds maximum supported CPUs", cpu_id);
        }

        PER_CPU_DATA[cpu_id as usize].cpu_id = cpu_id;
        PER_CPU_DATA[cpu_id as usize].apic_id = apic_id;
        PER_CPU_DATA[cpu_id as usize].install();
    }

    // Validate installation
    let percpu = PerCpuData::current();
    assert!(percpu.validate(), "AP {} Per-CPU data validation failed", cpu_id);
}

/// Get Per-CPU data for a specific CPU (by CPU ID)
pub fn get_cpu_data(cpu_id: u32) -> Option<&'static mut PerCpuData> {
    unsafe {
        if (cpu_id as usize) >= PER_CPU_DATA.len() {
            return None;
        }

        let data = &mut PER_CPU_DATA[cpu_id as usize];
        if data.self_ptr == 0 {
            None
        } else {
            Some(data)
        }
    }
}

/// Get the number of initialized CPUs
pub fn get_cpu_count() -> u32 {
    unsafe {
        let mut count = 0;
        for cpu in &PER_CPU_DATA {
            if cpu.self_ptr != 0 {
                count += 1;
            }
        }
        count
    }
}

/// Read the TSC (Time Stamp Counter)
#[inline]
pub fn read_tsc() -> u64 {
    unsafe {
        let low: u32;
        let high: u32;
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }
}

/// Calibrate TSC frequency for this CPU
pub fn calibrate_tsc() {
    // Use HPET or PIT to calibrate TSC frequency
    // For now, assume a reasonable default (2.4 GHz)
    let percpu = PerCpuData::current();
    percpu.tsc_frequency = 2_400_000_000; // 2.4 GHz
}
