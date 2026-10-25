//! Architecture Abstraction Layer
//
//! Provides architecture-independent interfaces to hardware-specific code.
//! The arch layer is intentionally small: only the things that differ
//! between x86_64, aarch64, riscv64 and loongarch64 live here. Anything
//! portable goes in `hal::*` instead.

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "loongarch64"
))]
use core::arch::asm;

// `core::arch::asm!` and `global_asm!` are the only way to write
// inline assembly in stable Rust. The `asm!` form requires
// `target_feature = "asm"` on some targets, but for the four
// architectures we support (x86_64, aarch64, riscv64, loongarch64)
// it is enabled by default.

// Architecture-common submodule (shared PerCpuArea, Paging trait, etc.)
pub mod boot;
pub mod common;

// Architecture-specific modules
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

// Boot module
//pub mod boot;

// Re-export commonly used items
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

/// Install exception/TLB-refill vectors before the memory manager
/// enables paging.
///
/// On LoongArch64 the first instruction fetch with `CRMD.PG=1`
/// immediately takes a TLB refill, so the refill vector (TLBRENTRY),
/// the page-walk CSRs (PWCL/PWCH) and CSR_PGD must all be live
/// *before* `mm::init()` flips PG. The other architectures enable
/// paging without taking a synchronous refill on the next fetch, so
/// their vectors stay in `init_hardware()` (called after `mm::init`),
/// which is where the page-fault handler's PFN dependencies are
/// satisfied. Idempotent.
pub fn install_exception_vectors() {
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::init_page_walk();
        loongarch64::idt::init();
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {}
}

/// Initialize hardware (architecture-specific).
///
/// On x86_64 we set up the GDT, IDT and a basic syscall stub. On
/// aarch64 we set up the exception vector, EL1 EL0 split and MAIR.
/// On riscv64 we set up `stvec`. On loongarch64 we set up TLB-related
/// registers and the exception vector.
///
/// NOTE: This function is called BEFORE MM is fully initialized, so
/// it must NOT use // kprintln! (which requires the MM page fault handler).
/// Use UART directly for debug output.
pub fn init_hardware() {
    // Make sure interrupts are off before we touch the IDT. UEFI
    // (or a buggy earlier step) may have left IF=1, and a stray
    // IRQ into an empty IDT slot causes #GP, which causes #GP, …
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("cli", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::serial::write_string("arch_start\r\n");

        // CRITICAL-010: Initialize the 8259 PIC and immediately mask
        // all 16 IRQ lines. This must run BEFORE `idt::init()` so
        // that any stray IRQ before the IDT is fully populated is
        // silently dropped at the PIC rather than raising #GP into
        // an empty IDT slot. The PIC data ports end up at 0xFF / 0xFF
        // (all masked) once this returns.
        crate::hal::pic::init_and_mask_all();
        crate::boot_debug_println!("pic_done");

        // Initialize GDT, IDT, TSS - these are safe to call early
        x86_64::tss::init();
        crate::hal::serial::write_string("tss_done\r\n");
        x86_64::gdt::init();
        crate::arch::boot::early_write_str(b"[ARCH] gdt_done\r\n");
        x86_64::idt::init();
        crate::arch::boot::early_write_str(b"[ARCH] idt_done\r\n");
        // SMEP (CR4 bit 9) and SMAP (CR4 bit 10) are the hardware half of
        // the ring boundary. Without them every user-pointer check in the
        // kernel is a software-only policy: a path that forgets to probe
        // silently reads or writes user memory instead of raising a
        // catchable #PF. Set them as early as possible, on every CPU.
        crate::arch::boot::early_write_str(b"[ARCH] smep_smap_begin\r\n");
        x86_64::cpu_flags::enable_user_boundary_protection();
        crate::arch::boot::early_write_str(b"[ARCH] smep_smap_done\r\n");
        crate::arch::boot::early_write_str(b"[ARCH] syscall_msrs_begin\r\n");
        x86_64::syscall::init_syscall_msrs();
        crate::arch::boot::early_write_str(b"[ARCH] syscall_done\r\n");

        // Try to init PIT/HPET/keyboard, but don't fail if they need MM
        crate::arch::boot::early_write_str(b"[ARCH] pit_begin\r\n");
        let _ = crate::hal::pit::init(1000);
        let apic_timer_ready = crate::hal::x86_64::apic::init()
            && crate::hal::x86_64::apic::init_timer_calibrated(1000);
        if !apic_timer_ready {
            crate::hal::pic::unmask_irq(0);
        }
        crate::arch::boot::early_write_str(b"[ARCH] pit_done\r\n");
        crate::arch::boot::early_write_str(b"[ARCH] hpet_begin\r\n");
        let _ = crate::hal::hpet::init(0);
        crate::arch::boot::early_write_str(b"[ARCH] hpet_done\r\n");
        // NOTE: keyboard::init() is NOT called here because:
        // 1. The keyboard driver is initialized in kernel_main where
        //    boot_mode is known (SafeModeCmd vs Normal boot have different needs)
        // 2. keyboard::enable_irq() is NOT called here - it should only be
        //    called after mm::init() and in the appropriate boot mode paths.
        //    SafeModeCmd runs with interrupts disabled and uses polling I/O.

        crate::hal::x86_64::mark_arch_initialized();
        crate::arch::boot::early_write_str(b"[ARCH] arch_done\r\n");
    }

    #[cfg(target_arch = "aarch64")]
    {
        let hardware = common::device_tree::hardware();
        crate::hal::serial::write_string("arch_aarch64_start\r\n");
        aarch64::init();
        aarch64::paging::init();
        crate::hal::serial::write_string("aarch64_init_done\r\n");
        aarch64::idt::init();
        crate::hal::serial::write_string("aarch64_idt_done\r\n");
        let uart_base = hardware.uart.map_or(0x0900_0000, |range| range.base);
        aarch64::serial::serial_init(uart_base);
        crate::hal::serial::write_string("aarch64_serial_done\r\n");
        aarch64::pit::timer_init();
        crate::hal::serial::write_string("aarch64_pit_done\r\n");
        let gicd_base = hardware.gicd.map_or(0x0800_0000, |range| range.base);
        let gicc_base = hardware.gicc.map_or(0x0801_0000, |range| range.base);
        aarch64::apic::init(gicd_base, gicc_base);
        crate::hal::serial::write_string("aarch64_apic_done\r\n");
    }

    #[cfg(target_arch = "riscv64")]
    {
        crate::boot_debug_println!("[RISCV] arch init start");
        riscv64::init();
        crate::boot_debug_println!("[RISCV] core init done");
        riscv64::paging::init();
        crate::boot_debug_println!("[RISCV] paging init done");
        riscv64::idt::init();
        crate::boot_debug_println!("[RISCV] trap init done");
        riscv64::serial::serial_init(0);
        crate::boot_debug_println!("[RISCV] serial init done");
        riscv64::pit::init(0x0200_0000);
        crate::boot_debug_println!("[RISCV] timer init done");
        riscv64::pic::init(0xC00_0000);
        crate::boot_debug_println!("[RISCV] interrupt init done");
        crate::hal::common::init();
        crate::boot_debug_println!("[RISCV] common HAL init done");
    }

    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::init();
        loongarch64::paging::init();
        loongarch64::idt::init();
        loongarch64::serial::serial_init(0);
        loongarch64::pit::init(0x1FE0_0000);
        loongarch64::pic::init(0x1FE0_0000 + 0x1000);
        crate::hal::common::keyboard_unified::enable_serial_rx_irq();
        loongarch64::syscall::init();
        crate::hal::common::init();
        crate::boot_debug_println!("[LA64] common HAL init done");
    }
}

/// Bring application processors online and synchronise the scheduler's
/// CPU inventory.
///
/// This must be called only after memory management is ready: AP bring-up
/// allocates identity-mapped trampoline and stack pages. Callers do not
/// need architecture-specific branches; unsupported targets remain at one
/// CPU until their platform bring-up is implemented in this facade.
pub fn start_smp() {
    let page_root_pfn = read_current_page_root() >> 12;
    if page_root_pfn != 0 {
        unsafe {
            common::smp::boot_secondary_cpus(page_root_pfn);
        }
    }
    #[cfg(target_arch = "riscv64")]
    let ap_count = riscv64::smp::cpu_count();
    #[cfg(not(target_arch = "riscv64"))]
    let ap_count = common::smp::cpu_count();
    let mut n = ap_count;
    let mut digits = [0u8; 10];
    let mut len = 0;
    if n == 0 {
        digits[len] = b'0';
        len += 1;
    } else {
        while n > 0 && len < 10 {
            digits[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
    }
    crate::arch::boot::early_write_str(b"[SMP] cpu_count=");
    crate::arch::boot::early_write_str(&digits[..len]);
    crate::arch::boot::early_write_str(b"\r\n");

    // The architecture implementation is responsible for scheduling PRCB
    // allocation before AP entry, because only it knows the true CPU count.
}

/// Prepare the per-architecture kernel stack used by early exceptions
/// and interrupt entry. x86_64 records the live RSP in `TSS.rsp0`;
/// the other architectures wire their kernel stack during
/// `init_hardware()`.
pub fn init_kernel_stack() {
    #[cfg(target_arch = "x86_64")]
    x86_64::tss::set_rsp0_during_init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// Return the current BSP kernel stack base for diagnostic output.
///
/// Architectures without an equivalent pre-kernel stack register
/// return `None`; their stack is owned by `init_hardware()` and the
/// per-CPU area.
pub fn kernel_stack_base() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        Some(x86_64::tss::rsp0())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Mask IRQ 0 while filesystems perform legacy interrupt-sensitive I/O.
pub fn mask_irq0() {
    #[cfg(target_arch = "x86_64")]
    crate::hal::pic::mask_irq(0);
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// Read the architecture's high-resolution hardware cycle counter.
pub fn hardware_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Platform timer selected by the architecture-specific HAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformTimer {
    Hpet,
    Pit,
    Generic,
}

/// Return the best platform timer available on the current CPU.
pub fn platform_timer() -> PlatformTimer {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::hal::hpet::hpet_freq_hz() > 0 {
            return PlatformTimer::Hpet;
        }
        if crate::hal::pit::pit_freq_hz() > 0 {
            return PlatformTimer::Pit;
        }
    }
    PlatformTimer::Generic
}

/// Initialize the architecture-specific paging implementation.
///
/// Most targets install their paging root during early hardware
/// bring-up; x86_64 exposes an explicit late initialization hook.
pub unsafe fn init_paging() {
    #[cfg(target_arch = "x86_64")]
    x86_64::paging::init();
    #[cfg(target_arch = "aarch64")]
    aarch64::paging::init();
    #[cfg(target_arch = "riscv64")]
    riscv64::paging::init();
    #[cfg(target_arch = "loongarch64")]
    loongarch64::paging::init();
}

/// Map one physical page at `va` using architecture-specific paging flags.
pub fn map_page(va: u64, pa: u64, flags: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::paging::map_page(va, pa, flags);
    #[cfg(target_arch = "aarch64")]
    return aarch64::paging::map_page(va, pa, flags);
    #[cfg(target_arch = "riscv64")]
    return riscv64::paging::map_page(va, pa, flags);
    #[cfg(target_arch = "loongarch64")]
    return loongarch64::paging::map_page(va, pa, flags);
}

#[cfg(target_arch = "riscv64")]
pub unsafe fn map_page_in_root(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    riscv64::paging::map_page_in_root(root_pfn, va, pa, flags)
}

#[cfg(target_arch = "loongarch64")]
pub unsafe fn map_page_in_root(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    loongarch64::paging::map_page_in_root(root_pfn, va, pa, flags)
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
pub unsafe fn map_page_in_root(root_pfn: u64, va: u64, pa: u64, flags: u64) -> bool {
    let previous_root = read_page_root_pfn();
    if previous_root != root_pfn {
        load_page_root(root_pfn);
    }
    let mapped = map_page(va, pa, flags);
    if previous_root != root_pfn {
        load_page_root(previous_root);
    }
    mapped
}

/// Report whether a page is mapped in an arbitrary root table without
/// switching hardware context. This is required because the generic VAS
/// layer may be asked to verify mappings while the MMU is still in bare
/// mode or while a different address space is active.
#[cfg(target_arch = "riscv64")]
pub fn page_is_mapped_in_root(root_pfn: u64, va: u64) -> bool {
    riscv64::paging::page_is_mapped_in_root(root_pfn, va)
}

#[cfg(target_arch = "loongarch64")]
pub fn page_is_mapped_in_root(root_pfn: u64, va: u64) -> bool {
    loongarch64::paging::page_is_mapped_in_root(root_pfn, va)
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
pub fn page_is_mapped_in_root(_root_pfn: u64, _va: u64) -> bool {
    false
}

/// Unmap one page and return its physical address when available.
pub fn unmap_page(va: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::paging::unmap_page(va);
    #[cfg(target_arch = "aarch64")]
    return aarch64::paging::unmap_page(va);
    #[cfg(target_arch = "riscv64")]
    return riscv64::paging::unmap_page(va);
    #[cfg(target_arch = "loongarch64")]
    return loongarch64::paging::unmap_page(va);
}

/// Translate a virtual address to a physical address.
pub fn translate_virt(va: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::paging::translate_virt(va);
    #[cfg(target_arch = "aarch64")]
    return aarch64::paging::translate_virt(va);
    #[cfg(target_arch = "riscv64")]
    return riscv64::paging::translate_virt(va);
    #[cfg(target_arch = "loongarch64")]
    return loongarch64::paging::translate_virt(va);
}

/// Return the architecture-specific leaf PTE backing a virtual address.
pub fn leaf_entry(va: u64) -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::paging::leaf_entry(va);
    #[cfg(target_arch = "aarch64")]
    return aarch64::paging::leaf_entry(va);
    #[cfg(target_arch = "riscv64")]
    return riscv64::paging::leaf_entry(va);
    #[cfg(target_arch = "loongarch64")]
    return loongarch64::paging::leaf_entry(va);
}

/// Interpret a leaf PTE for user-space access checks.
pub fn page_user_accessible(entry: u64, require_write: bool) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return (entry & 4) != 0 && (!require_write || (entry & 2) != 0);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let user_accessible = (entry & (1 << 6)) != 0;
        let read_only = (entry & (1 << 7)) != 0;
        return user_accessible && (!require_write || !read_only);
    }
    #[cfg(target_arch = "riscv64")]
    {
        return (entry & (1 << 4)) != 0 && (!require_write || (entry & (1 << 2)) != 0);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        return (entry & (3 << 2)) == (3 << 2) && (!require_write || (entry & (1 << 1)) != 0);
    }
}

/// Return the physical kernel page root when the PFN database must
/// be widened to cover it during bootstrap.
pub fn kernel_page_root() -> Option<u64> {
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    {
        Some(read_current_page_root())
    }
    #[cfg(target_arch = "aarch64")]
    {
        None
    }
}

/// Return the highest physical address usable by the identity map,
/// if the current platform has that bootstrap restriction.
pub const fn identity_mapping_limit() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    return Some(0x1_0000_0000);
    #[cfg(target_arch = "loongarch64")]
    return Some(0x1000_0000); // 256 MB low-RAM identity window
                              // RISC-V: QEMU virt RAM starts at 0x8000_0000; mapping from PA 0
                              // would waste 2 GiB of page-table work on non-existent memory.
                              // The RISC-V-specific block in `vas::init()` maps the RAM window.
    #[cfg(target_arch = "aarch64")]
    return Some(0x1000_0000); // 256 MB low-RAM identity window
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "loongarch64",
        target_arch = "aarch64"
    )))]
    None
}

/// Return the NT self-map base and PML4 index for validation.
pub const fn self_map_info() -> Option<(u64, usize)> {
    #[cfg(target_arch = "x86_64")]
    return Some((
        crate::mm::constants::PXE_BASE,
        crate::mm::constants::MI_SELF_MAP_INDEX,
    ));
    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// Calculate a square root with the platform's floating-point unit.
pub fn sqrt_f64(value: f64) -> f64 {
    if value < 0.0 {
        return f64::NAN;
    }
    if value == 0.0 {
        return 0.0;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let xmm = core::arch::x86_64::_mm_set_sd(value);
        let result = core::arch::x86_64::_mm_sqrt_sd(xmm, xmm);
        core::arch::x86_64::_mm_cvtsd_f64(result)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut estimate = value;
        for _ in 0..20 {
            estimate = (estimate + value / estimate) * 0.5;
        }
        estimate
    }
}

/// Calculate a 32-bit square root with the platform's floating-point unit.
pub fn sqrt_f32(value: f32) -> f32 {
    if value < 0.0 {
        return f32::NAN;
    }
    if value == 0.0 {
        return 0.0;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let xmm = core::arch::x86_64::_mm_set_ss(value);
        let result = core::arch::x86_64::_mm_sqrt_ss(xmm);
        core::arch::x86_64::_mm_cvtss_f32(result)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut estimate = value;
        for _ in 0..15 {
            estimate = (estimate + value / estimate) * 0.5;
        }
        estimate
    }
}

/// Return the address of the current thread's TEB, if the CPU base
/// register exposes it.
pub fn current_teb() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let value: u64;
        unsafe {
            core::arch::asm!("mov {}, gs:0x60", out(reg) value, options(nostack, preserves_flags));
        }
        Some(value)
    }
    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// Read the CPU's FS segment base, when the ISA exposes a direct
/// instruction for it. WoW64 and per-CPU code use this accessor; all
/// other layers must not issue architecture-specific instructions.
pub fn read_fs_base() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u64;
        core::arch::asm!("rdfsbase {0}", out(reg) value, options(nomem, nostack));
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Write the CPU's FS segment base, when the ISA exposes a direct
/// instruction for it.
pub fn write_fs_base(value: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("wrfsbase {0}", in(reg) value, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = value;
}

/// Read the CPU's GS segment base, when the ISA exposes a direct
/// instruction for it.
pub fn read_gs_base() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let value: u64;
        core::arch::asm!("rdgsbase {0}", out(reg) value, options(nomem, nostack));
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Write the CPU's GS segment base, when the ISA exposes a direct
/// instruction for it.
pub fn write_gs_base(value: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("wrgsbase {0}", in(reg) value, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = value;
}

/// Initialize architecture-specific per-CPU kernel state.
pub fn init_per_cpu(cpu_id: u32) {
    #[cfg(target_arch = "x86_64")]
    x86_64::syscall::init_per_cpu(cpu_id);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = cpu_id;
}

/// Request a scheduler IPI on the target logical CPU.
///
/// The DPC queue already owns the policy for whether a cross-CPU
/// notification is needed. Architectures that do not yet expose an
/// SMP IPI doorbell keep this call as a bounded no-op at the HAL
/// boundary rather than letting kernel subsystems query hardware
/// directly.
pub fn request_reschedule_ipi(target_cpu: u32) {
    let _ = target_cpu;
}

/// Return the compact CPU architecture name for boot banners.
pub const fn architecture_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64"
    }
    #[cfg(target_arch = "loongarch64")]
    {
        "loongarch64"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )))]
    {
        "unknown"
    }
}

/// Report whether the current platform has a firmware serial console.
pub const fn serial_console_available() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
    {
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "loongarch64")))]
    {
        false
    }
}

/// Report whether the current platform supports blocking serial input.
pub const fn serial_console_input_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Read one character from the platform serial console, if available.
pub fn serial_read_char() -> Option<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::x86_64::serial::read_char()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Report whether the platform can execute 32-bit compatibility processes.
pub const fn supports_wow64() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Encode an IRQL using the interrupt controller's native priority field.
pub fn interrupt_priority_encoding(level: u8, fallback: u8) -> u8 {
    let _ = level;
    #[cfg(target_arch = "x86_64")]
    {
        if level <= 15 {
            return level << 4;
        }
        fallback
    }
    #[cfg(not(target_arch = "x86_64"))]
    fallback
}

/// Switch to the system address space used for physical-memory writes.
///
/// Returns the previous root so the caller can restore the user address
/// space after a bulk PE load. Targets without a separate system/user
/// root return `None` and leave the address space unchanged.
pub fn switch_to_system_address_space() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let per_cpu = x86_64::syscall::get_per_cpu();
        let system_root = if !per_cpu.is_null() {
            unsafe { (*per_cpu).system_pml4 }
        } else {
            0
        };
        let target = if system_root != 0 {
            system_root
        } else {
            read_current_page_root()
        };
        let saved = read_current_page_root();
        if target != saved {
            unsafe { load_page_root(target >> 12) };
        }
        Some(saved)
    }
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        let system_root = crate::mm::vas::MM_SYSTEM_VAS.lock().pml4_phys;
        #[cfg(target_arch = "riscv64")]
        {
            let satp: u64;
            unsafe {
                core::arch::asm!("csrr {}, satp", out(reg) satp, options(nostack));
            }
            let satp_root = (satp & 0x0000_0FFF_FFFF_FFFF) << 12;
            crate::hal::serial::write_string_always(&alloc::format!(
                "[SYSSW] satp_root={:#x} mirror={:#x}\r\n",
                satp_root,
                read_current_page_root()
            ));
            if satp >> 60 == 0 {
                return None;
            }
            if satp_root == system_root {
                return Some(system_root);
            }
        }
        crate::hal::serial::write_string_always(&alloc::format!(
            "[SYSSW] system={:#x} saved={:#x}\r\n",
            system_root,
            read_current_page_root()
        ));
        if system_root == 0 {
            return None;
        }
        let saved = read_current_page_root();
        if system_root != saved {
            unsafe { load_page_root(system_root >> 12) };
        }
        Some(saved)
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )))]
    None
}

/// Restore a root returned by `switch_to_system_address_space`.
pub fn restore_system_address_space(saved_root: Option<u64>) {
    if let Some(root) = saved_root {
        let current = read_current_page_root();
        if current != root {
            unsafe { load_page_root(root >> 12) };
        }
    }
}

/// Return the current kernel stack pointer, when the architecture exposes it.
pub fn stack_pointer() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let value: u64;
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) value) };
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Read one word of hardware entropy, if the platform provides it.
pub fn hardware_random_u64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    return crate::arch::x86_64::cpu_flags::rdseed_u64()
        .or_else(crate::arch::x86_64::cpu_flags::rdrand_u64);
    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// Yield briefly to the CPU in a busy-wait loop.
pub fn cpu_pause() {
    #[cfg(target_arch = "x86_64")]
    core::arch::x86_64::_mm_pause();
    #[cfg(not(target_arch = "x86_64"))]
    core::hint::spin_loop();
}

/// Program the interrupt-controller task priority.
pub fn set_interrupt_priority(priority: u8) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if !crate::hal::x86_64::apic::is_ready() {
            return false;
        }
        crate::arch::x86_64::cpu_flags::write_cr8(priority as u64);
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = priority;
        false
    }
}

/// Show the Safe-Mode console on the platform's primary display.
pub fn show_safe_mode_console() {
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::text_console::show_safe_mode_console();
    #[cfg(not(target_arch = "x86_64"))]
    crate::hal::text_console::show_safe_mode_console();
}

/// Render a fatal kernel error through the architecture-independent
/// boot video backend.
pub fn bugcheck_screen(code: u32, message: &str) {
    crate::drivers::bootvid::bugcheck_screen(code, message);
}

/// Halt the CPU until the next interrupt arrives.
pub fn halt() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("hlt");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("wfi");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        asm!("idle 0");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("wfi");
    }
}

/// Halt the CPU forever. Used as the final act of fatal paths
/// (e.g. `mm::vas::try_enable_self_map` failure, page-table
/// corruption). The function is `#[inline(never)]` and contains
/// no allocations, no calls into the kernel's logger (the logger
/// itself may have been the cause of the failure), and no
/// recursion — it is the absolute last thing the kernel does.
#[inline(never)]
pub fn halt_loop() -> ! {
    loop {
        halt();
    }
}

/// Enable maskable interrupts on the current CPU.
pub fn enable_interrupts() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("sti");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("msr daifclr, #2");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        // crmd.ie = 1
        asm!("li.w $t0, 0x4
	li.w $t1, 0x4
	csrxchg $t0, $t1, 0x0", out("$t0") _, out("$t1") _);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("csrsi sstatus, 0x2");
    }
}

/// Disable maskable interrupts on the current CPU.
pub fn disable_interrupts() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("cli");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("msr daifset, #2");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        // csrxchg rd, rj, csr: rd supplies the new value, rj supplies
        // the bit-selection mask. To clear CRMD.IE (bit 2): rd = 0,
        // mask = 0x4. The previous code had rd and rj swapped (mask=0)
        // making this a no-op — the timer interrupt was never masked.
        asm!("li.w $t0, 0\n\tli.w $t1, 0x4\n\tcsrxchg $t0, $t1, 0x0", out("$t0") _, out("$t1") _);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("csrci sstatus, 0x2");
    }
}

/// CRITICAL-004: Enable maskable interrupts once.
///
/// This function is idempotent across the entire kernel lifetime: the
/// first caller executes `sti` (or the platform equivalent), every
/// subsequent caller is a no-op. It exists so that the kernel has a
/// single, well-defined point at which hardware IRQ delivery is
/// permitted.
///
/// The gating policy is:
///   1. The page-fault handler installed by `idt::init()` must be
///      ready (i.e. `mm::init()` has completed).
///   2. The PIC must be masked (CRITICAL-010 — done by
///      `pic::init_and_mask_all()` before IDT load).
///   3. The per-device drivers that need IRQs (PIT, keyboard, …)
///      must have explicitly unmasked their IRQ lines before any
///      IRQ can fire.
///
/// Calling `sti` directly is incorrect because the page-fault
/// handler relies on the PFN database and the zero-page allocator
/// being initialised.
static INTERRUPTS_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Tracks whether `enable_interrupts_once` has already executed
/// the `sti` instruction. Separate from INTERRUPTS_READY so the
/// two meanings ("safe to enable" vs "already enabled") do not
/// collide.
static INTERRUPTS_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Mark that it is now safe to deliver IRQs on the current CPU.
/// This is called from `kernel_main` once `mm::init()`,
/// `arch::init_hardware()`, and the per-device drivers have all
/// completed their setup. See `enable_interrupts_once`.
pub fn mark_interrupts_ready() {
    INTERRUPTS_READY.store(true, core::sync::atomic::Ordering::Release);
}

/// Returns true if `mark_interrupts_ready()` has been called.
pub fn interrupts_ready() -> bool {
    INTERRUPTS_READY.load(core::sync::atomic::Ordering::Acquire)
}

/// CRITICAL-004: Enable interrupts, but only once.
///
/// Returns `true` on the first call (when it actually executed
/// `sti`), `false` on every subsequent call. The first call also
/// requires that `mark_interrupts_ready()` has been called first
/// (i.e. all IRQ subsystems are initialised); if it has not, the
/// function will not enable IRQs and will return `false` with a
/// diagnostic to the serial console.
pub fn enable_interrupts_once() -> bool {
    use core::sync::atomic::Ordering;
    // Only flip the gate on the first caller; treat every later
    // invocation as a no-op that reports the underlying state.
    if INTERRUPTS_ENABLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if INTERRUPTS_READY.load(Ordering::Acquire) {
            enable_interrupts();
            true
        } else {
            // Roll back the gate so a subsequent caller that
            // arrives after `mark_interrupts_ready` can still
            // emit the `sti`.
            INTERRUPTS_ENABLED.store(false, Ordering::Release);
            false
        }
    } else if INTERRUPTS_READY.load(Ordering::Acquire) {
        // Already enabled before — still report success.
        true
    } else {
        false
    }
}

/// Wait for interrupt (enable + halt in one atomic step).
pub fn wait_for_interrupt() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("sti; hlt");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("msr daifclr, #2\n\twfi");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("csrsi sstatus, 0x2\n\twfi");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        asm!("li.w $t0, 0x4
	li.w $t1, 0x4
	csrxchg $t0, $t1, 0x0
	idle 0", out("$t0") _, out("$t1") _);
    }
}

/// CPU-relax hint for short spin loops. The exact instruction is
/// ISA-specific: x86_64 has `pause`, aarch64 has `yield`, riscv64
/// has no equivalent and we fall back to a `nop`. Use this instead
/// of inline `core::arch::asm!("pause")` in non-arch modules.
pub fn cpu_relax() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("pause", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("yield", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("nop", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        asm!("nop", options(nostack, preserves_flags));
    }
}

/// Full memory barrier, ordering all loads/stores before to all
/// loads/stores after.
pub fn memory_barrier() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mfence", options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dmb ish", options(nostack));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence rw, rw", options(nostack));
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("dbar 0", options(nostack));
    }
}

/// Save the current interrupt state and return an opaque token
/// suitable for `irql_state_restore`. The token encodes the previous
/// "interrupts enabled" state in its LSB.
pub fn irql_state_save() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let rflags: u64;
        asm!("pushfq; pop {}", out(reg) rflags, options(nostack));
        rflags & 0x200 // IF
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let daif: u64;
        asm!("mrs {}, daif", out(reg) daif, options(nostack));
        // bit 7: I (IRQ mask). 0 = enabled, 1 = disabled.
        if daif & 0x80 != 0 {
            0
        } else {
            1
        }
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let s: u64;
        asm!("csrr {}, sstatus", out(reg) s, options(nostack));
        s & 0x2 // SIE
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        let c: u64;
        asm!("csrrd {}, 0x0", out(reg) c, options(nostack));
        c & 0x4 // crmd.ie
    }
}

/// Restore the interrupt state saved by `irql_state_save`.
pub fn irql_state_restore(token: u64) {
    if token & 1 != 0 {
        enable_interrupts();
    } else {
        disable_interrupts();
    }
}

/// read CPU ID (architecture-specific). On x86_64 this is the APIC
/// ID, on aarch64 it is `MPIDR_EL1`, on riscv64 it is `mhartid`,
/// on loongarch64 it is `cpuid`.
pub fn get_cpu_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // Bootstrap CPU is 0. SMP bring-up will set up the per-CPU
        // GS base via the APIC trampoline and read the APIC ID from
        // there.
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) id, options(nostack));
        }
        (id & 0xFFFFFF) as u32
    }
    #[cfg(target_arch = "riscv64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("csrr {}, mhartid", out(reg) id, options(nostack));
        }
        id as u32
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("csrrd {}, 0x20", out(reg) id, options(nostack));
        }
        id as u32
    }
}

/// Load the page-table root for the current address space. The
/// supplied PFN is the physical page frame number of the PML4 (or
/// platform equivalent). After this call the MMU will translate
/// virtual addresses through the new root.
pub unsafe fn load_page_root(pml4_pfn: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::paging::load_page_root(pml4_pfn);
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::load_page_root(pml4_pfn);
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::load_page_root(pml4_pfn);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::load_page_root(pml4_pfn);
    }
}

/// read the current page-table root PFN.
pub fn read_page_root_pfn() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::paging::read_page_root_pfn()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::read_page_root_pfn()
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::read_page_root_pfn()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::read_page_root_pfn()
    }
}
/// Invalidate the TLB entry for a single virtual address.
pub fn invalidate_tlb(va: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::paging::invalidate_tlb(va);
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::invalidate_tlb(va);
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::invalidate_tlb(va);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::invalidate_tlb(va);
    }
}

/// Flush the entire TLB (all entries).
pub fn flush_tlb() {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::paging::flush_tlb();
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::flush_tlb();
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::flush_tlb();
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::flush_tlb();
    }
}

pub fn get_stack_pointer() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let sp: u64;
        unsafe {
            asm!("mov {}, rsp", out(reg) sp);
        }
        sp
    }
    #[cfg(target_arch = "aarch64")]
    {
        let sp: u64;
        unsafe {
            asm!("mov {}, sp", out(reg) sp);
        }
        sp
    }
    #[cfg(target_arch = "riscv64")]
    {
        let sp: u64;
        unsafe {
            asm!("mv {}, sp", out(reg) sp);
        }
        sp
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let sp: u64;
        unsafe {
            asm!("move {}, $sp", out(reg) sp);
        }
        sp
    }
}

/// read the current page-table root as a physical address.
/// On x86_64 this is CR3, on aarch64 this is TTBR1_EL1,
/// on riscv64 this is satp (PPN only), on loongarch64 this is PGDH.
pub fn read_current_page_root() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        }
        cr3 & !0xFFFu64
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::current_l0_phys()
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::read_page_root_phys()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let pgdh: u64;
        unsafe {
            core::arch::asm!("csrrd {}, 0x1A", out(reg) pgdh, options(nostack));
        }
        pgdh & !0xFFFu64
    }
}

/// Switch the current thread's stack pointer to `new_rsp`, saving
/// the old value through `out_rsp`. The unified facade over
/// `arch::<arch>::context_switch::swap_context`.
///
/// This is the kernel's hot context-switch path; it lives in the
/// `arch::*` layer because the call site (`ke::scheduler`) is
/// architecture-agnostic.
pub unsafe fn swap_context(out_rsp: *mut u64, new_rsp: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::context_switch::swap_context(out_rsp, new_rsp);
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::context_switch::swap_context(out_rsp, new_rsp);
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::context_switch::swap_context(out_rsp, new_rsp);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::context_switch::swap_context(out_rsp, new_rsp);
    }
}

/// Identity-map the kernel heap region `[pa, pa + size)` so the
/// pointer returned by `global_alloc::alloc` resolves under the
/// kernel's page tables.
///
/// On x86_64 this delegates to `ensure_low_identity_map`, which
/// installs 2 MiB large-page PDEs. For RAM regions the firmware
/// already identity-mapped this is idempotent (re-writing the same
/// PDE), and for MMIO windows (e.g. the PCI ECAM at 0xC0000000 on
/// QEMU q35) it creates the missing mappings. On
/// aarch64 / riscv64 / loongarch64 the firmware does not always
/// leave the entire RAM region 1:1-mapped — especially on the
/// QEMU `virt` machine where all RAM is above 4 GiB — so the
/// kernel must explicitly map the heap region after
/// `mm::heap::init()` returns.
///
/// Returns `true` on success. If any page-table allocation fails
/// mid-way the function returns `false` and the caller should fall
/// back to its existing fast path.
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // Delegate to the 2 MiB large-page mapper. For RAM the
        // firmware already identity-mapped this is idempotent; for
        // MMIO windows (PCI ECAM) it creates the missing PDEs.
        crate::mm::vas::ensure_low_identity_map(pa, size);
        true
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::paging::identity_map_region(pa, size)
    }
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::identity_map_region(pa, size)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::identity_map_region(pa, size)
    }
}

/// Re-encode a portable x86-format root entry for the active MMU.
pub fn translate_x86_root_entry(entry: u64) -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::paging::translate_x86_root_entry(entry)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::paging::translate_x86_root_entry(entry)
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        entry & !crate::mm::pte::PTE_US
    }
}
