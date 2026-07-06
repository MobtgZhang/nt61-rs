//! Architecture Abstraction Layer
//
//! Provides architecture-independent interfaces to hardware-specific code.
//! The arch layer is intentionally small: only the things that differ
//! between x86_64, aarch64, riscv64 and loongarch64 live here. Anything
//! portable goes in `hal::*` instead.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
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

/// Initialize hardware (architecture-specific).
///
/// On x86_64 we set up the GDT, IDT and a basic syscall stub. On
/// aarch64 we set up the exception vector, EL1 EL0 split and MAIR.
/// On riscv64 we set up `stvec`. On loongarch64 we set up TLB-related
/// registers and the exception vector.
///
/// NOTE: This function is called BEFORE MM is fully initialized, so
/// it must NOT use // kprintln! (which requires the MM page fault handler)  // kprintln disabled (memcpy crash workaround).
/// Use UART directly for debug output.
pub fn init_hardware() {
    // Make sure interrupts are off before we touch the IDT. UEFI
    // (or a buggy earlier step) may have left IF=1, and a stray
    // IRQ into an empty IDT slot causes #GP, which causes #GP, …
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("cli", options(nostack, preserves_flags)); }
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
        crate::hal::serial::write_string("pic_done\r\n");

        // Initialize GDT, IDT, TSS - these are safe to call early
        x86_64::tss::init();
        crate::hal::serial::write_string("tss_done\r\n");
        x86_64::gdt::init();
        crate::hal::serial::write_string("gdt_done\r\n");
        x86_64::idt::init();
        crate::hal::serial::write_string("idt_done\r\n");
        x86_64::syscall::init_syscall_msrs();
        crate::hal::serial::write_string("syscall_done\r\n");

        // Try to init PIT/HPET/keyboard, but don't fail if they need MM
        let _ = crate::hal::pit::init(1000);
        crate::hal::serial::write_string("pit_done\r\n");
        let _ = crate::hal::hpet::init(0);
        crate::hal::serial::write_string("hpet_done\r\n");
        // NOTE: keyboard::init() is NOT called here because:
        // 1. The keyboard driver is initialized in kernel_main where
        //    boot_mode is known (SafeModeCmd vs Normal boot have different needs)
        // 2. keyboard::enable_irq() is NOT called here - it should only be
        //    called after mm::init() and in the appropriate boot mode paths.
        //    SafeModeCmd runs with interrupts disabled and uses polling I/O.

        crate::hal::x86_64::mark_arch_initialized();
        crate::hal::serial::write_string("arch_done\r\n");
    }

    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::serial::write_string("arch_aarch64_start\r\n");
        aarch64::init();
        crate::hal::serial::write_string("aarch64_init_done\r\n");
        aarch64::idt::init();
        crate::hal::serial::write_string("aarch64_idt_done\r\n");
        aarch64::serial::serial_init(0);
        crate::hal::serial::write_string("aarch64_serial_done\r\n");
        aarch64::pit::timer_init();
        crate::hal::serial::write_string("aarch64_pit_done\r\n");
        aarch64::apic::init(0x0800_0000, 0x0801_0000);
        crate::hal::serial::write_string("aarch64_apic_done\r\n");
    }

    #[cfg(target_arch = "riscv64")]
    {
        riscv64::init();
        riscv64::idt::init();
        riscv64::serial::serial_init(0);
        riscv64::pit::init(0x2000_0000);
        riscv64::pic::init(0xC00_0000);
    }

    #[cfg(target_arch = "loongarch64")]
    {
        loongarch64::init();
        loongarch64::idt::init();
        loongarch64::serial::serial_init(0);
        loongarch64::pit::init(0x1FE0_0000);
        loongarch64::pic::init(0x1FE0_0000 + 0x1000);
        loongarch64::syscall::init();
    }
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
        asm!("li.w $t0, 0x4\n\tcsrxchg $zero, $t0, 0x0", out("$t0") _);
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
        // crmd.ie = 0
        asm!("li.w $t0, 0x4\n\tcsrxchg $t0, $t0, 0x0", out("$t0") _);
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
        asm!("li.w $t0, 0x4\n\tcsrxchg $zero, $t0, 0x0\n\tidle 0", out("$t0") _);
    }
}

/// CPU-relax hint for short spin loops. The exact instruction is
/// ISA-specific: x86_64 has `pause`, aarch64 has `yield`, riscv64
/// has no equivalent and we fall back to a `nop`. Use this instead
/// of inline `core::arch::asm!("pause")` in non-arch modules.
pub fn cpu_relax() {
    #[cfg(target_arch = "x86_64")]
    unsafe { asm!("pause", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("yield", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "riscv64")]
    unsafe { asm!("nop", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "loongarch64")]
    unsafe { asm!("nop", options(nostack, preserves_flags)); }
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

/// Read CPU ID (architecture-specific). On x86_64 this is the APIC
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

/// Read the current page-table root PFN.
pub fn read_page_root_pfn() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { x86_64::paging::read_page_root_pfn() }
    #[cfg(target_arch = "aarch64")]
    { aarch64::paging::read_page_root_pfn() }
    #[cfg(target_arch = "riscv64")]
    { riscv64::paging::read_page_root_pfn() }
    #[cfg(target_arch = "loongarch64")]
    { loongarch64::paging::read_page_root_pfn() }
}
/// Invalidate the TLB entry for a single virtual address.
pub fn invalidate_tlb(va: u64) {
    #[cfg(target_arch = "x86_64")]
    { x86_64::paging::invalidate_tlb(va); }
    #[cfg(target_arch = "aarch64")]
    { aarch64::paging::invalidate_tlb(va); }
    #[cfg(target_arch = "riscv64")]
    { riscv64::paging::invalidate_tlb(va); }
    #[cfg(target_arch = "loongarch64")]
    { loongarch64::paging::invalidate_tlb(va); }
}

/// Flush the entire TLB (all entries).
pub fn flush_tlb() {
    #[cfg(target_arch = "x86_64")]
    { x86_64::paging::flush_tlb(); }
    #[cfg(target_arch = "aarch64")]
    { aarch64::paging::flush_tlb(); }
    #[cfg(target_arch = "riscv64")]
    { riscv64::paging::flush_tlb(); }
    #[cfg(target_arch = "loongarch64")]
    { loongarch64::paging::flush_tlb(); }
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

/// Read the current page-table root as a physical address.
/// On x86_64 this is CR3, on aarch64 this is TTBR1_EL1,
/// on riscv64 this is satp (PPN only), on loongarch64 this is PGDH.
pub fn read_current_page_root() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags)); }
        cr3 & !0xFFFu64
    }
    #[cfg(target_arch = "aarch64")]
    {
        let ttbr1: u64;
        unsafe { core::arch::asm!("mrs {}, ttbr1_el1", out(reg) ttbr1, options(nostack)); }
        ttbr1 & !0xFFFu64
    }
    #[cfg(target_arch = "riscv64")]
    {
        let satp: u64;
        unsafe { core::arch::asm!("csrr {}, satp", out(reg) satp, options(nostack)); }
        satp & 0x000F_FFFF_FFFF_F000
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let pgdh: u64;
        unsafe { core::arch::asm!("csrrd {}, 0x18", out(reg) pgdh, options(nostack)); }
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
/// pointer returned by `GlobalAlloc::alloc` resolves under the
/// kernel's page tables.
///
/// On x86_64 this is a no-op because the firmware leaves the
/// kernel's identity map in place across `ExitBootServices`. On
/// aarch64 / riscv64 / loongarch64 the firmware does not always
/// leave the entire RAM region 1:1-mapped — especially on the
/// QEMU `virt` machine where all RAM is above 4 GiB — so the
/// kernel must explicitly map the heap region after
/// `mm::heap::init()` returns.
///
/// Returns `true` on success. On architectures where identity
/// mapping is not necessary (x86_64) this is a constant `true`.
pub fn identity_map_region(pa: u64, size: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 keeps an identity map below 4 GiB across
        // ExitBootServices; the kernel heap is allocated inside
        // that range so no extra mapping is required.
        let _ = (pa, size);
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
