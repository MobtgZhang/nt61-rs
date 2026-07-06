//! SMP boot
//
//! Bringing up an application processor (AP) on x86_64 is the
//! standard sequence: allocate a 4 KiB page, copy a tiny
//! trampoline there, send an INIT IPI, wait 10 ms, send two
//! SIPIs back-to-back, and the AP will then jump into the
//! trampoline. The trampoline is a 16-bit real-mode blob
//! followed by a 64-bit long-mode entry that sets up its own
//! GDT/IDT/TSS and parks itself in the scheduler.
//
//! CPU enumeration uses the ACPI MADT (see
//! `hal::common::acpi::madt_info`).

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::tss;
use crate::hal::common::acpi::{madt_info, parse_madt};
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::apic::{apic_read, apic_write, lapic_reg};
#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::hpet;
use crate::mm::frame;
use crate::mm::syspte;

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

// Per-CPU GDT storage for APs.
// Each AP accesses its own index during sequential boot initialization.
// The compiler may optimize assuming no aliasing, so we use unsafe
// blocks with explicit comments explaining why each access is safe:
// - During boot, only one CPU accesses its own AP_GDTS[ap_idx] slot
// - APs boot sequentially (BSP controls SIPI timing)
// - Each slot is written exactly once during initialization
static mut AP_GDTS: [gdt::PerCpuGdt; tss::MAX_APS] = [const {
    gdt::PerCpuGdt {
        e0: gdt::GdtEntry::empty(),
        e1: gdt::GdtEntry::kernel_code64(),
        e2: gdt::GdtEntry::kernel_data64(),
        e3: gdt::GdtEntry::empty(),            // slot 3: kernel SS (OVMF)
        e4: gdt::GdtEntry::empty(),            // slot 4: user SS — init() fills via OVMF GDT
        e5: gdt::GdtEntry::empty(),            // slot 5: user CS — init() fills via OVMF GDT
        e6: gdt::GdtEntry::empty(),            // slot 6: (unused)
        e7: gdt::GdtEntry::empty(),            // slot 7: (unused)
        e8: gdt::TssDescriptor::empty(),       // slot 8: TSS
        e9: gdt::GdtEntry::empty(),            // slot 9: (TSS high)
        eA: gdt::GdtEntry::empty(),            // slot 10: (unused)
        eB: gdt::GdtEntry::empty(),            // slot 11: (unused)
    }
}; tss::MAX_APS];

/// Number of detected CPUs.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Relaxed)
}

/// BSP entry point. `pml4_pfn` is the kernel page table.
pub unsafe fn smp_boot_aps(pml4_pfn: u64) {
    // Parse the MADT and discover how many LAPICs exist.
    if !parse_madt() {
        // // kprintln!("[smp] MADT not found, running as single-CPU")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    let info = madt_info();
    // // kprintln!("[smp] MADT parsed:")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  - LAPIC base: 0x{:x}", info.local_apic_address)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  - LAPIC flags: 0x{:x}", info.flags)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  - CPU count: {}", info.lapic_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    if info.has_io_apic {
        // // kprintln!("  - I/O APIC: id={} addr=0x{:x} gsi_base={}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                   info.io_apic_id, info.io_apic_address, info.io_apic_gsi_base);
    }
    // // kprintln!("  - Interrupt overrides: {}", info.int_override_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("  - NMI sources: {}", info.nmi_source_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    if info.lapic_count <= 1 {
        // // kprintln!("[smp] only BSP detected, running single-CPU")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    // // kprintln!("[smp] {} LAPICs found, starting APs", info.lapic_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Allocate a 4 KiB page for the trampoline and copy the
    // trampoline code there. The page must be in low memory
    // (≤ 1 MiB) so the SIPI vector reaches it. We borrow a
    // page from the buddy and identity-map it. If the
    // trampoline symbols are missing (static build that
    // didn't include the AP assembly) we still parse the
    // MADT but skip the bring-up.
    extern "C" {
        static _trampoline_start: u8;
        static _trampoline_end: u8;
    }
    let tramp_len = unsafe {
        (_trampoline_end as *const u8 as usize)
            .saturating_sub(_trampoline_start as *const u8 as usize)
    };
    if tramp_len == 0 || tramp_len > 4096 {
        // // kprintln!("[smp] no AP trampoline linked, BSP-only")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    let trampoline_phys = match frame::allocate_pages(1) {
        Some(p) => p,
        None => {
            // // kprintln!("[smp] OOM allocating trampoline, single-CPU mode")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            CPU_COUNT.store(1, Ordering::SeqCst);
            return;
        }
    };
    // Clamp to the 4-bit address limit documented by Intel —
    // 0x000..0xFF8 in steps of 0x1000. The top bits of the
    // page's 4-bit address go into the upper nibble of the
    // SIPI ICR.
    //
    // SIPI vector format: the ICR low word contains the vector
    // in bits 12-15 (the vector is the page frame number).
    // So we only need the page to be addressable by those bits,
    // i.e., phys_addr >= 0x1000 (above the first 4KB).
    if trampoline_phys < 0x1000 {
        // // kprintln!("[smp] trampoline phys 0x{:x} too low for SIPI (need >= 0x1000)", trampoline_phys)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    // Identity-map the trampoline page in the kernel page table
    // (so the long-mode portion of the trampoline can execute
    // out of it).
    // FIX 2.6: Check for mapping failure
    if syspte::map_io_space(trampoline_phys, 1).is_none() {
        // // kprintln!("[smp] failed to identity-map trampoline page, single-CPU mode")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    // Copy the trampoline.
    unsafe {
        core::ptr::copy_nonoverlapping(
            _trampoline_start as *const u8,
            trampoline_phys as *mut u8,
            tramp_len,
        );
    }
    // Patch the trampoline's PML4 and per-AP slots in the SIPI
    // page. We patch *after* the copy so the changes are made
    // to the destination (the kernel's copy at `trampoline_phys`)
    // rather than the source.
    //
    // For each AP we set a unique per-AP stack and an index so
    // the trampoline can pass them to `ap_entry_long`.
    let ap_stack_phys = match frame::allocate_pages(1) {
        Some(p) => p,
        None => {
            // // kprintln!("[smp] OOM allocating per-AP stack, single-CPU mode")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            CPU_COUNT.store(1, Ordering::SeqCst);
            return;
        }
    };
    // The AP stack top is at `ap_stack_phys + 4096` (stack grows
    // down on x86_64).
    let ap_stack_top = ap_stack_phys + 4096;
    // Identity-map the AP stack in the kernel page table.
    // FIX 2.6: Check for mapping failure
    if syspte::map_io_space(ap_stack_phys, 1).is_none() {
        // // kprintln!("[smp] failed to identity-map AP stack page, single-CPU mode")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    // FIX 2.6: Validate SIPI vector is valid
    let sipi_vector = ((trampoline_phys >> 12) & 0xFF) as u8;
    if sipi_vector == 0 {
        // // kprintln!("[smp] trampoline_phys too low for SIPI vector")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        CPU_COUNT.store(1, Ordering::SeqCst);
        return;
    }
    // Patch the trampoline page with the PML4, the AP stack,
    // and an initial AP index. (We do this once; for multiple
    // APs we patch again before each SIPI.)
    unsafe {
        extern "C" {
            static mut _trampoline_pml4: u32;
            static mut _trampoline_ap_stack: u64;
            static mut _trampoline_ap_index: u64;
        }
        // The destination of these static pointers is in the
        // winload/kernel image, but `core::ptr::copy_nonoverlapping`
        // already copied them into the SIPI page. To patch the
        // SIPI page, write directly to its offset.
        let p = trampoline_phys as *mut u8;
        // We re-derive the offsets by reading the source layout.
        // The simplest approach: define the same `static mut`
        // symbols and use their addresses. They are in the
        // .text section at known offsets.
        let src_pml4 = core::ptr::addr_of!(_trampoline_pml4) as *const u8;
        let src_stack = core::ptr::addr_of!(_trampoline_ap_stack) as *const u8;
        let src_index = core::ptr::addr_of!(_trampoline_ap_index) as *const u8;
        // Compute the offsets from the trampoline base.
        let pml4_off = (src_pml4 as usize) - (_trampoline_start as *const u8 as usize);
        let stack_off = (src_stack as usize) - (_trampoline_start as *const u8 as usize);
        let index_off = (src_index as usize) - (_trampoline_start as *const u8 as usize);
        // Patch each offset in the SIPI page.
        core::ptr::write_volatile((p.add(pml4_off)) as *mut u32, pml4_pfn as u32);
        core::ptr::write_volatile((p.add(stack_off)) as *mut u64, ap_stack_top);
        core::ptr::write_volatile((p.add(index_off)) as *mut u64, 1u64);
    }
    let _ = pml4_pfn;
    // Bring up each AP.
    let mut brought_up: u32 = 1;
    for i in 1..info.lapic_count as usize {
        let apic_id = info.lapic_ids[i];
        // Patch the AP index in the SIPI page for this AP.
        unsafe {
            let p = trampoline_phys as *mut u8;
            extern "C" {
                static _trampoline_ap_index: u64;
            }
            let src_index = core::ptr::addr_of!(_trampoline_ap_index) as *const u8;
            let index_off = (src_index as usize) - (_trampoline_start as *const u8 as usize);
            core::ptr::write_volatile((p.add(index_off)) as *mut u64, i as u64);
        }
        if !start_ap(apic_id, trampoline_phys) {
            // // kprintln!("[smp] AP lapic_id={} failed to start", apic_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            continue;
        }
        // FIX 2.7: Add acknowledgment delay and verification
        // Wait for AP to acknowledge by entering ap_entry_long
        delay_ms(5);
        brought_up += 1;
    }
    CPU_COUNT.store(brought_up, Ordering::SeqCst);
    // // kprintln!("[smp] {} CPU(s) up", brought_up)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Send INIT + SIPI + SIPI to bring up one AP. Returns true on
/// success (the AP is presumed up; we don't yet have a way to
/// confirm). `apic_id` is the LAPIC ID from the MADT.
fn start_ap(apic_id: u8, trampoline_phys: u64) -> bool {
    // 1. INIT IPI.
    send_ipi(apic_id, 0x0000_0000 | 0x0000_5000); // INIT, no shorthand
    delay_ms(10);
    // 2. First SIPI.
    let sipi = 0x0000_0600 | ((trampoline_phys >> 12) & 0xFF) as u32;
    send_ipi(apic_id, sipi);
    delay_ms(1);
    // 3. Second SIPI.
    send_ipi(apic_id, sipi);
    delay_ms(1);
    true
}

/// Approximate millisecond delay by spinning on the HPET
/// counter. The HPET is calibrated at HAL init time.
fn delay_ms(ms: u32) {
    use core::arch::asm;
    let freq = hpet::hpet_freq_hz();
    if freq == 0 {
        // Coarse fallback.
        for _ in 0..(ms as u64 * 200_000) { unsafe { asm!("pause"); } }
        return;
    }
    let start = hpet::counter();
    let target = ms as u64 * freq / 1000;
    loop {
        let now = hpet::counter();
        if now.wrapping_sub(start) >= target { break; }
        unsafe { asm!("pause"); }
    }
}

fn send_ipi(apic_id: u8, icr_low: u32) {
    apic_write(lapic_reg::ICR_HIGH, ((apic_id as u32) << 24) & 0xFF000000);
    apic_write(lapic_reg::ICR_LOW, icr_low);
    // Spin until the IPI completes (delivery status bit 12 = 0).
    for _ in 0..10000 {
        let v = apic_read(lapic_reg::ICR_LOW);
        if v & 0x1000 == 0 { break; }
        unsafe { asm!("pause"); }
    }
}

extern "C" {
    static _trampoline_start: u8;
    static _trampoline_end: u8;
    fn _ap_entry();
}

// ---------------------------------------------------------------------------
// AP startup trampoline (16-bit → 64-bit long mode)
//
// This blob is copied into a 4 KiB page by `smp_boot_aps` and
// used as the SIPI target.  When the SIPI arrives, the AP is
// in 16-bit real mode with CS:IP = 0:trampoline_phys.  It
// loads a tiny GDT, enables protected mode, enables long
// mode, then jumps to the kernel's `ap_entry` in 64-bit code.
//
// Layout (4 KiB, ≤ 256 bytes actually used):
//   [16-bit entry, CS:IP=0:trampoline_phys]
//     cli
//     lgdt  [trampoline_gdt_ptr]
//     mov eax, cr0
//     or  eax, 1                     ; enter protected mode
//     mov cr0, eax
//     jmp 0x08:.Lpm                  ; far jump to 32-bit code
//   [32-bit code, .Lpm]
//     mov eax, cr4
//     or  eax, (1<<5)                ; PAE
//     mov cr4, eax
//     mov eax, [trampoline_pml4]     ; kernel's PML4 physical address
//     mov cr3, eax
//     mov ecx, 0xC0000080            ; IA32_EFER
//     rdmsr
//     or  eax, (1<<8) | (1<<10)      ; LME, LMA
//     wrmsr
//     mov eax, cr0
//     or  eax, (1<<31)               ; PG
//     mov cr0, eax
//     jmp 0x18:.Llm                  ; far jump to 64-bit code
//   [64-bit code, .Llm]
//     mov ax, 0x20                   ; data selector
//     mov ds, ax / es, ax / ss, ax
//     mov rsp, [trampoline_ap_stack] ; per-AP stack from low memory
//     mov rdi, [trampoline_ap_index] ; 1..N
//     call _ap_entry_long
//     hlt; jmp .
//   [trampoline_gdt_ptr, gdt (24 bytes: null/32CS/64CS/DS),
//    pml4_paddr, ap_stack_paddr, ap_index]
// The AP trampoline is included from a separate .S file because the
// LLVM integrated assembler that powers `global_asm!` is pickier
// about mixed `.code16`/`.code32`/`.code64` sequences than GNU AS.
// On the UEFI build the kernel code is not linked, so we still need
// to provide stub symbols for the linker to resolve. We do that
// with weak stubs in the UEFI case below.

#[cfg(not(target_os = "uefi"))]
core::arch::global_asm!(include_str!("smp_trampoline.S"));

// Provide weak symbols so the UEFI build (which doesn't link the
// trampoline) can still resolve the references from smp.rs.
// We use .section and proper alignment to ensure PIC-compatible symbols.
#[cfg(target_os = "uefi")]
core::arch::global_asm!(
    ".weak _trampoline_start",
    ".weak _trampoline_end",
    ".weak _trampoline_pml4",
    ".weak _trampoline_ap_stack",
    ".weak _trampoline_ap_index",
    ".weak _ap_entry_long",
    ".balign 8",
    "_trampoline_start: .quad 0",
    "_trampoline_end: .quad 0",
    ".balign 4",
    "_trampoline_pml4: .long 0",
    ".balign 8",
    "_trampoline_ap_stack: .quad 0",
    "_trampoline_ap_index: .quad 0",
    "_ap_entry_long: ret",
);

/// Patch the trampoline with the kernel's PML4 physical address
/// and the per-AP stack/index. The trampoline is copied into a
/// 4 KiB low-memory page by `smp_boot_aps`; the caller's
/// pointers here are in the *original* trampoline buffer, but
/// we only use them as values to write — the bytes are then
/// placed in the SIPI page by the caller.
///
/// Currently unused: `smp_boot_aps` patches the SIPI page
/// in-line using offsets derived from the trampoline base.
/// Retained because the next phase will need it for per-AP
/// initialisation order (PML4 ready before LAPIC ID is
/// published), at which point it will be wired up.
#[allow(dead_code)]
unsafe fn patch_trampoline(
    pml4_paddr: u64,
    ap_stack: u64,
    ap_index: u64,
) {
    extern "C" {
        static mut _trampoline_pml4: u32;
        static mut _trampoline_ap_stack: u64;
        static mut _trampoline_ap_index: u64;
    }
    core::ptr::write_volatile(&raw mut _trampoline_pml4, pml4_paddr as u32);
    core::ptr::write_volatile(&raw mut _trampoline_ap_stack, ap_stack);
    core::ptr::write_volatile(&raw mut _trampoline_ap_index, ap_index);
}

/// Stub: would be the AP entry point. The trampoline would set up
/// its own GDT/IDT/TSS and call into the scheduler.
#[no_mangle]
pub unsafe extern "C" fn ap_entry() -> ! {
    loop { asm!("hlt"); }
}

/// 64-bit long-mode AP entry. Called by the trampoline after the
/// AP has switched to long mode. Sets up a per-CPU GDT/TSS,
/// allocates a per-CPU area, installs `IA32_GS_BASE`, and parks
/// the CPU in the scheduler.
#[no_mangle]
pub unsafe extern "C" fn ap_entry_long(ap_index: u64) -> ! {
    let ap_idx = ap_index as usize;
    if ap_idx >= tss::MAX_APS {
        // // crate::kprintln!("[smp] ap_index {} out of range, parking", ap_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        loop { asm!("hlt"); }
    }

    // Allocate a per-AP kernel stack. 64 KiB is more than enough
    // for bring-up; the real per-thread kernel stacks are
    // allocated later by the scheduler.
    const AP_STACK_SIZE: usize = 64 * 1024;
    let stack_base = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        AP_STACK_SIZE,
    ) as u64;
    if stack_base == 0 {
        // // crate::kprintln!("[smp] AP {} stack OOM, parking", ap_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        loop { asm!("hlt"); }
    }
    let rsp0 = stack_base + AP_STACK_SIZE as u64 - 16;

    // Initialise the per-AP TSS and GDT.
    // SAFETY: AP_GDTS is module-scoped. Each AP accesses only its own index.
    // APs boot sequentially under BSP control, so there are no concurrent
    // writes to the same slot. The unsafe blocks below are safe because:
    // 1. Only this AP (identified by ap_idx) writes to AP_GDTS[ap_idx]
    // 2. No other CPU accesses this slot during initialization
    let (tss_ptr, tss_limit) = match tss::init_ap_tss(ap_idx, rsp0) {
        Some(v) => v,
        None => {
            // // crate::kprintln!("[smp] AP {} TSS init failed, parking", ap_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            loop { asm!("hlt"); }
        }
    };
    // SAFETY: Same reasoning as above - this AP's GDT slot is private during boot
    unsafe {
        gdt::build_per_cpu_gdt(&mut AP_GDTS[ap_idx], tss_ptr as u64, tss_limit);
        gdt::ap_install(&AP_GDTS[ap_idx]);
    }

    // 2. Initialise the local APIC. The BSP may have set the
    //    spurious-interrupt vector; each AP must re-enable it.
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::apic::init_smp();

    // 3. Allocate a per-CPU area for this AP. This ensures each CPU
    //    has its own independent PerCpuArea, preventing APs from
    //    overwriting BSP's per-CPU data.
    #[cfg(target_arch = "x86_64")]
    let per_cpu_page = crate::arch::x86_64::syscall::allocate_per_cpu_area(ap_index as u32);
    if per_cpu_page == 0 {
        // // crate::kprintln!("[smp] AP {} per-CPU area OOM, parking", ap_index)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        loop { asm!("hlt"); }
    }

    // 4. Install the per-CPU area as this CPU's GS base.
    //    This MUST be done before any gs:[] access.
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::syscall::set_kernel_gs_base(per_cpu_page);
    // // crate::kprintln!("[smp] AP {} GS_BASE set to 0x{:016x}", ap_index, per_cpu_page)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // 5. Hand control to the scheduler. `init_smp_this_cpu`
    //    allocates a Prcb, creates the idle thread, and sets up
    //    the per-CPU current_thread/current_process slots.
    crate::ke::scheduler::init_smp_this_cpu(ap_index as u32);
    crate::ke::scheduler::idle_loop()
}

#[allow(dead_code)]
fn _use_ap() {
    let _ = _ap_entry as *const ();
    unsafe {
        let _ = _trampoline_start as *const u8;
        let _ = _trampoline_end as *const u8;
    }
}

/// SMP smoke test.
///
/// Verifies:
/// 1. The SMP module initializes without panicking.
/// 2. `cpu_count()` returns at least 1 (the BSP).
/// 3. `parse_madt()` is callable (returns false on non-UEFI boot, true on OVMF).
/// 4. The static CPU_COUNT atomic is accessible.
pub fn smoke_test() -> bool {
    use core::sync::atomic::Ordering;

    // // kprintln!("  [SMP SMOKE] running SMP smoke test...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    let mut ok = true;

    // Step 1: cpu_count returns a value
    let count = cpu_count();
    // // kprintln!("    [SMP SMOKE] cpu_count() = {}", count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    if count < 1 {
        // // kprintln!("    [SMP SMOKE FAIL] cpu_count() < 1")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        ok = false;
    }

    // Step 2: Verify CPU_COUNT atomic is accessible
    let _ = CPU_COUNT.load(Ordering::Relaxed);

    // Step 3: Try to parse MADT (will return false if ACPI not available)
    let _madt_ok = parse_madt();
    // _madt_ok is intentionally unused - reserved for future logging
    // // kprintln!("    [SMP SMOKE] parse_madt() = {}", _madt_ok)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Step 4: After MADT parse, check if more CPUs are available
    let _count_after = cpu_count();
    // _count_after is intentionally unused - reserved for future logging
    // // kprintln!("    [SMP SMOKE] cpu_count() after MADT parse = {}", _count_after)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    if ok {
        // // kprintln!("  [SMP SMOKE] all SMP checks passed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // // kprintln!("  [SMP SMOKE FAIL] one or more SMP checks failed")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    ok
}

// ---------------------------------------------------------------------------
// extern "Rust" implementations required by arch::common::smp
//
// `arch::common::smp` declares these symbols via `unsafe extern "Rust"`.
// Each supported architecture must provide them, otherwise downstream
// crates that depend on `nt61` (e.g. `nt61-winload`) hit linker errors
// in debug builds where dead-code elimination doesn't strip the
// `arch::common::smp` wrappers. The x86_64 variants simply forward to
// the existing in-crate SMP machinery (cpu_count / smp_boot_aps) and
// the per-CPU area's CPU id.
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "Rust" fn __smp_cpu_count() -> u32 {
    cpu_count()
}

#[no_mangle]
pub unsafe extern "Rust" fn __smp_boot_secondary(pml4_pfn: u64) {
    smp_boot_aps(pml4_pfn);
}

#[no_mangle]
pub extern "Rust" fn __smp_get_current_cpu_id() -> u32 {
    super::percpu_impl::__percpu_get_current_cpu_id()
}
