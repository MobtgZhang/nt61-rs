//! Memory Manager
//
//! Virtual and physical memory management. NT 6.1 layout with a
//! full page-table management implementation, a PFN database,
//! recursive self-map, MmAccessFault dispatcher, COW path, and
//! page file support.
//
//! Subsystem layout:
//!   * `constants` — unified memory management constants
//!   * `pte` — _MMPTE union and protection code translation
//!   * `pfn` — PFN database, state machine, allocation
//!   * `vas` — address spaces and the recursive self-map
//!   * `syspte` — system PTE pool
//!   * `hyperspace` — temporary mapping window
//!   * `access_fault` — page fault dispatcher
//!   * `cow` — copy-on-write
//!   * `working_set` — working set management
//!   * `zeropage` — zero-page thread
//!   * `writer` — modified/mapped page writer
//!   * `pagefile` — page file support
//!   * `frame` — old flat buddy allocator (kept as a fallback)
//!   * `heap` — kernel heap (bump)
//!   * `pool` — kernel pool
//!   * `vm` — virtual memory policy layer
//!   * `vad` — VAD tree
//!   * `mdl` — MDL
//!   * `logging` — log level system
//!   * `perf` — performance counters
//!   * `smoke` — smoke tests
//!   * `pager` — pager subsystem
//!   * `hiber` — hibernate support
//!   * `memtest` — memory test engine

#![allow(non_snake_case)]

/// Print a u64 in decimal via the unified serial facade. Used by
/// early-boot debug breadcrumbs inside `init()` where the `kprintln!`
/// buffered writer is not yet safe to call.
pub(crate) fn write_decimal_u64(mut x: u64) {
    if x == 0 {
        crate::hal::serial::write_string("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut d = 0;
    while x > 0 {
        buf[d] = b'0' + (x % 10) as u8;
        x /= 10;
        d += 1;
    }
    for i in (0..d).rev() {
        if let Ok(s) = core::str::from_utf8(&buf[i..i + 1]) {
            crate::hal::serial::write_string(s);
        }
    }
}

pub mod constants;
pub mod pte;
pub mod pfn;
pub mod vas;
#[cfg(target_arch = "x86_64")]
pub mod syspte;
#[cfg(not(target_arch = "x86_64"))]
#[path = "syspte_stub.rs"]
pub mod syspte;
pub mod hyperspace;
pub mod access_fault;
pub mod cow;
pub mod working_set;
pub mod zeropage;
pub mod writer;
pub mod pagefile;
pub mod smoke;
#[cfg(target_arch = "x86_64")]
pub mod dynamic_paging;
pub mod pager;     // Pager subsystem - memory pressure detection and pageout
pub mod hiber;    // Hibernate support - S3/S4 power states
pub mod memtest;  // Memory test engine for Windows Memory Diagnostic

pub mod frame;
pub mod heap;
pub mod pool;
pub mod vm;
pub mod vad;
pub mod mdl;
pub mod logging;
pub mod perf;

use core::sync::atomic::{AtomicBool, Ordering};

// Re-export the canonical `BootInfo` so existing `mm::BootInfo`
// imports continue to compile. The real definition lives in
// `crate::boot_types` so the loader, the kernel, and the memory
// manager all share the same struct layout.
pub use crate::boot_types::BootInfo;

#[derive(Debug, Clone, Copy)]
pub enum MemoryType {
    Usable = 1,
    Reserved = 2,
    ACPIReclaimable = 3,
    ACPINVS = 4,
    Bad = 5,
    Persistent = 7,
    Hiberbox = 8,
}

#[repr(C)]
pub struct MemoryDescriptor {
    pub base_address: u64,
    pub length: u64,
    pub memory_type: u32,
    pub acpi_extended: u32,
}

pub struct FrameDatabase {
    pub total_frames: u64,
    pub free_frames: u64,
    pub reserved_frames: u64,
    pub highest_frame: u64,
}

impl FrameDatabase {
    pub const fn new() -> Self {
        Self { total_frames: 0, free_frames: 0, reserved_frames: 0, highest_frame: 0 }
    }
    pub fn free_count(&self) -> u64 { self.free_frames }
    pub fn total_count(&self) -> u64 { self.total_frames }
}

/// Default boot RAM base. The kernel image is loaded at 1 MiB by
/// both grub (multiboot) and the UEFI stub.
pub const BOOT_RAM_BASE: u64 = 0x0010_0000; // 1 MiB

/// Default boot RAM size. The QEMU command line passes
/// `-m 8G` but the buddy allocator and the PFN database must
/// scale to whatever the firmware reports. The hard upper bound
/// the bookkeeping is designed for is 192 GiB; below that the
/// tables are sized dynamically at boot. QEMU's default 8 GiB
/// fit comfortably; in production the same code handles
/// 2 GiB / 8 GiB / 32 GiB / 192 GiB machines with no change to
/// the init sequence.
pub const BOOT_RAM_SIZE: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB (QEMU default)

/// Hard upper bound the static bookkeeping buffers are sized to
/// support. 192 GiB is the practical limit of the current page
/// table scheme on x86_64 with a 48-bit virtual address space
/// (canonical addresses give 256 TiB; 192 GiB is the largest
/// range the static PFN DB tables fit).  The buddy + PFN DB
/// are dynamic, but we keep a hard ceiling so the kernel BSS
/// stays bounded.
pub const MAX_RAM_BYTES: u64 = 192 * 1024 * 1024 * 1024;
pub const MAX_RAM_FRAMES: u64 = MAX_RAM_BYTES / 4096;

/// Initialise the entire memory manager.
///
/// `boot_info` supplies the firmware-provided memory map. We use
/// it to determine the actual RAM range, which can be anything
/// from 2 GiB (smallest practical) up to `MAX_RAM_BYTES` (192
/// GiB, the upper limit the static bookkeeping buffers are sized
/// for). The QEMU command line passes `-m 8G`; production
/// machines report anywhere in that 2–192 GiB range.
///
/// The order is:
/// 1. Frame allocator (the legacy buddy in `frame.rs`) — sized
///    from the memory map, not a hard-coded constant.
/// 2. Virtual memory subsystem: install the recursive self-map and
///    the PML4 for the system address space.
/// 3. PFN database: build a database for the entire physical memory
///    and seed the free list with the usable PFNs.
/// 4. System PTE pool, hyperspace window, working-set,
///    zero-page, writer, page file.
pub fn init(boot_info: &BootInfo) {

    // ============================================================
    // FULL MM INITIALIZATION
    // ============================================================
    //
    // This is the *authoritative* Phase 0 of the Windows 6.1 boot
    // sequence.  We bring up the buddy allocator, install the
    // recursive self-map, build the PFN database, and finally
    // expose the system PTE pool, hyperspace window, working-set
    // manager, zero-page thread, modified writer and page-file
    // subsystem.  The `INITIALIZED` flag is flipped to true *only*
    // once every subsystem is up — the page-fault dispatcher reads
    // this flag to decide between `early_pf_halt` (no MM) and the
    // full PFN/VAD resolution path (MM up).
    //
    // The init order is:
    //   1.  Raw UART debug breadcrumb (`MM1`).
    //   2.  Pick the largest *usable* (EfiConventionalMemory) range
    //       from the boot map → hand it to `frame::init_with_range`.
    //       If the map is missing or empty we fall back to the
    //       legacy 16 MiB region at 1 MiB.
    //   3.  Virtual address space: install the recursive PML4
    //       self-map.  Until this completes the kernel cannot
    //       dereference kernel-VA pointers through the new layout.
    //   4.  PFN database: sized from the chosen range, seeded with
    //       the free PFNs.
    //   5.  System PTE pool, hyperspace window.
    //   6.  Kernel heap, kernel pool.
    //   7.  Working-set manager, zero-page, modified writer,
    //       page-file support.
    //   8.  Set `INITIALIZED = true`.  Only after this point is the
    //       page-fault handler allowed to consult the PFN DB.
    //
    // The whole init is wrapped in a single `kprintln!` banner so
    // failures show up immediately in the serial log.

    #[cfg(target_arch = "x86_64")]
    crate::hal::serial::write_string("MM1\r\n");

    // Direct UART output for diagnostic messages — bypasses kprintln
    // (which itself triggers a page fault if any of its static state
    // is unmapped). Now unified through `crate::hal::serial::write_string`.
    crate::hal::serial::write_string("MM2\r\n");

    // ------------------------------------------------------------------
    // 1. Pick a sane physical region from the boot map.
    //
    //    We deliberately cap at 1 GiB for the bootstrap. The legacy
    //    static BSS tables (`FRAME_TABLE`, `PFN_STORAGE_BOOTSTRAP`)
    //    are sized for a 1 GiB region, so picking anything bigger
    //    either crashes on a bounds check or silently truncates the
    //    bookkeeping. The dynamic two-phase path in
    //    `frame::init_with_range` then re-initialises the buddy
    //    with the *full* chosen range using dynamic tables
    //    allocated out of the 1 GiB bootstrap window.
    //
    //    If the boot map pointer is NULL or the count is 0 we fall
    //    back to a 16 MiB region at 1 MiB.
    // ------------------------------------------------------------------
    let mut chosen_base: u64 = BOOT_RAM_BASE;
    let mut chosen_size: u64 = BOOT_RAM_SIZE; // 8 GiB default

    if boot_info.memory_map != 0 && boot_info.memory_map_entries != 0 {
        // The descriptor size is u32 in BootInfo.  Default to the
        // 24-byte NT layout if the bootloader didn't supply one
        // (older stub).
        let desc_size: usize = if boot_info.memory_descriptor_size != 0 {
            boot_info.memory_descriptor_size as usize
        } else {
            core::mem::size_of::<MemoryDescriptor>()
        };
        let count = boot_info.memory_map_entries as usize;
        let base_ptr = boot_info.memory_map as *const u8;
        // Safety: the bootloader guarantees the memory map is
        // identity-mapped physical memory that we can read.
        unsafe {
            let mut best_size: u64 = 0;
            for i in 0..count {
                let p = base_ptr.add(i * desc_size) as *const MemoryDescriptor;
                let entry = core::ptr::read_unaligned(p);
                let ty = entry.memory_type;
                let usable = matches!(ty,
                    1 | // EfiConventionalMemory
                    7 | // EfiPersistentMemory
                    9   // EfiConventionalMemory (alias)
                );
                if !usable {
                    continue;
                }
                // Sanity-check the range: the base must be page-
                // aligned.  On x86_64 the kernel relies on an
                // identity mapping below 4 GiB to bootstrap the
                // PFN database without an MMU walk, so anything
                // above 4 GiB is skipped.  On aarch64 / riscv64
                // QEMU's `virt` machine all RAM is above 4 GiB
                // (typically `0x40000000+`), so the cap doesn't
                // apply there.
                #[cfg(target_arch = "x86_64")]
                if entry.base_address >= 0x1_0000_0000 {
                    continue;
                }
                if entry.base_address & 0xFFF != 0 {
                    continue;
                }
                if entry.length > best_size {
                    best_size = entry.length;
                    chosen_base = entry.base_address;
                    chosen_size = entry.length;
                }
            }
            if best_size == 0 {
                // No usable entries at all — fall back.
                crate::hal::serial::write_string("[mm] No usable memory in map, falling back\r\n");
                chosen_base = BOOT_RAM_BASE;
                chosen_size = 16 * 1024 * 1024;
            }
        }
    }

    // Cap the chosen region to the static-bookkeeping bootstrap
    // limit.  FRAME_TABLE_ENTRIES = 16384 frames = 64 MiB of RAM.
    // The dynamic phase-2 init path can re-init the buddy over the
    // full range using dynamic tables allocated from this window.
    if chosen_size > frame::BOOTSTRAP_REGION {
        chosen_size = frame::BOOTSTRAP_REGION;
    }
    // Round down to a 4 KiB boundary and make sure we have at
    // least 16 MiB.
    chosen_size &= !0xFFFu64;
    if chosen_size < 16 * 1024 * 1024 {
        chosen_size = 16 * 1024 * 1024;
    }

    // PFN DB storage: we constrain the PFN DB to the static
    // bootstrap buffer (~327 KiB, ~17000 PFNs, ~64 MiB of RAM) so
    // we don't have to allocate a dynamic table out of the buddy
    // for it. The buddy's static 64 MiB region is also what the
    // heap and pool are sized against, so keeping chosen_size
    // small keeps the bookkeeping in the BSS FRAME_TABLE.
    const BOOTSTRAP_RAM: u64 = 64 * 1024 * 1024;
    if chosen_size > BOOTSTRAP_RAM {
        chosen_size = BOOTSTRAP_RAM;
    }

    // Widen the PFN DB so it covers the live CR3 PML4. OVMF
    // often places its reserved page-table pages just past the
    // largest `EfiConventionalMemory` region (e.g. q35 `-m 8G`
    // lands the PML4 at `0x7f801000`), outside the 64 MiB
    // bootstrap window. `frame::init` will clamp `num_frames`
    // to FRAME_TABLE_ENTRIES (128 MiB) and emit `AI0_CLAMP`;
    // PFN DB storage is allocated out of the buddy separately.
    #[cfg(target_arch = "x86_64")]
    {
        let cr3_phys: u64 = {
            let v: u64;
            unsafe {
                core::arch::asm!(
                    "mov {}, cr3",
                    out(reg) v,
                    options(nostack, preserves_flags)
                );
            }
            v & !0xFFFu64
        };
        let cr3_pfn_end = (cr3_phys >> 12) + 1;
        let chosen_end_pfn = (chosen_base / 4096) + (chosen_size / 4096);
        if cr3_pfn_end > chosen_end_pfn {
            const MAX_PFN_DB_COVERAGE: u64 = 512 * 1024 * 1024;
            let base_pfn = chosen_base / 4096;
            let new_size = (cr3_pfn_end - base_pfn) * 4096;
            let aligned = (new_size + 0xFFF) & !0xFFF;
            chosen_size = if aligned > MAX_PFN_DB_COVERAGE {
                MAX_PFN_DB_COVERAGE
            } else {
                aligned
            };
            crate::hal::serial::write_string(
                "[mm] extended PFN DB to cover CR3 PML4\r\n",
            );
        }
    }

    {
        // Print the chosen region. The hex formatting and decimal
        // MB count stay local; the serial output goes through the
        // unified facade.
        crate::hal::serial::write_string("[mm] region=");
        let hex = b"0123456789abcdef";
        for shift in (0..16u32).rev() {
            let c = hex[((chosen_base >> (shift * 4)) & 0xF) as usize];
            let arr = [c];
            if let Ok(s) = core::str::from_utf8(&arr) {
                crate::hal::serial::write_string(s);
            }
        }
        crate::hal::serial::write_string(" size=");
        let size_mb = chosen_size / (1024 * 1024);
        write_decimal_u64(size_mb);
        crate::hal::serial::write_string("M\r\n");
    }

    // ------------------------------------------------------------------
    // 2. Frame allocator (buddy). This is the first thing we bring
    //    up: every later subsystem (PFN DB, heap, pool) needs to be
    //    able to allocate physical frames.
    //
    //    The buddy uses a static BSS bookkeeping buffer (5 MiB
    //    FRAME_TABLE, ~80 KiB usable → 4096 frame entries → 16 MiB
    //    of managed RAM) and the static FRAME_TABLE free list. The
    //    legacy path with a 16 MiB region is well-tested: it is
    //    large enough to host a dynamic PFN DB (12 MiB) and a
    //    kernel heap (16-96 MiB in tiny pages allocated from the
    //    pool), and small enough to fit in winload.efi's image
    //    layout. We use it for the bootstrap window.
    //
    //    `frame::init()` (the legacy entry-point) is hard-coded for
    //    an x86_64 1 MiB base; that address is unmapped on aarch64
    //    / riscv64 QEMU `virt`, where all RAM lives above 4 GiB.
    //    Going through `init_with_range(chosen_base, chosen_size)`
    //    keeps a single code path and lets the buddy track the
    //    region we just picked instead of trusting a constant that
    //    only makes sense on the legacy architecture.
    // ------------------------------------------------------------------
    frame::init_with_range(chosen_base, chosen_size);

    crate::hal::serial::write_string("MM3 frame_init_done\r\n");

    // CRITICAL FIX: Initialize PFN database BEFORE vas::init().
    // `vas::init` calls `pfn::allocate_pfn()` to get pages for the
    // self-map page-table chain, so PFN DB must come up first.
    crate::hal::serial::write_string("[mm] pfn::init starting\r\n");
    let base_pfn = chosen_base / 4096;
    let pfn_count = chosen_size / 4096;
    pfn::init(base_pfn, pfn_count);

    crate::hal::serial::write_string("MM3b pfn_init_done\r\n");

    crate::hal::serial::write_string("MM4a vas_init_about\r\n");
    vas::init();

    crate::hal::serial::write_string("MM4 vas_init_done\r\n");

    // ------------------------------------------------------------------
    // 5. System PTE pool, hyperspace window.
    // ------------------------------------------------------------------
    syspte::init();
    hyperspace::init();

    crate::hal::serial::write_string("MM6 syspte_hyperspace_done\r\n");

    // ------------------------------------------------------------------
    // 6. Kernel heap and kernel pool.
    //    `heap::init` and `pool::init` use direct serial output
    //    (not kprintln) on the failure / fallback path so they
    //    are safe to call from the early boot context.
    // ------------------------------------------------------------------
    crate::hal::serial::write_string("[mm] heap::init/about\r\n");
    heap::init();
    crate::hal::serial::write_string("[mm] heap::init done\r\n");

    // ------------------------------------------------------------------
    // 6a. Identity-map the heap region into the kernel's translation
    //     tables. Required on architectures where the firmware does
    //     not leave a 1:1 map of all RAM in place after
    //     `ExitBootServices` — primarily aarch64 / riscv64 /
    //     loongarch64 QEMU `virt` machines where all RAM lives above
    //     4 GiB. Without this map, the first `GlobalAlloc::alloc`
    //     call (and consequently `pool::allocate`, `ob::init`, ...)
    //     dereferences a pointer that does not resolve under the
    //     kernel's page tables, raising a synchronous data-abort /
    //     load-page-fault before any pool code runs.
    //
    //     `arch::identity_map_region` is a no-op on x86_64 because
    //     the firmware already identity-maps the low memory region.
    // ------------------------------------------------------------------
    if let Some((base, size)) = heap::KERNEL_HEAP.configured_region() {
        crate::hal::serial::write_string("[mm] identity-mapping kernel heap region\r\n");
        // Hex-formatted base + size sentinels so we can see in the
        // serial log whether the region we are about to map covers
        // every page the kernel heap will hand back to callers.
        crate::hal::serial::write_string("[mm] heap-base=");
        crate::hal::serial::write_hex_u64(base as u64);
        crate::hal::serial::write_string(" size=");
        crate::hal::serial::write_hex_u64(size as u64);
        crate::hal::serial::write_string("\r\n");
        let mapped = crate::arch::identity_map_region(base as u64, size as u64);
        if !mapped {
            crate::hal::serial::write_string(
                "[mm] WARN: identity_map_region returned false; \
                 heap pool operations may fault on non-x86_64 targets\r\n",
            );
        } else {
            crate::hal::serial::write_string("[mm] identity-map ok\r\n");
        }
    }

    pool::init();
    crate::hal::serial::write_string("MM7 heap_pool_done\r\n");

    working_set::init();
    zeropage::init();
    writer::init();
    pagefile::init();

    crate::hal::serial::write_string("MM8 subsystems_done\r\n");

    // ------------------------------------------------------------------
    // 8. Mark MM as fully initialized.  After this point the
    //    page-fault handler will consult the PFN DB to resolve
    //    demand-zero faults.
    // ------------------------------------------------------------------
    INITIALIZED.store(true, Ordering::SeqCst);

    // CRITICAL-001 root cause fix: flip the early/late logging gate.
    // `kprintln!` previously pulled in `BufferWriter::copy_from_slice`
    // which LLVM lowered to a `memcpy` thunk; that thunk went through
    // PLT indirection that wasn't always resolved at the very start
    // of the boot sequence.  Now that the MM is up (and the page
    // fault handler has the PFN database + zero-page allocator
    // wired up), `kprintln!` is safe to use in its full form.
    crate::rtl::klog::mark_post_mm();

    crate::hal::serial::write_string("MM9 full_init_done\r\n");
}

/// True once `init()` has successfully completed. The page fault
/// handler reads this to detect fatal pre-MM faults.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Returns true if the memory manager has been fully initialised.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// CRITICAL-007: Fatal out-of-memory handler. Emits a structured
/// diagnostic to the serial console and then halts the CPU.
///
/// This function does not return. Callers (e.g. the per-CPU area
/// allocator, the IST stack allocator) use it instead of silently
/// returning `null` from `pool::allocate()`, which would otherwise
/// leave the kernel running with corrupted per-CPU state.
#[cold]
#[inline(never)]
pub fn fatal_alloc<T>(tag: &'static str) -> *mut T {
    crate::hal::serial::write_string("[MM-FATAL] OOM at ");
    crate::hal::serial::write_string(tag);
    crate::hal::serial::write_string("\r\n");
    crate::arch::halt_loop();
}

pub fn get_total_physical() -> u64 { frame::get_total_physical() }
pub fn get_free_physical() -> u64 { frame::get_free_physical() }
pub fn virt_to_phys(virt: u64) -> Option<u64> { vm::virt_to_phys(virt) }
pub fn allocate_pages(count: u64) -> Option<u64> { frame::allocate_pages(count) }
pub fn free_pages(phys: u64, count: u64) { frame::free_pages(phys, count) }

/// End-to-end smoke test for the memory manager. The full
/// implementation lives in the `smoke` submodule; this is a
/// re-export so callers can write `mm::smoke_test()`.
pub fn smoke_test() -> bool { smoke::smoke_test() }

/// Re-export pager subsystem functions for external access
pub use pager::{
    MemoryPressure,
    PagerStats,
    get_memory_pressure,
    get_stats as get_pager_stats,
    check_and_pageout,
    emergency_pageout,
    print_status as print_pager_status,
};

/// Re-export hibernate subsystem functions for external access
pub use hiber::{
    PowerState,
    HibernateStats,
    HibernateType,
    check_hiberfil,
    enter_power_state,
    get_stats as get_hibernate_stats,
    print_status as print_hibernate_status,
};

/// Re-export logging subsystem functions for external access
pub use logging::{
    LogLevel,
    get_log_level,
    set_log_level,
    should_log,
};

/// Re-export performance counter functions for external access
pub use perf::{
    PerfCounters,
    PERF,
    record_pfn_alloc,
    record_pfn_free,
    record_page_fault,
    record_tlb_invalidate,
    record_cr3_switch,
    record_vad_insert,
    record_vad_remove,
    record_syspte_alloc,
    record_syspte_free,
    print_stats as print_perf_stats,
    get_pfn_stats,
    get_page_fault_stats,
};

/// Walk the firmware memory map and pick the largest usable RAM
/// range. We use the largest range because that is what QEMU
/// reports (one contiguous block above 1 MiB) and what real
/// firmware reports on most servers. The selected range is
/// clamped to `MAX_RAM_BYTES` (192 GiB) so the kernel BSS
/// bookkeeping never blows past its design limit.
///
/// Falls back to `BOOT_RAM_BASE`/`BOOT_RAM_SIZE` (8 GiB at
/// 1 MiB) if the memory map is missing or has no usable range.
pub fn discover_ram(boot_info: &BootInfo) -> (u64, u64) {
    if boot_info.memory_map == 0 || boot_info.memory_map_entries == 0 {
        return (BOOT_RAM_BASE, BOOT_RAM_SIZE);
    }
    unsafe {
        let entries = boot_info.memory_map as *const MemoryDescriptor;
        let n = boot_info.memory_map_entries as usize;
        let mut best_base = BOOT_RAM_BASE;
        let mut best_size = BOOT_RAM_SIZE;
        for i in 0..n {
            let e = core::ptr::read_unaligned(entries.add(i));
            // MemoryType::Usable == 1 (see enum above)
            if e.memory_type != MemoryType::Usable as u32 {
                continue;
            }
            // Skip the low 1 MiB (real-mode IVT, BDA, VGA).
            let base = if e.base_address < BOOT_RAM_BASE {
                BOOT_RAM_BASE
            } else {
                e.base_address
            };
            let end = e.base_address.saturating_add(e.length);
            let size = end.saturating_sub(base);
            if size > best_size {
                best_base = base;
                best_size = size;
            }
        }
        if best_size > MAX_RAM_BYTES {
            // // kprintln!("  [mm] clamping discovered RAM 0x{:x} to MAX_RAM_BYTES 0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                       best_size, MAX_RAM_BYTES);
            best_size = MAX_RAM_BYTES;
        }
        (best_base, best_size)
    }
}
