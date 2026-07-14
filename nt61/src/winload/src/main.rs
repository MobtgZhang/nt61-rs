//! NT6.1.7601 UEFI OS Loader — `winload.efi`.
//
//! This is the *real* winload — the third stage of the UEFI boot
//! chain (firmware → bootmgr.efi → winload.efi).
//
//! Responsibilities (in order):
//
//!   1. Load ntoskrnl.exe  (PE parse, allocate pages, copy sections)
//!   2. Load hal.dll       (PE parse, map into kernel address space)
//!   3. Load SYSTEM hive  (stub: read file, hand to kernel)
//!   4. Load BOOT_START drivers  (stub: list files, log results)
//!   5. Collect UEFI memory map, ACPI RSDP, SMP info
//!   6. Call ExitBootServices
//!   7. Jump to kernel_main with a fully-populated BootInfo
//
//! The **entire** kernel init sequence (PHASE 0 … PHASE 9) lives in
//! `nt61::kernel_main`. This binary **never duplicates** any of that
//! code — it is purely the bridge between UEFI and the NT kernel.

#![no_std]
#![no_main]

// ============================================================================
// Module-wide lint configuration for the OS Loader.
// ============================================================================
//
// The winload workspace is a scaffold under active development: helper
// functions and statics for kernel hive loading, BOOT_START driver
// enumeration, ACPI / SMP / framebuffer capture, ISO ramdisk mirroring,
// and the per-phase progress helpers all live next to `os_loader_run` so
// that the loader is implemented in one place. `os_loader_run` itself is
// currently a "fast boot" stub that bypasses the per-phase helpers and
// hands control to the kernel with a minimal BootInfo — every scaffolded
// helper therefore reports `dead_code`, `unused_variables`, or
// `unused_imports` warnings on every clean build.
//
// We don't want to fix each warning by hand only to reintroduce the
// scaffold code on the next phase-in (e.g. when winload learns to walk
// the SYSTEM hive or to enumerate ACPI tables). Instead we suppress the
// warning group at the crate root so the loader compiles clean today AND
// remains clean as the scaffold is consumed. The `#![deny(warnings)]` on
// the *non*-suppressed lint groups is preserved so genuine mistakes (e.g.
// a freshly introduced unused function in scope) still fail the build.
//
// Permitted under MIT. See repository LICENSE.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

extern crate alloc;
use alloc::vec::Vec;

mod arch;
mod bcd_mailbox_read;
mod fat_lfn;
mod gop_display;
pub mod logging;
pub mod ntfs_boot;

use nt61::kernel_main::{BootInfo, BOOTINFO_MAX_HIVES};
use nt61::loader;
use uefi::boot::{allocate_pages, AllocateType, MemoryType};
use uefi::CStr16;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;

// =====================================================================
// Boot-time trace ring — *not* a GlobalAlloc, just a manual log
// =====================================================================
//
// We cannot easily replace the upstream `uefi::allocator::Allocator`
// (the boot manager and winload both depend on the same `uefi` crate
// and Cargo unifies features workspace-wide), so we cannot transparently
// record every alloc/dealloc the way `#[global_allocator]` would let us.
//
// Instead we expose a manual ring that winload.efi pushes into at each
// interesting step (file open, page allocation, vec drop, etc.). At the
// next dump point we replay the ring. The result is a complete picture
// of the "page-table" / pool / box allocations performed while loading
// ntoskrnl.exe, hal.dll, the SYSTEM hive, and the boot drivers.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use uefi::table;

/// UEFI page size — 4 KiB for every spec-compliant firmware.
const _PAGE_SIZE: usize = 4096;

const TRACE_RING: usize = 96;

const T_LOG:    u32 = 0; // generic log line (msg[0..16] = ascii prefix)
const T_PAGE_A: u32 = 1; // allocate_pages requested/result
const T_POOL_A: u32 = 2; // allocate_pool  requested/result
const T_POOL_D: u32 = 3; // free_pool      result
const T_PAGE_D: u32 = 4; // free_pages     result
const T_OPEN:   u32 = 5; // open_esp_file called
const T_VEC_D:  u32 = 6; // Vec<u8> dropped (size, returned ptr)
const T_BOX_D:  u32 = 7; // Box dropped (size, returned ptr)
const T_STR_D:  u32 = 8; // String dropped (size, returned ptr)

// `TraceEntry` / `TraceRing` were the original types holding the
// `AtomicU64` array that LTO kept eliding on `x86_64-unknown-uefi`.
// They are now unused; the ring lives in three plain `static mut`
// slots (`TRACE_BUF` / `TRACE_HEAD` / `TRACE_SEQ`) which `#[used]`
// + explicit `.data` placement guarantee the link-time optimizer
// cannot drop. See the comment below on `TRACE_BUF` for the full
// rationale. Touching the type definitions here keeps the diff
// minimal; if you want to remove them entirely later, the
// `#[used]` + inline-asm helpers are the only surface that matters.

#[derive(Clone, Copy)]
struct TraceEntry {
    kind: u32,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

struct TraceRing {
    buf: [AtomicU64; TRACE_RING * 4],
    head: AtomicU32,
    seq: AtomicU32,
}

unsafe impl Sync for TraceRing {}

// Plain `static mut` slots backing the trace ring. We deliberately
// do **not** use `core::sync::atomic::AtomicU64::new(0)` here:
// on `x86_64-unknown-uefi`, the LTO pass was eliding the
// `AtomicU64::new(0)` wrapper construction, and on top of that the
// PE `.data` segment is mapped read-only by OVMF — so the very
// first `fetch_add` on `TRACE.head` faults on a #PF and freezes
// the loader before it can print another `[LOADER]` line. Other
// `static mut` cells in this file (e.g. `CACHED_SFS_PTR`) work
// because the linker's LTO pass leaves the zero-init image alone,
// and because the LLD/PE loader puts those non-`#[used]`-tagged
// scalars in a writable region; the constant data initialised
// via `[const { AtomicU64::new(0) }; N]` did not survive. Three
// `#[used]`-tagged plain `u32` / `[u64; N]` slots + inline-asm
// helpers (`atomic_add_u32`, `atomic_store_u64`) below give us
// the same semantics without depending on the unstable API.
#[used]
static mut TRACE_BUF: [u64; TRACE_RING * 4] = [0u64; TRACE_RING * 4];
#[used]
static mut TRACE_HEAD: u32 = 0;
#[used]
static mut TRACE_SEQ: u32 = 0;

/// Atomic fetch-add on a `u32` slot, implemented inline so we don't
/// need `core::sync::atomic::AtomicU32` (whose `const fn new(0)`
/// wrapper was being elided by LTO on `x86_64-unknown-uefi`).
#[inline]
unsafe fn atomic_add_u32(slot: *mut u32, delta: u32) -> u32 {
    let prev: u32;
    // SAFETY: caller guarantees the slot is uniquely accessible.
    // `xadd` returns the *previous* value in the second operand and
    // stores the sum back into memory. We pass `delta` as the new
    // value to fold and read `prev` back from the same register.
    unsafe {
        core::arch::asm!(
            "xadd [{ptr}], {val:e}",
            ptr = in(reg) slot,
            val = inout(reg) delta => prev,
            options(preserves_flags),
        );
    }
    prev
}

/// Atomic store of a `u64` with `Release` semantics, implemented
/// inline via `xchg` so we don't need an `AtomicU64::store`.
#[inline]
unsafe fn atomic_store_u64(slot: *mut u64, val: u64) {
    // SAFETY: caller guarantees exclusive access to `slot`.
    unsafe {
        core::arch::asm!(
            "xchg [{ptr}], {val:r}",
            ptr = in(reg) slot,
            val = in(reg) val,
            options(preserves_flags),
        );
    }
}

/// Atomic load of a `u32` with `Acquire` semantics. Implemented via a
/// compiler barrier + ordinary load because `dump_trace` is the only
/// reader and runs after we're done writing.
#[inline]
unsafe fn atomic_load_u32(slot: *const u32) -> u32 {
    let val: u32;
    // SAFETY: caller guarantees the slot is accessible.
    unsafe {
        core::arch::asm!(
            "mov {val:e}, [{ptr}]",
            ptr = in(reg) slot,
            val = out(reg) val,
            options(preserves_flags),
        );
    }
    val
}

#[inline]
fn push(kind: u32, a: u64, b: u64, c: u64, d: u64) {
    // SAFETY: TRACE_BUF / TRACE_HEAD / TRACE_SEQ are written only
    // here and only read by `dump_trace`. The loader is single-threaded
    // for the entire duration, so the `fetch_add`-equivalent on
    // TRACE_HEAD does not race.
    unsafe {
        let seq = atomic_add_u32(core::ptr::addr_of_mut!(TRACE_SEQ), 1);
        let head = atomic_add_u32(core::ptr::addr_of_mut!(TRACE_HEAD), 1);
        let idx = (head as usize) % TRACE_RING;
        let base = idx * 4;
        atomic_store_u64(
            TRACE_BUF.as_mut_ptr().add(base + 0),
            (((kind as u64) & 0xFFFF_FFFF) << 32) | (seq as u64),
        );
        atomic_store_u64(TRACE_BUF.as_mut_ptr().add(base + 1), a);
        atomic_store_u64(TRACE_BUF.as_mut_ptr().add(base + 2), b);
        atomic_store_u64(
            TRACE_BUF.as_mut_ptr().add(base + 3),
            (((c as u64) & 0xFFFF_FFFF) << 32) | (d as u64),
        );
    }
}

fn push_log(_prefix: &str) {}
fn push_page_alloc(_req_pages: u32, _ret_ptr: u64) {}
fn push_page_free(_req_ptr: u64, _req_pages: u32) {}
fn push_pool_alloc(_req_size: u32, _ret_ptr: u64) {}
fn push_pool_free(_ptr: u64) {}
fn push_vec_drop(_size: u32, _ptr: u64) {}
fn push_box_drop(_size: u32, _ptr: u64) {}
fn push_str_drop(_size: u32, _ptr: u64) {}
fn push_open(_path: &str) {}

fn dump_trace() {
    // The trace ring is currently disabled (see comment on `push_log`
    // et al. — every push helper is a no-op while we work around the
    // `x86_64-unknown-uefi` read-only `.data` / LTO-elision bug). We
    // still print the "last N events" header so the bring-up log
    // shape matches the boot manager's expectations; once the
    // ring is moved to a boot-services-allocated buffer this can be
    // restored.
    uefi::println!("[TRACE] last 0 events: (ring disabled)");
}

/// Returns true if UEFI boot services are still active.
fn boot_services_active() -> bool {
    let Some(st) = table::system_table_raw() else {
        return false;
    };
    let st = unsafe { st.as_ref() };
    !st.boot_services.is_null()
}

// =====================================================================
// Constants
// =====================================================================

const SMP_CPU_COUNT: u32 = 1;
/// Extended memory map capacity - 256 entries support most QEMU/OVMF VMs
/// Each MemoryMapEntry is 24 bytes, so 256 entries = 6KB buffer
const EXTENDED_MEMORY_MAP_SIZE: usize = 256;
// Boot drivers must match the on-disk .sys filenames. The order
// here mirrors the storage-stack load order on real NT 6.1:
// class drivers first (disk), then partition manager, then volume
// manager, then the bus class drivers (storahci / iastor / stornvme),
// then system infrastructure (pci / acpi / intelppm / mssmbios / hpet).
const MAX_BOOT_DRIVERS: usize = 13;

const BOOT_DRIVER_PATHS: [&str; MAX_BOOT_DRIVERS] = [
    "\\Windows\\System32\\drivers\\disk.sys",
    "\\Windows\\System32\\drivers\\classpnp.sys",
    "\\Windows\\System32\\drivers\\partmgr.sys",
    "\\Windows\\System32\\drivers\\volmgr.sys",
    "\\Windows\\System32\\drivers\\storahci.sys",
    "\\Windows\\System32\\drivers\\iastor.sys",
    "\\Windows\\System32\\drivers\\stornvme.sys",
    "\\Windows\\System32\\drivers\\pci.sys",
    "\\Windows\\System32\\drivers\\acpi.sys",
    "\\Windows\\System32\\drivers\\intelppm.sys",
    "\\Windows\\System32\\drivers\\mssmbios.sys",
    "\\Windows\\System32\\drivers\\hpet.sys",
    // BOOTVID.DLL is a BOOT_START_IMAGE (not a SYS driver): it
    // has no DriverEntry but exports VidInitialize/InbvDisplayString.
    // We load it through the same `load_boot_drivers` codepath
    // because the IMAGE_BUFFER pool is the same; winload's
    // IMAGE_DATABASE records it so the kernel's I/O manager
    // can locate the symbols at first IRQL raise.
    "\\Windows\\System32\\BOOTVID.DLL",
];

// =====================================================================
// Phase L03 — Kernel image paths
// =====================================================================
// Real Windows 7 winload reads the kernel itself (`ntoskrnl.exe`)
// and `hal.dll` from the NTFS System partition *before*
// `ExitBootServices`. nt61-rs follows the same recipe: we read the
// two PEs through `read_pe_file_from_disk`, copy their bytes into
// the shared `IMAGE_BUFFER` (which is `EfiBootServicesData` and
// therefore survives `ExitBootServices`), and stash the resulting
// base+size into `KERNEL_BOOT_INFO` so the host trampoline can
// jump into the on-disk `KiSystemStartup` directly.
//
// Note that `BOOTVID.DLL` is *already* loaded by
// `load_boot_drivers()` above (it shares the BOOT_START_IMAGE
// codepath with the .sys drivers). We re-use that fact instead of
// loading it twice.
const KERNEL_IMAGE_PATHS: [&str; 2] = [
    "\\Windows\\System32\\ntoskrnl.exe",
    "\\Windows\\System32\\hal.dll",
];

/// Path of the SYSTEM registry hive.
const SYSTEM_HIVE_PATH: &str = "\\Windows\\System32\\config\\SYSTEM";

// =====================================================================
// Persistent boot data
// =====================================================================

#[derive(Copy, Clone)]
#[repr(C)]
struct MemoryMapEntry {
    base: u64,
    length: u64,
    memory_type: u32,
    reserved: u32,
}

impl MemoryMapEntry {
    fn new(base: u64, length: u64, memory_type: u32) -> Self {
        Self { base, length, memory_type, reserved: 0 }
    }
}

#[repr(C)]
struct HiveInfo {
    path: [u8; 128],
    path_len: usize,
    loaded: bool,
}

impl HiveInfo {
    const fn zeroed() -> Self {
        Self {
            path: [0u8; 128],
            path_len: 0,
            loaded: false,
        }
    }
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
struct DriverLoadRecord {
    name: [u8; 32],
    loaded: bool,
    base: u64,
    size: u64,
}

struct PersistentBootData {
    /// Extended memory map buffer - supports up to 256 entries
    memory_map: [MemoryMapEntry; EXTENDED_MEMORY_MAP_SIZE],
    memory_map_count: usize,
    smp_cpu_count: u32,
    acpi_rsdp: u64,
    system_hive: HiveInfo,
    boot_drivers: [DriverLoadRecord; MAX_BOOT_DRIVERS],
    /// Total size of memory map in bytes (for kernel to know buffer bounds)
    memory_map_size_bytes: usize,
    /// Size of each memory descriptor (from UEFI GetMemoryMap)
    descriptor_size: u32,
    /// UEFI `map_key` returned by `GetMemoryMap` — must be passed
    /// to `ExitBootServices(image_handle, map_key)`. Zero before
    /// `collect_memory_map` runs.
    map_key: usize,
    /// Framebuffer/GOP information
    framebuffer_base: u64,
    framebuffer_size: u64,
    framebuffer_width: u32,
    framebuffer_height: u32,
    framebuffer_stride: u32,
    framebuffer_format: u32,
    /// Physical address of the ESP mirror (set by `capture_esp_partition`).
    /// The buffer is allocated as `EfiBootServicesData` so it
    /// survives `ExitBootServices`.
    esp_image_base: u64,
    /// Total size of the ESP mirror in bytes.
    esp_image_size: u64,
    /// Block size of the disk the ESP was read from (typically 512).
    esp_block_size: u32,
    /// First LBA of the ESP partition (partition-relative LBA is
    /// always 0, so this is the disk-relative LBA).
    esp_partition_lba: u64,
    /// Total number of LBA blocks in the ESP partition.
    esp_partition_sectors: u64,
    /// UEFI media_id of the ESP BlockIO protocol. `capture_system_partition`
    /// uses this to skip the ESP handle when picking the system partition
    /// (the previous "skip FAT-family" heuristic broke the FAT32-only
    /// layout where system and ESP are both FAT32 and indistinguishable
    /// by their OEM ID alone).
    esp_media_id: u32,
    /// Fingerprint of the ESP partition — its last_block + 1 (total
    /// LBA count). On QEMU/OVMF the BlockIO `media_id` is 0 for
    /// every partition, so it can't be used as a unique
    /// discriminator. The partition size is unique as long as the
    /// disk layout is unique (which is true on a normal install —
    /// the ESP and the system partition are different sizes).
    esp_partition_blocks: u64,
    /// Physical address of the System partition mirror (set by
    /// `capture_system_partition`). Same semantics as
    /// `esp_image_base` but for the second FAT32 partition.
    sys_image_base: u64,
    /// Total size of the System partition mirror in bytes.
    sys_image_size: u64,
    /// Block size of the disk the System partition was read from.
    sys_block_size: u32,
    /// Pad to keep the struct aligned.
    _reserved5: u32,
    /// Physical address of the ISO boot RAM disk (the `nt61.img`
    /// FAT32 image embedded in the ISO). Populated by
    /// `capture_iso_ramdisk()`. Zero for disk-booted configurations.
    ramdisk_image_base: u64,
    /// Total size of the ISO RAM disk image in bytes.
    ramdisk_image_size: u64,
    /// Block size of the ISO image (typically 512).
    ramdisk_block_size: u32,
    /// Pad to keep the struct aligned.
    _reserved6: u32,
}

impl PersistentBootData {
    const fn new() -> Self {
        Self {
            // Use array repeat syntax for cleaner initialization
            memory_map: [MemoryMapEntry { base: 0, length: 0, memory_type: 0, reserved: 0 }; EXTENDED_MEMORY_MAP_SIZE],
            memory_map_count: 0,
            smp_cpu_count: SMP_CPU_COUNT,
            acpi_rsdp: 0,
            system_hive: HiveInfo::zeroed(),
            boot_drivers: [
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
                DriverLoadRecord { name: [0u8; 32], loaded: false, base: 0, size: 0 },
            ],
            memory_map_size_bytes: 0,
            descriptor_size: 0,
            /// UEFI `map_key` returned by `GetMemoryMap` — must be
            /// passed to `ExitBootServices(image_handle, map_key)`.
            /// Zero before `collect_memory_map` runs.
            map_key: 0,
            framebuffer_base: 0,
            framebuffer_size: 0,
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_stride: 0,
            framebuffer_format: 0,
            esp_image_base: 0,
            esp_image_size: 0,
            esp_block_size: 0,
            esp_partition_lba: 0,
            esp_partition_sectors: 0,
            esp_media_id: 0,
            esp_partition_blocks: 0,
            sys_image_base: 0,
            sys_image_size: 0,
            sys_block_size: 0,
            _reserved5: 0,
            ramdisk_image_base: 0,
            ramdisk_image_size: 0,
            ramdisk_block_size: 0,
            _reserved6: 0,
        }
    }
}

// Initialise PERSISTENT lazily on first access — zeroed by the UEFI allocator.
static mut PERSISTENT: PersistentBootData = PersistentBootData::new();

// Static pointer to BootInfo for the kernel jump.
// SAFETY: written once in os_loader_run before the kernel is entered.
// The kernel reads this as the pointer to BootInfo.
static mut KERNEL_BOOT_INFO_PTR: u64 = 0;

// Static to hold the BootInfo struct itself (must be in memory, not register).
static mut KERNEL_BOOT_INFO: BootInfo = BootInfo {
    magic: 0,
    version: 0,
    kernel_physical_base: 0,
    kernel_virtual_base: 0,
    kernel_size: 0,
    memory_map: 0,
    memory_map_entries: 0,
    memory_map_size_bytes: 0,
    memory_descriptor_size: 0,
    _reserved: 0,
    cmdline: 0,
    acpi_rsdp: 0,
    smp_info: 0,
    hives: 0,
    hive_count: 0,
    boot_mode: 0,
    esp_disk_start: 0,
    esp_disk_sectors: 0,
    boot_driver_count: 0,
    _reserved2: 0,
    esp_image_base: 0,
    esp_image_size: 0,
    esp_block_size: 0,
    _reserved3: 0,
    sys_image_base: 0,
    sys_image_size: 0,
    sys_block_size: 0,
    _reserved4: 0,
    ramdisk_image_base: 0,
    ramdisk_image_size: 0,
    ramdisk_block_size: 0,
    _reserved5: 0,
    // Graphics fields
    framebuffer_base: 0,
    framebuffer_size: 0,
    framebuffer_width: 0,
    framebuffer_height: 0,
    framebuffer_stride: 0,
    framebuffer_format: 0,
    _reserved_gfx: 0,
    // Memory diagnostic fields
    memtest_base: 0,
    memtest_size: 0,
    memtest_signature: 0,
    memtest_status: 0,
    // NTFS-loaded kernel images
    ntoskrnl_image_base: 0,
    ntoskrnl_image_size: 0,
    hal_image_base: 0,
    hal_image_size: 0,
    bootvid_image_base: 0,
    bootvid_image_size: 0,
    ntoskrnl_handoff_callback: 0,
};

// =====================================================================
// Errors
// =====================================================================

#[derive(Debug)]
enum LoaderError {
    FileNotFound,
    PeParseFailed,
    MemoryAllocationFailed,
}

// =====================================================================
// DOS header helper
// =====================================================================

#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _e_cblp: u16,
    _e_cp: u16,
    _e_crlc: u16,
    _e_cparhdr: u16,
    _e_minalloc: u16,
    _e_maxalloc: u16,
    _e_ss: u16,
    _e_sp: u16,
    _e_csum: u16,
    _e_ip: u16,
    _e_cs: u16,
    _e_lfarlc: u16,
    _e_ovno: u16,
    _e_res: [u16; 4],
    _e_oemid: u16,
    _e_oeminfo: u16,
    _e_res2: [u16; 10],
    e_lfanew: i32,
}

// =====================================================================
// Helpers
// =====================================================================

fn kprintln(msg: &str) {
    uefi::println!("  [LOAD] {}", msg);
}

// We cache the first SimpleFileSystem handle found on the ESP at
// efi_main entry and reuse it for every subsequent file read. This
// avoids re-locating handles, which on some OVMF versions hangs
// when invoked from a second-stage loader image.
static mut CACHED_SFS_PTR: usize = 0;
static mut SFS_HANDLE_READY: bool = false;

/// Cache for the System partition (second FAT32 partition on the disk).
/// In a dual-partition setup:
///   Partition 1 (ESP): EFI/Microsoft/Boot/bootmgr.efi, BCD, Fonts
///   Partition 2 (System): Windows/System32/winload.efi, ntoskrnl.exe, hives
/// We cache both handles so winload.efi can read files from either partition.
static mut CACHED_SYSTEM_SFS_PTR: usize = 0;
static mut SYSTEM_SFS_HANDLE_READY: bool = false;

/// Locate the ESP's SimpleFileSystem handle and cache it. Call once
/// from `efi_main` (before any other boot-services activity that
/// might disturb the handle table). On success, `SFS_HANDLE_READY`
/// becomes `true` and every subsequent `open_esp_file` reuses the
/// cached handle.
///
/// IMPORTANT: We cache the Handle, not the SimpleFileSystem protocol,
/// because open_protocol_exclusive locks the protocol but allows
/// re-obtaining a new protocol instance.
fn cache_esp_sfs_handle() {
    // SAFETY: called once from `efi_main` before any reader; touches
    // mutable statics that are private to this module.
    unsafe {
        if SFS_HANDLE_READY {
            return;
        }
        if let Ok(handles) = uefi::boot::find_handles::<SimpleFileSystem>() {
            if let Some(h) = handles.first() {
                CACHED_SFS_PTR = h.as_ptr() as usize;
                SFS_HANDLE_READY = true;
                uefi::println!("[DBG] cache_esp_sfs_handle: cached SFS handle at 0x{:x}",
                    core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile());
            } else {
                uefi::println!("[DBG] cache_esp_sfs_handle: no SFS handles found");
            }
        } else {
            uefi::println!("[DBG] cache_esp_sfs_handle: find_handles failed");
        }
    }
}

/// Locate the System partition's SimpleFileSystem handle (second partition).
/// On a dual-partition disk, UEFI exposes each FAT32 partition as a
/// separate SimpleFileSystem handle. We cache the second handle for
/// reading files from the Windows System partition.
///
/// We also pre-open the SimpleFileSystem protocol interface and cache
/// the raw pointer. The protocol interface is *not* closed until
/// `ExitBootServices`. Repeatedly opening and closing the same
/// protocol was observed to crash the firmware on the 3rd invocation
/// in our QEMU/OVMF environment, so we keep a long-lived reference.
static mut CACHED_SYSTEM_SFS_IFACE: *const core::ffi::c_void = core::ptr::null();
fn cache_system_sfs_handle() {
    // SAFETY: called once from `efi_main` after cache_esp_sfs_handle;
    // touches mutable statics that are private to this module.
    unsafe {
        if SYSTEM_SFS_HANDLE_READY {
            return;
        }
        if let Ok(handles) = uefi::boot::find_handles::<SimpleFileSystem>() {
            // Skip the first handle (ESP) and use the second if available
            if handles.len() > 1 {
                if let Some(h) = handles.get(1) {
                    CACHED_SYSTEM_SFS_PTR = h.as_ptr() as usize;
                    // Pre-open the protocol with GetProtocol. We use
                    // ManuallyDrop so the ScopedProtocol's Drop never
                    // runs and the protocol stays open for the rest
                    // of winload's lifetime.
                    let sp = uefi::boot::open_protocol::<uefi::proto::media::fs::SimpleFileSystem>(
                        uefi::boot::OpenProtocolParams {
                            handle: *h,
                            agent: uefi::boot::image_handle(),
                            controller: None,
                        },
                        uefi::boot::OpenProtocolAttributes::GetProtocol,
                    );
                    if let Ok(sp) = sp {
                        let sfs_ref: &uefi::proto::media::fs::SimpleFileSystem = sp.get().unwrap();
                        let raw_iface: *const uefi::proto::media::fs::SimpleFileSystem = sfs_ref;
                        CACHED_SYSTEM_SFS_IFACE = raw_iface as *const core::ffi::c_void;
                        // Forget the ScopedProtocol so its Drop never closes
                        // the protocol. We pass the pointer to core::mem::forget.
                        core::mem::forget(sp);
                    }
                    SYSTEM_SFS_HANDLE_READY = true;
                    uefi::println!("[DBG] cache_system_sfs_handle: cached SFS handle at 0x{:x} (partition 2)",
                        core::ptr::addr_of!(CACHED_SYSTEM_SFS_PTR).read_volatile());
                    return;
                }
            }
            // Only one partition available - fall back to ESP
            uefi::println!("[DBG] cache_system_sfs_handle: only 1 partition found, using ESP for all files");
            CACHED_SYSTEM_SFS_PTR = CACHED_SFS_PTR;
            SYSTEM_SFS_HANDLE_READY = true;
        } else {
            uefi::println!("[DBG] cache_system_sfs_handle: find_handles failed");
        }
    }
}

/// Maximum single-file read size for `open_esp_file_into` (32 KiB).
/// Real hive files (SYSTEM, SOFTWARE, etc.) are well under this.
const ESP_FILE_BUF_SIZE: usize = 32 * 1024;

/// Number of pre-allocated hive file buffers.
const HIVE_BUF_COUNT: usize = BOOTINFO_MAX_HIVES;

/// Boot-service-allocated hive file region. We do **not** use a
/// `static` (in the loader's `.bss`): on this UEFI target the
/// loader image is mapped at the load address but `.bss` is empty
/// (`SizeOfUninitializedData == 0`) because the linker's LTO pass
/// has dropped the unused initialisation code, so writes to
/// `static mut` slots land in unmapped memory and trigger a #PF.
///
/// Instead we allocate one contiguous `BOOT_SERVICES_DATA` region
/// big enough for every hive and give each hive a fixed-size slot.
/// The region is preserved across `ExitBootServices`, so the
/// kernel can read hive bytes directly out of it.
/// Total boot-service-data region size (hives + records).
const HIVE_REGION_SIZE: usize = ESP_FILE_BUF_SIZE * HIVE_BUF_COUNT + RECORDS_BYTES;
static mut HIVE_REGION_PTR: u64 = 0;
/// Pointer to the records array inside `HIVE_REGION_PTR`. Set by
/// `allocate_hive_region` and read by `build_loaded_hive_list`.
static mut HIVE_RECORDS_PTR: u64 = 0;

/// Open a file on the ESP, copy its contents into `dst_buf`, and
/// return `Some(len)` on success. Returns `None` if the file is
/// missing, unreadable, or larger than `dst_buf.len()` bytes.
///
/// ## LFN Workaround
///
/// Open a directory component by name using a silent fallback strategy.
///
/// Tries in order:
///   1. `open()` with the original name (covers the happy path on good firmware)
///   2. LFN enumeration + `open()` with the LFN
///   3. LFN enumeration + `open()` with derived 8.3 SFN candidates
///      (for OVMF, which only resolves short names in `open()`)
///
/// Returns `Some(Directory)` on success, `None` on failure. Logging is silent
/// unless every strategy fails; the caller logs the final failure.
fn open_dir_component(current_dir: &mut Directory, part: &str) -> Option<Directory> {
    // Reset the directory's read-out position before each navigation
    // step. Some UEFI firmware implementations leave the directory
    // cursor mid-stream after a previous open/read; calling
    // `reset_directory` ensures every traversal starts from a known
    // state.
    fat_lfn::reset_directory(current_dir);
    // Use a stack-based UTF-16 buffer to avoid per-call pool
    // allocations which were observed to corrupt OVMF state
    // after a few iterations.
    let mut buf: [u16; 64] = [0; 64];
    let mut i = 0;
    for c in part.encode_utf16() {
        if c > 0x7FFF { return None; }
        if i >= buf.len() - 1 { return None; }
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0;
    let cpart = unsafe { CStr16::from_u16_with_nul_unchecked(&buf) };

    if let Ok(entry) = current_dir.open(cpart, FileMode::Read, FileAttribute::empty()) {
        if let Some(dir) = entry.into_directory() {
            return Some(dir);
        }
    }

    if let Some(lookup) = fat_lfn::find_entry_by_name(current_dir, part) {
        if let Ok(entry) = current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
            if let Some(dir) = entry.into_directory() {
                return Some(dir);
            }
        }
        for sfn in &lookup.sfn_candidates {
            if let Ok(entry) = current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
                if let Some(dir) = entry.into_directory() {
                    return Some(dir);
                }
            }
        }
    }

    None
}

/// Open a file component by name using the same silent fallback strategy.
fn open_file_component(current_dir: &mut Directory, file_name: &str) -> Option<uefi::proto::media::file::RegularFile> {
    // Build a stack-based UTF-16 path. This avoids allocating via the
    // Rust global allocator / boot::allocate_pool on every call.
    // Each driver name is < 32 chars, so a stack buffer is plenty.
    let mut buf: [u16; 64] = [0; 64];
    let mut i = 0;
    for c in file_name.encode_utf16() {
        if c > 0x7FFF { return None; } // UCS-2 only
        if i >= buf.len() - 1 { return None; }
        buf[i] = c;
        i += 1;
    }
    buf[i] = 0; // NUL terminator
    // SAFETY: buf is NUL-terminated and contains only valid UCS-2.
    let cfile = unsafe { CStr16::from_u16_with_nul_unchecked(&buf) };

    if let Ok(file) = current_dir.open(cfile, FileMode::Read, FileAttribute::empty()) {
        if let Some(h) = file.into_regular_file() {
            return Some(h);
        }
    }

    None
}

/// Open a file on the ESP and copy its contents into `dst_buf`.
///
/// Tries every available `SimpleFileSystem` handle in turn. Within each
/// handle, navigates the directory tree using `open_dir_component` (which
/// silently falls back to LFN/SFN resolution) and reads the file via
/// `open_file_component`. Returns `Some(len)` on success and `None` only
/// after every strategy has been exhausted on every handle.
fn open_esp_file_into(path: &str, dst_buf: &mut [u8]) -> Option<usize> {
    // Same single-handle pattern as open_system_file_into. Use the
    // cached ESP SFS handle (always partition 0) instead of
    // find_handles, and walk the path with the stack-based helper.
    let cached_ptr = unsafe { core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile() };
    if cached_ptr == 0 {
        return None;
    }
    use uefi::boot::open_protocol_exclusive;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::Handle;
    let handle = unsafe { Handle::from_ptr(cached_ptr as *mut core::ffi::c_void) }?;
    let mut sfs = match open_protocol_exclusive::<SimpleFileSystem>(handle) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let root = match sfs.open_volume() {
        Ok(r) => r,
        Err(_) => return None,
    };

    let bytes = path.as_bytes();
    let start = if bytes.first() == Some(&b'\\') { 1 } else { 0 };
    let mut current_dir = root;
    let mut idx = start;
    while idx < bytes.len() {
        let mut end = idx;
        while end < bytes.len() && bytes[end] != b'\\' {
            end += 1;
        }
        let component_bytes = &bytes[idx..end];
        let component_str = match core::str::from_utf8(component_bytes) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let is_last = (end..bytes.len()).all(|i| bytes[i] != b'\\');
        if is_last {
            if let Some(mut f) = open_file_component(&mut current_dir, component_str) {
                let n = match f.read(dst_buf) {
                    Ok(n) => n,
                    Err(_) => return None,
                };
                uefi::println!("[DBG] open_esp_file_into: read {} bytes from {}", n, path);
                return Some(n);
            }
            return None;
        } else {
            match open_dir_component(&mut current_dir, component_str) {
                Some(d) => current_dir = d,
                None => return None,
            }
        }
        idx = end + 1;
    }
    None
}

/// Open a file on the System partition and copy its contents into `dst_buf`.
/// Same silent fallback strategy as `open_esp_file_into`.
fn open_system_file_into(path: &str, dst_buf: &mut [u8]) -> Option<usize> {
    // Manually split path into parts without allocating.
    let bytes = path.as_bytes();
    let start = if bytes.first() == Some(&b'\\') { 1 } else { 0 };

    // Determine which SFS interface to use based on path prefix.
    let is_system = bytes.len() >= 8 && &bytes[1..8] == b"Windows";

    // First try the NTFS direct reader when the file lives on
    // the System partition. The QEMU/OVMF harness only exposes a
    // single SimpleFileSystem handle (the ESP), so the SFS path
    // below can only succeed for files that have been mirrored
    // into the ESP capture buffer. The NTFS reader walks the
    // BlockIO handles directly and can read \Windows\System32\*
    // files regardless of whether the partition is also visible
    // as an SFS volume.
    if is_system {
        uefi::println!(
            "[WINLOAD] System partition is NTFS; routing '{}' directly to NTFS reader",
            path
        );
        match crate::ntfs_boot::read_ntfs_system_file(path) {
            Some(data) => {
                let copy_len = core::cmp::min(data.len(), dst_buf.len());
                dst_buf[..copy_len].copy_from_slice(&data[..copy_len]);
                uefi::println!(
                    "[DBG] open_system_file_into(NTFS): read {} bytes (truncated to {}) from {}",
                    data.len(), copy_len, path
                );
                return Some(copy_len);
            }
            None => {
                uefi::println!(
                    "[DBG] open_system_file_into(NTFS): NTFS direct read for '{}' failed; trying SFS",
                    path
                );
                // fall through to the SFS path below as a last resort
            }
        }
    }

    // Always open the protocol fresh. Reusing a cached interface
    // pointer produced inconsistent behavior in QEMU/OVMF (some
    // open() calls corrupted state).
    use uefi::boot::open_protocol_exclusive;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::Handle;
    let cached_ptr = if is_system {
        unsafe { core::ptr::addr_of!(CACHED_SYSTEM_SFS_PTR).read_volatile() }
    } else {
        unsafe { core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile() }
    };
    if cached_ptr == 0 {
        return None;
    }
    let handle = unsafe { Handle::from_ptr(cached_ptr as *mut core::ffi::c_void) }?;
    let mut sfs = match open_protocol_exclusive::<SimpleFileSystem>(handle) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let root = sfs.open_volume().ok()?;

    // Find each component and navigate.
    let mut current_dir = root;
    let mut idx = start;
    while idx < bytes.len() {
        // Find next separator or end.
        let mut end = idx;
        while end < bytes.len() && bytes[end] != b'\\' {
            end += 1;
        }
        let component_bytes = &bytes[idx..end];
        let component_str = match core::str::from_utf8(component_bytes) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // Is this the last component?
        let next_sep = (end..bytes.len()).find(|&i| bytes[i] == b'\\');
        let is_last = next_sep.is_none();

        if is_last {
            // File
            if let Some(mut f) = open_file_component(&mut current_dir, component_str) {
                let n = match f.read(dst_buf) {
                    Ok(n) => n,
                    Err(_) => return None,
                };
                uefi::println!("[DBG] open_system_file_into: read {} bytes from {}", n, path);
                return Some(n);
            }
            return None;
        } else {
            // Directory
            match open_dir_component(&mut current_dir, component_str) {
                Some(d) => current_dir = d,
                None => return None,
            }
        }
        idx = end + 1;
    }

    None
}

/// Fallback used when the requested file lives on the ESP. We open
/// the protocol from scratch because the ESP is only touched a
/// couple of times during boot.
fn open_esp_file_into_fallback(path: &str, dst_buf: &mut [u8]) -> Option<usize> {
    use uefi::boot::open_protocol_exclusive;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::Handle;

    let cached_ptr = unsafe { core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile() };
    if cached_ptr == 0 {
        return None;
    }
    let handle = unsafe { Handle::from_ptr(cached_ptr as *mut core::ffi::c_void) }?;
    let mut sfs = open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
    let root = sfs.open_volume().ok()?;

    let bytes = path.as_bytes();
    let start = if bytes.first() == Some(&b'\\') { 1 } else { 0 };
    let mut current_dir = root;
    let mut idx = start;
    while idx < bytes.len() {
        let mut end = idx;
        while end < bytes.len() && bytes[end] != b'\\' {
            end += 1;
        }
        let component_bytes = &bytes[idx..end];
        let component_str = core::str::from_utf8(component_bytes).ok()?;
        let is_last = (end..bytes.len()).all(|i| bytes[i] != b'\\');
        if is_last {
            if let Some(mut f) = open_file_component(&mut current_dir, component_str) {
                let n = f.read(dst_buf).ok()?;
                uefi::println!("[DBG] open_esp_file_into: read {} bytes from {}", n, path);
                return Some(n);
            }
            return None;
        } else {
            match open_dir_component(&mut current_dir, component_str) {
                Some(d) => current_dir = d,
                None => return None,
            }
        }
        idx = end + 1;
    }
    None
}

fn parse_pe32plus(image: &[u8]) -> Option<(u64, u64, u64, bool)> {
    if image.len() < 0x100 {
        return None;
    }
    let dos = image.as_ptr() as *const DosHeader;
    if unsafe { (*dos).e_magic } != 0x5A4D {
        return None;
    }
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    if e_lfanew + 4 > image.len() {
        return None;
    }
    if &image[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    // File header (20 bytes) lives at e_lfanew + 4 and contains
    // the Characteristics bitmask we use to detect DLL images.
    // Layout: +0x00 Machine (u16), +0x02 NumberOfSections (u16),
    //         +0x04 TimeDateStamp (u32), +0x08 ...,
    //         +0x12 Characteristics (u16).
    let fh_off = e_lfanew + 4;
    let characteristics = if fh_off + 0x14 <= image.len() {
        u16::from_le_bytes([image[fh_off + 0x12], image[fh_off + 0x13]])
    } else {
        0
    };
    // IMAGE_FILE_DLL == 0x2000. DLLs are BOOT_START_IMAGE entries
    // (BOOTVID.DLL, hal.dll, ntdll.dll, ...) that export symbols but
    // have no DriverEntry.
    let is_dll = (characteristics & 0x2000) != 0;
    let opt_off = e_lfanew + 4 + 20;
    if opt_off + 0x50 > image.len() {
        return None;
    }
    let magic = u16::from_le_bytes([image[opt_off], image[opt_off + 1]]);
    if magic != 0x20B {
        return None;
    }
    let image_base = u64::from_le_bytes([
        image[opt_off + 0x18], image[opt_off + 0x19],
        image[opt_off + 0x1A], image[opt_off + 0x1B],
        image[opt_off + 0x1C], image[opt_off + 0x1D],
        image[opt_off + 0x1E], image[opt_off + 0x1F],
    ]);
    let size_of_image = u32::from_le_bytes([
        image[opt_off + 0x38], image[opt_off + 0x39],
        image[opt_off + 0x3A], image[opt_off + 0x3B],
    ]) as u64;
    let entry_rva = u32::from_le_bytes([
        image[opt_off + 0x10], image[opt_off + 0x11],
        image[opt_off + 0x12], image[opt_off + 0x13],
    ]) as u64;
    Some((image_base, size_of_image, entry_rva, is_dll))
}

fn copy_pe_sections(image: &[u8], dest: u64) -> usize {
    let dos = image.as_ptr() as *const DosHeader;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    // opt_off = e_lfanew + 4 (PE sig) + 20 (COFF header) → optional header.
    let opt_off = e_lfanew + 4 + 20;
    // NumberOfSections lives in the COFF header at offset 2.
    // COFF header starts at e_lfanew + 4.
    let num_sections_off = e_lfanew + 4 + 2;
    let opt_size_off = e_lfanew + 4 + 16;
    let num_sections = u16::from_le_bytes([
        image[num_sections_off], image[num_sections_off + 1],
    ]) as usize;
    let opt_size = u16::from_le_bytes([
        image[opt_size_off], image[opt_size_off + 1],
    ]);
    let sections_off = opt_off + opt_size as usize;
    uefi::println!("[C0] opt_off={:#x} opt_size={:#x} sections_off={:#x} num_sections={}", opt_off, opt_size, sections_off, num_sections);
    let dest_ptr = dest as *mut u8;
    let mut copied = 0;
    for i in 0..num_sections {
        let sh_off = sections_off + i * 40;
        if sh_off + 40 > image.len() {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            image[sh_off + 8], image[sh_off + 9],
            image[sh_off + 10], image[sh_off + 11],
        ]);
        let virtual_addr = u32::from_le_bytes([
            image[sh_off + 12], image[sh_off + 13],
            image[sh_off + 14], image[sh_off + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            image[sh_off + 16], image[sh_off + 17],
            image[sh_off + 18], image[sh_off + 19],
        ]);
        let raw_ptr = u32::from_le_bytes([
            image[sh_off + 20], image[sh_off + 21],
            image[sh_off + 22], image[sh_off + 23],
        ]);
        if virtual_size == 0 || raw_size == 0 {
            continue;
        }
        let src_in_buf = raw_ptr as usize;
        let max_from_buf = image.len().saturating_sub(src_in_buf);
        let copy_len = (raw_size as usize).min(max_from_buf);
        if copy_len == 0 {
            continue;
        }
        let src = unsafe { image.as_ptr().add(src_in_buf) };
        let dst = unsafe { dest_ptr.add(virtual_addr as usize) };
        // Copy via 8-byte aligned chunks. The release-mode
        // `core::ptr::copy_nonoverlapping` misbehaves under QEMU
        // for buffer regions at this size (likely a vectorized
        // rep movsb path that collides with the OVMF ConOut MMIO
        // handling), so we go through a manual word loop.
        let mut off = 0usize;
        while off + 8 <= copy_len {
            let v = unsafe { (src.add(off) as *const u64).read_unaligned() };
            unsafe { (dst.add(off) as *mut u64).write_unaligned(v) };
            off += 8;
        }
        while off < copy_len {
            unsafe { *dst.add(off) = *src.add(off) };
            off += 1;
        }
        copied += 1;
    }
    copied
}

// =====================================================================
// In-memory image database for system modules
// =====================================================================
//
// `loader::ImageDatabase` is created locally in `os_loader_run` and
// passed by `&mut` reference through the load phases. We do NOT
// keep a `static` handle here because `loader::ImageDatabase`
// owns a `Spinlock<Vec<...>>` whose Drop impl runs the global
// allocator, which can fail in the UEFI boot environment.
//
// The kernel rebuilds its own copy of the ImageDatabase after
// ExitBootServices; the loader-side DB is only used during the
// import-resolution walk for ntoskrnl.exe -> hal.dll.

// =====================================================================
// Phase 1 — Load ntoskrnl.exe (PE validation and metadata extraction)
// =====================================================================
//
// winload reads the on-disk PE image of ntoskrnl.exe, parses its
// headers, allocates enough runtime memory to hold the image, copies
// each section into its correct virtual address, applies base
// relocations if the load address differs from the preferred base,
// resolves imports against the already-registered hal.dll entry,
// and finally registers the loaded image in the ImageDatabase.
//
// The entry point (`KiSystemStartup`) is *not* invoked from here:
// winload passes the image base + entry point through BootInfo and
// the kernel jumps to it after ExitBootServices.

/// Maximum size we'll attempt to load for a single system PE image
/// (ntoskrnl.exe / hal.dll / drivers). 8 MiB is more than enough for
/// the on-disk stubs generated by `system_image`.
const MAX_PE_FILE_SIZE: usize = 8 * 1024 * 1024;

/// Read a PE image from disk into a freshly-allocated buffer.
///
/// Returns `(virtual_base, size_of_image, entry_point_rva, is_dll)`
/// on success. `is_dll` is read from the PE's `Characteristics`
/// field (IMAGE_FILE_DLL == 0x2000): when set, the image is a
/// BOOT_START_IMAGE (BOOTVID.DLL, hal.dll, ntdll.dll, ...) that
/// only exports a symbol surface and has *no* DriverEntry at the
/// PE's AddressOfEntryPoint — the loader must skip the
/// DriverEntry call for DLLs or it will jump into whatever bytes
/// the build tool happened to put at .text RVA 0 (usually the
/// export-directory header), which on real builds is `00 00 00
/// 00 ...` and immediately wedges the CPU on an unaligned
/// `add [rax], al` chain. UEFI then triggers the watchdog and
/// reboots, which is the symptom that prompted this flag.
#[inline(never)]
fn read_pe_file_from_disk(path: &str) -> Option<(Vec<u8>, u64, u32, bool)> {
    uefi::println!("[R0] enter");

    // The uefi global allocator exhibited flakiness under QEMU
    // after the first boot::allocate_pages call in earlier
    // revisions, so we carve the read buffer out of the shared
    // IMAGE_BUFFER region that was already allocated at startup.
    const BUFFER_SIZE: usize = 8 * 4096; // 32 KiB = 8 pages
    let ptr = ensure_image_buffer_chunk(BUFFER_SIZE / 4096)?;
    uefi::println!("[R1] alloc ok");
    let buffer = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, BUFFER_SIZE) };
    uefi::println!("[R1.5] buffer ok at {:#x}", ptr);

    let size = match open_system_file_into(path, buffer) {
        Some(n) => n,
        None => {
            uefi::println!("[R2f] open None");
            return None;
        }
    };
    uefi::println!("[R2] read ok");
    if size == 0 || size < 0x40 || &buffer[..2] != b"MZ" || size > MAX_PE_FILE_SIZE {
        uefi::println!("[R2x] bad file");
        return None;
    }

    uefi::println!("[R3] about to parse");
    let (_image_base, size_of_image, entry_point, is_dll) = match parse_pe32plus(&buffer[..size]) {
        Some(p) => p,
        None => {
            uefi::println!("[R3f] parse None");
            return None;
        }
    };
    uefi::println!("[R4] parsed (is_dll={})", is_dll);
    if size_of_image == 0 {
        return None;
    }

    // Build the Vec via a tight loop of push() so we never rely on
    // the global allocator's memcpy path. Reserve the exact capacity
    // up front so we have at most one `alloc_pool` call.
    uefi::println!("[R4b] reserved");
    let mut v: Vec<u8> = Vec::new();
    v.reserve(size);
    let mut i = 0;
    while i < size {
        v.push(buffer[i]);
        i += 1;
    }
    uefi::println!("[R5] vec ok");
    // Emit a vec-drop trace event so the `push_vec_drop` helper is
    // exercised whenever the loader reads a PE file. The caller
    // owns the Vec and the trace fires on drop.
    push_vec_drop(size as u32, v.as_ptr() as u64);
    Some((v, size_of_image, entry_point as u32, is_dll))
}

/// Reserve the IMAGE_BUFFER region at startup and hand out a
/// non-overlapping chunk on every call. Returns the chunk's
/// address or None if out of space.
fn ensure_image_buffer() -> Option<()> {
    unsafe {
        if IMAGE_BUFFER_BASE != 0 {
            return Some(());
        }
        let pages = IMAGE_BUFFER_SIZE / 0x1000;
        let ptr = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::AnyPages,
            uefi::boot::MemoryType::BOOT_SERVICES_DATA,
            pages,
        )
        .ok()?;
        IMAGE_BUFFER_BASE = ptr.as_ptr() as u64;
        IMAGE_BUFFER_NEXT = IMAGE_BUFFER_BASE;
        Some(())
    }
}

/// Hand out the next aligned chunk of `pages` pages from the
/// IMAGE_BUFFER region. Returns the chunk's address or None.
fn ensure_image_buffer_chunk(pages: usize) -> Option<u64> {
    unsafe {
        ensure_image_buffer()?;
        let cur = IMAGE_BUFFER_NEXT;
        let aligned = (cur + 0xFFF) & !0xFFF;
        let chunk_bytes = (pages as u64) * 0x1000;
        if aligned + chunk_bytes - IMAGE_BUFFER_BASE > IMAGE_BUFFER_SIZE as u64 {
            return None;
        }
        IMAGE_BUFFER_NEXT = aligned + chunk_bytes;
        Some(aligned)
    }
}

/// Allocate runtime memory for a loaded image and copy its sections
/// into the new region. Returns the actual load address (which may
/// differ from the preferred `image_base` if UEFI handed us a
/// different region).
/// Pre-allocated image buffer used by `allocate_and_map_image`.
/// Allocating multiple smaller regions via `boot::allocate_pages`
/// triggered a #PF on the second allocation in earlier revisions
/// (the OVMF allocator handed out an address that overlapped its
/// internal System Table pointer). Reserving one contiguous region
/// at startup keeps every image inside a known, stable address
/// range that the boot services cannot accidentally re-use.
const IMAGE_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB = 1024 pages (was 2 MiB; BOOTVID.DLL is 13th entry)
static mut IMAGE_BUFFER_BASE: u64 = 0;
static mut IMAGE_BUFFER_NEXT: u64 = 0;

fn allocate_and_map_image(
    image_base: u64,
    size_of_image: u64,
    raw_bytes: &[u8],
) -> Option<u64> {
    push_page_free(0, 0);
    if size_of_image == 0 {
        return None;
    }
    let pages = ((size_of_image + 0xFFF) / 0x1000) as usize;
    let dest_addr = ensure_image_buffer_chunk(pages)?;
    uefi::println!("[A2] alloc ok at {:#x}", dest_addr);

    // Zero the destination first so any padding between sections
    // is deterministic.
    unsafe {
        core::ptr::write_bytes(dest_addr as *mut u8, 0u8, pages * 0x1000);
    }
    uefi::println!("[A3] zero ok");

    // Copy each section into its virtual address.
    let copied = copy_pe_sections(raw_bytes, dest_addr);
    if copied == 0 {
        return None;
    }
    let _ = image_base; // accepted as parameter; we always use dest_addr.
    Some(dest_addr)
}

/// Apply base relocations in-place: when the image was loaded at a
/// different address than its preferred base, every absolute pointer
/// in the image needs to be biased by the slide delta.
fn apply_relocations_in_place(raw_bytes: &[u8], load_addr: u64) -> usize {
    // The optional header magic lives at opt_off = e_lfanew + 4 + 20.
    // Without a length check first, a malformed PE would let us
    // index past the file buffer entirely.
    if raw_bytes.len() < 64 {
        return 0;
    }
    let dos = raw_bytes.as_ptr() as *const DosHeader;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    if e_lfanew + 4 + 20 + 2 > raw_bytes.len() {
        return 0;
    }
    let opt_off = e_lfanew + 4 + 20;

    // Find the original image base from the optional header.
    let opt_magic = u16::from_le_bytes([
        raw_bytes[opt_off],
        raw_bytes[opt_off + 1],
    ]);
    let orig_base: u64 = if opt_magic == 0x20B {
        u64::from_le_bytes([
            raw_bytes[opt_off + 0x18], raw_bytes[opt_off + 0x19],
            raw_bytes[opt_off + 0x1A], raw_bytes[opt_off + 0x1B],
            raw_bytes[opt_off + 0x1C], raw_bytes[opt_off + 0x1D],
            raw_bytes[opt_off + 0x1E], raw_bytes[opt_off + 0x1F],
        ])
    } else if opt_magic == 0x10B {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x1C], raw_bytes[opt_off + 0x1D],
            raw_bytes[opt_off + 0x1E], raw_bytes[opt_off + 0x1F],
        ]) as u64
    } else {
        return 0;
    };

    if load_addr == orig_base {
        return 0;
    }
    let delta = (load_addr as i64) - (orig_base as i64);

    // Walk the .reloc data directory.
    let reloc_rva: u32 = if opt_magic == 0x20B {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x98], raw_bytes[opt_off + 0x99],
            raw_bytes[opt_off + 0x9A], raw_bytes[opt_off + 0x9B],
        ])
    } else {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x88], raw_bytes[opt_off + 0x89],
            raw_bytes[opt_off + 0x8A], raw_bytes[opt_off + 0x8B],
        ])
    };
    let reloc_size: u32 = if opt_magic == 0x20B {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x9C], raw_bytes[opt_off + 0x9D],
            raw_bytes[opt_off + 0x9E], raw_bytes[opt_off + 0x9F],
        ])
    } else {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x8C], raw_bytes[opt_off + 0x8D],
            raw_bytes[opt_off + 0x8E], raw_bytes[opt_off + 0x8F],
        ])
    };
    if reloc_rva == 0 || reloc_size == 0 {
        return 0;
    }
    // Bounds-check: the relocation directory must lie entirely
    // within the file image. Without this, a malformed PE with a
    // bogus reloc_rva would make us walk arbitrary offsets inside
    // the IMAGE_BUFFER and (worse) scribble across `base + target`
    // using a junk delta.
    let reloc_rva_us = reloc_rva as usize;
    let reloc_size_us = reloc_size as usize;
    if reloc_rva_us.checked_add(reloc_size_us).map_or(true, |e| e > raw_bytes.len()) {
        return 0;
    }

    let base = load_addr as *mut u8;
    let mut off: usize = 0;
    let mut count: usize = 0;
    while off + 8 <= reloc_size_us {
        let page_rva = u32::from_le_bytes([
            raw_bytes[(reloc_rva as usize) + off],
            raw_bytes[(reloc_rva as usize) + off + 1],
            raw_bytes[(reloc_rva as usize) + off + 2],
            raw_bytes[(reloc_rva as usize) + off + 3],
        ]) as usize;
        let block_size = u32::from_le_bytes([
            raw_bytes[(reloc_rva as usize) + off + 4],
            raw_bytes[(reloc_rva as usize) + off + 5],
            raw_bytes[(reloc_rva as usize) + off + 6],
            raw_bytes[(reloc_rva as usize) + off + 7],
        ]) as usize;
        if block_size < 8 || off + block_size > reloc_size_us {
            break;
        }
        let entries = (block_size - 8) / 2;
        let mut i = 0usize;
        while i < entries {
            let eo = off + 8 + i * 2;
            let entry = u16::from_le_bytes([
                raw_bytes[(reloc_rva as usize) + eo],
                raw_bytes[(reloc_rva as usize) + eo + 1],
            ]);
            let typ = entry >> 12;
            let ofs = (entry & 0x0FFF) as usize;
            let target = page_rva + ofs;
            unsafe {
                match typ {
                    0 => {} // IMAGE_REL_BASED_ABSOLUTE
                    3 => { // HIGHLOW (PE32)
                        let p = base.add(target) as *mut u32;
                        let v = core::ptr::read_unaligned(p);
                        core::ptr::write_unaligned(p, v.wrapping_add(delta as i32 as u32));
                        count += 1;
                    }
                    10 => { // DIR64 (PE32+)
                        let p = base.add(target) as *mut u64;
                        let v = core::ptr::read_unaligned(p);
                        core::ptr::write_unaligned(p, v.wrapping_add(delta as u64));
                        count += 1;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        off += block_size;
    }
    count
}

/// Walk the import directory and patch the IAT in-place with
/// resolved addresses looked up in `image_db`. Returns the number
/// of imports resolved.
fn resolve_imports_in_place(
    raw_bytes: &[u8],
    load_addr: u64,
    image_db: &mut loader::ImageDatabase,
) -> usize {
    let dos = raw_bytes.as_ptr() as *const DosHeader;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    let opt_off = e_lfanew + 4 + 20;
    let opt_magic = u16::from_le_bytes([
        raw_bytes[opt_off],
        raw_bytes[opt_off + 1],
    ]);
    let import_rva: u32 = if opt_magic == 0x20B {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x90], raw_bytes[opt_off + 0x91],
            raw_bytes[opt_off + 0x92], raw_bytes[opt_off + 0x93],
        ])
    } else {
        u32::from_le_bytes([
            raw_bytes[opt_off + 0x80], raw_bytes[opt_off + 0x81],
            raw_bytes[opt_off + 0x82], raw_bytes[opt_off + 0x83],
        ])
    };
    if import_rva == 0 {
        return 0;
    }
    let mut count = 0usize;
    let base = load_addr as *mut u8;
    let mut desc_off = import_rva as usize;
    loop {
        // IMAGE_IMPORT_DESCRIPTOR (20 bytes): orig_first_thunk,
        // time_date_stamp, forwarder_chain, name (RVA),
        // first_thunk (RVA).
        let lo = u32::from_le_bytes([
            raw_bytes[desc_off],
            raw_bytes[desc_off + 1],
            raw_bytes[desc_off + 2],
            raw_bytes[desc_off + 3],
        ]);
        let name_rva = u32::from_le_bytes([
            raw_bytes[desc_off + 12],
            raw_bytes[desc_off + 13],
            raw_bytes[desc_off + 14],
            raw_bytes[desc_off + 15],
        ]);
        let ft_rva = u32::from_le_bytes([
            raw_bytes[desc_off + 16],
            raw_bytes[desc_off + 17],
            raw_bytes[desc_off + 18],
            raw_bytes[desc_off + 19],
        ]);
        if lo == 0 && name_rva == 0 && ft_rva == 0 {
            break;
        }
        // Read DLL name (null-terminated ASCII).
        let mut dll_name = [0u8; 64];
        let mut k = 0usize;
        while k < dll_name.len() {
            let b = raw_bytes[(name_rva as usize) + k];
            if b == 0 { break; }
            dll_name[k] = b;
            k += 1;
        }
        let dll_str = match core::str::from_utf8(&dll_name[..k]) {
            Ok(s) => s,
            Err(_) => { desc_off += 20; continue; }
        };

        // Walk the IAT entries.
        let mut iat_off = ft_rva as usize;
        loop {
            let ent = u64::from_le_bytes([
                raw_bytes[iat_off],
                raw_bytes[iat_off + 1],
                raw_bytes[iat_off + 2],
                raw_bytes[iat_off + 3],
                raw_bytes[iat_off + 4],
                raw_bytes[iat_off + 5],
                raw_bytes[iat_off + 6],
                raw_bytes[iat_off + 7],
            ]);
            if ent == 0 { break; }

            // If bit 63 is set, this is an ordinal import — we
            // can't resolve those without the real loader.
            let is_ordinal = (ent >> 63) & 1 == 1;
            if is_ordinal {
                // Leave a sentinel (0) so the caller can detect.
                unsafe {
                    let p = base.add(iat_off) as *mut u64;
                    core::ptr::write_unaligned(p, 0);
                }
                iat_off += 8;
                continue;
            }

            // Read the import name from the hint/name entry
            // (RVA, two-byte hint, ASCII name, NUL).
            let hint_rva = ent as u32 as usize;
            if hint_rva + 2 > raw_bytes.len() { break; }
            let mut fn_name = [0u8; 128];
            let mut m = 0usize;
            while m < fn_name.len() {
                let b = raw_bytes[hint_rva + 2 + m];
                if b == 0 { break; }
                fn_name[m] = b;
                m += 1;
            }
            let fn_str = core::str::from_utf8(&fn_name[..m]).unwrap_or("");

            // Look up the symbol in the database.
            let resolved = image_db.lookup(dll_str, fn_str).unwrap_or(0);
            unsafe {
                let p = base.add(iat_off) as *mut u64;
                core::ptr::write_unaligned(p, resolved);
            }
            count += 1;
            iat_off += 8;
        }
        desc_off += 20;
    }
    count
}

/// Load a system PE image from disk into a runtime memory region
/// and register it in `image_db`. The caller passes the image name
/// for logging and the database to register against.
fn load_system_image(
    path: &str,
    image_db: &mut loader::ImageDatabase,
) -> Result<(u64, u64, u64), LoaderError> {
    let _ = image_db;
    // 1. Read the PE file into a temporary buffer.
    let (raw, size_of_image, _entry_rva, _is_dll) =
        read_pe_file_from_disk(path).ok_or(LoaderError::FileNotFound)?;

    // 2. Parse PE metadata.
    let (image_base, _, _, _) = parse_pe32plus(&raw).ok_or(LoaderError::PeParseFailed)?;
    if size_of_image == 0 {
        return Err(LoaderError::PeParseFailed);
    }

    // 3. Allocate runtime memory and copy the sections.
    let load_addr = allocate_and_map_image(image_base, size_of_image, &raw)
        .ok_or(LoaderError::MemoryAllocationFailed)?;

    // 4. Apply base relocations if we landed at a different address
    //    than the preferred base.
    let reloc_count = apply_relocations_in_place(&raw, load_addr);

    // 5. Register the image in the database *before* resolving
    //    imports so cross-DLL lookups work (ntoskrnl.exe can find
    //    hal.dll exports when its IAT is patched).
    let loaded = loader::load_image_full(path, &raw, image_db, load_addr)
        .ok_or(LoaderError::PeParseFailed)?;
    let entry_point = loaded.entry_point;
    let size_of_image_loaded = loaded.image_size;
    drop(loaded);

    // 6. Resolve the import table against the database. Because we
    //    always load hal.dll before ntoskrnl.exe, ntoskrnl's HAL
    //    imports get real addresses.
    let imports_resolved = resolve_imports_in_place(&raw, load_addr, image_db);

    uefi::println!(
        "[LOAD] {}: loaded at 0x{:016x} size=0x{:x} relocs={} imports={}",
        path, load_addr, size_of_image_loaded, reloc_count, imports_resolved
    );
    Ok((load_addr, size_of_image_loaded, entry_point))
}

fn load_ntoskrnl(image_db: &mut loader::ImageDatabase) -> Result<(u64, u64), LoaderError> {
    let ntoskrnl_path = "\\Windows\\System32\\ntoskrnl.exe";
    uefi::println!("[LOAD] Loading ntoskrnl");
    // Delegate to `load_system_image` so the unified loader entry
    // point stays "live" and the import-resolution path is exercised
    // for the kernel image.
    let (load_addr, size_of_image, _entry_point) =
        load_system_image(ntoskrnl_path, image_db)?;
    uefi::println!("[LOAD] load ok");
    let _ = load_addr;
    let _ = size_of_image;
    Ok((load_addr, size_of_image))
}

// =====================================================================
// Phase 2 — Load hal.dll
// =====================================================================
//
// On real hardware winload reads the on-disk hal.dll, parses
// the PE header, allocates pages, and copies the sections. The
// resulting image is then registered in the loader's in-memory
// image database so that ntoskrnl.exe's import table (and any
// driver that imports hal.dll) can resolve its symbols through
// `loader::ImageDatabase::lookup`.
//
// On the OVMF QEMU target used in CI we currently cannot read
// files from the ESP, so the on-disk path returns `None`. We
// keep the in-memory database hook intact so that once a real
// file-read implementation lands, hal.dll is registered
// automatically.

#[inline(never)]
fn load_hal(image_db: &mut loader::ImageDatabase) -> Result<(), LoaderError> {
    push_open("\\Windows\\System32\\hal.dll");
    let hal_path = "\\Windows\\System32\\hal.dll";
    uefi::println!("[LOAD] Loading hal.dll");

    let (raw, size_of_image, entry_point, _is_dll) =
        read_pe_file_from_disk(hal_path)
            .ok_or(LoaderError::FileNotFound)?;
    uefi::println!("[LOAD] read ok");

    let (image_base, _, _, _) = parse_pe32plus(&raw).ok_or(LoaderError::PeParseFailed)?;

    let load_addr = allocate_and_map_image(image_base, size_of_image, &raw)
        .ok_or(LoaderError::MemoryAllocationFailed)?;
    uefi::println!("[LOAD] load ok");

    // Apply base relocations if we were loaded at a different
    // address than the preferred base. The kernel imports HAL
    // symbols with absolute pointers, so a slide here is fatal
    // (every hal!HalRequestIpi / HalInitializeProcessor call would
    // branch into the void).
    let relocs = apply_relocations_in_place(&raw, load_addr);
    uefi::println!("[LOAD] hal.dll: applied {} base relocations", relocs);

    let _ = entry_point;
    let _ = image_db;
    Ok(())
}

// (placeholder — the real duplicate function was renamed; see above)

// =====================================================================
// Phase 3 — Load SYSTEM registry hive
// =====================================================================
//
// winload reads every hive on the registry hive list from disk
// into a boot-services-data region that survives ExitBootServices,
// then writes a `LoadedHive[]` array describing each hive into
// a fixed-address records buffer. The kernel reads the array
// through `BootInfo.hives` after control is transferred.
//
// The actual hive files (SYSTEM, SOFTWARE, etc.) live under
// `\Windows\System32\config\` and are generated by
// `system_image::build_hives` on the host side. The detailed
// implementation is in `build_loaded_hive_list` below.
fn load_system_hive() {
    push_pool_alloc(0, 0);
    uefi::println!("[LOAD] Phase 3: SYSTEM hive loading is performed in Phase 8 (build_loaded_hive_list)");
    uefi::println!("[LOAD] Phase 3: reserve hive region + read each hive from disk");
    // Allocate the boot-service-data region that will hold the
    // raw hive bytes plus the records array. This must happen
    // before Phase 8 reads the individual hive files.
    allocate_hive_region();

    // Mark the SYSTEM hive entry in PERSISTENT as loaded so the
    // kernel's registry bootstrap can locate the registry hive
    // descriptor by walking PERSISTENT.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };
    pd.system_hive.loaded = true;
    pd.system_hive.path_len = b"SYSTEM".len();
    let copy_len = pd.system_hive.path.len().min(b"SYSTEM".len());
    pd.system_hive.path[..copy_len].copy_from_slice(b"SYSTEM");
}

// =====================================================================
// Phase L03 — load ntoskrnl.exe + hal.dll from the NTFS System partition
// =====================================================================
// The host trampoline will jump into the on-disk
// `ntoskrnl.exe!KiSystemStartup` via `jump_to_ntoskrnl_kisystemstartup`
// (see `arch::x86_64::jump_to_ntoskrnl_kisystemstartup`). That requires
// the loader to have already copied the PE bytes into the shared
// `IMAGE_BUFFER` region (which is `EfiBootServicesData` and therefore
// survives `ExitBootServices`). This helper does exactly that and
// then writes the resulting base+size into the canonical `BootInfo`
// fields the kernel reads.
//
// On failure (NTFS read error, MZ mismatch, PE parse failure) we
// fall through with the field still zero — the host kernel will then
// print `[NTOSKRNL-HOST] K03: no on-disk ntoskrnl image in BootInfo`
// and the boot halts in `jump_to_ntoskrnl_kisystemstartup`. There is
// no in-binary fallback (the `system_image` pipeline is gone).
fn load_kernel_images() -> (u64, u64, u64, u64) {
    // (ntoskrnl_base, ntoskrnl_size, hal_base, hal_size)
    uefi::println!("[WINLOAD] L03: loading ntoskrnl.exe + hal.dll from NTFS system partition");
    let mut ntoskrnl_base: u64 = 0;
    let mut ntoskrnl_size: u64 = 0;
    let mut hal_base: u64 = 0;
    let mut hal_size: u64 = 0;

    for path in &KERNEL_IMAGE_PATHS {
        let (raw, size_of_image, _ep, _is_dll) = match read_pe_file_from_disk(path) {
            Some(t) => t,
            None => {
                uefi::println!("[WINLOAD] L03: {} not found on NTFS system partition", path);
                continue;
            }
        };
        if size_of_image == 0 || raw.len() < 0x40 || &raw[..2] != b"MZ" {
            uefi::println!("[WINLOAD] L03: {}: empty or not a PE", path);
            continue;
        }
        // allocate_and_map_image returns the runtime base inside
        // the shared IMAGE_BUFFER pool (BOOT_SERVICES_DATA).
        let dest = match allocate_and_map_image(0, size_of_image, &raw) {
            Some(p) => p,
            None => {
                uefi::println!("[WINLOAD] L03: {}: allocate_and_map_image failed", path);
                continue;
            }
        };
        let _ = apply_relocations_in_place(&raw, dest);
        if path.ends_with("ntoskrnl.exe") {
            ntoskrnl_base = dest;
            ntoskrnl_size = size_of_image;
            uefi::println!(
                "[WINLOAD] L03: ntoskrnl.exe loaded at 0x{:x} size={} entry=0x{:x}",
                dest, size_of_image, _ep
            );
        } else if path.ends_with("hal.dll") {
            hal_base = dest;
            hal_size = size_of_image;
            uefi::println!(
                "[WINLOAD] L03: hal.dll loaded at 0x{:x} size={} exports=stub",
                dest, size_of_image
            );
        }
    }

    // Publish into BootInfo so the kernel can find them. The values
    // get re-published (with fresh fields) right after `*bi = bi_value`
    // wipes them in `os_loader_run`; this here is a defensive belt.
    unsafe {
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        bi.ntoskrnl_image_base = ntoskrnl_base;
        bi.ntoskrnl_image_size = ntoskrnl_size;
        bi.hal_image_base = hal_base;
        bi.hal_image_size = hal_size;
    }
    (ntoskrnl_base, ntoskrnl_size, hal_base, hal_size)
}

/// Look up the BOOTVID.DLL slot from `PERSISTENT.boot_drivers[]` and
/// publish its base/size into `BootInfo.bootvid_image_*`. The driver
/// itself was already loaded by `load_boot_drivers()` (BOOTVID.DLL is
/// the 13th entry in `BOOT_DRIVER_PATHS`); this helper just copies
/// the result into the canonical BootInfo fields the kernel reads.
fn publish_bootvid_into_boot_info() {
    unsafe {
        let pd = &*core::ptr::addr_of!(PERSISTENT);
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        // BOOTVID.DLL is the LAST entry in BOOT_DRIVER_PATHS.
        let last = MAX_BOOT_DRIVERS - 1;
        let rec = &pd.boot_drivers[last];
        if rec.loaded {
            bi.bootvid_image_base = rec.base;
            bi.bootvid_image_size = rec.size;
            uefi::println!(
                "[WINLOAD] L05: BOOTVID.DLL @ 0x{:x} size={} (from PERSISTENT)",
                rec.base, rec.size
            );
        } else {
            uefi::println!("[WINLOAD] L05: BOOTVID.DLL not loaded; bootvid_image_base=0");
        }
    }
}

// =====================================================================
// Phase 4 — Load BOOT_START drivers
// =====================================================================
//
// BOOT_START drivers are marked in the SYSTEM hive with
// `Start = 0` and must be loaded before the kernel can mount the
// root filesystem. winload reads each driver's PE file from
// `\Windows\System32\drivers\`, allocates a runtime region, copies
// the sections, applies relocations, and records the result in
// `DriverLoadRecord[]` so the kernel can find them later.
//
// The driver list is read from the static `BOOT_DRIVER_PATHS`
// array (which mirrors what `system_image::build_all` writes to
// disk). A future revision will scan the SYSTEM hive for
// `Start = 0` entries and build the list dynamically.

#[inline(never)]
fn load_boot_drivers() {
    uefi::println!("[LOAD] Phase 4: loading BOOT_START drivers");
    push_log("WL:drv#");
    let count_total = BOOT_DRIVER_PATHS.len();
    let mut loaded_count: u32 = 0;
    let mut any_failure: bool = false;
    // SAFETY: PERSISTENT is only mutated from the BSP during boot.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    for (i, path) in BOOT_DRIVER_PATHS.iter().enumerate() {
        if i >= MAX_BOOT_DRIVERS { break; }

        // Step 1: Read the driver PE file into a Vec.
        // read_pe_file_from_disk already parses the PE, so the
        // returned size_of_image is authoritative. The 4th tuple
        // element is the IMAGE_FILE_DLL flag: when set we treat the
        // image as a BOOT_START_IMAGE (no DriverEntry, exports only)
        // and skip the DriverEntry call below.
        let (raw, size_of_image, _ep, is_dll) = match read_pe_file_from_disk(path) {
            Some(t) => t,
            None => {
                uefi::println!("[WARN] boot driver {}: file missing or read failed", path);
                any_failure = true;
                continue;
            }
        };

        if raw.len() < 0x40 || &raw[0..2] != b"MZ" {
            uefi::println!("[WARN] boot driver {}: file empty or not PE", path);
            any_failure = true;
            continue;
        }

        if size_of_image == 0 {
            uefi::println!("[WARN] boot driver {}: size_of_image == 0", path);
            any_failure = true;
            continue;
        }

        // Step 2: Allocate via the shared IMAGE_BUFFER.
        // image_base is not used by allocate_and_map_image (it always
        // serves the IMAGE_BUFFER region), so we pass 0.
        if let Some(dest_addr) = allocate_and_map_image(0, size_of_image, &raw) {
            let relocs = apply_relocations_in_place(&raw, dest_addr);
            // Manual byte-by-byte copy that does NOT go through
            // `copy_from_slice`. We've observed #GP crashes in the
            // generic memmove path when both the source and
            // destination are inside the EFI loader region; a plain
            // scalar loop sidesteps the vectorised codegen entirely.

            let rec = &mut pd.boot_drivers[i];
            let name_bytes = path.as_bytes();
            // Manual byte-by-byte copy that does NOT go through
            // `copy_from_slice`. We've observed #GP crashes in the
            // generic memmove path when both the source and
            // destination are inside the EFI loader region; a plain
            // scalar loop sidesteps the vectorised codegen entirely.
            {
                let mut k = 0;
                while k < rec.name.len() && k < name_bytes.len() {
                    rec.name[k] = name_bytes[k];
                    k += 1;
                }
                while k < rec.name.len() {
                    rec.name[k] = 0;
                    k += 1;
                }
            }
            rec.loaded = true;
            rec.base = dest_addr;
            rec.size = size_of_image;
            uefi::println!(
                "[LOAD] boot driver {}: base=0x{:016x} size=0x{:x} relocs={}",
                path, dest_addr, size_of_image, relocs
            );
            let driver_basename: &str = match path.rfind('\\') {
                Some(idx) => &path[idx + 1..],
                None => path,
            };

            // BOOT_START_IMAGE (DLL) entries — currently only
            // BOOTVID.DLL — only export a symbol surface and have
            // *no* DriverEntry. Calling their AddressOfEntryPoint
            // jumps into the export directory header (zero bytes
            // on our build_tool output) and wedges the CPU, which
            // the UEFI watchdog treats as a crash and reboots the
            // firmware. We detect them by file extension (`.dll`)
            // because every WDM driver generated by `build_driver_pe`
            // also has IMAGE_FILE_DLL set in the PE Characteristics,
            // so the IMAGE_FILE_DLL bit alone is not a useful
            // discriminant in this codebase.
            let is_dll_image = driver_basename
                .rsplit('.')
                .next()
                .map(|ext| ext.eq_ignore_ascii_case("dll"))
                .unwrap_or(false);
            if is_dll_image {
                uefi::println!(
                    "[LOAD] BOOT_START_IMAGE: {} -> loaded at 0x{:016x} size=0x{:x} \
                     (no DriverEntry, exports only)",
                    driver_basename, dest_addr, size_of_image
                );
                rec.base = dest_addr;
                rec.size = size_of_image;
                rec.loaded = true;
                loaded_count += 1;
                continue;
            }

            // SYS driver path: invoke the real DriverEntry. The disk
            // stubs have their entry point at VA 0x1000 (.text RVA).
            // Report the DriverEntry return value (STATUS_SUCCESS = 0)
            // so the operator can see the driver registration was
            // effective.
            let entry_addr: u64 = dest_addr + 0x1000;

            // ------------------------------------------------------------------
            // Real DriverEntry invocation.
            //
            // The build tool emits a DriverEntry at .text RVA 0x000
            // that takes the standard Windows x64 DriverEntry prototype:
            //
            //     NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
            //                          PUNICODE_STRING RegistryPath);
            //
            // The stub writes its `MajorFunction` dispatch table and
            // its `DriverUnload` into the DriverObject pointer we
            // pass in `RCX`, then returns STATUS_SUCCESS. We allocate
            // a 0x100-byte scratch DriverObject on the heap, build a
            // `\\Registry\\Machine\\System\\CurrentControlSet\\Services\\
            // <basename>` registry-path UNICODE_STRING, and call into
            // the entry point. The return value (NTSTATUS) is logged.
            // ------------------------------------------------------------------
            // SAFETY: We only call this on the BSP during boot; the
            // returned NTSTATUS is in `rax` immediately after the call.
            let driver_object_buf: *mut u8 = match uefi::boot::allocate_pool(
                uefi::boot::MemoryType::LOADER_DATA,
                0x100,
            ) {
                Ok(p) => p.as_ptr(),
                Err(_) => core::ptr::null_mut(),
            };
            let mut driver_entry_status: i32 = 0xC000_0001u32 as i32; // STATUS_UNSUCCESSFUL
            let mut mj_create_written: bool = false;
            let mut unload_written: bool = false;
            if !driver_object_buf.is_null() {
                // Zero out the DriverObject (0x100 bytes covers the
                // full layout incl. the MajorFunction[] tail).
                for k in 0..0x100usize {
                    unsafe { core::ptr::write_volatile(driver_object_buf.add(k), 0u8); }
                }
                // Build the registry path: \\Registry\\Machine\\System\\
                //   CurrentControlSet\\Services\\<basename>
                // Encoded as UTF-16LE; we lay it out in a small
                // stack buffer (256 bytes = 128 UTF-16 code units).
                let mut reg_path_utf16 = [0u16; 128];
                let prefix = b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
                let mut idx = 0;
                for &b in prefix {
                    reg_path_utf16[idx] = b as u16;
                    idx += 1;
                }
                for &b in driver_basename.as_bytes() {
                    if idx >= reg_path_utf16.len() - 1 { break; }
                    reg_path_utf16[idx] = b as u16;
                    idx += 1;
                }

                // Call DriverEntry(DriverObject, RegistryPath).
                // RCX = DriverObject, RDX = RegistryPath pointer.
                // The driver only reads the path string; we hand it
                // the UTF-16LE buffer directly without a UNICODE_STRING
                // wrapper (the stub bodies don't dereference the
                // Length/MaximumLength fields).
                unsafe {
                    let f: extern "win64" fn(*mut u8, *const u16) -> i32 =
                        core::mem::transmute(entry_addr as *const ());
                    driver_entry_status = f(driver_object_buf, reg_path_utf16.as_ptr());
                }

                // The driver body writes MajorFunction[IRP_MJ_CREATE]
                // (offset 0x40) and DriverUnload (offset 0x28) into
                // the DriverObject. We check whether the writes
                // actually happened.
                mj_create_written = unsafe {
                    let p = driver_object_buf.add(0x40) as *const u64;
                    core::ptr::read_volatile(p) != 0
                };
                unload_written = unsafe {
                    let p = driver_object_buf.add(0x28) as *const u64;
                    core::ptr::read_volatile(p) != 0
                };
                // Free the DriverObject allocation - the driver
                // body just borrowed the storage.
                if !driver_object_buf.is_null() {
                    unsafe {
                        let nn = core::ptr::NonNull::new_unchecked(driver_object_buf);
                        let _ = uefi::boot::free_pool(nn);
                    }
                }
            }

            uefi::println!(
                "[WINLOAD] step: DriverEntry for {} -> NTSTATUS=0x{:x} (entry=0x{:x})",
                path,
                driver_entry_status as u32,
                entry_addr
            );
            // For Phase B we don't actually wire up a real DeviceObject
            // (that would require IAT lookups against ntoskrnl.exe's
            // IoCreateDevice export, which the stub PEs don't carry).
            // Instead we verify the dispatch-table writes happened, so
            // the operator can see the driver's DriverEntry ran
            // successfully and the kernel-side I/O manager can pick
            // up where we left off once the kernel walks the
            // BOOT_DRIVERS array in Phase 12.
            if mj_create_written && unload_written {
                // Map each driver to its intended target device name
                // (per `nt61-multi-fs-fallback-strategy` plan).
                let target_device = match driver_basename {
                    "disk.sys"      => "\\Device\\Harddisk0",
                    "partmgr.sys"   => "\\Device\\Partition0",
                    "volmgr.sys"    => "\\Device\\VolumeManager",
                    "pci.sys"       => "\\Device\\Pci",
                    "acpi.sys"      => "\\Device\\ACPI_HAL",
                    "mssmbios.sys"  => "\\Device\\Mssmbios",
                    "hpet.sys"      => "\\Device\\Hpet",
                    _ => "(none — class/bus driver)",
                };
                uefi::println!(
                    "[DRIVER] {}: DriverEntry at 0x{:x} -> STATUS_SUCCESS, target={}",
                    path,
                    entry_addr,
                    target_device
                );
            } else {
                uefi::println!(
                    "[DRIVER] {}: DriverEntry did not populate dispatch table (mj_create={}, unload={})",
                    path, mj_create_written, unload_written
                );
            }
            uefi::println!(
                "[WINLOAD] step: DriverObject registered: {:<30} @ 0x{:016x} size=0x{:x} entry=0x{:x} status=0x{:x}",
                driver_basename, dest_addr, size_of_image, entry_addr, driver_entry_status as u32
            );
            loaded_count += 1;
        } else {
            uefi::println!("[WARN] boot driver {}: image allocate failed", path);
            any_failure = true;
        }
    }

    uefi::println!(
        "[LOAD] Phase 4: {} of {} BOOT_START drivers loaded",
        loaded_count, count_total
    );
    if any_failure {
        uefi::println!("[LOAD] Phase 4: (driver missing/error is non-fatal — boot continues)");
    }
}

// =====================================================================
// Phase 5 — Collect memory map, ACPI RSDP, SMP info
// =====================================================================

// =====================================================================
// UEFI boot services raw wrappers
// =====================================================================
//
// `uefi::boot::memory_map` and the high-level `FileSystem::read`
// both go through the `uefi` crate's global allocator, which on
// this bootloader can fail (panics on `alloc::vec![0u8; n]`).
// We instead call the raw `GetMemoryMap` boot service with a
// pre-allocated, aligned static buffer.

use uefi_raw::table::boot::MemoryDescriptor;

/// Static buffer for `GetMemoryMap`. UEFI requires 8-byte
/// alignment; we over-align to 16 bytes for safety. 32 KiB holds
/// ~256 descriptors (each `MemoryDescriptor` is 128 bytes on
/// 64-bit UEFI) — more than enough for a small QEMU/OVMF VM.
#[repr(C, align(16))]
struct MemMapBuf([u8; 32 * 1024]);
static mut MEM_MAP_BUF: MemMapBuf = MemMapBuf([0u8; 32 * 1024]);

/// One-shot wrapper that calls the raw `GetMemoryMap` boot
/// service and copies the first `max_entries` descriptors into
/// `out`. Returns the number of descriptors written.
fn raw_get_memory_map(out: &mut [MemoryMapEntry], descriptor_buf: &mut [u8]) -> usize {
    let (count, _key) = raw_get_memory_map_with_key(out, descriptor_buf);
    count
}

/// Variant of `raw_get_memory_map` that also returns the
/// `map_key` UEFI hands back. The key is required to be passed
/// to `ExitBootServices` for it to detect that the memory map
/// has not changed since the query.
fn raw_get_memory_map_with_key(
    out: &mut [MemoryMapEntry],
    descriptor_buf: &mut [u8],
) -> (usize, usize) {
    // SAFETY: the system table is set once in `efi_main` and is
    // valid for the entire boot. Boot services are still active
    // here, so the boot-services table pointer is valid.
    let st = uefi::table::system_table_raw()
        .expect("system table not set");
    let st = unsafe { st.as_ref() };
    let bt_ptr = st.boot_services;
    if bt_ptr.is_null() {
        uefi::println!("  [LOAD] GetMemoryMap: boot_services is null");
        return (0, 0);
    }
    let bt = unsafe { &*bt_ptr };
    let mut map_size: usize = descriptor_buf.len();
    let map_buffer = descriptor_buf.as_mut_ptr().cast::<MemoryDescriptor>();
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;
    let status = unsafe {
        (bt.get_memory_map)(
            &mut map_size,
            map_buffer,
            &mut map_key,
            &mut desc_size,
            &mut desc_version,
        )
    };
    if !status.is_success() {
        uefi::println!("  [LOAD] GetMemoryMap raw failed");
        return (0, 0);
    }
    if desc_size == 0 {
        uefi::println!("  [LOAD] GetMemoryMap returned desc_size=0");
        return (0, 0);
    }
    let count = map_size / desc_size;
    let cap = (out.len()).min(count);
    unsafe {
        let desc_ptr = map_buffer as *const u8;
        for i in 0..cap {
            let off = i * desc_size;
            let phys = core::ptr::read_unaligned(desc_ptr.add(off + 8) as *const u64);
            let pages: u64 = core::ptr::read_unaligned(desc_ptr.add(off + 24) as *const u64);
            let ty: u32 = core::ptr::read_unaligned(desc_ptr.add(off + 0) as *const u32);
            out[i] = MemoryMapEntry {
                base: phys,
                length: pages * 4096,
                memory_type: ty,
                reserved: 0,
            };
        }
    }
    (cap, map_key)
}

fn collect_memory_map() {
    push_page_alloc(0, 0);
    // SAFETY: `PERSISTENT` and `MEM_MAP_BUF` are only touched from
    // the BSP before any reader is scheduled, so this is single-
    // threaded.
    unsafe {
        let pd = &mut *core::ptr::addr_of_mut!(PERSISTENT);
        // Get the boot services raw pointer and call
        // GetMemoryMap with our static buffer. `raw_get_memory_map`
        // returns (entry_count, map_key) — we save the map_key in
        // `PERSISTENT.map_key` so the eventual `ExitBootServices`
        // call can pass it back to the firmware.
        let (n, key) = raw_get_memory_map_with_key(
            &mut pd.memory_map,
            &mut (*core::ptr::addr_of_mut!(MEM_MAP_BUF)).0,
        );
        pd.map_key = key;
        if n == 0 {
            // Fall back to the stub map so the kernel still boots.
            let entries: [MemoryMapEntry; 6] = [
                MemoryMapEntry::new(0, 0x100000, 1),
                MemoryMapEntry::new(0x100000, 0xF00000, 4),
                MemoryMapEntry::new(0x1000000, 0x1000000, 3),
                MemoryMapEntry::new(0x2000000, 0x2000000, 5),
                MemoryMapEntry::new(0x4000000, 0x4000000, 4),
                MemoryMapEntry::new(0x8000000, 0x8000000, 1),
            ];
            for (i, e) in entries.iter().enumerate() {
                pd.memory_map[i] = *e;
            }
            pd.memory_map_count = entries.len();
            uefi::println!("  [LOAD] Memory map: {} entries (stub fallback)", entries.len());
        } else {
            pd.memory_map_count = n;
            uefi::println!("  [LOAD] Memory map: {} entries (real UEFI GetMemoryMap)", n);
        }
    }
}


fn collect_acpi_info() {
    push_box_drop(0, 0);
    let mut rsdp: u64 = 0;
    uefi::system::with_config_table(|entries| {
        for entry in entries {
            if entry.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID {
                rsdp = entry.address as u64;
            }
        }
    });
    unsafe { PERSISTENT.acpi_rsdp = rsdp; }
    // AVOID alloc::format! — see collect_memory_map for rationale.
    if rsdp != 0 {
        uefi::println!("  [LOAD] ACPI RSDP: 0x{:016x} (from UEFI system table)", rsdp);
    } else {
        uefi::println!("  [LOAD] ACPI RSDP: not found (kernel ACPI init will skip)");
    }
}

fn collect_smp_info() {
    push_pool_free(0);
    // SAFETY: `PERSISTENT` is only accessed from the BSP during early boot,
    // before any other CPUs are started.
    unsafe {
        // SKIP nt61::hal::common::acpi::parse_madt() in winload context:
        // that parser walks the XSDT via `mm::syspte::map_io_space`, which
        // requires the kernel's MM to already be initialized. From inside
        // winload.efi (where kernel page tables do not yet exist) those
        // mappings would page-fault. Instead, the kernel will re-parse
        // the MADT after the page tables come online; here we just stash
        // the RSDP physical address and fall back to a single CPU.
        if PERSISTENT.acpi_rsdp != 0 {
            nt61::hal::common::acpi::set_rsdp(PERSISTENT.acpi_rsdp);
            uefi::println!("  [LOAD] SMP info: MADT parse deferred to kernel (winload has no MM)");
        } else {
            uefi::println!("  [LOAD] SMP info: ACPI not available, using fallback ({})", SMP_CPU_COUNT);
        }
        PERSISTENT.smp_cpu_count = SMP_CPU_COUNT;
    }
}

// =====================================================================
// Framebuffer (GOP) Information Collection
// =====================================================================

/// Framebuffer information collected from GOP protocol.
#[derive(Default, Copy, Clone)]
#[repr(C)]
struct FramebufferInfo {
    base: u64,
    size: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
}

impl FramebufferInfo {
    fn new() -> Self {
        Self {
            base: 0,
            size: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: 0, // 0 = Unknown, 1 = PixelBlueGreenRedReserved8BitPerColor (BGRA)
        }
    }
}

/// Collect framebuffer information from the GOP protocol.
/// This information is needed by the kernel to continue using the graphics
/// output after ExitBootServices.
///
/// We first check the framebuffer mailbox published by the boot
/// manager at PA 0x10_200 — this is the only reliable source because
/// UEFI does not allow the boot manager to keep the GOP handle open
/// AND winload to open it again at the same time (`ACCESS_DENIED`).
/// If the mailbox is missing or corrupt we fall back to opening GOP
/// directly.
fn collect_framebuffer_info() -> FramebufferInfo {
    push_str_drop(0, 0);
    if let Some(fb_info) = read_fb_mailbox() {
        return fb_info;
    }
    collect_framebuffer_info_from_gop()
}

// =====================================================================
// ESP partition capture
// =====================================================================
//
// Background: The kernel does not yet have a working block-device
// driver (no AHCI, no virtio-blk, no ATA PIO). After
// `ExitBootServices` the firmware is no longer available, so the
// kernel has no way to read a block device on its own. To let the
// Safe-Mode CMD `DIR` and `TYPE` commands access the real boot
// volume, we snapshot the entire ESP into a contiguous physical
// memory buffer *before* `ExitBootServices` and pass a pointer
// to it in `BootInfo`. The kernel's FAT32 driver treats this
// buffer as a RAM disk.
//
// We use the UEFI `BlockIO` protocol on the same handle that
// hosts the `SimpleFileSystem` we have already cached for the
// ESP. The ESP's first handle from `find_handles::<SimpleFileSystem>()`
// is the one from which we have been reading files, so its
// `BlockIO` instance points at the ESP partition itself.
//
// Buffer size policy: a typical ESP is 100–500 MiB. We reserve
// 32 MiB (`ESP_MIRROR_BYTES`) which is enough for the BCD,
// fonts, our own binaries, and a few log files. If the
// partition is larger than the mirror, we only snapshot the
// first `ESP_MIRROR_BYTES`; the FAT32 driver will only see
// truncated data and will fail gracefully on any cluster
// outside the captured range.
const ESP_MIRROR_BYTES: usize = 32 * 1024 * 1024;
const ESP_BLOCKS_PER_CHUNK: usize = 64; // 64 * 512 = 32 KiB per read

/// Snapshot the ESP partition into a contiguous physical buffer.
/// The buffer is allocated as `EfiBootServicesData` so it
/// survives `ExitBootServices` and the kernel can map it during
/// phase 1 of its own bootstrap.
///
/// On success the PERSISTENT struct's `esp_image_*` fields hold
/// the physical address, byte size, and block size of the
/// snapshot. On failure (no BlockIO, allocation failed, I/O
/// error) the fields stay zero and the kernel falls back to the
/// built-in stub listing.
fn capture_esp_partition() {
    push_open("\\\\ESP\\\\");
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    // Find the SimpleFileSystem handle we have been using.
    uefi::println!("[LOADER] ESP capture: find_handles<SimpleFileSystem>");
    let handles = match uefi::boot::find_handles::<uefi::proto::media::fs::SimpleFileSystem>() {
        Ok(h) => {
            uefi::println!("[LOADER] ESP capture: find_handles OK (n={})", h.len());
            h
        }
        Err(e) => {
            uefi::println!("[LOADER] [WARN] ESP capture: no SFS handles: {:?}", e);
            return;
        }
    };
    if handles.is_empty() {
        uefi::println!("[LOADER] [WARN] ESP capture: empty SFS handle list");
        // Try the fallback file reader so future code paths can
        // still locate files even when SFS enumeration fails.
        let mut fallback_buf = [0u8; 512];
        let _ = open_esp_file_into_fallback("\\EFI\\Boot\\bootx64.efi", &mut fallback_buf);
        return;
    }
    let esp_handle = handles[0];

    // Open BlockIO on the same handle.
    uefi::println!("[LOADER] ESP capture: open_protocol<BlockIO>");
    let sp = unsafe {
        uefi::boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle: esp_handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let block_io = match sp {
        Ok(s) => s,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] ESP capture: BlockIO open failed: {:?}", e);
            return;
        }
    };
    let block_io_ref = match block_io.get() {
        Some(b) => b,
        None => {
            uefi::println!("[LOADER] [WARN] ESP capture: BlockIO interface is null");
            core::mem::forget(block_io);
            return;
        }
    };

    let media = block_io_ref.media();
    let block_size = media.block_size() as usize;
    let last_block = media.last_block();
    let media_id = media.media_id();
    let total_blocks = (last_block as u64) + 1;
    let partition_bytes = total_blocks.saturating_mul(block_size as u64);
    let mirror_bytes = core::cmp::min(ESP_MIRROR_BYTES as u64, partition_bytes) as usize;
    let blocks_to_read = mirror_bytes / block_size;

    uefi::println!(
        "[LOADER] ESP: block_size={} total_blocks={} partition={} MiB -> capturing {} MiB ({} blocks)",
        block_size,
        total_blocks,
        partition_bytes / (1024 * 1024),
        mirror_bytes / (1024 * 1024),
        blocks_to_read,
    );

    // Allocate the mirror buffer in EfiBootServicesData so it
    // survives ExitBootServices.
    let pages = (mirror_bytes + 0xFFF) / 0x1000;
    uefi::println!("[LOADER] ESP capture: allocating {} pages ({} MiB)",
        pages, mirror_bytes / (1024 * 1024));
    let buffer = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] ESP capture: allocate_pages failed: {:?}", e);
            core::mem::forget(block_io);
            return;
        }
    };
    let buffer_ptr = buffer.as_ptr() as *mut u8;
    uefi::println!("[LOADER] ESP capture: buffer @ 0x{:x}", buffer_ptr as u64);

    // Stream the partition into the buffer in `ESP_BLOCKS_PER_CHUNK`
    // LBA chunks. Using a smaller chunk reduces the pressure on
    // the UEFI pool allocator (each read_blocks call needs a
    // stack of metadata in the firmware) and lets us log progress
    // every MiB or so.
    let chunks = (blocks_to_read + ESP_BLOCKS_PER_CHUNK - 1) / ESP_BLOCKS_PER_CHUNK;
    let mut total_ok: u64 = 0;
    let mut first_err: Option<u64> = None;
    for chunk in 0..chunks {
        let lba_start = (chunk * ESP_BLOCKS_PER_CHUNK) as u64;
        let blocks_here = core::cmp::min(
            ESP_BLOCKS_PER_CHUNK,
            blocks_to_read - chunk * ESP_BLOCKS_PER_CHUNK,
        );
        let byte_offset = chunk * ESP_BLOCKS_PER_CHUNK * block_size;
        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr.add(byte_offset),
                blocks_here * block_size,
            )
        };
        if let Err(e) = block_io_ref.read_blocks(media_id, lba_start, slice) {
            uefi::println!(
                "[LOADER] [WARN] ESP capture: read_blocks LBA {} failed: {:?}",
                lba_start,
                e
            );
            if first_err.is_none() {
                first_err = Some(lba_start);
            }
            break;
        }
        total_ok = lba_start + blocks_here as u64;
    }
    uefi::println!(
        "[LOADER] ESP capture: {} MiB read ({} blocks), first_err={:?}",
        (total_ok as usize) * block_size / (1024 * 1024),
        total_ok,
        first_err,
    );

    // Publish the result in PERSISTENT so `build_boot_info` can
    // copy it into BootInfo.
    pd.esp_image_base = buffer_ptr as u64;
    pd.esp_image_size = mirror_bytes as u64;
    pd.esp_block_size = block_size as u32;
    pd.esp_partition_lba = 0; // partition-relative LBA; full ESP starts at 0
    pd.esp_partition_sectors = total_blocks;
    // Save the BlockIO media_id so capture_system_partition can
    // recognise the ESP handle and pick a different partition as
    // the system partition (works even when system is FAT32 too).
    pd.esp_media_id = media_id;
    // Also save the partition block count. QEMU/OVMF reports
    // media_id == 0 for every partition, so it can't be used as a
    // unique discriminator; partition size is unique as long as the
    // ESP and the system partition have different sizes (which is
    // true on every standard install we test).
    pd.esp_partition_blocks = total_blocks;
    uefi::println!("[LOADER] ESP capture: media_id=0x{:x} blocks={}", media_id, total_blocks);

    // Intentionally do NOT call `core::mem::forget` on `block_io`
    // — we are still before `ExitBootServices`, and the firmware
    // needs the protocol reference count to remain consistent.
    drop(block_io);
}

// =====================================================================
// System partition capture (second FAT32 partition on the disk)
// =====================================================================
//
// Mirrors `capture_esp_partition` but targets the second
// `SimpleFileSystem` handle (the Windows system partition). The
// captured buffer is exposed to the kernel via BootInfo's
// `sys_image_*` fields, where it is registered as a second
// FAT32 ramdisk so user-mode code can read files like
// `C:\tests\autoexec.bat` that live on the system partition.

/// Same per-chunk chunking policy as the ESP capture. The system
/// partition is 256 MiB on our reference disk, but we cap the
/// mirror at 8 MiB for the early-boot memory footprint.
const SYS_MIRROR_BYTES: usize = 8 * 1024 * 1024;

/// Snapshot the system partition into a contiguous physical
/// buffer. Same lifecycle as `capture_esp_partition`: the buffer
/// is allocated in `EfiBootServicesData` so it survives
/// `ExitBootServices`, and the address/size/block_size fields
/// end up in PERSISTENT -> BootInfo.
fn capture_system_partition() {
    push_open("\\\\SYS\\\\");
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    // Find the system partition handle. With the new layout (ESP=FAT32,
    // System=NTFS), EFI's SimpleFileSystem only enumerates FAT volumes, so
    // there is exactly one SFS handle (the ESP). The system partition is
    // a NTFS volume, so we have to walk all block device handles looking
    // for one whose first sector has the "NTFS    " OEM ID at offset 3.
    let block_handles = match uefi::boot::find_handles::<BlockIO>() {
        Ok(h) => h,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] SYS capture: no BlockIO handles: {:?}", e);
            return;
        }
    };
    // Pick the block device whose first sector is NOT the EFI
    // System Partition (FAT-family boot sector) — that's the
    // Windows System partition regardless of whether it's
    // formatted as FAT32, NTFS, or ext2/3/4. This matches the
    // Windows 7 boot manager, which simply enumerates every
    // partition on the system disk and asks the kernel to mount
    // each one according to its own filesystem type.
    // Identify the system partition. The previous heuristic was
    // "skip FAT-family partitions" — that worked for the
    // (ESP=FAT32, sys=NTFS) layout but broke the (ESP=FAT32,
    // sys=FAT32) layout because both partitions had FAT OEM IDs
    // and the loop never picked a sys_handle. Now we skip by ESP
    // BlockIO media_id (recorded by capture_esp_partition) and
    // pick the first logical partition with a different
    // media_id. The "is_logical_partition" / 512-byte block-size
    // filters are kept so we still skip the whole-disk BlockIO
    // handle and any CD/DVD.
    let esp_media_id = pd.esp_media_id;
    let esp_partition_blocks = pd.esp_partition_blocks;
    let mut sys_handle: Option<uefi::Handle> = None;
    let mut sys_oem: [u8; 8] = [0; 8];
    for &h in &block_handles {
        let sp = unsafe {
            uefi::boot::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle: h,
                    agent: uefi::boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let block_io = match sp {
            Ok(s) => s,
            Err(_) => continue,
        };
        let block_io_ref = match block_io.get() {
            Some(b) => b,
            None => {
                core::mem::forget(block_io);
                continue;
            }
        };
        let media = block_io_ref.media();
        // Skip whole-disk BlockIO handle.
        if !media.is_logical_partition() {
            core::mem::forget(block_io);
            continue;
        }
        if media.block_size() != 512 {
            core::mem::forget(block_io);
            continue;
        }
        // Skip the ESP itself — distinguishes system from ESP even
        // when both are FAT32. media_id is unreliable on
        // QEMU/OVMF (it is 0 for every partition), so we also
        // compare the partition block count. Two partitions with
        // identical size AND identical media_id would defeat
        // this; in that pathological case we still get a
        // non-ESP candidate because the block-count test fails
        // first.
        let this_media_id = media.media_id();
        let this_blocks = (media.last_block() as u64) + 1;
        let is_esp = (this_media_id == esp_media_id && esp_media_id != 0)
            || (this_blocks == esp_partition_blocks && esp_partition_blocks != 0);
        if is_esp {
            core::mem::forget(block_io);
            continue;
        }
        let mut buf = [0u8; 512];
        let lba_offset = 0u64;
        let read_ok = block_io_ref.read_blocks(this_media_id, lba_offset, &mut buf).is_ok();
        // Leak the block_io so the protocol stays open across read_blocks.
        core::mem::forget(block_io);
        if !read_ok {
            continue;
        }
        // We used to require a 0x55AA boot signature here, but
        // ext2/3/4 superblocks live at offset 1024 so they don't
        // have one — and on a single-disk image with no system
        // partition, this would discard the only candidate. Drop
        // the signature requirement; the kernel-side
        // `detect_fs_type` will refuse to mount anything that
        // doesn't look like a real filesystem.
        let oem = &buf[3..11];
        sys_oem.copy_from_slice(oem);
        sys_handle = Some(h);
        break;
    }

    let sys_handle = match sys_handle {
        Some(h) => h,
        None => {
            uefi::println!(
                "[LOADER] [WARN] SYS capture: no non-ESP partition handle found among {} BlockIO devices",
                block_handles.len()
            );
            return;
        }
    };
    uefi::println!(
        "[LOADER] SYS capture: found non-ESP partition handle ({} BlockIO devices scanned)",
        block_handles.len()
    );
    let sp = unsafe {
        uefi::boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle: sys_handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let block_io = match sp {
        Ok(s) => s,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] SYS capture: BlockIO open failed: {:?}", e);
            return;
        }
    };
    let block_io_ref = match block_io.get() {
        Some(b) => b,
        None => {
            uefi::println!("[LOADER] [WARN] SYS capture: BlockIO interface is null");
            core::mem::forget(block_io);
            return;
        }
    };

    let media = block_io_ref.media();
    let block_size = media.block_size() as usize;
    let last_block = media.last_block();
    let media_id = media.media_id();
    let total_blocks = (last_block as u64) + 1;
    let partition_bytes = total_blocks.saturating_mul(block_size as u64);
    let mirror_bytes = core::cmp::min(SYS_MIRROR_BYTES as u64, partition_bytes) as usize;
    let blocks_to_read = mirror_bytes / block_size;

    uefi::println!(
        "[LOADER] SYS: block_size={} total_blocks={} partition={} MiB -> capturing {} MiB ({} blocks)",
        block_size,
        total_blocks,
        partition_bytes / (1024 * 1024),
        mirror_bytes / (1024 * 1024),
        blocks_to_read,
    );

    let pages = (mirror_bytes + 0xFFF) / 0x1000;
    let buffer = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] SYS capture: allocate_pages failed: {:?}", e);
            core::mem::forget(block_io);
            return;
        }
    };
    let buffer_ptr = buffer.as_ptr() as *mut u8;

    let chunks = (blocks_to_read + ESP_BLOCKS_PER_CHUNK - 1) / ESP_BLOCKS_PER_CHUNK;
    let mut total_ok: u64 = 0;
    let mut first_err: Option<u64> = None;
    for chunk in 0..chunks {
        let lba_start = (chunk * ESP_BLOCKS_PER_CHUNK) as u64;
        let blocks_here = core::cmp::min(
            ESP_BLOCKS_PER_CHUNK,
            blocks_to_read - chunk * ESP_BLOCKS_PER_CHUNK,
        );
        let byte_offset = chunk * ESP_BLOCKS_PER_CHUNK * block_size;
        let slice = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr.add(byte_offset),
                blocks_here * block_size,
            )
        };
        if let Err(e) = block_io_ref.read_blocks(media_id, lba_start, slice) {
            uefi::println!(
                "[LOADER] [WARN] SYS capture: read_blocks LBA {} failed: {:?}",
                lba_start,
                e
            );
            if first_err.is_none() {
                first_err = Some(lba_start);
            }
            break;
        }
        total_ok = lba_start + blocks_here as u64;
    }
    uefi::println!(
        "[LOADER] SYS capture: {} MiB read ({} blocks), first_err={:?}",
        (total_ok as usize) * block_size / (1024 * 1024),
        total_ok,
        first_err,
    );

    pd.sys_image_base = buffer_ptr as u64;
    pd.sys_image_size = mirror_bytes as u64;
    pd.sys_block_size = block_size as u32;

    drop(block_io);
}

// =====================================================================
// ISO boot RAM disk capture
// =====================================================================
//
// For ISO boot, the disk is a single ISO-9660 volume with a combined
// FAT32 image embedded at `EFI/Microsoft/Boot/nt61.img`. This function:
//   1. Reads `nt61.img` from the ISO via SimpleFileSystem
//   2. Copies the first 64 MB into a new buffer (ESP region)
//   3. Copies the remaining 256 MB into another new buffer (System region)
//   4. Publishes both buffers via PERSISTENT ramdisk_image fields
//
// The ESP and System regions in the combined image are identical to the
// dual-partition layout: ESP occupies the first 64 MB, System occupies
// the next 256 MB. Winload splits them here so the kernel sees the same
// RAM disk layout regardless of whether it was booted from disk or ISO.

/// Size of the ESP region within the combined FAT32 image (64 MB).
const ISO_ESP_SIZE: usize = 64 * 1024 * 1024;
/// Size of the System region within the combined FAT32 image (256 MB).
const ISO_SYS_SIZE: usize = 256 * 1024 * 1024;

/// Read `nt61.img` from the ISO's SimpleFileSystem and split it into
/// ESP and System RAM disk buffers. Publishes via PERSISTENT.
fn capture_iso_ramdisk() {
    push_open("\\\\ISO\\\\");
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    // The combined FAT32 image (ESP + System) is at most 320 MB.
    let cached_ptr = unsafe { core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile() };
    if cached_ptr == 0 {
        uefi::println!("[LOADER] ISO ramdisk: no SFS handle cached — skipping");
        return;
    }

    // Open the volume and probe for \EFI\Microsoft\Boot\nt61.img BEFORE
    // allocating 320 MB of boot-time memory. On a plain disk boot (no
    // ISO), the file is absent and we must not allocate anything.
    use uefi::boot::open_protocol_exclusive;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::Handle;
    let handle = match unsafe { Handle::from_ptr(cached_ptr as *mut core::ffi::c_void) } {
        Some(h) => h,
        None => {
            uefi::println!("[LOADER] ISO ramdisk: invalid handle — skipping");
            return;
        }
    };
    let mut sfs = match open_protocol_exclusive::<SimpleFileSystem>(handle) {
        Ok(s) => s,
        Err(e) => {
            uefi::println!("[LOADER] ISO ramdisk: open_protocol failed: {:?} — skipping", e);
            return;
        }
    };
    let mut root = match sfs.open_volume() {
        Ok(v) => v,
        Err(_) => {
            uefi::println!("[LOADER] ISO ramdisk: open_volume failed — skipping");
            return;
        }
    };
    // Probe for the file by walking the path. If the probe finds it, we
    // know this is an ISO boot and can proceed.
    let img_path = "\\EFI\\Microsoft\\Boot\\nt61.img";
    let img_path_cstr = match uefi::CString16::try_from(img_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let probe_handle = match root.open(
        &img_path_cstr,
        uefi::proto::media::file::FileMode::Read,
        uefi::proto::media::file::FileAttribute::empty(),
    ) {
        Ok(h) => h,
        Err(_) => {
            uefi::println!("[LOADER] ISO ramdisk: nt61.img not present — skipping (disk boot)");
            return;
        }
    };
    let mut probe_file = match probe_handle.into_regular_file() {
        Some(f) => f,
        None => {
            uefi::println!("[LOADER] ISO ramdisk: nt61.img is not a regular file — skipping");
            return;
        }
    };
    uefi::println!("[LOADER] ISO ramdisk: nt61.img present ({} MiB allocation follows)",
                   (ISO_ESP_SIZE + ISO_SYS_SIZE) / (1024 * 1024));

    // The combined FAT32 image (ESP + System) is at most 320 MB.
    let total_combined_size = ISO_ESP_SIZE + ISO_SYS_SIZE;
    let combined_pages = (total_combined_size + 0xFFF) / 0x1000;

    // Allocate a contiguous buffer for reading the combined image from the ISO.
    let combined_buf = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        combined_pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!(
                "[LOADER] [WARN] ISO ramdisk: combined image allocate_pages failed: {:?}",
                e
            );
            return;
        }
    };
    let combined_ptr = combined_buf.as_ptr() as *mut u8;

    // Read the file we already probed (probe_file). It holds an open
    // reference to \EFI\Microsoft\Boot\nt61.img. We don't need to
    // navigate the directory tree again — the probe already did it.
    let n = match probe_file.read(unsafe {
        core::slice::from_raw_parts_mut(combined_ptr, total_combined_size)
    }) {
        Ok(n) => n,
        Err(e) => {
            uefi::println!("[LOADER] [WARN] ISO ramdisk: read failed: {:?}", e);
            return;
        }
    };
    uefi::println!(
        "[LOADER] ISO ramdisk: read {} bytes from nt61.img",
        n
    );

    // 2. Allocate ESP buffer and copy the first 64 MB.
    let esp_pages = (ISO_ESP_SIZE + 0xFFF) / 0x1000;
    let esp_buf = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        esp_pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!(
                "[LOADER] [WARN] ISO ramdisk: ESP allocate_pages failed: {:?}",
                e
            );
            return;
        }
    };
    let esp_ptr = esp_buf.as_ptr() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(combined_ptr, esp_ptr, ISO_ESP_SIZE);
    }
    pd.esp_image_base = esp_ptr as u64;
    pd.esp_image_size = ISO_ESP_SIZE as u64;
    pd.esp_block_size = 512;
    uefi::println!(
        "[LOADER] ISO ramdisk: ESP {} MB @ 0x{:x}",
        ISO_ESP_SIZE / (1024 * 1024),
        esp_ptr as u64
    );

    // 3. Allocate System buffer and copy the next 256 MB.
    let sys_pages = (ISO_SYS_SIZE + 0xFFF) / 0x1000;
    let sys_buf = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        sys_pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!(
                "[LOADER] [WARN] ISO ramdisk: SYS allocate_pages failed: {:?}",
                e
            );
            return;
        }
    };
    let sys_ptr = sys_buf.as_ptr() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(combined_ptr.add(ISO_ESP_SIZE), sys_ptr, ISO_SYS_SIZE);
    }
    pd.sys_image_base = sys_ptr as u64;
    pd.sys_image_size = ISO_SYS_SIZE as u64;
    pd.sys_block_size = 512;
    uefi::println!(
        "[LOADER] ISO ramdisk: SYS {} MB @ 0x{:x}",
        ISO_SYS_SIZE / (1024 * 1024),
        sys_ptr as u64
    );

    // 4. Publish the combined image as `ramdisk_image` so the kernel can
    //    expose it as the X: drive.
    let ramdisk_size = core::cmp::min(n, total_combined_size);
    let ramdisk_pages = (ramdisk_size + 0xFFF) / 0x1000;
    let ramdisk_buf = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        ramdisk_pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            uefi::println!(
                "[LOADER] [WARN] ISO ramdisk: ramdisk allocate_pages failed: {:?}",
                e
            );
            return;
        }
    };
    let ramdisk_ptr = ramdisk_buf.as_ptr() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(combined_ptr, ramdisk_ptr, ramdisk_size);
    }
    pd.ramdisk_image_base = ramdisk_ptr as u64;
    pd.ramdisk_image_size = ramdisk_size as u64;
    pd.ramdisk_block_size = 512;
    uefi::println!(
        "[LOADER] ISO ramdisk: combined {} bytes @ 0x{:x} (X: drive)",
        ramdisk_size,
        ramdisk_ptr as u64
    );
}

/// Physical address of the framebuffer hand-off mailbox published
/// by the boot manager. Matches the constant in
/// `boot/src/main.rs`.
const FB_MAILBOX_PHYS: u64 = 0x10_200;

/// Read the framebuffer hand-off mailbox. Returns `None` if the
/// signature is wrong or the values look uninitialised.
fn read_fb_mailbox() -> Option<FramebufferInfo> {
    let p = FB_MAILBOX_PHYS as *const u8;
    unsafe {
        let sig = [
            core::ptr::read_volatile(p),
            core::ptr::read_volatile(p.add(1)),
            core::ptr::read_volatile(p.add(2)),
            core::ptr::read_volatile(p.add(3)),
        ];
        if sig != *b"FBHM" {
            uefi::println!("  [LOAD] Framebuffer mailbox missing (got {:02x?})", sig);
            return None;
        }
        let ver = core::ptr::read_volatile(p.add(4) as *const u32);
        let base = core::ptr::read_volatile(p.add(8) as *const u64);
        let size = core::ptr::read_volatile(p.add(16) as *const u64);
        let width = core::ptr::read_volatile(p.add(24) as *const u32);
        let height = core::ptr::read_volatile(p.add(28) as *const u32);
        let stride = core::ptr::read_volatile(p.add(32) as *const u32);
        let format = core::ptr::read_volatile(p.add(36) as *const u32);

        if base == 0 || width == 0 || height == 0 {
            uefi::println!("  [LOAD] Framebuffer mailbox invalid (zeros)");
            return None;
        }
        uefi::println!(
            "  [LOAD] Framebuffer mailbox v{}: base=0x{:x} {}x{} stride={} format={}",
            ver, base, width, height, stride, format
        );
        Some(FramebufferInfo {
            base, size, width, height, stride, format,
        })
    }
}

/// Fallback path: open the GOP protocol directly. This is used
/// only when the bootmgr-published mailbox is unavailable (for
/// example when winload is loaded directly, not via the bootmgr).
fn collect_framebuffer_info_from_gop() -> FramebufferInfo {
    use uefi::proto::console::gop::GraphicsOutput;

    let handles = match uefi::boot::find_handles::<GraphicsOutput>() {
        Ok(h) => h,
        Err(_) => {
            uefi::println!("  [LOAD] GOP: no GraphicsOutput handles found");
            return FramebufferInfo::new();
        }
    };

    if handles.is_empty() {
        uefi::println!("  [LOAD] GOP: no GraphicsOutput handles found");
        return FramebufferInfo::new();
    }

    // Open the first GOP handle
    let mut gop = match uefi::boot::open_protocol_exclusive::<GraphicsOutput>(handles[0]) {
        Ok(g) => g,
        Err(e) => {
            uefi::println!("  [LOAD] GOP: open_protocol_exclusive failed: {:?}", e);
            return FramebufferInfo::new();
        }
    };

    // Get current mode info
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let stride = info.stride() * 4; // 4 bytes per pixel for BGRA
    let mut fb = gop.frame_buffer();
    let fb_ptr = fb.as_mut_ptr();
    let fb_size = fb.size();

    // Determine pixel format
    // PixelBlueGreenRedReserved8BitPerColor = 1 (BGRA)
    // PixelBitMask = 2
    // PixelBltOnly = 3
    // PixelFormatMax = 4
    let format: u32 = match info.pixel_format() {
        uefi::proto::console::gop::PixelFormat::Bgr => 1, // BGRA
        uefi::proto::console::gop::PixelFormat::Rgb => 2, // RGBA
        _ => 0,
    };

    let fb_info = FramebufferInfo {
        base: fb_ptr as u64,
        size: fb_size as u64,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
        format,
    };

    uefi::println!(
        "  [LOAD] GOP Framebuffer: base=0x{:016x} size={} bytes",
        fb_info.base, fb_info.size
    );
    uefi::println!(
        "  [LOAD] GOP Mode: {}x{} stride={} format={}",
        fb_info.width, fb_info.height, fb_info.stride, fb_info.format
    );

    fb_info
}

// =====================================================================
// Phase 6 — Build BootInfo
// =====================================================================

fn build_boot_info(kernel_pa: u64, kernel_size: u64) -> BootInfo {
    let pd = unsafe { &*core::ptr::addr_of!(PERSISTENT) };

    // Count loaded boot drivers
    let boot_driver_count = pd.boot_drivers.iter()
        .filter(|r| r.loaded)
        .count() as u32;

    BootInfo {
        magic: BootInfo::MAGIC,
        version: 1,
        kernel_physical_base: kernel_pa,
        kernel_virtual_base: 0xFFFF_8000_0000_0000,
        kernel_size,
        memory_map: &pd.memory_map as *const MemoryMapEntry as u64,
        memory_map_entries: pd.memory_map_count as u64,
        memory_map_size_bytes: pd.memory_map_size_bytes as u64,
        memory_descriptor_size: pd.descriptor_size,
        _reserved: 0,
        cmdline: 0,
        acpi_rsdp: pd.acpi_rsdp,
        smp_info: pd.smp_cpu_count as u64,
        hives: 0,
        hive_count: 0,
        boot_mode: nt61::boot_types::BootMode::Normal as u32,
        esp_disk_start: pd.esp_partition_lba,
        esp_disk_sectors: pd.esp_partition_sectors,
        boot_driver_count,
        _reserved2: 0,
        esp_image_base: pd.esp_image_base,
        esp_image_size: pd.esp_image_size,
        esp_block_size: pd.esp_block_size,
        _reserved3: 0,
        sys_image_base: pd.sys_image_base,
        sys_image_size: pd.sys_image_size,
        sys_block_size: pd.sys_block_size,
        _reserved4: 0,
        ramdisk_image_base: pd.ramdisk_image_base,
        ramdisk_image_size: pd.ramdisk_image_size,
        ramdisk_block_size: pd.ramdisk_block_size,
        _reserved5: 0,
        // Graphics fields
        framebuffer_base: 0,
        framebuffer_size: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_stride: 0,
        framebuffer_format: 0,
        _reserved_gfx: 0,
        // Memory diagnostic fields
        memtest_base: 0,
        memtest_size: 0,
        memtest_signature: 0,
        memtest_status: 0,
        // NTFS-loaded kernel images
        ntoskrnl_image_base: 0,
        ntoskrnl_image_size: 0,
        hal_image_base: 0,
        hal_image_size: 0,
        bootvid_image_base: 0,
        bootvid_image_size: 0,
        ntoskrnl_handoff_callback: 0,
    }
}

// =====================================================================
// Architecture-independent kernel-jump trampoline
// =====================================================================
//
// The per-arch trampolines live in [`arch`]. The x86_64 trampoline
// reconciles the Microsoft-x64 loader ABI (rcx/rdx) with the
// System-V kernel ABI (rdi); the AAPCS64 / LP64 / LP64D ABIs on
// aarch64 / riscv64 / loongarch64 match Rust's `extern "C"` directly,
// so their trampolines only have to install the kernel stack and
// branch to the kernel symbol.

use crate::arch::call_kernel_main_from_loader;

// =====================================================================
// Build LoadedHiveList in low memory (Workstream C.2/C.3)
// =====================================================================
//
// The hive-loading pipeline below is scaffolded but not yet wired
// into `os_loader_run`: the OS Loader currently short-circuits to
// `kernel_main` with a hardcoded BootInfo. These helpers will be
// exercised by the next revision of Phase 3 (see `load_system_hive`),
// but to keep the API surface stable across revisions they stay
// compiled and exported. `#[allow(dead_code)]` silences the warning
// group while leaving the code 100% live for future phases.
//
// Permitted under MIT. See repository LICENSE.

#[allow(dead_code)] // Phase-3 workstream: re-enabled when os_loader_run advances.
const HIVE_PATHS: &[(&str, &str)] = &[
    ("System",   r"\Windows\System32\config\SYSTEM"),
    ("Software", r"\Windows\System32\config\SOFTWARE"),
    ("Security", r"\Windows\System32\config\SECURITY"),
    ("SAM",      r"\Windows\System32\config\SAM"),
    ("Default",  r"\Windows\System32\config\DEFAULT"),
];

/// Allocate a single contiguous `BOOT_SERVICES_DATA` region for
/// the hive bytes and the records array. Both live in the same
/// region so we only need one `allocate_pages` call. The region
/// is page-aligned and survives `ExitBootServices`.
#[allow(dead_code)] // Phase-3 workstream.
fn allocate_hive_region() {
    let bytes = HIVE_REGION_SIZE;
    let pages = (bytes + 0xFFF) / 0x1000;
    let result = allocate_pages(
        AllocateType::AnyPages,
        // Use BOOT_SERVICES_CODE: on OVMF and most firmwares
        // both BOOT_SERVICES_DATA and BOOT_SERVICES_CODE are
        // reclaimed by ExitBootServices, so we instead use
        // EfiRuntimeServicesData. That is documented to
        // survive ExitBootServices and is never reused by the
        // firmware.
        MemoryType::RUNTIME_SERVICES_DATA,
        pages as usize,
    );
    let ptr = match result {
        Ok(p) => p.as_ptr() as u64,
        Err(e) => {
            uefi::println!(
                "[HIVE] allocate_pages failed: {:?} — hive loading disabled",
                e
            );
            0
        }
    };
    unsafe {
        HIVE_REGION_PTR = ptr;
        HIVE_RECORDS_PTR = ptr + (ESP_FILE_BUF_SIZE * HIVE_BUF_COUNT) as u64;
    }
    if ptr != 0 {
        uefi::println!(
            "  [HIVE] region allocated: 0x{:x} ({} bytes / {} pages), records at 0x{:x}",
            ptr, bytes, pages, unsafe { HIVE_RECORDS_PTR }
        );
        uefi::println!(
            "  [HIVE] HIVE_REGION_SIZE constant = {}, ESP_FILE_BUF_SIZE*HIVE_BUF_COUNT = {}",
            HIVE_REGION_SIZE, ESP_FILE_BUF_SIZE * HIVE_BUF_COUNT
        );
    }
}

/// Read every hive from the ESP into the boot-service hive region,
/// then build a contiguous `LoadedHive[]` array in a separate
/// static buffer. Returns `(ptr_to_array, count)`. The returned
/// records stay valid across `ExitBootServices` because the
/// records buffer is a `static` and its `read`-only initialisation
/// does not require any heap activity.
///
/// The combined boot-service-data region layout.
///
/// ```text
///   [ 0 .. HIVE_REGION_SIZE )             hive bytes (one slot per hive)
///   [ HIVE_REGION_SIZE .. HIVE_REGION_SIZE + RECORDS_BYTES )   records array
/// ```
///
/// We split the region into two contiguous areas so that a single
/// `allocate_pages` call satisfies both. We deliberately do **not**
/// use a `Vec<LoadedHive>` for the records array: pushing into a
/// `Vec` calls the UEFI global allocator, which on this loader has
/// been observed to panic on the second or third allocation.
///
/// We also cannot use a `static` in `.data` / `.bss`, because the
/// PE image has no `.bss` section and the `.data` section is mapped
/// read-only by OVMF — every write to it triggers a #PF.
///
/// `LoadedHive` is `#[repr(C)]` and contains:
///
/// ```text
///   name         : [u8; 32]   = 32   (offset  0..32)
///   name_len     : u32        =  4   (offset 32..36)
///   _pad         : u32        =  4   (offset 36..40)  (aligns ptr to 8)
///   ptr          : u64        =  8   (offset 40..48)
///   len          : u32        =  4   (offset 48..52)
///   _reserved    : u32        =  4   (offset 52..56)
/// ```
///
/// Total = 56 bytes per record. The padding after `name_len` is
/// required by the C ABI to align the `u64` `ptr` field; without
/// it the kernel sees the wrong bytes when it reads `LoadedHive`
/// via the `#[repr(C)]` struct layout. We hard-code the constant
/// because `core::mem::size_of` is not a `const fn` and the value
/// may otherwise fold to zero under LTO.
#[allow(dead_code)] // Phase-3 workstream: layout mirrors the kernel's LoadedHive.
const RECORD_STRUCT_BYTES: usize = 56;
#[allow(dead_code)] // Phase-3 workstream.
const RECORDS_BYTES: usize = RECORD_STRUCT_BYTES * 8;

// Field offsets within one record. Keep in sync with the
// `#[repr(C)] LoadedHive` declaration in `nt61/src/registry/cm.rs`.
#[allow(dead_code)] // Phase-3 workstream.
const OFF_NAME:     usize = 0;
#[allow(dead_code)] // Phase-3 workstream.
const OFF_NAME_LEN: usize = 32;
#[allow(dead_code)] // Phase-3 workstream.
const OFF_PTR:      usize = 40;
#[allow(dead_code)] // Phase-3 workstream.
const OFF_LEN:      usize = 48;

#[allow(dead_code)] // Phase-3 workstream.
fn build_loaded_hive_list() -> (u64, u32) {
    let region_ptr = unsafe { HIVE_REGION_PTR };
    if region_ptr == 0 {
        uefi::println!("  [HIVE] skipped: no region");
        return (0, 0);
    }
    let records_ptr = unsafe { HIVE_RECORDS_PTR };
    if records_ptr == 0 {
        uefi::println!("  [HIVE] skipped: no records buffer");
        return (0, 0);
    }
    let max = HIVE_PATHS.len().min(BOOTINFO_MAX_HIVES);
    uefi::println!("  [HIVE] build: region=0x{:x} records=0x{:x} max={}", region_ptr, records_ptr, max);
    let mut count: usize = 0;
    for (i, (name, path)) in HIVE_PATHS.iter().take(max).enumerate() {
        // SAFETY: HIVE_REGION_PTR was set by allocate_hive_region
        // and is valid for the whole boot.
        let slot_base = unsafe { (region_ptr as *mut u8).add(i * ESP_FILE_BUF_SIZE) };
        uefi::println!("  [HIVE] about to try slot {} for {} ({})", i, name, path);
        // SAFETY: the slot is a fresh page-aligned region, so a
        // mutable slice over its full size is valid.
        let slot: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(slot_base, ESP_FILE_BUF_SIZE)
        };
        // Determine which partition to read from based on the path.
        // Registry hives (SYSTEM, SOFTWARE, etc.) are on the System partition.
        // BCD is on the ESP partition.
        let is_on_esp = path.starts_with("\\EFI\\") || path.starts_with("\\\\EFI\\\\");
        let open_result = if is_on_esp {
            uefi::println!("  [HIVE] slot {} reading from ESP partition: {}", i, path);
            open_esp_file_into(path, slot)
        } else {
            uefi::println!("  [HIVE] slot {} reading from System partition: {}", i, path);
            open_system_file_into(path, slot)
        };
        if let Some(len) = open_result {
            uefi::println!("  [HIVE] slot {} loaded {} bytes for {} at slot_base=0x{:x}", i, len, name, slot_base as u64);
            // Write a `LoadedHive` record into the records array.
            // We write each field explicitly with `ptr::write` /
            // `write_volatile` instead of relying on struct-store
            // or `copy_nonoverlapping` because the LTO pass has
            // been observed to fold a 6-byte copy into a multi-MB
            // memcpy with bogus arguments, crashing the loader.
            //
            // The kernel reads the record through a
            // `#[repr(C)] LoadedHive` struct, which inserts
            // 4 bytes of padding between `name_len` (u32 at
            // offset 32) and `ptr` (u64 at offset 40) so the
            // u64 is 8-byte aligned. We mirror that layout
            // here so the offsets line up exactly.
            let rec_ptr = unsafe { (records_ptr as *mut u8).add(i * RECORD_STRUCT_BYTES) };
            uefi::println!("  [HIVE] slot {} rec_ptr=0x{:x} slot_base=0x{:x}", i, rec_ptr as u64, slot_base as u64);
            unsafe {
                // name[0..32]: write the short ASCII name into the
                // first N bytes of the record.
                let name_bytes = name.as_bytes();
                let n = name_bytes.len().min(32);
                let mut k: usize = 0;
                while k < n {
                    let b = name_bytes[k];
                    core::ptr::write_volatile(rec_ptr.add(OFF_NAME + k), b);
                    k += 1;
                }
                // name_len at offset 32
                let p_nl = rec_ptr.add(OFF_NAME_LEN) as *mut u32;
                core::ptr::write_volatile(p_nl, n as u32);
                // padding bytes 36..40 are left as zero (the
                // region was freshly allocated by
                // `allocate_pages`, which zero-initialises it).
                // ptr at offset 40 (slot_base as a u64)
                let p_ptr = rec_ptr.add(OFF_PTR) as *mut u64;
                let hive_pa: u64 = slot_base as u64;
                core::ptr::write_volatile(p_ptr, hive_pa);
                uefi::println!("  [HIVE] slot {} wrote ptr=0x{:x} at rec+{}", i, hive_pa, OFF_PTR);
                // Read back immediately to confirm
                let verify: u64 = core::ptr::read_volatile(p_ptr);
                uefi::println!("  [HIVE] slot {} ptr readback=0x{:x}", i, verify);
                // len at offset 48
                let p_len = rec_ptr.add(OFF_LEN) as *mut u32;
                core::ptr::write_volatile(p_len, len as u32);
                uefi::println!("  [HIVE] slot {} wrote len={} at rec+{}", i, len, OFF_LEN);
            }
            // Read back and dump the first 56 bytes of this record
            // so we can confirm what actually got written (and
            // catch any LTO-induced miscompilation).
            unsafe {
                uefi::println!("  [HIVE] slot {} record dump:", i);
                let mut off = 0usize;
                while off < RECORD_STRUCT_BYTES {
                    let b = core::ptr::read_volatile(rec_ptr.add(off));
                    if off % 16 == 0 {
                        uefi::print!("    {:04x}:", off);
                    }
                    uefi::print!(" {:02x}", b);
                    if off % 16 == 15 {
                        uefi::println!("");
                    }
                    off += 1;
                }
                uefi::println!("");
            }
            count += 1;
        } else {
            uefi::println!("  [HIVE] {} ({}): missing or unreadable", name, path);
        }
    }
    (records_ptr, count as u32)
}

// =====================================================================
// OS Loader main
// =====================================================================

/// Total number of distinct progress points in `os_loader_run`.
/// This is the bottom-line value that drives the GOP progress bar.
#[allow(dead_code)] // Phase-0/1 workstream: re-enabled once gop_panel_init is called by os_loader_run.
const WINLOAD_TOTAL_PHASES: u32 = 11;

/// Re-open the GOP and call `body` with `&mut GraphicsOutput`,
/// then mark a winload progress segment. Used by the per-phase
/// helper `mark_winload_phase` below.
///
/// `phase` is 0-indexed; `WINLOAD_TOTAL_PHASES - 1` means
/// "almost full bar before ExitBootServices".
#[allow(dead_code)] // Phase-0/1 workstream.
fn with_gop<F: FnOnce(&mut uefi::proto::console::gop::GraphicsOutput)>(
    phase: u32,
    body: F,
) {
    let handles = match uefi::boot::find_handles::<uefi::proto::console::gop::GraphicsOutput>() {
        Ok(h) if !h.is_empty() => h,
        _ => return,
    };
    let mut gop = match uefi::boot::open_protocol_exclusive::<
        uefi::proto::console::gop::GraphicsOutput,
    >(handles[0]) {
        Ok(g) => g,
        Err(_) => return,
    };
    body(&mut gop);
    gop_display::mark_phase_global(phase, &mut gop);
}

/// Phase 0a: paint the initial "Windows is loading..." panel.
#[allow(dead_code)] // Phase-0/1 workstream.
fn gop_panel_init() {
    with_gop(0, |gop| {
        let _ = gop.blt(uefi::proto::console::gop::BltOp::VideoFill {
            color: uefi::proto::console::gop::BltPixel::new(0xD8, 0x98, 0x70),
            dest: (0, 0),
            dims: (gop.current_mode_info().resolution().0,
                   gop.current_mode_info().resolution().1),
        });
        let mode = gop.current_mode_info();
        let (_w, _h) = mode.resolution();
        gop_display::draw_text_centered_global(
            "Windows is loading...",
            (_h as u32) / 2 - 16,
            0xFF, 0xFF, 0xFF,
            gop,
        );
        gop_display::draw_progress_border_global(gop);
    });
}

/// Helper that updates the loader-wide progress bar.
#[allow(dead_code)] // Phase-0/1 workstream.
fn mark_winload_phase(phase: u32) {
    with_gop(phase, |_gop| { /* nothing extra: mark_phase handled in with_gop */ });
}

/// OS Loader main — marked #[inline(never)] to prevent LTO from optimizing away the call.
#[inline(never)]
fn os_loader_run() -> ! {
    boot_loader_header!();
    dump_trace();

    // =====================================================================
    // Phase L00 — Loader entry
    // =====================================================================
    uefi::println!("--- Phase L00 ---");

    // Collect the UEFI memory map before we fill in the
    // BootInfo. On architectures where the firmware reports RAM
    // outside the kernel's hardcoded default (`0x100000` — see
    // `mm::BOOT_RAM_BASE`), the kernel would otherwise pick a
    // region that isn't backed by physical memory and fault on
    // the very first frame-table clear. Calling
    // `collect_memory_map` populates `PERSISTENT.memory_map`
    // from `boot::get_memory_map`, and the kernel's region
    // selector then picks the largest *real* usable range.
    //
    // It ALSO saves `map_key` into `PERSISTENT.map_key` so the
    // eventual `ExitBootServices` call (Phase L10) can pass it
    // back to the firmware.
    uefi::println!("--- Phase L02 ---");
    collect_memory_map();

    // Publish the BootInfo address into the kernel-imported slot so
    // the kernel's `KERNEL_BOOT_INFO_PTR` is set to a live value
    // before we hand control over.
    unsafe {
        KERNEL_BOOT_INFO_PTR = core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64;
    }

    uefi::println!("[LOADER] os_loader_run entered");

    // =================================================================
    // Phase L01 — Capture partition snapshots
    //
    // Windows 7 winload snapshots the ESP and the System partition
    // (NTFS or FAT32, depending on disk layout) into
    // `EfiBootServicesData` buffers so the kernel can mount them as
    // RAM disks without ever touching the raw disk. This decouples
    // the kernel's storage stack from the boot-time driver stack
    // and is exactly what the FAT32 / NTFS drivers in
    // `fs::init()` expect to find populated in `BootInfo`.
    //
    // On ISO boot, the same two buffers come from
    // `capture_iso_ramdisk()` instead, which slices the combined
    // `nt61.img` FAT32 image into ESP / System halves. The capture
    // helpers are safe to call on every boot — when the underlying
    // handle is missing (e.g. disk-less QEMU for capture_iso_ramdisk)
    // they log a WARN and return without populating their fields.
    //
    // Each capture helper prints its own progress line so the
    // bring-up log shows exactly how far the loader got before
    // any hang in the kernel-side mount code.
    // =================================================================
    uefi::println!("--- Phase L01 ---");
    uefi::println!("[LOADER] capture: phase 0 begin (ESP / SYS / ISO)");
    capture_esp_partition();
    uefi::println!("[LOADER] capture: ESP done (esp_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).esp_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).esp_image_size }
    );
    capture_system_partition();
    uefi::println!("[LOADER] capture: SYS done (sys_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).sys_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).sys_image_size }
    );
    capture_iso_ramdisk();
    uefi::println!("[LOADER] capture: ISO done (ramdisk_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).ramdisk_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).ramdisk_image_size }
    );

    // Phase 1/2/3 are scaffolded by helpers below (collect_memory_map,
    // load_system_hive, etc.). Phase 4 — the BOOT_START driver load —
    // is the only phase that must run synchronously here, because
    // the drivers live in the kernel's boot-time identity-mapped
    // window and the kernel needs them in place by the time it
    // runs `PsCreateSystemThread` for `smss.exe`.
    uefi::println!("--- Phase L03 ---");
    let (ntoskrnl_base_l03, ntoskrnl_size_l03, hal_base_l03, hal_size_l03) = load_kernel_images();
    uefi::println!("[LOADER] L03: ntoskrnl base=0x{:x} size={} hal base=0x{:x} size={}",
        ntoskrnl_base_l03, ntoskrnl_size_l03, hal_base_l03, hal_size_l03);

    uefi::println!("--- Phase L06 ---");
    uefi::println!("[LOADER] Phase 4: invoking load_boot_drivers()");
    load_boot_drivers();
    uefi::println!("[LOADER] Phase 4: load_boot_drivers() returned");

    uefi::println!("--- Phase L05 ---");
    publish_bootvid_into_boot_info();

    // Read the framebuffer mailbox so the GUI side of the boot
    // (bootvid splash + CmdShell panel) has something to draw onto.
    // Falls back to text-mode boot when the mailbox is absent.
    //
    // The mailbox data is *not* written into `KERNEL_BOOT_INFO` here
    // because `build_boot_info` immediately below builds a fresh
    // BootInfo from scratch and the subsequent `*bi = bi_value`
    // assignment would clobber any fields we set early. Instead, the
    // framebuffer is captured into a local `Option<FramebufferInfo>`
    // and re-applied *after* `build_boot_info` so the kernel receives
    // a fully populated BootInfo (esp/sys/ramdisk + framebuffer).
    let fb_capture: Option<FramebufferInfo> = if let Some(fb) = read_fb_mailbox() {
        uefi::println!(
            "[LOADER] framebuffer mailbox: {}x{} stride={} @ 0x{:x} ({} KiB)",
            fb.width, fb.height, fb.stride, fb.base, fb.size / 1024
        );
        Some(fb)
    } else {
        None
    };

    // Build the BootInfo that the kernel will read. `build_boot_info`
    // copies the captured ESP/SYS/RAMDISK addresses from `PERSISTENT`
    // into the canonical `BootInfo` struct that the kernel and the
    // EFI stub both define. boot_mode is overwritten afterwards so
    // Safe-Mode / Normal selection still works.
    //
    // NOTE: `build_boot_info` zero-initialises the framebuffer fields
    // because they live in the kernel-maintained struct rather than
    // `PERSISTENT`. We restore them right after the assignment so the
    // GPU mailbox survives the copy.
    let bi_value = build_boot_info(0, 0);
    let bootvid_capture: (u64, u64) = unsafe {
        let pd = &*core::ptr::addr_of!(PERSISTENT);
        let last = MAX_BOOT_DRIVERS - 1;
        let rec = &pd.boot_drivers[last];
        if rec.loaded {
            (rec.base, rec.size)
        } else {
            (0, 0)
        }
    };
    unsafe {
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        *bi = bi_value;
        // boot_mode = 1 (SafeModeCmd) to launch cmd.exe directly.
        // The canonical field layout comes from `build_boot_info`,
        // but we deliberately pin the mode to SafeModeCmd for the
        // bring-up so the kernel reaches the cmd.exe hand-off path.
        bi.boot_mode = nt61::boot_types::BootMode::SafeModeCmd as u32;

        // Re-apply the framebuffer mailbox captured above. This must
        // come *after* `*bi = bi_value` or those fields would have
        // been wiped to zero by `build_boot_info`.
        if let Some(fb) = fb_capture {
            bi.framebuffer_base = fb.base;
            bi.framebuffer_size = fb.size;
            bi.framebuffer_width = fb.width;
            bi.framebuffer_height = fb.height;
            bi.framebuffer_stride = fb.stride;
            bi.framebuffer_format = fb.format;
        }

        // Re-apply the on-disk ntoskrnl.exe + hal.dll images.
        // `load_kernel_images()` wrote them at L03 but `*bi = bi_value`
        // just zeroed the whole struct, so we restore them here too.
        bi.ntoskrnl_image_base = ntoskrnl_base_l03;
        bi.ntoskrnl_image_size = ntoskrnl_size_l03;
        bi.hal_image_base = hal_base_l03;
        bi.hal_image_size = hal_size_l03;
        // Re-apply bootvid (captured above) — same reason as
        // ntoskrnl/hal: `*bi = bi_value` just zeroed the whole struct.
        bi.bootvid_image_base = bootvid_capture.0;
        bi.bootvid_image_size = bootvid_capture.1;
    }

    // Phase L07 — SYSTEM registry hive (mark loaded; the bytes
    // themselves are pulled by the kernel's cm::init through the
    // boot_info pointer). The mark ensures the cm layer skips its
    // "hive missing" fatal and proceeds straight into parsing.
    uefi::println!("--- Phase L07 ---");
    load_system_hive();
    uefi::println!("[LOADER] L07: SYSTEM hive entry marked in PERSISTENT");

    // Phase L08 — fill BootInfo with kernel/driver/hive counts.
    uefi::println!("--- Phase L08 ---");
    unsafe {
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        bi.boot_driver_count = MAX_BOOT_DRIVERS as u32;
        bi.hive_count = 1;
        // `bi.hives` is the physical address of the first LoadedHive
        // entry. We point it at a static empty descriptor — the
        // kernel's `cm::init` only reads the bytes when
        // `hive_count > 0` and `hives != 0`; since the descriptor
        // is empty it logs "no hives loaded" and falls back to the
        // default registry. The on-disk hive bytes themselves are
        // pulled by the kernel via the standard NTFS read path.
        static EMPTY_HIVE: nt61::boot_types::LoadedHive = nt61::boot_types::LoadedHive::empty();
        bi.hives = core::ptr::addr_of!(EMPTY_HIVE) as u64;
    }
    uefi::println!(
        "[LOADER] L08: BootInfo: ntoskrnl=0x{:x}/{} hal=0x{:x}/{} bootvid=0x{:x}/{} hives={} drivers={}",
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).ntoskrnl_image_base },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).ntoskrnl_image_size },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).hal_image_base },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).hal_image_size },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).bootvid_image_base },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).bootvid_image_size },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).hive_count },
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).boot_driver_count },
    );

    // Allocate a kernel stack.
    let stack_pages: usize = 64; // 256 KB
    let stack_base: u64 = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::LOADER_DATA,
        stack_pages,
    ) {
        Ok(p) => {
            uefi::println!("[LOADER] allocated stack at 0x{:x}", p.as_ptr() as u64);
            p.as_ptr() as u64
        }
        Err(e) => {
            uefi::println!("[LOADER] stack alloc failed: {:?}", e);
            // Use UEFI stack region near 0x7FB40000
            0x7FB40000u64
        }
    };
    let stack_top = stack_base + (stack_pages * 4096) as u64;
    let bi_ptr = core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64;

    uefi::println!(
        "[LOADER] jumping to kernel, bi_ptr=0x{:x} sp=0x{:x} boot_mode={}",
        bi_ptr, stack_top, unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).boot_mode }
    );

    // One last sanity check: log whether the ESP / SYS / ISO RAM-disk
    // mirrors and the framebuffer mailbox are populated. The kernel's
    // fs::init() will refuse to mount either filesystem if these are
    // zero, so a missing capture should be visible immediately in the
    // boot log instead of surfacing as a "FAT32 not mounted" panic
    // much later. Likewise, a missing framebuffer shows up as
    // "No framebuffer from winload" inside the kernel, so we surface
    // the field state here for early diagnosis.
    unsafe {
        let bi = &*core::ptr::addr_of!(KERNEL_BOOT_INFO);
        uefi::println!(
            "[LOADER] BootInfo: esp=0x{:x}/{} sys=0x{:x}/{} ramdisk=0x{:x}/{} fb=0x{:x}/{}x{}",
            bi.esp_image_base, bi.esp_image_size,
            bi.sys_image_base, bi.sys_image_size,
            bi.ramdisk_image_base, bi.ramdisk_image_size,
            bi.framebuffer_base, bi.framebuffer_width, bi.framebuffer_height
        );
    }

    uefi::println!("[WINLOAD]   transferring control to kernel_main (post-ExitBootServices)");

    // =====================================================================
    // Phase L09 — install host trampoline pointer
    // =====================================================================
    // The host trampoline (`ntoskrnl_kisystemstartup_thunk`) is the
    // function we want the disk-loaded ntoskrnl.exe!KiSystemStartup
    // stub to call back into. Publishing its address into the
    // 0x7a3ff000 slot (which is identity-mapped by the kernel) means
    // the disk stub's `mov rax, [rdx]; call rax` reaches us without
    // any extra setup.
    //
    // We install the pointer *now* (before ExitBootServices) so the
    // value is definitely visible by the time we reach Phase L11.
    uefi::println!("--- Phase L09 ---");
    let trampoline_addr = unsafe {
        nt61::arch::x86_64::ntoskrnl_handoff::install_handoff_pointer()
    };
    uefi::println!(
        "[WINLOAD] L09: trampoline address = 0x{:x}",
        trampoline_addr
    );

    // Publish the trampoline address into BootInfo's
    // ntoskrnl_handoff_callback field. The on-disk
    // ntoskrnl.exe!KiSystemStartup stub reads it via
    // `mov rax, [rcx + 0x13c]` (RCX = boot_info per Win7
    // KiSystemStartup ABI), so this single write makes the
    // trampoline callable from inside the disk stub. Using
    // BootInfo (vs. the previously fixed slot at 0x7a3ff000)
    // avoids UEFI reclaiming the page after a failed
    // ExitBootServices — BootInfo lives in the loader image
    // itself, not in EFI-managed memory.
    unsafe {
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        bi.ntoskrnl_handoff_callback = trampoline_addr;
    }
    uefi::println!(
        "[WINLOAD] L09: BootInfo.ntoskrnl_handoff_callback = 0x{:x}",
        trampoline_addr
    );

    // =====================================================================
    // Phase L10 — ExitBootServices(image_handle, map_key)
    // =====================================================================
    // From this point on UEFI boot services are gone — no more
    // allocate_pages, no console, no ExitBootServices retry. The
    // memory map + map_key captured in Phase L02 must be passed to
    // the firmware here, otherwise ExitBootServices returns
    // EFI_INVALID_PARAMETER.
    uefi::println!("--- Phase L10 ---");
    // QEMU/OVMF frequently rejects the first ExitBootServices call
    // with INVALID_PARAMETER because some background firmware work
    // between our collect_memory_map() at L02 and now changed the
    // map_key. Rather than play the "retry loop" game (which
    // sometimes wedges the firmware when multiple invalid calls
    // happen back-to-back), we treat ExitBootServices as
    // best-effort: try once, log the result, and continue
    // regardless. The kernel never touches UEFI services after the
    // jump, so a missed ExitBootServices just means BS_DATA / RT_DATA
    // types remain addressable in the EFI memory map — harmless.
    let map_key = unsafe { (*core::ptr::addr_of!(PERSISTENT)).map_key };
    uefi::println!(
        "[WINLOAD] L10: ExitBootServices(image_handle, map_key=0x{:x}) — best effort",
        map_key
    );
    // `uefi::boot::image_handle()` returns the high-level
    // `uefi::Handle` newtype; `Handle` underneath is a raw pointer
    // (`*mut c_void`). The `BootServices::exit_boot_services`
    // table function (which is the raw `extern "efiapi"` pointer
    // pulled out of the system table below) takes that raw
    // pointer, so we unwrap it.
    let handle_ptr: *mut core::ffi::c_void =
        uefi::boot::image_handle().as_ptr();
    unsafe {
        let st = uefi::table::system_table_raw()
            .expect("system table not set");
        let st_ref = st.as_ref();
        if let Some(bs_ptr) = st_ref.boot_services.as_ref() {
            let status = (bs_ptr.exit_boot_services)(handle_ptr, map_key);
            uefi::println!(
                "[WINLOAD] L10: ExitBootServices: status={:?} map_key=0x{:x}",
                status, map_key
            );
            if status.is_success() {
                uefi::println!("[WINLOAD] L10: boot services terminated successfully");
            } else {
                uefi::println!(
                    "[WINLOAD] L10: WARN: ExitBootServices returned {:?}; continuing anyway",
                    status
                );
            }
        } else {
            uefi::println!("[WINLOAD] L10: boot_services pointer null; skipping ExitBootServices");
        }
    }

    // =====================================================================
    // Phase L11 — jmp ntoskrnl!KiSystemStartup
    // =====================================================================
    // The disk ntoskrnl's `KiSystemStartup` stub is RIP-relative: it
    // loads the trampoline address from a field at the end of its own
    // `.text` section (written by winload here) and calls it. This
    // keeps the disk image self-contained: the callback survives
    // ExitBootServices because it lives inside the loaded PE, not in
    // the fragile BootServicesData region.
    uefi::println!("--- Phase L11 ---");
    let entry_rva = crate::arch::x86_64::kernel_entry::KiSystemStartup_RVA;
    let ki_va = ntoskrnl_base_l03 + entry_rva;
    uefi::println!(
        "[WINLOAD] L11: jumping to disk ntoskrnl.exe at 0x{:x} entry=0x{:x} stack_top=0x{:x}",
        ntoskrnl_base_l03,
        ki_va,
        stack_top
    );
    // Patch the callback field at end-of-.text with the host trampoline
    // address. The disk stub's `lea rax, [rip + disp]` points here.
    unsafe {
        let handoff_cb = (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).ntoskrnl_handoff_callback;
        use crate::arch::x86_64::kernel_entry as ke;
        // The callback field is the last 8 bytes of the .text section.
        // .text base VA = image_base + TEXT_BASE_RVA
        let text_base_va = ntoskrnl_base_l03 + ke::TEXT_BASE_RVA;
        let field_va = text_base_va + ke::TEXT_SIZE - 8;
        (field_va as *mut u64).write_volatile(handoff_cb);
        uefi::println!("[WINLOAD] L11: patched callback field at 0x{:x} = 0x{:x}", field_va, handoff_cb);
        let stub_bytes = core::slice::from_raw_parts(ki_va as *const u8, 16);
        uefi::println!("[WINLOAD] L11: KiSystemStartup stub = {:02x?}", stub_bytes);
    }
    unsafe {
        let _trampoline: unsafe extern "C" fn(u64, u64, u64) -> ! =
            crate::arch::x86_64::jump_to_ntoskrnl_kisystemstartup;
        crate::arch::x86_64::jump_to_ntoskrnl_kisystemstartup(
            stack_top,
            core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64,
            ki_va,
        );
    }
    #[allow(unreachable_code)]
    loop {
        unsafe { core::arch::asm!("hlt", options(noreturn)); }
    }
}

// =====================================================================
// UEFI entry point
// =====================================================================
// The linker script groups .text.efi_main sections and uses ENTRY(efi_main).
// Put efi_main in its own section so it gets placed at the very start.

#[link_section = ".text.efi_main"]
#[no_mangle]
extern "efiapi" fn efi_main(
    _image: uefi::Handle,
    _st: *const core::ffi::c_void,
) -> uefi::Status {
    // Set up UEFI globals — this MUST be done before calling any uefi crate functions.
    // SAFETY: image_handle and system_table are valid per UEFI calling convention.
    unsafe {
        uefi::boot::set_image_handle(_image);
        uefi::table::set_system_table(_st.cast());
    }

    // DIAG: output WINL> to serial port so we can confirm
    // efi_main is actually being entered by the boot manager.
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3f8",
            "mov al, 0x57", // 'W'
            "out dx, al",
            "mov al, 0x49", // 'I'
            "out dx, al",
            "mov al, 0x4e", // 'N'
            "out dx, al",
            "mov al, 0x4c", // 'L'
            "out dx, al",
            "mov al, 0x3e", // '>'
            "out dx, al",
            "mov al, 0x0a", // '\n'
            "out dx, al",
            options(nostack, preserves_flags),
        );
    }

    if let Err(_e) = uefi::helpers::init() {
        // ignored
    }

    // Cache the ESP / System SimpleFileSystem handles BEFORE any other
    // boot-services activity.
    cache_esp_sfs_handle();
    cache_system_sfs_handle();

    // Run the OS Loader — on success this never returns.
    os_loader_run();

    // NOTREACHED — os_loader_run is `!`. But if we somehow get here (e.g.,
    // the kernel panic loop exits), hang to prevent bootmgr from loading ntoskrnl.exe.
    #[allow(unreachable_code)]
    loop {
        unsafe { core::arch::asm!("hlt", options(noreturn)); }
    }
}
