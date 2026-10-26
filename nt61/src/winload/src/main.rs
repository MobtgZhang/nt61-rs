//! NT6.1.7601 UEFI OS Loader — `winload.efi`.
//
//! This is the *real* winload — the third stage of the UEFI boot
//! chain (firmware → bootmgr.efi → winload.efi).
//
//! Responsibilities (in order):
//
//!   1. Load ntoskrnl.exe  (PE parse, allocate pages, copy sections)
//!   2. Load hal.dll       (PE parse, map into kernel address space)
//!   3. Load SYSTEM hive  (read file, hand to kernel)
//!   4. Load BOOT_START drivers  (enumerate, parse, invoke DriverEntry)
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
// drives the full per-phase loading pipeline (PE parse, section copy,
// relocation, hive loading, BOOT_START driver enumeration).
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
extern crate alloc;

/// Host builds (`cargo check/test` on the developer Linux target) may link
/// `std` through workspace feature unification, and no workspace dependency
/// provides a panic handler on the host. Link `std` explicitly here so the
/// host build is deterministic and `std` supplies the `panic_impl` lang
/// item. Real firmware targets keep `no_std` and receive the kernel panic
/// handler from the `nt61` dependency (`binary_panic` feature).
#[cfg(all(not(test), target_os = "linux"))]
extern crate std;

#[cfg(feature = "log_level_debug")]
struct UartWriter;

#[cfg(feature = "log_level_debug")]
impl core::fmt::Write for UartWriter {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.as_bytes() {
            crate::arch::current::write_com1_marker(core::slice::from_ref(byte));
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! debug_println {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        #[cfg(feature = "log_level_debug")]
        {
            use core::fmt::Write as _;
            let mut writer = $crate::UartWriter;
            let _ = core::write!(writer, "{}\r\n", format_args!($fmt, $($arg),*));
        }
        #[cfg(not(feature = "log_level_debug"))]
        {
            // Borrow every argument so call sites do not trip the
            // unused-variable lint in non-debug builds. The borrows
            // are dropped immediately and nothing is formatted.
            let _ = (&$fmt, $(&$arg),*);
        }
    }};
}

#[macro_export]
macro_rules! debug_print {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        #[cfg(not(feature = "log_level_debug"))]
        if false {
            uefi::print!($fmt, $($arg),*);
        }
        #[cfg(feature = "log_level_debug")]
        uefi::print!($fmt, $($arg),*);
    }};
}
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};

mod arch;
mod ext4_boot;
mod fat32_boot;
mod fat_lfn;
mod gop_display;
pub mod logging;
pub mod ntfs_boot;
mod pe;
mod verify;

static EXIT_BOOT_SERVICES_DONE: AtomicBool = AtomicBool::new(false);

const HYBRID_HEADER_SIZE: usize = 64;
const HYBRID_MAGIC: u64 = 0x4e_54_36_31_48_59_42_52;
const HYBRID_ORIGIN_UEFI: u64 = 1;
const HYBRID_ORIGIN_KERNEL: u64 = 2;

#[repr(C)]
struct HybridAllocHeader {
    magic: u64,
    origin: u64,
    base_size: usize,
    base_align: usize,
    base_ptr: *mut u8,
    _reserved: [u8; 24],
}

struct HybridAllocator;

#[global_allocator]
static HYBRID_ALLOCATOR: HybridAllocator = HybridAllocator;

impl HybridAllocator {
    fn backend_alloc(layout: Layout) -> (*mut u8, u64) {
        if nt61::mm::heap::KERNEL_HEAP
            .configured_region()
            .is_some()
        {
            let ptr = unsafe {
                nt61::mm::heap::KERNEL_HEAP.alloc(layout)
            };
            (ptr, HYBRID_ORIGIN_KERNEL)
        } else {
            let ptr = unsafe { uefi::allocator::Allocator.alloc(layout) };
            (ptr, HYBRID_ORIGIN_UEFI)
        }
    }

    fn backend_dealloc(ptr: *mut u8, layout: Layout, origin: u64) {
        if origin == HYBRID_ORIGIN_KERNEL {
            unsafe {
                nt61::mm::heap::KERNEL_HEAP.dealloc(ptr, layout);
            }
        } else if !EXIT_BOOT_SERVICES_DONE.load(Ordering::Acquire) {
            unsafe {
                uefi::allocator::Allocator.dealloc(ptr, layout);
            }
        }
    }
}

unsafe impl GlobalAlloc for HybridAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base_align = layout.align().max(8);
        let base_size = layout
            .size()
            .checked_add(HYBRID_HEADER_SIZE + layout.align())
            .unwrap_or(usize::MAX);
        let Ok(base_layout) = Layout::from_size_align(base_size, base_align) else {
            return core::ptr::null_mut();
        };
            let (base, origin) = HybridAllocator::backend_alloc(base_layout);
        if base.is_null() {
            return core::ptr::null_mut();
        }
        let user_addr = (base as usize + HYBRID_HEADER_SIZE + base_align - 1)
            & !(base_align - 1);
        let user = user_addr as *mut u8;
        let header = user.sub(HYBRID_HEADER_SIZE) as *mut HybridAllocHeader;
        unsafe {
            (*header).magic = HYBRID_MAGIC;
            (*header).origin = origin;
            (*header).base_size = base_size;
            (*header).base_align = base_align;
            (*header).base_ptr = base;
        }
        user
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let header = ptr.sub(HYBRID_HEADER_SIZE) as *const HybridAllocHeader;
        if unsafe { (*header).magic } != HYBRID_MAGIC {
            return;
        }
        let Ok(base_layout) = Layout::from_size_align(
            unsafe { (*header).base_size },
            unsafe { (*header).base_align },
        ) else {
            return;
        };
        let base = unsafe { (*header).base_ptr };
        let origin = unsafe { (*header).origin };
        HybridAllocator::backend_dealloc(base, base_layout, origin);
    }
}

use nt61::boot_types::{DeviceRange, DeviceTreeHardware};
use nt61::kernel_main::{BootInfo, BOOTINFO_MAX_HIVES};
use nt61::loader;
use uefi::boot::{allocate_pages, AllocateType, MemoryType};
use uefi::mem::memory_map::MemoryAttribute;
use uefi::proto::media::file::FileInfo;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileMode};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::security::MemoryProtection;
use uefi::proto::unsafe_protocol;
use uefi::runtime::VariableVendor;
use uefi::CStr16;

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

/// UEFI page size — 4 KiB for every spec-compliant firmware.
const _PAGE_SIZE: usize = 4096;

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
    "\\Windows\\System32\\hal.dll",
    "\\Windows\\System32\\ntoskrnl.exe",
];

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

/// Read a complete system file into heap memory.
///
/// The NTFS path already returns a complete stream. For FAT/SFS paths,
/// `FileInfo` supplies the exact file size before allocation, which
/// avoids the subtle truncation that previously made only the first
/// 32 KiB of a several-MiB kernel PE available to the loader.
/// Raw FAT32 reader (nt61_bootfs): last-resort path when the cached
/// SimpleFileSystem handle cannot serve the file.
fn fat32_system_fallback(path: &str) -> Option<Vec<u8>> {
    if path.len() >= 8 && &path[1..8] == "Windows" {
        return crate::fat32_boot::read_fat32_system_file(path);
    }
    None
}

fn open_system_file_data(path: &str) -> Option<Vec<u8>> {
    let is_system = path.len() >= 8 && &path[1..8] == "Windows";
    if is_system {
        if let Some(data) = crate::ntfs_boot::read_ntfs_system_file(path) {
            return Some(data);
        }
        // EXT4 System partition: UEFI SimpleFileSystem only speaks
        // FAT, so EXT4 volumes are resolved by the in-tree reader.
        if let Some(data) = crate::ext4_boot::read_ext4_system_file(path) {
            return Some(data);
        }
        #[cfg(feature = "log_level_debug")]
        crate::ext4_boot::log_ext4_layout();
    }

    let cached_ptr = unsafe { core::ptr::addr_of!(CACHED_SYSTEM_SFS_PTR).read_volatile() };
    if cached_ptr == 0 {
        return fat32_system_fallback(path);
    }
    use uefi::boot::open_protocol_exclusive;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::Handle;
    let handle = unsafe { Handle::from_ptr(cached_ptr as *mut core::ffi::c_void) }?;
    let mut sfs = open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
    let mut current_dir = sfs.open_volume().ok()?;

    let bytes = path.as_bytes();
    let start = if bytes.first() == Some(&b'\\') { 1 } else { 0 };
    let mut idx = start;
    while idx < bytes.len() {
        let end = bytes[idx..]
            .iter()
            .position(|byte| *byte == b'\\')
            .map(|offset| idx + offset)
            .unwrap_or(bytes.len());
        let component = core::str::from_utf8(&bytes[idx..end]).ok()?;
        if end == bytes.len() {
            let mut file = open_file_component(&mut current_dir, component)?;
            let mut info_buffer = [0u8; 512];
            let info = file.get_info::<FileInfo>(&mut info_buffer).ok()?;
            let file_size = usize::try_from(info.file_size()).ok()?;
            if file_size > MAX_PE_FILE_SIZE {
                return None;
            }
            let mut data = Vec::new();
            data.resize(file_size, 0u8);
            let bytes_read = file.read(&mut data).ok()?;
            if bytes_read != file_size {
                return None;
            }
            return Some(data);
        }
        current_dir = open_dir_component(&mut current_dir, component)?;
        idx = end + 1;
    }
    fat32_system_fallback(path)
}

impl MemoryMapEntry {
    fn new(base: u64, length: u64, memory_type: u32) -> Self {
        Self {
            base,
            length,
            memory_type,
            reserved: 0,
        }
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
    /// uses this to exclude the ESP handle when picking the system partition
    /// (the previous FAT-family exclusion heuristic broke the FAT32-only
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
    device_tree_base: u64,
    device_tree_size: u32,
    device_tree_hardware: DeviceTreeHardware,
}

impl PersistentBootData {
    const fn new() -> Self {
        Self {
            // Use array repeat syntax for cleaner initialization
            memory_map: [MemoryMapEntry {
                base: 0,
                length: 0,
                memory_type: 0,
                reserved: 0,
            }; EXTENDED_MEMORY_MAP_SIZE],
            memory_map_count: 0,
            smp_cpu_count: SMP_CPU_COUNT,
            acpi_rsdp: 0,
            system_hive: HiveInfo::zeroed(),
            boot_drivers: [
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
                DriverLoadRecord {
                    name: [0u8; 32],
                    loaded: false,
                    base: 0,
                    size: 0,
                },
            ],
            memory_map_size_bytes: 0,
            descriptor_size: 0,
            // UEFI `map_key` returned by `GetMemoryMap` — must be
            // passed to `ExitBootServices(image_handle, map_key)`.
            // Zero before `collect_memory_map` runs.
            map_key: 0,
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
            device_tree_base: 0,
            device_tree_size: 0,
            device_tree_hardware: DeviceTreeHardware {
                uart: None,
                gicd: None,
                gicc: None,
                pci_ecam: None,
            },
        }
    }
}

// Initialise PERSISTENT lazily on first access — zeroed by the UEFI allocator.
static mut PERSISTENT: PersistentBootData = PersistentBootData::new();

// Static pointer to BootInfo for the kernel jump.
// SAFETY: written once in os_loader_run before the kernel is entered.
// The kernel reads this as the pointer to BootInfo.
static mut KERNEL_BOOT_INFO_PTR: u64 = 0;

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct EfiGuid([u8; 16]);

#[repr(C)]
struct EfiConfigurationTable {
    vendor_guid: EfiGuid,
    vendor_table: *mut core::ffi::c_void,
}

#[repr(C)]
struct EfiSystemTable {
    header: [u8; 24],
    firmware_vendor: *const u16,
    firmware_revision: u32,
    _reserved: u32,
    console_in_handle: usize,
    console_in: *const core::ffi::c_void,
    console_out_handle: usize,
    console_out: *const core::ffi::c_void,
    standard_error_handle: usize,
    standard_error: *const core::ffi::c_void,
    runtime_services: *const core::ffi::c_void,
    boot_services: *const core::ffi::c_void,
    number_of_table_entries: usize,
    configuration_table: *const EfiConfigurationTable,
}

const EFI_DTB_TABLE_GUID: EfiGuid = EfiGuid([
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41, 0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
]);

const EFI_FB_MAILBOX_TABLE_GUID: EfiGuid = EfiGuid([
    0x9d, 0x0f, 0x7e, 0x8a, 0x8d, 0x21, 0x4f, 0x7f, 0x98, 0x7f, 0x3c, 0x9d, 0x0c, 0x5f, 0x4b, 0x61,
]);

/// ACPI 2.0+ RSDP table GUID (all UEFI firmwares install this).
const EFI_ACPI_20_TABLE_GUID: EfiGuid = EfiGuid([
    0xc8, 0xe8, 0x68, 0x88, 0xa5, 0x1c, 0xbd, 0x4b, 0xa0, 0x24, 0x69, 0xa0, 0xc9, 0x9c, 0x02, 0x91,
]);

/// ACPI 1.0 RSDP table GUID (fallback for ancient firmwares).
const EFI_ACPI_TABLE_GUID: EfiGuid = EfiGuid([
    0x32, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd8, 0x11, 0x9a, 0x41, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
]);

/// FDT Client protocol exposed by EDK2 on generic ARM64 virtual machines.
#[repr(C)]
#[unsafe_protocol("e11faca0-4710-4c8e-a7a2-01baa2591b4c")]
struct FdtClientProtocol {
    get_node_property: usize,
    set_node_property: usize,
    find_compatible_node: usize,
    find_next_compatible_node: usize,
    find_compatible_node_property: usize,
    find_compatible_node_reg: FdtClientFindCompatibleNodeReg,
}

type FdtClientFindCompatibleNodeReg = unsafe extern "efiapi" fn(
    this: *const FdtClientProtocol,
    compatible: *const u8,
    reg: *mut *const u8,
    address_cells: *mut usize,
    size_cells: *mut usize,
    reg_size: *mut u32,
) -> uefi::Status;

/// Read up to four `reg` ranges from a Device Tree property.
fn read_reg_ranges(value: &[u8], address_cells: usize, size_cells: usize) -> [DeviceRange; 4] {
    let mut ranges = [DeviceRange::default(); 4];
    let Some(address_stride) = address_cells.checked_mul(4) else {
        return ranges;
    };
    let Some(size_stride) = size_cells.checked_mul(4) else {
        return ranges;
    };
    let Some(range_stride) = address_stride.checked_add(size_stride) else {
        return ranges;
    };
    if range_stride == 0 {
        return ranges;
    }
    for (index, range) in ranges.iter_mut().enumerate() {
        let start = match index.checked_mul(range_stride) {
            Some(start) => start,
            None => break,
        };
        let address_end = match start.checked_add(address_stride) {
            Some(end) => end,
            None => break,
        };
        let range_end = match address_end.checked_add(size_stride) {
            Some(end) => end,
            None => break,
        };
        if value.len() < range_end {
            break;
        }
        *range = DeviceRange {
            base: read_big_endian_u64(&value[start..address_end]),
            size: read_big_endian_u64(&value[address_end..range_end]),
        };
    }
    ranges
}

fn read_big_endian_u64(bytes: &[u8]) -> u64 {
    let read_be = |bytes: &[u8]| -> u64 {
        let mut result = 0u64;
        for byte in bytes.iter().take(8) {
            result = result.wrapping_shl(8) | u64::from(*byte);
        }
        result
    };
    read_be(bytes)
}

/// Query one compatible node's first `reg` range through the EDK2 protocol.
fn query_fdt_client_reg(client: &FdtClientProtocol, compatible: &[u8]) -> Option<DeviceRange> {
    let mut reg = core::ptr::null::<u8>();
    let mut address_cells = 0usize;
    let mut size_cells = 0usize;
    let mut reg_size = 0u32;
    let status = unsafe {
        (client.find_compatible_node_reg)(
            client,
            compatible.as_ptr(),
            &mut reg,
            &mut address_cells,
            &mut size_cells,
            &mut reg_size,
        )
    };
    if !status.is_success() || reg.is_null() {
        debug_println!(
            "[LOADER] FDT reg query '{}' failed: status={:?} reg_null={}",
            core::str::from_utf8(compatible).unwrap_or("???"),
            status,
            reg.is_null()
        );
        return None;
    }
    let value = unsafe { core::slice::from_raw_parts(reg, reg_size as usize) };
    let ranges = read_reg_ranges(value, address_cells, size_cells);
    debug_println!(
        "[LOADER] FDT reg query '{}': cells={}/{} bytes={} base={:#x} size={:#x}",
        core::str::from_utf8(compatible).unwrap_or("???"),
        address_cells,
        size_cells,
        reg_size,
        ranges[0].base,
        ranges[0].size
    );
    ranges.first().copied()
}

fn query_fdt_client_gic(client: &FdtClientProtocol) -> (Option<DeviceRange>, Option<DeviceRange>) {
    let mut reg = core::ptr::null::<u8>();
    let mut address_cells = 0usize;
    let mut size_cells = 0usize;
    let mut reg_size = 0u32;
    let mut ranges = [DeviceRange::default(); 4];
    for compatible in [
        b"arm,gic-400\0".as_slice(),
        b"arm,cortex-a15-gic\0".as_slice(),
    ] {
        let status = unsafe {
            (client.find_compatible_node_reg)(
                client,
                compatible.as_ptr(),
                &mut reg,
                &mut address_cells,
                &mut size_cells,
                &mut reg_size,
            )
        };
        if status.is_success() && !reg.is_null() {
            let value = unsafe { core::slice::from_raw_parts(reg, reg_size as usize) };
            ranges = read_reg_ranges(value, address_cells, size_cells);
            break;
        }
    }
    (ranges.first().copied(), ranges.get(1).copied())
}

/// Build an architecture-neutral hardware description from the EDK2 FDT
/// Client protocol. This avoids hard-coded QEMU `virt` addresses on generic
/// ARM64 systems.
fn capture_device_tree_hardware() -> DeviceTreeHardware {
    let Ok(handle) = uefi::boot::get_handle_for_protocol::<FdtClientProtocol>() else {
        return DeviceTreeHardware::default();
    };
    let Ok(client) = (unsafe {
        uefi::boot::open_protocol::<FdtClientProtocol>(
            uefi::boot::OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            uefi::boot::OpenProtocolAttributes::GetProtocol,
        )
    }) else {
        return DeviceTreeHardware::default();
    };
    let mut hardware = DeviceTreeHardware::default();
    // The FDT client protocol consumes NUL-terminated C strings;
    // Rust byte literals must carry the terminator explicitly.
    hardware.uart = query_fdt_client_reg(&client, b"arm,pl011\0");
    let (gicd, gicc) = query_fdt_client_gic(&client);
    hardware.gicd = gicd;
    hardware.gicc = gicc;
    hardware.pci_ecam = query_fdt_client_reg(&client, b"pci-host-ecam-generic\0");
    hardware
}

/// Locate the UEFI DTB table, copy it into runtime-surviving memory, and
/// record its exact address/size for `BootInfo`. The firmware-owned DTB is
/// not guaranteed to remain valid after `ExitBootServices`, so winload owns
/// the copy just like the Windows memory map and hive buffers.
fn capture_device_tree() {
    let Some(system_table) = uefi::table::system_table_raw() else {
        debug_println!("[LOADER] [WARN] DTB capture: system table unavailable");
        return;
    };
    let hardware = capture_device_tree_hardware();
    let persistent_probe = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };
    persistent_probe.device_tree_hardware = hardware;
    if hardware.uart.is_some() {
        debug_println!("[LOADER] FDT hardware captured through FDT client protocol");
    }
    let table = unsafe { &*(system_table.as_ptr() as *const EfiSystemTable) };
    let entries = unsafe {
        core::slice::from_raw_parts(table.configuration_table, table.number_of_table_entries)
    };
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.vendor_guid == EFI_DTB_TABLE_GUID)
    else {
        if hardware.uart.is_none() {
            debug_println!("[LOADER] DTB capture unavailable: no FDT client or DTB table");
        }
        return;
    };
    let source = entry.vendor_table as *const u8;
    if source.is_null() {
        debug_println!("[LOADER] [WARN] DTB capture: null vendor table");
        return;
    }
    let magic = u32::from_be_bytes(unsafe {
        [
            source.read_volatile(),
            source.add(1).read_volatile(),
            source.add(2).read_volatile(),
            source.add(3).read_volatile(),
        ]
    });
    if magic != 0xd00d_feed {
        debug_println!("[LOADER] [WARN] DTB capture: invalid magic 0x{:08x}", magic);
        return;
    }
    let total_size = u32::from_be_bytes(unsafe {
        [
            source.add(4).read_volatile(),
            source.add(5).read_volatile(),
            source.add(6).read_volatile(),
            source.add(7).read_volatile(),
        ]
    });
    if total_size == 0 || total_size > 8 * 1024 * 1024 {
        debug_println!("[LOADER] [WARN] DTB capture: invalid size {}", total_size);
        return;
    }
    let page_count = (total_size as usize + 0xfff) / 0x1000;
    let Ok(mut destination) = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        page_count,
    ) else {
        debug_println!("[LOADER] [WARN] DTB capture: allocation failed");
        return;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(source, destination.as_mut(), total_size as usize);
    }
    let persistent = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };
    persistent.device_tree_base = destination.as_ptr() as u64;
    persistent.device_tree_size = total_size;
    debug_println!(
        "[LOADER] DTB captured: base=0x{:x} size={}",
        persistent.device_tree_base,
        persistent.device_tree_size
    );
}

/// Locate the ACPI RSDP through the EFI configuration table and
/// record its address for the kernel. UEFI exposes the RSDP
/// pointer under the ACPI 2.0 GUID (every modern firmware,
/// including EDK2, installs it) with the ACPI 1.0 GUID as a
/// fallback. The kernel consumes `BootInfo.acpi_rsdp` during
/// Phase 1 to resolve MCFG / FADT / MADT through `find_table`.
fn capture_acpi_rsdp() {
    let Some(system_table) = uefi::table::system_table_raw() else {
        debug_println!("[LOADER] [WARN] ACPI capture: system table unavailable");
        return;
    };
    let table = unsafe { &*(system_table.as_ptr() as *const EfiSystemTable) };
    let entries = unsafe {
        core::slice::from_raw_parts(table.configuration_table, table.number_of_table_entries)
    };
    let rsdp = entries
        .iter()
        .find(|entry| entry.vendor_guid == EFI_ACPI_20_TABLE_GUID)
        .or_else(|| {
            entries
                .iter()
                .find(|entry| entry.vendor_guid == EFI_ACPI_TABLE_GUID)
        })
        .map(|entry| entry.vendor_table as u64);
    match rsdp {
        Some(rsdp_phys) if rsdp_phys != 0 => {
            let persistent = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };
            persistent.acpi_rsdp = rsdp_phys;
            debug_println!("[LOADER] ACPI RSDP captured: 0x{:x}", rsdp_phys);
        }
        _ => {
            debug_println!("[LOADER] [WARN] ACPI capture: no RSDP in configuration table");
        }
    }
}

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
    device_tree_base: 0,
    device_tree_size: 0,
    device_tree_hardware: DeviceTreeHardware {
        uart: None,
        gicd: None,
        gicc: None,
        pci_ecam: None,
    },
};

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
        // Prefer the device handle winload itself was loaded from
        // (EFI_LOADED_IMAGE_PROTOCOL). When bootmgfw chain-loads us this
        // is the authoritative ESP and avoids guessing between handles.
        if let Some(device) = chain_loaded_device_handle() {
            if device_has_simple_filesystem(device) {
                CACHED_SFS_PTR = device.as_ptr() as usize;
                SFS_HANDLE_READY = true;
                debug_println!(
                    "[DBG] cache_esp_sfs_handle: using chain-loaded device 0x{:x}",
                    device.as_ptr() as u64,
                );
                return;
            }
        }
        if let Ok(handles) = uefi::boot::find_handles::<SimpleFileSystem>() {
            if let Some(h) = handles.first() {
                CACHED_SFS_PTR = h.as_ptr() as usize;
                SFS_HANDLE_READY = true;
                debug_println!(
                    "[DBG] cache_esp_sfs_handle: cached SFS handle at 0x{:x}",
                    core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile()
                );
            } else {
                debug_println!("[DBG] cache_esp_sfs_handle: no SFS handles found");
            }
        } else {
            debug_println!("[DBG] cache_esp_sfs_handle: find_handles failed");
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
            // Ignore the first handle (ESP) and use the second if available
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
                    debug_println!(
                        "[DBG] cache_system_sfs_handle: cached SFS handle at 0x{:x} (partition 2)",
                        core::ptr::addr_of!(CACHED_SYSTEM_SFS_PTR).read_volatile()
                    );
                    return;
                }
            }
            // Only one partition available - fall back to ESP
            debug_println!(
                "[DBG] cache_system_sfs_handle: only 1 partition found, using ESP for all files"
            );
            CACHED_SYSTEM_SFS_PTR = CACHED_SFS_PTR;
            SYSTEM_SFS_HANDLE_READY = true;
        } else {
            debug_println!("[DBG] cache_system_sfs_handle: find_handles failed");
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
        if c > 0x7FFF {
            return None;
        }
        if i >= buf.len() - 1 {
            return None;
        }
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
        if let Ok(entry) =
            current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty())
        {
            if let Some(dir) = entry.into_directory() {
                return Some(dir);
            }
        }
        for sfn in &lookup.sfn_candidates {
            if let Ok(entry) =
                current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty())
            {
                if let Some(dir) = entry.into_directory() {
                    return Some(dir);
                }
            }
        }
    }

    None
}

/// Open a file component by name using the same silent fallback strategy.
fn open_file_component(
    current_dir: &mut Directory,
    file_name: &str,
) -> Option<uefi::proto::media::file::RegularFile> {
    // Build a stack-based UTF-16 path. This avoids allocating via the
    // Rust global allocator / boot::allocate_pool on every call.
    // Each driver name is < 32 chars, so a stack buffer is plenty.
    let mut buf: [u16; 64] = [0; 64];
    let mut i = 0;
    for c in file_name.encode_utf16() {
        if c > 0x7FFF {
            return None;
        } // UCS-2 only
        if i >= buf.len() - 1 {
            return None;
        }
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
                debug_println!("[DBG] open_esp_file_into: read {} bytes from {}", n, path);
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
        debug_println!(
            "[WINLOAD] System partition is NTFS; routing '{}' directly to NTFS reader",
            path
        );
        match crate::ntfs_boot::read_ntfs_system_file(path) {
            Some(data) => {
                let copy_len = core::cmp::min(data.len(), dst_buf.len());
                dst_buf[..copy_len].copy_from_slice(&data[..copy_len]);
                debug_println!(
                    "[DBG] open_system_file_into(NTFS): read {} bytes (truncated to {}) from {}",
                    data.len(),
                    copy_len,
                    path
                );
                return Some(copy_len);
            }
            None => {
                debug_println!(
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
                debug_println!(
                    "[DBG] open_system_file_into: read {} bytes from {}",
                    n,
                    path
                );
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
                debug_println!("[DBG] open_esp_file_into: read {} bytes from {}", n, path);
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
        image[opt_off + 0x18],
        image[opt_off + 0x19],
        image[opt_off + 0x1A],
        image[opt_off + 0x1B],
        image[opt_off + 0x1C],
        image[opt_off + 0x1D],
        image[opt_off + 0x1E],
        image[opt_off + 0x1F],
    ]);
    let size_of_image = u32::from_le_bytes([
        image[opt_off + 0x38],
        image[opt_off + 0x39],
        image[opt_off + 0x3A],
        image[opt_off + 0x3B],
    ]) as u64;
    let entry_rva = u32::from_le_bytes([
        image[opt_off + 0x10],
        image[opt_off + 0x11],
        image[opt_off + 0x12],
        image[opt_off + 0x13],
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
    let num_sections =
        u16::from_le_bytes([image[num_sections_off], image[num_sections_off + 1]]) as usize;
    let opt_size = u16::from_le_bytes([image[opt_size_off], image[opt_size_off + 1]]);
    let sections_off = opt_off + opt_size as usize;
    debug_println!(
        "[C0] opt_off={:#x} opt_size={:#x} sections_off={:#x} num_sections={}",
        opt_off,
        opt_size,
        sections_off,
        num_sections
    );
    let dest_ptr = dest as *mut u8;
    // Copy the PE headers into the mapped image. Relocation processing
    // reads the optional header and relocation directory from the
    // runtime layout, and a complete image should preserve its headers
    // just as a real Windows PE loader does.
    let size_of_headers_off = opt_off + 0x3C;
    if size_of_headers_off + 4 <= image.len() {
        let headers_len = u32::from_le_bytes([
            image[size_of_headers_off],
            image[size_of_headers_off + 1],
            image[size_of_headers_off + 2],
            image[size_of_headers_off + 3],
        ]) as usize;
        if headers_len <= image.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(image.as_ptr(), dest_ptr, headers_len);
            }
        }
    }
    let mut copied = 0;
    for i in 0..num_sections {
        let sh_off = sections_off + i * 40;
        if sh_off + 40 > image.len() {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            image[sh_off + 8],
            image[sh_off + 9],
            image[sh_off + 10],
            image[sh_off + 11],
        ]);
        let virtual_addr = u32::from_le_bytes([
            image[sh_off + 12],
            image[sh_off + 13],
            image[sh_off + 14],
            image[sh_off + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            image[sh_off + 16],
            image[sh_off + 17],
            image[sh_off + 18],
            image[sh_off + 19],
        ]);
        let raw_ptr = u32::from_le_bytes([
            image[sh_off + 20],
            image[sh_off + 21],
            image[sh_off + 22],
            image[sh_off + 23],
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
/// (ntoskrnl.exe / hal.dll / drivers). The real RISC-V kernel is
/// ~23 MB on disk, so 64 MiB leaves headroom for debug builds.
const MAX_PE_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Read a PE image from disk into a freshly-allocated buffer.
///
/// Returns `(virtual_base, size_of_image, entry_point_rva, is_dll)`
/// on success. `is_dll` is read from the PE's `Characteristics`
/// field (IMAGE_FILE_DLL == 0x2000): when set, the image is a
/// BOOT_START_IMAGE (BOOTVID.DLL, hal.dll, ntdll.dll, ...) that
/// only exports a symbol surface and has *no* DriverEntry at the
/// PE's AddressOfEntryPoint — the loader must bypass the
/// DriverEntry call for DLLs or it will jump into whatever bytes
/// the build tool happened to put at .text RVA 0 (usually the
/// export-directory header), which on real builds is `00 00 00
/// 00 ...` and immediately wedges the CPU on an unaligned
/// `add [rax], al` chain. UEFI then triggers the watchdog and
/// reboots, which is the symptom that prompted this flag.
#[inline(never)]
fn read_pe_file_from_disk(path: &str) -> Option<(Vec<u8>, u64, u32, bool)> {
    debug_println!("[R0] enter");

    uefi::println!("[WINLOAD] PE read begin {}", path);
    let raw = open_system_file_data(path)?;
    let size = raw.len();
    uefi::println!("[WINLOAD] PE read bytes {} size={}", path, size);
    debug_println!("[R2] read ok");
    if size == 0 || size < 0x40 || &raw[..2] != b"MZ" || size > MAX_PE_FILE_SIZE {
        debug_println!("[R2x] bad file");
        return None;
    }

    // Integrity gate: SHA-256 sidecar, PE CheckSum and the optional
    // RSA signature are all checked here, before any parsing or
    // mapping happens.
    if let Err(err) = crate::verify::verify_image(path, &raw) {
        debug_println!("[R2v] verify failed: {}", err);
        uefi::println!("[WINLOAD] {} integrity check failed: {}", path, err);
        return None;
    }
    debug_println!("[R2v] verify ok");

    debug_println!("[R3] about to parse");
    uefi::println!("[WINLOAD] PE parse begin {}", path);
    let (_image_base, size_of_image, entry_point, is_dll) = match parse_pe32plus(&raw[..size]) {
        Some(p) => p,
        None => {
            debug_println!("[R3f] parse None");
            return None;
        }
    };
    debug_println!("[R4] parsed (is_dll={})", is_dll);
    uefi::println!("[WINLOAD] PE parse end {} image={}", path, size_of_image);
    if size_of_image == 0 {
        return None;
    }

    let v = raw;
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
            uefi::boot::MemoryType::LOADER_CODE,
            pages,
        )
        .ok()?;
        IMAGE_BUFFER_BASE = ptr.as_ptr() as u64;
        IMAGE_BUFFER_NEXT = IMAGE_BUFFER_BASE;
        clear_execute_protect(IMAGE_BUFFER_BASE, IMAGE_BUFFER_SIZE as u64);
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
const IMAGE_BUFFER_SIZE: usize = 256 * 1024 * 1024;
static mut IMAGE_BUFFER_BASE: u64 = 0;
static mut IMAGE_BUFFER_NEXT: u64 = 0;

/// Remove firmware NX protection from a manually loaded image region.
///
/// Some AArch64 firmware keeps UEFI allocations non-executable until a
/// loader explicitly clears `EXECUTE_PROTECT`. Calling this helper after
/// allocation makes the behavior deterministic on protected firmware while
/// remaining harmless on firmware that already maps code pages executable.
fn clear_execute_protect(base: u64, size: u64) {
    if base == 0 || size == 0 {
        return;
    }

    let Ok(handle) = uefi::boot::get_handle_for_protocol::<MemoryProtection>() else {
        return;
    };
    let Ok(mut protocol) = uefi::boot::open_protocol_exclusive::<MemoryProtection>(handle) else {
        return;
    };

    if let Some(protection) = protocol.get_mut() {
        let region = base..base.checked_add(size).unwrap_or(u64::MAX);
        let _ = protection.clear_memory_attributes(region, MemoryAttribute::EXECUTE_PROTECT);
    }
}

fn allocate_and_map_image(image_base: u64, size_of_image: u64, raw_bytes: &[u8]) -> Option<u64> {
    if size_of_image == 0 {
        return None;
    }
    let pages = ((size_of_image + 0xFFF) / 0x1000) as usize;
    let dest_addr = ensure_image_buffer_chunk(pages)?;
    debug_println!("[A2] alloc ok at {:#x}", dest_addr);

    // Zero the destination first so any padding between sections
    // is deterministic.
    unsafe {
        core::ptr::write_bytes(dest_addr as *mut u8, 0u8, pages * 0x1000);
    }
    debug_println!("[A3] zero ok");

    // Copy each section into its virtual address.
    let copied = copy_pe_sections(raw_bytes, dest_addr);
    if copied == 0 {
        return None;
    }
    let _ = image_base; // accepted as parameter; we always use dest_addr.
    Some(dest_addr)
}

/// Parse the just-copied image, log its section permission layout and
/// apply per-section EXECUTE_PROTECT / READ_ONLY through the UEFI
/// Memory Attribute protocol. Must run *after* relocations have been
/// applied so relocation writes to read-only sections are not blocked.
fn finalize_image_protection(path: &str, load_addr: u64, raw: &[u8]) {
    if let Some(info) = crate::pe::parse_image_layout(raw) {
        crate::pe::log_image_layout(path, &info);
        crate::pe::apply_section_permissions(load_addr, &info);
    }
}

/// Apply base relocations in-place: when the image was loaded at a
/// different address than its preferred base, every absolute pointer
/// in the image needs to be biased by the slide delta.
fn apply_relocations_in_place(load_addr: u64, mapped_size: u64) -> usize {
    // Relocations operate on the mapped image, not on the on-disk file.
    // A PE's relocation directory is described by RVA, while the raw
    // file uses section alignment; translating those RVAs separately
    // for every section is both fragile and unnecessary once the image
    // has been copied to its runtime layout.
    let mapped_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            load_addr as *mut u8,
            usize::try_from(mapped_size).unwrap_or(0),
        )
    };
    if mapped_size < 64 {
        return 0;
    }
    let dos = mapped_bytes.as_ptr() as *const DosHeader;
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    if e_lfanew + 4 + 20 + 2 > mapped_bytes.len() {
        return 0;
    }
    let opt_off = e_lfanew + 4 + 20;

    // Find the original image base from the optional header.
    let opt_magic = u16::from_le_bytes([mapped_bytes[opt_off], mapped_bytes[opt_off + 1]]);
    let orig_base: u64 = if opt_magic == 0x20B {
        u64::from_le_bytes([
            mapped_bytes[opt_off + 0x18],
            mapped_bytes[opt_off + 0x19],
            mapped_bytes[opt_off + 0x1A],
            mapped_bytes[opt_off + 0x1B],
            mapped_bytes[opt_off + 0x1C],
            mapped_bytes[opt_off + 0x1D],
            mapped_bytes[opt_off + 0x1E],
            mapped_bytes[opt_off + 0x1F],
        ])
    } else if opt_magic == 0x10B {
        u32::from_le_bytes([
            mapped_bytes[opt_off + 0x1C],
            mapped_bytes[opt_off + 0x1D],
            mapped_bytes[opt_off + 0x1E],
            mapped_bytes[opt_off + 0x1F],
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
            mapped_bytes[opt_off + 0x98],
            mapped_bytes[opt_off + 0x99],
            mapped_bytes[opt_off + 0x9A],
            mapped_bytes[opt_off + 0x9B],
        ])
    } else {
        u32::from_le_bytes([
            mapped_bytes[opt_off + 0x88],
            mapped_bytes[opt_off + 0x89],
            mapped_bytes[opt_off + 0x8A],
            mapped_bytes[opt_off + 0x8B],
        ])
    };
    let reloc_size: u32 = if opt_magic == 0x20B {
        u32::from_le_bytes([
            mapped_bytes[opt_off + 0x9C],
            mapped_bytes[opt_off + 0x9D],
            mapped_bytes[opt_off + 0x9E],
            mapped_bytes[opt_off + 0x9F],
        ])
    } else {
        u32::from_le_bytes([
            mapped_bytes[opt_off + 0x8C],
            mapped_bytes[opt_off + 0x8D],
            mapped_bytes[opt_off + 0x8E],
            mapped_bytes[opt_off + 0x8F],
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
    if reloc_rva_us
        .checked_add(reloc_size_us)
        .map_or(true, |e| e > mapped_bytes.len())
    {
        return 0;
    }

    let base = load_addr as *mut u8;
    let mut off: usize = 0;
    let mut count: usize = 0;
    while off + 8 <= reloc_size_us {
        let page_rva = u32::from_le_bytes([
            mapped_bytes[reloc_rva_us + off],
            mapped_bytes[reloc_rva_us + off + 1],
            mapped_bytes[reloc_rva_us + off + 2],
            mapped_bytes[reloc_rva_us + off + 3],
        ]) as usize;
        let block_size = u32::from_le_bytes([
            mapped_bytes[reloc_rva_us + off + 4],
            mapped_bytes[reloc_rva_us + off + 5],
            mapped_bytes[reloc_rva_us + off + 6],
            mapped_bytes[reloc_rva_us + off + 7],
        ]) as usize;
        if block_size < 8 || off + block_size > reloc_size_us {
            break;
        }
        let entries = (block_size - 8) / 2;
        let mut i = 0usize;
        while i < entries {
            let eo = off + 8 + i * 2;
            let entry = u16::from_le_bytes([
                mapped_bytes[reloc_rva_us + eo],
                mapped_bytes[reloc_rva_us + eo + 1],
            ]);
            let typ = entry >> 12;
            let ofs = (entry & 0x0FFF) as usize;
            let target = page_rva + ofs;
            unsafe {
                match typ {
                    0 => {} // IMAGE_REL_BASED_ABSOLUTE
                    3 => {
                        // HIGHLOW (PE32)
                        let p = base.add(target) as *mut u32;
                        let v = core::ptr::read_unaligned(p);
                        core::ptr::write_unaligned(p, v.wrapping_add(delta as i32 as u32));
                        count += 1;
                    }
                    10 => {
                        // DIR64 (PE32+)
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
    debug_println!(
        "[LOAD] Phase 3: SYSTEM hive loading is performed in Phase 8 (build_loaded_hive_list)"
    );
    debug_println!("[LOAD] Phase 3: reserve hive region + read each hive from disk");
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
fn load_kernel_images() -> (u64, u64, u64, u64, u64) {
    // (ntoskrnl_base, ntoskrnl_size, hal_base, hal_size)
    debug_println!("[WINLOAD] L03: loading ntoskrnl.exe + hal.dll from NTFS system partition");
    let mut ntoskrnl_base: u64 = 0;
    let mut ntoskrnl_size: u64 = 0;
    let mut hal_base: u64 = 0;
    let mut hal_size: u64 = 0;
    let mut kernel_entry_rva: u64 = 0;
    let mut image_db = loader::ImageDatabase::new();

    for path in &KERNEL_IMAGE_PATHS {
        let (raw, size_of_image, entry_point_rva, _is_dll) = match read_pe_file_from_disk(path) {
            Some(t) => t,
            None => {
                debug_println!("[WINLOAD] L03: {} not found on NTFS system partition", path);
                continue;
            }
        };
        uefi::println!("[WINLOAD] driver read returned {}", path);
        if size_of_image == 0 || raw.len() < 0x40 || &raw[..2] != b"MZ" {
            debug_println!("[WINLOAD] L03: {}: empty or not a PE", path);
            continue;
        }
        // allocate_and_map_image returns the runtime base inside
        // the shared IMAGE_BUFFER pool (BOOT_SERVICES_DATA).
        let dest = match allocate_and_map_image(0, size_of_image, &raw) {
            Some(p) => p,
            None => {
                debug_println!("[WINLOAD] L03: {}: allocate_and_map_image failed", path);
                continue;
            }
        };
        let image_name = path.rsplit('\\').next().unwrap_or(path);
        let loaded = match loader::load_image_full(image_name, &raw, &mut image_db, dest) {
            Some(loaded) => loaded,
            None => {
                debug_println!("[WINLOAD] L03: {}: PE pipeline failed", path);
                continue;
            }
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                loaded.bytes.as_ptr(),
                dest as *mut u8,
                loaded.bytes.len(),
            );
        }
        image_db.register(&loaded, &raw);
        finalize_image_protection(*path, dest, &raw);
        if path.ends_with("ntoskrnl.exe") {
            ntoskrnl_base = dest;
            ntoskrnl_size = size_of_image;
            kernel_entry_rva = entry_point_rva as u64;
            debug_println!(
                "[WINLOAD] L03: ntoskrnl.exe loaded at 0x{:x} size={} entry=0x{:x}",
                dest,
                size_of_image,
                entry_point_rva
            );
        } else if path.ends_with("hal.dll") {
            hal_base = dest;
            hal_size = size_of_image;
            debug_println!(
                "[WINLOAD] L03: hal.dll loaded at 0x{:x} size={} exports=real",
                dest,
                size_of_image
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
    (
        ntoskrnl_base,
        ntoskrnl_size,
        hal_base,
        hal_size,
        kernel_entry_rva,
    )
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
            debug_println!(
                "[WINLOAD] L05: BOOTVID.DLL @ 0x{:x} size={} (from PERSISTENT)",
                rec.base,
                rec.size
            );
        } else {
            debug_println!("[WINLOAD] L05: BOOTVID.DLL not loaded; bootvid_image_base=0");
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
    debug_println!("[LOAD] Phase 4: loading BOOT_START drivers");
    let count_total = BOOT_DRIVER_PATHS.len();
    let mut loaded_count: u32 = 0;
    let mut any_failure: bool = false;
    // SAFETY: PERSISTENT is only mutated from the BSP during boot.
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    for (i, path) in BOOT_DRIVER_PATHS.iter().enumerate() {
        if i >= MAX_BOOT_DRIVERS {
            break;
        }

        uefi::println!(
            "[WINLOAD] load driver {}/{}: {}",
            i + 1,
            BOOT_DRIVER_PATHS.len(),
            path
        );
        let (raw, size_of_image, entry_point_rva, _is_dll) = match read_pe_file_from_disk(path) {
            Some(t) => t,
            None => {
                debug_println!("[WARN] boot driver {}: file missing or read failed", path);
                any_failure = true;
                continue;
            }
        };

        if raw.len() < 0x40 || &raw[0..2] != b"MZ" {
            debug_println!("[WARN] boot driver {}: file empty or not PE", path);
            any_failure = true;
            continue;
        }

        if size_of_image == 0 {
            debug_println!("[WARN] boot driver {}: size_of_image == 0", path);
            any_failure = true;
            continue;
        }

        // Step 2: Allocate via the shared IMAGE_BUFFER.
        // image_base is not used by allocate_and_map_image (it always
        // serves the IMAGE_BUFFER region), so we pass 0.
        uefi::println!("[WINLOAD] driver map begin {}", path);
        if let Some(dest_addr) = allocate_and_map_image(0, size_of_image, &raw) {
            uefi::println!("[WINLOAD] driver map end {}", path);
            let relocs = apply_relocations_in_place(dest_addr, size_of_image);
            finalize_image_protection(*path, dest_addr, &raw);
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
            debug_println!(
                "[LOAD] boot driver {}: base=0x{:016x} size=0x{:x} relocs={}",
                path,
                dest_addr,
                size_of_image,
                relocs
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
                debug_println!(
                    "[LOAD] BOOT_START_IMAGE: {} -> loaded at 0x{:016x} size=0x{:x} \
                     (no DriverEntry, exports only)",
                    driver_basename,
                    dest_addr,
                    size_of_image
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
            let entry_addr: u64 = dest_addr + entry_point_rva as u64;

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
            let driver_object_buf: *mut u8 =
                match uefi::boot::allocate_pool(uefi::boot::MemoryType::LOADER_DATA, 0x100) {
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
                    unsafe {
                        core::ptr::write_volatile(driver_object_buf.add(k), 0u8);
                    }
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
                    if idx >= reg_path_utf16.len() - 1 {
                        break;
                    }
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
                    let f: extern "C" fn(*mut u8, *const u16) -> i32 =
                        core::mem::transmute(entry_addr as *const ());
                    driver_entry_status = f(driver_object_buf, reg_path_utf16.as_ptr());
                }

                // The driver body writes MajorFunction[IRP_MJ_CREATE]
                // and DriverUnload into the DriverObject using the
                // kernel's actual layout. We check whether the writes
                // happened before continuing the boot chain.
                mj_create_written = unsafe {
                    let p = driver_object_buf.add(0x60) as *const u64;
                    core::ptr::read_volatile(p) != 0
                };
                unload_written = unsafe {
                    let p = driver_object_buf.add(0x58) as *const u64;
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

            debug_println!(
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
                    "disk.sys" => "\\Device\\Harddisk0",
                    "partmgr.sys" => "\\Device\\Partition0",
                    "volmgr.sys" => "\\Device\\VolumeManager",
                    "pci.sys" => "\\Device\\Pci",
                    "acpi.sys" => "\\Device\\ACPI_HAL",
                    "mssmbios.sys" => "\\Device\\Mssmbios",
                    "hpet.sys" => "\\Device\\Hpet",
                    _ => "(none — class/bus driver)",
                };
                debug_println!(
                    "[DRIVER] {}: DriverEntry at 0x{:x} -> STATUS_SUCCESS, target={}",
                    path,
                    entry_addr,
                    target_device
                );
            } else {
                debug_println!(
                    "[DRIVER] {}: DriverEntry did not populate dispatch table (mj_create={}, unload={})",
                    path, mj_create_written, unload_written
                );
            }
            debug_println!(
                "[WINLOAD] step: DriverObject registered: {:<30} @ 0x{:016x} size=0x{:x} entry=0x{:x} status=0x{:x}",
                driver_basename, dest_addr, size_of_image, entry_addr, driver_entry_status as u32
            );
            loaded_count += 1;
        } else {
            debug_println!("[WARN] boot driver {}: image allocate failed", path);
            any_failure = true;
        }
    }

    debug_println!(
        "[LOAD] Phase 4: {} of {} BOOT_START drivers loaded",
        loaded_count,
        count_total
    );
    if any_failure {
        debug_println!("[LOAD] Phase 4: (driver missing/error is non-fatal — boot continues)");
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
    let st = uefi::table::system_table_raw().expect("system table not set");
    let st = unsafe { st.as_ref() };
    let bt_ptr = st.boot_services;
    if bt_ptr.is_null() {
        debug_println!("  [LOAD] GetMemoryMap: boot_services is null");
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
        debug_println!("  [LOAD] GetMemoryMap raw failed");
        return (0, 0);
    }
    if desc_size == 0 {
        debug_println!("  [LOAD] GetMemoryMap returned desc_size=0");
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
            // Fall back to a conservative static map so the kernel still
            // boots on firmware that fails `GetMemoryMap` during boot.
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
            debug_println!(
                "  [LOAD] Memory map: {} entries (stub fallback)",
                entries.len()
            );
        } else {
            pd.memory_map_count = n;
            debug_println!(
                "  [LOAD] Memory map: {} entries (real UEFI GetMemoryMap)",
                n
            );
        }
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
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    // Find the SimpleFileSystem handle we have been using.
    debug_println!("[LOADER] ESP capture: find_handles<SimpleFileSystem>");
    let handles = match uefi::boot::find_handles::<uefi::proto::media::fs::SimpleFileSystem>() {
        Ok(h) => {
            debug_println!("[LOADER] ESP capture: find_handles OK (n={})", h.len());
            h
        }
        Err(e) => {
            debug_println!("[LOADER] [WARN] ESP capture: no SFS handles: {:?}", e);
            return;
        }
    };
    if handles.is_empty() {
        debug_println!("[LOADER] [WARN] ESP capture: empty SFS handle list");
        // Try the fallback file reader so future code paths can
        // still locate files even when SFS enumeration fails.
        let mut fallback_buf = [0u8; 512];
        let _ = open_esp_file_into_fallback("\\EFI\\Boot\\bootx64.efi", &mut fallback_buf);
        return;
    }
    let esp_handle = handles[0];

    // Open BlockIO on the same handle.
    debug_println!("[LOADER] ESP capture: open_protocol<BlockIO>");
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
            debug_println!("[LOADER] [WARN] ESP capture: BlockIO open failed: {:?}", e);
            return;
        }
    };
    let block_io_ref = match block_io.get() {
        Some(b) => b,
        None => {
            debug_println!("[LOADER] [WARN] ESP capture: BlockIO interface is null");
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

    debug_println!(
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
    debug_println!(
        "[LOADER] ESP capture: allocating {} pages ({} MiB)",
        pages,
        mirror_bytes / (1024 * 1024)
    );
    let buffer = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            debug_println!(
                "[LOADER] [WARN] ESP capture: allocate_pages failed: {:?}",
                e
            );
            core::mem::forget(block_io);
            return;
        }
    };
    let buffer_ptr = buffer.as_ptr() as *mut u8;
    debug_println!("[LOADER] ESP capture: buffer @ 0x{:x}", buffer_ptr as u64);

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
            core::slice::from_raw_parts_mut(buffer_ptr.add(byte_offset), blocks_here * block_size)
        };
        if let Err(e) = block_io_ref.read_blocks(media_id, lba_start, slice) {
            debug_println!(
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
    debug_println!(
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
    debug_println!(
        "[LOADER] ESP capture: media_id=0x{:x} blocks={}",
        media_id,
        total_blocks
    );

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
/// partition is 256 MiB on our reference disk and the mirror must
/// cover the *whole* partition: the NTFS build tool allocates
/// non-resident file data in clusters starting ~1 MiB into the
/// volume and keeps going for every user file, so a truncated
/// mirror makes any file whose clusters land past the cap fail
/// reads with an out-of-bounds error in the kernel-side NTFS
/// driver (observed as a silent failure to load cmd.exe).
const SYS_MIRROR_BYTES: usize = 256 * 1024 * 1024;

/// Snapshot the system partition into a contiguous physical
/// buffer. Same lifecycle as `capture_esp_partition`: the buffer
/// is allocated in `EfiBootServicesData` so it survives
/// `ExitBootServices`, and the address/size/block_size fields
/// end up in PERSISTENT -> BootInfo.
fn capture_system_partition() {
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
            debug_println!("[LOADER] [WARN] SYS capture: no BlockIO handles: {:?}", e);
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
    // "ignore FAT-family partitions" — that worked for the
    // (ESP=FAT32, sys=NTFS) layout but broke the (ESP=FAT32,
    // sys=FAT32) layout because both partitions had FAT OEM IDs
    // and the loop never picked a sys_handle. Now we match by ESP
    // BlockIO media_id (recorded by capture_esp_partition) and
    // pick the first logical partition with a different
    // media_id. The "is_logical_partition" / 512-byte block-size
    // filters are kept so we still exclude the whole-disk BlockIO
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
        // Exclude whole-disk BlockIO handle.
        if !media.is_logical_partition() {
            core::mem::forget(block_io);
            continue;
        }
        if media.block_size() != 512 {
            core::mem::forget(block_io);
            continue;
        }
        // Exclude the ESP itself — distinguishes system from ESP even
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
        let read_ok = block_io_ref
            .read_blocks(this_media_id, lba_offset, &mut buf)
            .is_ok();
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
            debug_println!(
                "[LOADER] [WARN] SYS capture: no non-ESP partition handle found among {} BlockIO devices",
                block_handles.len()
            );
            return;
        }
    };
    debug_println!(
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
            debug_println!("[LOADER] [WARN] SYS capture: BlockIO open failed: {:?}", e);
            return;
        }
    };
    let block_io_ref = match block_io.get() {
        Some(b) => b,
        None => {
            debug_println!("[LOADER] [WARN] SYS capture: BlockIO interface is null");
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

    debug_println!(
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
            debug_println!(
                "[LOADER] [WARN] SYS capture: allocate_pages failed: {:?}",
                e
            );
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
            core::slice::from_raw_parts_mut(buffer_ptr.add(byte_offset), blocks_here * block_size)
        };
        if let Err(e) = block_io_ref.read_blocks(media_id, lba_start, slice) {
            debug_println!(
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
    debug_println!(
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
    let pd = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENT) };

    // The combined FAT32 image (ESP + System) is at most 320 MB.
    let cached_ptr = unsafe { core::ptr::addr_of!(CACHED_SFS_PTR).read_volatile() };
    if cached_ptr == 0 {
        debug_println!("[LOADER] ISO ramdisk: no SFS handle cached — not available");
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
            debug_println!("[LOADER] ISO ramdisk: invalid handle — ignored");
            return;
        }
    };
    let mut sfs = match open_protocol_exclusive::<SimpleFileSystem>(handle) {
        Ok(s) => s,
        Err(e) => {
            debug_println!(
                "[LOADER] ISO ramdisk: open_protocol failed: {:?} — ignored",
                e
            );
            return;
        }
    };
    let mut root = match sfs.open_volume() {
        Ok(v) => v,
        Err(_) => {
            debug_println!("[LOADER] ISO ramdisk: open_volume failed — ignored");
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
            debug_println!("[LOADER] ISO ramdisk: nt61.img not present — absent (disk boot)");
            return;
        }
    };
    let mut probe_file = match probe_handle.into_regular_file() {
        Some(f) => f,
        None => {
            debug_println!("[LOADER] ISO ramdisk: nt61.img is not a regular file — ignored");
            return;
        }
    };
    debug_println!(
        "[LOADER] ISO ramdisk: nt61.img present ({} MiB allocation follows)",
        (ISO_ESP_SIZE + ISO_SYS_SIZE) / (1024 * 1024)
    );

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
            debug_println!(
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
    let n = match probe_file
        .read(unsafe { core::slice::from_raw_parts_mut(combined_ptr, total_combined_size) })
    {
        Ok(n) => n,
        Err(e) => {
            debug_println!("[LOADER] [WARN] ISO ramdisk: read failed: {:?}", e);
            return;
        }
    };
    debug_println!("[LOADER] ISO ramdisk: read {} bytes from nt61.img", n);

    // 2. Allocate ESP buffer and copy the first 64 MB.
    let esp_pages = (ISO_ESP_SIZE + 0xFFF) / 0x1000;
    let esp_buf = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        esp_pages,
    ) {
        Ok(p) => p,
        Err(e) => {
            debug_println!(
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
    debug_println!(
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
            debug_println!(
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
    debug_println!(
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
            debug_println!(
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
    debug_println!(
        "[LOADER] ISO ramdisk: combined {} bytes @ 0x{:x} (X: drive)",
        ramdisk_size,
        ramdisk_ptr as u64
    );
}

/// Vendor GUID for the framebuffer hand-off variable. It must match
/// the boot manager's writer.
const FB_VARIABLE_VENDOR: VariableVendor =
    VariableVendor(uefi::guid!("9d0f7e8a-8d21-4f7f-987f-3c9d0c5f4b61"));
const FB_VARIABLE_NAME: &CStr16 = uefi::cstr16!("NT61FB");

/// Read the framebuffer hand-off variable. Returns `None` if the
/// signature is wrong or the values look uninitialised.
fn read_fb_mailbox() -> Option<FramebufferInfo> {
    if let Some(fb) = read_fb_mailbox_from_config_table() {
        return Some(fb);
    }

    let mut payload = [0u8; 40];
    let (value, _attributes) =
        match uefi::runtime::get_variable(FB_VARIABLE_NAME, &FB_VARIABLE_VENDOR, &mut payload) {
            Ok(result) => result,
            Err(error) => {
                debug_println!(
                    "  [LOAD] Framebuffer variable unavailable: {:?}",
                    error.status()
                );
                return None;
            }
        };
    if value.len() != 40 || &value[0..4] != b"FBHM" {
        debug_println!(
            "  [LOAD] Framebuffer variable invalid (len={})",
            value.len()
        );
        return None;
    }

    let base = u64::from_le_bytes(value[8..16].try_into().unwrap());
    let size = u64::from_le_bytes(value[16..24].try_into().unwrap());
    let width = u32::from_le_bytes(value[24..28].try_into().unwrap());
    let height = u32::from_le_bytes(value[28..32].try_into().unwrap());
    let stride = u32::from_le_bytes(value[32..36].try_into().unwrap());
    let format = u32::from_le_bytes(value[36..40].try_into().unwrap());

    if base == 0 || width == 0 || height == 0 {
        debug_println!("  [LOAD] Framebuffer variable invalid (zeros)");
        return None;
    }
    debug_println!(
        "  [LOAD] Framebuffer variable v1: base=0x{:x} {}x{} stride={} format={}",
        base,
        width,
        height,
        stride,
        format
    );
    Some(FramebufferInfo {
        base,
        size,
        width,
        height,
        stride,
        format,
    })
}

/// Read the BCD mailbox that the boot manager wrote before
/// chain-loading winload. Returns the 16-byte selected entry GUID,
/// or `None` when the mailbox is absent (e.g. direct kernel load
/// without a boot manager).
fn read_bcd_mailbox() -> Option<[u8; 16]> {
    // Try the UEFI Configuration Table first (aarch64/riscv64/
    // loongarch64 — stricter memory protections).
    if let Some(guid) = read_bcd_mailbox_from_config_table() {
        return Some(guid);
    }

    // Fall back to the fixed low-memory address (x86_64).
    if !cfg!(target_arch = "x86_64") {
        return None;
    }
    let mailbox = 0x10_100usize as *const u8;
    let payload = unsafe { core::slice::from_raw_parts(mailbox, 0x1C + 16) };
    if &payload[0..4] != b"BCDE" {
        return None;
    }
    let guid: [u8; 16] = payload[0x0C..0x1C].try_into().ok()?;
    debug_println!(
        "[LOAD] BCD mailbox (fixed): guid={:02x}{:02x}{:02x}{:02x}...",
        guid[0],
        guid[1],
        guid[2],
        guid[3]
    );
    Some(guid)
}

/// Read the BCD mailbox through the UEFI Configuration Table.
/// The boot manager installs the mailbox physical address under the
/// same GUID the framebuffer mailbox uses for non-x86_64 archs.
fn read_bcd_mailbox_from_config_table() -> Option<[u8; 16]> {
    let Some(system_table) = uefi::table::system_table_raw() else {
        return None;
    };
    let table = unsafe { &*(system_table.as_ptr() as *const EfiSystemTable) };
    let entries = unsafe {
        core::slice::from_raw_parts(table.configuration_table, table.number_of_table_entries)
    };
    // The BCD mailbox uses the same config-table GUID mechanism
    // as the framebuffer mailbox on non-x86_64 architectures.
    // We scan for a table entry whose payload starts with "BCDE".
    for entry in entries {
        let mailbox = entry.vendor_table as *const u8;
        if mailbox.is_null() {
            continue;
        }
        let header = unsafe { core::slice::from_raw_parts(mailbox, 4) };
        if header != b"BCDE" {
            continue;
        }
        let payload = unsafe { core::slice::from_raw_parts(mailbox, 0x1C + 16) };
        let guid: [u8; 16] = payload[0x0C..0x1C].try_into().ok()?;
        debug_println!(
            "[LOAD] BCD mailbox (config table): guid={:02x}{:02x}{:02x}{:02x}...",
            guid[0],
            guid[1],
            guid[2],
            guid[3]
        );
        return Some(guid);
    }
    None
}

/// Map a BCD entry GUID (as written by the boot manager) to the
/// kernel `BootMode` enum. Falls back to `Desktop` for unknown
/// GUIDs, matching the default boot entry.
fn bcd_guid_to_boot_mode(guid: &[u8; 16]) -> nt61::boot_types::BootMode {
    // Match on the first 4 bytes — the well-known GUID prefixes.
    match &guid[0..4] {
        [0xB2, 0x72, 0x1D, 0x66] => nt61::boot_types::BootMode::Cmd,
        [0x51, 0x89, 0xB2, 0x5C] => nt61::boot_types::BootMode::DebugCmd,
        [0xA3, 0x4C, 0x8E, 0xD1] => nt61::boot_types::BootMode::SafeMode,
        _ => nt61::boot_types::BootMode::Desktop,
    }
}

/// Read the framebuffer hand-off through the UEFI Configuration Table.
/// Boot managers on generic ARM64/RISC-V/LoongArch firmware install this
/// table entry after opening the GOP, avoiding runtime variable services.
fn read_fb_mailbox_from_config_table() -> Option<FramebufferInfo> {
    let Some(system_table) = uefi::table::system_table_raw() else {
        return None;
    };
    let table = unsafe { &*(system_table.as_ptr() as *const EfiSystemTable) };
    let entries = unsafe {
        core::slice::from_raw_parts(table.configuration_table, table.number_of_table_entries)
    };
    let entry = entries
        .iter()
        .find(|entry| entry.vendor_guid == EFI_FB_MAILBOX_TABLE_GUID)?;
    let mailbox = entry.vendor_table as *const u8;
    if mailbox.is_null() {
        return None;
    }
    let payload = unsafe { core::slice::from_raw_parts(mailbox, 40) };
    if &payload[0..4] != b"FBHM" {
        return None;
    }
    let base = u64::from_le_bytes(payload[8..16].try_into().ok()?);
    let size = u64::from_le_bytes(payload[16..24].try_into().ok()?);
    let width = u32::from_le_bytes(payload[24..28].try_into().ok()?);
    let height = u32::from_le_bytes(payload[28..32].try_into().ok()?);
    let stride = u32::from_le_bytes(payload[32..36].try_into().ok()?);
    let format = u32::from_le_bytes(payload[36..40].try_into().ok()?);
    if base == 0 || width == 0 || height == 0 {
        return None;
    }
    debug_println!(
        "[LOAD] framebuffer config table: base=0x{:x} {}x{} stride={} format={}",
        base,
        width,
        height,
        stride,
        format
    );
    Some(FramebufferInfo {
        base,
        size,
        width,
        height,
        stride,
        format,
    })
}

// =====================================================================
// Phase 6 — Build BootInfo
// =====================================================================

fn build_boot_info(kernel_pa: u64, kernel_size: u64) -> BootInfo {
    let pd = unsafe { &*core::ptr::addr_of!(PERSISTENT) };

    // Count loaded boot drivers
    let boot_driver_count = pd.boot_drivers.iter().filter(|r| r.loaded).count() as u32;

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
        boot_mode: nt61::boot_types::BootMode::Desktop as u32,
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
        device_tree_base: pd.device_tree_base,
        device_tree_size: pd.device_tree_size,
        device_tree_hardware: pd.device_tree_hardware,
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

const HIVE_PATHS: &[(&str, &str)] = &[
    ("System", r"\Windows\System32\config\SYSTEM"),
    ("Software", r"\Windows\System32\config\SOFTWARE"),
    ("Security", r"\Windows\System32\config\SECURITY"),
    ("SAM", r"\Windows\System32\config\SAM"),
    ("Default", r"\Windows\System32\config\DEFAULT"),
];

/// Allocate a single contiguous `BOOT_SERVICES_DATA` region for
/// the hive bytes and the records array. Both live in the same
/// region so we only need one `allocate_pages` call. The region
/// is page-aligned and survives `ExitBootServices`.
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
            debug_println!(
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
        debug_println!(
            "  [HIVE] region allocated: 0x{:x} ({} bytes / {} pages), records at 0x{:x}",
            ptr,
            bytes,
            pages,
            unsafe { HIVE_RECORDS_PTR }
        );
        debug_println!(
            "  [HIVE] HIVE_REGION_SIZE constant = {}, ESP_FILE_BUF_SIZE*HIVE_BUF_COUNT = {}",
            HIVE_REGION_SIZE,
            ESP_FILE_BUF_SIZE * HIVE_BUF_COUNT
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
const RECORD_STRUCT_BYTES: usize = 56;
const RECORDS_BYTES: usize = RECORD_STRUCT_BYTES * 8;

// Field offsets within one record. Keep in sync with the
// `#[repr(C)] LoadedHive` declaration in `nt61/src/registry/cm.rs`.
const OFF_NAME: usize = 0;
const OFF_NAME_LEN: usize = 32;
const OFF_PTR: usize = 40;
const OFF_LEN: usize = 48;

fn build_loaded_hive_list() -> (u64, u32) {
    let region_ptr = unsafe { HIVE_REGION_PTR };
    if region_ptr == 0 {
        debug_println!("  [HIVE] not loaded: no region");
        return (0, 0);
    }
    let records_ptr = unsafe { HIVE_RECORDS_PTR };
    if records_ptr == 0 {
        debug_println!("  [HIVE] not loaded: no records buffer");
        return (0, 0);
    }
    let max = HIVE_PATHS.len().min(BOOTINFO_MAX_HIVES);
    debug_println!(
        "  [HIVE] build: region=0x{:x} records=0x{:x} max={}",
        region_ptr,
        records_ptr,
        max
    );
    let mut count: usize = 0;
    for (i, (name, path)) in HIVE_PATHS.iter().take(max).enumerate() {
        // SAFETY: HIVE_REGION_PTR was set by allocate_hive_region
        // and is valid for the whole boot.
        let slot_base = unsafe { (region_ptr as *mut u8).add(i * ESP_FILE_BUF_SIZE) };
        debug_println!("  [HIVE] about to try slot {} for {} ({})", i, name, path);
        // SAFETY: the slot is a fresh page-aligned region, so a
        // mutable slice over its full size is valid.
        let slot: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(slot_base, ESP_FILE_BUF_SIZE) };
        // Determine which partition to read from based on the path.
        // Registry hives (SYSTEM, SOFTWARE, etc.) are on the System partition.
        // BCD is on the ESP partition.
        let is_on_esp = path.starts_with("\\EFI\\") || path.starts_with("\\\\EFI\\\\");
        let open_result = if is_on_esp {
            debug_println!("  [HIVE] slot {} reading from ESP partition: {}", i, path);
            open_esp_file_into(path, slot)
        } else {
            debug_println!(
                "  [HIVE] slot {} reading from System partition: {}",
                i,
                path
            );
            open_system_file_into(path, slot)
        };
        if let Some(len) = open_result {
            debug_println!(
                "  [HIVE] slot {} loaded {} bytes for {} at slot_base=0x{:x}",
                i,
                len,
                name,
                slot_base as u64
            );
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
            debug_println!(
                "  [HIVE] slot {} rec_ptr=0x{:x} slot_base=0x{:x}",
                i,
                rec_ptr as u64,
                slot_base as u64
            );
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
                debug_println!(
                    "  [HIVE] slot {} wrote ptr=0x{:x} at rec+{}",
                    i,
                    hive_pa,
                    OFF_PTR
                );
                // Read back immediately to confirm
                let verify: u64 = core::ptr::read_volatile(p_ptr);
                debug_println!("  [HIVE] slot {} ptr readback=0x{:x}", i, verify);
                // len at offset 48
                let p_len = rec_ptr.add(OFF_LEN) as *mut u32;
                core::ptr::write_volatile(p_len, len as u32);
                debug_println!("  [HIVE] slot {} wrote len={} at rec+{}", i, len, OFF_LEN);
            }
            // Read back and dump the first 56 bytes of this record
            // so we can confirm what actually got written (and
            // catch any LTO-induced miscompilation).
            unsafe {
                debug_println!("  [HIVE] slot {} record dump:", i);
                let mut off = 0usize;
                while off < RECORD_STRUCT_BYTES {
                    let b = core::ptr::read_volatile(rec_ptr.add(off));
                    if off % 16 == 0 {
                        crate::debug_print!("    {:04x}:", off);
                    }
                    crate::debug_print!(" {:02x}", b);
                    if off % 16 == 15 {
                        debug_println!("");
                    }
                    off += 1;
                }
                debug_println!("");
            }
            count += 1;
        } else {
            debug_println!("  [HIVE] {} ({}): missing or unreadable", name, path);
        }
    }
    (records_ptr, count as u32)
}

// =====================================================================
// OS Loader main
// =====================================================================

/// Re-open the GOP and call `body` with `&mut GraphicsOutput`,
/// then mark a winload progress segment. Used by the per-phase
/// helper `mark_winload_phase` below.
///
/// `phase` is 0-indexed; `WINLOAD_TOTAL_PHASES - 1` means
/// "almost full bar before ExitBootServices".
fn with_gop<F: FnOnce(&mut uefi::proto::console::gop::GraphicsOutput)>(phase: u32, body: F) {
    let handles = match uefi::boot::find_handles::<uefi::proto::console::gop::GraphicsOutput>() {
        Ok(h) if !h.is_empty() => h,
        _ => return,
    };
    let mut gop = match uefi::boot::open_protocol_exclusive::<
        uefi::proto::console::gop::GraphicsOutput,
    >(handles[0])
    {
        Ok(g) => g,
        Err(_) => return,
    };
    body(&mut gop);
    gop_display::mark_phase_global(phase, &mut gop);
}

/// Phase 0a: paint the initial "Windows is loading..." panel.
fn gop_panel_init() {
    with_gop(0, |gop| {
        uefi::println!("[WINLOAD] gop body entered");
        let _ = gop.blt(uefi::proto::console::gop::BltOp::VideoFill {
            color: uefi::proto::console::gop::BltPixel::new(0xD8, 0x98, 0x70),
            dest: (0, 0),
            dims: (
                gop.current_mode_info().resolution().0,
                gop.current_mode_info().resolution().1,
            ),
        });
        uefi::println!("[WINLOAD] gop fill done");
        let mode = gop.current_mode_info();
        let (_w, _h) = mode.resolution();
        gop_display::draw_text_centered_global(
            "Windows is loading...",
            (_h as u32) / 2 - 16,
            0xFF,
            0xFF,
            0xFF,
            gop,
        );
        gop_display::draw_progress_border_global(gop);
    });
}

/// Helper that updates the loader-wide progress bar.
fn mark_winload_phase(phase: u32) {
    with_gop(
        phase,
        |_gop| { /* nothing extra: mark_phase handled in with_gop */ },
    );
}

/// OS Loader main — marked #[inline(never)] to prevent LTO from optimizing away the call.
#[inline(never)]
fn os_loader_run() -> ! {
    uefi::println!("[WINLOAD] os_loader_run pre-header");
    boot_loader_header!();
    gop_panel_init();
    uefi::println!("[WINLOAD] os_loader_run entered");

    // =====================================================================
    // Phase L00 — Loader entry
    // =====================================================================
    debug_println!("--- Phase L00 ---");
    mark_winload_phase(0);
    uefi::println!("[WINLOAD] before memory map");

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
    debug_println!("--- Phase L02 ---");
    mark_winload_phase(1);
    capture_device_tree();
    capture_acpi_rsdp();
    uefi::println!("[WINLOAD] before collect_memory_map");
    collect_memory_map();
    uefi::println!("[WINLOAD] after collect_memory_map");

    // Publish the BootInfo address into the kernel-imported slot so
    // the kernel's `KERNEL_BOOT_INFO_PTR` is set to a live value
    // before we hand control over.
    unsafe {
        KERNEL_BOOT_INFO_PTR = core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64;
    }

    debug_println!("[LOADER] os_loader_run entered");

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
    debug_println!("--- Phase L01 ---");
    mark_winload_phase(2);
    debug_println!("[LOADER] capture: phase 0 begin (ESP / SYS / ISO)");
    uefi::println!("[WINLOAD] capture ESP begin");
    capture_esp_partition();
    uefi::println!("[WINLOAD] capture ESP end");
    debug_println!(
        "[LOADER] capture: ESP done (esp_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).esp_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).esp_image_size }
    );
    uefi::println!("[WINLOAD] capture SYS begin");
    capture_system_partition();
    uefi::println!("[WINLOAD] capture SYS end");
    debug_println!(
        "[LOADER] capture: SYS done (sys_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).sys_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).sys_image_size }
    );
    uefi::println!("[WINLOAD] capture ISO begin");
    capture_iso_ramdisk();
    uefi::println!("[WINLOAD] capture ISO end");
    debug_println!(
        "[LOADER] capture: ISO done (ramdisk_image_base=0x{:x}, size={})",
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).ramdisk_image_base },
        unsafe { (*core::ptr::addr_of!(PERSISTENT)).ramdisk_image_size }
    );

    // Phase 1/2/3 are scaffolded by helpers below (collect_memory_map,
    // load_system_hive, etc.). Phase 4 — the BOOT_START driver load —
    // is the only phase that must run synchronously here, because
    // the drivers live in the kernel's boot-time identity-mapped
    // window and the kernel needs them in place by the time it
    // runs `PsCreateSystemThread` for `smss.exe`.
    debug_println!("--- Phase L03 ---");
    mark_winload_phase(3);
    uefi::println!("[WINLOAD] load kernel begin");
    let (ntoskrnl_base_l03, ntoskrnl_size_l03, hal_base_l03, hal_size_l03, kernel_entry_rva_l03) =
        load_kernel_images();
    uefi::println!("[WINLOAD] load kernel end");
    debug_println!(
        "[LOADER] L03: ntoskrnl base=0x{:x} size={} hal base=0x{:x} size={}",
        ntoskrnl_base_l03,
        ntoskrnl_size_l03,
        hal_base_l03,
        hal_size_l03
    );

    debug_println!("--- Phase L06 ---");
    mark_winload_phase(4);
    debug_println!("[LOADER] Phase 4: invoking load_boot_drivers()");
    uefi::println!("[WINLOAD] load drivers begin");
    load_boot_drivers();
    uefi::println!("[WINLOAD] load drivers end");
    debug_println!("[LOADER] Phase 4: load_boot_drivers() returned");

    debug_println!("--- Phase L05 ---");
    mark_winload_phase(5);
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
        debug_println!(
            "[LOADER] framebuffer mailbox: {}x{} stride={} @ 0x{:x} ({} KiB)",
            fb.width,
            fb.height,
            fb.stride,
            fb.base,
            fb.size / 1024
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
        // Read the BCD mailbox that the boot manager wrote and map
        // the selected entry GUID to the kernel `BootMode`. This
        // replaces the previous hard-coded `Desktop` — the four
        // boot menu entries (Desktop / CMD / Debug CMD / Safe Mode)
        // now propagate correctly to the kernel.
        let selected_mode = match read_bcd_mailbox() {
            Some(guid) => bcd_guid_to_boot_mode(&guid),
            None => nt61::boot_types::BootMode::Desktop,
        };
        debug_println!("[LOAD] boot mode from BCD mailbox: {:?}", selected_mode);
        bi.boot_mode = selected_mode as u32;

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
    // boot_info pointer). The mark ensures the cm layer bypasses its
    // "hive missing" fatal and proceeds straight into parsing.
    debug_println!("--- Phase L07 ---");
    mark_winload_phase(6);
    load_system_hive();
    debug_println!("[LOADER] L07: SYSTEM hive entry marked in PERSISTENT");

    // Phase L08 — fill BootInfo with kernel/driver/hive counts.
    debug_println!("--- Phase L08 ---");
    mark_winload_phase(7);
    let (hive_ptr, hive_count) = build_loaded_hive_list();
    unsafe {
        let bi = &mut *core::ptr::addr_of_mut!(KERNEL_BOOT_INFO);
        bi.boot_driver_count = MAX_BOOT_DRIVERS as u32;
        bi.hive_count = hive_count;
        bi.hives = hive_ptr;
    }
    debug_println!(
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
    let stack_pages: usize = 256; // 1 MiB
    let stack_base: u64 = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        // LOADER_DATA is reclaimed by the firmware after
        // ExitBootServices; the kernel stack must live in a
        // runtime-survivable type (same rationale as the hive
        // region below).
        uefi::boot::MemoryType::RUNTIME_SERVICES_DATA,
        stack_pages,
    ) {
        Ok(p) => {
            debug_println!("[LOADER] allocated stack at 0x{:x}", p.as_ptr() as u64);
            p.as_ptr() as u64
        }
        Err(e) => {
            debug_println!("[LOADER] stack alloc failed: {:?}", e);
            // Use UEFI stack region near 0x7FB40000
            0x7FB40000u64
        }
    };
    let stack_top = stack_base + (stack_pages * 4096) as u64;
    let bi_ptr = core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64;

    debug_println!(
        "[LOADER] jumping to kernel, bi_ptr=0x{:x} sp=0x{:x} boot_mode={}",
        bi_ptr,
        stack_top,
        unsafe { (*core::ptr::addr_of!(KERNEL_BOOT_INFO)).boot_mode }
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
        debug_println!(
            "[LOADER] BootInfo: esp=0x{:x}/{} sys=0x{:x}/{} ramdisk=0x{:x}/{} fb=0x{:x}/{}x{}",
            bi.esp_image_base,
            bi.esp_image_size,
            bi.sys_image_base,
            bi.sys_image_size,
            bi.ramdisk_image_base,
            bi.ramdisk_image_size,
            bi.framebuffer_base,
            bi.framebuffer_width,
            bi.framebuffer_height
        );
    }

    debug_println!("[WINLOAD]   transferring control to kernel_main (post-ExitBootServices)");

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
    debug_println!("--- Phase L09 ---");
    mark_winload_phase(8);
    let trampoline_addr = arch::current::install_kernel_handoff();
    debug_println!(
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
    debug_println!(
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
    debug_println!("--- Phase L10 ---");
    mark_winload_phase(9);
    // QEMU/OVMF frequently rejects the first ExitBootServices call
    // with INVALID_PARAMETER because some background firmware work
    // between our collect_memory_map() at L02 and now changed the
    // map_key. On the first failure we refresh the memory map and
    // retry exactly once. If the retry also fails, the firmware may
    // reclaim boot-services memory (the ESP/SYS mirrors, the hive
    // region and the image buffer all live there), so it is NOT safe
    // to hand control to the kernel: halt instead of continuing.
    let map_key = unsafe { (*core::ptr::addr_of!(PERSISTENT)).map_key };
    debug_println!(
        "[WINLOAD] L10: ExitBootServices(image_handle, map_key=0x{:x})",
        map_key
    );
    EXIT_BOOT_SERVICES_DONE.store(true, Ordering::Release);
    // `uefi::boot::image_handle()` returns the high-level
    // `uefi::Handle` newtype; `Handle` underneath is a raw pointer
    // (`*mut c_void`). The `BootServices::exit_boot_services`
    // table function (which is the raw `extern "efiapi"` pointer
    // pulled out of the system table below) takes that raw
    // pointer, so we unwrap it.
    let handle_ptr: *mut core::ffi::c_void = uefi::boot::image_handle().as_ptr();
    unsafe {
        let st = uefi::table::system_table_raw().expect("system table not set");
        let st_ref = st.as_ref();
        if let Some(bs_ptr) = st_ref.boot_services.as_ref() {
            let mut key = map_key;
            let mut status = (bs_ptr.exit_boot_services)(handle_ptr, key);
            debug_println!(
                "[WINLOAD] L10: ExitBootServices: status={:?} map_key=0x{:x}",
                status,
                key
            );
            if !status.is_success() {
                // Stale map key: refresh the map and retry once.
                debug_println!(
                    "[WINLOAD] L10: ExitBootServices failed; refreshing memory map and retrying once"
                );
                let pd = &mut *core::ptr::addr_of_mut!(PERSISTENT);
                let (n, fresh_key) = raw_get_memory_map_with_key(
                    &mut pd.memory_map,
                    &mut (*core::ptr::addr_of_mut!(MEM_MAP_BUF)).0,
                );
                if n > 0 {
                    pd.memory_map_count = n;
                }
                pd.map_key = fresh_key;
                key = fresh_key;
                debug_println!(
                    "[WINLOAD] L10: refreshed map_key=0x{:x} ({} entries); retrying ExitBootServices",
                    key,
                    n
                );
                status = (bs_ptr.exit_boot_services)(handle_ptr, key);
                debug_println!("[WINLOAD] L10: ExitBootServices retry: status={:?}", status);
            }
            if status.is_success() {
                debug_println!("[WINLOAD] L10: boot services terminated successfully");
            } else {
                debug_println!(
                    "[WINLOAD] L10: FATAL: ExitBootServices failed twice — the firmware may reclaim boot-services memory the kernel depends on; halting instead of jumping to the kernel"
                );
                loop {
                    core::hint::spin_loop();
                }
            }
        } else {
            debug_println!(
                "[WINLOAD] L10: boot_services pointer null; ExitBootServices not called"
            );
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
    debug_println!("--- Phase L11 ---");
    if !EXIT_BOOT_SERVICES_DONE.load(Ordering::Acquire) {
        mark_winload_phase(10);
    }
    let ki_va = ntoskrnl_base_l03 + kernel_entry_rva_l03;
    debug_println!(
        "[WINLOAD] L11: ntoskrnl_base=0x{:x} entry_rva=0x{:x} ki_va=0x{:x} stack=0x{:x} bi=0x{:x}",
        ntoskrnl_base_l03,
        kernel_entry_rva_l03,
        ki_va,
        stack_top,
        core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64
    );
    debug_println!(
        "[WINLOAD] L11: jumping to disk ntoskrnl.exe at 0x{:x} entry=0x{:x} stack_top=0x{:x}",
        ntoskrnl_base_l03,
        ki_va,
        stack_top
    );
    // Patch the callback field at end-of-.text with the host trampoline
    // address. The disk stub's `lea rax, [rip + disp]` points here.
    unsafe {
        arch::current::launch_kernel(
            stack_top,
            core::ptr::addr_of!(KERNEL_BOOT_INFO) as u64,
            ki_va,
        );
    }
}

// =====================================================================
// UEFI entry point
// =====================================================================
// The linker script groups .text.efi_main sections and uses ENTRY(efi_main).
// Put efi_main in its own section so it gets placed at the very start.

/// Firmware-supplied image handle, captured at `efi_main` entry. Used
/// to open the EFI_LOADED_IMAGE_PROTOCOL for chain-loaded launches.
static mut WINLOAD_IMAGE_HANDLE: u64 = 0;

/// Pool buffer holding our own PE bytes, served through the
/// EFI_LOAD_FILE_PROTOCOL below.
static mut LOAD_FILE_IMAGE_BASE: u64 = 0;
static mut LOAD_FILE_IMAGE_SIZE: u64 = 0;

static mut WINLOAD_LOAD_FILE_PROTOCOL: uefi_raw::protocol::media::LoadFileProtocol =
    uefi_raw::protocol::media::LoadFileProtocol {
        load_file: winload_load_file_callback,
    };

/// EFI_LOAD_FILE_PROTOCOL callback: serves the winload.efi image bytes
/// so bootmgfw (or the firmware BDS) can chain-load this loader via
/// LoadFile resolution instead of raw block reads.
extern "efiapi" fn winload_load_file_callback(
    _this: *mut uefi_raw::protocol::media::LoadFileProtocol,
    _file_path: *const uefi_raw::protocol::device_path::DevicePathProtocol,
    _boot_policy: uefi_raw::Boolean,
    buffer_size: *mut usize,
    buffer: *mut core::ffi::c_void,
) -> uefi::Status {
    let (base, size) = unsafe { (LOAD_FILE_IMAGE_BASE, LOAD_FILE_IMAGE_SIZE) };
    if base == 0 || size == 0 {
        return uefi::Status::UNSUPPORTED;
    }
    unsafe {
        let requested = &mut *buffer_size;
        if buffer.is_null() || *requested < size as usize {
            *requested = size as usize;
            return uefi::Status::BUFFER_TOO_SMALL;
        }
        core::ptr::copy_nonoverlapping(base as *const u8, buffer.cast::<u8>(), size as usize);
    }
    uefi::Status::SUCCESS
}

/// Capture our own PE image bytes into a boot-services pool buffer and
/// install the EFI_LOAD_FILE_PROTOCOL on a fresh handle. Returns the
/// new handle on success. Safe to skip: the direct-launch path does
/// not depend on the protocol.
unsafe fn install_load_file_protocol() -> Option<uefi::Handle> {
    const SELF_PATHS: [&str; 2] = [
        "\\EFI\\Microsoft\\Boot\\winload.efi",
        "\\Windows\\System32\\winload.efi",
    ];
    let mut image: Option<Vec<u8>> = None;
    for path in SELF_PATHS {
        if let Some(data) = open_system_file_data(path) {
            image = Some(data);
            break;
        }
    }
    let image = image?;
    let pool = uefi::boot::allocate_pool(uefi::boot::MemoryType::LOADER_DATA, image.len()).ok()?;
    core::ptr::copy_nonoverlapping(image.as_ptr(), pool.as_ptr(), image.len());
    LOAD_FILE_IMAGE_BASE = pool.as_ptr() as u64;
    LOAD_FILE_IMAGE_SIZE = image.len() as u64;
    let handle = uefi::boot::install_protocol_interface(
        None,
        &uefi_raw::protocol::media::LoadFileProtocol::GUID,
        core::ptr::addr_of!(WINLOAD_LOAD_FILE_PROTOCOL).cast(),
    )
    .ok()?;
    debug_println!(
        "[WINLOAD] EFI_LOAD_FILE_PROTOCOL installed on handle 0x{:x}",
        handle.as_ptr() as u64
    );
    Some(handle)
}

/// The device handle winload.efi itself was loaded from, obtained via
/// the EFI_LOADED_IMAGE_PROTOCOL. When bootmgfw chain-loads this
/// loader, this is the authoritative ESP handle; no BlockIO scan
/// needed.
fn chain_loaded_device_handle() -> Option<uefi::Handle> {
    let raw = unsafe { WINLOAD_IMAGE_HANDLE };
    if raw == 0 {
        return None;
    }
    let image = unsafe { uefi::Handle::from_ptr(raw as *mut core::ffi::c_void)? };
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::loaded_image::LoadedImage;
    let loaded = unsafe {
        uefi::boot::open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let device = loaded.get().and_then(|img| img.device());
    drop(loaded);
    device
}

/// True when `handle` exposes the SimpleFileSystem protocol.
fn device_has_simple_filesystem(handle: uefi::Handle) -> bool {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::fs::SimpleFileSystem;
    match unsafe {
        uefi::boot::open_protocol::<SimpleFileSystem>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(scoped) => {
            let ok = scoped.get().is_some();
            drop(scoped);
            ok
        }
        Err(_) => false,
    }
}

#[link_section = ".text.efi_main"]
#[no_mangle]
extern "efiapi" fn efi_main(_image: uefi::Handle, _st: *const core::ffi::c_void) -> uefi::Status {
    crate::arch::current::write_com1_marker(b"[WINLOAD] entered\r\n");

    // Capture the firmware image handle for LoadedImage-based device
    // discovery before anything else touches it.
    unsafe {
        WINLOAD_IMAGE_HANDLE = _image.as_ptr() as u64;
    }

    // Set up UEFI globals — this MUST be done before calling any uefi crate functions.
    // SAFETY: image_handle and system_table are valid per UEFI calling convention.
    unsafe {
        uefi::boot::set_image_handle(_image);
        uefi::table::set_system_table(_st.cast());
    }

    arch::current::write_debug_marker(b"WINL>\r\n");

    debug_println!("[WINLOAD] before helpers init");
    if let Err(_e) = uefi::helpers::init() {
        // ignored
    }
    debug_println!("[WINLOAD] after helpers init");

    // Cache the ESP / System SimpleFileSystem handles BEFORE any other
    // boot-services activity.
    debug_println!("[WINLOAD] before cache_esp_sfs_handle");
    cache_esp_sfs_handle();
    debug_println!("[WINLOAD] after cache_esp_sfs_handle");
    debug_println!("[WINLOAD] before cache_system_sfs_handle");
    cache_system_sfs_handle();
    debug_println!("[WINLOAD] after cache_system_sfs_handle");

    // Expose winload.efi through the EFI_LOAD_FILE_PROTOCOL so bootmgfw
    // can chain-load us through the standard UEFI resolution path.
    unsafe {
        let _ = install_load_file_protocol();
    }

    // Run the OS Loader — on success this never returns.
    os_loader_run();

    // NOTREACHED — os_loader_run is `!`. But if we somehow get here (e.g.,
    // the kernel panic loop exits), hang to prevent bootmgr from loading ntoskrnl.exe.
}
