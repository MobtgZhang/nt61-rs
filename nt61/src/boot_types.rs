//! Boot-time types shared by the kernel, the bare-metal stub, and
//! the UEFI `winload.efi`.
//
//! The original NT 6.1 equivalent is `LOADER_PARAMETER_BLOCK`
//! (`ntos\inc\ketypes.h`, filled in by `winload.exe` and consumed by
//! `ntoskrnl` during `Phase 0`/`Phase 1`). Our equivalent is a
//! much smaller `BootInfo` struct passed by value through `rdi`.
//
//! All three boot paths (multiboot stub, UEFI winload, and the
//! legacy QEMU direct-load path) build a `BootInfo` with the same
//! `#[repr(C)]` layout, so the kernel-side code here is the
//! *single* source of truth. Putting the type in a dedicated
//! module — instead of inlining it into `kernel_main` and
//! re-defining a parallel copy in `mm` — keeps the boot
//! contract honest: the fields the kernel expects are exactly
//! the fields the loader emits, and a compiler error fires the
//! moment any of them drifts.
//
//! # Phase change history
//
//!   * 2026-06: original 16-field structure (framebuffer + ESP mirror).
//!   * 2026-07-01: ESP image-base / size added (FAT32 mirror).
//!   * 2026-07-02: System partition mirror added.
//!   * 2026-07-02: Memory-diagnostic block added for Phase 1a.
//
//! No new field may be appended at the *end* of the struct without
//! a bump to `BootInfo::MAGIC` — that gives the loader a chance to
//! reject kernels compiled against an older contract.

/// Boot mode selected by `bootmgr` and forwarded to the kernel via
/// `BootInfo.boot_mode`. The kernel uses this to gate certain
/// init-time behaviour (e.g. spawn the Safe-Mode CMD shell instead
/// of going straight to IDLE, or enable the debug logger).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Default — full Windows 7 startup, drivers + services +
    /// SMSS + CSRSS + IDLE.
    Normal = 0,
    /// Safe Mode with Command Prompt — boot only the core drivers
    /// and drop into a `cmd.exe`-style shell instead of the
    /// graphical subsystem.
    SafeModeCmd = 1,
    /// Debug boot — enable the kernel debugger transport (kdcom)
    /// and stream every `[kdbg]` line to COM1 before IDLE.
    SafeModeDebug = 2,
}

impl BootMode {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => BootMode::Normal,
            1 => BootMode::SafeModeCmd,
            2 => BootMode::SafeModeDebug,
            _ => BootMode::Normal,
        }
    }
}

/// A single hive image passed by `winload.efi` to the kernel
/// via the `BootInfo.hives` pointer. The bytes are pinned in
/// physical memory that survives `ExitBootServices` and is
/// never reused by the kernel's allocator.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LoadedHive {
    pub name: [u8; 32],
    pub name_len: u32,
    pub ptr: u64,
    pub len: u32,
    pub _reserved: u32,
}

impl LoadedHive {
    pub const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            ptr: 0,
            len: 0,
            _reserved: 0,
        }
    }
}

/// Maximum number of loaded hives the loader can pass in
/// `BootInfo`. Must match `registry::cm::BOOTINFO_MAX_HIVES`
/// and `MAX_HIVES` in `winload/src/main.rs`.
pub const BOOTINFO_MAX_HIVES: usize = 8;

/// Boot information passed from bootloader.
///
/// This must match the layout used by every loader (the bare-metal
/// stub in `src/main.rs`, the UEFI loader in `src/winload/`, and
/// any future loader). The fields mirror the Windows 7
/// `LOADER_PARAMETER_BLOCK` essentials, in a much smaller form.
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u64,
    pub kernel_physical_base: u64,
    pub kernel_virtual_base: u64,
    pub kernel_size: u64,
    pub memory_map: u64,
    pub memory_map_entries: u64,
    /// Total size of the memory map buffer in bytes.
    /// Useful for kernel to detect if truncation occurred.
    pub memory_map_size_bytes: u64,
    /// Size of each memory descriptor in bytes.
    /// Allows kernel to interpret the memory map correctly.
    pub memory_descriptor_size: u32,
    /// Reserved for alignment
    pub _reserved: u32,
    pub cmdline: u64,
    pub acpi_rsdp: u64,
    pub smp_info: u64,
    /// Physical address of a `LoadedHiveList` (an array of
    /// `LoadedHive` of length `hive_count`).
    pub hives: u64,
    pub hive_count: u32,
    /// Boot mode (one of `BootMode::*`).
    pub boot_mode: u32,
    /// ESP disk start sector (for FAT32 filesystem access in CMD).
    /// The LBA is on the *raw* disk (not the partition) because we
    /// do not yet have a virtio-blk driver. Winload converts the
    /// partition-relative LBA to a disk-relative LBA using the
    /// `DiskIO` protocol before populating this field.
    pub esp_disk_start: u64,
    /// ESP disk sector count.
    pub esp_disk_sectors: u64,
    /// Number of boot drivers loaded by winload
    pub boot_driver_count: u32,
    /// Reserved for alignment
    pub _reserved2: u32,

    // =====================================================================
    // ESP in-memory mirror (added 2026-07-01)
    // =====================================================================
    /// Physical address of a contiguous buffer holding a snapshot
    /// of the entire ESP partition (or as much of it as fits in
    /// memory). The buffer is `esp_image_size` bytes long and
    /// contains a verbatim copy of the partition's blocks as
    /// returned by `EFI_BLOCK_IO_PROTOCOL::ReadBlocks`.
    ///
    /// The kernel uses this buffer as a `RamDisk`-style backing
    /// store for the FAT32 driver in CMD until a real
    /// AHCI/virtio-blk driver becomes available. When this field
    /// is zero, the kernel falls back to the built-in directory
    /// listing (the old behaviour).
    pub esp_image_base: u64,
    /// Total size of the ESP mirror in bytes.
    pub esp_image_size: u64,
    /// Block size of the underlying disk (typically 512). The FAT
    /// driver uses this to translate cluster numbers into buffer
    /// offsets inside `esp_image_base`.
    pub esp_block_size: u32,
    /// Pad to keep the struct 8-byte aligned.
    pub _reserved3: u32,

    // =====================================================================
    // System partition in-memory mirror (added 2026-07-02)
    // =====================================================================
    /// Physical address of a contiguous buffer holding a snapshot
    /// of the Windows system partition (the second FAT32 partition
    /// on the disk). Same semantics as `esp_image_base` but for
    /// the system partition. Zero means no mirror (kernel falls
    /// back to its built-in stub).
    pub sys_image_base: u64,
    /// Total size of the system partition mirror in bytes.
    pub sys_image_size: u64,
    /// Block size of the underlying disk (typically 512) for the
    /// system partition. Same as `esp_block_size` on the same disk.
    pub sys_block_size: u32,
    /// Pad to keep the struct 8-byte aligned.
    pub _reserved4: u32,

    // =====================================================================
    // ISO boot RAM disk (added 2026-07-02)
    // =====================================================================
    /// Physical address of a contiguous buffer holding the ISO boot
    /// RAM disk image (the `nt61.img` FAT32 embedded in the ISO).
    /// This is only populated for ISO boot; for disk-booted images
    /// this field is always zero.
    pub ramdisk_image_base: u64,
    /// Total size of the ISO RAM disk image in bytes.
    pub ramdisk_image_size: u64,
    /// Block size of the ISO image filesystem (typically 512).
    pub ramdisk_block_size: u32,
    /// Pad to keep the struct 8-byte aligned.
    pub _reserved5: u32,

    // =====================================================================
    // Graphics / Framebuffer Information (for graphical boot UI)
    // =====================================================================
    /// Physical address of framebuffer
    pub framebuffer_base: u64,
    /// Framebuffer size in bytes
    pub framebuffer_size: u64,
    /// Framebuffer width in pixels
    pub framebuffer_width: u32,
    /// Framebuffer height in pixels
    pub framebuffer_height: u32,
    /// Framebuffer stride (bytes per row)
    pub framebuffer_stride: u32,
    /// Framebuffer pixel format (0=BGRA, 1=RGBA, 2=BGR, 3=RGB)
    pub framebuffer_format: u32,
    /// Reserved
    pub _reserved_gfx: u32,

    // =====================================================================
    // Memory Diagnostic Information
    // =====================================================================
    /// Memory test results buffer physical address
    pub memtest_base: u64,
    /// Memory test results buffer size
    pub memtest_size: u64,
    /// Memory test signature ("MTES")
    pub memtest_signature: u32,
    /// Memory test status (0=not run, 1=running, 2=passed, 3=failed)
    pub memtest_status: u32,

    // =====================================================================
    // NTFS-loaded kernel images (added 2026-07-09)
    // =====================================================================
    // The real Windows 7 boot sequence has winload.efi read ntoskrnl.exe
    // and hal.dll from the NTFS System partition, then jump to the
    // kernel's entry point. Our boot flow used to bake these binaries
    // directly into the kernel as "in-binary" stubs (see
    // `system_image::build_all`). This field carries the on-disk ntoskrnl
    // bytes across ExitBootServices so the kernel can map them itself
    // instead of relying on a baked-in copy.
    /// Physical address of `ntoskrnl.exe` bytes read from the NTFS
    /// system partition by winload. The buffer is allocated as
    /// `EfiRuntimeServicesData` so it survives `ExitBootServices`.
    /// Zero means "no on-disk ntoskrnl; the kernel should fall back to
    /// the embedded image" (only valid for the bring-up build).
    pub ntoskrnl_image_base: u64,
    /// Size of the ntoskrnl.exe image in bytes.
    pub ntoskrnl_image_size: u64,
    /// Physical address of `hal.dll` bytes read from NTFS. Same
    /// semantics as `ntoskrnl_image_base`.
    pub hal_image_base: u64,
    /// Size of the hal.dll image in bytes.
    pub hal_image_size: u64,
    /// Physical address of `bootvid.dll` bytes (loaded by winload as a
    /// BOOT_START_IMAGE before ExitBootServices so the kernel can call
    /// into its Inbv* exports during Phase 0/1 video bring-up).
    pub bootvid_image_base: u64,
    /// Size of the bootvid.dll image in bytes.
    pub bootvid_image_size: u64,
    /// Address of the host `ntoskrnl_kisystemstartup_thunk` (a
    /// `extern "C" fn(*const BootInfo) -> !`). The on-disk
    /// `ntoskrnl.exe!KiSystemStartup` stub reads this via
    /// `boot_info->ntoskrnl_handoff_callback` and `call`s it
    /// directly — no fixed slot indirection needed. This field is
    /// populated by winload *before* the jump to the disk stub;
    /// the value is the runtime address of the trampoline computed
    /// via RIP-relative LEA in `install_handoff_pointer`.
    pub ntoskrnl_handoff_callback: u64,
}

impl BootInfo {
    /// "NT61BOOT" — ASCII for the magic value.
    pub const MAGIC: u64 = 0x4E543631_424F4F54;
    /// Current contract version. Bumped whenever a field is added
    /// or removed. Match this against the loader's build constant.
    pub const VERSION: u64 = 6;

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC
    }

    /// Build a `BootInfo` with sane defaults for bring-up paths
    /// (bare-metal stub, automated tests). Real boot flows always
    /// replace this with the loader-emitted struct.
    pub fn defaults() -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            kernel_physical_base: 0x100000,
            kernel_virtual_base: 0x100000,
            kernel_size: 0,
            memory_map: 0,
            memory_map_entries: 0,
            memory_map_size_bytes: 0,
            memory_descriptor_size: 24,
            _reserved: 0,
            cmdline: 0,
            acpi_rsdp: 0,
            smp_info: 0,
            hives: 0,
            hive_count: 0,
            boot_mode: BootMode::Normal as u32,
            esp_disk_start: 0,
            esp_disk_sectors: 0,
            boot_driver_count: 0,
            _reserved2: 0,
            esp_image_base: 0,
            esp_image_size: 0,
            esp_block_size: 512,
            _reserved3: 0,
            sys_image_base: 0,
            sys_image_size: 0,
            sys_block_size: 512,
            _reserved4: 0,
            ramdisk_image_base: 0,
            ramdisk_image_size: 0,
            ramdisk_block_size: 512,
            _reserved5: 0,
            framebuffer_base: 0,
            framebuffer_size: 0,
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_stride: 0,
            framebuffer_format: 0,
            _reserved_gfx: 0,
            memtest_base: 0,
            memtest_size: 0,
            memtest_signature: 0,
            memtest_status: 0,
            ntoskrnl_image_base: 0,
            ntoskrnl_image_size: 0,
            hal_image_base: 0,
            hal_image_size: 0,
            bootvid_image_base: 0,
            bootvid_image_size: 0,
            ntoskrnl_handoff_callback: 0,
        }
    }

    /// Zero-filled `BootInfo` for paths that legitimately have no
    /// loader-supplied context (e.g. `cargo test` harnesses).
    pub fn zeroed() -> Self {
        Self {
            magic: Self::MAGIC,
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
            boot_mode: BootMode::Normal as u32,
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
            framebuffer_base: 0,
            framebuffer_size: 0,
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_stride: 0,
            framebuffer_format: 0,
            _reserved_gfx: 0,
            memtest_base: 0,
            memtest_size: 0,
            memtest_signature: 0,
            memtest_status: 0,
            ntoskrnl_image_base: 0,
            ntoskrnl_image_size: 0,
            hal_image_base: 0,
            hal_image_size: 0,
            bootvid_image_base: 0,
            bootvid_image_size: 0,
            ntoskrnl_handoff_callback: 0,
        }
    }
}
