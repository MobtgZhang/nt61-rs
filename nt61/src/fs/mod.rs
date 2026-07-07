//! File System Module
//
//! Virtual File System and file system implementations
//! Implements NT-style I/O manager with file system drivers

// FS module uses NT-driver naming (FCB, VCB, IRP_MJ_*, ...).

pub mod vfs;
pub mod fat32;
pub mod ntfs;
#[cfg(target_arch = "x86_64")]
pub mod ext2;   // ext2/ext3/ext4 filesystem support
#[cfg(target_arch = "x86_64")]
pub mod refs;    // ReFS (Resilient File System) support
pub mod windows_paths; // Windows 7 path and directory mapping
pub mod smoke;

use crate::ke::sync::Spinlock;

/// Device selection strategy for filesystem operations.
#[derive(Debug, Clone, Copy)]
pub enum DeviceSelection {
    /// Use the first available device
    FirstAvailable,
    /// Use a specific device by index
    ByIndex(usize),
    /// Use a device by storage type (RAM disk, AHCI, etc.)
    ByType(StorageDeviceType),
}

/// Storage device types for selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StorageDeviceType {
    Unknown = 0,
    AhciDisk = 1,
    RamDisk = 2,
    VirtioDisk = 3,
}

impl DeviceSelection {
    /// Select a device based on the strategy.
    /// Returns the device ID, or None if no suitable device found.
    pub fn select(&self) -> Option<usize> {
        match self {
            DeviceSelection::FirstAvailable => {
                // Try to get the first available device
                let count = crate::drivers::storage::device_count();
                if count > 0 {
                    Some(0)
                } else {
                    None
                }
            }
            DeviceSelection::ByIndex(index) => {
                // Check if the specific device exists
                if crate::drivers::storage::is_device_present(*index) {
                    Some(*index)
                } else {
                    None
                }
            }
            DeviceSelection::ByType(_device_type) => {
                // Search for a device of the specified type
                let count = crate::drivers::storage::device_count();
                for i in 0..count {
                    if let Some(device) = crate::drivers::storage::get_device(i) {
                        let matches = match (self, device.device_type) {
                            (DeviceSelection::ByType(StorageDeviceType::RamDisk), 
                             crate::drivers::storage::StorageDeviceType::RamDisk) => true,
                            (DeviceSelection::ByType(StorageDeviceType::AhciDisk),
                             crate::drivers::storage::StorageDeviceType::AhciDisk) => true,
                            _ => false,
                        };
                        if matches && device.present {
                            return Some(i);
                        }
                    }
                }
                None
            }
        }
    }

    /// Get the first available device.
    pub fn first_available() -> Option<usize> {
        Self::FirstAvailable.select()
    }
}

/// File system type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileSystemType {
    Unknown = 0,
    Fat12 = 1,
    Fat16 = 2,
    Fat32 = 3,
    Ntfs = 4,
    ExFat = 5,
    Cdfs = 6,
    Udfs = 7,
    // === ext2/ext3/ext4 support ===
    Ext2 = 8,
    Ext3 = 9,
    Ext4 = 10,
    // === ReFS support ===
    Refs = 11,
}

/// File system error codes (NT-style status codes).
/// These are modeled after Windows NT status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsError {
    /// Operation completed successfully
    Success = 0,

    // File/object not found errors
    /// File not found
    FileNotFound = 0xC000000F,
    /// Path not found
    PathNotFound = 0xC000003A,
    /// No such file
    NoSuchFile = 0xC0000229,  // STATUS_NO_SUCH_FILE
    /// Object name invalid
    ObjectNameInvalid = 0xC0000033,
    /// Object path not found
    ObjectPathNotFound = 0xC000003B,  // Use a different value

    // Access control errors
    /// Access denied
    AccessDenied = 0xC0000022,
    /// Access violation
    AccessViolation = 0xC0000005,
    /// Cannot delete file not closed
    DeletePending = 0xC0000056,

    // Object type errors
    /// Not a directory
    NotADirectory = 0xC0000103,
    /// Is a directory
    IsADirectory = 0xC00000BA,
    /// File is a directory (alias)
    FileIsADirectory = 0xC00000BB,  // Different value for alias
    /// Directory not empty
    DirectoryNotEmpty = 0xC0000101,

    // File system errors
    /// Disk full
    DiskFull = 0xC000007F,
    /// File system limit exceeded
    FileSystemLimit = 0xC0000034,
    /// Invalid parameter
    InvalidParameter = 0xC000000D,
    /// Invalid device request
    InvalidDeviceRequest = 0xC0000010,

    // I/O errors
    /// End of file
    EndOfFile = 0xC0000011,
    /// Buffer overflow
    BufferOverflow = 0xC0000035,
    /// Data error (CRC check failed)
    DataError = 0xC000003E,
    /// Disk corruption detected
    DiskCorrupt = 0xC0000032,

    // Object collision errors
    /// Object name collision
    ObjectNameCollision = 0xC0000063,
    /// Object ID collision
    ObjectIdCollision = 0xC0000058,

    // Media errors
    /// Media write protected
    MediaWriteProtected = 0xC00000A8,
    /// Media not present
    MediaNotPresent = 0xC0000012,
    /// Device not ready
    DeviceNotReady = 0xC00000E3,

    // Lock violations
    /// File lock conflict
    LockNotGranted = 0xC0000052,
    /// File lock conflict with read
    LockConflict = 0xC0000051,

    // Sharing violations
    /// Sharing violation
    SharingViolation = 0xC0000043,

    // Volume errors
    /// Volume not mounted
    VolumeNotMounted = 0xC00000E6,

    // Unknown/internal error
    Unknown = 0xFFFFFFFF,
}

impl FsError {
    /// Convert error to NT status code.
    pub fn to_status(&self) -> u32 {
        *self as u32
    }

    /// Create error from NT status code.
    pub fn from_status(status: u32) -> Self {
        match status {
            0 => FsError::Success,
            0xC000000F => FsError::FileNotFound,
            0xC000003A => FsError::PathNotFound,
            0xC0000033 => FsError::ObjectNameInvalid,
            0xC0000022 => FsError::AccessDenied,
            0xC0000005 => FsError::AccessViolation,
            0xC0000103 => FsError::NotADirectory,
            0xC00000BA => FsError::IsADirectory,
            0xC0000101 => FsError::DirectoryNotEmpty,
            0xC000007F => FsError::DiskFull,
            0xC0000034 => FsError::FileSystemLimit,
            0xC000000D => FsError::InvalidParameter,
            0xC0000011 => FsError::EndOfFile,
            0xC000003E => FsError::DataError,
            0xC0000032 => FsError::DiskCorrupt,
            0xC0000063 => FsError::ObjectNameCollision,
            0xC00000A8 => FsError::MediaWriteProtected,
            0xC0000010 => FsError::MediaNotPresent,
            0xC00000E3 => FsError::DeviceNotReady,
            0xC0000043 => FsError::SharingViolation,
            0xC00000E6 => FsError::VolumeNotMounted,
            _ => FsError::Unknown,
        }
    }

    /// Check if this error represents success.
    pub fn is_success(&self) -> bool {
        *self == FsError::Success
    }

    /// Get a human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            FsError::Success => "Success",
            FsError::FileNotFound => "File not found",
            FsError::PathNotFound => "Path not found",
            FsError::NoSuchFile => "No such file",
            FsError::ObjectNameInvalid => "Object name invalid",
            FsError::ObjectPathNotFound => "Object path not found",
            FsError::AccessDenied => "Access denied",
            FsError::AccessViolation => "Access violation",
            FsError::DeletePending => "Cannot delete - file not closed",
            FsError::NotADirectory => "Not a directory",
            FsError::IsADirectory => "Is a directory",
            FsError::FileIsADirectory => "File is a directory",
            FsError::DirectoryNotEmpty => "Directory not empty",
            FsError::DiskFull => "Disk full",
            FsError::FileSystemLimit => "File system limit exceeded",
            FsError::InvalidParameter => "Invalid parameter",
            FsError::InvalidDeviceRequest => "Invalid device request",
            FsError::EndOfFile => "End of file",
            FsError::BufferOverflow => "Buffer overflow",
            FsError::DataError => "Data error",
            FsError::DiskCorrupt => "Disk corruption detected",
            FsError::ObjectNameCollision => "Object name collision",
            FsError::ObjectIdCollision => "Object ID collision",
            FsError::MediaWriteProtected => "Media write protected",
            FsError::MediaNotPresent => "Media not present",
            FsError::DeviceNotReady => "Device not ready",
            FsError::LockNotGranted => "Lock not granted",
            FsError::LockConflict => "Lock conflict",
            FsError::SharingViolation => "Sharing violation",
            FsError::VolumeNotMounted => "Volume not mounted",
            FsError::Unknown => "Unknown error",
        }
    }
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Result type for filesystem operations using FsError.
pub type FsResult<T> = Result<T, FsError>;

/// File system information
pub struct FileSystemInfo {
    pub fs_type: FileSystemType,
    pub volume_name: [u16; 64],
    pub serial_number: u32,
    pub flags: u32,
}

/// Registered file systems (simplified - fixed size array)
pub static FILE_SYSTEMS: Spinlock<FileSystemRegistry> =
    Spinlock::new(FileSystemRegistry::new());

pub struct FileSystemRegistry {
    pub drivers: [*mut FileSystemDriver; 8],
    pub count: usize,
}

impl FileSystemRegistry {
    pub const fn new() -> Self {
        Self {
            drivers: [core::ptr::null_mut(); 8],
            count: 0,
        }
    }
}

/// File system driver structure
pub struct FileSystemDriver {
    pub name: [u16; 8],
    pub fs_type: FileSystemType,
    pub mount: Option<fn(device: *mut (), path: &[u16]) -> *mut FileSystem>,
    pub unmount: Option<fn(fs: *mut FileSystem)>,
}

/// File system instance
pub struct FileSystem {
    pub driver: *mut FileSystemDriver,
    pub device: *mut (),
    pub volume_name: [u16; 64],
    pub fs_type: FileSystemType,
    pub sector_size: u32,
    pub cluster_size: u32,
    pub total_clusters: u64,
    pub free_clusters: u64,
}

/// Volume control block (VCB)
pub struct Vcb {
    pub header: DispatcherHeader,
    pub device_object: *mut (),
    pub fs_rec: *mut (),
    pub fs_type: FileSystemType,
    pub volume_label: [u16; 64],
    pub serial_number: u32,
    pub sector_size: u32,
    pub cluster_size: u32,
}

impl Vcb {
    pub fn new() -> Self {
        Self {
            header: DispatcherHeader::new(0),
            device_object: core::ptr::null_mut(),
            fs_rec: core::ptr::null_mut(),
            fs_type: FileSystemType::Unknown,
            volume_label: [0; 64],
            serial_number: 0,
            sector_size: 512,
            cluster_size: 4096,
        }
    }
}

/// File object (FOBC)
pub struct FileObject {
    pub header: ObjectHeader,
    pub device_object: *mut (),
    pub vpb: *mut Vcb,
    pub fs_context: *mut (),
    pub fs_context2: *mut (),
    pub section_of_pointer: *mut (),
    pub access_mode: u8,
    pub shared_read: bool,
    pub shared_write: bool,
    pub shared_delete: bool,
    pub flags: u32,
    pub file_name: UnicodeString,
    pub current_byte_offset: i64,
    pub final_status: i32,
}

/// Object header (from ob module)
#[repr(C)]
pub struct ObjectHeader {
    pub pointer_count: i64,
    pub handle_count: i64,
    pub object_type: *mut ObjectType,
    pub name: *const u16,
    pub root_directory: *mut (),
}

/// Object type (from ob module)
pub struct ObjectType {
    pub _reserved: u64,
}

/// Unicode string (NT-compatible layout)
#[repr(C)]
pub struct UnicodeString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UnicodeString {
    pub fn new() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        }
    }
}

/// Dispatcher header (from ke module)
#[repr(C)]
pub struct DispatcherHeader {
    pub type_: u8,
    pub signal_state: u8,
    pub size: u16,
    pub inserted: u8,
    pub spare: [u8; 3],
}

impl DispatcherHeader {
    /// Create a new dispatcher header.
    /// `object_type` is stored in the type field for object type identification.
    pub fn new(object_type: u8) -> Self {
        Self {
            type_: object_type,
            signal_state: 0,
            size: 0,
            inserted: 0,
            spare: [0; 3],
        }
    }
}

/// Register a file system driver
pub fn register(filesystem: *mut FileSystemDriver) {
    let mut fs_list = FILE_SYSTEMS.lock();
    if fs_list.count < fs_list.drivers.len() {
        let idx = fs_list.count;
        fs_list.drivers[idx] = filesystem;
        fs_list.count += 1;
    }
}

/// Unregister a file system driver from the registry.
pub fn unregister(filesystem: *mut FileSystemDriver) {
    let mut fs_list = FILE_SYSTEMS.lock();
    
    // Search for the filesystem in the registry and remove it
    let mut found = false;
    for i in 0..fs_list.count {
        if fs_list.drivers[i] == filesystem {
            found = true;
        }
        // Shift remaining drivers down
        if found && i + 1 < fs_list.count {
            fs_list.drivers[i] = fs_list.drivers[i + 1];
        }
    }
    
    if found && fs_list.count > 0 {
        let new_count = fs_list.count - 1;
        fs_list.count = new_count;
        fs_list.drivers[new_count] = core::ptr::null_mut();
    }
    
    // Prevent unused variable warning - filesystem pointer used for comparison above
    let _ = filesystem;
}

/// Mount a file system
/// Allocates a new FileSystem structure and initializes it with the given device and type.
pub fn mount(device: *mut (), _path: &[u16], fs_type: FileSystemType) -> Option<&'static mut FileSystem> {
    let fs = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<FileSystem>(),
    ) as *mut FileSystem;
    
    if !fs.is_null() {
        // Avoid the aggregate `core::ptr::write(fs, FileSystem {...})`
        // pattern that emits a non-temporal SSE store on the
        // compiler's behalf. The pool backs onto heap memory which
        // can be UC-typed (MTRR set by the firmware), and UC memory
        // does not behave like Write-Back memory: non-temporal
        // stores are silently dropped. Field-by-field assignment
        // compiles down to a sequence of normal scalar stores.
        unsafe {
            (*fs).driver = core::ptr::null_mut();
            (*fs).device = device;
            (*fs).volume_name = [0; 64];
            (*fs).fs_type = fs_type;
            (*fs).sector_size = 512;
            (*fs).cluster_size = 4096;
            (*fs).total_clusters = 0;
            (*fs).free_clusters = 0;
        }

        return unsafe { fs.as_mut() };
    }

    None
}

/// Unmount a file system
pub fn unmount(fs: *mut FileSystem) {
    if !fs.is_null() {
        unsafe {
            // Flush buffers, close handles, etc.
            core::ptr::drop_in_place(&mut (*fs));
        }
        let _ = crate::mm::pool::free(fs as *mut u8);
    }
}

/// Initialize file systems
pub fn init() {
    // Register FAT32 driver
    crate::boot_println!("[FS-INIT] registering FAT32");
    fat32::register_driver();

    // Register NTFS driver
    crate::boot_println!("[FS-INIT] registering NTFS");
    ntfs::register_driver();

    // Register EXT2/EXT3/EXT4 driver (shares infrastructure with ext2).
    // ext2 / ext3 / ext4 are gated to x86_64 because the AHCI
    // controller used by them is x86_64-only in this build.
    #[cfg(target_arch = "x86_64")]
    {
        crate::boot_println!("[FS-INIT] registering EXT2");
        ext2::register_driver();
    }

    // Bring up the VFS layer (creates the root VfsNode).
    crate::boot_println!("[FS-INIT] calling vfs::init");
    vfs::init();
    crate::boot_println!("[FS-INIT] vfs::init returned");

    // Mount the ESP (Z:) — always FAT32 by UEFI convention.
    crate::boot_println!("[FS-INIT] calling mount_esp_partition");
    mount_esp_partition();
    crate::boot_println!("[FS-INIT] mount_esp_partition returned");

    // Mount the System partition (C:). The actual filesystem type
    // (FAT32 / NTFS / ext2/3/4) is probed at runtime by
    // `mount_partition_detected`, so this single call covers the
    // (FAT32,FAT32), (FAT32,NTFS) and (FAT32,ext4) image layouts.
    crate::boot_println!("[FS-INIT] calling mount_system_partition");
    mount_system_partition();
    crate::boot_println!("[FS-INIT] mount_system_partition returned");
}

/// FAT32 device backed by an in-memory snapshot of the ESP.
/// Created by `mount_esp_from_bootinfo` when `BootInfo.esp_image_base`
/// is non-zero. The driver treats the buffer as a contiguous
/// byte stream; the FAT32 parser walks clusters entirely from
/// memory and never touches the underlying disk.
pub struct EspRamdisk {
    /// Virtual address of the ESP mirror. Set by
    /// `mount_esp_from_bootinfo` once the kernel has mapped the
    /// physical address from `BootInfo`.
    base: *const u8,
    /// Size of the mirror in bytes.
    size: usize,
    /// Underlying block size (typically 512).
    block_size: u32,
}

/// Singleton that holds the RAM-disk metadata for the FAT32
/// driver. `None` until `mount_fat32_partition` succeeds.
static ESP_RAMDISK: Spinlock<Option<EspRamdisk>> = Spinlock::new(None);

/// Singleton that holds the RAM-disk metadata for the Windows
/// System partition (the second FAT32 partition on the disk).
/// `None` until `mount_sys_from_bootinfo` succeeds. The polled
/// CMD shell uses this to read files that live on the system
/// partition (e.g. `C:\tests\autoexec.bat`).
static SYS_RAMDISK: Spinlock<Option<EspRamdisk>> = Spinlock::new(None);

/// Singleton for the ISO boot RAM disk (the combined FAT32 image
/// embedded in the ISO at `EFI/Microsoft/Boot/nt61.img`).
/// Populated by `mount_ramdisk_from_bootinfo` for ISO boot;
/// the X: drive exposes this partition to user-mode code.
static RAMDISK_IMAGE: Spinlock<Option<EspRamdisk>> = Spinlock::new(None);

/// Boot-time size of the system partition in bytes. Captured by
/// `mount_sys_from_bootinfo` so the EXT4 mount path can size the
/// global RAM_DISK it installs.
static SYS_PARTITION_SIZE: Spinlock<usize> = Spinlock::new(0);
/// Block size of the system partition (typically 512).
static SYS_PARTITION_SECTOR_SIZE: Spinlock<usize> = Spinlock::new(512);

/// Return the raw mirror pointer for the ESP partition, or `None`
/// if winload did not populate one.
pub fn esp_mirror_address() -> Option<*const u8> {
    ESP_RAMDISK.lock().as_ref().map(|d| d.base)
}

/// Return the raw mirror pointer for the System partition, or `None`
/// if winload did not populate one.
pub fn sys_mirror_address() -> Option<*const u8> {
    SYS_RAMDISK.lock().as_ref().map(|d| d.base)
}

/// Return the size in bytes of the System partition mirror, or `None`.
pub fn sys_mirror_size() -> Option<usize> {
    SYS_RAMDISK.lock().as_ref().map(|d| d.size)
}

/// Return the size in bytes of the ESP partition mirror, or `None`.
pub fn esp_mirror_size() -> Option<usize> {
    ESP_RAMDISK.lock().as_ref().map(|d| d.size)
}

/// Detect which filesystem type is on the System partition (C:).
/// Returns `FsType` so callers can dispatch to the right driver
/// without hard-coding "NTFS" or "FAT32". Used by `load_cmd_exe_from_disk`
/// in the boot path to pick the right FS driver for reading cmd.exe.
pub fn detect_system_partition_type() -> FsType {
    match sys_mirror_address() {
        Some(base) => detect_fs_type(base),
        None => FsType::Unknown,
    }
}

/// Accessor for the System partition size (filled by
/// `mount_sys_from_bootinfo`).
pub fn sys_partition_size() -> &'static Spinlock<usize> { &SYS_PARTITION_SIZE }
/// Accessor for the System partition sector size.
pub fn sys_partition_sector_size() -> &'static Spinlock<usize> { &SYS_PARTITION_SECTOR_SIZE }

/// Pointer that the dispatcher sets to whichever partition mirror
/// is currently being mounted. Read by `fat32::read_sector` so that
/// the FAT32 driver can mount either the ESP (Z:) or the System
/// partition (C:) when the install picked FAT32 for both. NTFS has
/// its own sys-ramdisk path, EXT2 has its own RAM_DISK, so this
/// flag only matters for the FAT32 driver.
static ACTIVE_PARTITION_RAMDISK: Spinlock<Option<*const u8>> = Spinlock::new(None);
/// Tracks the size of the active partition mirror so FAT32 can
/// bounds-check sector reads without dereferencing past the
/// mirror end. Set whenever `set_active_partition_ramdisk` is
/// called.
static ACTIVE_PARTITION_SIZE: Spinlock<usize> = Spinlock::new(0);

/// Set the "active partition" pointer consulted by the FAT32
/// driver's `read_sector`. The dispatcher sets this before
/// `fat32::mount` so the boot-sector probe reads from the right
/// mirror. The corresponding size is auto-derived from the ESP or
/// System mirror registries.
pub fn set_active_partition_ramdisk(base: Option<*const u8>) {
    *ACTIVE_PARTITION_RAMDISK.lock() = base;
    // Auto-derive size from whichever mirror matches the base address.
    let size = match base {
        Some(b) => {
            let sys_b = SYS_RAMDISK.lock().as_ref().map(|d| d.base);
            let esp_b = ESP_RAMDISK.lock().as_ref().map(|d| d.base);
            if Some(b) == sys_b {
                SYS_RAMDISK.lock().as_ref().map(|d| d.size)
            } else if Some(b) == esp_b {
                ESP_RAMDISK.lock().as_ref().map(|d| d.size)
            } else {
                None
            }
        }
        None => None,
    };
    *ACTIVE_PARTITION_SIZE.lock() = size.unwrap_or(0);
}
/// Read the active partition pointer.
pub fn active_partition_ramdisk() -> Option<*const u8> {
    ACTIVE_PARTITION_RAMDISK.lock().clone()
}
/// Set the size (in bytes) of the active partition mirror.
pub fn set_active_partition_size(size: usize) {
    *ACTIVE_PARTITION_SIZE.lock() = size;
}
/// Read the active partition size.
pub fn active_partition_size() -> Option<usize> {
    let v = *ACTIVE_PARTITION_SIZE.lock();
    if v == 0 { None } else { Some(v) }
}

/// Read a contiguous range of bytes from the ESP mirror.
/// `offset` is relative to the start of the partition; `buf` is
/// the destination slice. Truncates silently if the request
/// runs past the end of the mirror.
pub fn esp_ramdisk_read(offset: u64, buf: &mut [u8]) -> usize {
    crate::boot_println!("    [ESP-RD] esp_ramdisk_read entered, offset=0x{:x} buf.len={}", offset, buf.len());
    let guard = ESP_RAMDISK.lock();
    crate::boot_println!("    [ESP-RD] ESP_RAMDISK locked");
    let disk = match guard.as_ref() {
        Some(d) => d,
        None => {
            crate::boot_println!("    [ESP-RD] ESP_RAMDISK is None, returning 0");
            return 0;
        }
    };
    let off = offset as usize;
    crate::boot_println!("    [ESP-RD] disk.base=0x{:x} size=0x{:x}", disk.base as u64, disk.size);
    if off >= disk.size {
        crate::boot_println!("    [ESP-RD] offset past end, returning 0");
        return 0;
    }
    let avail = disk.size - off;
    let n = core::cmp::min(buf.len(), avail);
    crate::boot_println!("    [ESP-RD] about to copy_nonoverlapping from 0x{:x} ({} bytes)", disk.base as u64 + off as u64, n);
    // SAFETY: `base..base+size` is a valid allocation that
    // survives ExitBootServices (the UEFI pool is preserved by
    // the kernel's early page mapping). The `read_volatile` keeps
    // the compiler from hoisting the load out of the call site
    // when used inside a tight loop.
    unsafe {
        let src = disk.base.add(off);
        // Byte-by-byte volatile copy. The compiler is otherwise free
        // to lower `copy_nonoverlapping` to a `rep movsb` that hits
        // a UC-typed MTRR on the underlying physical range (the
        // firmware leaves some boot-time regions as UC, and the
        // capture buffers happen to fall in one of those on OVMF).
        // Volatile single-byte loads/stores do not trip the MTRR
        // fault path and still produce correct results.
        for i in 0..n {
            let b = core::ptr::read_volatile(src.add(i));
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), b);
        }
    }
    crate::boot_println!("    [ESP-RD] copy done, returning {}", n);
    n
}

/// Read a contiguous range of bytes from the System partition
/// mirror. Same semantics as `esp_ramdisk_read`. Returns 0 when
/// the mirror is not registered.
pub fn sys_ramdisk_read(offset: u64, buf: &mut [u8]) -> usize {
    crate::hal::serial::write_string("[SYS-RD] entered\n");
    let guard = SYS_RAMDISK.lock();
    let disk = match guard.as_ref() {
        Some(d) => d,
        None => return 0,
    };
    let off = offset as usize;
    if off >= disk.size {
        return 0;
    }
    let avail = disk.size - off;
    let n = core::cmp::min(buf.len(), avail);
    crate::hal::serial::write_string("[SYS-RD] copy\n");
    // SAFETY: same as `esp_ramdisk_read`. The winload-side
    // capture is allocated in `EfiBootServicesData` so the buffer
    // is identity-mapped for the kernel.
    unsafe {
        let src = disk.base.add(off);
        // Same MTRR / UC workaround as `esp_ramdisk_read` —
        // `rep movsb` faults on UnCacheable-typed regions; byte
        // loads/stores survive.
        for i in 0..n {
            let b = core::ptr::read_volatile(src.add(i));
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), b);
        }
    }
    crate::hal::serial::write_string("[SYS-RD] done\n");
    n
}

/// Return the block size of the ESP mirror (typically 512).
/// Returns 0 when the mirror was not initialised.
pub fn esp_ramdisk_block_size() -> u32 {
    let guard = ESP_RAMDISK.lock();
    guard.as_ref().map(|d| d.block_size).unwrap_or(0)
}

/// Return the block size of the System partition mirror.
/// Returns 0 when the mirror was not initialised.
pub fn sys_ramdisk_block_size() -> u32 {
    let guard = SYS_RAMDISK.lock();
    guard.as_ref().map(|d| d.block_size).unwrap_or(0)
}

/// Read a sector from the System partition mirror (used by the
/// polled CMD shell's BAT executor so it can read files that
/// live on `C:\`, e.g. `tests\autoexec.bat`). `sector` is
/// partition-relative. Returns `Err(())` when the mirror is not
/// mounted.
pub fn sys_ramdisk_read_sector(sector: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    let n = sys_ramdisk_read(sector * 512, buffer);
    if n >= 512 {
        Ok(())
    } else {
        Err(())
    }
}

/// Return `true` when the System partition mirror is mounted.
pub fn sys_ramdisk_is_mounted() -> bool {
    SYS_RAMDISK.lock().is_some()
}

/// Read bytes from the ISO boot RAM disk (combined FAT32 image from ISO).
/// Used by the FAT32 driver to access the ISO-embedded nt61.img.
pub fn ramdisk_image_read(offset: u64, buf: &mut [u8]) -> usize {
    let guard = RAMDISK_IMAGE.lock();
    let disk = match guard.as_ref() {
        Some(d) => d,
        None => return 0,
    };
    let off = offset as usize;
    if off >= disk.size {
        return 0;
    }
    let avail = disk.size - off;
    let n = core::cmp::min(buf.len(), avail);
    // SAFETY: same as `esp_ramdisk_read`.
    unsafe {
        let src = disk.base.add(off);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
    }
    n
}

/// Read a 512-byte sector from the ISO boot RAM disk.
pub fn ramdisk_image_read_sector(sector: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    let n = ramdisk_image_read(sector * 512, buffer);
    if n >= 512 {
        Ok(())
    } else {
        Err(())
    }
}

/// Return `true` when the ISO boot RAM disk mirror is mounted.
pub fn ramdisk_image_is_mounted() -> bool {
    RAMDISK_IMAGE.lock().is_some()
}

/// Mount the FAT32 partition. If `BootInfo.esp_image_base` is
/// non-zero, the in-memory ESP mirror from winload is registered
/// as a RAM disk and the FAT32 driver picks it up on its first
/// directory enumeration. Otherwise we fall back to the
/// built-in directory stub (the legacy behaviour).
pub fn mount_esp_from_bootinfo(boot_info: &crate::boot_types::BootInfo) {
    crate::boot_println!("    [ESP-MNT] mount_esp_from_bootinfo entered, esp_image_base=0x{:x} size={} block_size={} disk_start=0x{:x} disk_sectors={}",
        boot_info.esp_image_base, boot_info.esp_image_size,
        boot_info.esp_block_size, boot_info.esp_disk_start, boot_info.esp_disk_sectors);
    if boot_info.esp_image_base == 0 || boot_info.esp_image_size == 0 {
        // // kprintln!("    FAT32: no ESP mirror in BootInfo; using built-in listing")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return;
    }
    // Ensure the kernel page table identity-maps the winload capture
    // buffers. OVMF exits boot services with the low-memory identity
    // mapping still in place, but `mm::vas::init` installs the
    // kernel's own PML4 which only wires up the recursive self-map
    // and the PML4 page itself — the capture buffers allocated by
    // winload's `AllocatePages` (ESP and SYS mirrors) live at
    // arbitrary physical addresses outside that pre-built identity
    // region. Without explicit identity-map entries, the very first
    // `copy_nonoverlapping` from the buffer's physical base faults
    // with a #PF and QEMU resets. Add a 2 MiB identity map per slice
    // so the FS layer can dereference the captures directly.
    crate::mm::vas::ensure_low_identity_map(boot_info.esp_image_base, boot_info.esp_image_size);
    if boot_info.sys_image_base != 0 && boot_info.sys_image_size != 0 {
        crate::mm::vas::ensure_low_identity_map(boot_info.sys_image_base, boot_info.sys_image_size);
    }
    // Read-back probe: dereference one byte at the ESP image base
    // before handing the pointer to `esp_ramdisk_read`. If this
    // succeeds the identity-map is live; if it #PFs the kernel
    // panic happens here with a diagnostic on the serial log.
    let probe_ptr = boot_info.esp_image_base as *const u8;
    let probe_byte = unsafe { core::ptr::read_volatile(probe_ptr) };
    crate::boot_println!("    [ESP-MNT] probe byte @ 0x{:x} = 0x{:x}", boot_info.esp_image_base, probe_byte);
    // SAFETY: `boot_info.esp_image_base` is a UEFI-allocated
    // physical page that winload explicitly preserves across
    // ExitBootServices. The kernel's early page map covers all
    // physical memory below the kernel's own load address with
    // a 2 MiB identity mapping, so any address in that range is
    // safely dereferenceable. We do not take ownership — the
    // buffer is freed by the firmware when the runtime services
    // tear down — so this is a borrow for the lifetime of the
    // kernel.
    crate::boot_println!("    [ESP-MNT] about to construct EspRamdisk");
    let base = boot_info.esp_image_base as *const u8;
    let size = boot_info.esp_image_size as usize;
    let block_size = if boot_info.esp_block_size == 0 {
        512
    } else {
        boot_info.esp_block_size
    };
    crate::boot_println!("    [ESP-MNT] about to lock ESP_RAMDISK");
    *ESP_RAMDISK.lock() = Some(EspRamdisk {
        base,
        size,
        block_size,
    });
    crate::boot_println!("    [ESP-MNT] ESP_RAMDISK set");
    // // kprintln!("    FAT32: ESP mirror @ phys 0x{:x} ({} MiB, block={})",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    //     base as u64, size / (1024 * 1024), block_size);

    // Publish the start-sector/count fields used by CMD for
    // legacy code paths (the fat32 driver itself reads from the
    // RAM disk, but other subsystems probe these values).
    crate::boot_println!("    [ESP-MNT] about to call set_fat32_partition_info");
    set_fat32_partition_info(boot_info.esp_disk_start, boot_info.esp_disk_sectors);
    crate::boot_println!("    [ESP-MNT] mount_esp_from_bootinfo returning");
}

/// Mount the ISO boot RAM disk from BootInfo. This is used for
/// ISO-9660 boot where the combined FAT32 image (containing both ESP
/// and System content) is embedded in the ISO and exposed as a RAM disk.
/// It is mounted as the X: drive so user-mode code can access it.
pub fn mount_ramdisk_from_bootinfo(boot_info: &crate::boot_types::BootInfo) {
    if boot_info.ramdisk_image_base == 0 || boot_info.ramdisk_image_size == 0 {
        // kprintln!("    ISO ramdisk: no ramdisk image in BootInfo (not an ISO boot)");
        return;
    }
    let base = boot_info.ramdisk_image_base as *const u8;
    let size = boot_info.ramdisk_image_size as usize;
    let block_size = if boot_info.ramdisk_block_size == 0 {
        512
    } else {
        boot_info.ramdisk_block_size
    };
    *RAMDISK_IMAGE.lock() = Some(EspRamdisk {
        base,
        size,
        block_size,
    });
    // kprintln!("    ISO ramdisk: mounted {} MiB @ 0x{:x} (X: drive)",
    //     size / (1024 * 1024), base as u64);
}

/// Register the System partition mirror (the second NTFS
/// partition on the disk) as a second RAM disk. Winload captures
/// the system partition in parallel with the ESP and publishes
/// the physical address/size through BootInfo. The NTFS driver
/// reads from this mirror when probing the boot sector for
/// mounting.
pub fn mount_sys_from_bootinfo(boot_info: &crate::boot_types::BootInfo) {
    if boot_info.sys_image_base == 0 || boot_info.sys_image_size == 0 {
        // kprintln!("    FAT32: no System mirror in BootInfo; sys path disabled");
        return;
    }
    // See the long comment in `mount_esp_from_bootinfo` for why this
    // identity-map step is necessary. The kernel PML4 installed by
    // `mm::vas::init` does not cover the System partition capture
    // buffer that winload allocated, so reading its first sector
    // from `sys_ramdisk_read` would otherwise raise #PF and reboot
    // QEMU before any diagnostic could print.
    crate::mm::vas::ensure_low_identity_map(boot_info.sys_image_base, boot_info.sys_image_size);
    let base = boot_info.sys_image_base as *const u8;
    let size = boot_info.sys_image_size as usize;
    let block_size = if boot_info.sys_block_size == 0 {
        512
    } else {
        boot_info.sys_block_size
    };
    *SYS_RAMDISK.lock() = Some(EspRamdisk {
        base,
        size,
        block_size,
    });
    // Stash the size/sector_size for the EXT4 mount path so that
    // branch can install the system partition into the global
    // RAM_DISK layer that ext2::read_sector reaches through.
    *SYS_PARTITION_SIZE.lock() = size;
    *SYS_PARTITION_SECTOR_SIZE.lock() = block_size as usize;
    // kprintln!("    FAT32: System mirror @ phys 0x{:x} ({} MiB, block={})",
    //     base as u64, size / (1024 * 1024), block_size);
}

/// Detected filesystem type of an in-memory partition mirror.
/// The kernel reads the first sector's magic bytes to choose
/// between the FAT32, NTFS and EXT2/3/4 drivers. `Unknown` means
/// the partition is not one of those three; in that case the kernel
/// logs a warning and skips mounting the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Fat32,
    Ntfs,
    Ext4,
    Ext3,
    Ext2,
    Unknown,
}

impl FsType {
    fn as_str(&self) -> &'static str {
        match self {
            FsType::Fat32 => "FAT32",
            FsType::Ntfs  => "NTFS",
            FsType::Ext4  => "ext4",
            FsType::Ext3  => "ext3",
            FsType::Ext2  => "ext2",
            FsType::Unknown => "unknown",
        }
    }
}

/// Read the boot sector of a partition mirror and identify which
/// filesystem driver should own it.
///
/// * FAT32/NTFS share the 0x55AA signature at offset 510; they
///   distinguish themselves via the OEM ID at offset 0x03 (`"FAT32   "`
///   vs. `"NTFS    "`).
/// * EXT2/3/4 put the magic word 0xEF53 at offset 0x438 (i.e. 1024 + 56),
///   because the ext superblock lives at byte offset 1024. The first
///   sector is therefore checked twice: once for the FAT/NTFS OEM
///   signature, once for the ext superblock magic.
///
/// `base_ptr` is the physical base of the mirror and must be
/// dereferenceable (see `ensure_low_identity_map` for the paging
/// setup that makes the winload-captured buffers safe to read).
pub fn detect_fs_type(base_ptr: *const u8) -> FsType {
    if base_ptr.is_null() {
        return FsType::Unknown;
    }
    let sector = unsafe { core::slice::from_raw_parts(base_ptr, 0x1000) };
    // 1) FAT32 / NTFS share the 0x55AA boot signature at offset 510.
    if sector[510] == 0x55 && sector[511] == 0xAA {
        // OEM ID lives at offset 3 .. 11.
        let oem = &sector[3..11];
        if oem == b"FAT32   " || oem == b"FAT16   " || oem == b"FAT12   " || oem == b"FAT     " {
            return FsType::Fat32;
        }
        if oem == b"NTFS    " {
            return FsType::Ntfs;
        }
    }
    // 2) ext2/3/4 magic 0xEF53 at offset 0x438 (1024 + 56).
    if sector.len() >= 0x43A {
        let magic = u16::from_le_bytes([sector[0x438], sector[0x439]]);
        if magic == 0xEF53 {
            // Distinguish ext4 from ext2/3 by reading `s_feature_incompat`.
            // Offset of incompatible feature flags inside the superblock:
            //   s_inodes_count @ 0x00 (4)
            //   s_blocks_count @ 0x04 (4)
            //   ... (see ext2/superblock.rs)
            //   s_feature_incompat @ 0x60 (relative to superblock start at 1024).
            //   So the absolute offset is 1024 + 0x60 = 0x460.
            let incompat = u32::from_le_bytes([
                sector[0x460], sector[0x461], sector[0x462], sector[0x463],
            ]);
            // EXT4_FEATURE_INCOMPAT_EXTENTS = 0x0040
            if (incompat & 0x0040) != 0 {
                return FsType::Ext4;
            }
            // EXT3_FEATURE_COMPAT_HAS_JOURNAL = 0x0004
            // s_feature_compat is at sb-offset 0x5C, superblock starts
            // at partition byte 1024 (=0x400), so the absolute offset
            // is 0x45C.
            let compat = u32::from_le_bytes([
                sector[0x45C], sector[0x45D], sector[0x45E], sector[0x45F],
            ]);
            if (compat & 0x0004) != 0 {
                return FsType::Ext3;
            }
            return FsType::Ext2;
        }
    }
    FsType::Unknown
}

/// Mount the partition at `base_ptr` (raw mirror address) onto the
/// given Windows-style drive letter (e.g. `b'C' as u16` or `b'Z'`),
/// dispatching to the right driver based on the detected filesystem
/// type. Returns `true` if a driver claimed the partition.
fn mount_partition_detected(drive_letter: u16, base_ptr: *const u8, ramdisk: PartRamdisk) -> bool {
    let fs_type = detect_fs_type(base_ptr);
    crate::boot_println!("[MOUNT] drive={}: detected {} (base=0x{:x})",
        drive_letter as u8 as char, fs_type.as_str(), base_ptr as u64);
    match fs_type {
        FsType::Fat32 => {
            let path = [drive_letter, 0];
            // FAT32::read_sector consults `ACTIVE_PARTITION_RAMDISK`,
            // so we set it here to the partition we're about to
            // mount (Z:→ESP, C:→System). Restored to ESP on the
            // way out so legacy call sites still see the ESP.
            let prev = active_partition_ramdisk();
            set_active_partition_ramdisk(Some(base_ptr));
            let res = fat32::mount(core::ptr::null_mut(), &path);
            set_active_partition_ramdisk(prev);
            match res {
                Some(_fs) => {
                    crate::boot_println!("[MOUNT] drive={}: FAT32 mounted", drive_letter as u8 as char);
                    true
                }
                None => {
                    crate::boot_println!("[MOUNT] drive={}: FAT32 mount failed", drive_letter as u8 as char);
                    false
                }
            }
        }
        FsType::Ntfs => {
            let path = [drive_letter, 0];
            match crate::fs::ntfs::mount(core::ptr::null_mut(), &path) {
                Some(_fs) => {
                    crate::boot_println!("[MOUNT] drive={}: NTFS mounted", drive_letter as u8 as char);
                    true
                }
                None => {
                    crate::boot_println!("[MOUNT] drive={}: NTFS mount failed", drive_letter as u8 as char);
                    false
                }
            }
        }
        FsType::Ext2 | FsType::Ext3 | FsType::Ext4 => {
            // EXT2/3/4 driver reads via `drivers::storage::ramdisk::read`,
            // which expects the system partition mirror to be installed
            // there. `ramdisk` tells us whether the caller already wired
            // ESP/SYS into the global RAM_DISK, or whether this is the
            // system partition that still needs registering.
            if ramdisk == PartRamdisk::System {
                let disk_size = match ramdisk.kind_size() {
                    Some(s) => s,
                    None => {
                        crate::boot_println!("[MOUNT] drive={}: EXT4 mount skipped (no size info)",
                            drive_letter as u8 as char);
                        return false;
                    }
                };
                let sector_size = match ramdisk.kind_sector_size() {
                    Some(s) => s,
                    None => 512,
                };
                let ok = crate::drivers::storage::ramdisk::install_from_external(
                    base_ptr as *mut u8,
                    disk_size,
                    sector_size,
                    /*read_only=*/ true,
                );
                if !ok {
                    crate::boot_println!("[MOUNT] drive={}: EXT4 install_from_external failed",
                        drive_letter as u8 as char);
                    return false;
                }
            }
            // ext2::mount's first argument is the device pointer; the
            // driver ignores it and goes through `drivers::storage::ramdisk`.
            match crate::fs::ext2::mount(core::ptr::null_mut(), 0) {
                Some(_fs) => {
                    crate::boot_println!("[MOUNT] drive={}: {} mounted", drive_letter as u8 as char, fs_type.as_str());
                    true
                }
                None => {
                    crate::boot_println!("[MOUNT] drive={}: {} mount failed", drive_letter as u8 as char, fs_type.as_str());
                    false
                }
            }
        }
        FsType::Unknown => {
            crate::boot_println!("[MOUNT] drive={}: unknown filesystem type, NOT mounted",
                drive_letter as u8 as char);
            false
        }
    }
}

/// Discriminator passed to `mount_partition_detected` so the EXT4
/// path knows whether it has to wire the partition into
/// `drivers::storage::ramdisk::RAM_DISK` (system partition case) or
/// leave that layer alone (ESP case — already in use by FAT32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartRamdisk {
    /// Caller has already wired `drivers::storage::ramdisk::RAM_DISK`
    /// to point at the partition.
    Esp,
    /// Caller must install the partition mirror into the global
    /// RAM_DISK before the EXT4 driver can read it.
    System,
}

impl PartRamdisk {
    /// Total size of the corresponding mirror in bytes (System only).
    fn kind_size(&self) -> Option<usize> {
        match self {
            PartRamdisk::System => {
                // Hand-rolled read of BootInfo is impossible here — the
                // size must be supplied via the system_partition_size
                // global set by `mount_sys_from_bootinfo`. Default to
                // 32 MiB when unknown.
                Some(*crate::fs::sys_partition_size().lock())
            }
            PartRamdisk::Esp => None,
        }
    }
    fn kind_sector_size(&self) -> Option<usize> {
        match self {
            PartRamdisk::System => Some(*crate::fs::sys_partition_sector_size().lock()),
            PartRamdisk::Esp => None,
        }
    }
}

/// Mount the ESP (Z:) partition. The kernel mirrors the ESP partition
/// into RAM via winload (see `mount_esp_from_bootinfo`). The actual
/// mount dispatch is driven by `mount_partition_detected`, which
/// inspects the boot sector and selects the right driver (FAT32/NTFS/EXT4)
/// for that partition.
fn mount_esp_partition() {
    let drive = b'Z' as u16;
    let (base, _size) = match esp_mirror_address() {
        Some(b) => (b, 0),
        None => {
            crate::boot_println!("[FS] mount_esp_partition: no ESP mirror, nothing to mount");
            return;
        }
    };
    mount_partition_detected(drive, base, PartRamdisk::Esp);
}

/// Mount the System partition (C:). The mirror is captured by winload's
/// `capture_system_partition` and registered in `BootInfo.sys_image_base`.
/// As with `mount_esp_partition`, the actual filesystem type is probed
/// from the mirror and the right driver (FAT32/NTFS/EXT4) is picked.
fn mount_system_partition() {
    let drive = b'C' as u16;
    let (base, _size) = match sys_mirror_address() {
        Some(b) => (b, 0),
        None => {
            crate::boot_println!("[FS] mount_system_partition: no System mirror, nothing to mount");
            return;
        }
    };
    mount_partition_detected(drive, base, PartRamdisk::System);
}

/// Global FAT32 partition info for CMD to use
static FAT32_START_SECTOR: Spinlock<u64> = Spinlock::new(0);
static FAT32_SECTOR_COUNT: Spinlock<u64> = Spinlock::new(0);
static FAT32_MOUNTED: Spinlock<bool> = Spinlock::new(false);

/// Set the FAT32 partition information. Exposed for code that needs to
/// register a discovered FAT32 partition before the normal mount path.
pub fn set_fat32_partition_info(start: u64, count: u64) {
    *FAT32_START_SECTOR.lock() = start;
    *FAT32_SECTOR_COUNT.lock() = count;
    *FAT32_MOUNTED.lock() = true;
}

/// Get FAT32 partition info for CMD
pub fn get_fat32_partition_info() -> (u64, u64, bool) {
    let start = *FAT32_START_SECTOR.lock();
    let count = *FAT32_SECTOR_COUNT.lock();
    let mounted = *FAT32_MOUNTED.lock();
    (start, count, mounted)
}

/// Re-export of the file-system smoke test. The full implementation
/// lives in the `smoke` submodule; this re-export keeps the call
/// site readable as `fs::smoke_test()` (matching the convention used
/// by the other subsystems).
pub fn smoke_test() -> bool { smoke::smoke_test() }
