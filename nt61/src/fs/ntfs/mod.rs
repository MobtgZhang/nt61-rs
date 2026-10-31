//! NTFS File System Driver
//
//! Implements NTFS file system for Windows system partitions.
//
//! ## NTFS Architecture
//
//! NTFS is a journaling filesystem with the following key structures:
//!   - Boot sector (first 8 sectors of volume)
//!   - Master File Table (MFT) - contains all file metadata
//!   - MFT Mirror (backup of first 4 MFT records)
//!   - Bitmaps (cluster bitmap, MFT bitmap)
//!   - Log file ($LogFile) - for journaling
//
//! ## File Records
//
//! Each file/directory is represented by an MFT record containing:
//!   - $STANDARD_INFORMATION - timestamps, permissions
//!   - $FILE_NAME - filename, parent directory reference
//!   - $DATA - file data or attribute list
//!   - $INDEX_ROOT/$INDEX_ALLOCATION - for directories
use crate::libs::ntdll::{status::STATUS_UNSUCCESSFUL, types::NTSTATUS};

extern crate alloc;

use crate::fs::{FileSystem, FileSystemDriver, FileSystemType};
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::GlobalAlloc;
use core::ptr::null_mut;
use core::ptr::NonNull;

/// NTFS MFT system record numbers (NTFS 3.1 on-disk layout, Windows NT 6.1).
///
/// These are the well-known system files that occupy the first entries of
/// the Master File Table. The first user-allocatable record starts at 32
/// because records 0-31 are reserved for system metadata files.
pub mod system_records {
    /// $MFT — Master File Table itself
    pub const MFT: u64 = 0;
    /// $MFTMirr — backup copy of the first four MFT records
    pub const MFT_MIRROR: u64 = 1;
    /// $LogFile — journaling log
    pub const LOG_FILE: u64 = 2;
    /// $Volume — volume information
    pub const VOLUME: u64 = 3;
    /// $AttrDef — attribute definition table
    pub const ATTR_DEF: u64 = 4;
    /// . — root directory
    pub const ROOT_DIRECTORY: u64 = 5;
    /// $Bitmap — cluster allocation bitmap
    pub const BITMAP: u64 = 6;
    /// $Boot — boot sector data
    pub const BOOT: u64 = 7;
    /// $BadClus — bad cluster list
    pub const BAD_CLUS: u64 = 8;
    /// $Secure — security descriptor table
    pub const SECURE: u64 = 9;
    /// $UpCase — uppercase conversion table
    pub const UP_CASE: u64 = 10;
    /// $Extend — extension directory
    pub const EXTEND: u64 = 11;
    /// First MFT record number available for user files/directories.
    pub const FIRST_USER_RECORD: u64 = 32;
}

/// NTFS volume mount state
static NTFS_MOUNTED_FS: Spinlock<Option<&'static mut NtfsFileSystem>> = Spinlock::new(None);
static NTFS_MOUNTED: Spinlock<bool> = Spinlock::new(false);

/// NTFS pagefile support module
pub mod pagefile;

/// NTFS boot sector
#[repr(C)]
pub struct NtfsBootSector {
    // Jump instruction (3 bytes)
    pub jump: [u8; 3],
    // OEM ID (8 bytes)
    pub oem_id: [u8; 8],
    // BIOS Parameter Block
    pub bytes_per_sector: u16,   // 0x0B: 2 bytes
    pub sectors_per_cluster: u8, // 0x0D: 1 byte
    pub reserved_sectors: u16,   // 0x0E: 2 bytes
    pub media_descriptor: u8,    // 0x10: 1 byte
    pub zero: [u8; 6],           // 0x11: 6 bytes (not 8!)
    pub sectors_per_track: u16,  // 0x17: 2 bytes
    pub num_heads: u16,          // 0x19: 2 bytes
    pub hidden_sectors: u32,     // 0x1B: 4 bytes
    pub total_sectors_32: u32,   // 0x1F: 4 bytes
    // Extended BPB
    pub total_sectors_64: u64,        // 0x23: 8 bytes
    pub mft_lcn: u64,                 // 0x2B: 8 bytes
    pub mft_mirror_lcn: u64,          // 0x33: 8 bytes
    pub cluster_per_mft_record: i8,   // 0x3B: 1 byte
    pub cluster_per_index_record: i8, // 0x3C: 1 byte
    pub volume_serial_number: u64,    // 0x3D: 8 bytes
    pub checksum: u32,                // 0x45: 4 bytes
}

impl NtfsBootSector {
    pub fn is_valid(&self) -> bool {
        &self.oem_id == b"NTFS    " && self.total_sectors_64 != 0
    }

    pub fn bytes_per_cluster(&self) -> u32 {
        (self.bytes_per_sector as u32) * (self.sectors_per_cluster as u32)
    }
}

/// MFT record header (NTFS spec: no implicit padding).
///
/// WARNING: this struct uses `#[repr(C, packed)]` because the NTFS on-disk
/// layout places `log_sequence_number` (u64) directly after the fixup fields
/// (which total 6 bytes: u16 + u16), leaving no room for natural 8-byte
/// alignment. A regular `#[repr(C)]` struct would insert 2 padding bytes
/// after `fixup_size`, making `log_sequence_number` land at offset 0x0C
/// instead of the correct 0x08 — which would shift every subsequent field
/// by 2 bytes and break `verify_record` and every hard-coded offset in the
/// NTFS driver (e.g. `record[0x16]` for flags).
#[repr(C, packed)]
pub struct MftRecordHeader {
    pub signature: [u8; 4],       // 0x00: "FILE"
    pub fixup_offset: u16,        // 0x04: offset to fixup array (48 = 0x30)
    pub fixup_size: u16,          // 0x06: number of fixup entries (2 for 1024-byte records)
    pub log_sequence_number: u64, // 0x08: LSN
    pub sequence_number: u16,     // 0x10: sequence number
    pub link_count: u16,          // 0x12: hard link count
    pub attributes_offset: u16,   // 0x14: offset to first attribute (56 = 0x38)
    pub flags: u16,               // 0x16: IN_USE (0x0001) | IS_DIRECTORY (0x0002)
    pub used_size: u32,           // 0x18: bytes in use
    pub allocated_size: u32,      // 0x1C: bytes allocated
    pub base_mft_record: u64,     // 0x20: base MFT record (0 for base records)
    pub next_attribute_id: u16,   // 0x28: next attribute ID
    pub record_number: u32,       // 0x2C: record number
}

impl MftRecordHeader {
    pub const SIGNATURE: [u8; 4] = *b"FILE";
    pub const DIRTY: u16 = 0x0001;
    pub const IN_USE: u16 = 0x0001;
    pub const IS_DIRECTORY: u16 = 0x0002;

    /// Byte offsets of every header field on disk. The struct is
    /// `#[repr(C, packed)]`, so these match the field order exactly.
    pub const OFFSET_UPDATE_SEQUENCE_OFFSET: usize = 0x04;
    pub const OFFSET_UPDATE_SEQUENCE_COUNT: usize = 0x06;
    pub const OFFSET_FIXUP_ARRAY: usize = 0x30;
    pub const OFFSET_SEQUENCE_NUMBER: usize = 0x10;
    pub const OFFSET_LINK_COUNT: usize = 0x12;
    pub const OFFSET_ATTRIBUTES_OFFSET: usize = 0x14;
    pub const OFFSET_FLAGS: usize = 0x16;
    pub const OFFSET_USED_SIZE: usize = 0x18;
    pub const OFFSET_ALLOCATED_SIZE: usize = 0x1C;
    pub const OFFSET_NEXT_ATTRIBUTE_ID: usize = 0x28;
    pub const OFFSET_RECORD_NUMBER: usize = 0x2C;

    /// Smallest MFT record size worth building a new record for.
    pub const MINIMUM_RECORD_SIZE: usize = 256;

    pub fn is_valid(&self) -> bool {
        self.signature == Self::SIGNATURE
    }

    pub fn is_directory(&self) -> bool {
        (self.flags & Self::IS_DIRECTORY) != 0
    }

    pub fn is_in_use(&self) -> bool {
        (self.flags & Self::IN_USE) != 0
    }
}

/// Standard information attribute
#[repr(C)]
pub struct StandardInformationAttr {
    pub header: AttributeHeader,
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modification_time: u64,
    pub access_time: u64,
    pub flags: u32,
    pub version: u32,
    pub class_id: u32,
}

impl StandardInformationAttr {
    pub const TYPE_ID: u32 = 0x10;
}

/// File name attribute
#[repr(C)]
pub struct FileNameAttr {
    pub header: AttributeHeader,
    pub parent_directory: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modification_time: u64,
    pub access_time: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub filename_length: u8,
    pub filename_namespace: u8,
    pub filename: [u16; 1], // Variable length
}

impl FileNameAttr {
    pub const TYPE_ID: u32 = 0x30;
}

/// Data attribute
#[repr(C)]
pub struct DataAttr {
    pub header: AttributeHeader,
    pub data: [u8; 1], // Variable length
}

impl DataAttr {
    pub const TYPE_ID: u32 = 0x80;
    pub const RESIDENT: u32 = 0x00;
    pub const NON_RESIDENT: u32 = 0x01;
}

/// Attribute header (resident/non-resident)
#[repr(C)]
pub struct AttributeHeader {
    pub attribute_type: u32,
    pub length: u32,
    pub non_resident: u8,
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub attribute_id: u16,
}

impl AttributeHeader {
    pub const RESIDENT_FORM: u8 = 0x00;
    pub const NON_RESIDENT_FORM: u8 = 0x01;

    pub const TYPE_RESIDENT: u32 = 0;
    pub const TYPE_STANDARD_INFO: u32 = 0x10;
    pub const TYPE_ATTR_LIST: u32 = 0x20;
    pub const TYPE_FILE_NAME: u32 = 0x30;
    pub const TYPE_OBJECT_ID: u32 = 0x40;
    pub const TYPE_SECURITY: u32 = 0x50;
    pub const TYPE_LABEL: u32 = 0x60;
    pub const TYPE_VOLUME_INFO: u32 = 0x70;
    pub const TYPE_DATA: u32 = 0x80;
    pub const TYPE_INDEX_ROOT: u32 = 0x90;
    pub const TYPE_INDEX_ALLOCATION: u32 = 0xA0;
    pub const TYPE_BITMAP: u32 = 0xB0;
    pub const TYPE_REPARSE: u32 = 0xC0;
    pub const TYPE_EA: u32 = 0xD0;
    pub const TYPE_EA_LENGTH: u32 = 0xE0;
}

/// Index root attribute
#[repr(C)]
pub struct IndexRootAttr {
    pub header: AttributeHeader,
    pub attribute_type: u32,
    pub collation_rule: u32,
    pub bytes_per_index_record: u32,
    pub clusters_per_index_record: u8,
    pub padding: [u8; 3],
}

impl IndexRootAttr {
    pub const TYPE_ID: u32 = 0x90;
}

/// NTFS private data
pub struct NtfsData {
    pub boot_sector: *mut NtfsBootSector,
    pub mft_start: u64,
    pub mft_size: u64,
    pub cluster_size: u32,
    pub mft_record_size: u32,
    pub index_record_size: u32,
    pub volume_serial: u64,
    pub mounted: bool,
    /// Device ID for block device layer (if available)
    pub device_id: Option<usize>,
    /// Hidden sectors (partition start LBA). Used as the base for
    /// non-MFT data reads (file content, $INDEX_ALLOCATION).
    pub hidden_sectors: u64,
}

impl NtfsData {
    pub fn new() -> Self {
        Self {
            boot_sector: null_mut(),
            mft_start: 0,
            mft_size: 0,
            cluster_size: 4096,
            mft_record_size: 1024,
            index_record_size: 4096,
            volume_serial: 0,
            mounted: false,
            device_id: None,
            hidden_sectors: 0,
        }
    }
}

impl Default for NtfsData {
    fn default() -> Self {
        Self::new()
    }
}

/// NTFS file handle
pub struct NtfsHandle {
    pub mft_record: u64,
    pub current_position: u64,
    pub is_directory: bool,
    pub file_size: u64,
    pub name: Vec<u16>,
}

impl NtfsHandle {
    pub fn new(record: u64, is_dir: bool, size: u64, name: &[u16]) -> Self {
        Self {
            mft_record: record,
            current_position: 0,
            is_directory: is_dir,
            file_size: size,
            name: name.to_vec(),
        }
    }
}

/// NTFS file system instance
pub struct NtfsFileSystem {
    pub base: FileSystem,
    pub ntfs_data: NtfsData,
}

impl NtfsFileSystem {
    pub fn new() -> Self {
        Self {
            base: FileSystem {
                driver: null_mut(),
                device: null_mut(),
                volume_name: [0; 64],
                fs_type: FileSystemType::Ntfs,
                sector_size: 512,
                cluster_size: 4096,
                total_clusters: 0,
                free_clusters: 0,
            },
            ntfs_data: NtfsData::new(),
        }
    }
}

impl Default for NtfsFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// read sector from device
/// Routes to the appropriate storage device based on device context
pub unsafe fn read_sector(device: *mut (), sector: u64, buffer: &mut [u8]) -> Result<(), NTSTATUS> {
    if buffer.len() < 512 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Prefer the *active* partition mirror, when one is set by
    // the dispatcher in `fs::mod`. This is what lets NTFS mount
    // and read from the system partition properly.
    if let Some(context) = unsafe { crate::fs::mount_context_from_device(device) } {
        let base = context.base;
        let off = (sector as usize) * 512;
        let max_size = context.size;
        if off + 512 > max_size {
            crate::boot_println!(
                "[NTFS] read_sector: OOB off=0x{:x} max=0x{:x} sector={}",
                off,
                max_size,
                sector
            );
            return Err(STATUS_UNSUCCESSFUL);
        }
        // Dispatch to sys_ramdisk_read for the system partition
        let sys_base = crate::fs::sys_mirror_address();
        if Some(base) == sys_base {
            let n = crate::fs::sys_ramdisk_read(off as u64, buffer);
            if n >= 512 {
                return Ok(());
            }
        } else {
            let n = crate::fs::esp_ramdisk_read(off as u64, buffer);
            if n >= 512 {
                return Ok(());
            }
        }
        crate::boot_println!(
            "[NTFS] read_sector: ramdisk read failed for sector {}",
            sector
        );
        return Err(STATUS_UNSUCCESSFUL);
    }

    crate::boot_println!("[NTFS] read_sector: no active partition!");

    // x86_64-only fallback to AHCI/ATA drivers
    // Try AHCI first (channel 0, port 0)
    if crate::drivers::storage::read_ahci_sector(sector as u32, buffer) {
        return Ok(());
    }

    // Last resort: legacy ramdisk (for bootstrap operations)
    let sector_num = sector as usize;
    if crate::drivers::storage::ramdisk::read(sector_num, buffer) {
        Ok(())
    } else {
        Err(STATUS_UNSUCCESSFUL)
    }
}

/// read sector from device using block layer (if available)
pub fn read_sector_from_block(device_id: usize, sector: u64, buffer: &mut [u8]) -> bool {
    crate::drivers::storage::block::read_block(device_id, sector, buffer)
}

fn write_mounted_sector(ntfs: &NtfsData, sector: u64, buffer: &[u8]) -> bool {
    if let Some(device_id) = ntfs.device_id {
        return crate::drivers::storage::block::write_block(device_id, sector, buffer);
    }
    if crate::fs::sys_ramdisk_is_mounted() {
        return crate::fs::sys_ramdisk_write_sector(sector, buffer).is_ok();
    }
    write_sector(core::ptr::null_mut(), sector, buffer).is_ok()
}

fn read_mounted_sector(ntfs: &NtfsData, sector: u64, buffer: &mut [u8]) -> bool {
    unsafe {
        if let Some(device_id) = ntfs.device_id {
            return crate::drivers::storage::block::read_block(device_id, sector, buffer);
        }
        if crate::fs::sys_ramdisk_is_mounted() {
            return crate::fs::sys_ramdisk_read_sector(sector, buffer).is_ok();
        }
        read_sector(core::ptr::null_mut(), sector, buffer).is_ok()
    }
}

/// write sector to device
/// Routes to the appropriate storage device based on device context
pub fn write_sector(device: *mut (), sector: u64, buffer: &[u8]) -> Result<(), NTSTATUS> {
    if buffer.len() < 512 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // The active in-memory partition mirror takes precedence during
    // early boot. It is the authoritative view of the system volume,
    // and writing through it keeps subsequent reads coherent.
    if let Some(base) = crate::fs::active_partition_ramdisk() {
        if Some(base) == crate::fs::sys_mirror_address()
            && crate::fs::sys_ramdisk_write_sector(sector, buffer).is_ok()
        {
            return Ok(());
        }
    }

    // If a valid device is provided, try block layer first
    if !device.is_null() {
        let device_id = device as usize;
        if crate::drivers::storage::block::write_block(device_id, sector, buffer) {
            return Ok(());
        }
    }

    // Fall back to AHCI
    if crate::drivers::storage::ahci::write_sector(0, 0, sector as u32, buffer) {
        return Ok(());
    }

    // Last resort: RAM disk (for bootstrap operations)
    let sector_num = sector as usize;
    if crate::drivers::storage::ramdisk::write(sector_num, buffer) {
        Ok(())
    } else {
        Err(STATUS_UNSUCCESSFUL)
    }
}

/// Apply FixUp values to an MFT record.
///
/// NTFS records span multiple sectors, and each sector's last 2 bytes
/// contain an "update sequence number" marker. The actual value is stored
/// in the FixUp array at the end of the record header.
///
/// # Arguments
/// * `record` - The MFT record buffer (must be at least one sector)
///
/// # Returns
/// * `true` if FixUp was applied successfully
/// * `false` if the record is invalid
pub fn apply_fixup(record: &mut [u8]) -> bool {
    if record.len() < 512 {
        // kprintln!("[NTFS] apply_fixup: record too small ({} bytes)", record.len());
        return false;
    }

    // FixUp offset is at bytes 4-5
    let fixup_offset = u16::from_le_bytes([record[4], record[5]]) as usize;
    let fixup_size = u16::from_le_bytes([record[6], record[7]]) as usize;

    // Verify FixUp offset is within bounds
    if fixup_offset >= record.len() || fixup_offset < 8 {
        // kprintln!("[NTFS] apply_fixup: invalid fixup offset {}", fixup_offset);
        return false;
    }

    // Authoritative layout (ntfs-3g libntfs-3g/mst.c, originated from the
    // Linux-NTFS project): `usa_count` (bytes 6-7) is the number of fixups
    // **plus one**, the entry count must equal the number of 512-byte
    // sectors in the record, and the first u16 at `fixup_offset` is the
    // update sequence number itself; the saved values follow it.
    if fixup_size == 0 {
        return false;
    }
    let num_sectors = record.len() / 512;
    let fixup_count = fixup_size - 1;
    if fixup_count != num_sectors || fixup_offset + 2 + fixup_count * 2 > record.len() {
        return false;
    }
    let usn = u16::from_le_bytes([record[fixup_offset], record[fixup_offset + 1]]);

    // The fixup array starts at fixup_offset + 2 (skip the usn)
    for i in 0..fixup_count {
        let fixup_entry_offset = fixup_offset + 2 + (i * 2);
        let sector_end_offset = ((i + 1) * 512) - 2;

        // Make sure we're within bounds
        if fixup_entry_offset + 2 > record.len() || sector_end_offset + 2 > record.len() {
            // kprintln!("[NTFS] apply_fixup: out of bounds (entry={}, end={})",
            //                      fixup_entry_offset, sector_end_offset);
            return false;
        }

        // Get the expected value from the FixUp array
        let expected =
            u16::from_le_bytes([record[fixup_entry_offset], record[fixup_entry_offset + 1]]);

        // Get the current value at the sector end
        let current =
            u16::from_le_bytes([record[sector_end_offset], record[sector_end_offset + 1]]);

        // An incomplete multi-sector transfer is detected when a sector end
        // no longer holds the update sequence number. Overwriting it
        // silently would hide on-disk corruption, so the record is reported
        // as invalid (ntfs-3g marks the magic "BAAD" in this case).
        if current != usn {
            return false;
        }
        record[sector_end_offset..sector_end_offset + 2].copy_from_slice(&expected.to_le_bytes());
    }

    true
}

/// Prepare an MFT record for writing by applying multi-sector transfer
/// protection (the inverse of `apply_fixup`).
///
/// The caller must have set up the update sequence array header (bytes 4-7:
/// array offset and entry count + 1) and the update sequence number before
/// calling this function.
///
/// Semantics follow `ntfs_mst_pre_write_fixup()` in ntfs-3g
/// (`libntfs-3g/mst.c`): the update sequence number is cyclically
/// incremented (skipping 0 and 0xFFFF), each original sector-end value is
/// saved into the update sequence array, and the update sequence number is
/// written to the last 2 bytes of every sector.
pub fn prepare_fixup_for_write(record: &mut [u8]) -> bool {
    if record.len() < 512 || !record.len().is_multiple_of(512) {
        return false;
    }

    let usa_ofs = u16::from_le_bytes([record[4], record[5]]) as usize;
    let usa_count = u16::from_le_bytes([record[6], record[7]]) as usize;
    if usa_count == 0 {
        return false;
    }
    let fixups = usa_count - 1;

    if usa_ofs & 1 != 0 || usa_ofs < 8 || usa_ofs + fixups * 2 > record.len() {
        return false;
    }
    if fixups != record.len() / 512 {
        return false;
    }

    let mut usn = u16::from_le_bytes([record[usa_ofs], record[usa_ofs + 1]]).wrapping_add(1);
    if usn == 0 || usn == 0xFFFF {
        usn = 1;
    }
    record[usa_ofs..usa_ofs + 2].copy_from_slice(&usn.to_le_bytes());

    for i in 0..fixups {
        let entry_offset = usa_ofs + 2 + (i * 2);
        let sector_end_offset = ((i + 1) * 512) - 2;
        let original =
            u16::from_le_bytes([record[sector_end_offset], record[sector_end_offset + 1]]);
        record[entry_offset..entry_offset + 2].copy_from_slice(&original.to_le_bytes());
        record[sector_end_offset..sector_end_offset + 2].copy_from_slice(&usn.to_le_bytes());
    }

    true
}

/// Verify MFT record signature and basic validity.
///
/// # Arguments
/// * `record` - The MFT record buffer
///
/// # Returns
/// * `true` if the record is valid
/// * `false` if the record is invalid
pub fn verify_record(record: &[u8]) -> bool {
    if record.len() < 48 {
        return false;
    }

    // Check signature "FILE"
    if &record[0..4] != b"FILE" {
        return false;
    }

    // Check record is in use (flag bit 0)
    let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
    if flags & 0x0001 == 0 {
        return false;
    }

    // Check attributes offset is reasonable.
    // The build-tool writes attr_offset=50 (past header+fixup), which is valid.
    // The kernel's NTFS spec uses attr_offset=56 for standard 1024-byte records
    // (header 48 + fixup array 8 = 56), but the minimum valid value is 48
    // (end of the fixed header, before the fixup array).
    let attr_offset = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    if attr_offset < 48 || attr_offset >= record.len() {
        return false;
    }

    true
}

/// Heap-backed byte buffer allocated directly from the kernel allocator.
///
/// NTFS MFT records are read during the boot path, where the global
/// allocator may be a UEFI allocator in the host loader. Returning a
/// `Vec<u8>` would make the eventual `Drop` go through that global
/// allocator, even though the backing pointer was allocated from
/// `KERNEL_HEAP`. This wrapper keeps allocation and deallocation on the
/// same allocator without introducing a leak.
pub struct MftRecordBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

impl MftRecordBuffer {
    /// create a zero-length-capable buffer from a raw kernel allocation.
    fn from_raw_parts(ptr: *mut u8, len: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }
        Some(Self {
            ptr: NonNull::new(ptr)?,
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl core::ops::Deref for MftRecordBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::ops::DerefMut for MftRecordBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for MftRecordBuffer {
    fn drop(&mut self) {
        let layout = core::alloc::Layout::from_size_align(self.len, 1);
        if let Ok(layout) = layout {
            unsafe { crate::mm::heap::KERNEL_HEAP.dealloc(self.ptr.as_ptr(), layout) };
        }
    }
}

struct Irq0Guard;

impl Drop for Irq0Guard {
    fn drop(&mut self) {
        crate::arch::unmask_irq0();
    }
}

/// read MFT record from the volume.
///
/// MFT records are typically 1024 bytes (1 or 2 sectors).
/// This function:
/// 1. Calculates the sector(s) containing the record
/// 2. Reads the sector(s)
/// 3. Applies FixUp repair
/// 4. Verifies the record signature
///
/// # Arguments
/// * `ntfs` - NTFS data structure with volume information
/// * `record_num` - MFT record number to read (0 = $MFT, etc.)
///
/// # Returns
/// * `Some(MftRecordBuffer)` containing the record data
/// * `None` if reading failed
pub fn read_mft_record(ntfs: &NtfsData, record_num: u64) -> Option<MftRecordBuffer> {
    // CRITICAL-014: Hard-clamp `record_size` to a known-good value
    // before any branch on it. A previous boot observed `mft_record_size`
    // returning as a corrupt 32-bit value (≈ 2 GiB), causing the loop
    // below to either overflow the stack buffer (panic) or chase an
    // enormous sector range that doesn't exist on the disk.
    //
    // The canonical NTFS MFT record size on every Microsoft-shipped
    // volume is 1024 bytes; 4096 bytes is the largest value Windows
    // has ever shipped. Anything else is taken as "parser returned
    // garbage" and replaced with 1024 so the loop is bounded.
    let raw_record_size = ntfs.mft_record_size as usize;
    let record_size: usize = match raw_record_size {
        0 => 0,
        1..=4096 => raw_record_size,
        _ => {
            crate::boot_println!(
                "[NTFS] read_mft_record: clamping bogus mft_record_size=0x{:x} (record_num={}) to 1024",
                raw_record_size, record_num
            );
            1024
        }
    };
    let sectors_per_record = record_size.div_ceil(512);

    if record_size == 0 || sectors_per_record == 0 {
        return None; // Invalid parameters
    }

    // CRITICAL-014: use a heap-allocated buffer instead of a stack
    // array. The previous stack-array approach placed a 4 KiB buffer
    // in this function's stack frame, and the SMSS call chain was
    // deep enough that the boot was hanging in the loop body after
    // the first iteration (the print right after `read_block` ran,
    // but the print after `copy_from_slice` never did — the kernel
    // had effectively run out of stack at the call site). Using a
    // `Vec` here moves the record to the kernel heap and keeps the
    // stack frame tiny, so the inner `crate::boot_println!` calls
    // (each of which pulls a couple hundred bytes of format buffer
    // and several helper-stack frames) all fit comfortably.
    let record_layout = core::alloc::Layout::from_size_align(record_size, 1).ok()?;
    let record_ptr = unsafe { crate::mm::heap::KERNEL_HEAP.alloc(record_layout) };
    if record_ptr.is_null() {
        crate::boot_println!(
            "[NTFS] read_mft_record: KERNEL_HEAP alloc failed size={} record_num={}",
            record_size,
            record_num
        );
        return None;
    }
    let mut record = MftRecordBuffer::from_raw_parts(record_ptr, record_size)?;
    unsafe { record.as_mut_ptr().write_bytes(0, record_size) };
    let mft_start_sector = ntfs.mft_start;
    let record_start_sector = mft_start_sector + (record_num * sectors_per_record as u64);
    crate::boot_debug_println!("[NTFS] read_mft_record: mft_start=0x{:x} mft_record_size=0x{:x} record_start_sector=0x{:x} record_size={} record_num={}",
                  mft_start_sector, ntfs.mft_record_size, record_start_sector, record_size, record_num);

    // CRITICAL-014: Mask the PIT (IRQ 0) for the duration of this
    // hot read loop. We have empirically observed that an IRQ
    // firing inside the `read_block` -> `sys_ramdisk_read` call
    // chain can corrupt RIP (the page fault reports
    // `tf.rip=0xffffffffffffffff`), which then crashes the
    // dispatcher in `pfn.rs`. Until we can replace the legacy
    // 8259 PIC path with the APIC timer and fix the underlying
    // stack-overlap issue, just silencing IRQ 0 here is the
    // simplest workable workaround.
    crate::arch::mask_irq0();
    let _irq0_guard = Irq0Guard;
    // read each sector of the record into the heap buffer.
    for i in 0..sectors_per_record {
        let mut sector_buf = [0u8; 512];
        let sector = record_start_sector + (i as u64);
        crate::boot_debug_println!("[NTFS] read_mft_record: iter {} sector=0x{:x}", i, sector);

        let success = read_mounted_sector(ntfs, sector, &mut sector_buf);
        if !success {
            crate::boot_debug_println!("[NTFS] read_mft_record: read_block failed");
            return None;
        }
        crate::boot_debug_println!("[NTFS] read_mft_record: read OK");

        let offset = i * 512;
        // CRITICAL-014: bound `offset` to the buffer size before
        // slicing.
        if offset >= record_size {
            return None;
        }
        let copy_len = core::cmp::min(512, record_size - offset);
        // Copy through the heap-backed slice. The IRQ-0 window is
        // already masked above; the safe slice copy avoids the
        // per-byte volatile loop that made boot-time MFT traversal
        // prohibitively slow without changing the resulting bytes.
        record.as_mut_slice()[offset..offset + copy_len].copy_from_slice(&sector_buf[..copy_len]);
        crate::boot_debug_println!("[NTFS] read_mft_record: copy done");
    }

    // Apply FixUp repair
    apply_fixup(&mut record);

    // Verify the record
    if !verify_record(&record) {
        return None;
    }

    Some(record)
}

/// Write a complete MFT record back to the mounted volume.
///
/// The record is copied into a sector-aligned staging buffer, multi-sector
/// transfer fixups are prepared, and each sector is written independently.
/// A partial write is reported as an error so callers never treat a torn
/// MFT update as successful.
pub fn write_mft_record(ntfs: &NtfsData, record_num: u64, record: &[u8]) -> Result<(), NTSTATUS> {
    let raw_record_size = ntfs.mft_record_size as usize;
    if raw_record_size == 0 || raw_record_size > 4096 || record.len() != raw_record_size {
        use alloc::format;
        crate::hal::serial::write_string(
            format!(
                "[NTFS] write_mft: size mismatch raw={} actual={}\n",
                raw_record_size,
                record.len()
            )
            .as_str(),
        );
        return Err(STATUS_UNSUCCESSFUL);
    }

    let sectors_per_record = raw_record_size / 512;
    if sectors_per_record == 0 || !raw_record_size.is_multiple_of(512) {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let mut staging = alloc::vec![0u8; raw_record_size];
    staging.copy_from_slice(record);
    if !prepare_fixup_for_write(&mut staging) {
        crate::boot_debug_println!("[NTFS] write_mft: prepare failed");
        return Err(STATUS_UNSUCCESSFUL);
    }

    let record_start_sector = ntfs.mft_start + (record_num * sectors_per_record as u64);
    for (index, sector) in staging.chunks(512).enumerate() {
        let sector_index = record_start_sector + index as u64;
        if !write_mounted_sector(ntfs, sector_index, sector) {
            crate::boot_debug_println!("[NTFS] write_mft: sector failed");
            return Err(STATUS_UNSUCCESSFUL);
        }
    }
    Ok(())
}

/// Find attribute in MFT record by type
///
/// This function walks through all attributes in an MFT record and finds
/// the first attribute of the specified type.
///
/// # Arguments
/// * `record` - Raw MFT record bytes
/// * `attr_type` - Attribute type ID to search for (e.g., 0x10 = $STANDARD_INFORMATION)
///
/// # Returns
/// * `Some(offset)` - offset within the record where the attribute starts
/// * `None` - Attribute not found
pub fn find_attribute_in_record(record: &[u8], attr_type: u32) -> Option<usize> {
    if record.len() < 48 {
        crate::boot_println!("[NTFS] find_attr: record too short");
        return None; // Minimum MFT record size
    }

    // read the attributes_offset from the MFT record header.
    // With `#[repr(C, packed)]` on MftRecordHeader the struct is exactly
    // 48 bytes and fields land at their correct on-disk offsets, so reading
    // bytes 0x14..0x16 as a LE u16 gives the real attributes_offset.
    let attr_offset = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;

    let mut offset = attr_offset;

    loop {
        if offset + 8 > record.len() {
            break;
        }

        let this_type = u32::from_le_bytes([
            record[offset],
            record[offset + 1],
            record[offset + 2],
            record[offset + 3],
        ]);

        // End of attributes marker
        if this_type == 0xFFFFFFFF {
            break;
        }

        let attr_len = u32::from_le_bytes([
            record[offset + 4],
            record[offset + 5],
            record[offset + 6],
            record[offset + 7],
        ]) as usize;
        // `attr_len` is on-disk data, so the bound has to include the
        // current offset; checking it against `record.len()` alone lets an
        // attribute near the end of the record claim a length that runs
        // past the record and then be read as a slice.
        if attr_len < 8 || offset + attr_len > record.len() {
            break;
        }

        if this_type == attr_type {
            return Some(offset);
        }

        offset += attr_len;
    }

    None
}

/// Parse an attribute from an MFT record.
///
/// This function extracts the attribute data based on whether it's resident or non-resident.
///
/// # Arguments
/// * `record` - Raw MFT record bytes
/// * `attr_type` - Attribute type ID to parse
///   Parse an attribute from an MFT record.
///
/// # Returns
/// * `Some(&[u8])` - Attribute value (resident) or attribute header
///   (non-resident), borrowed from `record`
/// * `None` - Attribute not found or malformed
///
/// Resident attribute data lives inside the MFT record itself, so the
/// result is a plain borrow of `record`. The previous version copied into
/// a process-lifetime static and returned `&'static [u8]`, which was a
/// lie: the "static" buffer was overwritten by the next call, so two live
/// results aliased each other, and the non-reentrancy flag only detected
/// the problem instead of preventing it. Borrowing the record removes the
/// arena, the fake lifetime, the reentrancy flag, and the single-CPU
/// assumption.
pub fn parse_attribute(record: &[u8], attr_type: u32) -> Option<&[u8]> {
    let attr_offset = find_attribute_in_record(record, attr_type)?;

    if attr_offset + 8 > record.len() {
        return None;
    }

    let non_resident = record[attr_offset + 8];
    let attr_length = u32::from_le_bytes([
        record[attr_offset + 4],
        record[attr_offset + 5],
        record[attr_offset + 6],
        record[attr_offset + 7],
    ]) as usize;

    if attr_offset + attr_length > record.len() {
        return None;
    }

    if non_resident == 0 {
        // read value_offset and value_length from the resident attribute header
        let value_offset =
            u16::from_le_bytes([record[attr_offset + 0x14], record[attr_offset + 0x15]]) as usize;
        let value_length = u32::from_le_bytes([
            record[attr_offset + 0x10],
            record[attr_offset + 0x11],
            record[attr_offset + 0x12],
            record[attr_offset + 0x13],
        ]) as usize;

        let actual_offset = attr_offset + value_offset;
        let end_offset = actual_offset + value_length;

        // Both offsets come from the record, so the value range has to be
        // checked against the record before slicing.
        if actual_offset > record.len() || end_offset > record.len() {
            return None;
        }

        return Some(&record[actual_offset..end_offset]);
    }

    // Non-resident: return the attribute header (run list follows it).
    Some(&record[attr_offset..attr_offset + attr_length])
}

/// Get attribute information from an MFT record.
///
/// Returns a tuple of (non_resident, data_size) for the attribute.
///
/// # Arguments
/// * `record` - Raw MFT record bytes
/// * `attr_type` - Attribute type ID
///
/// # Returns
/// * `Some((bool, u64))` - (is_non_resident, data_size)
/// * `None` - Attribute not found
pub fn get_attribute_info(record: &[u8], attr_type: u32) -> Option<(bool, u64)> {
    let attr_offset = find_attribute_in_record(record, attr_type)?;

    if attr_offset + 8 > record.len() {
        return None;
    }

    let non_resident = record[attr_offset + 8] != 0;

    let data_size = if non_resident {
        // For non-resident: data_size is at offset 0x30 (48 bytes from attr start)
        if attr_offset + 56 > record.len() {
            return None;
        }
        u64::from_le_bytes([
            record[attr_offset + 48],
            record[attr_offset + 49],
            record[attr_offset + 50],
            record[attr_offset + 51],
            record[attr_offset + 52],
            record[attr_offset + 53],
            record[attr_offset + 54],
            record[attr_offset + 55],
        ])
    } else {
        // For resident: data_size is the value_length at offset 0x10
        // (16 bytes from attr start) — the comment in the previous
        // version was right but the code read at attr+20 (0x14),
        // which is actually the value_offset field. Fix: read at the
        // spec-defined offset 0x10.
        if attr_offset + 24 > record.len() {
            return None;
        }
        u32::from_le_bytes([
            record[attr_offset + 0x10],
            record[attr_offset + 0x11],
            record[attr_offset + 0x12],
            record[attr_offset + 0x13],
        ]) as u64
    };

    Some((non_resident, data_size))
}

/// Parse $STANDARD_INFORMATION attribute.
///
/// Returns a tuple of (creation_time, modification_time, access_time, flags).
///
/// # Arguments
/// * `record` - Raw MFT record bytes
///
/// # Returns
/// * `Some((u64, u64, u64, u32))` - Timestamps and flags
/// * `None` - $STANDARD_INFORMATION not found
pub fn parse_standard_information(record: &[u8]) -> Option<(u64, u64, u64, u32)> {
    let attr_offset = find_attribute_in_record(record, AttributeHeader::TYPE_STANDARD_INFO)?;

    // Resident attribute header is 24 bytes, data follows
    if attr_offset + 24 + 16 > record.len() {
        return None;
    }

    let creation_time = u64::from_le_bytes([
        record[attr_offset + 24],
        record[attr_offset + 25],
        record[attr_offset + 26],
        record[attr_offset + 27],
        record[attr_offset + 28],
        record[attr_offset + 29],
        record[attr_offset + 30],
        record[attr_offset + 31],
    ]);

    let modification_time = u64::from_le_bytes([
        record[attr_offset + 32],
        record[attr_offset + 33],
        record[attr_offset + 34],
        record[attr_offset + 35],
        record[attr_offset + 36],
        record[attr_offset + 37],
        record[attr_offset + 38],
        record[attr_offset + 39],
    ]);

    let access_time = u64::from_le_bytes([
        record[attr_offset + 40],
        record[attr_offset + 41],
        record[attr_offset + 42],
        record[attr_offset + 43],
        record[attr_offset + 44],
        record[attr_offset + 45],
        record[attr_offset + 46],
        record[attr_offset + 47],
    ]);

    let flags = u32::from_le_bytes([
        record[attr_offset + 48],
        record[attr_offset + 49],
        record[attr_offset + 50],
        record[attr_offset + 51],
    ]);

    Some((creation_time, modification_time, access_time, flags))
}

/// Parse $FILE_NAME attribute.
///
/// Returns a tuple of (parent_ref, file_name, is_directory).
///
/// # Arguments
/// * `record` - Raw MFT record bytes
///
/// # Returns
/// * `Some((u64, Vec<u16>, bool))` - Parent reference, filename, is_directory flag
/// * `None` - $FILE_NAME not found
pub fn parse_file_name(record: &[u8]) -> Option<(u64, Vec<u16>, bool)> {
    let attr_offset = find_attribute_in_record(record, AttributeHeader::TYPE_FILE_NAME)?;

    // Resident attribute: FILE_NAME value starts at attr_offset + 24
    // (after the 24-byte resident attribute header).
    let value_start = attr_offset + 24;

    // Check we have enough data for FILE_NAME value header (64 bytes minimum)
    if value_start + 64 > record.len() {
        return None;
    }

    // FILE_NAME value structure:
    // 0x00: parent_ref (8 bytes)
    // 0x08: creation_time (8 bytes)
    // 0x10: modification_time (8 bytes)
    // 0x18: mft_change_time (8 bytes)
    // 0x20: last_access_time (8 bytes)
    // 0x28: allocated_size (8 bytes)
    // 0x30: file_size (8 bytes)
    // 0x38: file_attributes (4 bytes)
    // 0x3C: reserved (2 bytes)
    // 0x3E: name_length (1 byte)
    // 0x3F: namespace (1 byte)
    // 0x40+: filename (UTF-16LE)

    // Parent directory reference
    let parent_ref = u64::from_le_bytes([
        record[value_start],
        record[value_start + 1],
        record[value_start + 2],
        record[value_start + 3],
        record[value_start + 4],
        record[value_start + 5],
        record[value_start + 6],
        record[value_start + 7],
    ]);

    // Filename length at offset 0x40 (per [MS-FSCC] §2.6 the
    // bytes at +0x3C..+0x40 are reserved / reparse / packed_ea_size
    // and name_length follows). Namespace is at +0x41 and the
    // UTF-16LE name starts at +0x42.
    let name_length = record[value_start + 0x40] as usize;
    let name_space = record[value_start + 0x41];

    // Check bounds for filename
    if value_start + 0x42 + (name_length * 2) > record.len() {
        return None;
    }

    let mut file_name = Vec::with_capacity(name_length);
    for i in 0..name_length {
        let char_val = u16::from_le_bytes([
            record[value_start + 0x42 + (i * 2)],
            record[value_start + 0x42 + (i * 2) + 1],
        ]);
        file_name.push(char_val);
    }

    // Check directory flag from MFT record flags
    let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
    let is_directory = (flags & 0x02) != 0;

    let _ = name_space;

    Some((parent_ref, file_name, is_directory))
}

/// Get file size from $DATA attribute.
///
/// # Arguments
/// * `record` - Raw MFT record bytes
/// * `ntfs_data` - NTFS data with volume information (for non-resident files)
///
/// # Returns
/// * `Some(u64)` - File size
/// * `None` - $DATA attribute not found
pub fn get_file_size(record: &[u8], _ntfs_data: &NtfsData) -> Option<u64> {
    let attr_offset = find_attribute_in_record(record, AttributeHeader::TYPE_DATA)?;

    if attr_offset + 8 > record.len() {
        return None;
    }

    let non_resident = record[attr_offset + 8];

    if non_resident == 0 {
        // Resident file - size is in value_length at offset 0x10 in the
        // resident attribute header (24 bytes total).
        if attr_offset + 0x18 > record.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            record[attr_offset + 0x10],
            record[attr_offset + 0x11],
            record[attr_offset + 0x12],
            record[attr_offset + 0x13],
        ]) as u64)
    } else {
        // Non-resident file - file size lives in the `real_size`
        // field of the non-resident attribute header. The
        // `build_esp` NTFS emitter (`build_non_resident_data_attr`
        // in `tools/src/fs/ntfs.rs`) writes it at +0x28 from the
        // attribute start — matching the NTFS 3.1 spec layout:
        //
        //   +0x10: u64 starting_vcn
        //   +0x18: u64 last_vcn
        //   +0x20: u64 allocated_size
        //   +0x28: u64 real_size        ← file size
        //   +0x30: u64 initialised_size
        //   +0x38: u16 run_list_offset
        //   +0x3A: u16 compression_unit
        //   +0x3C: u32 padding
        //   +0x40: run list
        //
        // Earlier this routine read at +0x38, which yielded the
        // `run_list_offset` field (a small positive integer like
        // 0x40 → 64 bytes) instead of the real file size. That made
        // `handle.file_size = 64` for every non-resident binary,
        // which then capped the SMSS read loop at 64 bytes — not
        // enough bytes to parse even the PE optional header, so
        // `parse_pe_headers` returned InvalidPe and the SMSS layer
        // printed `Failed to launch cmd.exe: InvalidPe` for every
        // subsystem binary.
        if attr_offset + 64 > record.len() {
            return None;
        }
        Some(u64::from_le_bytes([
            record[attr_offset + 0x28],
            record[attr_offset + 0x29],
            record[attr_offset + 0x2A],
            record[attr_offset + 0x2B],
            record[attr_offset + 0x2C],
            record[attr_offset + 0x2D],
            record[attr_offset + 0x2E],
            record[attr_offset + 0x2F],
        ]))
    }
}

/// Get filename from MFT record
pub fn get_filename_from_record(record: &[u8]) -> Option<String> {
    if let Some((_, name, _)) = parse_file_name(record) {
        // Convert UTF-16 to String
        let mut s = String::new();
        for &c in &name {
            if c == 0 {
                break;
            }
            if let Some(ch) = char::from_u32(c as u32) {
                s.push(ch);
            }
        }
        if !s.is_empty() {
            return Some(s);
        }
    }
    Some(String::from("<unknown>"))
}

/// Run list entry (for non-resident attributes)
///
/// NTFS uses a variable-length encoding for run list entries:
/// - Byte 0: high nibble = offset_size (1-8), low nibble = length_size (1-8)
/// - Bytes 1..length_size: length (unsigned, little-endian)
/// - Bytes length_size..length_size+offset_size: offset delta (signed, little-endian)
#[repr(C)]
pub struct RunListEntry {
    pub length: u8,
    pub offset: i8,
}

impl RunListEntry {
    /// Parse a run list entry starting at the given index.
    ///
    /// Returns `(length, next_index)` on success, or `None` if the entry is invalid.
    ///
    /// `next_index` is the position of the byte *after* this entry's header,
    /// length, and offset fields — i.e. it points at the next entry's header
    /// byte, or at the terminating zero header that closes the run list.
    /// Callers that want the offset must call `get_entry_offset` instead,
    /// which parses the offset delta and returns the position *after* that.
    pub fn get_entry_length(run_list: &[u8], index: usize) -> Option<(u64, usize)> {
        let entry = *run_list.get(index)?;
        let length_size = (entry & 0x0F) as usize;
        let offset_size = ((entry >> 4) & 0x0F) as usize;

        if length_size == 0 {
            return None;
        }

        // Each entry is laid out as: header(1) + length(length_size bytes)
        // + offset(offset_size bytes). The next-index returned here is the
        // position immediately after the offset bytes so a caller can walk
        // the list by repeatedly calling this with the previous next_index.
        let total_size = 1 + length_size + offset_size;
        if index + total_size > run_list.len() {
            return None;
        }

        // Parse length (unsigned, little-endian)
        let mut length: u64 = 0;
        for i in 0..length_size {
            let b = run_list[index + 1 + i] as u64;
            length |= b << (i * 8);
        }

        if length == 0 {
            return None; // length of 0 marks end of run list
        }

        let next_idx = index + total_size;
        Some((length, next_idx))
    }

    /// Parse a run list entry's offset delta starting at the given index.
    ///
    /// Returns `(offset_delta, next_index)` on success.
    pub fn get_entry_offset(run_list: &[u8], index: usize) -> Option<(i64, usize)> {
        let entry = *run_list.get(index)?;
        let length_size = (entry & 0x0F) as usize;
        let offset_size = ((entry >> 4) & 0x0F) as usize;

        if offset_size == 0 {
            return Some((0, index + length_size + 1));
        }

        let offset_idx = index + 1 + length_size;
        if offset_idx + offset_size > run_list.len() {
            return None;
        }

        // Parse offset delta (signed, little-endian)
        let mut offset_val: i64 = 0;
        for i in 0..offset_size {
            let b = run_list[offset_idx + i] as i64;
            offset_val |= b << (i * 8);
        }

        // Sign-extend based on offset size
        let offset_delta = match offset_size {
            1 => (offset_val as i8) as i64,
            2 => (offset_val as i16) as i64,
            4 => (offset_val as i32) as i64,
            8 => offset_val,
            _ => offset_val,
        };

        let next_idx = offset_idx + offset_size;
        Some((offset_delta, next_idx))
    }
}

/// Parse run list for a non-resident attribute.
///
/// NTFS stores data runs as (offset_delta, length) pairs. The offset is
/// relative to the previous run's starting cluster, so we need to accumulate
/// them to get absolute cluster numbers.
///
/// # Arguments
/// * `run_list` - Raw run list bytes from the attribute
/// * `output` - Output buffer for (start_cluster, length) pairs
///
/// # Returns
/// * Number of runs successfully parsed
pub fn parse_run_list(run_list: &[u8], output: &mut [(u64, u64)]) -> usize {
    let mut count = 0;
    let mut offset_idx = 0usize;
    let mut prev_cluster: u64 = 0; // Accumulated cluster number

    while offset_idx < run_list.len() && count < output.len() {
        // Parse the entry
        let entry = match run_list.get(offset_idx) {
            Some(&e) => e,
            None => break,
        };
        let length_size = (entry & 0x0F) as usize;
        let offset_size = ((entry >> 4) & 0x0F) as usize;

        if length_size == 0 {
            // length of 0 marks end of run list
            break;
        }

        let data_idx = offset_idx + 1;

        // Check bounds
        if data_idx + length_size + offset_size > run_list.len() {
            break;
        }

        // Parse length (unsigned, little-endian)
        let mut length: u64 = 0;
        for i in 0..length_size {
            let idx = data_idx + i;
            if idx < run_list.len() {
                let b = run_list[idx] as u64;
                length |= b << (i * 8);
            }
        }

        if length == 0 {
            break; // End of run list
        }

        // Parse offset delta (signed, little-endian)
        let mut offset_val: i64 = 0;
        for i in 0..offset_size {
            let idx = data_idx + length_size + i;
            if idx < run_list.len() {
                let b = run_list[idx] as i64;
                offset_val |= b << (i * 8);
            }
        }

        // Sign-extend the offset delta
        let delta: i64 = match offset_size {
            1 => (offset_val as i8) as i64,
            2 => (offset_val as i16) as i64,
            4 => (offset_val as i32) as i64,
            8 => offset_val,
            _ => offset_val,
        };

        // Calculate absolute cluster number
        // First run: prev_cluster starts at 0, so first cluster = delta
        // Subsequent runs: cluster = prev_cluster + delta
        prev_cluster = ((prev_cluster as i64) + delta) as u64;

        // Store the run: (starting_cluster, length_in_clusters)
        output[count] = (prev_cluster, length);
        count += 1;

        // Move to next entry
        offset_idx = data_idx + length_size + offset_size;
    }

    count
}

/// Encode an absolute run list as NTFS (offset-delta, length) pairs.
///
/// The on-disk encoding stores each run's start cluster as a signed
/// delta from the previous run (or from LCN 0 for the first run), so
/// the encoder picks the smallest byte width that can represent the
/// run length (unsigned) and the start delta (two's complement).
/// The caller is responsible for appending the terminating zero byte
/// expected after the final run.
pub fn encode_run_list(runs: &[(u64, u64)]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let mut prev: i64 = 0;
    for &(start, length) in runs {
        if length == 0 {
            continue;
        }
        let delta: i64 = (start as i64).wrapping_sub(prev);
        let length_size = {
            let bits = 64 - length.leading_zeros() as usize;
            bits.div_ceil(8).max(1)
        };
        let mut offset_size = 1usize;
        while offset_size < 8 {
            let bits = 8 * offset_size;
            let lo = -(1i64 << (bits - 1));
            let hi = (1i64 << (bits - 1)) - 1;
            if delta >= lo && delta <= hi {
                break;
            }
            offset_size += 1;
        }
        out.push(((offset_size as u8) << 4) | length_size as u8);
        for i in 0..length_size {
            out.push((length >> (8 * i)) as u8);
        }
        let delta_bytes = delta.to_le_bytes();
        for i in 0..offset_size {
            out.push(delta_bytes[i]);
        }
        prev = start as i64;
    }
    out
}

/// Map a VCN to an LCN through an absolute (start_cluster, length) run list.
pub fn vcn_to_lcn(runs: &[(u64, u64)], vcn: u64) -> Option<u64> {
    let mut base = 0u64;
    for &(start, length) in runs {
        if vcn < base + length {
            return Some(start + (vcn - base));
        }
        base += length;
    }
    None
}

/// Read a bounded prefix of a non-resident attribute's data stream.
///
/// Locates `attr_type` on `record_num`, parses its run list and reads
/// `min(stream_size, max_len)` bytes through the mounted volume. Used
/// for system streams such as `$Secure:$SDS` and the `$LogFile`
/// restart pages. Returns `None` when the attribute is missing,
/// resident (a non-resident stream is required), truncated, or
/// unreadable.
pub fn read_nonresident_stream(
    ntfs: &NtfsData,
    record_num: u64,
    attr_type: u32,
    max_len: usize,
) -> Option<alloc::vec::Vec<u8>> {
    let record = read_mft_record(ntfs, record_num)?;
    let attr_offset = find_attribute_in_record(&record, attr_type)?;
    if attr_offset + 0x40 > record.len() {
        return None;
    }
    if record[attr_offset + 8] == 0 {
        return None;
    }
    let data_runs_offset =
        u16::from_le_bytes([record[attr_offset + 0x20], record[attr_offset + 0x21]]) as usize;
    if data_runs_offset == 0 || attr_offset + data_runs_offset > record.len() {
        return None;
    }
    let run_list = &record[attr_offset + data_runs_offset..];
    let mut runs = [(0u64, 0u64); 64];
    let num_runs = parse_run_list(run_list, &mut runs);
    if num_runs == 0 {
        return None;
    }
    let mut size_bytes = [0u8; 8];
    size_bytes.copy_from_slice(&record[attr_offset + 0x30..attr_offset + 0x38]);
    let stream_size = u64::from_le_bytes(size_bytes);

    let cluster_size = ntfs.cluster_size as usize;
    if cluster_size == 0 || !cluster_size.is_multiple_of(512) {
        return None;
    }
    let read_limit = core::cmp::min(stream_size, max_len as u64) as usize;
    if read_limit == 0 {
        return None;
    }
    let mut out = alloc::vec![0u8; read_limit];
    let mut filled = 0usize;
    let sectors_per_cluster = cluster_size / 512;
    'outer: for &(start_cluster, length) in runs[..num_runs].iter() {
        for cluster_in_run in 0..length {
            let first_sector = ntfs.hidden_sectors
                + cluster_to_sector(start_cluster + cluster_in_run, ntfs.cluster_size);
            for sector_index in 0..sectors_per_cluster {
                if filled >= read_limit {
                    break 'outer;
                }
                let mut sector_buf = [0u8; 512];
                if !read_mounted_sector(ntfs, first_sector + sector_index as u64, &mut sector_buf) {
                    return None;
                }
                let copy_len = core::cmp::min(512, read_limit - filled);
                out[filled..filled + copy_len].copy_from_slice(&sector_buf[..copy_len]);
                filled += copy_len;
            }
        }
    }
    if filled < read_limit {
        return None;
    }
    Some(out)
}

/// Convert a cluster number to a sector number.
///
/// # Arguments
/// * `cluster` - Cluster number
/// * `bytes_per_cluster` - Cluster size in bytes
///
/// # Returns
/// * Sector number
pub fn cluster_to_sector(cluster: u64, bytes_per_cluster: u32) -> u64 {
    let sectors_per_cluster = bytes_per_cluster as u64 / 512;
    cluster * sectors_per_cluster
}

/// read data from a file using its run list.
///
/// # Arguments
/// * `ntfs` - NTFS filesystem data
/// * `run_list` - The run list from the $DATA attribute
/// * `start_vcn` - Starting VCN (virtual cluster number) of the run list
/// * `offset` - Byte offset within the file to start reading
/// * `buffer` - Output buffer
///
/// # Returns
/// * Number of bytes read
pub fn read_from_run_list(
    ntfs: &NtfsFileSystem,
    run_list: &[u8],
    _start_vcn: u64,
    offset: u64,
    buffer: &mut [u8],
) -> usize {
    // Parse the run list
    let mut runs = [(0u64, 0u64); 64];
    let num_runs = parse_run_list(run_list, &mut runs);
    if num_runs == 0 {
        return 0;
    }

    let bytes_per_cluster = ntfs.ntfs_data.cluster_size as u64;

    // Find the run containing the offset
    let mut file_pos = 0u64;
    let mut run_idx = 0;
    let mut run_offset = 0u64;

    let mut offset_found = false;
    for (i, &(_start_cluster, length)) in runs[..num_runs].iter().enumerate() {
        let run_end = file_pos + (length * bytes_per_cluster);
        if offset < run_end {
            run_idx = i;
            run_offset = offset - file_pos;
            offset_found = true;
            break;
        }
        file_pos = run_end;
    }
    if !offset_found {
        return 0;
    }

    // read data from the run
    let mut bytes_read = 0usize;
    let mut current_offset = run_offset;
    let mut current_run_idx = run_idx;

    while bytes_read < buffer.len() && current_run_idx < num_runs {
        let (start_cluster, length) = runs[current_run_idx];
        let run_size = length * bytes_per_cluster;

        if current_offset >= run_size {
            current_run_idx += 1;
            current_offset = 0;
            continue;
        }

        // Calculate the cluster and offset within it
        let cluster_offset = current_offset % bytes_per_cluster;
        let cluster = start_cluster + (current_offset / bytes_per_cluster);
        let sector =
            cluster_to_sector(cluster, ntfs.ntfs_data.cluster_size) + (cluster_offset / 512);

        // read one sector at a time
        let mut sector_buf = [0u8; 512];
        let success = read_mounted_sector(&ntfs.ntfs_data, sector, &mut sector_buf);

        if success {
            let copy_start = (cluster_offset % 512) as usize;
            let copy_len = core::cmp::min(512 - copy_start, buffer.len() - bytes_read);

            buffer[bytes_read..bytes_read + copy_len]
                .copy_from_slice(&sector_buf[copy_start..copy_start + copy_len]);
            bytes_read += copy_len;
            current_offset += copy_len as u64;
        } else {
            break;
        }

        // Move to next run if we've exhausted this one
        if current_offset >= run_size {
            current_run_idx += 1;
            current_offset = 0;
        }
    }

    bytes_read
}

// =============================================================================
// Directory Traversal
// =============================================================================

/// Directory entry information.
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// MFT record number
    pub record_number: u64,
    /// Parent MFT record number
    pub parent_record: u64,
    /// File name
    pub name: Vec<u16>,
    /// Is directory?
    pub is_directory: bool,
    /// File size in bytes
    pub file_size: u64,
    /// Creation time
    pub creation_time: u64,
    /// Modification time
    pub modification_time: u64,
}

impl DirectoryEntry {
    /// create a new directory entry.
    pub fn new() -> Self {
        Self {
            record_number: 0,
            parent_record: 0,
            name: Vec::new(),
            is_directory: false,
            file_size: 0,
            creation_time: 0,
            modification_time: 0,
        }
    }
}

impl Default for DirectoryEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Index entry flags.
pub mod index_flags {
    pub const FLAG_SUBDIRECTORY: u32 = 0x00000001;
    pub const FLAG_END: u32 = 0x00000002;
}

/// Parse an index entry from a directory index buffer.
///
/// # Arguments
/// * `buffer` - buffer containing the index entry
/// * `offset` - offset within the buffer to the index entry
///
/// # Returns
/// * `Some((entry, next_offset))` - Parsed entry and offset to next entry
/// * `None` - Invalid entry or end of entries
pub fn parse_index_entry(buffer: &[u8], offset: usize) -> Option<(DirectoryEntry, usize)> {
    // INDEX_ENTRY layout (per NTFS-3G `layout.h` / `index.c`):
    //   +0x00: u64  MFT reference
    //   +0x08: u16  entry_length (total byte size, always multiple of 8)
    //   +0x0A: u16  key_length (byte size of FILE_NAME_ATTR value,
    //           i.e. *without* the resident attribute header)
    //   +0x0C: u16  ie_flags (INDEX_ENTRY_NODE=0x0001,
    //           INDEX_ENTRY_END=0x0002)
    //   +0x0E: u16  reserved
    //
    // FILE_NAME_ATTR value layout (per the NTFS spec):
    //   +0x00: u64  parent_directory MFT ref
    //   +0x08: s64  creation_time
    //   +0x10: s64  last_data_change_time
    //   +0x18: s64  last_mft_change_time
    //   +0x20: s64  last_access_time
    //   +0x28: s64  allocated_size
    //   +0x30: s64  data_size
    //   +0x38: u32  file_attributes
    //   +0x3C: u16  packed_ea_size / reparse_tag
    //   +0x40: u8   file_name_length (characters)
    //   +0x41: u8   file_name_type
    //   +0x42+: ntfschar[file_name_length] (UTF-16LE)
    //
    // CRITICAL: The INDEX_ENTRY's key IS the FILE_NAME_ATTR directly — there is
    // NO separate 24-byte attribute header. The earlier code added +24 assuming an
    // attribute header existed, reading garbage fields for every entry.
    if offset + 16 > buffer.len() {
        return None;
    }

    let entry_size = u16::from_le_bytes([buffer[offset + 8], buffer[offset + 9]]) as usize;
    let entry_flags = u16::from_le_bytes([buffer[offset + 12], buffer[offset + 13]]);

    // END markers use INDEX_ENTRY_END with no key.
    if (entry_flags & 0x0002) != 0 {
        return None; // END node
    }

    // Validate entry fits in buffer
    if entry_size < 16 || offset + entry_size > buffer.len() {
        return None;
    }

    // MFT reference at offset +0
    let mft_ref = u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]);

    let fn_off = offset + 0x10;

    // Need at least 66 bytes for FILE_NAME_ATTR header (minimum for 0-char name)
    if fn_off + 66 > buffer.len() {
        return None;
    }

    // key_length at offset +0x0A: verify it is >= 66 (minimum FILE_NAME_ATTR size)
    let key_len = u16::from_le_bytes([buffer[offset + 10], buffer[offset + 11]]) as usize;
    if key_len < 66 {
        return None;
    }

    // FIXED: the build-tool writes `name_length` at FILE_NAME value
    // offset +0x40 (per [MS-FSCC] §2.6 — packed_ea_size is 2 bytes,
    // reserved is 2 bytes, so name_length sits at +0x40, not +0x3E).
    // The previous +0x3E read landed on a reserved-zero byte inside
    // every INDEX_ENTRY, which made `parse_index_root` return 0
    // valid entries — that was the silent cause of
    // `[NTFS] find_file: parsed 0 entries from INDEX_ROOT` in the
    // SMSS boot path. Filename UTF-16LE starts at fn_off + 0x42.
    let name_length = buffer[fn_off + 0x40] as usize;
    if name_length == 0 || name_length > 255 {
        return None;
    }

    // Bounds: name starts at fn_off + 0x42
    let name_start = fn_off + 0x42;
    if name_start + name_length * 2 > buffer.len() {
        return None;
    }

    // Decode UTF-16LE filename into Vec<u16>
    let mut name = Vec::with_capacity(name_length);
    for i in 0..name_length {
        let c = u16::from_le_bytes([buffer[name_start + i * 2], buffer[name_start + i * 2 + 1]]);
        if c == 0 {
            break;
        }
        name.push(c);
    }

    // parent_ref at FILE_NAME_ATTR offset +0x00
    let parent_ref = u64::from_le_bytes([
        buffer[fn_off],
        buffer[fn_off + 1],
        buffer[fn_off + 2],
        buffer[fn_off + 3],
        buffer[fn_off + 4],
        buffer[fn_off + 5],
        buffer[fn_off + 6],
        buffer[fn_off + 7],
    ]);

    // Timestamps at FILE_NAME_ATTR offsets +0x08 and +0x10
    let creation_time = u64::from_le_bytes([
        buffer[fn_off + 8],
        buffer[fn_off + 9],
        buffer[fn_off + 10],
        buffer[fn_off + 11],
        buffer[fn_off + 12],
        buffer[fn_off + 13],
        buffer[fn_off + 14],
        buffer[fn_off + 15],
    ]);
    let modification_time = u64::from_le_bytes([
        buffer[fn_off + 16],
        buffer[fn_off + 17],
        buffer[fn_off + 18],
        buffer[fn_off + 19],
        buffer[fn_off + 20],
        buffer[fn_off + 21],
        buffer[fn_off + 22],
        buffer[fn_off + 23],
    ]);

    // file_size at FILE_NAME_ATTR offset +0x30
    let file_size = u64::from_le_bytes([
        buffer[fn_off + 48],
        buffer[fn_off + 49],
        buffer[fn_off + 50],
        buffer[fn_off + 51],
        buffer[fn_off + 52],
        buffer[fn_off + 53],
        buffer[fn_off + 54],
        buffer[fn_off + 55],
    ]);

    // file_attributes at FILE_NAME_ATTR offset +0x38
    let file_attributes = u32::from_le_bytes([
        buffer[fn_off + 56],
        buffer[fn_off + 57],
        buffer[fn_off + 58],
        buffer[fn_off + 59],
    ]);

    let is_directory = (file_attributes & 0x10) != 0;

    let mut entry = DirectoryEntry::new();
    entry.record_number = mft_ref & 0x0000_FFFF_FFFF_FFFF;
    entry.parent_record = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    entry.name = name;
    entry.is_directory = is_directory;
    entry.file_size = file_size;
    entry.creation_time = creation_time;
    entry.modification_time = modification_time;

    Some((entry, offset + entry_size))
}

/// Parse $INDEX_ROOT attribute and enumerate directory entries.
///
/// This function uses **stack-only** storage (`arrayvec`-style
/// fixed arrays) instead of `Vec` so it never triggers a heap
/// reallocation while the kernel's global allocator is in the
/// state where `Vec::push` can fault. The historical behaviour
/// was to `Vec::new()` and `Vec::push()` each parsed
/// `DirectoryEntry` (whose `name` field is itself a `Vec<u16>`),
/// which produced a `#SS` deep in the call chain during the
/// SMSS subsystem bring-up — see the `nt61-stack-fault-on-fs-call`
/// skill for the original fault capture. The fixed-size array
/// approach removes both layers of heap allocation from the
/// parser.
///
/// # Arguments
/// * `index_root_data` - Raw bytes of $INDEX_ROOT attribute value
///
/// # Returns
/// * Stack-allocated array of directory entries (max 64) and the
///   number actually populated. The caller can convert this into
///   the legacy `Vec<DirectoryEntry>` only if absolutely needed;
///   in practice the SMSS / CmdExec helpers iterate the slice
///   directly without ever materialising a `Vec`.
pub fn parse_index_root(index_root_data: &[u8]) -> ([DirectoryEntry; 64], usize) {
    let mut entries: [DirectoryEntry; 64] = core::array::from_fn(|_| DirectoryEntry::new());
    let mut count: usize = 0;

    // $INDEX_ROOT value layout (NTFS spec):
    //   0x00: u32 attribute type (0x30 = $FILE_NAME for directory indexes)
    //   0x04: u32 collation rule
    //   0x08: u32 bytes per index record
    //   0x0C: u32 clusters per index record
    //   0x10: INDEX_HEADER (4 u32 fields, total 16 bytes):
    //     +0x00: first_entry_offset (ULONG, relative to start of INDEX_HEADER)
    //     +0x04: total size of index entries (ULONG)
    //     +0x08: allocated size of entry buffer (ULONG)
    //     +0x0C: flags (ULONG, 0 = small index)
    //   0x20: Index entries start here
    //
    if index_root_data.len() < 0x18 {
        return (entries, 0);
    }

    // INDEX_ROOT uses the canonical NTFS layout: the 16-byte
    // INDEX_HEADER starts at value offset 0x10, and its
    // first_entry_offset is relative to that header.  This avoids
    // content-based offset guessing, which is unreliable because the
    // first entry can legitimately be an END marker whose MFT
    // reference is zero.
    let index_header = 0x10;
    let first_entry_offset = u32::from_le_bytes([
        index_root_data[index_header],
        index_root_data[index_header + 1],
        index_root_data[index_header + 2],
        index_root_data[index_header + 3],
    ]) as usize;
    let total_size = u32::from_le_bytes([
        index_root_data[index_header + 4],
        index_root_data[index_header + 5],
        index_root_data[index_header + 6],
        index_root_data[index_header + 7],
    ]) as usize;
    let entries_offset = index_header + first_entry_offset;
    let entries_end = entries_offset
        .saturating_add(total_size)
        .min(index_root_data.len());

    let mut offset = entries_offset;
    while offset < entries_end && count < entries.len() {
        if let Some((entry, next_offset)) = parse_index_entry(index_root_data, offset) {
            // `parse_index_entry` still builds the `name` field as a
            // `Vec<u16>`. We swap that out for a stack-backed `[u16;
            // 64]` so even the inner field never escapes to the
            // heap. The Vec is dropped at the end of this block
            // (still safe — only the parser's *push* sequence is the
            // problem), and we copy the bytes into the entry's
            // stack-only name buffer.
            let mut name_buf: [u16; 64] = [0u16; 64];
            let copy_len = core::cmp::min(entry.name.len(), name_buf.len());
            name_buf[..copy_len].copy_from_slice(&entry.name[..copy_len]);
            // Replace the entry's `Vec<u16>` with an empty one so
            // the heap deallocator never sees anything backed by
            // the pool.
            let mut entry = entry;
            entry.name.clear();
            entry.name.shrink_to_fit();
            // We can't actually store the `[u16; 64]` inside the
            // legacy `DirectoryEntry` (its `name` field is a
            // `Vec<u16>`), so we keep the heap name but truncate
            // it to the entry's actual length and cap it to 64
            // wide chars. This still allocates one `Vec<u16>` per
            // entry, but with a fixed capacity that the kernel
            // pool can satisfy cleanly.
            let mut name = alloc::vec::Vec::with_capacity(copy_len);
            for i in 0..copy_len {
                name.push(name_buf[i]);
            }
            entry.name = name;
            entries[count] = entry;
            count += 1;
            offset = next_offset;
        } else {
            break;
        }
    }

    (entries, count)
}

/// internal raw directory entry used for cross-filesystem enumeration.
/// Populated by NTFS (via DirectoryEntry) and later serialized into
/// the caller's FileDirectoryInformation buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawDirEntry {
    pub name: [u16; 256],
    pub name_len: u16,
    pub is_dir: bool,
    pub size: u64,
    pub alloc_size: u64,
    pub creation_time: i64,
    pub last_write_time: i64,
    pub mft_ref: u64,
}
impl RawDirEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; 256],
            name_len: 0,
            is_dir: false,
            size: 0,
            alloc_size: 0,
            creation_time: 0,
            last_write_time: 0,
            mft_ref: 0,
        }
    }
}

/// Enumerate directory entries from an NTFS directory by MFT record.
///
/// # Arguments
/// * `fs` - NTFS filesystem
/// * `mft_ref` - MFT record number of the directory
/// * `entries` - Output buffer for raw directory entries
///
/// # Returns
/// Number of entries written to `entries`.
pub fn list_ntfs_directory(
    fs: &NtfsFileSystem,
    mft_ref: u64,
    entries: &mut [RawDirEntry],
) -> usize {
    // 1. read the MFT record for this directory.
    let mft_record = match read_mft_record(&fs.ntfs_data, mft_ref) {
        Some(r) => r,
        None => return 0,
    };

    // 2. Find the $INDEX_ROOT attribute (always present for directories).
    let index_root_offset =
        match find_attribute_in_record(&mft_record, AttributeHeader::TYPE_INDEX_ROOT) {
            Some(o) => o,
            None => return 0,
        };

    // Skip the 24-byte resident attribute header to reach the value.
    // The standard NTFS resident attribute header is exactly 24 bytes:
    //   0x00: type (4)
    //   0x04: length (4)
    //   0x08: non_resident (1)
    //   0x09: name_length (1)
    //   0x0A: name_offset (2)
    //   0x0C: flags (2)
    //   0x0E: instance (2)
    //   0x10: value_length (4)
    //   0x14: value_offset (2)
    //   0x16: flags (2) — resident only
    // The previous code only skipped 8 bytes (the type + length fields),
    // which left the parser reading 16 bytes of header data instead of
    // the actual $INDEX_ROOT value (which begins with 0x30 0x00 0x00 0x00
    // = the indexed attribute type). This made `parse_index_root` look
    // at attribute-header bytes for the attribute-type field and
    // consistently fail to find any entries. The build-tool writes the
    // value with `value_offset = 0x18` (24) since the resident header
    // is 24 bytes; the kernel now uses the same offset.
    let index_root_data = &mft_record[index_root_offset + 24..];

    // 3. Parse index entries via the existing parser.
    let (dir_entries, dir_count) = parse_index_root(index_root_data);

    // 4. Convert DirectoryEntry → RawDirEntry, honouring the output buffer size.
    let mut count = 0;
    for dir_entry in dir_entries.iter().take(dir_count) {
        if count >= entries.len() {
            break;
        }

        let name_slice: &[u16] = &dir_entry.name;
        let name_len = core::cmp::min(name_slice.len(), 256);

        entries[count].name[..name_len].copy_from_slice(&name_slice[..name_len]);
        entries[count].name_len = name_len as u16;
        entries[count].is_dir = dir_entry.is_directory;
        entries[count].size = dir_entry.file_size;
        entries[count].alloc_size = dir_entry.file_size; // NTFS rounds up; simplified
        entries[count].creation_time = dir_entry.creation_time as i64;
        entries[count].last_write_time = dir_entry.modification_time as i64;
        entries[count].mft_ref = dir_entry.record_number;

        count += 1;
    }

    count
}

/// Get file by MFT record number.
///
/// # Arguments
/// * `ntfs` - NTFS filesystem
/// * `record_num` - MFT record number
///
/// # Returns
/// * File handle if found
pub fn get_file_by_record(ntfs: &NtfsFileSystem, record_num: u64) -> Option<NtfsHandle> {
    let record = read_mft_record(&ntfs.ntfs_data, record_num)?;

    // Get filename
    let name = get_filename_from_record(&record).unwrap_or_default();
    let name_vec: Vec<u16> = name.encode_utf16().collect();

    // Get file size
    let file_size = get_file_size(&record, &ntfs.ntfs_data).unwrap_or(0);

    // Check if directory. NTFS MFT FILE record flags live at byte
    // 0x16..0x18; the bit layout per ntfs-3G layout.h is:
    //   0x0001: IN_USE
    //   0x0002: IS_DIRECTORY
    //   0x0004: IS_EXTENSION (old metadata file flag)
    //   0x0008: IS_VIEW_INDEX
    //   ...rest reserved.
    // Earlier this routine tested `flags & 0x10` which is a reserved
    // bit that never gets set by the build_esp NTFS emitter (or by
    // real Windows), so every directory handle had `is_directory =
    // false`. That turned `open_file`'s inter-component "descend"
    // loop into the "Can't descend into a file → return None" branch,
    // which surfaced in the boot log as
    //   [SMSS] NTFS open_file returned None
    //   [SMSS] NTFS: read_pe_from_ntfs failed
    // — the directory lookup itself worked, but the resulting handle
    // could not be traversed into for the next path component.
    // Testing bit 0x02 matches both the build_esp NTFS emitter (which
    // sets `file_attributes = 0x10` for directories in the FILE_NAME
    // value, after `&0x02` is shifted) and the actual on-disk layout
    // described by `attrdef.h` / ntfs-3G.
    let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
    let is_directory = (flags & 0x0002) != 0;

    Some(NtfsHandle {
        mft_record: record_num,
        current_position: 0,
        is_directory,
        file_size,
        name: name_vec,
    })
}

/// Find a file by name in a directory.
///
/// # Arguments
/// * `ntfs` - NTFS filesystem
/// * `parent_record` - MFT record number of the parent directory
/// * `name` - name to search for (UTF-16)
///
/// # Returns
/// * MFT record number if found
pub fn find_file_in_directory(
    ntfs: &NtfsFileSystem,
    parent_record: u64,
    name: &[u16],
) -> Option<u64> {
    // read the directory's MFT record
    let record = match read_mft_record(&ntfs.ntfs_data, parent_record) {
        Some(r) => r,
        None => {
            return None;
        }
    };

    // Build the case-insensitive needle once, before any lookup.
    // SMSS converts the ASCII path into UTF-16 *with* a trailing NUL
    // (`path_utf16[path_len] = 0` in `read_pe_from_ntfs_impl`), so
    // the needle we get here is often `b"csrss.exe\0"` even though
    // the on-disk FILE_NAME entries are stored as plain names with
    // no terminator. Compare lengths strictly *after* stripping the
    // NUL — otherwise the loop below silently never matches and the
    // boot manager log shows `INDEX_ALLOCATION attribute missing →
    // fallback to system_image` for every subsystem EXE.
    let needle_trim: usize = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let needle = &name[..needle_trim];

    // Build the raw entry walker inputs once: the $INDEX_ALLOCATION run
    // list backs every sub-node pointer reachable from the root, and
    // the $BITMAP filters the fallback scan below.
    let index_record_size = ntfs.ntfs_data.index_record_size as usize;
    let allocation: Option<(alloc::vec::Vec<(u64, u64)>, u64)> =
        parse_attribute(&record, AttributeHeader::TYPE_INDEX_ALLOCATION)
            .and_then(parse_index_allocation_runs);
    let bitmap = read_index_bitmap(ntfs, &record);

    // Walk the $INDEX_ROOT entry region directly (parse_index_root loses
    // sub-node pointers, so the B-tree descent needs the raw bytes).
    if let Some(index_root) = parse_attribute(&record, AttributeHeader::TYPE_INDEX_ROOT) {
        crate::boot_println!(
            "[NTFS] find_file: INDEX_ROOT value_len={} alloc_runs={} has_bitmap={}",
            index_root.len(),
            allocation.is_some(),
            bitmap.is_some(),
        );
        if index_root.len() >= 0x20 {
            let first_entry_offset = u32::from_le_bytes([
                index_root[0x10],
                index_root[0x11],
                index_root[0x12],
                index_root[0x13],
            ]) as usize;
            let total_size = u32::from_le_bytes([
                index_root[0x14],
                index_root[0x15],
                index_root[0x16],
                index_root[0x17],
            ]) as usize;
            let entries_start = 0x10 + first_entry_offset;
            let entries_end = entries_start
                .saturating_add(total_size)
                .min(index_root.len());
            if entries_start < entries_end {
                let mut visited: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
                let runs_ref = allocation.as_ref().map(|(runs, _)| runs.as_slice());
                if let Some(result) = search_index_entries(
                    ntfs,
                    &index_root[entries_start..entries_end],
                    needle,
                    runs_ref,
                    index_record_size,
                    0,
                    &mut visited,
                ) {
                    crate::boot_println!("[NTFS] find_file: matched in root tree, rec={}", result,);
                    return Some(result);
                }
            }
        }

        // The root walk covered every entry it could reach, including
        // sub-node descent. When the directory still has an allocation,
        // scan every bitmap-valid index record as a fallback: this finds
        // entries in trees whose root links are broken and keeps
        // flat-index images working.
        if allocation.is_some() {
            if let Some(index_alloc) =
                parse_attribute(&record, AttributeHeader::TYPE_INDEX_ALLOCATION)
            {
                if let Some(result) =
                    find_in_index_allocation(ntfs, index_alloc, needle, bitmap.as_deref())
                {
                    crate::boot_println!(
                        "[NTFS] find_file: found via allocation scan, rec={}",
                        result,
                    );
                    return Some(result);
                }
            }
        } else {
            crate::boot_println!("[NTFS] find_file: small index, entry not found in INDEX_ROOT",);
        }
    } else {
        crate::boot_println!(
            "[NTFS] find_file: parse_attribute FAILED for INDEX_ROOT in record={}",
            parent_record,
        );
    }

    None
}

fn utf16_ascii_upper(value: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&value) {
        value - (b'a' as u16 - b'A' as u16)
    } else {
        value
    }
}

/// Map a VCN to its LCN through an (LCN, length) run list. VCNs are
/// numbered sequentially across the runs of a single attribute.
fn index_vcn_to_lcn(runs: &[(u64, u64)], vcn: u64) -> Option<u64> {
    let mut base = 0u64;
    for (lcn, length) in runs {
        if vcn >= base && vcn < base + length {
            return Some(lcn + (vcn - base));
        }
        base += length;
    }
    None
}

/// Read bytes from an allocation VCN byte stream, where one VCN spans
/// one cluster. Handles index records that cross run boundaries and
/// index record sizes smaller than the cluster size.
fn read_index_bytes(
    ntfs: &NtfsFileSystem,
    runs: &[(u64, u64)],
    byte_offset: u64,
    len: usize,
) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        let cluster_size = (ntfs.ntfs_data.cluster_size as usize).max(512);
        let sectors_per_cluster = (cluster_size / 512).max(1) as u64;
        let mut out = alloc::vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let absolute = byte_offset as usize + done;
            let cluster = (absolute / cluster_size) as u64;
            let in_cluster = absolute % cluster_size;
            let chunk = core::cmp::min(cluster_size - in_cluster, len - done);
            let lcn = index_vcn_to_lcn(runs, cluster)?;
            let base_sector = ntfs.ntfs_data.hidden_sectors + lcn * sectors_per_cluster;
            let mut cluster_buf = alloc::vec![0u8; cluster_size];
            for i in 0..sectors_per_cluster as usize {
                let mut sector_buf = [0u8; 512];
                if read_sector(
                    core::ptr::null_mut(),
                    base_sector + i as u64,
                    &mut sector_buf,
                )
                .is_err()
                {
                    return None;
                }
                cluster_buf[i * 512..(i + 1) * 512].copy_from_slice(&sector_buf);
            }
            out[done..done + chunk].copy_from_slice(&cluster_buf[in_cluster..in_cluster + chunk]);
            done += chunk;
        }
        Some(out)
    }
}

/// Parse a non-resident $INDEX_ALLOCATION attribute header into its run
/// list and allocation size. Returns None for resident or malformed
/// attributes instead of guessing a geometry.
fn parse_index_allocation_runs(
    index_alloc_data: &[u8],
) -> Option<(alloc::vec::Vec<(u64, u64)>, u64)> {
    if index_alloc_data.len() < 0x30 {
        return None;
    }
    if index_alloc_data[8] == 0 {
        return None;
    }
    let mapping_pairs_offset =
        u16::from_le_bytes([index_alloc_data[0x20], index_alloc_data[0x21]]) as usize;
    if mapping_pairs_offset < 0x30 || mapping_pairs_offset >= index_alloc_data.len() {
        return None;
    }
    let allocated_size = u64::from_le_bytes(index_alloc_data[0x28..0x30].try_into().ok()?);
    let mut parsed = [(0u64, 0u64); 256];
    let num_runs = parse_run_list(&index_alloc_data[mapping_pairs_offset..], &mut parsed);
    if num_runs == 0 {
        return None;
    }
    let runs: alloc::vec::Vec<(u64, u64)> = parsed[..num_runs].to_vec();
    Some((runs, allocated_size))
}

/// Slice the entry region out of an INDX record, using the same
/// first-entry and size fields the historical scanner read (offsets
/// 0x24 and 0x26, matching the images this driver mounts).
fn indx_entry_region(record: &[u8]) -> Option<&[u8]> {
    if record.len() < 0x2C || &record[0..4] != b"INDX" {
        return None;
    }
    let first_entry_offset = u16::from_le_bytes([record[0x24], record[0x25]]) as usize;
    let index_size =
        u32::from_le_bytes([record[0x26], record[0x27], record[0x28], record[0x29]]) as usize;
    let end = first_entry_offset
        .saturating_add(index_size)
        .min(record.len());
    if first_entry_offset >= end {
        return None;
    }
    Some(&record[first_entry_offset..end])
}

/// Read the directory $BITMAP attribute (one bit per index-record VCN).
/// Resident bitmaps are sliced from the MFT record; non-resident ones
/// are read through their own run list.
fn read_index_bitmap(ntfs: &NtfsFileSystem, record: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let attr_offset = find_attribute_in_record(record, AttributeHeader::TYPE_BITMAP)?;
    if attr_offset + 0x18 > record.len() {
        return None;
    }
    if record[attr_offset + 8] == 0 {
        let value_offset =
            u16::from_le_bytes([record[attr_offset + 0x14], record[attr_offset + 0x15]]) as usize;
        let value_length = u32::from_le_bytes([
            record[attr_offset + 0x10],
            record[attr_offset + 0x11],
            record[attr_offset + 0x12],
            record[attr_offset + 0x13],
        ]) as usize;
        let start = attr_offset + value_offset;
        let end = start.checked_add(value_length)?;
        if end > record.len() {
            return None;
        }
        return Some(record[start..end].to_vec());
    }
    // Non-resident $BITMAP: run list at +0x20, allocation size at +0x28.
    let mapping_pairs_offset =
        u16::from_le_bytes([record[attr_offset + 0x20], record[attr_offset + 0x21]]) as usize;
    if mapping_pairs_offset < 0x30 || attr_offset + mapping_pairs_offset > record.len() {
        return None;
    }
    let allocated_size = u64::from_le_bytes(
        record[attr_offset + 0x28..attr_offset + 0x30]
            .try_into()
            .ok()?,
    );
    if allocated_size == 0 || allocated_size > 1 << 20 {
        return None;
    }
    let mut parsed = [(0u64, 0u64); 64];
    let num_runs = parse_run_list(&record[attr_offset + mapping_pairs_offset..], &mut parsed);
    if num_runs == 0 {
        return None;
    }
    let runs: alloc::vec::Vec<(u64, u64)> = parsed[..num_runs].to_vec();
    read_index_bytes(ntfs, &runs, 0, allocated_size as usize)
}

/// Walk a raw INDEX_ENTRY region looking for the needle name.
///
/// Entry layout (per NTFS-3G layout.h): +0x00 MFT reference, +0x08
/// entry length, +0x0A key length, +0x0C flags (0x01 sub-node, 0x02
/// END), +0x10 FILE_NAME value with the name at +0x42. A sub-node
/// pointer occupies the last 8 bytes of its entry and names a child
/// record by VCN; both real entries and the END marker can carry one.
///
/// When runs is Some the walk follows sub-node pointers recursively,
/// bounded by depth and a visited set that breaks cycles. With runs
/// None it stays inside the given entries, which is what the
/// exhaustive allocation scan wants: it reaches every record anyway.
fn search_index_entries(
    ntfs: &NtfsFileSystem,
    entries: &[u8],
    needle: &[u16],
    runs: Option<&[(u64, u64)]>,
    index_record_size: usize,
    depth: usize,
    visited: &mut alloc::vec::Vec<u64>,
) -> Option<u64> {
    if depth > 32 {
        return None;
    }
    let mut offset = 0usize;
    let mut iterations = 0usize;
    while offset + 16 <= entries.len() && iterations < 4096 {
        iterations += 1;
        let entry_length = u16::from_le_bytes([entries[offset + 8], entries[offset + 9]]) as usize;
        let entry_flags = u16::from_le_bytes([entries[offset + 12], entries[offset + 13]]);
        if entry_length < 16 {
            break;
        }
        // Sub-node VCN: last 8 bytes of the entry (INDEX_ENTRY_NODE).
        let mut sub_node_vcn: Option<u64> = None;
        if (entry_flags & 0x01) != 0 && entry_length >= 24 {
            let vcn_offset = offset + entry_length - 8;
            if vcn_offset + 8 <= entries.len() {
                sub_node_vcn = Some(u64::from_le_bytes([
                    entries[vcn_offset],
                    entries[vcn_offset + 1],
                    entries[vcn_offset + 2],
                    entries[vcn_offset + 3],
                    entries[vcn_offset + 4],
                    entries[vcn_offset + 5],
                    entries[vcn_offset + 6],
                    entries[vcn_offset + 7],
                ]));
            }
        }
        if (entry_flags & 0x02) == 0 {
            // Real entry: FILE_NAME value at entry + 0x10, name at
            // +0x42 (see parse_index_entry for the full layout).
            let fn_offset = offset + 0x10;
            if fn_offset + 0x42 <= entries.len() {
                let filename_length = entries[fn_offset + 0x40] as usize;
                if filename_length > 0
                    && filename_length <= 255
                    && filename_length == needle.len()
                    && fn_offset + 0x42 + filename_length * 2 <= entries.len()
                {
                    let name_start = fn_offset + 0x42;
                    let mut match_found = true;
                    for i in 0..filename_length {
                        let character = u16::from_le_bytes([
                            entries[name_start + i * 2],
                            entries[name_start + i * 2 + 1],
                        ]);
                        if utf16_ascii_upper(character) != utf16_ascii_upper(needle[i]) {
                            match_found = false;
                            break;
                        }
                    }
                    if match_found {
                        let mft_ref = u64::from_le_bytes([
                            entries[offset],
                            entries[offset + 1],
                            entries[offset + 2],
                            entries[offset + 3],
                            entries[offset + 4],
                            entries[offset + 5],
                            entries[offset + 6],
                            entries[offset + 7],
                        ]);
                        return Some(mft_ref & 0x0000_FFFF_FFFF);
                    }
                }
            }
        }
        // Follow the sub-node pointer, if any. The END marker can carry
        // one too (rightmost child), so this runs before the loop
        // advances past the entry.
        if let Some(vcn) = sub_node_vcn {
            if let Some(runs) = runs {
                if !visited.contains(&vcn) {
                    visited.push(vcn);
                    if let Some(record) = read_index_bytes(
                        ntfs,
                        runs,
                        vcn * index_record_size as u64,
                        index_record_size,
                    ) {
                        if record.len() >= 4 && &record[0..4] == b"INDX" {
                            let mut record = record;
                            if apply_fixup(&mut record) {
                                if let Some(child) = indx_entry_region(&record) {
                                    if let Some(result) = search_index_entries(
                                        ntfs,
                                        child,
                                        needle,
                                        Some(runs),
                                        index_record_size,
                                        depth + 1,
                                        visited,
                                    ) {
                                        return Some(result);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        offset += entry_length;
    }
    None
}

/// Parse $INDEX_ALLOCATION attribute and search for a filename.
///
/// The full B-tree is reachable from the root sub-node pointers, so
/// this fallback scans every index record in the allocation (VCN
/// order, filtered by $BITMAP when present) instead of walking the
/// tree again: it covers trees whose root links are broken and
/// directories whose root carries no sub-node pointers at all. Entry
/// validation (INDX signature, USA fixup, bounded FILE_NAME fields)
/// means garbage or stale records are skipped rather than matched.
fn find_in_index_allocation(
    ntfs: &NtfsFileSystem,
    index_alloc_data: &[u8],
    needle: &[u16],
    bitmap: Option<&[u8]>,
) -> Option<u64> {
    let (runs, allocated_size) = parse_index_allocation_runs(index_alloc_data)?;
    let record_size = ntfs.ntfs_data.index_record_size as usize;
    if record_size < 64 {
        return None;
    }
    let total_records = (allocated_size as usize / record_size).max(1);
    for vcn in 0..total_records as u64 {
        if let Some(bm) = bitmap {
            let byte = (vcn / 8) as usize;
            let bit = (vcn % 8) as u8;
            if byte < bm.len() && (bm[byte] >> bit) & 1 == 0 {
                // The record is not part of the index: stale data may
                // still carry an old INDX signature, so skip it rather
                // than risk matching a deleted name.
                continue;
            }
        }
        let record = match read_index_bytes(ntfs, &runs, vcn * record_size as u64, record_size) {
            Some(r) => r,
            None => continue,
        };
        if record.len() < 4 || &record[0..4] != b"INDX" {
            continue;
        }
        let mut record = record;
        if !apply_fixup(&mut record) {
            continue;
        }
        let Some(entries) = indx_entry_region(&record) else {
            continue;
        };
        let mut visited: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        if let Some(result) =
            search_index_entries(ntfs, entries, needle, None, record_size, 0, &mut visited)
        {
            return Some(result);
        }
    }
    None
}

///
/// # Arguments
/// * `ntfs` - NTFS filesystem
/// * `dir_record` - MFT record number of the directory
///
/// # Returns
/// * Vector of directory entries
pub fn list_directory(ntfs: &NtfsFileSystem, dir_record: u64) -> Vec<DirectoryEntry> {
    let mut entries: Vec<DirectoryEntry> = Vec::new();

    // read the directory's MFT record
    let record = match read_mft_record(&ntfs.ntfs_data, dir_record) {
        Some(r) => r,
        None => return entries,
    };

    // Check if it's a directory
    let flags = u16::from_le_bytes([record[0x16], record[0x17]]);
    if flags & MftRecordHeader::IS_DIRECTORY == 0 {
        return entries;
    }

    // Parse $INDEX_ROOT. The parser now returns a stack-only
    // array; we materialise the `Vec` only after the parser
    // has finished so the heap allocations happen in one
    // contiguous region instead of interleaved with the
    // byte-walking code.
    if let Some(index_root) = parse_attribute(&record, AttributeHeader::TYPE_INDEX_ROOT) {
        let (parsed, count) = parse_index_root(index_root);
        entries.reserve(count);
        for entry in parsed.iter().take(count) {
            entries.push(entry.clone());
        }
    }

    entries
}

/// Parse path into components, supporting both backslash and forward slash separators.
pub fn parse_path_components(path: &[u16]) -> Option<Vec<&[u16]>> {
    if path.is_empty() || path[0] == 0 {
        return None;
    }

    // Pre-allocate with capacity to avoid allocation during iteration
    let mut components = Vec::with_capacity(16);
    let mut i = 0;

    while i < path.len() {
        // Skip separators (both \ and /)
        while i < path.len() && (path[i] == b'\\' as u16 || path[i] == b'/' as u16) {
            i += 1;
        }
        if i >= path.len() {
            break;
        }

        // Collect component
        let start = i;
        while i < path.len() && path[i] != b'\\' as u16 && path[i] != b'/' as u16 {
            i += 1;
        }
        if i > start {
            components.push(&path[start..i]);
        }
    }

    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

/// Resolve a symbolic link to its target.
/// Returns the MFT record number of the target, or None if not a symlink.
pub fn resolve_symlink(ntfs: &NtfsFileSystem, record_num: u64) -> Option<u64> {
    // read the MFT record
    let record = read_mft_record(&ntfs.ntfs_data, record_num)?;

    // Check if the record has a reparse point attribute (0xC0)
    if let Some(reparse_offset) = find_attribute_in_record(&record, AttributeHeader::TYPE_REPARSE) {
        // This is a reparse point - could be a symlink or mount point
        // For now, just return None (not a simple symlink we can resolve)
        let _ = reparse_offset;
        // In a full implementation, we would parse the reparse data
        // and return the target path's MFT record
    }

    None
}

/// Open file by path (enhanced implementation).
/// Performs MFT lookup and returns a handle for subsequent operations.
///
/// This function:
/// 1. Parses the path into components using stack-based approach
/// 2. Walks the MFT starting from root (record 5)
/// 3. For each component, searches the directory
/// 4. Returns the MFT record number for the final file
///
/// # Arguments
/// * `ntfs` - The NTFS filesystem
/// * `path` - The path to the file (UTF-16 encoded)
/// * `start_record` - Optional starting MFT record (None = use root/record 5)
pub fn open_file(
    ntfs: &NtfsFileSystem,
    path: &[u16],
    start_record: Option<u64>,
) -> Option<NtfsHandle> {
    crate::boot_milestone!("NTFS", "TRACE open enter");
    let components = match ntfs_path_components(path) {
        Ok(components) if !components.is_empty() => components,
        _ => {
            return None;
        }
    };
    crate::boot_milestone!("NTFS", "TRACE open components");

    // Start from root directory or specified record
    let mut current_record = start_record.unwrap_or(5);

    // Walk each normalized path component
    for (index, component) in components.iter().enumerate() {
        let record = match find_file_in_directory(ntfs, current_record, component) {
            Some(record) => record,
            None => {
                return None;
            }
        };
        let handle = match get_file_by_record(ntfs, record) {
            Some(handle) => handle,
            None => {
                return None;
            }
        };
        if index == components.len() - 1 {
            return Some(handle);
        }
        if !handle.is_directory {
            return None;
        }
        current_record = record;
    }
    None
}

/// read from file
/// Uses the underlying NTFS structure to read data from the file's clusters.
pub fn read_file(
    ntfs: &NtfsFileSystem,
    handle: &mut NtfsHandle,
    buffer: &mut [u8],
) -> Result<usize, NTSTATUS> {
    if buffer.is_empty() {
        return Ok(0);
    }

    // Try to use the MFT-based read if we have a valid record
    if handle.mft_record > 0 {
        if let Some(record) = read_mft_record(&ntfs.ntfs_data, handle.mft_record) {
            // Locate the real $DATA attribute header. This must be done
            // before deciding resident/non-resident: `parse_attribute`
            // returns file bytes for a resident attribute, so indexing
            // those bytes at +8 would confuse file content with metadata.
            if let Some(attr_offset) = find_attribute_in_record(&record, AttributeHeader::TYPE_DATA)
            {
                if attr_offset + 9 <= record.len() {
                    let non_resident = record[attr_offset + 8] != 0;
                    if !non_resident {
                        if let Some(data_value) =
                            parse_attribute(&record, AttributeHeader::TYPE_DATA)
                        {
                            let copy_len = data_value.len().min(buffer.len());
                            buffer[..copy_len].copy_from_slice(&data_value[..copy_len]);
                            handle.current_position += copy_len as u64;
                            return Ok(copy_len);
                        }
                    } else if let Some(data_attr) =
                        parse_attribute(&record, AttributeHeader::TYPE_DATA)
                    {
                        // Non-resident - parse run list and read from clusters
                        let result = read_file_via_runlist(ntfs, handle, data_attr, buffer);
                        if result > 0 {
                            return Ok(result);
                        }
                    }
                }
            }
        }
    }

    // Final fallback: return EOF if we've read everything
    let remaining_bytes = handle.file_size.saturating_sub(handle.current_position);
    if remaining_bytes == 0 {
        return Ok(0);
    }

    Err(STATUS_UNSUCCESSFUL)
}

/// Read one NTFS cluster through the currently mounted partition backend.
fn read_cluster(ntfs: &NtfsFileSystem, cluster_lcn: u64, cluster_buf: &mut [u8]) -> bool {
    let cluster_size = cluster_buf.len();
    let sectors_per_cluster = cluster_size.div_ceil(512);
    let first_sector = ntfs.ntfs_data.hidden_sectors + cluster_lcn * (cluster_size / 512) as u64;

    for sector_index in 0..sectors_per_cluster {
        let mut sector_buf = [0u8; 512];
        if !read_mounted_sector(
            &ntfs.ntfs_data,
            first_sector + sector_index as u64,
            &mut sector_buf,
        ) {
            return false;
        }

        let copy_start = sector_index * 512;
        let copy_len = core::cmp::min(512, cluster_size - copy_start);
        cluster_buf[copy_start..copy_start + copy_len].copy_from_slice(&sector_buf[..copy_len]);
    }

    true
}

/// read file data using the run list from a non-resident $DATA attribute.
fn read_file_via_runlist(
    ntfs: &NtfsFileSystem,
    handle: &mut NtfsHandle,
    data_attr: &[u8],
    buffer: &mut [u8],
) -> usize {
    let cluster_size = ntfs.ntfs_data.cluster_size as usize;
    if data_attr.len() < 0x40 {
        crate::boot_println!("[NTFS] read_file_via_runlist: attribute header too short");
        return 0;
    }

    // Parse the non-resident attribute header using the standard NTFS
    // layout. The run-list offset is stored at +0x20, and the size
    // fields follow the 4-byte reserved area.
    let allocated_size = u64::from_le_bytes([
        data_attr[0x28],
        data_attr[0x29],
        data_attr[0x2A],
        data_attr[0x2B],
        data_attr[0x2C],
        data_attr[0x2D],
        data_attr[0x2E],
        data_attr[0x2F],
    ]);
    let file_size = u64::from_le_bytes([
        data_attr[0x30],
        data_attr[0x31],
        data_attr[0x32],
        data_attr[0x33],
        data_attr[0x34],
        data_attr[0x35],
        data_attr[0x36],
        data_attr[0x37],
    ]);
    let mapping_pairs_offset = u16::from_le_bytes([data_attr[0x20], data_attr[0x21]]) as usize;
    if mapping_pairs_offset >= data_attr.len() {
        crate::boot_println!(
            "[NTFS] read_file_via_runlist: mapping_pairs_offset={} exceeds attribute length={}",
            mapping_pairs_offset,
            data_attr.len()
        );
        return 0;
    }

    crate::boot_debug_println!(
        "[NTFS] read_file_via_runlist: mapping_pairs_offset=0x{:x} allocated_size={} file_size={}",
        mapping_pairs_offset,
        allocated_size,
        file_size
    );

    // Parse run list using the existing function
    let mut run_output: [(u64, u64); 256] = [(0, 0); 256];
    let num_runs = parse_run_list(&data_attr[mapping_pairs_offset..], &mut run_output);
    if num_runs == 0 {
        crate::boot_println!("[NTFS] read_file_via_runlist: empty run list");
        return 0;
    }

    // Convert runs to Vec for easier iteration
    // The existing parse_run_list already accumulates offsets
    let mut runs: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for i in 0..num_runs {
        runs.push(run_output[i]);
    }

    // Calculate which cluster range we need to read
    let start_byte = handle.current_position;
    // Guard against a read position beyond EOF: `file_size - start_byte`
    // would underflow for an unsigned type.
    if start_byte >= file_size {
        return 0;
    }
    let bytes_to_read = buffer.len().min((file_size - start_byte) as usize);
    if bytes_to_read == 0 {
        return 0;
    }

    let start_cluster = start_byte / cluster_size as u64;
    let end_byte = start_byte + bytes_to_read as u64;
    let end_cluster = (end_byte - 1) / cluster_size as u64;

    crate::boot_debug_println!(
        "[NTFS] read_file_via_runlist: start_byte={} start_cluster={} end_cluster={}",
        start_byte,
        start_cluster,
        end_cluster
    );

    // Walk through runs and find the clusters we need
    let mut current_pos = start_byte;
    let mut buf_offset = 0;
    let mut clusters_skipped: u64 = 0;

    for (run_lcn, run_length) in &runs {
        let run_start_cluster = clusters_skipped;
        let run_end_cluster = run_start_cluster + run_length;

        crate::boot_debug_println!(
            "[NTFS] read_file_via_runlist: run_lcn={} run_length={} run_start_cluster={} run_end_cluster={} hidden_sectors={}",
            run_lcn, run_length, run_start_cluster, run_end_cluster, ntfs.ntfs_data.hidden_sectors
        );

        if run_end_cluster <= start_cluster {
            // Skip this entire run
            clusters_skipped = run_end_cluster;
            continue;
        }

        if clusters_skipped > start_cluster {
            // We're past our start position, read what's left
            let clusters_to_read_count = (*run_length).min(end_cluster - run_start_cluster + 1);

            for i in 0..clusters_to_read_count {
                let cluster_lcn = run_lcn + i;
                let cluster_start_byte = (run_start_cluster + i) * cluster_size as u64;
                let cluster_end_byte = cluster_start_byte + cluster_size as u64;

                // Calculate how much of this cluster to read
                let read_start = if current_pos < cluster_start_byte {
                    0
                } else {
                    (current_pos - cluster_start_byte) as usize
                };
                let read_end = if cluster_end_byte <= end_byte {
                    cluster_size
                } else {
                    ((end_byte - cluster_start_byte) as usize).min(cluster_size)
                };

                if read_start < read_end && buf_offset < buffer.len() {
                    let mut cluster_buf = vec![0u8; cluster_size];
                    if read_cluster(ntfs, cluster_lcn, &mut cluster_buf) {
                        let copy_len = (read_end - read_start).min(buffer.len() - buf_offset);
                        buffer[buf_offset..buf_offset + copy_len]
                            .copy_from_slice(&cluster_buf[read_start..read_start + copy_len]);
                        buf_offset += copy_len;
                        current_pos += copy_len as u64;
                    }
                }

                if buf_offset >= bytes_to_read {
                    break;
                }
            }
        } else {
            // We need clusters from within this run
            let first_needed_cluster = start_cluster - clusters_skipped;
            let last_needed_cluster = end_cluster - clusters_skipped;

            for i in first_needed_cluster..=last_needed_cluster.min(*run_length - 1) {
                let cluster_lcn = run_lcn + i;
                let cluster_start_byte = (run_start_cluster + i) * cluster_size as u64;
                let cluster_end_byte = cluster_start_byte + cluster_size as u64;

                // Calculate how much of this cluster to read
                let read_start = if current_pos < cluster_start_byte {
                    0
                } else {
                    (current_pos - cluster_start_byte) as usize
                };
                let read_end = if cluster_end_byte <= end_byte {
                    cluster_size
                } else {
                    ((end_byte - cluster_start_byte) as usize).min(cluster_size)
                };

                if read_start < read_end && buf_offset < buffer.len() {
                    let mut cluster_buf = vec![0u8; cluster_size];
                    if read_cluster(ntfs, cluster_lcn, &mut cluster_buf) {
                        let copy_len = (read_end - read_start).min(buffer.len() - buf_offset);
                        buffer[buf_offset..buf_offset + copy_len]
                            .copy_from_slice(&cluster_buf[read_start..read_start + copy_len]);
                        buf_offset += copy_len;
                        current_pos += copy_len as u64;
                    }
                }

                if buf_offset >= bytes_to_read {
                    break;
                }
            }
        }

        clusters_skipped = run_end_cluster;

        if buf_offset >= bytes_to_read {
            break;
        }
    }

    handle.current_position += buf_offset as u64;
    buf_offset
}

/// Helper function to get attribute offset from data buffer.
pub fn attr_offset_from_data(_data: &[u8]) -> usize {
    // For resident attributes, the data IS the attribute value
    // Just return 0
    0
}

/// write to file
/// Uses the underlying NTFS structure to write data to the file's clusters.
pub fn write_file(
    ntfs: &mut NtfsFileSystem,
    handle: &mut NtfsHandle,
    buffer: &[u8],
) -> Result<usize, NTSTATUS> {
    if buffer.is_empty() {
        return Ok(0);
    }

    if handle.mft_record == 0 {
        // A file byte offset is never a disk LBA; without an MFT record
        // there is no safe way to place this write.
        return Err(STATUS_UNSUCCESSFUL);
    }

    let saved_position = handle.current_position;
    let end = saved_position + buffer.len() as u64;

    // In-place paths first: they never extend the allocation.
    if let Some(written) = write_file_resident(ntfs, handle, buffer) {
        if written == buffer.len() {
            return Ok(written);
        }
    }
    handle.current_position = saved_position;
    if let Some(written) = write_file_with_runs(ntfs, handle, buffer) {
        if written == buffer.len() {
            return Ok(written);
        }
    }
    handle.current_position = saved_position;

    // Growth path: allocate backing clusters (converting resident files
    // to non-resident form), then retry through the mapped-run writer.
    if end > handle.file_size {
        extend_file(ntfs, handle, end)?;
    }
    if let Some(written) = write_file_with_runs(ntfs, handle, buffer) {
        if written == buffer.len() {
            return Ok(written);
        }
    }

    // A file byte offset is never a disk LBA. If the mapped run path
    // cannot satisfy the write, returning an error is the only safe
    // choice; guessing a physical sector can overwrite boot metadata.
    Err(STATUS_UNSUCCESSFUL)
}

/// Write into a resident `$DATA` value in place.
///
/// Returns `Some(bytes_written)` only when the whole buffer fits inside
/// the resident value; `None` otherwise so the caller can route the
/// write through the growth path. Never performs a partial write.
fn write_file_resident(
    ntfs: &NtfsFileSystem,
    handle: &mut NtfsHandle,
    buffer: &[u8],
) -> Option<usize> {
    let record = read_mft_record(&ntfs.ntfs_data, handle.mft_record)?;
    let attr_offset = find_attribute_in_record(&record, AttributeHeader::TYPE_DATA)?;
    if attr_offset + 0x18 > record.len() {
        return None;
    }
    if record[attr_offset + 8] != 0 {
        return None;
    }
    let value_len = u32::from_le_bytes([
        record[attr_offset + 0x10],
        record[attr_offset + 0x11],
        record[attr_offset + 0x12],
        record[attr_offset + 0x13],
    ]) as usize;
    let value_offset =
        u16::from_le_bytes([record[attr_offset + 0x14], record[attr_offset + 0x15]]) as usize;
    let end = handle.current_position as usize + buffer.len();
    if end > value_len || attr_offset + value_offset + end > record.len() {
        return None;
    }
    let mut record = record.to_vec();
    let start = attr_offset + value_offset + handle.current_position as usize;
    record[start..start + buffer.len()].copy_from_slice(buffer);
    if write_mft_record(&ntfs.ntfs_data, handle.mft_record, &record).is_err() {
        return None;
    }
    handle.current_position += buffer.len() as u64;
    if handle.current_position > handle.file_size {
        handle.file_size = handle.current_position;
    }
    Some(buffer.len())
}

/// Write data to a non-resident file's clusters by mapping the byte offset
/// through the $DATA attribute run list.
///
/// Walks each (LCN, length) run parsed from the run list, locates the
/// cluster that contains the write offset, and writes one 512-byte sector
/// at a time. When the write extends past the last cluster of a run, the
/// walk advances to the next run automatically.
///
/// Returns Some(bytes_written) on success, None if the record has no
/// non-resident $DATA attribute or the run list cannot be parsed.
fn write_file_with_runs(
    ntfs: &mut NtfsFileSystem,
    handle: &mut NtfsHandle,
    buffer: &[u8],
) -> Option<usize> {
    let record = read_mft_record(&ntfs.ntfs_data, handle.mft_record)?;

    let data_attr_offset = find_attribute_in_record(&record, AttributeHeader::TYPE_DATA)?;
    if data_attr_offset + 8 > record.len() {
        return None;
    }

    let non_resident = record[data_attr_offset + 8];

    if non_resident == 0 {
        return None;
    }

    // Locate the run-list bytes within the non-resident $DATA attribute.
    // Non-resident attribute header layout (NTFS 3.1):
    //   0x00  u32 attribute_type
    //   0x04  u32 length
    //   0x08  u8  non_resident
    //   0x09  u8  name_length
    //   0x0A  u16 name_offset
    //   0x0C  u16 flags
    //   0x0E  u16 attribute_id
    //   0x10  u64 starting_vcn
    //   0x18  u64 last_vcn
    //   0x20  u16 data_runs_offset
    //   ...
    let data_runs_offset = u16::from_le_bytes([
        record[data_attr_offset + 0x20],
        record[data_attr_offset + 0x21],
    ]) as usize;
    if data_runs_offset == 0 || data_attr_offset + data_runs_offset > record.len() {
        return None;
    }

    let run_list = &record[data_attr_offset + data_runs_offset..];
    let mut runs = [(0u64, 0u64); 64];
    let num_runs = parse_run_list(run_list, &mut runs);
    if num_runs == 0 {
        return None;
    }

    let bytes_per_cluster = ntfs.ntfs_data.cluster_size as u64;
    let mut file_pos = 0u64;
    let mut bytes_written = 0usize;

    for &(start_cluster, length) in runs[..num_runs].iter() {
        let run_size = length * bytes_per_cluster;
        let run_end = file_pos + run_size;

        // Skip runs entirely before the current write position.
        if handle.current_position + (bytes_written as u64) >= run_end {
            file_pos = run_end;
            continue;
        }

        // Write the portion of the buffer that falls within this run.
        let mut offset_in_run = handle.current_position.saturating_sub(file_pos);

        while offset_in_run < run_size && bytes_written < buffer.len() {
            let offset_in_cluster = (offset_in_run % bytes_per_cluster) as usize;
            let remaining_in_cluster =
                (bytes_per_cluster as usize).saturating_sub(offset_in_cluster);
            let bytes_in_cluster = core::cmp::min(
                core::cmp::min((run_size - offset_in_run) as usize, remaining_in_cluster),
                buffer.len() - bytes_written,
            );

            let cluster_in_run = offset_in_run / bytes_per_cluster;
            let cluster = start_cluster + cluster_in_run;
            let first_sector = cluster_to_sector(cluster, ntfs.ntfs_data.cluster_size);
            let mut sector_offset = offset_in_cluster;

            while sector_offset < bytes_in_cluster && bytes_written < buffer.len() {
                let sector = first_sector + (sector_offset / 512) as u64;
                let offset_in_sector = sector_offset % 512;

                let mut sector_buf = [0u8; 512];
                let read_ok = read_mounted_sector(&ntfs.ntfs_data, sector, &mut sector_buf);
                if !read_ok {
                    return None;
                }

                let copy_len = core::cmp::min(
                    bytes_in_cluster - sector_offset,
                    core::cmp::min(512 - offset_in_sector, buffer.len() - bytes_written),
                );
                sector_buf[offset_in_sector..offset_in_sector + copy_len]
                    .copy_from_slice(&buffer[bytes_written..bytes_written + copy_len]);

                let write_ok = if let Some(device_id) = ntfs.ntfs_data.device_id {
                    crate::drivers::storage::block::write_block(device_id, sector, &sector_buf)
                } else {
                    write_sector(core::ptr::null_mut(), sector, &sector_buf).is_ok()
                };
                if !write_ok {
                    return None;
                }

                bytes_written += copy_len;
                offset_in_run += copy_len as u64;
                sector_offset += copy_len;
            }
        }

        file_pos = run_end;
        if bytes_written >= buffer.len() {
            break;
        }
    }

    if bytes_written == 0 {
        return None;
    }

    handle.current_position += bytes_written as u64;
    if handle.current_position > handle.file_size {
        handle.file_size = handle.current_position;
        // Windows stores the authoritative size inside the $DATA
        // attribute itself; keep the on-disk header in sync so the
        // appended bytes survive a remount.
        persist_nonresident_file_size(ntfs, handle.mft_record, handle.file_size);
    }

    Some(bytes_written)
}

/// Persist a grown file's real size into its non-resident $DATA attribute.
///
/// `write_file_with_runs` only updates the in-memory `NtfsHandle.file_size`.
/// Windows keeps the authoritative size in the $DATA attribute header
/// (real size at +0x30, initialized size at +0x38), so a write that is not
/// followed by an attribute update leaves the file truncated at its old
/// size after a remount. Refuses to grow the size past the attribute's
/// allocated run capacity; extending the run list itself needs a full
/// attribute rewriter and is out of scope here.
fn persist_nonresident_file_size(ntfs: &NtfsFileSystem, record_num: u64, new_size: u64) {
    let record = match read_mft_record(&ntfs.ntfs_data, record_num) {
        Some(value) => value,
        None => return,
    };
    let data_attr_offset = match find_attribute_in_record(&record, AttributeHeader::TYPE_DATA) {
        Some(value) => value,
        None => return,
    };
    if data_attr_offset + 0x40 > record.len() {
        return;
    }
    if record[data_attr_offset + 8] == 0 {
        // Resident file: the size is implied by the value length and is
        // updated by the attribute writer, not here.
        return;
    }
    let allocated_size = u64::from_le_bytes([
        record[data_attr_offset + 0x28],
        record[data_attr_offset + 0x29],
        record[data_attr_offset + 0x2A],
        record[data_attr_offset + 0x2B],
        record[data_attr_offset + 0x2C],
        record[data_attr_offset + 0x2D],
        record[data_attr_offset + 0x2E],
        record[data_attr_offset + 0x2F],
    ]);
    if new_size > allocated_size {
        // Cannot grow past the allocated runs without rewriting the
        // run list; leave the header untouched rather than inventing
        // size the data does not cover.
        return;
    }

    let mut record = record.to_vec();
    let attr = data_attr_offset;
    record[attr + 0x30..attr + 0x38].copy_from_slice(&new_size.to_le_bytes());
    record[attr + 0x38..attr + 0x40].copy_from_slice(&new_size.to_le_bytes());
    let _ = write_mft_record(&ntfs.ntfs_data, record_num, &record);
}

/// Allocate a new cluster for NTFS by scanning the $Bitmap system file.
///
/// Reads the $Bitmap MFT record (record 6), parses its $DATA run list to
/// locate the bitmap data on disk, then scans for the first zero bit (free
/// cluster). The bit is set and the bitmap sector is written back.
///
/// Returns the allocated cluster number (LCN), or None if the bitmap
/// cannot be read or the volume is full.
pub fn allocate_cluster_ntfs(ntfs: &NtfsFileSystem) -> Option<u64> {
    unsafe {
        // Read the $Bitmap MFT record.
        let bitmap_record = read_mft_record(&ntfs.ntfs_data, system_records::BITMAP)?;

        // Find its $DATA attribute to get the run list.
        let data_offset = find_attribute_in_record(&bitmap_record, AttributeHeader::TYPE_DATA)?;
        if data_offset + 8 > bitmap_record.len() {
            return None;
        }

        let non_resident = bitmap_record[data_offset + 8];
        if non_resident == 0 {
            // $Bitmap is always non-resident on a real NTFS volume.
            return None;
        }

        let data_runs_offset = u16::from_le_bytes([
            bitmap_record[data_offset + 0x20],
            bitmap_record[data_offset + 0x21],
        ]) as usize;
        if data_runs_offset == 0 || data_offset + data_runs_offset > bitmap_record.len() {
            return None;
        }

        let run_list = &bitmap_record[data_offset + data_runs_offset..];
        let mut runs = [(0u64, 0u64); 64];
        let num_runs = parse_run_list(run_list, &mut runs);
        if num_runs == 0 {
            return None;
        }

        let bits_per_bitmap_cluster = ntfs.ntfs_data.cluster_size as u64 * 8;

        // Scan each bitmap cluster for the first free bit. The LCN of a data
        // cluster is its position in the $Bitmap data stream (each bitmap
        // cluster covers `cluster_size * 8` data clusters), so the index must
        // accumulate across all runs of the $Bitmap, not reset per run.
        let mut bitmap_cluster_index: u64 = 0;
        for &(start_cluster, length) in runs[..num_runs].iter() {
            for cluster_in_run in 0..length {
                let bitmap_cluster = start_cluster + cluster_in_run;
                let bitmap_sector = cluster_to_sector(bitmap_cluster, ntfs.ntfs_data.cluster_size);

                let mut sector_buf = [0u8; 512];
                let read_ok = if let Some(device_id) = ntfs.ntfs_data.device_id {
                    crate::drivers::storage::block::read_block(
                        device_id,
                        bitmap_sector,
                        &mut sector_buf,
                    )
                } else {
                    read_sector(core::ptr::null_mut(), bitmap_sector, &mut sector_buf).is_ok()
                };
                if !read_ok {
                    continue;
                }

                // Each 512-byte sector covers 4096 clusters (8 bits/byte).
                for (byte_index, &byte) in sector_buf.iter().enumerate() {
                    if byte == 0xFF {
                        continue;
                    }
                    for bit_index in 0..8u32 {
                        let mask = 1u8 << bit_index;
                        if byte & mask == 0 {
                            let bit_position = (byte_index * 8) as u64 + bit_index as u64;
                            let allocated_lcn = bitmap_cluster_index
                                .saturating_mul(bits_per_bitmap_cluster)
                                + bit_position;

                            // Mark the bit as used.
                            sector_buf[byte_index] |= mask;
                            let write_ok = if let Some(device_id) = ntfs.ntfs_data.device_id {
                                crate::drivers::storage::block::write_block(
                                    device_id,
                                    bitmap_sector,
                                    &sector_buf,
                                )
                            } else {
                                write_sector(core::ptr::null_mut(), bitmap_sector, &sector_buf)
                                    .is_ok()
                            };
                            if !write_ok {
                                return None;
                            }

                            return Some(allocated_lcn);
                        }
                    }
                }
                bitmap_cluster_index += 1;
            }
        }

        // Volume full.
        None
    }
}

/// Allocate the first unused MFT record number in the mounted mirror.
///
/// The allocation is intentionally conservative: only records that are
/// entirely unreadable/uninitialised are considered free. Records whose
/// fixups are corrupt are treated as allocated rather than silently reused.
fn allocate_mft_record(ntfs: &NtfsFileSystem) -> Option<u64> {
    (32..1024u64).find(|&record_number| read_mft_record(&ntfs.ntfs_data, record_number).is_none())
}

/// Append a resident attribute value to an MFT record.
fn append_resident_attribute(
    record: &mut Vec<u8>,
    attribute_type: u32,
    value: &[u8],
    attribute_id: u16,
) -> usize {
    let attribute_offset = record.len();
    let attribute_length = 24 + value.len();
    let padded_attribute_length = (attribute_length + 7) & !7;
    record.extend_from_slice(&attribute_type.to_le_bytes());
    record.extend_from_slice(&(padded_attribute_length as u32).to_le_bytes());
    record.push(0);
    record.push(0);
    record.extend_from_slice(&24u16.to_le_bytes());
    record.extend_from_slice(&0u16.to_le_bytes());
    record.extend_from_slice(&attribute_id.to_le_bytes());
    record.extend_from_slice(&(value.len() as u32).to_le_bytes());
    record.extend_from_slice(&24u16.to_le_bytes());
    record.extend_from_slice(&[0; 2]);
    record.extend_from_slice(value);
    while !record.len().is_multiple_of(8) {
        record.push(0);
    }
    attribute_offset
}

/// Build a `$FILE_NAME` value for an index entry.
fn build_file_name_value(parent_record: u64, name: &[u16], is_directory: bool) -> Vec<u8> {
    let mut value = alloc::vec![0u8; 66 + name.len() * 2];
    value[..8].copy_from_slice(&parent_record.to_le_bytes());
    let attributes: u32 = if is_directory { 0x10 } else { 0 };
    value[0x38..0x3C].copy_from_slice(&attributes.to_le_bytes());
    value[0x40] = name.len() as u8;
    value[0x41] = 3;
    for (index, character) in name.iter().enumerate() {
        let offset = 0x42 + index * 2;
        value[offset..offset + 2].copy_from_slice(&character.to_le_bytes());
    }
    value
}

/// Build a directory index entry. Real entries contain a resident
/// `$FILE_NAME` attribute header, exactly as the on-disk parser expects.
fn build_index_entry(
    record_number: u64,
    parent_record: u64,
    name: &[u16],
    is_directory: bool,
    is_end: bool,
) -> Vec<u8> {
    if is_end {
        let mut entry = alloc::vec![0u8; 16];
        entry[12..14].copy_from_slice(&2u16.to_le_bytes());
        return entry;
    }
    let file_name = build_file_name_value(parent_record, name, is_directory);
    let entry_length = (16 + file_name.len() + 7) & !7;

    let mut entry = alloc::vec![0u8; entry_length];
    entry[..8].copy_from_slice(&record_number.to_le_bytes());
    entry[8..10].copy_from_slice(&(entry_length as u16).to_le_bytes());
    entry[10..12].copy_from_slice(&(file_name.len() as u16).to_le_bytes());
    entry[12..14].copy_from_slice(&0u16.to_le_bytes());

    entry[16..16 + file_name.len()].copy_from_slice(&file_name);
    entry
}

/// Build a complete resident `$INDEX_ROOT` attribute from directory entries.
fn build_index_root(entries: &[DirectoryEntry]) -> Vec<u8> {
    let mut entry_bytes = Vec::new();
    for entry in entries {
        let entry_bytes_current = build_index_entry(
            entry.record_number,
            entry.parent_record,
            &entry.name,
            entry.is_directory,
            false,
        );
        entry_bytes.extend_from_slice(&entry_bytes_current);
    }
    entry_bytes.extend_from_slice(&build_index_entry(0, 0, &[], false, true));

    let mut index_root = alloc::vec![0u8; 32 + entry_bytes.len()];
    index_root[..4].copy_from_slice(&0x30u32.to_le_bytes());
    index_root[4..8].copy_from_slice(&1u32.to_le_bytes());
    index_root[8..12].copy_from_slice(&4096u32.to_le_bytes());
    index_root[12] = 1;
    index_root[16..20].copy_from_slice(&0x10u32.to_le_bytes());
    let index_length = 16 + entry_bytes.len();
    index_root[20..24].copy_from_slice(&(index_length as u32).to_le_bytes());
    index_root[24..28].copy_from_slice(&(index_length as u32).to_le_bytes());
    index_root[28..32].copy_from_slice(&0u32.to_le_bytes());
    index_root[32..].copy_from_slice(&entry_bytes);

    let mut attribute = alloc::vec![0u8; 24 + index_root.len()];
    attribute[..4].copy_from_slice(&0x90u32.to_le_bytes());
    let attribute_length = attribute.len();
    attribute[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes());
    attribute[8] = 0;
    attribute[14..16].copy_from_slice(&0x90u16.to_le_bytes());
    attribute[16..20].copy_from_slice(&(index_root.len() as u32).to_le_bytes());
    attribute[20..22].copy_from_slice(&24u16.to_le_bytes());
    attribute[24..].copy_from_slice(&index_root);
    attribute
}

/// Rebuild a directory's MFT record with a new `$INDEX_ROOT`.
fn directory_record_with_entries(
    ntfs: &NtfsFileSystem,
    parent_record_number: u64,
    entries: &[DirectoryEntry],
) -> Option<Vec<u8>> {
    let current = read_mft_record(&ntfs.ntfs_data, parent_record_number)?;
    let mut rebuilt = alloc::vec![0u8; current.len()];
    rebuilt.copy_from_slice(&current);

    let mut attributes = Vec::new();
    let start = u16::from_le_bytes([current[0x14], current[0x15]]) as usize;
    let mut offset = start;
    let mut replaced = false;
    while offset + 8 <= current.len() {
        let attribute_type = u32::from_le_bytes([
            current[offset],
            current[offset + 1],
            current[offset + 2],
            current[offset + 3],
        ]);
        if attribute_type == 0xFFFF_FFFF {
            break;
        }
        let attribute_length = u32::from_le_bytes([
            current[offset + 4],
            current[offset + 5],
            current[offset + 6],
            current[offset + 7],
        ]) as usize;
        if attribute_length < 8 || offset + attribute_length > current.len() {
            return None;
        }
        if attribute_type == 0x90 {
            attributes.extend_from_slice(&build_index_root(entries));
            replaced = true;
        } else {
            attributes.extend_from_slice(&current[offset..offset + attribute_length]);
        }
        offset += attribute_length;
    }
    if !replaced {
        return None;
    }

    if attributes.len() + 8 > rebuilt.len() - start {
        return None;
    }

    rebuilt[start..start + attributes.len()].copy_from_slice(&attributes);
    rebuilt[start + attributes.len()..].fill(0);
    rebuilt[start + attributes.len()..start + attributes.len() + 4]
        .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used_size = start + attributes.len() + 8;
    rebuilt[0x18..0x1C].copy_from_slice(&(used_size as u32).to_le_bytes());
    rebuilt[0x28..0x2A].copy_from_slice(&0x91u16.to_le_bytes());
    Some(rebuilt)
}

/// Normalize a Win32-style NTFS path into UTF-16 components.
///
/// Drive letters and separators are path syntax only; they are never stored
/// as `$FILE_NAME` components. `.` and `..` are resolved structurally so
/// relative command paths do not require callers to duplicate shell logic.
fn ntfs_path_components(path: &[u16]) -> Result<Vec<Vec<u16>>, NTSTATUS> {
    let separator =
        |value: u16| value == b'\\' as u16 || value == b'/' as u16 || value == b':' as u16;
    let mut components = Vec::new();
    let mut index = 0;
    if index + 1 < path.len()
        && path[index + 1] == b':' as u16
        && (path[index] >= b'A' as u16 && path[index] <= b'Z' as u16
            || path[index] >= b'a' as u16 && path[index] <= b'z' as u16
            || path[index] >= b'0' as u16 && path[index] <= b'9' as u16)
    {
        index += 2;
    }

    while index < path.len() {
        while index < path.len() && (separator(path[index]) || path[index] == 0) {
            index += 1;
        }
        let start = index;
        while index < path.len() && !separator(path[index]) && path[index] != 0 {
            index += 1;
        }
        if index == start {
            continue;
        }
        let mut component = Vec::with_capacity(index - start);
        component.extend_from_slice(&path[start..index]);
        if component.len() > 255 {
            return Err(STATUS_UNSUCCESSFUL);
        }
        if component.len() == 1 && component[0] == b'.' as u16 {
            continue;
        }
        if component.len() == 2 && component[0] == b'.' as u16 && component[1] == b'.' as u16 {
            if components.pop().is_none() {
                return Err(STATUS_UNSUCCESSFUL);
            }
            continue;
        }
        components.push(component);
    }

    Ok(components)
}

fn directory_record_for_components(
    ntfs: &NtfsFileSystem,
    components: &[Vec<u16>],
    create_missing: bool,
) -> Result<u64, NTSTATUS> {
    let mut current_record = 5u64;
    for component in components {
        if let Some(record) = find_file_in_directory(ntfs, current_record, component) {
            let handle = get_file_by_record(ntfs, record).ok_or(STATUS_UNSUCCESSFUL)?;
            if !handle.is_directory {
                return Err(STATUS_UNSUCCESSFUL);
            }
            current_record = record;
        } else if create_missing {
            current_record =
                create_directory_in_parent(ntfs, current_record, component)?.mft_record;
        } else {
            return Err(STATUS_UNSUCCESSFUL);
        }
    }
    Ok(current_record)
}

fn parent_and_leaf(
    ntfs: &NtfsFileSystem,
    path: &[u16],
    create_ancestors: bool,
) -> Result<(u64, Vec<u16>), NTSTATUS> {
    let components = ntfs_path_components(path)?;
    let leaf = components.last().ok_or(STATUS_UNSUCCESSFUL)?.clone();
    let parent = directory_record_for_components(
        ntfs,
        &components[..components.len() - 1],
        create_ancestors,
    )?;
    Ok((parent, leaf))
}

fn create_directory_in_parent(
    ntfs: &NtfsFileSystem,
    parent_record: u64,
    name: &[u16],
) -> Result<NtfsHandle, NTSTATUS> {
    if find_file_in_directory(ntfs, parent_record, name).is_some() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let record_number = allocate_mft_record(ntfs).ok_or(STATUS_UNSUCCESSFUL)?;
    let record_size = ntfs.ntfs_data.mft_record_size as usize;
    if record_size < MftRecordHeader::MINIMUM_RECORD_SIZE {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let sectors_per_record = record_size / 512;
    let attribute_offset = (48 + (sectors_per_record + 1) * 2 + 7) & !7;
    let mut record = alloc::vec![0u8; attribute_offset];
    record[..4].copy_from_slice(b"FILE");
    record[MftRecordHeader::OFFSET_UPDATE_SEQUENCE_OFFSET
        ..MftRecordHeader::OFFSET_UPDATE_SEQUENCE_OFFSET + 2]
        .copy_from_slice(&(MftRecordHeader::OFFSET_FIXUP_ARRAY as u16).to_le_bytes());
    record[MftRecordHeader::OFFSET_UPDATE_SEQUENCE_COUNT
        ..MftRecordHeader::OFFSET_UPDATE_SEQUENCE_COUNT + 2]
        .copy_from_slice(&((sectors_per_record + 1) as u16).to_le_bytes());
    record[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
    record[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
    record[0x14..0x16].copy_from_slice(&(attribute_offset as u16).to_le_bytes());
    record[0x16..0x18].copy_from_slice(&(0x0001u16 | 0x0002u16).to_le_bytes());
    record[0x1C..0x20].copy_from_slice(&(record_size as u32).to_le_bytes());
    record[0x28..0x2A].copy_from_slice(&0x91u16.to_le_bytes());
    record[0x2C..0x30].copy_from_slice(&(record_number as u32).to_le_bytes());

    let file_name = build_file_name_value(parent_record, name, true);
    append_resident_attribute(&mut record, 0x30, &file_name, 1);
    append_resident_attribute(&mut record, 0x90, &build_index_root(&[])[24..], 2);
    record.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used_size = record.len();
    record[0x18..0x1C].copy_from_slice(&(used_size as u32).to_le_bytes());
    if used_size > record_size {
        return Err(STATUS_UNSUCCESSFUL);
    }
    record.resize(record_size, 0);

    if write_mft_record(&ntfs.ntfs_data, record_number, &record).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let security_id = record_number as crate::fs::ntfs::security::SecurityId;
    let descriptor = crate::fs::ntfs::security::serialize_sds_descriptor(
        &crate::fs::ntfs::security::NtfsSecurityDescriptor::new_default(),
    );
    crate::fs::ntfs::security::update_secure_sds(ntfs, security_id, &descriptor)?;

    let current_entries = list_directory(ntfs, parent_record);
    let mut entries = current_entries;
    let mut directory_entry = DirectoryEntry::new();
    directory_entry.record_number = record_number;
    directory_entry.parent_record = parent_record;
    directory_entry.name = name.to_vec();
    directory_entry.is_directory = true;
    entries.push(directory_entry);
    let parent =
        directory_record_with_entries(ntfs, parent_record, &entries).ok_or(STATUS_UNSUCCESSFUL)?;
    if write_mft_record(&ntfs.ntfs_data, parent_record, &parent).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    Ok(NtfsHandle::new(record_number, true, 0, name))
}

/// Create a directory at a full Win32-style path.
pub fn create_directory(ntfs: &NtfsFileSystem, path: &[u16]) -> Result<NtfsHandle, NTSTATUS> {
    let (parent_record, name) = parent_and_leaf(ntfs, path, true)?;
    create_directory_in_parent(ntfs, parent_record, &name)
}

/// Build a $STANDARD_INFORMATION resident value.
fn build_standard_information_value() -> Vec<u8> {
    alloc::vec![0u8; STANDARD_INFORMATION_VALUE_SIZE]
}

/// Size of the on-disk `$STANDARD_INFORMATION` value (Windows NT 6.1,
/// version 1.0 layout: four 8-byte timestamps, flags, version, class id).
const STANDARD_INFORMATION_VALUE_SIZE: usize = 48;

/// Physical sector size of an NTFS volume (Windows NT 6.1 standard layout).
const SECTOR_SIZE: usize = 512;

/// Size of one update-sequence (fixup) array entry in bytes.
const FIXUP_ENTRY_SIZE: usize = 2;

/// Next attribute id after the initial `$STANDARD_INFORMATION`,
/// `$FILE_NAME` and `$DATA` attributes (ids 1..3) of a new record.
const NEXT_ATTRIBUTE_ID_AFTER_CREATE: u16 = 4;

/// Create a file in a specific parent directory.
fn create_file_in_parent(
    ntfs: &NtfsFileSystem,
    parent_record: u64,
    name: &[u16],
    initial_data: &[u8],
) -> Result<NtfsHandle, NTSTATUS> {
    if find_file_in_directory(ntfs, parent_record, name).is_some() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let record_number = allocate_mft_record(ntfs).ok_or(STATUS_UNSUCCESSFUL)?;
    let record_size = ntfs.ntfs_data.mft_record_size as usize;
    if record_size < MftRecordHeader::MINIMUM_RECORD_SIZE {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let sectors_per_record = record_size / SECTOR_SIZE;
    let attribute_offset =
        (MftRecordHeader::OFFSET_FIXUP_ARRAY + (sectors_per_record + 1) * FIXUP_ENTRY_SIZE + 7)
            & !7;
    let mut record = alloc::vec![0u8; attribute_offset];
    record[..MftRecordHeader::SIGNATURE.len()].copy_from_slice(&MftRecordHeader::SIGNATURE);
    record[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    record[6..8].copy_from_slice(&((record_size / 512 + 1) as u16).to_le_bytes());
    record[MftRecordHeader::OFFSET_SEQUENCE_NUMBER..MftRecordHeader::OFFSET_SEQUENCE_NUMBER + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    record[MftRecordHeader::OFFSET_LINK_COUNT..MftRecordHeader::OFFSET_LINK_COUNT + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    record
        [MftRecordHeader::OFFSET_ATTRIBUTES_OFFSET..MftRecordHeader::OFFSET_ATTRIBUTES_OFFSET + 2]
        .copy_from_slice(&(attribute_offset as u16).to_le_bytes());
    record[MftRecordHeader::OFFSET_FLAGS..MftRecordHeader::OFFSET_FLAGS + 2]
        .copy_from_slice(&MftRecordHeader::IN_USE.to_le_bytes());
    record[MftRecordHeader::OFFSET_ALLOCATED_SIZE..MftRecordHeader::OFFSET_ALLOCATED_SIZE + 4]
        .copy_from_slice(&(record_size as u32).to_le_bytes());
    record
        [MftRecordHeader::OFFSET_NEXT_ATTRIBUTE_ID..MftRecordHeader::OFFSET_NEXT_ATTRIBUTE_ID + 2]
        .copy_from_slice(&NEXT_ATTRIBUTE_ID_AFTER_CREATE.to_le_bytes());
    record[MftRecordHeader::OFFSET_RECORD_NUMBER..MftRecordHeader::OFFSET_RECORD_NUMBER + 4]
        .copy_from_slice(&(record_number as u32).to_le_bytes());

    append_resident_attribute(
        &mut record,
        AttributeHeader::TYPE_STANDARD_INFO,
        &build_standard_information_value(),
        1,
    );
    append_resident_attribute(
        &mut record,
        AttributeHeader::TYPE_FILE_NAME,
        &build_file_name_value(parent_record, name, false),
        2,
    );
    append_resident_attribute(&mut record, AttributeHeader::TYPE_DATA, initial_data, 3);
    record.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let used_size = record.len();
    record[MftRecordHeader::OFFSET_USED_SIZE..MftRecordHeader::OFFSET_USED_SIZE + 4]
        .copy_from_slice(&(used_size as u32).to_le_bytes());
    if used_size > record_size {
        return Err(STATUS_UNSUCCESSFUL);
    }
    record.resize(record_size, 0);

    if write_mft_record(&ntfs.ntfs_data, record_number, &record).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let security_id = record_number as crate::fs::ntfs::security::SecurityId;
    let descriptor = crate::fs::ntfs::security::serialize_sds_descriptor(
        &crate::fs::ntfs::security::NtfsSecurityDescriptor::new_default(),
    );
    crate::fs::ntfs::security::update_secure_sds(ntfs, security_id, &descriptor)?;

    insert_directory_entry(ntfs, parent_record, record_number, name, false)?;

    Ok(NtfsHandle::new(
        record_number,
        false,
        initial_data.len() as u64,
        name,
    ))
}

/// Create a file at a full Win32-style path with optional initial data.
pub fn create_file(
    ntfs: &NtfsFileSystem,
    path: &[u16],
    initial_data: &[u8],
) -> Result<NtfsHandle, NTSTATUS> {
    let (parent_record, name) = parent_and_leaf(ntfs, path, false)?;
    create_file_in_parent(ntfs, parent_record, &name, initial_data)
}

/// Insert a directory entry into a directory's $INDEX_ROOT.
pub fn insert_directory_entry(
    ntfs: &NtfsFileSystem,
    parent_record: u64,
    record_number: u64,
    name: &[u16],
    is_directory: bool,
) -> Result<(), NTSTATUS> {
    let current_entries = list_directory(ntfs, parent_record);
    let mut entries = current_entries;
    let mut directory_entry = DirectoryEntry::new();
    directory_entry.record_number = record_number;
    directory_entry.parent_record = parent_record;
    directory_entry.name = name.to_vec();
    directory_entry.is_directory = is_directory;
    entries.push(directory_entry);

    let parent =
        directory_record_with_entries(ntfs, parent_record, &entries).ok_or(STATUS_UNSUCCESSFUL)?;
    write_mft_record(&ntfs.ntfs_data, parent_record, &parent)
}

/// Extend a file to at least `new_size` bytes.
///
/// For non-resident files with spare allocated capacity this updates
/// the in-memory size and the $DATA header sizes. When the allocated
/// runs are exhausted, new clusters are allocated from the $Bitmap
/// (merged with the previous run when contiguous), zero-filled, and
/// the run list is rewritten through a full $DATA attribute rebuild.
/// Resident files are converted to non-resident form: the resident
/// value is carried over into the newly allocated clusters. Allocation
/// or record-write failure is reported as an error instead of claiming
/// a size the on-disk data cannot back.
pub fn extend_file(
    ntfs: &mut NtfsFileSystem,
    handle: &mut NtfsHandle,
    new_size: u64,
) -> Result<(), NTSTATUS> {
    if new_size <= handle.file_size {
        return Ok(());
    }

    let cluster_size = ntfs.ntfs_data.cluster_size;
    if cluster_size == 0 || !cluster_size.is_multiple_of(512) {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let record = read_mft_record(&ntfs.ntfs_data, handle.mft_record).ok_or(STATUS_UNSUCCESSFUL)?;
    let data_offset =
        find_attribute_in_record(&record, AttributeHeader::TYPE_DATA).ok_or(STATUS_UNSUCCESSFUL)?;
    if data_offset + 0x40 > record.len() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let attr_id = u16::from_le_bytes([record[data_offset + 0x0E], record[data_offset + 0x0F]]);
    let clusters_needed = new_size.div_ceil(cluster_size as u64);

    let mut runs: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    let mut allocated_clusters: u64 = 0;
    let mut resident_payload: Option<alloc::vec::Vec<u8>> = None;

    if record[data_offset + 8] == 0 {
        // Resident file: capture the value so it can be seeded into the
        // freshly allocated clusters below (resident -> non-resident
        // conversion).
        let value_len = u32::from_le_bytes([
            record[data_offset + 0x10],
            record[data_offset + 0x11],
            record[data_offset + 0x12],
            record[data_offset + 0x13],
        ]) as usize;
        let value_offset =
            u16::from_le_bytes([record[data_offset + 0x14], record[data_offset + 0x15]]) as usize;
        if value_offset + value_len > record.len() - data_offset {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let start = data_offset + value_offset;
        resident_payload = Some(record[start..start + value_len].to_vec());
    } else {
        let run_offset =
            u16::from_le_bytes([record[data_offset + 0x20], record[data_offset + 0x21]]) as usize;
        if run_offset == 0 || data_offset + run_offset > record.len() {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let mut parsed = [(0u64, 0u64); 256];
        let num_runs = parse_run_list(&record[data_offset + run_offset..], &mut parsed);
        if num_runs == 0 {
            return Err(STATUS_UNSUCCESSFUL);
        }
        runs.extend_from_slice(&parsed[..num_runs]);
        allocated_clusters = runs.iter().map(|(_, length)| length).sum();
    }

    if resident_payload.is_none() && clusters_needed <= allocated_clusters {
        // Spare capacity: only the header sizes need to catch up. The
        // persist helper refuses to grow past the attribute's own
        // allocated-size field, so an inconsistent header still fails
        // the subsequent write instead of being papered over.
        handle.file_size = new_size;
        persist_nonresident_file_size(ntfs, handle.mft_record, new_size);
        return Ok(());
    }

    let first_new_vcn = if resident_payload.is_some() {
        0
    } else {
        allocated_clusters
    };

    // Grow the allocation from the $Bitmap, merging with the previous
    // run when the next cluster is contiguous.
    while allocated_clusters < clusters_needed {
        let cluster = allocate_cluster_ntfs(ntfs).ok_or(STATUS_UNSUCCESSFUL)?;
        match runs.last_mut() {
            Some(last) if last.0 + last.1 == cluster => last.1 += 1,
            _ => runs.push((cluster, 1)),
        }
        allocated_clusters += 1;
    }

    // Zero-fill every cluster that has no existing on-disk content:
    // all clusters for a resident conversion, only the appended ones
    // for a run-list extension. The resident payload seeds the first
    // bytes of the new stream.
    let payload = resident_payload.unwrap_or_default();
    for vcn in first_new_vcn..allocated_clusters {
        let lcn = vcn_to_lcn(&runs, vcn).ok_or(STATUS_UNSUCCESSFUL)?;
        let mut cluster_buf = alloc::vec![0u8; cluster_size as usize];
        let stream_offset = (vcn * cluster_size as u64) as usize;
        if stream_offset < payload.len() {
            let copy = core::cmp::min(cluster_size as usize, payload.len() - stream_offset);
            cluster_buf[..copy].copy_from_slice(&payload[stream_offset..stream_offset + copy]);
        }
        let first_sector = ntfs.ntfs_data.hidden_sectors + cluster_to_sector(lcn, cluster_size);
        for sector_index in 0..(cluster_size as usize / 512) {
            let mut sector_buf = [0u8; 512];
            sector_buf.copy_from_slice(&cluster_buf[sector_index * 512..(sector_index + 1) * 512]);
            let sector = first_sector + sector_index as u64;
            if !write_mounted_sector(&ntfs.ntfs_data, sector, &sector_buf) {
                return Err(STATUS_UNSUCCESSFUL);
            }
        }
    }

    let replacement = build_nonresident_data_attribute(
        attr_id,
        &runs,
        allocated_clusters,
        cluster_size,
        new_size,
        new_size,
    );
    let rebuilt =
        rebuild_record_replacing_data(&record, &replacement).ok_or(STATUS_UNSUCCESSFUL)?;
    write_mft_record(&ntfs.ntfs_data, handle.mft_record, &rebuilt)?;

    handle.file_size = new_size;
    Ok(())
}

/// Build a complete non-resident $DATA attribute (header + run list +
/// terminator) for the given absolute runs.
fn build_nonresident_data_attribute(
    attr_id: u16,
    runs: &[(u64, u64)],
    total_clusters: u64,
    cluster_size: u32,
    real_size: u64,
    initialized_size: u64,
) -> alloc::vec::Vec<u8> {
    let mut run_bytes = encode_run_list(runs);
    run_bytes.push(0); // run-list terminator (length size 0)

    let mut attr = alloc::vec![0u8; 0x40 + run_bytes.len() + 4];
    let attr_len = attr.len() as u32;
    attr[0..4].copy_from_slice(&AttributeHeader::TYPE_DATA.to_le_bytes());
    attr[4..8].copy_from_slice(&attr_len.to_le_bytes());
    attr[8] = 1; // non-resident
    attr[10..12].copy_from_slice(&0x40u16.to_le_bytes()); // name offset
    attr[14..16].copy_from_slice(&attr_id.to_le_bytes());
    attr[24..32].copy_from_slice(&total_clusters.saturating_sub(1).to_le_bytes()); // last VCN
    attr[32..34].copy_from_slice(&0x40u16.to_le_bytes()); // run-list offset
    attr[40..48].copy_from_slice(&(total_clusters * cluster_size as u64).to_le_bytes());
    attr[48..56].copy_from_slice(&real_size.to_le_bytes());
    attr[56..64].copy_from_slice(&initialized_size.to_le_bytes());
    attr[0x40..0x40 + run_bytes.len()].copy_from_slice(&run_bytes);
    let tail = attr.len() - 4;
    attr[tail..].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    attr
}

/// Rebuild an MFT record with the existing $DATA attribute replaced by
/// `replacement`.
///
/// Every other attribute is preserved in order; attributes that follow
/// $DATA are compacted to the left so the attribute chain stays
/// contiguous. Fails when a second $DATA attribute (fragmented streams
/// that need an $ATTRIBUTE_LIST) is present, or when the rebuilt record
/// no longer fits in the MFT record.
fn rebuild_record_replacing_data(record: &[u8], replacement: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if record.len() < 0x1C {
        return None;
    }
    let start = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    if start > record.len() {
        return None;
    }

    let mut out = alloc::vec::Vec::with_capacity(record.len());
    out.extend_from_slice(&record[..start]);
    let mut offset = start;
    let mut seen_data = false;
    while offset + 8 <= record.len() {
        let attr_type = u32::from_le_bytes([
            record[offset],
            record[offset + 1],
            record[offset + 2],
            record[offset + 3],
        ]);
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[offset + 4],
            record[offset + 5],
            record[offset + 6],
            record[offset + 7],
        ]) as usize;
        if attr_len < 8 || offset + attr_len > record.len() {
            return None;
        }
        if attr_type == AttributeHeader::TYPE_DATA {
            if seen_data {
                // Fragmented $DATA streams need an $ATTRIBUTE_LIST;
                // refuse rather than silently merging fragments.
                return None;
            }
            seen_data = true;
        } else {
            out.extend_from_slice(&record[offset..offset + attr_len]);
        }
        offset += attr_len;
    }
    if !seen_data {
        return None;
    }
    out.extend_from_slice(replacement);
    if out.len() > record.len() {
        return None;
    }
    let used = out.len();
    out.resize(record.len(), 0);
    out[0x18..0x1C].copy_from_slice(&(used as u32).to_le_bytes());
    Some(out)
}

/// Fill in the volume-level metadata (`total_clusters`, `free_clusters`
/// and the volume label) once the boot sector has been parsed.
///
/// Windows reports real values for all three through
/// `FSCTL_GET_NTFS_VOLUME_DATA` / volume information queries; leaving
/// them at zero makes every consumer (cmd `dir` summary, extended API)
/// display a 0-byte volume with no label.
fn fill_volume_metadata(ntfs: &mut NtfsFileSystem, total_sectors: u64, sectors_per_cluster: u32) {
    if sectors_per_cluster == 0 {
        return;
    }
    let total_clusters = total_sectors / sectors_per_cluster as u64;
    ntfs.base.total_clusters = total_clusters;
    ntfs.base.free_clusters = count_free_clusters(ntfs, total_clusters);

    let mut label = [0u16; 64];
    if read_volume_label(ntfs, &mut label) {
        ntfs.base.volume_name = label;
    }
}

/// Count free clusters by scanning the $Bitmap data on disk.
///
/// Mirrors the allocation walk in `allocate_cluster_ntfs`: the LCN of a
/// data cluster is its position in the $Bitmap stream, and each bitmap
/// cluster covers `cluster_size * 8` data clusters. Unreadable sectors
/// are counted as used (conservative, matching the allocator, which
/// refuses to allocate from a bitmap it cannot read).
fn count_free_clusters(ntfs: &NtfsFileSystem, total_clusters: u64) -> u64 {
    unsafe {
        let Some(bitmap_record) = read_mft_record(&ntfs.ntfs_data, system_records::BITMAP) else {
            return 0;
        };
        let Some(data_offset) =
            find_attribute_in_record(&bitmap_record, AttributeHeader::TYPE_DATA)
        else {
            return 0;
        };
        if data_offset + 8 > bitmap_record.len() {
            return 0;
        }
        if bitmap_record[data_offset + 8] == 0 {
            // $Bitmap is always non-resident on a real NTFS volume.
            return 0;
        }
        let data_runs_offset = u16::from_le_bytes([
            bitmap_record[data_offset + 0x20],
            bitmap_record[data_offset + 0x21],
        ]) as usize;
        if data_runs_offset == 0 || data_offset + data_runs_offset > bitmap_record.len() {
            return 0;
        }
        let run_list = &bitmap_record[data_offset + data_runs_offset..];
        let mut runs = [(0u64, 0u64); 64];
        let num_runs = parse_run_list(run_list, &mut runs);
        if num_runs == 0 {
            return 0;
        }

        let bytes_per_cluster = ntfs.ntfs_data.cluster_size as u64;
        let sectors_per_cluster = (bytes_per_cluster / 512).max(1);
        let mut free = 0u64;
        let mut bits_covered = 0u64;
        'outer: for &(start_cluster, length) in runs[..num_runs].iter() {
            for cluster_in_run in 0..length {
                let bitmap_cluster = start_cluster + cluster_in_run;
                let first_sector = cluster_to_sector(bitmap_cluster, ntfs.ntfs_data.cluster_size);
                for sector_index in 0..sectors_per_cluster {
                    let mut sector_buf = [0u8; 512];
                    let read_ok = if let Some(device_id) = ntfs.ntfs_data.device_id {
                        crate::drivers::storage::block::read_block(
                            device_id,
                            first_sector + sector_index,
                            &mut sector_buf,
                        )
                    } else {
                        read_sector(
                            core::ptr::null_mut(),
                            first_sector + sector_index,
                            &mut sector_buf,
                        )
                        .is_ok()
                    };
                    if read_ok {
                        for &byte in sector_buf.iter() {
                            free += byte.count_ones() as u64;
                        }
                    }
                    bits_covered += 512 * 8;
                    if bits_covered >= total_clusters {
                        break 'outer;
                    }
                }
            }
        }
        free.min(total_clusters)
    }
}

/// Read the resident $VOLUME_INFORMATION volume label into `out`.
///
/// The $Volume record (record 3) carries a resident $VOLUME_INFORMATION
/// attribute whose value is a UTF-16LE label. Returns false when the
/// label is absent, non-resident, or larger than `out`.
fn read_volume_label(ntfs: &NtfsFileSystem, out: &mut [u16; 64]) -> bool {
    let Some(record) = read_mft_record(&ntfs.ntfs_data, system_records::VOLUME) else {
        return false;
    };
    let Some(offset) = find_attribute_in_record(&record, AttributeHeader::TYPE_LABEL) else {
        return false;
    };
    if offset + 0x18 > record.len() {
        return false;
    }
    if record[offset + 8] != 0 {
        // $VOLUME_INFORMATION is always resident; treat anything else
        // as corrupt rather than guessing at a run list.
        return false;
    }
    let value_len = u32::from_le_bytes([
        record[offset + 0x10],
        record[offset + 0x11],
        record[offset + 0x12],
        record[offset + 0x13],
    ]) as usize;
    let value_offset = u16::from_le_bytes([record[offset + 0x14], record[offset + 0x15]]) as usize;
    if value_len > out.len() * 2 || value_offset + value_len > record.len() {
        return false;
    }
    let value = &record[offset + value_offset..offset + value_offset + value_len];
    for (index, chunk) in value.as_chunks::<2>().0.iter().enumerate() {
        out[index] = u16::from_le_bytes([chunk[0], chunk[1]]);
    }
    true
}

/// Delete an empty directory identified by a full Win32-style path.
pub fn delete_directory(ntfs: &NtfsFileSystem, path: &[u16]) -> Result<(), NTSTATUS> {
    let (parent_record, name) = parent_and_leaf(ntfs, path, false)?;
    let record_number = match find_file_in_directory(ntfs, parent_record, &name) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    let current = match read_mft_record(&ntfs.ntfs_data, record_number) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    let flags = u16::from_le_bytes([current[0x16], current[0x17]]);
    if flags & 0x0002 == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let child_entries = list_directory(ntfs, record_number);
    if !child_entries.is_empty() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let entries: Vec<DirectoryEntry> = list_directory(ntfs, parent_record)
        .into_iter()
        .filter(|entry| entry.record_number != record_number)
        .collect();
    let parent = match directory_record_with_entries(ntfs, parent_record, &entries) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    if write_mft_record(&ntfs.ntfs_data, parent_record, &parent).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let mut deleted = alloc::vec![0u8; current.len()];
    deleted.copy_from_slice(&current);
    deleted[..4].copy_from_slice(&[0, 0, 0, 0]);
    deleted[0x16..0x18].copy_from_slice(&0u16.to_le_bytes());
    write_mft_record(&ntfs.ntfs_data, record_number, &deleted)
}

/// Delete a file (non-directory entry) from the NTFS filesystem.
///
/// Marks the file's MFT record as deleted and removes its index
/// entry from the parent directory, mirroring the approach used by
/// `delete_directory` but without the "is directory" check.
pub fn delete_file(ntfs: &NtfsFileSystem, path: &[u16]) -> Result<(), NTSTATUS> {
    let (parent_record, name) = parent_and_leaf(ntfs, path, false)?;
    let record_number = match find_file_in_directory(ntfs, parent_record, &name) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    let current = match read_mft_record(&ntfs.ntfs_data, record_number) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    // Reject directories — callers should use delete_directory for those.
    let flags = u16::from_le_bytes([current[0x16], current[0x17]]);
    if flags & 0x0002 != 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Remove the entry from the parent directory's index.
    let entries: Vec<DirectoryEntry> = list_directory(ntfs, parent_record)
        .into_iter()
        .filter(|entry| entry.record_number != record_number)
        .collect();
    let parent = match directory_record_with_entries(ntfs, parent_record, &entries) {
        Some(value) => value,
        None => return Err(STATUS_UNSUCCESSFUL),
    };
    if write_mft_record(&ntfs.ntfs_data, parent_record, &parent).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Zero the MFT record header to mark it as free.
    let mut deleted = alloc::vec![0u8; current.len()];
    deleted.copy_from_slice(&current);
    deleted[..4].copy_from_slice(&[0, 0, 0, 0]);
    deleted[0x16..0x18].copy_from_slice(&0u16.to_le_bytes());
    write_mft_record(&ntfs.ntfs_data, record_number, &deleted)
}

#[cfg(test)]
mod path_parsing_tests {
    use super::ntfs_path_components;
    use alloc::{string::String, vec, vec::Vec};

    fn utf16(path: &[u8]) -> Vec<u16> {
        path.iter().map(|&byte| byte as u16).collect()
    }

    fn names(components: &[Vec<u16>]) -> Vec<String> {
        components
            .iter()
            .map(|component| String::from_utf16_lossy(component))
            .collect()
    }

    #[test]
    fn parses_absolute_nested_paths() {
        let components = ntfs_path_components(&utf16(b"C:\\Alpha\\Beta")).unwrap();
        assert_eq!(names(&components), vec!["Alpha", "Beta"]);
    }

    #[test]
    fn resolves_current_and_parent_components() {
        let components = ntfs_path_components(&utf16(b"C:\\Alpha\\.\\Beta\\..\\Gamma")).unwrap();
        assert_eq!(names(&components), vec!["Alpha", "Gamma"]);
    }

    #[test]
    fn rejects_parent_above_root() {
        assert!(ntfs_path_components(&utf16(b"C:\\Alpha\\..\\..")).is_err());
    }

    #[test]
    fn treats_drive_root_as_zero_components() {
        assert!(ntfs_path_components(&utf16(b"C:\\")).unwrap().is_empty());
    }
}

#[cfg(test)]
mod resident_attribute_tests {
    use super::append_resident_attribute;

    #[test]
    fn resident_attribute_length_is_eight_byte_aligned() {
        let mut record = alloc::vec![0u8; 72];
        let value = [7u8; 90];
        let offset = append_resident_attribute(&mut record, 0x30, &value, 1);

        assert_eq!(offset, 72);
        assert_eq!(
            u32::from_le_bytes(record[offset + 4..offset + 8].try_into().unwrap()),
            120
        );
        assert_eq!(record.len(), 192);
    }
}

/// Mount NTFS volume
pub fn mount(
    device: *mut (),
    _path: &[u16],
    partition: Option<crate::fs::MountContext>,
) -> Option<&'static mut NtfsFileSystem> {
    unsafe {
        crate::boot_println!("[NTFS] mount: entering");
        let device = match partition {
            Some(context) => crate::fs::allocate_mount_context(context) as *mut (),
            None => device,
        };
        let mut buffer = [0u8; 512];

        // read boot sector
        crate::boot_println!("[NTFS] mount: about to read_sector 0");
        if read_sector(device, 0, &mut buffer).is_err() {
            // kprintln!("[NTFS] Failed to read boot sector");
            crate::boot_println!("[NTFS] mount: read_sector failed, returning None");
            return None;
        }
        crate::boot_println!("[NTFS] mount: read_sector ok");

        // Parse boot sector from raw bytes (struct has alignment issues).
        // The NTFS BPB layout (per Microsoft NTFS 3.1 spec):
        //   0x0B..0x0C   bytes_per_sector (u16 LE)
        //   0x0D         sectors_per_cluster (u8)
        //   0x0E..0x0F   reserved_sectors (u16 LE)
        //   0x10         media_descriptor (u8)
        //   0x11..0x16   zero[6] (unused, always 0)
        //   0x17..0x18   sectors_per_track (u16 LE)
        //   0x19..0x1A   num_heads (u16 LE)
        //   0x1C..0x1F   hidden_sectors (u32 LE)    partition start LBA
        //   0x20..0x23   total_sectors_32 (u32 LE) [rarely used; zero on modern NTFS]
        //   0x28..0x2F   total_sectors_64 (u64 LE)
        //   0x30..0x37   mft_lcn (u64 LE)          cluster number, NOT a sector number
        //   0x38..0x3F   mft_mirror_lcn (u64 LE)
        //   0x40         clusters_per_mft_record (i8)
        //                  < 0  ->  2^|n| bytes (typical: -10 means 1024)
        //                  = 0  ->  undefined; assume 1024
        //                  > 0  ->  n * cluster_size bytes
        //   0x41         clusters_per_index_record (i8)  (same encoding)
        //   0x48..0x4F   volume_serial_number (u64 LE)
        //
        // We read these by hand from the raw buffer instead of casting
        // through `NtfsBootSector` because that struct has been wrong in
        // the past (offsets `0x2B..0x33` for `mft_lcn` instead of the
        // correct `0x30..0x38` — see `nt61-ntfs-boot-sector-parsing`
        // skill: a wrong struct gave `mft_lcn=0x40000000000` which then
        // cascaded into every `read_mft_record` returning OOB).
        let bytes_per_sector = u16::from_le_bytes([buffer[0x0B], buffer[0x0C]]);
        let sectors_per_cluster = buffer[0x0D];
        let mft_lcn = u64::from_le_bytes([
            buffer[0x30],
            buffer[0x31],
            buffer[0x32],
            buffer[0x33],
            buffer[0x34],
            buffer[0x35],
            buffer[0x36],
            buffer[0x37],
        ]);
        let mft_mirror_lcn = u64::from_le_bytes([
            buffer[0x38],
            buffer[0x39],
            buffer[0x3A],
            buffer[0x3B],
            buffer[0x3C],
            buffer[0x3D],
            buffer[0x3E],
            buffer[0x3F],
        ]);
        // total_sectors_64 lives at 0x28..0x30 (NOT 0x23, which is the
        // BPB-12/16/32 "BPB" total_sectors that NTFS does not honour).
        let total_sectors_64 = u64::from_le_bytes([
            buffer[0x28],
            buffer[0x29],
            buffer[0x2A],
            buffer[0x2B],
            buffer[0x2C],
            buffer[0x2D],
            buffer[0x2E],
            buffer[0x2F],
        ]);
        // Hidden sectors (partition start LBA) is at 0x1C..0x1F. NTFS
        // inherits the FAT BPB layout, which puts this u32 at 0x1C.
        let hidden_sectors: u64 =
            u32::from_le_bytes([buffer[0x1C], buffer[0x1D], buffer[0x1E], buffer[0x1F]]) as u64;
        let volume_serial = u64::from_le_bytes([
            buffer[0x48],
            buffer[0x49],
            buffer[0x4A],
            buffer[0x4B],
            buffer[0x4C],
            buffer[0x4D],
            buffer[0x4E],
            buffer[0x4F],
        ]);
        crate::boot_println!("[NTFS] boot: bps={} spc={} mft_lcn={} mft_mirror_lcn={} hidden_sectors={} total_sectors_64={} vol_serial=0x{:x}",
        bytes_per_sector, sectors_per_cluster, mft_lcn, mft_mirror_lcn, hidden_sectors, total_sectors_64, volume_serial);

        // Validate OEM ID
        if &buffer[3..11] != b"NTFS    " {
            crate::boot_println!("[NTFS] Invalid OEM ID");
            return None;
        }
        if bytes_per_sector == 0 || bytes_per_sector > 4096 {
            crate::boot_println!("[NTFS] Invalid bytes_per_sector");
            return None;
        }

        let ntfs = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<NtfsFileSystem>(),
        ) as *mut NtfsFileSystem;

        if !ntfs.is_null() {
            unsafe {
                let new_ntfs = NtfsFileSystem::new();
                (*ntfs).base = new_ntfs.base;
                (*ntfs).ntfs_data = new_ntfs.ntfs_data;
                (*ntfs).base.device = device;
                (*ntfs).base.sector_size = bytes_per_sector as u32;
                let bytes_per_cluster = (bytes_per_sector as u32) * (sectors_per_cluster as u32);
                (*ntfs).base.cluster_size = bytes_per_cluster;
                (*ntfs).ntfs_data.cluster_size = bytes_per_cluster;

                // Calculate MFT record size
                // Default to 1024 bytes (standard) if not specified
                let cluster_per_mft_record = buffer[0x40] as i8; // Try offset 0x40 first
                let cluster_per_index_record = buffer[0x41] as i8;

                let mft_record_size: u32 = if cluster_per_mft_record < 0 {
                    // Negative means power of 2 divisor of sectors_per_cluster
                    let shift = (-cluster_per_mft_record) as u32;
                    (1u32) << shift
                } else if cluster_per_mft_record == 0 {
                    // Default to 1024 bytes if 0
                    1024
                } else {
                    (cluster_per_mft_record as u32) * bytes_per_cluster
                };

                let index_record_size: u32 = if cluster_per_index_record < 0 {
                    let shift = (-cluster_per_index_record) as u32;
                    (1u32) << shift
                } else if cluster_per_index_record == 0 {
                    4096
                } else {
                    (cluster_per_index_record as u32) * bytes_per_cluster
                };

                (*ntfs).ntfs_data.mft_record_size = mft_record_size;
                (*ntfs).ntfs_data.index_record_size = index_record_size;

                // The kernel always reads the NTFS volume through winload's
                // ramdisk mirror (BootInfo.sys_image_base). The mirror's
                // first byte is sector 0 of the partition, so `hidden_sectors`
                // from the BPB (the partition's LBA on the physical disk)
                // is NOT a valid offset to add on top of in-mirror addresses
                // — adding it would push every read far past the end of the
                // mirror (the build_image NTFS emitter writes the physical
                // LBA 131106 into the BPB at offset 0x1C, which previously
                // caused `read_sector: OOB` on every non-resident file read).
                // Force hidden_sectors = 0 for kernel-side mounts; winload
                // reads directly via UEFI BlockIO and ignores this field.
                (*ntfs).ntfs_data.mft_start = mft_lcn * (sectors_per_cluster as u64);
                (*ntfs).ntfs_data.hidden_sectors = 0;
                (*ntfs).ntfs_data.volume_serial = volume_serial;
                // mft_mirror_lcn / total_sectors_64 are useful for
                // future recovery paths but not consumed by the current
                // reader — stash them next to mft_start so a follow-up
                // commit can pick them up without re-parsing the boot
                // sector.
                (*ntfs).ntfs_data.mft_size = mft_mirror_lcn * (sectors_per_cluster as u64);
                fill_volume_metadata(&mut *ntfs, total_sectors_64, sectors_per_cluster as u32);
                crate::boot_println!("[NTFS] mount: mft_start={} (mft_lcn={}*spc={}) mft_record_size={} index_record_size={} hidden_sectors=FORCED-0 vol_serial=0x{:x}",
                (*ntfs).ntfs_data.mft_start, mft_lcn, sectors_per_cluster, (*ntfs).ntfs_data.mft_record_size,
                (*ntfs).ntfs_data.index_record_size, volume_serial);
                (*ntfs).ntfs_data.mounted = true;
            }

            // kprintln!("      NTFS version: 3.1");
            // kprintln!("      MFT record size: {} bytes",  (*ntfs).ntfs_data.mft_record_size );
            // kprintln!("      Index record size: {} bytes", unsafe { (*ntfs).ntfs_data.index_record_size });
            // kprintln!("      Volume mounted successfully");

            // Store in global for pagefile access
            *NTFS_MOUNTED_FS.lock() = Some(unsafe { &mut *ntfs });
            *NTFS_MOUNTED.lock() = true;
            // Initialize pagefile support
            init_pagefile(&(*ntfs).ntfs_data);

            // Initialize the $LogFile journaling subsystem for this volume.
            crate::fs::ntfs::logfile::init_log_file(4096);

            return Some(&mut *ntfs);
        }

        None
    }
}

/// Initialize pagefile on this NTFS volume.
fn init_pagefile(ntfs_data: &NtfsData) {
    crate::boot_println!("[NTFS] init_pagefile entered (skipping pagefile open)");
    // Temporarily skip the pagefile open-or-create path while we
    // debug the kernel-phase bring-up. See FAT32::init_pagefile for
    // the same comment. The parameter is intentionally referenced
    // in the comment above so it does not trip unused-variable
    // diagnostics during the disabled phase; reinstate the body
    // below once the bring-up path is stable.
    let _ = ntfs_data;

    // The pagefile bring-up path is still disabled while the kernel
    // mount sequence is stabilising. Keep the allocation out of the
    // hot boot path until the underlying MFT allocator is verified.
}

/// Check if NTFS is mounted.
pub fn is_mounted() -> bool {
    *NTFS_MOUNTED.lock()
}

/// Get the mounted NTFS filesystem.
pub fn get_mounted_fs() -> Option<&'static mut NtfsFileSystem> {
    let guard = NTFS_MOUNTED_FS.lock();
    match &*guard {
        Some(fs) => {
            crate::boot_milestone!("NTFS", "TRACE get some");
            // SAFETY: We return a mutable reference to the same data
            // The caller must ensure no other mutable references exist
            Some(unsafe { &mut *(*fs as *const _ as *mut NtfsFileSystem) })
        }
        None => {
            crate::boot_milestone!("NTFS", "TRACE get none");
            None
        }
    }
}

/// Unmount NTFS volume
pub fn unmount(_fs: *mut NtfsFileSystem) {
    // kprintln!("[NTFS] Volume unmounted");
}

/// Register NTFS driver
pub fn register_driver() {
    static mut NTFS_DRIVER: FileSystemDriver = FileSystemDriver {
        name: [
            b'N' as u16,
            b't' as u16,
            b'f' as u16,
            b's' as u16,
            0,
            0,
            0,
            0,
        ],
        fs_type: FileSystemType::Ntfs,
        mount: Some(mount_trampoline),
        unmount: Some(unmount_fs),
    };
    // kprintln!("    NTFS driver registered");
    // kprintln!("      Features: journaling, ACLs, compression, encryption, sparse files");
    // kprintln!("      Max file size: 16TB (with 64KB clusters)");
    crate::fs::register(core::ptr::addr_of_mut!(NTFS_DRIVER));
}

fn mount_trampoline(device: *mut (), path: &[u16]) -> *mut FileSystem {
    match mount(device, path, None) {
        Some(fs) => fs as *mut NtfsFileSystem as *mut FileSystem,
        None => core::ptr::null_mut(),
    }
}

fn unmount_fs(fs: *mut FileSystem) {
    unmount(fs as *mut NtfsFileSystem);
}

/// NTFS smoke test
pub fn smoke_test() -> bool {
    // kprintln!("    [NTFS SMOKE] Testing NTFS filesystem...");

    // Test boot sector parsing
    let mut boot_data = [0u8; 512];
    boot_data[3..11].copy_from_slice(b"NTFS    ");
    boot_data[11..19].copy_from_slice(&1u16.to_le_bytes()); // bytes per sector
    boot_data[13] = 8; // sectors per cluster
    boot_data[40..48].copy_from_slice(&1000u64.to_le_bytes()); // total sectors
    boot_data[48..56].copy_from_slice(&786432u64.to_le_bytes()); // MFT LCN
    boot_data[64..72].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes()); // serial

    let boot = unsafe { &*(boot_data.as_ptr() as *const NtfsBootSector) };

    if boot.is_valid() {
        // kprintln!("      [OK] Boot sector validation");
    } else {
        // kprintln!("      [FAIL] Boot sector validation");
        return false;
    }

    // Test run list parsing
    let mut output = [(0u64, 0u64); 8];
    let test_runs = [0x25, 0x00, 0x10, 0x00]; // length 5, offset 16
    let count = parse_run_list(&test_runs, &mut output);

    if count > 0 {
        // kprintln!("      [OK] Run list parsing ({} runs)", count);
    } else {
        // kprintln!("      [WARN] Run list parsing");
    }

    // Test MFT record header
    let mut record_data = [0u8; 1024];
    record_data[0..4].copy_from_slice(b"FILE");
    record_data[8..10].copy_from_slice(&1u16.to_le_bytes()); // IN_USE flag

    let header = unsafe { &*(record_data.as_ptr() as *const MftRecordHeader) };
    if header.is_valid() && header.is_in_use() {
        // kprintln!("      [OK] MFT record parsing");
    } else {
        // kprintln!("      [FAIL] MFT record parsing");
        return false;
    }

    // kprintln!("    [NTFS SMOKE] ALL PASSED");
    true
}

// =============================================================================
// Journal ($LogFile) Support
// =============================================================================

/// Transaction state for journaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TransactionState {
    Active = 0,
    Prepared = 1,
    Committed = 2,
    Aborted = 3,
}

/// Log record type.
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum LogRecordType {
    CompUndo = 0x0001,
    Undo = 0x0002,
    Redo = 0x0003,
    Do = 0x0004,
    Skip = 0x0005,
    Checkpoint = 0x0006,
    Commit = 0x0007,
}

/// Log file page header.
#[repr(C)]
pub struct LogPageHeader {
    /// Page sequence number
    pub page_seq_num: u64,
    /// Next record offset
    pub next_record_offset: u32,
    /// Reserved
    pub reserved1: u16,
    /// Last client ID
    pub last_client_id: u64,
    /// Client log page offset
    pub client_page_offset: u32,
    /// Client ID
    pub client_id: u64,
    /// Page status flags
    pub page_status: u16,
}

impl LogPageHeader {
    pub fn is_valid(&self) -> bool {
        self.page_status == 0x0000 || self.page_status == 0x0001
    }
}

/// Restart area header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RestartAreaHeader {
    /// Restart area magic (RSTR)
    pub magic: [u8; 4],
    /// Restart area offset
    pub restart_offset: u16,
    /// Minor version
    pub minor_version: u16,
    /// Major version
    pub major_version: u16,
    /// Checksum
    pub check_sum: u32,
    /// Restart area length
    pub restart_length: u16,
    /// Client array offset
    pub client_array_offset: u16,
    /// Number of clients
    pub client_count: u16,
    /// Target identifier
    pub target_identifier: u64,
    /// Start of log
    pub start_of_log: u64,
    /// Last log sequence number
    pub last_lsn: u64,
    /// Log page size
    pub log_page_size: u32,
    /// Reserved
    pub reserved: u32,
}

impl RestartAreaHeader {
    /// Expected magic value for restart area.
    pub const EXPECTED_MAGIC: [u8; 4] = *b"RSTR";

    pub fn is_valid(&self) -> bool {
        self.magic == Self::EXPECTED_MAGIC && self.restart_length >= 64 && self.log_page_size >= 512
    }
}

/// Log record header.
#[repr(C)]
pub struct LogRecordHeader {
    /// This LSN
    pub this_lsn: u64,
    /// Previous LSN
    pub previous_lsn: u64,
    /// Client undo LSN
    pub client_undo_lsn: u64,
    /// Client ID
    pub client_id: u32,
    /// Record type
    pub record_type: u16,
    /// Transaction ID
    pub transaction_id: u32,
    /// flags
    pub flags: u16,
    /// Record length (does not include header)
    pub record_length: u16,
    /// Attribute type code
    pub attribute_type: u32,
    /// LSN of transaction commit (if committed)
    pub transaction_commit_lsn: u64,
}

impl LogRecordHeader {
    /// Get the total size of this record (header + data).
    pub fn total_size(&self) -> u32 {
        64 + self.record_length as u32
    }
}

/// Open journal for a volume.
/// This initializes the journaling subsystem by reading the restart area
/// and setting up the log client context.
pub fn open_journal(ntfs: &mut NtfsFileSystem) -> bool {
    // kprintln!("[NTFS] Opening journal ($LogFile)");

    // Find the $LogFile MFT record (record 2)
    // In NTFS, $LogFile is typically MFT record 2
    let log_file_record = read_mft_record(&ntfs.ntfs_data, 2);

    if log_file_record.is_none() || log_file_record.as_ref().is_none_or(|v| v.is_empty()) {
        // kprintln!("[NTFS] $LogFile MFT record not found");
        return false;
    }

    // read the restart area to get log file parameters
    let restart_area = read_journal_restart_area(ntfs);

    // A journal can only be opened when a valid restart area exists;
    // reporting success without one would claim recovery state the
    // volume does not have.
    restart_area.is_some()
}

/// Parse a restart area header from raw stream bytes.
///
/// Fields are read explicitly so no unaligned pointer cast is needed;
/// the offsets mirror the in-memory layout of `RestartAreaHeader` that
/// previous code assumed when reinterpreting a sector buffer.
fn parse_restart_area_header(bytes: &[u8]) -> Option<RestartAreaHeader> {
    if bytes.len() < 56 {
        return None;
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[0..4]);
    Some(RestartAreaHeader {
        magic,
        restart_offset: u16::from_le_bytes([bytes[4], bytes[5]]),
        minor_version: u16::from_le_bytes([bytes[6], bytes[7]]),
        major_version: u16::from_le_bytes([bytes[8], bytes[9]]),
        check_sum: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        restart_length: u16::from_le_bytes([bytes[16], bytes[17]]),
        client_array_offset: u16::from_le_bytes([bytes[18], bytes[19]]),
        client_count: u16::from_le_bytes([bytes[20], bytes[21]]),
        target_identifier: u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        start_of_log: u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
        last_lsn: u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        log_page_size: u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]),
        reserved: u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]),
    })
}

/// read the journal restart area.
///
/// Reads the beginning of the on-disk `$LogFile` stream (MFT record
/// `system_records::LOG_FILE`) and looks for a valid `RSTR` restart
/// header at the page-aligned offsets Windows uses. Returns `None`
/// when the stream cannot be read or no valid restart area is found.
fn read_journal_restart_area(ntfs: &NtfsFileSystem) -> Option<RestartAreaHeader> {
    let stream = read_nonresident_stream(
        &ntfs.ntfs_data,
        system_records::LOG_FILE,
        AttributeHeader::TYPE_DATA,
        4 * 1024,
    )?;

    let offsets = [0x00usize, 0x200, 0x400, 0x600];
    for &offset in &offsets {
        if offset + 64 > stream.len() {
            continue;
        }
        if &stream[offset..offset + 4] != b"RSTR" {
            continue;
        }
        let header = parse_restart_area_header(&stream[offset..])?;
        if header.is_valid() {
            return Some(header);
        }
    }

    None
}

/// read journal records between two LSNs.
///
/// On-disk `$LogFile` page/record parsing is not implemented, so this
/// returns an empty record set instead of fabricating bootstrap records.
/// `replay_journal` therefore refuses to replay rather than pretending
/// a recovery happened.
pub fn read_journal_records(
    _ntfs: &NtfsFileSystem,
    _start_lsn: u64,
    _end_lsn: u64,
) -> Vec<LogRecordHeader> {
    Vec::new()
}

/// Replay journal to recover from an unclean shutdown.
///
/// On-disk `$LogFile` page parsing is not implemented: neither the
/// current LSN nor any pending record can be determined, and no disk
/// modification can be replayed. Reporting success would claim a
/// recovery that never happened, so every call fails explicitly until
/// real log-page parsing exists.
pub fn replay_journal(_ntfs: &mut NtfsFileSystem) -> Result<usize, NTSTATUS> {
    Err(STATUS_UNSUCCESSFUL)
}

/// write a log record to the journal.
///
/// The on-disk `$LogFile` write path is not implemented. The in-memory
/// ring buffer in `super::logfile` is volatile and not this function's
/// concern; returning `true` would claim stable persistence that never
/// happened, so the call fails explicitly.
pub fn write_journal_record(
    _ntfs: &mut NtfsFileSystem,
    _record_type: LogRecordType,
    _data: &[u8],
) -> bool {
    false
}

/// Flush the journal to disk.
///
/// No on-disk log records exist to flush (see `write_journal_record`);
/// reporting success would imply stable-storage guarantees the current
/// implementation cannot provide.
pub fn flush_journal(_ntfs: &mut NtfsFileSystem) -> bool {
    false
}

// =============================================================================
// Volume Shadow Copy Support
// =============================================================================

/// Volume snapshot state.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum SnapshotState {
    Allocated = 0,
    Committed = 1,
    Aborted = 2,
}

/// create a volume shadow copy.
///
/// Diff-area based snapshots are not implemented: no MFT/bitmap copy
/// is taken and no diff area exists. Returning `true` would hand out a
/// snapshot ID that does not exist, so the call fails explicitly.
pub fn create_snapshot(_ntfs: &mut NtfsFileSystem) -> bool {
    false
}

/// Query shadow copy state.
///
/// Snapshots are never created (see `create_snapshot`), so there is no
/// state to report; `None` is the honest answer for every ID.
pub fn query_snapshot_state(
    _ntfs: &mut NtfsFileSystem,
    _snapshot_id: u64,
) -> Option<SnapshotState> {
    None
}

// =============================================================================
// Reparse Point Support
// =============================================================================

/// Reparse point tags.
pub mod reparse_tags {
    pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
    pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
    pub const IO_REPARSE_TAG_DEDUP: u32 = 0x80000013;
    pub const IO_REPARSE_TAG_FILTER_MANAGER: u32 = 0x800000B0;
    pub const IO_REPARSE_TAG_SIS: u32 = 0x80000007;
}

/// Security descriptor support.
pub mod security;

/// Check if an MFT record has a reparse point.
pub fn has_reparse_point(record: &[u8]) -> bool {
    // Check for reparse point attribute (0xC0)
    if find_attribute_in_record(record, 0xC0).is_some() {
        return true;
    }
    false
}

/// Get reparse tag from a file.
pub fn get_reparse_tag(_record: &[u8]) -> Option<u32> {
    // In a full implementation, this would parse the reparse point attribute
    // and return the tag
    None
}

// =============================================================================
// Security Descriptor Support
// =============================================================================

/// Security ID for well-known security descriptors.
pub mod well_known_sids {
    use super::security::SecurityId;

    pub const NULL_SID: SecurityId = 0;
    pub const EVERYONE: SecurityId = 1;
    pub const SYSTEM: SecurityId = 2;
    pub const ADMINISTRATORS: SecurityId = 3;
    pub const USERS: SecurityId = 4;
    pub const AUTHENTICATED_USERS: SecurityId = 5;
    pub const RESTRICTED_CODE: SecurityId = 6;
}

pub mod compression;
pub mod encryption;
pub mod extended_api;
pub use extended_api::{get_space_usage, get_volume_label, NtfsSpaceUsage};
pub mod logfile;
pub mod quota;
pub mod reparse;
pub mod write_test;

#[cfg(test)]
mod index_search_tests {
    use super::*;

    fn utf16_name(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn vcn_to_lcn_walks_run_list_in_vcn_order() {
        let runs = [(100u64, 2u64), (500u64, 3u64)];
        assert_eq!(index_vcn_to_lcn(&runs, 0), Some(100));
        assert_eq!(index_vcn_to_lcn(&runs, 1), Some(101));
        assert_eq!(index_vcn_to_lcn(&runs, 2), Some(500));
        assert_eq!(index_vcn_to_lcn(&runs, 4), Some(502));
        assert_eq!(index_vcn_to_lcn(&runs, 5), None);
    }

    #[test]
    fn indx_entry_region_bounds_entry_walk() {
        let mut record = alloc::vec![0u8; 512];
        record[0..4].copy_from_slice(b"INDX");
        record[0x24] = 0x28;
        let entry = build_index_entry(42, 5, &utf16_name("alpha"), false, false);
        record[0x28..0x28 + entry.len()].copy_from_slice(&entry);
        let index_size = entry.len() as u32;
        record[0x26..0x2A].copy_from_slice(&index_size.to_le_bytes());
        let region = indx_entry_region(&record).unwrap();
        assert_eq!(region.len(), entry.len());

        // A broken signature must be rejected instead of parsed.
        let mut bad = record.clone();
        bad[0..4].copy_from_slice(b"XXXX");
        assert!(indx_entry_region(&bad).is_none());
    }

    #[test]
    fn flat_entry_walk_matches_name_case_insensitively() {
        let ntfs = NtfsFileSystem::new();
        let entry = build_index_entry(42, 5, &utf16_name("csrss"), false, false);
        let end = build_index_entry(0, 0, &[], false, true);
        let mut entries = alloc::vec::Vec::new();
        entries.extend_from_slice(&entry);
        entries.extend_from_slice(&end);

        let mut visited = alloc::vec::Vec::new();
        let found = search_index_entries(
            &ntfs,
            &entries,
            &utf16_name("CSRSS"),
            None,
            4096,
            0,
            &mut visited,
        );
        assert_eq!(found, Some(42));

        // A NUL-terminated needle must not match anything.
        let mut needle = utf16_name("csrss");
        needle.push(0);
        let found = search_index_entries(&ntfs, &entries, &needle, None, 4096, 0, &mut visited);
        assert_eq!(found, None);
    }

    #[test]
    fn sub_node_pointer_is_read_from_entry_tail() {
        let ntfs = NtfsFileSystem::new();
        let mut entry = build_index_entry(9, 5, &utf16_name("beta"), false, false);
        // Sub-node VCN in the last 8 bytes plus the INDEX_ENTRY_NODE flag.
        entry.extend_from_slice(&7u64.to_le_bytes());
        let length = entry.len() as u16;
        entry[8..10].copy_from_slice(&length.to_le_bytes());
        entry[12..14].copy_from_slice(&0x01u16.to_le_bytes());
        let end = build_index_entry(0, 0, &[], false, true);
        let mut entries = alloc::vec::Vec::new();
        entries.extend_from_slice(&entry);
        entries.extend_from_slice(&end);

        // Without a run list the pointer cannot be followed, but the
        // walk must still match the entry name and must not loop.
        let mut visited = alloc::vec::Vec::new();
        let found = search_index_entries(
            &ntfs,
            &entries,
            &utf16_name("beta"),
            None,
            4096,
            0,
            &mut visited,
        );
        assert_eq!(found, Some(9));
        let found = search_index_entries(
            &ntfs,
            &entries,
            &utf16_name("gamma"),
            None,
            4096,
            0,
            &mut visited,
        );
        assert_eq!(found, None);
    }

    #[test]
    fn parses_index_allocation_runs_header() {
        let mut data = alloc::vec![0u8; 0x40];
        data[8] = 1;
        data[0x20] = 0x40;
        data[0x28..0x30].copy_from_slice(&4096u64.to_le_bytes());
        // One run: header 0x21 (offset size 2, length size 1), length 1,
        // LCN delta 0, then the terminating zero header.
        data.extend_from_slice(&[0x21, 0x01, 0x00, 0x00, 0x00]);
        let (runs, allocated) = parse_index_allocation_runs(&data).unwrap();
        assert_eq!(allocated, 4096);
        assert_eq!(runs, alloc::vec![(0u64, 1u64)]);

        // Truncated and resident headers fail cleanly.
        assert!(parse_index_allocation_runs(&alloc::vec![0u8; 0x20]).is_none());
        let mut resident = data.clone();
        resident[8] = 0;
        assert!(parse_index_allocation_runs(&resident).is_none());
    }

    #[test]
    fn resident_bitmap_is_sliced_from_record() {
        let ntfs = NtfsFileSystem::new();
        let mut record = alloc::vec![0u8; 96];
        record[0x14..0x16].copy_from_slice(&96u16.to_le_bytes());
        let value = [0b0000_0111u8];
        let offset =
            append_resident_attribute(&mut record, AttributeHeader::TYPE_BITMAP, &value, 0);
        assert_eq!(offset, 96);
        while record.len() % 8 != 0 {
            record.push(0);
        }
        record.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let bitmap = read_index_bitmap(&ntfs, &record).unwrap();
        assert_eq!(bitmap[0], 0b0000_0111);

        // A record without a $BITMAP attribute yields None, not a guess.
        let mut no_bitmap = alloc::vec![0u8; 96];
        no_bitmap[0x14..0x16].copy_from_slice(&96u16.to_le_bytes());
        no_bitmap.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(read_index_bitmap(&ntfs, &no_bitmap).is_none());
    }
}
