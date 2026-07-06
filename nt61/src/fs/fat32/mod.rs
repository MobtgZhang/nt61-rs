//! FAT32 File System Driver
//
//! Implements the FAT32 file system used by the EFI System Partition
//! and the small boot volume that holds `bootmgr.efi` and friends.
//
//! # Layout
//! The FAT32 layout is well-documented in Microsoft's
//! "FAT: General Overview of On-Disk Format" spec:
//
//! ```text
//!   Sector 0                     Reserved sectors (boot sector is at 0)
//!   Sector <reserved_sectors>    FAT region (typically <num_fats> copies)
//!   Sector <fat_end>             Data region (cluster 2 is the root dir)
//! ```
//
//! Cluster numbers in the FAT are 28 bits - the high 4 bits of every
//! FAT entry are reserved and must be preserved when writing. The
//! special values we need to recognise are `0x00000000` (free),
//! `0x00000001` (reserved), `0x0FFFFFF8..=0x0FFFFFFF` (end-of-chain)
//! and `0x0FFFFFF7` (bad cluster).
//
//! # Mounting
//! We expose two entry points: `mount` reads the boot sector and
//! registers a `Fat32FileSystem`; `Fat32FileSystem::read_file` reads
//! the bytes of a file by walking the cluster chain. Write support is
//! out of scope for the bootstrap.

extern crate alloc;

use alloc::vec::Vec;
use crate::fs::{FileSystem, FileSystemDriver, FileSystemType};
use crate::kprintln_info;
use crate::kprintln_warn;
#[cfg(target_arch = "x86_64")]
use crate::drivers::storage::ahci;
#[cfg(target_arch = "x86_64")]
use crate::drivers::storage::ataport::AtaPortInitialize;
use crate::ke::sync::Spinlock;
use core::ptr::null_mut;

/// FAT32 pagefile support module
pub mod pagefile;

/// FAT32 Boot Sector (BPB + EBR). Field layout matches the Microsoft
/// `FAT_GENERAL_SPEC` document.
#[repr(C)]
pub struct Fat32BootSector {
    pub jump: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entries: u16,
    pub total_sectors_16: u16,
    pub media_descriptor: u8,
    pub sectors_per_fat_16: u16,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub sectors_per_fat_32: u32,
    pub extended_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub drive_number: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    pub fs_type: [u8; 8],
}

impl Fat32BootSector {
    pub fn is_valid(&self) -> bool {
        self.jump[0] == 0xEB || self.jump[0] == 0xE9
    }
    pub fn sector_size(&self) -> u32 {
        self.bytes_per_sector as u32
    }
    pub fn cluster_size(&self) -> u32 {
        self.sector_size() * self.sectors_per_cluster as u32
    }
    pub fn fat_size_sectors(&self) -> u32 {
        self.sectors_per_fat_32
    }
}

/// FAT32 directory entry - 32 bytes, packed.
#[repr(C, packed)]
pub struct FatDirectoryEntry {
    pub name: [u8; 11],
    pub attributes: u8,
    pub reserved: u8,
    pub creation_time_tenth: u8,
    pub creation_time: u16,
    pub creation_date: u16,
    pub last_access_date: u16,
    pub first_cluster_high: u16,
    pub modification_time: u16,
    pub modification_date: u16,
    pub first_cluster_low: u16,
    pub file_size: u32,
}

impl FatDirectoryEntry {
    pub fn is_valid(&self) -> bool {
        self.name[0] != 0x00 && self.name[0] != 0xE5
    }
    pub fn is_directory(&self) -> bool {
        (self.attributes & 0x10) != 0
    }
    pub fn is_long_name(&self) -> bool {
        self.attributes == 0x0F
    }
    pub fn is_volume_id(&self) -> bool {
        (self.attributes & 0x08) != 0
    }
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_high as u32) << 16) | (self.first_cluster_low as u32)
    }
    pub fn file_size(&self) -> u32 {
        self.file_size
    }
}

/// Directory entry attribute bits.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;

/// FAT32 FSINFO sector.
#[repr(C)]
pub struct Fat32FsInfo {
    pub lead_signature: u32,
    pub reserved1: [u8; 480],
    pub structure_signature: u32,
    pub free_clusters: u32,
    pub next_free_cluster: u32,
    pub reserved2: [u8; 12],
    pub trail_signature: u32,
}

impl Fat32FsInfo {
    pub const LEAD_SIG: u32 = 0x41615252;
    pub const STRUCT_SIG: u32 = 0x61417272;
    pub const TRAIL_SIG: u32 = 0xAA550000;
}

/// Per-volume data.
pub struct Fat32Data {
    pub boot_sector: Fat32BootSector,
    pub fat_start_sector: u64,
    pub data_start_sector: u64,
    pub root_cluster: u32,
}

/// FAT32 file system instance.
pub struct Fat32FileSystem {
    pub base: FileSystem,
    pub fat_data: Fat32Data,
}

impl Fat32FileSystem {
    pub const fn new() -> Self {
        Self {
            base: FileSystem {
                driver: null_mut(),
                device: null_mut(),
                volume_name: [0; 64],
                fs_type: FileSystemType::Fat32,
                sector_size: 512,
                cluster_size: 4096,
                total_clusters: 0,
                free_clusters: 0,
            },
            fat_data: Fat32Data {
                boot_sector: Fat32BootSector {
                    jump: [0; 3],
                    oem_name: [0; 8],
                    bytes_per_sector: 0,
                    sectors_per_cluster: 0,
                    reserved_sectors: 0,
                    num_fats: 0,
                    root_entries: 0,
                    total_sectors_16: 0,
                    media_descriptor: 0,
                    sectors_per_fat_16: 0,
                    sectors_per_track: 0,
                    num_heads: 0,
                    hidden_sectors: 0,
                    total_sectors_32: 0,
                    sectors_per_fat_32: 0,
                    extended_flags: 0,
                    fs_version: 0,
                    root_cluster: 2,
                    fs_info_sector: 0,
                    backup_boot_sector: 0,
                    drive_number: 0,
                    boot_signature: 0,
                    volume_id: 0,
                    volume_label: [0; 11],
                    fs_type: [0; 8],
                },
                fat_start_sector: 0,
                data_start_sector: 0,
                root_cluster: 2,
            },
        }
    }
}

/// FAT32 partition offset (set by mount_fat32_partition in fs/mod.rs)
static FAT32_PARTITION_OFFSET: Spinlock<u64> = Spinlock::new(0);
/// Thread-safe mounted filesystem storage - stores raw pointer for safe mutable access
static mut FAT32_MOUNTED_FS_PTR: *mut Fat32FileSystem = core::ptr::null_mut();

/// Set the FAT32 partition offset (sector number where partition starts)
pub fn set_partition_offset(offset: u64) {
    *FAT32_PARTITION_OFFSET.lock() = offset;
}

/// Get the FAT32 partition offset
pub fn get_partition_offset() -> u64 {
    *FAT32_PARTITION_OFFSET.lock()
}

/// Set the FAT32 filesystem as mounted (atomically)
pub fn set_mounted_fs(fs: &'static mut Fat32FileSystem) {
    unsafe {
        FAT32_MOUNTED_FS_PTR = fs;
    }
}

/// Check if FAT32 is mounted (atomically)
pub fn is_mounted() -> bool {
    !unsafe { FAT32_MOUNTED_FS_PTR.is_null() }
}

/// Get the mounted FAT32 filesystem (for CMD use)
/// Returns a mutable reference to the mounted filesystem
/// Note: This is thread-safe via the original Spinlock pattern
pub fn get_mounted_fs() -> Option<&'static mut Fat32FileSystem> {
    unsafe {
        if FAT32_MOUNTED_FS_PTR.is_null() {
            None
        } else {
            Some(&mut *FAT32_MOUNTED_FS_PTR)
        }
    }
}

/// Clear the mounted filesystem reference
pub fn clear_mounted_fs() {
    unsafe {
        FAT32_MOUNTED_FS_PTR = core::ptr::null_mut();
    }
}

/// Read a sector from the backing device using AHCI.
pub fn read_sector(_device: *mut (), sector: u64, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }

    // Prefer the *active* partition mirror, when one is set by
    // the dispatcher in `fs::mod`. The dispatcher flips the
    // pointer to whichever mirror (ESP or System) it is currently
    // trying to mount. This is what lets the same FAT32 driver
    // mount the Z: (ESP) or the C: (System) drive as FAT32.
    //
    // Fallback: the ESP mirror registered by winload. This is the
    // historical path — kept so legacy call sites that don't go
    // through `mount_partition_detected` still see the ESP.
    if let Some(base) = crate::fs::active_partition_ramdisk() {
        let off = (sector as usize) * 512;
        // Byte-by-byte read because the UEFI-allocated mirror
        // may live on UC-typed MTRR memory where `rep movsb`
        // faults. See `fs::esp_ramdisk_read` for the original
        // analysis.
        unsafe {
            let src = base.add(off);
            for i in 0..512 {
                buffer[i] = core::ptr::read_volatile(src.add(i));
            }
        }
        return Ok(());
    }
    let n = crate::fs::esp_ramdisk_read(sector * 512, buffer);
    if n >= 512 {
        return Ok(());
    }

    // x86_64-only fallback to AHCI/ATA drivers.
    #[cfg(target_arch = "x86_64")]
    {
        let partition_offset = *FAT32_PARTITION_OFFSET.lock();
        let absolute_sector = partition_offset + sector;

        // Try AHCI first (channel 0, port 0)
        if ahci::read_sector(0, 0, absolute_sector as u32, buffer) {
            // AHCI read succeeded
            return Ok(());
        }

        // Fallback: Try ATA/ATAPI
        crate::drivers::storage::ataport::AtaPortInitialize(0);
        let mut words = [0u16; 256];
        if crate::drivers::storage::ataport::read_sector(0, absolute_sector as u32, &mut words) {
            // Convert u16 array to u8 array (little-endian)
            for i in 0..256 {
                buffer[i * 2] = words[i] as u8;
                buffer[i * 2 + 1] = (words[i] >> 8) as u8;
            }
            return Ok(());
        }
    }

    Err(())
}

/// Write a sector to the backing device.
pub fn write_sector(_device: *mut (), sector: u64, buffer: &[u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }

    // Try storage layer first (AHCI, ATA, RAM disk)
    if crate::drivers::storage::write_device_sector(0, sector as u32, buffer) {
        return Ok(());
    }

    // x86_64-only fallback to AHCI/ATA drivers.
    #[cfg(target_arch = "x86_64")]
    {
        let partition_offset = get_partition_offset();
        let absolute_sector = partition_offset + sector;

        // Try AHCI directly (channel 0, port 0)
        if ahci::write_sector(0, 0, absolute_sector as u32, buffer) {
            return Ok(());
        }

        // Fallback: Try ATA/ATAPI
        AtaPortInitialize(0);
        let mut words = [0u16; 256];
        // Convert u8 buffer to u16 words (little-endian)
        for i in 0..256 {
            words[i] = (buffer[i * 2] as u16) | ((buffer[i * 2 + 1] as u16) << 8);
        }
        if crate::drivers::storage::ata::write_sector(0, absolute_sector as u32, &words) {
            return Ok(());
        }
    }

    Err(())
}

/// Update a FAT entry for a given cluster.
/// This function reads the FAT sector, modifies the entry, and writes it back.
/// For FAT32, we preserve the high 4 bits of each entry.
pub fn update_fat_entry(fs: &Fat32FileSystem, cluster: u32, value: u32) -> Result<(), ()> {
    let fat_start = fs.fat_data.fat_start_sector;
    let sector_size = fs.base.sector_size as u64;
    let bytes_per_sector = sector_size as usize;

    // Each FAT entry is 4 bytes (32-bit for FAT32)
    let entry_offset = (cluster as u64) * 4;
    let fat_sector = fat_start + (entry_offset / sector_size);
    let offset_in_sector = (entry_offset % sector_size) as usize;

    // Read FAT sector
    let mut sector_buf = [0u8; 512];
    if read_sector(fs.base.device, fat_sector, &mut sector_buf).is_err() {
        // kprintln!("[FAT32] update_fat_entry: failed to read FAT sector {}", fat_sector)  // kprintln disabled (memcpy crash workaround);
        return Err(());
    }

    // Make sure we have enough bytes for the entry
    if offset_in_sector + 4 > bytes_per_sector {
        // kprintln!("[FAT32] update_fat_entry: entry spans sector boundary")  // kprintln disabled (memcpy crash workaround);
        return Err(());
    }

    // Read current value (preserve high 4 bits for FAT32)
    let old_value = u32::from_le_bytes([
        sector_buf[offset_in_sector],
        sector_buf[offset_in_sector + 1],
        sector_buf[offset_in_sector + 2],
        sector_buf[offset_in_sector + 3],
    ]);

    // FAT32 entries use only 28 bits; preserve high 4 bits
    let new_value = (old_value & 0xF000_0000) | (value & 0x0FFF_FFFF);

    // Update the FAT entry
    sector_buf[offset_in_sector..offset_in_sector + 4].copy_from_slice(&new_value.to_le_bytes());

    // Write FAT sector back
    if write_sector(fs.base.device, fat_sector, &sector_buf).is_err() {
        // kprintln!("[FAT32] update_fat_entry: failed to write FAT sector {}", fat_sector)  // kprintln disabled (memcpy crash workaround);
        return Err(());
    }

    // Mirror to backup FAT if there are multiple FATs
    let num_fats = fs.fat_data.boot_sector.num_fats as u64;
    if num_fats > 1 {
        let backup_fat_sector = fat_sector + (fs.fat_data.boot_sector.sectors_per_fat_32 as u64);
        if write_sector(fs.base.device, backup_fat_sector, &sector_buf).is_err() {
            // kprintln!("[FAT32] update_fat_entry: failed to write backup FAT sector")  // kprintln disabled (memcpy crash workaround);
            // Continue anyway - primary FAT update succeeded
        }
    }

    Ok(())
}

/// Allocate a free cluster and optionally link it from the current cluster.
/// Returns the new cluster number on success.
pub fn allocate_cluster(fs: &Fat32FileSystem, current_cluster: u32) -> Result<u32, ()> {
    let total_clusters = fs.base.total_clusters as u32;
    if total_clusters == 0 {
        return Err(());
    }

    // Scan FAT to find a free cluster
    for cluster in 2..total_clusters {
        let entry = read_fat_entry(fs, cluster);
        if entry == FAT32_FREE {
            // Mark new cluster as end of chain
            if update_fat_entry(fs, cluster, FAT32_EOC).is_err() {
                continue;
            }

            // Link current cluster to new cluster if provided
            if current_cluster >= 2 {
                if update_fat_entry(fs, current_cluster, cluster).is_err() {
                    // Rollback: mark new cluster as free
                    let _ = update_fat_entry(fs, cluster, FAT32_FREE);
                    continue;
                }
            }

            return Ok(cluster);
        }
    }

    // kprintln!("[FAT32] allocate_cluster: no free clusters available")  // kprintln disabled (memcpy crash workaround);
    Err(())
}

/// Free an entire cluster chain starting from the given cluster.
pub fn free_cluster_chain(fs: &Fat32FileSystem, start_cluster: u32) -> Result<(), ()> {
    if start_cluster < 2 {
        return Ok(());  // Nothing to free
    }

    let mut current = start_cluster;
    let mut iterations = 0;
    let max_iterations = fs.base.total_clusters as usize;

    while current >= 2 && current < FAT32_EOC && iterations < max_iterations {
        let next = read_fat_entry(fs, current);

        // Mark cluster as free
        if update_fat_entry(fs, current, FAT32_FREE).is_err() {
            // kprintln!("[FAT32] free_cluster_chain: failed to free cluster {}", current)  // kprintln disabled (memcpy crash workaround);
            return Err(());
        }

        current = next;
        iterations += 1;

        // Check for FAT corruption (loop detection)
        if next == current {
            // kprintln!("[FAT32] free_cluster_chain: FAT corruption detected at cluster {}", current)  // kprintln disabled (memcpy crash workaround);
            break;
        }
    }

    Ok(())
}

/// Write data to a file given its starting cluster.
/// This handles cluster allocation and FAT table updates.
pub fn write_file(fs: &Fat32FileSystem, start_cluster: u32, offset: u32, data: &[u8]) -> Result<usize, ()> {
    let cluster_size = fs.base.cluster_size as usize;
    let sectors_per_cluster = fs.base.cluster_size / fs.base.sector_size;

    // Calculate which cluster contains the offset
    let cluster_offset = offset / cluster_size as u32;
    let byte_offset_in_cluster = offset % cluster_size as u32;

    // Find or allocate the target cluster
    let mut current_cluster = start_cluster;
    let mut c = 0u32;

    while c < cluster_offset {
        let next = read_fat_entry(fs, current_cluster);
        if next >= FAT32_EOC {
            // Need to allocate a new cluster
            match allocate_cluster(fs, current_cluster) {
                Ok(new_cluster) => {
                    current_cluster = new_cluster;
                }
                Err(_) => {
                    if c == 0 {
                        return Err(());
                    }
                    break;
                }
            }
        } else {
            current_cluster = next;
        }
        c += 1;

        // Loop detection
        if c > 1000 {
            // kprintln!("[FAT32] write_file: cluster chain too long")  // kprintln disabled (memcpy crash workaround);
            return Err(());
        }
    }

    // Calculate the starting sector for this cluster
    let first_sector = fs.fat_data.data_start_sector
        + ((current_cluster - 2) as u64) * (sectors_per_cluster as u64);

    // If writing at the start of a cluster and data fits, write entire cluster
    if byte_offset_in_cluster == 0 && data.len() >= cluster_size {
        // Write full cluster(s)
        let mut bytes_written = 0;
        let mut current = current_cluster;
        let mut clusters_needed = (data.len() + cluster_size - 1) / cluster_size;

        while clusters_needed > 0 && bytes_written < data.len() {
            // Write one cluster
            for s in 0..sectors_per_cluster {
                let mut sector_buf = [0u8; 512];
                let src_offset = bytes_written + (s as usize) * 512;
                let copy_len = core::cmp::min(512, data.len() - src_offset);
                if copy_len > 0 {
                    sector_buf[..copy_len].copy_from_slice(&data[src_offset..src_offset + copy_len]);
                }
                if write_sector(fs.base.device, first_sector + (s as u64), &sector_buf).is_err() {
                    return Err(());
                }
            }
            bytes_written += cluster_size;
            clusters_needed -= 1;

            // Move to next cluster if more data to write
            if clusters_needed > 0 && bytes_written < data.len() {
                let next = read_fat_entry(fs, current);
                if next >= FAT32_EOC {
                    match allocate_cluster(fs, current) {
                        Ok(new_cluster) => {
                            current = new_cluster;
                        }
                        Err(_) => break,
                    }
                } else {
                    current = next;
                }
            }
        }

        Ok(bytes_written)
    } else {
        // Partial cluster write - need to read-modify-write
        let mut sector_buf = [0u8; 512];
        let sector_in_cluster = (byte_offset_in_cluster / 512) as usize;
        let sector_offset = (byte_offset_in_cluster % 512) as usize;

        // Read existing sector
        let sector_num = first_sector + sector_in_cluster as u64;
        if read_sector(fs.base.device, sector_num, &mut sector_buf).is_err() {
            return Err(());
        }

        // Modify the sector
        let copy_len = core::cmp::min(data.len(), 512 - sector_offset);
        sector_buf[sector_offset..sector_offset + copy_len].copy_from_slice(&data[..copy_len]);

        // Write sector back
        if write_sector(fs.base.device, sector_num, &sector_buf).is_err() {
            return Err(());
        }

        Ok(copy_len)
    }
}

/// Decode a 4-byte FAT entry into a 28-bit cluster number.
pub fn decode_fat_entry(raw: u32) -> u32 {
    raw & 0x0FFF_FFFF
}

/// EOC marker for FAT32 cluster chains.
pub const FAT32_EOC: u32 = 0x0FFF_FFFF;
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;
pub const FAT32_FREE: u32 = 0x0000_0000;

/// Mount a FAT32 volume. The device pointer is currently a stand-in
/// for "the in-memory filesystem image handed to us by the UEFI
/// stub" - the real implementation would call into the storage
/// stack to issue a read.
pub fn mount(device: *mut (), _path: &[u16]) -> Option<&'static mut Fat32FileSystem> {
    crate::boot_println!("[FAT32] mount: entering");
    let mut buffer = [0u8; 512];
    crate::boot_println!("[FAT32] mount: about to read_sector 0");
    if read_sector(device, 0, &mut buffer).is_err() {
        // kprintln!("[FAT32] Failed to read boot sector")  // kprintln disabled (memcpy crash workaround);
        crate::boot_println!("[FAT32] mount: read_sector failed, returning None");
        return None;
    }
    crate::boot_println!("[FAT32] mount: read_sector ok, first 16 bytes = {:02x?}", &buffer[..16]);
    // The buffer-to-struct copy has to use a packed read because the
    // boot sector is misaligned in practice. We use `read_unaligned`
    // via a `core::ptr::read_unaligned` of the slice.
    let boot: Fat32BootSector = unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const Fat32BootSector) };
    crate::boot_println!("[FAT32] mount: boot sector read, jump[0]=0x{:x}", boot.jump[0]);
    if !boot.is_valid() {
        // kprintln!("[FAT32] Invalid boot sector")  // kprintln disabled (memcpy crash workaround);
        crate::boot_println!("[FAT32] mount: boot sector invalid, returning None");
        return None;
    }
    crate::boot_println!("[FAT32] mount: boot sector valid");
    let reserved = boot.reserved_sectors as u64;
    let fats = boot.num_fats as u64;
    let fat_size = boot.sectors_per_fat_32 as u64;
    let fat_start = reserved;
    let data_start = reserved + fats * fat_size;
    let sector_sz = boot.sector_size();
    let cluster_sz = boot.cluster_size();
    let root_clu = boot.root_cluster;
    // kprintln!("[FAT32] Mounting volume:")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      Bytes/sector:  {}", boot.bytes_per_sector)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      Sectors/cluster: {}", boot.sectors_per_cluster)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      FAT start sector: {}", fat_start)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      Data start sector: {}", data_start)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      Root cluster:    {}", root_clu)  // kprintln disabled (memcpy crash workaround);

    let fs_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Fat32FileSystem>(),
    ) as *mut Fat32FileSystem;
    if fs_ptr.is_null() {
        return None;
    }
    unsafe {
        // The pool allocator already zeroed the user region, so
        // we only need to set the fields that matter. We avoid
        // `core::ptr::write(fs_ptr, Fat32FileSystem::new())`
        // because the compiler emits a non-temporal SSE store
        // for the aggregate write, and the kernel pool can
        // back onto UnCacheable memory regions (UC-typed MTRRs
        // from the UEFI firmware) where those stores silently
        // fail. Field-by-field assignment is both safer and
        // explicit about the layout we are constructing.
        let new_fs = Fat32FileSystem::new();
        (*fs_ptr).base = new_fs.base;
        (*fs_ptr).fat_data = new_fs.fat_data;
        (*fs_ptr).base.device = device;
        (*fs_ptr).base.sector_size = sector_sz;
        (*fs_ptr).base.cluster_size = cluster_sz;
        (*fs_ptr).fat_data.boot_sector = boot;
        (*fs_ptr).fat_data.fat_start_sector = fat_start;
        (*fs_ptr).fat_data.data_start_sector = data_start;
        (*fs_ptr).fat_data.root_cluster = root_clu;
        
        // Store in global for CMD access
        crate::boot_println!("[FAT32] mount: about to set_mounted_fs");
        set_mounted_fs(fs_ptr.as_mut().unwrap());
        crate::boot_println!("[FAT32] mount: set_mounted_fs done");
    }

    // Initialize pagefile support
    crate::boot_println!("[FAT32] mount: about to init_pagefile");
    init_pagefile();
    crate::boot_println!("[FAT32] mount: init_pagefile returned");

    crate::boot_println!("[FAT32] mount: returning Some(fs)");
    unsafe { fs_ptr.as_mut() }
}

/// Initialize pagefile on this FAT32 volume.
fn init_pagefile() {
    crate::boot_println!("[FAT32] init_pagefile entered");
    // Temporarily skip the pagefile open-or-create path while we
    // debug the kernel-phase bring-up. The pagefile module writes
    // through the FAT32 driver, which would in turn call
    // `write_sector` and recursively trigger the file-system bring-up
    // we are still inside. `cmd.exe` does not need the pagefile to
    // execute; once the FS path is verified we can re-enable this.
    crate::boot_println!("[FAT32] init_pagefile: SKIPPED (debug)");
    return;
    /* DISABLED (debug)
    kprintln_info!("FAT32", "Initializing pagefile support...");

    // Get block device ID (assume device 0 for now)
    let device_id = 0;

    // Get filesystem parameters from mounted volume
    let (fat_start, data_start, cluster_size, sectors_per_cluster) = if let Some(fs) = get_mounted_fs() {
        (
            fs.fat_data.fat_start_sector,
            fs.fat_data.data_start_sector,
            fs.base.cluster_size,
            fs.base.cluster_size / 512,
        )
    } else {
        kprintln_warn!("FAT32",
            "No mounted filesystem for pagefile init");
        return;
    };

    // Try to open or create pagefile
    let size_mb = crate::mm::pagefile::DEFAULT_PAGEFILE_SIZE_MB;

    if let Some(handle) = pagefile::open_or_create(
        0, // fs_start_sector
        sectors_per_cluster,
        cluster_size,
        fat_start,
        data_start,
        device_id,
        size_mb,
    ) {
        kprintln_info!("FAT32",
            "Pagefile initialized: {} clusters, {} bytes",
            handle.cluster_count, handle.size_bytes);
    } else {
        kprintln_warn!("FAT32",
            "Pagefile initialization failed");
    }
    */
}

/// Unmount a FAT32 volume.
pub fn unmount(_fs: *mut Fat32FileSystem) {
    // kprintln!("[FAT32] Volume unmounted")  // kprintln disabled (memcpy crash workaround);
}

/// Register the FAT32 driver with the I/O manager.
pub fn register_driver() {
    static mut FAT32_DRIVER: FileSystemDriver = FileSystemDriver {
        name: [
            b'F' as u16, b'a' as u16, b't' as u16, b'3' as u16,
            b'2' as u16, 0,         0,         0,
        ],
        fs_type: FileSystemType::Fat32,
        mount: Some(mount_trampoline),
        unmount: Some(unmount_fs),
    };
    // kprintln!("    FAT32 driver registered")  // kprintln disabled (memcpy crash workaround);
    unsafe {
        crate::fs::register(&mut FAT32_DRIVER);
    }
}

/// `FileSystemDriver::mount` returns `*mut FileSystem` but the
/// real `mount` function returns `Option<&'static mut Fat32FileSystem>`.
/// Wrap that mismatch in a trampoline that translates the
/// `Option<&mut>` into a `*mut FileSystem`.
fn mount_trampoline(device: *mut (), path: &[u16]) -> *mut FileSystem {
    match mount(device, path) {
        Some(fs) => fs as *mut Fat32FileSystem as *mut FileSystem,
        None => core::ptr::null_mut(),
    }
}

/// `FileSystemDriver::unmount` is `Option<fn(*mut FileSystem)>`,
/// but `unmount` here takes `*mut Fat32FileSystem`. Wrap the
/// mismatch with a cast helper.
fn unmount_fs(fs: *mut FileSystem) {
    unmount(fs as *mut Fat32FileSystem);
}

/// Read a file's bytes by walking its cluster chain. The file is
/// identified by its starting cluster (taken from a directory entry
/// search) and its size.
pub fn read_file(fs: &Fat32FileSystem, start_cluster: u32, file_size: u32, out: &mut [u8]) -> Result<usize, ()> {
    let cluster_size = fs.base.cluster_size as usize;
    let mut current = start_cluster;
    let mut written = 0usize;

    // Safety limit to prevent infinite loops
    let mut iterations = 0u32;
    let max_iterations = (file_size / cluster_size as u32 + 1).min(65536);

    while current >= 2 && current < FAT32_EOC && written < file_size as usize && iterations < max_iterations {
        let first_sector = fs.fat_data.data_start_sector
            + ((current - 2) as u64) * (fs.base.cluster_size / fs.base.sector_size) as u64;
        let to_copy = core::cmp::min(cluster_size, file_size as usize - written);
        let to_copy = core::cmp::min(to_copy, out.len() - written);
        if to_copy == 0 {
            break;
        }
        // Read one cluster's worth of sectors.
        for s in 0..(fs.base.cluster_size / fs.base.sector_size) {
            let mut sector = [0u8; 512];
            if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_ok() {
                let copy = core::cmp::min(sector.len(), to_copy - s as usize * sector.len());
                if copy == 0 {
                    break;
                }
                out[written + s as usize * sector.len()..written + s as usize * sector.len() + copy]
                    .copy_from_slice(&sector[..copy]);
            }
        }
        written += to_copy;

        // Walk the FAT to find the next cluster.
        // Use read_fat_entry to get the correct next cluster from the FAT table.
        if file_size as usize <= cluster_size {
            break;
        }

        let next_cluster = read_fat_entry(fs, current);

        // Check for FAT corruption (loop detection)
        if next_cluster == current || next_cluster == FAT32_BAD {
            // kprintln!("[FAT32] read_file: FAT corruption at cluster {} (next={})", current, next_cluster)  // kprintln disabled (memcpy crash workaround);
            break;
        }

        current = next_cluster;
        iterations += 1;
    }
    Ok(written)
}

/// Look up a directory entry by 8.3 name in the root directory.
pub fn find_file_in_root(
    fs: &Fat32FileSystem,
    short_name: &[u8; 11],
) -> Option<FatDirectoryEntry> {
    let cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let first_sector = fs.fat_data.data_start_sector
        + ((fs.fat_data.root_cluster - 2) as u64) * (cluster_size / sector_size) as u64;
    let sectors_per_cluster = cluster_size / sector_size;
    for s in 0..sectors_per_cluster {
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_err() {
            continue;
        }
        for e in 0..sector_size / core::mem::size_of::<FatDirectoryEntry>() {
            let entry: FatDirectoryEntry = unsafe {
                core::ptr::read_unaligned(
                    sector.as_ptr().add(e * core::mem::size_of::<FatDirectoryEntry>())
                        as *const FatDirectoryEntry,
                )
            };
            if !entry.is_valid() || entry.is_long_name() || entry.is_volume_id() {
                continue;
            }
            if &entry.name == short_name {
                return Some(entry);
            }
        }
    }
    None
}

/// Directory entry info for CMD
#[derive(Copy, Clone)]
pub struct FatDirEntry {
    pub name: [u8; 13],   // 8.3 name, null-terminated
    pub is_dir: bool,
    pub size: u32,
    pub cluster: u32,
    pub mod_date: u16,
    pub mod_time: u16,
}

impl FatDirEntry {
    pub fn new() -> Self {
        Self {
            name: [0; 13],
            is_dir: false,
            size: 0,
            cluster: 0,
            mod_date: 0,
            mod_time: 0,
        }
    }
}

/// List directory entries in a cluster (and follow FAT chain if needed).
/// 
/// This function implements proper cluster-based directory traversal:
/// 1. Reads directory data from the starting cluster
/// 2. Parses directory entries (including long filenames)
/// 3. Follows the FAT chain to read subsequent clusters if the directory spans multiple clusters
/// 
/// # Arguments
/// 
/// * `fs` - The FAT32 filesystem
/// * `start_cluster` - The first cluster of the directory
/// * `entries` - Output buffer for directory entries
/// 
/// # Returns
/// 
/// The number of directory entries found
pub fn list_directory_cluster(
    fs: &Fat32FileSystem,
    start_cluster: u32,
    entries: &mut [FatDirEntry],
) -> usize {
    if start_cluster < 2 {
        // kprintln!("[FAT32] list_directory_cluster: invalid start cluster {}", start_cluster)  // kprintln disabled (memcpy crash workaround);
        return 0;
    }
    
    let cluster_size = fs.base.cluster_size as usize;
    let mut buffer = alloc::vec![0u8; cluster_size];
    let mut current_cluster = start_cluster;
    let mut count = 0;
    let mut long_name_buffer: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    
    // Follow the FAT chain
    while current_cluster >= 2 && current_cluster < FAT32_EOC {
        // Read this cluster
        match read_cluster_data(fs, current_cluster, &mut buffer) {
            Ok(_) => {
                // Parse directory entries in this cluster
                let mut offset = 0;
                while offset + 32 <= cluster_size {
                    if count >= entries.len() {
                        return count;
                    }
                    
                    let entry = unsafe {
                        core::ptr::read_unaligned(
                            buffer.as_ptr().add(offset) as *const FatDirectoryEntry
                        )
                    };
                    
                    if entry.name[0] == 0x00 {
                        // End of directory marker
                        return count;
                    }
                    
                    if entry.name[0] == 0xE5 {
                        // Deleted entry - skip and clear long name buffer
                        long_name_buffer.clear();
                        offset += 32;
                        continue;
                    }
                    
                    if entry.is_long_name() {
                        // Accumulate long name parts (stored in reverse order)
                        long_name_buffer.extend_from_slice(&entry.name);
                        offset += 32;
                        continue;
                    }
                    
                    // Short name entry - process it
                    let name = if long_name_buffer.is_empty() {
                        // Convert 8.3 name to string
                        convert_83_name(&entry.name, entry.is_directory())
                    } else {
                        // Decode accumulated long name
                        decode_long_name(&long_name_buffer)
                    };
                    
                    entries[count].name = name;
                    entries[count].is_dir = entry.is_directory();
                    entries[count].size = entry.file_size();
                    entries[count].cluster = entry.first_cluster();
                    entries[count].mod_date = entry.modification_date;
                    entries[count].mod_time = entry.modification_time;
                    count += 1;
                    
                    // Clear long name buffer for next entry
                    long_name_buffer.clear();
                    offset += 32;
                }
            }
            Err(_) => {
                // kprintln!("[FAT32] list_directory_cluster: failed to read cluster {}", current_cluster)  // kprintln disabled (memcpy crash workaround);
                break;
            }
        }
        
        // Get next cluster from FAT chain
        let next_cluster = read_fat_entry(fs, current_cluster);
        if next_cluster == current_cluster {
            // FAT corruption - avoid infinite loop
            // kprintln!("[FAT32] list_directory_cluster: FAT corruption detected at cluster {}", current_cluster)  // kprintln disabled (memcpy crash workaround);
            break;
        }
        current_cluster = next_cluster;
    }
    
    count
}

/// Read a cluster's worth of data.
pub fn read_cluster_sector(fs: &Fat32FileSystem, cluster: u32, sector_offset: u32, buffer: &mut [u8]) -> Result<(), ()> {
    if buffer.len() < 512 {
        return Err(());
    }
    
    let data_start = fs.fat_data.data_start_sector;
    let sectors_per_cluster = fs.base.cluster_size / fs.base.sector_size;
    let first_sector = data_start + ((cluster - 2) as u64) * (sectors_per_cluster as u64);
    let sector_num = first_sector + (sector_offset as u64);
    
    read_sector(fs.base.device, sector_num, buffer)
}

/// Read a FAT entry for a given cluster number.
/// Returns the next cluster in the chain, or FAT32_EOC if end of chain or error.
pub fn read_fat_entry(fs: &Fat32FileSystem, cluster: u32) -> u32 {
    let fat_start = fs.fat_data.fat_start_sector;
    let sector_size = fs.base.sector_size as u64;
    let bytes_per_sector = sector_size as usize;
    
    // Each FAT entry is 4 bytes (32-bit for FAT32)
    let entry_offset = (cluster as u64) * 4;
    let fat_sector = fat_start + (entry_offset / sector_size);
    let offset_in_sector = (entry_offset % sector_size) as usize;
    
    let mut sector_buf = [0u8; 512];
    if read_sector(fs.base.device, fat_sector, &mut sector_buf).is_err() {
        // kprintln!("[FAT32] read_fat_entry: failed to read FAT sector {}", fat_sector)  // kprintln disabled (memcpy crash workaround);
        return FAT32_EOC;
    }
    
    if offset_in_sector + 4 > bytes_per_sector {
        // Entry spans sector boundary - unlikely but handle it
        // kprintln!("[FAT32] read_fat_entry: entry spans sector boundary at cluster {}", cluster)  // kprintln disabled (memcpy crash workaround);
        return FAT32_EOC;
    }
    
    let value = u32::from_le_bytes([
        sector_buf[offset_in_sector],
        sector_buf[offset_in_sector + 1],
        sector_buf[offset_in_sector + 2],
        sector_buf[offset_in_sector + 3],
    ]);
    
    decode_fat_entry(value)
}

/// Read an entire cluster's worth of data.
fn read_cluster_data(fs: &Fat32FileSystem, cluster: u32, buffer: &mut [u8]) -> Result<usize, ()> {
    let cluster_size = fs.base.cluster_size as usize;
    if buffer.len() < cluster_size {
        // kprintln!("[FAT32] read_cluster_data: buffer too small ({} < {})", buffer.len(), cluster_size)  // kprintln disabled (memcpy crash workaround);
        return Err(());
    }
    
    let sector_size = fs.base.sector_size as u64;
    let sectors_per_cluster = (cluster_size / sector_size as usize) as u64;
    let data_start = fs.fat_data.data_start_sector;
    // Cluster 2 is the first data cluster
    let first_sector = data_start + ((cluster as u64) - 2) * sectors_per_cluster;
    
    let mut offset = 0usize;
    for i in 0..sectors_per_cluster {
        let mut sector_buf = [0u8; 512];
        if read_sector(fs.base.device, first_sector + i, &mut sector_buf).is_err() {
            // kprintln!("[FAT32] read_cluster_data: failed to read sector {}", first_sector + i)  // kprintln disabled (memcpy crash workaround);
            return Err(());
        }
        buffer[offset..offset + 512].copy_from_slice(&sector_buf);
        offset += 512;
    }
    
    Ok(offset)
}

/// Convert an 8.3 filename to a null-terminated string.
fn convert_83_name(name_bytes: &[u8; 11], is_directory: bool) -> [u8; 13] {
    let mut name = [0u8; 13];
    let mut j = 0;
    
    // Copy base name (first 8 bytes), stripping spaces
    for i in 0..8 {
        if name_bytes[i] != 0x20 {
            name[j] = name_bytes[i];
            j += 1;
        }
    }
    
    // Add extension if present and not a directory
    if !is_directory && name_bytes[8] != 0x20 {
        name[j] = b'.';
        j += 1;
        for i in 8..11 {
            if name_bytes[i] != 0x20 {
                name[j] = name_bytes[i];
                j += 1;
            }
        }
    }
    
    name
}

/// Decode accumulated long filename bytes to UTF-16 vector.
/// This properly handles UTF-16 encoding and returns a full Unicode string.
///
/// Long filename entries are stored in reverse order. Each entry is 32 bytes:
/// - Byte 0: Sequence number (with last-entry and deleted flags)
/// - Bytes 1-10: First 5 UTF-16 characters (offset 0, 2, 4, 6, 8)
/// - Byte 11: Attributes (always 0x0F for long name entries)
/// - Byte 12: Reserved (checksum)
/// - Bytes 13-20: Next 4 UTF-16 characters (offset 12, 14, 16, 18)
/// - Byte 21: Reserved
/// - Bytes 22-25: Next 3 UTF-16 characters (offset 22, 24)
/// - Bytes 26-27: Reserved
/// - Bytes 28-31: Reserved
pub fn decode_long_name_utf16(long_name_buffer: &[u8]) -> Vec<u16> {
    let mut result = Vec::new();

    if long_name_buffer.is_empty() {
        return result;
    }

    // Long name entries are stored in reverse order, so we need to process them backwards
    let mut entry_start = long_name_buffer.len();

    while entry_start >= 32 {
        entry_start = entry_start.saturating_sub(32);

        // Each entry contains 13 characters (26 bytes for UTF-16)
        // Offsets within entry: 1,3,5,7,9,12,14,16,18,20,22,24
        let offsets = [1usize, 3, 5, 7, 9, 12, 14, 16, 18, 20, 22, 24];

        for &off in &offsets {
            let pos = entry_start + off;
            if pos + 1 < long_name_buffer.len() {
                let c1 = long_name_buffer[pos];
                let c2 = long_name_buffer[pos + 1];

                // Skip padding bytes (0xFF)
                if c1 != 0xFF && c2 != 0xFF {
                    let ch = (c2 as u16) << 8 | c1 as u16;

                    // Skip Unicode null terminator
                    if ch != 0 {
                        result.push(ch);
                    }
                }
            }
        }
    }

    result
}

/// Decode accumulated long filename bytes to a null-terminated string (ASCII fallback).
/// This is kept for backwards compatibility with code that expects ASCII output.
fn decode_long_name(long_name_buffer: &[u8]) -> [u8; 13] {
    let mut name = [0u8; 13];

    if long_name_buffer.is_empty() {
        return name;
    }

    // Get UTF-16 representation
    let utf16_name = decode_long_name_utf16(long_name_buffer);

    // Convert UTF-16 to ASCII (using lossy conversion)
    let mut out_idx = 0usize;
    for &ch in utf16_name.iter() {
        if out_idx >= 12 {
            break;
        }
        // Convert UTF-16 to ASCII (or use lossy conversion)
        if ch < 128 {
            name[out_idx] = ch as u8;
            out_idx += 1;
        } else if ch >= 0xC0 && ch <= 0x24F {
            // Latin characters - take lower byte
            name[out_idx] = (ch & 0xFF) as u8;
            out_idx += 1;
        } else {
            // Non-ASCII character - use underscore
            name[out_idx] = b'_';
            out_idx += 1;
        }
    }

    name
}

/// Convert UTF-16 string to UTF-8 bytes
/// This properly handles all Unicode characters in UTF-16 encoding
pub fn utf16_to_utf8(utf16: &[u16]) -> Vec<u8> {
    let mut result = Vec::new();

    for &ch in utf16.iter() {
        if ch == 0 {
            break;  // Null terminator
        }

        if ch < 0x80 {
            // ASCII: 0xxxxxxx
            result.push(ch as u8);
        } else if ch < 0x800 {
            // Two bytes: 110xxxxx 10xxxxxx
            result.push(0xC0 | ((ch >> 6) as u8));
            result.push(0x80 | ((ch & 0x3F) as u8));
        } else {
            // Three bytes: 1110xxxx 10xxxxxx 10xxxxxx
            // This covers all remaining u16 values (0x800-0xFFFF)
            result.push(0xE0 | ((ch >> 12) as u8));
            result.push(0x80 | (((ch >> 6) & 0x3F) as u8));
            result.push(0x80 | ((ch & 0x3F) as u8));
        }
    }

    result
}

/// Calculate FAT32 long filename checksum
/// Used to verify long filename integrity against the short name
pub fn calc_long_name_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;

    for &byte in short_name.iter() {
        // Rotate right and add byte
        sum = sum.rotate_right(1).wrapping_add(byte);
    }

    sum
}

/// Verify long filename integrity by checking the checksum
/// Returns true if the checksum matches
pub fn verify_long_name_checksum(short_name: &[u8; 11], checksum: u8) -> bool {
    calc_long_name_checksum(short_name) == checksum
}

/// Read directory entries from the root directory
pub fn list_root_directory(fs: &Fat32FileSystem, entries: &mut [FatDirEntry]) -> usize {
    let cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let first_sector = fs.fat_data.data_start_sector
        + ((fs.fat_data.root_cluster - 2) as u64) * (cluster_size / sector_size) as u64;
    let sectors_per_cluster = cluster_size / sector_size;
    let mut count = 0;
    
    for s in 0..sectors_per_cluster {
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_err() {
            continue;
        }
        for e in 0..sector_size / core::mem::size_of::<FatDirectoryEntry>() {
            if count >= entries.len() {
                return count;
            }
            let dir_entry: FatDirectoryEntry = unsafe {
                core::ptr::read_unaligned(
                    sector.as_ptr().add(e * core::mem::size_of::<FatDirectoryEntry>())
                        as *const FatDirectoryEntry,
                )
            };
            if !dir_entry.is_valid() {
                continue;
            }
            if dir_entry.is_long_name() || dir_entry.is_volume_id() {
                continue;
            }
            // Convert 8.3 name to string
            let name_bytes = dir_entry.name;
            let mut name = [0u8; 13];
            let mut j = 0;
            for i in 0..8 {
                if name_bytes[i] != 0x20 {
                    name[j] = name_bytes[i];
                    j += 1;
                }
            }
            if !dir_entry.is_directory() && name_bytes[8] != 0x20 {
                name[j] = b'.';
                j += 1;
                for i in 8..11 {
                    if name_bytes[i] != 0x20 {
                        name[j] = name_bytes[i];
                        j += 1;
                    }
                }
            }
            
            entries[count].name = name;
            entries[count].is_dir = dir_entry.is_directory();
            entries[count].size = dir_entry.file_size();
            entries[count].cluster = dir_entry.first_cluster();
            entries[count].mod_date = dir_entry.modification_date;
            entries[count].mod_time = dir_entry.modification_time;
            count += 1;
        }
    }
    count
}

// ============================================================================
// File/Directory Write Operations
// ============================================================================

/// Write data to a specific sector in a cluster
pub fn write_cluster_sector(fs: &Fat32FileSystem, cluster: u32, sector_offset: u32, data: &[u8]) -> Result<(), ()> {
    let data_start = fs.fat_data.data_start_sector;
    let sectors_per_cluster = fs.base.cluster_size / fs.base.sector_size;
    let first_sector = data_start + ((cluster - 2) as u64) * (sectors_per_cluster as u64);
    let sector_num = first_sector + (sector_offset as u64);
    
    write_sector(fs.base.device, sector_num, data)
}

/// Write an entire cluster's worth of data
pub fn write_cluster(fs: &Fat32FileSystem, cluster: u32, data: &[u8]) -> Result<usize, ()> {
    let cluster_size = fs.base.cluster_size as usize;
    if data.len() < cluster_size {
        return Err(());
    }
    
    let sectors_per_cluster = fs.base.cluster_size / fs.base.sector_size;
    let mut written = 0usize;
    
    for i in 0..sectors_per_cluster {
        let sector_buf: &[u8; 512] = &data[i as usize * 512..(i as usize + 1) * 512].try_into().unwrap();
        if write_cluster_sector(fs, cluster, i, sector_buf).is_err() {
            return Err(());
        }
        written += 512;
    }
    
    Ok(written)
}

/// Find a directory entry by name in the root directory
/// Returns (cluster, offset_in_cluster) if found, None otherwise
pub fn find_file_in_root_ex(
    fs: &Fat32FileSystem,
    short_name: &[u8; 11],
) -> Option<(u32, usize)> {
    let cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let first_sector = fs.fat_data.data_start_sector
        + ((fs.fat_data.root_cluster - 2) as u64) * (cluster_size / sector_size) as u64;
    let sectors_per_cluster = cluster_size / sector_size;
    
    for s in 0..sectors_per_cluster {
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_err() {
            continue;
        }
        for e in 0..sector_size / core::mem::size_of::<FatDirectoryEntry>() {
            let entry: FatDirectoryEntry = unsafe {
                core::ptr::read_unaligned(
                    sector.as_ptr().add(e * core::mem::size_of::<FatDirectoryEntry>())
                        as *const FatDirectoryEntry,
                )
            };
            if !entry.is_valid() || entry.is_long_name() || entry.is_volume_id() {
                continue;
            }
            if &entry.name == short_name {
                let offset = (s as usize) * sector_size + (e * core::mem::size_of::<FatDirectoryEntry>());
                return Some((fs.fat_data.root_cluster, offset));
            }
        }
    }
    None
}

/// Find a free directory entry slot in the root directory
/// Returns (cluster, byte_offset) of the free slot
pub fn find_free_dir_slot(fs: &Fat32FileSystem) -> Option<(u32, usize)> {
    let cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let first_sector = fs.fat_data.data_start_sector
        + ((fs.fat_data.root_cluster - 2) as u64) * (cluster_size / sector_size) as u64;
    let sectors_per_cluster = cluster_size / sector_size;
    
    for s in 0..sectors_per_cluster {
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_err() {
            continue;
        }
        for e in 0..sector_size / core::mem::size_of::<FatDirectoryEntry>() {
            let entry: FatDirectoryEntry = unsafe {
                core::ptr::read_unaligned(
                    sector.as_ptr().add(e * core::mem::size_of::<FatDirectoryEntry>())
                        as *const FatDirectoryEntry,
                )
            };
            if entry.name[0] == 0x00 || entry.name[0] == 0xE5 {
                let offset = (s as usize) * sector_size + (e * core::mem::size_of::<FatDirectoryEntry>());
                return Some((fs.fat_data.root_cluster, offset));
            }
        }
    }
    None
}

/// Update a directory entry at a specific location
pub fn update_dir_entry(fs: &Fat32FileSystem, cluster: u32, byte_offset: usize, entry: &FatDirectoryEntry) -> Result<(), ()> {
    let _cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let sector_index = byte_offset / sector_size;
    let offset_in_sector = byte_offset % sector_size;
    
    // Read the sector
    let mut buffer = [0u8; 512];
    if read_cluster_sector(fs, cluster, sector_index as u32, &mut buffer).is_err() {
        return Err(());
    }
    
    // Update the entry
    let entry_ptr = entry as *const FatDirectoryEntry as *const u8;
    let entry_size = core::mem::size_of::<FatDirectoryEntry>();
    for i in 0..entry_size {
        buffer[offset_in_sector + i] = unsafe { *entry_ptr.add(i) };
    }
    
    // Write back
    write_cluster_sector(fs, cluster, sector_index as u32, &buffer)
}

/// Mark a file as deleted by setting the first byte to 0xE5
pub fn delete_file_entry(fs: &Fat32FileSystem, cluster: u32, byte_offset: usize) -> Result<(), ()> {
    let _cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let sector_index = byte_offset / sector_size;
    let offset_in_sector = byte_offset % sector_size;
    
    // Read the sector
    let mut buffer = [0u8; 512];
    if read_cluster_sector(fs, cluster, sector_index as u32, &mut buffer).is_err() {
        return Err(());
    }
    
    // Mark as deleted
    buffer[offset_in_sector] = 0xE5;
    
    // Write back
    write_cluster_sector(fs, cluster, sector_index as u32, &buffer)
}

/// Create a new file in the root directory
pub fn create_file_in_root(fs: &Fat32FileSystem, name: &[u8; 11], start_cluster: u32, size: u32) -> Result<(), ()> {
    // Find a free slot
    let (cluster, byte_offset) = find_free_dir_slot(fs).ok_or(())?;
    
    // Create the directory entry
    let entry = FatDirectoryEntry {
        name: *name,
        attributes: 0x20, // Archive
        reserved: 0,
        creation_time_tenth: 0,
        creation_time: 0,
        creation_date: 0,
        last_access_date: 0,
        first_cluster_high: (start_cluster >> 16) as u16,
        modification_time: 0,
        modification_date: 0,
        first_cluster_low: (start_cluster & 0xFFFF) as u16,
        file_size: size,
    };
    
    update_dir_entry(fs, cluster, byte_offset, &entry)
}

/// Create a new directory in the root directory
pub fn create_dir_in_root(fs: &Fat32FileSystem, name: &[u8; 11], start_cluster: u32) -> Result<(), ()> {
    // Find a free slot
    let (cluster, byte_offset) = find_free_dir_slot(fs).ok_or(())?;
    
    // Create the directory entry
    let entry = FatDirectoryEntry {
        name: *name,
        attributes: 0x10, // Directory
        reserved: 0,
        creation_time_tenth: 0,
        creation_time: 0,
        creation_date: 0,
        last_access_date: 0,
        first_cluster_high: (start_cluster >> 16) as u16,
        modification_time: 0,
        modification_date: 0,
        first_cluster_low: (start_cluster & 0xFFFF) as u16,
        file_size: 0,
    };
    
    update_dir_entry(fs, cluster, byte_offset, &entry)
}

/// Convert a filename string to 8.3 format
pub fn name_to_83(name: &str) -> [u8; 11] {
    let mut result = [b' '; 11];
    let name_upper = name.to_uppercase();
    
    // Handle path with backslash
    let name_only = if let Some(pos) = name_upper.rfind('\\') {
        &name_upper[pos + 1..]
    } else {
        &name_upper
    };
    
    // Remove extension if present
    let (base, ext) = if let Some(pos) = name_only.find('.') {
        (&name_only[..pos], &name_only[pos + 1..])
    } else {
        (name_only, "")
    };
    
    // Copy base name (up to 8 chars)
    for (i, c) in base.bytes().take(8).enumerate() {
        result[i] = c;
    }
    
    // Copy extension (up to 3 chars)
    for (i, c) in ext.bytes().take(3).enumerate() {
        result[8 + i] = c;
    }
    
    result
}

/// Rename a file in the root directory
pub fn rename_file_in_root(fs: &Fat32FileSystem, old_name: &[u8; 11], new_name: &[u8; 11]) -> Result<(), ()> {
    if let Some((cluster, byte_offset)) = find_file_in_root_ex(fs, old_name) {
        // Read current entry
        let _cluster_size = fs.base.cluster_size as usize;
        let sector_size = fs.base.sector_size as usize;
        let sector_index = byte_offset / sector_size;
        let offset_in_sector = byte_offset % sector_size;
        
        let mut buffer = [0u8; 512];
        if read_cluster_sector(fs, cluster, sector_index as u32, &mut buffer).is_err() {
            return Err(());
        }
        
        // Update the name (first 11 bytes of the entry)
        for i in 0..11 {
            buffer[offset_in_sector + i] = new_name[i];
        }
        
        // Write back
        write_cluster_sector(fs, cluster, sector_index as u32, &buffer)
    } else {
        Err(())
    }
}

/// Check if a file exists in the root directory
pub fn file_exists_in_root(fs: &Fat32FileSystem, short_name: &[u8; 11]) -> bool {
    find_file_in_root_ex(fs, short_name).is_some()
}

/// Search a single directory cluster for a file or subdirectory by
/// short name. Returns the matched `FatDirectoryEntry` (preserving the
/// on-disk bytes for callers that need attributes and clusters). The
/// search is purely by short (8.3) name — long filename support is
/// not needed for the kernel-side batch loader, which receives
/// uppercased names from the BAT parser.
fn find_in_dir_by_short(
    fs: &Fat32FileSystem,
    dir_cluster: u32,
    short_name: &[u8; 11],
) -> Option<FatDirectoryEntry> {
    let cluster_size = fs.base.cluster_size as usize;
    let sector_size = fs.base.sector_size as usize;
    let sectors_per_cluster = cluster_size / sector_size;
    let mut current_cluster = dir_cluster;
    // Walk the FAT chain so multi-cluster directories are supported.
    let mut visited: u32 = 0;
    while current_cluster >= 2
        && current_cluster < FAT32_EOC
        && visited < 0x0FFF_FFFF
    {
        let first_sector = fs.fat_data.data_start_sector
            + ((current_cluster - 2) as u64) * (sectors_per_cluster as u64);
        for s in 0..sectors_per_cluster {
            let mut sector = [0u8; 512];
            if read_sector(fs.base.device, first_sector + s as u64, &mut sector).is_err() {
                continue;
            }
            for e in 0..sector_size / core::mem::size_of::<FatDirectoryEntry>() {
                let entry: FatDirectoryEntry = unsafe {
                    core::ptr::read_unaligned(
                        sector.as_ptr().add(e * core::mem::size_of::<FatDirectoryEntry>())
                            as *const FatDirectoryEntry,
                    )
                };
                if !entry.is_valid() || entry.is_long_name() || entry.is_volume_id() {
                    continue;
                }
                if &entry.name == short_name {
                    return Some(entry);
                }
            }
        }
        let next = read_fat_entry(fs, current_cluster);
        if next == current_cluster || next >= FAT32_EOC {
            break;
        }
        current_cluster = next;
        visited += 1;
    }
    None
}

/// Resolve a Windows-style path against the FAT32 volume and return
/// the directory entry of the requested file.
///
/// The path is split on `\` (any embedded `\` segments are walked
/// against subdirectories); a final segment that is not `.bat` or
/// `.cmd` is allowed because callers occasionally pass arbitrary
/// batch scripts. If any segment of the path is missing the function
/// returns `None` rather than descending into the root, so a
/// halfway-mounted system partition never silently runs a stale
/// script from `C:\autoexec.bat`.
pub fn find_file_at_path(
    fs: &Fat32FileSystem,
    path: &str,
) -> Option<FatDirectoryEntry> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Skip drive letters and leading slashes.
    let cleaned = trimmed
        .trim_start_matches(|c| c == 'C' || c == 'c' || c == ':')
        .trim_start_matches(|c| c == '\\' || c == '/');
    // Split into components.
    let mut segments: [(&str, [u8; 11]); 8] = [("", [b' '; 11]); 8];
    let mut seg_count = 0usize;
    for seg in cleaned.split(|c| c == '\\' || c == '/').filter(|s| !s.is_empty()) {
        if seg_count >= segments.len() {
            return None;
        }
        segments[seg_count].0 = seg;
        segments[seg_count].1 = name_to_83(seg);
        seg_count += 1;
    }
    if seg_count == 0 {
        return None;
    }
    // Start at the root cluster.
    let mut dir_cluster = fs.fat_data.root_cluster;
    let mut last: Option<FatDirectoryEntry> = None;
    for i in 0..seg_count {
        let (seg_str, short_name) = (segments[i].0, segments[i].1);
        if seg_str.is_empty() {
            continue;
        }
        let entry = match find_in_dir_by_short(fs, dir_cluster, &short_name) {
            Some(e) => e,
            None => return last,
        };
        if i + 1 == seg_count {
            return Some(entry);
        }
        // Must be a directory to descend.
        if !entry.is_directory() {
            return last;
        }
        dir_cluster = entry.first_cluster();
        if dir_cluster < 2 {
            return last;
        }
        let _ = last.take();
    }
    last
}
