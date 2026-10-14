//! Extended FAT32 API used by the command layer (`VOL`, `LABEL`, `CHKDSK`).
//!
//! Only the entry points that the real driver in `fs/fat32/mod.rs` does not
//! provide live here. The previous copy of this file re-declared the whole
//! driver API as stubs that returned fabricated values (`100000` free
//! clusters, a constant volume label), which shadowed the real
//! implementations whenever this module was re-exported.
//!
//! On-disk layout follows Microsoft's "FAT: General Overview of On-Disk
//! Format" (FSInfo structure signatures `0x41615252`, `0x61417272`,
//! `0xAA550000`; cluster 0 holds the media descriptor, cluster 1 is reserved
//! and must read as an end-of-chain value).

extern crate alloc;

use super::{
    list_root_directory, read_fat_entry, read_sector, write_sector, Fat32FileSystem, Fat32FsInfo,
    FatDirEntry,
};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

pub const FAT32_EOC: u32 = 0x0FFFFFF8;

/// Boot sector sanity checks performed by `CHKDSK`.
pub fn verify_boot_sector(fs: &Fat32FileSystem) -> bool {
    let bs = &fs.fat_data.boot_sector;
    if bs.jump[0] != 0xEB && bs.jump[0] != 0xE9 {
        return false;
    }
    if bs.boot_signature != 0x28 && bs.boot_signature != 0x29 {
        return false;
    }
    if bs.bytes_per_sector == 0 || bs.sectors_per_cluster == 0 || bs.num_fats == 0 {
        return false;
    }
    if bs.sectors_per_fat_32 == 0 && bs.sectors_per_fat_16 == 0 {
        return false;
    }
    // FAT16 uses root_entries; FAT32 must have a root cluster >= 2.
    if bs.root_cluster < 2 {
        return false;
    }
    true
}

/// Validate the FAT header entries and, when a mirror exists, that both
/// copies agree on the first two entries.
pub fn verify_fat_tables(fs: &Fat32FileSystem) -> bool {
    let bs = &fs.fat_data.boot_sector;
    if bs.num_fats == 0 {
        return false;
    }
    let media = (bs.media_descriptor as u32) | 0xFFFFF800;
    if read_fat_entry(fs, 0) != media {
        return false;
    }
    let reserved = read_fat_entry(fs, 1);
    if !(FAT32_EOC..=0x0FFFFFFF).contains(&reserved) {
        return false;
    }
    if bs.num_fats > 1 {
        let mirror = fs.fat_data.fat_start_sector + bs.sectors_per_fat_32 as u64;
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, mirror, &mut sector).is_err() {
            return false;
        }
        let entry0 = u32::from_le_bytes([sector[0], sector[1], sector[2], sector[3]]);
        let entry1 = u32::from_le_bytes([sector[4], sector[5], sector[6], sector[7]]);
        if entry0 != media || entry1 != reserved {
            return false;
        }
    }
    true
}

/// Walk the root directory and report whether every entry parses.
pub fn verify_directory_entries(fs: &Fat32FileSystem) -> bool {
    let mut entries: Vec<FatDirEntry> = alloc::vec![FatDirEntry::new(); 64];
    let count = list_root_directory(fs, &mut entries);
    count > 0
}

/// Free cluster count.
///
/// Prefers the FSInfo free-cluster counter (authoritative when its
/// signatures are intact), then the driver-maintained counter, and finally
/// falls back to a full FAT walk.
pub fn count_free_clusters(fs: &Fat32FileSystem) -> u32 {
    let bs = &fs.fat_data.boot_sector;
    if bs.fs_info_sector != 0 {
        let mut sector = [0u8; 512];
        if read_sector(fs.base.device, bs.fs_info_sector as u64, &mut sector).is_ok() {
            // FSInfo on-disk layout (Microsoft FAT spec, as implemented by
            // FreeBSD/NetBSD sys/fs/msdosfs/bpb.h and Linux
            // include/uapi/linux/msdos_fs.h):
            //   0   lead signature   0x41615252
            //   484 structure signature 0x61417272
            //   488 free cluster count
            //   492 most recently allocated cluster
            //   508 trail signature  0xAA550000
            let lead = u32::from_le_bytes([sector[0], sector[1], sector[2], sector[3]]);
            let struct_sig =
                u32::from_le_bytes([sector[484], sector[485], sector[486], sector[487]]);
            let trail = u32::from_le_bytes([sector[508], sector[509], sector[510], sector[511]]);
            if lead == Fat32FsInfo::LEAD_SIG
                && struct_sig == Fat32FsInfo::STRUCT_SIG
                && trail == Fat32FsInfo::TRAIL_SIG
            {
                let free = u32::from_le_bytes([sector[488], sector[489], sector[490], sector[491]]);
                if free != 0 && free <= fs.base.total_clusters as u32 {
                    return free;
                }
            }
        }
    }
    if fs.base.free_clusters != 0 {
        return fs.base.free_clusters as u32;
    }
    let total = fs.base.total_clusters as u32;
    if total < 2 {
        return 0;
    }
    let mut free = 0u32;
    for cluster in 2..total {
        if read_fat_entry(fs, cluster) == 0 {
            free += 1;
        }
    }
    free
}

/// Volume label from the boot sector (11 space-padded bytes).
pub fn get_volume_label(fs: &Fat32FileSystem) -> Result<String, ()> {
    let raw = &fs.fat_data.boot_sector.volume_label;
    let trimmed: String = raw
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect::<String>()
        .trim_end()
        .to_string();
    if trimmed.is_empty() {
        return Err(());
    }
    Ok(trimmed)
}

/// Update the boot sector volume label. Requires a writable volume.
pub fn set_volume_label(fs: &mut Fat32FileSystem, label: &str) -> Result<(), ()> {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 11 {
        return Err(());
    }
    let mut name = [b' '; 11];
    for (i, &b) in bytes.iter().enumerate() {
        name[i] = b.to_ascii_uppercase();
    }
    fs.fat_data.boot_sector.volume_label = name;
    let mut sector = [0u8; 512];
    if read_sector(fs.base.device, 0, &mut sector).is_err() {
        return Err(());
    }
    sector[71..82].copy_from_slice(&name);
    write_sector(fs.base.device, 0, &sector)
}
