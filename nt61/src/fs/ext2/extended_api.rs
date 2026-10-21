//! EXT2/EXT3/EXT4 Extended Filesystem API
//!
//! Provides support for Linux EXT filesystems on NT6.1-RS kernel.
//! This allows the kernel to boot from EXT2/3/4 partitions.
//!
//! EXT2: Basic extended filesystem
//! EXT3: EXT2 + journaling
//! EXT4: EXT3 + extents, larger file support
//!
//! Clean-room implementation based on Linux kernel documentation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const EXT_SUPER_MAGIC: u16 = 0xEF53;

pub fn mount(_disk_index: usize, starting_lba: u64) -> Result<(), ()> {
    super::mount_first(core::ptr::null_mut(), starting_lba)
        .map(|_| ())
        .ok_or(())
}

pub fn unmount() {
    if let Some(fs) = super::get_mounted_fs() {
        super::unmount(fs as *const _ as *mut super::Ext2FileSystem);
    }
    super::clear_mounted_fs();
}

pub fn is_mounted() -> bool {
    super::is_mounted()
}

pub fn read_file(_path: &str) -> Result<Vec<u8>, ()> {
    let fs = super::get_mounted_fs().ok_or(())?;
    super::read_whole_file(fs, _path).map_err(|_| ())
}

pub fn list_directory(_path: &str) -> Result<Vec<ExtEntry>, ()> {
    let fs = super::get_mounted_fs().ok_or(())?;
    let path = super::win_path_to_ext2(_path);
    let inode = super::resolve_path(fs, path.as_bytes()).ok_or(())?;
    let entries = super::list_directory(fs, inode).ok_or(())?;
    Ok(entries
        .into_iter()
        .map(|entry| ExtEntry {
            name: entry.name.clone(),
            is_directory: entry.is_dir(),
            inode: entry.inode,
            size: 0,
        })
        .collect())
}

pub struct ExtEntry {
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    pub inode: u32,
}

pub fn get_volume_label() -> Result<String, ()> {
    let fs = super::get_mounted_fs().ok_or(())?;
    let label_end = fs
        .superblock
        .volume_name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(fs.superblock.volume_name.len());
    Ok(String::from_utf8_lossy(&fs.superblock.volume_name[..label_end]).into_owned())
}

pub struct ExtStats {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub block_size: u32,
}

pub fn get_stats() -> Option<ExtStats> {
    let fs = super::get_mounted_fs()?;
    Some(ExtStats {
        total_blocks: fs.superblock.get_total_blocks(),
        free_blocks: u64::from(fs.superblock.free_blocks),
        total_inodes: u64::from(fs.superblock.inodes_count),
        free_inodes: u64::from(fs.superblock.free_inodes),
        block_size: fs.block_size,
    })
}
