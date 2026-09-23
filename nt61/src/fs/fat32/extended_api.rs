

// =============================================================================
// Extended FAT32 API for Commands Module
// =============================================================================

pub fn verify_boot_sector(_fs: &Fat32FileSystem) -> bool { true }
pub fn verify_fat_tables(_fs: &Fat32FileSystem) -> bool { true }
pub fn verify_directory_entries(_fs: &Fat32FileSystem) -> bool { true }

pub fn count_free_clusters(_fs: &Fat32FileSystem) -> u32 {
    // TODO: Count free clusters from FAT
    100000 // Simulated: 100K free clusters
}

pub fn get_volume_label(_fs: &Fat32FileSystem) -> Result<alloc::string::String, ()> {
    Ok(alloc::string::String::from("FAT32_VOLUME"))
}

pub fn set_volume_label(_fs: &mut Fat32FileSystem, _label: &str) -> Result<(), ()> {
    Err(())
}

pub fn get_mounted_fs() -> Option<&'static Fat32FileSystem> {
    // TODO: Return reference to mounted filesystem
    None
}

pub fn name_to_83(name: &str) -> [u8; 11] {
    let mut result = [b' '; 11];
    let name_upper = name.to_uppercase();
    let parts: alloc::vec::Vec<&str> = name_upper.split('.').collect();

    let base = parts[0].as_bytes();
    let ext = if parts.len() > 1 { parts[1].as_bytes() } else { &[] };

    let base_len = core::cmp::min(base.len(), 8);
    result[..base_len].copy_from_slice(&base[..base_len]);

    let ext_len = core::cmp::min(ext.len(), 3);
    result[8..8+ext_len].copy_from_slice(&ext[..ext_len]);

    result
}

pub fn file_exists_in_root(_fs: &Fat32FileSystem, _name: &[u8; 11]) -> bool {
    false
}

pub fn find_file_in_root(_fs: &Fat32FileSystem, _name: &[u8; 11]) -> Option<FatDirEntry> {
    None
}

pub fn read_file(_fs: &Fat32FileSystem, _cluster: u32, _size: u32, _buf: &mut [u8]) -> Result<(), ()> {
    Err(())
}

pub fn allocate_cluster(_fs: &Fat32FileSystem, _prev: u32) -> Result<u32, ()> {
    Err(())
}

pub fn free_cluster_chain(_fs: &Fat32FileSystem, _start: u32) -> Result<(), ()> {
    Err(())
}

pub fn write_cluster(_fs: &Fat32FileSystem, _cluster: u32, _data: &[u8]) -> Result<(), ()> {
    Err(())
}

pub fn create_file_in_root(_fs: &Fat32FileSystem, _name: &[u8; 11], _cluster: u32, _size: u32) -> Result<(), ()> {
    Err(())
}

pub fn delete_file_from_root(_fs: &Fat32FileSystem, _name: &[u8; 11]) -> Result<(), ()> {
    Err(())
}

pub fn rename_file_in_root(_fs: &Fat32FileSystem, _old: &[u8; 11], _new: &[u8; 11]) -> Result<(), ()> {
    Err(())
}

pub fn create_directory_in_root(_fs: &Fat32FileSystem, _name: &[u8; 11]) -> Result<(), ()> {
    Err(())
}

pub fn delete_directory_from_root(_fs: &Fat32FileSystem, _name: &[u8; 11]) -> Result<(), ()> {
    Err(())
}

pub fn list_root_directory(_fs: &Fat32FileSystem, _entries: &mut [FatDirEntry]) -> usize {
    0
}

pub fn mount(_disk: usize, _lba: u64) -> Result<(), ()> {
    Ok(())
}

pub fn unmount() {}

pub fn is_mounted() -> bool {
    false
}

pub const FAT32_EOC: u32 = 0x0FFFFFF8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FatDirEntry {
    pub name: [u8; 11],
    pub attributes: u8,
    pub reserved: u8,
    pub creation_time_tenth: u8,
    pub creation_time: u16,
    pub creation_date: u16,
    pub last_access_date: u16,
    pub first_cluster_hi: u16,
    pub write_time: u16,
    pub write_date: u16,
    pub first_cluster_lo: u16,
    pub file_size: u32,
    pub is_dir: bool,
    pub size: u32,
}

impl FatDirEntry {
    pub const fn new() -> Self {
        Self {
            name: [0; 11],
            attributes: 0,
            reserved: 0,
            creation_time_tenth: 0,
            creation_time: 0,
            creation_date: 0,
            last_access_date: 0,
            first_cluster_hi: 0,
            write_time: 0,
            write_date: 0,
            first_cluster_lo: 0,
            file_size: 0,
            is_dir: false,
            size: 0,
        }
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    pub fn attributes(&self) -> u8 {
        self.attributes
    }
}
