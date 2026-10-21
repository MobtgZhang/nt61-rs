#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;

const SYSTEM_TYPE_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

#[derive(Debug, Clone, Copy)]
struct Fat32Geometry {
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    fat_count: u32,
    fat_sectors: u32,
    root_cluster: u32,
}

pub trait SectorReader {
    fn read_sectors(&self, start_lba: u64, sector_count: u32) -> Option<Vec<u8>>;
}

pub fn find_fat32_system_partition(reader: &dyn SectorReader) -> Option<u64> {
    let gpt_header = reader.read_sectors(1, 1)?;
    if gpt_header.get(0..8)? != b"EFI PART" {
        return None;
    }
    let entry_lba = u64::from_le_bytes(gpt_header.get(72..80)?.try_into().ok()?);
    let entry_count = u32::from_le_bytes(gpt_header.get(80..84)?.try_into().ok()?);
    let entry_size = u32::from_le_bytes(gpt_header.get(84..88)?.try_into().ok()?) as usize;
    if entry_size < 128 || entry_count == 0 || entry_count > 1024 {
        return None;
    }

    let entries_per_sector = SECTOR_SIZE / entry_size;
    let entry_sectors = (entry_count as usize + entries_per_sector - 1) / entries_per_sector;
    if entries_per_sector == 0 || entry_sectors == 0 {
        return None;
    }
    let entries = reader.read_sectors(entry_lba, entry_sectors as u32)?;
    for index in 0..entry_count as usize {
        let entry = entries.get(index * entry_size..(index + 1) * entry_size)?;
        if entry.get(0..16)? != SYSTEM_TYPE_GUID {
            continue;
        }
        let first_lba = u64::from_le_bytes(entry.get(32..40)?.try_into().ok()?);
        let last_lba = u64::from_le_bytes(entry.get(40..48)?.try_into().ok()?);
        if last_lba <= first_lba {
            continue;
        }
        let boot_sector = reader.read_sectors(first_lba, 1)?;
        if boot_sector.len() < SECTOR_SIZE || &boot_sector[82..90] != b"FAT32   " {
            continue;
        }
        return Some(first_lba);
    }
    None
}

fn parse_geometry(boot_sector: &[u8]) -> Option<Fat32Geometry> {
    if boot_sector.len() < 512
        || boot_sector[510] != 0x55
        || boot_sector[511] != 0xAA
        || &boot_sector[82..90] != b"FAT32   "
    {
        return None;
    }
    let bytes_per_sector = u16::from_le_bytes(boot_sector[11..13].try_into().ok()?);
    if bytes_per_sector != SECTOR_SIZE as u16 {
        return None;
    }
    let sectors_per_cluster = boot_sector[13] as u32;
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
        return None;
    }
    let reserved_sectors = u16::from_le_bytes(boot_sector[14..16].try_into().ok()?) as u32;
    let fat_count = boot_sector[16] as u32;
    let fat_sectors = u32::from_le_bytes(boot_sector[36..40].try_into().ok()?);
    let root_cluster = u32::from_le_bytes(boot_sector[44..48].try_into().ok()?);
    if fat_count == 0 || fat_sectors == 0 || reserved_sectors == 0 || root_cluster < 2 {
        return None;
    }
    Some(Fat32Geometry {
        sectors_per_cluster,
        reserved_sectors,
        fat_count,
        fat_sectors,
        root_cluster,
    })
}

pub fn read_fat32_file(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    path: &str,
) -> Option<Vec<u8>> {
    let boot_sector = reader.read_sectors(partition_start_lba, 1)?;
    let geometry = parse_geometry(&boot_sector)?;
    let components = normalize_path(path)?;
    let current = resolve_directory_entry(reader, partition_start_lba, &geometry, &components)?;
    read_file_data(reader, partition_start_lba, &geometry, &current)
}

fn normalize_path(path: &str) -> Option<Vec<String>> {
    let mut components = Vec::new();
    for raw in path.split('\\') {
        for part in raw.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                components.pop();
                continue;
            }
            if !part.is_ascii() {
                return None;
            }
            let mut bytes = part.as_bytes().to_vec();
            bytes.make_ascii_uppercase();
            components.push(String::from_utf8(bytes).ok()?);
        }
    }
    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

fn data_start(geometry: &Fat32Geometry) -> u32 {
    geometry.reserved_sectors + geometry.fat_count * geometry.fat_sectors
}

fn cluster_lba(partition_start_lba: u64, geometry: &Fat32Geometry, cluster: u32) -> u64 {
    partition_start_lba
        + (data_start(geometry) + (cluster - 2) * geometry.sectors_per_cluster) as u64
}

fn read_cluster(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    geometry: &Fat32Geometry,
    cluster: u32,
) -> Option<Vec<u8>> {
    if cluster < 2 {
        return None;
    }
    reader.read_sectors(
        cluster_lba(partition_start_lba, geometry, cluster),
        geometry.sectors_per_cluster,
    )
}

fn next_cluster(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    geometry: &Fat32Geometry,
    cluster: u32,
) -> Option<u32> {
    let fat_lba = partition_start_lba + geometry.reserved_sectors as u64;
    let fat_offset = cluster as usize * 4;
    let sector = fat_offset / SECTOR_SIZE;
    let byte = fat_offset % SECTOR_SIZE;
    let fat = reader.read_sectors(fat_lba + sector as u64, 1)?;
    Some(u32::from_le_bytes(
        fat.get(byte..byte + 4)?.try_into().ok()?,
    ))
}

#[derive(Clone)]
struct DirectoryEntry {
    name: String,
    cluster: u32,
    size: u32,
    is_directory: bool,
}

fn read_directory_chain(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    geometry: &Fat32Geometry,
    first_cluster: u32,
) -> Option<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    let mut lfn_parts: Vec<(u8, Vec<u16>)> = Vec::new();
    let mut cluster = first_cluster;
    for _ in 0..0x10000 {
        let sector_data = read_cluster(reader, partition_start_lba, geometry, cluster)?;
        for entry_bytes in sector_data.chunks_exact(32) {
            if entry_bytes[0] == 0 {
                return Some(entries);
            }
            if entry_bytes[0] == 0xE5 || entry_bytes[11] == 0x0F {
                if entry_bytes[11] == 0x0F {
                    if let Some(lfn) = parse_lfn(entry_bytes.try_into().ok()?) {
                        lfn_parts.push(lfn);
                    }
                }
                continue;
            }
            let raw_name = &entry_bytes[0..11];
            let attributes = entry_bytes[11];
            let high = u16::from_le_bytes(entry_bytes[20..22].try_into().ok()?);
            let low = u16::from_le_bytes(entry_bytes[26..28].try_into().ok()?);
            let cluster = (u32::from(high) << 16) | u32::from(low);
            let size = u32::from_le_bytes(entry_bytes[28..32].try_into().ok()?);
            let mut name = if lfn_parts.is_empty() {
                decode_sfn(raw_name)?
            } else {
                decode_lfn(&mut lfn_parts)?
            };
            while name.ends_with(' ') || name.ends_with('.') {
                name.pop();
            }
            entries.push(DirectoryEntry {
                name: name.to_ascii_uppercase(),
                cluster,
                size,
                is_directory: attributes & 0x10 != 0,
            });
        }
        cluster = next_cluster(reader, partition_start_lba, geometry, cluster)?;
        if cluster >= 0x0FFF_FFF8 || cluster < 2 {
            break;
        }
    }
    Some(entries)
}

fn parse_lfn(entry: &[u8; 32]) -> Option<(u8, Vec<u16>)> {
    let sequence = entry[0] & 0x1F;
    if sequence == 0 || sequence > 20 {
        return None;
    }
    let mut chars = Vec::with_capacity(13);
    for offset in (1..10usize).step_by(2) {
        let value = u16::from_le_bytes([entry[offset], entry[offset + 1]]);
        chars.push(value);
    }
    for offset in (14..26usize).step_by(2) {
        let value = u16::from_le_bytes([entry[offset], entry[offset + 1]]);
        chars.push(value);
    }
    for offset in (28..30usize).step_by(2) {
        let value = u16::from_le_bytes([entry[offset], entry[offset + 1]]);
        chars.push(value);
    }
    Some((sequence, chars))
}

fn decode_lfn(parts: &mut Vec<(u8, Vec<u16>)>) -> Option<String> {
    parts.sort_by_key(|(sequence, _)| *sequence);
    let mut chars = Vec::new();
    for (_, part) in parts.drain(..) {
        chars.extend(part);
    }
    let mut name = String::new();
    for value in chars {
        if value == 0 || value == 0xFFFF {
            break;
        }
        name.push(char::from_u32(u32::from(value))?);
    }
    Some(name)
}

fn decode_sfn(raw: &[u8]) -> Option<String> {
    if raw.len() != 11 {
        return None;
    }
    let mut name = String::with_capacity(12);
    for &byte in &raw[..8] {
        if byte == 0x20 {
            break;
        }
        name.push(char::from_u32(u32::from(byte))?);
    }
    let mut extension = String::new();
    for &byte in &raw[8..] {
        if byte == 0x20 {
            break;
        }
        extension.push(char::from_u32(u32::from(byte))?);
    }
    if !extension.is_empty() {
        name.push('.');
        name.push_str(&extension);
    }
    Some(name)
}

fn resolve_directory_entry(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    geometry: &Fat32Geometry,
    components: &[String],
) -> Option<DirectoryEntry> {
    let mut current_entry: Option<DirectoryEntry> = None;
    for component in components {
        let entries = match &current_entry {
            Some(entry) if entry.is_directory => {
                read_directory_chain(reader, partition_start_lba, geometry, entry.cluster)?
            }
            Some(_) => return None,
            None => {
                read_directory_chain(reader, partition_start_lba, geometry, geometry.root_cluster)?
            }
        };
        let index = entries.iter().position(|entry| entry.name == *component)?;
        current_entry = Some(entries[index].clone());
    }
    current_entry
}

fn read_file_data(
    reader: &dyn SectorReader,
    partition_start_lba: u64,
    geometry: &Fat32Geometry,
    entry: &DirectoryEntry,
) -> Option<Vec<u8>> {
    if entry.is_directory {
        return None;
    }
    let cluster_size = geometry.sectors_per_cluster as usize * SECTOR_SIZE;
    let mut output = Vec::with_capacity(entry.size as usize);
    let mut remaining = entry.size as usize;
    let mut cluster = entry.cluster;
    for _ in 0..0x10000 {
        let data = read_cluster(reader, partition_start_lba, geometry, cluster)?;
        let take = remaining.min(cluster_size);
        output.extend_from_slice(data.get(..take)?);
        remaining -= take;
        if remaining == 0 || take < cluster_size {
            break;
        }
        cluster = next_cluster(reader, partition_start_lba, geometry, cluster)?;
        if cluster >= 0x0FFF_FFF8 || cluster < 2 {
            break;
        }
    }
    if remaining != 0 {
        return None;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    struct FileSectorReader {
        file: File,
    }

    impl SectorReader for FileSectorReader {
        fn read_sectors(&self, start_lba: u64, sector_count: u32) -> Option<Vec<u8>> {
            let mut file = self.file.try_clone().ok()?;
            file.seek(SeekFrom::Start(start_lba * SECTOR_SIZE as u64))
                .ok()?;
            let mut buffer = alloc::vec![0u8; sector_count as usize * SECTOR_SIZE];
            file.read_exact(&mut buffer).ok()?;
            Some(buffer)
        }
    }

    #[test]
    fn reads_fat32_system_file_from_built_image() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../build/x86_64/fat32/images/disk.img"
        );
        let file = File::open(path).expect("built FAT32 image");
        let reader = FileSectorReader { file };
        let partition_lba = find_fat32_system_partition(&reader).expect("FAT32 system partition");
        let data = read_fat32_file(&reader, partition_lba, "\\Windows\\System32\\winload.efi")
            .unwrap_or_else(|| panic!("winload.efi missing"));
        assert!(!data.is_empty());
    }
}
