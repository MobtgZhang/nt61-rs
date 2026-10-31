use crate::libs::ntdll::{status::STATUS_UNSUCCESSFUL, types::NTSTATUS};
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::bitmap;
use super::dir::{calculate_entry_size, EXT2_FT_DIR, EXT2_FT_REG_FILE};
use super::group::{read_group_descriptor, Ext2GroupDesc};
use super::inode::{read_inode, write_inode, Ext2Inode};
use super::superblock::Ext2SuperBlock;

struct DirectoryLocation {
    logical_block: u32,
    offset: usize,
}

const SUPERBLOCK_SECTOR: u64 = 2;

fn read_dir_buffer(device: *mut (), sb: &Ext2SuperBlock, inode: &Ext2Inode) -> Option<Vec<u8>> {
    unsafe {
        if !inode.is_dir() {
            return None;
        }

        let block_size = sb.get_block_size() as usize;
        let block_count = (inode.get_size(sb) as usize).div_ceil(block_size);
        let mut buffer = vec![0u8; block_count * block_size];
        for block in 0..block_count {
            let lba = super::inode::logical_to_lba(device, sb, inode, block as u32)?;
            if super::superblock::read_sector(
                device,
                lba,
                &mut buffer[block * block_size..(block + 1) * block_size],
            )
            .is_err()
            {
                return None;
            }
        }

        Some(buffer)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn write_dir_buffer(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode: &Ext2Inode,
    buffer: &[u8],
) -> Result<(), NTSTATUS> {
    let block_size = sb.get_block_size() as usize;
    if !buffer.len().is_multiple_of(block_size) {
        return Err(STATUS_UNSUCCESSFUL);
    }
    for block in 0..buffer.len() / block_size {
        let lba = unsafe { super::inode::logical_to_lba(device, sb, inode, block as u32) }
            .ok_or(STATUS_UNSUCCESSFUL)?;
        super::superblock::write_sector(
            device,
            lba,
            &buffer[block * block_size..(block + 1) * block_size],
        )?;
    }

    Ok(())
}

fn entry_size(sb: &Ext2SuperBlock, name_len: usize) -> u16 {
    calculate_entry_size(name_len, (sb.incompatible_features & 0x02) != 0)
}

fn find_insert_location(
    buffer: &[u8],
    block_size: usize,
    required: u16,
) -> Option<DirectoryLocation> {
    let mut logical_block = 0usize;

    while logical_block * block_size < buffer.len() {
        let mut offset = 0usize;
        let block_start = logical_block * block_size;
        while offset + 8 <= block_size {
            let base = block_start + offset;
            let inode = u32::from_le_bytes(buffer[base..base + 4].try_into().ok()?);
            let rec_len = u16::from_le_bytes(buffer[base + 4..base + 6].try_into().ok()?);
            if rec_len < 8 || offset + rec_len as usize > block_size {
                return None;
            }

            if inode == 0 && rec_len >= required {
                return Some(DirectoryLocation {
                    logical_block: logical_block as u32,
                    offset,
                });
            }

            let name_len = u16::from_le_bytes(buffer[base + 6..base + 8].try_into().ok()?) as usize;
            let minimal = calculate_entry_size(name_len, (buffer[base + 8] & 0xFC) == 0x40);
            if offset + rec_len as usize == block_size && rec_len >= minimal + required {
                return Some(DirectoryLocation {
                    logical_block: logical_block as u32,
                    offset,
                });
            }

            offset += rec_len as usize;
        }

        logical_block += 1;
    }

    None
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn write_entry(
    buffer: &mut [u8],
    block_size: usize,
    location: &DirectoryLocation,
    inode_num: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), NTSTATUS> {
    let base = location.logical_block as usize * block_size + location.offset;
    let rec_len = u16::from_le_bytes(
        buffer[base + 4..base + 6]
            .try_into()
            .map_err(|_| STATUS_UNSUCCESSFUL)?,
    ) as usize;
    let has_filetype = (buffer[base + 8] & 0xFC) == 0x40;
    let minimal = calculate_entry_size(name.len(), has_filetype) as usize;
    if rec_len < minimal {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let next_rec_len = (rec_len - minimal) as u16;
    buffer[base..base + minimal].fill(0);
    buffer[base..base + 4].copy_from_slice(&inode_num.to_le_bytes());
    buffer[base + 4..base + 6].copy_from_slice(&(minimal as u16).to_le_bytes());
    buffer[base + 6..base + 8].copy_from_slice(&(name.len() as u16).to_le_bytes());
    if has_filetype {
        buffer[base + 8] = file_type;
    }
    if !has_filetype {
        buffer[base + 8] = 0;
    }
    buffer[base + 8..base + 8 + name.len()].copy_from_slice(name);

    let next_base = base + minimal;
    if next_rec_len > 0 {
        buffer[next_base..next_base + 4].fill(0);
        buffer[next_base + 4..next_base + 6].copy_from_slice(&next_rec_len.to_le_bytes());
        buffer[next_base + 6..next_base + 8].copy_from_slice(&0u16.to_le_bytes());
    }

    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn allocate_inode(
    device: *mut (),
    sb: &Ext2SuperBlock,
    is_directory: bool,
) -> Result<u32, NTSTATUS> {
    if sb.get_group_count() == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let group = 0;
    let mut inode_bitmap =
        unsafe { bitmap::read_inode_bitmap(device, sb, group) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let max_inodes = sb.inodes_per_group as usize;
    let first_index_in_group = if group == 0 {
        sb.first_ino.saturating_sub(1) as usize
    } else {
        0
    };
    let index = (first_index_in_group..max_inodes)
        .find(|candidate| !bitmap::test_bit(&inode_bitmap, *candidate))
        .ok_or(STATUS_UNSUCCESSFUL)?;
    bitmap::set_bit(&mut inode_bitmap, index);

    let group_desc =
        unsafe { read_group_descriptor(device, sb, group) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let lba = group_desc.inode_bitmap_lba(sb);
    if super::superblock::write_sector(device, lba, &inode_bitmap).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let inode_num = group * sb.inodes_per_group + index as u32 + 1;
    write_group_descriptor(device, sb, group, |desc| {
        desc.free_inodes_count = desc.free_inodes_count.saturating_sub(1);
        if is_directory {
            desc.used_dirs_count = desc.used_dirs_count.saturating_add(1);
        }
    })?;

    Ok(inode_num)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn write_superblock(device: *mut (), sb: &Ext2SuperBlock) -> Result<(), NTSTATUS> {
    let mut buffer = vec![0u8; 1024];
    unsafe {
        core::ptr::copy_nonoverlapping(
            sb as *const Ext2SuperBlock as *const u8,
            buffer.as_mut_ptr(),
            core::mem::size_of::<Ext2SuperBlock>(),
        );
    }
    super::superblock::write_sector(device, SUPERBLOCK_SECTOR, &buffer)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn write_group_descriptor(
    device: *mut (),
    sb: &Ext2SuperBlock,
    group: u32,
    update: impl FnOnce(&mut Ext2GroupDesc),
) -> Result<(), NTSTATUS> {
    unsafe {
        let original = read_group_descriptor(device, sb, group).ok_or(STATUS_UNSUCCESSFUL)?;
        let mut updated = original;
        update(&mut updated);

        let block_size = sb.get_block_size() as usize;
        let desc_size = if sb.is_dynamic_rev() && sb.inode_size >= 255 {
            super::group::EXT2_BGDESC_SIZE_NEW
        } else {
            super::group::EXT2_BGDESC_SIZE_OLD
        };
        let gdt_start = super::group::get_gdt_start_block(sb);
        let desc_offset = group as usize * desc_size;
        let gdt_block = gdt_start + (desc_offset / block_size) as u64;
        let offset_in_block = desc_offset % block_size;
        let mut buffer = vec![0u8; block_size];
        let sector = gdt_block * (block_size / 512) as u64;
        if super::superblock::read_sector(device, sector, &mut buffer).is_err() {
            return Err(STATUS_UNSUCCESSFUL);
        }

        core::ptr::copy_nonoverlapping(
            &updated as *const Ext2GroupDesc as *const u8,
            buffer.as_mut_ptr().add(offset_in_block),
            core::mem::size_of::<Ext2GroupDesc>(),
        );

        super::superblock::write_sector(device, sector, &buffer)
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn new_inode(sb: &Ext2SuperBlock, is_directory: bool, block_num: u32) -> Ext2Inode {
    let mut inode: Ext2Inode = unsafe { core::mem::zeroed() };
    inode.mode = if is_directory { 0o40755 } else { 0o100644 };
    inode.links_count = if is_directory { 2 } else { 1 };
    inode.block[0] = block_num;
    if is_directory {
        inode.size = sb.get_block_size();
    }

    inode
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn initialize_dir_block(
    device: *mut (),
    sb: &Ext2SuperBlock,
    dir_inode: u32,
    parent_inode: u32,
    block_num: u32,
) -> Result<(), NTSTATUS> {
    let block_size = sb.get_block_size() as usize;
    let mut block = vec![0u8; block_size];
    write_entry_at(
        &mut block,
        block_size,
        0,
        dir_inode,
        b".",
        EXT2_FT_DIR,
        block_size as u16,
    )?;
    write_entry_at(
        &mut block,
        block_size,
        12,
        parent_inode,
        b"..",
        EXT2_FT_DIR,
        (block_size - 12) as u16,
    )?;
    let lba = block_num as u64 * (block_size / 512) as u64;
    super::superblock::write_sector(device, lba, &block)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn write_entry_at(
    buffer: &mut [u8],
    _block_size: usize,
    offset: usize,
    inode_num: u32,
    name: &[u8],
    file_type: u8,
    rec_len: u16,
) -> Result<(), NTSTATUS> {
    buffer[offset..offset + 4].copy_from_slice(&inode_num.to_le_bytes());
    buffer[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
    buffer[offset + 6..offset + 8].copy_from_slice(&(name.len() as u16).to_le_bytes());
    buffer[offset + 8] = file_type;
    buffer[offset + 8 + 1..offset + 8 + 1 + name.len()].copy_from_slice(name);
    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn create_file(
    device: *mut (),
    sb: &Ext2SuperBlock,
    parent_inode: u32,
    name: &[u8],
) -> Result<u32, NTSTATUS> {
    if name.is_empty() || name.len() > super::dir::EXT2_NAME_LEN {
        return Err(STATUS_UNSUCCESSFUL);
    }
    if unsafe { super::dir::find_entry_in_dir(device, sb, parent_inode, name) }.is_some() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let inode_num = allocate_inode(device, sb, false)?;
    let inode = new_inode(sb, false, 0);
    unsafe { write_inode(device, sb, inode_num, &inode) }?;
    add_dir_entry(device, sb, parent_inode, inode_num, name, EXT2_FT_REG_FILE)?;

    Ok(inode_num)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn mkdir(
    device: *mut (),
    sb: &Ext2SuperBlock,
    parent_inode: u32,
    name: &[u8],
) -> Result<u32, NTSTATUS> {
    if name.is_empty() || name.len() > super::dir::EXT2_NAME_LEN {
        return Err(STATUS_UNSUCCESSFUL);
    }
    if unsafe { super::dir::find_entry_in_dir(device, sb, parent_inode, name) }.is_some() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let block_num = bitmap::allocate_block(device, sb).ok_or(STATUS_UNSUCCESSFUL)?;
    let inode_num = allocate_inode(device, sb, true)?;
    initialize_dir_block(device, sb, inode_num, parent_inode, block_num)?;
    let inode = new_inode(sb, true, block_num);
    unsafe { write_inode(device, sb, inode_num, &inode) }?;
    add_dir_entry(device, sb, parent_inode, inode_num, name, EXT2_FT_DIR)?;

    Ok(inode_num)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn add_dir_entry(
    device: *mut (),
    sb: &Ext2SuperBlock,
    parent_inode: u32,
    inode_num: u32,
    name: &[u8],
    file_type: u8,
) -> Result<(), NTSTATUS> {
    let parent = unsafe { read_inode(device, sb, parent_inode) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let mut buffer = read_dir_buffer(device, sb, &parent).ok_or(STATUS_UNSUCCESSFUL)?;
    let block_size = sb.get_block_size() as usize;
    let required = entry_size(sb, name.len());
    let location = match find_insert_location(&buffer, block_size, required) {
        Some(location) => location,
        None => return Err(STATUS_UNSUCCESSFUL),
    };

    write_entry(
        &mut buffer,
        block_size,
        &location,
        inode_num,
        name,
        file_type,
    )?;
    write_dir_buffer(device, sb, &parent, &buffer)?;

    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn unlink(
    device: *mut (),
    sb: &Ext2SuperBlock,
    parent_inode: u32,
    name: &[u8],
) -> Result<(), NTSTATUS> {
    let entry = unsafe { super::dir::find_entry_in_dir(device, sb, parent_inode, name) }
        .ok_or(STATUS_UNSUCCESSFUL)?;
    let inode = unsafe { read_inode(device, sb, entry.inode) }.ok_or(STATUS_UNSUCCESSFUL)?;
    if inode.is_dir() && inode.links_count > 2 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    remove_dir_entry(device, sb, parent_inode, name)?;
    free_inode_blocks(device, sb, &inode)?;
    free_inode_number(device, sb, entry.inode, inode.is_dir())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn remove_dir_entry(
    device: *mut (),
    sb: &Ext2SuperBlock,
    parent_inode: u32,
    name: &[u8],
) -> Result<(), NTSTATUS> {
    let parent = unsafe { read_inode(device, sb, parent_inode) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let mut buffer = read_dir_buffer(device, sb, &parent).ok_or(STATUS_UNSUCCESSFUL)?;
    let mut previous: Option<usize> = None;
    let mut offset = 0usize;

    while offset + 8 <= buffer.len() {
        let inode_num = u32::from_le_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .map_err(|_| STATUS_UNSUCCESSFUL)?,
        );
        let rec_len = u16::from_le_bytes(
            buffer[offset + 4..offset + 6]
                .try_into()
                .map_err(|_| STATUS_UNSUCCESSFUL)?,
        ) as usize;
        if rec_len < 8 || offset + rec_len > buffer.len() {
            return Err(STATUS_UNSUCCESSFUL);
        }
        if inode_num != 0 {
            let name_len = u16::from_le_bytes(
                buffer[offset + 6..offset + 8]
                    .try_into()
                    .map_err(|_| STATUS_UNSUCCESSFUL)?,
            ) as usize;
            if &buffer[offset + 8..offset + 8 + name_len] == name {
                if let Some(prev) = previous {
                    let prev_rec = u16::from_le_bytes(
                        buffer[prev + 4..prev + 6]
                            .try_into()
                            .map_err(|_| STATUS_UNSUCCESSFUL)?,
                    );
                    let merged = prev_rec.saturating_add(rec_len as u16);
                    buffer[prev + 4..prev + 6].copy_from_slice(&merged.to_le_bytes());
                } else {
                    buffer[offset..offset + 4].fill(0);
                }
                return write_dir_buffer(device, sb, &parent, &buffer);
            }
            previous = Some(offset);
        }
        offset += rec_len;
    }

    Err(STATUS_UNSUCCESSFUL)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn free_inode_blocks(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode: &Ext2Inode,
) -> Result<(), NTSTATUS> {
    if inode.has_extents() {
        return Ok(());
    }

    let block_size = sb.get_block_size() as u64;
    let size = inode.get_size(sb);
    let logical_count = size.div_ceil(block_size) as u32;

    for logical in 0..logical_count {
        if let Some(lba) = unsafe { super::inode::logical_to_lba(device, sb, inode, logical) } {
            let block = lba / (block_size / 512);
            bitmap::free_block(device, sb, block)?;
        }
    }

    for block in inode.block.iter() {
        if *block != 0 && block_size > 0 {
            bitmap::free_block(device, sb, *block as u64)?;
        }
    }

    Ok(())
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn free_inode_number(
    device: *mut (),
    sb: &Ext2SuperBlock,
    inode_num: u32,
    is_directory: bool,
) -> Result<(), NTSTATUS> {
    if inode_num == 0 || inode_num > sb.inodes_count {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let group = super::group::inode_to_group(sb, inode_num);
    let mut inode_bitmap =
        unsafe { bitmap::read_inode_bitmap(device, sb, group) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let index = ((inode_num - 1) % sb.inodes_per_group) as usize;
    if !bitmap::test_bit(&inode_bitmap, index) {
        return Ok(());
    }
    bitmap::clear_bit(&mut inode_bitmap, index);
    let group_desc =
        unsafe { read_group_descriptor(device, sb, group) }.ok_or(STATUS_UNSUCCESSFUL)?;
    let lba = group_desc.inode_bitmap_lba(sb);
    super::superblock::write_sector(device, lba, &inode_bitmap)?;
    write_group_descriptor(device, sb, group, |desc| {
        desc.free_inodes_count = desc.free_inodes_count.saturating_add(1);
        if is_directory {
            desc.used_dirs_count = desc.used_dirs_count.saturating_sub(1);
        }
    })
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
pub unsafe fn rename(
    device: *mut (),
    sb: &Ext2SuperBlock,
    old_parent: u32,
    old_name: &[u8],
    new_parent: u32,
    new_name: &[u8],
) -> Result<(), NTSTATUS> {
    let entry = unsafe { super::dir::find_entry_in_dir(device, sb, old_parent, old_name) }
        .ok_or(STATUS_UNSUCCESSFUL)?;
    if unsafe { super::dir::find_entry_in_dir(device, sb, new_parent, new_name) }.is_some() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    add_dir_entry(
        device,
        sb,
        new_parent,
        entry.inode,
        new_name,
        entry.file_type,
    )?;
    remove_dir_entry(device, sb, old_parent, old_name)
}
