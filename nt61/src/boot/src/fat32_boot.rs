use nt61_bootfs::{find_fat32_system_partition, read_fat32_file, SectorReader};
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::proto::media::block::BlockIO;

struct BlockIoReader {
    block_io: *const BlockIO,
    media_id: u32,
}

impl SectorReader for BlockIoReader {
    fn read_sectors(&self, start_lba: u64, sector_count: u32) -> Option<alloc::vec::Vec<u8>> {
        let mut buffer = alloc::vec![0u8; sector_count as usize * 512];
        let block_io = unsafe { &*self.block_io };
        block_io
            .read_blocks(self.media_id, start_lba, &mut buffer)
            .ok()?;
        Some(buffer)
    }
}

pub fn read_fat32_system_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let handles = uefi::boot::find_handles::<BlockIO>().ok()?;
    uefi::println!("[FAT32] scanning {} BlockIO handle(s)", handles.len());
    for handle in handles {
        let protocol = unsafe {
            uefi::boot::open_protocol::<BlockIO>(
                OpenProtocolParams {
                    handle,
                    agent: uefi::boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let Ok(protocol) = protocol else { continue };
        let Some(block_io) = protocol.get() else {
            core::mem::forget(protocol);
            continue;
        };
        let media = block_io.media();
        uefi::println!(
            "[FAT32] handle block_size={} logical={} media_id={}",
            media.block_size(),
            media.is_logical_partition(),
            media.media_id()
        );
        if media.block_size() != 512 || media.is_logical_partition() {
            core::mem::forget(protocol);
            continue;
        }
        let reader = BlockIoReader {
            block_io: block_io as *const BlockIO,
            media_id: media.media_id(),
        };
        if let Some(partition_lba) = find_fat32_system_partition(&reader) {
            uefi::println!("[FAT32] found system partition at LBA {}", partition_lba);
            let result = read_fat32_file(&reader, partition_lba, path);
            uefi::println!(
                "[FAT32] read result bytes={}",
                result.as_ref().map_or(0, |d| d.len())
            );
            return result;
        }
        core::mem::forget(protocol);
    }
    None
}
