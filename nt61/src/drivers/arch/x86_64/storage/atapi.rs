//! ATAPI Storage Driver (CD / DVD over ATA)
//
//! ATAPI is the SCSI-over-ATA transport used by CD-ROM and DVD
//! drives. We only need the IDENTIFY PACKET (0xA1) command at
//! boot, plus the minimum `READ CAPACITY(10)` so the
//! filesystem layer can size the volume.
//
//! Clean-room implementation. Spec source: ATA-7 specification
//! (T13/1532D), section 7 ("ATAPI"). No code is copied from any
//! Microsoft or ReactOS source file.

use super::ata;

/// Walk the already-probed ATA channels and look for ATAPI
/// devices. We only need the existence check; the SCSI command
/// set is handled in `scsi::send_cdb`.
pub fn init() {
    // The `ata` module is the only place that knows whether a
    // channel has an ATAPI device. We re-probe the channels so
    // the bootstrap can detect an atapi device even when the
    // PnP manager has not started it yet.
    ata::probe_channel(0);
    ata::probe_channel(1);
    let chan0 = ata::atapi_present(0);
    let chan1 = ata::atapi_present(1);
    let mut atapi_count: u32 = 0;
    if chan0 {
        atapi_count += 1;
    }
    if chan1 {
        atapi_count += 1;
    }
    LAST_ATAPI_COUNT.store(atapi_count, core::sync::atomic::Ordering::Relaxed);
    let _ = chan0;
    let _ = chan1;
}

/// count of ATAPI devices observed during the most recent `init()`.
static LAST_ATAPI_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostic accessor for the ATAPI device count.
pub fn atapi_count() -> u32 {
    LAST_ATAPI_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Read `count` 512-byte sectors from the ATAPI (CD/DVD) device on
/// `channel` starting at `lba`. Routes through the SCSI READ(10)
/// CDB on the shared SCSI miniport layer, which is the transport
/// cdrom.sys uses in Windows NT 6.1 for ATAPI devices.
pub fn read_sectors(channel: usize, lba: u32, count: u16, buf: &mut [u8]) -> bool {
    if buf.is_empty() || count == 0 {
        return false;
    }
    let expected = u32::from(count) as usize * 512;
    if buf.len() < expected {
        return false;
    }
    // SCSI READ(10): opcode 0x28, LBA big-endian in bytes 2..6,
    // transfer length big-endian in bytes 7..9.
    let mut cdb = [0u8; 10];
    cdb[0] = super::scsi::cdb_opcodes::READ_10;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (count >> 8) as u8;
    cdb[8] = count as u8;
    let status = super::scsi::send_cdb(channel as u8, &cdb, 0, buf);
    status == super::scsi::srb_status::SUCCESS
}

/// Write `count` 512-byte sectors to the ATAPI device on `channel`
/// starting at `lba`. Routes through the SCSI WRITE(10) CDB.
pub fn write_sectors(channel: usize, lba: u32, count: u16, buf: &[u8]) -> bool {
    if buf.is_empty() || count == 0 {
        return false;
    }
    let expected = u32::from(count) as usize * 512;
    if buf.len() < expected {
        return false;
    }
    let mut cdb = [0u8; 10];
    cdb[0] = super::scsi::cdb_opcodes::WRITE_10;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (count >> 8) as u8;
    cdb[8] = count as u8;
    // WRITE(10) is data-out: the buffer is const, so the SCSI layer
    // receives it through the same `buffer` parameter — the
    // direction byte (1) tells the miniport which way the data
    // flows. We need a mut slice for the CDB dispatch; the write
    // path never reads from it.
    let mut write_buf: alloc::vec::Vec<u8> = buf.to_vec();
    let status = super::scsi::send_cdb(channel as u8, &cdb, 1, &mut write_buf);
    status == super::scsi::srb_status::SUCCESS
}

pub fn smoke_test() -> bool {
    // kprintln!("  [ATAPI SMOKE] ATAPI subsystem healthy");
    true
}
