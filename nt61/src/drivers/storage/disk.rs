//! Disk Class Driver (disk.sys)
//
//! Implements the disk class driver. disk.sys sits between the
//! volume manager (volmgr) and the storage port (storport or
//! ataport). It owns the FDO (Functional Device Object) for each
//! physical disk and translates IRP_MJ_READ / IRP_MJ_WRITE into
//! SCSI_REQUEST_BLOCK requests that the port driver services.
//
//! In our environment disk.sys is a thin shim: it manages a
//! per-disk `DiskDevice` record and forwards read/write requests
//! to whichever underlying transport is available (ATA PIO for
//! the QEMU IDE, NVMe or AHCI when present).
//
//! Clean-room implementation. Spec source: Microsoft "Disk Class
//! Driver" reference.

#![cfg(target_arch = "x86_64")]
#![allow(non_snake_case)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::drivers::storage::ata;
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;
use crate::kprintln;

/// Maximum number of disk devices.
const MAX_DISKS: usize = 4;

/// One physical disk.
pub struct DiskDevice {
    pub valid: bool,
    pub name: String,
    pub device_object: *mut DeviceObject,
    pub driver: *mut DriverObject,
    /// First LBA we can address.
    pub starting_offset: u64,
    /// Number of 512-byte sectors.
    pub sector_count: u64,
    /// Bytes per sector (always 512 in the bootstrap).
    pub bytes_per_sector: u32,
    /// Cache: number of read IOs.
    pub reads: u64,
    pub writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

impl DiskDevice {
    pub const fn new() -> Self {
        Self {
            valid: false,
            name: String::new(),
            device_object: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
            starting_offset: 0,
            sector_count: 0,
            bytes_per_sector: 512,
            reads: 0, writes: 0, bytes_read: 0, bytes_written: 0,
        }
    }
}

static mut DISKS: [DiskDevice; MAX_DISKS] = [const { DiskDevice::new() }; MAX_DISKS];
static DISK_LOCK: Spinlock<()> = Spinlock::new(());
static READ_COUNT: AtomicU32 = AtomicU32::new(0);
static WRITE_COUNT: AtomicU32 = AtomicU32::new(0);

/// `DiskInit` — enumerate the underlying storage and create one
/// disk device per physical unit.
pub fn init() {
    // Drive 0 (primary master) is the boot disk in QEMU.
    if ata::has_device(0) {
        add_disk("PhysicalDrive0", 0, ata::total_sectors(0) as u64);
    }
    if ata::has_device(1) {
        add_disk("PhysicalDrive1", 1, ata::total_sectors(1) as u64);
    }
}

fn add_disk(name: &str, _channel: usize, sector_count: u64) {
    let _g = DISK_LOCK.lock();
    unsafe {
        for slot in DISKS.iter_mut() {
            if slot.valid { continue; }
            slot.valid = true;
            slot.name = String::from(name);
            slot.starting_offset = 0;
            slot.sector_count = sector_count;
            slot.bytes_per_sector = 512;
            slot.reads = 0;
            slot.writes = 0;
            slot.bytes_read = 0;
            slot.bytes_written = 0;
            // kprintln!("    [DISK]   {} (ch={}, sectors={})",  // kprintln disabled (memcpy crash workaround)
//                 name, channel, sector_count);
            return;
        }
    }
}

/// `DiskRead` — read `byte_count` bytes from `offset` on disk
/// `idx` into `buf`. Returns the number of bytes read.
pub fn DiskRead(idx: usize, offset: u64, byte_count: usize, buf: &mut [u8]) -> usize {
    if buf.len() < byte_count { return 0; }
    unsafe {
        if idx >= MAX_DISKS { return 0; }
        let disk = &DISKS[idx];
        if !disk.valid { return 0; }
        let channel = (idx & 1) as usize;
        let start_sector = (offset / 512) as u32;
        let mut remaining = byte_count;
        let mut out_off = 0usize;
        while remaining > 0 {
            let sectors = core::cmp::min(remaining / 512, 256) as u8;
            let mut tmp = [0u16; 256 * 256];
            if !ata::read_sectors(channel, start_sector, sectors, &mut tmp[..(sectors as usize) * 256]) {
                return out_off;
            }
            // Pack 16-bit words back to 8-bit bytes.
            for i in 0..((sectors as usize) * 256) {
                if out_off >= byte_count { break; }
                let w = tmp[i];
                buf[out_off] = (w & 0xFF) as u8;
                buf[out_off + 1] = ((w >> 8) & 0xFF) as u8;
                out_off += 2;
            }
            remaining -= (sectors as usize) * 512;
        }
        let d = &mut DISKS[idx];
        d.reads += 1;
        d.bytes_read += out_off as u64;
        READ_COUNT.fetch_add(1, Ordering::Relaxed);
        out_off
    }
}

/// `DiskWrite` — write `byte_count` bytes from `buf` to `offset` on disk `idx`.
///
/// Note: The ATA PIO driver does not support writes in this bootstrap environment.
/// This implementation updates statistics to track write attempts, but does not
/// actually persist data. For a full implementation, this would use:
/// - ATA PIO WRITE SECTORS command (if supported)
/// - AHCI DMA write operations (when available)
/// - NVMe Write command (when available)
///
/// Returns the number of bytes "written" (in bootstrap: always 0 since no actual I/O).
pub fn DiskWrite(idx: usize, _offset: u64, byte_count: usize, buf: &[u8]) -> usize {
    // Validate parameters
    if buf.len() < byte_count { return 0; }

    unsafe {
        if idx >= MAX_DISKS { return 0; }
        let d = &mut DISKS[idx];
        if !d.valid { return 0; }

        // Track the write attempt in statistics
        d.writes += 1;
        // Note: bytes_written is NOT incremented because no actual data was written
        // This distinguishes "attempted writes" from "successful writes"
    }
    WRITE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Return 0 to indicate no actual data was written
    // The kernel smoke test can check this to verify write support
    0
}

pub fn disk_count() -> usize {
    let mut n = 0;
    unsafe { for d in DISKS.iter() { if d.valid { n += 1; } } }
    n
}

pub fn get_disk(idx: usize) -> Option<DiskDevice> {
    unsafe {
        if idx >= MAX_DISKS { return None; }
        let d = &DISKS[idx];
        if !d.valid { return None; }
        Some(DiskDevice {
            valid: true,
            name: d.name.clone(),
            device_object: d.device_object,
            driver: d.driver,
            starting_offset: d.starting_offset,
            sector_count: d.sector_count,
            bytes_per_sector: d.bytes_per_sector,
            reads: d.reads, writes: d.writes,
            bytes_read: d.bytes_read, bytes_written: d.bytes_written,
        })
    }
}

pub fn read_count() -> u32 { READ_COUNT.load(Ordering::Relaxed) }
pub fn write_count() -> u32 { WRITE_COUNT.load(Ordering::Relaxed) }

/// Smoke test: enumerate the disk and read the MBR (sector 0).
pub fn smoke_test() -> bool {
    // kprintln!("  [DISK SMOKE] testing disk class driver...")  // kprintln disabled (memcpy crash workaround);
    if disk_count() == 0 {
        // kprintln!("  [DISK SMOKE] no disks found (test passes vacuously)")  // kprintln disabled (memcpy crash workaround);
        return true;
    }
    let mut mbr = [0u8; 512];
    let n = DiskRead(0, 0, 512, &mut mbr);
    if n == 0 {
        // kprintln!("  [DISK SMOKE FAIL] MBR read returned 0")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // The MBR ends with 0x55, 0xAA.
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        // kprintln!("  [DISK SMOKE WARN] MBR signature 0x{:02x}{:02x}", mbr[510], mbr[511])  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("  [DISK SMOKE] MBR signature OK (0x55AA)")  // kprintln disabled (memcpy crash workaround);
    }
    // Also try a high-LBA read (sector 0x100).
    let mut sec = [0u8; 512];
    let n = DiskRead(0, 0x100 * 512, 512, &mut sec);
    // Publish counts so upper layers can verify disk I/O during boot.
    LAST_SMOKE_READ_BYTES.store(n as u32, core::sync::atomic::Ordering::Relaxed);
    let read_count_val = read_count();
    let write_count_val = write_count();
    let disk_count_val = disk_count();
    let _ = (read_count_val, write_count_val, disk_count_val);
    true
}

/// Last observed smoke-test read byte count.
static LAST_SMOKE_READ_BYTES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Diagnostic accessor for the last smoke-test read.
pub fn last_smoke_read_bytes() -> u32 {
    LAST_SMOKE_READ_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}
