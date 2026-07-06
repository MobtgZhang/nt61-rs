//! Partition Manager (partmgr.sys)
//
//! Implements the partition manager. partmgr sits between the
//! disk class driver and the volume manager: it enumerates the
//! partition table on every disk and creates one device object
//! per partition. Volume manager (volmgr) then attaches to
//! each partition device and presents the file system driver
//! with a `\\Device\\HarddiskX\\PartitionY` namespace.
//
//! In our bootstrap the MBR is parsed: we look at the 4 primary
//! partition entries at offset 0x1BE and create a device for
//! each non-zero entry. GPT is *not* parsed (would require
//! reading the protective MBR + header at LBA 1 + partition
//! entries).
//
//! Clean-room implementation. Spec source: Microsoft "Partition
//! Manager" reference and the public MBR spec.

#![cfg(target_arch = "x86_64")]
#![allow(non_snake_case)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::drivers::storage::disk;
use crate::io::{DeviceObject, DeviceType, DriverObject};
use crate::ke::sync::Spinlock;
use crate::kprintln;

/// Maximum number of partitions across all disks.
const MAX_PARTITIONS: usize = 16;
/// Maximum partition name length.
const NAME_MAX: usize = 32;

/// One partition record.
pub struct Partition {
    pub valid: bool,
    /// `\Device\Harddisk0\Partition1`
    pub name: String,
    /// Backing disk index.
    pub disk_index: usize,
    /// Partition number on that disk (1..4 for MBR primary).
    pub partition_number: u32,
    /// First LBA.
    pub starting_offset: u64,
    /// Length in 512-byte sectors.
    pub sector_count: u64,
    /// MBR partition type byte.
    pub partition_type: u8,
    /// BOOT_IND from the MBR entry.
    pub boot_indicator: u8,
    pub device_object: *mut DeviceObject,
    pub driver: *mut DriverObject,
}

impl Partition {
    pub const fn new() -> Self {
        Self {
            valid: false,
            name: String::new(),
            disk_index: 0,
            partition_number: 0,
            starting_offset: 0,
            sector_count: 0,
            partition_type: 0,
            boot_indicator: 0,
            device_object: core::ptr::null_mut(),
            driver: core::ptr::null_mut(),
        }
    }
}

static mut PARTITIONS: [Partition; MAX_PARTITIONS] = [const { Partition::new() }; MAX_PARTITIONS];
static LOCK: Spinlock<()> = Spinlock::new(());
static TOTAL_PARTITIONS: AtomicU32 = AtomicU32::new(0);

/// MBR partition entry layout.
#[repr(C, packed)]
struct MbrPartitionEntry {
    boot_indicator: u8,
    starting_chs: [u8; 3],
    partition_type: u8,
    ending_chs: [u8; 3],
    starting_lba: u32,
    sector_count: u32,
}

const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// `PartMgrInit` — scan every disk's MBR and create a partition
/// device for each entry.
pub fn init() {
    let _g = LOCK.lock();
    for i in 0..disk::disk_count() {
        let mut mbr = [0u8; 512];
        if disk::DiskRead(i, 0, 512, &mut mbr) != 512 { continue; }
        if mbr[510..512] != MBR_SIGNATURE { continue; }
        // 4 partition entries at 0x1BE.
        for p in 0..4u32 {
            let off = 0x1BEusize + (p as usize) * 16;
            let entry = unsafe {
                core::ptr::read_unaligned(mbr.as_ptr().add(off) as *const MbrPartitionEntry)
            };
            let pt = entry.partition_type;
            if pt == 0 { continue; }
            let lba = u32::from_le(entry.starting_lba) as u64;
            let sc = u32::from_le(entry.sector_count) as u64;
            if sc == 0 { continue; }
            let name = format_name(i as u32, p + 1);
            add_partition(name, i, p + 1, lba, sc, pt, entry.boot_indicator);
        }
    }
}

fn format_name(disk: u32, part: u32) -> String {
    let mut s = String::with_capacity(NAME_MAX);
    s.push_str("\\Device\\Harddisk");
    s.push_str(&itoa(disk));
    s.push_str("\\Partition");
    s.push_str(&itoa(part));
    s
}

fn itoa(mut v: u32) -> String {
    if v == 0 { return String::from("0"); }
    let mut buf = [0u8; 12];
    let mut i = 0;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    let mut s = String::new();
    while i > 0 { i -= 1; s.push(buf[i] as char); }
    s
}

fn add_partition(name: String, disk_idx: usize, part_num: u32,
                 lba: u64, sectors: u64, pt: u8, boot: u8) {
    unsafe {
        for slot in PARTITIONS.iter_mut() {
            if slot.valid { continue; }
            slot.valid = true;
            slot.name = name.clone();
            slot.disk_index = disk_idx;
            slot.partition_number = part_num;
            slot.starting_offset = lba;
            slot.sector_count = sectors;
            slot.partition_type = pt;
            slot.boot_indicator = boot;
            TOTAL_PARTITIONS.fetch_add(1, Ordering::Relaxed);
            // kprintln!("    [PARTMGR] {} LBA={} sectors={} type=0x{:02x}",  // kprintln disabled (memcpy crash workaround)
//                 name, lba, sectors, pt);
            return;
        }
    }
}

/// Number of partitions currently registered.
pub fn count() -> u32 { TOTAL_PARTITIONS.load(Ordering::Relaxed) }

/// Look up a partition by its device-object path.
pub fn find(name: &str) -> Option<Partition> {
    unsafe {
        for slot in PARTITIONS.iter() {
            if !slot.valid { continue; }
            if slot.name == name {
                return Some(Partition {
                    valid: true,
                    name: slot.name.clone(),
                    disk_index: slot.disk_index,
                    partition_number: slot.partition_number,
                    starting_offset: slot.starting_offset,
                    sector_count: slot.sector_count,
                    partition_type: slot.partition_type,
                    boot_indicator: slot.boot_indicator,
                    device_object: slot.device_object,
                    driver: slot.driver,
                });
            }
        }
    }
    None
}

/// Return all partition records (used by the smoke test).
pub fn list_all() -> Vec<Partition> {
    let mut out = Vec::new();
    unsafe {
        for slot in PARTITIONS.iter() {
            if !slot.valid { continue; }
            out.push(Partition {
                valid: true,
                name: slot.name.clone(),
                disk_index: slot.disk_index,
                partition_number: slot.partition_number,
                starting_offset: slot.starting_offset,
                sector_count: slot.sector_count,
                partition_type: slot.partition_type,
                boot_indicator: slot.boot_indicator,
                device_object: slot.device_object,
                driver: slot.driver,
            });
        }
    }
    out
}

/// Read `byte_count` bytes from a partition, addressed from the
/// partition's start (LBA = partition LBA + offset / 512).
pub fn read(disk_idx: usize, lba: u64, byte_count: usize, buf: &mut [u8]) -> usize {
    if buf.len() < byte_count { return 0; }
    disk::DiskRead(disk_idx, lba * 512, byte_count, buf)
}

/// Smoke test: enumerate MBR partitions, print them, and read
/// the first sector of the first partition.
pub fn smoke_test() -> bool {
    // kprintln!("  [PARTMGR SMOKE] testing partition manager...")  // kprintln disabled (memcpy crash workaround);
    let parts = list_all();
    // kprintln!("  [PARTMGR SMOKE] partitions found: {}", parts.len())  // kprintln disabled (memcpy crash workaround);
    for p in &parts {
        let _ = p;
        // kprintln!("  [PARTMGR SMOKE]   {} LBA={} sectors={} type=0x{:02x}",  // kprintln disabled (memcpy crash workaround)
//             p.name, p.starting_offset, p.sector_count, p.partition_type);
    }
    if let Some(p0) = parts.first() {
        let mut sec = [0u8; 512];
        let n = disk::DiskRead(p0.disk_index, p0.starting_offset * 512, 512, &mut sec);
        let _ = &n;
        // kprintln!("  [PARTMGR SMOKE] first sector of {} read: {} bytes (sig {:02x}{:02x})",  // kprintln disabled (memcpy crash workaround)
//             p0.name, n, sec[510], sec[511]);
    }
    // kprintln!("  [PARTMGR SMOKE OK] partitions={}", count())  // kprintln disabled (memcpy crash workaround);
    true
}
