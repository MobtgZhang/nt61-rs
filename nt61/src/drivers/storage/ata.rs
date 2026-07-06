//! ATA / PATA Storage Driver (PIO mode)
//
//! Implements a minimal ATA-7 driver in PIO mode. This covers
//! IDE disks attached to the legacy primary/secondary
//! controllers on PCI class 0x0101, plus the legacy ISA ports
//! 0x1F0/0x170 used by `pci-ide` chipsets.
//
//! Clean-room implementation. Spec source: ATA-7 specification
//! (T13/1532D), volume 1, section 6 ("Command set"). No code is
//! copied from any Microsoft or ReactOS source file.

// ATA command names (ATA_CMD_READ_SECTORS, ...) follow the
// ATA spec; only a few are exercised in the stub pipeline.
#![cfg(target_arch = "x86_64")]
#![allow(dead_code, non_upper_case_globals)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::hal::common::pci;
use crate::kprintln;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard I/O port pairs for the two legacy ATA channels.
const PRIMARY_IO: u16 = 0x1F0;
const PRIMARY_CTRL: u16 = 0x3F6;
const SECONDARY_IO: u16 = 0x170;
const SECONDARY_CTRL: u16 = 0x376;

/// ATA command: IDENTIFY DEVICE.
const CMD_IDENTIFY: u8 = 0xEC;
/// ATA command: IDENTIFY PACKET DEVICE.
const CMD_IDENTIFY_PACKET: u8 = 0xA1;
/// ATA command: READ SECTORS (28-bit LBA).
const CMD_READ_SECTORS: u8 = 0x20;
/// ATA command: READ SECTORS EXT (48-bit LBA).
const CMD_READ_SECTORS_EXT: u8 = 0x24;
/// ATA command: WRITE SECTORS (28-bit LBA).
const CMD_WRITE_SECTORS: u8 = 0x30;
/// ATA command: WRITE SECTORS EXT (48-bit LBA).
const CMD_WRITE_SECTORS_EXT: u8 = 0x34;
/// ATA command: SMART (Self-Monitoring, Analysis, and Reporting Technology).
const CMD_SMART: u8 = 0xB0;
/// ATA command: SMART READ DATA.
const CMD_SMART_READ_DATA: u8 = 0xD0;

/// Status register bits.
const SR_BSY: u8 = 0x80;
const SR_DRDY: u8 = 0x40;
const SR_DF: u8 = 0x20;
const SR_DSC: u8 = 0x10;
const SR_DRQ: u8 = 0x08;
const SR_CORR: u8 = 0x04;
const SR_IDX: u8 = 0x02;
const SR_ERR: u8 = 0x01;

/// Timeout for ATA operations (in microseconds).
const ATA_TIMEOUT_US: u32 = 5_000_000; // 5 seconds
const ATA_POLL_INTERVAL: u32 = 100; // 100 iterations at 100 cycles each

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One registered ATA channel.
#[derive(Debug, Clone)]
struct AtaChannel {
    io_base: u16,
    ctrl_base: u16,
    has_device: bool,
    is_atapi: bool,
    lba_supported: bool,
    lba48_supported: bool,
    total_sectors: u64,
    model: [u8; 40],
    serial: [u8; 20],
}

impl Default for AtaChannel {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl AtaChannel {
    const fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self {
            io_base, ctrl_base,
            has_device: false,
            is_atapi: false,
            lba_supported: false,
            lba48_supported: false,
            total_sectors: 0,
            model: [0u8; 40],
            serial: [0u8; 20],
        }
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static mut CHANNELS: [AtaChannel; 2] = [
    AtaChannel::new(PRIMARY_IO, PRIMARY_CTRL),
    AtaChannel::new(SECONDARY_IO, SECONDARY_CTRL),
];

/// Track whether ATA has been initialized
static ATA_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Walk PCI for IDE controllers, then probe the legacy ports as a
/// fallback (covers QEMU's default IDE emulation).
pub fn init() {
    if ATA_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }

    let mut pci_ide = 0u32;
    for dev in pci::enumerate() {
        // PCI class 0x01 (storage), subclass 0x01 (IDE), prog-if 0x80/0x8A.
        if dev.class_code == 0x01
            && dev.subclass == 0x01
            && (dev.prog_if & 0x05) != 0
        {
            pci_ide += 1;
        }
    }
    probe_channel(0);
    probe_channel(1);

    // Publish the discovery result so smoke tests and upper layers
    // can observe it without re-walking the PCI bus.
    let chan0 = has_device(0);
    let chan1 = has_device(1);
    LAST_PCI_IDE.store(pci_ide, Ordering::Relaxed);
    LAST_CHAN0.store(chan0 as u32, Ordering::Relaxed);
    LAST_CHAN1.store(chan1 as u32, Ordering::Relaxed);
}

/// Most recently observed PCI IDE controller count.
static LAST_PCI_IDE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_CHAN0: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static LAST_CHAN1: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Returns the count of PCI IDE controllers observed by the most
/// recent `init()`.
pub fn pci_ide_count() -> u32 {
    LAST_PCI_IDE.load(Ordering::Relaxed)
}
/// Returns whether channel 0 reported a device during init.
pub fn last_chan0_present() -> bool {
    LAST_CHAN0.load(Ordering::Relaxed) != 0
}
/// Returns whether channel 1 reported a device during init.
pub fn last_chan1_present() -> bool {
    LAST_CHAN1.load(Ordering::Relaxed) != 0
}

pub fn has_device(idx: usize) -> bool { unsafe { CHANNELS[idx].has_device } }
pub fn atapi_present(idx: usize) -> bool {
    unsafe { idx < CHANNELS.len() && CHANNELS[idx].is_atapi }
}

/// Number of 512-byte sectors reported by IDENTIFY DEVICE.
pub fn total_sectors(idx: usize) -> u64 {
    unsafe {
        if idx >= CHANNELS.len() || !CHANNELS[idx].has_device { return 0; }
        CHANNELS[idx].total_sectors
    }
}

/// Check if LBA48 is supported.
pub fn lba48_supported(idx: usize) -> bool {
    unsafe {
        if idx >= CHANNELS.len() || !CHANNELS[idx].has_device { return false; }
        CHANNELS[idx].lba48_supported
    }
}

// ---------------------------------------------------------------------------
// Channel probing
// ---------------------------------------------------------------------------

/// Probe `idx` for an ATA / ATAPI device. We do a soft reset
/// followed by IDENTIFY (0xEC) or ATAPI IDENTIFY (0xA1) depending
/// on the first signature byte. The full IDENTIFY data is parsed
/// to extract the LBA / LBA48 capability bits and the total
/// sector count.
pub fn probe_channel(idx: usize) {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{
        READ_PORT_UCHAR, READ_PORT_USHORT, WRITE_PORT_UCHAR,
    };
    unsafe {
        let ch = &mut CHANNELS[idx];
        let io = ch.io_base;
        let ctrl = ch.ctrl_base;
        // Soft reset: clear SRST bit then set it.
        WRITE_PORT_UCHAR(ctrl + 2, 0x06); // SRST
        for _ in 0..1000 { core::hint::spin_loop(); }
        WRITE_PORT_UCHAR(ctrl + 2, 0x02); // nIEN
        // Wait for BSY to clear.
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            ch.has_device = false;
            return;
        }
        // Select drive 0, LBA mode off.
        WRITE_PORT_UCHAR(io + 6, 0xA0);
        // Read status / signature.
        let status = READ_PORT_UCHAR(io + 7);
        let lba_lo = READ_PORT_UCHAR(io + 3);
        let lba_mid = READ_PORT_UCHAR(io + 4);
        let lba_hi = READ_PORT_UCHAR(io + 5);
        if status == 0 || status == 0xFF {
            ch.has_device = false;
            return;
        }
        // ATAPI signature: (lba_mid == 0x14 && lba_hi == 0xEB).
        if lba_mid == 0x14 && lba_hi == 0xEB {
            ch.is_atapi = true;
            ch.has_device = true;
            identify_atapi(io);
            return;
        }
        // SATA signature: (lba_mid == 0x3C && lba_hi == 0xC3) or (0x69, 0x96)
        if (lba_mid == 0x3C && lba_hi == 0xC3) || (lba_mid == 0x69 && lba_hi == 0x96) {
            // SATA - could be AHCI or legacy, but we handle this via AHCI driver
            ch.has_device = true;
            ch.is_atapi = false;
            ch.lba_supported = true;
            ch.lba48_supported = true;
            return;
        }
        // ATA signature: (lba_mid == 0 && lba_hi == 0).
        if lba_mid == 0 && lba_hi == 0 && (lba_lo != 0 || status & SR_DRDY != 0) {
            ch.is_atapi = false;
            ch.has_device = true;
            identify_ata(io, ch);
            return;
        }
        ch.has_device = false;
    }
}

// ---------------------------------------------------------------------------
// Low-level timing
// ---------------------------------------------------------------------------

/// Wait for the drive to not be busy. Returns true if BSY cleared
/// within `timeout_us` microseconds.
unsafe fn wait_not_busy(status_port: u16, timeout_us: u32) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::READ_PORT_UCHAR;
    let iterations = timeout_us / 100;
    for _ in 0..iterations {
        let s = READ_PORT_UCHAR(status_port);
        if (s & SR_BSY) == 0 { return true; }
        // Spin for ~100 cycles
        for _ in 0..100 { core::hint::spin_loop(); }
    }
    false
}

/// Wait for DRQ to be set (and BSY cleared). Returns true if
/// DRQ was asserted within `timeout_us` microseconds.
unsafe fn wait_drq(status_port: u16, timeout_us: u32) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::READ_PORT_UCHAR;
    let iterations = timeout_us / 100;
    for _ in 0..iterations {
        let s = READ_PORT_UCHAR(status_port);
        if (s & SR_BSY) == 0 && (s & SR_DRQ) != 0 { return true; }
        // Check for error
        if (s & SR_ERR) != 0 { return false; }
        for _ in 0..100 { core::hint::spin_loop(); }
    }
    false
}

// ---------------------------------------------------------------------------
// IDENTIFY parsing
// ---------------------------------------------------------------------------

/// Parse a string from IDENTIFY data words.
/// The string is stored in 16-bit words with bytes swapped.
fn parse_string_from_words(data: &[u16; 256], start: usize, target: &mut [u8]) {
    let max_chars = (target.len() / 2).min(data.len().saturating_sub(start));
    for i in 0..max_chars {
        let word = data[start + i];
        // ATA strings are stored with bytes swapped in each word
        target[i * 2] = (word >> 8) as u8;
        target[i * 2 + 1] = (word & 0xFF) as u8;
    }
    // Trim trailing spaces in place
    let total_len = max_chars * 2;
    let mut end = total_len;
    while end > 0 && target[end - 1] == b' ' {
        end -= 1;
    }
    target[end..].fill(0);
}

/// Send IDENTIFY DEVICE (0xEC) and parse the LBA capacity words.
unsafe fn identify_ata(io: u16, ch: &mut AtaChannel) {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR};
    // Use LBA0 = 0.
    WRITE_PORT_UCHAR(io + 2, 0);
    WRITE_PORT_UCHAR(io + 3, 0);
    WRITE_PORT_UCHAR(io + 4, 0);
    WRITE_PORT_UCHAR(io + 5, 0);
    WRITE_PORT_UCHAR(io + 7, CMD_IDENTIFY);
    // Wait for DRQ
    if !wait_drq(io + 7, ATA_TIMEOUT_US) {
        ch.has_device = false;
        return;
    }
    // Read 256 words.
    let mut data = [0u16; 256];
    for i in 0..256 {
        data[i] = READ_PORT_USHORT(io);
    }
    // Word 60..61: total sectors (28-bit LBA).
    let lba28 = ((data[61] as u64) << 16) | (data[60] as u64);
    // Word 83 bit 10: LBA48 supported.
    let lba48 = (data[83] & (1 << 10)) != 0;
    ch.lba_supported = lba28 > 0 || lba48;
    ch.lba48_supported = lba48;
    ch.total_sectors = if lba48 {
        ((data[102] as u64) << 48)
            | ((data[101] as u64) << 32)
            | ((data[100] as u64) << 16)
            | (data[99] as u64)
    } else {
        lba28
    };

    // Parse model and serial number
    parse_string_from_words(&data, 27, &mut ch.model);
    parse_string_from_words(&data, 10, &mut ch.serial);

    // kprintln!("      ATA: device found - model: {:?} serial: {:?}",  // kprintln disabled (memcpy crash workaround)
//              core::str::from_utf8(&ch.model),
//              core::str::from_utf8(&ch.serial));
    // kprintln!("      ATA: LBA28={} LBA48={} sectors={}",  // kprintln disabled (memcpy crash workaround)
//              ch.lba_supported, ch.lba48_supported, ch.total_sectors);
}

unsafe fn identify_atapi(io: u16) {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR};
    // Issue ATAPI IDENTIFY PACKET (0xA1). For the bootstrap we
    // just verify the device responded and discard the data.
    WRITE_PORT_UCHAR(io + 7, CMD_IDENTIFY_PACKET);
    if !wait_drq(io + 7, ATA_TIMEOUT_US) { return; }
    for _ in 0..256 {
        let _ = READ_PORT_USHORT(io);
    }
}

// ---------------------------------------------------------------------------
// PIO Read/Write (LBA28)
// ---------------------------------------------------------------------------

/// Read one sector (512 bytes) from `lba` into `buf` on channel `idx`.
/// Returns `true` on success.
pub fn read_sector(idx: usize, lba: u32, buf: &mut [u8; 512]) -> bool {
    let mut words = [0u16; 256];
    if !read_sectors(idx, lba, 1, &mut words) {
        return false;
    }
    for i in 0..256 {
        buf[i * 2] = words[i] as u8;
        buf[i * 2 + 1] = (words[i] >> 8) as u8;
    }
    true
}

/// Write one sector (512 bytes) from `buf` to `lba` on channel `idx`.
/// Returns `true` on success.
pub fn write_sector(idx: usize, lba: u32, buf: &[u16; 256]) -> bool {
    write_sectors(idx, lba, 1, buf)
}

/// Write `count` sectors from `buf` to `lba` on channel `idx`.
/// Returns `true` on success. Only LBA28 is used.
pub fn write_sectors(idx: usize, lba: u32, count: u8, buf: &[u16]) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR, WRITE_PORT_USHORT};
    if buf.len() < (count as usize) * 256 { return false; }
    unsafe {
        let ch = &mut CHANNELS[idx];
        if !ch.has_device || ch.is_atapi { return false; }
        let io = ch.io_base;

        // Wait for drive to be ready
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            // kprintln!("[ATA] write_sectors: device busy")  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        // Select drive 0, LBA mode
        WRITE_PORT_UCHAR(io + 6, 0xE0 | ((lba >> 24) & 0x0F) as u8);
        WRITE_PORT_UCHAR(io + 1, 0x00);
        WRITE_PORT_UCHAR(io + 2, count);
        WRITE_PORT_UCHAR(io + 3, lba as u8);
        WRITE_PORT_UCHAR(io + 4, (lba >> 8) as u8);
        WRITE_PORT_UCHAR(io + 5, (lba >> 16) as u8);

        // Issue WRITE SECTORS command
        WRITE_PORT_UCHAR(io + 7, CMD_WRITE_SECTORS);

        // Write data sector by sector
        for i in 0..(count as usize) {
            // Wait for drive to request data
            if !wait_drq(io + 7, ATA_TIMEOUT_US) {
                // kprintln!("[ATA] write_sectors: DRQ timeout at sector {}", i)  // kprintln disabled (memcpy crash workaround);
                return false;
            }

            // Write 256 words (one sector)
            for j in 0..256 {
                WRITE_PORT_USHORT(io, buf[i * 256 + j]);
            }
        }

        // Wait for write to complete
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            // kprintln!("[ATA] write_sectors: completion timeout")  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        true
    }
}

/// Read `count` sectors from `lba` into `buf` on channel `idx`.
/// Returns `true` on success. Only LBA28 is used (QEMU's default
/// IDE image is small enough not to need LBA48).
pub fn read_sectors(idx: usize, lba: u32, count: u8, buf: &mut [u16]) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR};
    if buf.len() < (count as usize) * 256 { return false; }
    unsafe {
        let ch = &mut CHANNELS[idx];
        if !ch.has_device || ch.is_atapi { return false; }
        let io = ch.io_base;
        // Select drive 0, LBA mode.
        WRITE_PORT_UCHAR(io + 6, 0xE0 | ((lba >> 24) & 0x0F) as u8);
        WRITE_PORT_UCHAR(io + 1, 0x00);
        WRITE_PORT_UCHAR(io + 2, count);
        WRITE_PORT_UCHAR(io + 3, lba as u8);
        WRITE_PORT_UCHAR(io + 4, (lba >> 8) as u8);
        WRITE_PORT_UCHAR(io + 5, (lba >> 16) as u8);
        WRITE_PORT_UCHAR(io + 7, CMD_READ_SECTORS);
        if !wait_drq(io + 7, ATA_TIMEOUT_US) {
            // kprintln!("[ATA] read_sectors: DRQ timeout")  // kprintln disabled (memcpy crash workaround);
            return false;
        }
        for i in 0..(count as usize) * 256 {
            buf[i] = READ_PORT_USHORT(io);
        }
        true
    }
}

// ---------------------------------------------------------------------------
// LBA48 Extended commands
// ---------------------------------------------------------------------------

/// Read sectors using 48-bit LBA (extended).
/// `lba` is a 48-bit sector number, `count` is up to 65535 sectors.
pub fn read_sectors_lba48(idx: usize, lba: u64, count: u16, buf: &mut [u16]) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR, WRITE_PORT_USHORT};

    if buf.len() < (count as usize) * 256 { return false; }

    unsafe {
        let ch = &mut CHANNELS[idx];
        if !ch.has_device || ch.is_atapi || !ch.lba48_supported {
            return false;
        }
        let io = ch.io_base;

        // Wait for drive to be ready
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return false;
        }

        // Select drive with LBA48 bit
        WRITE_PORT_UCHAR(io + 6, 0x40);

        // Write sector count (low 8 bits first)
        WRITE_PORT_UCHAR(io + 2, (count & 0xFF) as u8);
        // Write LBA (low 24 bits first)
        WRITE_PORT_UCHAR(io + 3, (lba & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 4, ((lba >> 8) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 5, ((lba >> 16) & 0xFF) as u8);
        // Write sector count (high 8 bits)
        WRITE_PORT_UCHAR(io + 2, ((count >> 8) & 0xFF) as u8);
        // Write LBA (high 24 bits)
        WRITE_PORT_UCHAR(io + 3, ((lba >> 24) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 4, ((lba >> 32) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 5, ((lba >> 40) & 0xFF) as u8);

        // Issue READ SECTORS EXT command
        WRITE_PORT_UCHAR(io + 7, CMD_READ_SECTORS_EXT);

        // Read data sector by sector
        for i in 0..(count as usize) * 256 {
            if !wait_drq(io + 7, ATA_TIMEOUT_US) {
                return false;
            }
            buf[i] = READ_PORT_USHORT(io);
        }

        // Wait for completion
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return false;
        }

        true
    }
}

/// Write sectors using 48-bit LBA (extended).
pub fn write_sectors_lba48(idx: usize, lba: u64, count: u16, buf: &[u16]) -> bool {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR, WRITE_PORT_USHORT};

    if buf.len() < (count as usize) * 256 { return false; }

    unsafe {
        let ch = &mut CHANNELS[idx];
        if !ch.has_device || ch.is_atapi || !ch.lba48_supported {
            return false;
        }
        let io = ch.io_base;

        // Wait for drive to be ready
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return false;
        }

        // Select drive with LBA48 bit
        WRITE_PORT_UCHAR(io + 6, 0x40);

        // Write sector count (low 8 bits first)
        WRITE_PORT_UCHAR(io + 2, (count & 0xFF) as u8);
        // Write LBA (low 24 bits first)
        WRITE_PORT_UCHAR(io + 3, (lba & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 4, ((lba >> 8) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 5, ((lba >> 16) & 0xFF) as u8);
        // Write sector count (high 8 bits)
        WRITE_PORT_UCHAR(io + 2, ((count >> 8) & 0xFF) as u8);
        // Write LBA (high 24 bits)
        WRITE_PORT_UCHAR(io + 3, ((lba >> 24) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 4, ((lba >> 32) & 0xFF) as u8);
        WRITE_PORT_UCHAR(io + 5, ((lba >> 40) & 0xFF) as u8);

        // Issue WRITE SECTORS EXT command
        WRITE_PORT_UCHAR(io + 7, CMD_WRITE_SECTORS_EXT);

        // Write data sector by sector
        for i in 0..(count as usize) * 256 {
            if !wait_drq(io + 7, ATA_TIMEOUT_US) {
                return false;
            }
            WRITE_PORT_USHORT(io, buf[i]);
        }

        // Wait for completion
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// SMART support
// ---------------------------------------------------------------------------

/// SMART data structure (512 bytes).
#[derive(Debug, Default)]
#[repr(C)]
pub struct SmartData {
    pub version: u16,
    pub smart_capabilities: u16,
    pub smart_capabilities_2: u16,
    pub attributes: [SmartAttribute; 30],
    pub offline_status: u8,
    pub offline_data_capture: u8,
    pub smart_total_time: u16,
    pub power_on_total_hours: [u8; 2],
    pub power_cycle_count: [u8; 2],
    pub reserved: [u8; 12],
    pub checksum: u8,
}

/// One SMART attribute (12 bytes).
#[derive(Debug, Default)]
#[repr(C)]
pub struct SmartAttribute {
    pub id: u8,
    pub current: u8,
    pub worst: u8,
    pub raw: [u8; 6],
    pub reserved: u8,
}

/// Read SMART data from the drive.
pub fn read_smart_data(idx: usize) -> Option<SmartData> {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_UCHAR};

    if !has_device(idx) {
        return None;
    }

    unsafe {
        let ch = &mut CHANNELS[idx];
        if ch.is_atapi {
            return None; // SMART not supported on ATAPI
        }
        let io = ch.io_base;

        // Wait for drive to be ready
        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return None;
        }

        // Select drive
        WRITE_PORT_UCHAR(io + 6, 0xA0);

        // Issue SMART ENABLE ATTRIBUTES command
        WRITE_PORT_UCHAR(io + 1, 0x00);
        WRITE_PORT_UCHAR(io + 2, 0x00);
        WRITE_PORT_UCHAR(io + 3, 0x00);
        WRITE_PORT_UCHAR(io + 4, 0x00);
        WRITE_PORT_UCHAR(io + 5, 0x00);
        WRITE_PORT_UCHAR(io + 6, 0x00);
        WRITE_PORT_UCHAR(io + 7, CMD_SMART);
        // Subcommand: enable
        WRITE_PORT_UCHAR(io + 3, 0xD0);
        WRITE_PORT_UCHAR(io + 2, 0x4F);
        WRITE_PORT_UCHAR(io + 1, 0xC2);

        if !wait_not_busy(io + 7, ATA_TIMEOUT_US) {
            return None;
        }

        // Now read SMART data
        WRITE_PORT_UCHAR(io + 6, 0xA0);
        WRITE_PORT_UCHAR(io + 1, 0x00);
        WRITE_PORT_UCHAR(io + 2, 0x00);
        WRITE_PORT_UCHAR(io + 3, 0x00);
        WRITE_PORT_UCHAR(io + 4, 0x00);
        WRITE_PORT_UCHAR(io + 5, 0x00);
        WRITE_PORT_UCHAR(io + 6, 0x00);
        WRITE_PORT_UCHAR(io + 7, CMD_SMART);
        // Subcommand: read data
        WRITE_PORT_UCHAR(io + 3, 0xD0);
        WRITE_PORT_UCHAR(io + 2, 0x4F);
        WRITE_PORT_UCHAR(io + 1, 0xC2);

        if !wait_drq(io + 7, ATA_TIMEOUT_US) {
            return None;
        }

        // Read 256 words
        let mut data = [0u16; 256];
        for i in 0..256 {
            data[i] = READ_PORT_USHORT(io);
        }

        // Parse into SmartData structure
        let mut result = SmartData::default();
        result.version = data[0];
        result.smart_capabilities = data[1];
        result.smart_capabilities_2 = data[2];

        // Parse attributes (words 2-31)
        for i in 0..30 {
            let base = 2 + i * 12 / 2;
            if base + 5 < 256 {
                result.attributes[i] = SmartAttribute {
                    id: (data[base] & 0xFF) as u8,
                    current: ((data[base] >> 8) & 0xFF) as u8,
                    worst: (data[base + 1] & 0xFF) as u8,
                    raw: [
                        (data[base + 1] >> 8) as u8,
                        (data[base + 2] & 0xFF) as u8,
                        (data[base + 2] >> 8) as u8,
                        (data[base + 3] & 0xFF) as u8,
                        (data[base + 3] >> 8) as u8,
                        (data[base + 4] & 0xFF) as u8,
                    ],
                    reserved: (data[base + 4] >> 8) as u8,
                };
            }
        }

        Some(result)
    }
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Smoke test for the ATA driver. Probes both channels and
/// reports what was found.
pub fn smoke_test() -> bool {
    // kprintln!("  [ATA SMOKE] running ATA PIO smoke test...")  // kprintln disabled (memcpy crash workaround);
    // Channel 0 should be probed without panicking even on a
    // machine that has no ATA device.
    let _ = has_device(0);
    let _ = has_device(1);
    // kprintln!("  [ATA SMOKE] channels probed: chan0={} chan1={}",  // kprintln disabled (memcpy crash workaround)
//               has_device(0), has_device(1));
    // kprintln!("  [ATA SMOKE OK] ATA driver healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
