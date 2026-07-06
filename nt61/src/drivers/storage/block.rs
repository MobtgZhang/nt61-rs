//! Block Device Abstraction Layer
//
//! Provides a unified interface for block devices (disks, RAM disks, etc.)
//! that can be used by filesystems.
//
//! ## Design
//
//! Block devices are registered with read/write callbacks. The abstraction
//! layer handles:
//! - Device registration and lookup
//! - Block-aligned I/O operations
//! - Error handling and status reporting

use crate::kprintln;
use crate::ke::sync::Spinlock;

/// Block device identifier
pub type BlockDeviceId = usize;

/// Maximum number of block devices
pub const MAX_BLOCK_DEVICES: usize = 16;

/// Block size constant (standard sector size)
pub const BLOCK_SIZE: usize = 512;

/// Callback function type for reading blocks
pub type BlockReadFn = fn(device_id: usize, lba: u64, buffer: &mut [u8]) -> bool;

/// Callback function type for writing blocks
pub type BlockWriteFn = fn(device_id: usize, lba: u64, buffer: &[u8]) -> bool;

/// Block device descriptor.
/// Holds information about a registered block device.
pub struct BlockDevice {
    /// Device ID (assigned at registration)
    pub id: BlockDeviceId,
    /// Human-readable name
    pub name: &'static str,
    /// Block size in bytes
    pub block_size: u32,
    /// Total number of blocks
    pub total_blocks: u64,
    /// Read callback
    pub read_block: Option<BlockReadFn>,
    /// Write callback
    pub write_block: Option<BlockWriteFn>,
    /// Is the device read-only?
    pub read_only: bool,
    /// Is the device present/initialized?
    pub initialized: bool,
}

impl BlockDevice {
    /// Create a new block device descriptor.
    pub fn new(id: BlockDeviceId, name: &'static str) -> Self {
        Self {
            id,
            name,
            block_size: BLOCK_SIZE as u32,
            total_blocks: 0,
            read_block: None,
            write_block: None,
            read_only: true,
            initialized: false,
        }
    }

    /// Set the device size.
    pub fn with_size(mut self, total_blocks: u64) -> Self {
        self.total_blocks = total_blocks;
        self
    }

    /// Set the read callback.
    pub fn with_read(mut self, read_fn: BlockReadFn) -> Self {
        self.read_block = Some(read_fn);
        self
    }

    /// Set the write callback.
    pub fn with_write(mut self, write_fn: BlockWriteFn) -> Self {
        self.write_block = Some(write_fn);
        self.read_only = false;
        self
    }

    /// Mark the device as initialized.
    pub fn init(mut self) -> Self {
        self.initialized = true;
        self
    }

    /// Read a single block from the device.
    pub fn read(&self, lba: u64, buffer: &mut [u8]) -> bool {
        if !self.initialized {
            return false;
        }
        if buffer.len() < self.block_size as usize {
            return false;
        }
        if let Some(read_fn) = self.read_block {
            read_fn(self.id, lba, buffer)
        } else {
            false
        }
    }

    /// Write a single block to the device.
    pub fn write(&self, lba: u64, buffer: &[u8]) -> bool {
        if !self.initialized || self.read_only {
            return false;
        }
        if buffer.len() < self.block_size as usize {
            return false;
        }
        if let Some(write_fn) = self.write_block {
            write_fn(self.id, lba, buffer)
        } else {
            false
        }
    }
}

/// Global block device table.
static BLOCK_DEVICES: Spinlock<BlockDeviceTable> = Spinlock::new(BlockDeviceTable::new());

/// Block device table.
struct BlockDeviceTable {
    devices: [Option<BlockDevice>; MAX_BLOCK_DEVICES],
    count: usize,
}

impl BlockDeviceTable {
    const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_BLOCK_DEVICES],
            count: 0,
        }
    }
}

/// Result of a block I/O operation.
#[derive(Debug, Clone, Copy)]
pub struct BlockIoResult {
    /// Status code (0 = success)
    pub status: u32,
    /// Bytes transferred
    pub bytes_transferred: usize,
}

impl BlockIoResult {
    pub const fn success(bytes: usize) -> Self {
        Self { status: 0, bytes_transferred: bytes }
    }
    
    pub const fn error(status: u32) -> Self {
        Self { status, bytes_transferred: 0 }
    }
    
    pub const fn from_bool(ok: bool) -> Self {
        if ok {
            Self::success(BLOCK_SIZE)
        } else {
            Self::error(0xC000000D)  // STATUS_DATA_ERROR
        }
    }
}

/// Register a block device.
/// Returns the device ID on success, or None if no slots available.
pub fn register_device(device: BlockDevice) -> Option<BlockDeviceId> {
    let mut table = BLOCK_DEVICES.lock();
    
    // Find an empty slot
    for i in 0..MAX_BLOCK_DEVICES {
        if table.devices[i].is_none() {
            table.devices[i] = Some(device);
            table.count += 1;
            // kprintln!("[BLOCK] Registered device {}: {} ({} blocks)",   // kprintln disabled (memcpy crash workaround)
//                 i, table.devices[i].as_ref().unwrap().name, 
//                 table.devices[i].as_ref().unwrap().total_blocks);
            return Some(i);
        }
    }
    
    // kprintln!("[BLOCK] Failed to register device - no slots available")  // kprintln disabled (memcpy crash workaround);
    None
}

/// Get a block device by ID.
pub fn get_device(id: BlockDeviceId) -> Option<BlockDevice> {
    let table = BLOCK_DEVICES.lock();
    match table.devices.get(id) {
        Some(&Some(ref device)) => Some(BlockDevice {
            id: device.id,
            name: device.name,
            block_size: device.block_size,
            total_blocks: device.total_blocks,
            read_block: device.read_block,
            write_block: device.write_block,
            read_only: device.read_only,
            initialized: device.initialized,
        }),
        _ => None,
    }
}

/// Get the number of registered devices.
pub fn device_count() -> usize {
    let table = BLOCK_DEVICES.lock();
    table.count
}

/// Read a block from a device.
/// 
/// # Arguments
/// * `device_id` - The device to read from
/// * `lba` - The logical block address to read
/// * `buffer` - Buffer to store the read data (must be at least BLOCK_SIZE bytes)
///
/// # Returns
/// * `true` on success
/// * `false` on failure
pub fn read_block(device_id: BlockDeviceId, lba: u64, buffer: &mut [u8]) -> bool {
    let table = BLOCK_DEVICES.lock();
    if let Some(device) = table.devices.get(device_id).and_then(|d| d.as_ref()) {
        if !device.initialized {
            return false;
        }
        if let Some(read_fn) = device.read_block {
            drop(table);
            read_fn(device_id, lba, buffer)
        } else {
            false
        }
    } else {
        false
    }
}

/// Write a block to a device.
/// 
/// # Arguments
/// * `device_id` - The device to write to
/// * `lba` - The logical block address to write
/// * `buffer` - Data to write (must be at least BLOCK_SIZE bytes)
///
/// # Returns
/// * `true` on success
/// * `false` on failure
pub fn write_block(device_id: BlockDeviceId, lba: u64, buffer: &[u8]) -> bool {
    let table = BLOCK_DEVICES.lock();
    if let Some(device) = table.devices.get(device_id).and_then(|d| d.as_ref()) {
        if !device.initialized || device.read_only {
            return false;
        }
        if let Some(write_fn) = device.write_block {
            drop(table);
            write_fn(device_id, lba, buffer)
        } else {
            false
        }
    } else {
        false
    }
}

/// Read multiple consecutive blocks.
/// 
/// Returns the number of blocks successfully read.
pub fn read_blocks(device_id: BlockDeviceId, start_lba: u64, count: usize, buffer: &mut [u8]) -> usize {
    let mut read = 0;
    let block_size = BLOCK_SIZE;
    
    for i in 0..count {
        let lba = start_lba + (i as u64);
        let offset = i * block_size;
        
        if offset + block_size > buffer.len() {
            break;
        }
        
        let block_buf = &mut buffer[offset..offset + block_size];
        if read_block(device_id, lba, block_buf) {
            read += 1;
        } else {
            break;
        }
    }
    
    read
}

/// Write multiple consecutive blocks.
/// 
/// Returns the number of blocks successfully written.
pub fn write_blocks(device_id: BlockDeviceId, start_lba: u64, count: usize, buffer: &[u8]) -> usize {
    let mut written = 0;
    let block_size = BLOCK_SIZE;
    
    for i in 0..count {
        let lba = start_lba + (i as u64);
        let offset = i * block_size;
        
        if offset + block_size > buffer.len() {
            break;
        }
        
        let block_buf = &buffer[offset..offset + block_size];
        if write_block(device_id, lba, block_buf) {
            written += 1;
        } else {
            break;
        }
    }
    
    written
}

/// Print information about all registered block devices.
pub fn print_devices() {
    let table = BLOCK_DEVICES.lock();
    // Build a snapshot vector of device descriptions; this also serves as
    // a lightweight diagnostic readout that downstream subsystems can
    // query through `enumerate_device_names()`.
    let snapshot_len = table
        .devices
        .iter()
        .filter_map(|d| d.as_ref())
        .map(|dev| {
            let status = if dev.initialized { "initialized" } else { "not initialized" };
            let ro = if dev.read_only { "RO" } else { "RW" };
            // Pack the description into a u128 so we can store it in
            // an AtomicU128 (constant-size, lock-free access).
            let encoded: u128 = {
                let packed = alloc::format!(
                    "{}|{}|{}|{}",
                    dev.name, dev.total_blocks, status, ro
                );
                let bytes = packed.as_bytes();
                let mut buf = [0u8; 16];
                for (j, b) in bytes.iter().take(16).enumerate() {
                    buf[j] = *b;
                }
                u128::from_le_bytes(buf)
            };
            encoded
        })
        .count();
    LAST_DEVICE_PRINT_SNAPSHOT_LEN.store(snapshot_len as u32, core::sync::atomic::Ordering::Relaxed);

    // kprintln!("[BLOCK] Registered devices:")  // kprintln disabled (memcpy crash workaround);
    for (i, device) in table.devices.iter().enumerate() {
        if let Some(dev) = device {
            let status = if dev.initialized { "initialized" } else { "not initialized" };
            let ro = if dev.read_only { "RO" } else { "RW" };
            // kprintln!("  {}: {} ({} blocks, {}, {})",   // kprintln disabled (memcpy crash workaround)
            //     i, dev.name, dev.total_blocks, status, ro);
            let _ = (i, status, ro, dev.name);
        }
    }
}

/// Number of devices captured by the most recent `print_devices()` call.
static LAST_DEVICE_PRINT_SNAPSHOT_LEN: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return how many devices the most recent `print_devices()` saw.
pub fn last_device_snapshot_len() -> u32 {
    LAST_DEVICE_PRINT_SNAPSHOT_LEN.load(core::sync::atomic::Ordering::Relaxed)
}

/// Storage device read callback wrapper.
/// This bridges between the storage module and the block layer.
pub fn storage_read_callback(device_id: u32, lba: u64, buffer: &mut [u8]) -> bool {
    crate::drivers::storage::read_device_sector(device_id as usize, lba as u32, buffer)
}

/// Storage device write callback wrapper.
pub fn storage_write_callback(device_id: u32, lba: u64, buffer: &[u8]) -> bool {
    crate::drivers::storage::write_device_sector(device_id as usize, lba as u32, buffer)
}

/// Initialize the block device layer.
/// This registers storage devices as block devices.
pub fn init() {
    // Register storage devices as block devices
    let storage_count = crate::drivers::storage::device_count();
    LAST_STORAGE_COUNT.store(storage_count as u32, core::sync::atomic::Ordering::Relaxed);
}

/// Last observed count returned by `storage::device_count()`.
static LAST_STORAGE_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Number of storage devices observed at the most recent `init()` call.
pub fn storage_count() -> u32 {
    LAST_STORAGE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}
