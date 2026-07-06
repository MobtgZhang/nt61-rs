//! RAM Disk Driver
//
//! A simple RAM disk implementation for filesystem testing and bootstrap.
//! Provides a block device backed by memory that can be used when
//! real disk hardware is not available.

use crate::kprintln;
use crate::mm::pool;

/// Default sector size (512 bytes)
pub const SECTOR_SIZE: usize = 512;

/// Default RAM disk size (16 MB)
pub const DEFAULT_RAM_DISK_SECTORS: usize = 32 * 1024; // 32K sectors = 16 MB

/// RAM disk state
pub struct RamDisk {
    /// Number of sectors
    sector_count: usize,
    /// Sector size in bytes
    sector_size: usize,
    /// Is the disk read-only?
    read_only: bool,
    /// Base pointer to sector data (allocated from pool)
    data: *mut u8,
}

unsafe impl Send for RamDisk {}

impl RamDisk {
    /// Create a new RAM disk with the given number of sectors.
    pub fn new(sector_count: usize) -> Option<Self> {
        let sector_size = SECTOR_SIZE;
        let total_size = sector_count * sector_size;

        if sector_count == 0 {
            return None;
        }

        // Allocate from kernel pool
        let data = pool::allocate(pool::PoolType::NonPaged, total_size) as *mut u8;
        if data.is_null() {
            return None;
        }

        // Zero the memory
        unsafe {
            core::ptr::write_bytes(data, 0, total_size);
        }

        // Initialize with valid boot sector signature
        // For FAT12/FAT16, boot sector signature is 0xAA55 at offset 510
        unsafe {
            core::ptr::write(data.add(510), 0x55);
            core::ptr::write(data.add(511), 0xAA);
        }

        Some(Self {
            sector_count,
            sector_size,
            read_only: false,
            data,
        })
    }

    /// Create a RAM disk with default size, with fallback to smaller sizes.
    /// Tries progressively larger sizes if allocation succeeds, starting from smallest.
    /// This ensures we use the smallest possible amount of pool memory.
    /// Note: RAM disk is optional for boot - if pool is tight, we skip it entirely.
    pub fn new_default() -> Option<Self> {
        // Try progressively larger sizes: 128KB -> 256KB -> 512KB
        // Start very small to conserve pool memory for system_image::build_all()
        let sizes = [
            256,        // 128 KB - minimum
            512,        // 256 KB
            1 * 1024,   // 512 KB - maximum
        ];

        for &sectors in &sizes {
            if let Some(disk) = Self::new(sectors) {
                // Successfully allocated
                return Some(disk);
            }
            // Allocation failed, try larger size
        }

        // All allocations failed - RAM disk is optional
        None
    }

    /// Get the number of sectors.
    pub fn sector_count(&self) -> usize {
        self.sector_count
    }

    /// Get the sector size.
    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Get total size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.sector_count * self.sector_size
    }

    /// Read a single sector.
    /// Returns true on success.
    pub fn read_sector(&self, sector: usize, buffer: &mut [u8]) -> bool {
        if sector >= self.sector_count {
            return false;
        }
        if buffer.len() < self.sector_size {
            return false;
        }

        let offset = sector * self.sector_size;
        unsafe {
            // Byte-by-byte read — the underlying buffer can live on
            // UC-typed MTRR memory (the UEFI boot-services data
            // region used by `winload` for its capture mirrors),
            // where `rep movsb` raises #PF. Single-byte loads
            // survive.
            let src = self.data.add(offset);
            for i in 0..self.sector_size {
                buffer[i] = core::ptr::read_volatile(src.add(i));
            }
        }
        true
    }

    /// Write a single sector.
    /// Returns true on success.
    pub fn write_sector(&mut self, sector: usize, buffer: &[u8]) -> bool {
        if sector >= self.sector_count {
            return false;
        }
        if self.read_only {
            return false;
        }
        if buffer.len() < self.sector_size {
            return false;
        }

        let offset = sector * self.sector_size;
        unsafe {
            // Byte-by-byte write — see `read_sector` for the MTRR
            // rationale.
            let dst = self.data.add(offset);
            for i in 0..self.sector_size {
                core::ptr::write_volatile(dst.add(i), buffer[i]);
            }
        }
        true
    }

    /// Read multiple consecutive sectors.
    pub fn read_sectors(&self, start_sector: usize, count: usize, buffer: &mut [u8]) -> bool {
        let total_size = count * self.sector_size;
        if start_sector + count > self.sector_count {
            return false;
        }
        if buffer.len() < total_size {
            return false;
        }

        let offset = start_sector * self.sector_size;
        unsafe {
            // Byte-by-byte read; see `read_sector` for the MTRR
            // rationale. We could in principle coalesce by
            // checking the MTRR but for now the safety win is
            // worth the perf cost on early-boot code paths.
            let src = self.data.add(offset);
            for i in 0..total_size {
                buffer[i] = core::ptr::read_volatile(src.add(i));
            }
        }
        true
    }

    /// Write multiple consecutive sectors.
    pub fn write_sectors(&mut self, start_sector: usize, count: usize, buffer: &[u8]) -> bool {
        let total_size = count * self.sector_size;
        if start_sector + count > self.sector_count {
            return false;
        }
        if self.read_only {
            return false;
        }
        if buffer.len() < total_size {
            return false;
        }

        let offset = start_sector * self.sector_size;
        unsafe {
            // Byte-by-byte write; see `read_sector` for the MTRR
            // rationale.
            let dst = self.data.add(offset);
            for i in 0..total_size {
                core::ptr::write_volatile(dst.add(i), buffer[i]);
            }
        }
        true
    }
}

impl Drop for RamDisk {
    fn drop(&mut self) {
        if !self.data.is_null() {
            let total_size = self.sector_count * self.sector_size;
            // Track how many bytes the ramdisk owned at drop time so
            // that diagnostics can verify the lifetime of allocations.
            LAST_RAMDISK_DROP_BYTES.store(
                total_size as u32,
                core::sync::atomic::Ordering::Relaxed,
            );
            {
                let _ = pool::free(self.data);
            }
        }
    }
}

/// Bytes owned by the most recently dropped `RamDisk`.
static LAST_RAMDISK_DROP_BYTES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Last observed ramdisk drop byte count.
pub fn last_ramdisk_drop_bytes() -> u32 {
    LAST_RAMDISK_DROP_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Global RAM disk instance
static RAM_DISK: crate::ke::sync::Spinlock<Option<RamDisk>> =
    crate::ke::sync::Spinlock::new(None);

/// Initialize the RAM disk.
/// RAM disk is OPTIONAL - skip if pool memory is tight to avoid crashes.
pub fn init() {
    // kprintln!("  Initializing RAM disk...")  // kprintln disabled (memcpy crash workaround);
    // Skip RAM disk initialization to conserve pool memory for critical subsystems.
    // The AHCI driver already provides disk access in this environment.
    // RAM disk can be re-enabled once pool fragmentation is resolved.
    // if let Some(disk) = RamDisk::new_default() {
    //     let mut guard = RAM_DISK.lock();
    //     *guard = Some(disk);
    // }
}

/// Read a sector from the global RAM disk.
pub fn read(sector: usize, buffer: &mut [u8]) -> bool {
    let guard = RAM_DISK.lock();
    match &*guard {
        Some(disk) => disk.read_sector(sector, buffer),
        None => false,
    }
}

/// Write a sector to the global RAM disk.
pub fn write(sector: usize, buffer: &[u8]) -> bool {
    let mut guard = RAM_DISK.lock();
    match &mut *guard {
        Some(disk) => disk.write_sector(sector, buffer),
        None => false,
    }
}

/// Get RAM disk info.
pub fn info() -> (usize, usize) {
    let guard = RAM_DISK.lock();
    match &*guard {
        Some(disk) => (disk.sector_count(), disk.sector_size()),
        None => (0, 0),
    }
}

/// Install a RAM disk that *aliases* an external (already-allocated) byte
/// buffer. This is used during early boot when the winload-captured
/// partition image (FAT32/NTFS/EXT2/3/4) lives at a UEFI-allocated
/// physical page that is identity-mapped into the kernel — we don't
/// want to copy it into the pool allocator (wasteful, and the source
/// memory may be UC-typed where `rep movsb` faults), we just want the
/// block-device layer to point at it directly.
pub fn install_from_external(base: *mut u8, total_bytes: usize, sector_size: usize, read_only: bool) -> bool {
    if base.is_null() || total_bytes == 0 || sector_size == 0 {
        return false;
    }
    let sector_count = total_bytes / sector_size;
    if sector_count == 0 {
        return false;
    }
    let disk = RamDisk {
        sector_count,
        sector_size,
        read_only,
        data: base,
    };
    let mut guard = RAM_DISK.lock();
    *guard = Some(disk);
    true
}
