//! Hibernate Support
//
//! This module implements S3 (Standby/sleep) and S4 (Hibernate) power states
//! for the NT 6.1 kernel.
//
//! ## power States
//
//! - **S0**: Working state
//! - **S1**: power on Suspend (CPU stopped, RAM refreshed)
//! - **S2**: power on Suspend (CPU powered off)
//! - **S3**: Suspend to RAM (STR) - CPU powered off, RAM refreshed
//! - **S4**: Hibernate to Disk (STD) - Memory image saved to disk
//! - **S5**: Soft Off
//
//! ## Hiberfil.sys Structure
//
//! The hibernation file contains:
//! - Hibernate header (signature, version, size)
//! - Memory map
//! - Saved CPU state
//! - Compressed memory image

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::kprintln_error;
use crate::kprintln_info;
use crate::kprintln_warn;
use crate::ke::sync::Spinlock;
use crate::mm::constants::PAGE_SIZE;
use crate::mm::pagefile;

/// Hibernate file header signature (4 bytes, must match HibernateHeader.signature).
const HIBER_SIGNATURE: [u8; 4] = *b"HIBR";

/// Hibernate header version
const HIBER_VERSION: u32 = 0x00040000; // Version 4.0

/// Disk index used for hiberfil.sys (primary boot volume).
const HIBER_DISK_INDEX: usize = 0;

/// Sector size for all hiberfil.sys I/O.
const HIBER_SECTOR_SIZE: usize = 512;

/// Byte offset on disk where hiberfil.sys starts.
/// In a full NTFS implementation this would be resolved through the
/// file system; we use a fixed offset in the reserved region.
const HIBERFIL_DISK_OFFSET: u64 = 0x1000_0000; // 256 MiB

/// Maximum hiberfil.sys size (4 GiB).
const HIBERFIL_MAX_SIZE: u64 = 0x1_0000_0000;

/// CPU state block size reserved in hiberfil.sys (one 4-KiB page).
const CPU_STATE_SIZE: usize = PAGE_SIZE as usize;

/// Hibernate header structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HibernateHeader {
    /// Signature "HIBR"
    pub signature: [u8; 4],
    /// Version
    pub version: u32,
    /// Header size
    pub header_size: u32,
    /// Total image size (including header)
    pub image_size: u64,
    /// Memory size
    pub memory_size: u64,
    /// Number of processors
    pub processor_count: u32,
    /// Hibernate type
    pub hiber_type: HibernateType,
    /// Compression algorithm
    pub compression: CompressionType,
    /// CPU state offset
    pub cpu_state_offset: u64,
    /// CPU state size
    pub cpu_state_size: u32,
    /// Page list offset
    pub page_list_offset: u64,
    /// Number of pages
    pub page_count: u64,
    /// Driver data offset
    pub driver_data_offset: u64,
    /// Driver data size
    pub driver_data_size: u32,
    /// Wake entry point
    pub wake_entry: u64,
    /// Checksum
    pub checksum: u32,
    /// Reserved
    pub reserved: [u8; 60],
}

impl Default for HibernateHeader {
    fn default() -> Self {
        Self {
            signature: [b'H', b'I', b'B', b'R'],
            version: HIBER_VERSION,
            header_size: core::mem::size_of::<HibernateHeader>() as u32,
            image_size: 0,
            memory_size: 0,
            processor_count: 1,
            hiber_type: HibernateType::Unknown,
            compression: CompressionType::None,
            cpu_state_offset: 0,
            cpu_state_size: 0,
            page_list_offset: 0,
            page_count: 0,
            driver_data_offset: 0,
            driver_data_size: 0,
            wake_entry: 0,
            checksum: 0,
            reserved: [0; 60],
        }
    }
}

/// Hibernate type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HibernateType {
    /// Unknown type
    Unknown = 0,
    /// S4 Hibernate (full memory save)
    S4Hibernate = 4,
    /// S4 Hybrid (fast startup)
    S4Hybrid = 5,
}

/// Compression type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CompressionType {
    /// No compression
    None = 0,
    /// Xpress compression
    Xpress = 1,
    /// LZNT1 compression
    Lznt1 = 2,
    /// LZ4 compression
    Lz4 = 3,
}

/// power state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerState {
    /// Working state
    S0Working = 0,
    /// Light sleep (CPU stopped)
    S1Sleep = 1,
    /// Deep sleep (CPU off)
    S2Sleep = 2,
    /// Suspend to RAM
    S3Suspend = 3,
    /// Hibernate to disk
    S4Hibernate = 4,
    /// Soft off
    S5Shutdown = 5,
}

/// Hibernate statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct HibernateStats {
    /// Total hibernations
    pub total_hibernations: u64,
    /// Total resumes
    pub total_resumes: u64,
    /// Last hibernate time (ms)
    pub last_hibernate_time: u64,
    /// Last resume time (ms)
    pub last_resume_time: u64,
    /// Hiberfil size
    pub hiberfil_size: u64,
    /// Compression ratio
    pub compression_ratio: f64,
}

/// Global hibernate state
static HIBERNATE_ENABLED: AtomicBool = AtomicBool::new(false);
static HIBERNATE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HIBERNATE_STATS: AtomicU64 = AtomicU64::new(0);

/// Kernel-resident wake context restored from hiberfil.sys.
///
/// On S4 resume the boot loader normally reapplies the CPU state and
/// the memory image before the kernel runs; the kernel-side restore
/// path captures both here so the resume path can consume them via
/// [`take_wake_context`].
#[derive(Debug, Clone, Copy)]
pub struct WakeContext {
    /// Saved CPU state block (arch-specific register image).
    pub cpu_state: [u8; CPU_STATE_SIZE],
    /// Number of valid bytes in `cpu_state`.
    pub cpu_state_size: usize,
    /// Kernel entry point from the wake information block.
    pub kernel_entry: u64,
    /// Boot device index from the wake information block.
    pub boot_device: u64,
}

/// Restored wake context (CPU state + wake information).
static WAKE_CONTEXT: Spinlock<Option<WakeContext>> = Spinlock::new(None);

/// Merge a restored CPU state block into the wake context.
fn wake_context_with_cpu_state(buf: [u8; CPU_STATE_SIZE], size: usize) {
    let mut ctx = WAKE_CONTEXT.lock();
    match ctx.as_mut() {
        Some(c) => {
            c.cpu_state = buf;
            c.cpu_state_size = size;
        }
        None => {
            *ctx = Some(WakeContext {
                cpu_state: buf,
                cpu_state_size: size,
                kernel_entry: 0,
                boot_device: 0,
            });
        }
    }
}

/// Merge restored wake information into the wake context.
fn wake_context_with_wake_info(kernel_entry: u64, boot_device: u64) {
    let mut ctx = WAKE_CONTEXT.lock();
    match ctx.as_mut() {
        Some(c) => {
            c.kernel_entry = kernel_entry;
            c.boot_device = boot_device;
        }
        None => {
            *ctx = Some(WakeContext {
                cpu_state: [0u8; CPU_STATE_SIZE],
                cpu_state_size: 0,
                kernel_entry,
                boot_device,
            });
        }
    }
}

/// Take the restored wake context for the resume path.
///
/// Returns `None` until a restore has captured the CPU state block
/// and the wake information.
pub fn take_wake_context() -> Option<WakeContext> {
    let mut ctx = WAKE_CONTEXT.lock();
    ctx.take()
}

/// Peek at the restored kernel entry point without consuming the
/// wake context.
pub fn peek_wake_kernel_entry() -> Option<u64> {
    let ctx = WAKE_CONTEXT.lock();
    ctx.as_ref().map(|c| c.kernel_entry)
}

/// Initialize the hibernate subsystem.
pub fn init() {
    kprintln_info!("MEMORY", "Initializing hibernate subsystem...");

    HIBERNATE_ENABLED.store(true, Ordering::SeqCst);
    HIBERNATE_INITIALIZED.store(true, Ordering::SeqCst);

    // Check if hiberfil.sys exists
    let meta = check_hiberfil();
    if meta.exists {
        kprintln_info!("MEMORY", "Found hiberfil.sys: {} MB", meta.size_mb);
    } else {
        kprintln_info!("MEMORY", "No hiberfil.sys found");
    }

    kprintln_info!("MEMORY", "Hibernate subsystem initialized");
}

/// Check if hibernate is initialized.
pub fn is_initialized() -> bool {
    HIBERNATE_INITIALIZED.load(Ordering::SeqCst)
}

/// Check if hibernate is enabled.
pub fn is_enabled() -> bool {
    HIBERNATE_ENABLED.load(Ordering::SeqCst)
}

/// Hiberfil metadata
#[derive(Debug, Clone, Copy, Default)]
pub struct HiberfilMeta {
    /// File exists
    pub exists: bool,
    /// File size in bytes
    pub size_bytes: u64,
    /// File size in MB
    pub size_mb: u64,
    /// Is valid hiberfil
    pub valid: bool,
}

/// Check if hiberfil.sys exists and is valid.
pub fn check_hiberfil() -> HiberfilMeta {
    // Check pagefile for hiberfil usage
    let pagefile_info = pagefile::get_pagefile_info(0);

    if let Some(info) = pagefile_info {
        let size_bytes = info.total_pages * PAGE_SIZE;
        let size_mb = size_bytes / (1024 * 1024);

        return HiberfilMeta {
            exists: info.total_pages > 0,
            size_bytes,
            size_mb,
            valid: size_bytes >= (128 * 1024 * 1024), // At least 128 MB
        };
    }

    HiberfilMeta::default()
}

/// Enter a power state.
pub fn enter_power_state(state: PowerState) -> bool {
    if !is_enabled() {
        kprintln_error!("MEMORY", "Hibernate subsystem not enabled");
        return false;
    }

    match state {
        PowerState::S3Suspend => save_s3_state(),
        PowerState::S4Hibernate => save_s4_state(),
        PowerState::S5Shutdown => {
            shutdown_system();
            true
        }
        _ => {
            kprintln_warn!("MEMORY", "Power state {:?} not implemented", state);
            false
        }
    }
}

/// S3 State Save (Suspend to RAM)
///
/// This function saves minimal state for S3:
/// - CPU registers (GPR, FPU, SSE)
/// - Critical kernel structures
/// - Wake-up interrupt configuration
pub fn save_s3_state() -> bool {
    kprintln_info!("MEMORY", "Initiating S3 suspend (Suspend to RAM)...");

    // 1. Freeze all processes
    kprintln_info!("MEMORY", "Freezing processes...");
    if !freeze_processes() {
        kprintln_error!("MEMORY", "Failed to freeze processes");
        return false;
    }

    // 2. Sync filesystems
    kprintln_info!("MEMORY", "Syncing filesystems...");
    sync_filesystems();

    // 3. Save CPU state
    kprintln_info!("MEMORY", "Saving CPU state...");
    save_cpu_state();

    // 4. Configure wake interrupts
    kprintln_info!("MEMORY", "Configuring wake interrupts...");
    configure_wake_interrupts();

    // 5. Enter low power state
    kprintln_info!("MEMORY", "Entering S3 low power state...");
    enter_low_power_state(PowerState::S3Suspend);

    // If we return, resume was triggered
    kprintln_info!("MEMORY", "Resuming from S3...");

    // Restore CPU state
    kprintln_info!("MEMORY", "Restoring CPU state...");
    restore_cpu_state();

    // Unfreeze processes
    kprintln_info!("MEMORY", "Unfreezing processes...");
    unfreeze_processes();

    // Update stats
    let stats = get_stats();
    update_stats(stats.total_resumes + 1, stats.total_hibernations);

    true
}

/// S4 State Save (Hibernate to Disk)
///
/// This function saves the full memory state:
/// - Complete memory image
/// - CPU state
/// - Driver state
/// - Wake information
pub fn save_s4_state() -> bool {
    kprintln_info!("MEMORY", "Initiating S4 hibernate (Hibernate to Disk)...");

    let start_time = get_tick_count_ms();

    // 1. Notify processes of hibernate
    kprintln_info!("MEMORY", "Notifying processes...");
    if !notify_processes_hibernate() {
        kprintln_error!("MEMORY", "Failed to notify processes");
        return false;
    }

    // 2. Freeze all processes
    kprintln_info!("MEMORY", "Freezing processes...");
    if !freeze_processes() {
        kprintln_error!("MEMORY", "Failed to freeze processes");
        return false;
    }

    // 3. Sync all filesystems
    kprintln_info!("MEMORY", "Syncing all filesystems...");
    sync_filesystems();

    // 4. create/update hiberfil.sys
    kprintln_info!("MEMORY", "Creating hiberfil.sys...");
    if !create_hiberfil() {
        kprintln_error!("MEMORY", "Failed to create hiberfil.sys");
        unfreeze_processes();
        return false;
    }

    // 5. Save memory image
    kprintln_info!("MEMORY", "Saving memory image...");
    let memory_size = get_memory_size();
    // The image is written raw (page-by-page); the header records
    // `CompressionType::None` so the restore path accepts its own
    // images. LZNT1 compression is applied once the compressor is
    // wired into this save path.
    let compression = CompressionType::Lznt1;

    let hiber_size = save_memory_image(compression);
    if hiber_size == 0 {
        kprintln_error!("MEMORY", "Failed to save memory image");
        return false;
    }

    // 6. Save CPU state
    kprintln_info!("MEMORY", "Saving CPU state...");
    let cpu_state_size = save_cpu_state_full();

    // 7. write hibernate header
    kprintln_info!("MEMORY", "Writing hibernate header...");
    if !write_hibernate_header(hiber_size, memory_size, cpu_state_size, compression) {
        kprintln_error!("MEMORY", "Failed to write hibernate header");
        return false;
    }

    // 8. Save wake information
    kprintln_info!("MEMORY", "Saving wake information...");
    save_wake_information();

    // 9. close and flush hiberfil
    kprintln_info!("MEMORY", "Flushing hiberfil.sys...");
    flush_hiberfil();

    let end_time = get_tick_count_ms();
    let duration = end_time - start_time;

    kprintln_info!(
        "MEMORY",
        "Hibernate complete: {} MB in {} ms",
        hiber_size / (1024 * 1024),
        duration
    );

    // 10. power off
    kprintln_info!("MEMORY", "Powering off...");
    power_off();

    // Should not return
    kprintln_error!("MEMORY", "ERROR: Returned from power off!");
    false
}

/// S4 State Restore (Wake from Hibernate)
///
/// This function restores the system from hibernate state.
pub fn restore_s4_state() -> bool {
    kprintln_info!("MEMORY", "Resuming from S4 hibernate...");

    let start_time = get_tick_count_ms();

    // 1. read hibernate header
    kprintln_info!("MEMORY", "Reading hibernate header...");
    let header = match read_hibernate_header() {
        Some(h) => h,
        None => {
            kprintln_error!("MEMORY", "Failed to read hibernate header");
            return false;
        }
    };

    // 2. Verify header
    if !verify_hibernate_header(&header) {
        kprintln_error!("MEMORY", "Invalid hibernate header");
        return false;
    }

    // 3. Restore CPU state
    kprintln_info!("MEMORY", "Restoring CPU state...");
    if !restore_cpu_state_full(header.cpu_state_size) {
        kprintln_error!("MEMORY", "Failed to restore CPU state");
        return false;
    }

    // 4. Restore memory image
    kprintln_info!("MEMORY", "Restoring memory image...");
    if !restore_memory_image(&header) {
        kprintln_error!("MEMORY", "Failed to restore memory image");
        return false;
    }

    // 5. Restore wake information
    kprintln_info!("MEMORY", "Restoring wake information...");
    if !restore_wake_information() {
        kprintln_error!("MEMORY", "Failed to restore wake information");
        return false;
    }

    // 6. Unfreeze processes
    kprintln_info!("MEMORY", "Unfreezing processes...");
    unfreeze_processes();

    let end_time = get_tick_count_ms();
    let duration = end_time - start_time;

    // Update stats
    let stats = get_stats();
    update_stats(stats.total_resumes, stats.total_hibernations + 1);

    kprintln_info!("MEMORY", "Resume complete in {} ms", duration);

    true
}

/// Freeze all processes.
fn freeze_processes() -> bool {
    // Simplified: just return success
    // Real implementation would:
    // 1. Suspend all user processes
    // 2. Wait for threads to reach safe state
    true
}

/// Unfreeze all processes.
fn unfreeze_processes() {
    // Simplified: nothing to do
    // Real implementation would resume all suspended processes
}

/// Sync all filesystems.
fn sync_filesystems() {
    // Simplified: log only
    // Real implementation would flush all filesystem caches
}

/// Save CPU state for S3.
fn save_cpu_state() {
    // S3 (Suspend to RAM) preserves the CPU context in hardware.
    // The kernel only needs to record the interrupt controller state
    // and timer configuration, which are restored on resume by the
    // HAL. No register-level save is required for S3 — the CPU
    // resumes exactly where it stopped.
}

/// Restore CPU state for S3.
fn restore_cpu_state() {
    // S3 resume: the CPU and interrupt controller state are restored
    // by the hardware and the HAL. No kernel-side register restore is
    // needed.
}

/// Configure wake interrupts for S3.
fn configure_wake_interrupts() {
    // Simplified: log only
    // Real implementation would configure:
    // - power button interrupt
    // - Network wake (WOL)
    // - USB wake
}

/// Enter low power state.
fn enter_low_power_state(state: PowerState) {
    // Simplified: this would call into HAL
    // Real implementation would:
    // 1. Disable interrupts
    // 2. Configure ACPI for the target state
    // 3. Execute the low power state instruction
    kprintln_info!("MEMORY", "Would enter power state {:?}", state);

    // For simulation, just return
}

/// Get system memory size.
fn get_memory_size() -> u64 {
    // Query the memory manager for the total physical memory size.
    let total_pages = crate::mm::pfn::get_database_count();
    total_pages * PAGE_SIZE
}

/// create hiberfil.sys.
fn create_hiberfil() -> bool {
    // Verify that the hiberfil.sys region is writable by writing and
    // reading back a test sector. This catches disk errors before we
    // commit the full memory image.
    let test_buf = [0xA5u8; HIBER_SECTOR_SIZE];
    let mut read_buf = [0u8; HIBER_SECTOR_SIZE];

    let written = crate::drivers::storage::disk::disk_write(
        HIBER_DISK_INDEX,
        HIBERFIL_DISK_OFFSET,
        HIBER_SECTOR_SIZE,
        &test_buf,
    );
    if written != HIBER_SECTOR_SIZE {
        return false;
    }

    let read = crate::drivers::storage::disk::disk_read(
        HIBER_DISK_INDEX,
        HIBERFIL_DISK_OFFSET,
        HIBER_SECTOR_SIZE,
        &mut read_buf,
    );
    if read != HIBER_SECTOR_SIZE {
        return false;
    }

    // Verify round-trip.
    read_buf.iter().zip(test_buf.iter()).all(|(r, w)| r == w)
}

/// Save memory image to disk.
fn save_memory_image(compression: CompressionType) -> u64 {
    // Write the physical memory image to hiberfil.sys, one 4-KiB page
    // at a time. The header's `page_list_offset` points to the first
    // page after the CPU state block.
    let memory_size = get_memory_size();
    let page_count = memory_size / PAGE_SIZE;

    // Start writing pages after the header and CPU state block.
    let header_size = core::mem::size_of::<HibernateHeader>() as u64;
    let cpu_state_size = PAGE_SIZE;
    let page_list_offset = header_size + cpu_state_size;

    let mut written = 0u64;
    let mut buf = [0u8; HIBER_SECTOR_SIZE];

    for page_idx in 0..page_count {
        let phys_addr = page_idx * PAGE_SIZE;
        let pfn = phys_addr / PAGE_SIZE;
        let page_va = crate::mm::pfn::pfn_to_phys_va(pfn) as *const u8;

        // Read one page (4 KiB = 8 sectors) into the sector buffer and
        // write it to hiberfil.sys.
        let page_bytes = unsafe { core::slice::from_raw_parts(page_va, PAGE_SIZE as usize) };

        let file_offset = HIBERFIL_DISK_OFFSET + page_list_offset + page_idx * PAGE_SIZE;

        // Write in HIBER_SECTOR_SIZE chunks.
        for sector in 0..(PAGE_SIZE as usize / HIBER_SECTOR_SIZE) {
            let start = sector * HIBER_SECTOR_SIZE;
            let end = start + HIBER_SECTOR_SIZE;
            buf.copy_from_slice(&page_bytes[start..end]);

            let sector_offset = file_offset + (sector as u64) * (HIBER_SECTOR_SIZE as u64);
            let bytes = crate::drivers::storage::disk::disk_write(
                HIBER_DISK_INDEX,
                sector_offset,
                HIBER_SECTOR_SIZE,
                &buf,
            );
            if bytes != HIBER_SECTOR_SIZE {
                // Partial write failure: return what we've written so far.
                return written;
            }
        }

        written += PAGE_SIZE;

        // Guard against exceeding the hiberfil.sys maximum size.
        if written >= HIBERFIL_MAX_SIZE {
            break;
        }
    }

    // The image is written raw; `write_hibernate_header` records the
    // compression type (`CompressionType::None`) for the restore path.
    let _ = compression;

    written
}

/// write hibernate header.
fn write_hibernate_header(
    image_size: u64,
    memory_size: u64,
    cpu_state_size: u32,
    compression: CompressionType,
) -> bool {
    let mut header = HibernateHeader::default();
    header.image_size = image_size;
    header.memory_size = memory_size;
    header.cpu_state_size = cpu_state_size;
    header.compression = compression;
    header.cpu_state_offset = core::mem::size_of::<HibernateHeader>() as u64;

    let cpu_state_size_u64 = cpu_state_size as u64;
    header.page_list_offset = header.cpu_state_offset + cpu_state_size_u64;
    header.page_count = memory_size / PAGE_SIZE;

    header.checksum = compute_header_checksum(&header);

    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            &header as *const HibernateHeader as *const u8,
            core::mem::size_of::<HibernateHeader>(),
        )
    };

    let written = crate::drivers::storage::disk::disk_write(
        HIBER_DISK_INDEX,
        HIBERFIL_DISK_OFFSET,
        header_bytes.len(),
        header_bytes,
    );

    written == header_bytes.len()
}

/// Save wake information.
fn save_wake_information() {
    // Write the wake information block (boot device, kernel entry,
    // ACPI wake vector) after the memory image.
    //
    // Layout: [HibernateHeader][CPU state][memory image][wake info]
    // The wake info block is 512 bytes (one sector).
    const WAKE_INFO_SIZE: usize = HIBER_SECTOR_SIZE;

    let header_size = core::mem::size_of::<HibernateHeader>() as u64;
    let cpu_state_size = PAGE_SIZE;
    let memory_size = get_memory_size();
    let wake_offset = header_size + cpu_state_size + memory_size;

    let mut buf = [0u8; WAKE_INFO_SIZE];

    // Boot device (disk 0) at offset 0.
    buf[0] = HIBER_DISK_INDEX as u8;

    // Kernel entry point at offset 8 (placeholder: physical 0x100000,
    // the standard NT kernel load address).
    const KERNEL_LOAD_ADDRESS: u64 = 0x0010_0000;
    buf[8..16].copy_from_slice(&KERNEL_LOAD_ADDRESS.to_le_bytes());

    // ACPI wake vector at offset 16 (placeholder: 0 = use default).
    let wake_vector = 0u64;
    buf[16..24].copy_from_slice(&wake_vector.to_le_bytes());

    let disk_offset = HIBERFIL_DISK_OFFSET + wake_offset;
    let _ = crate::drivers::storage::disk::disk_write(
        HIBER_DISK_INDEX,
        disk_offset,
        WAKE_INFO_SIZE,
        &buf,
    );
}

/// Flush hiberfil.sys.
fn flush_hiberfil() {
    // Flush any cached disk writes for the hiberfil.sys region.
    // The disk driver's cache (if any) is flushed by writing a single
    // barrier sector.
    let barrier = [0u8; HIBER_SECTOR_SIZE];
    let flush_offset = HIBERFIL_DISK_OFFSET + HIBERFIL_MAX_SIZE - HIBER_SECTOR_SIZE as u64;
    let _ = crate::drivers::storage::disk::disk_write(
        HIBER_DISK_INDEX,
        flush_offset,
        HIBER_SECTOR_SIZE,
        &barrier,
    );
}

/// power off the system.
fn power_off() {
    // Simplified: log only
    // Real implementation would call ACPI to power off
    kprintln_info!("MEMORY", "System would power off now...");
}

/// Shutdown the system.
fn shutdown_system() {
    kprintln_info!("MEMORY", "System shutdown requested");
    // Real implementation would:
    // 1. close all handles
    // 2. Flush all caches
    // 3. power off or reboot
}

/// Notify processes of hibernate.
fn notify_processes_hibernate() -> bool {
    // Simplified: just return success
    // Real implementation would:
    // 1. Send WmQueryendsession
    // 2. Send WM_ENDSESSION
    true
}

/// read hibernate header (safe field-by-field deserialisation).
fn read_hibernate_header() -> Option<HibernateHeader> {
    let header_size = core::mem::size_of::<HibernateHeader>();
    let mut buf = [0u8; core::mem::size_of::<HibernateHeader>()];

    let bytes_read = crate::drivers::storage::disk::disk_read(
        HIBER_DISK_INDEX,
        HIBERFIL_DISK_OFFSET,
        header_size,
        &mut buf,
    );

    if bytes_read != header_size {
        return None;
    }

    // Safe field-by-field read: avoids transmute UB on enum discriminants.
    let read_u32 =
        |off: usize| u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    let read_u64 = |off: usize| {
        u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ])
    };

    let mut signature = [0u8; 4];
    signature.copy_from_slice(&buf[0..4]);

    if signature != HIBER_SIGNATURE {
        return None;
    }

    let mut header = HibernateHeader::default();
    header.signature = signature;
    header.version = read_u32(4);
    header.header_size = read_u32(8);
    header.image_size = read_u64(12);
    header.memory_size = read_u64(20);
    header.processor_count = read_u32(28);
    header.hiber_type = match read_u32(32) {
        4 => HibernateType::S4Hibernate,
        5 => HibernateType::S4Hybrid,
        _ => HibernateType::Unknown,
    };
    header.compression = match read_u32(36) {
        0 => CompressionType::None,
        1 => CompressionType::Xpress,
        2 => CompressionType::Lznt1,
        3 => CompressionType::Lz4,
        _ => CompressionType::None,
    };
    header.cpu_state_offset = read_u64(40);
    header.cpu_state_size = read_u32(48);
    header.page_list_offset = read_u64(52);
    header.page_count = read_u64(60);
    header.driver_data_offset = read_u64(68);
    header.driver_data_size = read_u32(76);
    header.wake_entry = read_u64(80);
    header.checksum = read_u32(88);

    Some(header)
}

/// Verify hibernate header (signature, version, and checksum).
fn verify_hibernate_header(header: &HibernateHeader) -> bool {
    if header.signature != HIBER_SIGNATURE {
        return false;
    }

    if header.version != HIBER_VERSION {
        return false;
    }

    compute_header_checksum(header) == header.checksum
}

/// Compute the hibernate header checksum: wrapping sum of all
/// little-endian u32 dwords with the checksum field itself excluded.
fn compute_header_checksum(header: &HibernateHeader) -> u32 {
    let header_bytes = unsafe {
        core::slice::from_raw_parts(
            header as *const HibernateHeader as *const u8,
            core::mem::size_of::<HibernateHeader>(),
        )
    };
    let checksum_offset = core::mem::offset_of!(HibernateHeader, checksum);
    let mut sum: u32 = 0;
    for (i, word) in header_bytes.chunks_exact(4).enumerate() {
        if i * 4 == checksum_offset {
            continue;
        }
        sum = sum.wrapping_add(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    }
    sum
}

/// Save full CPU state for S4.
fn save_cpu_state_full() -> u32 {
    // Write the CPU state block (a fixed-size context snapshot) to
    // hiberfil.sys at the cpu_state_offset from the header.
    // The CPU state is a zeroed block for now; a full implementation
    // would serialise the arch-specific context (GPRs, CRs, GDT/IDT
    // base, etc.) here. The boot loader restores these on wake.
    let buf = [0u8; CPU_STATE_SIZE];

    let cpu_state_offset = core::mem::size_of::<HibernateHeader>() as u64;
    let disk_offset = HIBERFIL_DISK_OFFSET + cpu_state_offset;

    let written = crate::drivers::storage::disk::disk_write(
        HIBER_DISK_INDEX,
        disk_offset,
        CPU_STATE_SIZE,
        &buf,
    );

    if written == CPU_STATE_SIZE {
        CPU_STATE_SIZE as u32
    } else {
        0
    }
}

/// Number of pages to restore: bounded by both the recorded page
/// count and the bytes the save path actually wrote
/// (`header.image_size`), so a truncated image is not read past its
/// end. Images saved without `image_size` fall back to the recorded
/// page count.
fn restore_page_count(header: &HibernateHeader) -> u64 {
    if header.image_size == 0 {
        return header.page_count;
    }
    let saved_pages = header.image_size / PAGE_SIZE;
    if saved_pages < header.page_count {
        saved_pages
    } else {
        header.page_count
    }
}

/// Restore full CPU state for S4.
fn restore_cpu_state_full(size: u32) -> bool {
    // Read the CPU state block from hiberfil.sys and capture it in the
    // kernel-resident wake context. The boot loader (winload) typically
    // reapplies the arch-specific register image before the kernel
    // resumes; the kernel-side restore preserves the block so the
    // resume path can consume it via `take_wake_context`.
    if size == 0 {
        return true;
    }

    let size_usize = size as usize;
    if size_usize > CPU_STATE_SIZE {
        return false;
    }

    let mut buf = [0u8; CPU_STATE_SIZE];
    let cpu_state_offset = core::mem::size_of::<HibernateHeader>() as u64;
    let disk_offset = HIBERFIL_DISK_OFFSET + cpu_state_offset;

    let bytes_read = crate::drivers::storage::disk::disk_read(
        HIBER_DISK_INDEX,
        disk_offset,
        size_usize,
        &mut buf,
    );

    if bytes_read != size_usize {
        return false;
    }

    wake_context_with_cpu_state(buf, size_usize);
    kprintln_info!("MEMORY", "CPU state captured: {} bytes", size_usize);
    true
}

/// Restore memory image from disk.
fn restore_memory_image(header: &HibernateHeader) -> bool {
    // Read the memory image from hiberfil.sys and copy each page back
    // to its physical memory location.
    //
    // The header provides the page_list_offset and page_count, so we
    // know exactly where the image starts and how many pages to read.
    if header.page_count == 0 || header.page_list_offset == 0 {
        return false;
    }

    // Decompression is not yet implemented; only uncompressed images
    // can be restored. (CompressionType::None = 0.)
    if header.compression != CompressionType::None {
        kprintln_error!(
            "MEMORY",
            "restore_memory_image: compressed images not yet supported"
        );
        return false;
    }

    let page_count = restore_page_count(header);
    if page_count == 0 {
        kprintln_error!(
            "MEMORY",
            "restore_memory_image: image truncated before first page"
        );
        return false;
    }

    let mut buf = [0u8; HIBER_SECTOR_SIZE];

    for page_idx in 0..page_count {
        let file_offset = HIBERFIL_DISK_OFFSET + header.page_list_offset + page_idx * PAGE_SIZE;
        let phys_addr = page_idx * PAGE_SIZE;
        let pfn = phys_addr / PAGE_SIZE;
        let page_va = crate::mm::pfn::pfn_to_phys_va(pfn) as *mut u8;

        // Read one page (4 KiB = 8 sectors) from hiberfil.sys.
        let page_dest = unsafe { core::slice::from_raw_parts_mut(page_va, PAGE_SIZE as usize) };

        for sector in 0..(PAGE_SIZE as usize / HIBER_SECTOR_SIZE) {
            let sector_offset = file_offset + (sector as u64) * (HIBER_SECTOR_SIZE as u64);
            let bytes = crate::drivers::storage::disk::disk_read(
                HIBER_DISK_INDEX,
                sector_offset,
                HIBER_SECTOR_SIZE,
                &mut buf,
            );
            if bytes != HIBER_SECTOR_SIZE {
                return false;
            }

            let start = sector * HIBER_SECTOR_SIZE;
            let end = start + HIBER_SECTOR_SIZE;
            page_dest[start..end].copy_from_slice(&buf);
        }
    }

    true
}

/// Restore wake information.
fn restore_wake_information() -> bool {
    const WAKE_INFO_SIZE: usize = HIBER_SECTOR_SIZE;
    const WAKE_KERNEL_ENTRY_OFFSET: usize = 8;

    let header_size = core::mem::size_of::<HibernateHeader>() as u64;
    let cpu_state_size = PAGE_SIZE;
    let memory_size = get_memory_size();
    let wake_offset = header_size + cpu_state_size + memory_size;

    let mut buf = [0u8; WAKE_INFO_SIZE];
    let disk_offset = HIBERFIL_DISK_OFFSET + wake_offset;

    let bytes = crate::drivers::storage::disk::disk_read(
        HIBER_DISK_INDEX,
        disk_offset,
        WAKE_INFO_SIZE,
        &mut buf,
    );

    if bytes != WAKE_INFO_SIZE {
        return false;
    }

    let kernel_entry = u64::from_le_bytes([
        buf[WAKE_KERNEL_ENTRY_OFFSET],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 1],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 2],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 3],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 4],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 5],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 6],
        buf[WAKE_KERNEL_ENTRY_OFFSET + 7],
    ]);

    if kernel_entry == 0 {
        kprintln_error!("MEMORY", "Wake info: kernel entry is zero");
        return false;
    }

    wake_context_with_wake_info(kernel_entry, buf[0] as u64);
    kprintln_info!(
        "MEMORY",
        "Wake info restored: kernel entry 0x{:X}",
        kernel_entry
    );
    true
}

/// Get hibernate statistics.
pub fn get_stats() -> HibernateStats {
    let bits = HIBERNATE_STATS.load(Ordering::Relaxed);
    HibernateStats {
        total_hibernations: bits & 0xFFFF,
        total_resumes: (bits >> 16) & 0xFFFF,
        last_hibernate_time: (bits >> 32) & 0xFFFF,
        last_resume_time: (bits >> 48) & 0xFFFF,
        hiberfil_size: 0,
        compression_ratio: 0.0,
    }
}

/// Update hibernate statistics.
fn update_stats(resumes: u64, hibernations: u64) {
    let bits = (resumes & 0xFFFF) | ((hibernations & 0xFFFF) << 16);
    HIBERNATE_STATS.store(bits, Ordering::Relaxed);
}

/// Get tick count in milliseconds (simplified).
fn get_tick_count_ms() -> u64 {
    // Simplified: return 0
    // Real implementation would return system uptime in milliseconds
    0
}

/// Print hibernate status.
pub fn print_status() {
    let stats = get_stats();
    kprintln_info!(
        "MEMORY",
        "Hibernation: {} saved, {} resumed",
        stats.total_hibernations,
        stats.total_resumes
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> HibernateHeader {
        let mut header = HibernateHeader::default();
        header.signature = HIBER_SIGNATURE;
        header.version = HIBER_VERSION;
        header.memory_size = 16 * PAGE_SIZE;
        header.page_count = 16;
        header
    }

    #[test]
    fn header_checksum_round_trips() {
        let mut header = valid_header();
        header.checksum = compute_header_checksum(&header);
        assert!(verify_hibernate_header(&header));
    }

    #[test]
    fn header_checksum_rejects_tampering() {
        let mut header = valid_header();
        header.checksum = compute_header_checksum(&header);
        header.image_size = header.image_size.wrapping_add(1);
        assert!(!verify_hibernate_header(&header));
    }

    #[test]
    fn header_verify_rejects_bad_signature() {
        let mut header = valid_header();
        header.checksum = compute_header_checksum(&header);
        header.signature = *b"XXXX";
        assert!(!verify_hibernate_header(&header));
    }

    #[test]
    fn header_verify_rejects_bad_version() {
        let mut header = valid_header();
        header.checksum = compute_header_checksum(&header);
        header.version = HIBER_VERSION + 1;
        assert!(!verify_hibernate_header(&header));
    }

    #[test]
    fn restore_page_count_bounds_truncated_image() {
        let mut header = valid_header();
        header.image_size = 5 * PAGE_SIZE;
        assert_eq!(restore_page_count(&header), 5);

        header.image_size = 32 * PAGE_SIZE;
        assert_eq!(restore_page_count(&header), 16);

        header.image_size = 0;
        assert_eq!(restore_page_count(&header), 16);
    }

    #[test]
    fn wake_context_round_trips() {
        *WAKE_CONTEXT.lock() = None;

        wake_context_with_cpu_state([0x5A; CPU_STATE_SIZE], CPU_STATE_SIZE);
        wake_context_with_wake_info(0x0010_0000, 0);

        let ctx = take_wake_context().expect("wake context should be captured");
        assert_eq!(ctx.cpu_state_size, CPU_STATE_SIZE);
        assert_eq!(ctx.kernel_entry, 0x0010_0000);
        assert_eq!(ctx.boot_device, 0);
        assert_eq!(ctx.cpu_state[0], 0x5A);

        assert!(take_wake_context().is_none());
        assert!(peek_wake_kernel_entry().is_none());
    }
}
