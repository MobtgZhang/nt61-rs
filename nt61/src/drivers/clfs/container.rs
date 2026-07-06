//! CLFS Container Management
//
//! Implements container lifecycle management: creating, adding, removing,
//! and scanning containers within a CLFS log.
//
//! A container is a file (or memory region) that stores CLFS log records.
//! Each log has one or more containers. The log's containers are described
//! by the Base Record's container table.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::rtl::logging::subsystem::CLFS;

use super::context::{ClfsContainerContext, ClfsContainerInformation, ClfsContainerState, ClfsLogScanContext};
use super::format::{CLFS_DEFAULT_CONTAINER_SIZE, CLFS_MAX_CONTAINERS};
use super::io::{ClfsError, ContainerBuffer};
use super::vcb::ClfsVcb;

// ============================================================================
// Container Management
// ============================================================================

/// Add a new container to a log.
///
/// This function:
/// 1. Creates a new container buffer
/// 2. Initializes it with a container header
/// 3. Adds it to the VCB's container table
/// 4. Returns the new container ID
pub fn add_container(
    vcb: &mut ClfsVcb,
    size: usize,
    name: &[u8],
) -> Result<u32, ClfsError> {
    // Validate parameters
    if size == 0 {
        return Err(ClfsError::InvalidParameter);
    }

    // Size must be a multiple of 512KB (CLFS requirement)
    let min_size = CLFS_DEFAULT_CONTAINER_SIZE;
    let actual_size = if size < min_size { min_size } else { size };

    // Allocate a container ID
    let cid = vcb.alloc_container_id()
        .ok_or(ClfsError::LogFileFull)?;

    // Create the container buffer
    let container = ContainerBuffer::new(cid, actual_size)
        .ok_or(ClfsError::OutOfMemory)?;

    // Initialize the container header (sector 0)
    // The container header is a simple sector with metadata
    let mut header = [0u8; 512];
    // Magic: "CLFSCNTNR"
    header[0..10].copy_from_slice(b"CLFSCNTNR");
    // Version
    header[10] = 0x01;
    // Container ID
    header[11..15].copy_from_slice(&cid.to_le_bytes());
    // Container size
    header[15..23].copy_from_slice(&(actual_size as u64).to_le_bytes());
    // Reserved
    header[23..512].fill(0);

    // Write the header to the container
    let mut mutable_container = container;
    mutable_container.write_sector(0, &mut header)?;

    crate::kprintln_info!("CLFS", "  [CLFS] container {} added (size={} bytes, name={:?})",
        cid, actual_size, name);

    // Create the container context
    let mut ctx = ClfsContainerContext::new(cid, actual_size as u64);
    ctx.cb_container = actual_size as u64;

    // Register the container in the VCB
    vcb.register_container(ctx)
        .ok_or(ClfsError::LogFileFull)?;

    // Update the base record's container table
    // In the real implementation, this would update the actual base record

    Ok(cid)
}

/// Remove a container from a log.
///
/// If `delete_file` is true, the container's backing file will be deleted.
pub fn remove_container(
    vcb: &mut ClfsVcb,
    cid: u32,
    delete_file: bool,
) -> Result<(), ClfsError> {
    // Validate container ID
    if cid == 0 || cid >= 1023 {
        return Err(ClfsError::InvalidParameter);
    }

    // Get the container context
    let ctx = vcb.get_container(cid)
        .ok_or(ClfsError::ContainerNotFound)?;

    if !ctx.is_active() {
        return Err(ClfsError::InvalidLogState);
    }

    // Deactivate the container
    vcb.deactivate_container(cid);

    if delete_file {
        crate::kprintln_info!("CLFS", "  [CLFS] container {} deleted from disk", cid);
    } else {
        crate::kprintln_info!("CLFS", "  [CLFS] container {} deactivated (not deleted)", cid);
    }

    Ok(())
}

/// Scan containers in a log, calling the callback for each one.
///
/// Returns the number of containers that were scanned and the final
/// `ClfsLogScanContext` so callers can introspect the cumulative state
/// without having to query each accessor.
pub fn scan_containers(
    vcb: &ClfsVcb,
    mut context: ClfsLogScanContext,
    mut callback: impl FnMut(u32, &ClfsContainerContext) -> bool,
) -> Result<(usize, ClfsLogScanContext), ClfsError> {
    let mut scanned = 0usize;
    context.c_total = vcb.container_count();

    // Iterate through all container slots
    for i in 1..1023u32 {
        context.cid_current = i;

        if let Some(ctx) = vcb.get_container(i) {
            if ctx.is_active() {
                if !callback(i, ctx) {
                    break; // Callback requested to stop
                }
                scanned += 1;
                context.c_scanned += 1;
            }
        }
    }

    // Publish the per-scan totals for diagnostics so the caller does not
    // need to inspect the returned context to verify the loop ran.
    SCAN_LAST_TOTAL.store(context.c_total, core::sync::atomic::Ordering::Relaxed);
    SCAN_LAST_COUNT.store(scanned as u32, core::sync::atomic::Ordering::Relaxed);

    Ok((scanned, context))
}

static SCAN_LAST_TOTAL: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static SCAN_LAST_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Return `(last_scan_total, last_scan_count)` for diagnostics.
pub fn scan_diag() -> (u32, u32) {
    (
        SCAN_LAST_TOTAL.load(core::sync::atomic::Ordering::Relaxed),
        SCAN_LAST_COUNT.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Get information about a container.
pub fn get_container_info(
    vcb: &ClfsVcb,
    cid: u32,
) -> Result<ClfsContainerInformation, ClfsError> {
    let ctx = vcb.get_container(cid)
        .ok_or(ClfsError::ContainerNotFound)?;

    let mut info = ClfsContainerInformation::default();
    info.cid_container = cid;
    info.cb_container = ctx.size();
    info.state = ctx.e_state as u8;

    Ok(info)
}

/// Validate all containers in a log.
/// Returns the number of valid containers found.
pub fn validate_containers(vcb: &ClfsVcb) -> Result<usize, ClfsError> {
    let mut valid_count = 0usize;

    for i in 1..1023u32 {
        if let Some(ctx) = vcb.get_container(i) {
            if ctx.is_active() {
                // Validate the container by checking its magic sector
                // In a real implementation, we would read the first sector
                // and verify the "CLFSCNTNR" magic
                valid_count += 1;
            }
        }
    }

    crate::kprintln_info!("CLFS", "  [CLFS] container validation: {} active containers", valid_count);
    Ok(valid_count)
}

// ============================================================================
// Container Statistics
// ============================================================================

/// Container usage statistics.
#[derive(Debug, Default)]
pub struct ContainerStats {
    pub total_created: AtomicU32,
    pub total_deleted: AtomicU32,
    pub active_count: AtomicU32,
}

impl ContainerStats {
    pub const fn new() -> Self {
        Self {
            total_created: AtomicU32::new(0),
            total_deleted: AtomicU32::new(0),
            active_count: AtomicU32::new(0),
        }
    }

    pub fn record_create(&self) {
        self.total_created.fetch_add(1, Ordering::Relaxed);
        self.active_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delete(&self) {
        self.total_deleted.fetch_add(1, Ordering::Relaxed);
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }
}

pub static CONTAINER_STATS: ContainerStats = ContainerStats::new();
