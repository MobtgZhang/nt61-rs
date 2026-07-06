//! CLFS Volume Control Block (VCB)
//
//! The VCB represents one open CLFS log (one .blf file + its containers).
//! It is the root data structure for all CLFS operations.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::rtl::logging::subsystem::CLFS;

use super::context::{ClfsContainerContext, ClfsClientContext, ClfsContainerState};
use super::format::{BlfMetadata, CLFS_DEFAULT_CONTAINER_SIZE};
use super::metadata::{ClfsBaseRecordHeader, ClfsControlRecord, ClfsLogState};
use super::record::ClfsLsn;

// ============================================================================
// Access Mode Flags
// ============================================================================

/// Desired access mode flags for opening a log.
pub const CLFS_FLAG_CREATE:          u32 = 0x0000_0001; // Create new log
pub const CLFS_FLAG_OPEN_EXISTING:   u32 = 0x0000_0002; // Open existing log
pub const CLFS_FLAG_FORCE_APPEND:    u32 = 0x0000_0004; // Force append mode
pub const CLFS_FLAG_FORCE_SEQUENCE:  u32 = 0x0000_0008; // Force sequential access

/// Share mode flags.
pub const CLFS_SHARE_READ:   u32 = 0x0000_0001;
pub const CLFS_SHARE_WRITE:  u32 = 0x0000_0002;

/// Create disposition flags.
pub const CLFS_CREATE_NEW:         u32 = 0x0000_0001;
pub const CLFS_CREATE_ALWAYS:      u32 = 0x0000_0002;
pub const CLFS_OPEN_EXISTING:      u32 = 0x0000_0003;
pub const CLFS_OPEN_ALWAYS:        u32 = 0x0000_0004;
pub const CLFS_TRUNCATE_EXISTING:  u32 = 0x0000_0005;

// ============================================================================
// VCB Structure
// ============================================================================

/// Volume Control Block — represents one open CLFS log.
///
/// The VCB is the root of the CLFS in-memory data structures. It holds
/// the log's metadata, all client contexts, all container contexts,
/// and the LSN allocation state.
pub struct ClfsVcb {
    /// Reference count — incremented for each FCB that references this VCB.
    pub ref_count: AtomicU32,

    /// Log name (Unicode16, null-terminated).
    pub name: [u16; 260],
    /// Length of the name in bytes.
    pub name_len: usize,

    /// Current log state.
    pub state: ClfsLogState,

    /// Control record — loaded from the BLF file.
    pub control_record: ClfsControlRecord,

    /// Base record — loaded from the BLF file.
    pub base_record: ClfsBaseRecordHeader,

    /// BLF metadata blocks (in-memory copy of the 6 metadata sectors).
    pub blf_metadata: BlfMetadata,

    /// Client contexts — one per registered client.
    /// Maximum 124 clients.
    pub clients: [Option<ClfsClientContext>; 124],

    /// Container contexts — one per container.
    /// Maximum 1023 containers.
    pub containers: [Option<ClfsContainerContext>; 1023],

    /// Next container ID to assign.
    pub next_container_id: AtomicU32,

    /// Next client ID to assign.
    pub next_client_id: AtomicU32,

    /// Active container count.
    pub active_containers: AtomicU32,

    /// File handle to the backing .blf file.
    /// In our kernel, this would be an IoFileObject or similar.
    pub blf_file_handle: u64,

    /// Access mask used to open this log.
    pub access_mask: u32,

    /// Share access flags.
    pub share_access: u32,

    /// Total log size (sum of all container sizes).
    pub total_log_size: AtomicU64,

    /// LSN allocator — manages LSN generation.
    pub lsn_alloc: super::record::LsnAllocator,
}

impl ClfsVcb {
    /// Create a new VCB with default values.
    pub fn new() -> Self {
        Self {
            ref_count: AtomicU32::new(1),
            name: [0u16; 260],
            name_len: 0,
            state: ClfsLogState::Uninitialized,
            control_record: ClfsControlRecord::new(),
            base_record: ClfsBaseRecordHeader::new(),
            blf_metadata: BlfMetadata::new(),
            clients: [const { None }; 124],
            containers: [const { None }; 1023],
            next_container_id: AtomicU32::new(1),
            next_client_id: AtomicU32::new(1),
            active_containers: AtomicU32::new(0),
            blf_file_handle: 0,
            access_mask: 0,
            share_access: 0,
            total_log_size: AtomicU64::new(0),
            lsn_alloc: super::record::LsnAllocator::new(),
        }
    }

    /// Initialize a new VCB with default metadata.
    pub fn initialize(&mut self) {
        self.state = ClfsLogState::Initialized;
        self.control_record = ClfsControlRecord::new();
        self.base_record = ClfsBaseRecordHeader::new();
        self.blf_metadata = BlfMetadata::new();
        crate::kprintln_info!("CLFS", "  [CLFS] VCB initialized");
    }

    /// Set the log name.
    pub fn set_name(&mut self, name: &[u8]) {
        // Convert UTF-8 name to Unicode16
        self.name_len = name.len().min(259);
        for (i, &byte) in name.iter().take(259).enumerate() {
            self.name[i] = byte as u16;
        }
        self.name[self.name_len] = 0;
    }

    /// Increment the reference count.
    pub fn add_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement the reference count. Returns true if the count reached zero.
    pub fn release(&self) -> bool {
        self.ref_count.fetch_sub(1, Ordering::SeqCst) == 1
    }

    /// Allocate a new container ID.
    pub fn alloc_container_id(&self) -> Option<u32> {
        let id = self.next_container_id.fetch_add(1, Ordering::Relaxed);
        if id >= 1023 {
            None // Out of container IDs
        } else {
            Some(id)
        }
    }

    /// Allocate a new client ID.
    pub fn alloc_client_id(&self) -> Option<u32> {
        let id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        if id >= 124 {
            None // Out of client IDs
        } else {
            Some(id)
        }
    }

    /// Register a new client.
    pub fn register_client(&mut self, ctx: ClfsClientContext) -> Option<u32> {
        let cid = ctx.client_id();
        if cid >= 124 {
            return None;
        }
        self.clients[cid as usize] = Some(ctx);
        self.base_record.c_clients += 1;
        Some(cid)
    }

    /// Find a client by ID.
    pub fn get_client(&self, cid: u32) -> Option<&ClfsClientContext> {
        if cid >= 124 { return None; }
        self.clients[cid as usize].as_ref()
    }

    /// Get a mutable reference to a client.
    pub fn get_client_mut(&mut self, cid: u32) -> Option<&mut ClfsClientContext> {
        if cid >= 124 { return None; }
        self.clients[cid as usize].as_mut()
    }

    /// Register a new container.
    pub fn register_container(&mut self, ctx: ClfsContainerContext) -> Option<u32> {
        let cid = ctx.container_id();
        if cid >= 1023 {
            return None;
        }
        self.containers[cid as usize] = Some(ctx);
        self.active_containers.fetch_add(1, Ordering::Relaxed);
        self.base_record.c_active_containers += 1;
        self.total_log_size.fetch_add(ctx.size(), Ordering::Relaxed);

        // Update base record
        self.base_record.rg_containers[cid as usize] = cid as u32; // Offset placeholder

        Some(cid)
    }

    /// Get a container by ID.
    pub fn get_container(&self, cid: u32) -> Option<&ClfsContainerContext> {
        if cid >= 1023 { return None; }
        self.containers[cid as usize].as_ref()
    }

    /// Mark a container as inactive.
    pub fn deactivate_container(&mut self, cid: u32) {
        if cid >= 1023 { return; }
        if let Some(ref ctx) = self.containers[cid as usize] {
            self.total_log_size.fetch_sub(ctx.size(), Ordering::Relaxed);
        }
        self.active_containers.fetch_sub(1, Ordering::Relaxed);
        self.base_record.c_active_containers = self.base_record.c_active_containers.saturating_sub(1);

        if let Some(ref mut ctx) = self.containers[cid as usize] {
            ctx.e_state = ClfsContainerState::Inactive;
        }
    }

    /// Allocate the next LSN for a record.
    pub fn alloc_lsn(&mut self) -> ClfsLsn {
        self.lsn_alloc.allocate()
    }

    /// Get the total log size.
    pub fn total_size(&self) -> u64 {
        self.total_log_size.load(Ordering::Relaxed)
    }

    /// Get the number of active containers.
    pub fn container_count(&self) -> u32 {
        self.active_containers.load(Ordering::Relaxed)
    }

    /// Get the number of active clients.
    pub fn client_count(&self) -> u32 {
        self.base_record.c_clients as u32
    }

    /// Check if the log is in a valid state for writing.
    pub fn can_write(&self) -> bool {
        matches!(self.state, ClfsLogState::Active | ClfsLogState::Initialized)
            && self.container_count() > 0
    }

    /// Transition to the active state.
    pub fn activate(&mut self) {
        self.state = ClfsLogState::Active;
        self.base_record.e_log_state = ClfsLogState::Active;
    }
}

impl Default for ClfsVcb {
    fn default() -> Self {
        Self::new()
    }
}
