//! CLFS Client and Container Context Structures
//
//! Defines the runtime state structures used to manage CLFS clients and
//! containers in memory.

use super::record::ClfsLsn;
use super::metadata::ClfsLogState;

// ============================================================================
// CLFS Node ID
// ============================================================================

/// CLFS node type identifiers (NTC values).
pub const CLFS_NODE_TYPE_FCB:                      u32 = 0xC1FDF001;
pub const CLFS_NODE_TYPE_VCB:                      u32 = 0xC1FDF002;
pub const CLFS_NODE_TYPE_CCB:                      u32 = 0xC1FDF003;
pub const CLFS_NODE_TYPE_SYMBOL:                   u32 = 0xC1FDF006;
pub const CLFS_NODE_TYPE_CLIENT_CONTEXT:           u32 = 0xC1FDF007;
pub const CLFS_NODE_TYPE_CONTAINER_CONTEXT:        u32 = 0xC1FDF008;
pub const CLFS_NODE_TYPE_SHARED_SECURITY_CONTEXT:   u32 = 0xC1FDF00D;

/// CLFS_NODE_ID — identifies the type and size of a CLFS node.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClfsNodeId {
    /// Node type (NTC — Node Type Code).
    pub c_type: u32,
    /// Size of the node in bytes.
    pub cb_node: u32,
}

impl ClfsNodeId {
    pub fn new(c_type: u32, cb_node: u32) -> Self {
        Self { c_type, cb_node }
    }

    /// Node ID for a client context.
    pub fn client_context() -> Self {
        Self { c_type: CLFS_NODE_TYPE_CLIENT_CONTEXT, cb_node: 0 }
    }

    /// Node ID for a container context.
    pub fn container_context() -> Self {
        Self { c_type: CLFS_NODE_TYPE_CONTAINER_CONTEXT, cb_node: 0 }
    }
}

// ============================================================================
// Container Context
// ============================================================================

/// Container state values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClfsContainerState {
    Initializing           = 0x01,
    Inactive              = 0x02,
    Active                = 0x04,
    ActivePendingDelete   = 0x08,
    PendingArchive        = 0x10,
    PendingArchiveAndDelete = 0x20,
}

impl ClfsContainerState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => ClfsContainerState::Initializing,
            0x02 => ClfsContainerState::Inactive,
            0x04 => ClfsContainerState::Active,
            0x08 => ClfsContainerState::ActivePendingDelete,
            0x10 => ClfsContainerState::PendingArchive,
            0x20 => ClfsContainerState::PendingArchiveAndDelete,
            _ => ClfsContainerState::Inactive,
        }
    }
}

/// CLFS_CONTAINER_CONTEXT — per-container runtime state.
/// This structure tracks the state of one container within a CLFS log.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClfsContainerContext {
    /// Node ID — {CLFS_NODE_TYPE_CONTAINER_CONTEXT, sizeof(ClfsContainerContext)}.
    pub cid_node: ClfsNodeId,
    /// Size of the container in bytes.
    pub cb_container: u64,
    /// Container identifier — unique within the log.
    pub cid_container: u32,
    /// Queue position for round-robin allocation.
    pub cid_queue: u32,
    /// Pointer to the in-memory container buffer (if mapped).
    /// In our kernel, this would be a pointer to a mapped memory region.
    pub p_container: u64,
    /// Current Update Sequence Number for this container.
    pub usn_current: u32,
    /// Container state.
    pub e_state: ClfsContainerState,
    /// Offset to the previous container in the chain.
    pub cb_prev_offset: u32,
    /// Offset to the next container in the chain.
    pub cb_next_offset: u32,
}

impl ClfsContainerContext {
    /// Create a new container context for a newly added container.
    pub fn new(cid: u32, size: u64) -> Self {
        Self {
            cid_node: ClfsNodeId::container_context(),
            cb_container: size,
            cid_container: cid,
            cid_queue: cid,
            p_container: 0, // Will be set when container is mapped
            usn_current: 0,
            e_state: ClfsContainerState::Active,
            cb_prev_offset: 0,
            cb_next_offset: 0,
        }
    }

    /// Check if this container is active.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.e_state == ClfsContainerState::Active
    }

    /// Get the container ID.
    #[inline]
    pub fn container_id(&self) -> u32 {
        self.cid_container
    }

    /// Get the container size in bytes.
    #[inline]
    pub fn size(&self) -> u64 {
        self.cb_container
    }

    /// Get the container size in sectors.
    #[inline]
    pub fn sector_count(&self) -> u64 {
        self.cb_container / 512
    }
}

impl Default for ClfsContainerContext {
    fn default() -> Self {
        Self {
            cid_node: ClfsNodeId::container_context(),
            cb_container: 0,
            cid_container: 0,
            cid_queue: 0,
            p_container: 0,
            usn_current: 0,
            e_state: ClfsContainerState::Inactive,
            cb_prev_offset: 0,
            cb_next_offset: 0,
        }
    }
}

// ============================================================================
// Client Context
// ============================================================================

/// CLFS_CLIENT_CONTEXT — per-client runtime state.
/// This structure tracks the state of one client within a CLFS log.
/// A client is an entity that writes records to the log (e.g., a registry
/// hive, a transaction manager, etc.).
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ClfsClientContext {
    /// Node ID — {CLFS_NODE_TYPE_CLIENT_CONTEXT, sizeof(ClfsClientContext)}.
    pub cid_node: ClfsNodeId,
    /// Client identifier — unique within the log.
    pub cid_client: u32,
    /// File attribute flags (FILE_ATTRIBUTE_*).
    pub f_attributes: u16,
    /// Unused / padding.
    pub _padding: u16,
    /// Flush threshold in bytes — when the client's data exceeds this,
    /// the log manager will attempt to flush.
    pub cb_flush_threshold: u32,
    /// Number of shadow sectors reserved for this client.
    pub c_shadow_sectors: u32,
    /// Size of the undo commitment area.
    pub cb_undo_commitment: u64,
    /// Creation time (FILETIME — 100-nanosecond intervals since 1601-01-01).
    pub ll_create_time: u64,
    /// Last access time.
    pub ll_access_time: u64,
    /// Last write time.
    pub ll_write_time: u64,
    /// LSN of the owner page.
    pub lsn_owner_page: ClfsLsn,
    /// LSN of the archive tail — records before this LSN have been archived.
    pub lsn_archive_tail: ClfsLsn,
    /// LSN of the first record written by this client.
    pub lsn_base: ClfsLsn,
    /// LSN of the last record written by this client.
    pub lsn_last: ClfsLsn,
    /// LSN of the client's restart area.
    pub lsn_restart: ClfsLsn,
    /// Physical base LSN of the container where this client's records live.
    pub lsn_physical_base: ClfsLsn,
    /// Unused LSN field.
    pub lsn_unused1: ClfsLsn,
    /// Unused LSN field.
    pub lsn_unused2: ClfsLsn,
    /// Current log state for this client.
    pub e_state: ClfsLogState,
    /// Handle to security context (if security is enabled).
    pub h_security_context: u64,
}

impl ClfsClientContext {
    /// Create a new client context for a newly registered client.
    pub fn new(cid: u32) -> Self {
        Self {
            cid_node: ClfsNodeId::client_context(),
            cid_client: cid,
            f_attributes: 0,
            _padding: 0,
            cb_flush_threshold: 40_000, // Default: 40KB
            c_shadow_sectors: 0,
            cb_undo_commitment: 0,
            ll_create_time: 0,
            ll_access_time: 0,
            ll_write_time: 0,
            lsn_owner_page: ClfsLsn::NULL,
            lsn_archive_tail: ClfsLsn::NULL,
            lsn_base: ClfsLsn::NULL,
            lsn_last: ClfsLsn::NULL,
            lsn_restart: ClfsLsn::NULL,
            lsn_physical_base: ClfsLsn::NULL,
            lsn_unused1: ClfsLsn::NULL,
            lsn_unused2: ClfsLsn::NULL,
            e_state: ClfsLogState::Initialized,
            h_security_context: 0,
        }
    }

    /// Update the last-write LSN to a new value.
    #[inline]
    pub fn update_last_lsn(&mut self, lsn: ClfsLsn) {
        self.ll_write_time = Self::current_filetime();
        self.lsn_last = lsn;
    }

    /// Check if the client needs flushing based on the flush threshold.
    #[inline]
    pub fn needs_flush(&self, current_size: u64) -> bool {
        current_size >= self.cb_flush_threshold as u64
    }

    /// Get the client ID.
    #[inline]
    pub fn client_id(&self) -> u32 {
        self.cid_client
    }

    /// Get a rough estimate of the client context size.
    pub fn size() -> usize {
        core::mem::size_of::<ClfsClientContext>()
    }

    /// Get the current FILETIME.
    fn current_filetime() -> u64 {
        // In a real kernel this would be KeQuerySystemTime.
        // For now, return a placeholder value.
        0
    }
}

impl Default for ClfsClientContext {
    fn default() -> Self {
        Self::new(0)
    }
}

// ============================================================================
// Container Scan Context
// ============================================================================

/// CLFS_LOG_SCAN_CONTEXT — state for container enumeration.
#[derive(Debug, Clone)]
pub struct ClfsLogScanContext {
    /// Starting container ID for the scan.
    pub cid_current: u32,
    /// Number of containers scanned so far.
    pub c_scanned: u32,
    /// Total containers in the log.
    pub c_total: u32,
    /// Flags controlling scan behavior.
    pub flags: u32,
    /// Last error code from the scan.
    pub last_error: u32,
}

impl ClfsLogScanContext {
    pub fn new(start_id: u32) -> Self {
        Self {
            cid_current: start_id,
            c_scanned: 0,
            c_total: 0,
            flags: 0,
            last_error: 0,
        }
    }

    /// Advance to the next container.
    pub fn advance(&mut self) {
        self.cid_current += 1;
        self.c_scanned += 1;
    }

    /// Check if the scan is complete.
    pub fn is_done(&self) -> bool {
        self.c_scanned >= self.c_total || self.last_error != 0
    }
}

impl Default for ClfsLogScanContext {
    fn default() -> Self {
        Self::new(0)
    }
}

/// CLFS_CONTAINER_INFORMATION — information about one container.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ClfsContainerInformation {
    /// Container identifier.
    pub cid_container: u32,
    /// Container file name (Unicode16).
    pub path: [u16; 260],
    /// Length of the path in bytes.
    pub cb_path: u32,
    /// Container state.
    pub state: u8,
    /// Unused.
    pub unused: [u8; 7],
    /// Container size in bytes.
    pub cb_container: u64,
    /// Physical byte offset of the container in the log.
    pub cb_offset: u64,
}

impl Default for ClfsContainerInformation {
    fn default() -> Self {
        Self {
            cid_container: 0,
            path: [0u16; 260],
            cb_path: 0,
            state: 0,
            unused: [0u8; 7],
            cb_container: 0,
            cb_offset: 0,
        }
    }
}
