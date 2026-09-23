//! ext3 Journal Support
//
//! Implements journaling for ext3 filesystems.
//! The journal provides crash recovery by recording filesystem operations
//! before they are committed to disk.
//
//! ## Journal Location
//! The journal is typically stored as a hidden file (inode journal_inode).
//! For external journals, it may be on a separate device.
//
//! ## Journal Structure
//! The journal consists of:
//! - Superblock (at the start)
//! - Descriptor blocks
//! - Data blocks
//! - Commit blocks
//
//! ## Transaction Format
//! Each transaction contains:
//! - Transaction header
//! - Descriptor block(s)
//! - Data block(s) (if any)
//! - Commit block

use alloc::vec;

use super::superblock::Ext2SuperBlock;
use super::inode::{read_inode, Ext2Inode};

// ============================================================================
// Journal Constants
// ============================================================================

/// Journal magic number
pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B3998;

/// Journal descriptor type
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;

/// Journal commit block type
pub const JBD2_COMMIT_BLOCK: u32 = 2;

/// Journal revoke block type
pub const JBD2_REVOKE_BLOCK: u32 = 3;

/// Journal superblock version
pub const JBD2_VERSION: u32 = 2;

/// Journal block size
pub const JOURNAL_BLOCK_SIZE: usize = 4096;

/// Maximum journal transactions
pub const MAX_JOURNAL_BLOCKS: u32 = 32768;

// ============================================================================
// Journal Structures
// ============================================================================

/// Journal superblock (located at the start of the journal device/file)
#[repr(C)]
pub struct JournalSuperBlock {
    /// Header (same format as fs superblock for compatibility)
    pub header: JournalHeader,
    /// Total blocks in the journal
    pub max_blocks: u32,
    /// Maximum transaction slots
    pub max_transactions: u32,
    /// First block of the first transaction
    pub first_block: u32,
    /// Start of the log
    pub start: u32,
    /// Last transaction ID committed
    pub last_transaction: u32,
    /// Transaction ID currently committing
    pub transaction_id: u32,
    /// Journal sequence number
    pub journal_sequence: u32,
    /// Minimum sequence number for recovery
    pub min_sequence: u32,
    /// Maximum sequence number for recovery
    pub max_sequence: u32,
    /// Tag of last checkpoint
    pub last_checkpoint: u32,
    /// Reserved
    pub reserved: [u32; 8],
}

/// Generic journal header (common to all journal blocks)
#[repr(C)]
pub struct JournalHeader {
    /// Magic number
    pub magic: u32,
    /// Block type (descriptor, commit, revoke, etc.)
    pub block_type: u32,
    /// Sequence number
    pub sequence: u32,
}

/// Journal descriptor block header
#[repr(C)]
pub struct JournalDescriptorHeader {
    /// Generic header
    pub header: JournalHeader,
    /// Block numbers for this transaction
    pub block_refs: [u32; 16],  // Variable size, padded to block size
}

impl JournalSuperBlock {
    /// Create a new journal superblock
    pub fn new() -> Self {
        Self {
            header: JournalHeader::new(JBD2_DESCRIPTOR_BLOCK),
            max_blocks: 0,
            max_transactions: 0,
            first_block: 0,
            start: 0,
            last_transaction: 0,
            transaction_id: 0,
            journal_sequence: 0,
            min_sequence: 0,
            max_sequence: 0,
            last_checkpoint: 0,
            reserved: [0; 8],
        }
    }

    /// Check if this is a valid journal superblock
    pub fn is_valid(&self) -> bool {
        self.header.magic == JBD2_MAGIC_NUMBER
    }

    /// Get the journal block size
    pub fn get_block_size(&self) -> u32 {
        JOURNAL_BLOCK_SIZE as u32
    }
}

impl JournalHeader {
    /// Create a new journal header
    pub fn new(block_type: u32) -> Self {
        Self {
            magic: JBD2_MAGIC_NUMBER,
            block_type,
            sequence: 0,
        }
    }

    /// Check if this is a valid header
    pub fn is_valid(&self) -> bool {
        self.magic == JBD2_MAGIC_NUMBER
    }

    /// Check if this is a descriptor block
    pub fn is_descriptor(&self) -> bool {
        self.block_type == JBD2_DESCRIPTOR_BLOCK
    }

    /// Check if this is a commit block
    pub fn is_commit(&self) -> bool {
        self.block_type == JBD2_COMMIT_BLOCK
    }

    /// Check if this is a revoke block
    pub fn is_revoke(&self) -> bool {
        self.block_type == JBD2_REVOKE_BLOCK
    }
}

// ============================================================================
// Journal State
// ============================================================================

/// Journal state for tracking open journals
pub struct JournalState {
    /// Filesystem superblock reference
    pub sb: Ext2SuperBlock,
    /// Journal inode number
    pub journal_inode: u32,
    /// Journal inode data
    pub inode: Ext2Inode,
    /// Transaction ID counter
    pub transaction_id: u32,
    /// Is this a read-only mount?
    pub read_only: bool,
    /// Is the journal replaying?
    pub replaying: bool,
    /// Last committed transaction
    pub last_transaction: u32,
    /// Journal device (None for internal journal)
    pub journal_device: Option<u64>,
}

impl JournalState {
    /// Create a new journal state
    pub fn new(sb: Ext2SuperBlock, journal_inode: u32) -> Self {
        Self {
            sb,
            journal_inode,
            inode: unsafe { core::mem::zeroed() },
            transaction_id: 0,
            read_only: false,
            replaying: false,
            last_transaction: 0,
            journal_device: None,
        }
    }
}

// ============================================================================
// Journal Operations
// ============================================================================

/// Open the journal and read the superblock
pub fn open_journal(
    device: *mut (),
    sb: &Ext2SuperBlock,
) -> Option<JournalSuperBlock> {
    let journal_inode = sb.journal_inode;
    
    if journal_inode == 0 {
        // kprintln!("[EXT3] No journal inode in superblock")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Read journal inode
    let inode = read_inode(device, sb, journal_inode)?;
    
    if inode.is_deleted() {
        // kprintln!("[EXT3] Journal inode has been deleted")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Read journal superblock from the journal inode
    let mut buffer = vec![0u8; JOURNAL_BLOCK_SIZE];
    let _offset = 0usize;
    
    // Read first block of journal
    let lba = super::inode::logical_to_lba(device, sb, &inode, 0)?;
    if super::superblock::read_sector(device, lba, &mut buffer).is_err() {
        // kprintln!("[EXT3] Failed to read journal superblock")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Parse journal superblock
    let j_sb = unsafe {
        core::ptr::read_unaligned(buffer.as_ptr() as *const JournalSuperBlock)
    };
    
    if !j_sb.is_valid() {
        // kprintln!("[EXT3] Invalid journal superblock")  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // kprintln!("[EXT3] Journal opened: {} blocks, max_trans={}",  // kprintln disabled (memcpy crash workaround)
//         j_sb.max_blocks, j_sb.max_transactions);
    
    Some(j_sb)
}

/// Replay the journal after a crash
pub fn replay_journal(
    device: *mut (),
    sb: &Ext2SuperBlock,
) -> Result<usize, ()> {
    if !sb.has_journal() {
        return Ok(0);  // No journal, nothing to replay
    }
    
    // Open the journal
    let j_sb = match open_journal(device, sb) {
        Some(js) => js,
        None => return Err(()),
    };
    
    // kprintln!("[EXT3] Replaying journal...")  // kprintln disabled (memcpy crash workaround);
    
    let mut replayed_count = 0;
    let mut current_block = j_sb.first_block;
    let end_block = j_sb.first_block + j_sb.max_blocks;
    
    while current_block < end_block {
        // Read journal block
        let mut buffer = vec![0u8; JOURNAL_BLOCK_SIZE];
        
        // For internal journals, read from journal inode
        // (simplified - assumes block 0 corresponds to journal block)
        if current_block >= j_sb.first_block && current_block < j_sb.first_block + 1 {
            // Read journal inode and get block 0
            let inode = match read_inode(device, sb, sb.journal_inode) {
                Some(i) => i,
                None => break,
            };
            
            if let Some(lba) = super::inode::logical_to_lba(device, sb, &inode, current_block - j_sb.first_block) {
                if super::superblock::read_sector(device, lba, &mut buffer).is_err() {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
        
        // Parse journal header
        let header = unsafe {
            core::ptr::read_unaligned(buffer.as_ptr() as *const JournalHeader)
        };
        
        if !header.is_valid() {
            break;
        }
        
        match header.block_type {
            JBD2_DESCRIPTOR_BLOCK => {
                // Descriptor block - process the blocks listed
                // kprintln!("[EXT3] Replaying descriptor block, seq={}", header.sequence)  // kprintln disabled (memcpy crash workaround);
                
                // In a full implementation, we would:
                // 1. Read the data blocks referenced
                // 2. Write them to the actual filesystem
                // 3. Wait for commit block
                replayed_count += 1;
            }
            JBD2_COMMIT_BLOCK => {
                // Commit block - transaction is complete
                // kprintln!("[EXT3] Transaction {} committed", header.sequence)  // kprintln disabled (memcpy crash workaround);
            }
            JBD2_REVOKE_BLOCK => {
                // Revoke block - some blocks were revoked
                // kprintln!("[EXT3] Revoke block, seq={}", header.sequence)  // kprintln disabled (memcpy crash workaround);
            }
            _ => {
                // Unknown block type
                break;
            }
        }
        
        current_block += 1;
        
        // Safety limit
        if replayed_count > 100 {
            // kprintln!("[EXT3] Replay limit reached")  // kprintln disabled (memcpy crash workaround);
            break;
        }
    }
    
    // kprintln!("[EXT3] Journal replayed {} blocks", replayed_count)  // kprintln disabled (memcpy crash workaround);
    Ok(replayed_count)
}

/// Check if the journal needs replay
pub fn journal_needs_recovery(sb: &Ext2SuperBlock) -> bool {
    // Check if RECOVER flag is set
    (sb.incompatible_features & 0x0004) != 0
}

/// Clear the recovery flag after successful replay
pub fn clear_recovery_flag(_sb: &mut Ext2SuperBlock) {
    // In a full implementation, we would:
    // 1. Modify the superblock
    // 2. Write it back to disk
    // This is simplified for now
}

/// Start a new journal transaction
pub fn journal_start_transaction(_sb: &Ext2SuperBlock) -> u32 {
    // Return a new transaction ID
    // In practice, this would be atomic and persistent
    static mut TRANSACTION_COUNTER: u32 = 0;
    unsafe {
        TRANSACTION_COUNTER += 1;
        TRANSACTION_COUNTER
    }
}

/// Commit a journal transaction
pub fn journal_commit_transaction(
    _device: *mut (),
    _sb: &Ext2SuperBlock,
    _transaction_id: u32,
) -> Result<(), ()> {
    // In a full implementation, we would:
    // 1. Write all modified blocks to journal
    // 2. Write commit block
    // 3. Wait for write completion
    // 4. Write blocks to actual filesystem
    // 5. Update superblock
    Ok(())
}

/// Abort a journal transaction (on error)
pub fn journal_abort_transaction(
    _device: *mut (),
    _sb: &Ext2SuperBlock,
    _transaction_id: u32,
) {
    // Mark journal as aborted
    // In a full implementation, we would:
    // 1. Stop logging
    // 2. Mark filesystem as needing fsck
    // kprintln!("[EXT3] Journal transaction {} aborted", _transaction_id)  // kprintln disabled (memcpy crash workaround);
}

// ============================================================================
// Journal Recovery
// ============================================================================

/// Find the last valid transaction in the journal
pub fn find_last_transaction(
    device: *mut (),
    sb: &Ext2SuperBlock,
) -> Option<u32> {
    let j_sb = open_journal(device, sb)?;
    
    // Start from the end and work backwards
    let mut current_block = j_sb.first_block + j_sb.max_blocks - 1;
    let mut last_valid_seq: Option<u32> = None;
    
    while current_block > j_sb.first_block {
        // Read block
        let inode = match read_inode(device, sb, sb.journal_inode) {
            Some(i) => i,
            None => break,
        };
        
        let mut buffer = vec![0u8; JOURNAL_BLOCK_SIZE];
        let lba = match super::inode::logical_to_lba(device, sb, &inode, current_block - j_sb.first_block) {
            Some(l) => l,
            None => break,
        };
        
        if super::superblock::read_sector(device, lba, &mut buffer).is_err() {
            current_block -= 1;
            continue;
        }
        
        let header = unsafe {
            core::ptr::read_unaligned(buffer.as_ptr() as *const JournalHeader)
        };
        
        if header.is_valid() && header.is_commit() {
            last_valid_seq = Some(header.sequence);
            break;
        }
        
        current_block -= 1;
    }
    
    last_valid_seq
}

/// Get the journal sequence number for recovery
pub fn get_journal_sequence(sb: &Ext2SuperBlock) -> Option<u32> {
    // Read journal superblock
    // Return the journal sequence number
    if !sb.has_journal() {
        return None;
    }
    
    // For now, return 0 as we haven't opened the journal yet
    Some(0)
}

// ============================================================================
// Journal Debug Output
// ============================================================================

/// Print journal superblock for debugging
pub fn debug_print_journal_sb(_sb: &JournalSuperBlock) {
    // kprintln!("[EXT3] Journal Superblock:")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Magic:        0x{:08x}", sb.header.magic)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Blocks:       {}", sb.max_blocks)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Max trans:    {}", sb.max_transactions)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  First block:  {}", sb.first_block)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Start:        {}", sb.start)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Last trans:   {}", sb.last_transaction)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Current trans: {}", sb.transaction_id)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  Sequence:     {}", sb.journal_sequence)  // kprintln disabled (memcpy crash workaround);
}
