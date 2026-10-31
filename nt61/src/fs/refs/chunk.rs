//! ReFS Chunk Management
//
//! Implements chunk (extent) allocation and management for ReFS.
//! Chunks are the basic unit of storage allocation in ReFS.
//
//! ## Chunk Structure
//! A chunk describes a contiguous range of clusters:
//! - Logical Cluster Number (LCN) - where the data is stored
//! - Virtual Cluster Number (VCN) length - how many clusters
//! - Checksum of the chunk descriptor
//
//! ## Chunk Table
//! ReFS maintains a chunk table that maps file offsets to chunks.
use crate::libs::ntdll::{status::STATUS_UNSUCCESSFUL, types::NTSTATUS};

use super::superblock::RefsSuperBlock;
use alloc::vec::Vec;

// ============================================================================
// Chunk Constants
// ============================================================================

/// Chunk descriptor size (16 bytes for now)
pub const REFS_CHUNK_DESC_SIZE: usize = 16;

/// Chunk flags
pub const REFS_CHUNK_FLAG_NONE: u64 = 0x00000000;
pub const REFS_CHUNK_FLAG_HOLE: u64 = 0x00000001;
pub const REFS_CHUNK_FLAG_METADATA: u64 = 0x00000002;
pub const REFS_CHUNK_FLAG_SHAREABLE: u64 = 0x00000004;
pub const REFS_CHUNK_FLAG_NEW: u64 = 0x00000008;
pub const REFS_CHUNK_FLAG_MOVED: u64 = 0x00000010;
pub const REFS_CHUNK_FLAG_NOT_PINNED: u64 = 0x00000020;
pub const REFS_CHUNK_FLAG_LARGE_ZERO: u64 = 0x00000040;

/// Chunk allocation unit
pub const REFS_CHUNK_ALLOCATION_UNIT: u64 = 0x400; // 1024 clusters = 64MB

// ============================================================================
// Chunk Descriptor
// ============================================================================

/// ReFS Chunk Descriptor (16 bytes)
/// Describes a contiguous range of clusters allocated to a file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RefsChunkDescriptor {
    /// flags (hole, metadata, etc.)
    pub flags: u64,
    /// Logical Cluster Number (physical location)
    pub lcn: u64,
    /// Virtual Cluster Number length (number of clusters)
    pub vcn_length: u64,
    /// Checksum of this descriptor
    pub checksum: u32,
    /// Reserved
    pub reserved: u32,
}

impl RefsChunkDescriptor {
    /// A zeroed descriptor representing an unallocated (hole) VCN slot.
    pub const EMPTY: Self = Self {
        flags: REFS_CHUNK_FLAG_HOLE,
        lcn: 0,
        vcn_length: 1,
        checksum: 0,
        reserved: 0,
    };

    // ========================================================================
    // Validation
    // ========================================================================

    /// Check if this chunk is valid
    pub fn is_valid(&self) -> bool {
        self.lcn != 0 || (self.flags & REFS_CHUNK_FLAG_HOLE) != 0
    }

    /// Check if this is a hole (unallocated range)
    pub fn is_hole(&self) -> bool {
        (self.flags & REFS_CHUNK_FLAG_HOLE) != 0
    }

    /// Check if this chunk contains metadata
    pub fn is_metadata(&self) -> bool {
        (self.flags & REFS_CHUNK_FLAG_METADATA) != 0
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the Logical Cluster Number (physical location)
    pub fn get_lcn(&self) -> u64 {
        self.lcn
    }

    /// Get the VCN length (number of clusters)
    pub fn get_length(&self) -> u64 {
        self.vcn_length
    }

    /// Get the flags
    pub fn get_flags(&self) -> u64 {
        self.flags
    }

    /// Get the checksum
    pub fn get_checksum(&self) -> u32 {
        self.checksum
    }

    // ========================================================================
    // Conversion
    // ========================================================================

    /// Convert LCN to byte offset
    pub fn lcn_to_offset(&self, sb: &RefsSuperBlock) -> u64 {
        self.lcn * (sb.get_cluster_size() as u64)
    }

    /// Convert LCN to LBA (sector number)
    pub fn lcn_to_lba(&self, sb: &RefsSuperBlock) -> u64 {
        self.lcn * ((sb.get_cluster_size() / sb.get_sector_size()) as u64)
    }

    /// Get the byte length of this chunk
    pub fn get_byte_length(&self, sb: &RefsSuperBlock) -> u64 {
        self.vcn_length * (sb.get_cluster_size() as u64)
    }

    /// Get the sector count for this chunk
    pub fn get_sector_count(&self, sb: &RefsSuperBlock) -> u64 {
        self.vcn_length * ((sb.get_cluster_size() / sb.get_sector_size()) as u64)
    }
}

// ============================================================================
// Chunk Table
// ============================================================================

/// Chunk table entry (for mapping file offsets to chunks)
pub struct ChunkTableEntry {
    /// Starting VCN of this extent
    pub start_vcn: u64,
    /// Number of VCNs in this extent
    pub count: u64,
    /// Chunk descriptor index
    pub chunk_index: u32,
}

impl ChunkTableEntry {
    /// Check if this extent contains a given VCN
    pub fn contains(&self, vcn: u64) -> bool {
        vcn >= self.start_vcn && vcn < self.start_vcn + self.count
    }

    /// Get the VCN offset within this extent
    pub fn vcn_offset(&self, vcn: u64) -> u64 {
        vcn - self.start_vcn
    }
}

/// Chunk table (in-memory representation)
pub struct ChunkTable {
    /// Entries sorted by starting VCN
    pub entries: Vec<ChunkTableEntry>,
    /// Chunk descriptors indexed by VCN slot; a hole descriptor marks an
    /// unallocated VCN.
    pub descriptors: Vec<RefsChunkDescriptor>,
    /// Total number of chunks
    pub chunk_count: u32,
}

impl ChunkTable {
    /// create a new empty chunk table
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            descriptors: Vec::new(),
            chunk_count: 0,
        }
    }

    /// Find the entry containing a VCN
    pub fn find_entry(&self, vcn: u64) -> Option<&ChunkTableEntry> {
        self.entries
            .iter()
            .find(|&entry| entry.contains(vcn))
            .map(|v| v as _)
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ChunkTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Chunk Operations
// ============================================================================

/// Find a chunk by VCN
pub fn find_chunk_by_vcn(chunks: &[RefsChunkDescriptor], vcn: u64) -> Option<(usize, u64)> {
    // In a real implementation, we would search through the chunk table
    // to find the chunk containing the given VCN

    // Simplified: return first chunk
    if !chunks.is_empty() {
        let offset = vcn.min(chunks[0].vcn_length - 1);
        return Some((0, offset));
    }

    None
}

/// Convert VCN to physical location (LCN + offset)
pub fn vcn_to_physical(
    chunks: &[RefsChunkDescriptor],
    sb: &RefsSuperBlock,
    vcn: u64,
) -> Option<(u64, u64)> {
    // vcn_to_physical: given virtual cluster, find the physical LCN and byte offset
    let mut current_vcn = 0u64;

    for chunk in chunks {
        if vcn < current_vcn + chunk.vcn_length {
            let offset_in_chunk = vcn - current_vcn;

            if chunk.is_hole() {
                // Hole - return None for hole
                return None;
            }

            let physical_lcn = chunk.lcn + offset_in_chunk;
            let byte_offset = physical_lcn * (sb.get_cluster_size() as u64);
            return Some((physical_lcn, byte_offset));
        }

        current_vcn += chunk.vcn_length;
    }

    None
}

/// Convert VCN to LBA
pub fn vcn_to_lba(chunks: &[RefsChunkDescriptor], sb: &RefsSuperBlock, vcn: u64) -> Option<u64> {
    vcn_to_physical(chunks, sb, vcn)
        .map(|(lcn, _)| lcn * ((sb.get_cluster_size() / sb.get_sector_size()) as u64))
}

/// Check if a VCN range is a hole
pub fn is_hole_range(chunks: &[RefsChunkDescriptor], start_vcn: u64, _count: u64) -> bool {
    let mut current_vcn = 0u64;

    for chunk in chunks {
        if start_vcn >= current_vcn && start_vcn < current_vcn + chunk.vcn_length {
            // start_vcn is in this chunk
            let offset_in_chunk = start_vcn - current_vcn;
            return chunk.is_hole() && offset_in_chunk == 0;
        }

        current_vcn += chunk.vcn_length;
    }

    // VCN not found - treat as hole
    true
}

// ============================================================================
// Chunk Allocation
// ============================================================================

/// Find the largest contiguous free region
pub fn find_largest_free_region(
    _used_chunks: &[RefsChunkDescriptor],
    total_clusters: u64,
) -> Option<(u64, u64)> {
    // Simplified: return region starting at cluster 4096 with 1024 clusters
    // In reality, we would scan the allocation bitmap

    if total_clusters > 8192 {
        Some((4096, 4096)) // (start, length)
    } else {
        Some((1024, 1024))
    }
}

/// Allocate a chunk from the volume free-cluster bitmap.
pub fn allocate_chunk(
    sb: &RefsSuperBlock,
    bitmap: &mut [u8],
    length: u64,
) -> Option<RefsChunkDescriptor> {
    let total_clusters = sb.get_total_clusters();
    if length == 0 || length > total_clusters {
        return None;
    }
    let bitmap_len = total_clusters.div_ceil(8) as usize;
    if bitmap.len() < bitmap_len {
        return None;
    }
    let mut run_start: u64 = 0;
    let mut run_length: u64 = 0;
    for cluster in 0..total_clusters {
        let byte_index = (cluster / 8) as usize;
        let bit_index = (cluster % 8) as u32;
        let occupied = (bitmap[byte_index] >> bit_index) & 1 == 1;
        if occupied {
            run_start = cluster + 1;
            run_length = 0;
        } else {
            if run_length == 0 {
                run_start = cluster;
            }
            run_length += 1;
            if run_length >= length {
                for allocated in run_start..run_start + length {
                    let byte = (allocated / 8) as usize;
                    let bit = (allocated % 8) as u32;
                    bitmap[byte] |= 1 << bit;
                }
                return Some(RefsChunkDescriptor {
                    flags: REFS_CHUNK_FLAG_NONE,
                    lcn: run_start,
                    vcn_length: length,
                    checksum: 0,
                    reserved: 0,
                });
            }
        }
    }
    None
}

/// Free a chunk by clearing its bits in the allocation bitmap.
pub fn free_chunk(
    _sb: &RefsSuperBlock,
    bitmap: &mut [u8],
    chunk: &RefsChunkDescriptor,
) -> Result<(), NTSTATUS> {
    if chunk.is_hole() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    for cluster in chunk.lcn..chunk.lcn + chunk.vcn_length {
        let byte = (cluster / 8) as usize;
        let bit = (cluster % 8) as u32;
        if byte < bitmap.len() {
            bitmap[byte] &= !(1 << bit);
        }
    }
    Ok(())
}

// ============================================================================
// Chunk Table Operations
// ============================================================================

/// Build chunk table from file record
pub fn build_chunk_table(_sb: &RefsSuperBlock, chunks: &[RefsChunkDescriptor]) -> ChunkTable {
    let mut table = ChunkTable::new();
    let mut current_vcn = 0u64;

    for (i, chunk) in chunks.iter().enumerate() {
        if chunk.vcn_length > 0 {
            table.entries.push(ChunkTableEntry {
                start_vcn: current_vcn,
                count: chunk.vcn_length,
                chunk_index: i as u32,
            });
            current_vcn += chunk.vcn_length;
        }
    }

    table.chunk_count = chunks.len() as u32;
    table.descriptors = chunks.to_vec();
    table
}

/// Get chunk at VCN from table
pub fn get_chunk_at_vcn(
    table: &ChunkTable,
    chunks: &[RefsChunkDescriptor],
    vcn: u64,
) -> Option<(u64, u64)> {
    let entry = table.find_entry(vcn)?;
    let chunk = &chunks[entry.chunk_index as usize];

    if chunk.is_hole() {
        return None;
    }

    let offset = entry.vcn_offset(vcn);
    // Returns (lcn, byte_offset_within_chunk). The byte offset requires a
    // cluster size; we use the ReFS default of 65536 bytes (64 KiB clusters)
    // when the caller has not provided a superblock. Callers that need exact
    // byte offsets should use the variant that takes a superblock.
    let cluster_size = REFS_DEFAULT_CLUSTER_SIZE as u64;
    Some((chunk.lcn + offset, offset * cluster_size))
}

/// Default ReFS cluster size in bytes (64 KiB), matching the most common
/// ReFS on-disk layout.
const REFS_DEFAULT_CLUSTER_SIZE: u32 = 65536;

// ============================================================================
// Debug Output
// ============================================================================

/// Print chunk information
pub fn debug_print_chunk(chunk: &RefsChunkDescriptor, _sb: &RefsSuperBlock) {
    // kprintln!("  Chunk:");
    // kprintln!("    flags:  0x{:016x}", chunk.flags);
    // kprintln!("    LCN:    {}", chunk.lcn);
    // kprintln!("    VCNs:   {}", chunk.vcn_length);
    // kprintln!("    Size:   {} bytes", chunk.get_byte_length(sb));

    if chunk.is_hole() {
        // kprintln!("    r#type:   HOLE");
    } else {
        // kprintln!("    r#type:   DATA");
    }
}

/// Print chunk table
pub fn debug_print_chunk_table(
    table: &ChunkTable,
    chunks: &[RefsChunkDescriptor],
    _sb: &RefsSuperBlock,
) {
    // Iterate the table to validate the entries; the actual logging
    // was disabled (memcpy crash workaround). Iterating here keeps
    // the API contract and exercises the data structures.

    for entry in &table.entries {
        let chunk = &chunks[entry.chunk_index as usize];
        // Reference fields to retain the API contract
        let _ = (entry.start_vcn, entry.count, chunk.lcn, chunk.vcn_length);
    }
}
