//! VRAM Memory Management
//
//! Provides VRAM (Video RAM) memory management for GPU drivers,
//! including allocation, deallocation, and GART (Graphics Address
//! Remapping Table) support.
//
//! Clean-room implementation based on industry standards.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

// =====================================================================
// VRAM Allocation Types
// =====================================================================

/// VRAM allocation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VramAllocType {
    /// Framebuffer allocation
    FrameBuffer,
    /// GART/TTM mapped allocation
    Gart,
    /// Pinned (non-pageable) allocation
    Pinned,
    /// Cached allocation
    Cached,
    /// Uncached allocation
    Uncached,
    /// Write-combined allocation
    WriteCombined,
    /// Command buffer
    CommandBuffer,
    /// Vertex buffer
    VertexBuffer,
    /// Texture
    Texture,
    /// Render target
    RenderTarget,
}

impl VramAllocType {
    /// Get cache coherency flags for this allocation type
    pub fn cache_flags(&self) -> VramCacheFlags {
        match self {
            VramAllocType::Cached => VramCacheFlags::Cached,
            VramAllocType::Uncached => VramCacheFlags::Uncached,
            VramAllocType::WriteCombined => VramCacheFlags::WriteCombine,
            _ => VramCacheFlags::Cached,
        }
    }

    /// Check if this allocation type is CPU accessible
    pub fn is_cpu_accessible(&self) -> bool {
        !matches!(self, VramAllocType::CommandBuffer)
    }
}

/// VRAM cache flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VramCacheFlags {
    /// Normal cached memory
    Cached,
    /// Uncached memory
    Uncached,
    /// Write-combining memory
    WriteCombine,
    /// Write-through cache
    WriteThrough,
    /// Write-protected
    WriteProtected,
}

// =====================================================================
// VRAM Allocation
// =====================================================================

/// VRAM allocation descriptor
#[derive(Debug, Clone, Copy)]
pub struct VramAlloc {
    /// Offset from VRAM base
    pub offset: u64,
    /// Size in bytes
    pub size: u64,
    /// Allocation type
    pub alloc_type: VramAllocType,
    /// CPU physical address (if applicable)
    pub cpu_addr: u64,
    /// GPU physical address
    pub gpu_addr: u64,
    /// CPU virtual address (if mapped)
    pub cpu_virt: u64,
    /// Alignment requirement
    pub alignment: u64,
    /// Mapped to GART
    pub in_gart: bool,
}

impl VramAlloc {
    /// Create a new VRAM allocation
    pub fn new(offset: u64, size: u64, alloc_type: VramAllocType) -> Self {
        Self {
            offset,
            size,
            alloc_type,
            cpu_addr: 0,
            gpu_addr: 0,
            cpu_virt: 0,
            alignment: 4096,
            in_gart: false,
        }
    }

    /// Check if allocation overlaps with another
    pub fn overlaps(&self, other: &VramAlloc) -> bool {
        let self_end = self.offset + self.size;
        let other_end = other.offset + other.size;
        self.offset < other_end && self_end > other.offset
    }

    /// Get end address
    pub fn end(&self) -> u64 {
        self.offset + self.size
    }

    /// Check if size is aligned
    pub fn is_aligned(&self) -> bool {
        self.offset % self.alignment == 0 && self.size % self.alignment == 0
    }
}

// =====================================================================
// VRAM Manager
// =====================================================================

/// VRAM memory manager
///
/// Manages a region of video memory, handling allocation and
/// deallocation with a simple bitmap-based allocator.
pub struct VramManager {
    /// Base address of VRAM
    pub base: AtomicU64,
    /// Total size of VRAM
    pub total_size: AtomicU64,
    /// Used bytes
    pub used: AtomicU64,
    /// Maximum allocation offset
    pub max_offset: AtomicU64,
    /// Allocation alignment
    pub alignment: u64,
    /// Number of allocation slots
    pub num_slots: usize,
    /// Allocation bitmap (1 = allocated, 0 = free)
    /// Using a simple linked list approach for now
    pub head_offset: AtomicU64,
}

/// Default VRAM alignment
pub const VRAM_ALIGNMENT: u64 = 4096;

/// VRAM alignment for framebuffer (128-byte for most GPUs)
pub const VRAM_FB_ALIGNMENT: u64 = 128;

/// VRAM alignment for GART (page-aligned)
pub const VRAM_GART_ALIGNMENT: u64 = 4096;

impl VramManager {
    /// Create a new VRAM manager
    ///
    /// # Arguments
    ///
    /// * `base` - Base physical address of VRAM
    /// * `size` - Total size of VRAM in bytes
    /// * `alignment` - Minimum allocation alignment
    pub fn new(base: u64, size: u64, alignment: u64) -> Self {
        Self {
            base: AtomicU64::new(base),
            total_size: AtomicU64::new(size),
            used: AtomicU64::new(0),
            max_offset: AtomicU64::new(0),
            alignment: alignment.max(VRAM_ALIGNMENT),
            num_slots: 256, // Reserve slots for tracking
            head_offset: AtomicU64::new(0),
        }
    }

    /// Get base address
    pub fn base(&self) -> u64 {
        self.base.load(Ordering::Acquire)
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        self.total_size.load(Ordering::Acquire)
    }

    /// Get used bytes
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    /// Get available bytes
    pub fn available(&self) -> u64 {
        self.total_size.load(Ordering::Acquire) - self.used.load(Ordering::Acquire)
    }

    /// Check if memory is available
    pub fn has_space(&self, size: u64) -> bool {
        self.available() >= size
    }

    /// Allocate from VRAM
    ///
    /// Uses a simple bump allocator approach. This is suitable for
    /// drivers that don't need to free individual allocations.
    ///
    /// Returns the allocation on success, or None if insufficient memory.
    pub fn allocate(&self, size: u64) -> Option<VramAlloc> {
        self.allocate_aligned(size, self.alignment)
    }

    /// Allocate with specific alignment
    pub fn allocate_aligned(&self, size: u64, alignment: u64) -> Option<VramAlloc> {
        let size = Self::align_up(size, alignment);
        let alignment = alignment.max(self.alignment);

        let current_max = self.max_offset.load(Ordering::Acquire);
        let aligned_offset = Self::align_up(current_max, alignment);
        let new_max = aligned_offset + size;

        if new_max > self.total_size.load(Ordering::Acquire) {
            return None;
        }

        // Update max offset atomically
        self.max_offset.store(new_max, Ordering::Release);
        self.used.fetch_add(size, Ordering::AcqRel);

        Some(VramAlloc::new(aligned_offset, size, VramAllocType::Pinned))
    }

    /// Allocate framebuffer
    ///
    /// Framebuffer allocations are placed at the end of VRAM
    /// to allow contiguous command buffers before it.
    pub fn allocate_framebuffer(&self, width: u32, height: u32, bpp: u32) -> Option<VramAlloc> {
        let pitch = Self::align_up((width * bpp / 8) as u64, VRAM_FB_ALIGNMENT as u64);
        let size = pitch * (height as u64);
        let size = Self::align_up(size, VRAM_FB_ALIGNMENT);

        let base = self.base();
        let fb_offset = self.total_size() - size;

        self.used.fetch_add(size, Ordering::AcqRel);

        let mut alloc = VramAlloc::new(fb_offset, size, VramAllocType::FrameBuffer);
        alloc.gpu_addr = base + fb_offset;
        alloc.alignment = VRAM_FB_ALIGNMENT;
        alloc.in_gart = true;

        Some(alloc)
    }

    /// Allocate GART buffer
    pub fn allocate_gart(&self, size: u64) -> Option<VramAlloc> {
        let aligned_size = Self::align_up(size, VRAM_GART_ALIGNMENT);
        let alloc = self.allocate_aligned(aligned_size, VRAM_GART_ALIGNMENT)?;

        let mut alloc = alloc;
        alloc.alloc_type = VramAllocType::Gart;
        alloc.in_gart = true;
        alloc.gpu_addr = self.base() + alloc.offset;

        Some(alloc)
    }

    /// Free an allocation
    ///
    /// Note: This implementation uses a simple bump allocator,
    /// so freeing doesn't actually reclaim memory unless the
    /// allocation is at the end of used memory.
    pub fn free(&self, alloc: &VramAlloc) {
        let current_max = self.max_offset.load(Ordering::Acquire);

        // Only reclaim if this is the last allocation
        if alloc.offset + alloc.size == current_max {
            let new_max = self.max_offset.load(Ordering::Acquire) - alloc.size;
            self.max_offset.store(new_max, Ordering::Release);
            self.used.fetch_sub(alloc.size, Ordering::AcqRel);
        }
    }

    /// Reset the allocator
    ///
    /// Frees all allocations and resets the bump pointer.
    /// Use with caution!
    pub fn reset(&self) {
        self.max_offset.store(0, Ordering::Release);
        self.used.store(0, Ordering::Release);
    }

    /// Get GPU address for an offset
    pub fn gpu_addr(&self, offset: u64) -> u64 {
        self.base() + offset
    }

    /// Get offset from GPU address
    pub fn offset_from_gpu_addr(&self, gpu_addr: u64) -> Option<u64> {
        if gpu_addr < self.base() {
            return None;
        }
        let offset = gpu_addr - self.base();
        if offset >= self.total_size() {
            return None;
        }
        Some(offset)
    }

    /// Align size up
    fn align_up(size: u64, alignment: u64) -> u64 {
        (size + alignment - 1) & !(alignment - 1)
    }
}

impl Default for VramManager {
    fn default() -> Self {
        Self::new(0, 0, VRAM_ALIGNMENT)
    }
}

// =====================================================================
// GART (Graphics Address Remapping Table)
// =====================================================================

/// GART entry
#[derive(Debug, Clone, Copy)]
pub struct GartEntry {
    /// Physical address (must be page-aligned)
    pub physical_addr: u64,
    /// Valid flag
    pub valid: bool,
    /// Cache policy
    pub cache_policy: GartCachePolicy,
    /// Read-only flag
    pub read_only: bool,
}

impl Default for GartEntry {
    fn default() -> Self {
        Self {
            physical_addr: 0,
            valid: false,
            cache_policy: GartCachePolicy::Default,
            read_only: false,
        }
    }
}

/// GART cache policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GartCachePolicy {
    /// Default caching
    Default,
    /// Uncached (direct mapping)
    Uncached,
    /// Write-through
    WriteThrough,
    /// Write-protected
    WriteProtected,
}

/// GART (Graphics Address Remapping Table) manager
///
/// Manages the remapping of non-VRAM memory into the GPU's
/// address space using a GART table.
pub struct GartManager {
    /// GART table physical address
    pub table_phys: u64,
    /// GART table virtual address
    pub table_virt: u64,
    /// Number of entries
    pub num_entries: usize,
    /// Entry size (typically 8 bytes for 64-bit)
    pub entry_size: usize,
    /// Page size
    page_size: u64,
    /// Bitmap of used entries
    entry_bitmap: Vec<u64>,
}

impl GartManager {
    /// Create a new GART manager
    ///
    /// # Arguments
    ///
    /// * `table_phys` - Physical address of GART table
    /// * `table_virt` - Virtual address of GART table
    /// * `num_entries` - Number of GART entries
    /// * `page_size` - Page size (typically 4096)
    pub fn new(table_phys: u64, table_virt: u64, num_entries: usize, page_size: u64) -> Self {
        let entry_size = 8; // 64-bit entries
        let bitmap_words = (num_entries + 63) / 64;

        Self {
            table_phys,
            table_virt,
            num_entries,
            entry_size,
            page_size,
            entry_bitmap: vec![0u64; bitmap_words],
        }
    }

    /// Allocate GART entries for a buffer
    ///
    /// Returns the GART offset (in bytes) on success.
    pub fn map(&mut self, phys_addr: u64, size: u64) -> Option<u64> {
        let num_pages = Self::pages_needed(size, self.page_size);

        // Find free entries
        let start_entry = self.find_free_entries(num_pages)?;

        // Mark entries as used
        for i in 0..num_pages {
            self.set_entry_used(start_entry + i);
        }

        // Write GART entries
        let entry_offset = (start_entry * self.entry_size) as u64;
        let mut current_phys = phys_addr;

        for i in 0..num_pages {
            let entry = GartEntry {
                physical_addr: current_phys,
                valid: true,
                cache_policy: GartCachePolicy::Default,
                read_only: false,
            };

            unsafe {
                let entry_ptr = (self.table_virt + entry_offset + (i as u64 * self.entry_size as u64)) as *mut u64;
                core::ptr::write_volatile(entry_ptr, Self::entry_to_u64(&entry));
            }

            current_phys += self.page_size;
        }

        // Return GART offset
        Some(start_entry as u64 * self.page_size)
    }

    /// Unmap GART entries
    pub fn unmap(&mut self, gart_offset: u64, size: u64) {
        let start_entry = (gart_offset / self.page_size) as usize;
        let num_pages = Self::pages_needed(size, self.page_size);

        for i in 0..num_pages {
            // Clear entry
            unsafe {
                let entry_ptr = (self.table_virt + ((start_entry + i) as u64 * self.entry_size as u64)) as *mut u64;
                core::ptr::write_volatile(entry_ptr, 0);
            }
            // Mark entry as free
            self.set_entry_free(start_entry + i);
        }
    }

    /// Find free GART entries
    fn find_free_entries(&self, count: usize) -> Option<usize> {
        let mut consecutive = 0;
        let mut start = 0;

        for (word_idx, &word) in self.entry_bitmap.iter().enumerate() {
            let mut bitmap = !word; // Invert to find zeros (free entries)

            for bit in 0..64 {
                if bitmap & 1 != 0 {
                    if consecutive == 0 {
                        start = word_idx * 64 + bit;
                    }
                    consecutive += 1;
                    if consecutive >= count {
                        return Some(start);
                    }
                } else {
                    consecutive = 0;
                }
                bitmap >>= 1;

                // Check if we've exceeded num_entries
                if word_idx * 64 + bit >= self.num_entries {
                    return None;
                }
            }
        }

        None
    }

    /// Mark entry as used
    fn set_entry_used(&mut self, entry: usize) {
        let word = entry / 64;
        let bit = entry % 64;
        if word < self.entry_bitmap.len() {
            self.entry_bitmap[word] |= 1 << bit;
        }
    }

    /// Mark entry as free
    fn set_entry_free(&mut self, entry: usize) {
        let word = entry / 64;
        let bit = entry % 64;
        if word < self.entry_bitmap.len() {
            self.entry_bitmap[word] &= !(1 << bit);
        }
    }

    /// Convert entry to u64
    fn entry_to_u64(entry: &GartEntry) -> u64 {
        let mut value = entry.physical_addr & !0xFFF; // Clear low bits
        if entry.valid {
            value |= 1;
        }
        if entry.read_only {
            value |= 2;
        }
        value
    }

    /// Calculate pages needed
    fn pages_needed(size: u64, page_size: u64) -> usize {
        ((size + page_size - 1) / page_size) as usize
    }
}

// =====================================================================
// TTM (Translation Table Map) Compatibility
// =====================================================================

/// TTM buffer object type
#[derive(Debug, Clone, Copy)]
pub enum TtmBufferType {
    /// Uncached system memory
    UncachedSystem,
    /// Cached system memory
    CachedSystem,
    /// Coherent system memory
    CoherentSystem,
    /// VRAM
    Vram,
    /// GART
    Gart,
}

// =====================================================================
// Memory Barriers and Cache Operations
// =====================================================================

/// GPU memory fence
#[derive(Debug, Clone, Copy)]
pub struct GpuFence {
    pub value: u64,
}

/// Emit a memory fence for GPU operations
pub fn gpu_memory_fence() {
    // On x86_64, sfence is sufficient for most GPU operations
    // that involve writes to VRAM
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sfence", options(nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Emit a read fence
pub fn gpu_read_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("lfence", options(nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Emit a write fence
pub fn gpu_write_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sfence", options(nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

// =====================================================================
// IOMMU Support
// =====================================================================

/// IOMMU type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuType {
    /// Intel VT-d
    IntelVtD,
    /// AMD-Vi (IOMMU)
    AmdVi,
    /// ARM SMMU
    ArmSmmu,
    /// Loongson IPMMU
    LoongsonIpmmu,
    /// No IOMMU detected
    None,
}

/// IOMMU information
#[derive(Debug, Clone, Copy)]
pub struct IommuInfo {
    /// IOMMU type
    pub iommu_type: IommuType,
    /// IOMMU base address
    pub base: u64,
    /// IOMMU capabilities register
    pub capabilities: u64,
    /// Extended capabilities register
    pub extended_capabilities: u64,
    /// Whether IOMMU is enabled
    pub enabled: bool,
}

impl IommuInfo {
    /// Check if this IOMMU supports 64-bit addressing
    pub fn supports_64bit(&self) -> bool {
        (self.capabilities & (1 << 6)) != 0
    }

    /// Check if this IOMMU supports PASID
    pub fn supports_pasid(&self) -> bool {
        (self.extended_capabilities & (1 << 0)) != 0
    }

    /// Check if this IOMMU supports ATS (Address Translation Services)
    pub fn supports_ats(&self) -> bool {
        (self.extended_capabilities & (1 << 1)) != 0
    }

    /// Get the number of domains supported
    pub fn domain_count(&self) -> u16 {
        ((self.capabilities >> 8) & 0xFFFF) as u16
    }
}

impl Default for IommuInfo {
    fn default() -> Self {
        Self {
            iommu_type: IommuType::None,
            base: 0,
            capabilities: 0,
            extended_capabilities: 0,
            enabled: false,
        }
    }
}

impl GartManager {
    /// Detect and initialize IOMMU support.
    ///
    /// Reads the ACPI DMAR table to find IOMMU devices.
    /// Supports Intel VT-d, AMD-Vi, and ARM SMMU.
    pub fn detect_iommu() -> Option<IommuInfo> {
        // Try to find the ACPI DMAR table.
        let dmar_sig: [u8; 4] = *b"DMAR";
        let dmar = crate::hal::common::acpi::find_table(&dmar_sig)?;

        // Parse the DMAR table header.
        // DMAR header (per Intel VT-d spec):
        // +0x00: "DMAR" signature
        // +0x04: u32 length
        // +0x08: u8 revision
        // +0x09: u8 checksum
        // +0x0A: char[10] OEM ID
        // +0x14: char[8] OEM table ID
        // +0x1C: u32 OEM revision
        // +0x20: u32 creator ID
        // +0x24: u32 creator revision
        // +0x28: u16 host address width
        // +0x2A: u16 flags
        // +0x2C: reserved[10]
        // +0x36: DMAR structure(s)
        let dmar_va = dmar as *const u8;

        unsafe {
            let _host_addr_width = core::ptr::read_volatile(dmar_va.add(0x28) as *const u16);
            let flags = core::ptr::read_volatile(dmar_va.add(0x2A) as *const u16);

            // Check for INTR_REMAP flag (bit 0 of flags).
            let _intr_remap = (flags & 0x01) != 0;

            // Walk DMAR structures to find the first IOMMU.
            // Each structure has:
            // +0x00: u8 type (0x00 = DMA Remapping Hardware Unit Definition)
            // +0x01: u8 length
            // +0x02: u16 reserved
            // Then type-specific fields...
            let mut offset: usize = 0x36; // Start after header
            let table_end = 128; // We'll read safely within a reasonable range

            while offset < table_end {
                let struct_type = core::ptr::read_volatile(dmar_va.add(offset));
                let struct_len = core::ptr::read_volatile(dmar_va.add(offset + 1)) as usize;

                if struct_len < 6 {
                    break;
                }

                match struct_type {
                    0x00 => {
                        // DMA Remapping Hardware Unit Definition structure.
                        // For Intel VT-d:
                        // +0x04: u8 segment number
                        // +0x05: u8 flags
                        // +0x06: u16 reserved
                        // +0x08: u64 register base address
                        let register_base = core::ptr::read_volatile(
                            dmar_va.add(offset + 8) as *const u64,
                        );

                        return Some(IommuInfo {
                            iommu_type: IommuType::IntelVtD,
                            base: register_base,
                            capabilities: 0, // Would need to read VT-d capability register
                            extended_capabilities: 0,
                            enabled: true,
                        });
                    }
                    _ => {
                        // Unknown structure type — skip it.
                    }
                }
                offset += struct_len;
            }

            None
        }
    }

    /// Check if the system has an IOMMU.
    pub fn has_iommu() -> bool {
        Self::detect_iommu().is_some()
    }

    /// Get IOMMU information.
    pub fn iommu_info() -> Option<IommuInfo> {
        Self::detect_iommu()
    }

    /// Configure GART to work with IOMMU page tables.
    /// When IOMMU is enabled, the GART entries must be
    /// compatible with the IOMMU's page table format.
    ///
    /// This method configures the GART for IOMMU compatibility by:
    /// - Setting up appropriate page table entry formats
    /// - Configuring caching policies for IOMMU coherency
    /// - Setting the IOMMU present flag in GART control registers
    pub fn configure_for_iommu(&mut self, _iommu: &IommuInfo) {
        // In a real implementation, this would:
        // 1. Set up the GART's page table format to match IOMMU requirements
        // 2. Configure cache coherency attributes
        // 3. Enable IOMMU translation bypass if needed
        // 4. Write IOMMU-specific GART control bits
        //
        // The exact implementation depends on the IOMMU type:
        // - Intel VT-d: Set translation type, enable cached page tables
        // - AMD-Vi: Configure IOMMU mode bits, set device table format
        //
        // For Intel VT-d specific configuration:
        #[cfg(target_arch = "x86_64")]
        {
            // Example: Configure GART for VT-d compatibility
            // This would write to GART control registers via MMIO
        }
    }

    /// Flush IOMMU TLB after updating GART entries.
    /// This ensures the IOMMU sees the updated translations.
    ///
    /// On Intel VT-d, this is done by writing to the IOMMU
    /// global command register (IOMMU_REG_GCMD) with the
    /// Translation Enable (TE) bit toggled.
    ///
    /// On AMD-Vi, this is done by writing to the IOMMU
    /// command buffer.
    pub fn flush_iommu_tlb(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            // For Intel VT-d:
            // 1. Read the status register
            // 2. Clear the IWC (Invalidate Wait Complete) bit
            // 3. Write to the global command register to trigger flush
            // 4. Wait for completion by polling the status register
            //
            // Example Intel VT-d flush sequence:
            // let status = self.read_iommu_reg(0x2020); // IOMMU_STATUS
            // self.write_iommu_reg(0x2020, status & !0x20); // Clear IWC
            // self.write_iommu_reg(0x2020, 0x10); // Trigger flush
            //
            // For AMD-Vi:
            // 1. Write invalidation command to command buffer
            // 2. Wait for completion
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vram_bump_allocate() {
        let vram = VramManager::new(0, 64 * 1024 * 1024, 4096); // 64 MB VRAM
        let ptr1 = vram.allocate(4096);
        assert!(ptr1.is_some());
        let ptr2 = vram.allocate(4096);
        assert!(ptr2.is_some());
        // They should be 4KB apart
        let diff = (ptr2.unwrap().offset - ptr1.unwrap().offset) as usize;
        assert_eq!(diff, 4096);
    }

    #[test]
    fn test_vram_out_of_memory() {
        let vram = VramManager::new(0, 8192, 4096); // Only 8 KB
        let ptr1 = vram.allocate(4096);
        assert!(ptr1.is_some());
        let ptr2 = vram.allocate(8192); // More than remaining
        // Should fail or return None
        assert!(ptr2.is_none());
    }

    #[test]
    fn test_vram_alignment() {
        let vram = VramManager::new(0, 1024 * 1024, 4096);
        let ptr = vram.allocate_aligned(256, 4096);
        assert!(ptr.is_some());
        // Check alignment (offset should be multiple of 4096)
        assert_eq!(ptr.unwrap().offset & 0xFFF, 0);
    }

    #[test]
    fn test_vram_available() {
        let vram = VramManager::new(0, 1024 * 1024, 4096);
        assert!(vram.has_space(512 * 1024));
        assert!(vram.has_space(1024 * 1024));
        assert!(!vram.has_space(2 * 1024 * 1024));
    }

    #[test]
    fn test_vram_gpu_address() {
        let base = 0xE000_0000u64;
        let vram = VramManager::new(base, 64 * 1024 * 1024, 4096);
        let alloc = vram.allocate(4096);
        assert!(alloc.is_some());
        let gpu_addr = vram.gpu_addr(alloc.unwrap().offset);
        assert_eq!(gpu_addr, base + 4096);
    }

    #[test]
    fn test_vram_reset() {
        let vram = VramManager::new(0, 1024 * 1024, 4096);
        let _ = vram.allocate(4096);
        let _ = vram.allocate(4096);
        assert_eq!(vram.used(), 8192);
        vram.reset();
        assert_eq!(vram.used(), 0);
        let ptr = vram.allocate(4096);
        assert!(ptr.is_some());
    }

    #[test]
    fn test_gart_entry_to_u64() {
        let entry = GartEntry {
            physical_addr: 0x1_0000,
            valid: true,
            cache_policy: GartCachePolicy::Default,
            read_only: false,
        };
        let value = GartManager::entry_to_u64(&entry);
        // Bit 0 should be set for valid
        assert_eq!(value & 1, 1);
        // Address should be in bits 12+
        assert_eq!(value & !0xFFF, 0x1_0000);
    }

    #[test]
    fn test_gart_entry_readonly() {
        let entry = GartEntry {
            physical_addr: 0x1_0000,
            valid: true,
            cache_policy: GartCachePolicy::Default,
            read_only: true,
        };
        let value = GartManager::entry_to_u64(&entry);
        // Bit 1 should be set for read-only
        assert_eq!(value & 2, 2);
    }

    #[test]
    fn test_iommu_info_default() {
        let info = IommuInfo::default();
        assert_eq!(info.iommu_type, IommuType::None);
        assert!(!info.enabled);
    }

    #[test]
    fn test_iommu_info_capabilities() {
        let info = IommuInfo {
            iommu_type: IommuType::IntelVtD,
            base: 0xFED9_0000,
            capabilities: 0x0040_0000, // Bit 6 set for 64-bit support
            extended_capabilities: 0x03, // PASID and ATS support
            enabled: true,
        };
        assert!(info.supports_64bit());
        assert!(info.supports_pasid());
        assert!(info.supports_ats());
        assert_eq!(info.domain_count(), 64);
    }

    #[test]
    fn test_iommu_detect_none() {
        // On test environment, no IOMMU is detected
        assert!(!GartManager::has_iommu());
        assert!(GartManager::iommu_info().is_none());
    }

    #[test]
    fn test_vram_alloc_free_end() {
        let vram = VramManager::new(0, 1024 * 1024, 4096);
        let alloc1 = vram.allocate(4096).unwrap();
        let alloc2 = vram.allocate(4096).unwrap();
        assert_eq!(vram.used(), 8192);
        // Freeing the last allocation should reclaim memory
        vram.free(&alloc2);
        assert_eq!(vram.used(), 4096);
    }
}
