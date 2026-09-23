//! Memory-Mapped File Support (Section Objects)
//!
//! Implements Windows 7 section objects for memory-mapped files.
//! Section objects allow files to be mapped into process address space
//! for efficient file I/O through memory operations.
//!
//! ## Architecture
//!
//! A section object represents a shared memory region backed by a file.
//! Multiple processes can map the same section for shared memory access.
//! The memory manager uses section objects to implement:
//! - File mapping (CreateFileMapping/MapViewOfFile)
//! - Executable image loading
//! - Shared memory between processes
//! - Copy-on-write semantics

extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionProtection {
    pub bits: u32,
}

impl SectionProtection {
    pub const PAGE_NOACCESS: Self = Self { bits: 0x01 };
    pub const PAGE_READONLY: Self = Self { bits: 0x02 };
    pub const PAGE_READWRITE: Self = Self { bits: 0x04 };
    pub const PAGE_WRITECOPY: Self = Self { bits: 0x08 };
    pub const PAGE_EXECUTE: Self = Self { bits: 0x10 };
    pub const PAGE_EXECUTE_READ: Self = Self { bits: 0x20 };
    pub const PAGE_EXECUTE_READWRITE: Self = Self { bits: 0x40 };
    pub const PAGE_EXECUTE_WRITECOPY: Self = Self { bits: 0x80 };

    pub const SEC_FILE: Self = Self { bits: 0x800000 };
    pub const SEC_IMAGE: Self = Self { bits: 0x1000000 };
    pub const SEC_RESERVE: Self = Self { bits: 0x4000000 };
    pub const SEC_COMMIT: Self = Self { bits: 0x8000000 };
    pub const SEC_NOCACHE: Self = Self { bits: 0x10000000 };

    pub fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub fn is_writable(&self) -> bool {
        self.contains(Self::PAGE_READWRITE) ||
        self.contains(Self::PAGE_WRITECOPY) ||
        self.contains(Self::PAGE_EXECUTE_READWRITE) ||
        self.contains(Self::PAGE_EXECUTE_WRITECOPY)
    }

    pub fn is_executable(&self) -> bool {
        self.contains(Self::PAGE_EXECUTE) ||
        self.contains(Self::PAGE_EXECUTE_READ) ||
        self.contains(Self::PAGE_EXECUTE_READWRITE) ||
        self.contains(Self::PAGE_EXECUTE_WRITECOPY)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    File = 0,
    Image = 1,
    PageFile = 2,
    Physical = 3,
}

pub struct Section {
    pub id: u64,
    pub section_type: SectionType,
    pub file_id: Option<u64>,
    pub max_size: u64,
    pub protection: SectionProtection,
    pub shared: bool,
    pub ref_count: u32,
    pub kernel_base: Option<u64>,
    pub segments: Vec<SectionSegment>,
}

impl Section {
    pub fn new(
        id: u64,
        section_type: SectionType,
        file_id: Option<u64>,
        max_size: u64,
        protection: SectionProtection,
    ) -> Self {
        Self {
            id,
            section_type,
            file_id,
            max_size,
            protection,
            shared: true,
            ref_count: 1,
            kernel_base: None,
            segments: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, segment: SectionSegment) {
        self.segments.push(segment);
    }

    pub fn add_ref(&mut self) {
        self.ref_count += 1;
    }

    pub fn release(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

#[derive(Debug, Clone)]
pub struct SectionSegment {
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: SectionProtection,
    pub name: [u8; 8],
}

pub struct SectionView {
    pub section_id: u64,
    pub process_id: u32,
    pub base_address: u64,
    pub size: u64,
    pub section_offset: u64,
    pub protection: SectionProtection,
}

pub struct SectionManager {
    sections: BTreeMap<u64, Section>,
    views: Vec<SectionView>,
    sections_created: AtomicU64,
    sections_destroyed: AtomicU64,
    views_created: AtomicU64,
    views_unmapped: AtomicU64,
}

impl SectionManager {
    pub fn new() -> Self {
        Self {
            sections: BTreeMap::new(),
            views: Vec::new(),
            sections_created: AtomicU64::new(0),
            sections_destroyed: AtomicU64::new(0),
            views_created: AtomicU64::new(0),
            views_unmapped: AtomicU64::new(0),
        }
    }

    pub fn create_section(
        &mut self,
        section_type: SectionType,
        file_id: Option<u64>,
        max_size: u64,
        protection: SectionProtection,
    ) -> u64 {
        let section_id = self.generate_section_id();
        let section = Section::new(section_id, section_type, file_id, max_size, protection);

        self.sections.insert(section_id, section);
        self.sections_created.fetch_add(1, Ordering::Relaxed);

        section_id
    }

    pub fn open_section(&mut self, section_id: u64) -> Result<(), ()> {
        if let Some(section) = self.sections.get_mut(&section_id) {
            section.add_ref();
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn close_section(&mut self, section_id: u64) -> Result<(), ()> {
        if let Some(section) = self.sections.get_mut(&section_id) {
            if section.release() {
                self.sections.remove(&section_id);
                self.sections_destroyed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn map_view(
        &mut self,
        section_id: u64,
        process_id: u32,
        base_address: Option<u64>,
        section_offset: u64,
        view_size: u64,
        protection: SectionProtection,
    ) -> Result<u64, ()> {
        let section = self.sections.get(&section_id).ok_or(())?;

        if section_offset + view_size > section.max_size {
            return Err(());
        }

        let base = base_address.unwrap_or_else(|| self.allocate_view_address(process_id, view_size));

        let view = SectionView {
            section_id,
            process_id,
            base_address: base,
            size: view_size,
            section_offset,
            protection,
        };

        self.views.push(view);
        self.views_created.fetch_add(1, Ordering::Relaxed);

        Ok(base)
    }

    pub fn unmap_view(&mut self, process_id: u32, base_address: u64) -> Result<(), ()> {
        if let Some(pos) = self.views.iter().position(|v| {
            v.process_id == process_id && v.base_address == base_address
        }) {
            self.views.remove(pos);
            self.views_unmapped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn get_section(&self, section_id: u64) -> Option<&Section> {
        self.sections.get(&section_id)
    }

    pub fn find_process_views(&self, process_id: u32) -> Vec<&SectionView> {
        self.views
            .iter()
            .filter(|v| v.process_id == process_id)
            .collect()
    }

    pub fn unmap_process_views(&mut self, process_id: u32) {
        let to_remove: Vec<u64> = self.views
            .iter()
            .filter(|v| v.process_id == process_id)
            .map(|v| v.base_address)
            .collect();

        for base in to_remove {
            let _ = self.unmap_view(process_id, base);
        }
    }

    fn allocate_view_address(&self, _process_id: u32, size: u64) -> u64 {
        // In a real implementation, this would use the memory manager
        static NEXT_ADDRESS: AtomicU64 = AtomicU64::new(0x10000000);
        let addr = NEXT_ADDRESS.fetch_add(size, Ordering::Relaxed);
        (addr + 0xFFFF) & !0xFFFF // Align to 64KB
    }

    fn generate_section_id(&self) -> u64 {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    }

    pub fn statistics(&self) -> SectionStatistics {
        SectionStatistics {
            sections_created: self.sections_created.load(Ordering::Relaxed),
            sections_destroyed: self.sections_destroyed.load(Ordering::Relaxed),
            views_created: self.views_created.load(Ordering::Relaxed),
            views_unmapped: self.views_unmapped.load(Ordering::Relaxed),
            active_sections: self.sections.len(),
            active_views: self.views.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SectionStatistics {
    pub sections_created: u64,
    pub sections_destroyed: u64,
    pub views_created: u64,
    pub views_unmapped: u64,
    pub active_sections: usize,
    pub active_views: usize,
}

static SECTION_MANAGER: Spinlock<Option<SectionManager>> = Spinlock::new(None);

pub fn init() {
    let mut guard = SECTION_MANAGER.lock();
    *guard = Some(SectionManager::new());
}

pub fn create_file_mapping(
    file_id: u64,
    max_size: u64,
    protection: SectionProtection,
) -> Result<u64, ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    Ok(mgr.create_section(SectionType::File, Some(file_id), max_size, protection))
}

pub fn create_image_section(
    file_id: u64,
    max_size: u64,
) -> Result<u64, ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    let protection = SectionProtection::PAGE_EXECUTE_READWRITE;
    Ok(mgr.create_section(SectionType::Image, Some(file_id), max_size, protection))
}

pub fn create_pagefile_section(
    max_size: u64,
    protection: SectionProtection,
) -> Result<u64, ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    Ok(mgr.create_section(SectionType::PageFile, None, max_size, protection))
}

pub fn map_view_of_section(
    section_id: u64,
    process_id: u32,
    base_address: Option<u64>,
    section_offset: u64,
    view_size: u64,
    protection: SectionProtection,
) -> Result<u64, ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.map_view(section_id, process_id, base_address, section_offset, view_size, protection)
}

pub fn unmap_view_of_section(process_id: u32, base_address: u64) -> Result<(), ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.unmap_view(process_id, base_address)
}

pub fn close_section(section_id: u64) -> Result<(), ()> {
    let mut mgr = SECTION_MANAGER.lock();
    let mgr = mgr.as_mut().ok_or(())?;
    mgr.close_section(section_id)
}

pub fn statistics() -> Option<SectionStatistics> {
    let mgr = SECTION_MANAGER.lock();
    mgr.as_ref().map(|m| m.statistics())
}
