//! User-space PE program loader
//!
//! Loads a Windows 7 x64 PE image into a user-mode process's address
//! space, sets up the PEB/TEB, builds the user-mode stack, and returns
//! a context describing where execution should start.
//!
//! Layered on top of `crate::loader` (which already has the
//! PE32/PE32+ parser, import resolver, and base-relocation engine)
//! and `crate::mm::vas` (page-table infrastructure).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::libs::ntdll::types::NTSTATUS;
use crate::mm::pte;
use crate::mm::vas;

/// NTSTATUS success / failure constants (subset)
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_INVALID_IMAGE_FORMAT: NTSTATUS = 0xC000_007B_u32 as i32;
pub const STATUS_NOT_FOUND: NTSTATUS = 0xC000_0225_u32 as i32;
pub const STATUS_NO_MEMORY: NTSTATUS = 0xC000_0017_u32 as i32;

/// PEB at this fixed address in every user process (matches what SMSS
/// already programs in `servers::smss::init_peb`).
pub const PEB_VA: u64 = 0x0000_0000_7FFE_D000;

/// TEB at this fixed address per user thread.
pub const TEB_VA: u64 = 0x0000_7FFF_FFDF_0000;

/// User-mode image default base — matches Windows 7 x64.
pub const DEFAULT_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;

/// User-stack top. Stack grows down.
pub const USER_STACK_TOP: u64 = TEB_VA - 0x2000;

/// Where the process_parameters block is placed (above the PEB).
pub const PROCESS_PARAMS_VA: u64 = 0x0000_0000_7FFE_D000 + 0x1000;

/// Total reserved process_parameters area (must hold params + env
/// + command line — keep generous for now).
pub const PROCESS_PARAMS_SIZE: u64 = 0x4000;

/// Default user stack size if nothing more specific is requested.
pub const DEFAULT_USER_STACK_SIZE: u64 = 0x80000; // 512 KiB

/// Result of a successful load.
#[derive(Debug, Clone, Copy)]
pub struct UserProcessContext {
    pub entry_point: u64,
    pub user_rsp: u64,
    pub peb_va: u64,
    pub teb_va: u64,
    pub image_base: u64,
}

/// Loader instance bound to a target PML4 physical address.
pub struct UserProgramLoader {
    pml4_phys: u64,
}

impl UserProgramLoader {
    pub const fn new(pml4_phys: u64) -> Self {
        Self { pml4_phys }
    }

    /// Resolve `image_path` to its on-disk bytes, then perform the
    /// full load. The file contents are owned by the file cache, so
    /// the loader can borrow them for the duration of the call.
    pub fn load_into_user_space(
        &mut self,
        image_path: &str,
        peb_already_initialized: bool,
        teb_already_initialized: bool,
    ) -> Result<UserProcessContext, NTSTATUS> {
        // ---- 1. Resolve file bytes. A missing image is a hard error:
        // we must never map a placeholder image and report success. ----
        let image_storage = match find_image_bytes(image_path) {
            Some(image) => image,
            None => return Err(STATUS_NOT_FOUND),
        };
        let bytes: &[u8] = &image_storage;

        // ---- 2. Run the complete PE pipeline and map the image ------
        let mapping = crate::loader::load_named_image_into_user_address_space(
            self.pml4_phys,
            bytes,
            image_path.rsplit('/').next().unwrap_or(image_path),
        )
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let image_base = mapping.image_base;
        let entry_point = mapping.entry_point;

        // ---- 6. Set up PEB / TEB ------------------------------------
        let peb = if peb_already_initialized {
            PEB_VA
        } else {
            init_peb_in_pml4(self.pml4_phys)?
        };
        let teb = if teb_already_initialized {
            TEB_VA
        } else {
            init_teb_in_pml4(self.pml4_phys, peb)?
        };

        // ---- 7. Build user-mode stack -------------------------------
        let user_rsp = build_user_stack(self.pml4_phys, teb, image_path)?;

        USER_LOAD_COUNT.fetch_add(1, Ordering::Relaxed);

        Ok(UserProcessContext {
            entry_point,
            user_rsp,
            peb_va: peb,
            teb_va: teb,
            image_base,
        })
    }

    /// Allocate a single page of user-mode virtual address.
    pub fn allocate_user_vma(&mut self, size: u64) -> Result<u64, NTSTATUS> {
        let aligned = ((size + 0xFFF) & !0xFFF) as u32;
        vas::allocate_user_va(self.pml4_phys, 0, aligned) // PAGE_READWRITE
            .ok_or(STATUS_NO_MEMORY)
    }
}

/// count of user-mode processes successfully loaded.
pub static USER_LOAD_COUNT: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// PE base relocation
// ---------------------------------------------------------------------------

/// PE format magic numbers (pepecoff.h): PE32 and PE32+.
const PE_MAGIC_PE32: u16 = 0x010B;
const PE_MAGIC_PE32PLUS: u16 = 0x020B;

/// Data-directory index of the base-relocation table (pepecoff.h).
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

/// Base relocation type values from the PE format spec, as Mm's
/// relocation processor consumes them on Windows 7.
const REL_BASED_ABSOLUTE: u16 = 0;
const REL_BASED_HIGH: u16 = 1;
const REL_BASED_LOW: u16 = 2;
const REL_BASED_HIGHLOW: u16 = 3;
const REL_BASED_HIGHADJ: u16 = 4;
const REL_BASED_REL32: u16 = 7;
const REL_BASED_DIR64: u16 = 10;

/// Optional-header layout offsets that differ between PE32 and PE32+.
struct OptHeaderLayout {
    data_directory_offset: usize,
}

impl OptHeaderLayout {
    fn for_magic(magic: u16) -> Option<Self> {
        if magic == PE_MAGIC_PE32PLUS {
            // PE32+: 0x70 bytes of fixed fields, then the data
            // directories.
            Some(Self {
                data_directory_offset: 0x70,
            })
        } else if magic == PE_MAGIC_PE32 {
            // PE32: 0x60 bytes of fixed fields, then the data
            // directories.
            Some(Self {
                data_directory_offset: 0x60,
            })
        } else {
            None
        }
    }
}

/// Locate a byte range in the raw PE file for an RVA, walking the
/// section table exactly as the kernel PE loader does: the address
/// lands in the section whose virtual range covers it, at the same
/// offset from the section's raw data start.
fn rva_to_file_offset(
    raw: &[u8],
    section_table_offset: usize,
    number_of_sections: u16,
    rva: u32,
) -> Option<usize> {
    for i in 0..number_of_sections as usize {
        let sh_off = section_table_offset + i * 40;
        if sh_off + 40 > raw.len() {
            return None;
        }
        let virtual_address = u32::from_le_bytes([
            raw[sh_off + 12],
            raw[sh_off + 13],
            raw[sh_off + 14],
            raw[sh_off + 15],
        ]);
        let size_of_raw_data = u32::from_le_bytes([
            raw[sh_off + 16],
            raw[sh_off + 17],
            raw[sh_off + 18],
            raw[sh_off + 19],
        ]);
        let pointer_to_raw_data = u32::from_le_bytes([
            raw[sh_off + 20],
            raw[sh_off + 21],
            raw[sh_off + 22],
            raw[sh_off + 23],
        ]);
        if rva >= virtual_address && rva < virtual_address.saturating_add(size_of_raw_data) {
            return Some(pointer_to_raw_data as usize + (rva - virtual_address) as usize);
        }
    }
    None
}

/// Apply the PE base-relocation table to an RVA-laid-out image.
///
/// This is the work Mm's relocation processor performs when the OS
/// loader maps a user image away from its preferred `ImageBase`
/// (Windows 7 always relocates rather than refusing to load, the
/// way SMSS loads cmd.exe into a fresh 4 GB process space). `image`
/// is the image laid out by RVA (headers at 0, sections copied);
/// `raw` is the source PE file, used to read the `.reloc`
/// directory, whose blocks live at file offsets the section table
/// maps. `delta` is actual_base - preferred_base; a zero delta
/// applies nothing, matching Mm.
///
/// Handled types are the ones x86/x64 images carry: ABSOLUTE (skip),
/// HIGH, LOW, HIGHLOW, HIGHADJ, REL32 and DIR64. Each block is walked
/// by byte range because HIGHADJ consumes two entry slots, so a fixed
/// entry count would read past the block. Returns the number of
/// relocations applied.
pub fn apply_base_relocations_to_image(image: &mut [u8], raw: &[u8], delta: i64) -> usize {
    if delta == 0 {
        return 0;
    }

    // --- Parse headers from the raw file --------------------------------
    if raw.len() < 0x40 {
        return 0;
    }
    let e_lfanew = u32::from_le_bytes([raw[0x3C], raw[0x3D], raw[0x3E], raw[0x3F]]) as usize;
    if e_lfanew + 4 + 20 + 2 > raw.len() {
        return 0;
    }
    if &raw[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return 0;
    }
    let cof_off = e_lfanew + 4; // COFF header follows the signature
    let number_of_sections = u16::from_le_bytes([raw[cof_off + 2], raw[cof_off + 3]]);
    let opt_off = cof_off + 20;
    let magic = u16::from_le_bytes([raw[opt_off], raw[opt_off + 1]]);
    let layout = match OptHeaderLayout::for_magic(magic) {
        Some(layout) => layout,
        None => return 0,
    };
    let is_pe32plus = magic == PE_MAGIC_PE32PLUS;
    // Size of the fixed optional-header fields before the data
    // directories: magic(2) + the rest, per pepecoff.h layout. The
    // directory array starts at opt_off + data_directory_offset.
    let dd_off = opt_off + layout.data_directory_offset;
    let reloc_index = dd_off + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
    if reloc_index + 8 > raw.len() {
        return 0;
    }
    let reloc_rva = u32::from_le_bytes([
        raw[reloc_index],
        raw[reloc_index + 1],
        raw[reloc_index + 2],
        raw[reloc_index + 3],
    ]);
    let reloc_size = u32::from_le_bytes([
        raw[reloc_index + 4],
        raw[reloc_index + 5],
        raw[reloc_index + 6],
        raw[reloc_index + 7],
    ]);
    if reloc_rva == 0 || reloc_size == 0 {
        return 0;
    }

    // The .reloc directory itself is usually inside .rdata (a section
    // the file maps 1:1), so resolve it through the section table.
    let section_table = opt_off + 2 + 18 * 2 + 4 + 4 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2;
    let mut cur = match rva_to_file_offset(raw, section_table, number_of_sections, reloc_rva) {
        Some(offset) => offset,
        None => return 0,
    };
    let end = cur.saturating_add(reloc_size as usize).min(raw.len());

    let mut applied = 0usize;
    while cur + 8 <= end {
        let page_rva = u32::from_le_bytes([raw[cur], raw[cur + 1], raw[cur + 2], raw[cur + 3]]);
        let block_size =
            u32::from_le_bytes([raw[cur + 4], raw[cur + 5], raw[cur + 6], raw[cur + 7]]);

        // Blocks are LONG-aligned and at most one page of entries.
        if !(8..=0x1000_0000).contains(&block_size) {
            break;
        }
        let block_end = cur.saturating_add(block_size as usize).min(end);
        cur += 8;

        while cur + 2 <= block_end {
            let entry = u16::from_le_bytes([raw[cur], raw[cur + 1]]);
            cur += 2;

            let reloc_type = entry >> 12;
            let offset_in_page = (entry & 0xFFF) as u32;
            let target_rva = page_rva.wrapping_add(offset_in_page) as usize;

            match reloc_type {
                REL_BASED_ABSOLUTE => {
                    // Padding entry; nothing to fix up.
                }
                REL_BASED_HIGH => {
                    if target_rva + 2 <= image.len() {
                        let current =
                            u16::from_le_bytes([image[target_rva], image[target_rva + 1]]);
                        let fixed = current.wrapping_add((delta >> 16) as u16);
                        image[target_rva..target_rva + 2].copy_from_slice(&fixed.to_le_bytes());
                        applied += 1;
                    }
                }
                REL_BASED_LOW => {
                    if target_rva + 2 <= image.len() {
                        let current =
                            u16::from_le_bytes([image[target_rva], image[target_rva + 1]]);
                        let fixed = current.wrapping_add(delta as u16);
                        image[target_rva..target_rva + 2].copy_from_slice(&fixed.to_le_bytes());
                        applied += 1;
                    }
                }
                REL_BASED_HIGHLOW => {
                    if target_rva + 4 <= image.len() {
                        let current = i32::from_le_bytes([
                            image[target_rva],
                            image[target_rva + 1],
                            image[target_rva + 2],
                            image[target_rva + 3],
                        ]);
                        let fixed = current.wrapping_add(delta as i32);
                        image[target_rva..target_rva + 4].copy_from_slice(&fixed.to_le_bytes());
                        applied += 1;
                    }
                }
                REL_BASED_HIGHADJ => {
                    // Two slots: the second supplies the signed low 16
                    // bits that reconstruct the 32-bit value whose high
                    // half this entry fixes, so carries propagate.
                    if cur + 2 > block_end {
                        break;
                    }
                    let next = u16::from_le_bytes([raw[cur], raw[cur + 1]]);
                    cur += 2;
                    if target_rva + 2 <= image.len() {
                        let current =
                            u16::from_le_bytes([image[target_rva], image[target_rva + 1]]);
                        let combined = ((current as i64) << 16)
                            .wrapping_add(i16::from_le_bytes(next.to_le_bytes()) as i64)
                            .wrapping_add(delta);
                        let fixed = (combined >> 16) as u16;
                        image[target_rva..target_rva + 2].copy_from_slice(&fixed.to_le_bytes());
                        applied += 1;
                    }
                }
                REL_BASED_REL32 => {
                    // RIP-relative 32-bit displacement: the delta was
                    // computed as (actual_base - preferred_base), which
                    // is exactly what the encoded relative offset must
                    // gain.
                    if target_rva + 4 <= image.len() {
                        let current = i32::from_le_bytes([
                            image[target_rva],
                            image[target_rva + 1],
                            image[target_rva + 2],
                            image[target_rva + 3],
                        ]);
                        let fixed = current.wrapping_add(delta as i32);
                        image[target_rva..target_rva + 4].copy_from_slice(&fixed.to_le_bytes());
                        applied += 1;
                    }
                }
                REL_BASED_DIR64 if is_pe32plus && target_rva + 8 <= image.len() => {
                    let mut current = [0u8; 8];
                    current.copy_from_slice(&image[target_rva..target_rva + 8]);
                    let fixed = (i64::from_le_bytes(current).wrapping_add(delta)) as u64;
                    image[target_rva..target_rva + 8].copy_from_slice(&fixed.to_le_bytes());
                    applied += 1;
                }
                _ => {
                    // Architecture-specific types (MIPS/ARM/RISC-V/
                    // LoongAuth) cannot appear in an x86/x64 image and
                    // would need a different fixup width; skip them.
                }
            }
        }
    }
    applied
}
// ---------------------------------------------------------------------------
// File / image resolution helpers
// ---------------------------------------------------------------------------

/// Look up an image by its NT path, consulting the on-disk file
/// cache via SMSS. Returns `None` when the path cannot be read;
/// callers must treat that as a load failure (`STATUS_NOT_FOUND`),
/// never as an invitation to substitute a placeholder image.
pub fn find_image_bytes(path: &str) -> Option<alloc::vec::Vec<u8>> {
    #[cfg(test)]
    {
        if let Some(image) = test_images()
            .iter()
            .find(|(candidate, _)| candidate == path)
            .map(|(_, image)| image.clone())
        {
            return Some(image);
        }
    }
    let mut nt_path = alloc::string::String::new();
    if !(path.starts_with('\\') || path.starts_with('/')) {
        nt_path.push('\\');
    }
    nt_path.push_str(path);
    let data = crate::servers::smss::read_pe_from_disk(&nt_path)?;
    Some(core::mem::ManuallyDrop::into_inner(data))
}

#[cfg(test)]
pub fn load_test_image(path: &str) {
    let image = alloc::vec::Vec::from(user_fallback_bytes());
    let mut images = test_images();
    if let Some(existing) = images.iter_mut().find(|(candidate, _)| candidate == path) {
        existing.1 = image;
    } else {
        images.push((alloc::string::String::from(path), image));
    }
}

#[cfg(test)]
fn test_images() -> crate::ke::sync::SpinlockGuard<
    'static,
    alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>,
> {
    static TEST_IMAGES: crate::ke::sync::Spinlock<
        alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>,
    > = crate::ke::sync::Spinlock::new(alloc::vec::Vec::new());
    TEST_IMAGES.lock()
}

/// Tiny placeholder "image" that is good enough to exercise the
/// loader without crashing: a single 4 KiB R/W page containing a
/// `ret` instruction at offset 0.
pub fn user_fallback_bytes() -> &'static [u8] {
    &FALLBACK_IMAGE
}

const FALLBACK_IMAGE: [u8; 16] = [
    0xC3, // ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PEB / TEB initialization in user PML4
// ---------------------------------------------------------------------------

/// Install a zeroed, R/W PEB page at `PEB_VA` and return its VA.
pub fn init_peb_in_pml4(pml4: u64) -> Result<u64, NTSTATUS> {
    let phys = match crate::mm::pfn::allocate_pfn() {
        Some(p) => crate::mm::pte::pfn_to_phys(p),
        None => return Err(STATUS_NO_MEMORY),
    };
    if phys == 0 {
        return Err(STATUS_NO_MEMORY);
    }
    let r = vas::map_page_in_pml4(pml4, PEB_VA, phys, pte::PTE_P | pte::PTE_RW | pte::PTE_US);
    if r != vas::MmStatus::Ok {
        return Err(STATUS_NO_MEMORY);
    }
    Ok(PEB_VA)
}

/// Install a zeroed, R/W TEB page at `TEB_VA` and return its VA.
pub fn init_teb_in_pml4(pml4: u64, _peb: u64) -> Result<u64, NTSTATUS> {
    let phys = match crate::mm::pfn::allocate_pfn() {
        Some(p) => crate::mm::pte::pfn_to_phys(p),
        None => return Err(STATUS_NO_MEMORY),
    };
    if phys == 0 {
        return Err(STATUS_NO_MEMORY);
    }
    let r = vas::map_page_in_pml4(pml4, TEB_VA, phys, pte::PTE_P | pte::PTE_RW | pte::PTE_US);
    if r != vas::MmStatus::Ok {
        return Err(STATUS_NO_MEMORY);
    }
    Ok(TEB_VA)
}

// ---------------------------------------------------------------------------
// User-stack construction
// ---------------------------------------------------------------------------

/// Reserve the canonical user stack above `TEB_VA`, write a small
/// startup frame, and return the initial user-mode RSP. The Windows
/// x64 ABI requires RSP to be 16-byte aligned at the call site.
pub fn build_user_stack(_pml4: u64, _teb_va: u64, _image_path: &str) -> Result<u64, NTSTATUS> {
    // The full implementation walks process_parameters, env, command
    // line, and a small "thread-startup" frame. For Phase 1 we hand
    // back a placeholder 16-byte-aligned address above the TEB.
    Ok(USER_STACK_TOP)
}
