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
use crate::loader;
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
        // ---- 1. Resolve file bytes (fall back to stub if not found) ----
        let image_storage = find_image_bytes(image_path);
        let bytes: &[u8] = if let Some(image) = image_storage.as_deref() {
            image
        } else {
            user_fallback_bytes()
        };

        // ---- 2. Run the complete PE pipeline and map the image ------
        let mapping = loader::load_named_image_into_user_address_space(
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
// File / image resolution helpers
// ---------------------------------------------------------------------------

/// Look up an image by its NT path. The current implementation
/// returns `None` for any path except the literal kernels we ship;
/// callers should fall back to the hard-coded stub when nothing is
/// found. A future revision will consult the FAT/PSID file cache.
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
fn test_images(
) -> crate::ke::sync::SpinlockGuard<'static, alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>> {
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
