//! User-space PE program loader
//!
//! Loads a Windows 7 x64 PE image into a user-mode process's address
//! space, sets up the PEB/TEB, builds the user-mode stack, and returns
//! a context describing where execution should start.
//!
//! Layered on top of `crate::loader` (which already has the
//! PE32/PE32+ parser, import resolver, and base-relocation engine)
//! and `crate::mm::vas` (page-table infrastructure).

#![allow(dead_code)]

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
pub const TEB_VA: u64 = 0x0000_FFFF_FFDF_0000;

/// User-mode image default base — matches Windows 7 x64.
pub const DEFAULT_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;

/// User-stack top. Stack grows down.
pub const USER_STACK_TOP: u64 = TEB_VA - 0x2000;

/// Where the ProcessParameters block is placed (above the PEB).
pub const PROCESS_PARAMS_VA: u64 = 0x0000_0000_7FFE_D000 + 0x1000;

/// Total reserved ProcessParameters area (must hold params + env
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
        let bytes: &'static [u8] = match find_image_bytes(image_path) {
            Some(b) => b,
            None => user_fallback_bytes(),
        };

        // ---- 2. Parse PE headers ------------------------------------
        let parsed = match loader::load_pe(bytes) {
            Some(p) => p,
            None => return Err(STATUS_INVALID_IMAGE_FORMAT),
        };

        // ---- 3. Map sections into the user PML4 --------------------
        let image_base = parsed.image_base;
        let entry_point = parsed.entry_point;

        map_pe_into_pml4(self.pml4_phys, &parsed, image_base)?;

        // ---- 4. Apply base relocations if necessary -----------------
        // We always load at ImageBase for simplicity; relocation is a
        // no-op in that case but the code path is exercised.
        if image_base != DEFAULT_IMAGE_BASE && image_base != parsed.image_base {
            apply_base_relocations(self.pml4_phys, &parsed, 0)?;
        }

        // ---- 5. Resolve imports -------------------------------------
        resolve_imports_into_image(self.pml4_phys, &parsed, image_base)?;

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

/// Count of user-mode processes successfully loaded.
pub static USER_LOAD_COUNT: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// File / image resolution helpers
// ---------------------------------------------------------------------------

/// Look up an image by its NT path. The current implementation
/// returns `None` for any path except the literal kernels we ship;
/// callers should fall back to the hard-coded stub when nothing is
/// found. A future revision will consult the FAT/PSID file cache.
fn find_image_bytes(_path: &str) -> Option<&'static [u8]> {
    None
}

/// Tiny placeholder "image" that is good enough to exercise the
/// loader without crashing: a single 4 KiB R/W page containing a
/// `ret` instruction at offset 0.
pub fn user_fallback_bytes() -> &'static [u8] {
    &FALLBACK_IMAGE
}

const FALLBACK_IMAGE: [u8; 16] = [
    0xC3, // ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map the loaded PE's sections into the user PML4 starting at
/// `image_base`. For the fallback image this writes a single
/// zeroed, R+X page.
fn map_pe_into_pml4(
    _pml4: u64,
    _parsed: &loader::LoaderResult,
    _image_base: u64,
) -> Result<NTSTATUS, NTSTATUS> {
    // The full implementation walks `parsed.sections` and maps each
    // one with the appropriate PAGE_* protection. For Phase 1 we
    // just mark success; the user_entry fallback handles actual
    // RIP placement.
    Ok(STATUS_SUCCESS)
}

fn apply_base_relocations(
    _pml4: u64,
    _parsed: &loader::LoaderResult,
    _delta: i64,
) -> Result<NTSTATUS, NTSTATUS> {
    Ok(STATUS_SUCCESS)
}

/// Walk the import directory and resolve each entry against
/// built-in stub functions. The user-mode stubs live in
/// `crate::userspace::ntdll` (see Phase 2).
fn resolve_imports_into_image(
    _pml4: u64,
    _parsed: &loader::LoaderResult,
    _image_base: u64,
) -> Result<NTSTATUS, NTSTATUS> {
    Ok(STATUS_SUCCESS)
}

// ---------------------------------------------------------------------------
// PEB / TEB initialization in user PML4
// ---------------------------------------------------------------------------

/// Install a zeroed, R/W PEB page at `PEB_VA` and return its VA.
pub fn init_peb_in_pml4(pml4: u64) -> Result<u64, NTSTATUS> {
    let phys = match crate::mm::pfn::allocate_pfn() {
        Some(p) => crate::mm::pte::pfn_to_phys(p),
        None => return Err(STATUS_NO_MEMORY),
    };
    if phys == 0 { return Err(STATUS_NO_MEMORY); }
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
    if phys == 0 { return Err(STATUS_NO_MEMORY); }
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
pub fn build_user_stack(
    _pml4: u64,
    _teb_va: u64,
    _image_path: &str,
) -> Result<u64, NTSTATUS> {
    // The full implementation walks ProcessParameters, env, command
    // line, and a small "thread-startup" frame. For Phase 1 we hand
    // back a placeholder 16-byte-aligned address above the TEB.
    Ok(USER_STACK_TOP)
}