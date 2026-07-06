//! Configuration Manager (CM).
//
//! The CM holds the set of mounted hives, each as a borrowed
//! `Hive<'static>` over a memory region that survives the
//! hand-off from `winload.efi` to the kernel. The kernel never
//! opens or reads a hive file directly: the loader has already
//! loaded every hive into a low-memory buffer, populated the
//! `LoadedHiveList` in `BootInfo.hives`, and the kernel mounts
//! them here in `init`.
//
//! # Static lifetime
//
//! The hive bytes live in physical memory that the UEFI loader
//! reserved before `ExitBootServices` and whose physical
//! address is baked into `BootInfo.hives`. The kernel's
//! physical-memory manager maps that range at its physical
//! base, so the bytes are visible at the same physical
//! address. We pin the address using a static mutable slice
//! that is filled in once at `init` time and never modified
//! after that.

extern crate alloc;
use crate::kprintln;
use alloc::string::String;
use alloc::vec::Vec;

use super::hive::{Hive, KeyNode, Value};
use super::path::{Hive as HiveId, ParsedPath};
use crate::boot_types::BootInfo;

/// Maximum number of simultaneously-mounted hives. We only
/// mount the standard five plus BCD, so eight is plenty.
pub const MAX_HIVES: usize = 8;

/// Maximum number of loaded hives the loader can pass in
/// `BootInfo`. Must match the same constant in
/// `winload/src/main.rs` (`MAX_HIVES` there).
pub const BOOTINFO_MAX_HIVES: usize = 8;

/// A single hive image as passed by the loader.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LoadedHive {
    /// 32-byte ASCII name (e.g. `System`, `Software`, `BCD`).
    /// NUL-terminated.
    pub name: [u8; 32],
    pub name_len: u32,
    /// Physical address of the hive bytes.
    pub ptr: u64,
    /// Size in bytes.
    pub len: u32,
    /// Reserved for future use (flags, hive class, ...).
    pub _reserved: u32,
}

impl LoadedHive {
    pub const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            ptr: 0,
            len: 0,
            _reserved: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        let n = (self.name_len as usize).min(self.name.len());
        core::str::from_utf8(&self.name[..n]).unwrap_or("")
    }
}

/// A mounted hive. We hold a static reference to the byte
/// slice for the lifetime of the kernel. The bytes are
/// assumed to remain valid (pinned physical memory).
struct MountedHive {
    hive: Hive<'static>,
}

/// The set of mounted hives, indexed by `HiveId`.
static mut MOUNTED: [Option<MountedHive>; MAX_HIVES] = [const { None }; MAX_HIVES];

/// True after `init` has run.
static mut INITIALIZED: bool = false;

/// Mount every hive listed in `BootInfo.hives`. Call this once
/// from `kernel_main` after Phase 1 (memory manager) and before
/// Phase 4 (I/O). Subsequent calls are no-ops.
pub fn init(boot_info: &BootInfo) {
    // SAFETY: This runs once on the BSP before any other CM
    // call. All writes are to static mutable state that we own.
    unsafe {
        if INITIALIZED { return; }

        kprintln!(
            subsystem: "CM",
            "    [CM] init: hives=0x{:x} count={}",
            boot_info.hives,
            boot_info.hive_count
        );

        let count = if boot_info.hive_count as usize <= BOOTINFO_MAX_HIVES {
            boot_info.hive_count as usize
        } else {
            BOOTINFO_MAX_HIVES
        };

        if boot_info.hives == 0 || count == 0 {
            kprintln!(
                subsystem: "CM",
                "    [CM] no hives to mount (hives=0x{:x} count={})",
                boot_info.hives,
                boot_info.hive_count
            );
            INITIALIZED = true;
            return;
        }

        // The hives pointer is a *physical* address that was
        // written by the UEFI loader. The kernel copied UEFI's
        // PML4 verbatim, so the low 512 GiB of physical memory
        // remains identity-mapped (VA == PA). We can therefore
        // read the records array and the hive bytes directly
        // through the physical address — no extra mapping is
        // required. This is much simpler (and more reliable)
        // than the system PTE pool, which is not yet wired up
        // for the page-table chain at this point in boot.
        let records_pa = boot_info.hives;

        // Sanity check: the first 6 bytes of the first record
        // should be the ASCII bytes of "System\0" (followed by
        // 0xAF 0xAF for the name_len field). If they are not,
        // the UEFI loader has handed us a bad pointer.
        let p = records_pa as *const u8;
        let b0 = core::ptr::read_volatile(p.add(0));
        let b1 = core::ptr::read_volatile(p.add(1));
        let b2 = core::ptr::read_volatile(p.add(2));
        let b3 = core::ptr::read_volatile(p.add(3));
        kprintln!(
            subsystem: "CM",
            "    [CM] sanity: PA=0x{:x} bytes [0..4] = 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
            records_pa, b0, b1, b2, b3
        );
        if b0 != b'S' || b1 != b'y' || b2 != b's' || b3 != b't' {
            kprintln!(
                subsystem: "CM",
                "    [CM] FATAL: first record is not 'System' (got 0x{:02x}{:02x}{:02x}{:02x})",
                b0, b1, b2, b3
            );
            INITIALIZED = true;
            return;
        }

        let base = records_pa as *const LoadedHive;

        for i in 0..count {
            kprintln!(
                subsystem: "CM",
                "    [CM] parsing hive {} of {}",
                i + 1,
                count
            );
            // SAFETY: we just mapped `records_va` from `records_pa`
            // for `records_pages` pages, so reading one record per
            // slot (52 bytes) is in-bounds.
            let lh = &*base.add(i);
            kprintln!(
                subsystem: "CM",
                "    [CM]   name={:?} ptr=0x{:x} len={}",
                lh.name_str(),
                lh.ptr,
                lh.len
            );
            if lh.ptr == 0 || lh.len == 0 {
                kprintln!(subsystem: "CM", "    [CM]   skipped (empty)");
                continue;
            }
            // The hive bytes are at a different PA. Since the
            // kernel identity-maps the low 512 GiB, we can read
            // them directly through the physical address.
            kprintln!(
                subsystem: "CM",
                "    [CM]   hive bytes PA=0x{:x} len={}",
                lh.ptr,
                lh.len
            );
            // SAFETY: the loader guaranteed the bytes are valid
            // for the entire kernel lifetime (it placed them
            // in memory that survives ExitBootServices and is
            // not reused by the kernel's allocator). The kernel
            // identity-maps this physical address, so the VA==
            // PA mapping lets us read them as a borrowed slice.
            let bytes: &'static [u8] = core::slice::from_raw_parts(
                lh.ptr as *const u8, lh.len as usize,
            );
            kprintln!(
                subsystem: "CM",
                "    [CM]   about to call Hive::parse on {} bytes",
                bytes.len()
            );
            match Hive::parse(bytes) {
                Ok(hive) => {
                    let name = lh.name_str();
                    let idx = match name {
                        "System"   => 0,
                        "Software" => 1,
                        "Security" => 2,
                        "SAM"      => 3,
                        "Default"  => 4,
                        "BCD"      => 5,
                        _ => continue, // unknown hive name
                    };
                    kprintln!(
                        subsystem: "CM",
                        "    [CM] mounted {} ({} bytes, {} cells)",
                        name,
                        lh.len,
                        hive.cell_count()
                    );
                    MOUNTED[idx] = Some(MountedHive { hive });
                }
                Err(e) => {
                    kprintln!(
                        subsystem: "CM",
                        "    [CM] hive parse FAILED for '{}': {}",
                        lh.name_str(),
                        e
                    );
                }
            }
        }

        INITIALIZED = true;
        kprintln!(subsystem: "CM", "    [CM] configuration manager initialized");
    }
}

fn mounted(h: HiveId) -> Option<&'static MountedHive> {
    let idx = match h {
        HiveId::System   => 0,
        HiveId::Software => 1,
        HiveId::Security => 2,
        HiveId::SAM      => 3,
        HiveId::Default  => 4,
        HiveId::BCD      => 5,
    };
    // SAFETY: We never write to MOUNTED after init.
    unsafe { MOUNTED[idx].as_ref() }
}

/// Look up a value by full path. Returns `None` if any
/// component of the path is missing.
pub fn query_value(path: &str, name: &str) -> Option<Value> {
    kprintln!(subsystem: "CM", "    [CM] query_value: path='{}' name='{}'", path, name);
    let parsed = match ParsedPath::parse(path) {
        Ok(p) => p,
        Err(e) => {
            kprintln!(subsystem: "CM", "    [CM] query_value: path parse error: {}", e);
            return None;
        }
    };
    kprintln!(
        subsystem: "CM",
        "    [CM] query_value: hive={:?} subkeys={:?}",
        parsed.hive,
        parsed.subkeys
    );
    let m = mounted(parsed.hive)?;
    let path_strs: Vec<&str> = parsed.subkeys.iter().map(|s| s.as_str()).collect();
    let node = m.hive.open_path(&path_strs).ok().flatten()?;
    let result = m.hive.find_value(&node, name).ok().flatten();
    kprintln!(
        subsystem: "CM",
        "    [CM] query_value: result={:?}",
        result.is_some()
    );
    result
}


/// Convenience: query a DWORD value.
pub fn query_dword(path: &str, name: &str) -> Option<u32> {
    kprintln!(
        subsystem: "CM",
        "    [CM] query_dword: path='{}' name='{}'",
        path,
        name
    );
    let result = query_value(path, name).and_then(|v| v.as_u32());
    kprintln!(
        subsystem: "CM",
        "    [CM] query_dword: result={:?}",
        result
    );
    result
}

/// Convenience: query a UTF-16 string value.
pub fn query_string(path: &str, name: &str) -> Option<String> {
    query_value(path, name).and_then(|v| v.as_utf16_string())
}

/// Enumerate the names of immediate subkeys under `path`.
pub fn enumerate_subkeys(path: &str) -> Option<Vec<String>> {
    kprintln!(
        subsystem: "CM",
        "    [CM] enumerate_subkeys: path='{}'",
        path
    );
    let parsed = ParsedPath::parse(path).ok()?;
    let m = mounted(parsed.hive)?;
    let path_strs: Vec<&str> = parsed.subkeys.iter().map(|s| s.as_str()).collect();
    let node = m.hive.open_path(&path_strs).ok()??;
    let subs = m.hive.subkeys(&node).ok()?;
    let result: Vec<String> = subs.into_iter().map(|k: KeyNode| k.name).collect();
    kprintln!(
        subsystem: "CM",
        "    [CM] enumerate_subkeys: count={}",
        result.len()
    );
    Some(result)
}

/// Enumerate value names on `path`.
pub fn enumerate_values(path: &str) -> Option<Vec<String>> {
    kprintln!(subsystem: "CM", "    [CM] enumerate_values: path='{}'", path);
    let parsed = ParsedPath::parse(path).ok()?;
    let m = mounted(parsed.hive)?;
    let path_strs: Vec<&str> = parsed.subkeys.iter().map(|s| s.as_str()).collect();
    let node = m.hive.open_path(&path_strs).ok()??;
    let vs = m.hive.values(&node).ok()?;
    let result: Vec<String> = vs.into_iter().map(|v: Value| v.name).collect();
    kprintln!(
        subsystem: "CM",
        "    [CM] enumerate_values: count={}",
        result.len()
    );
    Some(result)
}

/// Return whether a hive is mounted.
pub fn is_mounted(h: HiveId) -> bool {
    mounted(h).is_some()
}

/// Re-export the value type for callers.
pub use super::hive::ValueType as CmValueType;
