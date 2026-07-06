//! FAT32 Long Filename (LFN) Aware Directory Lookup
//
//! This module provides LFN-aware directory entry lookup to work around
//! OVMF firmware bugs where `EFI_FILE_PROTOCOL.Open()` does not properly
//! resolve long filenames. The UEFI spec says `open()` should match by LFN,
//! but some OVMF builds only match by the 8.3 short name (SFN).
//
//! ## Solution
//
//! Instead of relying on `open()` to find entries by LFN, we:
//! 1. Enumerate directory entries using `Directory::read_entry_boxed()`
//!    which handles heap allocation and proper alignment of FileInfo buffers.
//! 2. Match the desired name (case-insensitive) against each entry's LFN.
//! 3. Derive candidate 8.3 short names (SFNs) from the LFN and return them
//!    so the caller can try `open()` with SFN fallbacks. Some OVMF builds
//!    cannot resolve LFN in `open()` even when the entry clearly exists.

// Status: this module is reachable through the LFN-aware `open()`
// path on firmware builds that honour the UEFI 2.8+ semantics.
// EDK2 nightly does so, but the current boot pipeline only uses the
// direct `read_pe_file_from_disk` API, so these symbols are not
// pulled into the release binary. A module-level
// `#[allow(dead_code)]` keeps the implementation compiled and
// exported so cross-arch callers can opt in without `Cargo.toml`
// feature changes.

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use uefi::proto::media::file::Directory;
use uefi::CString16;

/// Search result containing the LFN and a list of SFN candidates to try.
#[derive(Debug, Clone)]
pub struct LookupResult {
    /// The canonical long filename as found in the directory.
    pub lfn: CString16,
    /// Candidate 8.3 short filenames derived from the LFN, in priority order.
    pub sfn_candidates: Vec<CString16>,
}

/// Find a directory entry by name (LFN-aware).
///
/// This function enumerates all entries in `dir` and finds one whose name
/// (case-insensitive, Unicode comparison) matches `wanted`. Returns a
/// `LookupResult` containing the canonical LFN and a list of SFN candidates.
///
/// Returns `None` if no matching entry is found. Logging is silent unless
/// the requested name isn't found at all - the caller already logs that.
pub fn find_entry_by_name(dir: &mut Directory, wanted: &str) -> Option<LookupResult> {
    let wanted_upper = to_uppercase_ascii(wanted);

    let _ = dir.reset_entry_readout();

    loop {
        match dir.read_entry_boxed() {
            Ok(Some(info)) => {
                let entry_name = info.file_name();
                let entry_str = cstr16_to_string(entry_name);
                let entry_upper = to_uppercase_ascii(&entry_str);

                if entry_upper == wanted_upper {
                    let lfn = make_cstring16(&entry_str)?;
                    let sfn_candidates = build_sfn_candidates(&entry_str);
                    let _ = dir.reset_entry_readout();
                    return Some(LookupResult {
                        lfn,
                        sfn_candidates,
                    });
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    let _ = dir.reset_entry_readout();
    None
}

/// Build a list of candidate 8.3 short filenames from a long filename.
fn build_sfn_candidates(lfn: &str) -> Vec<CString16> {
    let mut result = Vec::new();

    let (base, ext) = match lfn.rfind('.') {
        Some(idx) => (&lfn[..idx], &lfn[idx + 1..]),
        None => (lfn, ""),
    };

    let base_upper: String = base.chars().map(|c| c.to_ascii_uppercase()).collect();
    let ext_upper: String = ext.chars().map(|c| c.to_ascii_uppercase()).collect();

    let base_trimmed: String = base_upper
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '+' | ',' | ';' | '=' | '[' | ']'))
        .collect();

    let ext_trimmed: String = ext_upper
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '+' | ',' | ';' | '=' | '[' | ']'))
        .collect();

    // 1) If the LFN fits 8.3, the SFN may equal the LFN (upper-cased).
    if base_trimmed.len() <= 8 && ext_trimmed.len() <= 3 {
        let sfn = if ext_trimmed.is_empty() {
            base_trimmed.clone()
        } else {
            format!("{}.{}", base_trimmed, ext_trimmed)
        };
        if let Ok(c) = CString16::try_from(sfn.as_str()) {
            result.push(c);
        }
    }

    // 2) Generate numbered candidates ~1..~9.
    let base6: String = base_trimmed.chars().take(6).collect();

    for n in 1..=9u32 {
        let sfn = if ext_trimmed.is_empty() {
            format!("{}~{}", base6, n)
        } else {
            let ext3: String = ext_trimmed.chars().take(3).collect();
            format!("{}~{}.{}", base6, n, ext3)
        };
        if let Ok(c) = CString16::try_from(sfn.as_str()) {
            result.push(c);
        }
    }

    result
}

fn to_uppercase_ascii(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_uppercase()).collect()
}

/// Convert a CStr16 (UEFI string) to a Rust String.
///
/// LFN directory entries often contain invalid UCS-2 values (e.g., 0xFFFF)
/// as padding for the unused portion of the 13-char LFN slots. We treat
/// these as terminators, just like nulls.
fn cstr16_to_string(cstr: &uefi::CStr16) -> String {
    let mut result = String::new();
    for ch in cstr.iter() {
        let u16_val: u16 = (*ch).into();

        if u16_val == 0 {
            break;
        }

        if u16_val == 0xFFFF {
            break;
        }

        match char::from_u32(u16_val as u32) {
            Some(c) => result.push(c),
            None => {
                break;
            }
        }
    }
    result
}

/// Create a CString16 from a &str, ensuring it's valid for UEFI APIs.
fn make_cstring16(s: &str) -> Option<CString16> {
    if s.contains('\0') {
        return None;
    }
    CString16::try_from(s).ok()
}

/// Reset directory readout position so it can be re-enumerated.
pub fn reset_directory(dir: &mut Directory) {
    let _ = dir.reset_entry_readout();
}