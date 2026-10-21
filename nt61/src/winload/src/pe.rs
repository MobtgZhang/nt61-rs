//! PE32+ image layout parsing for winload.efi.
//!
//! Extends the loader beyond the "copy every section flat" model:
//!
//!   * every section header is parsed with its Characteristics so the
//!     loader can apply per-section R/W/X permissions through the UEFI
//!     Memory Attribute protocol (pe::apply_section_permissions),
//!   * WX (write+execute) sections are detected and reported,
//!   * the Load Config directory is parsed for CFG
//!     (IMAGE_GUARD_CF_INSTRUMENTED, guard function table / count),
//!   * SafeSEH (SEHandlerTable / SEHandlerCount) is read from the
//!     same Load Config structure,
//!   * the import directory (DLL dependency table) and the delay-load
//!     import directory are walked to produce the module's DLL
//!     dependency list.

use alloc::string::String;
use alloc::vec::Vec;

// IMAGE_SCN_* section characteristic flags.
const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

// IMAGE_GUARD_* flags from the Load Config directory.
const GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
const GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;

/// Offset of the CheckSum field inside a PE32+ optional header.
pub const PE32PLUS_CHECKSUM_OFFSET: usize = 0x40;
/// Offset of the DataDirectory array inside a PE32+ optional header.
const PE32PLUS_DATA_DIR_OFFSET: usize = 0x70;
const PE32PLUS_OPT_MIN_LEN: usize = PE32PLUS_DATA_DIR_OFFSET + 16 * 8;

/// Data directory indices used by the loader.
pub const DIR_IMPORT: usize = 1;
pub const DIR_LOAD_CONFIG: usize = 10;
pub const DIR_DELAY_IMPORT: usize = 13;

/// Parsed permission summary of a single PE section.
#[derive(Debug, Clone, Copy)]
pub struct SectionInfo {
    pub name: [u8; 8],
    pub rva: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }

    /// A write+execute section. Modern Windows images should not carry
    /// these outside of JIT trampolines; the loader surfaces them so the
    /// boot log records the deviation from W^X.
    pub fn is_wx(&self) -> bool {
        self.is_executable() && self.is_writable()
    }

    /// Page-aligned byte range this section occupies in the mapped
    /// image, or None when the section cannot be page-protected.
    fn protected_range(&self) -> Option<(u64, u64)> {
        const PAGE: u32 = 0x1000;
        let start = self.rva.div_ceil(PAGE) * PAGE;
        let end = self.rva.saturating_add(self.virtual_size) & !(PAGE - 1);
        if end > start {
            Some((u64::from(start), u64::from(end)))
        } else {
            None
        }
    }
}

/// Control Flow Guard metadata parsed from the Load Config directory.
#[derive(Debug, Clone, Copy)]
pub struct GuardConfig {
    pub guard_flags: u32,
    /// Virtual address of the guard CF function table.
    pub function_table_va: u64,
    pub function_count: u64,
}

impl GuardConfig {
    pub fn cf_instrumented(&self) -> bool {
        self.guard_flags & GUARD_CF_INSTRUMENTED != 0
    }

    pub fn function_table_present(&self) -> bool {
        self.guard_flags & GUARD_CF_FUNCTION_TABLE_PRESENT != 0
    }
}

/// SafeSEH metadata (x86 handler table).
#[derive(Debug, Clone, Copy)]
pub struct SafeSehInfo {
    pub handler_table_va: u64,
    pub handler_count: u64,
}

/// Everything the loader needs to know about one PE image beyond the
/// flat section copy.
#[derive(Debug, Clone)]
pub struct PeImageInfo {
    pub sections: Vec<SectionInfo>,
    /// DLL names from the import directory, in link order.
    pub dll_dependencies: Vec<String>,
    /// DLL names from the delay-load import directory.
    pub delay_load_dependencies: Vec<String>,
    pub cfg: Option<GuardConfig>,
    pub safe_seh: Option<SafeSehInfo>,
    /// True when at least one section is write+execute.
    pub has_wx_sections: bool,
}

fn u16_at(image: &[u8], off: usize) -> Option<u16> {
    let b = image.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(image: &[u8], off: usize) -> Option<u32> {
    let b = image.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(image: &[u8], off: usize) -> Option<u64> {
    let b = image.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn pe_layout(image: &[u8]) -> Option<(usize, usize, usize, usize)> {
    if image.len() < 0x40 {
        return None;
    }
    let dos = image.as_ptr() as *const crate::DosHeader;
    if unsafe { (*dos).e_magic } != 0x5A4D {
        return None;
    }
    let e_lfanew = unsafe { (*dos).e_lfanew } as usize;
    if e_lfanew + 4 > image.len() {
        return None;
    }
    let sig = [
        image[e_lfanew],
        image[e_lfanew + 1],
        image[e_lfanew + 2],
        image[e_lfanew + 3],
    ];
    if sig != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }
    let opt_off = e_lfanew + 4 + 20;
    let num_sections = u16_at(image, e_lfanew + 4 + 2)? as usize;
    let opt_size = u16_at(image, e_lfanew + 4 + 16)? as usize;
    let sections_off = opt_off + opt_size;
    Some((opt_off, num_sections, sections_off, opt_size))
}

/// Translate an RVA into a file offset using the section headers.
fn rva_to_offset(
    _image: &[u8],
    sections: &[SectionInfo],
    section_files: &[(u32, u32)],
    rva: u32,
) -> Option<usize> {
    for (i, s) in sections.iter().enumerate() {
        let (raw_ptr, raw_size) = section_files[i];
        let span = s.virtual_size.max(raw_size);
        if s.rva <= rva && rva < s.rva.saturating_add(span) {
            if raw_size == 0 {
                return None;
            }
            let delta = rva - s.rva;
            if delta >= raw_size {
                return None;
            }
            return Some(raw_ptr as usize + delta as usize);
        }
    }
    None
}

fn read_asciiz(image: &[u8], off: usize, max: usize) -> Option<String> {
    let end = image.get(off..off + max)?.iter().position(|&b| b == 0)?;
    let bytes = &image[off..off + end];
    if bytes.iter().any(|&b| b < 0x20 || b > 0x7E) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Parse the import directory and return the DLL dependency list.
fn parse_import_directory(
    image: &[u8],
    sections: &[SectionInfo],
    section_files: &[(u32, u32)],
    dir_rva: u32,
) -> Vec<String> {
    let mut names = Vec::new();
    let Some(mut off) = rva_to_offset(image, sections, section_files, dir_rva) else {
        return names;
    };
    for _ in 0..64 {
        if off + 20 > image.len() {
            break;
        }
        let name_rva = u32_at(image, off + 12).unwrap_or(0);
        let first_thunk = u32_at(image, off + 16).unwrap_or(0);
        if name_rva == 0 && first_thunk == 0 {
            break;
        }
        if let Some(noff) = rva_to_offset(image, sections, section_files, name_rva) {
            if let Some(name) = read_asciiz(image, noff, 64) {
                names.push(name);
            }
        }
        off += 20;
    }
    names
}

/// Parse the delay-load import directory (ImgDelayDescr entries).
fn parse_delay_import_directory(
    image: &[u8],
    sections: &[SectionInfo],
    section_files: &[(u32, u32)],
    dir_rva: u32,
) -> Vec<String> {
    let mut names = Vec::new();
    let Some(mut off) = rva_to_offset(image, sections, section_files, dir_rva) else {
        return names;
    };
    // ImgDelayDescr: grAttrs(4), szName(4 RVA), ...
    for _ in 0..64 {
        if off + 32 > image.len() {
            break;
        }
        let attrs = u32_at(image, off).unwrap_or(0);
        let name_field = u32_at(image, off + 4).unwrap_or(0);
        if name_field == 0 {
            break;
        }
        // grAttrs bit 1 (DLATTRS) marks the szName field as a VA.
        let name_off = if attrs & 1 != 0 {
            let rva = u32::try_from(name_field).unwrap_or(0);
            if rva == 0 {
                break;
            }
            rva_to_offset(image, sections, section_files, rva)
        } else {
            rva_to_offset(image, sections, section_files, name_field)
        };
        if let Some(noff) = name_off {
            if let Some(name) = read_asciiz(image, noff, 64) {
                names.push(name);
            }
        }
        off += 32;
    }
    names
}

/// PE32+ IMAGE_LOAD_CONFIG_DIRECTORY offsets used here.
const LC_SE_HANDLER_TABLE: usize = 96;
const LC_SE_HANDLER_COUNT: usize = 104;
const LC_GUARD_FLAGS: usize = 112;
const LC_GUARD_CF_TABLE: usize = 120;
const LC_GUARD_CF_COUNT: usize = 128;
const LC_MIN_PARSE_LEN: usize = LC_GUARD_CF_COUNT + 8;

fn parse_load_config(
    image: &[u8],
    sections: &[SectionInfo],
    section_files: &[(u32, u32)],
    dir_rva: u32,
) -> (Option<GuardConfig>, Option<SafeSehInfo>) {
    let mut cfg = None;
    let mut seh = None;
    let Some(off) = rva_to_offset(image, sections, section_files, dir_rva) else {
        return (None, None);
    };
    let size = u32_at(image, off).unwrap_or(0) as usize;
    if size < LC_MIN_PARSE_LEN || off + LC_MIN_PARSE_LEN > image.len() {
        return (None, None);
    }
    let seh_table = u64_at(image, off + LC_SE_HANDLER_TABLE).unwrap_or(0);
    let seh_count = u64_at(image, off + LC_SE_HANDLER_COUNT).unwrap_or(0);
    if seh_table != 0 {
        seh = Some(SafeSehInfo {
            handler_table_va: seh_table,
            handler_count: seh_count,
        });
    }
    let guard_flags = u32_at(image, off + LC_GUARD_FLAGS).unwrap_or(0);
    let table = u64_at(image, off + LC_GUARD_CF_TABLE).unwrap_or(0);
    let count = u64_at(image, off + LC_GUARD_CF_COUNT).unwrap_or(0);
    if guard_flags != 0 && table != 0 {
        cfg = Some(GuardConfig {
            guard_flags,
            function_table_va: table,
            function_count: count,
        });
    }
    (cfg, seh)
}

/// Parse the full image layout. Returns None for non-PE32+ images.
pub fn parse_image_layout(image: &[u8]) -> Option<PeImageInfo> {
    let (opt_off, num_sections, sections_off, _opt_size) = pe_layout(image)?;
    if u16_at(image, opt_off)? != 0x20B {
        return None;
    }
    if opt_off + PE32PLUS_OPT_MIN_LEN > image.len() {
        return None;
    }
    let mut sections = Vec::with_capacity(num_sections);
    let mut section_files = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sh = sections_off + i * 40;
        if sh + 40 > image.len() {
            break;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&image[sh..sh + 8]);
        let virtual_size = u32_at(image, sh + 8).unwrap_or(0);
        let rva = u32_at(image, sh + 12).unwrap_or(0);
        let raw_size = u32_at(image, sh + 16).unwrap_or(0);
        let raw_ptr = u32_at(image, sh + 20).unwrap_or(0);
        let characteristics = u32_at(image, sh + 36).unwrap_or(0);
        sections.push(SectionInfo {
            name,
            rva,
            virtual_size,
            characteristics,
        });
        section_files.push((raw_ptr, raw_size));
    }

    let read_dir = |index: usize| {
        let d = PE32PLUS_DATA_DIR_OFFSET + index * 8;
        u32_at(image, opt_off + d).unwrap_or(0)
    };

    let dll_dependencies =
        parse_import_directory(image, &sections, &section_files, read_dir(DIR_IMPORT));
    let delay_load_dependencies =
        parse_delay_import_directory(image, &sections, &section_files, read_dir(DIR_DELAY_IMPORT));
    let (cfg, safe_seh) =
        parse_load_config(image, &sections, &section_files, read_dir(DIR_LOAD_CONFIG));
    let has_wx_sections = sections.iter().any(|s| s.is_wx());

    Some(PeImageInfo {
        sections,
        dll_dependencies,
        delay_load_dependencies,
        cfg,
        safe_seh,
        has_wx_sections,
    })
}

/// Apply per-section memory permissions to the freshly mapped image.
///
/// The loader hands every image out of a shared executable pool, so
/// non-executable sections are the ones that need protection: they get
/// EXECUTE_PROTECT set. Read-only pages that are fully contained inside
/// a non-writable section additionally get READ_ONLY. All calls are
/// best-effort: firmware that refuses a range is tolerated.
pub fn apply_section_permissions(load_addr: u64, info: &PeImageInfo) {
    use uefi::mem::memory_map::MemoryAttribute;
    use uefi::proto::security::MemoryProtection;

    let Ok(handle) = uefi::boot::get_handle_for_protocol::<MemoryProtection>() else {
        return;
    };
    let Ok(mut protocol) = uefi::boot::open_protocol_exclusive::<MemoryProtection>(handle) else {
        return;
    };
    let Some(protection) = protocol.get_mut() else {
        return;
    };

    for section in &info.sections {
        if section.is_executable() {
            continue;
        }
        let Some((start, end)) = section.protected_range() else {
            continue;
        };
        let range = (load_addr + start)..(load_addr + end);
        let _ = protection.set_memory_attributes(range.clone(), MemoryAttribute::EXECUTE_PROTECT);
        if !section.is_writable() {
            let _ = protection.set_memory_attributes(range, MemoryAttribute::READ_ONLY);
        }
    }
}

/// Section name as printable text (NUL-terminated slice).
pub fn section_name(s: &SectionInfo) -> String {
    String::from_utf8_lossy(
        &s.name
            .iter()
            .copied()
            .take_while(|&b| b != 0)
            .collect::<Vec<u8>>(),
    )
    .into_owned()
}

/// Log the parsed layout: section permissions, WX sections, CFG,
/// SafeSEH and DLL dependencies.
pub fn log_image_layout(path: &str, info: &PeImageInfo) {
    for s in &info.sections {
        let perms = match (s.is_executable(), s.is_writable(), s.is_readable()) {
            (true, true, _) => "RWX",
            (true, false, _) => "RX",
            (false, true, _) => "RW",
            (false, false, true) => "R",
            (false, false, false) => "?",
        };
        let kind = if s.characteristics & SCN_CNT_CODE != 0 {
            " code"
        } else if s.characteristics & SCN_CNT_INITIALIZED_DATA != 0 {
            " data"
        } else {
            ""
        };
        debug_println!(
            "[PE] {} section {}{} rva={:#x} size={:#x} perms={}",
            path,
            section_name(s),
            kind,
            s.rva,
            s.virtual_size,
            perms
        );
    }
    if info.has_wx_sections {
        debug_println!("[PE] {} contains WX sections", path);
    }
    if let Some(cfg) = &info.cfg {
        debug_println!(
            "[PE] {} CFG instrumented={} table={:#x} count={}",
            path,
            cfg.cf_instrumented(),
            cfg.function_table_va,
            cfg.function_count
        );
        debug_println!(
            "[PE] {} CFG function-table-present={}",
            path,
            cfg.function_table_present()
        );
    }
    if let Some(seh) = &info.safe_seh {
        debug_println!(
            "[PE] {} SafeSEH table={:#x} handlers={}",
            path,
            seh.handler_table_va,
            seh.handler_count
        );
    }
    for dll in &info.dll_dependencies {
        debug_println!("[PE] {} depends on {}", path, dll);
    }
    for dll in &info.delay_load_dependencies {
        debug_println!("[PE] {} delay-loads {}", path, dll);
    }
}
