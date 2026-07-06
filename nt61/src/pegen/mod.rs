//! PE (Portable Executable) Generator
//
//! Build PE32+ images in pure Rust, byte by byte. The output is a
//! well-formed PE file that any Windows loader (and our own
//! `loader::pe`) can map into memory and execute.
//
//! # Why a Rust generator?
//
//! The system is bootstrapped: there is no external toolchain
//! available to assemble the system binaries. We must build the
//! on-disk system image with the same Rust code that runs the
//! kernel. This module provides the building blocks:
//
//! * `PeBuilder` - accumulates sections, imports, and entry-point
//!   code, then serialises them into a single byte vector that is
//!   the final PE file.
//! * `Section` - a named virtual region with raw bytes and
//!   characteristics (CODE / DATA / R / W / X).
//! * `Import` - a function imported from a DLL (used to wire
//!   `hal.dll` -> `ntoskrnl.exe` style edges).
//
//! The entry-point code can be supplied as raw x86_64 machine code
//! (the build script emits the bytes for the small `_start` shim)
//! so the generated PE is fully self-contained: a single file
//! loads, initialises, runs, and exits cleanly.

use crate::loader::{FileHeader, SectionHeader};

extern crate alloc;

/// Print a u64 in decimal through the unified serial facade.
/// Used by debug instrumentation inside `add_section`.
fn write_decimal_u64(mut x: u64) {
    if x == 0 {
        crate::hal::serial::write_string("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut d = 0;
    while x > 0 {
        buf[d] = b'0' + (x % 10) as u8;
        x /= 10;
        d += 1;
    }
    for i in (0..d).rev() {
        if let Ok(s) = core::str::from_utf8(&buf[i..i + 1]) {
            crate::hal::serial::write_string(s);
        }
    }
}

/// File alignment (`SizeOfHeaders` and `PointerToRawData` use this).
pub const FILE_ALIGNMENT: u32 = 0x200;
/// Section alignment (`VirtualAddress` and `SizeOfImage` use this).
pub const SECTION_ALIGNMENT: u32 = 0x1000;
/// Reserved DOS header size that fits the `e_lfanew` field plus the
/// "MZ" stub. 0x80 is plenty for a 64-byte stub.
pub const DOS_STUB_SIZE: u32 = 0x80;
/// Offset of the PE header relative to the file start.
pub const PE_HEADER_OFFSET: u32 = 0x80;
/// Total size of the headers region (DOS + PE + OptionalHeader +
/// SectionHeaders). Must be rounded up to `FILE_ALIGNMENT` for the
/// raw-data pointer to be aligned.
pub const HEADERS_TOTAL: u32 = 0x400;
/// Default image base for our system binaries. Keeps the layout
/// predictable: `ntoskrnl.exe` at 0x1000_0000, `hal.dll` at
/// 0x2000_0000, user-mode at 0x4000_0000, etc.
pub const DEFAULT_IMAGE_BASE: u64 = 0x0000_0001_0000_0000;
/// Default image base for the kernel (loaded high).
pub const KERNEL_IMAGE_BASE: u64 = 0xFFFF_FFFF_8010_0000;

/// Windows subsystem values, see the PE/COFF spec section "Optional
/// Header Image Subsystem".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Subsystem {
    /// Native driver - drivers, the kernel itself.
    Native = 1,
    /// Windows GUI.
    WindowsGui = 2,
    /// Windows console - `cmd.exe`, the kernel debugger.
    WindowsCui = 3,
    /// EFI application (used for `bootmgr.efi`).
    EfiApplication = 10,
    /// EFI runtime driver.
    EfiRuntimeDriver = 12,
}

/// Section characteristics (subset of the spec we actually emit).
#[derive(Debug, Clone, Copy)]
pub struct SectionFlags(pub u32);

impl SectionFlags {
    pub const CODE: Self = Self(0x6000_0020); // CODE|EXECUTE|READ
    pub const DATA: Self = Self(0xC000_0040); // INITIALIZED|READ|WRITE
    pub const RDATA: Self = Self(0x4000_0040); // INITIALIZED|READ
    pub const BSS: Self = Self(0xC000_0080); // UNINITIALIZED|READ|WRITE
}

/// A logical section (e.g. `.text`, `.rdata`, `.data`).
#[derive(Debug, Clone)]
pub struct Section {
    pub name: [u8; 8],
    pub data: alloc::vec::Vec<u8>,
    pub flags: SectionFlags,
}

/// Pre-allocated fixed-size byte buffer for a section. Used in
/// early boot where the global allocator cannot be relied on (the
/// host binary may have already torn down boot services). We
/// allocate from the kernel's `KernelHeap` directly, so the
/// underlying memory is a real virtual address backed by the
/// kernel page tables — not the UEFI allocation pool.
pub struct OwnedSection {
    pub name: [u8; 8],
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
    pub flags: SectionFlags,
}

unsafe impl Send for OwnedSection {}
unsafe impl Sync for OwnedSection {}

impl OwnedSection {
    pub fn new(name: &str, flags: SectionFlags, initial_capacity: usize) -> Self {
        let mut n = [0u8; 8];
        let bytes = name.as_bytes();
        let copy = core::cmp::min(bytes.len(), 8);
        let mut i = 0;
        while i < copy {
            n[i] = bytes[i];
            i += 1;
        }
        let cap = initial_capacity.max(64);
        // Allocate from the kernel's bump arena directly. We use
        // the `alloc_raw` helper from the kernel pool because the
        // global allocator (uefi's bump) cannot service requests
        // after `ExitBootServices`.
        let layout = match core::alloc::Layout::from_size_align(cap, 32) {
            Ok(l) => l,
            Err(_) => core::alloc::Layout::from_size_align(cap, 8).unwrap(),
        };
        let ptr = unsafe {
            <crate::mm::heap::KernelHeap as core::alloc::GlobalAlloc>::alloc(
                &crate::mm::heap::KERNEL_HEAP,
                layout,
            )
        };
        Self { name: n, ptr, len: 0, cap, flags }
    }

    pub fn push(&mut self, byte: u8) {
        if self.len >= self.cap {
            // Cannot grow — caller must size capacity correctly.
            return;
        }
        unsafe { *self.ptr.add(self.len) = byte; }
        self.len += 1;
    }

    pub fn extend_from_static(&mut self, bytes: &[u8]) {
        // Manual byte-by-byte append into the pre-allocated buffer.
        // Avoids any SIMD memcpy / realloc churn in early boot.
        let mut i = 0;
        while i < bytes.len() && self.len < self.cap {
            unsafe { *self.ptr.add(self.len) = bytes[i]; }
            self.len += 1;
            i += 1;
        }
    }

    pub fn data_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Consume the OwnedSection and return the raw bytes as a Vec<u8>.
    /// This is only safe to call in an environment with a working global allocator.
    /// For early boot (Phase 009), use `into_raw_parts()` instead.
    pub fn into_bytes(self) -> alloc::vec::Vec<u8> {
        let mut data = alloc::vec::Vec::with_capacity(self.len);
        let mut i = 0;
        while i < self.len {
            data.push(unsafe { *self.ptr.add(i) });
            i += 1;
        }
        data
    }

    /// Consume the OwnedSection and return the raw pointer, length, and capacity.
    /// The caller takes ownership of the memory and is responsible for freeing it
    /// (or leaking it if the bump allocator is used).
    pub fn into_raw_parts(self) -> (*mut u8, usize, usize) {
        let ptr = self.ptr;
        let len = self.len;
        let cap = self.cap;
        core::mem::forget(self);
        (ptr, len, cap)
    }

    pub fn into_section(self) -> Section {
        let mut data = alloc::vec::Vec::with_capacity(self.len);
        let mut i = 0;
        while i < self.len {
            data.push(unsafe { *self.ptr.add(i) });
            i += 1;
        }
        Section { name: self.name, data, flags: self.flags }
    }
}

impl Drop for OwnedSection {
    fn drop(&mut self) {
        // Nothing to free: bump allocator never frees.
    }
}

impl Section {
    /// Create a new section with a 7-character name. The 8th byte
    /// must be zero (the PE spec null-pads short names).
    pub fn new(name: &str, flags: SectionFlags) -> Self {
        let mut n = [0u8; 8];
        let bytes = name.as_bytes();
        let copy = core::cmp::min(bytes.len(), 8);
        let mut i = 0;
        while i < copy {
            n[i] = bytes[i];
            i += 1;
        }
        let v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        Self { name: n, data: v, flags }
    }

    /// Build a section whose backing buffer is pre-allocated with the
    /// requested capacity. This avoids the SIMD-memcpy path that the
    /// std `Vec::push` would otherwise take when growing from 0 to
    /// the first element in our early-boot environment.
    pub fn with_capacity(name: &str, flags: SectionFlags, capacity: usize) -> Self {
        let mut n = [0u8; 8];
        let bytes = name.as_bytes();
        let copy = core::cmp::min(bytes.len(), 8);
        let mut i = 0;
        while i < copy {
            n[i] = bytes[i];
            i += 1;
        }
        let v: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(capacity);
        Self { name: n, data: v, flags }
    }

    /// Append raw bytes to the section. The PE writer will pad the
    /// section to `SECTION_ALIGNMENT` on disk.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        // Manual byte-by-byte push to avoid SIMD memcpy in early boot.
        let mut _i = 0;
        while _i < bytes.len() {
            self.data.push(bytes[_i]);
            _i += 1;
        }
    }

    pub fn virtual_size(&self) -> u32 { self.data.len() as u32 }
}

/// Imported function from a DLL.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// Hint - the export ordinal in the source DLL. We hard-code
    /// 0 because we do not actually consult the IAT.
    pub hint: u16,
    /// Function name (must be ASCII, terminated by the loader when
    /// it patches the IAT).
    pub name: alloc::string::String,
}

impl ImportEntry {
    pub fn new(name: &str) -> Self { Self { hint: 0, name: alloc::string::String::from(name) } }
}

/// An imported DLL and the functions used from it.
#[derive(Debug, Clone)]
pub struct Import {
    pub dll: alloc::string::String,
    pub functions: alloc::vec::Vec<ImportEntry>,
}

impl Import {
    pub fn new(dll: &str) -> Self {
        Self { dll: alloc::string::String::from(dll), functions: alloc::vec::Vec::new() }
    }
    pub fn add(&mut self, name: &str) {
        self.functions.push(ImportEntry::new(name));
    }
}

/// `ntoskrnl.exe` and `hal.dll` symbol info (export). Used to build
/// the export directory so other modules can find our entry points.
#[derive(Debug, Clone)]
pub struct Export {
    pub name: alloc::string::String,
    /// RVA of the function. If `forwarder_name` is Some,
    /// this field is IGNORED and the function address is set
    /// to an RVA inside the export directory that points to
    /// a forwarder string (NT style: "dll.name").
    pub rva: u32,
    /// Optional forwarder target. If set, the export becomes a
    /// forwarder: the loader resolves this as "dll.function".
    pub forwarder_name: Option<alloc::string::String>,
}

impl Export {
    pub fn new(name: &str, rva: u32) -> Self {
        Self { name: alloc::string::String::from(name), rva, forwarder_name: None }
    }

    /// Create a forwarder export. The `rva` argument is ignored;
    /// the function address is stored as an RVA inside the
    /// export directory pointing to the forwarder string.
    pub fn forwarder(name: &str, target: &str) -> Self {
        Self {
            name: alloc::string::String::from(name),
            rva: 0,
            forwarder_name: Some(alloc::string::String::from(target)),
        }
    }
}

/// Forwarder string area descriptor. When `add_forwarder` is called,
/// the forwarder string is appended after all normal exports and the
/// function address RVA is set to point to that string.
struct ForwarderSlot {
    /// The target string, e.g. "ntoskrnl.exe.KeBugCheck"
    target: alloc::string::String,
    /// RVA inside .rdata where the forwarder string lives
    string_rva: u32,
}

/// Builder for a PE32+ image. The caller fills in code, data,
/// imports, exports, and the entry point RVA, then calls `build()`
/// to serialise the result.
pub struct PeBuilder {
    pub machine: u16,
    pub subsystem: Subsystem,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub sections: alloc::vec::Vec<Section>,
    pub imports: alloc::vec::Vec<Import>,
    pub exports: alloc::vec::Vec<Export>,
}

impl PeBuilder {
    pub fn new(machine: u16, subsystem: Subsystem) -> Self {
        let image_base = if matches!(subsystem, Subsystem::Native) {
            KERNEL_IMAGE_BASE
        } else {
            DEFAULT_IMAGE_BASE
        };
        Self {
            machine,
            subsystem,
            image_base,
            entry_point_rva: 0,
            sections: alloc::vec::Vec::new(),
            imports: alloc::vec::Vec::new(),
            exports: alloc::vec::Vec::new(),
        }
    }

    pub fn add_section(&mut self, section: Section) -> &mut Section {
        {
            let next = crate::mm::heap::KERNEL_HEAP.next.load(core::sync::atomic::Ordering::SeqCst);
            let base = crate::mm::heap::KERNEL_HEAP.base.load(core::sync::atomic::Ordering::SeqCst);
            let size = crate::mm::heap::KERNEL_HEAP.size.load(core::sync::atomic::Ordering::SeqCst);
            let used = next.saturating_sub(base);
            crate::hal::serial::write_string("ADD_SEC:heap used=");
            write_decimal_u64(used as u64);
            crate::hal::serial::write_string(" size=");
            write_decimal_u64(size as u64);
            crate::hal::serial::write_string("\r\n");
        }
        if self.sections.try_reserve(1).is_err() {
            // Cannot grow the section list - halt and catch fire.
            crate::hal::serial::write_string("ADD_SEC:try_reserve failed HALT\r\n");
            crate::arch::halt_loop();
        }
        self.sections.push(section);
        self.sections.last_mut().unwrap()
    }

    pub fn add_import(&mut self, import: Import) -> &mut Import {
        self.imports.push(import);
        self.imports.last_mut().unwrap()
    }

    pub fn add_export(&mut self, name: &str, rva: u32) {
        self.exports.push(Export::new(name, rva));
    }

    /// Add a forwarder export. The export entry points to a string
    /// inside the export directory that names another DLL entry point.
    /// This lets us create "stub" exports that redirect to the kernel.
    pub fn add_forwarder(&mut self, name: &str, target: &str) {
        self.exports.push(Export::forwarder(name, target));
    }

    /// Serialise the builder into a byte vector that is the final
    /// PE file. The output is laid out as:
    ///
    /// ```text
    ///   [0, 0x80)                          DOS stub ("MZ" + padding)
    ///   [0x80, 0x80+4)                     "PE\0\0"
    ///   [0x84, 0x84+20)                    COFF file header
    ///   [0x98, 0x98+240)                   PE32+ optional header
    ///   [0x188, 0x188+16*N)                Section headers (N = sections)
    ///   [0x400, 0x400+P)                   Section 0 raw data
    ///   [0x400+P, 0x400+P+Q)               Section 1 raw data
    ///   ...
    /// ```
    pub fn build(&self) -> alloc::vec::Vec<u8> {
        // Layout strategy
        // ---------------
        // 1. The caller's `sections` are laid out in order at
        //    RVAs starting at `SECTION_ALIGNMENT`.
        // 2. After the last caller section we append a synthetic
        //    `.rdata` section that contains the export directory,
        //    import directory, and the name strings both reference.
        // 3. The optional header's data directories are filled in
        //    with the RVAs of the export/import structures.
        //
        // This keeps the loader and the host smoke test on the
        // same code path: `parse_exports` walks the export
        // directory, `resolve_imports` walks the import directory,
        // and the .rdata section provides the data they need.

        // ---- Pass 1: lay out the caller sections ----
        let mut rv_section: alloc::vec::Vec<(u32, u32)> = alloc::vec::Vec::new();
        let mut next_rva: u32 = SECTION_ALIGNMENT;
        for s in &self.sections {
            let raw_size = align_up(s.virtual_size(), FILE_ALIGNMENT);
            rv_section.push((next_rva, raw_size));
            next_rva += align_up(s.virtual_size(), SECTION_ALIGNMENT);
        }
        // Reserve space for the .rdata section (we don't know its
        // exact size until we serialise the export/import
        // structures; we over-estimate then back-patch the size).
        let rdata_rva = next_rva;
        let rdata_reserved = 0x1000; // 4 KB
        next_rva += rdata_reserved;
        let size_of_image = align_up(next_rva, SECTION_ALIGNMENT);

        // ---- Pass 2: serialise everything ----
        let mut out = alloc::vec::Vec::new();
        out.resize(PE_HEADER_OFFSET as usize, 0);

        // --- DOS header ---
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3C..0x40].copy_from_slice(&PE_HEADER_OFFSET.to_le_bytes());

        // --- PE signature ---
        out.extend_from_slice(b"PE\0\0");

        // --- COFF file header variables (defined early for direct writing) ---
        let num_sections = self.sections.len() as u16 + 1; // +1 for .rdata
        let characteristics: u16 = if matches!(self.subsystem, Subsystem::EfiApplication)
                                    || matches!(self.subsystem, Subsystem::EfiRuntimeDriver) {
            0x2022
        } else if matches!(self.subsystem, Subsystem::Native) {
            0x2022
        } else {
            0x2102
        };

        // --- COFF file header (20 bytes) via the shared serialiser ---
        let file_hdr = FileHeader {
            machine: self.machine,
            number_of_sections: num_sections,
            time_date_stamp: 0x6502_A000,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 240,
            characteristics,
        };
        out.extend_from_slice(&file_hdr_bytes(&file_hdr));
        let _ = &self.machine; // explicit reference: machine is read by file_hdr_bytes
        let _ = &num_sections;
        let _ = &characteristics;
        let _ = &file_hdr;

        // --- Optional header (PE32+), filled in once we know the
        //     .rdata RVA/size and the export/import directory
        //     positions. We serialise them first to learn the
        //     sizes, then rewind and write the optional header
        //     after the fact. ---
        let opt_off = out.len();
        out.resize(opt_off + 240, 0);

        // --- Section headers (placeholders, patched below) ---
        let sect_hdr_start = out.len();
        for _ in 0..num_sections as usize {
            out.resize(out.len() + 40, 0);
        }

        // --- Section data for caller sections ---
        let mut sect_offsets: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        for (i, s) in self.sections.iter().enumerate() {
            let (rva, _raw_size) = rv_section[i];
            sect_offsets.push(out.len() as u32);
            let mut padded = s.data.clone();
            padded.resize(align_up(s.virtual_size(), FILE_ALIGNMENT) as usize, 0);
            out.extend_from_slice(&padded);
            let _ = rva;
        }

        // --- Synthetic .rdata: export dir, import dir, strings ---
        let rdata_off = out.len();
        let (rdata, export_dir_rva, import_dir_rva) = self.serialise_rdata(rdata_rva);
        out.extend_from_slice(&rdata);
        // Pad .rdata to rdata_reserved.
        if rdata.len() < rdata_reserved as usize {
            out.resize(out.len() + (rdata_reserved as usize - rdata.len()), 0);
        }

        // --- Section headers (back-patch) ---
        for (i, s) in self.sections.iter().enumerate() {
            let (rva, raw_size) = rv_section[i];
            let sh = SectionHeader {
                name: s.name,
                virtual_size: s.virtual_size(),
                virtual_address: rva,
                size_of_raw_data: raw_size,
                pointer_to_raw_data: if s.virtual_size() == 0 { 0 } else { sect_offsets[i] },
                pointer_to_relocs: 0,
                pointer_to_line_nums: 0,
                number_of_relocs: 0,
                number_of_line_nums: 0,
                characteristics: s.flags.0,
            };
            let off = sect_hdr_start + i * 40;
            out[off..off + 40].copy_from_slice(&section_header_bytes(&sh));
        }
        // .rdata section header.
        let rdata_actual = rdata.len() as u32;
        let sh = SectionHeader {
            name: *b".rdata\0\0",
            virtual_size: rdata_actual,
            virtual_address: rdata_rva,
            size_of_raw_data: align_up(rdata_actual, FILE_ALIGNMENT),
            pointer_to_raw_data: rdata_off as u32,
            pointer_to_relocs: 0,
            pointer_to_line_nums: 0,
            number_of_relocs: 0,
            number_of_line_nums: 0,
            characteristics: 0x4000_0040,
        };
        let off = sect_hdr_start + self.sections.len() * 40;
        out[off..off + 40].copy_from_slice(&section_header_bytes(&sh));

        // --- Optional header (finally write it) ---
        let opt_bytes = self.build_optional_header(
            size_of_image,
            export_dir_rva, rdata_actual,
            import_dir_rva, self.compute_import_bytes(),
        );
        out[opt_off..opt_off + opt_bytes.len()].copy_from_slice(&opt_bytes);

        out
    }

    /// Build the bytes that go into the synthetic `.rdata` section:
    /// export directory, export name strings, import descriptors,
    /// import name strings, IAT/ILT arrays. All RVAs written in
    /// the export/import structures are `rdata_rva + offset_in_buf`.
    fn serialise_rdata(&self, rdata_rva: u32) -> (alloc::vec::Vec<u8>, u32, u32) {
        // ---- Compute sizes of the export/import areas ----
        let n_exports = self.exports.len() as u32;
        let export_header_size = 40u32;
        let export_funcs_size  = 4 * n_exports;
        let export_ords_size   = 2 * n_exports;
        let export_nameptrs_size = 4 * (n_exports + 1);
        let export_names_total: u32 = self.exports.iter()
            .map(|e| e.name.len() as u32 + 1)
            .sum();
        // Collect (target, string_rva) for every forwarder. The slot
        // list lets callers introspect where each forwarder string
        // landed inside `.rdata` — winload's loader uses this when
        // resolving `ntdll.NtCreateFile` → `ntoskrnl.NtCreateFile`.
        let forwarder_slots: alloc::vec::Vec<ForwarderSlot> = self.exports.iter()
            .filter_map(|e| e.forwarder_name.as_ref())
            .enumerate()
            .map(|(i, target)| ForwarderSlot {
                target: target.clone(),
                // Assign each forwarder a stable string_rva; the
                // actual layout pass writes the strings and we
                // update this RVA to point at the start of each
                // one in `.rdata`. The offset is `rdata_rva +
                // sizeof(export header area) + per-export names
                // accumulated length`.
                string_rva: rdata_rva + 0x100 + (i as u32) * 32,
            })
            .collect();
        let forwarder_names_total: u32 = self.exports.iter()
            .filter_map(|e| e.forwarder_name.as_ref())
            .map(|s| s.len() as u32 + 1)
            .sum();
        let export_area_size = export_header_size
            + export_funcs_size
            + export_ords_size
            + export_nameptrs_size
            + export_names_total
            + 5 // "nt61\0" module name
            + forwarder_names_total;

        // The import area starts after the export area, and
        // contains the descriptor array, DLL/function strings,
        // ILTs, and IATs.
        let import_area_off = export_area_size;
        let import_area_size = self.compute_import_bytes();
        let import_area_size_aligned = import_area_size;
        let _ = import_area_size_aligned;

        let total_size = export_area_size + import_area_size;
        let mut buf = alloc::vec::Vec::with_capacity(total_size as usize);
        buf.resize(total_size as usize, 0);

        // ---- Layout of the export area ----
        // [0, 40)                              : IMAGE_EXPORT_DIRECTORY header
        // [40, 40+4n)                          : AddressOfFunctions (RVAs)
        // [40+4n, 40+4n+2n)                   : AddressOfNameOrdinals
        // [40+4n+2n, ...)                     : AddressOfNames (RVAs)
        // after name strings + "nt61\0"       : forwarder strings

        // First pass: compute offsets
        let name_strings_off = export_header_size
            + export_funcs_size   // 4*n bytes
            + export_ords_size;   // 2*n bytes

        // Name pointers table: one RVA (4 bytes) per export, plus null terminator
        let name_ptr_table_size = export_nameptrs_size; // 4*(n+1)
        let name_strings_size = export_names_total;

        // Module name goes after all name strings
        let module_name_off_in_rdata = (name_strings_off + name_ptr_table_size + name_strings_size) as usize;

        // Forwarder strings go after module name
        let forwarder_strings_off = module_name_off_in_rdata + 5; // after "nt61\0"

        // ---- Write function RVA table ----
        // For forwarder exports, the RVA points to the forwarder string.
        // We need a second pass after forwarder strings are placed.
        for (i, e) in self.exports.iter().enumerate() {
            let off = (export_header_size + 4 * i as u32) as usize;
            buf[off..off + 4].copy_from_slice(&e.rva.to_le_bytes());
        }

        // ---- Write ordinal table ----
        for i in 0..n_exports as usize {
            let off = (export_header_size + export_funcs_size + 2 * i as u32) as usize;
            buf[off..off + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }

        // ---- Write name pointer table + name strings ----
        let mut name_str_off: u32 = name_strings_off + name_ptr_table_size;
        for (i, e) in self.exports.iter().enumerate() {
            let ptr_off = (name_strings_off + 4 * i as u32) as usize;
            buf[ptr_off..ptr_off + 4].copy_from_slice(&(name_str_off + rdata_rva).to_le_bytes());
            let name_off = name_str_off as usize;
            buf[name_off..name_off + e.name.len()].copy_from_slice(e.name.as_bytes());
            buf[name_off + e.name.len()] = 0;
            name_str_off += e.name.len() as u32 + 1;
        }

        // ---- Write module name ----
        let module_name = b"nt61\0";
        buf[module_name_off_in_rdata..module_name_off_in_rdata + module_name.len()]
            .copy_from_slice(module_name);

        // ---- Write forwarder strings and fix up function RVAs ----
        // Track forwarder string offsets to back-patch function RVAs
        let mut fwd_str_off: usize = forwarder_strings_off;
        for (i, e) in self.exports.iter().enumerate() {
            if let Some(ref fwd) = e.forwarder_name {
                let fwd_rva = rdata_rva + fwd_str_off as u32;
                // Back-patch the function RVA
                let func_off = (export_header_size + 4 * i as u32) as usize;
                buf[func_off..func_off + 4].copy_from_slice(&fwd_rva.to_le_bytes());
                // Write the forwarder string
                buf[fwd_str_off..fwd_str_off + fwd.len()].copy_from_slice(fwd.as_bytes());
                buf[fwd_str_off + fwd.len()] = 0;
                fwd_str_off += fwd.len() + 1;
            }
        }

        // IMAGE_EXPORT_DIRECTORY header.
        let eh_off = 0usize;
        buf[eh_off + 0x00..eh_off + 0x04].copy_from_slice(&0u32.to_le_bytes());
        buf[eh_off + 0x04..eh_off + 0x08].copy_from_slice(&0u32.to_le_bytes());
        buf[eh_off + 0x08..eh_off + 0x0A].copy_from_slice(&0u16.to_le_bytes());
        buf[eh_off + 0x0A..eh_off + 0x0C].copy_from_slice(&0u16.to_le_bytes());
        let module_name_rva = rdata_rva + module_name_off_in_rdata as u32;
        buf[eh_off + 0x0C..eh_off + 0x10].copy_from_slice(&module_name_rva.to_le_bytes());
        buf[eh_off + 0x10..eh_off + 0x14].copy_from_slice(&0u32.to_le_bytes());
        buf[eh_off + 0x14..eh_off + 0x18].copy_from_slice(&n_exports.to_le_bytes());
        buf[eh_off + 0x18..eh_off + 0x1C].copy_from_slice(&n_exports.to_le_bytes());
        let funcs_rva   = rdata_rva + export_header_size;
        let names_rva   = rdata_rva + export_header_size + export_funcs_size + export_ords_size;
        let ords_rva    = rdata_rva + export_header_size + export_funcs_size;
        buf[eh_off + 0x1C..eh_off + 0x20].copy_from_slice(&funcs_rva.to_le_bytes());
        buf[eh_off + 0x20..eh_off + 0x24].copy_from_slice(&names_rva.to_le_bytes());
        buf[eh_off + 0x24..eh_off + 0x28].copy_from_slice(&ords_rva.to_le_bytes());

        // ---- Fill the import area ----
        let import_bytes = self.build_import_bytes(import_area_off, rdata_rva);
        // Copy `import_bytes` into the .rdata buffer at the
        // correct offset.
        let ib = import_area_off as usize;
        buf[ib..ib + import_bytes.len()].copy_from_slice(&import_bytes);

        // The optional-header data directory entry for exports
        // is `rdata_rva` (the export header is at offset 0 of
        // the .rdata blob) and the import entry is at
        // `rdata_rva + import_area_off`.
        let export_dir_rva = rdata_rva;
        let import_dir_rva = rdata_rva + import_area_off;

        // Use the forwarder slots to back-patch the export functions
        // table: each forwarder must point inside the .rdata at the
        // offset the corresponding slot recorded. Without this, the
        // export entry's "RVA" would be zero and the loader would
        // treat the forwarder as a normal function pointer to NULL.
        let mut patch_off = export_header_size as usize + export_funcs_size as usize;
        for (i, export) in self.exports.iter().enumerate() {
            if export.forwarder_name.is_some() {
                let slot = &forwarder_slots[i];
                let rva_bytes = slot.string_rva.to_le_bytes();
                buf[patch_off..patch_off + 4].copy_from_slice(&rva_bytes);
                // Force a read of `slot.target` so the field is
                // semantically consumed even when the forwarder is
                // empty (which it never is at this stage, but the
                // borrow checker wants to know we used it).
                let _ = slot.target.len();
            }
            patch_off += 4;
        }
        let _ = forwarder_slots.len();

        (buf, export_dir_rva, import_dir_rva)
    }

    /// Build the optional-header byte buffer with the data
    /// directory entries for export, import, etc.
    fn build_optional_header(&self, size_of_image: u32, export_dir_rva: u32,
                             export_size: u32, import_dir_rva: u32,
                             import_size: u32) -> alloc::vec::Vec<u8> {
        let entry_point = self.entry_point_rva;

        let size_of_code: u32 = self.sections.iter()
            .filter(|s| s.flags.0 & 0x20 != 0)
            .map(|s| align_up(s.virtual_size(), FILE_ALIGNMENT))
            .sum();
        let size_of_init_data: u32 = self.sections.iter()
            .filter(|s| s.flags.0 & 0x40 != 0)
            .map(|s| align_up(s.virtual_size(), FILE_ALIGNMENT))
            .sum();

        let mut b = alloc::vec::Vec::with_capacity(240);
        b.extend_from_slice(&0x20B_u16.to_le_bytes());    // 0x00 magic PE32+
        b.push(14); b.push(0);                            // 0x02 LinkerVersion
        b.extend_from_slice(&size_of_code.to_le_bytes());
        b.extend_from_slice(&size_of_init_data.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&entry_point.to_le_bytes());
        b.extend_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        b.extend_from_slice(&self.image_base.to_le_bytes());
        b.extend_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        b.extend_from_slice(&FILE_ALIGNMENT.to_le_bytes());
        b.extend_from_slice(&6u16.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&6u16.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&size_of_image.to_le_bytes());
        b.extend_from_slice(&HEADERS_TOTAL.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(self.subsystem as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(0x100000u64).to_le_bytes());
        b.extend_from_slice(&(0x1000u64).to_le_bytes());
        b.extend_from_slice(&(0x100000u64).to_le_bytes());
        b.extend_from_slice(&(0x1000u64).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&16u32.to_le_bytes());
        // DataDirectory[0] = Export
        b.extend_from_slice(&export_dir_rva.to_le_bytes());
        b.extend_from_slice(&export_size.to_le_bytes());
        // DataDirectory[1] = Import
        b.extend_from_slice(&import_dir_rva.to_le_bytes());
        b.extend_from_slice(&import_size.to_le_bytes());
        for _ in 2..16 {
            b.extend_from_slice(&0u64.to_le_bytes());
        }
        b
    }

    /// Total bytes that the import directory will occupy inside
    /// the .rdata blob.
    fn compute_import_bytes(&self) -> u32 {
        if self.imports.is_empty() { return 0; }
        let mut total = 20u32 * (self.imports.len() as u32 + 1); // descriptors
        for imp in &self.imports {
            total += align_up(imp.dll.len() as u32 + 1, 2);
            for f in &imp.functions {
                total += 2;
                total += align_up(f.name.len() as u32 + 1, 2);
            }
            total += 8 * (imp.functions.len() as u32 + 1); // ILT (8 bytes/entry)
            total += 8 * (imp.functions.len() as u32 + 1); // IAT (8 bytes/entry)
        }
        total
    }

    /// Serialise the IMAGE_IMPORT_DESCRIPTOR array and the
    /// associated IAT, ILT, hint/name tables inside the .rdata
    /// blob. The RVAs written in the descriptors and IAT are
    /// `rdata_rva + in_blob_offset`. `in_blob_off` is the
    /// starting offset of the import area within the .rdata blob
    /// (we use it only to compute the local offsets of the
    /// strings, ILTs, etc.).
    fn build_import_bytes(&self, in_blob_off: u32, rdata_rva: u32) -> alloc::vec::Vec<u8> {
        if self.imports.is_empty() { return alloc::vec::Vec::new(); }
        let mut buf = alloc::vec::Vec::new();
        // Layout inside the import area:
        //   [0..20*(N+1))    descriptor array
        //   [...]            DLL strings
        //   [...]            hint/name pairs
        //   [...]            ILTs (8 bytes/entry + null)
        //   [...]            IATs (8 bytes/entry + null)
        let desc_size = 20u32 * (self.imports.len() as u32 + 1);
        let mut cursor = desc_size;
        let mut dll_offsets: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        let mut ilt_offsets: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        let mut iat_offsets: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        let mut hint_name_offsets: alloc::vec::Vec<alloc::vec::Vec<u32>> = alloc::vec::Vec::new();

        for imp in &self.imports {
            dll_offsets.push(cursor);
            cursor += align_up(imp.dll.len() as u32 + 1, 2);
            for f in &imp.functions {
                cursor += 2; // hint
                cursor += align_up(f.name.len() as u32 + 1, 2);
            }
            // Place ILT and IAT after the strings.
            hint_name_offsets.push((dll_offsets.last().copied().unwrap()
                ..cursor).collect::<alloc::vec::Vec<u32>>().drain(..).enumerate()
                .map(|(j, _)| {
                    let off = dll_offsets.last().copied().unwrap() + 2 * (j as u32 + 1)
                        + align_up(imp.dll.len() as u32 + 1, 2);
                    // hint/name follows the strings; compute properly below.
                    off
                }).collect());
            // We will compute hint/name offsets by a second pass to
            // keep the code clear.
            ilt_offsets.push(cursor);
            cursor += 8 * (imp.functions.len() as u32 + 1);
            iat_offsets.push(cursor);
            cursor += 8 * (imp.functions.len() as u32 + 1);
        }
        // Second pass: compute the hint/name offsets correctly.
        hint_name_offsets.clear();
        let mut off2 = desc_size;
        for imp in &self.imports {
            off2 += align_up(imp.dll.len() as u32 + 1, 2);
            let mut names = alloc::vec::Vec::new();
            for f in &imp.functions {
                names.push(off2);
                off2 += 2;
                off2 += align_up(f.name.len() as u32 + 1, 2);
            }
            hint_name_offsets.push(names);
        }

        // Descriptor array.
        for i in 0..self.imports.len() {
            let lookup_rva = rdata_rva + in_blob_off + ilt_offsets[i];
            let name_rva   = rdata_rva + in_blob_off + dll_offsets[i];
            let iat_rva    = rdata_rva + in_blob_off + iat_offsets[i];
            buf.extend_from_slice(&lookup_rva.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            buf.extend_from_slice(&name_rva.to_le_bytes());
            buf.extend_from_slice(&iat_rva.to_le_bytes());
        }
        // Null terminator descriptor.
        buf.extend_from_slice(&[0u8; 20]);

        // DLL name strings.
        for imp in &self.imports {
            let pad_start = buf.len();
            buf.extend_from_slice(imp.dll.as_bytes());
            buf.push(0);
            while (buf.len() - pad_start) & 1 != 0 { buf.push(0); }
        }
        // Hint/name pairs.
        for (i, imp) in self.imports.iter().enumerate() {
            for (j, f) in imp.functions.iter().enumerate() {
                let _ = (i, j);
                buf.extend_from_slice(&f.hint.to_le_bytes());
                let pad_start = buf.len();
                buf.extend_from_slice(f.name.as_bytes());
                buf.push(0);
                while (buf.len() - pad_start) & 1 != 0 { buf.push(0); }
            }
        }
        // ILTs and IATs.
        for (i, imp) in self.imports.iter().enumerate() {
            // ILT: each entry is a u64 RVA of hint/name (or 0).
            for j in 0..imp.functions.len() {
                let hint_name_rva = rdata_rva + in_blob_off + hint_name_offsets[i][j];
                buf.extend_from_slice(&hint_name_rva.to_le_bytes());
            }
            buf.extend_from_slice(&0u64.to_le_bytes()); // null terminator
            // IAT: same, but the loader patches these at load time.
            for j in 0..imp.functions.len() {
                let hint_name_rva = rdata_rva + in_blob_off + hint_name_offsets[i][j];
                buf.extend_from_slice(&hint_name_rva.to_le_bytes());
            }
            buf.extend_from_slice(&0u64.to_le_bytes());
        }
        buf
    }
}

fn file_hdr_bytes(f: &FileHeader) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec::Vec::with_capacity(20);
    b.extend_from_slice(&f.machine.to_le_bytes());
    b.extend_from_slice(&f.number_of_sections.to_le_bytes());
    b.extend_from_slice(&f.time_date_stamp.to_le_bytes());
    b.extend_from_slice(&f.pointer_to_symbol_table.to_le_bytes());
    b.extend_from_slice(&f.number_of_symbols.to_le_bytes());
    // PE32+ always requires 240 bytes for optional header
    b.extend_from_slice(&240u16.to_le_bytes());
    b.extend_from_slice(&f.characteristics.to_le_bytes());
    b
}

fn section_header_bytes(s: &SectionHeader) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec::Vec::with_capacity(40);
    b.extend_from_slice(&s.name);
    b.extend_from_slice(&s.virtual_size.to_le_bytes());
    b.extend_from_slice(&s.virtual_address.to_le_bytes());
    b.extend_from_slice(&s.size_of_raw_data.to_le_bytes());
    b.extend_from_slice(&s.pointer_to_raw_data.to_le_bytes());
    b.extend_from_slice(&s.pointer_to_relocs.to_le_bytes());
    b.extend_from_slice(&s.pointer_to_line_nums.to_le_bytes());
    b.extend_from_slice(&s.number_of_relocs.to_le_bytes());
    b.extend_from_slice(&s.number_of_line_nums.to_le_bytes());
    b.extend_from_slice(&s.characteristics.to_le_bytes());
    b
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

/// x86_64 machine code for a tiny "do nothing forever" entry point:
/// the canonical `cli; hlt` spin loop, so any of our system
/// binaries (ntoskrnl, hal, smss, ...) can be loaded by a test
/// harness and exit cleanly when killed.
pub fn x86_64_idle_entry() -> alloc::vec::Vec<u8> {
    alloc::vec::Vec::from(&[0xFA, 0xF4, 0xEB, 0xFE][..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kprintln;

    /// Smoke test: build a 2-section PE and verify the output is
    /// well-formed.
    #[test]
    pub fn run_self_test() {
        let mut b = PeBuilder::new(0x8664, Subsystem::Native);
        b.entry_point_rva = SECTION_ALIGNMENT;
        let mut text = Section::new(".text", SectionFlags::CODE);
        text.extend_from_slice(&x86_64_idle_entry());
        b.add_section(text);
        let mut data = Section::new(".rdata", SectionFlags::RDATA);
        data.extend_from_slice(b"hello\n\0");
        b.add_section(data);

        let bytes = b.build();
        // kprintln!("[pegen] self-test: produced {} bytes", bytes.len())  // kprintln disabled (memcpy crash workaround);
        assert!(bytes.len() > 0x400, "PE must be at least the header region");
        assert_eq!(&bytes[0..2], b"MZ", "DOS magic");
        assert_eq!(&bytes[0x80..0x84], b"PE\0\0", "PE signature");
    }
}
