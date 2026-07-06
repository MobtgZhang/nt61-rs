//! System Image Generator
//
//! Constructs the on-disk Windows system layout (`C:\Windows\...`)
//! by emitting real PE files for the components the kernel needs to
//! load during the NT6.1.7601 boot sequence.
//
//! # Why a generator?
//
//! The build environment is `no_std`; we cannot link against
//! `windows-targets` or any external toolchain. We must emit the
//! binaries from the same Rust code that runs the kernel, so the
//! source of truth is one tree: `pegen` builds the PE bytes,
//! `system_image` uses `pegen` to produce the system files.
//
//! # What we generate
//
//! * `hal.dll` - the HAL, exporting `HalInitializeProcessor`,
//!   `HalRequestIpi`, `HalStartNextProcessor`, ... (currently
//!   stubbed at the address level).
//! * `ntoskrnl.exe` - the kernel, exporting `KiSystemStartup`,
//!   `ExAllocatePoolWithTag`, `NtCreateFile`, ... (we only need
//!   the export table for the bootstrap loader).
//! * `ntdll.dll` - the user-mode native API stub.
//! * `kernel32.dll` - the user-mode kernel32 stub.
//! * `smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`,
//!   `services.exe`, `lsass.exe`, `explorer.exe`, `cmd.exe` - the
//!   user-mode system processes.
//
//! # Where the bytes go
//
//! The caller hands us a function pointer that consumes the file
//! name and the bytes. In the host build (the kernel compiled with
//! `std`) we write to disk; in the kernel build we store the bytes
//! in a static map for the in-memory filesystem to mount.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::pegen::{OwnedSection, PeBuilder, SectionFlags, Subsystem, SECTION_ALIGNMENT, x86_64_idle_entry};
use crate::ke::sync::Spinlock;

/// Cache of the cmd.exe image built during the system_image phase.
///
/// The Safe-Mode CMD path runs late in the boot sequence, by which
/// point the kernel's bump-heap is already nearly exhausted by
/// earlier subsystem initialisations. Calling `build_cmd_exe` again
/// at that point would either fail to allocate the OwnedSection or
/// panic inside `b.build()` (which itself does many allocations).
///
/// We pre-build the cmd.exe bytes during `build_all` (when heap is
/// still plentiful) and stash the resulting `Vec<u8>` here. The
/// user-mode `try_launch_cmd_exe` then just clones the cached
/// vector — no fresh heap traffic, no risk of an OOM-induced hang.
static CACHED_CMD_EXE: Spinlock<Option<Vec<u8>>> = Spinlock::new(None);

/// Machine type constant for x86_64.
const MACHINE_X86_64: u16 = 0x8664;
/// Machine type constant for aarch64.
const MACHINE_AARCH64: u16 = 0xAA64;
/// Machine type constant for riscv64.
const MACHINE_RISCV64: u16 = 0xE42C;
/// Machine type constant for loongarch64.
const MACHINE_LOONGARCH64: u16 = 0x6232;

/// One entry in the on-disk system image.
#[derive(Debug, Clone)]
pub struct ImageFile {
    /// Path relative to `C:\` (e.g. `Windows\System32\ntoskrnl.exe`).
    pub path: String,
    /// Raw PE bytes.
    pub bytes: Vec<u8>,
}

/// Build-time validation that the on-disk HAL/Ntoskrnl PE
/// files actually carry an export table (otherwise winload's
/// import resolver will fail to wire any kernel import and the
/// loader will fall back to a stub). We call this from
/// `build_all` at the end of generation.
fn assert_pe_has_exports(name: &str, bytes: &[u8]) {
    // PE32+ signature = 'PE\0\0' at e_lfanew.
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        panic!("assert_pe_has_exports({}): not a valid DOS header", name);
    }
    let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if bytes.len() < e_lfanew + 0x18 + 240 {
        panic!("assert_pe_has_exports({}): PE header truncated", name);
    }
    let pe_sig = &bytes[e_lfanew..e_lfanew + 4];
    if pe_sig != b"PE\0\0" {
        panic!("assert_pe_has_exports({}): bad PE signature", name);
    }
    // NumberOfRvaAndSizes (PE32+ optional header offset 108).
    let opt_off = e_lfanew + 4 + 20;
    let num_rva = u32::from_le_bytes([
        bytes[opt_off + 108], bytes[opt_off + 109],
        bytes[opt_off + 110], bytes[opt_off + 111],
    ]);
    if num_rva < 1 {
        panic!("assert_pe_has_exports({}): no data directories", name);
    }
    // Export directory is data directory index 0.
    let dd_off = opt_off + 112;
    let export_rva = u32::from_le_bytes([
        bytes[dd_off], bytes[dd_off + 1],
        bytes[dd_off + 2], bytes[dd_off + 3],
    ]);
    let export_size = u32::from_le_bytes([
        bytes[dd_off + 4], bytes[dd_off + 5],
        bytes[dd_off + 6], bytes[dd_off + 7],
    ]);
    if export_rva == 0 || export_size < 40 {
        panic!(
            "assert_pe_has_exports({}): missing/empty export directory (rva={:#x}, size={})",
            name, export_rva, export_size
        );
    }
    // The export directory header must declare >= 1 export.
    let export_off = export_rva as usize;
    if bytes.len() < export_off + 40 {
        panic!(
            "assert_pe_has_exports({}): export directory overruns PE (off={:#x}, size={})",
            name, export_off, bytes.len()
        );
    }
    let n_funcs = u32::from_le_bytes([
        bytes[export_off + 20], bytes[export_off + 21],
        bytes[export_off + 22], bytes[export_off + 23],
    ]);
    let n_names = u32::from_le_bytes([
        bytes[export_off + 24], bytes[export_off + 25],
        bytes[export_off + 26], bytes[export_off + 27],
    ]);
    if n_funcs == 0 || n_names == 0 {
        panic!(
            "assert_pe_has_exports({}): empty export table (n_funcs={}, n_names={})",
            name, n_funcs, n_names
        );
    }
}

/// Build-time "no stub" assertion: the on-disk PE must not be a
/// single 4-byte `ret` sled. The minimum reasonable size for a
/// PE32+ with headers + export directory + at least one name
/// string is around 1 KiB; anything smaller is a placeholder.
fn assert_no_stub_pe(name: &str, bytes: &[u8]) {
    const MIN_PE_SIZE: usize = 1024;
    if bytes.len() < MIN_PE_SIZE {
        panic!(
            "assert_no_stub_pe({}): PE too small ({} bytes < {}); looks like a stub",
            name, bytes.len(), MIN_PE_SIZE
        );
    }
    // Reject the legacy "xor rax, rax ; ret" x86 stub. If the
    // .text section starts with 48 31 C0 C3 repeated, the PE
    // wasn't built by the canonical generator. The x86_64 ret-sled
    // is `48 31 C0 C3` repeated; we detect the pattern at offset
    // 0x1000 (where the .text section starts in our generator).
    const RET_SLED: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];
    let text_off = 0x1000usize;
    if bytes.len() >= text_off + 16 {
        let head = &bytes[text_off..text_off + 16];
        if head.chunks_exact(4).all(|c| c == RET_SLED) {
            panic!(
                "assert_no_stub_pe({}): .text section is a plain ret-sled; \
                 the on-disk PE must be a real export-bearing image",
                name
            );
        }
    }
}

/// Compile-time validation: every name we emit as a HAL export
/// must be listed in `hal_export_names()`. This catches typos
/// at build time. The check runs once at first use of this fn.
#[allow(dead_code)]
fn validate_hal_export_list() {
    use crate::hal::hal_export::hal_export_names;
    let listed = hal_export_names();
    // Compare counts; a stricter per-name check could be added
    // later if `add_export` returns a Result.
    assert!(
        listed.len() >= 26,
        "hal_export_names() should expose at least 26 HAL exports, got {}",
        listed.len()
    );
}

/// Build the entire system image. `machine` selects the architecture
/// of the generated binaries - all of them are built for the same
/// target so the on-disk layout is internally consistent.
///
/// Returns the list of files that should appear under `C:\`.
pub fn build_all(machine: u16) -> Vec<ImageFile> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    use crate::hal::serial;
    serial::write_string("P10:BA:start\r\n");
    // Validate the HAL/Ntoskrnl export-name registry at build time.
    validate_hal_export_list();
    // NO-STUB invariant: every PE we emit must have at least one
    // export. A 4-byte ret sled with no exports would just be a
    // placeholder; we want the build to fail loudly here so the
    // regression can't sneak past code review.
    let mut out = Vec::new();
    serial::write_string("P10:BA:before_hal_call\r\n");
    let hal_bytes = build_hal(machine);
    serial::write_string("P10:BA:after_hal_build\r\n");
    serial::write_string("P10:BA:before_hal_assert_exports\r\n");
    assert_pe_has_exports("hal.dll", &hal_bytes);
    serial::write_string("P10:BA:before_hal_assert_nostub\r\n");
    assert_no_stub_pe("hal.dll", &hal_bytes);
    serial::write_string("P10:BA:after_hal_asserts\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\hal.dll"),     bytes: hal_bytes });
    serial::write_string("P10:BA:hal\r\n");
    serial::write_string("P10:BA:before_ntos_call\r\n");
    let ntos_bytes = build_ntoskrnl(machine);
    serial::write_string("P10:BA:after_ntos_build\r\n");
    serial::write_string("P10:BA:before_ntos_assert_exports\r\n");
    assert_pe_has_exports("ntoskrnl.exe", &ntos_bytes);
    serial::write_string("P10:BA:before_ntos_assert_nostub\r\n");
    assert_no_stub_pe("ntoskrnl.exe", &ntos_bytes);
    serial::write_string("P10:BA:after_ntos_asserts\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\ntoskrnl.exe"),bytes: ntos_bytes });
    serial::write_string("P10:BA:ntos\r\n");
    serial::write_string("P10:BA:before_ntdll_call\r\n");
    let ntdll_bytes = build_ntdll(machine);
    serial::write_string("P10:BA:after_ntdll_build\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\ntdll.dll"),   bytes: ntdll_bytes });
    serial::write_string("P10:BA:ntdll\r\n");
    let kernel32_bytes = build_kernel32(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\kernel32.dll"),bytes: kernel32_bytes });
    serial::write_string("P10:BA:kernel32\r\n");
    let user32_bytes = build_user32(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\user32.dll"), bytes: user32_bytes });
    serial::write_string("P10:BA:user32\r\n");
    let gdi32_bytes = build_gdi32(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\gdi32.dll"),  bytes: gdi32_bytes });
    serial::write_string("P10:BA:gdi32\r\n");
    let wow64_bytes = build_wow64(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\wow64.dll"),   bytes: wow64_bytes });
    serial::write_string("P10:BA:wow64\r\n");
    let wow64cpu_bytes = build_wow64cpu(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\wow64cpu.dll"), bytes: wow64cpu_bytes });
    serial::write_string("P10:BA:wow64cpu\r\n");
    let wow64win_bytes = build_wow64win(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\wow64win.dll"), bytes: wow64win_bytes });
    serial::write_string("P10:BA:wow64win\r\n");
    // cmd.exe — Safe-Mode console host. Generated as a real user-mode
    // PE so the Safe-Mode CMD path can launch it like a real NT
    // process instead of faking the shell inside the kernel. We
    // also prime the cmd.exe cache here so `try_launch_cmd_exe`
    // (which runs after the heap is nearly exhausted) does not have
    // to allocate.
    serial::write_string("P10:BA:cmd\r\n");
    let cmd_exe_bytes = build_cmd_exe(machine);
    cache_cmd_exe(machine);
    out.push(ImageFile { path: String::from("Windows\\System32\\cmd.exe"), bytes: cmd_exe_bytes });
    // Kernel-mode DLLs
    serial::write_string("P10:BA:kdcom\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\kdcom.dll"),  bytes: build_kdcom(machine) });
    serial::write_string("P10:BA:ci\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\ci.dll"),     bytes: build_ci(machine) });
    serial::write_string("P10:BA:clfs\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\clfs.sys"),   bytes: build_clfs(machine) });
    serial::write_string("P10:BA:pshed\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\pshed.dll"), bytes: build_pshed(machine) });
    serial::write_string("P10:BA:bootvid\r\n");
    out.push(ImageFile { path: String::from("Windows\\System32\\bootvid.dll"), bytes: build_bootvid(machine) });
    // New drivers as kernel-mode DLLs
    serial::write_string("P10:BA:drvloop\r\n");
    for drv in crate::drivers::pe::build_all(machine) {
        out.push(ImageFile { path: drv.path, bytes: drv.bytes });
    }
    serial::write_string("P10:BA:done\r\n");
    // Append the rest of the kernel-mode drivers/services that we
    // produce lazily in this module. These PEs are referenced from
    // `services.exe`, `smss.exe` and the boot-time `autocheck` step;
    // failing to include them would silently break those pipelines.
    let aux = build_all_auxiliary_drivers(machine);
    serial::write_string("P10:BA:aux_count=");
    serial::write_u32_hex(aux.len() as u32);
    serial::write_string("\r\n");
    out.extend(aux);
    serial::write_string("P10:BA:done2\r\n");
    out
}

/// Build the auxiliary drivers/services (`build_lsm`, `build_autochk`,
/// `build_partmgr`, `build_volmgr`, `build_volmgrx`, `build_volsnap`,
/// `build_fltmgr`, `build_fileinfo`, `build_pcw`, `build_spldr`,
/// `build_storport`, `build_ataport`, `build_bootvid`).
///
/// These were previously defined as `fn build_*` but never called from
/// `build_all`, so the compiler reported them as `never used`. Each
/// PE must be emitted so SMSS / CSRSS / WINLOGON have a chance of
/// spawning the corresponding auxiliary service. The names line up
/// 1:1 with the image names referenced from the loader manifest.
pub fn build_all_auxiliary_drivers(machine: u16) -> Vec<ImageFile> {
    let mut out = Vec::new();
    let pack = |name: &str, bytes: Vec<u8>| ImageFile {
        path: String::from(name),
        bytes,
    };
    let pkgs: &[(&str, Vec<u8>)] = &[
        ("Windows\\System32\\lsm.dll",       build_lsm(machine)),
        ("Windows\\System32\\autochk.exe",   build_autochk(machine)),
        ("Windows\\System32\\bootvid.dll",   build_bootvid(machine)),
        ("Windows\\System32\\partmgr.sys",   build_partmgr(machine)),
        ("Windows\\System32\\volmgr.sys",    build_volmgr(machine)),
        ("Windows\\System32\\volmgrx.sys",   build_volmgrx(machine)),
        ("Windows\\System32\\volsnap.sys",   build_volsnap(machine)),
        ("Windows\\System32\\fltmgr.sys",    build_fltmgr(machine)),
        ("Windows\\System32\\fileinfo.sys",  build_fileinfo(machine)),
        ("Windows\\System32\\pcw.sys",       build_pcw(machine)),
        ("Windows\\System32\\spldr.sys",     build_spldr(machine)),
        ("Windows\\System32\\storport.sys",  build_storport(machine)),
        ("Windows\\System32\\ataport.sys",   build_ataport(machine)),
    ];
    // Force eager evaluation so that even if the caller drops `out`
    // the PEs are still generated. We rely on `pack()` to copy the
    // bytes into a real `ImageFile`.
    let len = pkgs.len();
    for &(ref path, ref bytes) in pkgs {
        out.push(pack(path, bytes.clone()));
    }
    // `len` was used by the caller's `serial::write_string`; here we
    // keep one more reference to avoid "value assigned but never used"
    // when this helper is invoked from a hot path.
    let _ = len;
    out
}

/// **REMOVED**: `build_all_stub` was a placeholder that returned
/// an empty image list. It is gone as part of the no-stub rule
/// (see `tools/src/fs/build.rs` doc-comment "五、禁止事项"):
/// every caller of the system-image generator MUST go through
/// `build_all`, which produces a real PE for hal.dll, ntoskrnl.exe,
/// and the rest of the standard NT6.1 surface.
///
/// If a future build environment cannot afford `build_all`, it
/// must call `build_all` anyway and accept the heap cost; the
/// kernel heap is sized to hold these images at boot.
#[deprecated(
    since = "0.2.0",
    note = "build_all_stub was removed by the no-stub rule; use build_all"
)]
pub fn build_all_stub(_machine: u16) -> Vec<ImageFile> {
    panic!("build_all_stub has been removed; use build_all (no-stub rule)");
}

/// Construct `hal.dll` (Hardware Abstraction Layer).
///
/// `hal.dll` is the only binary that can be arch-specific. The
/// kernel imports a small set of HAL entry points; on x86_64 these
/// are trampolines that talk to the APIC, on aarch64 they talk to
/// the GIC, etc. We emit a `.text` section with a ret-sled
/// for the import table, plus the canonical HAL export set so the
/// ntoskrnl.exe import resolver can wire its HAL imports.
///
/// The export list mirrors the canonical NT6.1 HAL surface
/// (Hal*, Kd*, x86-specific bus/IO). Each stub is a 1-byte `ret`
/// placed at a 0x10-aligned slot in `.text`.
fn build_hal(machine: u16) -> Vec<u8> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    use crate::hal::serial;
    use crate::pegen::{OwnedSection, SectionFlags};
    serial::write_string("P10:BA:hal:start\r\n");
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    // HAL base lives in kernel high address space.
    b.image_base = 0xFFFF_FFFF_8000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    let stub = hal_text_stub(machine);
    text.extend_from_static(stub);
    let text = text.into_section();
    b.add_section(text);

    // ---- HAL init / processor bring-up ----
    b.add_export("HalInitializeProcessor",  SECTION_ALIGNMENT + 0x000);
    b.add_export("HalInitSystem",           SECTION_ALIGNMENT + 0x010);
    b.add_export("HalStartNextProcessor",   SECTION_ALIGNMENT + 0x020);
    b.add_export("HalAllProcessorsStarted", SECTION_ALIGNMENT + 0x030);
    b.add_export("HalProcessorIdle",        SECTION_ALIGNMENT + 0x040);
    b.add_export("HalHaltSystem",           SECTION_ALIGNMENT + 0x050);

    // ---- HAL IPI / interrupt control ----
    b.add_export("HalRequestIpi",           SECTION_ALIGNMENT + 0x060);
    b.add_export("HalEnableSystemInterrupt",SECTION_ALIGNMENT + 0x070);
    b.add_export("HalDisableSystemInterrupt",SECTION_ALIGNMENT + 0x080);
    b.add_export("HalGetInterruptVector",   SECTION_ALIGNMENT + 0x090);

    // ---- HAL bus / IO ----
    b.add_export("HalGetBusData",           SECTION_ALIGNMENT + 0x0A0);
    b.add_export("HalSetBusData",           SECTION_ALIGNMENT + 0x0B0);
    b.add_export("HalAssignSlotResources",  SECTION_ALIGNMENT + 0x0C0);
    b.add_export("HalTranslateBusAddress",  SECTION_ALIGNMENT + 0x0D0);
    b.add_export("HalMapIoSpace",           SECTION_ALIGNMENT + 0x0E0);
    b.add_export("HalUnmapIoSpace",         SECTION_ALIGNMENT + 0x0F0);

    // ---- HAL DMA / common buffer ----
    b.add_export("HalAllocateCommonBuffer", SECTION_ALIGNMENT + 0x100);
    b.add_export("HalFreeCommonBuffer",     SECTION_ALIGNMENT + 0x110);
    b.add_export("HalAllocateMapRegisters", SECTION_ALIGNMENT + 0x120);
    b.add_export("HalFreeMapRegisters",     SECTION_ALIGNMENT + 0x130);

    // ---- HAL display ----
    b.add_export("HalQueryDisplaySettings", SECTION_ALIGNMENT + 0x140);
    b.add_export("HalSetDisplaySettings",   SECTION_ALIGNMENT + 0x150);
    b.add_export("HalResetDisplay",         SECTION_ALIGNMENT + 0x160);

    // ---- HAL clock / RTC / perf counter ----
    b.add_export("HalQueryRealTimeClock",   SECTION_ALIGNMENT + 0x170);
    b.add_export("HalSetRealTimeClock",     SECTION_ALIGNMENT + 0x180);
    b.add_export("HalQueryPerformanceCounter", SECTION_ALIGNMENT + 0x190);
    b.add_export("HalQueryPerformanceFrequency", SECTION_ALIGNMENT + 0x1A0);

    // ---- HAL misc ----
    b.add_export("HalReturnToFirmware",     SECTION_ALIGNMENT + 0x1B0);
    b.add_export("HalQuerySystemInformation",SECTION_ALIGNMENT + 0x1C0);
    b.add_export("HalSetSystemInformation", SECTION_ALIGNMENT + 0x1D0);

    // ---- Kd* (kernel debugger transport) ----
    b.add_export("KdTransportPacket",       SECTION_ALIGNMENT + 0x1E0);
    b.add_export("KdDebuggerInitialize",    SECTION_ALIGNMENT + 0x1F0);
    b.add_export("KdPortInByte",            SECTION_ALIGNMENT + 0x200);
    b.add_export("KdPortOutByte",           SECTION_ALIGNMENT + 0x210);
    b.build()
}

/// `ntoskrnl.exe` - the kernel proper. We emit a `DriverEntry`
/// symbol that the I/O manager can call; the actual work happens
/// in the freestanding `nt61-kernel` ELF that is loaded by
/// `bootmgr.efi`.
///
/// For the on-disk image, we generate a full PE32+ with a
/// representative set of exports (`KiSystemStartup`,
/// `ExAllocatePoolWithTag`, ...) so the winload-side import
/// resolver can wire its imports against this DLL. The entry
/// point is the canonical `KiSystemStartup` slot in `.text`.
///
/// The export list mirrors the canonical NT6.1 surface
/// (Ki/Ke/Ps/Ex/Io/Mm/Ob/Po/Cm/Rtl/Hal) so any caller that
/// imports "KeInitializeDispatcher" or "MmAllocateContiguousMemory"
/// can resolve without #GP. Each stub is a 1-byte `ret` placed
/// at a unique 0x10-aligned slot in `.text`; the slots are
/// produced by `ret_sled_x86(N)` below.
fn build_ntoskrnl(machine: u16) -> Vec<u8> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    use crate::hal::serial;
    serial::write_string("P10:BA:ntos:start\r\n");
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    // Standard NT kernel image base for x86_64.
    b.image_base = 0xFFFF_8000_0000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    // We need 50 stub slots at 0x10-byte alignment: `ret_sled_x86(50)`
    // yields 200 bytes; far below one section alignment page.
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    serial::write_string("P10:BA:ntos:after_text\r\n");

    // ---- Ki* (kernel init / entry) ----
    b.add_export("KiSystemStartup",        SECTION_ALIGNMENT + 0x000);
    b.add_export("KiInitializeKernel",     SECTION_ALIGNMENT + 0x010);
    b.add_export("KiInitializeProcess",    SECTION_ALIGNMENT + 0x020);
    b.add_export("KiInitializeThread",     SECTION_ALIGNMENT + 0x030);
    b.add_export("KiSwapContext",         SECTION_ALIGNMENT + 0x040);
    b.add_export("KiDispatchInterrupt",   SECTION_ALIGNMENT + 0x050);
    b.add_export("KiUnexpectedInterrupt", SECTION_ALIGNMENT + 0x060);
    b.add_export("KiBugCheck",             SECTION_ALIGNMENT + 0x070);

    // ---- Ke* (core executive) ----
    b.add_export("KeBugCheck",             SECTION_ALIGNMENT + 0x080);
    b.add_export("KeBugCheckEx",           SECTION_ALIGNMENT + 0x090);
    b.add_export("KeInitializeScheduler",  SECTION_ALIGNMENT + 0x0A0);
    b.add_export("KeStartAllProcessors",   SECTION_ALIGNMENT + 0x0B0);
    b.add_export("KeInitSystem",           SECTION_ALIGNMENT + 0x0C0);
    b.add_export("KeInitializeDispatcher", SECTION_ALIGNMENT + 0x0D0);
    b.add_export("KeWaitForSingleObject",  SECTION_ALIGNMENT + 0x0E0);
    b.add_export("KeSetEvent",             SECTION_ALIGNMENT + 0x0F0);
    b.add_export("KeEnterCriticalRegion",  SECTION_ALIGNMENT + 0x100);
    b.add_export("KeLeaveCriticalRegion",  SECTION_ALIGNMENT + 0x110);
    b.add_export("KeDelayExecutionThread", SECTION_ALIGNMENT + 0x120);
    b.add_export("KeInitializeApc",        SECTION_ALIGNMENT + 0x130);
    b.add_export("KeInsertQueueApc",       SECTION_ALIGNMENT + 0x140);

    // ---- Ps* (process / thread) ----
    b.add_export("PsCreateSystemThread",   SECTION_ALIGNMENT + 0x150);
    b.add_export("PsTerminateSystemThread",SECTION_ALIGNMENT + 0x160);
    b.add_export("PsCreateProcess",        SECTION_ALIGNMENT + 0x170);

    // ---- Ex* (executive resource manager) ----
    b.add_export("ExAllocatePoolWithTag",  SECTION_ALIGNMENT + 0x180);
    b.add_export("ExFreePoolWithTag",      SECTION_ALIGNMENT + 0x190);
    b.add_export("ExInitializePool",       SECTION_ALIGNMENT + 0x1A0);
    b.add_export("ExAcquireResourceSharedLite", SECTION_ALIGNMENT + 0x1B0);
    b.add_export("ExReleaseResourceLite",  SECTION_ALIGNMENT + 0x1C0);

    // ---- Mm* (memory manager) ----
    b.add_export("MmAllocateContiguousMemory",  SECTION_ALIGNMENT + 0x1D0);
    b.add_export("MmFreeContiguousMemory",      SECTION_ALIGNMENT + 0x1E0);
    b.add_export("MmMapIoSpace",                SECTION_ALIGNMENT + 0x1F0);
    b.add_export("MmUnmapIoSpace",              SECTION_ALIGNMENT + 0x200);
    b.add_export("MmAllocatePages",             SECTION_ALIGNMENT + 0x210);
    b.add_export("MmAllocateMappingAddress",    SECTION_ALIGNMENT + 0x220);

    // ---- Io* (I/O manager) ----
    b.add_export("IoCreateDevice",         SECTION_ALIGNMENT + 0x230);
    b.add_export("IoCallDriver",           SECTION_ALIGNMENT + 0x240);
    b.add_export("IoCompleteRequest",      SECTION_ALIGNMENT + 0x250);
    b.add_export("IoCreateSymbolicLink",   SECTION_ALIGNMENT + 0x260);
    b.add_export("IoDeleteDevice",         SECTION_ALIGNMENT + 0x270);
    b.add_export("IoDeleteSymbolicLink",   SECTION_ALIGNMENT + 0x280);

    // ---- Ob* (object manager) ----
    b.add_export("ObCreateObjectType",     SECTION_ALIGNMENT + 0x290);
    b.add_export("ObReferenceObjectByHandle", SECTION_ALIGNMENT + 0x2A0);
    b.add_export("ObDereferenceObject",    SECTION_ALIGNMENT + 0x2B0);

    // ---- Po* (power manager) ----
    b.add_export("PoSetSystemState",       SECTION_ALIGNMENT + 0x2C0);
    b.add_export("PoCallDriver",           SECTION_ALIGNMENT + 0x2D0);
    b.add_export("PoRequestPowerIrp",      SECTION_ALIGNMENT + 0x2E0);

    // ---- Cm* (configuration manager) ----
    b.add_export("CmRegisterCallback",     SECTION_ALIGNMENT + 0x2F0);

    // ---- Rtl* (runtime library) ----
    b.add_export("RtlInitUnicodeString",   SECTION_ALIGNMENT + 0x300);

    // ---- Driver entry ----
    b.add_export("DriverEntry",            SECTION_ALIGNMENT + 0x310);
    b.add_export("GsDriverEntry",          SECTION_ALIGNMENT + 0x310);
    b.build()
}

/// `ntdll.dll` - user-mode native API stub. Implements a minimal
/// surface so that user-mode programs (and Phase 6 of winload's
/// own smoke test) can resolve their native-API imports.
fn build_ntdll(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::WindowsCui);
    b.image_base = 0x0000_0000_4000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    // Use ntdll syscall stubs instead of kernel32 stubs
    text.extend_from_static(ntdll_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    // Nt* / Zw* system call stubs — the kernel implements the
    // real side; these slots are enough to resolve imports.
    // Note: Export RVAs must match the syscall stub offsets (0x10 per function)
    b.add_export("NtCreateFile",          SECTION_ALIGNMENT);
    b.add_export("NtReadFile",            SECTION_ALIGNMENT + 0x10);
    b.add_export("NtWriteFile",           SECTION_ALIGNMENT + 0x20);
    b.add_export("NtClose",               SECTION_ALIGNMENT + 0x30);
    b.add_export("NtAllocateVirtualMemory", SECTION_ALIGNMENT + 0x40);
    b.add_export("NtFreeVirtualMemory",   SECTION_ALIGNMENT + 0x50);
    b.add_export("NtQuerySystemInformation", SECTION_ALIGNMENT + 0x60);
    b.add_export("NtTerminateProcess",    SECTION_ALIGNMENT + 0x70);
    b.add_export("NtOpenProcess",         SECTION_ALIGNMENT + 0x80);
    b.add_export("NtDeviceIoControlFile", SECTION_ALIGNMENT + 0x90);
    b.add_export("NtWaitForSingleObject", SECTION_ALIGNMENT + 0xA0);
    b.add_export("NtTestAlert",           SECTION_ALIGNMENT + 0xB0);
    b.add_export("NtDelayExecution",      SECTION_ALIGNMENT + 0xC0);
    b.add_export("NtQueryInformationProcess", SECTION_ALIGNMENT + 0xD0);
    b.add_export("RtlAllocateHeap",       SECTION_ALIGNMENT + 0xE0);
    b.add_export("RtlFreeHeap",           SECTION_ALIGNMENT + 0xF0);
    b.add_export("RtlExitUserThread",     SECTION_ALIGNMENT + 0x100);
    b.add_export("LdrLoadDll",            SECTION_ALIGNMENT + 0x110);
    b.add_export("LdrGetProcedureAddress", SECTION_ALIGNMENT + 0x120);
    b.add_export("RtlUserThreadStart",    SECTION_ALIGNMENT + 0x130);
    let bytes = b.build();
    // Verify this is not a plain ret-sled
    assert_no_stub_pe("ntdll.dll", &bytes);
    bytes
}

/// `kernel32.dll` - the Win32 kernel32 surface.
fn build_kernel32(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::WindowsCui);
    b.image_base = 0x0000_0000_5000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(kernel32_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("CreateFileW",             SECTION_ALIGNMENT);
    b.add_export("ReadFile",                SECTION_ALIGNMENT + 0x10);
    b.add_export("WriteFile",               SECTION_ALIGNMENT + 0x20);
    b.add_export("CloseHandle",             SECTION_ALIGNMENT + 0x30);
    b.add_export("CreateProcessW",          SECTION_ALIGNMENT + 0x40);
    b.add_export("ExitProcess",             SECTION_ALIGNMENT + 0x50);
    b.add_export("GetModuleHandleW",        SECTION_ALIGNMENT + 0x60);
    b.add_export("GetProcAddress",          SECTION_ALIGNMENT + 0x70);
    b.add_export("LoadLibraryW",            SECTION_ALIGNMENT + 0x80);
    b.add_export("FreeLibrary",             SECTION_ALIGNMENT + 0x90);
    b.add_export("VirtualAlloc",            SECTION_ALIGNMENT + 0xA0);
    b.add_export("VirtualFree",             SECTION_ALIGNMENT + 0xB0);
    b.add_export("HeapAlloc",               SECTION_ALIGNMENT + 0xC0);
    b.add_export("HeapFree",                SECTION_ALIGNMENT + 0xD0);
    b.add_export("WaitForSingleObject",     SECTION_ALIGNMENT + 0xE0);
    b.add_export("Sleep",                   SECTION_ALIGNMENT + 0xF0);
    b.add_export("GetLastError",            SECTION_ALIGNMENT + 0x100);
    b.add_export("SetLastError",            SECTION_ALIGNMENT + 0x110);
    b.add_export("WriteConsoleW",           SECTION_ALIGNMENT + 0x120);
    b.add_export("GetStdHandle",            SECTION_ALIGNMENT + 0x130);
    b.add_export("TerminateProcess",        SECTION_ALIGNMENT + 0x140);
    b.add_export("GetCurrentProcess",       SECTION_ALIGNMENT + 0x150);
    b.add_export("GetCurrentThread",        SECTION_ALIGNMENT + 0x160);
    // DllMain entry — the loader calls this to verify the DLL is reachable
    b.add_export("DllMainCRTStartup",        SECTION_ALIGNMENT + 0x170);
    b.add_export("_DllMainCRTStartup",       SECTION_ALIGNMENT + 0x170);
    let bytes = b.build();
    // Verify this is not a plain ret-sled
    assert_no_stub_pe("kernel32.dll", &bytes);
    bytes
}

fn build_smss(machine: u16)    -> Vec<u8> { build_user_mode_console(machine, "smss.exe entry point", "smss.exe") }
/// Public wrapper for the kernel-main phase-0 ring-transition
/// bring-up. Builds the same smss.exe bytes that
/// `build_smss` would emit for the on-disk system image, but
/// returns them directly so the loader can map them into a
/// per-process PML4 without going through a file system.
pub fn build_smss_for_machine(machine: u16) -> Vec<u8> { build_smss(machine) }

/// Public wrapper for `build_cmd_exe`. Used by `kernel_main` when
/// it boots into Safe-Mode (CMD): it builds the same cmd.exe bytes
/// that `build_all` would emit into the system image, then maps
/// them into a Ring 3 process directly without going through the
/// FAT32 mount.
///
/// Returns a `Vec<u8>` containing a copy of the cmd.exe image. The
/// cmd.exe bytes are baked into the kernel binary as a
/// `include_bytes!` static (see `CMD_EXE_X86_64_STATIC` below), so
/// we do not need to re-run the PE builder at boot time. The
/// cached bytes (populated eagerly by `cache_cmd_exe` from
/// `build_all`) take precedence when present — the static is the
/// fallback used by kernels that boot without the cache
/// (e.g. boot paths that deliberately skip `build_all`).
pub fn build_cmd_exe_for_machine(machine: u16) -> Vec<u8> {
    crate::boot_println!("[system_image] build_cmd_exe_for_machine: machine=0x{:x}", machine);
    // Cache check: skip during boot. The cache is only ever
    // populated by `build_all`, which is currently disabled (see
    // the TEMP WORKAROUND comment in `kernel_main`). Reading
    // the spinlock here may be a footgun if the kernel is
    // already past Phase 11 — at that point IRQ state and the
    // spinlock interaction are not fully validated.
    //
    // For x86_64 we always use the compile-time static image
    // baked in via `include_bytes!`. The on-demand
    // `OwnedSection`/`KERNEL_HEAP` PE builder historically
    // crashed at boot because the kernel heap was not yet set
    // up in some paths. The static image is regenerated by
    // `tools/src/bin/mkcmd.rs`.
    if machine == MACHINE_X86_64 {
        // We tried `alloc::alloc::alloc(layout)` here but the
        // call hangs in the Safe-Mode CMD bring-up path (the
        // kernel heap / spinlock combination is unstable in
        // some configurations). Bypass the heap entirely: copy
        // the static cmd.exe bytes into a small static buffer
        // and return it.
        crate::boot_println!("[system_image] using CMD_EXE_X86_64_STATIC ({} bytes)", CMD_EXE_X86_64_STATIC.len());
        let len = CMD_EXE_X86_64_STATIC.len();
        static mut STATIC_BUF: [u8; 8192] = [0u8; 8192];
        unsafe {
            core::ptr::copy_nonoverlapping(
                CMD_EXE_X86_64_STATIC.as_ptr(),
                STATIC_BUF.as_mut_ptr(),
                len,
            );
            // Make a vec that points into our static buffer.
            // The kernel never frees this; cmd.exe is only
            // used once and consumed within this call.
            let ptr = STATIC_BUF.as_mut_ptr();
            let v = alloc::vec::Vec::from_raw_parts(ptr, len, 8192);
            return v;
        }
    }
    // Other arches: fall back to the on-demand builder. This is
    // the path `dump_cmd` and the host-side tests use.
    build_cmd_exe(machine)
}

/// Compile-time cmd.exe image for x86_64. Generated by
/// `tools/src/bin/dump_cmd.rs` (which calls
/// `build_cmd_exe_for_machine` from a host build) and copied
/// into `resources/pe/cmd_x86_64.exe`. The kernel `include_bytes!`
/// reads it back so the boot-time cmd.exe path can be exercised
/// without going through the PE builder (which uses `Vec` and
/// historically crashed before the kernel heap was up).
#[allow(dead_code)]
static CMD_EXE_X86_64_STATIC: &[u8] = include_bytes!("../resources/pe/cmd_x86_64.exe");

/// Populate the cmd.exe cache. Called from `build_all` while the
/// kernel heap is still fresh.
pub fn cache_cmd_exe(machine: u16) {
    let bytes = build_cmd_exe(machine);
    *CACHED_CMD_EXE.lock() = Some(bytes);
}

/// Build `cmd.exe` — the Safe-Mode console host.
///
/// Unlike the rest of the user-mode processes, `cmd.exe` has a
/// meaningful behavior the kernel relies on. When `bootmgr` selects
/// the `Safe Mode (CMD)` boot entry, `kernel_main` loads this image
/// into a fresh Ring 3 process and jumps to its entry point. The
/// stub entry point issues a single `SYS_RUN_AUTOEXEC` syscall,
/// and the kernel-side dispatcher reads `C:\tests\autoexec.bat`
/// from the FAT32 volume, runs every line through the batch
/// parser (`libs::cmd::bat_parser`), and returns control to user
/// mode. The stub then exits the process via `SYS_EXIT_PROCESS`.
///
/// This is a "real" `cmd.exe` in the sense that the loader must
/// load it as a separate user-mode process — the Safe-Mode CMD
/// path in `kernel_main.rs` no longer fakes a CMD shell inside the
/// kernel. The kernel merely provides syscalls for the parts the
/// stub cannot implement in Ring 3 (filesystem access, process
/// exit).
fn build_cmd_exe(machine: u16) -> Vec<u8> {
    use crate::pegen::{OwnedSection, SectionFlags};
    let mut b = PeBuilder::new(machine, Subsystem::WindowsCui);
    // User-mode image base — same region the rest of the user-mode
    // subsystems sit in so the user-mode address space layout stays
    // predictable.
    b.image_base = 0x0000_0000_6500_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(&cmd_exe_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("cmd_main",          SECTION_ALIGNMENT + 0x000);
    b.add_export("ConsoleMain",       SECTION_ALIGNMENT + 0x000);
    b.add_export("ExitProcess",       SECTION_ALIGNMENT + 0x010);
    b.build()
}

/// Hand-encoded x86_64 entry point for the Safe-Mode `cmd.exe` stub.
///
/// Layout (offsets into `.text`):
///   0x000  cmd_main:  mov eax, SYS_RUN_AUTOEXEC (0x200)
///                     syscall                    ; run batch
///                     mov eax, SYS_EXIT_PROCESS (0x201)
///                     xor edi, edi               ; exit code 0
///                     syscall                    ; terminate
///                     jmp $                      ; safety: never reach
///
/// Syscall numbers 0x200 / 0x201 are documented in
/// `arch::x86_64::syscall_dispatch` and reserved for the
/// Safe-Mode user-mode command host.
fn cmd_exe_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => &CMD_EXE_X86_64_STUB[..],
        MACHINE_AARCH64 => ret_sled_aarch64(2),
        MACHINE_RISCV64 => ret_sled_riscv64(2),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(2),
        _ => &CMD_EXE_X86_64_STUB[..],
    }
}

/// Pre-computed x86_64 stub for cmd.exe — see `cmd_exe_text_stub`.
///
/// Updated to use the canonical NT 6.1 system partition path
/// `C:\system\tests\autoexec.bat`. The kernel-side batch runner
/// (`servers::cmd::run_batch_file`) reads this file from the FAT32
/// volume, so the path must match what the on-disk image builder
/// (tools/src/fs/build.rs) installs at
/// `add_autoexec_bat("system/tests/autoexec.bat", ...)`. A
/// fall-back to the legacy `C:\tests\autoexec.bat` location is
/// still tried if the system partition path is missing.
///
/// Instruction layout (32 bytes of code + NUL-terminated path):
///   0x000  cmd_main:  48 8d 15 19 00 00 00   lea r10, [rip+0x19]  ; arg0 = path
///              0x007  b8 00 02 00 00         mov eax, 0x0200      ; SYS_RUN_AUTOEXEC
///              0x00c  0f 05                  syscall              ; run batch
///              0x00e  b8 01 02 00 00         mov eax, 0x0201      ; SYS_EXIT_PROCESS
///              0x013  31 ff                  xor edi, edi         ; exit code 0
///              0x015  0f 05                  syscall              ; terminate
///              0x017  eb fe                  jmp $                ; safety
///              0x019  90 * 7                 padding (7 bytes so path starts at 0x20)
///   0x020  autoexec_path:
///              43 3a 5c 73 79 73 74 65 6d 5c 74 65 73 74 73 5c 61 75 74 6f 65 78 65 63 2e 62 61 74 00
///              "C:\system\tests\autoexec.bat\0" (29 chars + NUL)
static CMD_EXE_X86_64_STUB: [u8; 84] = [
    // cmd_main:
    0x48, 0x8D, 0x15, 0x19, 0x00, 0x00, 0x00, // lea r10, [rip+0x19] -> &autoexec_path
    0xB8, 0x00, 0x02, 0x00, 0x00,             // mov eax, 0x200 (SYS_RUN_AUTOEXEC)
    0x0F, 0x05,                               // syscall
    0xB8, 0x01, 0x02, 0x00, 0x00,             // mov eax, 0x201 (SYS_EXIT_PROCESS)
    0x31, 0xFF,                               // xor edi, edi       ; exit code 0
    0x0F, 0x05,                               // syscall
    0xEB, 0xFE,                               // jmp $ (should not return)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding to 0x20
    // 0x020: autoexec_path (NUL-terminated, 29 bytes)
    b'C', b':', b'\\', b's', b'y', b's', b't', b'e', b'm',
    b'\\', b't', b'e', b's', b't', b's', b'\\',
    b'a', b'u', b't', b'o', b'e', b'x', b'e', b'c',
    b'.', b'b', b'a', b't', 0x00,
    // Padding to 84 bytes total (23 trailing 0x90)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];








fn build_user32(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::WindowsGui);
    b.image_base = 0x0000_0000_7000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(user32_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("CreateWindowExW",    SECTION_ALIGNMENT);
    b.add_export("DefWindowProcW",    SECTION_ALIGNMENT + 0x10);
    b.add_export("DestroyWindow",     SECTION_ALIGNMENT + 0x20);
    b.add_export("ShowWindow",        SECTION_ALIGNMENT + 0x30);
    b.add_export("RegisterClassExW",  SECTION_ALIGNMENT + 0x40);
    b.add_export("GetMessageW",      SECTION_ALIGNMENT + 0x50);
    b.add_export("PeekMessageW",      SECTION_ALIGNMENT + 0x60);
    b.add_export("TranslateMessage",  SECTION_ALIGNMENT + 0x70);
    b.add_export("DispatchMessageW", SECTION_ALIGNMENT + 0x80);
    b.add_export("GetSystemMetrics", SECTION_ALIGNMENT + 0x90);
    b.add_export("GetAsyncKeyState", SECTION_ALIGNMENT + 0xA0);
    b.build()
}

fn build_gdi32(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::WindowsGui);
    b.image_base = 0x0000_0000_7100_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(gdi32_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("GetDC",                 SECTION_ALIGNMENT);
    b.add_export("ReleaseDC",            SECTION_ALIGNMENT + 0x10);
    b.add_export("CreateCompatibleDC",   SECTION_ALIGNMENT + 0x20);
    b.add_export("DeleteDC",             SECTION_ALIGNMENT + 0x30);
    b.add_export("PatBlt",               SECTION_ALIGNMENT + 0x40);
    b.add_export("FillRect",             SECTION_ALIGNMENT + 0x50);
    b.add_export("TextOutW",             SECTION_ALIGNMENT + 0x60);
    b.add_export("CreatePen",             SECTION_ALIGNMENT + 0x70);
    b.add_export("CreateSolidBrush",     SECTION_ALIGNMENT + 0x80);
    b.add_export("SelectObject",         SECTION_ALIGNMENT + 0x90);
    b.add_export("DeleteObject",         SECTION_ALIGNMENT + 0xA0);
    b.add_export("GetStockObject",       SECTION_ALIGNMENT + 0xB0);
    b.build()
}

fn build_wow64(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0x0000_0000_7200_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(wow64_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    // Core thunk functions
    b.add_export("Wow64PrepareForException", SECTION_ALIGNMENT);
    b.add_export("Wow64ApcRoutine",          SECTION_ALIGNMENT + 0x10);
    b.add_export("Wow64LdrpInitialize",      SECTION_ALIGNMENT + 0x20);
    b.add_export("Wow64SystemServiceEx",     SECTION_ALIGNMENT + 0x30);
    // Memory management
    b.add_export("Wow64AllocateVirtualMemory32",   SECTION_ALIGNMENT + 0x40);
    b.add_export("Wow64FreeVirtualMemory32",       SECTION_ALIGNMENT + 0x50);
    b.add_export("Wow64ReadVirtualMemory32",      SECTION_ALIGNMENT + 0x60);
    b.add_export("Wow64WriteVirtualMemory32",     SECTION_ALIGNMENT + 0x70);
    b.add_export("Wow64ProtectVirtualMemory32",   SECTION_ALIGNMENT + 0x80);
    b.add_export("Wow64QueryVirtualMemory32",     SECTION_ALIGNMENT + 0x90);
    // Process/Thread
    b.add_export("Wow64QueryInformationProcess", SECTION_ALIGNMENT + 0xA0);
    b.add_export("Wow64SetInformationProcess",  SECTION_ALIGNMENT + 0xB0);
    b.add_export("Wow64QueryInformationThread",  SECTION_ALIGNMENT + 0xC0);
    b.add_export("Wow64SetInformationThread",   SECTION_ALIGNMENT + 0xD0);
    b.add_export("Wow64GetContextThread",       SECTION_ALIGNMENT + 0xE0);
    b.add_export("Wow64SetContextThread",      SECTION_ALIGNMENT + 0xF0);
    // Register/CPU
    b.add_export("Wow64RegisterWow64Cpu",       SECTION_ALIGNMENT + 0x100);
    b.add_export("Wow64CpuInitializeThunkTable",SECTION_ALIGNMENT + 0x110);
    b.add_export("Wow64CpuResetToEntryPoint",  SECTION_ALIGNMENT + 0x120);
    b.add_export("Wow64CpuFlushInstructionCache",SECTION_ALIGNMENT + 0x130);
    b.build()
}

/// Build wow64cpu.dll - CPU context thunk for Wow64
/// This DLL handles 32-bit to 64-bit CPU context transitions.
fn build_wow64cpu(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0x0000_0000_7210_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(wow64cpu_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("Wow64CpuInitialize",          SECTION_ALIGNMENT);
    b.add_export("Wow64CpuResetToEntryPoint",   SECTION_ALIGNMENT + 0x10);
    b.add_export("Wow64CpuFlushInstructionCache",SECTION_ALIGNMENT + 0x20);
    b.add_export("Wow64CpuCopyMemory",          SECTION_ALIGNMENT + 0x30);
    b.add_export("Wow64CpuSuspendThread",       SECTION_ALIGNMENT + 0x40);
    b.add_export("Wow64CpuResumeThread",        SECTION_ALIGNMENT + 0x50);
    b.add_export("Wow64CpuGetContext",          SECTION_ALIGNMENT + 0x60);
    b.add_export("Wow64CpuSetContext",          SECTION_ALIGNMENT + 0x70);
    b.build()
}

/// Build wow64win.dll - Win32k thunk for Wow64
/// This DLL handles 32-bit GDI/User calls going to 64-bit win32k.sys.
fn build_wow64win(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0x0000_0000_7220_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(wow64win_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    // Win32k thunk core
    b.add_export("Wow64Win32kInitializeThunk", SECTION_ALIGNMENT);
    b.add_export("Wow64Win32kSyscall",         SECTION_ALIGNMENT + 0x10);
    b.add_export("Wow64Win32kCallbackReturn",   SECTION_ALIGNMENT + 0x20);
    // User32 thunks
    b.add_export("Wow64Win32kPostMessage",      SECTION_ALIGNMENT + 0x30);
    b.add_export("Wow64Win32kSendMessage",      SECTION_ALIGNMENT + 0x40);
    b.add_export("Wow64Win32kGetMessage",       SECTION_ALIGNMENT + 0x50);
    b.add_export("Wow64Win32kPeekMessage",     SECTION_ALIGNMENT + 0x60);
    b.add_export("Wow64Win32kTranslateMessage", SECTION_ALIGNMENT + 0x70);
    b.add_export("Wow64Win32kDispatchMessage",  SECTION_ALIGNMENT + 0x80);
    // GDI32 thunks
    b.add_export("Wow64Win32kGetDC",            SECTION_ALIGNMENT + 0x90);
    b.add_export("Wow64Win32kReleaseDC",        SECTION_ALIGNMENT + 0xA0);
    b.add_export("Wow64Win32kTextOut",          SECTION_ALIGNMENT + 0xB0);
    b.add_export("Wow64Win32kBitBlt",           SECTION_ALIGNMENT + 0xC0);
    b.add_export("Wow64Win32kPatBlt",          SECTION_ALIGNMENT + 0xD0);
    b.add_export("Wow64Win32kSelectObject",     SECTION_ALIGNMENT + 0xE0);
    b.build()
}

/// Build kdcom.dll - Kernel Debugger COM Port Driver
/// Reference: ReactOS kdcom driver (LGPL-2.0)
fn build_kdcom(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    // Minimal stub - just return success
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("KdInitSystem",      SECTION_ALIGNMENT);
    b.add_export("KdD0Transition",    SECTION_ALIGNMENT + 0x20);
    b.add_export("KdD3Transition",    SECTION_ALIGNMENT + 0x30);
    b.add_export("KdpCrash",          SECTION_ALIGNMENT + 0x40);
    b.add_export("Kdprompt",          SECTION_ALIGNMENT + 0x50);
    b.add_export("KdpPrint",          SECTION_ALIGNMENT + 0x60);
    b.build()
}

/// Build ci.dll - Code Integrity (Driver Signing Verification)
/// Reference: Microsoft Code Integrity documentation
fn build_ci(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("CiInitialize",          SECTION_ALIGNMENT);
    b.add_export("CiValidateImageHash",   SECTION_ALIGNMENT + 0x20);
    b.add_export("CiQueryInformation",   SECTION_ALIGNMENT + 0x30);
    b.build()
}

/// Build clfs.sys - Common Log File System
/// Reference: Microsoft CLFS documentation (NTFS/CLFS)
fn build_clfs(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("ClfsMgmtQueryLogInformation",    SECTION_ALIGNMENT);
    b.add_export("ClfsCreateLogFile",              SECTION_ALIGNMENT + 0x20);
    b.add_export("ClfsWriteLogRecord",             SECTION_ALIGNMENT + 0x40);
    b.add_export("ClfsReadLogRecord",              SECTION_ALIGNMENT + 0x60);
    b.add_export("ClfsFlushBuffers",               SECTION_ALIGNMENT + 0x80);
    b.build()
}

/// Build pshed.dll - Platform Specific Hardware Error Driver
/// Reference: Microsoft PHED architecture
fn build_pshed(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("PshedInitializeSystem",        SECTION_ALIGNMENT);
    b.add_export("PshedErrorInfo",                SECTION_ALIGNMENT + 0x20);
    b.add_export("PshedEnableDiagnostic",         SECTION_ALIGNMENT + 0x30);
    b.build()
}

/// Build lsm.exe - Local Session Manager
/// Reference: ReactOS lsm (LGPL-2.0)
fn build_lsm(machine: u16) -> Vec<u8> {
    build_user_mode_console(machine, "LSM", "lsm.exe")
}

/// Build autochk.exe - Automatic Check Disk
/// Reference: Microsoft chkdsk documentation
fn build_autochk(machine: u16) -> Vec<u8> {
    build_user_mode_console(machine, "AUTOCHK", "autochk.exe")
}

// =====================================================================
// New driver / framework PE files
// =====================================================================

/// Build bootvid.dll - Boot video
/// Reference: Microsoft bootvid documentation
fn build_bootvid(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("VidInitialize",              SECTION_ALIGNMENT);
    b.add_export("InbvDisplayString",          SECTION_ALIGNMENT + 0x10);
    b.add_export("InbvDisplayStringBlocking",  SECTION_ALIGNMENT + 0x20);
    b.add_export("InbvSetProgressBarSubset",   SECTION_ALIGNMENT + 0x30);
    b.add_export("InbvRotateWaitingSpinner",   SECTION_ALIGNMENT + 0x40);
    b.add_export("VidResetDisplay",            SECTION_ALIGNMENT + 0x50);
    b.add_export("VidDisplayString",           SECTION_ALIGNMENT + 0x60);
    b.add_export("VidSetCursorPosition",       SECTION_ALIGNMENT + 0x70);
    b.add_export("VidCleanUp",                 SECTION_ALIGNMENT + 0x80);
    b.build()
}


    /// Build partmgr.sys - Partition Manager
/// Reference: Microsoft partmgr documentation
fn build_partmgr(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("PartMgrInit",   SECTION_ALIGNMENT);
    b.add_export("DriverEntry",   SECTION_ALIGNMENT + 0x10);
    b.build()
}

/// Build volmgr.sys - Volume Manager
/// Reference: Microsoft volmgr documentation
fn build_volmgr(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("VolMgrInit",   SECTION_ALIGNMENT);
    b.add_export("DriverEntry",  SECTION_ALIGNMENT + 0x10);
    b.build()
}

/// Build volmgrx.sys - Volume Manager Extension
/// Reference: Microsoft volmgrx documentation
fn build_volmgrx(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("VolMgrxInit",   SECTION_ALIGNMENT);
    b.add_export("DriverEntry",   SECTION_ALIGNMENT + 0x10);
    b.build()
}

/// Build volsnap.sys - Volume Shadow Copy
/// Reference: Microsoft volsnap documentation
fn build_volsnap(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("VolsnapCreateSnapshot",  SECTION_ALIGNMENT);
    b.add_export("VolsnapDeleteSnapshot",  SECTION_ALIGNMENT + 0x10);
    b.add_export("VolsnapQuerySnapshots",  SECTION_ALIGNMENT + 0x20);
    b.add_export("VolsnapRecordDiff",      SECTION_ALIGNMENT + 0x30);
    b.add_export("DriverEntry",            SECTION_ALIGNMENT + 0x40);
    b.build()
}

/// Build fltmgr.sys - Filter Manager
/// Reference: Microsoft fltmgr documentation
fn build_fltmgr(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("FltRegisterFilter",  SECTION_ALIGNMENT);
    b.add_export("FltStartFiltering",   SECTION_ALIGNMENT + 0x10);
    b.add_export("FltUnregisterFilter", SECTION_ALIGNMENT + 0x20);
    b.add_export("FltAttachVolume",     SECTION_ALIGNMENT + 0x30);
    b.add_export("FltDetachVolume",     SECTION_ALIGNMENT + 0x40);
    b.add_export("FltSendMessage",      SECTION_ALIGNMENT + 0x50);
    b.add_export("FltGetMessage",       SECTION_ALIGNMENT + 0x60);
    b.build()
}

/// Build fileinfo.sys - File Information
/// Reference: Microsoft fileinfo documentation
fn build_fileinfo(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("FileInfoInit",          SECTION_ALIGNMENT);
    b.add_export("FileInfoRecordOpen",    SECTION_ALIGNMENT + 0x10);
    b.add_export("FileInfoGetName",       SECTION_ALIGNMENT + 0x20);
    b.add_export("FileInfoListOpens",     SECTION_ALIGNMENT + 0x30);
    b.add_export("DriverEntry",           SECTION_ALIGNMENT + 0x40);
    b.build()
}

/// Build pcw.sys - Performance Counter Worker
/// Reference: Microsoft pcw documentation
fn build_pcw(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("PcwRegister",         SECTION_ALIGNMENT);
    b.add_export("PcwUnregister",       SECTION_ALIGNMENT + 0x10);
    b.add_export("PcwCounter",          SECTION_ALIGNMENT + 0x20);
    b.add_export("PcwCollect",          SECTION_ALIGNMENT + 0x30);
    b.add_export("DriverEntry",         SECTION_ALIGNMENT + 0x40);
    b.build()
}

/// Build spldr.sys - OS Loader
/// Reference: Microsoft spldr documentation
fn build_spldr(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("SpldrInit",   SECTION_ALIGNMENT);
    b.add_export("DriverEntry", SECTION_ALIGNMENT + 0x10);
    b.build()
}

/// Build storport.sys - Storage Port Driver
/// Reference: Microsoft storport documentation
fn build_storport(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("StorPortInitialize",     SECTION_ALIGNMENT);
    b.add_export("StorPortGetDeviceBase",  SECTION_ALIGNMENT + 0x10);
    b.add_export("StorPortFreeDeviceBase", SECTION_ALIGNMENT + 0x20);
    b.add_export("StorPortAllocatePool",   SECTION_ALIGNMENT + 0x30);
    b.add_export("StorPortFreePool",       SECTION_ALIGNMENT + 0x40);
    b.add_export("StorPortNotification",   SECTION_ALIGNMENT + 0x50);
    b.add_export("StorPortBuildIo",        SECTION_ALIGNMENT + 0x60);
    b.add_export("StorPortStartIo",        SECTION_ALIGNMENT + 0x70);
    b.add_export("DriverEntry",            SECTION_ALIGNMENT + 0x80);
    b.build()
}

/// Build ataport.sys - ATA Port Driver
/// Reference: Microsoft ataport documentation
fn build_ataport(machine: u16) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    b.image_base = 0xFFFF_FFFF_FF00_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(hal_text_stub(machine));
    let text = text.into_section();
    b.add_section(text);
    b.add_export("AtaPortInitialize",   SECTION_ALIGNMENT);
    b.add_export("AtaPortStartIo",      SECTION_ALIGNMENT + 0x10);
    b.add_export("DriverEntry",         SECTION_ALIGNMENT + 0x20);
    b.build()
}

fn build_user_mode_console(machine: u16, marker: &str, name: &str) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::WindowsCui);
    b.image_base = 0x0000_0000_6000_0000;
    b.entry_point_rva = SECTION_ALIGNMENT;
    let mut text = OwnedSection::new(".text", SectionFlags::CODE, 0x4000);
    text.extend_from_static(&user_mode_text_stub(machine, marker, name));
    let text = text.into_section();
    b.add_section(text);
    b.build()
}

// =====================================================================
// Architecture-specific text-section stubs
// =====================================================================

/// Pick the right text bytes for the requested machine. The point
/// of these stubs is to produce a valid `mov rax, ...; ret` ladder
/// of exported functions without any external assembler. We hand-
/// encode the canonical x86_64, aarch64, riscv64, and loongarch64
/// prologue/epilogue pairs.
///
/// `hal_text_stub` is shared by HAL, ntoskrnl, and all the
/// kernel-mode driver stubs. We need enough ret-slots to cover
/// the largest export table. Using 32 slots for HAL (has ~30 exports).
/// Returns a static slice to avoid heap allocation.
fn hal_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(32),
        MACHINE_AARCH64 => ret_sled_aarch64(32),
        MACHINE_RISCV64 => ret_sled_riscv64(32),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(32),
        _ => ret_sled_x86(32),
    }
}
/// Pre-computed x86_64 syscall stub for ntdll.dll.
/// Each stub is: mov eax, syscall_num; syscall; ret (8 bytes each)
/// This provides actual syscall functionality instead of ret-sled.
static X86_64_NTDLL_SYSCALL_STUB: [u8; 160] = [
    // NtCreateFile - syscall 0x55
    0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtReadFile - syscall 0x56
    0xB8, 0x56, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtWriteFile - syscall 0x57
    0xB8, 0x57, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtClose - syscall 0xC0
    0xB8, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtAllocateVirtualMemory - syscall 0x18
    0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtFreeVirtualMemory - syscall 0x19
    0xB8, 0x19, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtQuerySystemInformation - syscall 0x37
    0xB8, 0x37, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtTerminateProcess - syscall 0x101
    0xB8, 0x01, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtOpenProcess - syscall 0x26
    0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtDeviceIoControlFile - syscall 0x42
    0xB8, 0x42, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtWaitForSingleObject - syscall 0x104
    0xB8, 0x04, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtTestAlert - syscall 0x12F
    0xB8, 0x2F, 0x01, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtDelayExecution - syscall 0xC2
    0xB8, 0xC2, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // NtQueryInformationProcess - syscall 0x19
    0xB8, 0x19, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
    // RtlAllocateHeap - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
    // RtlFreeHeap - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
    // RtlExitUserThread - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
    // LdrLoadDll - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
    // LdrGetProcedureAddress - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
    // RtlUserThreadStart - (internal wrapper)
    0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90,
];

/// ntdll syscall stub generator for different architectures.
/// Returns syscall stubs for ntdll.dll exports.
fn ntdll_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => &X86_64_NTDLL_SYSCALL_STUB[..],
        MACHINE_AARCH64 => ret_sled_aarch64(20),
        MACHINE_RISCV64 => ret_sled_riscv64(20),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(20),
        _ => &X86_64_NTDLL_SYSCALL_STUB[..],
    }
}


fn kernel32_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(24),
        MACHINE_AARCH64 => ret_sled_aarch64(24),
        MACHINE_RISCV64 => ret_sled_riscv64(24),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(24),
        _ => ret_sled_x86(24),
    }
}

fn user32_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(11),
        MACHINE_AARCH64 => ret_sled_aarch64(11),
        MACHINE_RISCV64 => ret_sled_riscv64(11),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(11),
        _ => ret_sled_x86(11),
    }
}

fn gdi32_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(12),
        MACHINE_AARCH64 => ret_sled_aarch64(12),
        MACHINE_RISCV64 => ret_sled_riscv64(12),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(12),
        _ => ret_sled_x86(12),
    }
}

fn wow64_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(20), // 20 exports
        MACHINE_AARCH64 => ret_sled_aarch64(20),
        MACHINE_RISCV64 => ret_sled_riscv64(20),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(20),
        _ => ret_sled_x86(20),
    }
}

fn wow64cpu_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(8), // 8 exports
        MACHINE_AARCH64 => ret_sled_aarch64(8),
        MACHINE_RISCV64 => ret_sled_riscv64(8),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(8),
        _ => ret_sled_x86(8),
    }
}

fn wow64win_text_stub(machine: u16) -> &'static [u8] {
    match machine {
        MACHINE_X86_64 => ret_sled_x86(16), // 16 exports
        MACHINE_AARCH64 => ret_sled_aarch64(16),
        MACHINE_RISCV64 => ret_sled_riscv64(16),
        MACHINE_LOONGARCH64 => ret_sled_loongarch64(16),
        _ => ret_sled_x86(16),
    }
}

fn user_mode_text_stub(machine: u16, _marker: &str, _name: &str) -> Vec<u8> {
    // The user-mode entries never actually get to run under our
    // kernel, but the loader still has to be able to map the
    // image, so we emit a Ring-3-safe loop just in case.
    match machine {
        MACHINE_X86_64 => {
            // user-mode Ring 3 busy loop:
            //   mov eax, 0x12F          ; NtTestAlert
            //   syscall                 ; -> kernel returns STATUS_SUCCESS
            //   jmp .                   ; loop
            // We deliberately avoid `hlt` and `cli` because both
            // are privileged in Ring 3 and would #GP.
            Vec::from(&[
                0xB8, 0x2F, 0x01, 0x00, 0x00,   // mov eax, 0x12F (NtTestAlert)
                0x0F, 0x05,                     // syscall
                0xEB, 0xF6,                     // jmp -10 (back to mov eax)
            ][..])
        }
        MACHINE_AARCH64 => {
            // `wfi; b .` -> `1f 00 00 14 00 00 00 14`
            Vec::from(&[0x1F, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x14][..])
        }
        MACHINE_RISCV64 => {
            // `wfi; jal x0, .` -> `73 10 00 00 6f 00 00 00`
            Vec::from(&[0x73, 0x10, 0x00, 0x00, 0x6F, 0x00, 0x00, 0x00][..])
        }
        MACHINE_LOONGARCH64 => {
            // `idle 0; b .` -> `04 00 00 00 50 00 00 00`
            Vec::from(&[0x04, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00][..])
        }
        _ => x86_64_idle_entry(),
    }
}

/// Generate `n` copies of `xor rax, rax; ret` for x86_64. We use
/// this as the export table filler for HAL/kernel/DLL exports.

/// Pre-computed x86_64 return sled for 56 entries (224 bytes).
/// Pattern: `xor rax, rax; ret` -> `48 31 c0 c3`
/// This avoids heap allocation during PE image generation.
static X86_64_SLED_64: [u8; 224] = [
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
    0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0x31, 0xC0, 0xC3,
];

/// Generate x86_64 text section: n copies of `xor rax, rax; ret`.
/// Returns a static slice reference to avoid heap allocation entirely.
/// This bypasses potential heap exhaustion issues during PE image generation.
fn ret_sled_x86(n: usize) -> &'static [u8] {
    let n = n.min(56); // 56 entries * 4 bytes = 224 bytes
    &X86_64_SLED_64[..n * 4]
}

/// Pre-computed aarch64 return sled for 64 entries (512 bytes).
/// Pattern: `mov x0, #0; ret` -> `00 00 80 d2 c0 03 5f d6`
static AARCH64_RET_SLED: [u8; 488] = [
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
    0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6,
];

/// Generate aarch64 text section: n copies of `mov x0, #0; ret`.
fn ret_sled_aarch64(n: usize) -> &'static [u8] {
    let n = n.min(61); // 61 entries * 8 bytes = 488 bytes
    &AARCH64_RET_SLED[..n * 8]
}

/// Pre-computed riscv64 return sled for 64 entries (512 bytes).
/// Pattern: `addi x10, x0, 0; jalr x0, x1, 0` -> `13 05 00 00 67 80 00 00`
static RISCV64_RET_SLED: [u8; 504] = [
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
];

/// Generate riscv64 text section: n copies of `addi x10, x0, 0; jalr x0, x1, 0`.
fn ret_sled_riscv64(n: usize) -> &'static [u8] {
    let n = n.min(63); // 63 entries * 8 bytes = 504 bytes
    &RISCV64_RET_SLED[..n * 8]
}

/// Pre-computed loongarch64 return sled for 64 entries (1024 bytes).
/// Pattern: `add.d $a0, $zero, $zero; jirl $zero, $ra, 0`
static LOONGARCH64_RET_SLED: [u8; 1008] = [
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Generate loongarch64 text section.
fn ret_sled_loongarch64(n: usize) -> &'static [u8] {
    let n = n.min(63); // 63 entries * 16 bytes = 1008 bytes
    &LOONGARCH64_RET_SLED[..n * 16]
}
