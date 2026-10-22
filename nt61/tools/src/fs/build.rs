//! Build Pipeline Module
//!
//! This module handles the complete build pipeline:
//! 1. Build kernel
//! 2. Build boot manager
//! 3. Build winload
//! 4. Build ESP
//! 5. Create disk image
//!
//! All operations use pure Rust - no shell commands required.

use crate::error::{BuildError, Result};
use crate::fs::stubs::{LSM_EXE_TEXT_STUB, USERINIT_EXE_TEXT_STUB, WINLOGON_EXE_TEXT_STUB};
use crate::logger as log;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

// =====================================================================
// Build Paths
// =====================================================================

/// Get the kernel target triple
pub fn get_kernel_target() -> &'static str {
    "x86_64-unknown-none"
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetArch {
    X86_64,
    AArch64,
    RiscV64,
    LoongArch64,
}

impl TargetArch {
    fn from_name(name: &str) -> Self {
        match name {
            "aarch64" | "arm64" => Self::AArch64,
            "riscv64" => Self::RiscV64,
            "loongarch64" => Self::LoongArch64,
            _ => Self::X86_64,
        }
    }

    fn machine(&self) -> u16 {
        match self {
            Self::X86_64 => 0x8664,
            Self::AArch64 => 0xAA64,
            Self::RiscV64 => 0x5064,
            Self::LoongArch64 => 0x6264,
        }
    }
}

static PE_ARCH: OnceLock<TargetArch> = OnceLock::new();

fn set_pe_arch(arch: &str) {
    let target = TargetArch::from_name(arch);
    let _ = PE_ARCH.set(target);
}

fn current_pe_arch() -> TargetArch {
    PE_ARCH.get().copied().unwrap_or(TargetArch::X86_64)
}

/// Get the UEFI target triple
pub fn get_uefi_target() -> &'static str {
    "x86_64-unknown-uefi"
}

/// Resolve the kernel target triple for the build's architecture.
///
/// On architectures whose standard UEFI target isn't supported by the
/// Rust `uefi` crate (riscv64, loongarch64), the kernel still
/// needs a `*-unknown-none-*` triple so it can run via a
/// firmware-specific loader that hands control through the kernel's
/// `kernel_main` symbol directly, rather than via UEFI's standard
/// `LoadImage` / `StartImage` calls. The mapping below keeps the
/// kernel build self-consistent regardless of which UEFI PE flavour
/// the boot manager eventually emits.
pub fn kernel_target_for(arch: &str) -> &'static str {
    match arch {
        "x86_64" | "x64" => "x86_64-unknown-none",
        "aarch64" | "arm64" => "aarch64-unknown-none",
        "riscv64" => "riscv64gc-unknown-none-elf",
        "loongarch64" => "loongarch64-unknown-none",
        _ => "x86_64-unknown-none",
    }
}

/// Resolve the UEFI target triple for the build's architecture.
pub fn uefi_target_for(arch: &str) -> &'static str {
    match arch {
        "x86_64" | "x64" => "x86_64-unknown-uefi",
        "aarch64" | "arm64" => "aarch64-unknown-uefi",
        // The Rust `uefi` crate does not (yet) provide pre-built
        // targets for RISC-V or LoongArch. Boot managers on those
        // architectures are loaded as RISC-V/LoongArch ELF
        // executables by the firmware and re-export an
        // EFI-protocol-compatible entry; for the build_tool's
        // purposes we just fall back to the freestanding triple so
        // the cargo invocation is still well-formed.
        "riscv64" => "riscv64gc-unknown-none-elf",
        "loongarch64" => "loongarch64-unknown-none",
        _ => "x86_64-unknown-uefi",
    }
}

/// Resolve the cargo `--features` list for the kernel build, given the
/// target architecture. The list always includes `alloc` (the kernel
/// uses a bump-heap allocator that the rest of the build relies on)
/// and the arch-specific feature that gates the platform's
/// `arch::<arch>` module. `x86_64` is the default, so we explicitly
/// disable it for the other three targets via `--no-default-features`
/// in [`build_kernel`].
pub fn kernel_features_for(arch: &str) -> String {
    let mut features = match arch {
        "x86_64" | "x64" => "x86_64,binary_panic,alloc",
        "aarch64" | "arm64" => "aarch64,binary_panic,alloc",
        "riscv64" => "riscv64,binary_panic,alloc",
        "loongarch64" => "loongarch64,binary_panic,alloc",
        _ => "x86_64,binary_panic,alloc",
    }
    .to_owned();
    if is_debug_logging() {
        features.push_str(",log_level_debug");
    } else {
        features.push_str(",log_level_warn");
    }
    features
}

/// Return `true` when the generated kernel and loaders should compile the
/// full debug trace. `NT61_LOG_LEVEL=debug` is the explicit override;
/// ordinary `make build` produces a release trace that retains warnings and
/// errors but omits informational and debug records.
pub fn is_debug_logging() -> bool {
    std::env::var("NT61_LOG_LEVEL").as_deref() == Ok("debug")
}

/// Resolve the feature list for the standalone UEFI loader binaries.
pub fn loader_features(target: &str) -> String {
    let architecture = arch_for_kernel_target(target);
    if is_debug_logging() {
        format!("{architecture},log_level_debug")
    } else {
        format!("{architecture},log_level_warn")
    }
}

/// Get the workspace root
pub fn get_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get the build directory
pub fn get_build_dir(build_dir: &Path) -> BuildDirs {
    BuildDirs {
        root: build_dir.to_path_buf(),
        esp: build_dir.join("esp"),
        images: build_dir.join("images"),
        system: build_dir.join("system"),
    }
}

#[derive(Debug)]
pub struct BuildDirs {
    pub root: PathBuf,
    pub esp: PathBuf,
    pub images: PathBuf,
    pub system: PathBuf,
}

// =====================================================================
// Kernel Build
// =====================================================================

/// Build the kernel
pub fn build_kernel(target: &str) -> Result<PathBuf> {
    log::section("Building Kernel");
    log::info(&format!("Target: {}", target));

    let manifest_dir = get_workspace_root();
    let arch = arch_for_kernel_target(target);

    // Run cargo build. The kernel library uses architecture-gated
    // features (`x86_64`, `aarch64`, …); we must disable the
    // default `x86_64` feature and enable the target's feature
    // explicitly, otherwise the build pulls in the x86_64 crate
    // and triggers a `core::arch::x86_64` lookup that does not
    // exist on the other targets.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&manifest_dir);
    cmd.arg("build");
    cmd.arg("--release");
    cmd.arg("--target").arg(target);
    cmd.arg("-p").arg("nt61");
    cmd.arg("--no-default-features");
    cmd.arg("--features").arg(kernel_features_for(arch));

    // The standalone kernel needs linker-provided image boundaries.  Boot
    // targets already set their own linker script in their Cargo config;
    // only the kernel invocation gets the extra `-T` argument here.
    match arch {
        "riscv64" => {
            cmd.env("RUSTFLAGS", "-C link-arg=-Tsrc/boot/linker-rv64.ld -C link-arg=-no-gc-sections");
        }
        "loongarch64" => {
            cmd.env("RUSTFLAGS", "-C link-arg=-Tsrc/boot/linker-la64.ld -C link-arg=-no-gc-sections");
        }
        _ => {}
    }

    log::info("Running cargo build...");
    let status = cmd.status().map_err(BuildError::Io)?;

    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "Kernel build failed with exit code: {:?}",
            status.code()
        )));
    }

    // Find the output binary. On x86_64 the standalone `nt61-kernel`
    // ELF is produced by the [[bin]] entry; on every other arch the
    // kernel is statically linked into `nt61-winload.efi` (the OS
    // loader's own code) and there is no separate kernel binary.
    // For non-x86_64 builds we report success and return an empty
    // path — the caller treats the empty path as "no separate kernel
    // image; the winload bundle already contains the kernel".
    let output = manifest_dir
        .join("target")
        .join(target)
        .join("release")
        .join("nt61-kernel");

    if output.exists() {
        log::success(&format!("Kernel built: {}", output.display()));
        Ok(output)
    } else if arch == "x86_64" {
        Err(BuildError::MissingFile(output.display().to_string()))
    } else {
        log::info(&format!(
            "No standalone kernel binary for {}; the kernel is \
             statically linked into nt61-winload.efi",
            arch,
        ));
        Ok(PathBuf::new())
    }
}

/// Map a `-*-unknown-none[-elf]` target triple back to the
/// short architecture name used by [`kernel_features_for`] and the
/// rest of the build pipeline. Returns `"x86_64"` as the safe
/// default when the triple is unrecognised.
fn arch_for_kernel_target(target: &str) -> &'static str {
    if target.starts_with("x86_64") {
        "x86_64"
    } else if target.starts_with("aarch64") {
        "aarch64"
    } else if target.starts_with("riscv64") {
        "riscv64"
    } else if target.starts_with("loongarch64") {
        "loongarch64"
    } else {
        "x86_64"
    }
}

// =====================================================================
// Boot Manager Build
// =====================================================================

/// Ensure the project-local stub `libgcc.a` archive exists for the
/// LoongArch64 cross-toolchain. Debian/Ubuntu's
/// `libgcc-X-dev-loongarch64-cross` package is not in the default
/// repository set (only `binutils-loongarch64-linux-gnu` is), and
/// rustc unconditionally appends `-lgcc` to every cross-link
/// command, so without this stub the link fails with `cannot find
/// -lgcc` even though Rust's `compiler-builtins` rlib already
/// covers every CPU helper the EFI image references.
///
/// We pre-populate an empty archive at `tools/loongarch64/lib/`,
/// which `src/boot/.cargo/config.toml` and
/// `src/winload/.cargo/config.toml` point `-L` at. The archive is
/// checked in to source control and refreshed by this helper if a
/// developer deletes it; the build pipeline calls this function
/// before invoking `cargo build` so a clean checkout still links.
fn ensure_loongarch_libgcc_stub() -> Result<()> {
    if let Err(e) = std::process::Command::new("loongarch64-linux-gnu-ar")
        .arg("--version")
        .output()
    {
        log::warn(&format!(
            "loongarch64-linux-gnu-ar not available ({}); \
             skipping libgcc stub generation",
            e
        ));
        return Ok(());
    }
    let workspace_root = get_workspace_root();
    let dir = workspace_root.join("tools").join("loongarch64").join("lib");
    let archive = dir.join("libgcc.a");
    if archive.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir).map_err(BuildError::Io)?;
    // `ar -rcs` on an empty input set produces an 8-byte archive
    // with the ARM magic. The linker only cares that the path
    // resolves — it never actually pulls anything from the stub
    // because `compiler-builtins` already supplies every symbol
    // the EFI image references.
    let status = std::process::Command::new("loongarch64-linux-gnu-ar")
        .arg("-rcs")
        .arg(&archive)
        .status()
        .map_err(BuildError::Io)?;
    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "ar -rcs {} failed with exit code: {:?}",
            archive.display(),
            status.code()
        )));
    }
    log::info(&format!(
        "Created LoongArch64 libgcc stub: {}",
        archive.display()
    ));
    Ok(())
}

fn ensure_loongarch_libgcc_stub_for_target(target: &str) -> Result<()> {
    if target.starts_with("loongarch64") {
        ensure_loongarch_libgcc_stub()
    } else {
        Ok(())
    }
}

/// Patch the `ImageBase` field of an existing PE32+ file in place.
///
/// `rust-lld` (used by the `*-unknown-uefi` Rust targets) emits a
/// valid PE32+ with `ImageBase = 0x140000000` (5 GiB on x86_64)
/// regardless of any `QUAD(BASE_ADDRESS)` written by the linker
/// script — the PE emitter runs *after* the script and replaces
/// the value in the OptionalHeader. The boot manager (`nt61-boot`)
/// and the OS loader (`nt61-winload`) both end up with the same
/// preferred base, and when the firmware tries to load the second
/// image its `AllocateAddress(0x140000000)` fails because the boot
/// manager is already there. EDK2 should fall back to
/// `AllocateAnyPages` and apply the .reloc table, but the OVMF on
/// QEMU we test on returns `EFI_LOAD_ERROR` from `CoreLoadImage` in
/// that case, leaving the boot menu stuck in an auto-boot loop.
///
/// We rewrite the 8-byte `ImageBase` at `opt+0x18` to a base
/// outside the region used by the boot manager. The .reloc section
/// generated by rustc is at a fixed RVA relative to ImageBase, so
/// the loader will apply it to relocate the image to the new
/// preferred address — the only thing that needed to be patched is
/// the preferred-base value itself.
fn patch_pe_image_base(path: &std::path::Path, new_base: u64) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_image_base: {} is not a DOS/PE image (no MZ magic)",
            path.display()
        )));
    }

    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;

    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\0\0" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_image_base: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }

    let opt_off = e_lfanew + 4 + 20;
    // OptionalHeader.ImageBase sits at opt+0x18 for PE32+ (8 bytes wide).
    f.seek(SeekFrom::Start(opt_off + 0x18))
        .map_err(BuildError::Io)?;
    f.write_all(&new_base.to_le_bytes())
        .map_err(BuildError::Io)?;

    log::info(&format!(
        "patch_pe_image_base: {} ImageBase=0x{:x}",
        path.display(),
        new_base
    ));
    Ok(())
}

/// Patch the optional-header fields that GNU binutils' `pei-<arch>`
/// target leaves at zero but EDK2's PE/COFF loader actually consults.
///
/// UEFI Spec 2.10 §2.1.4 ("PE32+ Image Format") defines the layout
/// of the IMAGE_OPTIONAL_HEADER. Three fields in particular gate
/// whether the EDK2 image loader will dispatch a payload image:
///
///   * `Subsystem` (offset 0x44) — must be IMAGE_SUBSYSTEM_EFI_APPLICATION
///     (0x0A) for an EFI app; the `pei-<arch>` target leaves this at 0
///     (UNKNOWN).
///   * `SectionAlignment` (offset 0x20) — must be a power of two ≥ 0x200;
///     EDK2 uses this to verify the loaded image fits the requested
///     alignment. `pei-<arch>` writes 0, which trips an early
///     `EFI_UNSUPPORTED` in the loader.
///   * `FileAlignment` (offset 0x24) — must be a power of two ≥ 0x200
///     and ≤ SectionAlignment. Same rationale.
///   * `SizeOfImage` (offset 0x38) — total virtual size of the loaded
///     image including headers. The loader refuses any image whose
///     `SizeOfImage` does not span its preferred load address, so a
///     zero here is fatal.
///   * `SizeOfHeaders` (offset 0x3C) — combined size of the DOS header,
///     PE headers, and section table, rounded up to `FileAlignment`.
///     The loader uses this to figure out where the first section
///     begins in the file.
///
/// We read `e_lfanew` from the DOS header, derive the OptionalHeader
/// address, and rewrite all of those fields in place. `SectionAlignment`
/// is canonicalised to 0x1000 (the value every other architecture's
/// `rust-lld`-emitted PE carries) and `FileAlignment` to 0x200.
///
/// Layout reference: UEFI Spec 2.10 §2.1.4 ("PE32+ Image Format").
fn patch_pe_subsystem(path: &std::path::Path, subsystem: u16, relocations: &[u32]) -> Result<()> {
    patch_pe_subsystem_with_extent(path, subsystem, relocations, 0)
}

/// Same as `patch_pe_subsystem`, but with an explicit minimum image
/// extent (an RVA). `objcopy -O pei-*` drops `.bss`, so the PE
/// OptionalHeader `SizeOfImage` it synthesises only covers the
/// initialised sections. A kernel whose BSS extends past the last
/// initialised section would then be loaded without its BSS pages
/// reserved/zeroed, and every static in that region would alias
/// unrelated physical memory. The extent is the ELF maximum of
/// `sh_addr + sh_size` over allocated sections (including SHT_NOBITS),
/// minus the image base, and `inject_stub_reloc_section` both places
/// `.reloc` after it and extends `SizeOfImage` to cover it.
fn patch_pe_subsystem_with_extent(
    path: &std::path::Path,
    subsystem: u16,
    relocations: &[u32],
    image_extent_rva: u32,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    // DOS header sanity-check
    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_subsystem: {} is not a DOS/PE image (no MZ magic)",
            path.display()
        )));
    }

    // e_lfanew is the ULONG at file offset 0x3C
    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;

    // Verify the PE signature at e_lfanew
    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\0\0" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_subsystem: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }

    // OptionalHeader starts at e_lfanew + 4 (PE\0\0) + 20 (COFF FileHeader)
    let opt_off = e_lfanew + 4 + 20;

    // Read Magic to confirm this is PE32+ (0x020B). PE32 (0x010B) images
    // use a slightly different optional-header layout (BaseOfData field,
    // etc.) so we explicitly refuse those rather than silently writing
    // into the wrong offsets.
    f.seek(SeekFrom::Start(opt_off)).map_err(BuildError::Io)?;
    let mut magic_bytes = [0u8; 2];
    f.read_exact(&mut magic_bytes).map_err(BuildError::Io)?;
    let magic = u16::from_le_bytes(magic_bytes);
    if magic != 0x020B {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_subsystem: {} has PE magic 0x{:04x}, expected PE32+ (0x020B)",
            path.display(),
            magic
        )));
    }

    // The file ends at the last byte of the last section. Round up to
    // SECTION_ALIGN (0x1000) to derive SizeOfImage.
    //
    // `SizeOfHeaders` is *not* hardcoded to 0x400 because
    // `objcopy -O pei-loongarch64` lays out the PE differently from
    // rust-lld on x86_64: the DOS/PE/OptionalHeader block is only
    // 0x198 bytes here (it doesn't carry the hand-rolled `.efi_header`
    // section we put in the ELF), so the section table starts right
    // at offset 0x198 and ends near 0x1e8. The first `.text` data
    // begins at offset 0x200 on LoongArch64, well before 0x400.
    //
    // EDK2's PE/COFF loader rejects any section whose
    // `PointerToRawData` is strictly less than `SizeOfHeaders`
    // (`SizeOfRawData > 0` branch in `PeCoffLoaderReadSections`).
    // Hard-coding 0x400 makes the check fail with `Unsupported`,
    // which is exactly the failure mode we hit. Instead, walk the
    // section table, find the smallest `PointerToRawData` among
    // sections that actually carry data, and round it up to the
    // next FileAlignment boundary. That's the largest legal value
    // for `SizeOfHeaders` while still satisfying the constraint.
    let file_len = f.metadata().map_err(BuildError::Io)?.len();
    let section_align: u32 = 0x1000;
    let file_align: u32 = 0x200;
    let size_of_image =
        ((file_len + section_align as u64 - 1) & !(section_align as u64 - 1)) as u32;

    // Section table starts right after the OptionalHeader (offset
    // 0x18 from OptionalHeader start).
    let size_opt: u16 = {
        let mut b = [0u8; 2];
        f.seek(SeekFrom::Start(
            e_lfanew + 4 + 16, // COFF FileHeader.SizeOfOptionalHeader
        ))
        .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        u16::from_le_bytes(b)
    };
    let sec_table_off = opt_off + size_opt as u64;
    let num_sections = u16::from_le_bytes({
        let mut b = [0u8; 2];
        f.seek(SeekFrom::Start(e_lfanew + 4 + 2)) // COFF FileHeader.NumberOfSections
            .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        b
    });
    let mut first_data_off: Option<u32> = None;
    for i in 0..num_sections {
        let sh_off = sec_table_off + (i as u64) * 40;
        // Section header: Name(8) | VirtSize(4) | VirtAddr(4) | RawSize(4) | RawAddr(4)
        let raw_size = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(sh_off + 16))
                .map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        let raw_addr = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(sh_off + 20))
                .map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        if raw_size > 0 {
            first_data_off = Some(match first_data_off {
                Some(prev) => prev.min(raw_addr),
                None => raw_addr,
            });
        }
    }
    // Round up to FileAlignment — SizeOfHeaders must be a multiple
    // of FileAlignment per the PE spec.
    let headers_size: u32 = match first_data_off {
        Some(off) => off.div_ceil(file_align) * file_align,
        // Fallback if every section is empty (shouldn't happen for
        // an EFI Application, but be defensive).
        None => file_align,
    };

    let writes: &[(u64, &[u8])] = &[
        // Subsystem (offset 0x44)
        (opt_off + 0x44, &subsystem.to_le_bytes()),
        // SectionAlignment (offset 0x20)
        (opt_off + 0x20, &section_align.to_le_bytes()),
        // FileAlignment (offset 0x24)
        (opt_off + 0x24, &file_align.to_le_bytes()),
        // SizeOfImage (offset 0x38)
        (opt_off + 0x38, &size_of_image.to_le_bytes()),
        // SizeOfHeaders (offset 0x3C)
        (opt_off + 0x3C, &headers_size.to_le_bytes()),
    ];

    for (offset, bytes) in writes {
        f.seek(SeekFrom::Start(*offset)).map_err(BuildError::Io)?;
        f.write_all(bytes).map_err(BuildError::Io)?;
    }

    // Signal to the loader that this image *has* a relocation
    // table so it should fall back to `AllocateAnyPages` when the
    // preferred `ImageBase` happens to conflict with a region the
    // firmware already owns.
    //
    // UEFI's PE/COFF loader computes:
    //   ImageContext->RelocationsStripped =
    //     (DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
    // and then does:
    //   if (AllocateAddress(imageBase) fails AND !RelocationsStripped) {
    //       Status = AllocateAnyPages(...);
    //   }
    // Without this Directory entry populated, an EFI Application
    // whose preferred base is already in use is rejected as
    // `EFI_LOAD_ERROR` and the boot loader never starts.
    //
    // We append a stub `.reloc` section containing a single
    // zero-length BaseRelocation block (header-only) — that is a
    // legal PE relocation table. The block header has
    // `VirtualAddress = 0, SizeOfBlock = 8`, which the loader
    // treats as "no actual fixups in this range". Since the
    // LoongArch64 ABI used in this project is fully PIC (the Rust
    // compiler emits `pcaddi`/etc. for address materialisation),
    // there genuinely are no relocations to apply.
    inject_stub_reloc_section(&mut f, e_lfanew, relocations, image_extent_rva)?;
    // EDK2's PE/COFF loader is picky about the COFF FileHeader
    // `Characteristics` field — a 0x200 (IMAGE_FILE_32BIT_MACHINE) bit
    // makes it reject LoongArch64 images as `Unsupported` even when
    // COFF FileHeader Characteristics: 0x0022 mirrors the value
    // rust-lld emits for x86_64 EFI images:
    //   0x0002 IMAGE_FILE_EXECUTABLE_IMAGE
    //   0x0020 IMAGE_FILE_LARGE_ADDRESS_AWARE
    // (no IMAGE_FILE_DLL — UEFI §2.1.4.3 forbids it for
    // EFI Applications, and EDK2's PE/COFF loader rejects any
    // image with the DLL flag set. Some toolchains set the
    // `IMAGE_FILE_DLL` (0x2000) bit by default for cross-arch
    // compatibility — strip it explicitly here.)
    let characteristics: u16 = 0x0022;
    f.seek(SeekFrom::Start(e_lfanew + 4 + 18))
        .map_err(BuildError::Io)?;
    f.write_all(&characteristics.to_le_bytes())
        .map_err(BuildError::Io)?;
    // COFF FileHeader.PointerToSymbolTable (offset 8) and
    // NumberOfSymbols (offset 12): `pei-loongarch64` leaves a
    // stale pointer at offset 0x8 (some random value pointing
    // into the file body) and NumberOfSymbols at 0, which EDK2's
    // loader interprets as "symbol table present but empty" and
    // rejects the image as `Unsupported`. Zero both fields to
    // match the x86_64 rust-lld output and signal "no symbol
    // table".
    let zero_dword: [u8; 8] = [0; 8];
    f.seek(SeekFrom::Start(e_lfanew + 4 + 8))
        .map_err(BuildError::Io)?;
    f.write_all(&zero_dword).map_err(BuildError::Io)?;
    // OptionalHeader DllCharacteristics: 0x8160 mirrors the value
    // rust-lld emits on x86_64, including
    //   IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)
    //   IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
    //   IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (0x8000)
    // EDK2's loader doesn't strictly require this, but downstream
    // tools (e.g. the Microsoft `signtool` we use for test
    // signing) reject images with DllCharacteristics=0.
    let dll_chars: u16 = 0x8160;
    f.seek(SeekFrom::Start(opt_off + 0x46))
        .map_err(BuildError::Io)?;
    f.write_all(&dll_chars.to_le_bytes())
        .map_err(BuildError::Io)?;
    // MajorOSVersion / MajorSubsystemVersion: every other
    // `rust-lld` EFI image uses 6/0 (Windows Vista+) — a value
    // of 0 confuses some loaders that treat 0 as "pre-NT".
    let ver: u16 = 6;
    f.seek(SeekFrom::Start(opt_off + 0x28))
        .map_err(BuildError::Io)?;
    f.write_all(&ver.to_le_bytes()).map_err(BuildError::Io)?;
    f.seek(SeekFrom::Start(opt_off + 0x30))
        .map_err(BuildError::Io)?;
    f.write_all(&ver.to_le_bytes()).map_err(BuildError::Io)?;
    log::info(&format!(
        "Patched PE OptionalHeader (Subsystem=0x{:02x}, SectionAlign=0x{:x}, \
         FileAlign=0x{:x}, SizeOfImage=0x{:x}, SizeOfHeaders=0x{:x}, \
         Characteristics=0x{:x}, DllChars=0x{:x}, OSVer={}, SubVer={}) at {}",
        subsystem,
        section_align,
        file_align,
        size_of_image,
        headers_size,
        characteristics,
        dll_chars,
        ver,
        ver,
        path.display()
    ));
    Ok(())
}

/// Read three fields we need to recover from the ELF after the
/// `objcopy -O pei-<arch>` step has clobbered them in the
/// corresponding PE OptionalHeader:
///
///   * `entry_point_rva` — the RVA the loader should jump to
///     (AddressOfEntryPoint). We compute this as the `.text`
///     section's VMA on the assumption that the linker script
///     places `efi_main` at the very start of `.text` (which is
///     true for both `linker-la64.ld` and `linker-rv64.ld`).
///   * `base_of_code` — same as above but stored as a 32-bit value
///     (PE32+ BaseOfCode is always 32 bits; the upper 32 bits are
///     zero on these architectures anyway).
///   * `image_base` — the load address. We pull it from the first
///     PT_LOAD program header because that is the same value the
///     linker used for `BASE_ADDRESS`.
///
/// We deliberately read the ELF ourselves instead of shelling out
/// to `objdump`/`readelf` — the goal is to make the post-link fix
/// reproducible from a clean checkout without external parsing
/// tools, and the layout we need is fixed by our own linker
/// scripts so a hand-rolled parser is small.
///
/// Layout references:
///   * ELF64 header: `Elf64_Ehdr` (64 bytes)
///   * ELF64 section header: `Elf64_Shdr` (64 bytes)
///   * ELF64 program header: `Elf64_Phdr` (56 bytes)
fn read_elf_image_layout(elf_path: &std::path::Path) -> Result<(u32, u32, u64)> {
    use std::io::Read;

    let mut f = std::fs::File::open(elf_path).map_err(BuildError::Io)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(BuildError::Io)?;

    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} is not an ELF file",
            elf_path.display()
        )));
    }
    if buf[4] != 2 {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} is not ELF64",
            elf_path.display()
        )));
    }
    if buf[5] != 1 {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} is big-endian; only little-endian ELFs are supported",
            elf_path.display()
        )));
    }

    let read_u16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let read_u32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let read_u64 = |b: &[u8]| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);

    let sh_off = read_u64(&buf[40..48]) as usize;
    let sh_entsize = read_u16(&buf[58..60]) as usize;
    let sh_num = read_u16(&buf[60..62]) as usize;
    let sh_strndx = read_u16(&buf[62..64]) as usize;

    // Read the section-name string table first so we can find
    // `.text` without needing a name lookup library.
    let strtab_hdr_off = sh_off + sh_strndx * sh_entsize;
    if strtab_hdr_off + 40 > buf.len() {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} has truncated section header table",
            elf_path.display()
        )));
    }
    let strtab_off = read_u64(&buf[strtab_hdr_off + 24..strtab_hdr_off + 32]) as usize;
    let strtab_size = read_u64(&buf[strtab_hdr_off + 32..strtab_hdr_off + 40]) as usize;

    let strtab = if strtab_off + strtab_size <= buf.len() {
        &buf[strtab_off..strtab_off + strtab_size]
    } else {
        &[][..]
    };

    let mut text_vma: Option<u64> = None;
    let entry_vma = read_u64(&buf[24..32]);
    let mut image_base: Option<u64> = None;

    for i in 0..sh_num {
        let off = sh_off + i * sh_entsize;
        if off + sh_entsize > buf.len() {
            break;
        }
        let name_off = read_u32(&buf[off..off + 4]) as usize;
        let sh_type = read_u32(&buf[off + 4..off + 8]);
        let sh_addr = read_u64(&buf[off + 16..off + 24]);

        if sh_type == 1
            && strtab.get(name_off).copied() == Some(b'.')
            && strtab.len() >= name_off + 5
            && &strtab[name_off..name_off + 5] == b".text"
            && (strtab.len() == name_off + 5 || strtab[name_off + 5] == 0)
        {
            text_vma = Some(sh_addr);
        }
    }

    let ph_off = read_u64(&buf[32..40]) as usize;
    let ph_entsize = read_u16(&buf[54..56]) as usize;
    let ph_num = read_u16(&buf[56..58]) as usize;
    for i in 0..ph_num {
        let off = ph_off + i * ph_entsize;
        if off + ph_entsize > buf.len() {
            break;
        }
        let p_type = read_u32(&buf[off..off + 4]);
        if p_type == 1
        /* PT_LOAD */
        {
            image_base = Some(read_u64(&buf[off + 16..off + 24]));
            break;
        }
    }

    let Some(text) = text_vma else {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} has no .text section",
            elf_path.display()
        )));
    };
    let Some(base) = image_base else {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} has no PT_LOAD program header",
            elf_path.display()
        )));
    };
    let entry_rva = entry_vma.wrapping_sub(base);
    let text_rva = text.wrapping_sub(base);
    Ok((entry_rva as u32, text_rva as u32, base))
}

/// Highest virtual address covered by any allocated ELF section,
/// including `SHT_NOBITS` (`.bss`). Used to extend the PE
/// `SizeOfImage` because `objcopy -O pei-*` strips `.bss` and would
/// otherwise leave the kernel's zero-initialised statics outside the
/// loaded image.
fn read_elf_image_extent(elf_path: &std::path::Path) -> Result<u64> {
    use std::io::Read;

    let mut f = std::fs::File::open(elf_path).map_err(BuildError::Io)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(BuildError::Io)?;
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} is not an ELF file",
            elf_path.display()
        )));
    }
    let read_u16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let read_u32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let read_u64 = |b: &[u8]| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let sh_off = read_u64(&buf[40..48]) as usize;
    let sh_entsize = read_u16(&buf[58..60]) as usize;
    let sh_num = read_u16(&buf[60..62]) as usize;
    let mut extent: u64 = 0;
    for i in 0..sh_num {
        let off = sh_off + i * sh_entsize;
        if off + 64 > buf.len() {
            break;
        }
        let sh_type = read_u32(&buf[off + 4..off + 8]);
        let sh_flags = read_u64(&buf[off + 8..off + 16]);
        let sh_addr = read_u64(&buf[off + 16..off + 24]);
        let sh_size = read_u64(&buf[off + 32..off + 40]);
        if (sh_type != 1 && sh_type != 8) || sh_flags & 0x2 == 0 || sh_addr == 0 {
            continue;
        }
        extent = extent.max(sh_addr.saturating_add(sh_size));
    }
    if extent == 0 {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} has no allocated sections",
            elf_path.display()
        )));
    }
    Ok(extent)
}

/// Read absolute 64-bit relocation targets from an ELF64 image.
///
/// The x86_64, AArch64, RISC-V64, and LoongArch64 kernels are linked
/// as static ELF with `--emit-relocs` and converted to PE/COFF by
/// binutils, so the ELF keeps the relocation records of every
/// absolute 64-bit word the linker resolved. This function extracts
/// only the fixups that affect mapped, initialized image data:
/// `R_X86_64_64` / `R_X86_64_RELATIVE` for x86_64,
/// `R_AARCH64_ABS64` / `R_AARCH64_RELATIVE` for AArch64,
/// `R_RISCV_64` for RISC-V, and `R_LARCH_64` for LoongArch.
/// PC-relative relocations must not be translated into PE fixups,
/// because the target architectures derive those from the runtime
/// instruction address.
fn read_elf_absolute_relocations(elf_path: &std::path::Path, image_base: u64) -> Result<Vec<u32>> {
    use std::io::Read;

    let mut buf = Vec::new();
    std::fs::File::open(elf_path)
        .map_err(BuildError::Io)?
        .read_to_end(&mut buf)
        .map_err(BuildError::Io)?;
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} is not an ELF file",
            elf_path.display()
        )));
    }
    if buf[4] != 2 || buf[5] != 1 {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} must be a little-endian ELF64 image",
            elf_path.display()
        )));
    }

    let read_u16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let read_u32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let read_u64 = |b: &[u8]| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);

    // e_machine-specific set of absolute 64-bit relocation types that
    // must become PE `IMAGE_REL_BASED_DIR64` fixups.
    let absolute_types: &[u64] = match read_u16(&buf[18..20]) {
        62 => &[1, 8],       // R_X86_64_64, R_X86_64_RELATIVE
        183 => &[257, 1027], // R_AARCH64_ABS64, R_AARCH64_RELATIVE
        243 => &[2],         // R_RISCV_64
        262 => &[2, 64],     // legacy R_RISCV_64 value, R_LARCH_64
        _ => &[2],
    };

    let sh_off = read_u64(&buf[40..48]) as usize;
    let sh_entsize = read_u16(&buf[58..60]) as usize;
    let sh_num = read_u16(&buf[60..62]) as usize;
    let sh_strndx = read_u16(&buf[62..64]) as usize;
    if sh_entsize == 0 || sh_off >= buf.len() || sh_num == 0 {
        return Err(BuildError::ImageCreateFailed(format!(
            "{} has an invalid section header table",
            elf_path.display()
        )));
    }

    let section = |index: usize| -> Option<(&[u8], usize, u32, u64, u64, u64, u64)> {
        let off = sh_off.checked_add(index.checked_mul(sh_entsize)?)?;
        if off + 64 > buf.len() {
            return None;
        }
        let name_off = read_u32(&buf[off..off + 4]) as usize;
        let sh_type = read_u32(&buf[off + 4..off + 8]);
        let sh_flags = read_u64(&buf[off + 8..off + 16]);
        let _sh_addr = read_u64(&buf[off + 16..off + 24]);
        let sh_offset = read_u64(&buf[off + 24..off + 32]);
        let sh_size = read_u64(&buf[off + 32..off + 40]);
        Some((
            &buf[off..off + 64],
            name_off,
            sh_type,
            sh_flags,
            _sh_addr,
            sh_offset,
            sh_size,
        ))
    };

    let (shstrtab_hdr, _, _, _, _, shstrtab_off, shstrtab_size) =
        section(sh_strndx).ok_or_else(|| {
            BuildError::ImageCreateFailed(format!(
                "{} has no section-name string table",
                elf_path.display()
            ))
        })?;
    let _ = shstrtab_hdr;
    let shstrtab = buf
        .get(shstrtab_off as usize..(shstrtab_off as usize + shstrtab_size as usize))
        .unwrap_or(&[]);

    let section_name = |name_off: usize| -> Option<&str> {
        let bytes = shstrtab.get(name_off..)?;
        let end = bytes.iter().position(|&byte| byte == 0)?;
        core::str::from_utf8(&bytes[..end]).ok()
    };

    let mut relocations = BTreeSet::new();
    for index in 0..sh_num {
        let Some((_, name_off, sh_type, _, _, _, sh_size)) = section(index) else {
            continue;
        };
        if sh_type != 4 {
            continue;
        }
        let Some(name) = section_name(name_off) else {
            continue;
        };
        if !name.starts_with(".rela.") {
            continue;
        }

        // Section header layout: name(0), type(4), flags(8), addr(16),
        // offset(24), size(32), link(40), info(44).
        let header_index = sh_off + index * sh_entsize;
        if header_index + 64 > buf.len() {
            continue;
        }
        let rela_off = read_u64(&buf[header_index + 24..header_index + 32]) as usize;
        let rela_link = read_u32(&buf[header_index + 40..header_index + 44]) as usize;
        let rela_info = read_u32(&buf[header_index + 44..header_index + 48]) as usize;

        let Some((_, _, target_type, target_flags, target_addr, _, target_size)) =
            section(rela_info)
        else {
            continue;
        };
        // A relocation record for a non-allocated section (normally
        // debug info) is irrelevant to a runtime PE image.
        if target_type != 1 || target_flags & 0x2 == 0 {
            continue;
        }
        // The symbol table link is not needed because all R_LARCH_64
        // and R_RISCV_64 fixups are section-relative absolute words.
        let _ = rela_link;

        let entry_count = sh_size as usize / 24;
        for entry in 0..entry_count {
            let off = rela_off + entry * 24;
            if off + 24 > buf.len() {
                break;
            }
            let target = read_u64(&buf[off..off + 8]);
            let info = read_u64(&buf[off + 8..off + 16]);
            if !absolute_types.contains(&(info & 0xffff_ffff)) {
                continue;
            }
            if target < target_addr || target + 8 > target_addr + target_size {
                continue;
            }
            if target < image_base {
                continue;
            }
            let Some(rva) = (target - image_base).checked_sub(0) else {
                continue;
            };
            if rva <= u32::MAX as u64 {
                relocations.insert(rva as u32);
            }
        }
    }

    // The linker resolves GOT references (e.g. calls into
    // "compiler_builtins" soft-float helpers, which rustc compiles
    // with its own PIC settings and therefore reaches through
    // GOTPCREL) by baking link-time absolute addresses into '.got'
    // slots. A static non-PIE link emits no relocation records for
    // those slots, so the record walk above cannot see them. Every
    // non-zero '.got' slot holds an address inside this image by
    // definition of the GOT, so record each one as a DIR64 fixup;
    // zero slots (weak undefined symbols) and any value below the
    // image base are left untouched.
    for index in 0..sh_num {
        let Some((_, name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size)) = section(index)
        else {
            continue;
        };
        if sh_type != 1 || sh_flags & 0x2 == 0 {
            continue;
        }
        let Some(name) = section_name(name_off) else {
            continue;
        };
        if !(name == ".got" || name == ".got.plt") {
            continue;
        }
        let slot_count = sh_size as usize / 8;
        for slot in 0..slot_count {
            let off = sh_offset as usize + slot * 8;
            if off + 8 > buf.len() {
                break;
            }
            let value = read_u64(&buf[off..off + 8]);
            if value < image_base {
                continue;
            }
            // The fixup targets the slot itself, not the address the
            // slot holds: at runtime the whole 8-byte word must gain
            // the load delta.
            let Some(rva) = (sh_addr + (slot as u64) * 8).checked_sub(image_base) else {
                continue;
            };
            if rva <= u32::MAX as u64 {
                relocations.insert(rva as u32);
            }
        }
    }

    Ok(relocations.into_iter().collect())
}

/// Encode sorted 64-bit relocation RVAs as PE/COFF base relocation
/// blocks using `IMAGE_REL_BASED_DIR64`.
fn build_pe_base_relocation_table(relocations: &[u32]) -> Vec<u8> {
    if relocations.is_empty() {
        // A header-only block marks an image as relocatable without
        // asking the PE/COFF loader to patch any word.
        return vec![0, 0, 0, 0, 8, 0, 0, 0];
    }

    let mut body = Vec::new();
    let mut page: u32 = u32::MAX;
    let mut entries: Vec<u16> = Vec::new();

    let flush = |body: &mut Vec<u8>, page: u32, entries: &mut Vec<u16>| {
        if entries.is_empty() {
            return;
        }
        // Absolute entries are legal padding and keep every block
        // 4-byte aligned.
        if entries.len() % 2 != 0 {
            entries.push(0);
        }
        let block_size = 8u32 + entries.len() as u32 * 2;
        body.extend_from_slice(&page.to_le_bytes());
        body.extend_from_slice(&block_size.to_le_bytes());
        for entry in entries.iter() {
            body.extend_from_slice(&entry.to_le_bytes());
        }
        entries.clear();
    };

    for rva in relocations {
        if *rva & 0xFFFF_F000 != page {
            flush(&mut body, page, &mut entries);
            page = *rva & 0xFFFF_F000;
        }
        entries.push((0xA000 | (*rva & 0xFFF)) as u16);
    }
    flush(&mut body, page, &mut entries);
    body
}

/// Apply extra OptionalHeader fixes for LoongArch64 / RISC-V64 EFI
/// images built via `objcopy -O pei-<arch>`.
///
/// GNU binutils' `pei-<arch>` target synthesises a PE32+ wrapper but
/// leaves the following fields at zero, which EDK2's image loader
/// rejects as `Unsupported`:
///
///   * `AddressOfEntryPoint` (OptionalHeader +0x10)
///   * `BaseOfCode`         (OptionalHeader +0x14)
///   * `ImageBase`          (OptionalHeader +0x18, 8 bytes)
///
/// For LoongArch64 we use `BASE_ADDRESS = 0x40000000` in the linker
/// script and `efi_main` as the entry point; for RISC-V64 we use
/// `BASE_ADDRESS = 0x40000000` too. Both arches share the same fix-up
/// so this helper takes the address values explicitly rather than
/// re-parsing the linker script.
///
/// The fix is identical in spirit to `patch_pe_subsystem` (it
/// overwrites specific bytes in the OptionalHeader) so we keep the
/// same offset arithmetic and validation: read `e_lfanew`, find the
/// PE/COFF and OptionalHeader boundaries, verify the magic, then
/// splice the new values in.
fn patch_pe_entry_point_and_image_base(
    path: &std::path::Path,
    entry_point_rva: u32,
    base_of_code: u32,
    image_base: u64,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    // Reuse the same DOS/PE-header verification as patch_pe_subsystem
    // so a typo in the caller's path or a non-PE file is rejected
    // loudly rather than silently corrupting random bytes.
    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_entry_point_and_image_base: {} is not a DOS/PE image",
            path.display()
        )));
    }
    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;
    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\0\0" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_entry_point_and_image_base: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }
    let opt_off = e_lfanew + 4 + 20;
    f.seek(SeekFrom::Start(opt_off)).map_err(BuildError::Io)?;
    let mut magic_bytes = [0u8; 2];
    f.read_exact(&mut magic_bytes).map_err(BuildError::Io)?;
    if u16::from_le_bytes(magic_bytes) != 0x020B {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_entry_point_and_image_base: {} is not PE32+",
            path.display()
        )));
    }

    let writes: &[(u64, &[u8])] = &[
        // AddressOfEntryPoint (offset 0x10)
        (opt_off + 0x10, &entry_point_rva.to_le_bytes()),
        // BaseOfCode (offset 0x14)
        (opt_off + 0x14, &base_of_code.to_le_bytes()),
        // ImageBase (offset 0x18, 8 bytes)
        (opt_off + 0x18, &image_base.to_le_bytes()),
    ];

    for (offset, bytes) in writes {
        f.seek(SeekFrom::Start(*offset)).map_err(BuildError::Io)?;
        f.write_all(bytes).map_err(BuildError::Io)?;
    }
    log::info(&format!(
        "Patched PE AddressOfEntryPoint=0x{:x}, BaseOfCode=0x{:x}, \
         ImageBase=0x{:x} at {}",
        entry_point_rva,
        base_of_code,
        image_base,
        path.display()
    ));
    Ok(())
}

/// GNU binutils' `pei-loongarch64` and `pei-riscv64-little` BFD
/// targets synthesise a PE32+ image whose section table carries
/// **absolute** VirtualAddresses copied straight from the ELF input
/// (because binutils does not implement the PE RVA convention).
///
/// A working PE image needs each section's `VirtualAddress` to be an
/// RVA (relative to `ImageBase`): the UEFI loader computes the
/// destination address as `ImageBase + Section.VirtualAddress`. If
/// the section table already contains absolute addresses
/// (`BASE_ADDRESS + 0x1000` for `.text`, etc.), the loader would try
/// to map the section at `ImageBase + (BASE_ADDRESS + 0x1000)` which
/// is well outside the image and falls into the `Unsupported`
/// bucket of the EFI image validator.
///
/// The fix walks the section table once, and for every section
/// whose `VirtualAddress` is >= `image_base`, rewrites it as
/// `VirtualAddress - image_base`. Sections that already carry a
/// relative RVA (e.g. `.text` with VA=0x1000 on a stripped image)
/// are left alone.
fn patch_pe_section_addresses(path: &std::path::Path, image_base: u64) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    // Reuse the same DOS/PE-header verification as the other patch
    // helpers so a wrong file is rejected loudly.
    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_section_addresses: {} is not a DOS/PE image",
            path.display()
        )));
    }
    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;
    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\x00\x00" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_section_addresses: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }

    // COFF FileHeader (20 bytes): Machine(2) | NumSections(2) | ...
    let coff_off = e_lfanew + 4;
    f.seek(SeekFrom::Start(coff_off + 2))
        .map_err(BuildError::Io)?;
    let mut num_sections_bytes = [0u8; 2];
    f.read_exact(&mut num_sections_bytes)
        .map_err(BuildError::Io)?;
    let num_sections = u16::from_le_bytes(num_sections_bytes);

    // SizeOfOptionalHeader is at offset 16 of the FileHeader.
    f.seek(SeekFrom::Start(coff_off + 16))
        .map_err(BuildError::Io)?;
    let mut size_opt_bytes = [0u8; 2];
    f.read_exact(&mut size_opt_bytes).map_err(BuildError::Io)?;
    let size_opt = u16::from_le_bytes(size_opt_bytes) as u64;

    // Section table starts right after the OptionalHeader.
    let sec_table_off = coff_off + 20 + size_opt;

    // Section header is 40 bytes; field offsets within a section:
    //   +0  Name (8 bytes)
    //   +8  VirtualSize   (u32)
    //   +12 VirtualAddress(u32)
    //   +16 SizeOfRawData (u32)
    //   +20 PointerToRawData (u32)
    let mut fixed_count: u32 = 0;
    for i in 0..num_sections {
        let off = sec_table_off + (i as u64) * 40;
        f.seek(SeekFrom::Start(off + 12)).map_err(BuildError::Io)?;
        let mut va_bytes = [0u8; 4];
        f.read_exact(&mut va_bytes).map_err(BuildError::Io)?;
        let va = u32::from_le_bytes(va_bytes);
        // Only rebase sections whose VA is suspiciously close to
        // ImageBase. A valid RVA is always less than ImageBase so
        // the check naturally leaves already-relative entries
        // alone (which matters for x86_64 / aarch64 EFI binaries
        // built directly with rust-lld).
        if (va as u64) >= image_base {
            let new_va: u32 = va.wrapping_sub(image_base as u32);
            f.seek(SeekFrom::Start(off + 12)).map_err(BuildError::Io)?;
            f.write_all(&new_va.to_le_bytes()).map_err(BuildError::Io)?;
            fixed_count += 1;
        }
    }
    log::info(&format!(
        "Patched {} section VirtualAddress entries (rebased against \
         ImageBase=0x{:x}) at {}",
        fixed_count,
        image_base,
        path.display()
    ));
    Ok(())
}

/// Give wrapped PE sections real `Characteristics` flags.
///
/// GNU binutils' `pei-<arch>` output leaves every section
/// characteristic at zero. EDK2's memory-protection protocol therefore
/// treats writable sections (including the kernel's large `.data`/
/// `.bss` tables) as read-only after `ExitBootServices`, causing store
/// access faults during early kernel initialisation.
fn patch_pe_section_characteristics(path: &std::path::Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_section_characteristics: {} is not a DOS/PE image",
            path.display()
        )));
    }
    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;
    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\x00\x00" {
        return Err(BuildError::ImageCreateFailed(format!(
            "patch_pe_section_characteristics: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }

    let coff_off = e_lfanew + 4;
    f.seek(SeekFrom::Start(coff_off + 2)).map_err(BuildError::Io)?;
    let mut num_sections_bytes = [0u8; 2];
    f.read_exact(&mut num_sections_bytes).map_err(BuildError::Io)?;
    let num_sections = u16::from_le_bytes(num_sections_bytes);
    f.seek(SeekFrom::Start(coff_off + 16)).map_err(BuildError::Io)?;
    let mut size_opt_bytes = [0u8; 2];
    f.read_exact(&mut size_opt_bytes).map_err(BuildError::Io)?;
    let size_opt = u16::from_le_bytes(size_opt_bytes) as u64;
    let sec_table_off = coff_off + 20 + size_opt;

    let flags_for = |name: &[u8]| -> u32 {
        let name = name
            .iter()
            .position(|byte| *byte == 0)
            .map(|end| &name[..end])
            .unwrap_or(name);
        if name == b".text" || name.starts_with(b".text.") {
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        } else if name == b".bss" || name.starts_with(b".bss.") {
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        } else if name == b".rdata"
            || name.starts_with(b".rdata.")
            || name == b".rodata"
            || name.starts_with(b".rodata.")
        {
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        } else if name == b".reloc" {
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        } else {
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        }
    };

    let mut fixed_count = 0usize;
    for i in 0..num_sections {
        let off = sec_table_off + (i as u64) * 40;
        f.seek(SeekFrom::Start(off)).map_err(BuildError::Io)?;
        let mut hdr = [0u8; 40];
        f.read_exact(&mut hdr).map_err(BuildError::Io)?;
        let flags = flags_for(&hdr[0..8]);
        f.seek(SeekFrom::Start(off + 36)).map_err(BuildError::Io)?;
        f.write_all(&flags.to_le_bytes()).map_err(BuildError::Io)?;
        fixed_count += 1;
    }

    log::info(&format!(
        "Patched {} PE section characteristic entries at {}",
        fixed_count,
        path.display()
    ));
    Ok(())
}

/// Append a `.reloc` section (a single, empty BaseRelocation
/// block) and update the OptionalHeader DataDirectory so EDK2's
/// loader treats the image as relocatable.
///
/// The function has to do three things atomically:
///   1. Rewrite NumberOfSections (COFF FileHeader+2) to the new
///      count.
///   2. Extend SizeOfImage (OptionalHeader+0x38) to cover the
///      added section, rounded up to SectionAlignment.
///   3. Write the new section header + its 8-byte body at the end
///      of the file (after padding to SectionAlignment).
///   4. Update DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC] =
///      (RVA_of_section_data, Size_of_section_data).
///
/// We choose the stub's `VirtualAddress` to be the smallest
/// SectionAlignment-aligned offset that doesn't overlap the existing
/// `.text` / `.data` regions. With only `.text` and `.data` in
/// play, `.data` ends at `data_va_end = data_va + data_vsize`,
/// rounded up to `SectionAlignment` — there's no harm in placing
/// `.reloc` there because UEFI never actually maps/reads it after
/// the loader finishes the relocation pass.
///
/// Without this stub the loader falls into the
/// `AllocateAddress -> AllocateAnyPages` fallback path *only* when
/// the image is at >= 0x100000 **and** `PcdImageLargeAddressLoad`
/// is true (a per-platform PCD). On stock OVMF LoongArch64 we
/// can't rely on that PCD being set, so the only portable way to
/// get the loader to consider fallback allocations is to mark the
/// image as having a relocation table.
fn inject_stub_reloc_section(
    f: &mut std::fs::File,
    e_lfanew: u64,
    relocations: &[u32],
    image_extent_rva: u32,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let coff_off = e_lfanew + 4;
    let opt_off = coff_off + 20;

    // Read COFF NumberOfSections and OptionalHeader.SizeOfOptionalHeader.
    let num_sections = u16::from_le_bytes({
        let mut b = [0u8; 2];
        f.seek(SeekFrom::Start(coff_off + 2))
            .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        b
    });
    let size_opt = u16::from_le_bytes({
        let mut b = [0u8; 2];
        f.seek(SeekFrom::Start(coff_off + 16))
            .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        b
    });
    let section_align = u32::from_le_bytes({
        let mut b = [0u8; 4];
        f.seek(SeekFrom::Start(opt_off + 0x20))
            .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        b
    });
    let file_align = u32::from_le_bytes({
        let mut b = [0u8; 4];
        f.seek(SeekFrom::Start(opt_off + 0x24))
            .map_err(BuildError::Io)?;
        f.read_exact(&mut b).map_err(BuildError::Io)?;
        b
    });

    let sec_table_off = opt_off + size_opt as u64;

    // objcopy `-O pei-<arch>` emits its own `.reloc` section with raw
    // data whenever the source ELF still carries `.rela.*` sections —
    // the winload build is the common case. Appending a second
    // `.reloc` header in that case pushes the section table into the
    // first section's raw data and destroys the entry-point prologue,
    // so reuse the existing section instead of adding another one.
    let mut existing_reloc: Option<(u64, u32, u32, u32, u32)> = None;
    for i in 0..num_sections {
        let off = sec_table_off + i as u64 * 40;
        let mut name = [0u8; 8];
        f.seek(SeekFrom::Start(off)).map_err(BuildError::Io)?;
        f.read_exact(&mut name).map_err(BuildError::Io)?;
        if &name != b".reloc\0\0" {
            continue;
        }
        let mut b4 = [0u8; 4];
        f.seek(SeekFrom::Start(off + 8)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let vsize = u32::from_le_bytes(b4);
        f.seek(SeekFrom::Start(off + 12)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let va = u32::from_le_bytes(b4);
        f.seek(SeekFrom::Start(off + 16)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let rsize = u32::from_le_bytes(b4);
        f.seek(SeekFrom::Start(off + 20)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let rptr = u32::from_le_bytes(b4);
        if rsize > 0 {
            existing_reloc = Some((off, va, vsize, rsize, rptr));
            break;
        }
    }
    if let Some((hdr_off, va, vsize, rsize, rptr)) = existing_reloc {
        let body = build_pe_base_relocation_table(relocations);
        let body_size = body.len() as u32;
        // Prefer our canonical table layout; when it does not fit the
        // section's raw data, keep the bytes objcopy already wrote and
        // size the directory from what is actually backed by the file.
        let dir_size = if body_size <= rsize {
            f.seek(SeekFrom::Start(rptr as u64))
                .map_err(BuildError::Io)?;
            f.write_all(&body).map_err(BuildError::Io)?;
            let pad = rsize as usize - body.len();
            if pad > 0 {
                f.write_all(&vec![0u8; pad]).map_err(BuildError::Io)?;
            }
            body_size
        } else {
            vsize.min(rsize)
        };
        f.seek(SeekFrom::Start(hdr_off + 8))
            .map_err(BuildError::Io)?;
        f.write_all(&dir_size.to_le_bytes())
            .map_err(BuildError::Io)?;
        let ddir_off = opt_off + 0x70 + 5u64 * 8;
        f.seek(SeekFrom::Start(ddir_off)).map_err(BuildError::Io)?;
        f.write_all(&va.to_le_bytes()).map_err(BuildError::Io)?;
        f.write_all(&dir_size.to_le_bytes())
            .map_err(BuildError::Io)?;
        f.seek(SeekFrom::Start(opt_off + 0x6C))
            .map_err(BuildError::Io)?;
        f.write_all(&16u32.to_le_bytes()).map_err(BuildError::Io)?;
        let wanted_image_end = va.saturating_add(dir_size);
        let wanted_image_size = wanted_image_end
            .checked_next_multiple_of(section_align)
            .unwrap_or(wanted_image_end);
        f.seek(SeekFrom::Start(opt_off + 0x38))
            .map_err(BuildError::Io)?;
        let mut b4 = [0u8; 4];
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        if wanted_image_size > u32::from_le_bytes(b4) {
            f.seek(SeekFrom::Start(opt_off + 0x38))
                .map_err(BuildError::Io)?;
            f.write_all(&wanted_image_size.to_le_bytes())
                .map_err(BuildError::Io)?;
        }
        log::info(&format!(
            "inject_stub_reloc_section: reused existing .reloc (va=0x{:x}, dir_size={})",
            va, dir_size
        ));
        return Ok(());
    }

    // A freshly appended section header must not land inside any
    // existing section's raw data (objcopy places the section table
    // immediately before the first section's data). Shift the file
    // tail by whole file-aligned blocks and move the affected raw
    // pointers instead of letting the header overwrite real code.
    let new_hdr_off = sec_table_off + num_sections as u64 * 40;
    let mut shift_from: Option<u64> = None;
    for i in 0..num_sections {
        let off = sec_table_off + i as u64 * 40;
        let mut b4 = [0u8; 4];
        f.seek(SeekFrom::Start(off + 16)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let raw_size = u32::from_le_bytes(b4);
        if raw_size == 0 {
            continue;
        }
        f.seek(SeekFrom::Start(off + 20)).map_err(BuildError::Io)?;
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let start = u32::from_le_bytes(b4) as u64;
        let end = start + raw_size as u64;
        if new_hdr_off + 40 > start && new_hdr_off < end {
            shift_from = Some(match shift_from {
                Some(prev) => prev.min(start),
                None => start,
            });
        }
    }
    if let Some(from) = shift_from {
        let need = new_hdr_off + 40 - from;
        let shift = need.div_ceil(file_align as u64) * file_align as u64;
        let file_len = f.metadata().map_err(BuildError::Io)?.len();
        f.seek(SeekFrom::Start(from)).map_err(BuildError::Io)?;
        let mut tail = Vec::with_capacity((file_len - from) as usize);
        f.read_to_end(&mut tail).map_err(BuildError::Io)?;
        f.seek(SeekFrom::Start(from)).map_err(BuildError::Io)?;
        f.write_all(&vec![0u8; shift as usize])
            .map_err(BuildError::Io)?;
        f.write_all(&tail).map_err(BuildError::Io)?;
        for i in 0..num_sections {
            let off = sec_table_off + i as u64 * 40;
            let mut b4 = [0u8; 4];
            f.seek(SeekFrom::Start(off + 16)).map_err(BuildError::Io)?;
            f.read_exact(&mut b4).map_err(BuildError::Io)?;
            let raw_size = u32::from_le_bytes(b4);
            if raw_size == 0 {
                continue;
            }
            f.seek(SeekFrom::Start(off + 20)).map_err(BuildError::Io)?;
            f.read_exact(&mut b4).map_err(BuildError::Io)?;
            let raw_off = u32::from_le_bytes(b4) as u64;
            if raw_off >= from {
                f.seek(SeekFrom::Start(off + 20)).map_err(BuildError::Io)?;
                f.write_all(&((raw_off + shift) as u32).to_le_bytes())
                    .map_err(BuildError::Io)?;
            }
        }
        // The section table now extends past the original header
        // region, so widen SizeOfHeaders to cover it.
        let headers_end = (new_hdr_off + 40).div_ceil(file_align as u64) * file_align as u64;
        f.seek(SeekFrom::Start(opt_off + 0x3C))
            .map_err(BuildError::Io)?;
        let mut b4 = [0u8; 4];
        f.read_exact(&mut b4).map_err(BuildError::Io)?;
        let cur_headers = u32::from_le_bytes(b4) as u64;
        if headers_end > cur_headers {
            f.seek(SeekFrom::Start(opt_off + 0x3C))
                .map_err(BuildError::Io)?;
            f.write_all(&(headers_end as u32).to_le_bytes())
                .map_err(BuildError::Io)?;
        }
        log::info(&format!(
            "inject_stub_reloc_section: shifted file tail from 0x{:x} by {} bytes to make room for the section header",
            from, shift
        ));
    }

    // Compute where to place the new section body. Walk all existing
    // sections to find the end of the *actual data* (PointerToRawData
    // + SizeOfRawData), then round up to the next FileAlignment
    // boundary. Using `file_len` directly is wrong because the file
    // might have been padded by objcopy to align the last section's
    // data to FileAlignment — we only want to write past the actual
    // content, not past objcopy's padding.
    let mut last_data_end: u64 = 0;
    for i in 0..num_sections {
        let off = sec_table_off + i as u64 * 40;
        let raw_off = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(off + 20)).map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        let raw_size = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(off + 16)).map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        if raw_size > 0 {
            let end = (raw_off as u64) + (raw_size as u64);
            if end > last_data_end {
                last_data_end = end;
            }
        }
    }
    // Guarantee `body_off` is past every byte of the input file —
    // otherwise the loader's `ImageRead` probe at
    // `PointerToRawData + SizeOfRawData - 1` could fall into a
    // region that's just objcopy-injected padding (e.g. tail debug
    // info) rather than real section content, and fail with
    // `EFI_UNSUPPORTED`. Using max(section_end, file_len) makes
    // the choice robust regardless of objcopy's section-content
    // accounting.
    let file_len = f.metadata().map_err(BuildError::Io)?.len();
    last_data_end = last_data_end.max(file_len);
    // Round up to FileAlignment — section data must start at a
    // FileAlignment boundary.
    let body_off = (last_data_end + file_align as u64 - 1) & !(file_align as u64 - 1);

    // Walk the existing sections to find the end of the last
    // virtual region so we can place `.reloc` after it without
    // overlapping anything.
    let mut last_va_end: u32 = 0;
    for i in 0..num_sections {
        let off = sec_table_off + i as u64 * 40;
        let va = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(off + 12)).map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        let vs = u32::from_le_bytes({
            let mut b = [0u8; 4];
            f.seek(SeekFrom::Start(off + 8)).map_err(BuildError::Io)?;
            f.read_exact(&mut b).map_err(BuildError::Io)?;
            b
        });
        let end = va.saturating_add(vs);
        if end > last_va_end {
            last_va_end = end;
        }
    }
    let reloc_va = (last_va_end + section_align - 1) & !(section_align - 1);
    let reloc_va = (image_extent_rva as u64)
        .checked_next_multiple_of(section_align as u64)
        .map(|aligned| reloc_va.max(aligned as u32))
        .unwrap_or(reloc_va);

    // Write the stub relocation block: 8-byte header
    //   VirtualAddress = reloc_va (page-aligned, must point to a
    //                            mapped image page)
    //   SizeOfBlock    = 8  (header only — no entries)
    //
    // The loader walks SizeOfBlock chunks; an 8-byte block with no
    // 16-bit entries is a perfectly valid "no relocations here"
    // marker that still makes `RelocationsStripped` evaluate to
    // false. The VirtualAddress field has to be a *mapped* page RVA
    // (EDK2's PeCoffLoaderRelocateImage skips zero-RVA blocks with
    // `EFI_NOT_FOUND`); reloc_va is always page-aligned because we
    // compute it as `data_end + section_align - 1` rounded down.
    //
    // The block is then followed by a single
    // `IMAGE_REL_BASED_DIR64` (type 10, value 0x10) relocation entry
    // pointing at .text RVA=0, which signals to the loader that the
    // image needs a 64-bit delta-base relocation pass and that the
    // stub entrypoint will be relocated to ImageBase at runtime.
    // EDK2's loader rejects images whose `.reloc` section is empty
    // (8-byte header, no entries) with `EFI_UNSUPPORTED` on some
    // architectures, so we emit a real but trivial entry to satisfy
    // the loader while still having no observable effect on the
    // image once it has been loaded.
    let body = build_pe_base_relocation_table(relocations);
    let body_size = body.len() as u32;
    let raw_size = body_size
        .checked_next_multiple_of(file_align)
        .unwrap_or(file_align);

    // Pad the file out to body_off, then write the 8-byte stub
    // header followed by file-aligned padding so the section's
    // `PointerToRawData + SizeOfRawData - 1` byte actually exists
    // in the file. Without the trailing pad, the loader's
    // `ImageRead(ImageContext,
    //   PointerToRawData + SizeOfRawData - 1,
    //   ...) probe trips `EFI_UNSUPPORTED` because the seek
    // falls into a hole.
    f.seek(SeekFrom::Start(body_off)).map_err(BuildError::Io)?;
    f.write_all(&body).map_err(BuildError::Io)?;
    // Zero-pad the remainder of the file-aligned block so the
    // section's full SizeOfRawData is mapped in.
    let pad_len = raw_size as usize - body.len();
    if pad_len > 0 {
        let pad = vec![0u8; pad_len];
        f.write_all(&pad).map_err(BuildError::Io)?;
    }

    // Write the section header right after the existing table.
    let new_sec_hdr_off = sec_table_off + num_sections as u64 * 40;
    let sh: [u8; 40] = [
        // Name ".reloc\0\0" (8 bytes)
        b'.',
        b'r',
        b'e',
        b'l',
        b'o',
        b'c',
        0,
        0,
        // VirtualSize (4) — matches the in-memory body length (header
        // + 1 IMAGE_REL_BASED_DIR64 entry = 16 bytes). EDK2 reads
        // VirtualSize when scanning the reloc DataDirectory.
        body_size.to_le_bytes()[0],
        body_size.to_le_bytes()[1],
        body_size.to_le_bytes()[2],
        body_size.to_le_bytes()[3],
        // VirtualAddress (4) — RVA relative to ImageBase
        reloc_va.to_le_bytes()[0],
        reloc_va.to_le_bytes()[1],
        reloc_va.to_le_bytes()[2],
        reloc_va.to_le_bytes()[3],
        // SizeOfRawData (4) — file-aligned (file_align is 0x200, > 16)
        raw_size.to_le_bytes()[0],
        raw_size.to_le_bytes()[1],
        raw_size.to_le_bytes()[2],
        raw_size.to_le_bytes()[3],
        // PointerToRawData (4)
        (body_off as u32).to_le_bytes()[0],
        (body_off as u32).to_le_bytes()[1],
        (body_off as u32).to_le_bytes()[2],
        (body_off as u32).to_le_bytes()[3],
        // PointerToRelocations (4) — zero for PE images
        0,
        0,
        0,
        0,
        // PointerToLinenumbers (4)
        0,
        0,
        0,
        0,
        // NumberOfRelocations (2)
        0,
        0,
        // NumberOfLinenumbers (2)
        0,
        0,
        // Characteristics (4) —
        //   IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        //   = 0x40000040.
        // The previous `| IMAGE_SCN_MEM_DISCARDABLE` made the loader
        // skip the section during its section-end probe (the
        // `PeCoffLoaderGetImageInfo` loop at MdePkg/BasePeCoffLib/BasePeCoff.c
        // line 497 only runs its data-range check when
        // `SizeOfRawData > 0`, regardless of the flag), but EDK2's
        // relocation walk explicitly tests `MEM_DISCARDABLE` and
        // refuses to process a reloc section with that flag set.
        // Omitting it is the right choice — UEFI is still free to
        // drop the section after RelocateImage completes.
        0x4000_0040u32.to_le_bytes()[0],
        0x4000_0040u32.to_le_bytes()[1],
        0x4000_0040u32.to_le_bytes()[2],
        0x4000_0040u32.to_le_bytes()[3],
    ];
    f.seek(SeekFrom::Start(new_sec_hdr_off))
        .map_err(BuildError::Io)?;
    f.write_all(&sh).map_err(BuildError::Io)?;

    // NumberOfSections += 1.
    let new_num = num_sections + 1;
    f.seek(SeekFrom::Start(coff_off + 2))
        .map_err(BuildError::Io)?;
    f.write_all(&new_num.to_le_bytes())
        .map_err(BuildError::Io)?;

    // SizeOfImage = max(old_size, reloc_va + section_align)
    let new_size_image = (reloc_va + body_size)
        .checked_next_multiple_of(section_align)
        .unwrap_or(reloc_va + section_align);
    f.seek(SeekFrom::Start(opt_off + 0x38))
        .map_err(BuildError::Io)?;
    f.write_all(&new_size_image.to_le_bytes())
        .map_err(BuildError::Io)?;

    // DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC] =
    //   { VirtualAddress = reloc_va, Size = 16 }
    //
    // PE32+ OptionalHeader layout (240 bytes total):
    //   opt+0x00  Magic (2)              0x020B
    //   opt+0x02  Linker major (1)
    //   opt+0x03  Linker minor (1)
    //   opt+0x04  TextSize (4)
    //   opt+0x08  InitDataSize (4)
    //   opt+0x0C  UninitDataSize (4)
    //   opt+0x10  EntryPointRVA (4)
    //   opt+0x14  BaseOfCode (4)
    //   opt+0x18  ImageBase (8)
    //   opt+0x20  SectionAlignment (4)
    //   opt+0x24  FileAlignment (4)
    //   opt+0x28  OS major (2)
    //   opt+0x2A  OS minor (2)
    //   opt+0x2C  Image major (2)
    //   opt+0x2E  Image minor (2)
    //   opt+0x30  Subsystem major (2)
    //   opt+0x32  Subsystem minor (2)
    //   opt+0x34  Win32Version (4)
    //   opt+0x38  SizeOfImage (4)
    //   opt+0x3C  SizeOfHeaders (4)
    //   opt+0x40  CheckSum (4)
    //   opt+0x44  Subsystem (2)
    //   opt+0x46  DllCharacteristics (2)
    //   opt+0x48  SizeOfStackReserve (8)
    //   opt+0x50  SizeOfStackCommit (8)
    //   opt+0x58  SizeOfHeapReserve (8)
    //   opt+0x60  SizeOfHeapCommit (8)
    //   opt+0x68  LoaderFlags (4)
    //   opt+0x6C  NumberOfRvaAndSizes (4)
    //   opt+0x70  DataDirectory[0] (8)   ← IMAGE_DIRECTORY_ENTRY_EXPORT
    //   ...
    //   opt+0x98  DataDirectory[5] (8)   ← IMAGE_DIRECTORY_ENTRY_BASERELOC
    //
    // The DataDirectory array starts at opt+0x70 and each entry is 8
    // bytes. ImageBase (opt+0x18) is 8 bytes wide for PE32+, so the
    // layout diverges from PE32 (where ImageBase is 4 bytes and the
    // DataDirectory array starts at opt+0x60). Earlier versions of
    // this function applied the PE32 offsets to a PE32+ image, which
    // silently corrupted the heap/commit fields and left
    // NumberOfRvaAndSizes pointing into SizeOfHeapReserve — EDK2's
    // loader then refused the image with `EFI_UNSUPPORTED`.
    let ddir_off = opt_off + 0x70 + 5u64 * 8;
    log::info(&format!(
        "inject_stub_reloc_section: ddir_off=0x{:x} (opt_off=0x{:x}), \
         reloc_va=0x{:x}, fixups={}, table_size={}",
        ddir_off,
        opt_off,
        reloc_va,
        relocations.len(),
        body_size
    ));
    f.seek(SeekFrom::Start(ddir_off)).map_err(BuildError::Io)?;
    f.write_all(&reloc_va.to_le_bytes())
        .map_err(BuildError::Io)?;
    f.write_all(&body_size.to_le_bytes())
        .map_err(BuildError::Io)?;

    // Also set NumberOfRvaAndSizes to 16 so EDK2's PE/COFF loader
    // recognises the full DataDirectory table.  `pei-<arch>` leaves
    // this at 0, which makes the loader think there are no
    // data directories at all and reject the image. For PE32+ this
    // field sits at opt+0x6C (just before the DataDirectory array at
    // opt+0x70); the previous code wrote to opt+0x5E, which landed
    // inside SizeOfHeapCommit and corrupted that field.
    let nrva_off = opt_off + 0x6C;
    f.seek(SeekFrom::Start(nrva_off)).map_err(BuildError::Io)?;
    f.write_all(&16u32.to_le_bytes()).map_err(BuildError::Io)?;
    log::info(&format!(
        "inject_stub_reloc_section: wrote NumberOfRvaAndSizes=16 at 0x{:x}",
        nrva_off
    ));

    log::info(&format!(
        "Injected stub .reloc section at VA=0x{:x}, body_off=0x{:x}",
        reloc_va, body_off
    ));
    Ok(())
}

/// Build the boot manager
pub fn build_boot(target: &str) -> Result<PathBuf> {
    log::section("Building Boot Manager");
    log::info(&format!("Target: {}", target));

    let workspace_root = get_workspace_root();
    // Ensure the LoongArch64 libgcc stub exists before invoking
    // cargo; the linker for `loongarch64-unknown-none` fails with
    // `cannot find -lgcc` otherwise (see `ensure_loongarch_libgcc_stub`
    // for the full rationale).
    ensure_loongarch_libgcc_stub_for_target(target)?;
    // Cargo only auto-loads `.cargo/config.toml` from ancestors of
    // the *current working directory*. The per-crate configs in
    // `src/boot/.cargo/config.toml` (RISC-V / LoongArch linker
    // flags) and `src/winload/.cargo/config.toml` only take effect
    // when `cargo` is invoked from inside the crate directory, so
    // we explicitly set `current_dir` to the package manifest path
    // (the `boot` directory) before running the build. Running from
    // the workspace root would silently drop those settings and
    // fall back to plain `rust-lld`, producing a bare ELF that EDK2
    // cannot dispatch.
    let boot_dir = workspace_root.join("src").join("boot");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&boot_dir);
    cmd.arg("build");
    cmd.arg("--release");
    cmd.arg("--target").arg(target);
    cmd.arg("-p").arg("nt61-boot");
    // The `nt61-boot` [[bin]] entry in `src/boot/Cargo.toml` gates the
    // executable behind `required-features = ["x86_64"]` because the
    // boot manager still contains x86_64-specific inline-asm and a
    // GOP framebuffer layout that is not yet portable. Without the
    // matching `--features x86_64` here, cargo only compiles
    // `libnt61_boot.rlib` and the downstream pipeline fails with
    // "File not found: target/<arch>/release/nt61-boot.efi".
    cmd.arg("--features").arg(loader_features(target));

    log::info("Running cargo build...");
    let status = cmd.status().map_err(BuildError::Io)?;

    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "Boot build failed with exit code: {:?}",
            status.code()
        )));
    }

    // The boot binary name differs by target:
    //   * x86_64-unknown-uefi / aarch64-unknown-uefi  → nt61-boot.efi
    //     (rust-lld already emits real PE32+ for those `*-unknown-uefi`
    //     targets, so we use the file directly).
    //   * loongarch64 / riscv64 (no upstream `*-unknown-uefi` target
    //     yet) → GNU binutils (`-O pei-<arch>`) synthesises a real
    //     PE32+ image from our plain ELF, with a proper section
    //     table. Without this conversion EDK2's PE/COFF loader can
    //     read the MZ magic + e_lfanew fine, but it refuses to
    //     execute the image because the section table is empty /
    //     mismatched.
    let target_dir = workspace_root.join("target").join(target).join("release");
    let canonical = target_dir.join("nt61-boot.efi");
    let bare = target_dir.join("nt61-boot");
    // For RISC-V / LoongArch64 the rustc-built `nt61-boot.efi` is a
    // *plain ELF wrapper* masquerading under the `.efi` extension — the
    // cross-binutils `pei-<arch>` conversion to a real PE32+ is done by
    // the `else if bare.exists()` branch below. To avoid silently
    // re-using a stale PE produced by a previous tool version (which
    // would carry the unwanted `.comment` / `.bss..L_Merg[...]` /
    // `.riscv.attributes` sections that EDK2's PE/COFF loader rejects
    // with `EFI_UNSUPPORTED`), force the wrapper path whenever the
    // host architecture has no `*-unknown-uefi` target.
    let is_la64 = target.starts_with("loongarch64");
    let is_rv64 = target.starts_with("riscv64");
    let force_wrap = is_la64 || is_rv64;
    let output = if canonical.exists() && !force_wrap {
        canonical
    } else if bare.exists() {
        if is_la64 || is_rv64 {
            // Convert the ELF wrapper into a real PE32+ binary by
            // running the cross binutils `objcopy -O pei-<arch>`.
            // The GCC cross-toolchain ships its own pei target for
            // every architecture it supports, so this works out of
            // the box on Debian/Ubuntu without any custom linker
            // script or hand-rolled DOS/PE header bytes.
            // The cross binutils' PE target names are:
            //   * loongarch64  -> `pei-loongarch64`
            //   * riscv64      -> `pei-riscv64-little`
            //
            // The RISC-V target name is **not** symmetric with the
            // ELF name `elf64-littleriscv`: binutils uses the older
            // `little` suffix on the PE target because the
            // `littleriscv` (no-dash) variant was added later and
            // never retro-applied to the pei- target. Trying
            // `pei-riscv64-littleriscv` causes objcopy to fail with
            // `invalid bfd target`, which used to silently fall
            // through to the plain-ELF fallback — that produced a
            // `BOOTRISCV64.EFI` containing raw ELF bytes that EDK2's
            // image loader could not dispatch.
            let (objcopy, target_fmt) = if is_la64 {
                ("loongarch64-linux-gnu-objcopy", "pei-loongarch64")
            } else {
                ("riscv64-linux-gnu-objcopy", "pei-riscv64-little")
            };
            log::info(&format!(
                "Wrapping ELF -> PE32+ via {} -O {} for {}",
                objcopy, target_fmt, target
            ));
            // Drop the ELF metadata sections (`/DISCARD/` from the
            // linker script strips them from the executable output,
            // but `objcopy -O pei-<arch>` parses the ELF *input*
            // and copies every section — including the hand-rolled
            // `.efi_header` bytes — into the resulting PE's section
            // table). EDK2's PE/COFF loader rejects unknown or empty
            // sections, so we ask objcopy to remove them explicitly
            // before the conversion. `--remove-section` accepts
            // partial matches and is a no-op for sections that
            // don't exist, so the same command works whether the
            // linker dropped them or not.
            let status = Command::new(objcopy)
                .arg("-O")
                .arg(target_fmt)
                // GNU `objcopy -O pei-<arch>` keeps the input ELF's debug
                // info in the resulting PE file even when the linker
                // drops it (the source file is read section-by-section
                // and only the named ones are dropped). For rustc
                // --release on `*-unknown-none` targets the trailing
                // junk is a ~24 KiB `.file` symbol table that lives
                // past the last `PointerToRawData + SizeOfRawData`
                // boundary, which breaks the file-end accounting in
                // `inject_stub_reloc_section` and trips
                // EDK2's section-end probe with `EFI_UNSUPPORTED`.
                // `--strip-all` (== `-g -S`) drops every symbol,
                // debug, and relocation entry that isn't strictly
                // required, leaving a clean `.text + .data` PE.
                .arg("--strip-all")
                // The .efi_header pseudo-section has been hand-rolled
                // to hold the initial PE/COFF headers; we want it
                // gone before the post-link patches rewrite the
                // OptionalHeader in-place to avoid the loader seeing
                // a duplicate header in the section table.
                .arg("--remove-section=.efi_header")
                // GNU binutils leaves RISC-V/LoongArch-specific ELF
                // metadata sections (`.comment`, `.riscv.attributes`,
                // `.loongarch.attributes`) and rustc's
                // `.bss..L_MergedGlobals-<hash>` placeholder in the
                // output PE table even after `--strip-all`. The first
                // two end up as truncated `/<n>` PE section names that
                // reference the COFF string table — EDK2's PE/COFF
                // loader handles such names but treats the section
                // *contents* as raw symbol-table bytes and fails to
                // dispatch the image with `EFI_UNSUPPORTED`. The
                // `.bss*` placeholder has `PointerToRawData=0`,
                // `SizeOfRawData=0`, but a non-zero `VirtualAddress`;
                // its presence makes EDK2 think the image base has
                // two unlinked sections and aborts validation.
                //
                // Drop all three here so `objcopy -O pei-<arch>` only
                // emits the canonical `.text + .data (+ .reloc)` we
                // expect. The wildcard forms (`*comments*`,
                // `*attributes*`, `.bss*`) cover RISC-V, LoongArch64,
                // and any future architecture that uses similar
                // metadata sections.
                .arg("--remove-section=.comment")
                .arg("--remove-section=.riscv.attributes")
                .arg("--remove-section=.loongarch.attributes")
                .arg("--remove-section=.rela*")
                .arg("--remove-section=.bss")
                .arg("--remove-section=.bss*")
                .arg(&bare)
                .arg(&canonical)
                .status()
                .map_err(BuildError::Io)?;
            if !status.success() {
                return Err(BuildError::ImageCreateFailed(format!(
                    "{} -O {} failed with exit code: {:?}",
                    objcopy,
                    target_fmt,
                    status.code()
                )));
            }
            // objcopy copies the ELF's section VMAs straight into the
            // PE section table.  Those VMAs include the linker's
            // `BASE_ADDRESS` (e.g. 0x01000000), so a `.text` that lives
            // at 0x01001000 in the ELF shows up as `VA=0x01001000` in
            // the resulting PE — but PE `VirtualAddress` is an RVA, so
            // the loader would map it at `ImageBase + 0x01001000` =
            // 0x02001000.  Rebase every section whose VA is >=
            // ImageBase back to a plain RVA *before* any other PE
            // patch runs — `patch_pe_subsystem` walks the section
            // table to decide where to drop the new `.reloc` section,
            // and reading pre-rebased VAs there produces garbage.
            if let Ok((_entry, _boc, image_base)) = read_elf_image_layout(&bare) {
                let boot_relocations =
                    read_elf_absolute_relocations(&bare, image_base).unwrap_or_default();
                let image_extent_rva = read_elf_image_extent(&bare)
                    .map(|extent| extent.saturating_sub(image_base) as u32)
                    .unwrap_or(0);
                if let Err(e) = patch_pe_section_addresses(&canonical, image_base) {
                    log::warn(&format!(
                        "PE section-address rebase failed for boot \
                         ({}); continuing anyway",
                        e,
                    ));
                }
                if let Err(e) = patch_pe_section_characteristics(&canonical) {
                    log::warn(&format!(
                        "PE section-characteristics patch failed for boot ({}); continuing anyway",
                        e
                    ));
                }
                // GNU binutils' `pei-<arch>` target synthesises a
                // PE32+ image but leaves the OptionalHeader.Subsystem
                // field at 0 (`IMAGE_SUBSYSTEM_UNKNOWN`). EDK2's
                // EFI image loader refuses to dispatch an image
                // whose subsystem isn't EFI Application (0x0A), so
                // we patch it in-place after the conversion.
                //
                // OptionalHeader layout (PE32+):
                //   offset 0x00  Magic (USHORT) — 0x020B
                //   offset 0x44  Subsystem (USHORT)
                //
                // The OptionalHeader starts at `e_lfanew + 4 (PE\0\0)
                //  + 20 (COFF FileHeader)`. We read `e_lfanew` from
                // the DOS header, derive the optional-header address,
                // and rewrite the two-byte Subsystem field directly.
                patch_pe_subsystem_with_extent(
                    &canonical,
                    0x0A,
                    &boot_relocations,
                    image_extent_rva,
                )?;
                // The pei-<arch> target also zeroes
                // `AddressOfEntryPoint`, `BaseOfCode`, and `ImageBase`
                // — EDK2 rejects the resulting image as `Unsupported`
                // because it cannot determine where to start execution
                // nor how to relocate sections. Recover the values
                // from the ELF we just wrapped.
                if let Err(e) =
                    patch_pe_entry_point_and_image_base(&canonical, _entry, _boc, image_base)
                {
                    log::warn(&format!(
                        "PE entry-point/ImageBase patch failed for boot \\
                         ({}); continuing anyway",
                        e,
                    ));
                }
            } else {
                // Fall back to the original ordering if we couldn't
                // recover ImageBase from the ELF — `patch_pe_subsystem`
                // still does its core job (Subsystem + alignments +
                // stub .reloc section) even with non-rebased VAs.
                patch_pe_subsystem(&canonical, 0x0A, &[])?;
            }
            canonical
        } else {
            // The non-UEFI target produces a plain ELF — copy it to a
            // `.efi` filename so the rest of the build pipeline
            // (which assumes `BOOT<ARCH>.EFI`) can consume it
            // uniformly. The firmware will of course refuse to load
            // an ELF as a PE — that's a separate problem to solve
            // by adding a `<arch>-unknown-uefi` target.
            log::warn(&format!(
                "Boot binary lacks .efi extension; copying {} -> {}",
                bare.display(),
                canonical.display()
            ));
            if let Some(parent) = canonical.parent() {
                std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
            }
            std::fs::copy(&bare, &canonical).map_err(BuildError::Io)?;
            canonical
        }
    } else {
        return Err(BuildError::MissingFile(canonical.display().to_string()));
    };

    log::success(&format!("Boot manager built: {}", output.display()));
    Ok(output)
}

// =====================================================================
// Winload Build
// =====================================================================

/// Build the winload (OS loader)
pub fn build_winload(target: &str) -> Result<PathBuf> {
    log::section("Building Winload");
    log::info(&format!("Target: {}", target));

    let workspace_root = get_workspace_root();
    // Ensure the LoongArch64 libgcc stub exists before invoking
    // cargo; see the matching call in `build_boot` for context.
    ensure_loongarch_libgcc_stub_for_target(target)?;
    // See the matching note in `build_boot`: cargo only reads
    // `.cargo/config.toml` from ancestors of the cwd, so the
    // per-architecture linker settings live in
    // `src/winload/.cargo/config.toml` and are only honoured when
    // we point cargo at the `winload` package directory.
    let winload_dir = workspace_root.join("src").join("winload");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&winload_dir);
    cmd.arg("build");
    cmd.arg("--release");
    cmd.arg("--target").arg(target);
    cmd.arg("-p").arg("nt61-winload");
    // The `nt61-winload` [[bin]] entry in `src/winload/Cargo.toml`
    // also gates the executable behind `required-features = ["x86_64"]`
    // (the OS-loader body still references x86_64-only trampolines /
    // kernel-jump symbols). Without `--features x86_64` cargo only
    // emits `libnt61_winload.rlib` and the disk image pipeline fails
    // when it looks for `nt61-winload.efi`.
    cmd.arg("--features").arg(loader_features(target));

    log::info("Running cargo build...");
    let status = cmd.status().map_err(BuildError::Io)?;

    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "Winload build failed with exit code: {:?}",
            status.code()
        )));
    }

    // See `build_boot` above: UEFI targets emit `nt61-winload.efi`,
    // LoongArch64 / RISC-V64 ELF outputs go through `objcopy -O
    // pei-<arch>` (the same wrapper that turns `nt61-boot` into a
    // valid PE32+ EFI application). Without this step EDK2's
    // `EFI_IMAGE_LOADER` parses the ELF's PE-COFF header but
    // rejects it because the section table is empty, and the
    // OS loader is never handed control.
    let target_dir = workspace_root.join("target").join(target).join("release");
    let canonical = target_dir.join("nt61-winload.efi");
    let bare = target_dir.join("nt61-winload");
    // For RISC-V / LoongArch64 the rustc-built `nt61-winload.efi` is a
    // plain ELF wrapper that doesn't look like a PE32+ to EDK2 until
    // `objcopy -O pei-<arch>` rewrites it. Re-use a stale `.efi` only
    // when the host arch has a real `*-unknown-uefi` target.
    let is_la64 = target.starts_with("loongarch64");
    let is_rv64 = target.starts_with("riscv64");
    let force_wrap = is_la64 || is_rv64;
    let output = if canonical.exists() && !force_wrap {
        // x86_64-unknown-uefi produces a valid PE32+ directly. The
        // `patch_pe_image_base` is currently a no-op for the x86_64
        // target (rust-lld already emits 0x140000000, the standard
        // UEFI x86_64 base) but is kept here so the patch behaviour
        // is uniformly controlled for any other arch that needs a
        // different preferred base.
        if let Err(e) = patch_pe_image_base(&canonical, 0x140000000u64) {
            log::warn(&format!(
                "winload ImageBase patch failed: {}; continuing with rustc default",
                e,
            ));
        }
        canonical
    } else if bare.exists() {
        let is_la64 = target.starts_with("loongarch64");
        let is_rv64 = target.starts_with("riscv64");
        if is_la64 || is_rv64 {
            // Wrap ELF -> PE32+ via GNU binutils `objcopy`. This
            // mirrors `build_boot` so the boot manager and the OS
            // loader share the same image format and the same
            // PE-Subsystem post-fix (binutils leaves Subsystem=0
            // which EDK2 refuses to dispatch).
            let (objcopy_bin, pei_target) = if is_rv64 {
                ("riscv64-linux-gnu-objcopy", "pei-riscv64-little")
            } else {
                ("loongarch64-linux-gnu-objcopy", "pei-loongarch64")
            };
            log::info(&format!(
                "Wrapping ELF -> PE32+ via {} -O {} for {}",
                objcopy_bin, pei_target, target,
            ));
            if let Some(parent) = canonical.parent() {
                std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
            }
            let wrap = std::process::Command::new(objcopy_bin)
                .arg("-O")
                .arg(pei_target)
                // See the comment in `build_boot` for the rationale.
                .arg("--strip-all")
                .arg("--remove-section=.efi_header")
                // Same metadata-section scrub as `build_boot`: see the
                // long-form explanation for why `.comment`,
                // `.riscv.attributes`, `.loongarch.attributes`, and
                // `.bss*` must all be removed before EDK2's PE
                // loader will accept the image.
                .arg("--remove-section=.comment")
                .arg("--remove-section=.riscv.attributes")
                .arg("--remove-section=.loongarch.attributes")
                .arg("--remove-section=.bss")
                .arg("--remove-section=.bss*")
                .arg(&bare)
                .arg(&canonical)
                .status();
            match wrap {
                Ok(s) if s.success() => {
                    // Same PE-Subsystem patch as in `build_boot`:
                    // binutils' `pei-<arch>` leaves
                    // OptionalHeader.Subsystem at 0
                    // (IMAGE_SUBSYSTEM_UNKNOWN); EDK2 refuses to
                    // dispatch images that are not
                    // IMAGE_SUBSYSTEM_EFI_APPLICATION (0x0A).
                    if let Ok((entry, base_of_code, image_base)) = read_elf_image_layout(&bare) {
                        let winload_relocations =
                            read_elf_absolute_relocations(&bare, image_base).unwrap_or_default();
                        let image_extent_rva = read_elf_image_extent(&bare)
                            .map(|extent| extent.saturating_sub(image_base) as u32)
                            .unwrap_or(0);
                        // Same section-Table rebase as in
                        // `build_boot`: PE section VirtualAddress
                        // must be an RVA relative to ImageBase, but
                        // `pei-<arch>` writes the absolute ELF VMA.
                        // This MUST run before `patch_pe_subsystem`,
                        // because the latter walks the section table
                        // to compute a place for the new `.reloc`
                        // section and would otherwise use the
                        // pre-rebased absolute VMAs.
                        if let Err(e) = patch_pe_section_addresses(&canonical, image_base) {
                            log::warn(&format!(
                                "PE32+ section rebase failed for \
                                 winload ({}); continuing anyway",
                                e,
                            ));
                        }
                        if let Err(e) = patch_pe_section_characteristics(&canonical) {
                            log::warn(&format!(
                                "PE32+ section-characteristics patch failed for winload ({}); continuing anyway",
                                e
                            ));
                        }
                        if let Err(e) = patch_pe_subsystem_with_extent(
                            &canonical,
                            0x0A,
                            &winload_relocations,
                            image_extent_rva,
                        ) {
                            log::warn(&format!(
                                "PE32+ subsystem patch failed for winload ({}); continuing anyway",
                                e,
                            ));
                        }
                        if let Err(e) = patch_pe_entry_point_and_image_base(
                            &canonical,
                            entry,
                            base_of_code,
                            image_base,
                        ) {
                            log::warn(&format!(
                                "PE32+ entry-point patch failed for \\
                                 winload ({}); continuing anyway",
                                e,
                            ));
                        }
                    } else {
                        // Fall back to the bare subsystem patch when
                        // ELF introspection fails — the loader will
                        // still at least see a valid Subsystem field.
                        if let Err(e) = patch_pe_subsystem(&canonical, 0x0A, &[]) {
                            log::warn(&format!(
                                "PE32+ subsystem patch failed for winload ({}); continuing anyway",
                                e,
                            ));
                        }
                    }
                    canonical
                }
                _ => {
                    log::warn(&format!(
                        "PE32+ wrapping for winload failed; falling back to ELF copy ({} -> {})",
                        bare.display(),
                        canonical.display(),
                    ));
                    std::fs::copy(&bare, &canonical).map_err(BuildError::Io)?;
                    canonical
                }
            }
        } else {
            log::warn(&format!(
                "Winload binary lacks .efi extension; copying {} -> {}",
                bare.display(),
                canonical.display()
            ));
            if let Some(parent) = canonical.parent() {
                std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
            }
            std::fs::copy(&bare, &canonical).map_err(BuildError::Io)?;
            canonical
        }
    } else {
        return Err(BuildError::MissingFile(canonical.display().to_string()));
    };

    log::success(&format!("Winload built: {}", output.display()));
    Ok(output)
}

// =====================================================================
// Full Build Pipeline
// =====================================================================

/// Run the full build pipeline.
///
/// `format` selects the System partition filesystem:
///   * `fat32` — both ESP and System are FAT32 (legacy layout)
///   * `ntfs`  — ESP is FAT32, System is NTFS (default Windows 7 layout)
///   * `ext4`  — ESP is FAT32, System is EXT4 (Linux-native)
pub fn full_build(build_dir: &Path, format: &str, _size_mb: u32, arch: &str) -> Result<PathBuf> {
    log::banner(
        "NT6.1.7601 Full Build",
        &format!("Format: {} / Arch: {}", format, arch),
    );

    let fs_choice = super::image::DualPartitionFs::parse(format).ok_or_else(|| {
        BuildError::InvalidParam(format!(
            "unknown --format-flag value: {} (expected fat32 | ntfs | ext4)",
            format
        ))
    })?;

    let k_target = kernel_target_for(arch);
    let u_target = uefi_target_for(arch);
    set_pe_arch(arch);
    set_pe_arch(arch);

    // Create build directories
    let dirs = get_build_dir(build_dir);
    log::info(&format!("Build directory: {}", dirs.root.display()));

    crate::fs::dir::create_dir_all(&dirs.esp)?;
    crate::fs::dir::create_dir_all(&dirs.images)?;
    crate::fs::dir::create_dir_all(&dirs.system)?;

    // Step 1: Build kernel for the target architecture. A failure
    // here aborts the pipeline — there is no point in continuing
    // to build the boot manager or winload, both of which depend
    // on the kernel symbols being present in their build graph,
    // nor is there a usable disk image without all three pieces.
    let kernel = build_kernel(k_target)?;

    // Step 2: Build boot manager for the target architecture.
    let boot = build_boot(u_target)?;

    // Step 3: Build winload for the target architecture.
    let winload = build_winload(u_target)?;

    // Build the user-mode and driver PE artifacts for the selected
    // architecture. This step is essential for non-x86 targets: without
    // it, the generator would otherwise fall back to stale x86_64 files.
    build_userland_images(arch)?;

    // Step 4: Build the ESP (FAT32 boot partition) tree under
    // `<build-dir>/esp`. Only EFI/* content goes here.
    log::section("Building ESP");
    // The boot-screen font is license-safe and monospaced so the
    // UEFI text layout is aligned. A real NT6.1 install would ship
    // its own boot fonts; here we install DejaVu Sans Mono.
    let font_path = get_workspace_root()
        .join("resources")
        .join("fonts")
        .join("dejavu-fonts-XXXX")
        .join("DejaVuSansMono.ttf");
    let arch_label = match arch {
        "x86_64" | "x64" => "X64",
        "aarch64" | "arm64" => "AA64",
        "riscv64" => "RISCV64",
        "loongarch64" => "LOONGARCH64",
        _ => "X64",
    };
    super::esp::EspBuilder::new(&dirs.esp, arch_label)?
        .with_boot_efi(if boot.exists() { Some(&boot) } else { None })?
        .with_font(Some(&font_path))
        // winload.efi is NOT placed on ESP. Per Windows 7 layout:
        //   - ESP contains: BOOTX64.EFI, bootmgfw.efi, BCD, Fonts
        //   - System partition contains: Windows\System32\winload.efi
        // The BCD's ApplicationPath points to \Windows\System32\winload.efi
        // .with_winload()  <-- deliberately omitted: winload.efi belongs on System partition
        .build()?;
    super::esp::EspBuilder::write_bcd_file(&dirs.esp, &crate::hive_gen::build_bcd())?;

    // Step 5: Build the system partition tree under `<build-dir>/system`.
    // This is the Windows 7 system root, with the OS loader, kernel,
    // HAL, registry hives, and driver store at their canonical paths.
    log::section("Building System Partition");

    // The kernel ELF (`kernel`) is NOT used directly here. We
    // generate the on-disk PE files for ntoskrnl.exe, hal.dll,
    // ntdll.dll, kernel32.dll, and smss.exe from the kernel's
    // `system_image` module and drop them into
    // `<system>/Windows/System32/`. The placeholder paths are kept
    // only for tracing.
    let _kernel = kernel;

    // Generate PE files first.
    generate_system_pe_files(arch, &dirs.system)?;

    super::system::SystemBuilder::new(&dirs.system)?
        // Skip kernel/HAL — already generated above.
        .with_kernel(None)
        .with_hal(None)
        // Copy winload.efi at its canonical path.
        .with_winload(if winload.exists() {
            Some(winload.as_path())
        } else {
            None
        })
        // Install autoexec.bat at C:\tests\autoexec.bat so the CMD shell
        // can run it directly via `tests\autoexec.bat` or `call tests\autoexec.bat`.
        .add_autoexec_bat(
            get_workspace_root()
                .join("resources")
                .join("bat")
                .join("autoexec.bat"),
        )
        .build()?;

    // Step 6: Create dual-partition disk image for NT6.1.7601
    // Layout:
    // - Partition 1: ESP (FAT32) - EFI boot files (EFI/Boot/..., EFI/Microsoft/Boot/...)
    // - Partition 2: System (NTFS/EXT4/FAT32) - Windows system files (Windows/System32/...)
    //
    // This matches a real NT6.1 installation where:
    // - Boot manager reads BCD from ESP
    // - BCD OsDevice points to \Device\HarddiskVolume1 (System partition)
    // - winload.efi is loaded from \Device\HarddiskVolume1\Windows\System32\winload.efi
    //
    // The System partition filesystem is selected by `format` / `fs_choice`.
    // See `DualPartitionFs` for the available options.
    log::section("Creating Dual-Partition Disk Image");
    let image_path = dirs.images.join("disk.img");

    // ESP: 64MB, System: 256MB
    super::image::create_dual_partition_image_with_fs(
        &image_path,
        64,           // ESP partition size in MB
        256,          // System partition size in MB
        &dirs.esp,    // ESP source directory (EFI/* files)
        &dirs.system, // System source directory (Windows/* files)
        fs_choice,
    )?;

    log::summary(6, 0);
    log::success(&format!("Build complete! Image: {}", image_path.display()));

    Ok(image_path)
}

// =====================================================================
// ISO Image Build
// =====================================================================
//
// Build a bootable ISO-9660 image. The ISO has a flat directory
// structure — no partition table, no separate ESP.  All files are
// placed directly at the ISO root:
//
//   /EFI/BOOT/BOOTX64.EFI        <- nt61-boot.efi (El Torito boot)
//   /EFI/Microsoft/Boot/BCD      <- BCD store
//   /EFI/Microsoft/Boot/winload.efi <- OS loader
//   /Windows/System32/...        <- kernel + system files
//   /ProgramData/...
//   /Program Files/...
//   /Program Files (x86)/...
//   /tests/autoexec.bat
//   /Users/...
//
// Winload reads the kernel PE directly from the ISO9660 volume
// via EFI_BLOCK_IO.

/// Build the ISO-9660 bootable image. Called by `--build iso`.
///
/// The ISO has a FLAT directory structure — no partition table, no
/// separate ESP.  All files are placed directly at the ISO root:
///
///   /EFI/BOOT/BOOTX64.EFI
///   /EFI/Microsoft/Boot/BCD
///   /EFI/Microsoft/Boot/winload.efi
///   /Windows/System32/...
///   /ProgramData/...
///   /Program Files/...
///   /Program Files (x86)/...
///   /tests/autoexec.bat
///   /Users/...
pub fn build_iso(build_dir: &Path, _format: &str, _size_mb: u32, arch: &str) -> Result<PathBuf> {
    log::banner(
        "NT6.1.7601 ISO Build",
        &format!("ISO-9660 / El Torito / Arch: {}", arch),
    );

    let dirs = get_build_dir(build_dir);
    log::info(&format!("Build directory: {}", dirs.root.display()));

    crate::fs::dir::create_dir_all(&dirs.images)?;
    crate::fs::dir::create_dir_all(&dirs.system)?;

    let k_target = kernel_target_for(arch);
    let u_target = uefi_target_for(arch);

    // Step 1: Build kernel. Failure here aborts the pipeline
    // immediately — see the matching comment in `full_build`.
    let kernel = build_kernel(k_target)?;

    // Step 2: Build boot manager
    let boot = build_boot(u_target)?;

    // Step 3: Build winload
    let winload = build_winload(u_target)?;

    build_userland_images(arch)?;

    // Step 5: Build the system partition tree under `<build>/system`
    log::section("Building System Partition");
    let _kernel = kernel;
    generate_system_pe_files(arch, &dirs.system)?;
    super::system::SystemBuilder::new(&dirs.system)?
        .with_kernel(None)
        .with_hal(None)
        .with_winload(if winload.exists() {
            Some(winload.as_path())
        } else {
            None
        })
        .add_autoexec_bat(
            get_workspace_root()
                .join("resources")
                .join("bat")
                .join("autoexec.bat"),
        )
        .build()?;

    // Step 6: Build the ISO-9660 image.
    //
    // Per the user's spec, the ISO has a FLAT directory structure
    // at the root level — no partition table, no separate ESP/system
    // regions.  The UEFI firmware boots from the El Torito entry
    // (BOOTX64.EFI), which reads BCD from the ISO and launches
    // winload.efi.  Winload reads the kernel PE from the same ISO
    // volume via the EFI_BLOCK_IO protocol on the CD-ROM device.
    //
    // Layout:
    //   /EFI/BOOT/BOOTX64.EFI       <- boot manager (El Torito)
    //   /EFI/Microsoft/Boot/BCD     <- BCD store
    //   /EFI/Microsoft/Boot/winload.efi <- OS loader
    //   /Windows/System32/...       <- kernel PE + system files
    //   /ProgramData/...
    //   /Program Files/...
    //   /Program Files (x86)/...
    //   /tests/autoexec.bat
    //   /Users/...
    //
    // The system tree is copied at ISO root level (not embedded
    // inside a FAT32 image).  Winload will read the kernel PE
    // directly from the ISO9660 volume.

    // Step 7: Build the ISO-9660 image
    log::section("Building ISO-9660 Image");
    let mut iso = super::iso9660::IsoImage::new();

    // Per-arch fallback EFI file name. OVMF's UEFI removable media fallback
    // looks for \EFI\BOOT\BOOT<arch>.EFI; the convention is "X64", "AA64",
    // "RISCV64", "LOONGARCH64".
    let iso_arch_label = match arch {
        "x86_64" | "x64" => "X64",
        "aarch64" | "arm64" => "AA64",
        "riscv64" => "RISCV64",
        "loongarch64" => "LOONGARCH64",
        _ => "X64",
    };

    // /EFI/BOOT/BOOT<arch>.EFI — UEFI removable media path (El Torito)
    if boot.exists() {
        let boot_data = std::fs::read(&boot)?;
        let boot_iso_path = format!("/EFI/BOOT/BOOT{}.EFI", iso_arch_label);
        iso.add_file(&boot_iso_path, &boot_data)?;
        log::info(&format!("  Added {}", boot_iso_path));
    } else {
        log::warn("  nt61-boot.efi not found; ISO may not be bootable via El Torito");
    }

    // /EFI/Microsoft/Boot/BCD
    let bcd_data = crate::hive_gen::build_bcd();
    iso.add_file("/EFI/Microsoft/Boot/BCD", &bcd_data)?;
    log::info("  Added /EFI/Microsoft/Boot/BCD");

    // /EFI/Microsoft/Boot/winload.efi — the OS loader
    if winload.exists() {
        let winload_data = std::fs::read(&winload)?;
        iso.add_file("/EFI/Microsoft/Boot/winload.efi", &winload_data)?;
        log::info("  Added /EFI/Microsoft/Boot/winload.efi");
    }

    // System tree at root level: Windows/, ProgramData/, Program Files/,
    // Program Files (x86)/, tests/, Users/
    if dirs.system.exists() {
        copy_tree_to_iso(&mut iso, &dirs.system, "")?;
    }

    // Set up El Torito boot catalog — points to BOOTX64.EFI in the ISO.
    // UEFI will load and execute the PE file directly (no emulation).
    iso.add_boot_catalog(&[])?;
    log::info("  El Torito boot catalog configured");

    let iso_bytes = iso.finalize()?;
    let iso_path = dirs.images.join("nt61.iso");
    std::fs::write(&iso_path, &iso_bytes).map_err(BuildError::Io)?;

    log::summary(7, 0);
    log::success(&format!("ISO built: {}", iso_path.display()));

    Ok(iso_path)
}

/// Recursively copy a host directory tree into an ISO image.
fn copy_tree_to_iso(iso: &mut super::iso9660::IsoImage, src: &Path, prefix: &str) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let img_path = format!("{}/{}", prefix.trim_end_matches('/'), name);
        if path.is_dir() {
            copy_tree_to_iso(iso, &path, &img_path)?;
        } else {
            let data = std::fs::read(&path)?;
            iso.add_file(&img_path, &data)?;
        }
    }
    Ok(())
}

// =====================================================================
// PE file generation
// =====================================================================
//
// The on-disk PE files (`ntoskrnl.exe`, `hal.dll`, `ntdll.dll`,
// `kernel32.dll`, `smss.exe`, ...) are produced by the
// `build-esp` binary, which depends on `nt61::system_image`. We
// invoke it as a subprocess because `fs/build.rs` itself has no
// direct dependency on the `nt61` crate.
//
// The binary must be built first; we run `cargo build
// --bin build-esp` if it does not exist yet. The tool reads the
// list of PE images from `nt61::system_image::build_all` and
// drops them into the system32 directory.
pub fn build_userland_images(arch: &str) -> Result<()> {
    let target = uefi_target_for(arch);
    let workspace_root = get_workspace_root();
    log::section("Building nt61-cmd");
    log::info(&format!("Target: {target}"));
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .arg("-p")
        .arg("nt61-cmd")
        .status()
        .map_err(BuildError::Io)?;
    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "nt61-cmd build failed with exit code: {status:?}"
        )));
    }

    log::section("Building nt61-driver");
    log::info(&format!("Target: {target}"));
    let mut driver_command = Command::new("cargo");
    driver_command
        .current_dir(&workspace_root)
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .arg("-p")
        .arg("nt61-driver");
    if matches!(arch, "riscv64" | "loongarch64") {
        // These two targets link the kernel and loader with the
        // freestanding `kernel_entry` symbol, but a boot driver must be
        // entered through `DriverEntry`. Setting `RUSTFLAGS` here
        // overrides the workspace entry symbol for this crate only.
        driver_command.env("RUSTFLAGS", "-C link-arg=-e -C link-arg=DriverEntry");
    }
    let status = driver_command.status().map_err(BuildError::Io)?;
    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "nt61-driver build failed with exit code: {status:?}"
        )));
    }

    Ok(())
}

fn generate_system_pe_files(arch: &str, system_dir: &Path) -> Result<()> {
    let system32 = system_dir.join("Windows").join("System32");
    std::fs::create_dir_all(&system32)?;
    set_pe_arch(arch);

    // Direct in-process call into build_esp's PE generator. This
    // avoids spawning a subprocess (which fails to link because
    // of pre-existing nt61 library issues with the host target)
    // and is also faster.
    generate_pe_files_in_process(system32.as_path())
}

/// In-process call into the `build_esp` library function. Mirrors
/// what the `build-esp --pe-only` CLI does, but skips the
/// subprocess entirely so we don't have to deal with the host
/// link issues of `nt61::system_image`.
fn generate_pe_files_in_process(system32_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(system32_dir).map_err(BuildError::Io)?;

    // Re-implement the generator here using stdlib-only PE writing.
    // The PE layout is defined by `build_pe_image` below; see
    // docs/winload.efi.md "PE Layouts" section for details.
    let images = build_system_images();
    let mut total: usize = 0;
    let mut driver_count: usize = 0;
    // The whole system tree is mirrored to the ESP earlier
    // during the `build_all` pipeline (after
    // `generate_pe_files_in_process` writes the PE files into
    // `system32`), so this function only writes the PE images
    // themselves — the rest of the layout is built on-disk by
    // the driver before this is called.
    for img in &images {
        let dest = system32_dir.join(img.name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(BuildError::Io)?;
        }
        std::fs::write(&dest, &img.bytes).map_err(BuildError::Io)?;
        if img.bytes.len() >= 2 && &img.bytes[0..2] == b"MZ" {
            log::info(&format!(
                "Generated PE: {:?} ({} bytes)",
                dest,
                img.bytes.len()
            ));
        } else {
            log::warn(&format!("Warning: {:?} is not a valid PE file", dest));
        }
        if img.name.starts_with("drivers/") {
            driver_count += 1;
        }
        total += img.bytes.len();
    }
    log::info(&format!(
        "Total PE files: {} ({} drivers, {} bytes)",
        images.len(),
        driver_count,
        total
    ));
    Ok(())
}

/// A single PE image produced by the in-process generator.
struct SystemImage {
    name: &'static str,
    bytes: Vec<u8>,
}

/// Generate the standard set of system PE images used by
/// winload.efi at boot. Mirrors `nt61::system_image::build_all`.
///
/// Drivers are written under `<system32>/drivers/<name>.sys`
/// (matching the canonical NT 6.1 layout). Without these .sys
/// files on disk, winload.efi's BOOT_START driver loader reports
/// "file missing" and the kernel's I/O manager cannot bring up
/// storage, network, or input devices during boot.
fn real_pe(artifact_name: &str) -> Vec<u8> {
    let arch = current_pe_arch();
    let stem = artifact_name.trim_end_matches(".efi");
    let mut candidates: Vec<String> = Vec::new();
    // The bare-metal kernel artifact is the canonical source of the
    // on-disk PE: it is linked as a PIC ELF with relocation records
    // and its entry (`kernel_entry`) reads the BootInfo pointer that
    // winload passes. The UEFI-target build of the same crate has a
    // different entry ABI, so it must never shadow the bare-metal
    // artifact just because it was rebuilt more recently. Order the
    // bare-metal candidates first and only fall back to the UEFI
    // target when no bare-metal artifact exists.
    for target in [
        kernel_target_for(arch_name(arch)),
        uefi_target_for(arch_name(arch)),
    ] {
        candidates.push(format!("target/{target}/release/{stem}"));
        candidates.push(format!("target/{target}/release/{stem}.efi"));
        for profile in ["release", "debug"] {
            let dir = format!("target/{target}/{profile}/deps");
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let matches = path
                        .file_stem()
                        .and_then(|file_stem| file_stem.to_str())
                        .map(|file_stem| file_stem.starts_with(stem))
                        .unwrap_or(false);
                    if matches {
                        candidates.push(path.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    // Prefer the freshest artifact. A stale MZ from an older build of the
    // other target (e.g. a leftover UEFI kernel from hours ago) must not
    // shadow the just-built kernel ELF from the bare-metal target, so we
    // order all existing candidates newest-first instead of relying on the
    // fixed directory preference order.
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let bare_metal = kernel_target_for(arch_name(arch));
    candidates.sort_by(|a, b| {
        let mtime_of = |rel: &str| -> std::time::SystemTime {
            std::fs::metadata(workspace_root.join(rel))
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        };
        // Within a target: newest first. Across targets: the
        // bare-metal artifact always wins over the UEFI one.
        let a_bare = a.contains(&format!("target/{bare_metal}/"));
        let b_bare = b.contains(&format!("target/{bare_metal}/"));
        b_bare.cmp(&a_bare).then(mtime_of(b).cmp(&mtime_of(a)))
    });

    for candidate in candidates {
        let candidate_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(&candidate);
        let Ok(bytes) = std::fs::read(&candidate_path) else {
            continue;
        };
        if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
            return bytes;
        }
        if bytes.len() >= 5 && &bytes[0..5] == [0x7F, b'E', b'L', b'F', 2] {
            if let Some(pe) = wrap_elf_to_pe(&candidate_path, arch) {
                return pe;
            }
        }
    }

    panic!(
        "missing real {} system PE artifact {} (build it with make build ARCH={})",
        arch_name(arch),
        artifact_name,
        arch_name(arch)
    );
}

fn arch_name(arch: TargetArch) -> &'static str {
    match arch {
        TargetArch::X86_64 => "x86_64",
        TargetArch::AArch64 => "aarch64",
        TargetArch::RiscV64 => "riscv64",
        TargetArch::LoongArch64 => "loongarch64",
    }
}

/// Final consistency pass over a freshly wrapped PE image.
///
/// `objcopy -O pei-<arch>` copies the ELF section VMAs into the PE
/// section table verbatim (absolute, not RVA-relative) on some
/// targets, and the rebase pass above may see a section table that
/// was already rebased once (for example when the same driver ELF
/// is wrapped repeatedly into one shared `.pei.tmp`). The live
/// section table is therefore the only trustworthy source for where
/// `.text` actually ends up, so the entry point and `SizeOfImage`
/// are recomputed from it instead of trusting the earlier
/// ELF-derived values. Running the pass twice converges instead of
/// drifting, which keeps the wrapped image self-consistent.
fn fix_pe_entry_and_size(
    path: &std::path::Path,
    entry_rva: u32,
    text_rva: u32,
    min_size_of_image: u32,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BuildError::Io)?;

    let mut mz = [0u8; 2];
    f.read_exact(&mut mz).map_err(BuildError::Io)?;
    if &mz != b"MZ" {
        return Err(BuildError::ImageCreateFailed(format!(
            "fix_pe_entry_and_size: {} is not a DOS/PE image",
            path.display()
        )));
    }
    f.seek(SeekFrom::Start(0x3C)).map_err(BuildError::Io)?;
    let mut e_lfanew_bytes = [0u8; 4];
    f.read_exact(&mut e_lfanew_bytes).map_err(BuildError::Io)?;
    let e_lfanew = u32::from_le_bytes(e_lfanew_bytes) as u64;
    f.seek(SeekFrom::Start(e_lfanew)).map_err(BuildError::Io)?;
    let mut pe_sig = [0u8; 4];
    f.read_exact(&mut pe_sig).map_err(BuildError::Io)?;
    if &pe_sig != b"PE\x00\x00" {
        return Err(BuildError::ImageCreateFailed(format!(
            "fix_pe_entry_and_size: bad PE signature at e_lfanew=0x{:x}",
            e_lfanew
        )));
    }
    let coff_off = e_lfanew + 4;
    f.seek(SeekFrom::Start(coff_off + 2))
        .map_err(BuildError::Io)?;
    let mut num_sections_bytes = [0u8; 2];
    f.read_exact(&mut num_sections_bytes)
        .map_err(BuildError::Io)?;
    let num_sections = u16::from_le_bytes(num_sections_bytes);
    f.seek(SeekFrom::Start(coff_off + 16))
        .map_err(BuildError::Io)?;
    let mut size_opt_bytes = [0u8; 2];
    f.read_exact(&mut size_opt_bytes).map_err(BuildError::Io)?;
    let size_opt = u16::from_le_bytes(size_opt_bytes) as u64;
    let opt_off = coff_off + 20;
    f.seek(SeekFrom::Start(opt_off + 0x20))
        .map_err(BuildError::Io)?;
    let mut align_bytes = [0u8; 4];
    f.read_exact(&mut align_bytes).map_err(BuildError::Io)?;
    let section_align = u32::from_le_bytes(align_bytes).max(1);

    let sec_table_off = opt_off + size_opt;
    let mut text_pe_va: Option<u32> = None;
    let mut max_end: u32 = 0;
    for i in 0..num_sections {
        let off = sec_table_off + (i as u64) * 40;
        f.seek(SeekFrom::Start(off)).map_err(BuildError::Io)?;
        let mut hdr = [0u8; 40];
        f.read_exact(&mut hdr).map_err(BuildError::Io)?;
        let name = &hdr[0..8];
        let is_text =
            name[0] == b'.' && &name[1..5] == b"text" && (name[5] == 0 || name[5] == b'.');
        let va = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let vsize = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let raw = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
        if is_text {
            text_pe_va = Some(va);
        }
        max_end = max_end.max(va.saturating_add(vsize.max(raw)));
    }

    let entry_offset = entry_rva.saturating_sub(text_rva);
    let final_entry = match text_pe_va {
        Some(text_va) => text_va.saturating_add(entry_offset),
        None => entry_rva,
    };
    let final_size = max_end
        .max(final_entry)
        .max(min_size_of_image)
        .checked_next_multiple_of(section_align)
        .unwrap_or(max_end.max(final_entry));

    let writes: &[(u64, u32)] = &[(opt_off + 0x10, final_entry), (opt_off + 0x38, final_size)];
    for (offset, value) in writes {
        f.seek(SeekFrom::Start(*offset)).map_err(BuildError::Io)?;
        f.write_all(&value.to_le_bytes()).map_err(BuildError::Io)?;
    }
    log::info(&format!(
        "fix_pe_entry_and_size: {} entry=0x{:x} SizeOfImage=0x{:x}",
        path.display(),
        final_entry,
        final_size
    ));
    Ok(())
}
fn wrap_elf_to_pe(elf_path: &Path, arch: TargetArch) -> Option<Vec<u8>> {
    let (objcopy, pei_target) = match arch {
        TargetArch::X86_64 => ("x86_64-linux-gnu-objcopy", "pei-x86-64"),
        TargetArch::AArch64 => ("aarch64-linux-gnu-objcopy", "pei-aarch64-little"),
        TargetArch::RiscV64 => ("riscv64-linux-gnu-objcopy", "pei-riscv64-little"),
        TargetArch::LoongArch64 => ("loongarch64-linux-gnu-objcopy", "pei-loongarch64"),
    };
    let output_path = elf_path.with_extension("pei.tmp");
    let status = Command::new(objcopy)
        .arg("-O")
        .arg(pei_target)
        .arg("--strip-all")
        .arg("--remove-section=.comment")
        .arg("--remove-section=.riscv.attributes")
        .arg("--remove-section=.loongarch.attributes")
        // The relocation records are consumed below by
        // `read_elf_absolute_relocations` (straight from the ELF);
        // they must not leak into the PE section table.
        .arg("--remove-section=.rela*")
        .arg("--remove-section=.bss")
        .arg("--remove-section=.bss*")
        .arg(elf_path)
        .arg(&output_path)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    if let Ok((entry, base_of_code, image_base)) = read_elf_image_layout(elf_path) {
        let relocations = read_elf_absolute_relocations(elf_path, image_base).unwrap_or_default();
        let image_extent_rva = read_elf_image_extent(elf_path)
            .map(|extent| extent.saturating_sub(image_base) as u32)
            .unwrap_or(0);
        let _ = patch_pe_section_addresses(&output_path, image_base);
        let _ = patch_pe_section_characteristics(&output_path);
        let _ = patch_pe_entry_point_and_image_base(&output_path, entry, base_of_code, image_base);
        patch_pe_subsystem_with_extent(&output_path, 0x0A, &relocations, image_extent_rva).ok()?;
        let _ = fix_pe_entry_and_size(&output_path, entry, base_of_code, image_extent_rva);
    } else {
        let _ = patch_pe_subsystem(&output_path, 0x0A, &[]);
    }
    std::fs::read(&output_path).ok()
}

fn build_system_images() -> Vec<SystemImage> {
    vec![
        SystemImage {
            name: "ntoskrnl.exe",
            bytes: real_pe("nt61-kernel.efi"),
        },
        SystemImage {
            name: "hal.dll",
            bytes: real_pe("hal_dll.efi"),
        },
        // BOOTVID.DLL — Boot Video driver. Loaded by winload as a
        // BOOT_START_IMAGE (not a SYS driver). Exports the canonical
        // Vid/Inbv surface the kernel calls in Phase 0/1 before the
        // HAL display driver is up.
        SystemImage {
            name: "BOOTVID.DLL",
            bytes: build_bootvid_pe(),
        },
        SystemImage {
            name: "ntdll.dll",
            bytes: build_ntdll_pe(),
        },
        SystemImage {
            name: "kernel32.dll",
            bytes: build_kernel32_pe(),
        },
        // cmd.exe — the Safe-Mode CMD user-mode host. The kernel
        // reads this PE directly from `<system32>/cmd.exe` at
        // boot (see `try_launch_cmd_exe_arch` in `arch/boot.rs`),
        // instead of constructing one in memory from
        // `include_bytes!`. That way the on-disk image is the
        // single source of truth for what the kernel launches.
        SystemImage {
            name: "cmd.exe",
            bytes: real_pe("nt61-cmd.efi"),
        },
        SystemImage {
            name: "smss.exe",
            bytes: build_smss_pe(),
        },
        // NT 6.1 Session-0 user-mode subsystem processes. The boot
        // path in `arch::boot::try_launch_cmd_exe_arch` loads each
        // of these from `C:\Windows\System32\` directly (not via
        // the in-memory fallback) so the on-disk image is the
        // single source of truth for the boot chain.
        //
        // Each binary uses a distinct image base (0x60/0x61/0x62/
        // 0x63, see build_csrss_pe / build_wininit_pe / etc.)
        // because the loader maps them at their declared
        // `ImageBase`. Putting them all at the same address would
        // cause each new mapping to overwrite the previous one.
        SystemImage {
            name: "csrss.exe",
            bytes: build_csrss_pe(),
        },
        SystemImage {
            name: "wininit.exe",
            bytes: build_wininit_pe(),
        },
        SystemImage {
            name: "services.exe",
            bytes: build_services_pe(),
        },
        SystemImage {
            name: "lsass.exe",
            bytes: build_lsass_pe(),
        },
        // Session-1 subsystem chain: winlogon -> userinit -> cmd.
        // winlogon.exe spawns the Session-1 csrss and userinit; the
        // userinit stub then spawns cmd.exe. Each binary is a tiny
        // hand-encoded x86_64 stub generated by
        // `tools/cmd-stub-gen/all_stubs.py`.
        SystemImage {
            name: "lsm.exe",
            bytes: build_lsm_pe(),
        },
        SystemImage {
            name: "winlogon.exe",
            bytes: build_winlogon_pe(),
        },
        SystemImage {
            name: "userinit.exe",
            bytes: build_userinit_pe(),
        },
        // BOOT_START storage stack — must be loadable before any
        // device tree walker runs in the kernel.
        SystemImage {
            name: "drivers/disk.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/classpnp.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/partmgr.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/volmgr.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/storahci.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/iastor.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/stornvme.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        // System infrastructure drivers.
        SystemImage {
            name: "drivers/pci.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/acpi.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/intelppm.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/mssmbios.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/hpet.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        // Display driver stack — these are the three drivers
        // the user expects to see brought up before
        // bootvid LFB takeover:
        //   * vga.sys       — legacy VGA save driver
        //   * vgapnp.sys    — PnP version of the standard VGA driver
        //   * videoprt.sys  — video port driver (parent of all
        //                     miniport drivers; registers
        //                     \\Device\\Video0)
        SystemImage {
            name: "drivers/vga.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/vgapnp.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
        SystemImage {
            name: "drivers/videoprt.sys",
            bytes: real_pe("nt61-driver.efi"),
        },
    ]
}

/// Generate x86_64 machine code for a Windows driver.
///
/// Layout:
/// [0x00] DriverEntry: Initialize driver, set dispatch handlers, return success
/// [0x40] DispatchStub: Common dispatch handler for IRPs, return STATUS_SUCCESS
/// [0x50] DriverUnload: Cleanup when driver unloads
///
/// NTSTATUS values:
///   STATUS_SUCCESS           = 0x00000000

/// Emit a minimal but well-formed PE32+ driver image. Drivers
/// are IMAGE_SUBSYSTEM_NATIVE (1) and export `DriverEntry` plus
/// `DriverUnload` and `AddDevice`. They link against `ntoskrnl.exe`
/// for the I/O manager entry points.

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_PE_SIGNATURE: u32 = 0x00004550;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_FILE_DLL: u16 = 0x2000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

/// Build a minimal PE32+ image with one `.text` section and a
/// list of exported symbols.
///
/// The `Machine` field is selected from `build_target_arch`. We
/// support the four architectures this kernel builds for so the
/// resulting disk image is consistent with whichever target the
/// Makefile is producing. Two distinct machine sets are emitted:
///   * `Machine = 0x8664 / 0xAA64 / 0xE42C / 0x6264` for ELF-class
///     PE32+ binaries.
///   * `Machine = 0x014C` etc. would be PE32, but we don't emit
///     those.
fn build_pe_image(
    image_base: u64,
    entry_point_rva: u32,
    subsystem: u16,
    is_dll: bool,
    exports: &[(&str, u32)],
) -> Vec<u8> {
    // The PE Machine field is hard-coded to 0x8664 (AMD64) for
    // every image produced today. Per-arch machine IDs (0xAA64 /
    // 0xE42C / 0x6264) will be wired in once a non-x86_64 build of
    // the host-side emitter is actually exercised on the
    // corresponding host triple; until then the field is a
    // constant so the unused-feature warnings stop firing.
    let machine: u16 = current_pe_arch().machine();
    let headers_size: u32 = 0x400;
    let num_sections: u16 = 1;
    let optional_header_size: u16 = 240;

    let mut pe = vec![0u8; headers_size as usize];
    pe[0x00..0x02].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(&IMAGE_PE_SIGNATURE.to_le_bytes());

    let mut file_flags = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    if is_dll {
        file_flags |= IMAGE_FILE_DLL;
    }
    pe[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&num_sections.to_le_bytes());
    pe[0x88..0x8C].copy_from_slice(&0x2024_1118u32.to_le_bytes());
    pe[0x8C..0x90].copy_from_slice(&0u32.to_le_bytes());
    pe[0x90..0x94].copy_from_slice(&0u32.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&optional_header_size.to_le_bytes());
    pe[0x96..0x98].copy_from_slice(&file_flags.to_le_bytes());

    let opt_off = 0x98;
    pe[opt_off..opt_off + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    pe[opt_off + 2..opt_off + 3].copy_from_slice(&14u8.to_le_bytes());
    pe[opt_off + 3..opt_off + 4].copy_from_slice(&0u8.to_le_bytes());
    pe[opt_off + 4..opt_off + 8].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[opt_off + 8..opt_off + 12].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 12..opt_off + 16].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 16..opt_off + 20].copy_from_slice(&entry_point_rva.to_le_bytes());
    pe[opt_off + 20..opt_off + 24].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 24..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    pe[opt_off + 32..opt_off + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    pe[opt_off + 36..opt_off + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    pe[opt_off + 40..opt_off + 42].copy_from_slice(&10u16.to_le_bytes());
    pe[opt_off + 42..opt_off + 44].copy_from_slice(&0u16.to_le_bytes());
    pe[opt_off + 44..opt_off + 46].copy_from_slice(&0u16.to_le_bytes());
    pe[opt_off + 46..opt_off + 48].copy_from_slice(&0u16.to_le_bytes());
    pe[opt_off + 48..opt_off + 50].copy_from_slice(&10u16.to_le_bytes());
    pe[opt_off + 50..opt_off + 52].copy_from_slice(&0u16.to_le_bytes());
    pe[opt_off + 52..opt_off + 56].copy_from_slice(&0u32.to_le_bytes());
    // SizeOfImage filled later
    pe[opt_off + 56..opt_off + 60].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 60..opt_off + 64].copy_from_slice(&headers_size.to_le_bytes());
    pe[opt_off + 64..opt_off + 68].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 68..opt_off + 70].copy_from_slice(&subsystem.to_le_bytes());
    pe[opt_off + 70..opt_off + 72].copy_from_slice(&0u16.to_le_bytes());
    pe[opt_off + 72..opt_off + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
    pe[opt_off + 80..opt_off + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    pe[opt_off + 88..opt_off + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
    pe[opt_off + 96..opt_off + 104].copy_from_slice(&0x1000u64.to_le_bytes());
    pe[opt_off + 104..opt_off + 108].copy_from_slice(&0u32.to_le_bytes());
    pe[opt_off + 108..opt_off + 112].copy_from_slice(&16u32.to_le_bytes());

    // Build .text and export directory.
    let export_rva = SECTION_ALIGNMENT;
    let ed_off = 0usize;
    let num = exports.len() as u32;
    let addr_funcs_rel = 40 + num * 4;
    let addr_names_rel = addr_funcs_rel + num * 4;
    let addr_ords_rel = addr_names_rel + num * 4;
    let string_off_rel = addr_ords_rel + num * 2;
    let mut strings = Vec::<u8>::new();
    for (name, _) in exports {
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    let total_text_size = (string_off_rel as usize + strings.len() + 0xFFF) & !0xFFF;
    let size_of_image = SECTION_ALIGNMENT + total_text_size as u32;

    // Data directories: only export (index 0).
    let dd_off = opt_off + 112;
    if !exports.is_empty() {
        let export_rva_abs = SECTION_ALIGNMENT + ed_off as u32;
        pe[dd_off..dd_off + 4].copy_from_slice(&export_rva_abs.to_le_bytes());
        pe[dd_off + 4..dd_off + 8].copy_from_slice(&(total_text_size as u32).to_le_bytes());
    }

    // SizeOfImage
    pe[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());

    // Section table at 0x98 + 240 = 0x188.
    let sec_off = opt_off + optional_header_size as usize;
    pe[sec_off..sec_off + 5].copy_from_slice(b".text");
    let vsize_off = sec_off + 8;
    pe[vsize_off..vsize_off + 4].copy_from_slice(&(total_text_size as u32).to_le_bytes());
    pe[vsize_off + 4..vsize_off + 8].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    pe[vsize_off + 8..vsize_off + 12].copy_from_slice(&(total_text_size as u32).to_le_bytes());
    pe[vsize_off + 12..vsize_off + 16].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    pe[vsize_off + 24..vsize_off + 28].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Build .text section content.
    let mut text = vec![0u8; total_text_size];
    if !exports.is_empty() {
        // Export directory header (40 bytes).
        text[ed_off..ed_off + 4].copy_from_slice(&0u32.to_le_bytes());
        text[ed_off + 4..ed_off + 8].copy_from_slice(&0u32.to_le_bytes());
        text[ed_off + 8..ed_off + 10].copy_from_slice(&0u16.to_le_bytes());
        text[ed_off + 10..ed_off + 12].copy_from_slice(&0u16.to_le_bytes());
        // Name RVA: point to first string (the module name = first export).
        let name_rva = SECTION_ALIGNMENT + string_off_rel;
        text[ed_off + 12..ed_off + 16].copy_from_slice(&name_rva.to_le_bytes());
        text[ed_off + 16..ed_off + 20].copy_from_slice(&1u32.to_le_bytes());
        text[ed_off + 20..ed_off + 24].copy_from_slice(&num.to_le_bytes());
        text[ed_off + 24..ed_off + 28].copy_from_slice(&num.to_le_bytes());
        text[ed_off + 28..ed_off + 32]
            .copy_from_slice(&(SECTION_ALIGNMENT + addr_funcs_rel).to_le_bytes());
        text[ed_off + 32..ed_off + 36]
            .copy_from_slice(&(SECTION_ALIGNMENT + addr_names_rel).to_le_bytes());
        text[ed_off + 36..ed_off + 40]
            .copy_from_slice(&(SECTION_ALIGNMENT + addr_ords_rel).to_le_bytes());

        // Functions.
        for (i, (_, rva)) in exports.iter().enumerate() {
            let p = ed_off + 40 + i * 4;
            text[p..p + 4].copy_from_slice(&rva.to_le_bytes());
        }
        // Names pointers.
        let mut cur = string_off_rel;
        for (i, (name, _)) in exports.iter().enumerate() {
            let p = ed_off + addr_names_rel as usize + i * 4;
            text[p..p + 4].copy_from_slice(&(SECTION_ALIGNMENT + cur).to_le_bytes());
            cur += name.len() as u32 + 1;
        }
        // Ords.
        for (i, _) in exports.iter().enumerate() {
            let p = ed_off + addr_ords_rel as usize + i * 2;
            text[p..p + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        // Strings.
        let mut s_off = string_off_rel as usize;
        for (name, _) in exports {
            text[s_off..s_off + name.len()].copy_from_slice(name.as_bytes());
            text[s_off + name.len()] = 0;
            s_off += name.len() + 1;
        }
        let _ = export_rva;
    }

    // Concatenate.
    let mut out = Vec::with_capacity(SECTION_ALIGNMENT as usize + total_text_size);
    out.extend_from_slice(&pe);
    out.resize(SECTION_ALIGNMENT as usize, 0u8);
    out.extend_from_slice(&text);
    out
}

fn build_bootvid_pe() -> Vec<u8> {
    // Canonical NT6.1 BOOTVID.DLL export surface. Mirrors the
    // corresponding registry in `nt61::drivers::bootvid` and the
    // winload BOOT_DRIVER_PATHS table.
    let stride = 0x10u32;
    let stride_count = |i: u32| SECTION_ALIGNMENT + i * stride;
    let exports = [
        ("VidInitialize", stride_count(0)),
        ("InbvDisplayString", stride_count(1)),
        ("InbvDisplayStringBlocking", stride_count(2)),
        ("InbvSetProgressBarSubset", stride_count(3)),
        ("InbvRotateWaitingSpinner", stride_count(4)),
        ("VidResetDisplay", stride_count(5)),
        ("VidDisplayString", stride_count(6)),
        ("VidSetCursorPosition", stride_count(7)),
        ("VidCleanUp", stride_count(8)),
    ];
    build_pe_image(
        0xFFFF_FFFF_FF00_0000,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_NATIVE,
        true,
        &exports,
    )
}

fn build_ntdll_pe() -> Vec<u8> {
    let exports = [
        ("NtCreateFile", SECTION_ALIGNMENT),
        ("NtReadFile", SECTION_ALIGNMENT + 0x10),
        ("NtWriteFile", SECTION_ALIGNMENT + 0x20),
        ("NtClose", SECTION_ALIGNMENT + 0x30),
        ("NtAllocateVirtualMemory", SECTION_ALIGNMENT + 0x40),
        ("NtFreeVirtualMemory", SECTION_ALIGNMENT + 0x50),
        ("NtQuerySystemInformation", SECTION_ALIGNMENT + 0x60),
        ("RtlAllocateHeap", SECTION_ALIGNMENT + 0x70),
        ("RtlFreeHeap", SECTION_ALIGNMENT + 0x80),
        ("LdrLoadDll", SECTION_ALIGNMENT + 0x90),
        ("RtlUserThreadStart", SECTION_ALIGNMENT + 0xA0),
    ];
    build_pe_image(
        0x0000_1000_0000_0000,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        true,
        &exports,
    )
}

fn build_kernel32_pe() -> Vec<u8> {
    let exports = [
        ("CreateFileW", SECTION_ALIGNMENT),
        ("ReadFile", SECTION_ALIGNMENT + 0x10),
        ("WriteFile", SECTION_ALIGNMENT + 0x20),
        ("CloseHandle", SECTION_ALIGNMENT + 0x30),
        ("VirtualAlloc", SECTION_ALIGNMENT + 0x40),
        ("VirtualFree", SECTION_ALIGNMENT + 0x50),
        ("LoadLibraryW", SECTION_ALIGNMENT + 0x60),
        ("GetProcAddress", SECTION_ALIGNMENT + 0x70),
    ];
    build_pe_image(
        0x0000_1000_1000_0000,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        true,
        &exports,
    )
}

fn build_smss_pe() -> Vec<u8> {
    let exports = [
        ("SmSsInitialize", SECTION_ALIGNMENT),
        ("SmSsProcessStartup", SECTION_ALIGNMENT + 0x10),
    ];
    build_pe_image(
        0x0000_1000_2000_0000,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        false,
        &exports,
    )
}

// =====================================================================
// NT 6.1 subsystem PE builders (csrss / wininit / services / lsass)
//
// These four binaries correspond to the canonical Win7 Session-0 user-
// mode process tree (see docs/doc.md):
//
//   ntoskrnl
//     └── smss.exe
//          ├── csrss.exe (Session 0)
//          └── wininit.exe
//                 ├── services.exe
//                 ├── lsass.exe
//                 └── lsm.exe
//
// In our minimal-Ring-3 bring-up we do not actually transition into
// these user-mode stubs at boot — the loader maps them into each
// process's per-process PML4 so the process objects (with their
// PEB/TEB and address spaces) are visible to subsequent diagnostics
// (e.g. `!process` / `ProcessExplorer`-style listings), but their
// main threads stay parked on the user-mode idle loop
// (NtTestAlert; jmp $). The kernel then iretqs into cmd.exe at the
// very end of the boot chain.
//
// Each PE MUST use a distinct image base — the loader maps the
// image at its declared ImageBase, and overwriting an already-mapped
// page silently corrupts the other process's view of the world. The
// 0x60/0x61/0x62/0x63 spread below reserves 256 MiB per subsystem,
// far more than these stub binaries need, so the layout is future-
// proofed for richer system processes later.
// =====================================================================

const CSRSS_IMAGE_BASE: u64 = 0x0000_1000_3000_0000;
const WININIT_IMAGE_BASE: u64 = 0x0000_1000_4000_0000;
const SERVICES_IMAGE_BASE: u64 = 0x0000_1000_5000_0000;
const LSASS_IMAGE_BASE: u64 = 0x0000_1000_6000_0000;

fn build_csrss_pe() -> Vec<u8> {
    // Client/Server Runtime Subsystem — Win32 user-mode
    // essential subsystem.
    let exports = [
        ("CsrClientCallServer", SECTION_ALIGNMENT),
        ("CsrParseServerCommandLine", SECTION_ALIGNMENT + 0x10),
        ("CsrSbApiPortName", SECTION_ALIGNMENT + 0x20),
        ("CsrInitialize", SECTION_ALIGNMENT + 0x30),
    ];
    build_pe_image(
        CSRSS_IMAGE_BASE,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        false,
        &exports,
    )
}

fn build_wininit_pe() -> Vec<u8> {
    // Windows Start-Up Application — Session 0 user-mode
    // initializer that subsequently starts services.exe and lsass.exe.
    let exports = [
        ("WinInitInitialize", SECTION_ALIGNMENT),
        ("WinInitRunOnceEx", SECTION_ALIGNMENT + 0x10),
        ("WinInitRunLevel", SECTION_ALIGNMENT + 0x20),
        ("WinInitServiceManagerInit", SECTION_ALIGNMENT + 0x30),
    ];
    build_pe_image(
        WININIT_IMAGE_BASE,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        false,
        &exports,
    )
}

fn build_services_pe() -> Vec<u8> {
    // Service Control Manager — host for SCM and svchost.exe.
    let exports = [
        ("ScAutoStartServices", SECTION_ALIGNMENT),
        ("ScStartService", SECTION_ALIGNMENT + 0x10),
        ("ScControlService", SECTION_ALIGNMENT + 0x20),
        ("ScInitializeSCM", SECTION_ALIGNMENT + 0x30),
    ];
    build_pe_image(
        SERVICES_IMAGE_BASE,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        false,
        &exports,
    )
}

fn build_lsass_pe() -> Vec<u8> {
    // Local Security Authority Subsystem Service —
    // authentication / logon-session manager.
    let exports = [
        ("LsapAuOpenPolicy", SECTION_ALIGNMENT),
        ("LsapLogonSession", SECTION_ALIGNMENT + 0x10),
        ("LsapInitLsa", SECTION_ALIGNMENT + 0x20),
        ("LsapRegisterLogonProcess", SECTION_ALIGNMENT + 0x30),
    ];
    build_pe_image(
        LSASS_IMAGE_BASE,
        SECTION_ALIGNMENT,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        false,
        &exports,
    )
}

// =====================================================================
// lsm.exe / winlogon.exe / userinit.exe PE builders
//
// These three Session-1 subsystem processes were previously missing
// from disk.img. They use the SYS_SPAWN_SUBSYSTEM_PROCESS syscall
// (number 0x0210) to ask the kernel to load the next subsystem from
// disk - a faithful reproduction of how the real Windows boot
// sequence chains session creation through winlogon -> userinit -> cmd.
//
// lsm.exe is Session-0 only. It runs in parallel with services.exe
// and lsass.exe (both started from wininit via their own spawn
// syscalls) and idles on the keyboard poll loop so it can echo
// characters typed at the console.
//
// winlogon.exe is Session-1. It spawns the Session-1 csrss.exe and
// userinit.exe (which in turn spawns cmd.exe).
//
// userinit.exe is Session-1. It is the last subsystem to start before
// the user shell; it spawns cmd.exe and idles.
//
// Each binary uses a distinct image base so the loader maps them
// without aliasing.
// =====================================================================

const LSM_IMAGE_BASE: u64 = 0x0000_1000_7000_0000;
const WINLOGON_IMAGE_BASE: u64 = 0x0000_1000_8000_0000;
const USERINIT_IMAGE_BASE: u64 = 0x0000_1000_9000_0000;

/// Build a `Vec<u8>` PE image for a 256-byte user-mode subsystem
/// stub. The export table is minimal (just one function called
/// `subsystem_main` whose RVA equals the .text section's entry
/// point). The PE layout mirrors `build_cmd_exe_pe` (DOS + PE32+
/// headers + .text section + .rdata section carrying the export
/// table).
fn build_subsystem_pe(image_base: u64, image_name: &str, text_stub: &[u8]) -> Vec<u8> {
    // ------------------------------------------------------------------
    // .text section
    // ------------------------------------------------------------------
    // Each subsystem stub is exactly 256 bytes, padded to a single
    // page (0x1000) so the PE section layout matches the other
    // subsystem binaries.
    let mut text_data = text_stub.to_vec();
    while text_data.len() < SECTION_ALIGNMENT as usize {
        text_data.push(0x90); // NOP padding
    }

    // ------------------------------------------------------------------
    // .rdata section (single export: subsystem_main)
    // ------------------------------------------------------------------
    let mut rdata = vec![0u8; 0x100];
    let s_name = b"subsystem_main\x00";
    cmd_exe_write_u32(&mut rdata, 0x00, 0); // Characteristics
    cmd_exe_write_u32(&mut rdata, 0x04, 0); // TimeDateStamp
    cmd_exe_write_u16(&mut rdata, 0x08, 0); // MajorVersion
    cmd_exe_write_u16(&mut rdata, 0x0A, 0); // MinorVersion
    cmd_exe_write_u32(&mut rdata, 0x0C, CMD_EXE_RDATA_RVA + 0x028); // AddressOfFunctions RVA
    cmd_exe_write_u32(&mut rdata, 0x10, CMD_EXE_RDATA_RVA + 0x034); // AddressOfNames RVA
    cmd_exe_write_u32(&mut rdata, 0x14, CMD_EXE_RDATA_RVA + 0x040); // AddressOfNameOrdinals RVA
    cmd_exe_write_u32(&mut rdata, 0x18, 1); // NumberOfFunctions
    cmd_exe_write_u32(&mut rdata, 0x1C, 1); // NumberOfNames
                                            // AddressOfFunctions[1] = subsystem_main
    cmd_exe_write_u32(&mut rdata, 0x028, CMD_EXE_TEXT_RVA);
    // AddressOfNames[1] = name string RVA
    let name_off: usize = 0x050;
    cmd_exe_write_u32(&mut rdata, 0x034, CMD_EXE_RDATA_RVA + name_off as u32);
    rdata[name_off..name_off + s_name.len()].copy_from_slice(s_name);
    // AddressOfNameOrdinals[1]
    cmd_exe_write_u16(&mut rdata, 0x040, 0);

    // ------------------------------------------------------------------
    // PE headers + section table
    // ------------------------------------------------------------------
    let sect_off_u32: u32 = 0x188;
    let sect_off: usize = sect_off_u32 as usize;
    let text_raw_size: u32 = cmd_exe_align_up(text_data.len() as u32, FILE_ALIGNMENT);
    let rdata_raw_size: u32 = cmd_exe_align_up(rdata.len() as u32, FILE_ALIGNMENT);
    let text_raw_off: u32 = cmd_exe_align_up(sect_off_u32 + 2 * 40, FILE_ALIGNMENT);
    let rdata_raw_off: u32 = text_raw_off + text_raw_size;
    let total_size: u32 = rdata_raw_off + rdata_raw_size;
    let headers_size: u32 = cmd_exe_align_up(sect_off_u32 + 2 * 40, FILE_ALIGNMENT);

    let mut out = vec![0u8; total_size as usize];

    // DOS header
    out[0..2].copy_from_slice(b"MZ");
    cmd_exe_write_u32(&mut out, 0x3C, 0x80);

    // PE signature + COFF header + Optional header at offset 0x80
    let pe_off = 0x80usize;
    out[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");

    // COFF File Header (20 bytes)
    let coff_off = pe_off + 4;
    cmd_exe_write_u16(&mut out, coff_off, 0x8664); // Machine (AMD64)
    cmd_exe_write_u16(&mut out, coff_off + 0x02, 2); // NumberOfSections
    cmd_exe_write_u32(&mut out, coff_off + 0x04, 0); // TimeDateStamp
    cmd_exe_write_u32(&mut out, coff_off + 0x08, 0); // PointerToSymbolTable
    cmd_exe_write_u32(&mut out, coff_off + 0x0C, 0); // NumberOfSymbols
    cmd_exe_write_u16(&mut out, coff_off + 0x10, 240); // SizeOfOptionalHeader
    cmd_exe_write_u16(&mut out, coff_off + 0x12, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header
    let opt_off = coff_off + 0x14;
    cmd_exe_write_u16(&mut out, opt_off, 0x020B); // Magic: PE32+
    cmd_exe_write_u16(&mut out, opt_off + 0x02, 14);
    cmd_exe_write_u16(&mut out, opt_off + 0x04, 0);
    cmd_exe_write_u32(&mut out, opt_off + 0x06, text_raw_size);
    cmd_exe_write_u32(&mut out, opt_off + 0x0A, rdata_raw_size);
    cmd_exe_write_u32(&mut out, opt_off + 0x0E, 0);
    cmd_exe_write_u32(&mut out, opt_off + 0x10, CMD_EXE_TEXT_RVA); // EntryPoint
    cmd_exe_write_u32(&mut out, opt_off + 0x14, CMD_EXE_TEXT_RVA); // BaseOfCode
    cmd_exe_write_u64(&mut out, opt_off + 0x18, image_base);
    cmd_exe_write_u32(&mut out, opt_off + 0x20, SECTION_ALIGNMENT);
    cmd_exe_write_u32(&mut out, opt_off + 0x24, FILE_ALIGNMENT);
    cmd_exe_write_u16(&mut out, opt_off + 0x28, 10);
    cmd_exe_write_u16(&mut out, opt_off + 0x2A, 0);
    cmd_exe_write_u16(&mut out, opt_off + 0x2C, 0);
    cmd_exe_write_u16(&mut out, opt_off + 0x2E, 0);
    cmd_exe_write_u16(&mut out, opt_off + 0x30, 10);
    cmd_exe_write_u16(&mut out, opt_off + 0x32, 0);
    cmd_exe_write_u32(&mut out, opt_off + 0x34, 0);
    let size_of_image = CMD_EXE_RDATA_RVA + SECTION_ALIGNMENT;
    cmd_exe_write_u32(&mut out, opt_off + 0x38, size_of_image);
    cmd_exe_write_u32(&mut out, opt_off + 0x3C, headers_size);
    cmd_exe_write_u32(&mut out, opt_off + 0x40, 0);
    cmd_exe_write_u16(&mut out, opt_off + 0x44, 3); // WindowsCui
    cmd_exe_write_u16(&mut out, opt_off + 0x46, 0x0160);
    cmd_exe_write_u64(&mut out, opt_off + 0x48, 0x100000);
    cmd_exe_write_u64(&mut out, opt_off + 0x50, 0x1000);
    cmd_exe_write_u64(&mut out, opt_off + 0x58, 0x100000);
    cmd_exe_write_u64(&mut out, opt_off + 0x60, 0x1000);
    cmd_exe_write_u32(&mut out, opt_off + 0x68, 0);
    cmd_exe_write_u32(&mut out, opt_off + 0x6C, 16);

    // Data directories
    let dd_off = opt_off + 0x70;
    cmd_exe_write_u32(&mut out, dd_off, CMD_EXE_RDATA_RVA);
    cmd_exe_write_u32(&mut out, dd_off + 0x04, rdata.len() as u32);

    // Section headers
    let s = sect_off;
    out[s..s + 8].copy_from_slice(b".text\x00\x00\x00");
    cmd_exe_write_u32(&mut out, s + 0x08, text_data.len() as u32);
    cmd_exe_write_u32(&mut out, s + 0x0C, CMD_EXE_TEXT_RVA);
    cmd_exe_write_u32(&mut out, s + 0x10, text_raw_size);
    cmd_exe_write_u32(&mut out, s + 0x14, text_raw_off);
    cmd_exe_write_u32(&mut out, s + 0x18, 0);
    cmd_exe_write_u32(&mut out, s + 0x1C, 0);
    cmd_exe_write_u16(&mut out, s + 0x20, 0);
    cmd_exe_write_u16(&mut out, s + 0x22, 0);
    cmd_exe_write_u32(&mut out, s + 0x24, 0x60000020);

    let s = sect_off + 40;
    out[s..s + 8].copy_from_slice(b".rdata\x00\x00");
    cmd_exe_write_u32(&mut out, s + 0x08, rdata.len() as u32);
    cmd_exe_write_u32(&mut out, s + 0x0C, CMD_EXE_RDATA_RVA);
    cmd_exe_write_u32(&mut out, s + 0x10, rdata_raw_size);
    cmd_exe_write_u32(&mut out, s + 0x14, rdata_raw_off);
    cmd_exe_write_u32(&mut out, s + 0x18, 0);
    cmd_exe_write_u32(&mut out, s + 0x1C, 0);
    cmd_exe_write_u16(&mut out, s + 0x20, 0);
    cmd_exe_write_u16(&mut out, s + 0x22, 0);
    cmd_exe_write_u32(&mut out, s + 0x24, 0x40000040);

    // Section data
    out[text_raw_off as usize..(text_raw_off + text_data.len() as u32) as usize]
        .copy_from_slice(&text_data);
    out[rdata_raw_off as usize..(rdata_raw_off + rdata.len() as u32) as usize]
        .copy_from_slice(&rdata);

    let _ = image_name;
    out
}

fn build_lsm_pe() -> Vec<u8> {
    build_subsystem_pe(LSM_IMAGE_BASE, "lsm.exe", &LSM_EXE_TEXT_STUB)
}

fn build_winlogon_pe() -> Vec<u8> {
    build_subsystem_pe(WINLOGON_IMAGE_BASE, "winlogon.exe", &WINLOGON_EXE_TEXT_STUB)
}

fn build_userinit_pe() -> Vec<u8> {
    build_subsystem_pe(USERINIT_IMAGE_BASE, "userinit.exe", &USERINIT_EXE_TEXT_STUB)
}

// =====================================================================
// cmd.exe PE builder
//
// Mirrors `tools/src/bin/mkcmd.rs`. We re-implement it inline here
// (instead of shelling out to `cargo run -p nt61-tools --bin mkcmd`)
// so the build pipeline stays a single self-contained `build-tool`
// invocation. The produced bytes match `mkcmd.rs` byte-for-byte: a
// minimal PE32+ whose `.text` is the SYS_RUN_AUTOEXEC stub and
// whose `.rdata` carries the export table. The kernel reads this
// file directly from `<system32>/cmd.exe` at boot (see
// `arch::boot::try_launch_cmd_exe_arch`) — there is no
// `include_bytes!`-baked fallback.
// =====================================================================

const CMD_EXE_TEXT_RVA: u32 = SECTION_ALIGNMENT;
const CMD_EXE_RDATA_RVA: u32 = SECTION_ALIGNMENT * 2;

fn cmd_exe_align_up(x: u32, align: u32) -> u32 {
    (x + align - 1) & !(align - 1)
}

fn cmd_exe_write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn cmd_exe_write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn cmd_exe_write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(name, virtual_address, virtual_size)` for every section in a
    /// PE32+ image produced by this module.
    fn sections(pe: &[u8]) -> Vec<(&str, u32, u32)> {
        let pe_off = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let sect_off = pe_off + 4 + 20 + 240;
        let count = u16::from_le_bytes([pe[pe_off + 4 + 2], pe[pe_off + 4 + 3]]) as usize;
        let mut out = Vec::new();
        for i in 0..count {
            let s = sect_off + i * 40;
            let name = core::str::from_utf8(&pe[s..s + 6]).unwrap();
            let vsize = u32::from_le_bytes([pe[s + 8], pe[s + 9], pe[s + 10], pe[s + 11]]);
            let vaddr = u32::from_le_bytes([pe[s + 12], pe[s + 13], pe[s + 14], pe[s + 15]]);
            out.push((name, vaddr, vsize));
        }
        out
    }

    #[test]
    fn cmd_exe_pe_sections_do_not_overlap() {
        let images = build_system_images();
        let pe = images
            .iter()
            .find(|image| image.name == "cmd.exe")
            .map(|image| image.bytes.clone())
            .expect("build_system_images should produce cmd.exe");
        let pe_off = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let opt_off = pe_off + 4 + 20;
        let size_of_image = u32::from_le_bytes([
            pe[opt_off + 0x38],
            pe[opt_off + 0x39],
            pe[opt_off + 0x3A],
            pe[opt_off + 0x3B],
        ]);

        let secs = sections(&pe);
        assert_eq!(secs.len(), 2);

        for &(name, vaddr, vsize) in &secs {
            let span = vsize.max(cmd_exe_align_up(vsize, FILE_ALIGNMENT));
            assert!(
                vaddr + span <= size_of_image,
                "section {name} runs past SizeOfImage"
            );
        }

        for i in 0..secs.len() {
            for j in (i + 1)..secs.len() {
                let (n1, a1, s1) = secs[i];
                let (n2, a2, s2) = secs[j];
                let e1 = a1 + s1.max(cmd_exe_align_up(s1, FILE_ALIGNMENT));
                let e2 = a2 + s2.max(cmd_exe_align_up(s2, FILE_ALIGNMENT));
                assert!(
                    e1 <= a2 || e2 <= a1,
                    "sections {n1} and {n2} overlap in memory"
                );
            }
        }
    }
}

/// Build the canonical cmd.exe PE image. The output matches
/// `tools/src/bin/mkcmd.rs` byte-for-byte (modulo timestamps), so
/// either code path produces an on-disk `cmd.exe` that the kernel
/// can launch identically.

// =====================================================================
// Utilities
// =====================================================================

/// Run cargo command
pub fn run_cargo(args: &[&str]) -> Result<()> {
    let manifest_dir = get_workspace_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&manifest_dir);

    for arg in args {
        cmd.arg(arg);
    }

    let status = cmd.status().map_err(BuildError::Io)?;

    if !status.success() {
        return Err(BuildError::ImageCreateFailed(format!(
            "Cargo command failed: {:?}",
            args
        )));
    }

    Ok(())
}

// =====================================================================
// Cross-architecture PE emission helpers
// =====================================================================

// The PE Machine field is currently emitted as a constant 0x8664
// for every image; per-arch machine IDs are tracked in the
// arch-specific `make_cmd_emit` paths and will replace this
// helper once the host emitter is multi-target.
