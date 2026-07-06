//! NT6.1.7601 Build Tool
//!
//! A single-binary, shell-independent build tool for the NT6.1.7601 project.
//! Replaces `mkfs.fat`, `mcopy`, `mmd`, `cp`, `mkdir`, `rm`, and the `make`
//! glue with a clean Rust CLI.
//!
//! The CLI is structured as top-level flags rather than subcommands so that
//! commands like `build-tool --cp A B.img:C` feel natural in a Makefile.
//!
//! ## High-level flags
//!
//! | Flag | What it does |
//! |---|---|
//! | `--build <sub>`  | `system` / `esp` / `boot` / `kernel` / `all` |
//! | `--format <fs>`  | Format a `.img` (FAT32/EXT4/NTFS) or `.qcow2` |
//! | `--create <fmt>` | Create an empty image of the given format |
//! | `--cp`           | Copy host→image or image→host |
//! | `--mv`           | Move host→image or image→host |
//! | `--mkdir`        | Create a directory inside the image |
//! | `--rm`           | Remove a file/directory from the image |
//! | `--directory`    | List directory entries inside the image |
//! | `--version`      | Print version |
//! | `--help`         | Print help (clap native) |
//!
//! `--cp`, `--mv`, `--rm`, `--mkdir`, `--directory` operate on disk images
//! (FAT32 today; EXT4/NTFS/ISO/QCOW2 return a clear "not yet supported"
//! error). Image paths may be written as `image.img:inner/path` to refer to
//! an entry inside the image; the host-side path is always the bare path.
//! `-p <n>` selects the 1-based partition within a multi-partition image;
//! default is the first FAT32-capable partition (or the whole file if it is
//! a single FAT32 image).
//!
//! `-L <n>` is the recursion depth for `--directory`.

mod error;
mod logger;
pub mod fs;
use nt61_tools::hive_gen;

use std::path::{Path, PathBuf};
use clap::{Arg, ArgAction, ArgMatches, Command};

/// Build tool version
const VERSION: &str = "0.1.0";

// =====================================================================
// Entry point
// =====================================================================

fn main() {
    if let Err(e) = run() {
        logger::error(&e.to_string());
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cmd = build_cli();
    let matches = cmd.get_matches();
    logger::set_verbose(matches.get_flag("verbose"));

    // --help and --version are handled by clap directly via disable_help_flag(false)
    if matches.get_flag("version") {
        print_version();
        return Ok(());
    }

    // Each branch is mutually exclusive at the call site; clap's `requires`
    // only enforces relationship, not exclusivity, so we do it manually.
    if let Some(sub) = matches.get_one::<String>("build") {
        return run_build(sub, &matches);
    }
    if matches.get_flag("format") {
        return run_format(&matches);
    }
    if let Some(fmt) = matches.get_one::<String>("create") {
        return run_create(fmt, &matches);
    }
    if matches.get_flag("cp") {
        return run_copy(false, &matches);
    }
    if matches.get_flag("mv") {
        return run_copy(true, &matches);
    }
    if matches.get_flag("mkdir") {
        return run_mkdir(&matches);
    }
    if matches.get_flag("rm") {
        return run_rm(&matches);
    }
    if matches.get_flag("directory") {
        return run_directory(&matches);
    }

    // No recognized action: print help and exit 2.
    let mut cmd = build_cli();
    cmd.print_help().ok();
    println!();
    Ok(())
}

// =====================================================================
// CLI definition
// =====================================================================

fn build_cli() -> Command {
    Command::new("build-tool")
        .about("NT6.1.7601 Build Tool — create disk images without shell dependencies")
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::SetTrue)
                .help("Print version and exit"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Enable verbose output"),
        )
        // ---- build subactions -----------------------------------------
        .arg(
            Arg::new("build")
                .long("build")
                .value_name("SUB")
                .value_parser(["system", "esp", "boot", "kernel", "all", "iso"])
                .help("Build a sub-target: system (root tree), esp (EFI dir), boot, kernel, all (dual-partition disk), or iso (CD-ROM image)"),
        )
        .arg(
            Arg::new("build-dir")
                .long("build-dir")
                .value_name("DIR")
                .default_value("build")
                .help("Output root for --build (used for kernel/esp intermediates)"),
        )
        .arg(
            Arg::new("arch")
                .long("arch")
                .value_name("ARCH")
                .default_value("x64")
                .help("Architecture for --build esp (x64 | arm64 | arm | riscv64 | loongarch64)"),
        )
        .arg(
            Arg::new("format-flag")
                .long("format-flag")
                .value_name("FMT")
                .default_value("fat32")
                .help("Image format for --build all (fat32 | ntfs | ext4)"),
        )
        .arg(
            Arg::new("size-mb")
                .long("size-mb")
                .value_name("MB")
                .default_value("64")
                .help("Image size in MB for --build all / --create / --format"),
        )
        .arg(
            Arg::new("iso-mode")
                .long("iso-mode")
                .action(ArgAction::SetTrue)
                .help("Build an ISO image (--build iso). Combines ESP+System into a single FAT32 image inside the ISO."),
        )
        // ---- format ----------------------------------------------------
        .arg(
            Arg::new("format")
                .long("format")
                .action(ArgAction::SetTrue)
                .help("Format a raw image. Pair with -f (fs) and -s (size)"),
        )
        .arg(
            Arg::new("format-fs")
                .short('f')
                .long("format-fs")
                .value_name("FS")
                .help("Filesystem type for --format (fat32 | ntfs | ext4)"),
        )
        .arg(
            Arg::new("image")
                .long("image")
                .value_name("IMG")
                .help("Image file path for --format / --create / --cp / --rm etc."),
        )
        // ---- create ----------------------------------------------------
        .arg(
            Arg::new("create")
                .long("create")
                .value_name("FMT")
                .value_parser(["img", "iso", "qcow2"])
                .help("Create an empty image of the given container format"),
        )
        .arg(
            Arg::new("partition-table")
                .long("partition-table")
                .short('i')
                .value_name("STYLE")
                .value_parser(["gpt", "mbr", "none"])
                .default_value("none")
                .help("Partition table style to write around the filesystem (gpt | mbr | none). Default none = raw single-FS image."),
        )
        // ---- cp / mv / rm / mkdir / directory -------------------------
        .arg(
            Arg::new("cp")
                .long("cp")
                .action(ArgAction::SetTrue)
                .help("Copy host<->image (use --src and --dst)"),
        )
        .arg(
            Arg::new("mv")
                .long("mv")
                .action(ArgAction::SetTrue)
                .help("Move host<->image (use --src and --dst)"),
        )
        .arg(
            Arg::new("mkdir")
                .long("mkdir")
                .action(ArgAction::SetTrue)
                .help("Create a directory inside an image (use --dir)"),
        )
        .arg(
            Arg::new("rm")
                .long("rm")
                .action(ArgAction::SetTrue)
                .help("Remove a file/directory from inside an image (use --src)"),
        )
        .arg(
            Arg::new("directory")
                .long("directory")
                .alias("ls")
                .action(ArgAction::SetTrue)
                .help("List the contents of a directory inside an image (use --dir, -L for depth)"),
        )
        .arg(
            Arg::new("src")
                .long("src")
                .value_name("SRC")
                .help("Source path: bare host path or IMG:inner/path"),
        )
        .arg(
            Arg::new("dst")
                .long("dst")
                .value_name("DST")
                .help("Destination path: bare host path or IMG:inner/path"),
        )
        .arg(
            Arg::new("dir")
                .short('d')
                .long("dir")
                .value_name("DIR")
                .help("Directory path (host or IMG:inner/path) for --mkdir / --directory"),
        )
        .arg(
            Arg::new("partition")
                .short('p')
                .long("partition")
                .value_name("N")
                .help("1-indexed partition number (default: first FAT32 partition)"),
        )
        .arg(
            Arg::new("depth")
                .short('L')
                .long("level")
                .value_name("N")
                .help("Recursion depth for --directory (default: 1, the directory itself)"),
        )
        .arg(
            Arg::new("recursive")
                .short('r')
                .long("recursive")
                .action(ArgAction::SetTrue)
                .help("Recursive copy (for --cp)"),
        )
        .disable_help_flag(false)
}

// =====================================================================
// Version
// =====================================================================

fn print_version() {
    println!("NT6.1.7601 Build Tool v{}", VERSION);
    println!("Supported image formats:  img, iso, qcow2");
    println!("Supported filesystems:   FAT32, NTFS, EXT4");
    println!("Modify-supported FS:      FAT32 (read-modify-write)");
    println!("Other FS:                 create-only (modify returns NotImplemented)");
}

// =====================================================================
// --build <sub>
// =====================================================================

fn run_build(sub: &str, m: &ArgMatches) -> error::Result<()> {
    let build_dir = PathBuf::from(m.get_one::<String>("build-dir").unwrap());
    let arch = m.get_one::<String>("arch").unwrap().clone();
    let fmt = m.get_one::<String>("format-flag").unwrap().clone();
    let size_mb: u32 = m
        .get_one::<String>("size-mb")
        .unwrap()
        .parse()
        .map_err(|_| error::BuildError::InvalidParam("--size-mb must be a number".into()))?;

    match sub {
        "system" => build_system(&build_dir, m).map(|_| ()),
        "esp" => build_esp(&build_dir, &arch, m).map(|_| ()),
        "boot" => build_boot_only(&build_dir, &arch).map(|_| ()),
        "kernel" => build_kernel_only(&build_dir, &arch).map(|_| ()),
        "all" => fs::build::full_build(&build_dir, &fmt, size_mb, &arch, m.get_flag("verbose"))
            .map(|p| {
                logger::success(&format!("Image built: {}", p.display()));
            }),
        "iso" => fs::build::build_iso(&build_dir, &fmt, size_mb, &arch, m.get_flag("verbose"))
            .map(|p| {
                logger::success(&format!("ISO built: {}", p.display()));
            }),
        other => Err(error::BuildError::InvalidParam(format!(
            "unknown --build sub-target: {}",
            other
        ))),
    }?;
    Ok(())
}

fn build_system(build_dir: &Path, _m: &ArgMatches) -> error::Result<()> {
    let root = build_dir.join("system");
    fs::system::SystemBuilder::new(&root)?.build()?;
    logger::success(&format!("System root tree created: {}", root.display()));
    Ok(())
}

fn build_esp(build_dir: &Path, arch: &str, m: &ArgMatches) -> error::Result<()> {
    let out = build_dir.join("esp");
    // Try to find nt61-boot.efi in the expected locations
    let boot_efi = locate_built(m, "boot", "nt61-boot.efi")
        .or_else(|| {
            // Fallback: look in the UEFI target directory
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let target_dir = manifest_dir.parent().unwrap().join("target/x86_64-unknown-uefi/release/nt61-boot.efi");
            if target_dir.exists() {
                Some(target_dir)
            } else {
                None
            }
        });
    let font = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("resources/fonts/open-sans/OpenSans-Regular.ttf"));
    // NOTE: AUTOEXEC.BAT is intentionally placed in the *system*
    // partition only (C:\autoexec.bat), not the ESP. Per Windows
    // conventions the ESP is reserved for boot-time files; placing
    // user batch files there would diverge from real Win7 layout.
    fs::esp::EspBuilder::new(&out, arch)?
        .with_boot_efi(boot_efi.as_deref())?
        .with_font(font.as_ref())
        .build()?;
    // Note: BCD is now written by build_esp.rs::generate_bcd which handles padding
    logger::success(&format!("ESP built: {}", out.display()));
    Ok(())
}

fn build_boot_only(build_dir: &Path, arch: &str) -> error::Result<()> {
    let target = fs::build::uefi_target_for(arch);
    let _ = fs::build::build_boot(target, true)?;
    let _ = build_dir;
    Ok(())
}

fn build_kernel_only(build_dir: &Path, arch: &str) -> error::Result<()> {
    // "kernel" in the user's terminology means winload.efi + ntoskrnl.exe.
    // We don't have a real ntoskrnl.exe yet, so build the kernel crate and
    // the winload for completeness.
    let k_target = fs::build::kernel_target_for(arch);
    let u_target = fs::build::uefi_target_for(arch);
    let _ = fs::build::build_kernel(k_target, true)?;
    let _ = fs::build::build_winload(u_target, true)?;
    let _ = build_dir;
    Ok(())
}

fn locate_built(m: &ArgMatches, _kind: &str, file_name: &str) -> Option<PathBuf> {
    if let Some(dir) = m.get_one::<String>("build-dir") {
        let p = PathBuf::from(dir).join("system").join(file_name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// =====================================================================
// --format
// =====================================================================

fn run_format(m: &ArgMatches) -> error::Result<()> {
    let img = require_string(m, "image", "--format")?;
    let fs_name = require_string(m, "format-fs", "-f / --format-fs")?;
    let size_mb: u32 = m
        .get_one::<String>("size-mb")
        .unwrap()
        .parse()
        .map_err(|_| error::BuildError::InvalidParam("--size-mb must be a number".into()))?;
    let path = PathBuf::from(&img);
    fs::image::format_image(&path, &fs_name, size_mb, m.get_flag("verbose"))?;
    logger::success(&format!("Formatted {} ({}, {} MB)", path.display(), fs_name, size_mb));
    Ok(())
}

// =====================================================================
// --create <fmt>
// =====================================================================

fn run_create(fmt: &str, m: &ArgMatches) -> error::Result<()> {
    let img = require_string(m, "image", "--create")?;
    let size_mb: u32 = m
        .get_one::<String>("size-mb")
        .unwrap()
        .parse()
        .map_err(|_| error::BuildError::InvalidParam("--size-mb must be a number".into()))?;
    let pt_style = m.get_one::<String>("partition-table").cloned().unwrap_or_else(|| "none".to_string());
    let path = PathBuf::from(&img);

    // --create targets the *container* format (img / iso / qcow2). The
    // filesystem used inside the image is the one from --format-fs or fat32.
    let container = match fmt {
        "img" => "fat32",
        "iso" => "iso",
        "qcow2" => "qcow2",
        other => {
            return Err(error::BuildError::InvalidParam(format!(
                "unsupported container format: {}",
                other
            )));
        }
    };
    let inner_fs = m
        .get_one::<String>("format-fs")
        .map(|s| s.as_str())
        .unwrap_or(if container == "iso" || container == "qcow2" {
            container
        } else {
            "fat32"
        });

    // ReFS is explicitly excluded by the design.
    if inner_fs == "refs" {
        return Err(error::BuildError::ReFsNotImplemented);
    }

    // Partition table wrapping is only meaningful for raw .img files.
    if pt_style != "none" && container != "fat32" && container != "ntfs" && container != "ext4" {
        return Err(error::BuildError::InvalidParam(format!(
            "--partition-table {} only applies to raw .img images (got {})",
            pt_style, container
        )));
    }

    let pt = match pt_style.as_str() {
        "gpt" => fs::image::PartitionTable::Gpt,
        "mbr" => fs::image::PartitionTable::Mbr,
        "none" => fs::image::PartitionTable::None,
        other => {
            return Err(error::BuildError::InvalidParam(format!(
                "unknown partition table style: {} (expected gpt | mbr | none)",
                other
            )));
        }
    };

    fs::image::create_image_with_pt(&path, inner_fs, size_mb, None, m.get_flag("verbose"), pt)?;
    logger::success(&format!(
        "Created {} image ({} MB, fs={}, partition-table={})",
        path.display(),
        size_mb,
        inner_fs,
        pt_style
    ));
    Ok(())
}

// =====================================================================
// --cp / --mv
// =====================================================================

fn run_copy(is_move: bool, m: &ArgMatches) -> error::Result<()> {
    let src = require_string(m, "src", "--src")?;
    let dst = require_string(m, "dst", "--dst")?;
    let partition = m.get_one::<String>("partition").map(|s| s.as_str());

    let src_spec = PathSpec::parse(&src);
    let dst_spec = PathSpec::parse(&dst);

    // Resolve direction: at least one side must reference an image.
    match (&src_spec, &dst_spec) {
        (PathSpec::Host(src_path), PathSpec::Image(img, inner)) => {
            // host -> image
            copy_host_to_image(src_path, img, inner, partition, m.get_flag("recursive"))?;
            if is_move {
                if src_path.is_dir() {
                    fs::remove::remove_path(src_path)?;
                } else {
                    fs::remove::remove_file(src_path)?;
                }
                logger::info(&format!("Removed host path: {}", src_path.display()));
            }
        }
        (PathSpec::Image(img, inner), PathSpec::Host(dst_path)) => {
            // image -> host
            copy_image_to_host(img, inner, dst_path, partition, m.get_flag("recursive"))?;
            if is_move {
                let mut opened = fs::image::open_for_modify(Path::new(img), parse_partition(partition))?;
                opened.backend().remove(inner)?;
                opened.write_back(Path::new(img))?;
            }
        }
        (PathSpec::Image(img_a, inner_a), PathSpec::Image(img_b, inner_b)) => {
            // image -> image: route through host temp
            let tmp = std::env::temp_dir().join(format!(
                "build-tool-{}-{}",
                std::process::id(),
                inner_b.rsplit('/').next().unwrap_or("file")
            ));
            copy_image_to_host(img_a, inner_a, &tmp, partition, m.get_flag("recursive"))?;
            copy_host_to_image(&tmp, img_b, inner_b, None, m.get_flag("recursive"))?;
            std::fs::remove_file(&tmp).ok();
            if is_move {
                let mut opened = fs::image::open_for_modify(Path::new(img_a), parse_partition(partition))?;
                opened.backend().remove(inner_a)?;
                opened.write_back(Path::new(img_a))?;
            }
        }
        (PathSpec::Host(src_path), PathSpec::Host(dst_path)) => {
            // pure host-side copy
            let recursive = m.get_flag("recursive");
            if recursive {
                fs::copy::copy_dir_recursive(src_path, dst_path)?;
            } else {
                fs::copy::copy_file(src_path, dst_path)?;
            }
        }
    }
    Ok(())
}

fn copy_host_to_image(
    host: &Path,
    image: &str,
    inner: &str,
    partition: Option<&str>,
    recursive: bool,
) -> error::Result<()> {
    let mut opened = fs::image::open_for_modify(Path::new(image), parse_partition(partition))?;
    let fs_tree = opened.backend();
    if host.is_dir() {
        if !recursive {
            return Err(error::BuildError::InvalidParam(
                "source is a directory; pass -r / --recursive".into(),
            ));
        }
        let prefix = inner.trim_end_matches('/');
        for entry in std::fs::read_dir(host).map_err(error::BuildError::Io)? {
            let entry = entry.map_err(error::BuildError::Io)?;
            let src = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let dst = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };
            copy_host_path_into(fs_tree, &src, &dst, recursive)?;
        }
    } else {
        copy_host_path_into(fs_tree, host, inner.trim_end_matches('/'), recursive)?;
    }
    opened.write_back(Path::new(image))?;
    logger::success(&format!("Copied into image {} at {}", image, inner));
    Ok(())
}

fn copy_host_path_into(
    fs_tree: &mut dyn fs::backend::FsBackend,
    src: &Path,
    dst_inner: &str,
    recursive: bool,
) -> error::Result<()> {
    if src.is_dir() {
        if !recursive {
            return Err(error::BuildError::InvalidParam(
                "source is a directory; pass -r / --recursive".into(),
            ));
        }
        fs_tree.mkdir(dst_inner)?;
        for entry in std::fs::read_dir(src).map_err(error::BuildError::Io)? {
            let entry = entry.map_err(error::BuildError::Io)?;
            let child_src = entry.path();
            let child_name = entry.file_name().to_string_lossy().into_owned();
            let child_dst = format!("{}/{}", dst_inner, child_name);
            copy_host_path_into(fs_tree, &child_src, &child_dst, recursive)?;
        }
    } else {
        let data = std::fs::read(src).map_err(error::BuildError::Io)?;
        // Ensure parent directory exists in the image.
        if let Some(parent) = Path::new(dst_inner).parent() {
            let parent = parent.to_string_lossy().replace('\\', "/");
            if !parent.is_empty() {
                fs_tree.mkdir(&parent)?;
            }
        }
        fs_tree.write_file(dst_inner, &data)?;
    }
    Ok(())
}

fn copy_image_to_host(
    image: &str,
    inner: &str,
    host: &Path,
    partition: Option<&str>,
    _recursive: bool,
) -> error::Result<()> {
    let mut opened = fs::image::open_for_modify(Path::new(image), parse_partition(partition))?;
    // We do not need to call write_back since we only read.
    let bytes = read_image_bytes(opened.backend(), inner)?;
    if let Some(parent) = host.parent() {
        fs::dir::create_dir_all(parent)?;
    }
    std::fs::write(host, &bytes).map_err(error::BuildError::Io)?;
    logger::success(&format!("Copied {}:{} -> {}", image, inner, host.display()));
    Ok(())
}

fn read_image_bytes(fs_tree: &dyn fs::backend::FsBackend, inner: &str) -> error::Result<Vec<u8>> {
    fs_tree.read_file(inner)
}

// =====================================================================
// --mkdir
// =====================================================================

fn run_mkdir(m: &ArgMatches) -> error::Result<()> {
    let dir = require_string(m, "dir", "-d / --dir")?;
    let spec = PathSpec::parse(&dir);
    let partition = m.get_one::<String>("partition").map(|s| s.as_str());
    match spec {
        PathSpec::Host(p) => {
            fs::dir::create_dir_all(&p)?;
            logger::success(&format!("mkdir: {}", p.display()));
        }
        PathSpec::Image(img, inner) => {
            let mut opened = fs::image::open_for_modify(Path::new(&img), parse_partition(partition))?;
            opened.backend().mkdir(&inner)?;
            opened.write_back(Path::new(&img))?;
            logger::success(&format!("mkdir: {}:{}", img, inner));
        }
    }
    Ok(())
}

// =====================================================================
// --rm
// =====================================================================

fn run_rm(m: &ArgMatches) -> error::Result<()> {
    let src = require_string(m, "src", "--src")?;
    let spec = PathSpec::parse(&src);
    let partition = m.get_one::<String>("partition").map(|s| s.as_str());
    match spec {
        PathSpec::Host(p) => {
            if p.is_dir() {
                fs::remove::remove_path(&p)?;
            } else {
                fs::remove::remove_file(&p)?;
            }
            logger::success(&format!("rm: {}", p.display()));
        }
        PathSpec::Image(img, inner) => {
            let mut opened = fs::image::open_for_modify(Path::new(&img), parse_partition(partition))?;
            opened.backend().remove(&inner)?;
            opened.write_back(Path::new(&img))?;
            logger::success(&format!("rm: {}:{}", img, inner));
        }
    }
    Ok(())
}

// =====================================================================
// --directory
// =====================================================================

fn run_directory(m: &ArgMatches) -> error::Result<()> {
    let dir = require_string(m, "dir", "-d / --dir")?;
    let depth: u32 = m
        .get_one::<String>("depth")
        .map(|s| s.parse().unwrap_or(1))
        .unwrap_or(1)
        .max(1);
    let spec = PathSpec::parse(&dir);
    let partition = m.get_one::<String>("partition").map(|s| s.as_str());
    match spec {
        PathSpec::Host(_p) => {
            return Err(error::BuildError::InvalidParam(
                "--directory on a host path not supported; use ls(1) or pass an IMG:path".into(),
            ));
        }
        PathSpec::Image(img, inner) => {
            let mut opened = fs::image::open_for_modify(Path::new(&img), parse_partition(partition))?;
            list_recurse(opened.backend(), &inner, 0, depth);
        }
    }
    Ok(())
}

fn list_recurse(fs_tree: &dyn fs::backend::FsBackend, path: &str, cur_depth: u32, max_depth: u32) {
    let indent = "  ".repeat(cur_depth as usize);
    let children = match fs_tree.list_dir(path) {
        Ok(c) => c,
        Err(_) => {
            println!("{} {}: <not found>", indent, path);
            return;
        }
    };
    // Print the directory header (except for the very first call where
    // --directory already printed the path).
    if cur_depth > 0 {
        println!("{} {}:", indent.trim_end(), path);
    }
    for entry in &children {
        let marker = if entry.is_dir { "/" } else { "" };
        println!("{}  {}{}", indent, entry.name, marker);
    }
    if cur_depth + 1 < max_depth {
        for entry in &children {
            if entry.is_dir {
                let sub = if path.is_empty() || path.ends_with('/') {
                    format!("{}{}", path, entry.name)
                } else {
                    format!("{}/{}", path, entry.name)
                };
                list_recurse(fs_tree, &sub, cur_depth + 1, max_depth);
            }
        }
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn require_string(m: &ArgMatches, key: &str, hint: &str) -> error::Result<String> {
    m.get_one::<String>(key)
        .cloned()
        .ok_or_else(|| error::BuildError::InvalidParam(format!("missing required argument {}", hint)))
}

fn parse_partition(s: Option<&str>) -> Option<u32> {
    s.and_then(|v| v.parse().ok())
}

/// A `SRC` or `DST` argument. Either a plain host path, or an image path
/// followed by a colon and an inner path.
enum PathSpec {
    Host(PathBuf),
    Image(String, String),
}

impl PathSpec {
    fn parse(raw: &str) -> Self {
        if let Some(idx) = raw.rfind(':') {
            let left = &raw[..idx];
            let right = &raw[idx + 1..];
            if !left.is_empty() {
                // Always treat the colon form as image, even if right is
                // empty (caller wants the image root).
                if let Some(dot) = left.rfind('.') {
                    let ext = &left[dot..];
                    if matches!(ext, ".img" | ".qcow2" | ".iso") {
                        return PathSpec::Image(left.to_string(), right.to_string());
                    }
                }
                if left.contains('/') || left.contains('\\') {
                    return PathSpec::Image(left.to_string(), right.to_string());
                }
            }
        }
        PathSpec::Host(PathBuf::from(raw))
    }
}
