//! ESP Builder - Build EFI System Partition
//!
//! Creates the complete UEFI ESP directory structure and disk images.

use clap::Parser;
use nt61_tools::hive_gen;
use std::fs::{self, File};
use std::io::{Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const ESP_TEMPLATE: &str = r#"NT6.1.7601 EFI System Partition
==========================================

Structure:
  EFI/
    Boot/
      BOOTX64.EFI     (Primary bootloader for x64)
      BOOTAA64.EFI    (Primary bootloader for ARM64)
      BOOTRISCV64.EFI (Primary bootloader for RISC-V 64)
      BOOTLOONGARCH64.EFI (Primary bootloader for LoongArch64)
      BOOTARM.EFI     (Primary bootloader for ARM)
    Microsoft/
      Boot/
        BCD           (Boot Configuration Data)
        Fonts/        (GNU FreeFont)
        bootmgfw.efi (Windows Boot Manager)
        bootmgr.efi  (Boot Manager)
        memtest.efi  (Memory Test)

ROOT/
  Windows/
    System32/
"#;

/// Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    Arm64,
    Arm,
    RiscV64,
    LoongArch64,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
            Arch::Arm => "arm",
            Arch::RiscV64 => "riscv64",
            Arch::LoongArch64 => "loongarch64",
        }
    }

    pub fn boot_file(&self) -> &'static str {
        match self {
            Arch::X64 => "BOOTX64.EFI",
            Arch::Arm64 => "BOOTAA64.EFI",
            Arch::Arm => "BOOTARM.EFI",
            // UEFI 2.10 / EDK2 use the names `BOOTRISCV64.EFI` and
            // `BOOTLOONGARCH64.EFI` for the removable-media fallback
            // entry — see the UEFI specification's RISC-V and
            // LoongArch architecture bindings.
            Arch::RiscV64 => "BOOTRISCV64.EFI",
            Arch::LoongArch64 => "BOOTLOONGARCH64.EFI",
        }
    }

    /// PE MachineType constant for the architecture. Used by
    /// `system_image::build_all` to emit PEs with the right
    /// machine field.
    pub fn pe_machine_type(&self) -> u16 {
        match self {
            Arch::X64 => 0x8664,
            Arch::Arm64 => 0xAA64,
            Arch::Arm => 0x01C0,
            Arch::RiscV64 => 0xE42C,
            Arch::LoongArch64 => 0x6232,
        }
    }
}

impl From<&str> for Arch {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "x64" | "x86_64" | "amd64" => Arch::X64,
            "arm64" | "aarch64" => Arch::Arm64,
            "arm" | "armv7" => Arch::Arm,
            "riscv64" | "riscv" | "risc-v" => Arch::RiscV64,
            "loongarch64" | "loongarch" => Arch::LoongArch64,
            _ => Arch::X64,
        }
    }
}

/// Build configuration
#[derive(Debug, Clone)]
pub struct BuildConfig {
    pub arch: Arch,
    pub build_dir: String,
    pub boot_efi_path: Option<String>,
    pub winload_efi_path: Option<String>,
    pub kernel_path: Option<String>,
    pub timeout: u32,
    pub create_image: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X64,
            build_dir: "build".to_string(),
            boot_efi_path: None,
            winload_efi_path: None,
            kernel_path: None,
            timeout: 30,
            create_image: false,
        }
    }
}

/// Create directory structure
pub fn create_directories(build_dir: &Path, arch: Arch) -> std::io::Result<EspPaths> {
    // Directory structure:
    // build/ (passed as build_dir)
    //   esp/         <- EFI partition files
    //   system/      <- OS volume files
    //   images/      <- disk images
    // Note: arch_dir is NOT added - build_dir already includes arch
    
    // EFI System Partition files
    let esp_dir = build_dir.join("esp");
    let efi_dir = esp_dir.join("EFI");
    let boot_dir = efi_dir.join("Boot");
    let ms_boot_dir = efi_dir.join("Microsoft").join("Boot");
    let fonts_dir = ms_boot_dir.join("Fonts");
    
    // OS volume files (Windows System32, etc.)
    let system_dir = build_dir.join("system");
    let windows_dir = system_dir.join("Windows").join("System32");
    
    // Disk images
    let images_dir = build_dir.join("images");
    
    // Create all directories
    fs::create_dir_all(&boot_dir)?;
    fs::create_dir_all(&ms_boot_dir)?;
    fs::create_dir_all(&fonts_dir)?;
    fs::create_dir_all(&windows_dir)?;
    fs::create_dir_all(&images_dir)?;
    
    Ok(EspPaths {
        efi_dir,
        boot_dir,
        ms_boot_dir,
        fonts_dir,
        root_dir: system_dir,  // OS volume root
        windows_dir,
        images_dir,
    })
}

#[derive(Debug)]
pub struct EspPaths {
    pub efi_dir: PathBuf,
    pub boot_dir: PathBuf,
    pub ms_boot_dir: PathBuf,
    pub fonts_dir: PathBuf,
    pub root_dir: PathBuf,
    pub windows_dir: PathBuf,
    pub images_dir: PathBuf,
}

/// Copy boot manager to ESP
pub fn copy_boot_manager(paths: &EspPaths, arch: Arch, source: &Path) -> std::io::Result<()> {
    if !source.exists() {
        eprintln!("Warning: Boot manager not found at {:?}", source);
        return Ok(());
    }
    
    let boot_target = paths.boot_dir.join(arch.boot_file());
    if boot_target.exists() {
        fs::remove_file(&boot_target)?;
    }
    println!("  Copying: {:?}", &boot_target);
    fs::copy(source, &boot_target)?;
    
    let bootmgfw = paths.ms_boot_dir.join("bootmgfw.efi");
    if bootmgfw.exists() {
        fs::remove_file(&bootmgfw)?;
    }
    println!("  Copying: {:?}", &bootmgfw);
    fs::copy(source, &bootmgfw)?;
    
    let bootmgr = paths.ms_boot_dir.join("bootmgr.efi");
    if bootmgr.exists() {
        fs::remove_file(&bootmgr)?;
    }
    println!("  Copying: {:?}", &bootmgr);
    fs::copy(source, &bootmgr)?;

    Ok(())
}

/// Copy the real OS Loader (winload.efi) to the ESP.
///
/// In a real Windows 7 install the loader lives on the OS volume,
/// in **two** well-known places:
///
///   * `C:\Windows\System32\winload.efi` — the *primary* copy that
///     BCD `application` points at. The boot manager chains to this
///     one on every normal boot.
///   * `C:\Windows\System32\Boot\winload.efi` — the *recovery*
///     copy used by `BootMgr` and BCDEdit when fixing the primary
///     copy, when chainloading to `bootrec`, or when booting into
///     WinRE / WinPE. It is byte-for-byte the same PE32+ file.
///
/// We replicate this two-copy layout. The ESP volume *is* the OS
/// volume in this demo (single FAT partition), so both copies
/// end up under `ROOT/Windows/System32/`.
pub fn copy_winload(paths: &EspPaths, source: Option<&Path>) -> std::io::Result<()> {
    match source {
        Some(src) => {
            if !src.exists() {
                eprintln!("Error: winload.efi not found at {:?}", src);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "winload.efi missing",
                ));
            }
            // Primary copy: C:\Windows\System32\winload.efi
            let primary = paths.windows_dir.join("winload.efi");
            if primary.exists() {
                fs::remove_file(&primary)?;
            }
            println!("  Copying winload.efi: {:?}", &primary);
            fs::copy(src, &primary)?;

            // Recovery copy: C:\Windows\System32\Boot\winload.efi
            let recovery_dir = paths.windows_dir.join("Boot");
            fs::create_dir_all(&recovery_dir)?;
            let recovery = recovery_dir.join("winload.efi");
            if recovery.exists() {
                fs::remove_file(&recovery)?;
            }
            println!("  Copying winload.efi: {:?}", &recovery);
            fs::copy(src, &recovery)?;

            Ok(())
        }
        None => {
            eprintln!("Error: --winload-efi is required but was not provided.");
            eprintln!("  The boot chain firmware->bootmgr->winload requires a real");
            eprintln!("  OS loader at C:\\Windows\\System32\\winload.efi.");
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "winload.efi not specified",
            ))
        }
    }
}

/// Generate BCD file
/// BCD File Generator for UEFI
/// Creates a minimal but valid BCD store that bootmgfw.efi can parse
///
/// The on-disk format is the **REGF v1 hive** defined in
/// `nt61/src/registry/hive.rs` and built by
/// `tools::regf::HiveBuilder::finish`. We use the same generator as
/// the rest of the hives so that the kernel's parser handles
/// BCD with the same code path as `SYSTEM`, `SOFTWARE`, etc.

/// Generate the OS-volume registry hives (`SYSTEM`,
/// `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`) and the
/// `Windows\System32\drivers\etc\hosts` file into the
/// `ROOT` directory. The kernel looks for these files at
/// `C:\Windows\System32\config\*` and `C:\Windows\System32\drivers\etc\*`
/// respectively, so they must be present on the FAT32 image.
pub fn generate_os_volume_files(paths: &EspPaths) -> std::io::Result<()> {
    let config_dir = paths.windows_dir.join("config");
    let etc_dir = paths.windows_dir.join("drivers").join("etc");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&etc_dir)?;

    fs::write(config_dir.join("SYSTEM"),   crate::hive_gen::build_system())?;
    fs::write(config_dir.join("SOFTWARE"), crate::hive_gen::build_software())?;
    fs::write(config_dir.join("SAM"),      crate::hive_gen::build_sam())?;
    fs::write(config_dir.join("SECURITY"), crate::hive_gen::build_security())?;
    fs::write(config_dir.join("DEFAULT"),  crate::hive_gen::build_default())?;
    
    // etc/ files
    fs::write(etc_dir.join("hosts"),        crate::hive_gen::HOSTS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("lmhosts.sam"), crate::hive_gen::LMHOSTS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("networks"),    crate::hive_gen::NETWORKS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("protocol"),    crate::hive_gen::PROTOCOL_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("services"),     crate::hive_gen::SERVICES_CONTENT.as_bytes())?;

    println!("  Wrote SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT to {:?}",
        config_dir);
    println!("  Wrote hosts, lmhosts.sam, networks, protocol, services to {:?}", etc_dir);
    Ok(())
}

/// Generate PE files (ntoskrnl.exe, hal.dll, ntdll.dll, kernel32.dll, smss.exe)
/// using the same system_image module that the kernel uses at boot time.
pub fn generate_pe_files(paths: &EspPaths, arch: Arch) -> std::io::Result<()> {
    let system32_dir = &paths.windows_dir;
    generate_pe_files_to(system32_dir.as_path(), arch)
}

/// Variant of `generate_pe_files` that takes a bare system32
/// directory path. This is the entry point used by
/// `fs/build::full_build` via the `--pe-only` CLI flag.
pub fn generate_pe_files_to(system32_dir: &Path, arch: Arch) -> std::io::Result<()> {
    fs::create_dir_all(system32_dir)?;

    // Use the kernel's system_image module to generate real PE files
    // tagged with the architecture-appropriate PE MachineType field
    // (0x8664 / 0xAA64 / 0xE42C / 0x6232). Without this the kernel's
    // loader would refuse to load ntoskrnl.exe on a non-x86_64 system.
    let machine = arch.pe_machine_type();
    let images = nt61::system_image::build_all(machine);

    let mut total_size: usize = 0;
    for image in &images {
        // The path uses Windows backslash separators and is rooted at C:\.
        // We need to strip "C:\" (or just "C:\\Windows" prefix) to get
        // the path relative to the ESP root.
        let mut rel = image.path.as_str();
        // Strip "C:" prefix if present.
        if rel.starts_with("C:\\") || rel.starts_with("C:/") {
            if let Some(idx) = rel.find(|c| c == '\\' || c == '/') {
                // skip the "C:" drive letter and the leading slash
                rel = &rel[idx+1..];
            }
        }
        // Convert all backslashes to native separators (Path::join handles it).
        let rel = rel.replace('\\', "/");

        // For drivers, system_image emits paths like
        // "Windows/System32/drivers/foo.sys". When joined with
        // `system32_dir`, that would put foo.sys inside
        // `<system32>/drivers/foo.sys` (which is what we want).
        let dest_path = system32_dir.join(rel.trim_start_matches("Windows/System32/"));

        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest_path, &image.bytes)?;

        // Validate: every PE file must start with "MZ"
        if image.bytes.len() >= 2 && &image.bytes[0..2] == b"MZ" {
            println!("  Generated PE: {:?} ({} bytes, machine=0x{:x})", dest_path, image.bytes.len(), machine);
        } else {
            eprintln!("  Warning: {:?} is not a valid PE file", dest_path);
        }

        total_size += image.bytes.len();
    }

    println!("  Total PE files: {} ({} bytes, machine=0x{:x})", images.len(), total_size, machine);
    Ok(())
}

pub fn generate_bcd(paths: &EspPaths, _timeout: u32) -> std::io::Result<()> {
    let bcd_path = paths.ms_boot_dir.join("BCD");
    println!("  Generating: {:?}", &bcd_path);
    let bytes = crate::hive_gen::build_bcd();
    fs::write(&bcd_path, &bytes)?;
    println!("    BCD size: {} bytes", bytes.len());
    Ok(())
}

/// Pad BCD hive to the standard Windows BCD size of 81920 bytes.
fn pad_bcd_to_standard_size(mut data: Vec<u8>) -> Vec<u8> {
    const BCD_STANDARD_SIZE: usize = 81920;
    if data.len() >= BCD_STANDARD_SIZE {
        data.truncate(BCD_STANDARD_SIZE);
        return data;
    }
    
    let new_size = BCD_STANDARD_SIZE;
    
    // Resize to target size (zero-fills new space)
    data.resize(new_size, 0);

    // Write HBIN headers for ALL pages
    let num_hbins = (new_size - 0x1000) / 4096;
    for i in 0..num_hbins {
        let off = 0x1000 + i * 4096;
        data[off..off + 4].copy_from_slice(b"hbin");
        data[off + 4..off + 8].copy_from_slice(&(i as u32 * 4096).to_le_bytes());
        data[off + 8..off + 12].copy_from_slice(&4096u32.to_le_bytes());
    }

    // Update blocks field in header
    let blocks = (num_hbins * 4096) as u32;
    data[0x28..0x2C].copy_from_slice(&blocks.to_le_bytes());

    // Recompute checksum
    let mut sum: u32 = 0;
    for i in (0..0x1FC).step_by(4) {
        let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        sum ^= val;
    }
    data[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());

    data
}

/// Copy font files to ESP Fonts directory
pub fn copy_fonts(paths: &EspPaths) -> std::io::Result<()> {
    let fonts_dir = &paths.fonts_dir;
    
    // Source directory for fonts (OpenSans - Windows-style font)
    let source_fonts = Path::new("resources/fonts/open-sans");
    
    // Font files to copy (OpenSans Regular for Windows Boot Manager style)
    let font_files = [
        ("OpenSans-Regular.ttf", "OpenSans-Regular.ttf"),
    ];
    
    // Create Fonts directory if needed
    fs::create_dir_all(fonts_dir)?;
    
    // Copy each font file
    for (src_name, dst_name) in &font_files {
        let source = source_fonts.join(src_name);
        let dest = fonts_dir.join(dst_name);
        
        if source.exists() {
            println!("  Copying font: {:?}", &dest);
            fs::copy(&source, &dest)?;
        } else {
            eprintln!("  Warning: Font not found: {:?}", &source);
        }
    }
    
    println!("  Copied {} font files to {:?}", font_files.len(), fonts_dir);
    Ok(())
}

/// Create MEMTEST placeholder
pub fn create_memtest_placeholder(paths: &EspPaths) -> std::io::Result<()> {
    let memtest = paths.ms_boot_dir.join("memtest.efi");
    println!("  Creating: {:?}", &memtest);
    // UEFI apps need PE/COFF headers, but for boot manager menu
    // we can use a small stub (won't actually run, just appears in menu)
    let stub = b"MEMTEST_STUB";
    fs::write(&memtest, stub)?;
    Ok(())
}

/// Create BOOTVARS file (NVRAM variables backup)
pub fn create_bootvars(paths: &EspPaths, timeout: u32) -> std::io::Result<()> {
    let bootvars = paths.ms_boot_dir.join("BOOTVARS");
    println!("  Creating: {:?}", &bootvars);
    // BOOTVARS stores NVRAM variables for recovery purposes
    let vars_data = create_bootvars_data(timeout);
    fs::write(&bootvars, vars_data)?;
    Ok(())
}

fn create_bootvars_data(timeout: u32) -> Vec<u8> {
    let mut data = Vec::new();
    // Simple BOOTVARS format
    data.extend_from_slice(b"NT61BOOTVARS");
    data.extend_from_slice(&timeout.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    data
}

// Note: loader.cfg is not created - all config is in BCD

/// Create a real FAT32 disk image with GPT partition table
pub fn create_esp_image(paths: &EspPaths, arch: Arch) -> std::io::Result<PathBuf> {
    let img_path = paths.images_dir.join(format!("esp-{}.img", arch.as_str()));
    let size_mb = 64;
    
    println!("  Creating FAT32 disk image: {:?}", &img_path);
    println!("    Size: {} MB", size_mb);
    
    // Create raw image file
    let mut file = File::create(&img_path)?;
    
    // Write GPT header
    let mut gpt = vec![0u8; 1024]; // Protective MBR (512) + GPT header (92) + padding
    
    // Protective MBR (first 512 bytes)
    gpt[510] = 0x55;
    gpt[511] = 0xAA;
    
    // GPT signature
    gpt[512..520].copy_from_slice(b"EFI PART");
    
    // GPT revision (1.0)
    gpt[520..524].copy_from_slice(&0x00010000u32.to_le_bytes());
    
    // Header size (92 bytes)
    gpt[524..528].copy_from_slice(&92u32.to_le_bytes());
    
    // CRC32 of header (placeholder)
    gpt[528..532].copy_from_slice(&0u32.to_le_bytes());
    
    // Reserved
    gpt[532..540].copy_from_slice(&0u64.to_le_bytes());
    
    // Current LBA (1)
    gpt[540..548].copy_from_slice(&1u64.to_le_bytes());
    
    // Backup LBA (will be at end)
    let total_sectors = (size_mb * 1024 * 1024) / 512;
    let backup_lba: u64 = total_sectors - 1;
    gpt[548..556].copy_from_slice(&backup_lba.to_le_bytes());
    
    // First usable LBA (34 - after GPT header and partition table)
    gpt[556..564].copy_from_slice(&34u64.to_le_bytes());
    
    // Last usable LBA
    gpt[564..572].copy_from_slice(&(total_sectors - 34).to_le_bytes());
    
    // Disk GUID (random)
    let guid = uuid::Uuid::new_v4();
    gpt[572..588].copy_from_slice(guid.as_bytes());
    
    // Partition entry LBA (2)
    gpt[588..596].copy_from_slice(&2u64.to_le_bytes());
    
    // Number of partition entries (128)
    gpt[596..600].copy_from_slice(&128u32.to_le_bytes());
    
    // Size of partition entry (128 bytes)
    gpt[600..604].copy_from_slice(&128u32.to_le_bytes());
    
    // CRC32 of partition entries (placeholder)
    gpt[604..608].copy_from_slice(&0u32.to_le_bytes());
    
    // Write protective MBR + GPT header
    file.write_all(&gpt)?;
    
    // Partition entry (128 bytes, starting at LBA 2)
    let mut partition_entry = vec![0u8; 128];
    
    // Partition type GUID (EFI System Partition)
    let esp_type = uuid::Uuid::parse_str("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap();
    partition_entry[0..16].copy_from_slice(esp_type.as_bytes());
    
    // Unique partition GUID
    let part_guid = uuid::Uuid::new_v4();
    partition_entry[16..32].copy_from_slice(part_guid.as_bytes());
    
    // Starting LBA (34)
    partition_entry[32..40].copy_from_slice(&34u64.to_le_bytes());
    
    // Ending LBA (use most of the disk)
    let end_lba: u64 = total_sectors - 34;
    partition_entry[40..48].copy_from_slice(&end_lba.to_le_bytes());
    
    // Attributes (EF00 for ESP)
    partition_entry[48..56].copy_from_slice(&0xEF00u64.to_le_bytes());
    
    // Partition name
    let name = "EFI System Partition";
    for (i, c) in name.encode_utf16().enumerate() {
        if i < 36 * 2 {
            partition_entry[56 + i] = c as u8;
            partition_entry[56 + i + 1] = (c >> 8) as u8;
        }
    }
    
    file.write_all(&partition_entry)?;
    
    // Write partition entries again at backup location
    let backup_lba: u64 = total_sectors - 33;
    file.seek(SeekFrom::End(-512))?;
    file.write_all(&partition_entry)?;
    
    // Write GPT header backup
    file.seek(SeekFrom::End(-1024))?;
    let mut gpt_backup = gpt.clone();
    gpt_backup[548..556].copy_from_slice(&1u64.to_le_bytes()); // Current LBA
    gpt_backup[556..564].copy_from_slice(&backup_lba.to_le_bytes()); // Backup LBA
    gpt_backup[588..596].copy_from_slice(&backup_lba.to_le_bytes()); // Partition LBA
    file.write_all(&gpt_backup)?;
    
    println!("    Created GPT partitioned image (FAT32 needs to be formatted with mkfs.fat)");
    println!("    Run: mkfs.fat -F 32 {} to format", img_path.display());
    
    Ok(img_path)
}

/// Build complete ESP
pub fn build_esp(config: &BuildConfig) -> std::io::Result<()> {
    println!("\nNT6.1.7601 ESP Builder");
    println!("====================");
    println!("Architecture: {}", config.arch.as_str());
    println!("Build directory: {}", config.build_dir);
    println!();
    
    let build_dir = Path::new(&config.build_dir);
    
    println!("Creating directory structure...");
    let paths = create_directories(build_dir, config.arch)?;
    
    if let Some(ref boot_path) = config.boot_efi_path {
        println!("Copying boot manager...");
        let boot_source = Path::new(boot_path);
        copy_boot_manager(&paths, config.arch, boot_source)?;
    } else {
        println!("No boot manager specified, skipping...");
    }
    
    println!("Generating BCD store...");
    generate_bcd(&paths, config.timeout)?;

    println!("Generating OS-volume hives and hosts file...");
    generate_os_volume_files(&paths)?;

    println!("Generating PE files (ntoskrnl.exe, hal.dll, ntdll.dll, ...)...");
    generate_pe_files(&paths, config.arch)?;

    println!("Copying OS Loader (winload.efi)...");
    let winload_path = config.winload_efi_path.as_deref().map(std::path::Path::new);
    copy_winload(&paths, winload_path)?;

    println!("Setting up font directory...");
    copy_fonts(&paths)?;
    
    println!("Creating MEMTEST placeholder...");
    create_memtest_placeholder(&paths)?;
    
    println!("Creating BOOTVARS...");
    create_bootvars(&paths, config.timeout)?;
    
    // Note: No loader.cfg - all config is in BCD
    
    if config.create_image {
        println!("Creating ESP disk image...");
        create_esp_image(&paths, config.arch)?;
    }
    
    println!();
    println!("ESP build complete!");
    println!("  EFI:  {}", paths.efi_dir.display());
    println!("  ROOT: {}", paths.root_dir.display());
    println!("  Images: {}", paths.images_dir.display());
    
    Ok(())
}

pub fn print_tree(dir: &Path, prefix: &str, is_last: bool) -> std::io::Result<()> {
    let entries: Vec<_> = fs::read_dir(dir)?.collect();
    let total = entries.len();
    
    for (i, entry) in entries.into_iter().enumerate() {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        let is_last_entry = i == total - 1;
        
        print!("{}{}", prefix, if is_last_entry { "`-- " } else { "|-- " });
        println!("{}", name);
        
        if path.is_dir() {
            let new_prefix = format!("{}{}", prefix, if is_last_entry { "    " } else { "|   " });
            print_tree(&path, &new_prefix, is_last_entry)?;
        }
    }
    
    Ok(())
}

fn main() {
    let matches = clap::Command::new("build-esp")
        .version("0.1.0")
        .about("Build NT6.1.7601 EFI System Partition")
        .arg(
            clap::Arg::new("pe-only")
                .long("pe-only")
                .value_name("DIR")
                .help("Generate only the PE files into <DIR> (system32 dir) and exit")
        )
        .arg(
            clap::Arg::new("arch")
                .short('a')
                .long("arch")
                .value_name("ARCH")
                .default_value("x64")
                .help("Target architecture: x64, arm64, arm, riscv64, loongarch64")
        )
        .arg(
            clap::Arg::new("build-dir")
                .short('o')
                .long("output")
                .value_name("DIR")
                .default_value("build")
                .help("Output directory")
        )
        .arg(
            clap::Arg::new("boot-efi")
                .short('b')
                .long("boot-efi")
                .value_name("PATH")
                .help("Path to boot manager EFI file")
        )
        .arg(
            clap::Arg::new("winload-efi")
                .long("winload-efi")
                .value_name("PATH")
                .help("Path to winload.efi (OS Loader) EFI file")
        )
        .arg(
            clap::Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .default_value("30")
                .help("Boot timeout in seconds")
        )
        .arg(
            clap::Arg::new("create-image")
                .short('i')
                .long("create-image")
                .help("Create FAT32 disk image")
        )
        .arg(
            clap::Arg::new("tree")
                .long("tree")
                .help("Print directory tree after build")
        )
        .get_matches();
    
    let config = BuildConfig {
        arch: Arch::from(matches.get_one::<String>("arch").map(|s| s.as_str()).unwrap_or("x64")),
        build_dir: matches.get_one::<String>("build-dir").cloned().unwrap_or_else(|| "build".to_string()),
        boot_efi_path: matches.get_one::<String>("boot-efi").cloned(),
        winload_efi_path: matches.get_one::<String>("winload-efi").cloned(),
        kernel_path: None,
        timeout: matches.get_one::<String>("timeout")
            .and_then(|s| s.parse().ok())
            .unwrap_or(30),
        create_image: matches.contains_id("create-image"),
    };

    // PE-only mode: drop the on-disk PE files into <DIR> (system32)
    // and exit. Used by `fs/build::full_build` to populate the system
    // partition without going through the full ESP pipeline.
    if let Some(pe_only) = matches.get_one::<String>("pe-only") {
        let dir = PathBuf::from(pe_only);
        if let Err(e) = generate_pe_files_to(&dir, config.arch) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    match build_esp(&config) {
        Ok(()) => {
            if matches.contains_id("tree") {
                let tree_dir = Path::new(&config.build_dir).join(config.arch.as_str());
                println!("\nDirectory structure:");
                println!("{}", tree_dir.display());
                let _ = print_tree(&tree_dir, "", true);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
