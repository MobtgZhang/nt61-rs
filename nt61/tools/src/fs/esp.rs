//! ESP (EFI System Partition) Builder Module
//!
//! Builds the FAT32 EFI System Partition for an NT6.1.7601 (Windows 7)
//! boot flow. The on-disk layout of a real Windows 7 ESP is:
//!
//! ```text
//! \EFI\Boot\BOOTX64.EFI                <- removable-media fallback (firmware lookup)
//! \EFI\Microsoft\Boot\bootmgfw.efi     <- Windows Boot Manager
//! \EFI\Microsoft\Boot\BCD              <- Boot Configuration Data
//! \EFI\Microsoft\Boot\Fonts\            <- boot screen fonts
//! ```
//!
//! All Windows-specific files (bootmgfw, BCD, winload fallback) live
//! under `\EFI\Microsoft\Boot\` to mirror a real NT 6.1 install. Only
//! the firmware's removable-media fallback (`BOOT<arch>.EFI`) lives
//! directly under `\EFI\Boot\` so the UEFI firmware can find it on
//! non-x86_64 architectures (which OVMF boots from the removable-media
//! path on QEMU).

use crate::error::Result;
use crate::hive_gen;
use crate::logger as log;
use std::path::{Path, PathBuf};

// =====================================================================
// ESP Directory Structure (FAT32 boot partition layout)
//
// Mirrors a real Windows 7 install:
//   \EFI\BOOT\             — firmware removable-media fallback
//                            (per UEFI Spec 2.10 §3.4.1.1 the path
//                            MUST be uppercase; some firmware
//                            implementations — notably LoongArch64
//                            EDK2 builds and the Loongson XA61200
//                            board — treat removable-media paths as
//                            case-sensitive, so a lowercase
//                            "EFI/Boot" is silently dropped from the
//                            candidate boot list. See the GRUB
//                            commit "[PATCH v2] util/grub-mkrescue:
//                            use capitalised paths for removable EFI
//                            imag" on grub-devel for the canonical
//                            discussion.)
//   \EFI\Microsoft\Boot\   — Windows-specific boot files
//   \EFI\Microsoft\Boot\Fonts\
// =====================================================================

const ESP_STRUCTURE: &[&str] = &["EFI/BOOT", "EFI/Microsoft/Boot", "EFI/Microsoft/Boot/Fonts"];

// =====================================================================
// ESP Builder
// =====================================================================

/// Builder for an NT6.1.7601 EFI System Partition.
pub struct EspBuilder {
    output_dir: PathBuf,
    boot_efi: Option<PathBuf>,
    font: Option<PathBuf>,
    /// Architecture tag (e.g. "X64", "AA64", "RISCV64", "LOONGARCH64")
    /// used to name the fallback `BOOT<arch>.EFI` file the firmware
    /// searches for on architectures other than x86_64.
    arch: String,
    esp_files: Vec<(String, PathBuf)>,
}

impl EspBuilder {
    /// Create a new ESP builder rooted at `output_dir`.
    pub fn new(output_dir: &Path, arch: &str) -> Result<Self> {
        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            boot_efi: None,
            font: None,
            // Per-arch fallback EFI filename. OVMF looks for `BOOT<ARCH>.EFI`
            // in the ESP's `\EFI\Boot` directory on architectures other than
            // x86_64. The arch tag uses the OVMF naming convention:
            // x86_64 -> "X64", aarch64 -> "AA64", riscv64 -> "RISCV64",
            // loongarch64 -> "LOONGARCH64".
            arch: arch.to_string(),
            esp_files: Vec::new(),
        })
    }

    /// Provide the boot-manager EFI binary (the file that ends up at
    /// `EFI\Boot\bootmgfw.efi` and at `EFI\Boot\BOOT<arch>.EFI`).
    pub fn with_boot_efi(mut self, path: Option<&Path>) -> Result<Self> {
        self.boot_efi = path.map(|p| p.to_path_buf());
        Ok(self)
    }

    /// Provide a TTF font that will be installed at
    /// `EFI\Boot\Fonts\wgl4_boot.ttf`.
    pub fn with_font<P: AsRef<Path>>(mut self, path: Option<P>) -> Self {
        self.font = path.map(|p| p.as_ref().to_path_buf());
        self
    }

    /// Register an extra file to copy into the ESP.
    pub fn add_esp_file<P: AsRef<Path>>(mut self, relative_path: &str, source: P) -> Result<Self> {
        self.esp_files
            .push((relative_path.to_string(), source.as_ref().to_path_buf()));
        Ok(self)
    }

    /// Create the ESP directory skeleton.
    pub fn create_structure(&self) -> Result<()> {
        log::info("Creating ESP directory structure...");
        for path in ESP_STRUCTURE {
            let full_path = self.output_dir.join(path);
            crate::fs::dir::create_dir_all(&full_path)?;
            log::debug(&format!("Created: {}", path));
        }
        Ok(())
    }

    /// Install the Windows Boot Manager at the canonical Windows 7 path
    /// `EFI\Microsoft\Boot\bootmgfw.efi` (matching a real install).
    /// Also drop a copy at the firmware fallback path
    /// `EFI\Boot\BOOT<arch>.EFI` so OVMF on non-x86_64 QEMU can find it
    /// via the removable-media lookup.
    pub fn copy_boot_manager(&self) -> Result<()> {
        if let Some(ref src) = self.boot_efi {
            if !src.exists() {
                log::warn(&format!("Boot EFI not found: {}", src.display()));
                return Ok(());
            }
            let canonical = self.output_dir.join("EFI/Microsoft/Boot/bootmgfw.efi");
            log::info(&format!(
                "Copying boot manager: {} -> {}",
                src.display(),
                canonical.display()
            ));
            crate::fs::copy::copy_file(src, &canonical)?;

            let fallback = self
                .output_dir
                .join(format!("EFI/BOOT/BOOT{}.EFI", self.arch));
            log::info(&format!(
                "Copying boot manager (firmware fallback): {} -> {}",
                src.display(),
                fallback.display()
            ));
            crate::fs::copy::copy_file(src, &fallback)?;
        }
        Ok(())
    }

    /// Copy registered extra files into the ESP.
    pub fn copy_extra_files(&self) -> Result<()> {
        for (relative_path, source) in &self.esp_files {
            let dest = self.output_dir.join(relative_path);
            if let Some(parent) = dest.parent() {
                crate::fs::dir::create_dir_all(parent)?;
            }
            log::info(&format!(
                "Copying: {} -> {}",
                source.display(),
                dest.display()
            ));
            crate::fs::copy::copy_file(source, &dest)?;
        }
        Ok(())
    }

    /// Write the BCD file at `EFI\Microsoft\Boot\BCD` — the canonical
    /// Windows 7 location (and the only place a real Windows 7 install
    /// puts it; copying a duplicate to `EFI\BOOT\BCD` violates the
    /// Windows 7 layout and clutters the firmware fallback dir with
    /// files the firmware was never supposed to see).
    ///
    /// `bcd_bytes` should be the output of `hive_gen::build_bcd()`.
    pub fn write_bcd_file(output_dir: &Path, bcd_bytes: &[u8]) -> Result<()> {
        let bcd_path = output_dir.join("EFI/Microsoft/Boot/BCD");
        if let Some(parent) = bcd_path.parent() {
            crate::fs::dir::create_dir_all(parent)?;
        }
        std::fs::write(&bcd_path, bcd_bytes)?;
        log::info(&format!(
            "BCD written: {} ({} bytes)",
            bcd_path.display(),
            bcd_bytes.len()
        ));
        Ok(())
    }

    /// Generate and write BCD to a specific path.
    /// This is useful for testing or when BCD needs to be written separately.
    pub fn write_bcd_to_path(&self, path: &Path) -> Result<()> {
        let bcd_bytes = hive_gen::build_bcd();
        std::fs::write(path, &bcd_bytes)?;
        log::info(&format!(
            "BCD written: {} ({} bytes)",
            path.display(),
            bcd_bytes.len()
        ));
        Ok(())
    }

    /// Install the boot-screen font at
    /// `EFI\Microsoft\Boot\Fonts\wgl4_boot.ttf` — the canonical
    /// Windows 7 location. (The legacy `EFI\BOOT\Fonts\` path would
    /// live next to the firmware-removable dir's `BOOT<arch>.EFI`
    /// and is *not* produced by any real install — leaving it
    /// empty keeps `EFI\BOOT\` strictly minimal, which makes OVMF
    /// easier to reason about during bring-up.)
    pub fn copy_fonts(&self) -> Result<()> {
        let fonts_dir = self.output_dir.join("EFI/Microsoft/Boot/Fonts");
        crate::fs::dir::create_dir_all(&fonts_dir)?;

        if let Some(ref src) = self.font {
            if !src.exists() {
                log::warn(&format!("Boot font not found: {}", src.display()));
                return Ok(());
            }
            let dest = fonts_dir.join("wgl4_boot.ttf");
            log::info(&format!(
                "Installing boot font: {} -> {}",
                src.display(),
                dest.display()
            ));
            crate::fs::copy::copy_file(src, &dest)?;

            let dest_mono = fonts_dir.join("segmono_boot.ttf");
            crate::fs::copy::copy_file(src, &dest_mono)?;
            log::info(&format!(
                "Installing mono boot font: {} -> {}",
                src.display(),
                dest_mono.display()
            ));
        } else {
            log::warn("No boot font configured (EspBuilder::with_font)");
        }
        Ok(())
    }

    /// Build the complete ESP image on disk.
    /// This includes BCD generation at `EFI\Boot\BCD`.
    pub fn build(&self) -> Result<()> {
        log::section("ESP Build");
        self.create_structure()?;
        self.copy_boot_manager()?;
        self.write_bcd()?;
        self.copy_extra_files()?;
        self.copy_fonts()?;
        log::success(&format!(
            "ESP built successfully: {}",
            self.output_dir.display()
        ));
        Ok(())
    }

    /// Generate and write the BCD file at the canonical Windows 7
    /// path `EFI\Microsoft\Boot\BCD` only — the firmware fallback
    /// dir `EFI\BOOT\` is left empty except for `BOOT<arch>.EFI` so
    /// it matches what a real install produces.
    pub fn write_bcd(&self) -> Result<()> {
        log::info("Generating BCD store...");
        let bcd_bytes = hive_gen::build_bcd();
        let bcd_path = self.output_dir.join("EFI/Microsoft/Boot/BCD");
        if let Some(parent) = bcd_path.parent() {
            crate::fs::dir::create_dir_all(parent)?;
        }
        std::fs::write(&bcd_path, &bcd_bytes)?;
        log::info(&format!(
            "BCD written: {} ({} bytes)",
            bcd_path.display(),
            bcd_bytes.len()
        ));
        Ok(())
    }
}

// =====================================================================
// Helpers
// =====================================================================
