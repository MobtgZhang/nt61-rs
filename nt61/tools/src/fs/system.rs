//! System-partition Builder Module
//!
//! Builds the Windows 7 system partition (`C:`), the NTFS volume that
//! holds the operating-system image. The real NT6.1.7601 layout is:
//!
//! ```text
//! C:\Windows\
//!     System32\
//!         ntoskrnl.exe                <- kernel image
//!         hal.dll                     <- hardware abstraction layer
//!         winload.efi                 <- OS loader (EFI)
//!         config\                     <- registry hives
//!             SYSTEM, SOFTWARE, SAM,
//!             SECURITY, DEFAULT, BCD-Template
//!         drivers\                    <- boot-time driver store
//!             *.sys
//!     SysWOW64\                       <- 32-bit subsystem (WoW64)
//!         ...
//!     Boot\                           <- additional boot files
//!         Fonts\
//!         PCAT\
//!     Fonts\
//!     Help\
//!     ...
//! C:\Program Files\
//! C:\Users\
//! ```
//!
//! The builder only populates the boot-critical subset (the kernel,
//! the HAL, the OS loader, the registry hives, and the driver store).
//! Everything else is left for the runtime to materialise.

use std::path::{Path, PathBuf};
use crate::error::Result;
use crate::logger as log;

// =====================================================================
// Windows 7 system partition layout (relative to volume root)
// =====================================================================

const SYSTEM_STRUCTURE: &[(&str, bool)] = &[
    // Top-level Windows directories that exist on a real NT6.1 install.
    ("Windows", true),
    ("Windows/System32", true),
    ("Windows/System32/config", true),
    ("Windows/System32/drivers", true),
    ("Windows/SysWOW64", true),
    ("Windows/Boot", true),
    ("Windows/Boot/Fonts", true),
    ("Windows/Boot/PCAT", true),
    ("Windows/Boot/Diagnostics", true),
    ("Windows/Fonts", true),
    ("Windows/Help", true),
    ("Windows/inf", true),
    ("Windows/Logs", true),
    ("Windows/Prefetch", true),
    ("Windows/Repair", true),
    ("Windows/Resources", true),
    ("Windows/security", true),
    ("Windows/servicing", true),
    ("Windows/System", true),
    ("Windows/Temp", true),
    ("Windows/tracing", true),
    ("Windows/Web", true),
    ("Windows/winhlp32", true),
    ("Program Files", true),
    ("Program Files (x86)", true),
    ("ProgramData", true),
    ("Users", true),
    ("tests", true),
];

// =====================================================================
// System Builder
// =====================================================================

/// Builder for an NT6.1.7601 system partition tree.
pub struct SystemBuilder {
    output_dir: PathBuf,
    kernel: Option<PathBuf>,
    hal: Option<PathBuf>,
    winload: Option<PathBuf>,
    drivers: Vec<PathBuf>,
    extra_files: Vec<(String, PathBuf)>,
}

impl SystemBuilder {
    /// Create a new system builder rooted at `output_dir` (the volume
    /// root, e.g. `build/system/`).
    pub fn new(output_dir: &Path) -> Result<Self> {
        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            kernel: None,
            hal: None,
            winload: None,
            drivers: Vec::new(),
            extra_files: Vec::new(),
        })
    }

    /// Path to `ntoskrnl.exe` (the kernel image).
    pub fn with_kernel(mut self, path: Option<&Path>) -> Self {
        self.kernel = path.map(|p| p.to_path_buf());
        self
    }

    /// Path to `hal.dll`.
    pub fn with_hal(mut self, path: Option<&Path>) -> Self {
        self.hal = path.map(|p| p.to_path_buf());
        self
    }

    /// Path to `winload.efi` (the OS loader).
    pub fn with_winload(mut self, path: Option<&Path>) -> Self {
        self.winload = path.map(|p| p.to_path_buf());
        self
    }

    /// Register one or more driver files (will be copied to
    /// `Windows\System32\drivers\<basename>`).
    pub fn with_driver<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.drivers.push(path.as_ref().to_path_buf());
        self
    }

    /// Register an arbitrary file at an explicit volume-relative path.
    pub fn add_file<P: AsRef<Path>>(
        mut self,
        relative_path: &str,
        source: P,
    ) -> Self {
        self.extra_files
            .push((relative_path.to_string(), source.as_ref().to_path_buf()));
        self
    }

    /// Register `autoexec.bat` to be copied to multiple locations:
    ///
    ///  * `/autoexec.bat` (the legacy NT 6.1 root location — the
    ///    kernel-side `cmd.exe` shim falls back to this if the
    ///    `system/tests/` location is missing)
    ///  * `/tests/autoexec.bat` (used by the kernel-side interactive
    ///    CMD shell when the user types `tests\autoexec.bat` at the
    ///    prompt)
    ///  * `/system/tests/autoexec.bat` — the canonical Win7 system
    ///    layout location. This is what `cmd.exe`'s hand-coded
    ///    `SYS_RUN_AUTOEXEC` syscall passes to the kernel, so the
    ///    user-mode `C:\Windows\System32\cmd.exe` actually finds the
    ///    file at runtime.
    pub fn add_autoexec_bat<P: AsRef<Path>>(mut self, source: P) -> Self {
        let path = source.as_ref().to_path_buf();
        self.extra_files
            .push(("autoexec.bat".to_string(), path.clone()));
        self.extra_files
            .push(("tests/autoexec.bat".to_string(), path.clone()));
        self.extra_files
            .push(("system/tests/autoexec.bat".to_string(), path));
        self
    }

    /// Create the directory skeleton for the system partition.
    pub fn create_structure(&self) -> Result<()> {
        log::info("Creating system partition directory structure...");
        for (path, _) in SYSTEM_STRUCTURE {
            let full_path = self.output_dir.join(path);
            crate::fs::dir::create_dir_all(&full_path)?;
            log::debug(&format!("Created: {}", path));
        }
        Ok(())
    }

    /// Install the OS loader, kernel, and HAL at their canonical paths.
    ///
    /// IMPORTANT: this function deliberately does **not** copy
    /// `ntoskrnl.exe` or `hal.dll`. Both files are produced by
    /// `nt61_tools::build_esp::generate_pe_files`, which calls
    /// `nt61::system_image::build_all` and writes the on-disk PE
    /// images *before* this function runs. Copying the kernel
    /// ELF or the winload EFI binary over those PE files here
    /// would clobber them, which is exactly the failure mode the
    /// original `serial.log` showed (`ntoskrnl.exe: PE header
    /// parse failed`).
    ///
    /// We still copy `winload.efi` here because the OS loader is
    /// not produced by `system_image`; it is the host-built
    /// EFI application that needs to land at
    /// `C:\Windows\System32\winload.efi`.
    pub fn copy_kernel_artifacts(&self) -> Result<()> {
        let sys32 = self.output_dir.join("Windows/System32");
        // Skip ntoskrnl.exe — generated by generate_pe_files().
        // Skip hal.dll     — generated by generate_pe_files().
        if let Some(src) = &self.winload {
            if src.exists() {
                let dest = sys32.join("winload.efi");
                log::info(&format!(
                    "Copying winload: {} -> {}",
                    src.display(),
                    dest.display()
                ));
                crate::fs::copy::copy_file(src, &dest)?;
            } else {
                log::warn(&format!("Winload not found: {}", src.display()));
            }
        }
        Ok(())
    }

    /// Copy each registered driver to `Windows\System32\drivers\`.
    pub fn copy_drivers(&self) -> Result<()> {
        let drv_dir = self.output_dir.join("Windows/System32/drivers");
        for src in &self.drivers {
            if !src.exists() {
                log::warn(&format!("Driver not found: {}", src.display()));
                continue;
            }
            let Some(name) = src.file_name() else { continue };
            let dest = drv_dir.join(name);
            log::info(&format!(
                "Copying driver: {} -> {}",
                src.display(),
                dest.display()
            ));
            crate::fs::copy::copy_file(src, &dest)?;
        }
        Ok(())
    }

    /// Copy any extra files the caller registered.
    pub fn copy_extra_files(&self) -> Result<()> {
        for (rel, src) in &self.extra_files {
            if !src.exists() {
                log::warn(&format!("Extra file not found: {}", src.display()));
                continue;
            }
            let dest = self.output_dir.join(rel);
            if let Some(parent) = dest.parent() {
                crate::fs::dir::create_dir_all(parent)?;
            }
            log::info(&format!(
                "Copying: {} -> {}",
                src.display(),
                dest.display()
            ));
            crate::fs::copy::copy_file(src, &dest)?;
        }
        Ok(())
    }

    /// Generate the placeholder registry hives that ship on a fresh
    /// NT6.1 install under `Windows\System32\config\`. These are the
    /// files loaded by the kernel's configuration manager at Phase 1b.
    pub fn write_registry_hives(&self) -> Result<()> {
        let cfg = self.output_dir.join("Windows/System32/config");
        crate::fs::dir::create_dir_all(&cfg)?;
        for hive in &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"] {
            let p = cfg.join(hive);
            std::fs::write(&p, Self::hive_placeholder())?;
            log::info(&format!("Registry hive written: {}", p.display()));
        }
        Ok(())
    }

    /// Placeholder hive content. The real file is a registry-format
    /// binary; we emit the documented 32-byte `regf`/`hbin` header so
    /// the configuration manager has something to validate.
    fn hive_placeholder() -> Vec<u8> {
        let mut data = Vec::new();
        // HIVE signature ("regf"-style) plus a small body so the file
        // is non-empty and loadable by smoke tests.
        data.extend_from_slice(b"HIVE");
        data.extend_from_slice(&0x00000003u32.to_le_bytes()); // major version
        data.extend_from_slice(&0x00000000u32.to_le_bytes()); // minor version
        data.extend_from_slice(&[0u8; 20]); // reserved
        data
    }

    /// Build the full system-partition tree on disk.
    pub fn build(&self) -> Result<()> {
        log::section("System Partition Build");
        self.create_structure()?;
        self.copy_kernel_artifacts()?;
        self.copy_drivers()?;
        self.copy_extra_files()?;
        self.write_registry_hives()?;
        log::success(&format!(
            "System partition built: {}",
            self.output_dir.display()
        ));
        Ok(())
    }
}