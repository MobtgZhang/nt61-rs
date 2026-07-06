//! BCD Store - Boot Configuration Data
//
//! Windows 7 BCD store implementation compatible with UEFI

// Exposes a partial API surface; unused entries are kept for future
// boot-option handling.
#![allow(dead_code)]

use bitflags::bitflags;

/// Boot entry identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    #[allow(dead_code)]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Well-known BCD GUIDs
pub mod wellknown {
    use super::Guid;

    #[allow(dead_code)]
    pub const CURRENT_BOOT_ENTRY: Guid = Guid([
        0x9D, 0xA3, 0x12, 0x8B, 0xC1, 0x9A, 0x11, 0xD0,
        0x80, 0x5E, 0x00, 0xC0, 0x4F, 0xD9, 0x38, 0x9C,
    ]);

    #[allow(dead_code)]
    pub const BOOT_MANAGER: Guid = Guid([
        0x9D, 0xA3, 0x12, 0x8B, 0xC1, 0x9A, 0x11, 0xD0,
        0x80, 0x5E, 0x00, 0xC0, 0x4F, 0xD9, 0x38, 0x9D,
    ]);

    pub const WINDOWS_BOOT_LOADER: Guid = Guid([
        0xA5, 0xDC, 0x26, 0x9A, 0xE6, 0xB7, 0x11, 0xD0,
        0x93, 0xF7, 0x00, 0xA0, 0xC9, 0x69, 0xD4, 0x69,
    ]);

    /// Boot entry GUID for "Windows 7" (the default entry).
    /// Distinct from `WINDOWS_BOOT_LOADER` because the loader
    /// type and the entry type are different objects in BCD.
    /// winload matches on the FIRST 4 BYTES of the GUID slot:
    ///   0x9D 0xEA 0x86 0x2C  -> Normal
    pub const ENTRY_WINDOWS_7: Guid = Guid([
        0x9D, 0xEA, 0x86, 0x2C, 0x5C, 0xDD, 0x4E, 0x70,
        0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47, 0x95,
    ]);

    /// Boot entry GUID for "Windows 7 Safe Mode - CMD".
    /// First 4 bytes: 0xB2 0x72 0x1D 0x66 -> SafeModeCmd
    pub const ENTRY_SAFE_MODE_CMD: Guid = Guid([
        0xB2, 0x72, 0x1D, 0x66, 0x7D, 0xBF, 0x4E, 0x50,
        0xAE, 0x7C, 0xD2, 0x7F, 0x2D, 0x90, 0xCE, 0x20,
    ]);

    /// Boot entry GUID for "Windows 7 Safe Mode - Debug".
    /// First 4 bytes: 0x51 0x89 0xB2 0x5C -> SafeModeDebug
    pub const ENTRY_SAFE_MODE_DEBUG: Guid = Guid([
        0x51, 0x89, 0xB2, 0x5C, 0x55, 0x58, 0x4B, 0xF2,
        0xBB, 0x0F, 0xCD, 0x5A, 0x4F, 0x8C, 0x7E, 0x20,
    ]);
}

/// Boot entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BootType {
    BootLoader,
    Resume,
    Firmware,
    Startup,
    Manager,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BootFlags: u32 {
        const SAFE_BOOT_MINIMAL = 0x00000001;
        const SAFE_BOOT_NETWORK = 0x00000002;
        const SAFE_BOOT_DSREPAIR = 0x00000003;
        const SAFE_BOOT_SAFEMODE = 0x00000004;
        const NO_EXECUTE = 0x00000010;
        const LOAD_OPTIONS = 0x00000020;
        const DEBUG = 0x00000040;
    }
}

/// BCD element types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[allow(dead_code)]
pub enum BcdElementType {
    Device = 0x11000001,
    Object = 0x11000002,
    Description = 0x12000001,
    BootSequence = 0x14000001,
    DisplayOrder = 0x14000002,
    Sequence = 0x14000003,
    DefaultSequence = 0x14000004,
    Timeout = 0x15000001,
    ToolsDisplayOrder = 0x16000001,
    BootLoadOptions = 0x16000002,
    DebuggerSettings = 0x16000003,
    DebuggerType = 0x16000004,
    SerialPort = 0x16000005,
    SerialBaudRate = 0x16000006,
    OsDevice = 0x21000001,
    FilePath = 0x21000002,
    OsLoadOptions = 0x22000001,
    LoadOptions = 0x23000001,
}

/// Maximum length constants
pub const MAX_ENTRIES: usize = 16;
pub const MAX_DESCRIPTION_LEN: usize = 64;
#[allow(dead_code)]
pub const MAX_OPTIONS_LEN: usize = 128;

/// Static string storage for no_std
#[derive(Debug, Clone, Copy)]
pub struct StaticStr {
    data: [u16; MAX_DESCRIPTION_LEN],
    len: usize,
}

impl StaticStr {
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {
            data: [0; MAX_DESCRIPTION_LEN],
            len: 0,
        }
    }

    pub const fn from_str(s: &str) -> Self {
        let mut data = [0u16; MAX_DESCRIPTION_LEN];
        let mut i = 0;
        let bytes = s.as_bytes();

        let mut pos = 0;
        while pos < bytes.len() && i < MAX_DESCRIPTION_LEN - 1 {
            let c = bytes[pos];
            if c < 128 {
                data[i] = c as u16;
                i += 1;
            }
            pos += 1;
        }

        Self { data, len: i }
    }

    /// Create StaticStr from a UTF-16 slice (e.g., from BCD string store)
    pub fn from_u16_slice(slice: &[u16]) -> Self {
        let mut data = [0u16; MAX_DESCRIPTION_LEN];
        let mut i = 0;
        let max_len = MAX_DESCRIPTION_LEN - 1;

        for &c in slice {
            if c == 0 || i >= max_len {
                break;
            }
            data[i] = c;
            i += 1;
        }

        Self { data, len: i }
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.data[..self.len]
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }
}

// Single source of truth for which PE/EFI image a BCD entry should
// chain to. The boot manager reads this on ENTER and asks the UEFI
// firmware to LoadImage+StartImage the named file.
//
// In real Windows 7 the OS Loader is **not** on the ESP — it lives
// on the OS volume. The primary copy is at
// `C:\Windows\System32\winload.efi`; the same PE is also dropped
// at `C:\Windows\System32\Boot\winload.efi` (capital-B `Boot`)
// for BCDEdit / bootrec / WinRE. The ESP only holds
// `bootmgfw.efi` and the BCD.
// For UEFI boot, winload.efi is located on the ESP at this path.
pub const DEFAULT_WINLOAD_PATH: &str = "\\Windows\\System32\\winload.efi";

/// Boot entry with static storage
#[derive(Debug, Clone, Copy)]
pub struct BootEntry {
    #[allow(dead_code)]
    pub guid: Guid,
    pub description: StaticStr,
    #[allow(dead_code)]
    pub boot_type: BootType,
    pub os_load_options: StaticStr,
    #[allow(dead_code)]
    pub device_path: StaticStr,
    #[allow(dead_code)]
    pub system_root: StaticStr,
    pub boot_flags: BootFlags,
    /// Path to the EFI image the boot manager should chain to, in
    /// EFI-shell notation. Most entries are Windows boot loaders and
    /// point at winload.efi; the Tool entry would point at memtest.efi.
    pub application: StaticStr,
}

impl BootEntry {
    #[allow(dead_code)]
    pub const fn new(guid: Guid, desc: &str, boot_type: BootType) -> Self {
        Self {
            guid,
            description: StaticStr::from_str(desc),
            boot_type,
            os_load_options: StaticStr::new(),
            device_path: StaticStr::new(),
            system_root: StaticStr::new(),
            boot_flags: BootFlags::empty(),
            application: StaticStr::new(),
        }
    }

    pub const fn windows_loader(desc: &str, device: &str, sysroot: &str) -> Self {
        Self {
            guid: wellknown::WINDOWS_BOOT_LOADER,
            description: StaticStr::from_str(desc),
            boot_type: BootType::BootLoader,
            os_load_options: StaticStr::from_str("ntoskrnl.exe /kernel=ntoskrnl.exe"),
            device_path: StaticStr::from_str(device),
            system_root: StaticStr::from_str(sysroot),
            boot_flags: BootFlags::empty(),
            application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
        }
    }

    pub const fn with_options(mut self, options: &str) -> Self {
        self.os_load_options = StaticStr::from_str(options);
        self
    }

    pub const fn with_flags(mut self, flags: BootFlags) -> Self {
        self.boot_flags = flags;
        self
    }
    #[allow(dead_code)]
    pub const fn with_description(mut self, desc: &str) -> Self {
        self.description = StaticStr::from_str(desc);
        self
    }
}

/// BCD Store with static storage
#[derive(Debug, Clone, Copy)]
pub struct BcdStore {
    pub entries: [Option<BootEntry>; MAX_ENTRIES],
    pub display_order: [Option<Guid>; MAX_ENTRIES],
    pub entry_count: usize,
    pub display_count: usize,
    pub timeout: u32,
}

impl BcdStore {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ENTRIES],
            display_order: [None; MAX_ENTRIES],
            entry_count: 0,
            display_count: 0,
            timeout: 10,
        }
    }

    pub const fn with_defaults() -> Self {
        let mut store = Self::new();

        // Entry 0: Windows 7 (default — full startup -> IDLE)
        store.entries[0] = Some(
            BootEntry {
                guid: wellknown::ENTRY_WINDOWS_7,
                description: StaticStr::from_str("Windows 7"),
                boot_type: BootType::BootLoader,
                os_load_options: StaticStr::from_str("ntoskrnl.exe /kernel=ntoskrnl.exe"),
                device_path: StaticStr::from_str("\\Device\\HarddiskVolume1"),
                system_root: StaticStr::from_str("\\Windows"),
                boot_flags: BootFlags::empty(),
                application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
            },
        );
        store.display_order[0] = Some(wellknown::ENTRY_WINDOWS_7);
        store.entry_count = 1;
        store.display_count = 1;

        // Entry 1: Windows 7 Safe Mode with Command Prompt
        // (skips the graphical subsystem, drops to a CMD shell)
        store.entries[1] = Some(
            BootEntry {
                guid: wellknown::ENTRY_SAFE_MODE_CMD,
                description: StaticStr::from_str("Windows 7 (Safe Mode - CMD)"),
                boot_type: BootType::BootLoader,
                os_load_options: StaticStr::from_str("ntoskrnl.exe /safeboot:minimal /safeboot:shell"),
                device_path: StaticStr::from_str("\\Device\\HarddiskVolume1"),
                system_root: StaticStr::from_str("\\Windows"),
                boot_flags: BootFlags::SAFE_BOOT_SAFEMODE,
                application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
            },
        );
        store.display_order[1] = Some(wellknown::ENTRY_SAFE_MODE_CMD);
        store.entry_count = 2;
        store.display_count = 2;

        // Entry 2: Windows 7 Safe Mode with Debug logging
        // (kdcom logger on COM1, full debug log streamed to the
        // serial console before IDLE)
        store.entries[2] = Some(
            BootEntry {
                guid: wellknown::ENTRY_SAFE_MODE_DEBUG,
                description: StaticStr::from_str("Windows 7 (Safe Mode - Debug)"),
                boot_type: BootType::BootLoader,
                os_load_options: StaticStr::from_str("ntoskrnl.exe /debug /debugport=COM1 /baudrate=115200"),
                device_path: StaticStr::from_str("\\Device\\HarddiskVolume1"),
                system_root: StaticStr::from_str("\\Windows"),
                boot_flags: BootFlags::DEBUG,
                application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
            },
        );
        store.display_order[2] = Some(wellknown::ENTRY_SAFE_MODE_DEBUG);
        store.entry_count = 3;
        store.display_count = 3;

        store.timeout = 5;
        store
    }

    pub fn get_entry(&self, index: usize) -> Option<&BootEntry> {
        if index < self.entry_count {
            self.entries[index].as_ref()
        } else {
            None
        }
    }
    #[allow(dead_code)]
    pub fn entries(&self) -> impl Iterator<Item = &BootEntry> {
        self.entries.iter().flatten()
    }
    #[allow(dead_code)]
    pub fn display_order(&self) -> impl Iterator<Item = &Option<Guid>> {
        self.display_order.iter().take(self.display_count)
    }
    #[allow(dead_code)]
    pub fn set_timeout(&mut self, seconds: u32) {
        self.timeout = seconds;
    }
}

impl Default for BcdStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}
