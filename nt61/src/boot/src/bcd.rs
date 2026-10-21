//! BCD Store - Boot Configuration Data
//
//! Windows 7 BCD store implementation compatible with UEFI

// Exposes a partial API surface; unused entries are kept for future
// boot-option handling.

/// Boot entry identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {}

/// Well-known BCD GUIDs
pub mod wellknown {
    use super::Guid;

    /// Boot entry GUID for "Windows 7" (the default entry).
    /// Distinct from `WINDOWS_BOOT_LOADER` because the loader
    /// type and the entry type are different objects in BCD.
    /// winload matches on the FIRST 4 BYTES of the GUID slot:
    ///   0x9D 0xEA 0x86 0x2C  -> Normal
    pub const ENTRY_WINDOWS_7: Guid = Guid([
        0x9D, 0xEA, 0x86, 0x2C, 0x5C, 0xDD, 0x4E, 0x70, 0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47,
        0x95,
    ]);

    /// Boot entry GUID for "Windows 7 (Command Prompt)".
    /// First 4 bytes: 0xB2 0x72 0x1D 0x66 -> Cmd
    pub const ENTRY_CMD: Guid = Guid([
        0xB2, 0x72, 0x1D, 0x66, 0x7D, 0xBF, 0x4E, 0x50, 0xAE, 0x7C, 0xD2, 0x7F, 0x2D, 0x90, 0xCE,
        0x20,
    ]);

    /// Boot entry GUID for "Windows 7 (Debug CMD)".
    /// First 4 bytes: 0x51 0x89 0xB2 0x5C -> DebugCmd
    pub const ENTRY_DEBUG_CMD: Guid = Guid([
        0x51, 0x89, 0xB2, 0x5C, 0x55, 0x58, 0x4B, 0xF2, 0xBB, 0x0F, 0xCD, 0x5A, 0x4F, 0x8C, 0x7E,
        0x20,
    ]);

    /// Boot entry GUID for "Windows 7 (Safe Mode)".
    /// First 4 bytes: 0xA3 0x4C 0x8E 0xD1 -> SafeMode
    pub const ENTRY_SAFE_MODE: Guid = Guid([
        0xA3, 0x4C, 0x8E, 0xD1, 0x7B, 0xF2, 0x4A, 0x93, 0xBC, 0x1D, 0x6E, 0x5A, 0x3F, 0x8B, 0x7C,
        0x20,
    ]);
}

/// Maximum length constants
pub const MAX_ENTRIES: usize = 16;
pub const MAX_DESCRIPTION_LEN: usize = 64;

/// Static string storage for no_std
#[derive(Debug, Clone, Copy)]
pub struct StaticStr {
    data: [u16; MAX_DESCRIPTION_LEN],
    len: usize,
}

impl StaticStr {
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

    pub fn as_slice(&self) -> &[u16] {
        &self.data[..self.len]
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
    pub guid: Guid,
    pub description: StaticStr,
    /// Path to the EFI image the boot manager should chain to, in
    /// EFI-shell notation. Most entries are Windows boot loaders and
    /// point at winload.efi; the Tool entry would point at memtest.efi.
    pub application: StaticStr,
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

        // Entry 0: Windows 7 (default — Desktop mode: no log,
        // animation, then Ring 3 cmd.exe; future: desktop GUI)
        store.entries[0] = Some(BootEntry {
            guid: wellknown::ENTRY_WINDOWS_7,
            description: StaticStr::from_str("Windows 7"),
            application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
        });
        store.display_order[0] = Some(wellknown::ENTRY_WINDOWS_7);
        store.entry_count = 1;
        store.display_count = 1;

        // Entry 1: Windows 7 (Command Prompt) — CMD mode: no log,
        // animation, then Ring 3 cmd.exe; future: CMD GUI window.
        store.entries[1] = Some(BootEntry {
            guid: wellknown::ENTRY_CMD,
            description: StaticStr::from_str("Windows 7 (Command Prompt)"),
            application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
        });
        store.display_order[1] = Some(wellknown::ENTRY_CMD);
        store.entry_count = 2;
        store.display_count = 2;

        // Entry 2: Windows 7 (Debug CMD) — DebugCmd mode: full
        // verbose boot log, no animation, then Ring 3 cmd.exe.
        store.entries[2] = Some(BootEntry {
            guid: wellknown::ENTRY_DEBUG_CMD,
            description: StaticStr::from_str("Windows 7 (Debug CMD)"),
            application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
        });
        store.display_order[2] = Some(wellknown::ENTRY_DEBUG_CMD);
        store.entry_count = 3;
        store.display_count = 3;

        // Entry 3: Windows 7 (Safe Mode) — SafeMode mode: full
        // verbose boot log, no animation, minimal driver set,
        // skip user-mode subsystem init, enter kernel CMD shell.
        store.entries[3] = Some(BootEntry {
            guid: wellknown::ENTRY_SAFE_MODE,
            description: StaticStr::from_str("Windows 7 (Safe Mode)"),
            application: StaticStr::from_str(DEFAULT_WINLOAD_PATH),
        });
        store.display_order[3] = Some(wellknown::ENTRY_SAFE_MODE);
        store.entry_count = 4;
        store.display_count = 4;

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
}

impl Default for BcdStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}
