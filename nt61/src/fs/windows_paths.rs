//! Windows 7 NT Path Mapping
//
//! Implements Windows 7 NT path and DOS path semantics.

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether the filesystem path subsystem has been initialized
static FS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the filesystem path subsystem
pub fn init() {
    FS_INITIALIZED.store(true, Ordering::Release);
}

/// Check if filesystem path subsystem is initialized
pub fn is_initialized() -> bool {
    FS_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Windows 7 System Directories (Canonical Paths)
// ============================================================================

pub const WINDOWS_DIR: &str = "C:\\Windows";
pub const SYSTEM32_DIR: &str = "C:\\Windows\\System32";
pub const SYSWOW64_DIR: &str = "C:\\Windows\\SysWOW64";
pub const DRIVERS_DIR: &str = "C:\\Windows\\System32\\drivers";
pub const CONFIG_DIR: &str = "C:\\Windows\\System32\\config";
pub const WINEVT_LOGS_DIR: &str = "C:\\Windows\\System32\\winevt\\Logs";
pub const WINEVT_SYSTEM: &str = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx";
pub const WINEVT_APPLICATION: &str = "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx";
pub const WINEVT_SECURITY: &str = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
pub const WINEVT_SETUP: &str = "C:\\Windows\\System32\\winevt\\Logs\\Setup.evtx";
pub const NTBTLOG_TXT: &str = "C:\\Windows\\ntbtlog.txt";
pub const USERS_DIR: &str = "C:\\Users";
pub const DEFAULT_USER_DIR: &str = "C:\\Users\\Default";
pub const ADMINISTRATOR_DIR: &str = "C:\\Users\\Administrator";
pub const PROGRAM_FILES_DIR: &str = "C:\\Program Files";
pub const PROGRAM_FILES_X86_DIR: &str = "C:\\Program Files (x86)";

// ============================================================================
// NT Kernel Paths
// ============================================================================

pub mod nt_paths {
    pub const DEVICE_PREFIX: &str = "\\Device\\";
    pub const HARDDISK_PREFIX: &str = "\\Device\\HarddiskVolume";
    pub const SYMLINK_PREFIX: &str = "\\??\\";
    pub const SYSTEMROOT_PREFIX: &str = "\\SystemRoot\\";

    /// Convert a DOS path (e.g. `C:\Windows`) to its NT path (`\??\C:\Windows`).
    /// Output is written into `out` and the number of bytes written is returned.
    pub fn dos_to_nt(dos_path: &str, out: &mut [u8; 260]) -> usize {
        let bytes = dos_path.as_bytes();
        let mut pos = 0;

        // Drive letter: X: -> \??\X:
        if bytes.len() >= 2 && bytes[1] == b':' {
            let nt_prefix = b"\\??\\";
            for &b in nt_prefix {
                if pos < out.len() { out[pos] = b; pos += 1; }
            }
            if pos < out.len() { out[pos] = bytes[0]; pos += 1; }
            if pos < out.len() { out[pos] = b':'; pos += 1; }
            for &b in &bytes[2..] {
                let b = if b == b'/' { b'\\' } else { b };
                if pos < out.len() { out[pos] = b; pos += 1; }
            }
            return pos;
        }

        // Absolute path not under \??\: prefix with \SystemRoot\
        if bytes.starts_with(b"\\") && !bytes.starts_with(b"\\??\\") && !bytes.starts_with(b"\\Device\\") {
            let nt_prefix = b"\\SystemRoot\\";
            for &b in nt_prefix {
                if pos < out.len() { out[pos] = b; pos += 1; }
            }
            for &b in &bytes[1..] {
                let b = if b == b'/' { b'\\' } else { b };
                if pos < out.len() { out[pos] = b; pos += 1; }
            }
            return pos;
        }

        // Default: copy as-is with slash normalization
        for &b in bytes {
            let b = if b == b'/' { b'\\' } else { b };
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
        pos
    }

    /// Build \Device\HarddiskVolumeX\<path> form
    pub fn device_path(volume: u8, path: &str, out: &mut [u8; 260]) -> usize {
        let bytes = path.as_bytes();
        let mut pos = 0;
        let prefix = b"\\Device\\HarddiskVolume";
        for &b in prefix {
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
        if pos < out.len() {
            out[pos] = b'0' + (volume % 10);
            pos += 1;
        }
        if pos < out.len() { out[pos] = b'\\'; pos += 1; }
        for &b in bytes {
            let b = if b == b'/' { b'\\' } else { b };
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
        pos
    }
}

// ============================================================================
// Environment Variables
// ============================================================================

pub mod env {
    /// Get environment variable value as a String
    pub fn get_var(name: &str) -> Option<&'static str> {
        match name.to_ascii_uppercase().as_str() {
            "SYSTEMROOT" | "WINDIR" => Some("C:\\Windows"),
            "SYSTEMDRIVE" => Some("C:"),
            "PROGRAMFILES" => Some("C:\\Program Files"),
            "PROGRAMFILES(X86)" => Some("C:\\Program Files (x86)"),
            "USERPROFILE" => Some("C:\\Users\\Administrator"),
            "HOMEDRIVE" => Some("C:"),
            "HOMEPATH" => Some("\\Users\\Administrator"),
            "TEMP" | "TMP" => Some("C:\\Windows\\Temp"),
            "PATH" => Some("C:\\Windows\\System32;C:\\Windows"),
            "PATHEXT" => Some(".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH"),
            "COMSPEC" => Some("C:\\Windows\\System32\\cmd.exe"),
            "OS" => Some("Windows_NT"),
            "COMPUTERNAME" => Some("NT61"),
            "USERNAME" => Some("Administrator"),
            "USERDOMAIN" => Some("NT61"),
            "LOGONSERVER" => Some("\\\\NT61"),
            "SESSIONNAME" => Some("Console"),
            "PROCESSOR_ARCHITECTURE" => Some("AMD64"),
            "PROCESSOR_IDENTIFIER" => Some("Intel64 Family 6 Model 85 Stepping 4"),
            "NUMBER_OF_PROCESSORS" => Some("1"),
            "PROCESSOR_LEVEL" => Some("21"),
            "PROCESSOR_REVISION" => Some("5504"),
            _ => None,
        }
    }

    /// Expand the most common %VAR% sequences into `out`.
    /// Returns the number of bytes written.
    pub fn expand(path: &str, out: &mut [u8; 260]) -> usize {
        let bytes = path.as_bytes();
        let mut pos = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                // Find the closing %
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'%' { j += 1; }
                if j < bytes.len() {
                    // Variable name is bytes[i+1..j]
                    let name_bytes = &bytes[i + 1..j];
                    let name_str = core::str::from_utf8(name_bytes).unwrap_or("");
                    if let Some(val) = get_var(name_str) {
                        for &b in val.as_bytes() {
                            if pos < out.len() { out[pos] = b; pos += 1; }
                        }
                    } else {
                        // Keep original
                        for &b in &bytes[i..=j] {
                            if pos < out.len() { out[pos] = b; pos += 1; }
                        }
                    }
                    i = j + 1;
                    continue;
                }
            }
            if pos < out.len() {
                out[pos] = if bytes[i] == b'/' { b'\\' } else { bytes[i] };
                pos += 1;
            }
            i += 1;
        }
        pos
    }
}

// ============================================================================
// File System Attributes
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub device: bool,
    pub normal: bool,
    pub temporary: bool,
}

impl FileAttributes {
    pub const READONLY: u32 = 0x1;
    pub const HIDDEN: u32 = 0x2;
    pub const SYSTEM: u32 = 0x4;
    pub const DIRECTORY: u32 = 0x10;
    pub const ARCHIVE: u32 = 0x20;
    pub const DEVICE: u32 = 0x40;
    pub const NORMAL: u32 = 0x80;
    pub const TEMPORARY: u32 = 0x100;

    pub fn new() -> Self {
        Self {
            readonly: false,
            hidden: false,
            system: false,
            directory: false,
            archive: false,
            device: false,
            normal: true,
            temporary: false,
        }
    }

    pub fn from_u32(attr: u32) -> Self {
        Self {
            readonly: (attr & Self::READONLY) != 0,
            hidden: (attr & Self::HIDDEN) != 0,
            system: (attr & Self::SYSTEM) != 0,
            directory: (attr & Self::DIRECTORY) != 0,
            archive: (attr & Self::ARCHIVE) != 0,
            device: (attr & Self::DEVICE) != 0,
            normal: (attr & Self::NORMAL) != 0,
            temporary: (attr & Self::TEMPORARY) != 0,
        }
    }

    pub fn to_u32(&self) -> u32 {
        let mut attr = 0u32;
        if self.readonly { attr |= Self::READONLY; }
        if self.hidden { attr |= Self::HIDDEN; }
        if self.system { attr |= Self::SYSTEM; }
        if self.directory { attr |= Self::DIRECTORY; }
        if self.archive { attr |= Self::ARCHIVE; }
        if self.device { attr |= Self::DEVICE; }
        if self.normal { attr |= Self::NORMAL; }
        if self.temporary { attr |= Self::TEMPORARY; }
        attr
    }
}

impl Default for FileAttributes {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mock Directory Entries
// ============================================================================

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: [u8; 64],
    pub name_len: u8,
    pub attributes: u32,
    pub size: u64,
}

impl DirEntry {
    pub fn new(name: &str, is_dir: bool, size: u64) -> Self {
        let mut name_buf = [0u8; 64];
        let n = core::cmp::min(name.len(), 63);
        name_buf[..n].copy_from_slice(&name.as_bytes()[..n]);
        Self {
            name: name_buf,
            name_len: n as u8,
            attributes: if is_dir { FileAttributes::DIRECTORY } else { FileAttributes::NORMAL },
            size,
        }
    }
}

/// Provide a small static slice of mock entries for the System32 directory.
/// Caller-bounded to at most 16 entries at a time.
pub fn system32_entries() -> [DirEntry; 16] {
    [
        DirEntry::new(".", true, 0),
        DirEntry::new("..", true, 0),
        DirEntry::new("cmd.exe", false, 307200),
        DirEntry::new("notepad.exe", false, 2097152),
        DirEntry::new("regedit.exe", false, 4194304),
        DirEntry::new("diskpart.exe", false, 174080),
        DirEntry::new("tasklist.exe", false, 61440),
        DirEntry::new("taskkill.exe", false, 61440),
        DirEntry::new("sc.exe", false, 122880),
        DirEntry::new("net.exe", false, 512000),
        DirEntry::new("net1.exe", false, 512000),
        DirEntry::new("ipconfig.exe", false, 98304),
        DirEntry::new("hostname.exe", false, 28672),
        DirEntry::new("ping.exe", false, 40960),
        DirEntry::new("tracert.exe", false, 65536),
        DirEntry::new("wevtutil.exe", false, 262144),
    ]
}

pub fn windows_root_entries() -> [DirEntry; 12] {
    [
        DirEntry::new(".", true, 0),
        DirEntry::new("..", true, 0),
        DirEntry::new("Windows", true, 0),
        DirEntry::new("Program Files", true, 0),
        DirEntry::new("Program Files (x86)", true, 0),
        DirEntry::new("Users", true, 0),
        DirEntry::new("ProgramData", true, 0),
        DirEntry::new("bootmgr", false, 0),
        DirEntry::new("ntbtlog.txt", false, 0),
        DirEntry::new("autoexec.bat", false, 0),
        DirEntry::new("config.sys", false, 0),
        DirEntry::new("", false, 0),
    ]
}

pub fn windows_dir_entries() -> [DirEntry; 16] {
    [
        DirEntry::new(".", true, 0),
        DirEntry::new("..", true, 0),
        DirEntry::new("System32", true, 0),
        DirEntry::new("SysWOW64", true, 0),
        DirEntry::new("Boot", true, 0),
        DirEntry::new("Resources", true, 0),
        DirEntry::new("WinSxS", true, 0),
        DirEntry::new("inf", true, 0),
        DirEntry::new("Help", true, 0),
        DirEntry::new("addins", true, 0),
        DirEntry::new("AppPatch", true, 0),
        DirEntry::new("assembly", true, 0),
        DirEntry::new("Config", true, 0),
        DirEntry::new("Fonts", true, 0),
        DirEntry::new("notepad.exe", false, 2097152),
        DirEntry::new("regedit.exe", false, 4194304),
    ]
}

pub fn drivers_entries() -> [DirEntry; 16] {
    [
        DirEntry::new(".", true, 0),
        DirEntry::new("..", true, 0),
        DirEntry::new("disk.sys", false, 0),
        DirEntry::new("classpnp.sys", false, 0),
        DirEntry::new("kdcom.dll", false, 0),
        DirEntry::new("acpi.sys", false, 0),
        DirEntry::new("hal.dll", false, 0),
        DirEntry::new("ntoskrnl.exe", false, 0),
        DirEntry::new("ntfs.sys", false, 0),
        DirEntry::new("fastfat.sys", false, 0),
        DirEntry::new("cdrom.sys", false, 0),
        DirEntry::new("usbohci.sys", false, 0),
        DirEntry::new("usbehci.sys", false, 0),
        DirEntry::new("usbhub.sys", false, 0),
        DirEntry::new("hidclass.sys", false, 0),
        DirEntry::new("tcpip.sys", false, 0),
    ]
}
