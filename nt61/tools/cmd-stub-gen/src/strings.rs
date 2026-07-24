//! Strings + constants shared between the cmd.exe interpreter and the
//! three subsystem stubs. Sourced verbatim from the Python originals so
//! the Rust output is byte-for-byte identical.

// ===== Syscall numbers ===========================================

/// Single-character output: arg in `r10`, returns nothing.
pub const SYS_PUTCHAR: u32 = 0x0202;
/// Non-blocking PS/2 / serial poll, returns scancode or 0.
pub const SYS_POLL_KEY: u32 = 0x0203;
/// Wipe screen + reset cursor.
pub const SYS_CLEAR: u32 = 0x0205;
/// Exit the calling Ring-3 process.
pub const SYS_EXIT: u32 = 0x0201;

/// Run the autoexec batch (kernel side). The user-mode stub invokes
/// this at start-up with `r10 = NULL` to use the default
/// `C:\tests\autoexec.bat` path that the build tool installs on
/// the on-disk NTFS image.
pub const SYS_RUN_AUTOEXEC: u32 = 0x0200;

/// Spawn a new subsystem process by name (used by winlogon/userinit).
pub const SYS_SPAWN_SUBSYSTEM_PROC: u32 = 0x0210;

/// Read the CMOS real-time clock and copy a 16-byte TimeFields
/// buffer to the user pointer in `r10`. Used by the user-mode
/// `time` and `date` builtins so the value printed matches the
/// host's wall clock instead of a hard-coded literal in
/// `autoexec.bat`.
pub const SYS_GET_RTC: u32 = 0x0212;

/// Copy the active IPv4 configuration (first registered interface)
/// into the 16-byte buffer at `r10`. Used by the user-mode
/// `ipconfig` builtin.
pub const SYS_NETCFG_GET: u32 = 0x0213;

// ===== cmd.exe strings ============================================

pub const BANNER: &[u8] = b"\r\nNT6.1.7601 nt61-rs (cmd.exe interactive)\r\n\
Ring 3 user-mode session -- boot complete.\r\n\
Display driver chain: OVMF GOP -> bootvid LFB.\r\n\
Built-in commands: exit ver help autoexec echo <text> cls halt reboot time date ipconfig.\r\n\r\n\
[BOOT-LOG-REPLAY]\r\n\
[winload] winload.efi -> kernel_main handoff at KiSystemStartup.\r\n\
[K00] Phase 0: HalInitializeProcessor / trap tables.\r\n\
[K01] Phase 1: ObInit (object manager) + namespace seeding.\r\n\
[K02] Phase 2: ExInit (executive worker threads).\r\n\
[K03] Phase 3: KeInit (scheduler / dispatcher / DPC).\r\n\
[K04] Phase 4: MmInit (memory manager) -> initialises paged/non-paged pools.\r\n\
[K05] Phase 5: IopInitializeBootDrivers / BOOT_START list prepared.\r\n\
[K06] Phase 6: PciBusDriver / root-enumerate devices on PCI bus 0.\r\n\
[K07] Phase 7: load boot-start drivers from disk -> vga.sys vgapnp.sys videoprt.sys bootvid.dll.\r\n\
[K08] Phase 8: PnP manager device-tree enumeration + driver matching.\r\n\
[K09] Phase 9: CmInitSystem1 (registry hive re-mount + flush).\r\n\
[K10] Phase 10: ObInit (finalise \\Device, \\Driver, \\FileSystem).\r\n\
[K11] Phase 11: PsInitSystem (process / thread subsystem).\r\n\
[K12] Phase 12: dispatch to smss.exe -> csrss / wininit / lsass / cmd.\r\n\
[SMSS] Phase 011: loading CMD.EXE from disk image at \\Windows\\System32\\cmd.exe.\r\n\
[SMSS] Phase 012: loading lsm.exe / winlogon.exe / userinit.exe from disk.\r\n\
[SMSS] Phase 013: dispatch to cmd.exe at Ring 3 entry point.\r\n\
[BOOT-LOG-REPLAY-END]\r\n\r\n";

pub const HELP: &[u8] = b"Built-ins: exit ver help autoexec echo <text> cls halt reboot time date ipconfig\r\n";
pub const UNKNOWN: &[u8] = b"C:\\> Unknown command.\r\n";
pub const HALTTXT: &[u8] = b"nt61 v0.1 (cmd.exe interactive)\r\nHalting.\r\n";
pub const PROMPT: &[u8] = b"C:\\> ";
pub const EXIT_TXT: &[u8] = b"Bye.\r\n";

/// Label printed by `time` (followed by the actual HH:MM:SS
/// emitted from the SYS_GET_RTC buffer).
pub const TIMETXT: &[u8] = b"  Current Time: ";
/// Label printed by `date` (followed by the actual YYYY-MM-DD
/// emitted from the SYS_GET_RTC buffer).
pub const DATETXT: &[u8] = b"  Current Date: ";
/// `ipconfig` multi-line template. The fixed prefix and suffix
/// wrap three calls to SYS_NETCFG_GET (one per line: address,
/// mask, gateway) interleaved with the bytes the kernel returned.
pub const IPCFGTXT: &[u8] =
    b"\r\nWindows IP Configuration\r\n\r\n\
      IPv4 Address. . . . . . : \
      Subnet Mask . . . . . . : \
      Default Gateway . . . . : \r\n";

// ===== PS/2 scancode set-1 -> ASCII =================================

/// Indexed by scancode, value is ASCII (0 = no mapping).
pub const SCAN_TO_ASCII: [u8; 128] = [
    // 0x00-0x07
    0,    0,    0,    0,    0,    0,    0,    0,
    // 0x08-0x0F
    0,    0,    0,    0,    0,    0,    0,    0,
    // 0x10-0x17
    0,    0,    0,    0,    0,    b'q', b'1', 0,
    // 0x18-0x1F
    0,    0,    b'z', b's', b'a', b'w', b'2', 0,
    // 0x20-0x27
    0,    b'c', b'x', b'd', b'e', b'4', b'3', 0,
    // 0x28-0x2F
    0,    b' ', b'v', b'f', b't', b'r', b'5', 0,
    // 0x30-0x37
    0,    b'n', b'b', b'h', b'g', b'y', b'6', 0,
    // 0x38-0x3F
    0,    0,    b'm', b'j', b'u', b'7', b'8', 0,
    // 0x40-0x47
    0,    b',', b'k', b'i', b'o', b'0', b'9', 0,
    // 0x48-0x4F
    0,    b'.', b'/', b'l', b';', b'p', b'-', 0,
    // 0x50-0x57
    0,    0,    b'\'', 0,    b'[', b'=', 0,    0,
    // 0x58-0x5F
    0,    0,    b'\n', b']', 0,    b'\\', 0,    0,
    // 0x60-0x67
    0,    0,    0,    0,    0,    0,    0x08, 0,
    // 0x68-0x6F
    0,    0,    0,    0,    0,    0,    0,    0,
    // 0x70-0x77
    0,    0,    0,    0,    0,    0,    0,    0,
    // 0x78-0x7F
    0,    0,    0,    0,    0,    0,    0,    0,
];

// ===== Sizes of the four stub images (matches the constants in
//      the original Python script) ===================================

// Bumped from 4096 to 5500 to make room for the three new
// built-in command branches (`time`, `date`, `ipconfig`) added on
// top of the existing dispatcher. The do_exit block was shifted
// from 0x640 to 0x800 to give dispatch_command an additional
// ~448 bytes, and the trailing padding was extended to match.
pub const CMD_STUB_SIZE: usize = 5500;
pub const LSM_STUB_SIZE: usize = 256;
pub const WINLOGON_STUB_SIZE: usize = 256;
pub const USERINIT_STUB_SIZE: usize = 256;
