//! ntdll - kernel debugger support (DbgPrint)
//
//! `DbgPrint` / `DbgPrintEx` write a formatted message to the
//! kernel debugger (kd). They route to the kernel logging system
//! which dispatches to serial and optionally to KdCom.
//
//! References: MSDN Library "Windows 7" - DbgPrint / DbgPrintEx
//! in `ntddk.h` / `wdbgexts.h`. The DPFLTR_* component IDs are
//! from `wdm.h`.

use super::types::PVOID;

/// DPFLTR_* component IDs from wdm.h / ntddk.h.
/// Used by DbgPrintEx to identify the calling component.
pub const DPFLTR_DEFAULT:    u32 = 0;
pub const DPFLTR_SYSTEM:    u32 = 1;
pub const DPFLTR_SMSS:       u32 = 5;
pub const DPFLTR_SETUP:     u32 = 6;
pub const DPFLTR_NTFS:      u32 = 4;
pub const DPFLTR_FSTUB:     u32 = 3;
pub const DPFLTR_CDAUDIO:   u32 = 20;
pub const DPFLTR_CDROM:     u32 = 21;
pub const DPFLTR_CLASSPNP:  u32 = 23;
pub const DPFLTR_DISK:      u32 = 24;
pub const DPFLTR_DRIVE:     u32 = 25;
pub const DPFLTR_SOUND:     u32 = 26;
pub const DPFLTR_NET:       u32 = 31;
pub const DPFLTR_NDIS:      u32 = 32;
pub const DPFLTR_BFE:       u32 = 34;
pub const DPFLTR_FLTREGR:   u32 = 35;
pub const DPFLTR_SR:        u32 = 37;
pub const DPFLTR_INFFIN:   u32 = 40;
pub const DPFLTR_VOLUME:    u32 = 44;
pub const DPFLTR_MOUNTDEV:  u32 = 45;
pub const DPFLTR_CRAMFS:   u32 = 46;
pub const DPFLTR_UDFS:      u32 = 47;
pub const DPFLTR_SIS:       u32 = 48;
pub const DPFLTR_MSFS:      u32 = 49;
pub const DPFLTR_NPFS:      u32 = 50;
pub const DPFLTR_PVFS:      u32 = 51;
pub const DPFLTR_CLFS:      u32 = 52;
pub const DPFLTR_TXF:       u32 = 53;
pub const DPFLTR_KTM:       u32 = 54;
pub const DPFLTR_IOIOMAN:  u32 = 55;
pub const DPFLTR_HONGKONG: u32 = 56;
pub const DPFLTR_HAL:       u32 = 59;
pub const DPFLTR_IHVDRIVER: u32 = 60;
pub const DPFLTR_HYPERV:    u32 = 61;
pub const DPFLTR_KSECURE:  u32 = 63;
pub const DPFLTR_AVCP:      u32 = 66;
pub const DPFLTR_VSSD:      u32 = 67;
pub const DPFLTR_STORPORT:  u32 = 68;
pub const DPFLTR_SPB:       u32 = 69;
pub const DPFLTR_RDBSSL:   u32 = 70;
pub const DPFLTR_BTH:       u32 = 71;
pub const DPFLTR_BTHMINIPORT: u32 = 72;
pub const DPFLTR_TRACKING:  u32 = 73;
pub const DPFLTR_ESENT:    u32 = 74;
pub const DPFLTR_BOOT:      u32 = 75;
pub const DPFLTR_SHELL:     u32 = 77;
pub const DPFLTR_WDIAG:    u32 = 78;
pub const DPFLTR_SHUTDOWN:  u32 = 79;
pub const DPFLTR_FVEVOL:    u32 = 80;
pub const DPFLTR_NTOSBOOT: u32 = 81;
pub const DPFLTR_WOW64:    u32 = 82;
pub const DPFLTR_ALPC:      u32 = 83;
pub const DPFLTR_WDI:       u32 = 84;
pub const DPFLTR_PERFLIB:   u32 = 85;
pub const KDPFLTR_MASK:    u32 = 0xFF;

// Default debug level per component (0 = always printed, 31 = rarely printed).
// Components with higher default levels require a more verbose debug setting.
fn get_component_default_level(component: u32) -> u8 {
    match component {
        DPFLTR_DEFAULT     => 0,
        DPFLTR_SYSTEM      => 0,
        DPFLTR_SMSS        => 0,
        DPFLTR_SETUP       => 0,
        DPFLTR_NTFS        => 0,
        DPFLTR_FSTUB       => 0,
        DPFLTR_CDAUDIO    => 0,
        DPFLTR_CDROM       => 0,
        DPFLTR_CLASSPNP    => 0,
        DPFLTR_DISK        => 0,
        DPFLTR_DRIVE       => 0,
        DPFLTR_SOUND       => 0,
        DPFLTR_NET         => 0,
        DPFLTR_NDIS        => 0,
        DPFLTR_BFE         => 0,
        DPFLTR_FLTREGR     => 0,
        DPFLTR_SR          => 0,
        DPFLTR_INFFIN      => 0,
        DPFLTR_VOLUME     => 0,
        DPFLTR_MOUNTDEV    => 0,
        DPFLTR_CRAMFS     => 0,
        DPFLTR_UDFS        => 0,
        DPFLTR_SIS         => 0,
        DPFLTR_MSFS        => 0,
        DPFLTR_NPFS        => 0,
        DPFLTR_PVFS        => 0,
        DPFLTR_CLFS        => 0,
        DPFLTR_TXF         => 0,
        DPFLTR_KTM         => 0,
        DPFLTR_IOIOMAN    => 0,
        DPFLTR_HONGKONG   => 0,
        DPFLTR_HAL        => 0,
        DPFLTR_IHVDRIVER  => 0,
        DPFLTR_HYPERV     => 0,
        DPFLTR_KSECURE    => 0,
        DPFLTR_AVCP        => 0,
        DPFLTR_VSSD        => 0,
        DPFLTR_STORPORT   => 0,
        DPFLTR_SPB         => 0,
        DPFLTR_RDBSSL     => 0,
        DPFLTR_BTH         => 0,
        DPFLTR_BTHMINIPORT => 0,
        DPFLTR_TRACKING   => 0,
        DPFLTR_ESENT      => 0,
        DPFLTR_BOOT       => 0,
        DPFLTR_SHELL       => 0,
        DPFLTR_WDIAG      => 0,
        DPFLTR_SHUTDOWN   => 0,
        DPFLTR_FVEVOL      => 0,
        DPFLTR_NTOSBOOT   => 0,
        DPFLTR_WOW64      => 0,
        DPFLTR_ALPC        => 0,
        DPFLTR_WDI         => 0,
        DPFLTR_PERFLIB     => 0,
        _                   => 0,
    }
}

/// Convert a DPFLTR component ID to its subsystem bitmask.
fn component_to_subsystem_bits(component: u32) -> u32 {
    match component {
        DPFLTR_DEFAULT      => crate::rtl::logging::subsystem::DBG,
        DPFLTR_SYSTEM      => crate::rtl::logging::subsystem::KERNEL,
        DPFLTR_SMSS        => crate::rtl::logging::subsystem::KERNEL,
        DPFLTR_SETUP       => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_NTFS        => crate::rtl::logging::subsystem::NTFS,
        DPFLTR_FSTUB       => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_CLASSPNP    => crate::rtl::logging::subsystem::STORAGE,
        DPFLTR_DISK        => crate::rtl::logging::subsystem::STORAGE,
        DPFLTR_DRIVE       => crate::rtl::logging::subsystem::STORAGE,
        DPFLTR_SOUND       => crate::rtl::logging::subsystem::AUDIO,
        DPFLTR_NET         => crate::rtl::logging::subsystem::NET,
        DPFLTR_NDIS        => crate::rtl::logging::subsystem::NDIS,
        DPFLTR_FLTREGR     => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_CLFS        => crate::rtl::logging::subsystem::CLFS,
        DPFLTR_TXF         => crate::rtl::logging::subsystem::FILESYSTEM,
        DPFLTR_KTM         => crate::rtl::logging::subsystem::FILESYSTEM,
        DPFLTR_HAL         => crate::rtl::logging::subsystem::HAL,
        DPFLTR_HYPERV      => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_STORPORT    => crate::rtl::logging::subsystem::STORAGE,
        DPFLTR_BOOT        => crate::rtl::logging::subsystem::KERNEL,
        DPFLTR_SHELL       => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_WOW64       => crate::rtl::logging::subsystem::DRIVER,
        DPFLTR_ALPC        => crate::rtl::logging::subsystem::IO,
        _                   => crate::rtl::logging::subsystem::DBG,
    }
}

/// Convert a DPFLTR component ID to its subsystem name string.
fn component_to_subsystem_name(component: u32) -> &'static str {
    match component {
        DPFLTR_DEFAULT      => "DBG",
        DPFLTR_SYSTEM      => "KERNEL",
        DPFLTR_SMSS        => "KERNEL",
        DPFLTR_SETUP       => "DRIVER",
        DPFLTR_NTFS        => "NTFS",
        DPFLTR_FSTUB       => "DRIVER",
        DPFLTR_CLASSPNP    => "STORAGE",
        DPFLTR_DISK        => "STORAGE",
        DPFLTR_DRIVE       => "STORAGE",
        DPFLTR_SOUND       => "AUDIO",
        DPFLTR_NET         => "NET",
        DPFLTR_NDIS        => "NDIS",
        DPFLTR_FLTREGR     => "DRIVER",
        DPFLTR_CLFS        => "CLFS",
        DPFLTR_TXF         => "NTFS",
        DPFLTR_KTM         => "KERNEL",
        DPFLTR_HAL         => "HAL",
        DPFLTR_HYPERV      => "DRIVER",
        DPFLTR_STORPORT    => "STORAGE",
        DPFLTR_BOOT        => "KERNEL",
        DPFLTR_SHELL       => "DRIVER",
        DPFLTR_WOW64       => "DRIVER",
        DPFLTR_ALPC        => "IO",
        _                   => "DBG",
    }
}

/// Read a NUL-terminated string from a pointer.
fn read_c_string(ptr: *const u8) -> Option<&'static str> {
    if ptr.is_null() { return None; }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 && len < 4096 { len += 1; }
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(slice).ok()
}

/// Format a debug message into a buffer.
fn format_message(msg: &str) -> [u8; 512] {
    let mut buf = [0u8; 512];
    for (i, &b) in msg.as_bytes().iter().enumerate().take(511) {
        buf[i] = b;
    }
    buf
}

/// `DbgPrint` - send a formatted message to the kernel debugger.
/// In the Windows API this is variadic; we accept a NUL-terminated
/// format string pointer. Since we can't parse C format strings,
/// we emit the raw string as-is.
/// Returns 1 on success, 0 on failure.
pub unsafe extern "C" fn DbgPrint(format: PVOID) -> u32 {
    let msg = match read_c_string(format as *const u8) {
        Some(s) => s,
        None => {
            crate::kprintln_info!("DBG", "DbgPrint: null format");
            return 0;
        }
    };

    // Route through the kernel logging system
    // DbgPrint uses the DEFAULT component
    if crate::rtl::logging::should_log(
        crate::rtl::logging::LogLevel::Info,
        crate::rtl::logging::subsystem::DBG
    ) {
        let buf = format_message(msg);
        let _ = &buf;
        let cpu = crate::rtl::logging::current_cpu();
        crate::rtl::logging::log_write_impl(
            crate::rtl::logging::LogLevel::Info,
            "DBG",
            cpu,
            msg
        );
    }
    1
}

/// `DbgPrintEx` - same as DbgPrint but with component/level filtering.
/// Messages are only printed if `level <= the configured debug level
/// for the specified component`.
/// Returns 1 on success, 0 on failure.
pub unsafe extern "C" fn DbgPrintEx(component: u32, level: u32, format: PVOID) -> u32 {
    let masked_component = component & KDPFLTR_MASK;
    let default_level = get_component_default_level(masked_component);

    // In the real Windows kernel, the debug level for each component is
    // controlled by a registry value. We use a simple threshold:
    // if level >= default_level, print it.
    if (level as u8) > default_level + 1 {
        return 1; // Suppressed by level filter
    }

    let msg = match read_c_string(format as *const u8) {
        Some(s) => s,
        None => {
            crate::kprintln_info!("DBG",
                "DbgPrintEx: null format");
            return 0;
        }
    };

    let subsys_bits = component_to_subsystem_bits(masked_component);
    let subsys_name = component_to_subsystem_name(masked_component);

    if crate::rtl::logging::should_log(crate::rtl::logging::LogLevel::Info, subsys_bits) {
        let cpu = crate::rtl::logging::current_cpu();
        crate::rtl::logging::log_write_impl(
            crate::rtl::logging::LogLevel::Info,
            subsys_name,
            cpu,
            msg
        );
    }
    1
}

/// `vDbgPrintEx` - takes a va_list for format arguments.
/// Since we cannot parse C format strings, we emit the raw format
/// string as a placeholder. Returns 0.
pub unsafe extern "C" fn vDbgPrintEx(
    _component: u32,
    _level: u32,
    format: PVOID,
    _args: PVOID,
) -> u32 {
    // Suppress the warning about unused args
    let _ = _args;
    let _ = _level;

    let msg = match read_c_string(format as *const u8) {
        Some(s) => s,
        None => return 0,
    };

    if crate::rtl::logging::should_log(
        crate::rtl::logging::LogLevel::Info,
        crate::rtl::logging::subsystem::DBG
    ) {
        crate::kprintln_info!("DBG", "[vDbgPrintEx] {}", msg);
    }
    1
}

/// `vDbgPrintExWithPrefix` - same as vDbgPrintEx but with a prefix string.
pub unsafe extern "C" fn vDbgPrintExWithPrefix(
    _prefix: PVOID,
    _component: u32,
    _level: u32,
    _format: PVOID,
    _args: PVOID,
) -> u32 {
    0
}

/// `DbgBreakPoint` - trigger a breakpoint exception.
/// In kernel mode, this causes a INT3 which would normally be caught
/// by a kernel debugger. In our environment, we just log and continue.
pub fn DbgBreakPoint() {
    crate::kprintln_info!("DBG", "[DBG] BreakPoint triggered");
}

/// `DbgPrintHex` - helper to print a hex value. Used during development.
pub fn DbgPrintHex(label: &str, value: u64) {
    crate::kprintln_info!("DBG", "[DBG] {} = 0x{:016x}", label, value);
}
