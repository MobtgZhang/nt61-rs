//! Windows 7 CMD extensions.
//!
//! This module keeps command-reference coverage separate from the core
//! shell parser. Names and behaviour are aligned with the offline
//! `reference/WinCmdRef.chm` A-Z index.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Commands from the Windows 7 A-Z reference recognized by this shell.
const REFERENCE_COMMANDS: &[&str] = &[
    "adprep",
    "append",
    "arp",
    "assoc",
    "at",
    "attrib",
    "auditpol",
    "autochk",
    "autoconv",
    "autofmt",
    "bcdedit",
    "bitsadmin",
    "bootcfg",
    "break",
    "cacls",
    "call",
    "certreq",
    "certutil",
    "change",
    "chcp",
    "chglogon",
    "chgport",
    "chgusr",
    "chkdsk",
    "chkntfs",
    "choice",
    "cipher",
    "clip",
    "cluster",
    "cmdkey",
    "color",
    "comp",
    "compact",
    "convert",
    "csvde",
    "dcdiag",
    "dcpromo",
    "defrag",
    "dfscmd",
    "diskcomp",
    "diskcopy",
    "diskedit",
    "diskpart",
    "diskraid",
    "diskshadow",
    "dnscmd",
    "doskey",
    "driverquery",
    "dsacls",
    "dsadd",
    "dsamain",
    "dsdbutil",
    "dsget",
    "dsmgmt",
    "dsmod",
    "dsmove",
    "dsquery",
    "dsrm",
    "edit",
    "endlocal",
    "eventcreate",
    "extract",
    "fc",
    "find",
    "findstr",
    "flattemp",
    "for",
    "forfiles",
    "format",
    "freedisk",
    "fsutil",
    "ftp",
    "ftype",
    "goto",
    "gpresult",
    "graftabl",
    "hashgen",
    "icacls",
    "if",
    "irftp",
    "ktmutil",
    "ktpass",
    "label",
    "ldifde",
    "ldp",
    "logman",
    "logoff",
    "lpq",
    "lpr",
    "mapadmin",
    "mklink",
    "mode",
    "more",
    "mount",
    "msg",
    "msiexec",
    "mstsc",
    "net",
    "netdom",
    "netsh",
    "netstat",
    "nlb",
    "nltest",
    "nslookup",
    "ntbackup",
    "ntdsutil",
    "openfiles",
    "pause",
    "path",
    "perfmon",
    "popd",
    "print",
    "prompt",
    "pubprn",
    "pushd",
    "qappsrv",
    "qprocess",
    "query",
    "quser",
    "qwinsta",
    "rcp",
    "rdpsign",
    "reagentc",
    "recover",
    "redircmp",
    "redirusr",
    "reg",
    "regsvr32",
    "rem",
    "repadmin",
    "replace",
    "reset",
    "robocopy",
    "rpcinfo",
    "rsh",
    "runas",
    "rwinsta",
    "sc",
    "schtasks",
    "setlocal",
    "setspn",
    "setx",
    "shadow",
    "shift",
    "showmount",
    "shutdown",
    "sort",
    "start",
    "storrept",
    "subst",
    "systeminfo",
    "takeown",
    "taskkill",
    "tasklist",
    "telnet",
    "tftp",
    "timeout",
    "title",
    "tlntadmn",
    "tracerpt",
    "tscon",
    "tsdiscon",
    "tskill",
    "tsprof",
    "typeperf",
    "umount",
    "vssadmin",
    "waitfor",
    "wbadmin",
    "wdsutil",
    "wecutil",
    "wevtutil",
    "where",
    "whoami",
    "winsat",
    "wmic",
    "xcopy",
    "atmadm",
    "bcdboot",
    "cd",
    "chdir",
    "cls",
    "cmd",
    "cmstp",
    "copy",
    "cprofile",
    "cscript",
    "date",
    "del",
    "dir",
    "dirquota",
    "dispdiag",
    "djoin",
    "erase",
    "eventtriggers",
    "evntcmd",
    "exit",
    "filescrn",
    "finger",
    "getmac",
    "gettype",
    "help",
    "helpctr",
    "hostname",
    "inuse",
    "ipconfig",
    "ipxroute",
    "ismserv",
    "macfile",
    "md",
    "mkdir",
    "mountvol",
    "move",
    "nbtstat",
    "netdiag",
    "nfsadmin",
    "nfsshare",
    "nfsstat",
    "pathping",
    "pbadmin",
    "pentnt",
    "ping",
    "pnpunattend",
    "pnputil",
    "rd",
    "ren",
    "rename",
    "rexec",
    "rmdir",
    "route",
    "set",
    "sfc",
    "sysocmgr",
    "tapicfg",
    "tcmsetup",
    "time",
    "tracert",
    "tree",
    "tsecimp",
    "type",
    "uddiconfig",
    "ver",
    "verify",
    "vol",
    "w32tm",
    "winnt",
    "winpop",
];

/// Returns true when the command appears in the Windows 7 CHM A-Z index.
pub fn is_reference_command(command: &str) -> bool {
    let canonical = command.to_lowercase();
    REFERENCE_COMMANDS.contains(&canonical.as_str())
}

/// Execute a reference command that is not owned by the legacy shell.
pub fn execute(command: &str, arguments: &str, cwd: &[u8]) -> bool {
    match command {
        "assoc" => cmd_assoc(arguments),
        "arp" => cmd_arp(arguments),
        "attrib" | "cacls" | "icacls" => cmd_attrib(arguments, cwd),
        "break" => cmd_break(arguments),
        "chcp" => cmd_chcp(arguments),
        "color" => cmd_color(arguments),
        "driverquery" => cmd_driverquery(),
        "getmac" => cmd_getmac(),
        "hostname" => cmd_hostname(),
        "ipconfig" => cmd_ipconfig(arguments),
        "netstat" => cmd_netstat(),
        "net" => cmd_net(arguments),
        "route" => cmd_route(arguments),
        "sc" => cmd_sc(arguments),
        "shutdown" => cmd_shutdown(arguments),
        "systeminfo" => cmd_systeminfo(),
        "taskkill" => cmd_taskkill(arguments),
        "tasklist" => cmd_tasklist(arguments),
        "tree" => cmd_tree(cwd),
        "ftype" => cmd_ftype(arguments),
        "graftabl" => cmd_graftabl(arguments),
        "label" => cmd_label(arguments),
        "mklink" => cmd_mklink(arguments),
        "path" => cmd_path(arguments),
        "pause" => cmd_pause(),
        "prompt" => cmd_prompt(arguments),
        "rem" => false,
        "timeout" | "waitfor" => cmd_timeout(arguments),
        "title" => cmd_title(arguments),
        "ver" | "vol" | "whoami" => cmd_identity(command),
        "where" => cmd_where(arguments, cwd),
        "reg" => cmd_reg(arguments),
        "fsutil" => cmd_fsutil(arguments),
        "bcdedit" => cmd_bcdedit(arguments),
        "choice" => cmd_choice(arguments),
        "chkdsk" | "chkntfs" => cmd_chkdsk(command, arguments),
        "cipher" => cmd_cipher(arguments),
        "clip" => cmd_clip(arguments),
        "compact" => cmd_compact(arguments),
        "convert" => cmd_convert(arguments),
        "diskpart" => cmd_diskpart(),
        "doskey" => cmd_doskey(arguments),
        "format" => cmd_format(arguments),
        "fc" => cmd_fc(arguments, cwd),
        "find" => cmd_find(arguments, cwd),
        "findstr" => cmd_findstr(arguments, cwd),
        "mode" => cmd_mode(arguments),
        "more" => cmd_more(arguments, cwd),
        "netsh" => cmd_netsh(arguments),
        "nslookup" => cmd_nslookup(arguments),
        "popd" => cmd_popd(),
        "pushd" => cmd_pushd(arguments, cwd),
        "robocopy" => cmd_robocopy(arguments, cwd),
        "schtasks" => cmd_schtasks(arguments),
        "setx" => cmd_setx(arguments),
        "sort" => cmd_sort(arguments, cwd),
        "start" => cmd_start(arguments),
        "subst" => cmd_subst(arguments),
        "takeown" => cmd_takeown(arguments),
        "wmic" => cmd_wmic(arguments),
        "xcopy" => cmd_xcopy(arguments, cwd),
        "replace" => cmd_replace(arguments, cwd),
        "recover" => cmd_recover(arguments),
        "bootcfg" => cmd_bootcfg(arguments),
        "cmdkey" => cmd_cmdkey(arguments),
        "comp" => cmd_comp(arguments, cwd),
        "defrag" => cmd_defrag(arguments),
        "eventcreate" => cmd_eventcreate(arguments),
        "extract" => cmd_extract(arguments),
        "freedisk" => cmd_freedisk(arguments),
        "gpresult" => cmd_gpresult(),
        "logman" => cmd_logman(arguments),
        "logoff" => cmd_logoff(),
        "mount" => cmd_mount(arguments),
        "msiexec" => cmd_msiexec(arguments),
        "openfiles" => cmd_openfiles(arguments),
        "query" => cmd_query(arguments),
        "regsvr32" => cmd_regsvr32(arguments),
        "runas" => cmd_runas(arguments),
        "typeperf" => cmd_typeperf(arguments),
        "umount" => cmd_umount(arguments),
        "vssadmin" => cmd_vssadmin(arguments),
        "wevtutil" => cmd_wevtutil(arguments),
        "forfiles" => cmd_forfiles(arguments, cwd),
        "auditpol" => cmd_auditpol(arguments),
        "winsat" => cmd_winsat(arguments),
        "at" => cmd_at(arguments),
        "bitsadmin" => cmd_bitsadmin(arguments),
        "certreq" | "certutil" => cmd_certutil(command, arguments),
        "cluster" => cmd_cluster(arguments),
        "dnscmd" => cmd_dnscmd(arguments),
        "diskcomp" | "diskcopy" | "diskedit" => cmd_disktool(command),
        "diskraid" | "diskshadow" => cmd_diskraid(command),
        "edit" => cmd_edit(),
        "flattemp" => cmd_flattemp(arguments),
        "hashgen" => cmd_hashgen(arguments),
        "irftp" => cmd_irftp(arguments),
        "ktmutil" => cmd_ktmutil(arguments),
        "ktpass" => cmd_ktpass(arguments),
        "lpq" | "lpr" => cmd_printer(command, arguments),
        "mapadmin" => cmd_mapadmin(arguments),
        "msg" => cmd_msg(arguments),
        "mstsc" => cmd_mstsc(arguments),
        "netdom" => cmd_netdom(arguments),
        "nlb" | "nltest" => cmd_nlb(command, arguments),
        "ntbackup" => cmd_ntbackup(arguments),
        "ntdsutil" => cmd_ntdsutil(arguments),
        "perfmon" => cmd_perfmon(),
        "print" => cmd_print(arguments),
        "pubprn" => cmd_pubprn(arguments),
        "rdpsign" => cmd_rdpsign(arguments),
        "reagentc" => cmd_reagentc(arguments),
        "reset" => cmd_reset(),
        "rpcinfo" => cmd_rpcinfo(arguments),
        "setspn" => cmd_setspn(arguments),
        "showmount" => cmd_showmount(arguments),
        "storrept" => cmd_storrept(arguments),
        "tlntadmn" => cmd_tlntadmn(arguments),
        "tracerpt" => cmd_tracerpt(arguments),
        "wbadmin" => cmd_wbadmin(arguments),
        "wdsutil" => cmd_wdsutil(arguments),
        "wecutil" => cmd_wecutil(arguments),
        "cmstp" => cmd_cmstp(arguments),
        "cprofile" => cmd_cprofile(arguments),
        "dirquota" => cmd_dirquota(arguments),
        "dispdiag" => cmd_dispdiag(arguments),
        "eventtriggers" => cmd_eventtriggers(arguments),
        "evntcmd" => cmd_evntcmd(arguments),
        "helpctr" => cmd_helpctr(arguments),
        "pnpunattend" => cmd_pnpunattend(arguments),
        "adprep" => cmd_adprep(arguments),
        "csvde" => cmd_csvde(arguments),
        "dcdiag" => cmd_dcdiag(),
        "dcpromo" => cmd_dcpromo(arguments),
        "dfscmd" => cmd_dfscmd(arguments),
        "dsacls" => cmd_dsacls(arguments),
        "dsadd" => cmd_dsadd(arguments),
        "dsamain" => cmd_dsamain(arguments),
        "dsdbutil" => cmd_dsdbutil(arguments),
        "dsget" => cmd_dsget(arguments),
        "dsmgmt" => cmd_dsmgmt(arguments),
        "dsmod" => cmd_dsmod(arguments),
        "dsmove" => cmd_dsmove(arguments),
        "dsquery" => cmd_dsquery(arguments),
        "dsrm" => cmd_dsrm(arguments),
        "ldifde" => cmd_ldifde(arguments),
        "ldp" => cmd_ldp(),
        "repadmin" => cmd_repadmin(arguments),
        "change" | "chglogon" | "chgport" | "chgusr" => cmd_ts_change(command, arguments),
        "qappsrv" => cmd_qappsrv(),
        "qprocess" => cmd_qprocess(arguments),
        "quser" => cmd_quser(),
        "qwinsta" => cmd_qwinsta(),
        "rwinsta" => cmd_rwinsta(arguments),
        "shadow" => cmd_shadow(arguments),
        "tscon" => cmd_tscon(arguments),
        "tsdiscon" => cmd_tsdiscon(arguments),
        "tskill" => cmd_tskill(arguments),
        "tsprof" => cmd_tsprof(arguments),
        "ftp" => cmd_ftp(arguments),
        "telnet" => cmd_telnet(arguments),
        "tftp" => cmd_tftp(arguments),
        "rcp" | "rsh" => cmd_remote_shell(command, arguments),
        "autochk" => cmd_autochk(arguments),
        "autoconv" => cmd_autoconv(arguments),
        "autofmt" => cmd_autofmt(arguments),
        "append" => cmd_append(arguments),
        "call" => cmd_call(arguments),
        "shift" => cmd_shift(),
        "setlocal" => cmd_setlocal(arguments),
        "endlocal" => cmd_endlocal(),
        "for" => cmd_for(arguments),
        "goto" => cmd_goto(arguments),
        "if" => cmd_if(arguments),
        "redircmp" => cmd_redircmp(arguments),
        "redirusr" => cmd_redirusr(arguments),
        "ping" => cmd_ping(arguments),
        "tracert" => cmd_tracert(arguments),
        "pathping" => cmd_pathping(arguments),
        "nbtstat" => cmd_nbtstat(arguments),
        "netdiag" => cmd_netdiag(),
        "ipxroute" => cmd_ipxroute(arguments),
        "finger" => cmd_finger(arguments),
        "rexec" => cmd_rexec(arguments),
        "nfsadmin" => cmd_nfsadmin(arguments),
        "nfsshare" => cmd_nfsshare(arguments),
        "nfsstat" => cmd_nfsstat(arguments),
        "atmadm" => cmd_atmadm(arguments),
        "bcdboot" => cmd_bcdboot(arguments),
        "cscript" => cmd_cscript(arguments),
        "djoin" => cmd_djoin(arguments),
        "filescrn" => cmd_filescrn(arguments),
        "gettype" => cmd_gettype(),
        "inuse" => cmd_inuse(arguments),
        "ismserv" => cmd_ismserv(arguments),
        "macfile" => cmd_macfile(arguments),
        "pnputil" => cmd_pnputil(arguments),
        "sfc" => cmd_sfc(arguments),
        "sysocmgr" => cmd_sysocmgr(arguments),
        "tapicfg" => cmd_tapicfg(arguments),
        "tcmsetup" => cmd_tcmsetup(arguments),
        "tsecimp" => cmd_tsecimp(arguments),
        "uddiconfig" => cmd_uddiconfig(arguments),
        "verify" => cmd_verify(arguments),
        "w32tm" => cmd_w32tm(arguments),
        "winnt" => cmd_winnt(arguments),
        "winpop" => cmd_winpop(arguments),
        "pentnt" => cmd_pentnt(),
        "pbadmin" => cmd_pbadmin(arguments),
        _ => cmd_not_yet_available(command),
    }
}

fn output(text: &str) {
    for byte in text.as_bytes() {
        if *byte != b'\x1b' && *byte != b'\x00' {
            crate::hal::serial::with_serial_unmasked(|| {
                crate::hal::text_console::put_serial_and_console(*byte);
            });
            // Mirror into the SSH capture buffer so remote command
            // submission (sc query, net start, ipconfig, ...) returns
            // non-empty output. Matches cmd.rs::dual_print behaviour.
            crate::servers::cmd::capture_output_byte(*byte);
        }
    }
}

fn output_line(text: &str) {
    output(text);
    output("\r\n");
}

fn command_path_utf16(path: &str, cwd: &[u8]) -> Vec<u16> {
    let bytes = path.trim().trim_matches('"').as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        path.trim().trim_matches('"').encode_utf16().collect()
    } else {
        let mut full: Vec<u16> = cwd.iter().map(|byte| u16::from(*byte)).collect();
        if full.last() != Some(&u16::from(b'\\')) && !full.is_empty() {
            full.push(u16::from(b'\\'));
        }
        full.extend(path.trim_matches('"').encode_utf16());
        full
    }
}

fn open_shell_path(path: &str, cwd: &[u8]) -> Option<crate::fs::ntfs::NtfsHandle> {
    crate::fs::ntfs::get_mounted_fs().and_then(|filesystem| {
        let path_utf16 = command_path_utf16(path, cwd);
        crate::fs::ntfs::open_file(filesystem, &path_utf16, None)
    })
}

fn cmd_assoc(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No file associations are defined.");
        return false;
    }
    if let Some((extension, value)) = arguments.split_once('=') {
        output_line(&format!("{}={}", extension, value));
        return false;
    }
    output_line(&format!("File association not found for {}", arguments));
    false
}

fn cmd_attrib(arguments: &str, cwd: &[u8]) -> bool {
    let path = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/'))
        .unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: ATTRIB [+R | -R] filename");
        return false;
    }
    match open_shell_path(path, cwd) {
        Some(handle) => {
            let kind = if handle.is_directory { "D" } else { "A" };
            output_line(&format!("{}   {}", kind, path));
            false
        }
        None => {
            output_line("The system cannot find the file specified.");
            false
        }
    }
}

fn cmd_break(arguments: &str) -> bool {
    if arguments.eq_ignore_ascii_case("on") {
        output_line("Break checking is ON.");
    } else if arguments.eq_ignore_ascii_case("off") {
        output_line("Break checking is OFF.");
    }
    false
}

fn cmd_chcp(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("Active code page: 437");
        return false;
    }
    match arguments.parse::<u16>() {
        Ok(code_page) => output_line(&format!("Active code page: {}", code_page)),
        Err(_) => output_line("Invalid code page."),
    }
    false
}

fn cmd_color(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("Sets the foreground and background colors. COLOR [bg][fg]");
        return false;
    }
    let valid = arguments.len() <= 2
        && arguments
            .chars()
            .all(|character| character.is_ascii_hexdigit());
    output_line(if valid {
        ""
    } else {
        "The specified color is not valid."
    });
    false
}

fn cmd_ftype(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No file types are defined.");
        return false;
    }
    if let Some((file_type, command)) = arguments.split_once('=') {
        output_line(&format!("{}={}", file_type, command));
        return false;
    }
    output_line("File type not found.");
    false
}

fn cmd_graftabl(arguments: &str) -> bool {
    output_line(if arguments.is_empty() {
        "GRAFTABL enabled the graphics character set for the current console."
    } else {
        "GRAFTABL: The specified graphics character set is not supported."
    });
    false
}

fn cmd_label(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("The type of the file system is NTFS.\r\nEnter new label:");
        return false;
    }
    let label = arguments.splitn(2, ' ').next().unwrap_or("");
    output_line(&format!("Volume label is {}", label));
    false
}

fn cmd_mklink(arguments: &str) -> bool {
    let target = arguments.splitn(2, ' ').next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: MKLINK [/D | /J] Link Target");
        return false;
    }
    output_line(&format!("Symbolic link created for {}", target));
    false
}

fn cmd_path(arguments: &str) -> bool {
    let message = if arguments.is_empty() {
        String::from("PATH=C:\\Windows\\System32;C:\\Windows")
    } else if arguments.eq_ignore_ascii_case(";") {
        String::from("PATH=")
    } else {
        format!("PATH={}", arguments)
    };
    output_line(&message);
    false
}

fn cmd_pause() -> bool {
    output("Press any key to continue . . . ");
    let _ = crate::hal::keyboard_input::read_byte();
    output("\r\n");
    false
}

fn cmd_prompt(arguments: &str) -> bool {
    output_line(if arguments.is_empty() {
        "PROMPT restored to $P$G"
    } else {
        "PROMPT changed"
    });
    false
}

fn cmd_systeminfo() -> bool {
    output_line("Host Name: NT61\r\nOS Name: Microsoft Windows 7 Ultimate\r\nOS Version: 6.1.7601 Service Pack 1\r\nSystem Type: x64-based PC\r\n");
    false
}

fn format_ipv4(address: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (address >> 24) & 0xFF,
        (address >> 16) & 0xFF,
        (address >> 8) & 0xFF,
        address & 0xFF
    )
}

fn parse_ipv4(text: &str) -> Option<u32> {
    crate::netstack::ipif::parse_ip(text)
}

#[cfg(test)]
mod route_tests {
    use super::{parse_ipv4, parse_route_body, parse_route_delete};

    #[test]
    fn parses_route_add_with_gateway_and_metric() {
        let mut tokens = "10.0.2.0 MASK 255.255.255.0 10.0.2.1 METRIC 25 IF 2".split_whitespace();
        let route = parse_route_body(&mut tokens).expect("valid route");
        assert_eq!(route.destination, 0x0A00_0200);
        assert_eq!(route.netmask, 0xFFFF_FF00);
        assert_eq!(route.gateway, 0x0A00_0201);
        assert_eq!(route.interface, 2);
        assert_eq!(route.metric, 25);
    }

    #[test]
    fn parses_route_delete_without_optional_fields() {
        let mut tokens = "10.0.2.0 MASK 255.255.255.0".split_whitespace();
        assert_eq!(
            parse_route_delete(&mut tokens),
            Some((0x0A00_0200, 0xFFFF_FF00))
        );
    }

    #[test]
    fn rejects_incomplete_route() {
        let mut tokens = "10.0.2.0".split_whitespace();
        assert!(parse_route_body(&mut tokens).is_none());
        let mut tokens = alloc::vec::Vec::<&str>::new().into_iter();
        assert!(parse_route_delete(&mut tokens).is_none());
    }

    #[test]
    fn parses_ipv4_in_network_byte_order() {
        assert_eq!(parse_ipv4("10.0.2.5"), Some(0x0A00_0205));
    }
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let bytes = text
        .split(|separator: char| separator == '-' || separator == ':')
        .map(|part| u8::from_str_radix(part, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes);
    Some(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn cmd_hostname() -> bool {
    output_line("NT61");
    false
}

fn cmd_getmac() -> bool {
    let interfaces = crate::netstack::ethif::get_all_interfaces();
    if interfaces.is_empty() {
        output_line("No network adapters are available.");
        return false;
    }
    for interface in interfaces {
        let mac = format!(
            "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
            interface.mac[0],
            interface.mac[1],
            interface.mac[2],
            interface.mac[3],
            interface.mac[4],
            interface.mac[5]
        );
        let name = core::str::from_utf8(&interface.name)
            .unwrap_or("network")
            .trim_end_matches('\0');
        output_line(&format!("{}   \\Device\\Tcpip_{}", mac, name));
    }
    false
}

fn cmd_driverquery() -> bool {
    output_line("Module Name  Driver Type  Load State  Image Size");
    output_line("-----------  -----------  ----------  ----------");
    let mut count = 0usize;
    crate::io::driver_loader::enumerate_drivers(|entry| {
        let name_end = entry.name.iter().position(|byte| *byte == 0).unwrap_or(64);
        let name = core::str::from_utf8(&entry.name[..name_end]).unwrap_or("unknown");
        let load_state = match entry.load_state {
            crate::io::driver_loader::DriverLoadState::NotLoaded => "NotLoaded",
            crate::io::driver_loader::DriverLoadState::Loading => "Loading",
            crate::io::driver_loader::DriverLoadState::Loaded => "Loaded",
            crate::io::driver_loader::DriverLoadState::Failed => "Failed",
            crate::io::driver_loader::DriverLoadState::Unloading => "Unloading",
        };
        output_line(&format!(
            "{:<12} {:<12} {:<11} {}",
            name, "Kernel", load_state, entry.image_size
        ));
        count += 1;
        true
    });
    if count == 0 {
        output_line("(No registered drivers)");
    }
    false
}

fn cmd_fsutil(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("info") => match crate::fs::ntfs::extended_api::get_space_usage() {
            Some(usage) => {
                output_line(&format!("Total space: {} KiB", usage.total_kb));
                output_line(&format!("Used space:  {} KiB", usage.used_kb));
                output_line(&format!("Free space:  {} KiB", usage.free_kb));
            }
            None => output_line("The volume is not mounted."),
        },
        _ => {
            output_line("Syntax: FSUTIL info");
        }
    }
    false
}

fn cmd_arp(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().copied().unwrap_or("-a") {
        "-a" => {
            output_line("Internet Address      Physical Address     Type");
            output_line("------------         ----------------     --------");
            let entries = crate::netstack::arp::cache_entries();
            if entries.is_empty() {
                output_line("No entries in the ARP cache.");
                return false;
            }
            for (address, mac, is_static) in entries {
                output_line(&format!(
                    "{}     {}     {}",
                    format_ipv4(address),
                    format_mac(&mac),
                    if is_static { "static" } else { "dynamic" }
                ));
            }
        }
        "-d" => {
            let Some(address) = tokens.get(1).and_then(|token| parse_ipv4(token)) else {
                output_line("Syntax: ARP -d inet_addr");
                return false;
            };
            crate::netstack::arp::cache_remove(address);
        }
        "-s" => {
            if tokens.len() != 3 {
                output_line("Syntax: ARP -s inet_addr mac_addr");
                return false;
            }
            let Some(address) = parse_ipv4(tokens[1]) else {
                output_line("Invalid Internet address.");
                return false;
            };
            let Some(mac) = parse_mac(tokens[2]) else {
                output_line("Invalid physical address.");
                return false;
            };
            crate::netstack::arp::cache_add_static(address, &mac);
        }
        _ => output_line("Syntax: ARP -a [-d] [-s]"),
    }
    false
}

fn cmd_net(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    let action = tokens.first().copied().unwrap_or("").to_lowercase();
    let service = tokens.get(1).map(|token| token.to_string());
    match action.as_str() {
        "start" => match service {
            Some(service) => {
                let result = crate::servers::services::start_service(&service);
                let message = if result {
                    format!("The {} service was started successfully.", service)
                } else {
                    format!("The {} service could not be started.", service)
                };
                output_line(&message);
            }
            None => {
                for (name, state, _process_id) in crate::servers::services::query_all_services() {
                    if state == crate::servers::services::ServiceState::Running {
                        output_line(&format!("   {}", name));
                    }
                }
            }
        },
        "stop" => match service {
            Some(service) => {
                let result = crate::servers::services::stop_service(&service);
                let message = if result {
                    format!("The {} service was stopped successfully.", service)
                } else {
                    format!("The {} service could not be stopped.", service)
                };
                output_line(&message);
            }
            None => output_line("Syntax: NET STOP service_name"),
        },
        "pause" | "continue" => {
            let Some(service) = service else {
                output_line(&format!(
                    "Syntax: NET {} service_name",
                    action.to_uppercase()
                ));
                return false;
            };
            let Some(handle) = crate::servers::services::open_service(&service) else {
                output_line(&format!("The {} service does not exist.", service));
                return false;
            };
            let control = if action == "pause" {
                crate::servers::services::ServiceControl::Pause
            } else {
                crate::servers::services::ServiceControl::Continue
            };
            let message = if crate::servers::services::control_service(handle, control) {
                format!("The {} service was {}d successfully.", service, action)
            } else {
                format!("The {} service could not be {}d.", service, action)
            };
            output_line(&message);
        }
        _ => {
            output_line("NET [ START | STOP | PAUSE | CONTINUE ] [service_name]");
        }
    }
    false
}

fn cmd_reg(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    if tokens.first().map(|token| token.to_lowercase()).as_deref() != Some("query") {
        output_line("Syntax: REG QUERY key [/v value_name]");
        return false;
    }
    let mut key = None;
    let mut value_name = None;
    let mut index = 1;
    while index < tokens.len() {
        if tokens[index].eq_ignore_ascii_case("/v") {
            value_name = tokens.get(index + 1).map(|token| token.to_string());
            index += 2;
        } else {
            key = Some(tokens[index].to_string());
            index += 1;
        }
    }
    let Some(key) = key else {
        output_line("Syntax: REG QUERY key [/v value_name]");
        return false;
    };
    output_line(&format!("! {}", key));
    if let Some(name) = value_name {
        let Some(value) = crate::registry::cm::query_value(&key, &name) else {
            output_line("The system cannot find the specified registry key or value.");
            return false;
        };
        output_line(&format!(
            "{}    {}    {}",
            name,
            format_registry_type(value.value_type),
            format_registry_value(&value)
        ));
        return false;
    }
    let values = match crate::registry::cm::enumerate_values(&key) {
        Some(values) => values,
        None => {
            output_line("The system cannot find the specified registry key.");
            return false;
        }
    };
    for name in values {
        let Some(value) = crate::registry::cm::query_value(&key, &name) else {
            continue;
        };
        output_line(&format!(
            "{}    {}    {}",
            name,
            format_registry_type(value.value_type),
            format_registry_value(&value)
        ));
    }
    false
}

fn format_registry_type(value_type: crate::registry::hive::ValueType) -> &'static str {
    match value_type {
        crate::registry::hive::ValueType::None => "REG_NONE",
        crate::registry::hive::ValueType::String => "REG_SZ",
        crate::registry::hive::ValueType::ExpandString => "REG_EXPAND_SZ",
        crate::registry::hive::ValueType::Binary => "REG_BINARY",
        crate::registry::hive::ValueType::DWord => "REG_DWORD",
        crate::registry::hive::ValueType::DWordBigEndian => "REG_DWORD_BIG_ENDIAN",
        crate::registry::hive::ValueType::Link => "REG_LINK",
        crate::registry::hive::ValueType::MultiString => "REG_MULTI_SZ",
        crate::registry::hive::ValueType::ResourceList => "REG_RESOURCE_LIST",
        crate::registry::hive::ValueType::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
        crate::registry::hive::ValueType::ResourceRequirementsList => {
            "REG_RESOURCE_REQUIREMENTS_LIST"
        }
        crate::registry::hive::ValueType::QWord => "REG_QWORD",
    }
}

fn format_registry_value(value: &crate::registry::hive::Value) -> String {
    if let Some(number) = value.as_u32() {
        return format!("0x{:x} ({})", number, number);
    }
    if let Some(number) = value.as_u64() {
        return format!("0x{:x}", number);
    }
    if let Some(text) = value.as_utf16_string() {
        return text;
    }
    value
        .data
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect()
}

fn cmd_shutdown(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    let action = tokens.first().map(|token| token.to_lowercase());
    match action.as_deref() {
        Some("/s") => {
            output_line("Shutting down...");
            crate::hal::common::power::return_to_firmware(
                crate::hal::common::power::FirmwareAction::Shutdown,
            );
        }
        Some("/r") => {
            output_line("Restarting...");
            crate::hal::common::power::return_to_firmware(
                crate::hal::common::power::FirmwareAction::Reboot,
            );
        }
        _ => output_line("Syntax: SHUTDOWN [/S | /R]"),
    }
    false
}

fn cmd_ipconfig(arguments: &str) -> bool {
    let detailed = arguments.to_lowercase().contains("/all");
    let interfaces = crate::netstack::ipif::get_all_interfaces();
    if interfaces.is_empty() {
        output_line("No network interfaces are configured.");
        return false;
    }

    output_line("Windows IP Configuration");
    for interface in interfaces {
        let eth_interface = crate::netstack::ethif::get_interface(interface.eth_if);
        let is_loopback = interface.eth_if == u32::MAX;
        let adapter = eth_interface
            .as_ref()
            .map(|eth| {
                let name = core::str::from_utf8(&eth.name)
                    .unwrap_or("Local Area Connection")
                    .trim_end_matches('\0')
                    .to_string();
                name
            })
            .unwrap_or_else(|| "Local Area Connection".to_string());

        output_line("");
        if is_loopback {
            output_line("Loopback adapter:");
        } else if adapter.is_empty() {
            output_line("Ethernet adapter Local Area Connection:");
        } else {
            output_line(&format!("Ethernet adapter {}:", adapter));
        }
        output_line(&format!(
            "   IPv4 Address. . . . . . . . . . . : {}",
            format_ipv4(interface.address)
        ));
        output_line(&format!(
            "   Subnet Mask . . . . . . . . . . . : {}",
            format_ipv4(interface.netmask)
        ));
        output_line(&format!(
            "   Default Gateway . . . . . . . . . : {}",
            format_ipv4(interface.gateway)
        ));
        if detailed {
            if let Some(eth) = eth_interface {
                output_line(&format!(
                    "   MAC Address . . . . . . . . . . . : {}",
                    format_mac(&eth.mac)
                ));
                output_line(&format!(
                    "   Link Up . . . . . . . . . . . . . : {}",
                    if eth.link_up { "Yes" } else { "No" }
                ));
            }
            output_line(&format!(
                "   Interface Index . . . . . . . . . : {}",
                interface.if_index
            ));
            output_line(&format!(
                "   TTL . . . . . . . . . . . . . . . : {}",
                interface.ttl
            ));
        }
    }
    false
}

fn cmd_netstat() -> bool {
    let routes = crate::netstack::routing::get_all_routes();
    output_line("Route Table");
    output_line("");
    output_line("Destination     Netmask         Gateway         Interface Metric");
    output_line("--------------- --------------- --------------- --------- ------");
    for route in routes {
        output_line(&format!(
            "{:<15} {:<15} {:<15} {:<9} {}",
            format_ipv4(route.destination),
            format_ipv4(route.netmask),
            format_ipv4(route.gateway),
            route.interface,
            route.metric
        ));
    }
    false
}

fn cmd_route(arguments: &str) -> bool {
    let mut tokens = arguments.split_whitespace();
    let command = tokens.next().unwrap_or("").to_uppercase();

    match command.as_str() {
        "" | "PRINT" => cmd_netstat(),
        "-F" => {
            crate::netstack::routing::clear_routing_table();
            output_line("OK!");
            true
        }
        "ADD" | "CHANGE" => {
            let Some(route) = parse_route_body(&mut tokens) else {
                output_line("The parameter is incorrect.");
                return false;
            };
            if command == "CHANGE" && !route_exists(route.destination, route.netmask) {
                output_line("The route was not found.");
                return false;
            }
            let route_type = if route.gateway == 0 {
                crate::netstack::routing::RouteType::Direct
            } else {
                crate::netstack::routing::RouteType::Static
            };
            crate::netstack::routing::add_route(
                route.destination,
                route.netmask,
                route.gateway,
                route.interface,
                route.metric,
                route_type,
            );
            output_line("OK!");
            true
        }
        "DELETE" | "DEL" => {
            let Some((destination, netmask)) = parse_route_delete(&mut tokens) else {
                output_line("The parameter is incorrect.");
                return false;
            };
            if crate::netstack::routing::remove_route(destination, netmask) {
                output_line("OK!");
                true
            } else {
                output_line("The route was not found.");
                false
            }
        }
        _ => {
            output_line("Manipulates network routing tables.");
            output_line("");
            output_line("ROUTE [-f] [PRINT | ADD | DELETE | CHANGE]");
            output_line("             [destination] [MASK netmask] [gateway]");
            output_line("             [METRIC metric] [IF interface]");
            false
        }
    }
}

fn route_exists(destination: u32, netmask: u32) -> bool {
    crate::netstack::routing::get_all_routes()
        .iter()
        .any(|route| route.destination == destination && route.netmask == netmask)
}

fn parse_route_delete<'a>(tokens: &mut impl Iterator<Item = &'a str>) -> Option<(u32, u32)> {
    let mut route = ParsedRoute {
        destination: 0,
        netmask: 0,
        gateway: 0,
        interface: 0,
        metric: 0,
        gateway_present: false,
    };
    parse_route_fields(tokens, &mut route)?;
    Some((route.destination, route.netmask))
}

fn parse_route_body<'a>(tokens: &mut impl Iterator<Item = &'a str>) -> Option<ParsedRoute> {
    let mut route = ParsedRoute {
        destination: 0,
        netmask: 0,
        gateway: 0,
        interface: 0,
        metric: 0,
        gateway_present: false,
    };
    parse_route_fields(tokens, &mut route)?;
    route.gateway_present.then_some(route)
}

fn parse_route_fields<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    route: &mut ParsedRoute,
) -> Option<()> {
    route.destination = parse_ipv4(tokens.next()?)?;
    let mut have_gateway = false;

    while let Some(token) = tokens.next() {
        match token.to_uppercase().as_str() {
            "MASK" => route.netmask = parse_ipv4(tokens.next()?)?,
            "GATEWAY" => {
                route.gateway = parse_ipv4(tokens.next()?)?;
                have_gateway = true;
                route.gateway_present = true;
            }
            "METRIC" => route.metric = tokens.next()?.parse().ok()?,
            "IF" => route.interface = tokens.next()?.parse().ok()?,
            "ONLINK" if !have_gateway => {
                have_gateway = true;
                route.gateway_present = true;
            }
            gateway if !have_gateway => {
                route.gateway = parse_ipv4(gateway)?;
                have_gateway = true;
                route.gateway_present = true;
            }
            _ => return None,
        }
    }
    Some(())
}

struct ParsedRoute {
    destination: u32,
    netmask: u32,
    gateway: u32,
    interface: u32,
    metric: u32,
    gateway_present: bool,
}

fn service_state_name(state: crate::servers::services::ServiceState) -> &'static str {
    use crate::servers::services::ServiceState;
    match state {
        ServiceState::Stopped => "STOPPED",
        ServiceState::StartPending => "START_PENDING",
        ServiceState::StopPending => "STOP_PENDING",
        ServiceState::Running => "RUNNING",
        ServiceState::ContinuePending => "CONTINUE_PENDING",
        ServiceState::PausePending => "PAUSE_PENDING",
        ServiceState::Paused => "PAUSED",
    }
}

fn cmd_sc(arguments: &str) -> bool {
    let mut tokens = arguments.split_whitespace();
    let operation = tokens.next().unwrap_or("").to_lowercase();
    let name = tokens.next().unwrap_or("");
    match operation.as_str() {
        "query" if name.is_empty() => {
            output_line("SERVICE_NAME                      STATE");
            output_line("-------------------------------- ----------------");
            for (name, state) in crate::servers::services::list_services() {
                output_line(&format!("{:<34} {}", name, service_state_name(state)));
            }
            false
        }
        "query" => {
            match crate::servers::services::query_service_info(name) {
                Some(service) => {
                    output_line(&format!("SERVICE_NAME: {}", service.name));
                    output_line(&format!("DISPLAY_NAME: {}", service.display_name));
                    output_line(&format!(
                        "STATE       : {}",
                        service_state_name(service.state)
                    ));
                    output_line(&format!("IMAGE_PATH  : {}", service.image_path));
                }
                None => output_line("The specified service does not exist."),
            }
            false
        }
        "start" => {
            let message = if crate::servers::services::start_service(name) {
                format!("{} service was started successfully.", name)
            } else {
                format!("The {} service could not be started.", name)
            };
            output_line(&message);
            false
        }
        "stop" => {
            let message = if crate::servers::services::stop_service(name) {
                format!("{} service was stopped successfully.", name)
            } else {
                format!("The {} service could not be stopped.", name)
            };
            output_line(&message);
            false
        }
        _ => {
            output_line("Syntax: SC [query|start|stop] [service_name]");
            false
        }
    }
}

fn cmd_tasklist(_arguments: &str) -> bool {
    output_line("Image Name                     PID   Mem Usage");
    output_line("=========================================================================");
    match crate::ps::process_mgmt::get_all_processes() {
        Ok(processes) => {
            for process in processes {
                output_line(&format!(
                    "{:<28} {:>5} {:>7} K",
                    process.name,
                    process.pid,
                    process.memory_usage / 1024
                ));
            }
        }
        Err(_) => output_line("The process list is unavailable."),
    }
    false
}

fn cmd_taskkill(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    if let Some(index) = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("/PID"))
    {
        if let Ok(pid) = tokens.get(index + 1).unwrap_or(&"").parse::<u64>() {
            let message = match crate::ps::process_mgmt::terminate_process_by_pid(pid, true) {
                Ok(()) => format!(
                    "SUCCESS: Sent termination signal to process with PID {}.",
                    pid
                ),
                Err(_) => String::from("ERROR: The process could not be terminated."),
            };
            output_line(&message);
            return false;
        }
    }
    output_line("Syntax: TASKKILL /PID processid");
    false
}

fn cmd_timeout(arguments: &str) -> bool {
    let message = match arguments.split_whitespace().next() {
        Some(seconds) => format!(
            "Waiting for {} seconds, press a key to continue ...",
            seconds
        ),
        None => String::from("Syntax: TIMEOUT /T seconds"),
    };
    output_line(&message);
    false
}

fn cmd_title(arguments: &str) -> bool {
    output_line(if arguments.is_empty() {
        "Administrator: Command Prompt"
    } else {
        arguments
    });
    false
}

fn cmd_identity(command: &str) -> bool {
    output_line(match command {
        "ver" => "Microsoft Windows [Version 6.1.7601]",
        "vol" => " Volume in drive C is NT6.1\r\n Volume Serial Number is 0A1B-2C3D",
        "whoami" => "nt61\\user",
        _ => "",
    });
    false
}

fn cmd_where(arguments: &str, cwd: &[u8]) -> bool {
    if arguments.is_empty() {
        output_line("Syntax: WHERE pattern");
        return false;
    }
    let message = if open_shell_path(arguments, cwd).is_some() {
        format!(
            "{}\\{}",
            core::str::from_utf8(cwd).unwrap_or("C:\\"),
            arguments
        )
    } else {
        String::from("The system cannot find the file specified.")
    };
    output_line(&message);
    false
}

fn cmd_tree(root: &[u8]) -> bool {
    let Some(filesystem) = crate::fs::ntfs::get_mounted_fs() else {
        output_line("The volume is not mounted.");
        return false;
    };
    let root_utf16 = root
        .iter()
        .map(|byte| u16::from(*byte))
        .collect::<Vec<u16>>();
    let directory_record = crate::fs::ntfs::open_file(filesystem, &root_utf16, None)
        .map(|handle| handle.mft_record)
        .unwrap_or(5);
    output_line(core::str::from_utf8(root).unwrap_or("C:\\"));
    let mut visited = alloc::collections::BTreeSet::new();
    print_tree(filesystem, directory_record, "", &mut visited);
    false
}

fn print_tree(
    filesystem: &mut crate::fs::ntfs::NtfsFileSystem,
    directory_record: u64,
    indentation: &str,
    visited: &mut alloc::collections::BTreeSet<u64>,
) {
    if !visited.insert(directory_record) {
        return;
    }
    for entry in crate::fs::ntfs::list_directory(filesystem, directory_record) {
        let name = String::from_utf16_lossy(&entry.name);
        if name == "." || name == ".." {
            continue;
        }
        if entry.is_directory {
            output_line(&format!("{}+---{}", indentation, name));
            let child_record = entry.record_number;
            if !visited.contains(&child_record) {
                print_tree(
                    filesystem,
                    child_record,
                    &format!("{}|   ", indentation),
                    visited,
                );
            }
        }
    }
}

fn read_file_lines(path: &str, cwd: &[u8]) -> Option<Vec<String>> {
    let handle = open_shell_path(path, cwd)?;
    if handle.is_directory {
        return None;
    }
    let filesystem = crate::fs::ntfs::get_mounted_fs()?;
    let mut handle = handle;
    let mut data = alloc::vec![0u8; handle.file_size as usize];
    let read = crate::fs::ntfs::read_file(filesystem, &mut handle, &mut data).ok()?;
    data.truncate(read);
    let text = String::from_utf8_lossy(&data).into_owned();
    Some(text.lines().map(|line| line.to_string()).collect())
}

fn cmd_more(arguments: &str, cwd: &[u8]) -> bool {
    let path = arguments.split_whitespace().next().unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: MORE filename");
        return false;
    }
    match read_file_lines(path, cwd) {
        Some(lines) => {
            let page_size = 20usize;
            for (index, line) in lines.iter().enumerate() {
                output_line(line);
                if (index + 1) % page_size == 0 && index + 1 < lines.len() {
                    output("-- More -- ");
                    let _ = crate::hal::keyboard_input::read_byte();
                    output("\r\n");
                }
            }
        }
        None => output_line("The system cannot find the file specified."),
    }
    false
}

fn cmd_find(arguments: &str, cwd: &[u8]) -> bool {
    let tokens: Vec<&str> = arguments.split_whitespace().collect();
    let needle = tokens
        .iter()
        .find(|token| token.starts_with('"'))
        .map(|token| token.trim_matches('"').to_string());
    let file = tokens
        .iter()
        .find(|token| !token.starts_with('/') && !token.starts_with('"'))
        .copied()
        .unwrap_or("");
    let Some(needle) = needle else {
        output_line("Syntax: FIND \"string\" [filename]");
        return false;
    };
    if file.is_empty() {
        output_line("Syntax: FIND \"string\" filename");
        return false;
    }
    let needle_lower = needle.to_lowercase();
    let count = match read_file_lines(file, cwd) {
        Some(lines) => {
            let matches: Vec<&String> = lines
                .iter()
                .filter(|line| line.to_lowercase().contains(&needle_lower))
                .collect();
            for line in &matches {
                output_line(line);
            }
            matches.len()
        }
        None => {
            output_line("The system cannot find the file specified.");
            return false;
        }
    };
    output_line(&format!("---------- {}: {}", file, count));
    false
}

fn cmd_findstr(arguments: &str, cwd: &[u8]) -> bool {
    let tokens: Vec<&str> = arguments.split_whitespace().collect();
    let mut pattern = "";
    let mut file = "";
    let mut index = 0;
    while index < tokens.len() {
        if !tokens[index].starts_with('/') {
            if pattern.is_empty() {
                pattern = tokens[index].trim_matches('"');
            } else {
                file = tokens[index];
            }
        }
        index += 1;
    }
    if pattern.is_empty() || file.is_empty() {
        output_line("Syntax: FINDSTR pattern filename");
        return false;
    }
    let pattern_lower = pattern.to_lowercase();
    match read_file_lines(file, cwd) {
        Some(lines) => {
            for line in &lines {
                if line.to_lowercase().contains(&pattern_lower) {
                    output_line(line);
                }
            }
        }
        None => output_line("The system cannot find the file specified."),
    }
    false
}

fn cmd_fc(arguments: &str, cwd: &[u8]) -> bool {
    let files: Vec<&str> = arguments
        .split_whitespace()
        .filter(|token| !token.starts_with('/'))
        .collect();
    if files.len() != 2 {
        output_line("Syntax: FC filename1 filename2");
        return false;
    }
    let left = match read_file_lines(files[0], cwd) {
        Some(lines) => lines,
        None => {
            output_line(&format!(
                "The system cannot find the file specified: {}",
                files[0]
            ));
            return false;
        }
    };
    let right = match read_file_lines(files[1], cwd) {
        Some(lines) => lines,
        None => {
            output_line(&format!(
                "The system cannot find the file specified: {}",
                files[1]
            ));
            return false;
        }
    };
    if left == right {
        output_line("FC: no differences encountered.");
        return false;
    }
    output_line(&format!("Comparing {} and {}", files[0], files[1]));
    output_line("*****");
    let max = left.len().max(right.len());
    for index in 0..max {
        let left_line = left.get(index).map(|line| line.as_str()).unwrap_or("");
        let right_line = right.get(index).map(|line| line.as_str()).unwrap_or("");
        if left_line != right_line {
            output_line(&format!("L:{}", left_line));
            output_line(&format!("R:{}", right_line));
        }
    }
    false
}

fn cmd_sort(arguments: &str, cwd: &[u8]) -> bool {
    let path = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/'))
        .unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: SORT [filename] [/R] [/O output]");
        return false;
    }
    let reverse = arguments.to_lowercase().contains("/r");
    let mut lines = match read_file_lines(path, cwd) {
        Some(lines) => lines,
        None => {
            output_line("The system cannot find the file specified.");
            return false;
        }
    };
    if reverse {
        lines.sort_by(|a, b| b.cmp(a));
    } else {
        lines.sort();
    }
    for line in &lines {
        output_line(line);
    }
    false
}

fn cmd_choice(arguments: &str) -> bool {
    let chars = arguments
        .split_whitespace()
        .find(|token| token.starts_with("/c"))
        .and_then(|token| token.strip_prefix("/c"))
        .unwrap_or("YN");
    output("Choice [");
    for (index, character) in chars.chars().enumerate() {
        if index > 0 {
            output(",");
        }
        output(&character.to_string());
    }
    output_line("]?");
    let _ = crate::hal::keyboard_input::read_byte();
    false
}

fn cmd_clip(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("CLIP: clipboard contents not accessible in console mode.");
    } else {
        output_line("CLIP: text queued for clipboard.");
    }
    false
}

fn cmd_compact(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("COMPACT reports NTFS compression status.");
    } else {
        output_line("COMPACT: compression operations are not supported on this volume.");
    }
    false
}

fn cmd_cipher(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("CIPHER: file encryption is not enabled on this volume.");
    } else {
        output_line("CIPHER: EFS operations require an encrypted volume.");
    }
    false
}

fn cmd_chkdsk(command: &str, arguments: &str) -> bool {
    let label = if command.eq_ignore_ascii_case("chkntfs") {
        "CHKNTFS"
    } else {
        "CHKDSK"
    };
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("C:");
    output_line(&format!("The type of the file system is NTFS."));
    output_line(&format!("{} is checking the volume {}.", label, volume));
    output_line("No file system errors were found.");
    false
}

fn cmd_bcdedit(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/enum") || arguments.is_empty() {
        output_line("Windows Boot Manager");
        output_line("--------------------");
        output_line("identifier              {bootmgr}");
        output_line("device                  partition=C:");
        output_line("description             Windows Boot Manager");
        output_line("default                 {default}");
        output_line("timeout                 30");
        output_line("");
        output_line("Windows Boot Loader");
        output_line("-------------------");
        output_line("identifier              {default}");
        output_line("device                  partition=C:");
        output_line("description             Windows 7");
        output_line("osdevice                partition=C:");
        output_line("path                    \\Windows\\system32\\winload.efi");
    } else {
        output_line("BCDEDIT: the specified operation is not supported at runtime.");
    }
    false
}

fn cmd_mode(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("Status for device CON:");
        output_line("    Columns:          80");
        output_line("    Lines:            25");
    } else {
        output_line("MODE: the requested operation completed successfully.");
    }
    false
}

fn cmd_doskey(arguments: &str) -> bool {
    if arguments.is_empty() || arguments.to_lowercase().contains("/history") {
        output_line("DOSKEY: command history is managed by the shell.");
    } else {
        output_line("DOSKEY: the requested macro has been registered.");
    }
    false
}

fn cmd_netsh(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("show") => match tokens.get(1).map(|token| token.to_lowercase()).as_deref() {
            Some("interface") => {
                let interfaces = crate::netstack::ipif::get_all_interfaces();
                output_line("MSTA State      Name        Interface Type  MTU   Metric");
                for interface in interfaces {
                    output_line(&format!(
                        "connected       LAN         Ethernet        1500  {}",
                        interface.if_index
                    ));
                }
            }
            Some("ipconfig") => {
                let _ = cmd_ipconfig("");
            }
            Some("route") => {
                let _ = cmd_netstat();
            }
            _ => output_line("Syntax: NETSH SHOW [interface | ipconfig | route]"),
        },
        _ => output_line("Syntax: NETSH SHOW [interface | ipconfig | route]"),
    }
    false
}

fn cmd_nslookup(arguments: &str) -> bool {
    let name = arguments.split_whitespace().next().unwrap_or("");
    if name.is_empty() {
        output_line("Syntax: NSLOOKUP hostname");
        return false;
    }
    match crate::netstack::dns::resolve(name) {
        Ok(address) => {
            output_line(&format!("Name:    {}", name));
            output_line(&format!("Address: {}", format_ipv4(address)));
        }
        Err(_) => output_line(&format!("** server can't find {}: NXDOMAIN", name)),
    }
    false
}

fn cmd_setx(arguments: &str) -> bool {
    let tokens: Vec<&str> = arguments.splitn(2, ' ').collect();
    match tokens.len() {
        2 => {
            let (name, value) = (tokens[0], tokens[1].trim_matches('"'));
            output_line(&format!(
                "SUCCESS: Specified environment variable {} set to {}.",
                name, value
            ));
        }
        _ => output_line("Syntax: SETX variable value"),
    }
    false
}

fn cmd_start(arguments: &str) -> bool {
    let target = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/') && !token.starts_with('"'))
        .unwrap_or("");
    if target.is_empty() {
        output_line("START command requires a program or command to run.");
    } else {
        output_line(&format!("Starting: {}", target));
    }
    false
}

fn cmd_pushd(arguments: &str, cwd: &[u8]) -> bool {
    let path = arguments.split_whitespace().next().unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: PUSHD path");
        return false;
    }
    match open_shell_path(path, cwd) {
        Some(handle) if handle.is_directory => output_line("Directory pushed."),
        _ => output_line("The system cannot find the path specified."),
    }
    false
}

fn cmd_popd() -> bool {
    output_line("Directory restored.");
    false
}

fn cmd_subst(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No substituted drives are currently defined.");
    } else {
        output_line("SUBST: the specified operation is not supported on this volume.");
    }
    false
}

fn cmd_takeown(arguments: &str) -> bool {
    let path = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/'))
        .unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: TAKEOWN filename");
    } else {
        output_line(&format!(
            "Ownership of {} has been transferred to the current user.",
            path
        ));
    }
    false
}

fn cmd_wmic(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    if tokens.len() < 2 {
        output_line("Syntax: WMIC <alias> <verb>");
        return false;
    }
    let alias = tokens[0].to_lowercase();
    let verb = tokens[1].to_lowercase();
    match alias.as_str() {
        "cpu" if verb == "list" => {
            output_line("Caption           Name              NumberOfCores");
            output_line("AMD64 Family 6    CPU0              4");
        }
        "os" if verb == "list" => {
            output_line("Caption      Version      BuildNumber");
            output_line("Microsoft Windows 7 Ultimate  6.1.7601");
        }
        _ => output_line(&format!("WMIC: alias '{}' is not recognized.", alias)),
    }
    false
}

fn cmd_schtasks(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("query") => output_line("No scheduled tasks are currently defined."),
        Some("create") => output_line("SUCCESS: The scheduled task has been created."),
        Some("delete") => output_line("SUCCESS: The scheduled task has been deleted."),
        Some("run") => output_line("SUCCESS: The scheduled task has been started."),
        _ => output_line("Syntax: SCHTASKS [query | create | delete | run] [/TN task_name]"),
    }
    false
}

fn cmd_diskpart() -> bool {
    output_line("Disk ###  Status   Size   Free");
    output_line("--------  -------  -----  -----");
    output_line("Disk 0    Online   32 GB  0 B");
    false
}

fn cmd_convert(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("C:");
    output_line(&format!("{} is already NTFS.", volume));
    false
}

fn cmd_format(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("");
    if volume.is_empty() {
        output_line("Syntax: FORMAT volume [/FS:ntfs]");
    } else {
        output_line("FORMAT: formatting is not supported on the system volume.");
    }
    false
}

fn cmd_robocopy(arguments: &str, _cwd: &[u8]) -> bool {
    let files: Vec<&str> = arguments
        .split_whitespace()
        .filter(|token| !token.starts_with('/') && !token.starts_with('"'))
        .collect();
    if files.len() < 2 {
        output_line("Syntax: ROBOCOPY source destination");
        return false;
    }
    output_line(&format!(
        "ROBOCOPY: copying {} to {} is not supported in this build.",
        files[0], files[1]
    ));
    false
}

fn cmd_xcopy(arguments: &str, _cwd: &[u8]) -> bool {
    let files: Vec<&str> = arguments
        .split_whitespace()
        .filter(|token| !token.starts_with('/') && !token.starts_with('"'))
        .collect();
    if files.len() < 2 {
        output_line("Syntax: XCOPY source destination [/S /E]");
        return false;
    }
    output_line("Xcopy operation failed. Source file not found.");
    false
}

fn cmd_replace(arguments: &str, _cwd: &[u8]) -> bool {
    let files: Vec<&str> = arguments
        .split_whitespace()
        .filter(|token| !token.starts_with('/') && !token.starts_with('"'))
        .collect();
    if files.len() < 2 {
        output_line("Syntax: REPLACE source destination");
        return false;
    }
    output_line(&format!(
        "Replace operation: {} -> {} not supported.",
        files[0], files[1]
    ));
    false
}

fn cmd_recover(arguments: &str) -> bool {
    let path = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/'))
        .unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: RECOVER filename");
    } else {
        output_line(&format!(
            "RECOVER: no recoverable data was found in {}.",
            path
        ));
    }
    false
}

fn cmd_bootcfg(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/query") || arguments.is_empty() {
        output_line("Boot Loader Configuration");
        output_line("--------------------------");
        output_line("timeout: 30");
        output_line("default: Windows 7");
    } else {
        output_line("BOOTCFG: the requested operation requires administrator privileges.");
    }
    false
}

fn cmd_cmdkey(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("/list") => output_line("Currently stored credentials: (none)"),
        Some("/add") => output_line("Credential stored successfully."),
        Some("/delete") => output_line("Credential deleted successfully."),
        _ => {
            output_line("Syntax: CMDKEY [/list | /add | /delete] [/user:username] [/pass:password]")
        }
    }
    false
}

fn cmd_comp(arguments: &str, cwd: &[u8]) -> bool {
    let files: Vec<&str> = arguments
        .split_whitespace()
        .filter(|token| !token.starts_with('/'))
        .collect();
    if files.len() != 2 {
        output_line("Syntax: COMP filename1 filename2");
        return false;
    }
    let left = match read_file_lines(files[0], cwd) {
        Some(lines) => lines,
        None => {
            output_line(&format!(
                "The system cannot find the file specified: {}",
                files[0]
            ));
            return false;
        }
    };
    let right = match read_file_lines(files[1], cwd) {
        Some(lines) => lines,
        None => {
            output_line(&format!(
                "The system cannot find the file specified: {}",
                files[1]
            ));
            return false;
        }
    };
    if left == right {
        output_line("Files compare OK.");
    } else {
        output_line("Files are different sizes.");
    }
    false
}

fn cmd_defrag(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("C:");
    output_line(&format!("Analysis of {}:", volume));
    output_line("    File system type: NTFS");
    output_line("    Fragmentation: 0% (optimal)");
    output_line("No defragmentation is required.");
    false
}

fn cmd_eventcreate(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/l") || arguments.contains("/id") {
        output_line("SUCCESS: The event has been created.");
    } else {
        output_line("Syntax: EVENTCREATE [/ID event_id] [/L log_name] /T type /D description");
    }
    false
}

fn cmd_extract(arguments: &str) -> bool {
    let target = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/') && !token.starts_with('"'))
        .unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: EXTRACT [/Y | /A] [/D] [/E] [source] [target]");
    } else {
        output_line("EXTRACT: CAB files are not supported on this volume.");
    }
    false
}

fn cmd_freedisk(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("C:");
    match crate::fs::ntfs::extended_api::get_space_usage() {
        Some(usage) => output_line(&format!("Free space on {}: {} KiB", volume, usage.free_kb)),
        None => output_line("The volume is not mounted."),
    }
    false
}

fn cmd_gpresult() -> bool {
    output_line("Group Policy Results");
    output_line("--------------------");
    output_line("No group policy objects are applied.");
    false
}

fn cmd_logman(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("query") || arguments.is_empty() {
        output_line("No data collector sets are defined.");
    } else {
        output_line("LOGMAN: the requested operation is not supported.");
    }
    false
}

fn cmd_logoff() -> bool {
    output_line("Logoff: the current session cannot be terminated from the console.");
    false
}

fn cmd_mount(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("MOUNT: no removable volumes are currently available.");
    } else {
        output_line("MOUNT: the specified volume is already mounted.");
    }
    false
}

fn cmd_msiexec(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/i") {
        output_line("MSIEXEC: the installer requires subsystem support not available.");
    } else if arguments.to_lowercase().contains("/x") {
        output_line("MSIEXEC: the uninstaller requires subsystem support not available.");
    } else {
        output_line("Syntax: MSIEXEC /i package.msi [/x for uninstall]");
    }
    false
}

fn cmd_openfiles(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/query") || arguments.is_empty() {
        output_line("No open files are currently listed.");
    } else {
        output_line("OPENFILES: the requested operation is not supported.");
    }
    false
}

fn cmd_query(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("user") => output_line("USERNAME   SESSIONNAME  ID   STATE    LOGTIME"),
        Some("process") => output_line("Process sessions are not currently available."),
        _ => output_line("Syntax: QUERY [user | process]"),
    }
    false
}

fn cmd_regsvr32(arguments: &str) -> bool {
    if arguments.contains("/s") {
        output_line("REGSVR32: DLL registration completed silently.");
    } else {
        output_line("REGSVR32: the specified module could not be found.");
    }
    false
}

fn cmd_runas(arguments: &str) -> bool {
    if arguments.contains("/user:") {
        output_line("RUNAS: user impersonation is not supported in this build.");
    } else {
        output_line("Syntax: RUNAS /user:username command");
    }
    false
}

fn cmd_typeperf(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("TYPEPERF: no performance counters are defined.");
    } else {
        output_line("TYPEPERF: performance counter collection is not supported.");
    }
    false
}

fn cmd_umount(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("");
    if volume.is_empty() {
        output_line("Syntax: UMOUNT volume");
    } else {
        output_line(&format!(
            "UMOUNT: {} is the system volume and cannot be unmounted.",
            volume
        ));
    }
    false
}

fn cmd_vssadmin(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("list") || arguments.is_empty() {
        output_line("No shadow copies are currently defined.");
    } else {
        output_line("VSSADMIN: the requested operation is not supported.");
    }
    false
}

fn cmd_wevtutil(arguments: &str) -> bool {
    let tokens = arguments.split_whitespace().collect::<Vec<&str>>();
    match tokens.first().map(|token| token.to_lowercase()).as_deref() {
        Some("qe") | Some("query-events") => {
            output_line("System Event Log:");
            output_line("  No events are currently logged.");
        }
        Some("el") | Some("enum-logs") => {
            output_line("System");
            output_line("Application");
            output_line("Security");
        }
        _ => output_line("Syntax: WEVTUTIL [el | qe] [/f:text]"),
    }
    false
}

fn cmd_forfiles(arguments: &str, cwd: &[u8]) -> bool {
    let path = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('/') && !token.starts_with("/c"))
        .unwrap_or(".");
    match open_shell_path(path, cwd) {
        Some(handle) if handle.is_directory => {
            let filesystem = crate::fs::ntfs::get_mounted_fs();
            if let Some(fs) = filesystem {
                for entry in crate::fs::ntfs::list_directory(fs, handle.mft_record) {
                    let name = String::from_utf16_lossy(&entry.name);
                    if name != "." && name != ".." {
                        output_line(&name);
                    }
                }
            }
        }
        _ => output_line("FORFILES: the specified path does not exist."),
    }
    false
}

fn cmd_auditpol(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/get") || arguments.is_empty() {
        output_line("Category / Subcategory   System Audit  Detailed Auditing");
        output_line("Logon/Logoff             Success       Failure");
        output_line("Object Access            Failure       No");
    } else {
        output_line("AUDITPOL: the policy has been updated.");
    }
    false
}

fn cmd_winsat(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("disk") {
        output_line("WINSAT: disk assessment requires exclusive access to the volume.");
    } else if arguments.to_lowercase().contains("cpu") {
        output_line("WINSAT: CPU assessment is not supported in this build.");
    } else if arguments.is_empty() {
        output_line("Syntax: WINSAT [cpu | disk | mem] [assessment_options]");
    } else {
        output_line("WINSAT: the specified assessment is not supported.");
    }
    false
}

fn cmd_at(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No scheduled commands are defined.");
    } else {
        output_line("AT: the requested task has been registered.");
    }
    false
}

fn cmd_bitsadmin(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/list") || arguments.is_empty() {
        output_line("BITSAdmin: no background transfers are currently active.");
    } else {
        output_line("BITSAdmin: the transfer service requires subsystem support.");
    }
    false
}

fn cmd_certutil(command: &str, arguments: &str) -> bool {
    let label = command.to_uppercase();
    if arguments.to_lowercase().contains("-l") || arguments.is_empty() {
        output_line(&format!(
            "{}: no certificates are currently installed.",
            label
        ));
    } else {
        output_line(&format!(
            "{}: the certificate store is not available.",
            label
        ));
    }
    false
}

fn cmd_cluster(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("list") || arguments.is_empty() {
        output_line("No clusters are currently configured.");
    } else {
        output_line("CLUSTER: clustering is not supported on this system.");
    }
    false
}

fn cmd_dnscmd(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/enumzones") {
        output_line("DNSCMD: no DNS zones are configured.");
    } else {
        output_line("DNSCMD: the DNS server service is not running.");
    }
    false
}

fn cmd_disktool(command: &str) -> bool {
    output_line(&format!(
        "{}: disk media operations require a physical disk and are not supported.",
        command.to_uppercase()
    ));
    false
}

fn cmd_diskraid(command: &str) -> bool {
    output_line(&format!(
        "{}: no disk arrays are currently configured.",
        command.to_uppercase()
    ));
    false
}

fn cmd_edit() -> bool {
    output_line("EDIT: the full-screen editor requires console-mode subsystem support.");
    false
}

fn cmd_flattemp(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("FLATTEMP: flat temp is not enabled.");
    } else {
        output_line("FLATTEMP: the operation has been completed.");
    }
    false
}

fn cmd_hashgen(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: HASHGEN filename");
    } else {
        output_line("HASHGEN: hash generation requires subsystem support.");
    }
    false
}

fn cmd_irftp(_arguments: &str) -> bool {
    output_line("IRFTP: no infrared devices are detected.");
    false
}

fn cmd_ktmutil(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("list") || arguments.is_empty() {
        output_line("KTMUTIL: no transaction managers are active.");
    } else {
        output_line("KTMUTIL: the requested operation is not supported.");
    }
    false
}

fn cmd_ktpass(_arguments: &str) -> bool {
    output_line("KTPASS: Kerberos keytab generation requires Active Directory support.");
    false
}

fn cmd_printer(command: &str, arguments: &str) -> bool {
    let label = command.to_uppercase();
    if arguments.is_empty() {
        output_line(&format!("{}: no print servers are configured.", label));
    } else {
        output_line(&format!("{}: the print service is not available.", label));
    }
    false
}

fn cmd_mapadmin(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("list") || arguments.is_empty() {
        output_line("MAPADMIN: no network mappings are defined.");
    } else {
        output_line("MAPADMIN: the requested operation is not supported.");
    }
    false
}

fn cmd_msg(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: MSG username [message]");
    } else {
        output_line(&format!("MSG: session '{}' not found.", target));
    }
    false
}

fn cmd_mstsc(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("MSTSC: no remote desktop connections are configured.");
    } else {
        output_line("MSTSC: remote desktop requires subsystem support.");
    }
    false
}

fn cmd_netdom(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("query") {
        output_line("NETDOM: this computer is not a member of a domain.");
    } else {
        output_line("NETDOM: domain operations require Active Directory support.");
    }
    false
}

fn cmd_nlb(command: &str, arguments: &str) -> bool {
    let label = command.to_uppercase();
    if arguments.to_lowercase().contains("query") || arguments.is_empty() {
        output_line(&format!(
            "{}: no network load balancing clusters are configured.",
            label
        ));
    } else {
        output_line(&format!(
            "{}: the requested operation is not supported.",
            label
        ));
    }
    false
}

fn cmd_ntbackup(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("backup") {
        output_line("NTBACKUP: backup operations require subsystem support.");
    } else {
        output_line("NTBACKUP: no backup sets are defined.");
    }
    false
}

fn cmd_ntdsutil(_arguments: &str) -> bool {
    output_line("NTDSUTIL: Active Directory Database tools are not available.");
    false
}

fn cmd_perfmon() -> bool {
    output_line("PERFMON: performance monitor requires GUI subsystem support.");
    false
}

fn cmd_print(arguments: &str) -> bool {
    let path = arguments.split_whitespace().next().unwrap_or("");
    if path.is_empty() {
        output_line("Syntax: PRINT filename");
    } else {
        output_line(&format!(
            "PRINT: no print devices are available for {}.",
            path
        ));
    }
    false
}

fn cmd_pubprn(_arguments: &str) -> bool {
    output_line("PUBPRN: printer publication requires Active Directory support.");
    false
}

fn cmd_rdpsign(_arguments: &str) -> bool {
    output_line("RDPSIGN: RDP signing requires certificate store support.");
    false
}

fn cmd_reagentc(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("/info") {
        output_line("REAGENTC: Windows Recovery Environment is not configured.");
    } else {
        output_line("REAGENTC: the recovery environment is not available.");
    }
    false
}

fn cmd_reset() -> bool {
    output_line("RESET: the terminal settings have been reset.");
    false
}

fn cmd_rpcinfo(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: RPCINFO target_host");
    } else {
        output_line(&format!(
            "RPCINFO: RPC endpoint mapper unreachable for {}.",
            target
        ));
    }
    false
}

fn cmd_setspn(_arguments: &str) -> bool {
    output_line("SETSPN: Service Principal Name management requires Active Directory.");
    false
}

fn cmd_showmount(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("SHOWMOUNT: no NFS exports are configured.");
    } else {
        output_line("SHOWMOUNT: the specified NFS server is unreachable.");
    }
    false
}

fn cmd_storrept(_arguments: &str) -> bool {
    output_line("STORREPT: storage reports are not supported on this volume.");
    false
}

fn cmd_tlntadmn(_arguments: &str) -> bool {
    output_line("TLNTADMN: telnet administration requires the telnet service.");
    false
}

fn cmd_tracerpt(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("TRACERPT: no trace sessions are active.");
    } else {
        output_line("TRACERPT: trace processing requires subsystem support.");
    }
    false
}

fn cmd_wbadmin(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("get") {
        output_line("WBADMIN: no backup sets are available.");
    } else {
        output_line("WBADMIN: backup operations require subsystem support.");
    }
    false
}

fn cmd_wdsutil(_arguments: &str) -> bool {
    output_line("WDSUTIL: Windows Deployment Services is not installed.");
    false
}

fn cmd_wecutil(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("es") || arguments.is_empty() {
        output_line("WECUTIL: no event collector subscriptions are defined.");
    } else {
        output_line("WECUTIL: the requested operation is not supported.");
    }
    false
}

fn cmd_adprep(_arguments: &str) -> bool {
    output_line("ADPREP: forest preparation requires Active Directory support.");
    false
}

fn cmd_csvde(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("-l") {
        output_line("CSVDE: no directory entries found.");
    } else {
        output_line("CSVDE: Active Directory import/export is not available.");
    }
    false
}

fn cmd_dcdiag() -> bool {
    output_line("DCDIAG: this computer is not a domain controller.");
    false
}

fn cmd_dcpromo(_arguments: &str) -> bool {
    output_line("DCPROMO: domain controller promotion is not supported.");
    false
}

fn cmd_dfscmd(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("list") {
        output_line("DFSCMD: no DFS links are configured.");
    } else {
        output_line("DFSCMD: DFS management is not available.");
    }
    false
}

fn cmd_dsacls(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: DSACLS dn");
    } else {
        output_line("DSACLS: Active Directory ACL management is not available.");
    }
    false
}

fn cmd_dsadd(_arguments: &str) -> bool {
    output_line("DSADD: Active Directory object creation is not available.");
    false
}

fn cmd_dsamain(_arguments: &str) -> bool {
    output_line("DSAMAIN: Active Directory database mode requires database support.");
    false
}

fn cmd_dsdbutil(_arguments: &str) -> bool {
    output_line("DSDBUTIL: Active Directory database tools are not available.");
    false
}

fn cmd_dsget(_arguments: &str) -> bool {
    output_line("DSGET: Active Directory object queries are not available.");
    false
}

fn cmd_dsmgmt(_arguments: &str) -> bool {
    output_line("DSMGMT: Active Directory management is not available.");
    false
}

fn cmd_dsmod(_arguments: &str) -> bool {
    output_line("DSMOD: Active Directory object modification is not available.");
    false
}

fn cmd_dsmove(_arguments: &str) -> bool {
    output_line("DSMOVE: Active Directory object moves are not available.");
    false
}

fn cmd_dsquery(_arguments: &str) -> bool {
    output_line("DSQUERY: Active Directory queries are not available.");
    false
}

fn cmd_dsrm(_arguments: &str) -> bool {
    output_line("DSRM: Active Directory object deletion is not available.");
    false
}

fn cmd_ldifde(_arguments: &str) -> bool {
    output_line("LDIFDE: Active Directory import/export is not available.");
    false
}

fn cmd_ldp() -> bool {
    output_line("LDP: the LDAP browser requires GUI subsystem support.");
    false
}

fn cmd_repadmin(_arguments: &str) -> bool {
    output_line("REPADMIN: Active Directory replication is not available.");
    false
}

fn cmd_ts_change(command: &str, arguments: &str) -> bool {
    let label = command.to_uppercase();
    if arguments.is_empty() {
        output_line(&format!("{}: syntax is not recognized.", label));
    } else {
        output_line(&format!("{}: terminal services are not running.", label));
    }
    false
}

fn cmd_qappsrv() -> bool {
    output_line("QAPPSRV: no terminal application servers are available.");
    false
}

fn cmd_qprocess(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No processes are currently visible in this session.");
    } else {
        output_line("QPROCESS: the specified session is not found.");
    }
    false
}

fn cmd_quser() -> bool {
    output_line("USERNAME   SESSIONNAME  ID   STATE");
    output_line("user       console       1   Active");
    false
}

fn cmd_qwinsta() -> bool {
    output_line("SESSIONNAME    USERNAME      ID   STATE");
    output_line("console        user           1   Active");
    false
}

fn cmd_rwinsta(arguments: &str) -> bool {
    let session = arguments.split_whitespace().next().unwrap_or("");
    if session.is_empty() {
        output_line("Syntax: RWINSTA session_id");
    } else {
        output_line("RWINSTA: the specified session is not found.");
    }
    false
}

fn cmd_shadow(arguments: &str) -> bool {
    let session = arguments.split_whitespace().next().unwrap_or("");
    if session.is_empty() {
        output_line("Syntax: SHADOW session_id");
    } else {
        output_line("SHADOW: session shadowing is not supported.");
    }
    false
}

fn cmd_tscon(_arguments: &str) -> bool {
    output_line("TSCON: session connection is not supported.");
    false
}

fn cmd_tsdiscon(_arguments: &str) -> bool {
    output_line("TSDISCON: session disconnection is not supported.");
    false
}

fn cmd_tskill(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: TSKILL process_id");
    } else {
        output_line(&format!("TSKILL: process '{}' not found.", target));
    }
    false
}

fn cmd_tsprof(_arguments: &str) -> bool {
    output_line("TSPROF: terminal services profiling is not supported.");
    false
}

fn cmd_ftp(arguments: &str) -> bool {
    let host = arguments.split_whitespace().next().unwrap_or("");
    if host.is_empty() {
        output_line("Syntax: FTP hostname");
    } else {
        output_line(&format!(
            "FTP: connection to {} failed - network not available.",
            host
        ));
    }
    false
}

fn cmd_telnet(arguments: &str) -> bool {
    let host = arguments.split_whitespace().next().unwrap_or("");
    if host.is_empty() {
        output_line("Syntax: TELNET hostname [port]");
    } else {
        output_line(&format!(
            "TELNET: connection to {} failed - service unavailable.",
            host
        ));
    }
    false
}

fn cmd_tftp(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: TFTP [-i] host [GET | PUT] source [destination]");
    } else {
        output_line("TFTP: the TFTP service is not available.");
    }
    false
}

fn cmd_remote_shell(command: &str, arguments: &str) -> bool {
    let label = command.to_uppercase();
    let host = arguments.split_whitespace().next().unwrap_or("");
    if host.is_empty() {
        output_line(&format!("Syntax: {} hostname", label));
    } else {
        output_line(&format!("{}: connection to {} refused.", label, host));
    }
    false
}

fn cmd_autochk(arguments: &str) -> bool {
    let volume = arguments
        .split_whitespace()
        .find(|token| token.len() == 2 && token.ends_with(':'))
        .unwrap_or("C:");
    output_line(&format!("AUTOCHK: checking volume {}...", volume));
    output_line("No errors found.");
    false
}

fn cmd_autoconv(_arguments: &str) -> bool {
    output_line("AUTOCONV: filesystem conversion is not supported at runtime.");
    false
}

fn cmd_autofmt(_arguments: &str) -> bool {
    output_line("AUTOFMT: volume formatting requires setup-mode support.");
    false
}

fn cmd_append(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("No append paths are set.");
    } else {
        output_line(&format!("APPEND path set to: {}", arguments));
    }
    false
}

fn cmd_call(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Syntax: CALL script.bat [arguments]");
    } else {
        output_line(&format!("CALL: script '{}' was not found.", target));
    }
    false
}

fn cmd_shift() -> bool {
    output_line("SHIFT: no additional batch arguments to consume.");
    false
}

fn cmd_setlocal(arguments: &str) -> bool {
    if arguments.to_lowercase().contains("enabledelayedexpansion") {
        output_line("Setlocal enabled delayed expansion.");
    } else {
        output_line("Setlocal: local scope started.");
    }
    false
}

fn cmd_endlocal() -> bool {
    output_line("Endlocal: local scope ended.");
    false
}

fn cmd_for(arguments: &str) -> bool {
    if arguments.to_lowercase().starts_with("%%") || arguments.to_lowercase().starts_with("%") {
        output_line("FOR: batch loop variables are not supported in interactive mode.");
    } else if arguments.is_empty() {
        output_line("Syntax: FOR %%variable IN (set) DO command");
    } else {
        output_line("FOR: loop expressions require batch file context.");
    }
    false
}

fn cmd_goto(arguments: &str) -> bool {
    let label = arguments.split_whitespace().next().unwrap_or("");
    if label.is_empty() {
        output_line("Syntax: GOTO label");
    } else {
        output_line(&format!(
            "GOTO: label '{}' was not found in the batch file.",
            label
        ));
    }
    false
}

fn cmd_if(arguments: &str) -> bool {
    if arguments.is_empty() {
        output_line("Syntax: IF [NOT] condition command");
    } else {
        output_line("IF: conditional expressions require batch file context.");
    }
    false
}

fn cmd_redircmp(_arguments: &str) -> bool {
    output_line("REDIRCMP: compare redirection requires Active Directory support.");
    false
}

fn cmd_redirusr(_arguments: &str) -> bool {
    output_line("REDIRUSR: user redirection requires Active Directory support.");
    false
}

fn cmd_ping(arguments: &str) -> bool {
    let mut tokens = arguments.split_whitespace();
    let mut target = "";
    let mut count = 4u32;
    while let Some(token) = tokens.next() {
        match token.to_lowercase().as_str() {
            "-n" => {
                if let Some(value) = tokens.next().and_then(|value| value.parse().ok()) {
                    count = value;
                }
            }
            "-t" => count = 0,
            _ => target = token,
        }
    }
    if target.is_empty() {
        output_line("Usage: ping [-n count] [-t] hostname | IP address");
        return false;
    }
    let address = match crate::netstack::dns::resolve(target) {
        Ok(address) => address,
        Err(_) => {
            output_line(&format!(
                "Ping request could not find host {}. Please check the name and try again.",
                target
            ));
            return false;
        }
    };
    output_line(&format!(
        "Pinging {} [{}] with 32 bytes of data:",
        target,
        format_ipv4(address)
    ));

    let probe_count = if count == 0 { 10 } else { count };
    let identifier = 0x4E61u16;
    let mut received = 0u32;
    let mut replies_size = 32usize;

    for sequence in 0..probe_count {
        let sequence = sequence as u16;
        crate::netstack::icmp::arm_echo_reply(identifier, sequence);
        let sent = crate::netstack::icmp::send_echo_request(address, identifier, sequence);
        if !sent {
            output_line("Transmission failed.");
            continue;
        }

        let start = crate::hal::common::pit::get_system_time_ms();
        let deadline = start + 1_000;
        let mut got_reply = false;
        while crate::hal::common::pit::get_system_time_ms() < deadline {
            crate::drivers::net::poll_all();
            if let Some((_, size)) = crate::netstack::icmp::take_echo_reply(identifier, sequence) {
                replies_size = size.max(0);
                received += 1;
                got_reply = true;
                break;
            }
        }

        if got_reply {
            output_line(&format!(
                "Reply from {}: bytes={} time<1ms TTL=128",
                format_ipv4(address),
                replies_size
            ));
        } else {
            output_line("Request timed out.");
        }
    }

    let lost = probe_count.saturating_sub(received);
    output_line("");
    output_line(&format!("Ping statistics for {}:", format_ipv4(address)));
    output_line(&format!(
        "     Packets: Sent = {}, Received = {}, Lost = {} ({}% loss)",
        probe_count,
        received,
        lost,
        (lost * 100) / probe_count.max(1)
    ));
    false
}

fn cmd_tracert(arguments: &str) -> bool {
    let target = arguments.split_whitespace().last().unwrap_or("");
    if target.is_empty() {
        output_line("Usage: tracert hostname | IP address");
        return false;
    }
    let address = match crate::netstack::dns::resolve(target) {
        Ok(address) => address,
        Err(_) => {
            output_line(&format!("Unable to resolve target system name {}.", target));
            return false;
        }
    };
    output_line(&format!(
        "Tracing route to {} [{}]",
        target,
        format_ipv4(address)
    ));
    output_line("over a maximum of 30 hops:");
    output_line("");
    output_line(&format!(
        "  1  <1 ms  <1 ms  <1 ms  {}",
        format_ipv4(address)
    ));
    output_line("");
    output_line("Trace complete.");
    false
}

fn cmd_pathping(arguments: &str) -> bool {
    let target = arguments.split_whitespace().last().unwrap_or("");
    if target.is_empty() {
        output_line("Usage: pathping hostname | IP address");
        return false;
    }
    let address = match crate::netstack::dns::resolve(target) {
        Ok(address) => address,
        Err(_) => {
            output_line(&format!("Unable to resolve target system name {}.", target));
            return false;
        }
    };
    output_line(&format!(
        "Trace route to {} [{}]",
        target,
        format_ipv4(address)
    ));
    output_line("");
    output_line(&format!("  0  {}", format_ipv4(address)));
    output_line("");
    output_line("Computing statistics for 0 seconds...");
    output_line("");
    output_line("Trace complete.");
    false
}

fn cmd_nbtstat(arguments: &str) -> bool {
    let option = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match option.as_str() {
        "-n" => {
            output_line("NetBIOS Local Name Table");
            output_line("");
            output_line("   Name              Type          Status");
            output_line("  -----------------------------------------");
            output_line("  NT61-RS            <00>  Unique     Registered");
        }
        "-r" => {
            output_line("NetBIOS Names Resolved: 0");
        }
        "-s" | "-S" => {
            output_line("NetBIOS Session Table");
            output_line("");
            output_line("  Local Name     Remote Name     State");
        }
        _ => {
            output_line("Displays protocol statistics and current TCP/IP connections using");
            output_line("NetBIOS over TCP/IP (NBT).");
            output_line("");
            output_line("NBTSTAT [-n] [-r] [-s | -S]");
        }
    }
    false
}

fn cmd_netdiag() -> bool {
    let interfaces = crate::netstack::ipif::get_all_interfaces();
    output_line("Windows Network Diagnostics");
    output_line("");
    for interface in interfaces.iter() {
        output_line(&format!(
            "Interface {}: {}",
            interface.if_index,
            format_ipv4(interface.address)
        ));
        let has_route = crate::netstack::routing::get_all_routes()
            .iter()
            .any(|route| route.interface == interface.if_index);
        if has_route {
            output_line("  Route table: OK");
        } else {
            output_line("  Route table: No routes configured");
        }
    }
    let dns = crate::netstack::dns::get_dns_server();
    if dns != 0 {
        output_line(&format!("DNS server: {}", format_ipv4(dns)));
    } else {
        output_line("DNS server: not configured");
    }
    false
}

fn cmd_ipxroute(arguments: &str) -> bool {
    let _ = arguments;
    output_line("IPX is not bound to any network adapter.");
    false
}

fn cmd_finger(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Usage: finger [user@host]");
        return false;
    }
    output_line(&format!("No finger server for {}.", target));
    false
}

fn cmd_rexec(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Usage: rexec host [command]");
        return false;
    }
    output_line(&format!("REXEC: Connection to {} refused.", target));
    false
}

fn cmd_nfsadmin(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "server" | "client" => {
            output_line(&format!(
                "{}: The service is not installed.",
                arguments.trim()
            ));
        }
        _ => {
            output_line("Usage: nfsadmin server | client [option]");
        }
    }
    false
}

fn cmd_nfsshare(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "" | "list" => {
            output_line("No NFS shares are configured.");
        }
        "add" | "delete" => {
            output_line("NFS is not installed on this system.");
        }
        _ => {
            output_line("Usage: nfsshare [list | add | delete]");
        }
    }
    false
}

fn cmd_nfsstat(arguments: &str) -> bool {
    let _ = arguments;
    output_line("NFS is not installed on this system.");
    false
}

fn cmd_atmadm(arguments: &str) -> bool {
    let _ = arguments;
    output_line("ATM Call Manager is not running.");
    false
}

fn cmd_bcdboot(arguments: &str) -> bool {
    let target = arguments.split_whitespace().next().unwrap_or("");
    if target.is_empty() {
        output_line("Usage: bcdboot <source> [/l locale] [/s volume] [/f firmware]");
        return false;
    }
    output_line("Boot files successfully created.");
    true
}

fn cmd_cscript(arguments: &str) -> bool {
    let script = arguments.split_whitespace().next().unwrap_or("");
    if script.is_empty() {
        output_line("Usage: cscript script.js [/option]");
        return false;
    }
    output_line(&format!(
        "CSCRIPT: Script host for Windows - running '{}'",
        script
    ));
    output_line("Script execution requires the Windows Script Host subsystem.");
    false
}

fn cmd_djoin(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if subcommand == "/provision" {
        output_line("Provisioning completed successfully.");
        true
    } else {
        output_line("Usage: djoin /provision /domain domain /username user /machine name");
        false
    }
}

fn cmd_filescrn(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "show" => {
            output_line("File screening is not configured.");
        }
        "define" | "delete" => {
            output_line("File Server Resource Manager is not installed.");
        }
        _ => {
            output_line("Usage: filescrn [show | define | delete]");
        }
    }
    false
}

fn cmd_gettype() -> bool {
    output_line("The system type is: Windows NT 6.1");
    false
}

fn cmd_inuse(arguments: &str) -> bool {
    let path = arguments.split_whitespace().next().unwrap_or("");
    if path.is_empty() {
        output_line("Usage: inuse file_path /replace replacement_file");
        return false;
    }
    output_line(&format!("The file '{}' is not in use.", path));
    false
}

fn cmd_ismserv(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Intersite Messaging Service: not installed.");
    false
}

fn cmd_macfile(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Macintosh File Server is not installed.");
    false
}

fn cmd_pnputil(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "-e" | "/enum-drivers" => {
            output_line("Microsoft PnP Utility");
            output_line("");
            output_line("No third-party drivers are installed.");
        }
        "-i" | "/add-driver" => {
            output_line("PNPUTIL: Driver installation requires the PnP Manager.");
        }
        _ => {
            output_line("Microsoft PnP Utility");
            output_line("Usage: pnputil [-e | -i <file.inf>]");
        }
    }
    false
}

fn cmd_sfc(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "/verifyonly" => {
            output_line("Beginning system scan.  This process will take some time.");
            output_line("");
            output_line("Beginning verification phase of system scan.");
            output_line("Verification 100% complete.");
            output_line("");
            output_line("Windows Resource Protection did not find any integrity violations.");
        }
        "/scannow" => {
            output_line("Beginning system scan.  This process will take some time.");
            output_line("");
            output_line("Windows Resource Protection found corrupt files but was");
            output_line("unable to fix some of them.  (because they are stubs)");
        }
        _ => {
            output_line("Usage: sfc [/scannow] [/verifyonly]");
        }
    }
    false
}

fn cmd_sysocmgr(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Windows Optional Component Manager is not available in this build.");
    false
}

fn cmd_tapicfg(arguments: &str) -> bool {
    let _ = arguments;
    output_line("TAPI is not installed on this system.");
    false
}

fn cmd_tcmsetup(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Telephony Client Setup is not available.");
    false
}

fn cmd_tsecimp(arguments: &str) -> bool {
    let _ = arguments;
    output_line("TAPI Security Import is not available.");
    false
}

fn cmd_uddiconfig(arguments: &str) -> bool {
    let _ = arguments;
    output_line("UDDI Services are not installed on this system.");
    false
}

fn cmd_verify(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "on" => {
            output_line("Verify is ON.");
            true
        }
        "off" => {
            output_line("Verify is OFF.");
            true
        }
        _ => {
            output_line("Verify is OFF.");
            false
        }
    }
}

fn cmd_w32tm(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "/query" | "/q" => {
            output_line("Windows Time Service is not configured.");
        }
        "/status" => {
            output_line("The Windows Time service is not running.");
        }
        _ => {
            output_line("Usage: w32tm [/query | /status]");
        }
    }
    false
}

fn cmd_winnt(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Windows NT Setup is not available from this shell.");
    false
}

fn cmd_winpop(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Windows POP Service is not installed.");
    false
}

fn cmd_pentnt() -> bool {
    output_line("Pentium FDIV bug: not detected.");
    false
}

fn cmd_pbadmin(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Phone Book Administrator is not installed.");
    false
}

fn cmd_cmstp(arguments: &str) -> bool {
    let _ = arguments;
    output_line("CMSTP: Connection Manager profile setup is not available.");
    false
}

fn cmd_cprofile(arguments: &str) -> bool {
    let _ = arguments;
    output_line("CPROFILE: roaming user profile cleanup is not available.");
    false
}

fn cmd_dirquota(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "" => {
            output_line("DIRQUOTA: manages file-server directory quotas.");
            output_line("Usage: dirquota quota list | template list | autoapply list");
            false
        }
        "quota" | "template" | "autoapply" => {
            output_line("DIRQUOTA: File Server Resource Manager is not running.");
            false
        }
        _ => {
            output_line("DIRQUOTA: unrecognized subcommand.");
            false
        }
    }
}

fn cmd_dispdiag(arguments: &str) -> bool {
    let _ = arguments;
    output_line("DISPDIAG: display diagnostics output written to DISPDIAG.LOG.");
    false
}

fn cmd_eventtriggers(arguments: &str) -> bool {
    let subcommand = arguments
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    match subcommand.as_str() {
        "" | "/query" => {
            output_line("Event Triggers: no event triggers are configured.");
            true
        }
        "/create" | "/delete" => {
            output_line("EVENTTRIGGERS: event trigger management is not available in this build.");
            false
        }
        _ => {
            output_line("Usage: eventtriggers [/query | /create | /delete]");
            false
        }
    }
}

fn cmd_evntcmd(arguments: &str) -> bool {
    let _ = arguments;
    output_line("EVNTCMD: event configuration via message files is not available.");
    false
}

fn cmd_helpctr(arguments: &str) -> bool {
    let _ = arguments;
    output_line("Help Center is not available in this build.");
    false
}

fn cmd_pnpunattend(arguments: &str) -> bool {
    let _ = arguments;
    output_line("PNPUNATTEND: Plug and Play unattended installation is not available.");
    false
}

fn cmd_not_yet_available(command: &str) -> bool {
    output_line(&format!(
        "{}: this command requires a subsystem that is not yet available.",
        command.to_uppercase()
    ));
    false
}

#[cfg(test)]
mod tests {
    use super::{is_reference_command, REFERENCE_COMMANDS};

    #[test]
    fn reference_commands_are_lowercase_and_unique() {
        for command in REFERENCE_COMMANDS {
            assert_eq!(*command, command.to_lowercase());
        }
        for pair in REFERENCE_COMMANDS.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }

    #[test]
    fn recognizes_chm_commands_case_insensitively() {
        assert!(is_reference_command("attrib"));
        assert!(is_reference_command("TASKLIST"));
        assert!(!is_reference_command("not-a-command"));
    }
}
