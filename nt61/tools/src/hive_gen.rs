//! Hive file generator using the `regf` REGF v1 writer.
//!
//! Generates every hive file the kernel expects to find under
//! `C:\Windows\System32\config\` and the BCD on the ESP.

use std::fs;
use std::path::Path;

use crate::regf::{HiveBuilder, Node, Value};

// =====================================================================
// Top-level generator
// =====================================================================

/// Generate all registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT)
/// and hosts files into `root`.  The BCD is generated separately by
/// `build_bcd()` and written by the ESP step.
pub fn generate_all(root: &Path) -> std::io::Result<()> {
    let config_dir = root.join("Windows").join("System32").join("config");
    let etc_dir = root.join("Windows").join("System32").join("drivers").join("etc");
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&etc_dir)?;

    fs::write(config_dir.join("SYSTEM"),   build_system())?;
    fs::write(config_dir.join("SOFTWARE"), build_software())?;
    fs::write(config_dir.join("SAM"),      build_sam())?;
    fs::write(config_dir.join("SECURITY"), build_security())?;
    fs::write(config_dir.join("DEFAULT"),  build_default())?;

    fs::write(etc_dir.join("hosts"),       HOSTS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("lmhosts.sam"), LMHOSTS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("networks"),   NETWORKS_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("protocol"),   PROTOCOL_CONTENT.as_bytes())?;
    fs::write(etc_dir.join("services"),   SERVICES_CONTENT.as_bytes())?;

    Ok(())
}

// =====================================================================
// Static file contents
// =====================================================================

pub const HOSTS_CONTENT: &str = "\
# Copyright (c) Microsoft Corporation.\n\
127.0.0.1       localhost\n\
::1             localhost\n";

pub const LMHOSTS_CONTENT: &str = "\
# LMHOSTS file for Windows 7\n\
127.0.0.1       localhost\n";

pub const NETWORKS_CONTENT: &str = "\
loopback        127\n\
localnet        127.0.0.0\n";

pub const PROTOCOL_CONTENT: &str = "\
ip              0       IP\n\
icmp            1       ICMP\n\
tcp             6       TCP\n\
udp            17       UDP\n";

pub const SERVICES_CONTENT: &str = "\
http            80/tcp\n\
https          443/tcp\n";

fn node(name: &str) -> Node {
    Node::new(name)
}

/// Recursively ensure all parts of `path` exist as subkeys of `root`.
/// E.g. ensure_path(&mut root, "A\\B\\C") ensures root.subkeys has A,
/// A.subkeys has B, and B.subkeys has C, then returns a mutable ref to C.
fn ensure_path<'a>(root: &'a mut Node, path: &str) -> &'a mut Node {
    let parts: Vec<&str> = path.split('\\').collect();
    let mut cur = root;
    for part in parts {
        let idx = cur.subkeys.iter().position(|s| s.name == part);
        match idx {
            Some(i) => cur = &mut cur.subkeys[i],
            None => {
                cur.subkeys.push(Node::new(part));
                cur = cur.subkeys.last_mut().unwrap();
            }
        }
    }
    cur
}

// =====================================================================
// BCD builder - Standard Windows BCD layout
// =====================================================================

/// Build a BCD element subkey with a single "Element" value.
/// This creates the standard Windows BCD structure:
///   Elements\{TYPE}\Element = <value>
///
/// Windows BCD element types:
///   - 11000001: Device (binary device path)
///   - 12000002: FilePath (string) - Application path
///   - 12000004: Description (string)
///   - 12000005: Locale (string)
///   - 14000006: DisplayOrder (string-list, REG_MULTI_SZ)
///   - 15000011: Timeout (DWORD stored as binary)
///   - 21000001: OsDevice (binary device path)
///   - 22000001: OsLoadOptions (string)
///   - 22000002: SystemRoot (string)
///   - 23000003: AssociatedLocator (string)
fn element_subkey_string(type_id: &str, value: &str) -> Node {
    let mut n = Node::new(type_id);
    n.values.push(Value::sz("Element", value));
    n
}

fn element_subkey_binary(type_id: &str, data: &[u8]) -> Node {
    let mut n = Node::new(type_id);
    n.values.push(Value::binary("Element", data));
    n
}

fn element_subkey_dword(type_id: &str, value: u32) -> Node {
    let mut n = Node::new(type_id);
    n.values.push(Value::dword("Element", value));
    n
}

fn element_subkey_string_list(type_id: &str, values: &[&str]) -> Node {
    let mut n = Node::new(type_id);
    // Build REG_MULTI_SZ: each string + \0\0 at end
    let mut data: Vec<u8> = Vec::new();
    for s in values {
        for c in s.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.push(0);
        data.push(0);
    }
    // Final double-NUL
    data.push(0);
    data.push(0);
    n.values.push(Value {
        name: "Element".into(),
        data_type: crate::regf::REG_MULTI_SZ,
        data,
    });
    n
}

/// Build the Boot Configuration Data (BCD) store as a real Windows
/// `regf` hive parseable by `hivexsh`/`hivexget`/`hivexml`.
///
/// BCD object hierarchy (standard Windows layout):
///
/// ```text
/// NewStoreRoot\
///   Description\            (KeyName=BCD00000000, System=1, TreatAsSystem=1)
///   Objects\
///     {9dea862c-5cdd-4e70-acc1-f32b344d4795}  Boot Manager
///       Description\         (Type=0x10100002)
///       Elements\           (timeout, locale, display order, etc.)
///     {9dea862d-5cdd-4e70-acc1-f32b344d4795}  Windows 7 Normal
///       Description\         (Type=0x10200003)
///       Elements\           (device, path, description, etc.)
///     {b2721d66-7dbf-4e50-ae7c-d27f2d90ce20}  Safe Mode CMD
///       Description\         (Type=0x10200003)
///       Elements\           (device, path, load options, etc.)
///     {5189b25c-5558-4bf2-bb0f-cd5a4f8c7e20}  Safe Mode Debug
///       Description\         (Type=0x10200003)
///       Elements\           (device, path, debug options, etc.)
///     {aabbccdd-eeff-0011-2233-445566778899}  Resume
///       Description\         (Type=0x10200004)
///       Elements\           (resume path, description)
/// ```
///
/// Object types:
///   - 0x10100002: Boot Manager
///   - 0x10200003: Windows Boot Loader
///   - 0x10200004: Resume from Hibernate
///   - 0x10100010: Firmware Boot Manager
///   - 0x1030000A: BootApp (EFI application)
pub fn build_bcd() -> Vec<u8> {
    let mut root = node("NewStoreRoot").root();

    // --- NewStoreRoot\Description ----------------------------------------
    {
        let mut d = node("Description");
        d.values.push(Value::sz("KeyName", "BCD00000000"));
        d.values.push(Value::dword("System", 1));
        d.values.push(Value::dword("TreatAsSystem", 1));
        root.subkeys.push(d);
    }

    // --- NewStoreRoot\Objects -------------------------------------------
    {
        let mut objs = node("Objects");

        // Boot Manager {9dea862c-5cdd-4e70-acc1-f32b344d4795}
        {
            let mut bm = node("{9dea862c-5cdd-4e70-acc1-f32b344d4795}");
            {
                let mut bd = node("Description");
                bd.values.push(Value::dword("Type", 0x1010_0002));
                bm.subkeys.push(bd);
            }
            {
                let mut ee = node("Elements");
                // Timeout = 5 seconds (stored as DWORD, but in Elements as binary with Element value)
                ee.subkeys.push(element_subkey_dword("15000011", 5));
                ee.subkeys.push(element_subkey_string("12000004", "Windows Boot Manager"));
                ee.subkeys.push(element_subkey_string("12000005", "en-US"));
                // DisplayOrder: list of boot loader GUIDs
                ee.subkeys.push(element_subkey_string_list("14000006", &[
                    "{9dea862d-5cdd-4e70-acc1-f32b344d4795}",
                    "{b2721d66-7dbf-4e50-ae7c-d27f2d90ce20}",
                    "{5189b25c-5558-4bf2-bb0f-cd5a4f8c7e20}",
                    "{aabbccdd-eeff-0011-2233-445566778899}",
                ]));
                bm.subkeys.push(ee);
            }
            objs.subkeys.push(bm);
        }

        // Windows 7 Normal {9dea862d-5cdd-4e70-acc1-f32b344d4795}
        {
            let mut e = node("{9dea862d-5cdd-4e70-acc1-f32b344d4795}");
            {
                let mut ed = node("Description");
                ed.values.push(Value::dword("Type", 0x1020_0003));
                e.subkeys.push(ed);
            }
            {
                let mut ee = node("Elements");
                // Device = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("11000001", &create_device_path()));
                // ApplicationPath points to winload.efi on the System partition
                // Windows 7 correct layout: winload.efi is at C:\Windows\System32\winload.efi
                ee.subkeys.push(element_subkey_string("12000002", r"\Windows\System32\winload.efi"));
                ee.subkeys.push(element_subkey_string("12000004", "Windows 7"));
                ee.subkeys.push(element_subkey_string("12000005", "en-US"));
                // OsDevice = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("21000001", &create_device_path()));
                ee.subkeys.push(element_subkey_string("22000002", r"\Windows"));
                e.subkeys.push(ee);
            }
            objs.subkeys.push(e);
        }

        // Windows 7 Safe Mode CMD {b2721d66-7dbf-4e50-ae7c-d27f2d90ce20}
        {
            let mut e = node("{b2721d66-7dbf-4e50-ae7c-d27f2d90ce20}");
            {
                let mut ed = node("Description");
                ed.values.push(Value::dword("Type", 0x1020_0003));
                e.subkeys.push(ed);
            }
            {
                let mut ee = node("Elements");
                // Device = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("11000001", &create_device_path()));
                // ApplicationPath points to winload.efi on the System partition
                ee.subkeys.push(element_subkey_string("12000002", r"\Windows\System32\winload.efi"));
                ee.subkeys.push(element_subkey_string("12000004", "Windows 7 (Safe Mode - CMD)"));
                ee.subkeys.push(element_subkey_string("12000005", "en-US"));
                // OsDevice = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("21000001", &create_device_path()));
                ee.subkeys.push(element_subkey_string("22000002", r"\Windows"));
                ee.subkeys.push(element_subkey_string("22000001", "/safeboot:minimal /safeboot:shell"));
                e.subkeys.push(ee);
            }
            objs.subkeys.push(e);
        }

        // Windows 7 Safe Mode Debug {5189b25c-5558-4bf2-bb0f-cd5a4f8c7e20}
        {
            let mut e = node("{5189b25c-5558-4bf2-bb0f-cd5a4f8c7e20}");
            {
                let mut ed = node("Description");
                ed.values.push(Value::dword("Type", 0x1020_0003));
                e.subkeys.push(ed);
            }
            {
                let mut ee = node("Elements");
                // Device = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("11000001", &create_device_path()));
                // ApplicationPath points to winload.efi on the System partition
                ee.subkeys.push(element_subkey_string("12000002", r"\Windows\System32\winload.efi"));
                ee.subkeys.push(element_subkey_string("12000004", "Windows 7 (Safe Mode - Debug)"));
                ee.subkeys.push(element_subkey_string("12000005", "en-US"));
                // OsDevice = System partition (partition 2)
                ee.subkeys.push(element_subkey_binary("21000001", &create_device_path()));
                ee.subkeys.push(element_subkey_string("22000002", r"\Windows"));
                ee.subkeys.push(element_subkey_string("22000001", "/debug /debugport=COM1 /baudrate=115200"));
                e.subkeys.push(ee);
            }
            objs.subkeys.push(e);
        }

        // Resume from Hibernate {aabbccdd-eeff-0011-2233-445566778899}
        {
            let mut e = node("{aabbccdd-eeff-0011-2233-445566778899}");
            {
                let mut ed = node("Description");
                ed.values.push(Value::dword("Type", 0x1020_0004));
                e.subkeys.push(ed);
            }
            {
                let mut ee = node("Elements");
                ee.subkeys.push(element_subkey_string("12000002", r"\Windows\system32\winresume.efi"));
                ee.subkeys.push(element_subkey_string("12000004", "Windows 7 Resume"));
                ee.subkeys.push(element_subkey_string("12000005", "en-US"));
                e.subkeys.push(ee);
            }
            objs.subkeys.push(e);
        }

        root.subkeys.push(objs);
    }

    HiveBuilder::new(root).with_name("BCD").finish()
}

// GPT partition device path (MEDIA_DEVICE_PATH, subtype Hard Drive).
// For dual-partition setup:
//   Partition 1: ESP (FAT32) - boot files
//   Partition 2: System (NTFS) - Windows files (winload.efi lives here!)
// 
// Windows 7 correct layout:
//   - Boot manager (bootmgfw.efi) on ESP reads BCD
//   - BCD's OsDevice points to the System partition
//   - BCD's ApplicationPath is \Windows\System32\winload.efi (on System partition)
fn create_device_path() -> Vec<u8> {
    let mut p = Vec::with_capacity(40);
    // Type=4 (Media), SubType=1 (Hard Drive), Length=0x28 (40 bytes)
    p.push(4);
    p.push(1);
    p.extend_from_slice(&0x28u16.to_le_bytes());
    // Partition signature GUID (fixed for reproducibility)
    p.extend_from_slice(&[
        0x8Bu8, 0x1Cu8, 0x6Au8, 0x9Eu8,
        0x4Fu8, 0x2Du8, 0x11u8, 0xEFu8,
        0xBEu8, 0x7Cu8, 0x80u8, 0x6Eu8,
        0x6Fu8, 0x6Eu8, 0x69u8, 0x63u8,
    ]);
    // Partition number = 2 (System partition, where winload.efi lives)
    p.extend_from_slice(&2u32.to_le_bytes());
    // Start LBA (System partition starts after ESP)
    p.extend_from_slice(&0x800000u64.to_le_bytes());
    // Size in sectors
    p.extend_from_slice(&0x40000000u64.to_le_bytes());
    p
}

// =====================================================================
// REG_MULTI_SZ type constant
// =====================================================================

/// Registry value types (Windows constants).
pub const REG_MULTI_SZ: u32 = 7;

// =====================================================================
// SYSTEM hive
// =====================================================================

pub fn build_system() -> Vec<u8> {
    let mut root = node("$$$PROTO.Hiv").root();

    // Select
    {
        let mut sel = node("Select");
        sel.values.push(Value::dword("Current", 1));
        sel.values.push(Value::dword("Default", 1));
        sel.values.push(Value::dword("Failed", 0));
        sel.values.push(Value::dword("LastKnownGood", 1));
        root.subkeys.push(sel);
    }

    root.values.push(Value::sz("CurrentControlSet", "ControlSet001"));

    // ControlSet001\Control
    {
        let ctl = ensure_path(&mut root, "ControlSet001\\Control");
        ctl.values.push(Value::dword("BootDriverFlags", 0x10));
        ctl.values.push(Value::dword("SystemStartOptions", 0));
        ctl.values.push(Value::dword("WaitToKillServiceTimeout", 5000));
    }
    // ControlSet001\Control\Session Manager
    {
        let sm = ensure_path(&mut root, "ControlSet001\\Control\\Session Manager");
        sm.values.push(Value::dword("ProtectionMode", 0));
        sm.values.push(Value::dword("ObCaseInsensitive", 1));
        sm.values.push(Value::sz("BootExecute", "autocheck autochk *"));
    }
    // ControlSet001\Control\Session Manager\Memory Management
    {
        let mm = ensure_path(&mut root, "ControlSet001\\Control\\Session Manager\\Memory Management");
        mm.values.push(Value::dword("ClearPageFileAtShutdown", 0));
    }

    // Boot-start drivers
    let drivers = [
        ("disk", 0u32), ("partmgr", 0), ("classpnp", 0),
        ("storahci", 0), ("ntfs", 0), ("fastfat", 0),
        ("acpi", 0), ("pci", 0), ("volmgr", 0), ("mountmgr", 0),
    ];
    for (name, start) in drivers {
        let svc = ensure_path(&mut root, &format!("ControlSet001\\Services\\{}", name));
        svc.values.push(Value::dword("Start", start));
        svc.values.push(Value::dword("Type", 1));
        svc.values.push(Value::dword("ErrorControl", 1));
        svc.values.push(Value::sz("Group", "Boot"));
        svc.values.push(Value::sz("ImagePath",
            &format!(r"\SystemRoot\System32\drivers\{}.sys", name)));
        svc.values.push(Value::sz("DisplayName", name));
    }

    HiveBuilder::new(root).with_name("system").finish()
}

// =====================================================================
// SOFTWARE hive
// =====================================================================

pub fn build_software() -> Vec<u8> {
    let mut root = node("$$$PROTO.Hiv").root();

    let cv = ensure_path(&mut root, "Microsoft\\Windows NT\\CurrentVersion");
    cv.values.push(Value::sz("SystemRoot", r"\Windows"));
    cv.values.push(Value::sz("ProductName", "Windows 7 Ultimate"));
    cv.values.push(Value::sz("CurrentBuildNumber", "7601"));
    cv.values.push(Value::sz("EditionID", "Ultimate"));
    cv.values.push(Value::dword("InstallationType", 1));

    HiveBuilder::new(root).with_name("software").finish()
}

// =====================================================================
// SAM hive
// =====================================================================

pub fn build_sam() -> Vec<u8> {
    let mut root = node("$$$PROTO.Hiv").root();

    let users = ensure_path(&mut root, "Domains\\Account\\Users");
    for rid in [0x1F4u32, 0x1F5u32] {
        let u = ensure_path(users, &format!("{:08X}", rid));
        u.values.push(Value::dword("F", 0));
        u.values.push(Value::dword("V", 0));
    }

    HiveBuilder::new(root).with_name("sam").finish()
}

// =====================================================================
// SECURITY hive
// =====================================================================

pub fn build_security() -> Vec<u8> {
    let mut root = node("$$$PROTO.Hiv").root();
    let p = ensure_path(&mut root, "Policy");
    p.values.push(Value::dword("PolAdtEv", 0));
    HiveBuilder::new(root).with_name("security").finish()
}

// =====================================================================
// DEFAULT hive
// =====================================================================

pub fn build_default() -> Vec<u8> {
    let mut root = node("$$$PROTO.Hiv").root();

    let d = ensure_path(&mut root, "Control Panel\\Desktop");
    d.values.push(Value::sz("Wallpaper", ""));

    let s = ensure_path(&mut root, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
    s.values.push(Value::sz("Desktop", "%USERPROFILE%\\Desktop"));

    HiveBuilder::new(root).with_name("default").finish()
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcd_structure() {
        let bytes = build_bcd();
        
        // Verify magic
        assert_eq!(&bytes[0..4], b"regf", "should have regf magic");
        assert!(bytes.len() >= 8192, "BCD should be at least 2 HBIN pages");
        
        // Verify the hive can be read back
        // (Full roundtrip test in integration tests)
    }

    #[test]
    fn test_device_path() {
        let path = create_device_path();
        assert_eq!(path.len(), 40, "device path should be 40 bytes");
        assert_eq!(path[0], 4, "type should be Media (4)");
        assert_eq!(path[1], 1, "subtype should be Hard Drive (1)");
    }

    #[test]
    fn test_element_subkeys() {
        // Test string element
        let es = element_subkey_string("12000004", "Test Description");
        assert_eq!(es.name, "12000004");
        assert_eq!(es.values.len(), 1);
        assert_eq!(es.values[0].name, "Element");
        
        // Test binary element
        let eb = element_subkey_binary("11000001", &[0x01, 0x02, 0x03]);
        assert_eq!(eb.name, "11000001");
        assert_eq!(eb.values.len(), 1);
        assert_eq!(eb.values[0].name, "Element");
        
        // Test DWORD element
        let ed = element_subkey_dword("15000011", 30);
        assert_eq!(ed.name, "15000011");
        assert_eq!(ed.values.len(), 1);
        assert_eq!(ed.values[0].name, "Element");
        
        // Test string list element
        let el = element_subkey_string_list("14000006", &["guid1", "guid2"]);
        assert_eq!(el.name, "14000006");
        assert_eq!(el.values.len(), 1);
        assert_eq!(el.values[0].name, "Element");
    }
}
