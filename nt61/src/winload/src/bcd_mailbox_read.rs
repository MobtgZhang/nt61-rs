//! BCD Mailbox Reader for Winload
//!
//! Reads the BCD mailbox written by the boot manager. On x86_64
//! the mailbox lives at a fixed physical address (`0x10_100`),
//! but on architectures with stricter UEFI memory protections
//! (aarch64, riscv64) the boot manager allocates a page from
//! firmware memory and installs its physical address as a UEFI
//! Configuration Table. We try the Configuration Table first
//! and fall back to the fixed address when the table is absent.
//!
//! The mailbox contains the selected boot entry GUID, which is
//! used to determine the boot mode (Normal, SafeModeCmd, SafeModeDebug).
//!
//! Mailbox format:
//!   Offset 0x00: Signature "BCDE" (4 bytes)
//!   Offset 0x04: Version 0x00000003 (4 bytes)
//!   Offset 0x08: Length (4 bytes)
//!   Offset 0x0C: Entry GUID (16 bytes)
//!   Offset 0x1C: Boot options (variable, up to 224 bytes)

#![allow(dead_code)]

/// BCD Mailbox fallback physical address (x86_64 only).
/// Matches `BCD_MAILBOX_PHYS` in `boot/main.rs`.
const BCD_MAILBOX_PHYS: u64 = 0x10_100;

/// Configuration Table GUID installed by the boot manager when the
/// mailbox is allocated. The table's data pointer holds an 8-byte
/// little-endian physical address of the mailbox page.
const BCD_MAILBOX_TABLE_GUID: uefi::Guid =
    uefi::Guid::from_bytes([0x8B, 0xC9, 0xC6, 0xA0, 0x5B, 0x47, 0x4D, 0xCA,
                            0x8E, 0x40, 0xDB, 0x22, 0xCA, 0x1D, 0x5A, 0x6B]);

/// BCD Mailbox 签名验证
const BCD_MAILBOX_SIGNATURE: [u8; 4] = [b'B', b'C', b'D', b'E'];

/// BCD Mailbox 版本 (Windows 7)
const BCD_MAILBOX_VERSION: u32 = 0x00000003;

/// BCD Entry GUID 常量 - 对应 bcd.rs 中的 wellknown::ENTRY_WINDOWS_7
const GUID_WINDOWS_7: [u8; 16] = [
    0x9D, 0xEA, 0x86, 0x2C, 0x5C, 0xDD, 0x4E, 0x70,
    0xAC, 0xC1, 0xF3, 0x2B, 0x34, 0x4D, 0x47, 0x95,
];

/// BCD Entry GUID 常量 - 对应 bcd.rs 中的 wellknown::ENTRY_SAFE_MODE_CMD
const GUID_SAFE_MODE_CMD: [u8; 16] = [
    0xB2, 0x72, 0x1D, 0x66, 0x7D, 0xBF, 0x4E, 0x50,
    0xAE, 0x7C, 0xD2, 0x7F, 0x2D, 0x90, 0xCE, 0x20,
];

/// BCD Entry GUID 常量 - 对应 bcd.rs 中的 wellknown::ENTRY_SAFE_MODE_DEBUG
const GUID_SAFE_MODE_DEBUG: [u8; 16] = [
    0x51, 0x89, 0xB2, 0x5C, 0x55, 0x58, 0x4B, 0xF2,
    0xBB, 0x0F, 0xCD, 0x5A, 0x4F, 0x8C, 0x7E, 0x20,
];

/// Boot mode enumeration (matches `nt61::boot_types::BootMode`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BootMode {
    /// Normal boot - Windows 7
    Normal = 0,
    /// Safe Mode with Command Prompt
    SafeModeCmd = 1,
    /// Safe Mode with Debug logging
    SafeModeDebug = 2,
}

impl BootMode {
    /// Convert BootMode to kernel BootMode enum value
    /// (the `nt61::boot_types::BootMode` discriminant).
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// BCD Mailbox header structure
#[repr(C)]
struct BcdMailboxHeader {
    signature: [u8; 4],
    version: u32,
    length: u32,
}

/// Locate the physical address of the BCD mailbox.
///
/// Try the UEFI Configuration Table first (used by the boot
/// manager on aarch64/riscv64 where it cannot write to a
/// hard-coded low address). Fall back to the fixed low address
/// on architectures that permit such access.
fn locate_bcd_mailbox_phys() -> u64 {
    // The `uefi` crate exposes the configuration tables through
    // `with_config_table`, which iterates over the standard system
    // table's vendor-specific entries. We scan them for our GUID
    // and return the 8-byte little-endian physical address stored
    // at the entry's pointer.
    let mut found: Option<u64> = None;
    uefi::system::with_config_table(|slice| {
        for entry in slice {
            if entry.guid == BCD_MAILBOX_TABLE_GUID {
                let ptr = entry.address as *const u8;
                let bytes: [u8; 8] = unsafe {
                    core::ptr::read_volatile(ptr as *const [u8; 8])
                };
                found = Some(u64::from_le_bytes(bytes));
            }
        }
    });

    if let Some(addr) = found {
        uefi::println!(
            "[BCD-MBOX] Found ConfigTable entry, mailbox @ 0x{:x}",
            addr
        );
        return addr;
    }
    uefi::println!(
        "[BCD-MBOX] ConfigTable entry not found, using fixed 0x{:x}",
        BCD_MAILBOX_PHYS
    );
    BCD_MAILBOX_PHYS
}

/// Read the BCD mailbox from physical memory and return the entry GUID if valid.
pub fn read_bcd_mailbox() -> Option<[u8; 16]> {
    let mailbox_phys = locate_bcd_mailbox_phys();
    let mailbox_ptr = mailbox_phys as *const u8;

    unsafe {
        // 1. 验证签名 "BCDE"
        let sig_ptr = mailbox_ptr as *const [u8; 4];
        let sig = core::ptr::read_volatile(sig_ptr);
        if sig != BCD_MAILBOX_SIGNATURE {
            return None;
        }

        // 2. 验证版本
        let version_ptr = mailbox_ptr.add(4) as *const u32;
        let version = core::ptr::read_volatile(version_ptr);
        if version != BCD_MAILBOX_VERSION {
            return None;
        }

        // 3. 读取 Entry GUID (从偏移 0x0C 开始，共 16 字节)
        let guid_ptr = mailbox_ptr.add(0x0C) as *const [u8; 16];
        let guid = core::ptr::read_volatile(guid_ptr);

        Some(guid)
    }
}

/// 比较两个 GUID 是否相等 (完整 16 字节比较)
#[inline]
fn guid_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    // 完整比较所有 16 字节
    a[0] == b[0]
        && a[1] == b[1]
        && a[2] == b[2]
        && a[3] == b[3]
        && a[4] == b[4]
        && a[5] == b[5]
        && a[6] == b[6]
        && a[7] == b[7]
        && a[8] == b[8]
        && a[9] == b[9]
        && a[10] == b[10]
        && a[11] == b[11]
        && a[12] == b[12]
        && a[13] == b[13]
        && a[14] == b[14]
        && a[15] == b[15]
}

/// 根据 GUID 确定 BootMode
pub fn guid_to_boot_mode(guid: &[u8; 16]) -> u32 {
    if guid_eq(guid, &GUID_WINDOWS_7) {
        BootMode::Normal.as_u32()
    } else if guid_eq(guid, &GUID_SAFE_MODE_CMD) {
        BootMode::SafeModeCmd.as_u32()
    } else if guid_eq(guid, &GUID_SAFE_MODE_DEBUG) {
        BootMode::SafeModeDebug.as_u32()
    } else {
        // 未知的 GUID，默认返回 Normal
        BootMode::Normal.as_u32()
    }
}

/// 读取并解析 BCD mailbox，返回 (guid, boot_mode)
pub fn read_boot_mode() -> ([u8; 16], u32) {
    match read_bcd_mailbox() {
        Some(guid) => {
            let mode = guid_to_boot_mode(&guid);
            (guid, mode)
        }
        None => {
            // Mailbox 读取失败或无效，返回全零 GUID 和默认模式
            ([0u8; 16], BootMode::Normal.as_u32())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_eq() {
        let guid1: [u8; 16] = [0x9D, 0xEA, 0x86, 0x2C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let guid2: [u8; 16] = [0x9D, 0xEA, 0x86, 0x2C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let guid3: [u8; 16] = [0xB2, 0x72, 0x1D, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert!(guid_eq(&guid1, &guid2));
        assert!(!guid_eq(&guid1, &guid3));
    }

    #[test]
    fn test_guid_to_boot_mode() {
        assert_eq!(guid_to_boot_mode(&GUID_WINDOWS_7), BootMode::Normal.as_u32());
        assert_eq!(guid_to_boot_mode(&GUID_SAFE_MODE_CMD), BootMode::SafeModeCmd.as_u32());
        assert_eq!(guid_to_boot_mode(&GUID_SAFE_MODE_DEBUG), BootMode::SafeModeDebug.as_u32());

        // 未知 GUID 应返回 Normal
        let unknown: [u8; 16] = [0xFF; 16];
        assert_eq!(guid_to_boot_mode(&unknown), BootMode::Normal.as_u32());
    }
}
