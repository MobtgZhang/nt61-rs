//! ACPI discovery and table validation for the boot manager.
//!
//! The kernel owns full ACPI interpretation after handoff, but bootmgr
//! still needs a trusted summary of the fixed tables before selecting a
//! boot entry. This parser follows the ACPI layout and validates every
//! checksum before dereferencing a table body.

use alloc::format;
use alloc::string::String;

use uefi::table::cfg::ConfigTableEntry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    signature: [u8; 4],
    length: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcpiSummary {
    pub revision: u8,
    pub facp_present: bool,
    pub facp_pm_profile: u8,
    pub srat_entries: usize,
    pub slit_entries: usize,
    pub mcfg_entries: usize,
}

#[derive(Debug)]
pub struct AcpiError(&'static str);

impl core::fmt::Display for AcpiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn checksum(data: &[u8], checksum: u8) -> bool {
    data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == checksum.wrapping_neg()
}

unsafe fn table_header(address: u64) -> Option<Header> {
    if address == 0 || address & 3 != 0 {
        return None;
    }
    let base = address as *const u8;
    let length = u32::from_le_bytes(core::ptr::read_unaligned(base.add(4) as *const [u8; 4]));
    if !(36..=128 * 1024).contains(&length) {
        return None;
    }
    let mut signature = [0u8; 4];
    core::ptr::copy_nonoverlapping(base, signature.as_mut_ptr(), 4);
    let bytes = core::slice::from_raw_parts(base, length as usize);
    if !checksum(bytes, *base.add(9)) {
        return None;
    }
    Some(Header { signature, length })
}

unsafe fn root_table_addresses(rsdp_address: u64) -> Option<alloc::vec::Vec<u64>> {
    let base = rsdp_address as *const u8;
    if rsdp_address == 0 || rsdp_address & 7 != 0 {
        return None;
    }
    let signature = *base.cast::<[u8; 8]>();
    if &signature != b"RSD PTR " {
        return None;
    }
    let revision = *base.add(15);
    let length = u32::from_le_bytes(core::ptr::read_unaligned(base.add(28) as *const [u8; 4]));
    let v1_bytes = core::slice::from_raw_parts(base, 20);
    if !checksum(v1_bytes, *base.add(9)) {
        return None;
    }

    if revision < 2 {
        let rsdt = u64::from(u32::from_le_bytes(core::ptr::read_unaligned(
            base.add(16) as *const [u8; 4]
        )));
        return unsafe { child_table_addresses32(rsdt) };
    }

    if !(36..=44).contains(&length) {
        return None;
    }
    let v2_bytes = core::slice::from_raw_parts(base, length as usize);
    if !checksum(v2_bytes, *base.add(32)) {
        return None;
    }
    let xsdt = core::ptr::read_unaligned(base.add(24) as *const u64);
    unsafe { child_table_addresses64(xsdt) }
}

unsafe fn child_table_addresses32(root_address: u64) -> Option<alloc::vec::Vec<u64>> {
    unsafe { child_table_addresses(root_address, 4) }
}

unsafe fn child_table_addresses64(root_address: u64) -> Option<alloc::vec::Vec<u64>> {
    unsafe { child_table_addresses(root_address, 8) }
}

unsafe fn child_table_addresses(
    root_address: u64,
    pointer_size: usize,
) -> Option<alloc::vec::Vec<u64>> {
    let header = unsafe { table_header(root_address)? };
    let body_start = 36usize;
    let body_len = header.length as usize - body_start;
    if body_len == 0 || body_len % pointer_size != 0 {
        return None;
    }
    let mut addresses = alloc::vec::Vec::new();
    for offset in (0..body_len).step_by(pointer_size) {
        let pointer_address = root_address + body_start as u64 + offset as u64;
        let address = if pointer_size == 8 {
            unsafe { core::ptr::read_unaligned(pointer_address as *const u64) }
        } else {
            u64::from(unsafe { core::ptr::read_unaligned(pointer_address as *const u32) })
        };
        if address != 0 {
            addresses.push(address);
        }
    }
    Some(addresses)
}

unsafe fn summary_from_tables(
    rsdp_address: u64,
    children: &[u64],
) -> Result<AcpiSummary, AcpiError> {
    let mut summary = AcpiSummary::default();
    let base = rsdp_address as *const u8;
    summary.revision = *base.add(15);

    for &address in children {
        let header = unsafe { table_header(address).ok_or(AcpiError("invalid child ACPI table"))? };
        match &header.signature {
            b"FACP" => {
                summary.facp_present = true;
                summary.facp_pm_profile = *(address as *const u8).add(45);
            }
            b"SRAT" => {
                let body_len = header.length as usize - 48;
                summary.srat_entries += body_len / 16;
            }
            b"SLIT" => {
                let count =
                    u32::from_le_bytes(core::ptr::read_unaligned((address + 40) as *const [u8; 4]))
                        as usize;
                summary.slit_entries = count;
            }
            b"MCFG" => {
                let body_len = header.length as usize - 44;
                summary.mcfg_entries += body_len / 16;
            }
            _ => {}
        }
    }
    Ok(summary)
}

pub fn find_rsdp_address() -> Option<u64> {
    uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|entry| {
                entry.guid == ConfigTableEntry::ACPI2_GUID
                    || entry.guid == ConfigTableEntry::ACPI_GUID
            })
            .map(|entry| entry.address as u64)
    })
}

pub unsafe fn parse_rsdp(rsdp_address: u64) -> Result<AcpiSummary, AcpiError> {
    let children =
        unsafe { root_table_addresses(rsdp_address).ok_or(AcpiError("invalid ACPI root table"))? };
    unsafe { summary_from_tables(rsdp_address, &children) }
}

pub fn parse_firmware_tables() -> Option<AcpiSummary> {
    let address = find_rsdp_address()?;
    match unsafe { parse_rsdp(address) } {
        Ok(summary) => Some(summary),
        Err(_) => None,
    }
}

impl AcpiSummary {
    pub fn describe(&self) -> String {
        format!(
            "rev={} FACP={} SRAT={} SLIT={} MCFG={}",
            self.revision,
            self.facp_present,
            self.srat_entries,
            self.slit_entries,
            self.mcfg_entries,
        )
    }
}
