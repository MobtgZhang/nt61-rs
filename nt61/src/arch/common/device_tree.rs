//! Minimal flattened device-tree reader for generic UEFI platforms.
//!
//! A generic AArch64 boot has no fixed UART/GIC/PCI addresses. Firmware
//! supplies them in a Flattened Device Tree (DTB). This module parses the
//! standard structure block without allocating and exposes only the small
//! set of resources required for kernel bring-up.

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const FDT_MAGIC: u32 = 0xd00d_feed;
const MAX_DEPTH: usize = 32;
const MAX_REG_RANGES: usize = 4;

pub use crate::boot_types::{DeviceRange, DeviceTreeHardware};

#[derive(Clone, Copy)]
pub struct DeviceTree {
    bytes: &'static [u8],
}

#[derive(Clone, Copy)]
struct FdtHeader {
    total_size: u32,
    structure_offset: u32,
    strings_offset: u32,
}

#[derive(Clone, Copy)]
struct Cells {
    address: u32,
    size: u32,
}

impl DeviceTree {
    /// # Safety
    /// `base` must point to a complete runtime-surviving DTB of `size`
    /// bytes that remains readable for the kernel's lifetime.
    pub unsafe fn new(base: *const u8, size: u32) -> Option<Self> {
        if base.is_null() || size < 40 {
            return None;
        }
        let bytes = core::slice::from_raw_parts(base, size as usize);
        let tree = Self { bytes };
        let header = tree.header()?;
        if header.total_size != size {
            return None;
        }
        Some(tree)
    }

    fn header(&self) -> Option<FdtHeader> {
        if self.be_u32(0)? != FDT_MAGIC {
            return None;
        }
        Some(FdtHeader {
            total_size: self.be_u32(4)?,
            structure_offset: self.be_u32(8)?,
            strings_offset: self.be_u32(12)?,
        })
    }

    fn be_u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.bytes_at(offset, 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn bytes_at(&self, offset: usize, length: usize) -> Option<&'static [u8]> {
        let end = offset.checked_add(length)?;
        self.bytes.get(offset..end)
    }

    /// Calls `visit` for every node property. Returning `true` stops the walk.
    ///
    /// The callback receives node name, property name, property value, and
    /// the `#address-cells`/`#size-cells` values in effect for the node.
    pub fn for_each_property(
        &self,
        mut visit: impl FnMut(&[u8], &[u8], &[u8], u32, u32) -> bool,
    ) -> Option<()> {
        let header = self.header()?;
        let mut offset = header.structure_offset as usize;
        let end = self.bytes.len();
        let mut cells = [Cells {
            address: 2,
            size: 2,
        }; MAX_DEPTH];
        let mut depth = 0usize;
        let mut current_node_name: &[u8] = b"";

        while offset < end {
            let token = self.be_u32(offset)?;
            offset += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name_start = offset;
                    let mut name_end = name_start;
                    while name_end < end && self.bytes[name_end] != 0 {
                        name_end = name_end.checked_add(1)?;
                    }
                    let node_name = self.bytes_at(name_start, name_end - name_start)?;
                    offset = align4(name_end.checked_add(1)?);
                    depth = depth.checked_add(1)?;
                    if depth >= MAX_DEPTH {
                        return None;
                    }
                    if depth == 1 {
                        cells[depth] = Cells {
                            address: 2,
                            size: 2,
                        };
                    } else {
                        cells[depth] = cells[depth - 1];
                    }
                    current_node_name = node_name;
                }
                FDT_END_NODE => {
                    depth = depth.checked_sub(1)?;
                }
                FDT_PROP => {
                    let length = self.be_u32(offset)? as usize;
                    let name_offset = self.be_u32(offset.checked_add(4)?)? as usize;
                    let value_offset = offset.checked_add(8)?;
                    let value = self.bytes_at(value_offset, length)?;
                    let strings_offset = header.strings_offset as usize;
                    let property_name_offset = strings_offset.checked_add(name_offset)?;
                    let mut property_end = property_name_offset;
                    while property_end < end && self.bytes[property_end] != 0 {
                        property_end = property_end.checked_add(1)?;
                    }
                    let property_name =
                        self.bytes_at(property_name_offset, property_end - property_name_offset)?;
                    let current = cells[depth];
                    if property_name == b"#address-cells" && value.len() == 4 {
                        cells[depth].address =
                            u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    } else if property_name == b"#size-cells" && value.len() == 4 {
                        cells[depth].size =
                            u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    } else if visit(
                        current_node_name,
                        property_name,
                        value,
                        current.address,
                        current.size,
                    ) {
                        return Some(());
                    }
                    offset = align4(value_offset.checked_add(length)?);
                }
                FDT_NOP => {}
                FDT_END => return Some(()),
                _ => return None,
            }
        }
        Some(())
    }

    pub fn hardware(&self) -> DeviceTreeHardware {
        let mut hardware = DeviceTreeHardware::default();
        self.for_each_property(
            |node_name, property_name, value, address_cells, size_cells| {
                if property_name != b"reg" {
                    return false;
                }
                let ranges = parse_reg_ranges(value, address_cells, size_cells);
                let Some((first, rest)) = ranges.split_first() else {
                    return false;
                };
                if node_name.starts_with(b"serial") {
                    hardware.uart = Some(*first);
                } else if node_name.starts_with(b"interrupt-controller") {
                    hardware.gicd = Some(*first);
                    hardware.gicc = rest.first().copied();
                } else if node_name.starts_with(b"pcie") || node_name.starts_with(b"pci") {
                    hardware.pci_ecam = Some(*first);
                }
                false
            },
        );
        hardware
    }
}

fn align4(value: usize) -> usize {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .unwrap_or(usize::MAX)
}

fn parse_reg_ranges(
    value: &[u8],
    address_cells: u32,
    size_cells: u32,
) -> [DeviceRange; MAX_REG_RANGES] {
    let mut ranges = [DeviceRange { base: 0, size: 0 }; MAX_REG_RANGES];
    let address_stride = address_cells.saturating_mul(4) as usize;
    let size_stride = size_cells.saturating_mul(4) as usize;
    let range_stride = address_stride
        .checked_add(size_stride)
        .unwrap_or(usize::MAX);
    let count = if range_stride == 0 {
        0
    } else {
        value.len() / range_stride
    };
    for (index, range) in ranges.iter_mut().take(count).enumerate() {
        let start = index * range_stride;
        range.base =
            read_big_endian(value.get(start..start.checked_add(address_stride).unwrap_or(0)));
        range.size = read_big_endian(value.get(
            start.checked_add(address_stride).unwrap_or(0)
                ..start.checked_add(range_stride).unwrap_or(0),
        ));
    }
    ranges
}

fn read_big_endian(bytes: Option<&[u8]>) -> u64 {
    let Some(bytes) = bytes else { return 0 };
    let mut value = 0u64;
    for byte in bytes.iter().take(8) {
        value = value.wrapping_shl(8) | u64::from(*byte);
    }
    value
}

static mut DEVICE_TREE: Option<DeviceTree> = None;
static mut HARDWARE: Option<DeviceTreeHardware> = None;

/// # Safety
/// Call once after the loader-provided runtime FDT copy is readable.
pub unsafe fn init(base: u64, size: u32) {
    if base != 0 && size != 0 {
        DEVICE_TREE = DeviceTree::new(base as *const u8, size);
    }
}

pub fn hardware() -> DeviceTreeHardware {
    let installed = unsafe {
        let pointer = core::ptr::addr_of!(HARDWARE);
        *pointer
    };
    if let Some(hardware) = installed {
        return hardware;
    }
    let tree = unsafe {
        let pointer = core::ptr::addr_of!(DEVICE_TREE);
        (*pointer).as_ref().copied()
    };
    tree.map_or(DeviceTreeHardware::default(), |tree| tree.hardware())
}

pub fn set_hardware(hardware: DeviceTreeHardware) {
    unsafe {
        let pointer = core::ptr::addr_of_mut!(HARDWARE);
        *pointer = Some(hardware);
    }
}
