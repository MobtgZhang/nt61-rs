//! Architecture-specific driver support for riscv64.
//!
//! QEMU riscv64 virt machine exposes virtio devices on two
//! transports (hw/riscv/virt.c): the 8 virtio-mmio slots at
//! 0x10001000 (used by bare-metal boards with -device
//! virtio-blk-device) and the PCIe root complex (used by the default
//! -device virtio-blk-pci, whose transitional device id is 0x1001).
//! All devices share one PLIC source (IRQ 1); the kernel wires the
//! shared handler during PLIC bring-up, so this module only
//! discovers and registers devices.

use crate::drivers::virtio::{device_id, mmio::MmioTransport, pci::PciTransport, Transport};

// hw/riscv/virt.c constants.
pub const MMIO_BASE: u64 = 0x10001000;
pub const MMIO_SLOTS: usize = 8;
pub const MMIO_STRIDE: u64 = 0x1000;
/// PCIe ECAM window (hw/riscv/virt.c VIRT_PCIE_ECAM). The shared
/// PCI subsystem resolves the same window through MCFG / device
/// tree; scan the single root bus through it.
pub const PCI_BUS_COUNT: u8 = 1;

/// Discovered virtio device handles, indexed by discovery order.
pub struct VirtioDevices {
    pub blk: alloc::vec::Vec<crate::drivers::virtio::blk::VirtioBlk>,
    pub net: alloc::vec::Vec<crate::drivers::virtio::net::VirtioNet>,
    pub gpu: alloc::vec::Vec<crate::drivers::virtio::gpu::VirtioGpu>,
    pub transports: alloc::vec::Vec<alloc::boxed::Box<dyn Transport>>,
}

/// PCI vendor id for virtio devices (Linux PCI_VENDOR_ID_REDHAT).
const VIRTIO_PCI_VENDOR: u16 = 0x1af4;

/// Translate a virtio-pci device id into a virtio device type.
/// Transitional devices carry fixed historical ids (net=0x1000,
/// blk=0x1001); modern devices encode the type as id - 0x1040.
fn virtio_type_from_pci_id(pci_id: u16) -> Option<u32> {
    match pci_id {
        0x1000 => Some(device_id::NET),
        0x1001 => Some(device_id::BLOCK),
        id if (0x1040..0x1080).contains(&id) => Some(u32::from(id) - 0x1040),
        _ => None,
    }
}

/// Bring one discovered device up over its transport and record it
/// under the discovered index.
unsafe fn attach_device(
    devices: &mut VirtioDevices,
    virtio_type: u32,
    transport: alloc::boxed::Box<dyn Transport>,
) {
    let index = devices.transports.len();
    devices.transports.push(transport);
    let transport = devices.transports.last_mut().unwrap().as_mut();
    match virtio_type {
        device_id::BLOCK => {
            if let Some(dev) = crate::drivers::virtio::blk::VirtioBlk::probe(index, transport) {
                devices.blk.push(dev);
            }
        }
        device_id::NET => {
            if let Some(dev) = crate::drivers::virtio::net::VirtioNet::probe(index, transport) {
                devices.net.push(dev);
            }
        }
        device_id::GPU => {
            if let Some(dev) = crate::drivers::virtio::gpu::VirtioGpu::probe(index, transport) {
                devices.gpu.push(dev);
            }
        }
        _ => {}
    }
}

use crate::ke::sync::Spinlock;

static CACHED_DEVICES: Spinlock<Option<VirtioDevices>> = Spinlock::new(None);

/// IRP_MJ_READ handler for virtio-blk devices.
unsafe extern "C" fn virtio_blk_read(
    _device: *mut crate::io::DeviceObject,
    irp: *mut crate::io::Irp,
) -> i32 {
    let (offset, _count, buffer) = crate::io::dispatch::storage_request_parameters(irp);
    let lba = offset / 512;
    let mut guard = CACHED_DEVICES.lock();
    let ctx = guard.as_mut().unwrap();
    let dev = ctx.blk.first_mut().unwrap();
    let transport = ctx.transports.get_mut(dev.transport_index()).unwrap();
    if dev.read_sectors(
        &mut **transport,
        lba,
        core::slice::from_raw_parts_mut(buffer, 512),
    ) {
        crate::libs::ntdll::status::STATUS_SUCCESS
    } else {
        crate::libs::ntdll::status::STATUS_IO_DEVICE_ERROR
    }
}

/// IRP_MJ_WRITE handler for virtio-blk devices.
unsafe extern "C" fn virtio_blk_write(
    _device: *mut crate::io::DeviceObject,
    irp: *mut crate::io::Irp,
) -> i32 {
    let (offset, _count, buffer) = crate::io::dispatch::storage_request_parameters(irp);
    let lba = offset / 512;
    let mut guard = CACHED_DEVICES.lock();
    let ctx = guard.as_mut().unwrap();
    let dev = ctx.blk.first_mut().unwrap();
    let transport = ctx.transports.get_mut(dev.transport_index()).unwrap();
    if dev.write_sectors(
        &mut **transport,
        lba,
        core::slice::from_raw_parts(buffer as *const u8, 512),
    ) {
        crate::libs::ntdll::status::STATUS_SUCCESS
    } else {
        crate::libs::ntdll::status::STATUS_IO_DEVICE_ERROR
    }
}

/// Register virtio-blk devices into the storage dispatch registry.
pub unsafe fn register_dispatch() {
    crate::hal::serial::write_string_always("[RVDRV] register_dispatch enter\r\n");
    let driver = crate::io::allocate_driver(b"\\Driver\\virtio_blk");
    if driver.is_null() {
        return;
    }
    let mut table = crate::io::dispatch::DispatchTable::new();
    table.major_functions[crate::io::major::IRP_MJ_READ as usize] = Some(virtio_blk_read);
    table.major_functions[crate::io::major::IRP_MJ_WRITE as usize] = Some(virtio_blk_write);
    table.install(driver);
    crate::hal::serial::write_string_always("[RVDRV] probing virtio\r\n");
    let devices = probe_virtio_devices();
    crate::hal::serial::write_string_always("[RVDRV] probe done\r\n");
    *CACHED_DEVICES.lock() = Some(devices);
    crate::hal::serial::write_string_always("[RVDRV] cache stored\r\n");
    let count = CACHED_DEVICES.lock().as_ref().unwrap().blk.len();
    crate::hal::serial::write_string_always("[RVDRV] cache unlocked\r\n");
    for slot in 0..count {
        let device =
            crate::io::create_device(driver, crate::io::DeviceType::Disk, b"\\Device\\VirtioDisk");
        if device.is_null() {
            continue;
        }
        crate::drivers::storage::io_dispatch::register_device(slot, device);
    }
    crate::hal::serial::write_string_always("[RVDRV] registered\r\n");
}

/// Probe the PCIe root complex and the virtio-mmio slots, and
/// initialise matching drivers on whichever transport carries them.
pub unsafe fn probe_virtio_devices() -> VirtioDevices {
    let mut devices = VirtioDevices {
        blk: alloc::vec::Vec::new(),
        net: alloc::vec::Vec::new(),
        gpu: alloc::vec::Vec::new(),
        transports: alloc::vec::Vec::new(),
    };

    // PCIe path: enumerate through the shared PCI subsystem, enable
    // memory-space + bus-master decoding (BAR MMIO reads fail on an
    // unenabled function), then bring the device up over the shared
    // virtio-pci transport.
    if let Some(ecam) = crate::hal::common::pci::ecam_base() {
        for pci_dev in crate::hal::common::pci::enumerate() {
            if pci_dev.vendor_id != VIRTIO_PCI_VENDOR {
                continue;
            }
            let Some(virtio_type) = virtio_type_from_pci_id(pci_dev.device_id) else {
                continue;
            };
            crate::hal::common::pci::enable_memory_bus_master(
                pci_dev.bus,
                pci_dev.device,
                pci_dev.function,
            );
            if let Some(transport) =
                PciTransport::probe(ecam, pci_dev.bus, pci_dev.device, pci_dev.function)
            {
                attach_device(&mut devices, virtio_type, alloc::boxed::Box::new(transport));
            }
        }
    }

    // virtio-mmio path (bare-metal boards).
    for slot in 0..MMIO_SLOTS {
        let base = MMIO_BASE + (slot as u64) * MMIO_STRIDE;
        let transport = match MmioTransport::probe(base) {
            Some(t) => t,
            None => continue,
        };

        let virtio_type = transport.device_id();
        attach_device(&mut devices, virtio_type, alloc::boxed::Box::new(transport));
    }

    devices
}
