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

/// Heap-free transport wrapper for fixed device slots.
pub enum AnyTransport {
    Pci(PciTransport),
    Mmio(MmioTransport),
}

impl Transport for AnyTransport {
    fn device_id(&self) -> u32 {
        match self {
            AnyTransport::Pci(t) => t.device_id(),
            AnyTransport::Mmio(t) => t.device_id(),
        }
    }

    unsafe fn read_device_features(&mut self) -> u64 {
        match self {
            AnyTransport::Pci(t) => PciTransport::read_device_features(t),
            AnyTransport::Mmio(t) => MmioTransport::read_device_features(t),
        }
    }

    unsafe fn write_driver_features(&mut self, features: u64) {
        match self {
            AnyTransport::Pci(t) => PciTransport::write_driver_features(t, features),
            AnyTransport::Mmio(t) => MmioTransport::write_driver_features(t, features),
        }
    }

    unsafe fn setup_queue(&mut self, index: u16, queue: &crate::drivers::virtio::queue::QueueLayout) -> bool {
        match self {
            AnyTransport::Pci(t) => PciTransport::setup_queue(t, index, queue),
            AnyTransport::Mmio(t) => MmioTransport::setup_queue(t, index, queue),
        }
    }

    unsafe fn max_queue_size(&mut self, index: u16) -> u32 {
        match self {
            AnyTransport::Pci(t) => PciTransport::max_queue_size(t, index),
            AnyTransport::Mmio(t) => MmioTransport::max_queue_size(t, index),
        }
    }

    unsafe fn notify(&mut self, index: u16) {
        match self {
            AnyTransport::Pci(t) => PciTransport::notify(t, index),
            AnyTransport::Mmio(t) => MmioTransport::notify(t, index),
        }
    }

    unsafe fn read_isr(&mut self) -> u32 {
        match self {
            AnyTransport::Pci(t) => PciTransport::read_isr(t),
            AnyTransport::Mmio(t) => MmioTransport::read_isr(t),
        }
    }

    unsafe fn read_status(&mut self) -> u8 {
        match self {
            AnyTransport::Pci(t) => PciTransport::read_status(t),
            AnyTransport::Mmio(t) => MmioTransport::read_status(t),
        }
    }

    unsafe fn write_status(&mut self, status: u8) {
        match self {
            AnyTransport::Pci(t) => PciTransport::write_status(t, status),
            AnyTransport::Mmio(t) => MmioTransport::write_status(t, status),
        }
    }

    unsafe fn reset(&mut self) {
        match self {
            AnyTransport::Pci(t) => PciTransport::reset(t),
            AnyTransport::Mmio(t) => MmioTransport::reset(t),
        }
    }

    unsafe fn config_read_u8(&self, offset: u64) -> u8 {
        match self {
            AnyTransport::Pci(t) => PciTransport::config_read_u8(t, offset),
            AnyTransport::Mmio(t) => MmioTransport::config_read_u8(t, offset),
        }
    }

    unsafe fn config_read_u16(&self, offset: u64) -> u16 {
        match self {
            AnyTransport::Pci(t) => PciTransport::config_read_u16(t, offset),
            AnyTransport::Mmio(t) => MmioTransport::config_read_u16(t, offset),
        }
    }

    unsafe fn config_read_u32(&self, offset: u64) -> u32 {
        match self {
            AnyTransport::Pci(t) => PciTransport::config_read_u32(t, offset),
            AnyTransport::Mmio(t) => MmioTransport::config_read_u32(t, offset),
        }
    }

    unsafe fn config_read_u64(&self, offset: u64) -> u64 {
        match self {
            AnyTransport::Pci(t) => PciTransport::config_read_u64(t, offset),
            AnyTransport::Mmio(t) => MmioTransport::config_read_u64(t, offset),
        }
    }
}

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
    pub blk: [Option<crate::drivers::virtio::blk::VirtioBlk>; MAX_DEVICES],
    pub net: [Option<crate::drivers::virtio::net::VirtioNet>; MAX_DEVICES],
    pub gpu: [Option<crate::drivers::virtio::gpu::VirtioGpu>; MAX_DEVICES],
    pub transports: [Option<AnyTransport>; MAX_DEVICES],
}

const MAX_DEVICES: usize = 8;

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
    transport: AnyTransport,
) {
    let index = devices
        .transports
        .iter()
        .position(Option::is_none)
        .unwrap_or(MAX_DEVICES);
    if index >= MAX_DEVICES {
        return;
    }
    devices.transports[index] = Some(transport);
    let transport = devices.transports[index].as_mut().unwrap();
    crate::hal::serial::write_string_always("[ATTACH] type=");
    crate::hal::serial::write_hex_u64_always(virtio_type as u64);
    crate::hal::serial::write_string_always(" index=");
    crate::hal::serial::write_hex_u64_always(index as u64);
    crate::hal::serial::write_string_always("\r\n");
    match virtio_type {
        device_id::BLOCK => {
            crate::hal::serial::write_string_always("[ATTACH] blk probe enter\r\n");
            if let Some(dev) = crate::drivers::virtio::blk::VirtioBlk::probe(index, transport) {
                crate::hal::serial::write_string_always("[ATTACH] blk probe ok\r\n");
                devices.blk[index] = Some(dev);
            }
            crate::hal::serial::write_string_always("[ATTACH] blk probe return\r\n");
        }
        device_id::NET => {
            if let Some(dev) = crate::drivers::virtio::net::VirtioNet::probe(index, transport) {
                devices.net[index] = Some(dev);
            }
        }
        device_id::GPU => {
            if let Some(dev) = crate::drivers::virtio::gpu::VirtioGpu::probe(index, transport) {
                devices.gpu[index] = Some(dev);
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
    let dev = ctx.blk.iter_mut().flatten().next().unwrap();
    let transport = ctx
        .transports
        .get_mut(dev.transport_index())
        .unwrap()
        .as_mut()
        .unwrap();
    if dev.read_sectors(
        &mut *transport,
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
    let dev = ctx.blk.iter_mut().flatten().next().unwrap();
    let transport = ctx
        .transports
        .get_mut(dev.transport_index())
        .unwrap()
        .as_mut()
        .unwrap();
    if dev.write_sectors(
        &mut *transport,
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
    crate::hal::serial::write_string_always("[RP] enter\r\n");
    const VIRTIO_MMIO_BASE: u64 = crate::drivers::arch::riscv64::MMIO_BASE;
    const VIRTIO_MMIO_SIZE: u64 = crate::drivers::arch::riscv64::MMIO_SLOTS as u64 * 0x1000;
    let mmio_mapped = crate::arch::riscv64::paging::identity_map_region(
        VIRTIO_MMIO_BASE,
        VIRTIO_MMIO_SIZE,
    );
    crate::hal::serial::write_string_always("[RP] mmio mapping=");
    crate::hal::serial::write_string_always(if mmio_mapped { "ok" } else { "fail" });
    crate::hal::serial::write_string_always("\r\n");
    let mut devices = VirtioDevices {
        blk: [const { None }; MAX_DEVICES],
        net: [const { None }; MAX_DEVICES],
        gpu: [const { None }; MAX_DEVICES],
        transports: [const { None }; MAX_DEVICES],
    };

    // PCIe path: enumerate through the shared PCI subsystem, enable
    // memory-space + bus-master decoding (BAR MMIO reads fail on an
    // unenabled function), then bring the device up over the shared
    // virtio-pci transport.
    if let Some(ecam) = crate::hal::common::pci::ecam_base() {
        crate::hal::serial::write_string_always("[RP] ecam\r\n");
        for pci_dev in crate::hal::common::pci::enumerate() {
            crate::hal::serial::write_string_always("[RP] pci dev enter\r\n");
            crate::hal::serial::write_string_always("[RP] pci fmt enter\r\n");
            crate::hal::serial::write_string_always("[RP] pci bus=");
            crate::hal::serial::write_hex_u64_always(pci_dev.bus as u64);
            crate::hal::serial::write_string_always(" dev=");
            crate::hal::serial::write_hex_u64_always(pci_dev.device as u64);
            crate::hal::serial::write_string_always(" fn=");
            crate::hal::serial::write_hex_u64_always(pci_dev.function as u64);
            crate::hal::serial::write_string_always(" vendor=");
            crate::hal::serial::write_hex_u64_always(pci_dev.vendor_id as u64);
            crate::hal::serial::write_string_always(" device=");
            crate::hal::serial::write_hex_u64_always(pci_dev.device_id as u64);
            crate::hal::serial::write_string_always("\r\n");
            crate::hal::serial::write_string_always("[RP] pci fmt done\r\n");
            if pci_dev.vendor_id != VIRTIO_PCI_VENDOR {
                continue;
            }
            let Some(virtio_type) = virtio_type_from_pci_id(pci_dev.device_id) else {
                continue;
            };
            crate::hal::serial::write_string_always("[RP] virtio type=");
            crate::hal::serial::write_hex_u64_always(virtio_type as u64);
            crate::hal::serial::write_string_always("\r\n");
            crate::hal::common::pci::enable_memory_bus_master(
                pci_dev.bus,
                pci_dev.device,
                pci_dev.function,
            );
            crate::hal::serial::write_string_always("[RP] bus master enabled\r\n");
            if let Some(transport) =
                PciTransport::probe(ecam, pci_dev.bus, pci_dev.device, pci_dev.function)
            {
                crate::hal::serial::write_string_always("[RP] transport probed\r\n");
                attach_device(&mut devices, virtio_type, AnyTransport::Pci(transport));
            }
            crate::hal::serial::write_string_always("[RP] pci device done\r\n");
        }
    }

    // virtio-mmio path (bare-metal boards).
    crate::hal::serial::write_string_always("[RP] mmio\r\n");
    for slot in 0..MMIO_SLOTS {
        let base = MMIO_BASE + (slot as u64) * MMIO_STRIDE;
        let transport = match MmioTransport::probe(base) {
            Some(t) => t,
            None => continue,
        };

        let virtio_type = transport.device_id();
        attach_device(&mut devices, virtio_type, AnyTransport::Mmio(transport));
    }

    crate::hal::serial::write_string_always("[RP] done\r\n");
    devices
}
