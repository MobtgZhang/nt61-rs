//! Architecture-specific driver support for loongarch64.
//!
//! QEMU loongarch64 virt machine has no virtio-mmio; all virtio
//! devices are attached to the GPEx PCI host bridge (hw/loongarch/
//! virt.h). ECAM config space starts at VIRT_PCI_CFG_BASE = 0x20000000,
//! the first memory BAR window at VIRT_PCI_MEM_BASE = 0x40000000.
//! Discovery walks ECAM bus 0 for modern virtio-pci functions.

use crate::drivers::virtio::{device_id, pci::PciTransport};

// hw/loongarch/virt.h constants.
pub const ECAM_BASE: u64 = 0x20000000;
pub const PCI_MEM_BASE: u64 = 0x40000000;
pub const PCI_BUS_COUNT: u8 = 1;

/// Discovered virtio device handles.
pub struct VirtioDevices {
    pub blk: alloc::vec::Vec<crate::drivers::virtio::blk::VirtioBlk>,
    pub net: alloc::vec::Vec<crate::drivers::virtio::net::VirtioNet>,
    pub gpu: alloc::vec::Vec<crate::drivers::virtio::gpu::VirtioGpu>,
    pub transports: alloc::vec::Vec<PciTransport>,
}

use crate::ke::sync::Spinlock;

static CACHED_DEVICES: Spinlock<Option<VirtioDevices>> = Spinlock::new(None);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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
    if dev.read_sectors(transport, lba, core::slice::from_raw_parts_mut(buffer, 512)) {
        crate::libs::ntdll::status::STATUS_SUCCESS
    } else {
        crate::libs::ntdll::status::STATUS_IO_DEVICE_ERROR
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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
        transport,
        lba,
        core::slice::from_raw_parts(buffer as *const u8, 512),
    ) {
        crate::libs::ntdll::status::STATUS_SUCCESS
    } else {
        crate::libs::ntdll::status::STATUS_IO_DEVICE_ERROR
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Register virtio-blk devices into the storage dispatch registry.
pub unsafe fn register_dispatch() {
    let driver = crate::io::allocate_driver(b"\\Driver\\virtio_blk");
    if driver.is_null() {
        return;
    }
    let mut table = crate::io::dispatch::DispatchTable::new();
    table.major_functions[crate::io::major::IRP_MJ_READ as usize] = Some(virtio_blk_read);
    table.major_functions[crate::io::major::IRP_MJ_WRITE as usize] = Some(virtio_blk_write);
    table.install(driver);
    let devices = probe_virtio_devices();
    *CACHED_DEVICES.lock() = Some(devices);
    let count = CACHED_DEVICES.lock().as_ref().unwrap().blk.len();
    for slot in 0..count {
        let device =
            crate::io::create_device(driver, crate::io::DeviceType::Disk, b"\\Device\\VirtioDisk");
        if device.is_null() {
            continue;
        }
        crate::drivers::storage::io_dispatch::register_device(slot, device);
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Scan the ECAM window for modern virtio-pci devices and initialise
/// the matching drivers.
pub unsafe fn probe_virtio_devices() -> VirtioDevices {
    let mut transports = alloc::vec::Vec::new();
    let mut blk = alloc::vec::Vec::new();
    let mut net = alloc::vec::Vec::new();
    let mut gpu = alloc::vec::Vec::new();

    for bus in 0..PCI_BUS_COUNT {
        for transport in PciTransport::scan_bus(ECAM_BASE, bus) {
            match transport.device_id() {
                device_id::BLOCK => {
                    let idx = transports.len();
                    transports.push(transport);
                    let t = transports.last_mut().unwrap();
                    if let Some(dev) = crate::drivers::virtio::blk::VirtioBlk::probe(idx, t) {
                        blk.push(dev);
                    }
                }
                device_id::NET => {
                    let idx = transports.len();
                    transports.push(transport);
                    let t = transports.last_mut().unwrap();
                    if let Some(dev) = crate::drivers::virtio::net::VirtioNet::probe(idx, t) {
                        net.push(dev);
                    }
                }
                device_id::GPU => {
                    let idx = transports.len();
                    transports.push(transport);
                    let t = transports.last_mut().unwrap();
                    if let Some(dev) = crate::drivers::virtio::gpu::VirtioGpu::probe(idx, t) {
                        gpu.push(dev);
                    }
                }
                _ => {}
            }
        }
    }

    VirtioDevices {
        blk,
        net,
        gpu,
        transports,
    }
}
