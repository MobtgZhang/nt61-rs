//! Architecture-specific driver support for aarch64.
//!
//! QEMU aarch64 virt machine exposes virtio devices on the
//! virtio-mmio transport (hw/arm/virt.c VIRT_MMIO): 32 slots starting
//! at 0x0a000000 with a 0x200-byte stride. All devices share one
//! level-triggered SPI (GIC SPI 36 / INTID 68); the kernel wires the
//! shared handler during GIC bring-up, so this module only discovers
//! and registers devices.

use crate::drivers::virtio::{device_id, mmio::MmioTransport};

// hw/arm/virt.c VIRT_MMIO constants.
pub const MMIO_BASE: u64 = 0x0a000000;
pub const MMIO_SLOTS: usize = 32;
pub const MMIO_STRIDE: u64 = 0x200;

/// Discovered virtio device handles, indexed by discovery order.
pub struct VirtioDevices {
    pub blk: alloc::vec::Vec<crate::drivers::virtio::blk::VirtioBlk>,
    pub net: alloc::vec::Vec<crate::drivers::virtio::net::VirtioNet>,
    pub gpu: alloc::vec::Vec<crate::drivers::virtio::gpu::VirtioGpu>,
    /// Transports backing the discovered devices; the index in each
    /// device record refers back here.
    pub transports: alloc::vec::Vec<MmioTransport>,
}

use crate::ke::sync::Spinlock;

/// Cached probe result for the dispatch handlers (Spinlock for safe access).
static CACHED_DEVICES: Spinlock<Option<VirtioDevices>> = Spinlock::new(None);

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_READ handler for virtio-blk devices (dispatch callback).
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
/// IRP_MJ_WRITE handler for virtio-blk devices (dispatch callback).
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
/// Probe all virtio-mmio slots and initialise matching drivers.
pub unsafe fn probe_virtio_devices() -> VirtioDevices {
    let mut transports = alloc::vec::Vec::new();
    let mut blk = alloc::vec::Vec::new();
    let mut net = alloc::vec::Vec::new();
    let mut gpu = alloc::vec::Vec::new();

    for slot in 0..MMIO_SLOTS {
        let base = MMIO_BASE + (slot as u64) * MMIO_STRIDE;
        let transport = match MmioTransport::probe(base) {
            Some(t) => t,
            None => continue,
        };

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
            _ => {
                // Device type not yet supported; leave the slot idle.
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
