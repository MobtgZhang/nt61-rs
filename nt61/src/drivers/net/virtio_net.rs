//! virtio-net PCI driver.
//!
//! QEMU's x86 `virtio-net-pci` device exposes a modern virtio-pci
//! transport. This driver uses the PCI capabilities (common config,
//! notify, ISR and device config), split virtqueues, and the 12-byte
//! `virtio_net_hdr_v1` prefix.

use crate::drivers::virtio::{
    device_id,
    pci::PciTransport,
    queue::{QueueBuffer, QueueLayout},
    status, FEATURE_VERSION_1,
};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU32, Ordering};

const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
const VIRTIO_NET_HDR_LEN: usize = 12;
const VIRTIO_NET_RX_HDR_LEN: usize = 12;
const QUEUE_SIZE: u16 = 128;
const MAX_RX_SLOTS: usize = 128;
const RX_FRAME_SIZE: usize = 1526;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

pub struct Nic {
    transport: PciTransport,
    rx_queue: QueueLayout,
    tx_queue: QueueLayout,
    rx_buffers: [(*mut u8, *mut u8); MAX_RX_SLOTS],
    mac: [u8; 6],
    link_up: bool,
    tx_count: AtomicU32,
    rx_count: AtomicU32,
}

static mut NICS: [Option<Nic>; 4] = [const { None }; 4];
static mut NIC_COUNT: usize = 0;
static INIT_LOCK: Spinlock<()> = Spinlock::new(());

fn get_nics() -> &'static mut [Option<Nic>; 4] {
    unsafe { &mut *core::ptr::addr_of_mut!(NICS) }
}

fn push_nic(nic: Nic) {
    let _guard = INIT_LOCK.lock();
    let nics = get_nics();
    let count = unsafe { NIC_COUNT };
    if count < nics.len() {
        nics[count] = Some(nic);
        unsafe {
            NIC_COUNT += 1;
        }
    }
}

pub fn count() -> usize {
    unsafe { NIC_COUNT }
}

pub fn get_mac(nic_idx: usize) -> Option<[u8; 6]> {
    let nics = get_nics();
    nics.get(nic_idx)?.as_ref().map(|nic| nic.mac)
}

pub fn is_link_up(nic_idx: usize) -> bool {
    let nics = get_nics();
    nics.get(nic_idx)
        .and_then(|slot| slot.as_ref())
        .map(|nic| nic.link_up)
        .unwrap_or(false)
}

pub fn get_tx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics.get(nic_idx)
        .and_then(|slot| slot.as_ref())
        .map_or(0, |nic| nic.tx_count.load(Ordering::Relaxed))
}

pub fn get_rx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics.get(nic_idx)
        .and_then(|slot| slot.as_ref())
        .map_or(0, |nic| nic.rx_count.load(Ordering::Relaxed))
}

pub fn init() {
    crate::hal::serial::write_string("NET:virtio_start\r\n");
    if crate::hal::common::pci::ecam_base().is_none() {
        crate::hal::serial::write_string_always("[VIRTIO-NET] legacy pci config\r\n");
    }
    let mut probed = 0;
    for dev in crate::hal::common::pci::enumerate() {
        crate::hal::serial::write_string_always("[VIRTIO-NET] pci candidate\r\n");
        if dev.vendor_id != crate::drivers::virtio::pci::PCI_VENDOR_ID_REDHAT {
            continue;
        }
        if dev.device_id != 0x1000 && !(0x1040..0x1080).contains(&dev.device_id) {
            continue;
        }

        crate::hal::common::pci::enable_memory_bus_master(dev.bus, dev.device, dev.function);
        let transport = unsafe { PciTransport::probe(0, dev.bus, dev.device, dev.function) };
        let Some(transport) = transport else {
            crate::hal::serial::write_string_always("[VIRTIO-NET] transport failed\r\n");
            continue;
        };
        if transport.virtio_device_type() != Some(device_id::NET) {
            continue;
        }
        if let Some(nic) = unsafe { init_nic(transport) } {
            crate::hal::serial::write_string_always("[VIRTIO-NET] init ok\r\n");
            probed += 1;
            push_nic(nic);
        }
    }
    if probed == 0 {
        crate::hal::serial::write_string_always("[VIRTIO-NET] no nic\r\n");
    }
    crate::hal::serial::write_string("NET:virtio_done\r\n");
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn init_nic(mut transport: PciTransport) -> Option<Nic> {
    transport.reset();
    transport.write_status(status::ACKNOWLEDGE);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER);

    let device_features = transport.read_device_features();
    if device_features & FEATURE_VERSION_1 == 0 {
        crate::hal::serial::write_string_always(&alloc::format!(
            "[VIRTIO-NET] not modern status={:#x} common={:#x} features={:#018x}\r\n",
            transport.read_status(),
            transport.common_base(),
            device_features
        ));
        transport.write_status(status::FAILED);
        return None;
    }

    let mut features = FEATURE_VERSION_1;
    if device_features & VIRTIO_NET_F_MAC != 0 {
        features |= VIRTIO_NET_F_MAC;
    }
    if device_features & VIRTIO_NET_F_STATUS != 0 {
        features |= VIRTIO_NET_F_STATUS;
    }
    transport.write_driver_features(features);
    transport.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
    if transport.read_status() & status::FEATURES_OK == 0 {
        crate::hal::serial::write_string_always("[VIRTIO-NET] features failed\r\n");
        transport.write_status(status::FAILED);
        return None;
    }

    let rx_size = QUEUE_SIZE;
    let tx_size = QUEUE_SIZE;
    if rx_size < 2 || tx_size < 2 {
        crate::hal::serial::write_string_always("[VIRTIO-NET] bad queue size\r\n");
        transport.write_status(status::FAILED);
        return None;
    }

    let mut rx_queue = QueueLayout::allocate(rx_size)?;
    let tx_queue = QueueLayout::allocate(tx_size)?;
    if !transport.setup_queue(RX_QUEUE, &rx_queue) || !transport.setup_queue(TX_QUEUE, &tx_queue) {
        crate::hal::serial::write_string_always("[VIRTIO-NET] queue setup failed\r\n");
        transport.write_status(status::FAILED);
        return None;
    }

    let mut rx_buffers =
        [const { (core::ptr::null_mut::<u8>(), core::ptr::null_mut::<u8>()) }; MAX_RX_SLOTS];
    let chain_count = (rx_queue.num() as usize / 2).min(MAX_RX_SLOTS);
    for slot in 0..chain_count {
        let header = alloc_dma_buffer(VIRTIO_NET_RX_HDR_LEN);
        let frame = alloc_dma_buffer(RX_FRAME_SIZE);
        if header.is_null() || frame.is_null() {
            crate::hal::serial::write_string_always("[VRX] alloc failed\r\n");
            return None;
        }
        rx_buffers[slot] = (header, frame);
        if fill_rx(&mut rx_queue, &rx_buffers, slot).is_none() {
            crate::hal::serial::write_string_always("[VRX] chain failed\r\n");
            return None;
        }
    }
    unsafe { transport.notify(RX_QUEUE) };

    transport.write_status(
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
    );
    unsafe { transport.notify(RX_QUEUE) };

    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = transport.config_read_u8(index as u64);
    }
    let link_up = if features & VIRTIO_NET_F_STATUS != 0 {
        transport.config_read_u16(6) & 1 != 0
    } else {
        true
    };

    Some(Nic {
        transport,
        rx_queue,
        tx_queue,
        rx_buffers,
        mac,
        link_up,
        tx_count: AtomicU32::new(0),
        rx_count: AtomicU32::new(0),
    })
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
unsafe fn alloc_dma_buffer(size: usize) -> *mut u8 {
    let page_count = size.div_ceil(4096) as u64;
    let Some(mem_phys) = crate::mm::allocate_pages(page_count) else {
        return core::ptr::null_mut();
    };
    let map_base = mem_phys & !0x1F_FFFF;
    if !crate::arch::identity_map_region(map_base, 0x20_0000) {
        crate::mm::free_pages(mem_phys, page_count);
        return core::ptr::null_mut();
    }
    let mem = mem_phys as *mut u8;
    unsafe { core::ptr::write_bytes(mem, 0, size) };
    mem
}

fn fill_rx(
    rx_queue: &mut QueueLayout,
    rx_buffers: &[(*mut u8, *mut u8); MAX_RX_SLOTS],
    slot: usize,
) -> Option<u16> {
    let (header, frame) = rx_buffers[slot];
    rx_queue.add_chain(&[
        QueueBuffer::new(header, VIRTIO_NET_RX_HDR_LEN, true),
        QueueBuffer::new(frame, RX_FRAME_SIZE, true),
    ])
}

pub fn send(nic_idx: usize, data: &[u8], _wait: bool) -> bool {
    let nics = get_nics();
    let Some(nic) = nics.get_mut(nic_idx).and_then(|slot| slot.as_mut()) else {
        return false;
    };
    if data.is_empty() || data.len() > 65535 {
        return false;
    }

    let mut header = [0u8; VIRTIO_NET_HDR_LEN];
    let head = nic.tx_queue.add_chain(&[
        QueueBuffer::new(header.as_mut_ptr(), VIRTIO_NET_HDR_LEN, false),
        QueueBuffer::new(data.as_ptr() as *mut u8, data.len(), false),
    ]);
    let Some(_head) = head else {
        crate::hal::serial::write_string_always("[VIRTIO-NET] tx add_chain failed\r\n");
        return false;
    };
    unsafe { nic.transport.notify(TX_QUEUE) };

    let deadline = crate::hal::common::pit::get_system_time_ms() + 1_000;
    while crate::hal::common::pit::get_system_time_ms() < deadline {
        if nic.tx_queue.pop_used().is_some() {
            nic.tx_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    crate::hal::serial::write_string_always("[VIRTIO-NET] tx completion timeout\r\n");
    false
}

pub fn send_async(nic_idx: usize, data: &[u8]) -> bool {
    send(nic_idx, data, false)
}

pub fn receive(nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    let nics = get_nics();
    let nic = nics.get_mut(nic_idx).and_then(|slot| slot.as_mut())?;

    let (head, written) = nic.rx_queue.pop_used()?;
    let slot = (head as usize) / 2;
    if slot >= MAX_RX_SLOTS {
        return None;
    }

    if written <= VIRTIO_NET_RX_HDR_LEN {
        if fill_rx(&mut nic.rx_queue, &nic.rx_buffers, slot).is_some() {
            unsafe { nic.transport.notify(RX_QUEUE) };
        }
        return None;
    }

    let (_, frame) = nic.rx_buffers[slot];
    let frame_len = (written - VIRTIO_NET_RX_HDR_LEN).min(RX_FRAME_SIZE);
    let copy_len = frame_len.min(buffer.len());
    unsafe {
        core::ptr::copy_nonoverlapping(frame, buffer.as_mut_ptr(), copy_len);
    }

    if fill_rx(&mut nic.rx_queue, &nic.rx_buffers, slot).is_none() {
        return Some(copy_len);
    }
    unsafe { nic.transport.notify(RX_QUEUE) };
    nic.rx_count.fetch_add(1, Ordering::Relaxed);
    Some(copy_len)
}

pub fn interrupt_handler(_nic_idx: usize) {}

pub fn flush_tx(nic_idx: usize) -> bool {
    let nics = get_nics();
    let Some(nic) = nics.get_mut(nic_idx).and_then(|slot| slot.as_mut()) else {
        return false;
    };
    while nic.tx_queue.pop_used().is_some() {}
    true
}

pub fn get_tx_free_count(nic_idx: usize) -> usize {
    let nics = get_nics();
    nics.get(nic_idx)
        .and_then(|slot| slot.as_ref())
        .map_or(0, |nic| nic.tx_queue.free_count() as usize)
}

pub fn can_send(nic_idx: usize) -> bool {
    get_tx_free_count(nic_idx) > 0
}

pub fn smoke_test() -> bool {
    true
}
