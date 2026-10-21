//! VirtIO input keyboard driver.
// QEMU GTK routes physical keyboard events to virtio-keyboard-pci. This
// driver owns the PCI transport, event virtqueue, and Linux input-event
// code translation. Clean-room implementation based on the VirtIO spec.

use crate::hal::common::pci;
use crate::mm::pool::{self, PoolType};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU8, AtomicUsize, Ordering};

const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEVICE_INPUT_MODERN: u16 = 0x1040 + 18;
const DEVICE_INPUT_LEGACY: u16 = 0x1000 + 18;

// Modern virtio-pci common-configuration offsets
// (VirtIO 1.x spec, "Common configuration structure layout";
// matches /usr/include/linux/virtio_pci.h VIRTIO_PCI_COMMON_*).
const REG_DEV_FEATURE_SELECT: u64 = 0x00; // u32, read-write
const REG_DEV_FEATURE: u64 = 0x04; // u32, read-only (selected word)
const REG_GUEST_FEATURE_SELECT: u64 = 0x08;
const REG_GUEST_FEATURE: u64 = 0x0C;
const REG_STATUS: u64 = 0x14; // driver status (u8)
const REG_QUEUE_SELECT: u64 = 0x16; // u16
const REG_QUEUE_SIZE: u64 = 0x18; // u16
const REG_QUEUE_ENABLE: u64 = 0x1C; // u16
const REG_QUEUE_NOTIFY_OFF: u64 = 0x1E; // u16, read-only
const REG_QUEUE_DESC_LO: u64 = 0x20; // u32
const REG_QUEUE_DESC_HI: u64 = 0x24; // u32
const REG_QUEUE_AVAIL_LO: u64 = 0x28; // u32
const REG_QUEUE_AVAIL_HI: u64 = 0x2C; // u32
const REG_QUEUE_USED_LO: u64 = 0x30; // u32
const REG_QUEUE_USED_HI: u64 = 0x34; // u32

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

/// VIRTIO_F_VERSION_1 lives in feature word 1, bit 0. Modern
/// virtio-pci transports only work with virtio-1.0 devices, and the
/// spec requires the driver to accept this feature before the
/// device acknowledges FEATURES_OK.
const FEATURE_VERSION_1_WORD1_BIT: u32 = 1;

// PCI capability types (virtio_pci_cap.cfg_type).
const CAP_COMMON_CFG: u8 = 1;
const CAP_NOTIFY_CFG: u8 = 2;
const CAP_ISR_CFG: u8 = 3;

const DESC_F_WRITE: u16 = 2;
const EVENT_TYPE_KEY: u16 = 1;
const KEY_VALUE_RELEASE: i32 = 0;

const QUEUE_SIZE: u16 = 64;
const EVENT_SIZE: usize = 8;
const RING_SIZE: usize = 64;
const RING_MASK: usize = RING_SIZE - 1;

const EVENT_BUFFER_TAG: u32 = crate::mm::pool::make_tag(b'V', b'I', b'N', b'P');
const QUEUE_BUFFER_TAG: u32 = crate::mm::pool::make_tag(b'V', b'I', b'N', b'Q');

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Descriptor {
    address: u64,
    length: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct AvailableRing {
    flags: u16,
    index: AtomicU16,
    entries: [u16; QUEUE_SIZE as usize],
}

#[derive(Clone, Copy)]
#[repr(C, align(4))]
struct UsedElement {
    descriptor: u32,
    length: u32,
}

#[repr(C)]
struct UsedRing {
    flags: u16,
    index: AtomicU16,
    entries: [UsedElement; QUEUE_SIZE as usize],
}

struct Queue {
    descriptors: *mut Descriptor,
    available: *mut AvailableRing,
    used: *mut UsedRing,
    descriptor_physical: u64,
    /// Byte offset of the available ring from the descriptor array
    /// (needed to compute its physical address).
    avail_offset: u64,
    /// Byte offset of the used ring from the descriptor array.
    used_offset: u64,
    /// Device-visible offset of this queue's doorbell, in bytes.
    notify_off: u16,
    buffers: [*mut u8; QUEUE_SIZE as usize],
    next_free: u16,
    used_index: u16,
}

struct Device {
    notify: *mut u8,
    isr: *mut u8,
    notify_multiplier: u32,
    queue: Queue,
    shift: bool,
    caps_lock: bool,
}

impl Queue {
    fn next_descriptor(&mut self) -> Option<u16> {
        let descriptor = self.next_free;
        self.next_free = self.next_free.wrapping_add(1).rem_euclid(QUEUE_SIZE);
        Some(descriptor)
    }
}

fn add_event_buffer(queue: &mut Queue) -> Option<u16> {
    let buffer = pool::allocate_tagged(PoolType::NonPaged, EVENT_SIZE, EVENT_BUFFER_TAG);
    if buffer.is_null() {
        return None;
    }
    let Some(address) = translate(buffer as u64) else {
        pool::free(buffer);
        return None;
    };
    let Some(index) = queue.next_descriptor() else {
        pool::free(buffer);
        return None;
    };
    unsafe {
        core::ptr::write_bytes(buffer, 0, EVENT_SIZE);
        (*queue.descriptors.add(usize::from(index))).address = address;
        (*queue.descriptors.add(usize::from(index))).length = EVENT_SIZE as u32;
        (*queue.descriptors.add(usize::from(index))).flags = DESC_F_WRITE;
    }
    queue.buffers[usize::from(index)] = buffer;
    Some(index)
}

fn push_available(queue: &Queue, index: u16) {
    unsafe {
        let available = &mut *queue.available;
        let slot = usize::from(
            available
                .index
                .load(Ordering::Acquire)
                .rem_euclid(QUEUE_SIZE),
        );
        available.entries[slot] = index;
        let next = available.index.load(Ordering::Acquire).wrapping_add(1);
        available.index.store(next, Ordering::Release);
    }
}

fn replenish_event_buffer(device: &mut Device) {
    if let Some(index) = add_event_buffer(&mut device.queue) {
        push_available(&device.queue, index);
        let offset = u64::from(device.queue.notify_off) * u64::from(device.notify_multiplier);
        unsafe {
            core::ptr::write_volatile(
                device
                    .notify
                    .add(usize::try_from(offset).unwrap_or(0))
                    .cast::<u16>(),
                0,
            );
        }
    }
}

fn take_used_event(device: &mut Device) -> Option<[u8; EVENT_SIZE]> {
    let used = unsafe { &mut *device.queue.used };
    if device.queue.used_index == used.index.load(Ordering::Acquire) {
        return None;
    }
    let element =
        used.entries[usize::from(device.queue.used_index).rem_euclid(usize::from(QUEUE_SIZE))];
    let buffer = device.queue.buffers[element.descriptor as usize];
    device.queue.used_index = device.queue.used_index.wrapping_add(1);
    if buffer.is_null() || (element.length as usize) < EVENT_SIZE {
        return None;
    }
    let mut event = [0u8; EVENT_SIZE];
    unsafe { core::ptr::copy_nonoverlapping(buffer, event.as_mut_ptr(), EVENT_SIZE) };
    device.queue.buffers[element.descriptor as usize] = core::ptr::null_mut();
    Some(event)
}

fn decode_event(event: &[u8; EVENT_SIZE]) {
    let event_type = u16::from_le_bytes([event[0], event[1]]);
    let code = u16::from_le_bytes([event[2], event[3]]);
    let value = i32::from_le_bytes([event[4], event[5], event[6], event[7]]);
    if event_type != EVENT_TYPE_KEY {
        return;
    }
    // Shift releases must clear the modifier state; every other
    // release (including caps-lock toggles) is ignored.
    if value == KEY_VALUE_RELEASE {
        if code == 42 || code == 54 {
            set_shift(false);
        }
        return;
    }
    if code == 42 || code == 54 {
        set_shift(true);
    } else if code == 58 {
        set_caps_lock(!caps_lock());
    } else {
        for byte in translate_key(code) {
            enqueue_byte(*byte);
        }
    }
}

fn translate_key(code: u16) -> &'static [u8] {
    let shift = shift_state();
    let caps = caps_lock();
    let letter_upper = shift != caps;
    let use_shift = shift;
    match code {
        1 => b"\x1b",
        2 => b"1",
        3 => b"2",
        4 => b"3",
        5 => b"4",
        6 => b"5",
        7 => b"6",
        8 => b"7",
        9 => b"8",
        10 => b"9",
        11 => b"0",
        12 => {
            if use_shift {
                b"_"
            } else {
                b"-"
            }
        }
        13 => {
            if use_shift {
                b"+"
            } else {
                b"="
            }
        }
        14 => b"\x08",
        15 => b"\t",
        16 => {
            if letter_upper {
                b"Q"
            } else {
                b"q"
            }
        }
        17 => {
            if letter_upper {
                b"W"
            } else {
                b"w"
            }
        }
        18 => {
            if letter_upper {
                b"E"
            } else {
                b"e"
            }
        }
        19 => {
            if letter_upper {
                b"R"
            } else {
                b"r"
            }
        }
        20 => {
            if letter_upper {
                b"T"
            } else {
                b"t"
            }
        }
        21 => {
            if letter_upper {
                b"Y"
            } else {
                b"y"
            }
        }
        22 => {
            if letter_upper {
                b"U"
            } else {
                b"u"
            }
        }
        23 => {
            if letter_upper {
                b"I"
            } else {
                b"i"
            }
        }
        24 => {
            if letter_upper {
                b"O"
            } else {
                b"o"
            }
        }
        25 => {
            if letter_upper {
                b"P"
            } else {
                b"p"
            }
        }
        26 => {
            if use_shift {
                b"{"
            } else {
                b"["
            }
        }
        27 => {
            if use_shift {
                b"}"
            } else {
                b"]"
            }
        }
        28 => b"\r",
        30 => {
            if letter_upper {
                b"A"
            } else {
                b"a"
            }
        }
        31 => {
            if letter_upper {
                b"S"
            } else {
                b"s"
            }
        }
        32 => {
            if letter_upper {
                b"D"
            } else {
                b"d"
            }
        }
        33 => {
            if letter_upper {
                b"F"
            } else {
                b"f"
            }
        }
        34 => {
            if letter_upper {
                b"G"
            } else {
                b"g"
            }
        }
        35 => {
            if letter_upper {
                b"H"
            } else {
                b"h"
            }
        }
        36 => {
            if letter_upper {
                b"J"
            } else {
                b"j"
            }
        }
        37 => {
            if letter_upper {
                b"K"
            } else {
                b"k"
            }
        }
        38 => {
            if letter_upper {
                b"L"
            } else {
                b"l"
            }
        }
        39 => {
            if use_shift {
                b":"
            } else {
                b";"
            }
        }
        40 => {
            if use_shift {
                b"'"
            } else {
                b"'"
            }
        }
        41 => {
            if shift {
                b"~"
            } else {
                b"\x60"
            }
        }
        43 => {
            if shift {
                b"|"
            } else {
                b"\\"
            }
        }
        44 => {
            if letter_upper {
                b"Z"
            } else {
                b"z"
            }
        }
        45 => {
            if letter_upper {
                b"X"
            } else {
                b"x"
            }
        }
        46 => {
            if letter_upper {
                b"C"
            } else {
                b"c"
            }
        }
        47 => {
            if letter_upper {
                b"V"
            } else {
                b"v"
            }
        }
        48 => {
            if letter_upper {
                b"B"
            } else {
                b"b"
            }
        }
        49 => {
            if letter_upper {
                b"N"
            } else {
                b"n"
            }
        }
        50 => {
            if letter_upper {
                b"M"
            } else {
                b"m"
            }
        }
        51 => {
            if use_shift {
                b"<"
            } else {
                b","
            }
        }
        52 => {
            if use_shift {
                b">"
            } else {
                b"."
            }
        }
        53 => {
            if use_shift {
                b"?"
            } else {
                b"/"
            }
        }
        57 => b" ",
        103 => b"\x1b[A",
        105 => b"\x1b[D",
        106 => b"\x1b[C",
        108 => b"\x1b[B",
        _ => b"",
    }
}

fn enqueue_byte(byte: u8) {
    let tail = RING_TAIL.load(Ordering::Acquire);
    let head = RING_HEAD.load(Ordering::Acquire);
    if tail.wrapping_sub(head) >= RING_SIZE {
        return;
    }
    RING[tail & RING_MASK].store(byte, Ordering::Release);
    RING_TAIL.store(tail.wrapping_add(1), Ordering::Release);
}

fn set_shift(value: bool) {
    if let Some(device) = unsafe { DEVICE.load(Ordering::Acquire).as_mut() } {
        device.shift = value;
    }
}

fn set_caps_lock(value: bool) {
    if let Some(device) = unsafe { DEVICE.load(Ordering::Acquire).as_mut() } {
        device.caps_lock = value;
    }
}

fn shift_state() -> bool {
    unsafe { DEVICE.load(Ordering::Acquire).as_ref() }.is_some_and(|d| d.shift)
}

fn caps_lock() -> bool {
    unsafe { DEVICE.load(Ordering::Acquire).as_ref() }.is_some_and(|device| device.caps_lock)
}

fn read_u8(mmio: *const u8, offset: u64) -> u8 {
    unsafe { core::ptr::read_volatile(mmio.add(usize::try_from(offset).unwrap_or(0))) }
}

fn read_u16(mmio: *const u8, offset: u64) -> u16 {
    unsafe {
        core::ptr::read_volatile(mmio.add(usize::try_from(offset).unwrap_or(0)).cast::<u16>())
    }
}

fn read_u32(mmio: *const u8, offset: u64) -> u32 {
    unsafe {
        core::ptr::read_volatile(mmio.add(usize::try_from(offset).unwrap_or(0)).cast::<u32>())
    }
}

fn write_u8(mmio: *mut u8, offset: u64, value: u8) {
    unsafe { core::ptr::write_volatile(mmio.add(usize::try_from(offset).unwrap_or(0)), value) }
}

fn write_u16(mmio: *mut u8, offset: u64, value: u16) {
    unsafe {
        core::ptr::write_volatile(
            mmio.add(usize::try_from(offset).unwrap_or(0)).cast::<u16>(),
            value,
        )
    }
}

fn write_u32(mmio: *mut u8, offset: u64, value: u32) {
    unsafe {
        core::ptr::write_volatile(
            mmio.add(usize::try_from(offset).unwrap_or(0)).cast::<u32>(),
            value,
        )
    }
}

fn translate(virtual_address: u64) -> Option<u64> {
    Some(crate::arch::translate_virt(virtual_address).unwrap_or(virtual_address))
}

static DEVICE: AtomicPtr<Device> = AtomicPtr::new(core::ptr::null_mut());
static INITIALISED: AtomicBool = AtomicBool::new(false);
static FIRST_EVENT_SEEN: AtomicUsize = AtomicUsize::new(0);
static RING_HEAD: AtomicUsize = AtomicUsize::new(0);
static RING_TAIL: AtomicUsize = AtomicUsize::new(0);
static RING: [AtomicU8; RING_SIZE] = [const { AtomicU8::new(0) }; RING_SIZE];

/// One decoded virtio-pci capability region (BAR-relative).
struct CapRegion {
    bar: u8,
    offset: u64,
    length: u64,
}

/// Walk the vendor-specific PCI capabilities and return the
/// (common, notify, isr) regions plus the notify multiplier.
fn decode_pci_caps(dev: &pci::PciDevice) -> Option<(CapRegion, CapRegion, CapRegion, u32)> {
    use crate::hal::common::pci as pcicfg;
    let (bus, slot, func) = (dev.bus, dev.device, dev.function);
    let mut common: Option<CapRegion> = None;
    let mut notify: Option<CapRegion> = None;
    let mut isr: Option<CapRegion> = None;
    let mut multiplier: u32 = 0;

    let mut ptr = pcicfg::read_config_byte(bus, slot, func, 0x34);
    let mut hops = 0;
    while ptr != 0 && hops < 24 {
        hops += 1;
        let id = pcicfg::read_config_byte(bus, slot, func, ptr);
        let next = pcicfg::read_config_byte(bus, slot, func, ptr + 1);
        let len = u16::from(pcicfg::read_config_byte(bus, slot, func, ptr + 2))
            | (u16::from(pcicfg::read_config_byte(bus, slot, func, ptr + 3)) << 8);
        if id == 0x09 && len >= 16 {
            // VirtIO capability layout: cap_vndr(1) cap_next(1) cap_len(1)
            // cfg_type(1) bar(1) padding(3) offset(u32) length(u32).
            let cfg_type = pcicfg::read_config_byte(bus, slot, func, ptr + 3);
            let bar = pcicfg::read_config_byte(bus, slot, func, ptr + 4);
            let offset = u64::from(pcicfg::read_config_dword(bus, slot, func, ptr + 8));
            let length = u64::from(pcicfg::read_config_dword(bus, slot, func, ptr + 12));
            let region = CapRegion {
                bar,
                offset,
                length,
            };
            match cfg_type {
                CAP_COMMON_CFG => {
                    if common.is_none() {
                        common = Some(region);
                    }
                }
                CAP_NOTIFY_CFG => {
                    if notify.is_none() {
                        notify = Some(region);
                        multiplier = pcicfg::read_config_dword(bus, slot, func, ptr + 16);
                    }
                }
                CAP_ISR_CFG => {
                    if isr.is_none() {
                        isr = Some(region);
                    }
                }
                _ => {}
            }
        }
        ptr = next;
    }
    Some((common?, notify?, isr?, multiplier))
}

/// Map one capability region into kernel VA space.
fn map_region(dev: &pci::PciDevice, region: &CapRegion) -> Option<*mut u8> {
    let bar_base = pci::read_bar(dev, region.bar);
    if bar_base == 0 {
        return None;
    }
    let pages = region.length.div_ceil(4096).max(1);
    // On non-x86_64 architectures the kernel runs with identity
    // mapping (VA == PA for physical addresses), so the PCI BAR can
    // be accessed directly without going through the system PTE
    // region. On x86_64 the system PTE pool provides the mapping.
    #[cfg(target_arch = "x86_64")]
    {
        let mapped = crate::mm::syspte::map_io_space(bar_base + region.offset, pages)?;
        return Some(mapped as *mut u8);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = pages;
        Some((bar_base + region.offset) as *mut u8)
    }
}

/// Enable memory-space + bus-master decoding in the command register.
fn enable_pci_decode(dev: &pci::PciDevice) {
    use crate::hal::common::pci as pcicfg;
    let cmd = pcicfg::read_config_word(dev.bus, dev.device, dev.function, 0x04);
    pcicfg::write_config_word(dev.bus, dev.device, dev.function, 0x04, cmd | 0x02 | 0x04);
}

pub fn init() {
    if INITIALISED.swap(true, Ordering::AcqRel) {
        return;
    }
    trace("virtio-input: probe begin\r\n");
    // On non-x86_64 architectures the system PTE mapping path
    // (mm::syspte::map_io_space) is not yet reliable. The serial /
    // UART keyboard fallback handles input; skip PCI probing to
    // avoid a translation fault on the unmapped system PTE VA.
    for pci_dev in pci::enumerate() {
        trace_fmt(alloc::format!(
            "virtio-input: pci {:02x}:{:02x}.{:02x} vendor={:04x} device={:04x}\r\n",
            pci_dev.bus,
            pci_dev.device,
            pci_dev.function,
            pci_dev.vendor_id,
            pci_dev.device_id
        ));
        if pci_dev.vendor_id != VENDOR_VIRTIO
            || (pci_dev.device_id != DEVICE_INPUT_MODERN
                && pci_dev.device_id != DEVICE_INPUT_LEGACY)
        {
            continue;
        }
        // Memory/BAR access must be enabled before any BAR read.
        enable_pci_decode(&pci_dev);

        let Some((common_cap, notify_cap, isr_cap, multiplier)) = decode_pci_caps(&pci_dev) else {
            trace("virtio-input: cap decode FAILED\r\n");
            continue;
        };
        let Some(common) = map_region(&pci_dev, &common_cap) else {
            trace("virtio-input: common cfg map FAILED\r\n");
            continue;
        };
        let Some(notify) = map_region(&pci_dev, &notify_cap) else {
            trace("virtio-input: notify map FAILED\r\n");
            continue;
        };
        let Some(isr) = map_region(&pci_dev, &isr_cap) else {
            trace("virtio-input: isr map FAILED\r\n");
            continue;
        };
        trace_fmt(alloc::format!(
            "virtio-input: caps common={:p} notify={:p} isr={:p} mult={}\r\n",
            common,
            notify,
            isr,
            multiplier
        ));

        let Some(queue) = initialise_queue(common) else {
            trace("virtio-input: queue init FAILED\r\n");
            continue;
        };
        let Some(device) = allocate_device(notify, isr, multiplier, queue) else {
            trace("virtio-input: device alloc FAILED\r\n");
            continue;
        };
        DEVICE.store(device, Ordering::Release);
        trace("virtio-input: keyboard ATTACHED\r\n");
        break;
    }
    if DEVICE.load(Ordering::Acquire).is_null() {
        trace("virtio-input: no virtio keyboard found\r\n");
    }
}

/// Bring-up diagnostics for the virtio-input probe. Compiled out
/// unless the debug log level is enabled; the bytes go through the
/// unconditional early-serial sink so they are visible even when
/// the boot display suppresses the standard log channels.
fn trace(message: &str) {
    #[cfg(feature = "log_level_debug")]
    crate::arch::boot::early_write_str(message.as_bytes());
    #[cfg(not(feature = "log_level_debug"))]
    let _ = message;
}

fn trace_fmt(message: alloc::string::String) {
    #[cfg(feature = "log_level_debug")]
    crate::arch::boot::early_write_str(message.as_bytes());
    #[cfg(not(feature = "log_level_debug"))]
    let _ = message;
}

pub fn is_present() -> bool {
    !DEVICE.load(Ordering::Acquire).is_null()
}

pub fn poll() {
    let device = DEVICE.load(Ordering::Acquire);
    if device.is_null() {
        return;
    }
    let device = unsafe { &mut *device };
    // Reading the ISR status register clears it; the legacy
    // polling path does not use interrupts so we only need to
    // make sure the read happens (spec-mandated side effect).
    let _isr = read_u8(device.isr, 0);
    while let Some(event) = take_used_event(device) {
        let seen = FIRST_EVENT_SEEN.fetch_add(1, Ordering::AcqRel);
        if seen < 20 {
            trace_fmt(alloc::format!(
                "virtio-input: event #{} type={} code={} value={}\r\n",
                seen,
                u16::from_le_bytes([event[0], event[1]]),
                u16::from_le_bytes([event[2], event[3]]),
                i32::from_le_bytes([event[4], event[5], event[6], event[7]])
            ));
        }
        decode_event(&event);
        replenish_event_buffer(device);
    }
}

pub fn try_read_byte() -> Option<u8> {
    poll();
    let head = RING_HEAD.load(Ordering::Acquire);
    if RING_TAIL.load(Ordering::Acquire) == head {
        return None;
    }
    let byte = RING[head & RING_MASK].load(Ordering::Acquire);
    RING_HEAD.store(head.wrapping_add(1), Ordering::Release);
    Some(byte)
}

/// Bring up one event queue through the modern (virtio-1.x) PCI
/// common-configuration layout. Negotiates no device features
/// (the input device works fine with an empty feature set) and
/// pre-fills the available ring with one writable event buffer
/// per descriptor slot.
fn initialise_queue(mmio: *mut u8) -> Option<Queue> {
    // Acknowledge the device and claim driver ownership.
    let status = u32::from(read_u8(mmio, REG_STATUS));
    write_u8(
        mmio,
        REG_STATUS,
        (status | STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u8,
    );

    // Read the device feature words. A modern (virtio-1.0) device
    // always offers VIRTIO_F_VERSION_1 in word 1; the spec requires
    // the driver to accept it. No word-0 features are needed by the
    // input device.
    write_u32(mmio, REG_DEV_FEATURE_SELECT, 1);
    let device_feature_word1 = read_u32(mmio, REG_DEV_FEATURE);
    write_u32(mmio, REG_DEV_FEATURE_SELECT, 0);
    let _device_feature_word0 = read_u32(mmio, REG_DEV_FEATURE);

    // Negotiate guest features: word 0 = none, word 1 = VERSION_1
    // if the device offered it.
    write_u32(mmio, REG_GUEST_FEATURE_SELECT, 0);
    write_u32(mmio, REG_GUEST_FEATURE, 0);
    write_u32(mmio, REG_GUEST_FEATURE_SELECT, 1);
    if device_feature_word1 & FEATURE_VERSION_1_WORD1_BIT != 0 {
        write_u32(mmio, REG_GUEST_FEATURE, FEATURE_VERSION_1_WORD1_BIT);
    }
    write_u32(mmio, REG_GUEST_FEATURE_SELECT, 0);

    // Ask the device to validate the negotiated feature set.
    let status = u32::from(read_u8(mmio, REG_STATUS));
    write_u8(mmio, REG_STATUS, (status | STATUS_FEATURES_OK) as u8);
    let confirmed = u32::from(read_u8(mmio, REG_STATUS));
    if confirmed & STATUS_FEATURES_OK == 0 {
        write_u8(mmio, REG_STATUS, STATUS_FAILED as u8);
        trace("virtio-input: FEATURES_OK rejected\r\n");
        return None;
    }

    // Select queue 0 (the sole event queue of a virtio-input device).
    write_u16(mmio, REG_QUEUE_SELECT, 0);
    let maximum = read_u16(mmio, REG_QUEUE_SIZE);
    if maximum == 0 || QUEUE_SIZE > maximum {
        write_u8(mmio, REG_STATUS, STATUS_FAILED as u8);
        trace_fmt(alloc::format!(
            "virtio-input: queue size {} < required {}\r\n",
            maximum,
            QUEUE_SIZE
        ));
        return None;
    }

    let mut queue = allocate_queue(QUEUE_SIZE)?;
    write_u16(mmio, REG_QUEUE_SIZE, QUEUE_SIZE);
    write_u32(mmio, REG_QUEUE_DESC_LO, queue.descriptor_physical as u32);
    write_u32(
        mmio,
        REG_QUEUE_DESC_HI,
        (queue.descriptor_physical >> 32) as u32,
    );
    let avail_physical = queue.descriptor_physical + queue.avail_offset;
    write_u32(mmio, REG_QUEUE_AVAIL_LO, avail_physical as u32);
    write_u32(mmio, REG_QUEUE_AVAIL_HI, (avail_physical >> 32) as u32);
    let used_physical = queue.descriptor_physical + queue.used_offset;
    write_u32(mmio, REG_QUEUE_USED_LO, used_physical as u32);
    write_u32(mmio, REG_QUEUE_USED_HI, (used_physical >> 32) as u32);
    queue.notify_off = read_u16(mmio, REG_QUEUE_NOTIFY_OFF);

    // Pre-fill the available ring BEFORE the queue goes live so the
    // device has somewhere to write events from the first interrupt.
    for _ in 0..QUEUE_SIZE {
        if let Some(index) = add_event_buffer(&mut queue) {
            push_available(&queue, index);
        }
    }

    // Enable the queue, then signal driver readiness.
    write_u16(mmio, REG_QUEUE_ENABLE, 1);
    let status = u32::from(read_u8(mmio, REG_STATUS));
    write_u8(mmio, REG_STATUS, (status | STATUS_DRIVER_OK) as u8);
    Some(queue)
}

fn allocate_device(
    notify: *mut u8,
    isr: *mut u8,
    multiplier: u32,
    queue: Queue,
) -> Option<*mut Device> {
    let allocation =
        pool::allocate_tagged(PoolType::NonPaged, size_of::<Device>(), QUEUE_BUFFER_TAG);
    if allocation.is_null() {
        return None;
    }
    let device = allocation.cast::<Device>();
    unsafe {
        device.write(Device {
            notify,
            isr,
            notify_multiplier: multiplier.max(1),
            queue,
            shift: false,
            caps_lock: false,
        });
    }
    Some(device)
}

fn allocate_queue(size: u16) -> Option<Queue> {
    let count = usize::from(size);
    let descriptor_bytes = count * size_of::<Descriptor>();
    let available_bytes = 4 + count * 2;
    let used_bytes = 4 + count * size_of::<UsedElement>();
    let total_bytes = descriptor_bytes + available_bytes + used_bytes;
    let allocation = pool::allocate_aligned(PoolType::NonPaged, total_bytes, 4096);
    if allocation.is_null() {
        return None;
    }
    unsafe {
        core::ptr::write_bytes(allocation, 0, total_bytes);
        let mut queue = Queue {
            descriptors: allocation.cast::<Descriptor>(),
            available: allocation.add(descriptor_bytes).cast::<AvailableRing>(),
            used: allocation
                .add(descriptor_bytes + available_bytes)
                .cast::<UsedRing>(),
            descriptor_physical: 0,
            avail_offset: 0,
            used_offset: 0,
            notify_off: 0,
            buffers: [core::ptr::null_mut(); QUEUE_SIZE as usize],
            next_free: 0,
            used_index: 0,
        };
        (*queue.available).index = AtomicU16::new(0);
        (*queue.used).index = AtomicU16::new(0);
        queue.descriptor_physical = translate(allocation as u64)?;
        queue.avail_offset = descriptor_bytes as u64;
        queue.used_offset = (descriptor_bytes + available_bytes) as u64;
        for index in 0..count as u16 {
            (*queue.descriptors.add(usize::from(index))).next =
                index.wrapping_add(1).rem_euclid(size);
        }
        Some(queue)
    }
}
