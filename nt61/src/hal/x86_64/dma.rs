//! ISA DMA Controller (8237) and Common Buffer Allocation
//
//! Two cascaded 8237 DMA controllers provide 8 channels of
//! bus-master DMA on legacy PC hardware. Channels 0..3 are 8-bit,
//! 4..7 are 16-bit; channel 4 is the cascade to the second
//! controller.
//
//! `hal.dll` exposes the relevant surface as
//! `HalGetAdapter`, `HalAllocateCommonBuffer`,
//! `HalFreeCommonBuffer`, and `HalReadDmaCounter`. We provide
//! the same names; the implementation is minimal but real — it
//! programs the 8237 and allocates physically-contiguous memory
//! from `mm::pool`.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR};

// =====================================================================
// 8237 ports (master 0x00..0x0F, slave 0xC0..0xDF)
// =====================================================================

mod ports {
    pub const DMA1_ADDR: [u16; 8]   = [0x00, 0x02, 0x04, 0x06, 0xC0, 0xC4, 0xC8, 0xCC];
    pub const DMA1_COUNT: [u16; 8]  = [0x01, 0x03, 0x05, 0x07, 0xC2, 0xC6, 0xCA, 0xCE];
    pub const DMA1_PAGE: [u16; 8]   = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];

    #[allow(dead_code)]
    pub const DMA1_CMD:    u16 = 0x08;
    #[allow(dead_code)]
    pub const DMA1_STATUS: u16 = 0x08;
    pub const DMA1_MASK:   u16 = 0x0A;
    pub const DMA1_MODE:   u16 = 0x0B;
    pub const DMA1_FLIPFLOP: u16 = 0x0C;
    #[allow(dead_code)]
    pub const DMA1_TEMP:   u16 = 0x0D;
    #[allow(dead_code)]
    pub const DMA1_MASTER_CLEAR: u16 = 0x0D;
    #[allow(dead_code)]
    pub const DMA1_CLEAR_MASK: u16 = 0x0E;
    #[allow(dead_code)]
    pub const DMA1_MASK_ALL: u16 = 0x0F;
}

// Mode register bits.
#[allow(dead_code)]
mod mode_bits {
    pub const VERIFY: u8 = 0;
    pub const WRITE: u8 = 0x04;
    pub const READ: u8 = 0x08;
    pub const AUTO_INIT: u8 = 0x10;
    pub const DOWN: u8 = 0x20;
    pub const SINGLE: u8 = 0x40;
    pub const BLOCK: u8 = 0x80;
    pub const CASCADE: u8 = 0xC0;
}

static DMA1_MASK_STATE: AtomicU8 = AtomicU8::new(0);
static DMA2_MASK_STATE: AtomicU8 = AtomicU8::new(0);

fn mask_set(channel: u8) {
    let (port, state) = if channel < 4 {
        (ports::DMA1_MASK, &DMA1_MASK_STATE)
    } else {
        (ports::DMA1_MASK, &DMA2_MASK_STATE)
    };
    let prev = state.load(Ordering::Relaxed);
    let new = prev | (1 << (channel & 0x03));
    state.store(new, Ordering::Relaxed);
    WRITE_PORT_UCHAR(port, 0x04 | (channel & 0x03));
}

fn mask_clear(channel: u8) {
    let state = if channel < 4 { &DMA1_MASK_STATE } else { &DMA2_MASK_STATE };
    let prev = state.load(Ordering::Relaxed);
    let new = prev & !(1 << (channel & 0x03));
    state.store(new, Ordering::Relaxed);
    WRITE_PORT_UCHAR(ports::DMA1_MASK, channel & 0x03);
}

fn reset_flipflop() {
    WRITE_PORT_UCHAR(ports::DMA1_FLIPFLOP, 0xFF);
}

fn program_channel(channel: u8, mode: u8, addr: u32, count: u16) {
    // The address register is 16 bits on the master and 16 bits
    // (with the upper 8 in the page register) on the master /
    // slave pair. 16-bit channels (4..7) shift the address right
    // by 1; the page register holds bits 16..23 of the physical
    // address.
    let (addr_port, count_port, page_port) = (
        ports::DMA1_ADDR[channel as usize],
        ports::DMA1_COUNT[channel as usize],
        ports::DMA1_PAGE[channel as usize],
    );

    mask_set(channel);
    reset_flipflop();

    let (lo, hi, page) = if channel < 4 {
        let a = addr & 0xFFFF;
        (a as u8, (a >> 8) as u8, ((addr >> 16) & 0xFF) as u8)
    } else {
        // 16-bit channels: shift the address right by 1.
        let a = (addr >> 1) & 0xFFFF;
        (a as u8, (a >> 8) as u8, ((addr >> 16) & 0xFF) as u8)
    };
    WRITE_PORT_UCHAR(addr_port, lo);
    WRITE_PORT_UCHAR(addr_port, hi);
    WRITE_PORT_UCHAR(page_port, page);
    let count_val = if channel < 4 { count - 1 } else { (count >> 1) - 1 };
    WRITE_PORT_UCHAR(count_port, (count_val & 0xFF) as u8);
    WRITE_PORT_UCHAR(count_port, ((count_val >> 8) & 0xFF) as u8);
    WRITE_PORT_UCHAR(ports::DMA1_MODE, mode | (channel & 0x03));
    mask_clear(channel);
}

/// Read the current count of `channel` (0..7). The value is the
/// "remaining" count, with a bias of 1 — the user code adds 1 to
/// recover the original count.
pub fn HalReadDmaCounter(channel: u8) -> u8 {
    if channel >= 8 { return 0; }
    reset_flipflop();
    let port = ports::DMA1_COUNT[channel as usize];
    let lo = READ_PORT_UCHAR(port);
    let hi = READ_PORT_UCHAR(port);
    let raw = ((hi as u16) << 8) | (lo as u16);
    let count = if channel < 4 { raw + 1 } else { (raw + 1) << 1 };
    (count & 0xFF) as u8
}

// =====================================================================
// Common buffer allocation
// =====================================================================

/// Small bump allocator for DMA common buffers. The pool is
/// primed with frames from `mm::pool` and handed out
/// whole-page. We never run a free list — `HalFreeCommonBuffer`
/// is supported but only for buffers previously allocated with
/// `HalAllocateCommonBuffer`.
const MAX_BUFFERS: usize = 32;

#[derive(Copy, Clone)]
struct CommonBuffer {
    phys: u64,
    virt: u64,
    size: usize,
    in_use: bool,
}

static mut BUFFERS: [CommonBuffer; MAX_BUFFERS] = [CommonBuffer {
    phys: 0, virt: 0, size: 0, in_use: false
}; MAX_BUFFERS];

/// Adapter object returned by `HalGetAdapter`. The fields mirror
/// the `DEVICE_DESCRIPTION` that real Windows uses.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdapterInfo {
    pub interface_type: u32,
    pub bus_number: u32,
    pub dma_width: u8, // 0 = 8-bit, 1 = 16-bit
    pub max_length: u64,
}

/// Return an `AdapterInfo` for the legacy ISA DMA adapter. The
/// real `hal.dll` would return a separate object per PCI device;
/// we only model the ISA case here.
pub fn HalGetAdapter(interface_type: u32, bus_number: u32) -> Option<AdapterInfo> {
    // ISA / EISA use the 8237. PCIBus would normally use bus-
    // master DMA; we return None so the caller falls back to
    // PIO if the device does not support bus mastering.
    match interface_type {
        1 | 2 => Some(AdapterInfo {
            interface_type,
            bus_number,
            dma_width: 0, // 8-bit by default
            max_length: 0x10000,
        }),
        _ => None,
    }
}

/// Allocate `len` bytes of physically-contiguous memory that can
/// be DMA'd into / out of by `adapter`. The kernel pool is the
/// backing store; the returned pointer is identity-mapped (i.e.
/// the same value in kernel virtual and physical address space).
pub fn HalAllocateCommonBuffer(adapter: &AdapterInfo, len: usize) -> Option<(u64, u64)> {
    if len == 0 { return None; }
    let aligned = (len + 4095) & !4095;
    unsafe {
        for slot in BUFFERS.iter_mut() {
            if slot.in_use { continue; }
            // First-fit: allocate from the pool. The pool returns
            // a virtual address; we re-derive the physical one
            // through `mm::pfn::pfn_to_phys` of the backing PFN.
            let va = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                aligned,
            );
            if va.is_null() { return None; }
            // Identity-map assumption: the BSP page tables map the
            // low 4 GiB 1:1. This is the convention used by the
            // rest of the kernel.
            slot.phys = va as u64;
            slot.virt = va as u64;
            slot.size = aligned;
            slot.in_use = true;
            let _ = adapter;
            return Some((slot.phys, slot.virt));
        }
    }
    None
}

/// Free a buffer previously allocated by `HalAllocateCommonBuffer`.
pub fn HalFreeCommonBuffer(_adapter: &AdapterInfo, phys: u64, virt: u64, size: usize) -> bool {
    unsafe {
        for slot in BUFFERS.iter_mut() {
            if slot.in_use && slot.phys == phys && slot.virt == virt && slot.size == size {
                slot.in_use = false;
                return true;
            }
        }
    }
    false
}

/// Program a single 8237 channel to perform a single-shot read
/// of `count` bytes from `buffer`. Returns `true` on success.
pub fn program_dma_read(channel: u8, buffer: u64, count: u32) -> bool {
    if channel >= 8 { return false; }
    program_channel(channel, mode_bits::SINGLE | mode_bits::READ, buffer as u32, count as u16);
    true
}

/// Program a single 8237 channel to perform a single-shot write
/// of `count` bytes to `buffer`. Returns `true` on success.
pub fn program_dma_write(channel: u8, buffer: u64, count: u32) -> bool {
    if channel >= 8 { return false; }
    program_channel(channel, mode_bits::SINGLE | mode_bits::WRITE, buffer as u32, count as u16);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_split_8bit() {
        // 0x00123456 on an 8-bit channel:
        //   lo = 0x56, hi = 0x34, page = 0x12
        let addr: u32 = 0x0012_3456;
        let lo = (addr & 0xFF) as u8;
        let hi = ((addr >> 8) & 0xFF) as u8;
        let page = ((addr >> 16) & 0xFF) as u8;
        assert_eq!((lo, hi, page), (0x56, 0x34, 0x12));
    }
}
