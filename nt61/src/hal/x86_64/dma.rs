//! ISA DMA Controller (8237) and Common buffer Allocation
//
//! Two cascaded 8237 DMA controllers provide 8 channels of
//! bus-master DMA on legacy PC hardware. Channels 0..3 are 8-bit,
//! 4..7 are 16-bit; channel 4 is the cascade to the second
//! controller.
//
//! `hal.dll` exposes the relevant surface as
//! `hal_get_adapter`, `hal_allocate_common_buffer`,
//! `hal_free_common_buffer`, and `hal_read_dma_counter`. We provide
//! the same names; the implementation is minimal but real — it
//! programs the 8237 and allocates physically-contiguous memory
//! from `mm::pool`.

#![cfg(target_arch = "x86_64")]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(target_arch = "x86_64")]
use crate::hal::x86_64::io_port::{read_port_uchar, write_port_uchar};

// =====================================================================
// 8237 ports (master 0x00..0x0F, slave 0xC0..0xDF)
// =====================================================================

mod ports {
    pub const DMA1_ADDR: [u16; 8] = [0x00, 0x02, 0x04, 0x06, 0xC0, 0xC4, 0xC8, 0xCC];
    pub const DMA1_COUNT: [u16; 8] = [0x01, 0x03, 0x05, 0x07, 0xC2, 0xC6, 0xCA, 0xCE];
    pub const DMA1_PAGE: [u16; 8] = [0x87, 0x83, 0x81, 0x82, 0x8F, 0x8B, 0x89, 0x8A];

    pub const DMA1_MASK: u16 = 0x0A;
    pub const DMA1_MODE: u16 = 0x0B;
    pub const DMA1_FLIPFLOP: u16 = 0x0C;
}

// Mode register bits.
mod mode_bits {
    pub const WRITE: u8 = 0x04;
    pub const READ: u8 = 0x08;
    pub const SINGLE: u8 = 0x40;
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
    write_port_uchar(port, 0x04 | (channel & 0x03));
}

fn mask_clear(channel: u8) {
    let state = if channel < 4 {
        &DMA1_MASK_STATE
    } else {
        &DMA2_MASK_STATE
    };
    let prev = state.load(Ordering::Relaxed);
    let new = prev & !(1 << (channel & 0x03));
    state.store(new, Ordering::Relaxed);
    write_port_uchar(ports::DMA1_MASK, channel & 0x03);
}

fn reset_flipflop() {
    write_port_uchar(ports::DMA1_FLIPFLOP, 0xFF);
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
    write_port_uchar(addr_port, lo);
    write_port_uchar(addr_port, hi);
    write_port_uchar(page_port, page);
    let count_val = if channel < 4 {
        count - 1
    } else {
        (count >> 1) - 1
    };
    write_port_uchar(count_port, (count_val & 0xFF) as u8);
    write_port_uchar(count_port, ((count_val >> 8) & 0xFF) as u8);
    write_port_uchar(ports::DMA1_MODE, mode | (channel & 0x03));
    mask_clear(channel);
}

/// read the current count of `channel` (0..7). The value is the
/// "remaining" count, with a bias of 1 — the user code adds 1 to
/// recover the original count.
pub fn hal_read_dma_counter(channel: u8) -> u8 {
    if channel >= 8 {
        return 0;
    }
    reset_flipflop();
    let port = ports::DMA1_COUNT[channel as usize];
    let lo = read_port_uchar(port);
    let hi = read_port_uchar(port);
    let raw = ((hi as u16) << 8) | (lo as u16);
    let count = if channel < 4 { raw + 1 } else { (raw + 1) << 1 };
    (count & 0xFF) as u8
}

// =====================================================================
// Common buffer allocation
// =====================================================================

/// Small bump allocator for DMA common buffers. The pool is
/// primed with frames from `mm::pool` and handed out
/// whole-page. We never run a free list — `hal_free_common_buffer`
/// is supported but only for buffers previously allocated with
/// `hal_allocate_common_buffer`.
const MAX_BUFFERS: usize = 32;

#[derive(Copy, Clone)]
struct CommonBuffer {
    phys: u64,
    virt: u64,
    size: usize,
    in_use: bool,
}

/// Common-buffer slot table. Guarded by a spin lock so concurrent
/// allocate/free calls from different CPUs cannot hand out the same
/// slot twice or free a slot that is being claimed (audit hal_rtl
/// P0-2: the previous `static mut` table had no synchronization).
struct CommonBufferTable {
    lock: AtomicBool,
    buffers: UnsafeCell<[CommonBuffer; MAX_BUFFERS]>,
}

// SAFETY: the slot array is only accessed through `UnsafeCell::get`
// while `lock` is held.
unsafe impl Sync for CommonBufferTable {}

static BUFFERS: CommonBufferTable = CommonBufferTable {
    lock: AtomicBool::new(false),
    buffers: UnsafeCell::new(
        [CommonBuffer {
            phys: 0,
            virt: 0,
            size: 0,
            in_use: false,
        }; MAX_BUFFERS],
    ),
};

fn lock_buffers() {
    while BUFFERS
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn unlock_buffers() {
    BUFFERS.lock.store(false, Ordering::Release);
}

/// Adapter object returned by `hal_get_adapter`. The fields mirror
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
pub fn hal_get_adapter(interface_type: u32, bus_number: u32) -> Option<AdapterInfo> {
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
pub fn hal_allocate_common_buffer(adapter: &AdapterInfo, len: usize) -> Option<(u64, u64)> {
    if len == 0 {
        return None;
    }
    let aligned = (len + 4095) & !4095;

    // The pool allocator can run arbitrary kernel code; hold the
    // slot lock only around the table scan, not across the pool call.
    for slot_index in 0..MAX_BUFFERS {
        lock_buffers();
        let slot_free = unsafe { (*BUFFERS.buffers.get())[slot_index].in_use == false };
        if !slot_free {
            unlock_buffers();
            continue;
        }
        // Reserve the slot before dropping the lock so two CPUs
        // racing on the same free slot cannot both claim it.
        unsafe {
            (*BUFFERS.buffers.get())[slot_index].in_use = true;
        }
        unlock_buffers();

        // First-fit: allocate from the pool. The pool returns
        // a virtual address; we re-derive the physical one
        // through `mm::pfn::pfn_to_phys` of the backing PFN.
        let va = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, aligned);
        if va.is_null() {
            // Give the slot back.
            lock_buffers();
            unsafe {
                (*BUFFERS.buffers.get())[slot_index].in_use = false;
            }
            unlock_buffers();
            return None;
        }
        // Translate the pool virtual address into the physical address
        // the DMA engine programs. The old code assumed the kernel low
        // mappings were 1:1 (BSP identity map), which produced wrong bus
        // addresses on any layout where kernel VA space is not mapped
        // identity. Translation failure is a hard error: guessing an
        // address would corrupt memory below the device.
        let phys = match crate::mm::virt_to_phys(va as u64) {
            Some(p) => p,
            None => {
                // Return the slot and the pool allocation instead of
                // handing out an untranslatable buffer.
                crate::mm::pool::free(va);
                lock_buffers();
                unsafe {
                    (*BUFFERS.buffers.get())[slot_index].in_use = false;
                }
                unlock_buffers();
                return None;
            }
        };
        lock_buffers();
        unsafe {
            let slot = &mut (*BUFFERS.buffers.get())[slot_index];
            slot.phys = phys;
            slot.virt = va as u64;
            slot.size = aligned;
        }
        unlock_buffers();
        let _ = adapter;
        return Some((va as u64, phys));
    }
    None
}

/// Free a buffer previously allocated by `hal_allocate_common_buffer`.
pub fn hal_free_common_buffer(_adapter: &AdapterInfo, phys: u64, virt: u64, size: usize) -> bool {
    lock_buffers();
    let mut found = false;
    unsafe {
        for slot in (*BUFFERS.buffers.get()).iter_mut() {
            if slot.in_use && slot.phys == phys && slot.virt == virt && slot.size == size {
                slot.in_use = false;
                found = true;
                break;
            }
        }
    }
    unlock_buffers();
    found
}

/// Program a single 8237 channel to perform a single-shot read
/// of `count` bytes from `buffer`. Returns `true` on success.
pub fn program_dma_read(channel: u8, buffer: u64, count: u32) -> bool {
    if channel >= 8 {
        return false;
    }
    program_channel(
        channel,
        mode_bits::SINGLE | mode_bits::READ,
        buffer as u32,
        count as u16,
    );
    true
}

/// Program a single 8237 channel to perform a single-shot write
/// of `count` bytes to `buffer`. Returns `true` on success.
pub fn program_dma_write(channel: u8, buffer: u64, count: u32) -> bool {
    if channel >= 8 {
        return false;
    }
    program_channel(
        channel,
        mode_bits::SINGLE | mode_bits::WRITE,
        buffer as u32,
        count as u16,
    );
    true
}

#[cfg(test)]
mod tests {

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
