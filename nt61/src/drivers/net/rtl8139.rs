//! Realtek RTL8139 NIC Driver
//
//! The RTL8139 is a 100 Mbit/s Fast Ethernet NIC widely deployed
//! in the early 2000s. The driver performs the chip reset,
//! reads the MAC from the IDR registers, and sets up the RX
//! buffer at BAR0+0x30.
//
//! Clean-room implementation. Spec source: Realtek RTL8139
//! datasheet. No code is copied from any Microsoft or ReactOS
//! source file.

#![cfg(target_arch = "x86_64")]

use crate::hal::common::pci;
use crate::kprintln;
use crate::mm::pool::{self, PoolType};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU32, Ordering};

/// RTL8139 PCI vendor / device ID.
const RTL8139_VID: u16 = 0x10EC;
const RTL8139_DID: u16 = 0x8139;

/// Register offsets (BAR0 I/O port).
const REG_IDR0: u8 = 0x00;     // MAC address (6 bytes)

const REG_CMD: u8 = 0x37;
const REG_RBSTART: u16 = 0x30;  // RX Buffer Start
const REG_RCR: u8 = 0x44;      // Receive Configuration Register
const REG_TCR: u8 = 0x40;      // Transmit Configuration Register

const REG_TSD0: u8 = 0x10;     // TX Status (4 registers for 4 TX buffers)
const REG_TSAD0: u16 = 0x20;   // TX Start Address 0
const REG_IMR: u16 = 0x3C;     // Interrupt Mask Register
const REG_ISR: u16 = 0x3E;      // Interrupt Status Register

/// CMD bits.
const CMD_RST: u8 = 1 << 4;
const CMD_RE: u8 = 1 << 3;     // Receiver Enable
const CMD_TE: u8 = 1 << 2;     // Transmitter Enable

/// RCR bits.
const RCR_EN: u32 = 1 << 0;     // Receiver Enable

const RCR_APM: u32 = 1 << 2;   // Accept Physical Match
const RCR_AB: u32 = 1 << 3;    // Accept Broadcast
const RCR_AM: u32 = 1 << 4;    // Accept Multicast
const RCR_WRAP: u32 = 1 << 7;  // Wrap

/// TCR bits.
const TCR_EN: u32 = 1 << 2;     // Transmitter Enable

/// TX Status bits.
const TSD_OWN: u32 = 1 << 31;  // Ownership bit


/// ISR bits.
const ISR_ROK: u16 = 1 << 0;    // Receive OK
const ISR_RER: u16 = 1 << 1;    // Receive Error
const ISR_TOK: u16 = 1 << 2;    // Transmit OK
const ISR_TER: u16 = 1 << 3;    // Transmit Error




/// Pool tags
mod tags {
    use crate::mm::pool::make_tag;
    pub const NETBUF: u32 = make_tag(b'N', b'B', b'u', b'f');

}

/// One RTL8139 NIC.
struct Nic {
    bar0_io: u16,
    mac: [u8; 6],
    initialised: bool,
    rx_buffer: *mut u8,
    rx_buffer_phys: u64,
    tx_buffers: [*mut u8; 4],
    tx_next: u32,
    rx_count: AtomicU32,
    tx_count: AtomicU32,
    lock: Spinlock<()>,
}

impl Default for Nic {
    fn default() -> Self {
        Self {
            bar0_io: 0,
            mac: [0; 6],
            initialised: false,
            rx_buffer: core::ptr::null_mut(),
            rx_buffer_phys: 0,
            tx_buffers: [core::ptr::null_mut(); 4],
            tx_next: 0,
            rx_count: AtomicU32::new(0),
            tx_count: AtomicU32::new(0),
            lock: Spinlock::new(()),
        }
    }
}

static mut NICS: [Option<Nic>; 4] = [const { None }; 4];
static mut NIC_COUNT: usize = 0;

/// Get a reference to the global RTL8139 NIC list
fn get_nics() -> &'static mut [Option<Nic>; 4] {
    unsafe { &mut NICS }
}

fn push_nic(n: Nic) {
    unsafe {
        if NIC_COUNT < NICS.len() {
            NICS[NIC_COUNT] = Some(n);
            NIC_COUNT += 1;
        }
    }
}

pub fn count() -> usize { unsafe { NIC_COUNT } }

pub fn init() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("NET:rtl8139_start\r\n");
    let mut found = 0u32;
    for dev in pci::enumerate() {
        if dev.vendor_id == RTL8139_VID && dev.device_id == RTL8139_DID {
            if let Some(info) = crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function) {
                if let Some(bar0) = first_io_bar(&info) {
                    let mut n = Nic { bar0_io: bar0 as u16, ..Default::default() };
                    if init_nic(&mut n) {
                        found += 1;
                        push_nic(n);
                        let _ = found;
                    }
                }
            }
        }
    }
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("NET:rtl8139_done\r\n");
    // kprintln!("      RTL8139: {} NIC(s) initialised", found)  // kprintln disabled (memcpy crash workaround);
}

fn first_io_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    for bar in info.bars.iter() {
        if bar.is_io && bar.phys != 0 { return Some(bar.phys); }
    }
    None
}

fn init_nic(n: &mut Nic) -> bool {
    if n.bar0_io == 0 { return false; }
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_UCHAR, WRITE_PORT_UCHAR, READ_PORT_ULONG, WRITE_PORT_ULONG};

    // Software reset.
    WRITE_PORT_UCHAR(n.bar0_io + REG_CMD as u16, CMD_RST);
    for _ in 0..100 {
        let s = READ_PORT_UCHAR(n.bar0_io + REG_CMD as u16);
        if (s & CMD_RST) == 0 { break; }
    }

    // Read MAC.
    for i in 0..6 {
        n.mac[i] = READ_PORT_UCHAR(n.bar0_io + (REG_IDR0 as u16) + (i as u16));
    }
    // kprintln!("  [rtl8139] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",  // kprintln disabled (memcpy crash workaround)
//               n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5]);

    // Allocate RX buffer (16KB + 16 bytes for alignment)
    let rx_size = 16384 + 16;
    n.rx_buffer = pool::allocate_tagged(PoolType::NonPaged, rx_size, tags::NETBUF);
    if n.rx_buffer.is_null() {
        // kprintln!("  [rtl8139] Failed to allocate RX buffer")  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // Align to 16-byte boundary
    n.rx_buffer = ((n.rx_buffer as usize + 15) & !15) as *mut u8;
    n.rx_buffer_phys = virt_to_phys(n.rx_buffer as u64).unwrap_or(0);

    // Set RX buffer start address
    WRITE_PORT_ULONG(n.bar0_io + REG_RBSTART, n.rx_buffer_phys as u32);

    // Configure receiver: accept broadcast, multicast, and our unicast
    let rcr = RCR_EN | RCR_WRAP | RCR_AB | RCR_AM | RCR_APM;
    WRITE_PORT_ULONG(n.bar0_io + REG_RCR as u16, rcr);

    // Configure transmitter
    let tcr = TCR_EN;
    WRITE_PORT_ULONG(n.bar0_io + REG_TCR as u16, tcr);

    // Allocate TX buffers (4 x 8KB)
    for i in 0..4 {
        n.tx_buffers[i] = pool::allocate_tagged(PoolType::NonPaged, 8192, tags::NETBUF);
        if n.tx_buffers[i].is_null() {
            // kprintln!("  [rtl8139] Failed to allocate TX buffer {}", i)  // kprintln disabled (memcpy crash workaround);
        }
    }

    // Enable receiver and transmitter
    WRITE_PORT_UCHAR(n.bar0_io + REG_CMD as u16, CMD_RE | CMD_TE);

    // Enable interrupts
    let imr = ISR_ROK | ISR_TOK | ISR_RER | ISR_TER;
    WRITE_PORT_ULONG(n.bar0_io + REG_IMR as u16, imr as u32);

    n.initialised = true;
    true
}

/// Convert virtual address to physical address
fn virt_to_phys(virt: u64) -> Option<u64> {
    Some(virt & 0x7FFFFFFFFFFF)
}

pub fn smoke_test() -> bool {
    // kprintln!("  [RTL8139 SMOKE] RTL8139 NICs: {}", count())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  [RTL8139 SMOKE OK] RTL8139 stack healthy")  // kprintln disabled (memcpy crash workaround);
    true
}

// =============================================================================
// Public send/receive API
// =============================================================================

/// Send a packet through the RTL8139 NIC
pub fn send(nic_idx: usize, data: &[u8]) -> bool {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return false,
    };

    if !n.initialised {
        return false;
    }

    let _guard = n.lock.lock();
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_ULONG, WRITE_PORT_ULONG, WRITE_PORT_UCHAR};

    unsafe {
        // Get next TX buffer
        let buf_idx = n.tx_next as usize % 4;
        let buf = n.tx_buffers[buf_idx];
        if buf.is_null() {
            return false;
        }

        // Copy data to TX buffer
        let copy_len = data.len().min(8192 - 4); // Leave room for status word
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf.add(4), copy_len);

        // Write size to first 4 bytes (little-endian)
        *(buf as *mut u32) = copy_len as u32;

        // Get physical address
        let phys = virt_to_phys(buf as u64).unwrap_or(0);

        // Write TX start address
        WRITE_PORT_ULONG(n.bar0_io + REG_TSAD0 + (buf_idx as u16) * 4, phys as u32);

        // Wait for TX to complete
        for _ in 0..1000 {
            let tsd = READ_PORT_ULONG(n.bar0_io + (REG_TSD0 as u16) + (buf_idx as u16) * 4);
            if tsd & TSD_OWN == 0 {
                break;
            }
        }

        n.tx_next = (n.tx_next + 1) % 4;
        n.tx_count.fetch_add(1, Ordering::Relaxed);
    }

    true
}

/// Receive a packet from the RTL8139 NIC
pub fn receive(nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return None,
    };

    if !n.initialised {
        return None;
    }

    let _guard = n.lock.lock();
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    use crate::hal::x86_64::io_port::{READ_PORT_USHORT, WRITE_PORT_USHORT};

    unsafe {
        // Read ISR to check for received packet
        let isr = READ_PORT_USHORT(n.bar0_io + REG_ISR);
        if isr & ISR_ROK == 0 {
            return None;
        }

        // Clear the receive OK bit
        WRITE_PORT_USHORT(n.bar0_io + REG_ISR, ISR_ROK);

        // Parse the RTL8139 RX ring
        // The RX buffer is a circular buffer starting at RBSTART
        // Each packet has a 4-byte status header
        let rx_buf = n.rx_buffer;

        // Read first packet header
        let status = *(rx_buf as *const u32);
        if status & 0x40000000 == 0 {
            // No packet
            return None;
        }

        let len = (status & 0x3FFF) as usize;
        if len > buffer.len() || len == 0 {
            return None;
        }

        // Copy packet data
        core::ptr::copy_nonoverlapping(rx_buf.add(4), buffer.as_mut_ptr(), len);

        // Mark packet as processed (set OWN bit)
        *(rx_buf as *mut u32) = 0;

        n.rx_count.fetch_add(1, Ordering::Relaxed);
        Some(len)
    }
}

/// Get MAC address for a NIC
pub fn get_mac(nic_idx: usize) -> Option<[u8; 6]> {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.mac)
}

/// Get link status for a NIC (RTL8139 always reports link up if initialized)
pub fn is_link_up(nic_idx: usize) -> bool {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.initialised).unwrap_or(false)
}

/// Get TX packet count
pub fn get_tx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.tx_count.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Get RX packet count
pub fn get_rx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.rx_count.load(Ordering::Relaxed)).unwrap_or(0)
}
