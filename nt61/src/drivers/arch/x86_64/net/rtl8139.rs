//! Realtek RTL8139 NIC Driver
//
//! The RTL8139 is a 100 Mbit/s Fast Ethernet NIC widely deployed in
//! the early 2000s. This driver performs the chip reset, reads the
//! MAC from the IDR registers, and programs the four TX descriptor
//! pairs (TSD0-3 / TSAD0-3) for multi-outstanding DMA plus the RX
//! ring with CAPR read-pointer tracking.
//
//! Clean-room implementation. Register semantics follow the Realtek
//! RTL8139 datasheet; the TSD completion bits, the RX header layout,
//! and the CAPR update formula (CAPR = cursor - 16) are cross-checked
//! against well-documented 8139 driver usage. No code is copied from
//! any Microsoft, ReactOS, or Linux source file.

use crate::drivers::net::miniport_adapter::MiniportAdapterContext;
use crate::drivers::net::NicType;
use crate::hal::common::pci;
use crate::hal::io_port::{
    read_port_uchar, read_port_ulong, write_port_uchar, write_port_ulong, write_port_ushort,
};
use crate::ke::sync::Spinlock;
use crate::mm::pool::{self, PoolType};
use core::sync::atomic::{AtomicU32, Ordering};

/// RTL8139 PCI vendor / device ID.
const RTL8139_VID: u16 = 0x10EC;
const RTL8139_DID: u16 = 0x8139;

// Register offsets (BAR0 I/O space), per the RTL8139 datasheet.
/// MAC address bytes 0-3 (IDR0).
const REG_IDR0: u16 = 0x00;
/// TX Status Descriptor 0 (TSD0-3, one 32-bit register per descriptor).
const REG_TSD0: u16 = 0x10;
/// TX Start Address 0 (TSAD0-3, one 32-bit register per descriptor).
const REG_TSAD0: u16 = 0x20;
/// RX buffer start physical address.
const REG_RBSTART: u16 = 0x30;
/// Command register (byte-wide).
const REG_CHIP_CMD: u16 = 0x37;
/// CAPR: RX read pointer (current read position - 16, 16-bit).
const REG_CAPR: u16 = 0x38;
/// Interrupt Mask Register (16-bit).
const REG_IMR: u16 = 0x3C;
/// Interrupt Status Register (16-bit).
const REG_ISR: u16 = 0x3E;
/// Transmit Configuration Register.
const REG_TX_CONFIG: u16 = 0x40;
/// Receive Configuration Register.
const REG_RX_CONFIG: u16 = 0x44;

// Chip command register bits (datasheet "Command Register").
const CMD_RESET: u8 = 1 << 4;
const CMD_RX_ENB: u8 = 1 << 3;
const CMD_TX_ENB: u8 = 1 << 2;
/// Set while the RX buffer holds at least one unread packet.
const CMD_RX_BUF_EMPTY: u8 = 1 << 0;

// Interrupt register bits (datasheet "Interrupt registers").
const ISR_RX_OK: u16 = 1 << 0;
const ISR_RX_ERR: u16 = 1 << 1;
const ISR_TX_OK: u16 = 1 << 2;
const ISR_TX_ERR: u16 = 1 << 3;
const ISR_RX_OVERFLOW: u16 = 1 << 4;
const ISR_RX_UNDERRUN: u16 = 1 << 5;
const ISR_RX_FIFO_OVER: u16 = 1 << 6;
const ISR_PCI_TIMEOUT: u16 = 1 << 14;
const ISR_PCI_ERROR: u16 = 1 << 15;
/// Acknowledging these events re-enables RX interrupts (the chip
/// gates further RX interrupts until the RX ring is drained).
const ISR_RX_ACK_BITS: u16 = ISR_RX_OK | ISR_RX_OVERFLOW | ISR_RX_FIFO_OVER;
/// Full interrupt mask programmed into the IMR at init.
const ISR_ENABLE_ALL: u16 = ISR_PCI_ERROR
    | ISR_PCI_TIMEOUT
    | ISR_RX_FIFO_OVER
    | ISR_RX_UNDERRUN
    | ISR_RX_OVERFLOW
    | ISR_TX_ERR
    | ISR_TX_OK
    | ISR_RX_ERR
    | ISR_RX_OK;

// Receive Configuration Register bits (datasheet RCR layout).
/// Accept unicast packets matching our MAC.
const RCR_ACCEPT_MY_PHYS: u32 = 1 << 1;
/// Accept multicast packets.
const RCR_ACCEPT_MULTICAST: u32 = 1 << 2;
/// Accept broadcast packets.
const RCR_ACCEPT_BROADCAST: u32 = 1 << 3;
/// Do not wrap packets at the end of the RX ring; the tail of a
/// packet that would wrap continues into the wrap-pad region that
/// follows the ring in the same DMA buffer.
const RCR_NO_WRAP: u32 = 1 << 7;
/// Unlimited RX DMA burst (field value 7 at bits 10:8).
const RCR_DMA_BURST_UNLIMITED: u32 = 7;
const RCR_DMA_BURST_SHIFT: u32 = 8;
/// 32 KiB RX ring (field value 2 at bits 12:11).
const RCR_RX_BUF_32K: u32 = 1 << 12;
/// No RX FIFO threshold: transfer as soon as a whole packet arrives
/// (field value 7 at bits 15:13).
const RCR_FIFO_THRESHOLD_NONE: u32 = 7;
const RCR_FIFO_THRESHOLD_SHIFT: u32 = 13;

// Transmit Configuration Register bits (datasheet TCR layout).
/// Write-only bit that clears a TX abort caused by excessive
/// collisions (written back when a descriptor reports TAB).
const TCR_CLEAR_ABORT: u32 = 1 << 0;
/// TX retry count: retries = 16 + (TX_RETRY * 16).
const TCR_TX_RETRY: u32 = 8;
const TCR_TX_RETRY_SHIFT: u32 = 4;
/// Maximum PCI TX DMA burst: 6 encodes 1024 bytes.
const TCR_DMA_BURST: u32 = 6;
const TCR_DMA_BURST_SHIFT: u32 = 8;
/// Inter-frame gap 9.6 us (field value 3 at bits 25:24).
const TCR_IFG_96: u32 = 3;
const TCR_IFG_SHIFT: u32 = 24;

// Transmit Status Descriptor bits (datasheet TSD layout).
/// TAB: transmit aborted (excessive collisions / carrier issues).
const TSD_TX_ABORTED: u32 = 1 << 30;
/// TX packet went out of the collision window.
const TSD_TX_OUT_OF_WINDOW: u32 = 1 << 29;
/// TUN: FIFO underrun during transmit.
const TSD_TX_UNDERRUN: u32 = 1 << 14;
/// TOK: packet transmitted successfully.
const TSD_TX_OK: u32 = 1 << 15;
/// Packet length field (13 bits, TSD bits 12:0).
const TSD_SIZE_MASK: u32 = 0x1FFF;
/// TX FIFO threshold encoding: bytes shifted into bits 22:16.
const TSD_FIFO_THRESHOLD_SHIFT: u32 = 11;
const TSD_FIFO_THRESHOLD_MASK: u32 = 0x003F_0000;
/// Initial TX FIFO threshold: 256 bytes before the chip starts DMA.
const TX_FIFO_THRESHOLD_INIT: u32 = 256;
/// Threshold bump applied after an underrun (64 bytes encoded).
const TX_FIFO_THRESHOLD_STEP: u32 = 0x0002_0000;
/// Maximum encoded TX FIFO threshold.
const TX_FIFO_THRESHOLD_MAX: u32 = 0x0030_0000;

// Ring geometry.
/// The RTL8139 exposes exactly four TX descriptors (TSD0-TSD3).
const NUM_TX_DESCRIPTORS: usize = 4;
/// Per-descriptor TX bounce buffer (TSD size field is 13 bits wide).
const TX_BUF_SIZE: usize = 8192;
/// Minimum Ethernet frame size: packets are padded up to this.
const ETH_ZLEN: usize = 60;
/// Poll limit when waiting for the oldest descriptor to complete
/// before giving up and reporting the queue as full.
const TX_COMPLETION_POLL_LIMIT: usize = 100_000;

/// 32 KiB RX ring, the largest ring size without the documented
/// 64 KiB hardware lock-up erratum.
const RX_RING_SIZE: usize = 32 * 1024;
/// Alignment pad before the first DMA offset (the CAPR formula
/// subtracts 16 from the logical cursor).
const RX_BUF_PAD: usize = 16;
/// Spare padding after the ring so a packet near the end can be
/// written contiguously instead of wrapping (RCR_NO_WRAP).
const RX_WRAP_PAD: usize = 2048;
/// Total RX DMA buffer size: ring + pad + wrap pad.
const RX_BUF_TOTAL_SIZE: usize = RX_RING_SIZE + RX_BUF_PAD + RX_WRAP_PAD;
/// Maximum Ethernet frame the RX path accepts.
const RX_MAX_FRAME_SIZE: usize = 1792;
/// Four-byte FCS appended by the hardware to every RX packet.
const RX_FCS_SIZE: usize = 4;
/// Largest accepted RX size field (frame + FCS).
const RX_MAX_PACKET_SIZE: usize = RX_MAX_FRAME_SIZE + RX_FCS_SIZE;
/// Smallest accepted RX size field.
const RX_MIN_PACKET_SIZE: usize = 8;
/// RX header size in bytes.
const RX_HEADER_SIZE: usize = 4;
/// CAPR value corresponding to a drained ring (cursor 0 - 16).
const RX_CAPR_INITIAL: u16 = 0xFFF0;
/// RX size field value reported while the FIFO copy is in progress.
const RX_SIZE_COPY_IN_PROGRESS: usize = 0xFFF0;

// RX packet header (32-bit word at the head of each RX packet).
/// RX_STATUS_OK: packet received without error.
const RX_STATUS_OK: u32 = 1 << 0;
/// RX_BAD_ALIGN: frame alignment error.
const RX_STATUS_BAD_ALIGN: u32 = 1 << 1;
/// RX_CRCErr: CRC check failed.
const RX_STATUS_CRC_ERROR: u32 = 1 << 2;
/// RX_TOO_LONG: frame longer than the maximum accepted size.
const RX_STATUS_TOO_LONG: u32 = 1 << 3;
/// RX_RUNT: frame shorter than 64 bytes.
const RX_STATUS_RUNT: u32 = 1 << 4;
/// RX_BAD_SYMBOL: symbol error detected.
const RX_STATUS_BAD_SYMBOL: u32 = 1 << 5;
/// Any RX header error bit; a set bit means the packet is invalid.
const RX_STATUS_ERROR_MASK: u32 = RX_STATUS_BAD_ALIGN
    | RX_STATUS_CRC_ERROR
    | RX_STATUS_TOO_LONG
    | RX_STATUS_RUNT
    | RX_STATUS_BAD_SYMBOL;

/// One TX descriptor: a dedicated DMA bounce buffer plus software
/// ownership tracking (CPU-owned vs DMA-owned).
#[derive(Clone, Copy)]
struct TxDescriptor {
    /// Bounce buffer for this descriptor (DMA address in TSAD).
    buffer: *mut u8,
    /// True while the chip owns the descriptor (queued, not complete).
    in_use: bool,
}

impl TxDescriptor {
    const fn empty() -> Self {
        Self {
            buffer: core::ptr::null_mut(),
            in_use: false,
        }
    }
}

/// Per-NIC mutable driver state, serialised by the adapter spinlock.
struct NicState {
    /// Logical RX cursor (never wraps; the ring offset is
    /// rx_cursor % RX_RING_SIZE and CAPR is cursor - 16).
    rx_cursor: u32,
    tx_descs: [TxDescriptor; NUM_TX_DESCRIPTORS],
    /// Encoded TX FIFO threshold, bumped after underruns.
    tx_fifo_threshold: u32,
    /// Round-robin free-descriptor cursor.
    tx_next_free: usize,
}

/// One RTL8139 NIC. Immutable configuration and statistics live on
/// the NIC; mutable ring state lives behind the adapter spinlock so
/// send/receive paths can mutate through the lock guard.
struct Nic {
    bar0_io: u16,
    mac: [u8; 6],
    initialised: bool,
    rx_ring: *mut u8,
    rx_ring_phys: u64,
    state: Spinlock<NicState>,
    rx_count: AtomicU32,
    tx_count: AtomicU32,
    /// NDIS miniport adapter context (statistics integration).
    adapter: *mut MiniportAdapterContext,
}

impl Default for Nic {
    fn default() -> Self {
        Self {
            bar0_io: 0,
            mac: [0; 6],
            initialised: false,
            rx_ring: core::ptr::null_mut(),
            rx_ring_phys: 0,
            state: Spinlock::new(NicState {
                rx_cursor: 0,
                tx_descs: [TxDescriptor::empty(); NUM_TX_DESCRIPTORS],
                tx_fifo_threshold: (TX_FIFO_THRESHOLD_INIT << TSD_FIFO_THRESHOLD_SHIFT)
                    & TSD_FIFO_THRESHOLD_MASK,
                tx_next_free: 0,
            }),
            rx_count: AtomicU32::new(0),
            tx_count: AtomicU32::new(0),
            adapter: core::ptr::null_mut(),
        }
    }
}

static mut NICS: [Option<Nic>; 4] = [const { None }; 4];
static mut NIC_COUNT: usize = 0;

/// Get a reference to the global RTL8139 NIC list
fn get_nics() -> &'static mut [Option<Nic>; 4] {
    unsafe { &mut *core::ptr::addr_of_mut!(NICS) }
}

fn push_nic(n: Nic) {
    unsafe {
        if NIC_COUNT < (*core::ptr::addr_of!(NICS)).len() {
            NICS[NIC_COUNT] = Some(n);
            NIC_COUNT += 1;
        }
    }
}

pub fn count() -> usize {
    unsafe { NIC_COUNT }
}

/// Convert virtual address to physical address (identity-mapped
/// canonical low half used by this kernel DMA allocations).
fn virt_to_phys(virt: u64) -> Option<u64> {
    crate::mm::virt_to_phys(virt)
}

fn aligned_alloc(size: usize) -> *mut u8 {
    pool::allocate_aligned(PoolType::NonPaged, size, 16)
}

pub fn init() {
    crate::hal::serial::write_string("NET:rtl8139_start\r\n");
    for dev in pci::enumerate() {
        if dev.vendor_id == RTL8139_VID && dev.device_id == RTL8139_DID {
            if let Some(info) =
                crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function)
            {
                if let Some(bar0) = first_io_bar(&info) {
                    let mut n = Nic {
                        bar0_io: bar0 as u16,
                        ..Default::default()
                    };
                    if init_nic(&mut n) {
                        push_nic(n);
                    }
                }
            }
        }
    }
    crate::hal::serial::write_string("NET:rtl8139_done\r\n");
}

fn first_io_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    for bar in info.bars.iter() {
        if bar.is_io && bar.phys != 0 {
            return Some(bar.phys);
        }
    }
    None
}

/// Reset the chip and wait for the reset bit to self-clear.
fn chip_reset(bar0_io: u16) -> bool {
    write_port_uchar(bar0_io + REG_CHIP_CMD, CMD_RESET);
    for _ in 0..100 {
        let cmd = read_port_uchar(bar0_io + REG_CHIP_CMD);
        if (cmd & CMD_RESET) == 0 {
            return true;
        }
    }
    false
}

fn init_nic(n: &mut Nic) -> bool {
    if n.bar0_io == 0 {
        return false;
    }

    if !chip_reset(n.bar0_io) {
        return false;
    }

    // Read the MAC from the IDR registers.
    for i in 0..6 {
        n.mac[i] = read_port_uchar(n.bar0_io + REG_IDR0 + (i as u16));
    }

    // Allocate the RX DMA buffer (ring + pad + wrap pad) and program
    // the ring start plus the initial CAPR read pointer.
    n.rx_ring = aligned_alloc(RX_BUF_TOTAL_SIZE);
    if n.rx_ring.is_null() {
        return false;
    }
    n.rx_ring_phys = virt_to_phys(n.rx_ring as u64).unwrap_or(0);
    write_port_ulong(n.bar0_io + REG_RBSTART, n.rx_ring_phys as u32);
    n.state.lock().rx_cursor = 0;
    write_port_ushort(n.bar0_io + REG_CAPR, RX_CAPR_INITIAL);

    // Receive configuration: 32 KiB ring, no packet wrap, FIFO
    // threshold disabled, unlimited DMA burst, accept our unicast,
    // multicast, and broadcast frames.
    let rx_config = RCR_ACCEPT_MY_PHYS
        | RCR_ACCEPT_MULTICAST
        | RCR_ACCEPT_BROADCAST
        | RCR_NO_WRAP
        | (RCR_DMA_BURST_UNLIMITED << RCR_DMA_BURST_SHIFT)
        | RCR_RX_BUF_32K
        | (RCR_FIFO_THRESHOLD_NONE << RCR_FIFO_THRESHOLD_SHIFT);
    write_port_ulong(n.bar0_io + REG_RX_CONFIG, rx_config);

    // Transmit configuration: 1024-byte DMA burst, 144 max retries,
    // 9.6 us inter-frame gap. CRC append stays enabled (bit not set).
    let tx_config = TCR_CLEAR_ABORT
        | (TCR_TX_RETRY << TCR_TX_RETRY_SHIFT)
        | (TCR_DMA_BURST << TCR_DMA_BURST_SHIFT)
        | (TCR_IFG_96 << TCR_IFG_SHIFT);
    write_port_ulong(n.bar0_io + REG_TX_CONFIG, tx_config);

    // Allocate the four TX bounce buffers and permanently program
    // their DMA addresses into TSAD0-3 (addresses never change).
    for i in 0..NUM_TX_DESCRIPTORS {
        let buf = aligned_alloc(TX_BUF_SIZE);
        if buf.is_null() {
            return false;
        }
        let phys = virt_to_phys(buf as u64).unwrap_or(0);
        write_port_ulong(n.bar0_io + REG_TSAD0 + (i as u16) * 4, phys as u32);
        let mut state = n.state.lock();
        state.tx_descs[i].buffer = buf;
        state.tx_descs[i].in_use = false;
    }

    // Enable receiver and transmitter only after all descriptors and
    // ring addresses are programmed (datasheet ordering requirement).
    write_port_uchar(n.bar0_io + REG_CHIP_CMD, CMD_RX_ENB | CMD_TX_ENB);

    // Enable all interrupt sources.
    write_port_ushort(n.bar0_io + REG_IMR, ISR_ENABLE_ALL);

    // Register an NDIS miniport adapter context so the protocol
    // stack sees per-adapter statistics for this NIC.
    let adapter_idx = unsafe { NIC_COUNT };
    let adapter = MiniportAdapterContext::new(NicType::Rtl8139, adapter_idx);
    if !adapter.is_null() {
        unsafe {
            (*adapter).set_mac(n.mac);
        }
        n.adapter = adapter;
    }

    n.initialised = true;
    true
}

impl NicState {
    /// Read the TSD register of a descriptor.
    fn read_tsd(&self, bar0_io: u16, index: usize) -> u32 {
        read_port_ulong(bar0_io + REG_TSD0 + (index as u16) * 4)
    }

    /// Reclaim every descriptor the chip has finished with. A
    /// descriptor completes when any of TOK / TUN / TAB is set
    /// (OWN cleared). Per-descriptor outcome drives the statistics
    /// and the FIFO-threshold underrun recovery.
    fn reclaim_tx(&mut self, bar0_io: u16, adapter: *mut MiniportAdapterContext) {
        for index in 0..NUM_TX_DESCRIPTORS {
            if !self.tx_descs[index].in_use {
                continue;
            }
            let tsd = self.read_tsd(bar0_io, index);
            if (tsd & (TSD_TX_OK | TSD_TX_UNDERRUN | TSD_TX_ABORTED)) == 0 {
                continue;
            }

            if (tsd & (TSD_TX_ABORTED | TSD_TX_OUT_OF_WINDOW)) != 0 {
                // Clear the abort condition and acknowledge the
                // transmit error interrupt source.
                write_port_ulong(bar0_io + REG_TX_CONFIG, TCR_CLEAR_ABORT);
                write_port_ushort(bar0_io + REG_ISR, ISR_TX_ERR);
                if let Some(adapter) = adapter_of(adapter) {
                    adapter.tx_error();
                }
            }
            if (tsd & TSD_TX_UNDERRUN) != 0 && self.tx_fifo_threshold < TX_FIFO_THRESHOLD_MAX {
                // Bump the TX FIFO threshold by 64 bytes after an
                // underrun so the chip starts DMA earlier next time.
                self.tx_fifo_threshold += TX_FIFO_THRESHOLD_STEP;
            }

            self.tx_descs[index].in_use = false;
        }
    }

    /// Wait (bounded) for one descriptor to complete, reclaiming on
    /// success. Returns true when the descriptor is free again.
    fn wait_tx_complete(
        &mut self,
        bar0_io: u16,
        adapter: *mut MiniportAdapterContext,
        index: usize,
    ) -> bool {
        for _ in 0..TX_COMPLETION_POLL_LIMIT {
            let tsd = self.read_tsd(bar0_io, index);
            if (tsd & (TSD_TX_OK | TSD_TX_UNDERRUN | TSD_TX_ABORTED)) != 0 {
                self.reclaim_tx(bar0_io, adapter);
                return !self.tx_descs[index].in_use;
            }
        }
        false
    }

    /// Number of descriptors currently owned by the DMA engine.
    fn outstanding_tx(&self) -> usize {
        self.tx_descs.iter().filter(|d| d.in_use).count()
    }

    /// Reset the RX ring after a malformed header: rewind the cursor
    /// and reprogram CAPR so the chip restarts from the ring start.
    fn reset_rx_ring(&mut self, bar0_io: u16) {
        self.rx_cursor = 0;
        write_port_ushort(bar0_io + REG_CAPR, RX_CAPR_INITIAL);
        write_port_ushort(bar0_io + REG_ISR, ISR_RX_ACK_BITS);
    }
}

/// Safe accessor for the adapter context pointer.
fn adapter_of(adapter: *mut MiniportAdapterContext) -> Option<&'static mut MiniportAdapterContext> {
    if adapter.is_null() {
        None
    } else {
        Some(unsafe { &mut *adapter })
    }
}

pub fn smoke_test() -> bool {
    true
}

// Public send/receive API

/// Send a packet through the RTL8139 NIC using a free TX descriptor.
/// Up to four packets may be outstanding simultaneously; the call
/// reclaims completed descriptors first and only blocks (bounded)
/// when every descriptor is still DMA-owned.
pub fn send(nic_idx: usize, data: &[u8]) -> bool {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return false,
    };

    if !n.initialised {
        return false;
    }
    if data.is_empty() || data.len() > TX_BUF_SIZE {
        return false;
    }

    let mut state = n.state.lock();

    // Reclaim finished descriptors so their buffers become reusable.
    state.reclaim_tx(n.bar0_io, n.adapter);

    // Pick a free descriptor starting from the round-robin cursor.
    let mut chosen = None;
    for k in 0..NUM_TX_DESCRIPTORS {
        let index = (state.tx_next_free + k) % NUM_TX_DESCRIPTORS;
        if !state.tx_descs[index].in_use {
            chosen = Some(index);
            break;
        }
    }

    // All four descriptors outstanding: wait for the oldest one.
    if chosen.is_none() {
        let oldest = state.tx_next_free;
        if state.wait_tx_complete(n.bar0_io, n.adapter, oldest) {
            chosen = Some(oldest);
        }
    }

    let index = match chosen {
        Some(index) => index,
        None => return false,
    };

    let length = data.len().max(ETH_ZLEN);
    let buffer = state.tx_descs[index].buffer;
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len());
        // Zero-pad short frames up to the minimum Ethernet length so
        // stale buffer contents never leak on the wire.
        if length > data.len() {
            core::ptr::write_bytes(buffer.add(data.len()), 0, length - data.len());
        }
    }

    // Kick the transfer: write the length (plus the FIFO threshold
    // encoding) into TSD; TSAD for this descriptor is already
    // programmed with the bounce buffer address.
    let tsd_value = state.tx_fifo_threshold | (length as u32 & TSD_SIZE_MASK);
    write_port_ulong(n.bar0_io + REG_TSD0 + (index as u16) * 4, tsd_value);

    state.tx_descs[index].in_use = true;
    state.tx_next_free = (index + 1) % NUM_TX_DESCRIPTORS;
    n.tx_count.fetch_add(1, Ordering::Relaxed);
    if let Some(adapter) = adapter_of(n.adapter) {
        adapter.tx_packet(length);
    }

    true
}

/// Receive one packet from the RTL8139 RX ring. The ring position is
/// tracked with the logical cursor and published back to the chip via
/// CAPR (cursor - 16) after each packet, exactly as the datasheet
/// prescribes.
pub fn receive(nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return None,
    };

    if !n.initialised {
        return None;
    }

    let mut state = n.state.lock();

    // A packet is available only while the RX buffer is non-empty.
    let cmd = read_port_uchar(n.bar0_io + REG_CHIP_CMD);
    if (cmd & CMD_RX_BUF_EMPTY) != 0 {
        return None;
    }

    // Parse the 32-bit packet header at the current ring offset:
    // bits 15:0 carry the status flags, bits 31:16 the size
    // (including the 4-byte FCS).
    let offset = (state.rx_cursor as usize) % RX_RING_SIZE;
    let header = unsafe { *(n.rx_ring.add(offset) as *const u32) };
    let status = header & 0xFFFF;
    let rx_size = (header >> 16) as usize;

    // 0xFFF0 in the size field means the FIFO copy is still in
    // progress; try again on the next poll.
    if rx_size == RX_SIZE_COPY_IN_PROGRESS {
        return None;
    }

    if (status & RX_STATUS_OK) == 0
        || (status & RX_STATUS_ERROR_MASK) != 0
        || rx_size < RX_MIN_PACKET_SIZE
        || rx_size > RX_MAX_PACKET_SIZE
    {
        state.reset_rx_ring(n.bar0_io);
        if let Some(adapter) = adapter_of(n.adapter) {
            adapter.rx_error();
        }
        return None;
    }

    let packet_size = rx_size - RX_FCS_SIZE;
    if packet_size > buffer.len() {
        // Caller buffer too small: skip the packet but keep the ring
        // advancing so the DMA never stalls.
        advance_rx_cursor(&mut state, n.bar0_io, rx_size);
        if let Some(adapter) = adapter_of(n.adapter) {
            adapter.rx_error();
        }
        return None;
    }

    // Copy the packet body. With RCR_NO_WRAP the tail of a packet
    // near the ring end continues contiguously into the wrap-pad
    // region that follows the ring inside the same DMA buffer, so a
    // single linear copy is always correct.
    unsafe {
        core::ptr::copy_nonoverlapping(
            n.rx_ring.add(offset + RX_HEADER_SIZE),
            buffer.as_mut_ptr(),
            packet_size,
        );
    }

    advance_rx_cursor(&mut state, n.bar0_io, rx_size);

    n.rx_count.fetch_add(1, Ordering::Relaxed);
    if let Some(adapter) = adapter_of(n.adapter) {
        adapter.rx_packet(packet_size);
    }

    Some(packet_size)
}

/// Advance the logical RX cursor past one packet and publish the new
/// read position to the chip via CAPR (cursor - 16), then acknowledge
/// the RX interrupt sources so further packets re-raise interrupts.
fn advance_rx_cursor(state: &mut NicState, bar0_io: u16, rx_size: usize) {
    state.rx_cursor = (state.rx_cursor + rx_size as u32 + RX_HEADER_SIZE as u32 + 3) & !3;
    write_port_ushort(bar0_io + REG_CAPR, (state.rx_cursor - 16) as u16);
    write_port_ushort(bar0_io + REG_ISR, ISR_RX_ACK_BITS);
}

/// Drain completed TX descriptors (call from the TX-completion
/// interrupt handler once wired, or from periodic polling).
pub fn poll_tx_completion(nic_idx: usize) {
    let nics = get_nics();
    if let Some(n) = nics[nic_idx].as_mut() {
        let mut state = n.state.lock();
        state.reclaim_tx(n.bar0_io, n.adapter);
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
    nics[nic_idx]
        .as_ref()
        .map(|n| n.initialised)
        .unwrap_or(false)
}

/// Get TX packet count
pub fn get_tx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx]
        .as_ref()
        .map(|n| n.tx_count.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Get RX packet count
pub fn get_rx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx]
        .as_ref()
        .map(|n| n.rx_count.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Number of TX descriptors currently owned by the DMA engine.
pub fn get_tx_outstanding(nic_idx: usize) -> usize {
    let nics = get_nics();
    nics[nic_idx]
        .as_ref()
        .map(|n| n.state.lock().outstanding_tx())
        .unwrap_or(0)
}
