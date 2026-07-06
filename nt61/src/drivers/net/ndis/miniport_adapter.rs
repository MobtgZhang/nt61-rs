//! Miniport Adapter Context
//
//! Each NIC instance is represented by a MiniportAdapterContext structure
//! that holds the NIC's state, send/receive queues, and NDIS attributes.
//
//! Clean-room implementation based on NDIS 6.0 specification.

use crate::drivers::net::NicType;
use crate::mm::pool::{self, PoolType};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Pool tags
mod tags {
    use crate::mm::pool::make_tag;
    pub const MPADAPTER: u32 = make_tag(b'M', b'I', b'N', b'I');
}

/// Media type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    WiredEthernet = 0,
    WirelessWan = 1,
    Tunnel = 2,
    Unknown = 3,
}

/// NIC capabilities
#[repr(C)]
pub struct NicCapabilities {
    pub max_frame_size: u32,
    pub min_frame_size: u32,
    pub current_mac: [u8; 6],
    pub max_tx_buffers: u32,
    pub max_rx_buffers: u32,
    pub link_speed: u64,        // in 100 bps units
    pub media_type: MediaType,
    pub supported_oids: u64,   // bitmask of supported OIDs
}

impl Default for NicCapabilities {
    fn default() -> Self {
        Self {
            max_frame_size: 1514,
            min_frame_size: 60,
            current_mac: [0; 6],
            max_tx_buffers: 64,
            max_rx_buffers: 64,
            link_speed: 100_000_000, // 100 Mbps
            media_type: MediaType::WiredEthernet,
            supported_oids: 0,
        }
    }
}

/// Statistics counters
#[repr(C)]
pub struct NicStats {
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_errors: AtomicU64,
}

impl Default for NicStats {
    fn default() -> Self {
        Self {
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
        }
    }
}

/// Miniport adapter context - one per NIC instance
pub struct MiniportAdapterContext {
    /// NIC type (virtio-net, e1000, rtl8139)
    pub nic_type: NicType,
    /// NIC index within its driver
    pub nic_index: usize,
    /// MAC address
    pub mac: [u8; 6],
    /// Link state
    pub link_up: bool,
    /// Capabilities
    pub capabilities: NicCapabilities,
    /// Statistics
    pub stats: NicStats,
    /// Transmit in progress
    pub sending: AtomicBool,
    /// Receive in progress
    pub receiving: AtomicBool,
    /// Lock for send/receive operations
    pub lock: Spinlock<()>,
    /// OID request lock
    pub oid_lock: Spinlock<()>,
    /// Current packet filter
    pub current_filter: u32,
    /// Promiscuous mode
    pub promiscuous: bool,
}

impl MiniportAdapterContext {
    /// Create a new adapter context
    pub fn new(nic_type: NicType, nic_index: usize) -> *mut MiniportAdapterContext {
        let ctx = pool::allocate_tagged(
            PoolType::NonPaged,
            core::mem::size_of::<MiniportAdapterContext>(),
            tags::MPADAPTER,
        ) as *mut MiniportAdapterContext;

        if ctx.is_null() {
            return core::ptr::null_mut();
        }

        unsafe {
            ptr::write_bytes(ctx, 0, 1);
            (*ctx).nic_type = nic_type;
            (*ctx).nic_index = nic_index;
            (*ctx).link_up = true;
            (*ctx).sending = AtomicBool::new(false);
            (*ctx).receiving = AtomicBool::new(false);
            (*ctx).lock = Spinlock::new(());
            (*ctx).oid_lock = Spinlock::new(());
            (*ctx).current_filter = 0;
            (*ctx).promiscuous = false;
            (*ctx).capabilities = NicCapabilities::default();
            (*ctx).stats = NicStats::default();
        }

        ctx
    }

    /// Free an adapter context
    pub fn free(ctx: *mut MiniportAdapterContext) {
        if !ctx.is_null() {
            pool::free_with_tag(ctx as *mut u8, tags::MPADAPTER);
        }
    }

    /// Set MAC address
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
        self.capabilities.current_mac = mac;
    }

    /// Update link state
    pub fn set_link_state(&mut self, up: bool) {
        self.link_up = up;
    }

    /// Increment TX counter
    pub fn tx_packet(&mut self, bytes: usize) {
        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Increment RX counter
    pub fn rx_packet(&mut self, bytes: usize) {
        self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Increment TX error counter
    pub fn tx_error(&mut self) {
        self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment RX error counter
    pub fn rx_error(&mut self) {
        self.stats.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Check if we can send
    pub fn can_send(&self) -> bool {
        !self.sending.load(Ordering::Relaxed) && self.link_up
    }

    /// Mark as sending
    pub fn start_send(&self) {
        self.sending.store(true, Ordering::Relaxed);
    }

    /// Mark as done sending
    pub fn end_send(&self) {
        self.sending.store(false, Ordering::Relaxed);
    }
}
