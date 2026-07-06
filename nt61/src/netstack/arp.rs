//! ARP Protocol Implementation
//
//! Handles Address Resolution Protocol for mapping IP addresses to MAC addresses.
//
//! Clean-room implementation based on RFC 826.

use crate::netstack::eth::{self, ETHER_TYPE_ARP};
use crate::netstack::ipif;
use crate::netstack::ethif;
use crate::drivers::net::NicType;
use crate::ke::sync::Spinlock;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// ARP operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request = 1,
    Reply = 2,
}

/// ARP header structure
#[repr(C)]
pub struct ArpHeader {
    /// Hardware address type (1 = Ethernet)
    pub hw_type: u16,
    /// Protocol address type (0x0800 = IPv4)
    pub proto_type: u16,
    /// Hardware address length (6 for Ethernet)
    pub hw_size: u8,
    /// Protocol address length (4 for IPv4)
    pub proto_size: u8,
    /// Operation (1 = Request, 2 = Reply)
    pub operation: u16,
    /// Sender hardware address
    pub sender_mac: [u8; 6],
    /// Sender protocol address
    pub sender_ip: u32,
    /// Target hardware address
    pub target_mac: [u8; 6],
    /// Target protocol address
    pub target_ip: u32,
}

impl ArpHeader {
    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<ArpHeader> {
        if data.len() < 28 {
            return None;
        }

        Some(ArpHeader {
            hw_type: u16::from_be_bytes([data[0], data[1]]),
            proto_type: u16::from_be_bytes([data[2], data[3]]),
            hw_size: data[4],
            proto_size: data[5],
            operation: u16::from_be_bytes([data[6], data[7]]),
            sender_mac: [data[8], data[9], data[10], data[11], data[12], data[13]],
            sender_ip: u32::from_be_bytes([data[14], data[15], data[16], data[17]]),
            target_mac: [data[18], data[19], data[20], data[21], data[22], data[23]],
            target_ip: u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < 28 {
            return;
        }

        data[0..2].copy_from_slice(&self.hw_type.to_be_bytes());
        data[2..4].copy_from_slice(&self.proto_type.to_be_bytes());
        data[4] = self.hw_size;
        data[5] = self.proto_size;
        data[6..8].copy_from_slice(&self.operation.to_be_bytes());
        data[8..14].copy_from_slice(&self.sender_mac);
        data[14..18].copy_from_slice(&self.sender_ip.to_be_bytes());
        data[18..24].copy_from_slice(&self.target_mac);
        data[24..28].copy_from_slice(&self.target_ip.to_be_bytes());
    }
}

/// ARP cache entry
struct ArpCacheEntry {
    /// IP address
    pub ip: u32,
    /// MAC address
    pub mac: [u8; 6],
    /// Time last updated (relative)
    pub timestamp: u64,
    /// Is this a static entry
    pub static_entry: bool,
}

/// Global ARP cache
static ARP_CACHE: Spinlock<Vec<ArpCacheEntry>> = Spinlock::new(Vec::new());

/// Global clock for timestamps
static ARP_CLOCK: AtomicU64 = AtomicU64::new(0);

/// ARP cache timeout (in seconds)
const ARP_CACHE_TIMEOUT: u64 = 300;

/// Initialize the ARP module
pub fn init() {
    // Clear ARP cache
    ARP_CACHE.lock().clear();

    // Initialize clock
    ARP_CLOCK.store(0, Ordering::Relaxed);
}

/// Increment the ARP clock (called periodically)
pub fn tick() {
    ARP_CLOCK.fetch_add(1, Ordering::Relaxed);
}

/// Add an entry to the ARP cache
pub fn cache_add(ip: u32, mac: &[u8; 6]) {
    let mut cache = ARP_CACHE.lock();
    let now = ARP_CLOCK.load(Ordering::Relaxed);

    // Check if entry exists
    if let Some(entry) = cache.iter_mut().find(|e| e.ip == ip) {
        entry.mac = *mac;
        entry.timestamp = now;
        return;
    }

    // Add new entry
    cache.push(ArpCacheEntry {
        ip,
        mac: *mac,
        timestamp: now,
        static_entry: false,
    });
}

/// Add a static entry to the ARP cache
pub fn cache_add_static(ip: u32, mac: &[u8; 6]) {
    let mut cache = ARP_CACHE.lock();
    let now = ARP_CLOCK.load(Ordering::Relaxed);

    if let Some(entry) = cache.iter_mut().find(|e| e.ip == ip) {
        entry.mac = *mac;
        entry.timestamp = now;
        entry.static_entry = true;
        return;
    }

    cache.push(ArpCacheEntry {
        ip,
        mac: *mac,
        timestamp: now,
        static_entry: true,
    });
}

/// Remove an entry from the ARP cache
pub fn cache_remove(ip: u32) {
    let mut cache = ARP_CACHE.lock();
    cache.retain(|e| e.ip != ip);
}

/// Lookup a MAC address in the cache
pub fn cache_lookup(ip: u32) -> Option<[u8; 6]> {
    let cache = ARP_CACHE.lock();
    let now = ARP_CLOCK.load(Ordering::Relaxed);

    cache
        .iter()
        .find(|e| e.ip == ip && (e.static_entry || now - e.timestamp < ARP_CACHE_TIMEOUT))
        .map(|e| e.mac)
}

/// Clean up expired entries
pub fn cache_cleanup() {
    let mut cache = ARP_CACHE.lock();
    let now = ARP_CLOCK.load(Ordering::Relaxed);
    cache.retain(|e| e.static_entry || now - e.timestamp < ARP_CACHE_TIMEOUT);
}

/// Process an incoming ARP packet
pub fn arp_input(data: &[u8], nic_type: NicType, nic_index: usize) {
    let header = match ArpHeader::from_bytes(data) {
        Some(h) => h,
        None => return,
    };

    // Verify ARP packet is for IPv4 over Ethernet
    if header.hw_type != 1 || header.proto_type != 0x0800 || header.hw_size != 6 || header.proto_size != 4 {
        return;
    }

    // Get our IP addresses
    let our_ips = ipif::get_our_ip_addresses();
    if !our_ips.contains(&header.target_ip) {
        return;
    }

    // Add sender to cache
    cache_add(header.sender_ip, &header.sender_mac);

    // Process based on operation
    match header.operation {
        1 => {
            // ARP Request - send reply
            send_reply(header.target_ip, header.sender_ip, header.sender_mac, nic_type, nic_index);
        }
        2 => {
            // ARP Reply - already added to cache above
        }
        _ => {}
    }
}

/// Send an ARP request
pub fn send_request(target_ip: u32, nic_type: NicType, nic_index: usize) {
    // Get our MAC address
    let src_mac = match ethif::get_primary_mac() {
        Some(m) => m,
        None => return,
    };

    // Get our IP address
    let our_ips = ipif::get_our_ip_addresses();
    let src_ip = match our_ips.first() {
        Some(&ip) => ip,
        None => return,
    };

    // Build ARP request
    let header = ArpHeader {
        hw_type: 1, // Ethernet
        proto_type: 0x0800, // IPv4
        hw_size: 6,
        proto_size: 4,
        operation: 1, // Request
        sender_mac: src_mac,
        sender_ip: src_ip,
        target_mac: [0, 0, 0, 0, 0, 0],
        target_ip: target_ip,
    };

    let mut packet = vec![0u8; 28];
    header.to_bytes(&mut packet);

    // Build Ethernet frame
    let broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let frame = eth::build_ethernet_frame(&broadcast, &src_mac, ETHER_TYPE_ARP, &packet);

    // Send to NIC
    crate::drivers::net::send_to_nic(nic_type, nic_index, &frame);
}

/// Send an ARP reply
fn send_reply(
    target_ip: u32,
    sender_ip: u32,
    sender_mac: [u8; 6],
    nic_type: NicType,
    nic_index: usize,
) {
    // Get our MAC address
    let src_mac = match ethif::get_primary_mac() {
        Some(m) => m,
        None => return,
    };

    // Build ARP reply
    let header = ArpHeader {
        hw_type: 1,
        proto_type: 0x0800,
        hw_size: 6,
        proto_size: 4,
        operation: 2, // Reply
        sender_mac: src_mac,
        sender_ip: target_ip,
        target_mac: sender_mac,
        target_ip: sender_ip,
    };

    let mut packet = vec![0u8; 28];
    header.to_bytes(&mut packet);

    // Build Ethernet frame
    let frame = eth::build_ethernet_frame(&sender_mac, &src_mac, ETHER_TYPE_ARP, &packet);

    // Send to NIC
    crate::drivers::net::send_to_nic(nic_type, nic_index, &frame);
}

/// Resolve an IP address to a MAC address
/// Returns None if resolution fails
pub fn arp_resolve(ip: u32) -> Option<[u8; 6]> {
    // First check cache
    if let Some(mac) = cache_lookup(ip) {
        return Some(mac);
    }

    // Check if on local subnet
    let interfaces = ipif::get_all_interfaces();
    let mut found_local = false;
    for iface in &interfaces {
        if iface.is_on_subnet(ip) {
            // On local subnet, send ARP request
            if let Some((nic_type, nic_idx)) = ethif::get_primary_interface() {
                send_request(ip, nic_type, nic_idx);
            }
            found_local = true;
            break;
        }
    }

    // Not on local subnet, use gateway
    if !found_local {
        if let Some(gateway) = interfaces.first() {
            if let Some(mac) = cache_lookup(gateway.gateway) {
                return Some(mac);
            }

            // Try to resolve gateway
            if let Some((nic_type, nic_idx)) = ethif::get_primary_interface() {
                send_request(gateway.gateway, nic_type, nic_idx);
            }
        }
    }

    None
}
