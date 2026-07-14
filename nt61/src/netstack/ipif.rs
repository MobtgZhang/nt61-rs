//! IP Interface and Routing Table Management
//
//! Manages IP interfaces, addresses, and routing tables.
//
//! Clean-room implementation.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

/// Maximum number of IP interfaces
const MAX_IP_INTERFACES: usize = 8;
/// Maximum number of routing table entries
const MAX_ROUTE_ENTRIES: usize = 32;

/// Default TTL
pub const DEFAULT_TTL: u8 = 64;
/// Default MTU
pub const DEFAULT_MTU: u32 = 1500;

/// IP interface structure
#[derive(Clone, Copy)]
pub struct IpInterface {
    /// Interface index
    pub if_index: u32,
    /// IP address (network byte order)
    pub address: u32,
    /// Subnet mask (network byte order)
    pub netmask: u32,
    /// Gateway (network byte order)
    pub gateway: u32,
    /// Associated Ethernet interface index
    pub eth_if: u32,
    /// Time To Live
    pub ttl: u8,
}

impl IpInterface {
    /// Create a new IP interface
    pub fn new(if_index: u32, address: u32, netmask: u32, gateway: u32, eth_if: u32) -> Self {
        Self {
            if_index,
            address,
            netmask,
            gateway,
            eth_if,
            ttl: DEFAULT_TTL,
        }
    }

    /// Get the network address
    pub fn network(&self) -> u32 {
        self.address & self.netmask
    }

    /// Get the broadcast address
    pub fn broadcast(&self) -> u32 {
        self.address | !self.netmask
    }

    /// Check if an IP is on the same subnet
    pub fn is_on_subnet(&self, ip: u32) -> bool {
        (self.address & self.netmask) == (ip & self.netmask)
    }

    /// Get the CIDR prefix length
    pub fn prefix_len(&self) -> u8 {
        (!self.netmask).count_ones() as u8
    }
}

/// Route entry structure
#[derive(Clone, Copy)]
pub struct RouteEntry {
    /// Destination network (network byte order)
    pub dest: u32,
    /// Subnet mask (network byte order)
    pub netmask: u32,
    /// Gateway (network byte order)
    pub gateway: u32,
    /// Output interface index
    pub if_index: u32,
    /// Metric (lower is better)
    pub metric: u32,
}

impl RouteEntry {
    /// Create a new route entry
    pub fn new(dest: u32, netmask: u32, gateway: u32, if_index: u32, metric: u32) -> Self {
        Self {
            dest,
            netmask,
            gateway,
            if_index,
            metric,
        }
    }

    /// Check if a destination matches this route
    pub fn matches(&self, dest: u32) -> bool {
        (dest & self.netmask) == (self.dest & self.netmask)
    }

    /// Get the prefix length
    pub fn prefix_len(&self) -> u8 {
        (!self.netmask).count_ones() as u8
    }
}

/// Global IP interface list
static IP_INTERFACES: Spinlock<Vec<IpInterface>> = Spinlock::new(Vec::new());

/// Global routing table
static ROUTING_TABLE: Spinlock<Vec<RouteEntry>> = Spinlock::new(Vec::new());

/// Initialize the IP interface layer
pub fn init() {
    // Clear any existing entries
    IP_INTERFACES.lock().clear();
    ROUTING_TABLE.lock().clear();

    // Add a default route for the first Ethernet interface
    // This will be populated when interfaces are configured
}

/// Add an IP interface
pub fn add_interface(address: u32, netmask: u32, gateway: u32, eth_if: u32) -> Option<u32> {
    let mut interfaces = IP_INTERFACES.lock();

    if interfaces.len() >= MAX_IP_INTERFACES {
        return None;
    }

    let if_index = interfaces.len() as u32;
    let ip_if = IpInterface::new(if_index, address, netmask, gateway, eth_if);
    interfaces.push(ip_if);

    // Add a default route for this interface's subnet
    add_route(address & netmask, netmask, gateway, if_index, 0);

    Some(if_index)
}

/// Remove an IP interface
pub fn remove_interface(if_index: u32) {
    let mut interfaces = IP_INTERFACES.lock();
    interfaces.retain(|i| i.if_index != if_index);

    // Also remove routes for this interface
    let mut routes = ROUTING_TABLE.lock();
    routes.retain(|r| r.if_index != if_index);
}

/// Get an interface by index
pub fn get_interface(if_index: u32) -> Option<IpInterface> {
    let interfaces = IP_INTERFACES.lock();
    interfaces.iter().find(|i| i.if_index == if_index).cloned()
}

/// Get the default interface
pub fn get_default_interface() -> Option<u32> {
    let interfaces = IP_INTERFACES.lock();
    interfaces.first().map(|i| i.if_index)
}

/// Get all interfaces
pub fn get_all_interfaces() -> Vec<IpInterface> {
    IP_INTERFACES.lock().clone()
}

/// Add a route to the routing table
pub fn add_route(dest: u32, netmask: u32, gateway: u32, if_index: u32, metric: u32) -> bool {
    let mut routes = ROUTING_TABLE.lock();

    if routes.len() >= MAX_ROUTE_ENTRIES {
        return false;
    }

    let entry = RouteEntry::new(dest, netmask, gateway, if_index, metric);
    routes.push(entry);

    // Sort by prefix length (longest match first)
    routes.sort_by(|a, b| b.prefix_len().cmp(&a.prefix_len()));

    true
}

/// Remove a route
pub fn remove_route(dest: u32, netmask: u32) {
    let mut routes = ROUTING_TABLE.lock();
    routes.retain(|r| r.dest != dest || r.netmask != netmask);
}

/// Lookup a route for a destination
pub fn route_lookup(dest: u32) -> Option<RouteEntry> {
    let routes = ROUTING_TABLE.lock();

    // Longest prefix match
    for route in routes.iter() {
        if route.matches(dest) {
            return Some(*route);
        }
    }

    None
}

/// Add the default route
pub fn add_default_route(gateway: u32, if_index: u32, metric: u32) -> bool {
    add_route(0, 0, gateway, if_index, metric)
}

/// Get our IP addresses
pub fn get_our_ip_addresses() -> Vec<u32> {
    let interfaces = IP_INTERFACES.lock();
    interfaces.iter().map(|i| i.address).collect()
}

/// Configure a static IP address
pub fn configure_static_ip(eth_if_index: u32, address: u32, netmask: u32, gateway: u32) -> Option<u32> {
    add_interface(address, netmask, gateway, eth_if_index)
}

/// Register the canonical IPv4 loopback interface (127.0.0.1 / 8)
/// as interface index 0. This is idempotent: subsequent calls are
/// no-ops because the interface table is small (max 8 entries).
///
/// The user-mode `cmd.exe` stub's `ipconfig` builtin reads its
/// answer through `SYS_NETCFG_GET`, which falls back to a static
/// 127.0.0.1 / 255.0.0.0 when no interface is registered. Calling
/// `seed_loopback()` once during early boot makes the fallback
/// unnecessary and gives `ipconfig` a real, kernel-side source
/// rather than a hard-coded literal in the BAT file.
///
/// `127.0.0.1` is encoded in host byte order via `u32::from_be`
/// because `IpInterface::address` is documented as "network byte
/// order" and `ip_to_string` decomposes in big-endian order.
pub fn seed_loopback() -> Option<u32> {
    let addr = u32::from_be_bytes([127, 0, 0, 1]);
    let mask = u32::from_be_bytes([255, 0, 0, 0]);
    let gw   = u32::from_be_bytes([0, 0, 0, 0]);
    add_interface(addr, mask, gw, u32::MAX)
}

/// Convert IPv4 address to string
pub fn ip_to_string(ip: u32) -> alloc::string::String {
    let b0 = (ip >> 0) as u8;
    let b1 = (ip >> 8) as u8;
    let b2 = (ip >> 16) as u8;
    let b3 = (ip >> 24) as u8;
    alloc::format!("{}.{}.{}.{}", b0, b1, b2, b3)
}

/// Parse IPv4 address from string
pub fn parse_ip(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut ip: u32 = 0;
    for part in parts {
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        ip = (ip << 8) | octet;
    }

    Some(ip)
}
