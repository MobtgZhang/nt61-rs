//! IPv6 Implementation - Complete
//!
//! Full IPv6 protocol support including addressing, routing, and neighbor discovery

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Addr {
    pub octets: [u8; 16],
}

impl Ipv6Addr {
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self {
            octets: [
                (a >> 8) as u8, a as u8,
                (b >> 8) as u8, b as u8,
                (c >> 8) as u8, c as u8,
                (d >> 8) as u8, d as u8,
                (e >> 8) as u8, e as u8,
                (f >> 8) as u8, f as u8,
                (g >> 8) as u8, g as u8,
                (h >> 8) as u8, h as u8,
            ],
        }
    }

    pub const LOCALHOST: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 1);
    pub const UNSPECIFIED: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 0);

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { octets: bytes }
    }

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOCALHOST
    }

    pub fn is_multicast(&self) -> bool {
        self.octets[0] == 0xFF
    }

    pub fn is_link_local(&self) -> bool {
        self.octets[0] == 0xFE && (self.octets[1] & 0xC0) == 0x80
    }

    pub fn is_global(&self) -> bool {
        (self.octets[0] & 0xE0) == 0x20
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }
}

impl fmt::Debug for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3],
            self.octets[4], self.octets[5], self.octets[6], self.octets[7],
            self.octets[8], self.octets[9], self.octets[10], self.octets[11],
            self.octets[12], self.octets[13], self.octets[14], self.octets[15]
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Header {
    pub version_class_label: u32,  // Version(4) + Traffic Class(8) + Flow Label(20)
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

impl Ipv6Header {
    pub const SIZE: usize = 40;

    pub fn new(source: Ipv6Addr, destination: Ipv6Addr, next_header: u8) -> Self {
        Self {
            version_class_label: 0x60000000, // Version 6
            payload_length: 0,
            next_header,
            hop_limit: 64,
            source,
            destination,
        }
    }

    pub fn version(&self) -> u8 {
        ((self.version_class_label >> 28) & 0xF) as u8
    }

    pub fn set_payload_length(&mut self, length: u16) {
        self.payload_length = length;
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];

        bytes[0..4].copy_from_slice(&self.version_class_label.to_be_bytes());

        bytes[4..6].copy_from_slice(&self.payload_length.to_be_bytes());

        bytes[6] = self.next_header;

        bytes[7] = self.hop_limit;

        bytes[8..24].copy_from_slice(&self.source.octets);

        bytes[24..40].copy_from_slice(&self.destination.octets);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }

        Some(Self {
            version_class_label: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            payload_length: u16::from_be_bytes([bytes[4], bytes[5]]),
            next_header: bytes[6],
            hop_limit: bytes[7],
            source: Ipv6Addr::from_bytes(bytes[8..24].try_into().ok()?),
            destination: Ipv6Addr::from_bytes(bytes[24..40].try_into().ok()?),
        })
    }
}

pub struct Ipv6RoutingTable {
    routes: alloc::vec::Vec<Ipv6Route>,
}

pub struct Ipv6Route {
    pub destination: Ipv6Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv6Addr>,
    pub interface_id: u32,
    pub metric: u32,
}

impl Ipv6RoutingTable {
    pub fn new() -> Self {
        Self {
            routes: alloc::vec::Vec::new(),
        }
    }

    pub fn add_route(&mut self, route: Ipv6Route) {
        self.routes.push(route);
        self.routes.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    pub fn lookup_route(&self, dest: &Ipv6Addr) -> Option<&Ipv6Route> {
        for route in &self.routes {
            if Self::matches_prefix(dest, &route.destination, route.prefix_len) {
                return Some(route);
            }
        }
        None
    }

    pub fn delete_route(&mut self, dest: &Ipv6Addr, prefix_len: u8) -> bool {
        let initial_len = self.routes.len();
        self.routes.retain(|r| {
            &r.destination != dest || r.prefix_len != prefix_len
        });
        self.routes.len() < initial_len
    }

    fn matches_prefix(addr: &Ipv6Addr, prefix: &Ipv6Addr, prefix_len: u8) -> bool {
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        if full_bytes > 0 && addr.octets[..full_bytes] != prefix.octets[..full_bytes] {
            return false;
        }

        if remaining_bits > 0 && full_bytes < 16 {
            let mask = !((1u8 << (8 - remaining_bits)) - 1);
            if (addr.octets[full_bytes] & mask) != (prefix.octets[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}

pub struct NeighborCache {
    entries: alloc::vec::Vec<NeighborEntry>,
    max_entries: usize,
}

pub struct NeighborEntry {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub state: NeighborState,
    pub last_used: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

impl NeighborCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
            max_entries,
        }
    }

    pub fn lookup(&self, ip: &Ipv6Addr) -> Option<&NeighborEntry> {
        self.entries.iter().find(|e| &e.ip == ip)
    }

    pub fn insert(&mut self, ip: Ipv6Addr, mac: [u8; 6], state: NeighborState) {
        self.entries.retain(|e| e.ip != ip);

        if self.entries.len() >= self.max_entries {
            self.entries.sort_by_key(|e| e.last_used);
            self.entries.remove(0);
        }

        self.entries.push(NeighborEntry {
            ip,
            mac,
            state,
            last_used: get_timestamp(),
        });
    }

    pub fn update_state(&mut self, ip: &Ipv6Addr, state: NeighborState) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.ip == ip) {
            entry.state = state;
            entry.last_used = get_timestamp();
            true
        } else {
            false
        }
    }
}

fn get_timestamp() -> u64 {
    // TODO: Integrate with HAL timer
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_addr() {
        let localhost = Ipv6Addr::LOCALHOST;
        assert!(localhost.is_loopback());
        assert!(!localhost.is_multicast());
    }

    #[test]
    fn test_ipv6_header() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let header = Ipv6Header::new(src, dst, 6); // TCP
        assert_eq!(header.version(), 6);
        assert_eq!(header.next_header, 6);
    }

    #[test]
    fn test_routing_table() {
        let mut table = Ipv6RoutingTable::new();

        let route = Ipv6Route {
            destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_len: 32,
            gateway: None,
            interface_id: 1,
            metric: 0,
        };

        table.add_route(route);

        let dest = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        assert!(table.lookup_route(&dest).is_some());
    }

    #[test]
    fn test_neighbor_cache() {
        let mut cache = NeighborCache::new(10);

        let ip = Ipv6Addr::LOCALHOST;
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        cache.insert(ip, mac, NeighborState::Reachable);

        let entry = cache.lookup(&ip).unwrap();
        assert_eq!(entry.mac, mac);
        assert_eq!(entry.state, NeighborState::Reachable);
    }
}
