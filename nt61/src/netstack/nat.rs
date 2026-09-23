//! Network Address Translation (NAT) Support
//!
//! Implements basic NAT functionality for the Windows 7 network stack.
//! Supports:
//! - Source NAT (SNAT/Masquerade)
//! - Destination NAT (DNAT/Port Forwarding)
//! - Connection tracking
//! - Port allocation
//!
//! Clean-room implementation based on RFC 3022 and RFC 4787.

use crate::ke::sync::Spinlock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatState {
    New,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct NatConnection {
    pub orig_src_ip: u32,
    pub orig_src_port: u16,
    pub orig_dst_ip: u32,
    pub orig_dst_port: u16,
    pub nat_src_ip: u32,
    pub nat_src_port: u16,
    pub protocol: u8,
    pub state: NatState,
    pub last_activity: u64,
    pub created_at: u64,
}

impl NatConnection {
    fn new(
        orig_src_ip: u32,
        orig_src_port: u16,
        orig_dst_ip: u32,
        orig_dst_port: u16,
        nat_src_ip: u32,
        nat_src_port: u16,
        protocol: u8,
    ) -> Self {
        let now = crate::hal::common::pit::get_system_time_ms() as u64;
        Self {
            orig_src_ip,
            orig_src_port,
            orig_dst_ip,
            orig_dst_port,
            nat_src_ip,
            nat_src_port,
            protocol,
            state: NatState::New,
            last_activity: now,
            created_at: now,
        }
    }

    fn touch(&mut self) {
        self.last_activity = crate::hal::common::pit::get_system_time_ms() as u64;
    }

    fn is_expired(&self, timeout_ms: u64) -> bool {
        let now = crate::hal::common::pit::get_system_time_ms() as u64;
        now.saturating_sub(self.last_activity) > timeout_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct OutboundKey {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InboundKey {
    nat_src_port: u16,
    protocol: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct PortForwardRule {
    pub external_port: u16,
    pub internal_ip: u32,
    pub internal_port: u16,
    pub protocol: u8,
}

struct NatStateInternal {
    outbound: BTreeMap<OutboundKey, NatConnection>,
    inbound: BTreeMap<InboundKey, OutboundKey>,
    port_forwards: Vec<PortForwardRule>,
    next_port: u16,
}

impl NatStateInternal {
    fn new() -> Self {
        Self {
            outbound: BTreeMap::new(),
            inbound: BTreeMap::new(),
            port_forwards: Vec::new(),
            next_port: 49152, // Start of dynamic port range
        }
    }

    fn allocate_port(&mut self, protocol: u8) -> Option<u16> {
        let start = self.next_port;
        loop {
            let port = self.next_port;
            self.next_port = if self.next_port >= 65535 {
                49152
            } else {
                self.next_port + 1
            };

            let key = InboundKey {
                nat_src_port: port,
                protocol,
            };

            if !self.inbound.contains_key(&key) {
                return Some(port);
            }

            if self.next_port == start {
                return None;
            }
        }
    }
}

static NAT_STATE: Spinlock<NatStateInternal> = Spinlock::new(NatStateInternal {
    outbound: BTreeMap::new(),
    inbound: BTreeMap::new(),
    port_forwards: Vec::new(),
    next_port: 49152,
});

#[derive(Debug, Clone, Copy)]
pub struct NatStats {
    pub translations: u64,
    pub port_forwards: u64,
    pub expired: u64,
    pub errors: u64,
}

static NAT_STATS: Spinlock<NatStats> = Spinlock::new(NatStats {
    translations: 0,
    port_forwards: 0,
    expired: 0,
    errors: 0,
});

const TCP_TIMEOUT_MS: u64 = 7200_000; // 2 hours
const UDP_TIMEOUT_MS: u64 = 300_000;  // 5 minutes
const ICMP_TIMEOUT_MS: u64 = 60_000;  // 1 minute

pub fn init() {
    *NAT_STATE.lock() = NatStateInternal::new();
    *NAT_STATS.lock() = NatStats {
        translations: 0,
        port_forwards: 0,
        expired: 0,
        errors: 0,
    };
}

pub fn translate_outbound(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
    nat_ip: u32,
) -> Option<(u32, u16)> {
    let key = OutboundKey {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    };

    let mut state = NAT_STATE.lock();
    let mut stats = NAT_STATS.lock();

    if let Some(conn) = state.outbound.get_mut(&key) {
        conn.touch();
        return Some((conn.nat_src_ip, conn.nat_src_port));
    }

    let nat_port = state.allocate_port(protocol)?;

    let conn = NatConnection::new(
        src_ip, src_port, dst_ip, dst_port, nat_ip, nat_port, protocol,
    );

    let inbound_key = InboundKey {
        nat_src_port: nat_port,
        protocol,
    };

    state.outbound.insert(key, conn);
    state.inbound.insert(inbound_key, key);

    stats.translations += 1;

    Some((nat_ip, nat_port))
}

pub fn translate_inbound(
    dst_port: u16,
    protocol: u8,
) -> Option<(u32, u16)> {
    let inbound_key = InboundKey {
        nat_src_port: dst_port,
        protocol,
    };

    let mut state = NAT_STATE.lock();

    if let Some(outbound_key) = state.inbound.get(&inbound_key).cloned() {
        if let Some(conn) = state.outbound.get_mut(&outbound_key) {
            conn.touch();
            return Some((conn.orig_src_ip, conn.orig_src_port));
        }
    }

    for rule in &state.port_forwards {
        if rule.external_port == dst_port && rule.protocol == protocol {
            let mut stats = NAT_STATS.lock();
            stats.port_forwards += 1;
            return Some((rule.internal_ip, rule.internal_port));
        }
    }

    None
}

pub fn add_port_forward(
    external_port: u16,
    internal_ip: u32,
    internal_port: u16,
    protocol: u8,
) -> bool {
    let mut state = NAT_STATE.lock();

    if state.port_forwards.iter().any(|r| {
        r.external_port == external_port && r.protocol == protocol
    }) {
        return false;
    }

    state.port_forwards.push(PortForwardRule {
        external_port,
        internal_ip,
        internal_port,
        protocol,
    });

    true
}

pub fn remove_port_forward(external_port: u16, protocol: u8) -> bool {
    let mut state = NAT_STATE.lock();
    let before = state.port_forwards.len();
    state.port_forwards.retain(|r| {
        !(r.external_port == external_port && r.protocol == protocol)
    });
    state.port_forwards.len() != before
}

pub fn cleanup_expired() {
    let mut state = NAT_STATE.lock();
    let mut stats = NAT_STATS.lock();

    let expired_keys: Vec<OutboundKey> = state
        .outbound
        .iter()
        .filter_map(|(key, conn)| {
            let timeout = match conn.protocol {
                6 => TCP_TIMEOUT_MS,
                17 => UDP_TIMEOUT_MS,
                _ => ICMP_TIMEOUT_MS,
            };
            if conn.is_expired(timeout) {
                Some(*key)
            } else {
                None
            }
        })
        .collect();

    for key in expired_keys {
        if let Some(conn) = state.outbound.remove(&key) {
            let inbound_key = InboundKey {
                nat_src_port: conn.nat_src_port,
                protocol: conn.protocol,
            };
            state.inbound.remove(&inbound_key);
            stats.expired += 1;
        }
    }
}

pub fn get_stats() -> NatStats {
    *NAT_STATS.lock()
}

pub fn active_connections() -> usize {
    NAT_STATE.lock().outbound.len()
}

pub fn get_port_forwards() -> Vec<PortForwardRule> {
    NAT_STATE.lock().port_forwards.clone()
}
