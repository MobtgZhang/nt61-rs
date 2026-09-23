//! Network Routing Table
//!
//! Implements a routing table for IPv4 packet forwarding decisions.
//! Matches Windows 7 routing architecture with support for:
//! - Static routes
//! - Dynamic routes (from DHCP, ICMP redirects)
//! - Gateway resolution
//! - Route metrics
//! - Default gateway
//!
//! Clean-room implementation based on RFC 1812.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    pub destination: u32,
    pub netmask: u32,
    pub gateway: u32,
    pub interface: u32,
    pub metric: u32,
    pub route_type: RouteType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    Direct,
    Static,
    Dynamic,
    Redirect,
    Default,
}

impl RouteEntry {
    pub fn new(
        destination: u32,
        netmask: u32,
        gateway: u32,
        interface: u32,
        metric: u32,
        route_type: RouteType,
    ) -> Self {
        Self {
            destination,
            netmask,
            gateway,
            interface,
            metric,
            route_type,
        }
    }

    pub fn matches(&self, dst_ip: u32) -> bool {
        (dst_ip & self.netmask) == (self.destination & self.netmask)
    }

    pub fn prefix_len(&self) -> u32 {
        self.netmask.count_ones()
    }
}

static ROUTING_TABLE: Spinlock<Vec<RouteEntry>> = Spinlock::new(Vec::new());

pub fn init() {
    ROUTING_TABLE.lock().clear();
}

pub fn add_route(
    destination: u32,
    netmask: u32,
    gateway: u32,
    interface: u32,
    metric: u32,
    route_type: RouteType,
) {
    let mut table = ROUTING_TABLE.lock();

    table.retain(|r| !(r.destination == destination && r.netmask == netmask));

    let entry = RouteEntry::new(destination, netmask, gateway, interface, metric, route_type);
    table.push(entry);

    table.sort_by(|a, b| {
        let prefix_cmp = b.prefix_len().cmp(&a.prefix_len());
        if prefix_cmp == core::cmp::Ordering::Equal {
            a.metric.cmp(&b.metric)
        } else {
            prefix_cmp
        }
    });
}

pub fn remove_route(destination: u32, netmask: u32) -> bool {
    let mut table = ROUTING_TABLE.lock();
    let before = table.len();
    table.retain(|r| !(r.destination == destination && r.netmask == netmask));
    table.len() != before
}

pub fn find_route(dst_ip: u32) -> Option<RouteEntry> {
    let table = ROUTING_TABLE.lock();

    table.iter().find(|r| r.matches(dst_ip)).copied()
}

pub fn get_all_routes() -> Vec<RouteEntry> {
    ROUTING_TABLE.lock().clone()
}

pub fn set_default_gateway(gateway: u32, interface: u32, metric: u32) {
    add_route(0, 0, gateway, interface, metric, RouteType::Default);
}

pub fn get_default_gateway() -> Option<u32> {
    let table = ROUTING_TABLE.lock();
    table
        .iter()
        .find(|r| r.destination == 0 && r.netmask == 0)
        .map(|r| r.gateway)
}

pub fn add_direct_route(network: u32, netmask: u32, interface: u32) {
    add_route(network, netmask, 0, interface, 0, RouteType::Direct);
}

pub fn flush_dynamic_routes() {
    let mut table = ROUTING_TABLE.lock();
    table.retain(|r| r.route_type != RouteType::Dynamic);
}

pub fn get_route_count() -> usize {
    ROUTING_TABLE.lock().len()
}

pub fn format_ip(ip: u32) -> alloc::string::String {
    alloc::format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

pub fn get_routing_table() -> alloc::vec::Vec<RouteEntry> {
    alloc::vec::Vec::new()
}

pub fn clear_routing_table() {
}

