//! Windows Filtering Platform (WFP) Integration Points
//!
//! Provides filtering hooks for the Windows network stack.
//! Implements integration points for:
//! - Packet filtering (firewall rules)
//! - Connection authorization
//! - Stream inspection
//! - Layer-specific filtering
//!
//! Clean-room implementation based on Windows 7 WFP architecture.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterLayer {
    InboundIpv4,
    OutboundIpv4,
    InboundTransport,
    OutboundTransport,
    Stream,
    AleConnect,
    AleReceive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Permit,
    Block,
    Reject,
    Continue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDirection {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, Copy)]
pub enum FilterCondition {
    SourceIp(u32, u32), // IP, mask
    DestIp(u32, u32), // IP, mask
    SourcePort(u16),
    DestPort(u16),
    Protocol(u8),
    Interface(u32),
}

#[derive(Debug, Clone)]
pub struct Filter {
    pub id: u64,
    pub name: [u8; 64],
    pub layer: FilterLayer,
    pub weight: u32,
    pub action: FilterAction,
    pub conditions: Vec<FilterCondition>,
    pub enabled: bool,
}

impl Filter {
    pub fn new(id: u64, layer: FilterLayer, weight: u32, action: FilterAction) -> Self {
        Self {
            id,
            name: [0u8; 64],
            layer,
            weight,
            action,
            conditions: Vec::new(),
            enabled: true,
        }
    }

    pub fn add_condition(&mut self, condition: FilterCondition) {
        self.conditions.push(condition);
    }

    pub fn matches(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        interface: u32,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        for condition in &self.conditions {
            let matches = match condition {
                FilterCondition::SourceIp(ip, mask) => (src_ip & mask) == (ip & mask),
                FilterCondition::DestIp(ip, mask) => (dst_ip & mask) == (ip & mask),
                FilterCondition::SourcePort(port) => src_port == *port,
                FilterCondition::DestPort(port) => dst_port == *port,
                FilterCondition::Protocol(proto) => protocol == *proto,
                FilterCondition::Interface(iface) => interface == *iface,
            };

            if !matches {
                return false;
            }
        }

        true
    }
}

struct FilterEngine {
    filters: Vec<Filter>,
    next_id: u64,
}

impl FilterEngine {
    fn new() -> Self {
        Self {
            filters: Vec::new(),
            next_id: 1,
        }
    }

    fn add_filter(&mut self, mut filter: Filter) -> u64 {
        filter.id = self.next_id;
        self.next_id += 1;
        let filter_id = filter.id;
        self.filters.push(filter);

        self.filters.sort_by(|a, b| b.weight.cmp(&a.weight));

        filter_id
    }

    fn remove_filter(&mut self, id: u64) -> bool {
        let before = self.filters.len();
        self.filters.retain(|f| f.id != id);
        self.filters.len() != before
    }

    fn get_filters_for_layer(&self, layer: FilterLayer) -> impl Iterator<Item = &Filter> {
        self.filters.iter().filter(move |f| f.layer == layer)
    }
}

static FILTER_ENGINE: Spinlock<FilterEngine> = Spinlock::new(FilterEngine {
    filters: Vec::new(),
    next_id: 1,
});

#[derive(Debug, Clone, Copy)]
pub struct FilterStats {
    pub packets_inspected: u64,
    pub packets_allowed: u64,
    pub packets_blocked: u64,
    pub packets_rejected: u64,
}

static FILTER_STATS: Spinlock<FilterStats> = Spinlock::new(FilterStats {
    packets_inspected: 0,
    packets_allowed: 0,
    packets_blocked: 0,
    packets_rejected: 0,
});

pub fn init() {
    *FILTER_ENGINE.lock() = FilterEngine::new();
    *FILTER_STATS.lock() = FilterStats {
        packets_inspected: 0,
        packets_allowed: 0,
        packets_blocked: 0,
        packets_rejected: 0,
    };

    let mut default_filter = Filter::new(0, FilterLayer::InboundIpv4, 0, FilterAction::Permit);
    default_filter.enabled = true;
    add_filter(default_filter);
}

pub fn add_filter(filter: Filter) -> u64 {
    FILTER_ENGINE.lock().add_filter(filter)
}

pub fn remove_filter(id: u64) -> bool {
    FILTER_ENGINE.lock().remove_filter(id)
}

pub fn filter_packet(
    layer: FilterLayer,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    interface: u32,
) -> FilterAction {
    let engine = FILTER_ENGINE.lock();
    let mut stats = FILTER_STATS.lock();

    stats.packets_inspected += 1;

    for filter in engine.get_filters_for_layer(layer) {
        if filter.matches(src_ip, dst_ip, src_port, dst_port, protocol, interface) {
            match filter.action {
                FilterAction::Permit => {
                    stats.packets_allowed += 1;
                    return FilterAction::Permit;
                }
                FilterAction::Block => {
                    stats.packets_blocked += 1;
                    return FilterAction::Block;
                }
                FilterAction::Reject => {
                    stats.packets_rejected += 1;
                    return FilterAction::Reject;
                }
                FilterAction::Continue => {
                    continue;
                }
            }
        }
    }

    stats.packets_allowed += 1;
    FilterAction::Permit
}

pub fn check_connection(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    direction: FilterDirection,
) -> bool {
    let layer = match direction {
        FilterDirection::Outbound => FilterLayer::AleConnect,
        FilterDirection::Inbound => FilterLayer::AleReceive,
        FilterDirection::Both => FilterLayer::AleConnect,
    };

    let action = filter_packet(layer, src_ip, dst_ip, src_port, dst_port, protocol, 0);
    matches!(action, FilterAction::Permit | FilterAction::Continue)
}

pub fn get_stats() -> FilterStats {
    *FILTER_STATS.lock()
}

pub fn get_all_filters() -> Vec<Filter> {
    FILTER_ENGINE.lock().filters.clone()
}

pub fn set_filter_enabled(id: u64, enabled: bool) -> bool {
    let mut engine = FILTER_ENGINE.lock();
    if let Some(filter) = engine.filters.iter_mut().find(|f| f.id == id) {
        filter.enabled = enabled;
        true
    } else {
        false
    }
}

pub fn add_block_rule(
    layer: FilterLayer,
    src_ip: Option<(u32, u32)>,
    dst_ip: Option<(u32, u32)>,
    dst_port: Option<u16>,
    protocol: Option<u8>,
) -> u64 {
    let mut filter = Filter::new(0, layer, 1000, FilterAction::Block);

    if let Some((ip, mask)) = src_ip {
        filter.add_condition(FilterCondition::SourceIp(ip, mask));
    }
    if let Some((ip, mask)) = dst_ip {
        filter.add_condition(FilterCondition::DestIp(ip, mask));
    }
    if let Some(port) = dst_port {
        filter.add_condition(FilterCondition::DestPort(port));
    }
    if let Some(proto) = protocol {
        filter.add_condition(FilterCondition::Protocol(proto));
    }

    add_filter(filter)
}

pub fn add_allow_rule(
    layer: FilterLayer,
    src_ip: Option<(u32, u32)>,
    dst_ip: Option<(u32, u32)>,
    dst_port: Option<u16>,
    protocol: Option<u8>,
) -> u64 {
    let mut filter = Filter::new(0, layer, 500, FilterAction::Permit);

    if let Some((ip, mask)) = src_ip {
        filter.add_condition(FilterCondition::SourceIp(ip, mask));
    }
    if let Some((ip, mask)) = dst_ip {
        filter.add_condition(FilterCondition::DestIp(ip, mask));
    }
    if let Some(port) = dst_port {
        filter.add_condition(FilterCondition::DestPort(port));
    }
    if let Some(proto) = protocol {
        filter.add_condition(FilterCondition::Protocol(proto));
    }

    add_filter(filter)
}
