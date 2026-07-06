//! Ethernet Interface Management
//
//! Manages Ethernet network interfaces including MAC addresses,
//! link state, and packet filtering.
//
//! Clean-room implementation.

use crate::drivers::net::{self, NicType};
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use alloc::format;

/// Maximum number of Ethernet interfaces


/// Ethernet interface state
#[derive(Clone)]
pub struct EthInterface {
    /// Interface index
    pub if_index: u32,
    /// Interface name
    pub name: [u8; 16],
    /// MAC address
    pub mac: [u8; 6],
    /// MTU
    pub mtu: u32,
    /// Link state
    pub link_up: bool,
    /// NIC type
    pub nic_type: NicType,
    /// NIC index
    pub nic_index: usize,
    /// Promiscuous mode
    pub promiscuous: bool,
    /// Accept broadcast
    pub accept_broadcast: bool,
    /// Accept multicast
    pub accept_multicast: bool,
}

impl EthInterface {
    /// Create a new Ethernet interface
    pub fn new(
        if_index: u32,
        name: &[u8],
        mac: [u8; 6],
        nic_type: NicType,
        nic_index: usize,
    ) -> Self {
        let mut name_arr = [0u8; 16];
        name_arr[..name.len().min(16)].copy_from_slice(&name[..name.len().min(16)]);

        Self {
            if_index,
            name: name_arr,
            mac,
            mtu: 1500,
            link_up: true,
            nic_type,
            nic_index,
            promiscuous: false,
            accept_broadcast: true,
            accept_multicast: true,
        }
    }

    /// Check if a frame should be accepted based on MAC filtering
    pub fn should_accept_frame(&self, dst_mac: &[u8; 6]) -> bool {
        // Promiscuous mode accepts everything
        if self.promiscuous {
            return true;
        }

        // Broadcast
        if dst_mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return self.accept_broadcast;
        }

        // Multicast
        if dst_mac[0] & 0x01 != 0 {
            return self.accept_multicast;
        }

        // Unicast to our MAC
        if dst_mac == &self.mac {
            return true;
        }

        false
    }

    /// Set promiscuous mode
    pub fn set_promiscuous(&mut self, enable: bool) {
        self.promiscuous = enable;
    }
}

/// Global interface list
static ETH_INTERFACES: Spinlock<Vec<EthInterface>> = Spinlock::new(Vec::new());

/// Initialize the Ethernet interface layer
pub fn init() {
    let mut interfaces = ETH_INTERFACES.lock();

    // Discover and register NICs as interfaces
    let mut if_index: u32 = 0;

    // Register virtio-net interfaces
    let virtio_count = net::virtio_net::count();
    for i in 0..virtio_count {
        if let Some(mac) = net::virtio_net::get_mac(i) {
            let name = format!("virtio{}\0", i);
            let eth_if = EthInterface::new(
                if_index,
                name.as_bytes(),
                mac,
                NicType::VirtioNet,
                i,
            );
            interfaces.push(eth_if);
            if_index += 1;
        }
    }

    // Register e1000 interfaces
    let e1000_count = net::e1000::count();
    for i in 0..e1000_count {
        if let Some(mac) = net::e1000::get_mac(i) {
            let name = format!("e1000{}\0", i);
            let eth_if = EthInterface::new(
                if_index,
                name.as_bytes(),
                mac,
                NicType::E1000,
                i,
            );
            interfaces.push(eth_if);
            if_index += 1;
        }
    }

    // Register RTL8139 interfaces
    #[cfg(target_arch = "x86_64")]
    {
        let rtl_count = net::rtl8139::count();
        for i in 0..rtl_count {
            if let Some(mac) = net::rtl8139::get_mac(i) {
                let name = format!("rtl8139{}\0", i);
                let eth_if = EthInterface::new(
                    if_index,
                    name.as_bytes(),
                    mac,
                    NicType::Rtl8139,
                    i,
                );
                interfaces.push(eth_if);
                if_index += 1;
            }
        }
    }
}

/// Get an interface by index
pub fn get_interface(if_index: u32) -> Option<EthInterface> {
    let interfaces = ETH_INTERFACES.lock();
    interfaces.iter().find(|i| i.if_index == if_index).cloned()
}

/// Get an interface by NIC type and index
pub fn get_interface_by_nic(nic_type: NicType, nic_index: usize) -> Option<EthInterface> {
    let interfaces = ETH_INTERFACES.lock();
    interfaces
        .iter()
        .find(|i| i.nic_type == nic_type && i.nic_index == nic_index)
        .cloned()
}

/// Get all interfaces
pub fn get_all_interfaces() -> Vec<EthInterface> {
    ETH_INTERFACES.lock().clone()
}

/// Get the primary (first) interface
pub fn get_primary_interface() -> Option<(NicType, usize)> {
    let interfaces = ETH_INTERFACES.lock();
    interfaces.first().map(|i| (i.nic_type, i.nic_index))
}

/// Get the primary MAC address
pub fn get_primary_mac() -> Option<[u8; 6]> {
    let interfaces = ETH_INTERFACES.lock();
    interfaces.first().map(|i| i.mac)
}

/// Set interface promiscuous mode
pub fn set_promiscuous(if_index: u32, enable: bool) {
    let mut interfaces = ETH_INTERFACES.lock();
    if let Some(iface) = interfaces.iter_mut().find(|i| i.if_index == if_index) {
        iface.set_promiscuous(enable);
    }
}

/// Get interface count
pub fn interface_count() -> usize {
    ETH_INTERFACES.lock().len()
}
