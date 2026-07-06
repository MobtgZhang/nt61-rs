//! TCP/IP Network Stack
//
//! This module provides a complete TCP/IP protocol stack implementation
//! including Ethernet, IPv4, ARP, ICMP, TCP, and UDP protocols.
//
//! Clean-room implementation based on RFCs and standard networking practices.

pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod ethif;
pub mod ipif;
pub mod arp;
pub mod icmp;
pub mod tcp;
pub mod udp;
pub mod socket;
pub mod dhcp;


/// Global network stack state
static mut NETWORK_STACK_INITIALIZED: bool = false;

/// Initialize the network stack
pub fn init() {
    // kprintln!("    Network stack: initializing...")  // kprintln disabled (memcpy crash workaround);

    // Initialize submodules
    ethif::init();
    ipif::init();
    arp::init();
    icmp::init();
    tcp::init();
    udp::init();
    socket::init();

    unsafe {
        NETWORK_STACK_INITIALIZED = true;
    }

    // kprintln!("    Network stack: ready")  // kprintln disabled (memcpy crash workaround);
}

/// Check if the network stack is initialized
pub fn is_initialized() -> bool {
    unsafe { NETWORK_STACK_INITIALIZED }
}

/// Process an incoming packet from a NIC
/// This function is called by the NDIS layer when a packet is received
pub fn process_packet(data: &[u8], nic_type: crate::drivers::net::NicType, nic_index: usize) {
    // First, parse the Ethernet frame
    match eth::parse_ethernet_frame(data) {
        Some((header, payload)) => {
            // Dispatch to the appropriate handler based on EtherType
            match header.ether_type {
                eth::ETHER_TYPE_IPV4 => {
                    // Parse IPv4 packet
                    if let Some((ip_header, ip_payload)) = ipv4::parse_ipv4_header(payload) {
                        ipv4::ipv4_input(&ip_header, ip_payload, nic_type, nic_index);
                    }
                }
                eth::ETHER_TYPE_ARP => {
                    // Process ARP packet
                    arp::arp_input(payload, nic_type, nic_index);
                }
                _ => {
                    // Unknown EtherType, ignore
                }
            }
        }
        None => {
            // Invalid Ethernet frame
        }
    }
}

/// Send a packet through the network stack
pub fn send_packet(data: &[u8], protocol: ipv4::Protocol, dst_ip: u32) -> bool {
    // Get the default interface
    let Some(if_idx) = ipif::get_default_interface() else {
        return false;
    };

    // Get the interface
    let Some(ip_if) = ipif::get_interface(if_idx) else {
        return false;
    };

    // Send the packet
    ipv4::send_ipv4(ip_if.address, dst_ip, protocol as u8, data)
}
