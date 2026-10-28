//! End-to-end network stack verification.
//
// Pumps RX packets from every registered NIC into the protocol
// stack, then exercises DHCP address acquisition, ARP gateway
// resolution, TCP connection establishment, and DNS name resolution
// against QEMU user networking (slirp).
//
// Run with: `make run-x86_64-net`
// QEMU slirp provides: DHCP 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3.

use crate::drivers::net::{self, NicType};
use crate::netstack::icmp;

/// Physical bridge default gateway.
const BRIDGE_GATEWAY: u32 = 0xC0A8_C701;
/// Physical bridge DNS server.
const BRIDGE_DNS: u32 = 0xC0A8_C701;
/// TCP service on the physical host used to prove a real handshake.
const TCP_TEST_IP: u32 = 0xC0A8_C7C3;
const TCP_TEST_PORT: u16 = 18001;
/// The physical host on the test LAN. Slirp forwards this probe to the
/// host, so a reply proves real outbound ICMP connectivity.
const PHYSICAL_HOST_IP: u32 = 0xC0A8_C7C3;
/// Maximum RX poll buffer size.
const RX_BUF_SIZE: usize = 2048;
/// DHCP timeout in milliseconds.
const DHCP_TIMEOUT_MS: u64 = 10_000;
/// ARP / TCP / DNS timeout in milliseconds.
const PROTOCOL_TIMEOUT_MS: u64 = 3_000;

/// Poll all RX packets from all NICs and feed them into the stack.
fn poll_packets() {
    let mut buf = [0u8; RX_BUF_SIZE];
    let count = net::nic_count();
    for nic_idx in 0..count {
        // virtio-net is always probed first by drivers::net::init();
        // e1000 follows. We try virtio first, then e1000.
        let nic_type = if net::virtio_net::count() > nic_idx {
            NicType::VirtioNet
        } else {
            NicType::E1000
        };
        while let Some(len) = net::nic_receive(nic_type, nic_idx, &mut buf) {
            if len == 0 || len > buf.len() {
                break;
            }
            crate::netstack::process_packet(&buf[..len], nic_type, nic_idx);
        }
    }
}

/// Spin for `ms` milliseconds, polling RX packets continuously.
fn poll_for_ms(ms: u64) {
    let start = crate::hal::common::pit::get_system_time_ms();
    while crate::hal::common::pit::get_system_time_ms().saturating_sub(start) < ms {
        poll_packets();
    }
}

/// Run the full end-to-end network test.
/// Returns `true` when DHCP, ARP, TCP, and DNS all succeed.
pub fn run_e2e_test() -> bool {
    use crate::netstack::{arp, dhcp, dns, icmp, ipif, socket};

    if net::nic_count() == 0 {
        crate::kprintln_error!("NET-E2E", "no NIC registered");
        return false;
    }

    // --- Stage 1: IPv4 loopback. This is fully local and must not
    // depend on DHCP or the physical NIC.
    icmp::arm_echo_reply(0x4E61, 0);
    let loopback_sent = icmp::send_echo_request(u32::from_be_bytes([127, 0, 0, 1]), 0x4E61, 0);
    let loopback_reply = if loopback_sent {
        icmp::take_echo_reply(0x4E61, 0)
    } else {
        None
    };
    let loopback_ok = loopback_reply.is_some();
    crate::kprintln_info!(
        "NET-E2E",
        "ICMP loopback 127.0.0.1: {}",
        if loopback_ok { "ok" } else { "failed" }
    );

    // --- Stage 2: DHCP address acquisition.
    dhcp::init();
    let mac = match net::virtio_net::get_mac(0).or_else(|| net::e1000::get_mac(0)) {
        Some(m) => m,
        None => {
            crate::kprintln_error!("NET-E2E", "no MAC address available");
            return false;
        }
    };

    let mut client = dhcp::create_client();
    let discover = client.start_discovery(&mac);
    if !dhcp::send_dhcp_message(&discover) {
        crate::kprintln_error!("NET-E2E", "DHCP discover send failed");
        return false;
    }

    let mut buffer = [0u8; 1500];
    let mut request_sent = false;
    let dhcp_ok = {
        let deadline = crate::hal::common::pit::get_system_time_ms() + DHCP_TIMEOUT_MS;
        loop {
            poll_packets();
            if let Some(n) = dhcp::recv_dhcp_message(&mut buffer) {
                let accepted = client.process_message(&buffer[..n], &mac);
                if accepted {
                    match client.get_state() {
                        dhcp::DhcpState::Bound => {
                            break true;
                        }
                        dhcp::DhcpState::Requesting if !request_sent => {
                            let req = client.build_request_from_offer(&mac);
                            request_sent = dhcp::send_dhcp_message(&req);
                        }
                        _ => {}
                    }
                }
            }
            if crate::hal::common::pit::get_system_time_ms() > deadline {
                break false;
            }
        }
    };
    if !dhcp_ok {
        crate::kprintln_error!(
            "NET-E2E",
            "DHCP did not reach BOUND within {} ms",
            DHCP_TIMEOUT_MS
        );
        return false;
    }
    let lease = client.get_lease().cloned();
    let lease_ip = lease.as_ref().map(|l| l.ip_address).unwrap_or(0);
    crate::kprintln_info!("NET-E2E", "DHCP bound: {}", ipif::ip_to_string(lease_ip));

    // Publish the lease to IP/routing tables. Without this, ARP and
    // upper-layer traffic still use the loopback source address and
    // the external peer drops every packet.
    let interface_ok = lease
        .as_ref()
        .map(|lease| {
            ipif::add_interface(lease.ip_address, lease.subnet_mask, lease.gateway, 0).is_some()
        })
        .unwrap_or(false);
    if !interface_ok {
        crate::kprintln_error!("NET-E2E", "failed to install DHCP lease");
        return false;
    }

    // --- Stage 3: ARP resolution of the gateway.
    let arp_source = arp::source_for_target(BRIDGE_GATEWAY);
    if let Some(src_ip) = arp_source {
        arp::send_request_with_source(BRIDGE_GATEWAY, src_ip, NicType::VirtioNet, 0);
    }
    poll_for_ms(PROTOCOL_TIMEOUT_MS);
    let arp_ok = arp::arp_resolve(BRIDGE_GATEWAY).is_some();
    crate::kprintln_info!(
        "NET-E2E",
        "ARP 192.168.199.1: {}",
        if arp_ok { "resolved" } else { "failed" }
    );

    // --- Stage 4: TCP connection establishment.
    let _ = dns::set_dns_server(BRIDGE_DNS);
    let sock = socket::socket_auto(socket::SocketType::Stream);
    let tcp_ok = if let Some(sid) = sock {
        let addr = socket::SockAddr::new(2, TCP_TEST_PORT, TCP_TEST_IP);
        let connected = matches!(socket::connect(sid, &addr), Ok(()));
        connected
    } else {
        false
    };
    crate::kprintln_info!(
        "NET-E2E",
        "TCP connect 192.168.199.195:18001: {}",
        if tcp_ok { "ok" } else { "failed" }
    );

    // --- Stage 5: DNS resolution.
    let dns_ok = matches!(dns::resolve("example.com"), Ok(_));
    crate::kprintln_info!(
        "NET-E2E",
        "DNS resolve example.com: {}",
        if dns_ok { "ok" } else { "failed" }
    );

    // --- Stage 6: verify the DHCP address itself answers ICMP. This is
    // distinct from 127.0.0.1 because it exercises the installed virtio
    // interface and the IPv4/ARP input path.
    let self_ping_ok = ping_once(lease_ip, 0x4E61, 1);
    crate::kprintln_info!(
        "NET-E2E",
        "ICMP self ping {}: {}",
        ipif::ip_to_string(lease_ip),
        if self_ping_ok { "ok" } else { "failed" }
    );

    // --- Stage 7: verify the physical host is reachable through the
    // bridged/back-end network.
    let host_ping_ok = ping_once(PHYSICAL_HOST_IP, 0x4E61, 2);
    crate::kprintln_info!(
        "NET-E2E",
        "ICMP host ping {}: {}",
        ipif::ip_to_string(PHYSICAL_HOST_IP),
        if host_ping_ok { "ok" } else { "failed" }
    );

    dhcp_ok && loopback_ok && arp_ok && tcp_ok && dns_ok && self_ping_ok && host_ping_ok
}

/// Send one echo request and wait for its matching reply.
fn ping_once(target_ip: u32, identifier: u16, sequence: u16) -> bool {
    icmp::arm_echo_reply(identifier, sequence);
    if !icmp::send_echo_request(target_ip, identifier, sequence) {
        return false;
    }

    let start = crate::hal::common::pit::get_system_time_ms();
    while crate::hal::common::pit::get_system_time_ms().saturating_sub(start) < 1_000 {
        poll_packets();
        if icmp::take_echo_reply(identifier, sequence).is_some() {
            return true;
        }
    }
    false
}
