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

/// QEMU slirp default gateway: 10.0.2.2
const SLIRP_GATEWAY: u32 = 0x0A00_0202;
/// QEMU slirp default DNS server: 10.0.2.3
const SLIRP_DNS: u32 = 0x0A00_0203;
/// TCP connect target port (DNS on the slirp gateway).
const TCP_TEST_PORT: u16 = 53;
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
    use crate::netstack::{arp, dhcp, dns, ipif, socket};

    if net::nic_count() == 0 {
        crate::kprintln_error!("NET-E2E", "no NIC registered");
        return false;
    }

    // --- Stage 1: DHCP address acquisition.
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
                if client.process_message(&buffer[..n], &mac) {
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

    let lease_ip = client.get_lease().map(|l| l.ip_address).unwrap_or(0);
    crate::kprintln_info!("NET-E2E", "DHCP bound: {}", ipif::ip_to_string(lease_ip));

    // --- Stage 2: ARP resolution of the gateway.
    arp::send_request(SLIRP_GATEWAY, NicType::VirtioNet, 0);
    poll_for_ms(PROTOCOL_TIMEOUT_MS);
    let arp_ok = arp::arp_resolve(SLIRP_GATEWAY).is_some();
    crate::kprintln_info!(
        "NET-E2E",
        "ARP 10.0.2.2: {}",
        if arp_ok { "resolved" } else { "failed" }
    );

    // --- Stage 3: TCP connection establishment.
    let _ = dns::set_dns_server(SLIRP_DNS);
    let sock = socket::socket_auto(socket::SocketType::Stream);
    let tcp_ok = if let Some(sid) = sock {
        let addr = socket::SockAddr::new(2, TCP_TEST_PORT, SLIRP_GATEWAY);
        matches!(socket::connect(sid, &addr), Ok(()))
    } else {
        false
    };
    crate::kprintln_info!(
        "NET-E2E",
        "TCP connect 10.0.2.2:53: {}",
        if tcp_ok { "ok" } else { "failed" }
    );

    // --- Stage 4: DNS resolution.
    let dns_ok = matches!(dns::resolve("localhost"), Ok(_));
    crate::kprintln_info!(
        "NET-E2E",
        "DNS resolve localhost: {}",
        if dns_ok { "ok" } else { "failed" }
    );

    dhcp_ok && arp_ok && tcp_ok && dns_ok
}
