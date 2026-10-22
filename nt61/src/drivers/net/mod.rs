//! Network Driver Stack
//
//! Wraps the network interface cards (e1000 / rtl8139 / virtio-net)
//! behind an NDIS 6.0 miniport interface. The driver is
//! structured so that each NIC is registered as a PnP node; the
//! NDIS layer arbitrates the binding with the protocol stack
//! (TCP/IP, etc.).
//
//! Clean-room implementation. Spec source: NDIS 6.0 miniport
//! driver specification, the Intel 8254x specification, and the
//! virtio 1.0 specification. No code is copied from any
//! Microsoft or ReactOS source file.

extern crate alloc;

pub mod e1000;
/// NDIS miniport adapter context framework. The surrounding NDIS
/// wrapper modules (interrupt/oid/send) are staged separately and
/// are not wired into the build yet.
#[path = "ndis/miniport_adapter.rs"]
pub mod miniport_adapter;
pub mod virtio_net;

/// Initialise the network driver stack. Walks PCI for each
/// supported NIC and registers it.
pub fn init() {
    // kprintln!("    Network drivers: e1000, rtl8139, virtio-net");
    e1000::init();
    crate::drivers::arch::init_rtl8139();
    virtio_net::init();
    // kprintln!("    Network stack ready");
}

/// Smoke test for the network driver stack. Re-runs each NIC's
/// self-check.
pub fn smoke_test() -> bool {
    crate::drivers::arch::net_smoke_test()
}

// =============================================================================
// Protocol Stack Interface
// =============================================================================

/// Send data through a NIC
pub fn send_to_nic(nic_type: NicType, nic_idx: usize, data: &[u8]) -> bool {
    match nic_type {
        NicType::VirtioNet => virtio_net::send(nic_idx, data, false),
        NicType::E1000 => e1000::send(nic_idx, data),
        NicType::Rtl8139 => crate::drivers::arch::send_to_rtl8139(nic_idx, data),
        NicType::Unknown => false,
    }
}

/// Receive data from a NIC
pub fn nic_receive(nic_type: NicType, nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    match nic_type {
        NicType::VirtioNet => virtio_net::receive(nic_idx, buffer),
        NicType::E1000 => e1000::receive(nic_idx, buffer),
        NicType::Rtl8139 => crate::drivers::arch::receive_from_rtl8139(nic_idx, buffer),
        NicType::Unknown => None,
    }
}

/// NIC type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicType {
    VirtioNet,
    E1000,
    Rtl8139,
    Unknown,
}

/// Get the count of available NICs
pub fn nic_count() -> usize {
    virtio_net::count() + e1000::count() + { crate::drivers::arch::count_rtl8139() }
}

/// Drain all pending frames from every registered miniport and feed
/// them to the TCP/IP stack. Commands with synchronous waits (such as
/// `ping`) call this while waiting for replies.
pub fn poll_all() {
    let mut buffer = [0u8; 2048];

    for nic_idx in 0..virtio_net::count() {
        while let Some(len) = virtio_net::receive(nic_idx, &mut buffer) {
            if len == 0 {
                break;
            }
            crate::netstack::process_packet(&buffer[..len], NicType::VirtioNet, nic_idx);
        }
    }

    for nic_idx in 0..e1000::count() {
        while let Some(len) = e1000::receive(nic_idx, &mut buffer) {
            if len == 0 {
                break;
            }
            crate::netstack::process_packet(&buffer[..len], NicType::E1000, nic_idx);
        }
    }

    let rtl_count = crate::drivers::arch::count_rtl8139();
    for nic_idx in 0..rtl_count {
        while let Some(len) = crate::drivers::arch::receive_from_rtl8139(nic_idx, &mut buffer) {
            if len == 0 {
                break;
            }
            crate::netstack::process_packet(&buffer[..len], NicType::Rtl8139, nic_idx);
        }
    }

    crate::netstack::tcp::check_retransmit_timers();
}

pub mod tcpip;
