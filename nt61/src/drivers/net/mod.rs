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
#[cfg(target_arch = "x86_64")]
pub mod rtl8139;
pub mod virtio_net;

#[cfg(target_arch = "x86_64")]
pub mod smoke;

use crate::kprintln;

/// Initialise the network driver stack. Walks PCI for each
/// supported NIC and registers it.
pub fn init() {
    // kprintln!("    Network drivers: e1000, rtl8139, virtio-net")  // kprintln disabled (memcpy crash workaround);
    e1000::init();
    #[cfg(target_arch = "x86_64")]
    rtl8139::init();
    virtio_net::init();
    // kprintln!("    Network stack ready")  // kprintln disabled (memcpy crash workaround);
}

/// Smoke test for the network driver stack. Re-runs each NIC's
/// self-check.
pub fn smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    { smoke::smoke_test() }
    #[cfg(not(target_arch = "x86_64"))]
    { true }
}

// =============================================================================
// Protocol Stack Interface
// =============================================================================

/// Send data through a NIC
pub fn send_to_nic(nic_type: NicType, nic_idx: usize, data: &[u8]) -> bool {
    match nic_type {
        NicType::VirtioNet => virtio_net::send(nic_idx, data, false),
        NicType::E1000 => e1000::send(nic_idx, data),
        #[cfg(target_arch = "x86_64")]
        NicType::Rtl8139 => rtl8139::send(nic_idx, data),
        #[cfg(not(target_arch = "x86_64"))]
        NicType::Rtl8139 => false,
        NicType::Unknown => false,
    }
}

/// Receive data from a NIC
pub fn nic_receive(nic_type: NicType, nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    match nic_type {
        NicType::VirtioNet => virtio_net::receive(nic_idx, buffer),
        NicType::E1000 => e1000::receive(nic_idx, buffer),
        #[cfg(target_arch = "x86_64")]
        NicType::Rtl8139 => rtl8139::receive(nic_idx, buffer),
        #[cfg(not(target_arch = "x86_64"))]
        NicType::Rtl8139 => None,
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
    virtio_net::count() + e1000::count()
        + {
            #[cfg(target_arch = "x86_64")]
            { rtl8139::count() }
            #[cfg(not(target_arch = "x86_64"))]
            { 0 }
        }
}
