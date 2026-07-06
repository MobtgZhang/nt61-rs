//! NDIS Protocol Stack Core
//
//! This module provides the NDIS protocol layer that sits between
//! the network drivers and the TCP/IP protocol stack.
//
//! Clean-room implementation based on NDIS 6.0 specification.

use crate::kprintln;

/// NDIS status codes
pub mod status {
    pub const SUCCESS: i32 = 0x00000000;
    pub const PENDING: i32 = 0x00000103;
    pub const FAILURE: i32 = 0xC0000001;
    pub const RESOURCES: i32 = 0xC000009A;
    pub const HARDWARE_ERRORS: i32 = 0xC0000185;
    pub const MEDIA_DISCONNECTED: i32 = 0x4000000B;
    pub const MEDIA_CONNECTED: i32 = 0x4000000A;
    pub const NOT_SUPPORTED: i32 = 0xC00000BB;
}

/// Initialize the NDIS protocol layer
pub fn init() {
    // Initialize interrupt handling subsystem
    interrupt::init();
    
    // kprintln!("    NDIS protocol layer: initialized")  // kprintln disabled (memcpy crash workaround);
}

/// Network buffer list types
pub mod nbl;
/// OID query support
pub mod oid;
/// Packet send support
pub mod send;
/// Miniport adapter support
pub mod miniport_adapter;
/// Interrupt handling and DPC
pub mod interrupt;
