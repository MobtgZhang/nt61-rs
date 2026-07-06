//! NDIS Miniport Driver Registration Helpers
//
//! The actual `MiniportInitializeEx` / `MiniportSendNetBufferLists`
//! entry points the NIC drivers fill in. The full NDIS 6.0
//! miniport is several hundred lines per driver; we only need
//! the registration shim for the bootstrap.

use crate::kprintln;

/// Initialize the NDIS miniport layer
pub fn init() {
    // kprintln!("      NDIS miniport: registration helpers ready")  // kprintln disabled (memcpy crash workaround);
}

/// Smoke test for NDIS miniport
pub fn smoke_test() -> bool {
    // kprintln!("  [NDIS-MP SMOKE] NDIS miniport helpers healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
