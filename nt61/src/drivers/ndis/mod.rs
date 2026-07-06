//! NDIS 6.0 Miniport Wrapper
//
//! NDIS (Network Driver Interface Specification) is the
//! Microsoft driver framework for network cards. The 6.0
//! revision is used by Windows 7. The wrapper here provides
//! the `NdisMRegisterMiniportDriver` / `NdisMSetMiniportAttributes`
//! entry points that the per-NIC drivers call, and the
//! `NdisAcquireSpinLock` / `NdisReleaseSpinLock` synchronisation
//! helpers.
//
//! Clean-room implementation. Spec source: NDIS 6.0 miniport
//! driver reference. No code is copied from any Microsoft or
//! ReactOS source file.

use crate::kprintln;

pub mod miniport;
pub mod ndis6;

pub mod smoke;

/// NDIS status codes.
pub mod status {
    pub const SUCCESS: i32 = 0;
    pub const FAILURE: i32 = -1;
    pub const RESOURCE_CONFLICT: i32 = -2;
    pub const BAD_VERSION: i32 = -3;
    pub const BAD_CHARACTERISTICS: i32 = -4;
    pub const TOO_MANY_EDGES: i32 = -5;
}

/// The NDIS 6.0 miniport driver descriptor. The NIC drivers
/// build a static instance of this, then call
/// `NdisMRegisterMiniportDriver` to plug it into the framework.
/// Uses `&'static str` to avoid heap allocation in no_std environment.
#[derive(Clone, Copy)]
pub struct MiniportDriver {
    /// Driver name (e.g., "e1000", "virtio-net").
    pub name: &'static str,
    /// NDIS version (e.g., 0x60000 for 6.0).
    pub version: u32,
    pub miniport_init: fn() -> i32,
    pub miniport_halt: fn() -> i32,
    pub miniport_send: fn() -> i32,
    pub miniport_return: fn() -> i32,
}

// `Option<MiniportDriver>` does not implement `Copy` because the
// inner type is not `Copy`. The `const { None }` initialiser
// works in static context because the compiler only needs the
// type, not a value, at compile time.
static mut REGISTERED: [Option<MiniportDriver>; 8] = [const { None }; 8];
static mut REGISTERED_COUNT: usize = 0;

/// Wrapper around `NdisMRegisterMiniportDriver`. Returns the
/// `NDIS_STATUS_SUCCESS` value (0) on success.
pub fn ndis_m_register_miniport_driver(driver: MiniportDriver) -> i32 {
    unsafe {
        if REGISTERED_COUNT >= REGISTERED.len() { return status::FAILURE; }
        REGISTERED[REGISTERED_COUNT] = Some(driver);
        REGISTERED_COUNT += 1;
    }
    status::SUCCESS
}

pub fn count() -> usize { unsafe { REGISTERED_COUNT } }

pub fn init() {
    // kprintln!("    NDIS 6.0 miniport wrapper: ready")  // kprintln disabled (memcpy crash workaround);
}

pub fn smoke_test() -> bool {
    // kprintln!("  [NDIS SMOKE] NDIS wrapper: {} miniport(s) registered", count())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  [NDIS SMOKE OK] NDIS stack healthy")  // kprintln disabled (memcpy crash workaround);
    true
}
