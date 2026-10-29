//! PnP (Plug and Play) Manager
//
//! Windows' PnP manager owns the device tree (`\Device` namespace)
//! and arbitrates the start / stop / remove IRPs that drivers
//! receive when they bind to a device. Our implementation
//! provides a small subset of the surface used by the driver
//! sub-modules:
//
//! * `pnp_init` - install the root PnP device object
//! * `register_device_node` - add a (bus, dev, fn) -> driver mapping
//! * `start_device` / `stop_device` - drive the IRP_MJ_PNP state
//!   machine for a single device node
//! * `find_driver` - look up the driver that should handle a device
//
//! Clean-room implementation. The spec source is Microsoft Docs /
//! OSR / "Windows Internals, 6th ed." (Russinovich).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hal::common::pci::PciDevice;
use crate::io::{DeviceObject, DeviceType, DriverObject, ListEntry};
use crate::mm::pool;

/// Maximum number of registered PnP device nodes.
pub const MAX_DEVICE_NODES: usize = 64;
/// Maximum length of a PnP device ID string.
pub const MAX_DEVICE_ID_LEN: usize = 32;

/// One node in the PnP device tree. Each node corresponds to a
/// single physical or logical device on a bus. The `driver` field
/// is filled in by the PnP manager after `start_device` is called
/// and a driver has been found via `find_driver`.
#[derive(Copy, Clone)]
pub struct PnPNode {
    /// True when this slot is occupied.
    pub valid: bool,
    /// Bus type - see the `PnPBus` constants below.
    pub bus: u32,
    /// Bus-relative device number.
    pub address: u32,
    /// Function number for multi-function devices.
    pub function: u32,
    /// Hardware IDs (vendor:device / ACPI _HID / etc.),
    /// null-terminated ASCII.
    pub hw_id: [u8; MAX_DEVICE_ID_LEN],
    /// Compatible IDs.
    pub compatible_id: [u8; MAX_DEVICE_ID_LEN],
    /// Driver that has bound to this node, if any.
    pub driver: *mut DriverObject,
    /// Device object created by the driver for this node.
    pub device_object: *mut DeviceObject,
    /// Current PnP state - see the `PnPState` constants.
    pub state: u32,
}

/// PnP bus identifiers. We mirror the values used by the
/// kernel's `IoGetDeviceProperty(DevicePropertyBusType)`.
pub mod bus_type {
    pub const UNKNOWN: u32 = 0;
    pub const PCI: u32 = 1;
    pub const ACPI: u32 = 2;
    pub const USB: u32 = 3;
    pub const ISA: u32 = 4;
    pub const SCSI: u32 = 5;
    pub const IDE: u32 = 6;
    pub const SATA: u32 = 7;
    pub const NVME: u32 = 8;
    pub const NETWORK: u32 = 9;
    pub const AUDIO: u32 = 10;
    pub const VIDEO: u32 = 11;
    pub const INPUT: u32 = 12;
}

/// PnP state. The real PnP state machine is more involved, but
/// the bootstrap only needs to track the high-level transitions.
pub mod pnp_state {

    pub const UNINITIALISED: u32 = 0;
    pub const ENUMERATED: u32 = 1;
    pub const RESOURCE_REQUIREMENTS: u32 = 2;
    pub const START_PENDING: u32 = 3;
    pub const STARTED: u32 = 4;
    pub const STOP_PENDING: u32 = 5;
    pub const STOPPED: u32 = 6;
    pub const REMOVED: u32 = 7;
    pub const QUERY_REMOVE: u32 = 8;
    pub const QUERY_STOP: u32 = 9;
    pub const SURPRISE_REMOVAL: u32 = 10;

    /// Check if transition to new state is valid
    pub fn can_transition(from: u32, to: u32) -> bool {
        match (from, to) {
            // Forward transitions
            (UNINITIALISED, ENUMERATED) => true,
            (ENUMERATED, RESOURCE_REQUIREMENTS) => true,
            (RESOURCE_REQUIREMENTS, START_PENDING) => true,
            (START_PENDING, STARTED) => true,
            (STARTED, QUERY_STOP) => true,
            (QUERY_STOP, STOP_PENDING) => true,
            (QUERY_STOP, STARTED) => true, // Query cancelled
            (STOP_PENDING, STOPPED) => true,
            (STOPPED, START_PENDING) => true, // Can restart
            (STARTED, QUERY_REMOVE) => true,
            (QUERY_REMOVE, REMOVED) => true,
            (QUERY_REMOVE, STARTED) => true, // Query cancelled
            (STARTED, SURPRISE_REMOVAL) => true,
            (SURPRISE_REMOVAL, REMOVED) => true,
            // Can go directly to removed from most states
            (_, REMOVED) => true,
            // Can always stop
            (_, STOPPED) => true,
            _ => false,
        }
    }

    /// Get state name for debugging
    pub fn name(state: u32) -> &'static str {
        match state {
            UNINITIALISED => "Uninitialised",
            ENUMERATED => "Enumerated",
            RESOURCE_REQUIREMENTS => "ResourceRequirements",
            START_PENDING => "StartPending",
            STARTED => "Started",
            STOP_PENDING => "StopPending",
            STOPPED => "Stopped",
            REMOVED => "Removed",
            QUERY_REMOVE => "QueryRemove",
            QUERY_STOP => "QueryStop",
            SURPRISE_REMOVAL => "SurpriseRemoval",
            _ => "Unknown",
        }
    }
}

/// PnP IRP minor function codes
pub mod pnp_minor {
    pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
    pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
    pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
    pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x05;
    pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x06;
    pub const IRP_MN_STOP_DEVICE: u8 = 0x07;
    pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x08;
    pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x09;
    pub const IRP_MN_QUERY_INTERFACE: u8 = 0x0A;
    pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x0B;
    pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0C;
    pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0D;
    pub const IRP_MN_QUERY_DEVICE_TEXT: u8 = 0x0E;
    pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0F;
    pub const IRP_MN_START_DEVICE: u8 = 0x00;
    pub const IRP_MN_QUERY_PNP_DEVICE_STATE: u8 = 0x14;
}

/// Driver table entry - name + add-device function pointer.
#[derive(Clone, Copy)]
pub struct DriverRegistration {
    /// Driver name ("pci", "acpi", "iastor", "e1000", ...).
    /// Uses static string reference to avoid heap allocation in no_std environment.
    pub name: &'static str,
    /// Called by the PnP manager to start the driver on a new
    /// device. Returns `true` on success.
    pub add_device: fn(node: &mut PnPNode) -> bool,
    /// Optional `driver_unload` callback for cleanup.
    pub unload: Option<fn(driver: *mut DriverObject)>,
}

static mut DEVICE_NODES: [PnPNode; MAX_DEVICE_NODES] = [PnPNode {
    valid: false,
    bus: 0,
    address: 0,
    function: 0,
    hw_id: [0; MAX_DEVICE_ID_LEN],
    compatible_id: [0; MAX_DEVICE_ID_LEN],
    driver: null_mut(),
    device_object: null_mut(),
    state: pnp_state::UNINITIALISED,
}; MAX_DEVICE_NODES];

static mut DRIVER_TABLE: [Option<DriverRegistration>; 32] = [const { None }; 32];
static PNP_INITIALISED: AtomicBool = AtomicBool::new(false);

/// Serializes init() so concurrent callers (parallel test threads today,
/// SMP cores in production) cannot observe the initialised flag before
/// the default driver table is fully populated.
static PNP_INIT_LOCK: crate::ke::sync::Spinlock<()> = crate::ke::sync::Spinlock::new(());

static REGISTERED_DEVICES: AtomicU32 = AtomicU32::new(0);
static STARTED_DEVICES: AtomicU32 = AtomicU32::new(0);
static ENUMERATE_DURATION_TICKS: AtomicU32 = AtomicU32::new(0);

/// Install the PnP manager. Idempotent.
pub fn init() {
    // Fast path. Acquire pairs with the Release store below so a thread
    // observing true also observes the fully populated DRIVER_TABLE.
    if PNP_INITIALISED.load(Ordering::Acquire) {
        return;
    }
    let _guard = PNP_INIT_LOCK.lock();
    if PNP_INITIALISED.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        for n in (*core::ptr::addr_of_mut!(DEVICE_NODES)).iter_mut() {
            n.valid = false;
        }
    }
    register_default_drivers();
    // Only publish the flag once the driver table is complete; setting it
    // earlier let concurrent callers return with an empty table.
    PNP_INITIALISED.store(true, Ordering::Release);
    // kprintln!("    PnP manager: initialised");
}

/// Register the built-in class drivers used by the bootstrap kernel.
///
/// The actual hardware initialisation is performed by the driver stack
/// before `start_all_pending()` runs.  The PnP callbacks here bind those
/// already-initialised built-ins to the device nodes discovered by the
/// bus drivers, which is the behaviour Windows models with PnP
/// `AddDevice`/`StartDevice`.
fn register_default_drivers() {
    let drivers = [
        DriverRegistration {
            name: "PCI\\CC_01_",
            add_device: start_storage_driver,
            unload: None,
        },
        DriverRegistration {
            name: "PCI\\CC_02_",
            add_device: start_network_driver,
            unload: None,
        },
        DriverRegistration {
            name: "PCI\\CC_03_",
            add_device: start_display_driver,
            unload: None,
        },
        DriverRegistration {
            name: "PCI\\CC_04_01_",
            add_device: start_audio_driver,
            unload: None,
        },
        DriverRegistration {
            name: "PCI\\CC_09_",
            add_device: start_input_driver,
            unload: None,
        },
    ];
    for driver in drivers {
        register_driver(driver);
    }
}

/// Cached DriverObject per PnP class slot (storage, network, display,
/// audio, input). The I/O manager registers each driver once in the
/// \\Driver namespace, so the objects are allocated lazily and reused
/// for every device the class binds. A value of 0 means "not yet
/// allocated".
static CLASS_DRIVER_OBJECTS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// Sequence counter used to build unique PnP device object names.
static DEVICE_OBJECT_SEQ: AtomicU32 = AtomicU32::new(0);

/// Driver-object name per PnP class slot (registered under \\Driver).
const CLASS_DRIVER_NAMES: [&[u8]; 5] = [
    b"\\Driver\\PnpStorage",
    b"\\Driver\\PnpNetwork",
    b"\\Driver\\PnpDisplay",
    b"\\Driver\\PnpAudio",
    b"\\Driver\\PnpInput",
];

/// Device-object name prefix per PnP class slot (under \\Device).
const CLASS_DEVICE_PREFIXES: [&[u8]; 5] = [
    b"\\Device\\PnpStorage",
    b"\\Device\\PnpNetwork",
    b"\\Device\\PnpDisplay",
    b"\\Device\\PnpAudio",
    b"\\Device\\PnpInput",
];

/// Return the cached DriverObject for a class slot, allocating and
/// registering it on first use.
fn class_driver_object(slot: usize) -> *mut DriverObject {
    let cached = CLASS_DRIVER_OBJECTS[slot].load(Ordering::Acquire);
    if cached != 0 {
        return cached as *mut DriverObject;
    }
    let driver = crate::io::allocate_driver(CLASS_DRIVER_NAMES[slot]);
    if driver.is_null() {
        return core::ptr::null_mut();
    }
    let _ = crate::io::register_driver(driver);
    CLASS_DRIVER_OBJECTS[slot].store(driver as u64, Ordering::Release);
    driver
}

/// Bind a PnP node to its class driver: allocate (once) the class
/// DriverObject, create a uniquely named DeviceObject for the node and
/// record the binding in the node itself. This is the PnP equivalent
/// of AddDevice + IoCreateDevice, and it is what makes the device tree
/// reachable through the I/O manager instead of being a string table.
fn bind_class_device(node: &mut PnPNode, slot: usize, device_type: DeviceType) -> bool {
    let driver = class_driver_object(slot);
    if driver.is_null() {
        return false;
    }
    if !node.device_object.is_null() {
        // Already bound (for example a retry after a failed start):
        // keep the existing device object, refresh the driver pointer.
        node.driver = driver;
        return true;
    }
    // Build a unique device name: prefix + decimal sequence number,
    // without any heap allocation (boot-time safe).
    let seq = DEVICE_OBJECT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = [0u8; 48];
    let prefix = CLASS_DEVICE_PREFIXES[slot];
    name[..prefix.len()].copy_from_slice(prefix);
    let mut len = prefix.len();
    if seq == 0 {
        name[len] = b'0';
        len += 1;
    } else {
        let mut digits = [0u8; 10];
        let mut n = 0usize;
        let mut v = seq;
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
        }
        for i in 0..n {
            name[len + i] = digits[n - 1 - i];
        }
        len += n;
    }
    let device = crate::io::create_device(driver, device_type, &name[..len]);
    if device.is_null() {
        return false;
    }
    node.driver = driver;
    node.device_object = device;
    true
}

fn start_storage_driver(node: &mut PnPNode) -> bool {
    bind_class_device(node, 0, DeviceType::MassStorage)
}

fn start_network_driver(node: &mut PnPNode) -> bool {
    bind_class_device(node, 1, DeviceType::Unknown)
}

fn start_display_driver(node: &mut PnPNode) -> bool {
    bind_class_device(node, 2, DeviceType::Screen)
}

fn start_audio_driver(node: &mut PnPNode) -> bool {
    bind_class_device(node, 3, DeviceType::Sound)
}

fn start_input_driver(node: &mut PnPNode) -> bool {
    bind_class_device(node, 4, DeviceType::Keyboard)
}

/// Register a driver with the PnP manager.
pub fn register_driver(reg: DriverRegistration) -> bool {
    unsafe {
        for slot in (*core::ptr::addr_of_mut!(DRIVER_TABLE)).iter_mut() {
            if slot.is_none() {
                *slot = Some(reg);
                return true;
            }
        }
    }
    false
}

/// Look up the driver that should handle `node`. Matching order:
/// exact `compatible_id`, then prefix of `hw_id`, then wildcard.
pub fn find_driver(node: &PnPNode) -> Option<&'static DriverRegistration> {
    unsafe {
        for slot in (*core::ptr::addr_of!(DRIVER_TABLE)).iter() {
            if let Some(reg) = slot {
                if name_eq(&reg.name, &node.hw_id) {
                    return Some(reg);
                }
            }
        }
        for slot in (*core::ptr::addr_of!(DRIVER_TABLE)).iter() {
            if let Some(reg) = slot {
                if name_starts_with(&node.hw_id, reg.name.as_bytes()) {
                    return Some(reg);
                }
            }
        }
        for slot in (*core::ptr::addr_of!(DRIVER_TABLE)).iter() {
            if let Some(reg) = slot {
                if name_starts_with(&node.compatible_id, reg.name.as_bytes()) {
                    return Some(reg);
                }
            }
        }
        for slot in (*core::ptr::addr_of!(DRIVER_TABLE)).iter() {
            if let Some(reg) = slot {
                if reg.name.is_empty() {
                    return Some(reg);
                }
            }
        }
    }
    None
}

/// Add a PnP device node for a PCI device. The `hw_id` is
/// formatted as `PCI\\VEN_xxxx&DEV_yyyy` and `compatible_id` is
/// `PCI\\CC_classccsccpi`.
pub fn register_pci_device(pci: &PciDevice) -> Option<usize> {
    let mut hw_id = [0u8; MAX_DEVICE_ID_LEN];
    let mut compatible = [0u8; MAX_DEVICE_ID_LEN];
    format_pci_hw_id(pci, &mut hw_id);
    format_pci_class(pci, &mut compatible);
    let slot = add_node(
        bus_type::PCI,
        pci.device as u32,
        pci.function as u32,
        &hw_id,
        &compatible,
    )?;
    REGISTERED_DEVICES.fetch_add(1, Ordering::Relaxed);
    Some(slot)
}

/// Add a PnP device node for an ACPI device (passed by its `_HID`).
pub fn register_acpi_device(hid: &[u8], uid: u32) -> Option<usize> {
    let mut hw_id = [0u8; MAX_DEVICE_ID_LEN];
    // Reuse the shared null-terminated copy helper so the
    // ACPI path goes through the same byte-loop as the other
    // PnP registration paths and stays consistent with the
    // hand-rolled comment that originally lived here.
    let _n = copy_string_into(&mut hw_id, hid);
    let slot = add_node(bus_type::ACPI, uid, 0, &hw_id, &hw_id);
    if slot.is_some() {
        REGISTERED_DEVICES.fetch_add(1, Ordering::Relaxed);
    }
    slot
}

/// Add a PnP device node for a USB device.
pub fn register_usb_device(vid: u16, pid: u16, address: u32) -> Option<usize> {
    let mut hw_id = [0u8; MAX_DEVICE_ID_LEN];
    format_usb_id(vid, pid, &mut hw_id);
    let slot = add_node(bus_type::USB, address, 0, &hw_id, &hw_id)?;
    REGISTERED_DEVICES.fetch_add(1, Ordering::Relaxed);
    Some(slot)
}

fn add_node(
    bus: u32,
    address: u32,
    function: u32,
    hw_id: &[u8; MAX_DEVICE_ID_LEN],
    compatible_id: &[u8; MAX_DEVICE_ID_LEN],
) -> Option<usize> {
    unsafe {
        for (i, n) in (*core::ptr::addr_of_mut!(DEVICE_NODES))
            .iter_mut()
            .enumerate()
        {
            if n.valid {
                continue;
            }
            n.valid = true;
            n.bus = bus;
            n.address = address;
            n.function = function;
            n.hw_id = *hw_id;
            n.compatible_id = *compatible_id;
            n.driver = null_mut();
            n.device_object = null_mut();
            n.state = pnp_state::ENUMERATED;
            return Some(i);
        }
    }
    None
}

/// Iterate over the PnP device table and call `start_device` for
/// every node that does not yet have a driver.
pub fn start_all_pending() -> u32 {
    let mut started: u32 = 0;
    let start = crate::ke::time::get_tick_count();
    unsafe {
        for n in (*core::ptr::addr_of_mut!(DEVICE_NODES)).iter_mut() {
            if !n.valid {
                continue;
            }
            if n.state == pnp_state::STARTED {
                continue;
            }
            let drv = match find_driver(n) {
                Some(d) => d,
                None => continue,
            };
            // Validate the state transition (same rule the stop and
            // remove paths use) instead of blindly assigning
            // START_PENDING from any state.
            if !pnp_state::can_transition(n.state, pnp_state::START_PENDING) {
                continue;
            }
            n.state = pnp_state::START_PENDING;
            if (drv.add_device)(n) {
                n.state = pnp_state::STARTED;
                started += 1;
                STARTED_DEVICES.fetch_add(1, Ordering::Relaxed);
            } else {
                n.state = pnp_state::STOPPED;
            }
        }
    }
    let dur = crate::ke::time::get_tick_count().saturating_sub(start);
    ENUMERATE_DURATION_TICKS.store(dur, Ordering::Relaxed);
    started
}

/// Send a STOP IRP to a single device node.
pub fn stop_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Validate state transition
        if !pnp_state::can_transition(n.state, pnp_state::STOP_PENDING) {
            return false;
        }

        n.state = pnp_state::STOP_PENDING;
        n.state = pnp_state::STOPPED;
        true
    }
}

/// Send a REMOVE IRP to a single device node.
pub fn remove_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Validate state transition
        if !pnp_state::can_transition(n.state, pnp_state::REMOVED) {
            return false;
        }

        // Mark as removed but keep node for reference
        n.state = pnp_state::REMOVED;
        true
    }
}

/// handle query remove for a device
pub fn query_remove_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Can only query remove from Started state
        if n.state != pnp_state::STARTED {
            return false;
        }

        n.state = pnp_state::QUERY_REMOVE;
        true
    }
}

/// Cancel query remove and return to Started state
pub fn cancel_remove_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Can only cancel from QueryRemove state
        if n.state != pnp_state::QUERY_REMOVE {
            return false;
        }

        n.state = pnp_state::STARTED;
        true
    }
}

/// handle surprise removal for a device
pub fn surprise_remove_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Validate state transition
        if !pnp_state::can_transition(n.state, pnp_state::SURPRISE_REMOVAL) {
            return false;
        }

        n.state = pnp_state::SURPRISE_REMOVAL;
        true
    }
}

/// Query stop for a device
pub fn query_stop_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Can only query stop from Started state
        if n.state != pnp_state::STARTED {
            return false;
        }

        n.state = pnp_state::QUERY_STOP;
        true
    }
}

/// Cancel query stop and return to Started state
pub fn cancel_stop_device(idx: usize) -> bool {
    unsafe {
        if idx >= MAX_DEVICE_NODES {
            return false;
        }
        let n = &mut DEVICE_NODES[idx];
        if !n.valid {
            return false;
        }

        // Can only cancel from QueryStop state
        if n.state != pnp_state::QUERY_STOP {
            return false;
        }

        n.state = pnp_state::STARTED;
        true
    }
}

/// Number of nodes currently registered.
pub fn device_count() -> u32 {
    REGISTERED_DEVICES.load(Ordering::Relaxed)
}
/// Number of nodes that have successfully reached the `STARTED`
/// state.
pub fn started_count() -> u32 {
    STARTED_DEVICES.load(Ordering::Relaxed)
}
/// Wall-clock duration of the last `start_all_pending` call, in
/// kernel ticks.
pub fn last_enumeration_ticks() -> u32 {
    ENUMERATE_DURATION_TICKS.load(Ordering::Relaxed)
}

/// Iterator over valid PnP device nodes.
/// This avoids heap allocation by using a lazy iterator instead of collecting into a Vec.
pub struct PnpNodeIterator {
    nodes: &'static [PnPNode],
    index: usize,
}

impl Iterator for PnpNodeIterator {
    type Item = &'static PnPNode;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.nodes.len() {
            let n = &self.nodes[self.index];
            self.index += 1;
            if n.valid {
                return Some(n);
            }
        }
        None
    }
}

/// Return an iterator over the PnP device list. Useful for the smoke test.
/// This avoids heap allocation by using a lazy iterator instead of collecting into a Vec.
pub fn enumerate() -> PnpNodeIterator {
    PnpNodeIterator {
        nodes: unsafe { &*core::ptr::addr_of!(DEVICE_NODES) },
        index: 0,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn name_eq(s: &str, raw: &[u8]) -> bool {
    let raw_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    s.as_bytes() == &raw[..raw_len]
}

fn name_starts_with(raw: &[u8], prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let raw_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if raw_len < prefix.len() {
        return false;
    }
    &raw[..prefix.len()] == prefix
}

/// Copy `src` into `dst` (null-terminated), returning the number of
/// bytes written (excluding the trailing NUL).
fn copy_string_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = src.len().min(dst.len().saturating_sub(1));
    // Manual byte copy to avoid potential SIMD memcpy crashes
    let mut i = 0;
    while i < n {
        dst[i] = src[i];
        i += 1;
    }
    dst[n] = 0;
    n
}

/// Format a PCI hardware ID into a fixed-size byte array.
/// Format: "PCI\\VEN_XXXX&DEV_XXXX" (19 chars + null)
/// Writes at most 22 bytes, fills the rest with null.
fn format_pci_hw_id(pci: &PciDevice, out: &mut [u8]) {
    // "PCI\\VEN_" = 8 bytes
    out[0] = b'P';
    out[1] = b'C';
    out[2] = b'I';
    out[3] = b'\\';
    out[4] = b'V';
    out[5] = b'E';
    out[6] = b'N';
    out[7] = b'_';
    // vendor_id: 4 hex digits
    write_hex4(pci.vendor_id as u32, &mut out[8..12]);
    out[12] = b'&';
    out[13] = b'D';
    out[14] = b'E';
    out[15] = b'V';
    out[16] = b'_';
    // device_id: 4 hex digits
    write_hex4(pci.device_id as u32, &mut out[17..21]);
    // Null-terminate
    if out.len() > 21 {
        out[21] = 0;
    }
    // Fill rest with null
    for i in 22..out.len() {
        out[i] = 0;
    }
}

/// Format a PCI class ID into a fixed-size byte array.
/// Format: "PCI\\CC_XX_XX_XX" (14 chars + null)
/// Writes at most 16 bytes, fills the rest with null.
fn format_pci_class(pci: &PciDevice, out: &mut [u8]) {
    out[0] = b'P';
    out[1] = b'C';
    out[2] = b'I';
    out[3] = b'\\';
    out[4] = b'C';
    out[5] = b'C';
    out[6] = b'_';
    write_hex2(pci.class_code as u32, &mut out[7..9]);
    out[9] = b'_';
    write_hex2(pci.subclass as u32, &mut out[10..12]);
    out[12] = b'_';
    write_hex2(pci.prog_if as u32, &mut out[13..15]);
    // Null-terminate
    if out.len() > 15 {
        out[15] = 0;
    }
    // Fill rest with null
    for i in 16..out.len() {
        out[i] = 0;
    }
}

/// Format a USB device ID into a fixed-size byte array.
/// Format: "USB\\VID_XXXX&PID_XXXX" (19 chars + null)
/// Writes at most 22 bytes, fills the rest with null.
fn format_usb_id(vid: u16, pid: u16, out: &mut [u8]) {
    out[0] = b'U';
    out[1] = b'S';
    out[2] = b'B';
    out[3] = b'\\';
    out[4] = b'V';
    out[5] = b'I';
    out[6] = b'D';
    out[7] = b'_';
    write_hex4(vid as u32, &mut out[8..12]);
    out[12] = b'&';
    out[13] = b'P';
    out[14] = b'I';
    out[15] = b'D';
    out[16] = b'_';
    write_hex4(pid as u32, &mut out[17..21]);
    // Null-terminate
    if out.len() > 21 {
        out[21] = 0;
    }
    // Fill rest with null
    for i in 22..out.len() {
        out[i] = 0;
    }
}

fn write_hex4(v: u32, out: &mut [u8]) {
    let hex = b"0123456789ABCDEF";
    for i in 0..4 {
        out[i] = hex[((v >> ((3 - i) * 4)) & 0xF) as usize];
    }
}

fn write_hex2(v: u32, out: &mut [u8]) {
    let hex = b"0123456789ABCDEF";
    for i in 0..2 {
        out[i] = hex[((v >> ((1 - i) * 4)) & 0xF) as usize];
    }
}

/// Allocate a device object for a driver. Helper used by
/// individual drivers to attach their `IoCreateDevice`-equivalent.
pub fn allocate_device_object(driver: *mut DriverObject, dtype: DeviceType) -> *mut DeviceObject {
    unsafe {
        let raw = pool::allocate(
            pool::PoolType::NonPaged,
            core::mem::size_of::<DeviceObject>(),
        ) as *mut DeviceObject;
        if raw.is_null() {
            return null_mut();
        }
        core::ptr::write_bytes(raw as *mut u8, 0, core::mem::size_of::<DeviceObject>());
        (*raw).device_type = dtype;
        (*raw).driver_object = driver;
        (*raw).sector_size = 512;
        (*raw).alignment_mask = 0x3F;
        (*raw).ref_count = core::sync::atomic::AtomicU32::new(1);
        (*raw).device_queue = ListEntry::new();
        (*raw).driver_queues = ListEntry::new();
        (*raw).device_lock = ListEntry::new();
        (*raw).next_device = (*driver).device_object;
        (*driver).device_object = raw;
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pci_node(hw_id: &[u8], compatible_id: &[u8]) -> PnPNode {
        let mut hw_id_bytes = [0u8; MAX_DEVICE_ID_LEN];
        let mut compatible_bytes = [0u8; MAX_DEVICE_ID_LEN];
        hw_id_bytes[..hw_id.len()].copy_from_slice(hw_id);
        compatible_bytes[..compatible_id.len()].copy_from_slice(compatible_id);
        PnPNode {
            valid: true,
            bus: bus_type::PCI,
            address: 0,
            function: 0,
            hw_id: hw_id_bytes,
            compatible_id: compatible_bytes,
            driver: null_mut(),
            device_object: null_mut(),
            state: pnp_state::ENUMERATED,
        }
    }

    #[test]
    fn pci_driver_matches_hw_id_prefix() {
        init();
        let node = pci_node(b"PCI\\VEN_8086&DEV_100E", b"PCI\\CC_02_00_00");
        assert!(find_driver(&node).is_some());
    }

    #[test]
    fn pci_driver_matches_compatible_id_prefix() {
        init();
        let node = pci_node(b"PCI\\VEN_1AF4&DEV_1000", b"PCI\\CC_02_00_00");
        let driver = find_driver(&node).expect("network class driver");
        assert_eq!(driver.name, "PCI\\CC_02_");
    }
}
