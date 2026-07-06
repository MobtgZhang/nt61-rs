//! I/O Manager
//
//! NT-style I/O manager. The I/O manager is the layer between
//! user-mode applications and device drivers. It manages:
//
//!   * **IRP pool** — allocation of I/O Request Packets (IRPs).
//!   * **Driver database** — a linked list of `DriverObject`s.
//!   * **Device tree** — each driver owns a list of `DeviceObject`s.
//!   * **VPB table** — Volume Parameter Blocks for mounted filesystems.
//!   * **I/O system counters** — bytes read/written, IRPs processed.
//
//! The smoke test creates a dummy driver, attaches a dummy device,
//! allocates an IRP, routes it through the driver stack, and
//! completes it.

// I/O manager uses NT-driver naming (IRP, IRP_MJ_*, IO_*, ...).
#![allow(unused_imports)]

use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ke::sync::Spinlock;
use crate::kprintln;
use crate::mm::pool;

pub mod smoke;

// ---------------------------------------------------------------------------
// I/O system constants
// ---------------------------------------------------------------------------

/// Maximum drivers in the global driver list.
pub const MAX_DRIVERS: usize = 32;
/// Maximum devices per driver.
pub const MAX_DEVICES: usize = 64;
/// Maximum VPBs (mounted volumes).
pub const MAX_VPBs: usize = 16;
/// Maximum IRPs we can hold in the bootstrap pool.
pub const MAX_IRP_POOL: usize = 128;

/// I/O function codes.
pub mod major {
    pub const IRP_MJ_CREATE: u8 = 0x00;
    pub const IRP_MJ_CLOSE: u8 = 0x01;
    pub const IRP_MJ_READ: u8 = 0x03;
    pub const IRP_MJ_WRITE: u8 = 0x04;
    pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
    pub const IRP_MJ_PNP: u8 = 0x0F;
    pub const IRP_MJ_POWER: u8 = 0x10;
    pub const IRP_MJ_CLEANUP: u8 = 0x12;
}

/// PnP minor function codes (IRP_MN_*).
/// These are the minor function codes used in IRP_MJ_PNP IRPs.
pub mod pnp {
    pub const IRP_MN_START_DEVICE: u8 = 0x00;
    pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
    pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
    pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
    pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
    pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
    pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
    pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x07;
    pub const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
    pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;
    pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0A;
    pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0B;
    pub const IRP_MN_QUERY_DEVICE_TEXT: u8 = 0x0C;
    pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0D;
    pub const IRP_MN_CONFIRM_QUERY_DEVICE_CONFIRM: u8 = 0x0E;
    pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;
    pub const IRP_MN_QUERY_LEGACY_BUS_INFORMATION: u8 = 0x19;
}

/// Power IRP minor function codes (IRP_MN_*).
/// These are the minor function codes used in IRP_MJ_POWER IRPs.
pub mod power {
    pub const IRP_MN_WAIT_WAKE: u8 = 0x00;
    pub const IRP_MN_POWER_SEQUENCE: u8 = 0x01;
    pub const IRP_MN_SET_POWER: u8 = 0x02;
    pub const IRP_MN_QUERY_POWER: u8 = 0x03;
}

/// Power state types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerStateType {
    System = 0,
    Device = 1,
}

/// System power states (S0-S5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SystemPowerState {
    S0 = 0,  // Working
    S1 = 1,  // Sleep
    S2 = 2,  // Deeper sleep
    S3 = 3,  // Suspend to RAM
    S4 = 4,  // Hibernate
    S5 = 5,  // Soft off
}

/// Device power states (D0-D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DevicePowerState {
    D0 = 0,  // Working
    D1 = 1,  // Lightest sleep
    D2 = 2,  // Deeper sleep
    D3 = 3,  // Deepest sleep (hot removed)
}

/// Power action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerActionType {
    PowerActionNone = 0,
    PowerActionReserved = 1,
    PowerActionSleep = 2,
    PowerActionHibernate = 3,
    PowerActionShutdown = 4,
    PowerActionShutdownReset = 5,
    PowerActionShutdownOff = 6,
    PowerActionWarmEject = 7,
}

/// Device object types.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum DeviceType {
    Beep = 0x00000001,
    CDRom = 0x00000002,
    Disk = 0x00000007,
    FileSystem = 0x00000009,
    Keyboard = 0x0000000B,
    Mouse = 0x0000000D,
    ParallelPort = 0x00000015,
    SerialPort = 0x0000001A,
    Screen = 0x0000001B,
    Sound = 0x0000001C,
    Null = 0x00000014,
    Unknown = 0x00000021,
    VirtualDisk = 0x00000023,
    ACPI = 0x0000002E,
    MassStorage = 0x0000002C,
}

/// Device object flags.
pub const DO_VERIFY_VOLUME: u32 = 0x00000002;
pub const DO_BUFFERED_IO: u32 = 0x00000004;
pub const DO_EXCLUSIVE: u32 = 0x00000008;
pub const DO_BIT_LOCKED: u32 = 0x00000100;
pub const DO_POWER_PAGABLE: u32 = 0x00000100;

/// PnP device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DevicePnPState {
    /// Device is not yet registered.
    NotStarted = 0,
    /// Device is started and working.
    Started = 1,
    /// Device is stopped (was started, then stopped).
    Stopped = 2,
    /// Device is in the process of being removed.
    RemovePending = 3,
    /// Device has been surprise-removed.
    SurpriseRemoved = 4,
    /// Device is deleted.
    Deleted = 5,
}

/// PnP device state history for lifecycle tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DevicePreviousState {
    NotStarted = 0,
    Started = 1,
    Stopped = 2,
    RemovePending = 3,
    SurpriseRemoved = 4,
}

// ---------------------------------------------------------------------------
// I/O system state
// ---------------------------------------------------------------------------

struct IoStats {
    irps_allocated: u64,
    irps_completed: u64,
    irps_cancelled: u64,
    bytes_read: u64,
    bytes_written: u64,
    reads: u64,
    writes: u64,
}

static IO_STATS: Spinlock<IoStats> = Spinlock::new(IoStats {
    irps_allocated: 0,
    irps_completed: 0,
    irps_cancelled: 0,
    bytes_read: 0,
    bytes_written: 0,
    reads: 0,
    writes: 0,
});

/// Global driver list.
static DRIVER_LIST: Spinlock<[Option<DriverEntry>; MAX_DRIVERS]> =
    Spinlock::new([const { None }; MAX_DRIVERS]);

/// VPB (Volume Parameter Block) table.
#[allow(unused)]
static VPB_TABLE: Spinlock<[Option<Vpb>; MAX_VPBs]> =
    Spinlock::new([const { None }; MAX_VPBs]);

/// I/O manager signature tag for sanity checks.
pub const IO_MANAGER_TAG: u32 =
    (b'I' as u32) << 24
    | (b'o' as u32) << 16
    | (b'M' as u32) << 8
    | (b'0' as u32);

// ---------------------------------------------------------------------------
// List entry
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    pub const fn new() -> Self {
        Self { flink: null_mut(), blink: null_mut() }
    }

    pub fn init(&mut self) {
        self.flink = null_mut();
        self.blink = null_mut();
    }

    pub fn is_empty(&self) -> bool {
        self.flink.is_null() && self.blink.is_null()
    }
}

// ---------------------------------------------------------------------------
// IRP
// ---------------------------------------------------------------------------

/// IRP (I/O Request Packet). We only derive `Clone` (not `Copy`)
/// because `IoStackLocation` contains a union that is not `Copy`.
#[repr(C)]
pub struct Irp {
    pub mdl_address: *mut (),
    pub flags: u32,
    pub associated_irp: *mut Irp,
    pub thread_list_entry: ListEntry,
    pub io_status: IoStatusBlock,
    pub requestor_mode: u8,
    pub pending_returned: u8,
    pub stack_count: u8,
    pub current_location: u8,
    pub packet_type: u8,
    pub allocate_stack: u8,
    pub current_stack: *mut IoStackLocation,
    pub original_irp: *mut Irp,
}

impl Irp {
    pub const fn new() -> Self {
        Self {
            mdl_address: null_mut(),
            flags: 0,
            associated_irp: null_mut(),
            thread_list_entry: ListEntry::new(),
            io_status: IoStatusBlock::new(),
            requestor_mode: 0,
            pending_returned: 0,
            stack_count: 0,
            current_location: 0,
            packet_type: 0,
            allocate_stack: 0,
            current_stack: null_mut(),
            original_irp: null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct IoStatusBlock {
    pub status: u32,
    pub information: usize,
}

impl IoStatusBlock {
    pub const fn new() -> Self {
        Self { status: 0, information: 0 }
    }
}

#[repr(C)]
pub union IoParameters {
    pub as_u64: u64,
}

#[repr(C)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: IoParameters,
    pub device_object: *mut DeviceObject,
    pub file_object: *mut FileObject,
}

impl IoStackLocation {
    pub const fn new() -> Self {
        Self {
            major_function: 0,
            minor_function: 0,
            flags: 0,
            control: 0,
            parameters: IoParameters { as_u64: 0 },
            device_object: null_mut(),
            file_object: null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct FileObject {
    pub device_object: *mut DeviceObject,
    pub vpb: *mut Vpb,
    pub fcb: *mut (),
    pub file_name: UnicodeString,
    pub current_byte_offset: u64,
    pub flags: u32,
}

impl FileObject {
    pub const fn new() -> Self {
        Self {
            device_object: null_mut(),
            vpb: null_mut(),
            fcb: null_mut(),
            file_name: UnicodeString::new(),
            current_byte_offset: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UnicodeString {
    pub const fn new() -> Self {
        Self { Length: 0, MaximumLength: 0, Buffer: null_mut() }
    }
}

// ---------------------------------------------------------------------------
// Device object
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct DeviceObject {
    pub device_type: DeviceType,
    pub characteristics: u32,
    pub vpb: *mut Vpb,
    pub device_queue: ListEntry,
    pub dpc: *mut (),
    pub driver_object: *mut DriverObject,
    pub next_device: *mut DeviceObject,
    pub attached_device: *mut DeviceObject,
    pub current_irp: *mut Irp,
    pub sector_size: u16,
    pub alignment_mask: u16,
    pub driver_queues: ListEntry,
    pub security_descriptor: *mut (),
    pub device_lock: ListEntry,
    pub ref_count: AtomicU32,
    pub attached_to: Option<*mut DeviceObject>,
    pub device_name: UnicodeString,
    /// PnP state - device lifecycle state machine.
    pub pnp_state: DevicePnPState,
    /// Previous PnP state - used for state transitions.
    pub previous_pnp_state: DevicePreviousState,
    /// Current device power state.
    pub device_power_state: DevicePowerState,
    /// Device power flags.
    pub power_flags: u32,
}

impl DeviceObject {
    pub const fn new() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            characteristics: 0,
            vpb: null_mut(),
            device_queue: ListEntry::new(),
            dpc: null_mut(),
            driver_object: null_mut(),
            next_device: null_mut(),
            attached_device: null_mut(),
            current_irp: null_mut(),
            sector_size: 512,
            alignment_mask: 0x3F,
            driver_queues: ListEntry::new(),
            security_descriptor: null_mut(),
            device_lock: ListEntry::new(),
            ref_count: AtomicU32::new(0),
            attached_to: None,
            device_name: UnicodeString::new(),
            pnp_state: DevicePnPState::NotStarted,
            previous_pnp_state: DevicePreviousState::NotStarted,
            device_power_state: DevicePowerState::D0,
            power_flags: 0,
        }
    }

    /// Set the PnP state with proper transition tracking.
    pub fn set_pnp_state(&mut self, new_state: DevicePnPState) {
        self.previous_pnp_state = match self.pnp_state {
            DevicePnPState::NotStarted => DevicePreviousState::NotStarted,
            DevicePnPState::Started => DevicePreviousState::Started,
            DevicePnPState::Stopped => DevicePreviousState::Stopped,
            DevicePnPState::RemovePending => DevicePreviousState::RemovePending,
            DevicePnPState::SurpriseRemoved => DevicePreviousState::SurpriseRemoved,
            DevicePnPState::Deleted => DevicePreviousState::RemovePending,
        };
        self.pnp_state = new_state;
    }

    /// Set the device power state.
    pub fn set_device_power_state(&mut self, new_state: DevicePowerState) {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[I/O] Device power state transition: {:?} -> {:?}",
// //             self.device_power_state, new_state
// //         );
        self.device_power_state = new_state;
    }
}

// ---------------------------------------------------------------------------
// Driver object
// ---------------------------------------------------------------------------

/// Dispatch function type for driver major functions.
pub type DriverDispatch = Option<
    unsafe extern "C" fn(device: *mut DeviceObject, irp: *mut Irp) -> i32,
>;

#[repr(C)]
pub struct DriverObject {
    pub device_object: *mut DeviceObject,
    pub driver_start: u64,
    pub driver_size: u64,
    pub driver_section: *mut (),
    pub driver_extension: *mut (),
    pub driver_name: UnicodeString,
    pub hardware_database: *mut (),
    pub fast_io_dispatch: *mut (),
    pub driver_init: Option<unsafe extern "C" fn(*mut DriverObject, *mut u16) -> u32>,
    pub driver_start_io: Option<unsafe extern "C" fn(*mut DeviceObject)>,
    pub driver_unload: Option<unsafe extern "C" fn(*mut DriverObject)>,
    pub major_functions: [DriverDispatch; 28],
}

impl DriverObject {
    pub const fn new() -> Self {
        Self {
            device_object: null_mut(),
            driver_start: 0,
            driver_size: 0,
            driver_section: null_mut(),
            driver_extension: null_mut(),
            driver_name: UnicodeString::new(),
            hardware_database: null_mut(),
            fast_io_dispatch: null_mut(),
            driver_init: None,
            driver_start_io: None,
            driver_unload: None,
            major_functions: [None; 28],
        }
    }
}

/// Internal driver entry in the global list.
struct DriverEntry {
    #[allow(unused)]
    name: [u8; 32],
    driver: *mut DriverObject,
    next: *mut DriverEntry,
}

// ---------------------------------------------------------------------------
// VPB
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Vpb {
    pub r#type: u16,
    pub size: u16,
    pub flags: u32,
    pub volume_label: UnicodeString,
    pub serial_number: u32,
    pub real_device: *mut DeviceObject,
    pub mounted_device: *mut DeviceObject,
    pub file_system_device: *mut DeviceObject,
    pub file_system: [u8; 8],
    pub ref_count: AtomicU32,
}

impl Vpb {
    pub const fn new() -> Self {
        Self {
            r#type: 0,
            size: 0,
            flags: 0,
            volume_label: UnicodeString::new(),
            serial_number: 0,
            real_device: null_mut(),
            mounted_device: null_mut(),
            file_system_device: null_mut(),
            file_system: [0; 8],
            ref_count: AtomicU32::new(0),
        }
    }
}

/// Internal VPB table entry wrapper (used only as a storage slot marker).
#[allow(unused)]
struct VpbEntry {
    vpb: Vpb,
    mounted: bool,
}

/// VPB flags
pub mod vpb_flags {
    pub const REMOUNT: u32 = 0x00000001;     // Volume requires remount
    pub const MOUNTED: u32 = 0x00000002;     // Volume is mounted
    pub const LOCKED: u32 = 0x00000004;      // Volume is locked
    pub const DISMOUNT_PENDING: u32 = 0x00000008; // Dismount is pending
    pub const MOUNT_PENDING: u32 = 0x00000010;   // Mount is pending
    pub const SYSTEM: u32 = 0x00000020;      // System volume
    pub const BOOT: u32 = 0x00000040;       // Boot volume
    pub const BOOT_PARTITION: u32 = 0x00000080; // Boot partition
    pub const PAGEFAULT: u32 = 0x00000100;   // Page fault volume
}

/// Allocate a VPB for a device object.
pub fn allocate_vpb() -> *mut Vpb {
    let raw = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<Vpb>()) as *mut Vpb;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, core::mem::size_of::<Vpb>());
        (*raw).r#type = 0x0007;  // IO_TYPE_VPB
        (*raw).size = core::mem::size_of::<Vpb>() as u16;
        (*raw).ref_count = AtomicU32::new(1);
    }
    raw
}

/// Free a VPB.
pub fn free_vpb(vpb: *mut Vpb) {
    if vpb.is_null() {
        return;
    }
    unsafe {
        // Decrement reference count
        let old = (*vpb).ref_count.fetch_sub(1, Ordering::Release);
        if old == 1 {
            // Last reference, free the VPB
            pool::free(vpb as *mut u8);
        }
    }
}

/// Reference a VPB (increment reference count).
pub fn reference_vpb(vpb: *mut Vpb) {
    if !vpb.is_null() {
        unsafe {
            (*vpb).ref_count.fetch_add(1, Ordering::Acquire);
        }
    }
}

/// Attach a VPB to a device object.
pub fn attach_vpb(device: *mut DeviceObject, vpb: *mut Vpb) {
    if !device.is_null() && !vpb.is_null() {
        unsafe {
            (*device).vpb = vpb;
            reference_vpb(vpb);
        }
    }
}

/// Detach a VPB from a device object.
pub fn detach_vpb(device: *mut DeviceObject) -> *mut Vpb {
    if device.is_null() {
        return null_mut();
    }
    unsafe {
        let vpb = (*device).vpb;
        (*device).vpb = null_mut();
        vpb
    }
}

/// Mark a volume as mounted in the VPB.
pub fn mark_vpb_mounted(vpb: *mut Vpb, fs_name: &[u8]) {
    if !vpb.is_null() {
        unsafe {
            (*vpb).flags |= vpb_flags::MOUNTED;
            // Copy file system name (up to 8 bytes)
            let len = fs_name.len().min(8);
            (&mut (*vpb).file_system)[..len].copy_from_slice(&fs_name[..len]);
        }
    }
}

/// Check if a VPB volume is mounted.
pub fn is_vpb_mounted(vpb: *mut Vpb) -> bool {
    if vpb.is_null() {
        return false;
    }
    unsafe {
        ((*vpb).flags & vpb_flags::MOUNTED) != 0
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// IoCallDriver - Pass an IRP to the next lower driver
pub fn IoCallDriver(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if device.is_null() || irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    unsafe {
        // Get the current stack location
        let stack = (*irp).current_stack;
        if stack.is_null() {
            return STATUS_INVALID_PARAMETER as i32;
        }

        let major = (*stack).major_function;
        let driver = (*device).driver_object;

        if !driver.is_null() {
            // Call the driver's major function
            if let Some(handler) = (*driver).major_functions[major as usize] {
                return handler(device, irp);
            }
        }

        // No handler found - complete with error
        (*irp).io_status.status = STATUS_NO_SUCH_DEVICE as u32;
        IoCompleteRequest(irp, 0);
    }
    0
}

/// IoCompleteRequest - Complete an IRP
pub fn IoCompleteRequest(irp: *mut Irp, priority_boost: i32) {
    let _ = priority_boost;
    if irp.is_null() {
        return;
    }

    unsafe {
        // Update statistics
        let status = (*irp).io_status.status as i32;
        if status >= 0 {
            IO_STATS.lock().irps_completed += 1;
        } else {
            IO_STATS.lock().irps_cancelled += 1;
        }

        // Free the IRP
        free_irp(irp);
    }
}

/// Allocate an IRP from the pool. Returns `null_mut()` if the pool
/// is exhausted.
pub fn allocate_irp(_stack_locations: u8) -> *mut Irp {
    let sz = core::mem::size_of::<Irp>();
    let sl_sz = core::mem::size_of::<IoStackLocation>();
    let total = sz + (sl_sz * 1);
    let raw = pool::allocate(pool::PoolType::NonPaged, total) as *mut Irp;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, total);
        (*raw).stack_count = 1;
        (*raw).current_location = 1;
        // The stack location follows the IRP body.
        let sl_ptr = (raw as *mut u8).add(sz) as *mut IoStackLocation;
        (*raw).current_stack = sl_ptr;
        (*sl_ptr) = IoStackLocation::new();
    }
    IO_STATS.lock().irps_allocated += 1;
    raw
}

/// Free an IRP back to the non-paged pool.
/// This properly deallocates the IRP and its stack locations.
pub fn free_irp(irp: *mut Irp) {
    if irp.is_null() {
        return;
    }

    // Free the memory back to the pool
    let raw = irp as *mut u8;
    let _ = pool::free(raw);

    IO_STATS.lock().irps_completed += 1;
}

/// Complete an IRP with the given status. Updates the I/O stats.
pub fn complete_irp(irp: *mut Irp, status: i32, information: usize) {
    unsafe {
        (*irp).io_status.status = status as u32;
        (*irp).io_status.information = information;
        if status >= 0 {
            IO_STATS.lock().irps_completed += 1;
        } else {
            IO_STATS.lock().irps_cancelled += 1;
        }
    }
}

/// Allocate a driver object from the non-paged pool.
pub fn allocate_driver(name: &[u8]) -> *mut DriverObject {
    let raw = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<DriverObject>())
        as *mut DriverObject;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, core::mem::size_of::<DriverObject>());
        let d = &mut (*raw);
        d.driver_name.Length = name.len() as u16;
        d.driver_name.MaximumLength = name.len() as u16;
    }
    raw
}

/// Register a driver in the global list and the object manager namespace.
pub fn register_driver(driver: *mut DriverObject) -> bool {
    if driver.is_null() {
        return false;
    }
    let mut list = DRIVER_LIST.lock();
    for i in 0..MAX_DRIVERS {
        if list[i].is_none() {
            unsafe {
                // Field-by-field write to avoid the UC-memory
                // non-temporal-store fault that hits a 48-byte
                // Option<DriverEntry> copy.
                let s = &mut list[i];
                // discriminant: Some(1)
                let raw = s as *mut Option<DriverEntry> as *mut u8;
                core::ptr::write(raw, 1); // tag
                let de = s.as_mut().unwrap();
                de.driver = driver;
                de.next = core::ptr::null_mut();
                // de.name is already zero (Option::None with zeroed bytes)
            }
            
            // Get driver name from the driver object (extract from UnicodeString)
            let driver_name_storage = unsafe {
                let name_ptr = (*driver).driver_name.Buffer;
                let name_len = (*driver).driver_name.Length as usize;
                let mut name = [0u8; 64];
                let mut name_len_out = 0usize;
                if !name_ptr.is_null() && name_len > 0 {
                    let max_chars = (name_len / 2).min(32);
                    for j in 0..max_chars {
                        let c = core::ptr::read_volatile(name_ptr.add(j));
                        if c == 0 { break; }
                        if name_len_out < 64 {
                            name[name_len_out] = c as u8;
                            name_len_out += 1;
                        }
                    }
                }
                (name, name_len_out)
            };
            let driver_name_slice = &driver_name_storage.0[..driver_name_storage.1];

            drop(list);

            // Register in object manager namespace if name is available
            if !driver_name_slice.is_empty() {
                register_driver_in_object_manager(driver, driver_name_slice);
            }
            
            return true;
        }
    }
    false
}

/// Register a driver object in the object manager namespace at \Driver\<name>
fn register_driver_in_object_manager(driver: *mut DriverObject, driver_name: &[u8]) {
    if driver.is_null() || driver_name.is_empty() {
        return;
    }
    
    // Create an object header for the driver
    let header = crate::ob::create_object(
        b"\\Driver",
        driver_name,
        crate::ob::ObType::Driver,
        core::mem::size_of::<DriverObject>(),
    );
    
    if !header.is_null() {
        unsafe {
            // Set the body pointer to our driver object
            (*header).body = driver as *mut ();
            
            // Create a default security descriptor (NULL DACL = allow all)
            let sd = crate::se::seaccess::create_null_dacl_sd();
            if !sd.is_null() {
                (*header).security_descriptor = sd as *mut crate::se::seaccess::SecurityDescriptor;
            }
        }
        
        // Insert into the namespace
        let handle = crate::ob::insert_object(b"\\Driver", header);
        if handle != 0 {
            // // kprintln!("[I/O] Registered driver {:x?} in OB namespace, handle={}",   // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                      driver_name, handle);
        } else {
            // // kprintln!("[I/O] WARNING: Failed to insert driver into OB namespace")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    } else {
        // // kprintln!("[I/O] WARNING: Failed to create OB header for driver")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Create a device object and attach it to a driver.
/// This also registers the device in the object manager namespace.
pub fn create_device(
    driver: *mut DriverObject,
    device_type: DeviceType,
    device_name: &[u8],
) -> *mut DeviceObject {
    let raw = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<DeviceObject>())
        as *mut DeviceObject;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, core::mem::size_of::<DeviceObject>());
        (*raw).device_type = device_type;
        (*raw).driver_object = driver;
        (*raw).ref_count = AtomicU32::new(1);
        (*raw).sector_size = 512;
        (*raw).alignment_mask = 0x3F;
        (*raw).device_queue.init();
        (*raw).driver_queues.init();
        (*raw).device_lock.init();
        // Link into the driver's device list.
        (*raw).next_device = (*driver).device_object;
        (*driver).device_object = raw;
    }
    
    // Register the device in the object manager namespace
    // Skip registration if OB is not initialized yet (during early boot)
    if device_name.len() > 0 && !device_name.iter().all(|&b| b == 0) {
        register_device_in_object_manager(raw, device_name);
    }
    
    raw
}

/// Register a device object in the object manager namespace at \Device\<name>
fn register_device_in_object_manager(device: *mut DeviceObject, device_name: &[u8]) {
    if device.is_null() {
        return;
    }
    
    // Extract just the device name (without \Device\ prefix)
    let name = if device_name.starts_with(b"\\Device\\") {
        &device_name[b"\\Device\\".len()..]
    } else {
        device_name
    };
    
    // Create an object header for the device
    let header = crate::ob::create_object(
        b"\\Device",
        name,
        crate::ob::ObType::Device,
        core::mem::size_of::<DeviceObject>(),
    );
    
    if !header.is_null() {
        unsafe {
            // Set the body pointer to our device object
            (*header).body = device as *mut ();
            
            // Create a default security descriptor (NULL DACL = allow all)
            let sd = crate::se::seaccess::create_null_dacl_sd();
            if !sd.is_null() {
                (*header).security_descriptor = sd as *mut crate::se::seaccess::SecurityDescriptor;
            }
        }
        
        // Insert into the namespace
        let handle = crate::ob::insert_object(b"\\Device", header);
        if handle != 0 {
            // // kprintln!("[I/O] Registered device {:?} in OB namespace, handle={}", name, handle)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        } else {
            // // kprintln!("[I/O] WARNING: Failed to insert device {:?} into OB namespace", name)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    } else {
        // // kprintln!("[I/O] WARNING: Failed to create OB header for device {:?}", name)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Attach one device above another.
pub fn attach_device(above: *mut DeviceObject, below: *mut DeviceObject) {
    unsafe {
        (*above).attached_device = below;
        (*below).attached_to = Some(above);
    }
}

/// Get I/O system counters snapshot.
pub fn io_stats() -> IoStatsSnapshot {
    let s = IO_STATS.lock();
    IoStatsSnapshot {
        irps_allocated: s.irps_allocated,
        irps_completed: s.irps_completed,
        irps_cancelled: s.irps_cancelled,
        bytes_read: s.bytes_read,
        bytes_written: s.bytes_written,
        reads: s.reads,
        writes: s.writes,
    }
}

pub struct IoStatsSnapshot {
    pub irps_allocated: u64,
    pub irps_completed: u64,
    pub irps_cancelled: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub reads: u64,
    pub writes: u64,
}

impl Default for IoStatsSnapshot {
    fn default() -> Self {
        Self {
            irps_allocated: 0,
            irps_completed: 0,
            irps_cancelled: 0,
            bytes_read: 0,
            bytes_written: 0,
            reads: 0,
            writes: 0,
        }
    }
}

/// Initialize the I/O manager.
pub fn init() {
    {
        let mut s = IO_STATS.lock();
        s.irps_allocated = 0;
        s.irps_completed = 0;
        s.irps_cancelled = 0;
        s.bytes_read = 0;
        s.bytes_written = 0;
        s.reads = 0;
        s.writes = 0;
    }

    // Create NULL device driver for bootstrap
    let null_driver = allocate_driver(b"\\Driver\\Null");
    if !null_driver.is_null() {
        unsafe {
            // Set up default major function handlers
            (*null_driver).major_functions[major::IRP_MJ_CREATE as usize] = Some(null_create_dispatch);
            (*null_driver).major_functions[major::IRP_MJ_CLOSE as usize] = Some(null_close_dispatch);
            (*null_driver).major_functions[major::IRP_MJ_READ as usize] = Some(null_read_dispatch);
            (*null_driver).major_functions[major::IRP_MJ_WRITE as usize] = Some(null_write_dispatch);

            // Create the NULL device
            let null_device = create_device(null_driver, DeviceType::Null, b"\\Device\\Null");
            if !null_device.is_null() {
                // // kprintln!("      NULL device created")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
        register_driver(null_driver);
    }

    // Create filesystem device driver (placeholder for FAT32/NTFS)
    let fs_driver = allocate_driver(b"\\FileSystem\\Ntfs");
    if !fs_driver.is_null() {
        unsafe {
            // Set up filesystem major function handlers
            (*fs_driver).major_functions[major::IRP_MJ_CREATE as usize] = Some(fs_create_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_CLOSE as usize] = Some(fs_close_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_READ as usize] = Some(fs_read_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_WRITE as usize] = Some(fs_write_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_CLEANUP as usize] = Some(fs_cleanup_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_DEVICE_CONTROL as usize] = Some(fs_device_control_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_PNP as usize] = Some(fs_pnp_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_POWER as usize] = Some(fs_power_dispatch);

            // Create the filesystem device
            let fs_device = create_device(fs_driver, DeviceType::FileSystem, b"\\Device\\Fs");
            if !fs_device.is_null() {
                // // kprintln!("      Filesystem device created")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
        register_driver(fs_driver);
    }

    // // kprintln!("    I/O Manager: initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "      drivers_max={} devices_max={} vpb_max={} irp_pool={}",
// //         MAX_DRIVERS, MAX_DEVICES, MAX_VPBs, MAX_IRP_POOL
// //     );
}

// ---------------------------------------------------------------------------
// Default dispatch handlers
// ---------------------------------------------------------------------------

use crate::libs::ntdll::status::{
    STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_END_OF_FILE,
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_NO_MEMORY, STATUS_NOT_IMPLEMENTED, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_OBJECT_NAME_INVALID,
};

/// Default NULL device dispatch for IRP_MJ_CREATE
unsafe extern "C" fn null_create_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS
}

/// Default NULL device dispatch for IRP_MJ_CLOSE
unsafe extern "C" fn null_close_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS
}

/// Default NULL device dispatch for IRP_MJ_READ
unsafe extern "C" fn null_read_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        // NULL device returns end of file (0 bytes read)
        (*irp).io_status.status = STATUS_END_OF_FILE as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_END_OF_FILE
}

/// Default NULL device dispatch for IRP_MJ_WRITE
unsafe extern "C" fn null_write_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        // NULL device discards writes, returns success
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        // Information = bytes written (we report 0 for NULL)
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Filesystem dispatch handlers
// ---------------------------------------------------------------------------

/// IRP_MJ_CREATE dispatch for filesystem devices.
/// Opens or creates a file on the filesystem.
unsafe extern "C" fn fs_create_dispatch(
    device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    let stack = (*irp).current_stack;
    
    // Create a file object for this open
    let file_obj_ptr = pool::allocate(
        pool::PoolType::NonPaged,
        core::mem::size_of::<FileObject>(),
    ) as *mut FileObject;
    
    if file_obj_ptr.is_null() {
        (*irp).io_status.status = STATUS_NO_MEMORY as u32;
        (*irp).io_status.information = 0;
        IoCompleteRequest(irp, 0);
        return STATUS_NO_MEMORY as i32;
    }
    
    // Initialize file object
    (*file_obj_ptr).device_object = device;
    (*file_obj_ptr).vpb = (*device).vpb;
    (*file_obj_ptr).fcb = core::ptr::null_mut();
    (*file_obj_ptr).file_name = UnicodeString::new();
    (*file_obj_ptr).current_byte_offset = 0;
    (*file_obj_ptr).flags = 0;
    
    // Store file object in stack location for subsequent operations
    if !stack.is_null() {
        (*stack).file_object = file_obj_ptr;
    }
    
    (*irp).io_status.status = STATUS_SUCCESS as u32;
    (*irp).io_status.information = 0;
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

/// IRP_MJ_READ dispatch for filesystem devices.
/// Reads data from an open file.
unsafe extern "C" fn fs_read_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    // Get the file object to access current byte offset
    let file_obj = (*stack).file_object;
    if file_obj.is_null() {
        (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
        (*irp).io_status.information = 0;
        IoCompleteRequest(irp, 0);
        return STATUS_INVALID_PARAMETER as i32;
    }

    // Get parameters from the union (buffer address in lower 32 bits, length in upper 32 bits)
    let params = (*stack).parameters.as_u64;
    let buffer = (params & 0xFFFFFFFF) as *mut u8;
    let length = ((params >> 32) & 0xFFFFFFFF) as u32;
    
    // Route to the underlying filesystem via VFS
    let byte_offset = (*file_obj).current_byte_offset;
    
    if buffer.is_null() || length == 0 {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
        IoCompleteRequest(irp, 0);
        return STATUS_SUCCESS as i32;
    }
    
    // Use VFS to read from RAM disk
    let result = crate::fs::vfs::read_file_sectors(
        0,              // Use byte_offset-based reading
        buffer as u64,
        length,
        byte_offset,
    );
    
    // Update file position if read succeeded
    if result.status == 0 {
        (*file_obj).current_byte_offset += result.bytes_read as u64;
    }
    
    // Update statistics
    {
        let mut stats = IO_STATS.lock();
        stats.bytes_read += result.bytes_read as u64;
        stats.reads += 1;
    }
    
    (*irp).io_status.status = result.status;
    (*irp).io_status.information = result.bytes_read;
    IoCompleteRequest(irp, 0);
    result.status as i32
}

/// IRP_MJ_WRITE dispatch for filesystem devices.
/// Writes data to an open file.
unsafe extern "C" fn fs_write_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER as i32;
    }

    // Get the file object to access current byte offset
    let file_obj = (*stack).file_object;
    if file_obj.is_null() {
        (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
        (*irp).io_status.information = 0;
        IoCompleteRequest(irp, 0);
        return STATUS_INVALID_PARAMETER as i32;
    }

    // Get parameters from the union (buffer address in lower 32 bits, length in upper 32 bits)
    let params = (*stack).parameters.as_u64;
    let buffer = (params & 0xFFFFFFFF) as *mut u8;
    let length = ((params >> 32) & 0xFFFFFFFF) as u32;
    
    // Route to the underlying filesystem via VFS
    let byte_offset = (*file_obj).current_byte_offset;
    
    if buffer.is_null() || length == 0 {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
        IoCompleteRequest(irp, 0);
        return STATUS_SUCCESS as i32;
    }
    
    // Use VFS to write to RAM disk
    let result = crate::fs::vfs::write_file_sectors(
        0,              // Use byte_offset-based writing
        buffer as u64,
        length,
        byte_offset,
    );
    
    // Update file position if write succeeded
    if result.status == 0 {
        (*file_obj).current_byte_offset += result.bytes_written as u64;
    }
    
    // Update statistics
    {
        let mut stats = IO_STATS.lock();
        stats.bytes_written += result.bytes_written as u64;
        stats.writes += 1;
    }
    
    (*irp).io_status.status = result.status;
    (*irp).io_status.information = result.bytes_written;
    IoCompleteRequest(irp, 0);
    result.status as i32
}

/// IRP_MJ_CLOSE dispatch for filesystem devices.
/// Closes a file handle.
unsafe extern "C" fn fs_close_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

/// IRP_MJ_CLEANUP dispatch for filesystem devices.
/// Called when the last handle to a file is being closed.
unsafe extern "C" fn fs_cleanup_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

/// IRP_MJ_DEVICE_CONTROL dispatch for filesystem devices.
/// Handles IOCTL requests from user mode.
unsafe extern "C" fn fs_device_control_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        // Most IOCTLs are not supported in bootstrap
        (*irp).io_status.status = STATUS_INVALID_DEVICE_REQUEST as u32;
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_INVALID_DEVICE_REQUEST as i32
}

/// IRP_MJ_PNP dispatch for filesystem devices.
/// Handles Plug and Play IRPs.
unsafe extern "C" fn fs_pnp_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            let minor = (*stack).minor_function;
            match minor {
                0x00 => {
                    // IRP_MN_START_DEVICE — return success
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x01 => {
                    // IRP_MN_QUERY_REMOVE_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x02 => {
                    // IRP_MN_CANCEL_REMOVE_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x03 => {
                    // IRP_MN_SURPRISE_REMOVAL
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x04 => {
                    // IRP_MN_REMOVE_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                _ => {
                    (*irp).io_status.status = STATUS_NOT_IMPLEMENTED as u32;
                }
            }
        }
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

/// IRP_MJ_POWER dispatch for filesystem devices.
/// Handles power management IRPs with full minor function dispatch.
unsafe extern "C" fn fs_power_dispatch(
    _device: *mut DeviceObject,
    irp: *mut Irp,
) -> i32 {
    if !irp.is_null() {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            let minor = (*stack).minor_function;
            match minor {
                power::IRP_MN_WAIT_WAKE => {
                    // Wait/Wake - device can wake the system
                    // // kprintln!("[I/O] Power: IRP_MN_WAIT_WAKE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_POWER_SEQUENCE => {
                    // Power Sequence - query power sequence counters
                    // // kprintln!("[I/O] Power: IRP_MN_POWER_SEQUENCE")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_SET_POWER => {
                    // Set Power - transition device to new power state
                    // // kprintln!("[I/O] Power: IRP_MN_SET_POWER")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_QUERY_POWER => {
                    // Query Power - check if device can enter new power state
                    // // kprintln!("[I/O] Power: IRP_MN_QUERY_POWER")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                _ => {
                    // // kprintln!("[I/O] Power: unknown minor function 0x{:02x}", minor)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
                    (*irp).io_status.status = STATUS_NOT_IMPLEMENTED as u32;
                }
            }
        }
        (*irp).io_status.information = 0;
    }
    IoCompleteRequest(irp, 0);
    STATUS_SUCCESS as i32
}

/// Re-export of the I/O system smoke test. The full
/// implementation lives in the `smoke` submodule; this
/// re-export keeps the call site readable as `io::smoke_test()`
/// (matching the `mm::smoke_test()` / `ke::smoke_test()` /
/// `ob::smoke_test()` convention used by `kernel_main`).
pub fn smoke_test() -> bool { smoke::smoke_test() }

// ---------------------------------------------------------------------------
// PnP Device Startup Sequence
// ---------------------------------------------------------------------------

/// PnP device enumeration context.
/// Tracks the state of the bus enumeration process.
pub struct PnpEnumerationContext {
    /// Total devices found during enumeration.
    pub devices_found: u32,
    /// Devices successfully started.
    pub devices_started: u32,
    /// Devices that failed to start.
    pub devices_failed: u32,
}

impl PnpEnumerationContext {
    pub fn new() -> Self {
        Self {
            devices_found: 0,
            devices_started: 0,
            devices_failed: 0,
        }
    }
}

/// Enumerate devices on a bus and start them.
/// This implements the NT PnP device start sequence:
/// 1. IRP_MN_QUERY_DEVICE_RELATIONS (BusRelations)
/// 2. IRP_MN_QUERY_CAPABILITIES for each child device
/// 3. IRP_MN_START_DEVICE for each child device
///
/// For the bootstrap, this simulates bus enumeration and starts
/// detected devices.
pub fn pnp_start_device(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        // Check if device is already started
        if (*device).pnp_state == DevicePnPState::Started {
            // // kprintln!("[I/O] PnP: device already started")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return true;
        }

        // Query device capabilities first
        let cap_result = pnp_query_capabilities(device);
        if !cap_result {
            // // kprintln!("[I/O] PnP: device does not support required capabilities")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        // Start the device
        (*device).set_pnp_state(DevicePnPState::Started);
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[I/O] PnP: device started (type={:?})",
// //             (*device).device_type
// //         );

        true
    }
}

/// Query device capabilities for PnP.
fn pnp_query_capabilities(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    // In a full implementation, this would send IRP_MN_QUERY_CAPABILITIES
    // and wait for the result. For the bootstrap, we assume all
    // devices support basic PnP capabilities.
    // // kprintln!("[I/O] PnP: querying device capabilities")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    true
}

/// Query device relations (enumerate children).
pub fn pnp_query_device_relations(device: *mut DeviceObject) -> u32 {
    if device.is_null() {
        return 0;
    }

    // In a full implementation, this sends IRP_MN_QUERY_DEVICE_RELATIONS
    // and returns the number of child devices found.
    // For the bootstrap, we return 0 (no bus enumeration simulation).
    // // kprintln!("[I/O] PnP: querying device relations (no children in bootstrap)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    0
}

/// Handle device removal.
/// Transitions the device to the appropriate removal state.
pub fn pnp_remove_device(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        match (*device).pnp_state {
            DevicePnPState::Started => {
                // Device was started, need to stop first
                (*device).set_pnp_state(DevicePnPState::Stopped);
            }
            DevicePnPState::NotStarted => {
                // Device was never started, go directly to remove pending
            }
            _ => {
                // Already in a transition state
            }
        }

        (*device).set_pnp_state(DevicePnPState::RemovePending);
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[I/O] PnP: device removal pending (type={:?})",
// //             (*device).device_type
// //         );

        // In a full implementation, would send IRP_MN_REMOVE_DEVICE
        // to the device stack and clean up resources.

        (*device).set_pnp_state(DevicePnPState::Deleted);
        // // kprintln!("[I/O] PnP: device deleted")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

        true
    }
}

/// Handle surprise removal of a device.
pub fn pnp_surprise_removal(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        (*device).set_pnp_state(DevicePnPState::SurpriseRemoved);
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[I/O] PnP: device surprise removed (type={:?})",
// //             (*device).device_type
// //         );
        true
    }
}

/// Stop a device (for rebalancing or resource reconfiguration).
pub fn pnp_stop_device(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        if (*device).pnp_state != DevicePnPState::Started {
            // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //                 "[I/O] PnP: cannot stop device - not in Started state (current={:?})",
// //                 (*device).pnp_state
// //             );
            return false;
        }

        (*device).set_pnp_state(DevicePnPState::Stopped);
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "[I/O] PnP: device stopped (type={:?})",
// //             (*device).device_type
// //         );
        true
    }
}

/// Enumerate and start all devices on the system.
/// Walks the driver list and starts devices for each driver.
pub fn pnp_enumerate_and_start_all() {
    let drivers = DRIVER_LIST.lock();
    let mut started_count = 0;
    let mut failed_count = 0;

    for i in 0..MAX_DRIVERS {
        if let Some(driver_entry) = &drivers[i] {
            // Start each device owned by this driver
            let driver = driver_entry.driver;
            if !driver.is_null() {
                unsafe {
                    let mut dev = (*driver).device_object;
                    while !dev.is_null() {
                        if pnp_start_device(dev) {
                            started_count += 1;
                        } else {
                            failed_count += 1;
                        }
                        dev = (*dev).next_device;
                    }
                }
            }
        }
    }

    // [DISABLED] // // kprintln!("[I/O] PnP enumerated: started={}, failed={}", started_count, failed_count)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    let _ = (&started_count, &failed_count);
}

/// Initialize the PnP manager.
/// Sets up the PnP state machine and prepares for device enumeration.
pub fn pnp_init() {
    // // kprintln!("[I/O] PnP manager initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

// ============================================================================
// Device Stack Management
// ============================================================================

/// Device stack structure for managing filter device attachments.
/// The device stack represents the chain of devices attached to each other,
/// from the top (closest to user) to the bottom (closest to hardware).
#[derive(Debug)]
pub struct DeviceStack {
    /// Top device in the stack (filter drivers attach here)
    pub top_device: *mut DeviceObject,
    /// Bottom device in the stack (base device/hardware)
    pub bottom_device: *mut DeviceObject,
    /// List of attached filter devices
    pub attached_devices: Option<Vec<*mut DeviceObject>>,
}

impl DeviceStack {
    /// Create a new device stack with a base device.
    pub fn new(base_device: *mut DeviceObject) -> Option<Self> {
        if base_device.is_null() {
            return None;
        }
        Some(Self {
            top_device: base_device,
            bottom_device: base_device,
            attached_devices: Some(Vec::new()),
        })
    }

    /// Attach a filter device above another device in the stack.
    /// The filter device will receive IRPs before the target device.
    pub fn attach_filter_device(&mut self, filter: *mut DeviceObject) -> bool {
        if filter.is_null() {
            return false;
        }

        unsafe {
            // Link filter above target
            (*filter).attached_device = self.top_device;
            
            // Update target's attached_to field
            (*self.top_device).attached_to = Some(filter);
            
            // Add to our tracking list
            if let Some(ref mut list) = self.attached_devices {
                list.push(self.top_device);
            }
            
            // Update top to the filter
            self.top_device = filter;
        }
        true
    }

    /// Detach a filter device from the stack.
    pub fn detach_filter_device(&mut self, filter: *mut DeviceObject) -> bool {
        if filter.is_null() {
            return false;
        }

        unsafe {
            let below = (*filter).attached_device;
            let above = (*filter).attached_to;
            
            // Re-link the chain
            if let Some(above_dev) = above {
                (*above_dev).attached_device = below;
            }
            if !below.is_null() {
                (*below).attached_to = above;
            }
            
            // Update top/bottom if needed
            if self.top_device == filter {
                self.top_device = below;
            }
            if self.bottom_device == filter {
                self.bottom_device = below;
            }
            
            // Remove from tracking list
            if let Some(ref mut list) = self.attached_devices {
                list.retain(|&d| d != filter);
            }
        }
        true
    }

    /// Get the number of devices in the stack.
    pub fn depth(&self) -> usize {
        self.attached_devices.as_ref().map_or(0, |v| v.len()) + 1
    }
}

// ============================================================================
// Fast I/O Dispatch
// ============================================================================

/// Fast I/O dispatch table for high-performance I/O paths.
/// Fast I/O bypasses the IRP-based dispatch path for common operations,
/// providing lower latency for synchronous reads and writes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FastIoDispatch {
    /// Size of this structure (for versioning).
    pub size: u32,
    /// FastIoCheckIfPossible - verify fast I/O can be used.
    pub fast_io_check_if_possible: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _byte_offset: u64,
        _length: u32,
        _lock: bool,
        _check_for_read: bool,
        _wait: bool,
        _alert: bool,
    ) -> bool>,
    /// FastIoRead - read without creating an IRP.
    pub fast_io_read: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _buffer: *mut u8,
        _length: u32,
        _wait: bool,
    ) -> bool>,
    /// FastIoWrite - write without creating an IRP.
    pub fast_io_write: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _buffer: *const u8,
        _length: u32,
        _wait: bool,
    ) -> bool>,
    /// FastIoQueryBasicInfo - query basic file information.
    pub fast_io_query_basic_info: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _wait: bool,
    ) -> bool>,
    /// FastIoQueryStandardInfo - query standard file information.
    pub fast_io_query_standard_info: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _wait: bool,
    ) -> bool>,
    /// FastIoLock - lock a region of a file.
    pub fast_io_lock: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _byte_offset: u64,
        _length: u64,
        _wait: bool,
        _exclusive: bool,
    ) -> bool>,
    /// FastIoUnlockSingle - unlock a single region.
    pub fast_io_unlock_single: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _byte_offset: u64,
        _length: u64,
    ) -> bool>,
    /// FastIoUnlockAll - unlock all regions.
    pub fast_io_unlock_all: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
    ) -> bool>,
    /// FastIoUnlockAllByKey - unlock by key.
    pub fast_io_unlock_all_by_key: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _key: u64,
    ) -> bool>,
    /// FastIoDeviceControl - device I/O control.
    pub fast_io_device_control: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _wait: bool,
        _input: bool,
    ) -> bool>,
    /// FastIoAcquireForModWrite - acquire for modified write.
    pub fast_io_acquire_for_mod_write: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
        _byte_offset: u64,
        _length: u64,
    ) -> bool>,
    /// FastIoReleaseForModWrite - release from modified write.
    pub fast_io_release_for_mod_write: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
    ) -> bool>,
    /// FastIoAcquireForCcFlush - acquire for cache flush.
    pub fast_io_acquire_for_cc_flush: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
    ) -> bool>,
    /// FastIoReleaseForCcFlush - release from cache flush.
    pub fast_io_release_for_cc_flush: Option<unsafe extern "C" fn(
        _device: *mut DeviceObject,
        _file: *mut FileObject,
    ) -> bool>,
}

impl FastIoDispatch {
    /// Create a new FastIoDispatch with all fields set to None.
    pub fn new() -> Self {
        Self {
            size: core::mem::size_of::<Self>() as u32,
            ..Default::default()
        }
    }

    /// Create a FastIoDispatch with basic read/write handlers populated.
    /// This provides a reasonable default for file system drivers.
    pub fn with_basic_handlers() -> Self {
        Self {
            size: core::mem::size_of::<Self>() as u32,
            fast_io_check_if_possible: Some(fast_io_check_if_possible_impl),
            fast_io_read: Some(fast_io_read_impl),
            fast_io_write: Some(fast_io_write_impl),
            fast_io_query_basic_info: Some(fast_io_query_basic_info_impl),
            fast_io_query_standard_info: Some(fast_io_query_standard_info_impl),
            ..Default::default()
        }
    }
}

/// Default Fast I/O check handler.
/// Returns true if fast I/O is possible for the given parameters.
unsafe extern "C" fn fast_io_check_if_possible_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _byte_offset: u64,
    _length: u32,
    _lock: bool,
    _check_for_read: bool,
    _wait: bool,
    _alert: bool,
) -> bool {
    // By default, assume fast I/O is possible
    true
}

/// Default Fast I/O read handler.
/// This is a stub that returns false, forcing the IRP path.
/// Real file systems would implement actual reads here.
unsafe extern "C" fn fast_io_read_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _buffer: *mut u8,
    _length: u32,
    _wait: bool,
) -> bool {
    // Return false to indicate fast I/O cannot handle this read
    // The IRP path will be taken instead
    false
}

/// Default Fast I/O write handler.
/// This is a stub that returns false, forcing the IRP path.
unsafe extern "C" fn fast_io_write_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _buffer: *const u8,
    _length: u32,
    _wait: bool,
) -> bool {
    // Return false to indicate fast I/O cannot handle this write
    false
}

/// Default Fast I/O query basic info handler.
unsafe extern "C" fn fast_io_query_basic_info_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _wait: bool,
) -> bool {
    false
}

/// Default Fast I/O query standard info handler.
unsafe extern "C" fn fast_io_query_standard_info_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _wait: bool,
) -> bool {
    false
}

// ============================================================================
// IRP Cancellation Support
// ============================================================================

/// Cancellation state for an IRP.
/// Tracks whether an IRP has been cancelled and by whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpCancellationState {
    /// IRP is active and not cancelled.
    Active,
    /// IRP has been cancelled by the originator.
    Cancelled,
    /// IRP has been completed.
    Completed,
}

/// Cancel an IRP that is queued or in progress.
/// Returns true if the IRP was successfully cancelled.
pub fn cancel_irp(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    unsafe {
        // Mark the IRP as cancelled in its flags
        (*irp).flags |= IRP_CANCEL_INDICATED;
        true
    }
}

/// Check if an IRP has been cancelled.
pub fn irp_is_cancelled(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return true;
    }
    unsafe {
        ((*irp).flags & IRP_CANCEL_INDICATED) != 0
    }
}

/// Set cancel routine for an IRP.
/// This is called by the driver to set up cancellation support.
pub fn set_irp_cancel_routine(_irp: *mut Irp, _cancel_routine: Option<unsafe extern "C" fn(*mut Irp)>) {
    // In a full implementation, this would set a pointer to the cancel routine
    // that gets called when the IRP is cancelled.
    // For the bootstrap, we just track the cancelled state.
}

/// IRP flag: IRP was indicated to a cancel routine.
pub const IRP_CANCEL_INDICATED: u32 = 0x00000020;

/// IRP flag: IRP has associated MDL.
pub const IRP_ASSOCIATED_IRP: u32 = 0x00000001;

/// IRP flag: IRP was allocated from lookaside list.
pub const IRP_LOOKASIDE_LIST: u32 = 0x00000040;

// ============================================================================
// Driver Dispatch Table
// ============================================================================

/// Driver dispatch function table.
/// Provides a type-safe way to set up major function handlers.
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverDispatchTable {
    /// Create/Open
    pub create: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Close
    pub close: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Read
    pub read: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Write
    pub write: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Query Information (file)
    pub query_information: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Set Information (file)
    pub set_information: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Query EA (extended attributes)
    pub query_ea: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Set EA
    pub set_ea: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Flush Buffers
    pub flush_buffers: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Query Volume Information
    pub query_volume_information: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Set Volume Information
    pub set_volume_information: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Directory Control
    pub directory_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// File System Control
    pub file_system_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Device I/O Control
    pub device_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Internal Device Control
    pub internal_device_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Cleanup
    pub cleanup: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Close for maintenance
    pub close_mc: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Plug and Play
    pub pnp: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Power
    pub power: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Others (schema/locked pages)
    pub others: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
}

impl DriverDispatchTable {
    /// Create a new dispatch table with all handlers set to None.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install this dispatch table into a driver object.
    pub fn install(&self, driver: *mut DriverObject) {
        if driver.is_null() {
            return;
        }

        unsafe {
            if let Some(f) = self.create {
                (*driver).major_functions[major::IRP_MJ_CREATE as usize] = Some(f);
            }
            if let Some(f) = self.close {
                (*driver).major_functions[major::IRP_MJ_CLOSE as usize] = Some(f);
            }
            if let Some(f) = self.read {
                (*driver).major_functions[major::IRP_MJ_READ as usize] = Some(f);
            }
            if let Some(f) = self.write {
                (*driver).major_functions[major::IRP_MJ_WRITE as usize] = Some(f);
            }
            if let Some(f) = self.device_control {
                (*driver).major_functions[major::IRP_MJ_DEVICE_CONTROL as usize] = Some(f);
            }
            if let Some(f) = self.pnp {
                (*driver).major_functions[major::IRP_MJ_PNP as usize] = Some(f);
            }
            if let Some(f) = self.power {
                (*driver).major_functions[major::IRP_MJ_POWER as usize] = Some(f);
            }
            if let Some(f) = self.cleanup {
                (*driver).major_functions[major::IRP_MJ_CLEANUP as usize] = Some(f);
            }
        }
    }
}

