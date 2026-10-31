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
//!     The smoke test creates a dummy driver, attaches a dummy device,
//!     allocates an IRP, routes it through the driver stack, and
//!     completes it.

// I/O manager uses NT-driver naming (IRP, IRP_MJ_*, IO_*, ...).

use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pool;

pub mod named_pipe;
pub mod pipe;
pub mod smoke;

// ---------------------------------------------------------------------------
// I/O system constants
// ---------------------------------------------------------------------------

/// Maximum drivers in the global driver list.
pub const MAX_DRIVERS: usize = 32;
/// Maximum devices per driver.
pub const MAX_DEVICES: usize = 64;
/// Maximum VPBs (mounted volumes).
pub const MAX_VPBS: usize = 16;
/// Maximum IRPs we can hold in the bootstrap pool.
pub const MAX_IRP_POOL: usize = 128;

/// I/O function codes.
///
/// Values are the real NT 6.1 major function codes (wdm.h IRP_MJ_* family);
/// every driver indexes DriverObject::major_functions with these constants,
/// so the table size must stay at 28.
pub mod major {
    pub const IRP_MJ_CREATE: u8 = 0x00;
    pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
    pub const IRP_MJ_CLOSE: u8 = 0x02;
    pub const IRP_MJ_READ: u8 = 0x03;
    pub const IRP_MJ_WRITE: u8 = 0x04;
    pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
    pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
    pub const IRP_MJ_QUERY_EA: u8 = 0x07;
    pub const IRP_MJ_SET_EA: u8 = 0x08;
    pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
    pub const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0A;
    pub const IRP_MJ_SET_VOLUME_INFORMATION: u8 = 0x0B;
    pub const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0C;
    pub const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
    pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
    pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
    pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
    pub const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
    pub const IRP_MJ_CLEANUP: u8 = 0x12;
    pub const IRP_MJ_CREATE_MAILSLOT: u8 = 0x13;
    pub const IRP_MJ_QUERY_SECURITY: u8 = 0x14;
    pub const IRP_MJ_SET_SECURITY: u8 = 0x15;
    pub const IRP_MJ_POWER: u8 = 0x16;
    pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
    pub const IRP_MJ_DEVICE_CHANGE: u8 = 0x18;
    pub const IRP_MJ_QUERY_QUOTA: u8 = 0x19;
    pub const IRP_MJ_SET_QUOTA: u8 = 0x1A;
    pub const IRP_MJ_PNP: u8 = 0x1B;
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

/// power IRP minor function codes (IRP_MN_*).
/// These are the minor function codes used in IRP_MJ_POWER IRPs.
pub mod power;

/// power state types.
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
    S0 = 0, // Working
    S1 = 1, // sleep
    S2 = 2, // Deeper sleep
    S3 = 3, // Suspend to RAM
    S4 = 4, // Hibernate
    S5 = 5, // Soft off
}

/// Device power states (D0-D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DevicePowerState {
    D0 = 0, // Working
    D1 = 1, // Lightest sleep
    D2 = 2, // Deeper sleep
    D3 = 3, // Deepest sleep (hot removed)
}

/// power action types.
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
pub const DO_POWER_PAGABLE: u32 = 0x00000200;

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
pub static VPB_TABLE: Spinlock<[Option<Vpb>; MAX_VPBS]> = Spinlock::new([const { None }; MAX_VPBS]);

/// I/O manager signature tag for sanity checks.
pub const IO_MANAGER_TAG: u32 =
    (b'I' as u32) << 24 | (b'o' as u32) << 16 | (b'M' as u32) << 8 | (b'0' as u32);

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
        Self {
            flink: null_mut(),
            blink: null_mut(),
        }
    }

    pub fn init(&mut self) {
        self.flink = null_mut();
        self.blink = null_mut();
    }

    pub fn is_empty(&self) -> bool {
        self.flink.is_null() && self.blink.is_null()
    }
}

impl Default for ListEntry {
    fn default() -> Self {
        Self::new()
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
    /// Cancel routine registered by a driver; invoked by `cancel_irp`
    /// when the request is cancelled.
    pub cancel_routine: Option<unsafe extern "C" fn(*mut Irp)>,
    pub requestor_mode: u8,
    pub pending_returned: u8,
    pub stack_count: u8,
    pub current_location: u8,
    pub packet_type: u8,
    pub allocate_stack: u8,
    pub current_stack: *mut IoStackLocation,
    pub original_irp: *mut Irp,
    /// wdm.h `_IRP.UserBuffer`: caller buffer for buffered / direct I/O.
    pub user_buffer: *mut (),
    /// I/O completion port the IRP is bound to (0 = no port). Port ids are
    /// the ids returned by `iocp::create_io_completion_port`, so 0 is never
    /// a valid port and doubles as the "unbound" marker.
    pub completion_port: u64,
    /// Completion key delivered with the completion packet.
    pub completion_key: u64,
    /// Caller-supplied overlapped/APC-context value carried through to the
    /// completion packet.
    pub overlapped: u64,
}

impl Irp {
    pub const fn new() -> Self {
        Self {
            mdl_address: null_mut(),
            flags: 0,
            associated_irp: null_mut(),
            thread_list_entry: ListEntry::new(),
            io_status: IoStatusBlock::new(),
            cancel_routine: None,
            requestor_mode: 0,
            pending_returned: 0,
            stack_count: 0,
            current_location: 0,
            packet_type: 0,
            allocate_stack: 0,
            current_stack: null_mut(),
            original_irp: null_mut(),
            user_buffer: null_mut(),
            completion_port: 0,
            completion_key: 0,
            overlapped: 0,
        }
    }

    /// Bind this IRP's completion notification to an I/O completion port.
    /// When the IRP is completed via `io_complete_request`, a packet with
    /// `status`/`information` from the IRP plus this key and overlapped
    /// value is posted to the port.
    pub fn bind_completion(&mut self, port_id: u64, completion_key: u64, overlapped: u64) {
        self.completion_port = port_id;
        self.completion_key = completion_key;
        self.overlapped = overlapped;
    }
}

impl Default for Irp {
    fn default() -> Self {
        Self::new()
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
        Self {
            status: 0,
            information: 0,
        }
    }
}

impl Default for IoStatusBlock {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceIoControlParameters {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub io_control_code: u32,
    pub type3_input_buffer: *mut (),
}

/// wdm.h Parameters.Read / Parameters.Write for IRP_MJ_READ and
/// IRP_MJ_WRITE stack locations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadWriteParameters {
    pub byte_offset: u64,
    pub byte_count: u32,
    pub key: u32,
}

/// wdm.h Parameters.Create for IRP_MJ_CREATE stack locations. Only the
/// members the I/O manager consumes are modelled; the remaining
/// CREATE parameters (EA list, root directory, allocation size) live in
/// the caller's FileObject / IRP in the real NT and are not needed here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateParameters {
    /// FILE_* create disposition (wdm.h FILE_OPEN .. FILE_OVERWRITE_IF).
    pub disposition: u32,
    /// FILE_* create options (FILE_DIRECTORY_FILE, ...).
    pub options: u32,
}

/// wdm.h `_IO_STACK_LOCATION.Parameters`: a union of per-major-function
/// parameter blocks. Only the members used by the I/O manager are modelled.
#[repr(C)]
pub union IoParameters {
    pub as_u64: u64,
    pub device_io_control: DeviceIoControlParameters,
    pub read_write: ReadWriteParameters,
    pub create: CreateParameters,
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
    /// Completion routine registered on this stack location (wdm.h
    /// `IoSetCompletionRoutine`). Stored here instead of discarded so
    /// `io_complete_request` can invoke it as the IRP unwinds.
    pub completion_routine:
        Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp, *mut ()) -> i32>,
    /// Context value passed to `completion_routine`.
    pub completion_context: *mut (),
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
            completion_routine: None,
            completion_context: null_mut(),
        }
    }
}

impl Default for IoStackLocation {
    fn default() -> Self {
        Self::new()
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

impl Default for FileObject {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub const fn new() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: null_mut(),
        }
    }
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self::new()
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
    /// Driver-defined device extension (wdm.h DeviceObject.DeviceExtension):
    /// opaque per-device context owned by the functional driver.
    pub device_extension: *mut (),
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
            device_extension: null_mut(),
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
        // // kprintln!(
        // //             "[I/O] Device power state transition: {:?} -> {:?}",
        // //             self.device_power_state, new_state
        // //         );
        self.device_power_state = new_state;
    }
}

impl Default for DeviceObject {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Driver object
// ---------------------------------------------------------------------------

/// Dispatch function type for driver major functions.
pub type DriverDispatch =
    Option<unsafe extern "C" fn(device: *mut DeviceObject, irp: *mut Irp) -> i32>;

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

impl Default for DriverObject {
    fn default() -> Self {
        Self::new()
    }
}

/// internal driver entry in the global list.
pub struct DriverEntry {
    pub name: [u8; 32],
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

impl Default for Vpb {
    fn default() -> Self {
        Self::new()
    }
}

/// internal VPB table entry wrapper (used only as a storage slot marker).
pub struct VpbEntry {
    pub vpb: Vpb,
    pub mounted: bool,
}

/// VPB flags
pub mod vpb_flags {
    pub const REMOUNT: u32 = 0x00000001; // Volume requires remount
    pub const MOUNTED: u32 = 0x00000002; // Volume is mounted
    pub const LOCKED: u32 = 0x00000004; // Volume is locked
    pub const DISMOUNT_PENDING: u32 = 0x00000008; // Dismount is pending
    pub const MOUNT_PENDING: u32 = 0x00000010; // Mount is pending
    pub const SYSTEM: u32 = 0x00000020; // System volume
    pub const BOOT: u32 = 0x00000040; // Boot volume
    pub const BOOT_PARTITION: u32 = 0x00000080; // Boot partition
    pub const PAGEFAULT: u32 = 0x00000100; // Page fault volume
}

/// Allocate a VPB for a device object.
pub fn allocate_vpb() -> *mut Vpb {
    let raw = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<Vpb>()) as *mut Vpb;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, core::mem::size_of::<Vpb>());
        (*raw).r#type = 0x0007; // IO_TYPE_VPB
        (*raw).size = core::mem::size_of::<Vpb>() as u16;
        (*raw).ref_count = AtomicU32::new(1);
    }
    raw
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Free a VPB.
pub unsafe fn free_vpb(vpb: *mut Vpb) {
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Reference a VPB (increment reference count).
pub unsafe fn reference_vpb(vpb: *mut Vpb) {
    if !vpb.is_null() {
        unsafe {
            (*vpb).ref_count.fetch_add(1, Ordering::Acquire);
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Attach a VPB to a device object.
pub unsafe fn attach_vpb(device: *mut DeviceObject, vpb: *mut Vpb) {
    if !device.is_null() && !vpb.is_null() {
        unsafe {
            (*device).vpb = vpb;
            reference_vpb(vpb);
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Detach a VPB from a device object.
pub unsafe fn detach_vpb(device: *mut DeviceObject) -> *mut Vpb {
    if device.is_null() {
        return null_mut();
    }
    unsafe {
        let vpb = (*device).vpb;
        (*device).vpb = null_mut();
        vpb
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Mark a volume as mounted in the VPB.
pub unsafe fn mark_vpb_mounted(vpb: *mut Vpb, fs_name: &[u8]) {
    if !vpb.is_null() {
        unsafe {
            (*vpb).flags |= vpb_flags::MOUNTED;
            // Copy file system name (up to 8 bytes)
            let len = fs_name.len().min(8);
            (&mut (*vpb).file_system)[..len].copy_from_slice(&fs_name[..len]);
        }
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Check if a VPB volume is mounted.
pub unsafe fn is_vpb_mounted(vpb: *mut Vpb) -> bool {
    if vpb.is_null() {
        return false;
    }
    unsafe { ((*vpb).flags & vpb_flags::MOUNTED) != 0 }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// io_call_driver - Pass an IRP to the next lower driver
pub unsafe fn io_call_driver(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    unsafe { dispatch::dispatch_irp(device, irp) }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Invoke the completion routines registered on the IRP's stack locations,
/// walking the driver stack from the lowest slot upward the way NT does as
/// an IRP unwinds. Each routine is taken out of the stack location before
/// it is called so a routine that completes the IRP itself cannot be run
/// again. Returns false only when a routine returned
/// STATUS_MORE_PROCESSING_REQUIRED and now owns the IRP (it must complete
/// it later); the IRP must not be freed in that case.
unsafe fn invoke_completion_routines(irp: *mut Irp) -> bool {
    let count = (*irp).stack_count as usize;
    let status = (*irp).io_status.status as i32;
    let cancelled = ((*irp).flags & IRP_CANCEL_INDICATED) != 0;
    let base = (irp as *mut u8).add(core::mem::size_of::<Irp>()) as *mut IoStackLocation;

    for i in 0..count {
        let stack = base.add(i);
        // Take the routine out first: re-entrant completion from inside
        // the routine must not invoke it a second time.
        let routine = (*stack).completion_routine.take();
        let Some(routine) = routine else {
            continue;
        };
        let control = (*stack).control;
        let invoke = if cancelled {
            (control & irp_stack::SL_INVOKE_ON_CANCEL) != 0
        } else if status >= 0 {
            (control & irp_stack::SL_INVOKE_ON_SUCCESS) != 0
        } else {
            (control & irp_stack::SL_INVOKE_ON_ERROR) != 0
        };
        if !invoke {
            continue;
        }
        let device = (*stack).device_object;
        let context = (*stack).completion_context;
        let result = routine(device, irp, context);
        if result == crate::libs::ntdll::status::STATUS_MORE_PROCESSING_REQUIRED {
            return false;
        }
    }
    true
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// io_complete_request - Complete an IRP
///
/// Runs registered completion routines, updates statistics, delivers the
/// completion notification and frees the IRP.
///
/// # Completion notification (IOCP)
///
/// If the IRP was bound to an I/O completion port via
/// `Irp::bind_completion` (or directly through its `completion_port`
/// field), a packet carrying the IRP's real NTSTATUS, byte count, completion
/// key and overlapped value is posted to that port before the IRP is freed.
/// A thread waiting in `iocp::get_queued_completion_status` observes the
/// packet. This is the single completion-notification path: packets posted
/// by drivers via `nt_set_io_completion` land in the same queues.
///
/// # Completion notification (APC)
///
pub unsafe fn io_complete_request(irp: *mut Irp, priority_boost: i32) {
    let _ = priority_boost;
    if irp.is_null() {
        return;
    }

    unsafe {
        // Call registered completion routines before the IRP memory goes
        // away. A routine may take ownership of the IRP by returning
        // STATUS_MORE_PROCESSING_REQUIRED; then it completes the IRP later.
        if !invoke_completion_routines(irp) {
            return;
        }

        // Queue a kernel-mode I/O APC when the IRP was issued from
        // kernel mode and carries an overlapped context, so the I/O
        // APC queue is exercised on real completion rather than
        // remaining dead code. The issuing thread is the current
        // thread (the same thread that called io_complete_request);
        // a user-mode APC insertion requires the Nt*File caller to
        // pass its thread id, which the current file syscall path
        // does not track yet.
        if (*irp).requestor_mode == 1 && (*irp).overlapped != 0 {
            let thread_id =
                crate::ke::scheduler::with_current_thread(|t| t.client_id.unique_thread)
                    .unwrap_or(0);
            let _ = crate::io::apc::insert_io_apc(
                thread_id,
                crate::io::apc::ApcMode::KernelMode,
                None,
                (*irp).overlapped as *mut (),
                // The IRP's `IoStatusBlock` and the APC module's
                // `IoStatusBlock` are distinct types with the same
                // field layout, so the raw-pointer cast reinterprets
                // the address without changing the data.
                core::ptr::addr_of_mut!((*irp).io_status) as *mut crate::io::apc::IoStatusBlock,
            );
        }

        // Update statistics
        let status = (*irp).io_status.status as i32;
        if status >= 0 {
            IO_STATS.lock().irps_completed += 1;
        } else {
            IO_STATS.lock().irps_cancelled += 1;
        }

        // Deliver the completion notification while the IRP memory is still
        // valid: the packet carries values read from the IRP, and drivers
        // may read the IRP from the overlapped context afterwards.
        let port = (*irp).completion_port;
        if port != 0 {
            let result = crate::io::iocp::post_completion_status(
                port,
                (*irp).io_status.information as u64,
                (*irp).completion_key,
                (*irp).overlapped,
                (*irp).io_status.status,
            );
            if result != crate::io::iocp::STATUS_SUCCESS {
                // A bound port must exist and have queue capacity. Losing a
                // completion packet silently would hang the waiter, so the
                // failure is reported instead.
                crate::hal::serial::write_string(
                    "[IO] io_complete_request: dropped completion packet (port lookup or queue full)\r\n",
                );
            }
        }

        // Free the IRP
        free_irp(irp);
    }
}

/// Allocate an IRP from the pool. Returns `null_mut()` if the pool
/// is exhausted.
pub fn allocate_irp(stack_locations: u8) -> *mut Irp {
    if stack_locations == 0 {
        return null_mut();
    }

    let sz = core::mem::size_of::<Irp>();
    let sl_sz = core::mem::size_of::<IoStackLocation>();
    let total = sz + (sl_sz * stack_locations as usize);
    let raw = pool::allocate(pool::PoolType::NonPaged, total) as *mut Irp;
    if raw.is_null() {
        return null_mut();
    }

    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, total);

        // WRK `ExAllocateIrp`: the stack locations follow the IRP body and
        // are numbered 1..StackCount from the low end. `CurrentLocation`
        // starts at `StackCount` and `CurrentStack` points at location
        // StackCount, so `IoGetNextStackLocation` walks downwards through
        // the driver stack. Pointing at location 1 instead makes the first
        // `get_next_stack_location()` return memory before the allocation.
        (*raw).stack_count = stack_locations;
        (*raw).current_location = stack_locations;
        (*raw).allocate_stack = 1;

        let stack_base = (raw as *mut u8).add(sz) as *mut IoStackLocation;
        for i in 0..stack_locations as usize {
            let sl = stack_base.add(i);
            (*sl) = IoStackLocation::new();
            (*sl).device_object = null_mut();
            (*sl).file_object = null_mut();
        }
        (*raw).current_stack = stack_base.add((stack_locations - 1) as usize);
    }

    IO_STATS.lock().irps_allocated += 1;
    raw
}

/// Free an IRP back to the non-paged pool.
/// This properly deallocates the IRP and its stack locations.
pub fn free_irp(irp: *mut Irp) {
    unsafe {
        if irp.is_null() {
            return;
        }

        // Free the memory back to the pool
        let raw = irp as *mut u8;
        let _ = pool::free(raw);

        IO_STATS.lock().irps_completed += 1;
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Complete an IRP with the given status. Updates the I/O stats.
pub unsafe fn complete_irp(irp: *mut Irp, status: i32, information: usize) {
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
    // `UnicodeString` is a length plus a pointer: setting only the lengths left
    // `buffer` null, so any reader of `driver_name.buffer` dereferenced a null
    // pointer. Store the name in the same pool block as the object, matching
    // `create_device`.
    let name_units = match core::str::from_utf8(name) {
        Ok(s) => s.chars().count(),
        Err(_) => name.len(),
    };
    let block_size = core::mem::size_of::<DriverObject>() + (name_units + 1) * 2;
    let raw = pool::allocate(pool::PoolType::NonPaged, block_size) as *mut DriverObject;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, block_size);
        let d = &mut (*raw);
        let name_buffer = (raw as *mut u8).add(core::mem::size_of::<DriverObject>()) as *mut u16;
        let mut written = 0usize;
        if let Ok(s) = core::str::from_utf8(name) {
            for ch in s.chars().take(name_units) {
                core::ptr::write(name_buffer.add(written), ch as u16);
                written += 1;
            }
        } else {
            for &b in name {
                core::ptr::write(name_buffer.add(written), b as u16);
                written += 1;
            }
        }
        core::ptr::write(name_buffer.add(written), 0);
        d.driver_name.length = (written * 2) as u16;
        d.driver_name.maximum_length = ((written + 1) * 2) as u16;
        d.driver_name.buffer = name_buffer;
    }
    raw
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Register a driver in the global list and the object manager namespace.
pub unsafe fn register_driver(driver: *mut DriverObject) -> bool {
    if driver.is_null() {
        return false;
    }
    let mut list = DRIVER_LIST.lock();
    for i in 0..MAX_DRIVERS {
        if list[i].is_none() {
            unsafe {
                // Field-by-field write to avoid the UC-memory
                // non-temporal-store fault that hits a 48-byte
                // Option<driver_entry> copy.
                let s = &mut list[i];
                // discriminant: Some(1)
                let raw = s as *mut Option<DriverEntry> as *mut u8;
                core::ptr::write(raw, 1); // tag
                let de = s.as_mut().unwrap();
                de.driver = driver;
                de.next = core::ptr::null_mut();
                // Extract the driver name from the UnicodeString now (while
                // we have the driver pointer) and store it in de.name.
                let name_buf = (*driver).driver_name.buffer;
                let name_len_units = ((*driver).driver_name.length as usize) / 2;
                for j in 0..de.name.len() {
                    if j < name_len_units {
                        let ch = core::ptr::read_volatile(name_buf.add(j));
                        de.name[j] = ch as u8;
                    } else {
                        de.name[j] = 0;
                    }
                }
            }

            // Get driver name from the driver object (extract from UnicodeString)
            let driver_name_storage = unsafe {
                let name_ptr = (*driver).driver_name.buffer;
                let name_len = (*driver).driver_name.length as usize;
                let mut name = [0u8; 64];
                let mut name_len_out = 0usize;
                if !name_ptr.is_null() && name_len > 0 {
                    let max_chars = (name_len / 2).min(32);
                    for j in 0..max_chars {
                        let c = core::ptr::read_volatile(name_ptr.add(j));
                        if c == 0 {
                            break;
                        }
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

/// Look up a registered driver by its ASCII name. Returns a pointer to
/// the DriverObject, or null if no driver with that name is registered.
pub fn find_registered_driver(name: &[u8]) -> *mut DriverObject {
    let list = DRIVER_LIST.lock();
    for i in 0..MAX_DRIVERS {
        if let Some(entry) = &list[i] {
            let mut match_len = 0usize;
            for j in 0..entry.name.len() {
                if entry.name[j] == 0 {
                    break;
                }
                match_len = j + 1;
            }
            if match_len == name.len() && entry.name[..match_len] == *name {
                return entry.driver;
            }
        }
    }
    core::ptr::null_mut()
}

/// Register a driver object in the object manager namespace at \Driver\<name>
fn register_driver_in_object_manager(driver: *mut DriverObject, driver_name: &[u8]) {
    if driver.is_null() || driver_name.is_empty() {
        return;
    }

    // create an object header for the driver
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

            // create a default security descriptor (NULL DACL = allow all)
            let sd = crate::se::seaccess::create_null_dacl_sd();
            if !sd.is_null() {
                (*header).security_descriptor = sd as *mut crate::se::seaccess::SecurityDescriptor;
            }
        }

        // Insert into the namespace
        let handle = crate::ob::insert_object(b"\\Driver", header);
        if handle != 0 {
            // // kprintln!("[I/O] Registered driver {:x?} in OB namespace, handle={}",
            // //                      driver_name, handle);
        } else {
            // // kprintln!("[I/O] WARNING: Failed to insert driver into OB namespace");
        }
    } else {
        // // kprintln!("[I/O] WARNING: Failed to create OB header for driver");
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// create a device object and attach it to a driver.
/// This also registers the device in the object manager namespace.
pub unsafe fn create_device(
    driver: *mut DriverObject,
    device_type: DeviceType,
    device_name: &[u8],
) -> *mut DeviceObject {
    // The name is stored in the same pool block as the device object so the
    // UnicodeString buffer has the same lifetime as the object itself.
    let name_units = match core::str::from_utf8(device_name) {
        Ok(s) => s.chars().count(),
        Err(_) => device_name.len(),
    };
    let block_size = core::mem::size_of::<DeviceObject>() + (name_units + 1) * 2;
    let raw = pool::allocate(pool::PoolType::NonPaged, block_size) as *mut DeviceObject;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, block_size);
        (*raw).device_type = device_type;
        (*raw).driver_object = driver;
        (*raw).ref_count = AtomicU32::new(1);
        (*raw).sector_size = 512;
        (*raw).alignment_mask = 0x3F;
        (*raw).device_queue.init();
        (*raw).driver_queues.init();
        (*raw).device_lock.init();

        let name_buffer = (raw as *mut u8).add(core::mem::size_of::<DeviceObject>()) as *mut u16;
        let mut written = 0usize;
        if let Ok(s) = core::str::from_utf8(device_name) {
            for ch in s.chars().take(name_units) {
                core::ptr::write(name_buffer.add(written), ch as u16);
                written += 1;
            }
        }
        core::ptr::write(name_buffer.add(written), 0);
        (*raw).device_name = UnicodeString {
            length: (written * 2) as u16,
            maximum_length: ((written + 1) * 2) as u16,
            buffer: name_buffer,
        };

        // Link into the driver's device list.
        (*raw).next_device = (*driver).device_object;
        (*driver).device_object = raw;
    }

    // Register the device in the object manager namespace
    // Skip registration if OB is not initialized yet (during early boot)
    if !device_name.is_empty() && !device_name.iter().all(|&b| b == 0) {
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

    // create an object header for the device
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

            // create a default security descriptor (NULL DACL = allow all)
            let sd = crate::se::seaccess::create_null_dacl_sd();
            if !sd.is_null() {
                (*header).security_descriptor = sd as *mut crate::se::seaccess::SecurityDescriptor;
            }
        }

        // Insert into the namespace
        let handle = crate::ob::insert_object(b"\\Device", header);
        if handle != 0 {
            // // kprintln!("[I/O] Registered device {:?} in OB namespace, handle={}", name, handle);
        } else {
            // // kprintln!("[I/O] WARNING: Failed to insert device {:?} into OB namespace", name);
        }
    } else {
        // // kprintln!("[I/O] WARNING: Failed to create OB header for device {:?}", name);
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Attach one device above another.
pub unsafe fn attach_device(above: *mut DeviceObject, below: *mut DeviceObject) {
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

#[derive(Default)]
pub struct IoStatsSnapshot {
    pub irps_allocated: u64,
    pub irps_completed: u64,
    pub irps_cancelled: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub reads: u64,
    pub writes: u64,
}

/// Initialize the I/O manager.
pub fn init() {
    unsafe {
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
        // create NULL device driver for bootstrap
        let null_driver = allocate_driver(b"\\Driver\\Null");
        if !null_driver.is_null() {
            unsafe {
                // Set up default major function handlers
                (*null_driver).major_functions[major::IRP_MJ_CREATE as usize] =
                    Some(null_create_dispatch);
                (*null_driver).major_functions[major::IRP_MJ_CLOSE as usize] =
                    Some(null_close_dispatch);
                (*null_driver).major_functions[major::IRP_MJ_READ as usize] =
                    Some(null_read_dispatch);
                (*null_driver).major_functions[major::IRP_MJ_WRITE as usize] =
                    Some(null_write_dispatch);

                // create the NULL device
                let null_device = create_device(null_driver, DeviceType::Null, b"\\Device\\Null");
                if !null_device.is_null() {
                    // // kprintln!("      NULL device created");
                }
            }
            register_driver(null_driver);
        }

        // create filesystem device driver (placeholder for FAT32/NTFS)
        let fs_driver = allocate_driver(b"\\FileSystem\\Ntfs");
        if !fs_driver.is_null() {
            // Set up filesystem major function handlers
            (*fs_driver).major_functions[major::IRP_MJ_CREATE as usize] = Some(fs_create_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_CLOSE as usize] = Some(fs_close_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_READ as usize] = Some(fs_read_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_WRITE as usize] = Some(fs_write_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_CLEANUP as usize] =
                Some(fs_cleanup_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_DEVICE_CONTROL as usize] =
                Some(fs_device_control_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_PNP as usize] = Some(fs_pnp_dispatch);
            (*fs_driver).major_functions[major::IRP_MJ_POWER as usize] = Some(fs_power_dispatch);

            // create the filesystem device
            let fs_device = create_device(fs_driver, DeviceType::FileSystem, b"\\Device\\Fs");
            if !fs_device.is_null() {
                // // kprintln!("      Filesystem device created");
            }

            register_driver(fs_driver);
        }

        // Driver loader registry: give the bootstrap drivers service start
        // types and run the boot/system loading waves, so `load_driver` and
        // the `load_*_start_drivers` entry points have a live registry to
        // work with instead of an empty table.
        driver_loader::init();
        if !null_driver.is_null() {
            driver_loader::register_start_type_driver(
                null_driver,
                driver_loader::ServiceStartType::BootStart,
            );
        }
        if !fs_driver.is_null() {
            driver_loader::register_start_type_driver(
                fs_driver,
                driver_loader::ServiceStartType::SystemStart,
            );
        }
        driver_loader::load_boot_start_drivers();
        driver_loader::load_system_start_drivers();

        // // kprintln!("    I/O Manager: initialized");
        // // kprintln!(
        // //         "      drivers_max={} devices_max={} vpb_max={} irp_pool={}",
        // //         MAX_DRIVERS, MAX_DEVICES, MAX_VPBS, MAX_IRP_POOL
        // //     );
    }
}

// ---------------------------------------------------------------------------
// Default dispatch handlers
// ---------------------------------------------------------------------------

use crate::libs::ntdll::status::{
    STATUS_END_OF_FILE, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Default NULL device dispatch for IRP_MJ_CREATE
unsafe extern "C" fn null_create_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Default NULL device dispatch for IRP_MJ_CLOSE
unsafe extern "C" fn null_close_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Default NULL device dispatch for IRP_MJ_READ
unsafe extern "C" fn null_read_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        // NULL device returns end of file (0 bytes read)
        (*irp).io_status.status = STATUS_END_OF_FILE as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_END_OF_FILE
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Default NULL device dispatch for IRP_MJ_WRITE
unsafe extern "C" fn null_write_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        // NULL device discards writes, returns success
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        // Information = bytes written (we report 0 for NULL)
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Filesystem dispatch handlers
// ---------------------------------------------------------------------------

/// File objects created by `fs_create_dispatch`, held until
/// `fs_close_dispatch` releases them. The CREATE IRP's stack location is
/// freed together with its IRP, so a FileObject must not be owned by it;
/// this registry is the file-scoped owner instead. READ/WRITE dispatches
/// fall back to the oldest entry when their own stack location carries no
/// FileObject (per-close file identity arrives with the syscall/IRP
/// coupling work; until then the registry is one entry per open).
static OPEN_FILE_OBJECTS: Spinlock<Vec<*mut FileObject>> = Spinlock::new(Vec::new());

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_CREATE dispatch for filesystem devices.
/// Opens or creates a file on the filesystem.
///
/// When the caller supplies a FileObject on the stack location — the way
/// wdm.h IoCreateFile carries the FILE_OBJECT in the CREATE stack slot —
/// this dispatch fills in that object (device backpointer, VPB, and the
/// FCB, which is the NTFS handle in pool) instead of allocating its own.
/// The caller then owns the object, and per-file identity survives to the
/// READ/WRITE/CLOSE IRPs that carry the same FileObject. When no object
/// is supplied, a driver-owned FileObject is allocated and registered in
/// `OPEN_FILE_OBJECTS` as before.
///
/// Create dispositions (wdm.h FILE_*) are honoured: open-only
/// dispositions fail with STATUS_OBJECT_NAME_NOT_FOUND, FILE_CREATE
/// fails with STATUS_OBJECT_NAME_COLLISION when the name exists, and
/// create-capable dispositions create the missing file or directory.
unsafe extern "C" fn fs_create_dispatch(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let stack = (*irp).current_stack;
    let mut requested_path: Option<alloc::string::String> = None;
    let mut caller_object: *mut FileObject = null_mut();
    if !stack.is_null() && !(*stack).file_object.is_null() {
        caller_object = (*stack).file_object;
        let name = &(*(*stack).file_object).file_name;
        if name.length > 0 && !name.buffer.is_null() {
            let length = (name.length / 2) as usize;
            let units = unsafe { core::slice::from_raw_parts(name.buffer, length) };
            let mut result = alloc::string::String::new();
            for unit in units {
                if *unit == 0 {
                    break;
                }
                let code_units = [*unit];
                if let Ok(character) = alloc::string::String::from_utf16(&code_units) {
                    result.push_str(&character);
                }
            }
            requested_path = Some(result);
        }
    }

    let (file_obj_ptr, caller_owned) = if !caller_object.is_null() {
        (caller_object, true)
    } else {
        let allocated = pool::allocate(pool::PoolType::NonPaged, core::mem::size_of::<FileObject>())
            as *mut FileObject;
        if allocated.is_null() {
            (*irp).io_status.status = STATUS_NO_MEMORY as u32;
            (*irp).io_status.information = 0;
            io_complete_request(irp, 0);
            return STATUS_NO_MEMORY;
        }
        (allocated, false)
    };

    // Initialize the object. Caller-owned objects arrive with the name
    // already set by the issuer; the driver fills in the device wiring.
    (*file_obj_ptr).device_object = device;
    (*file_obj_ptr).vpb = (*device).vpb;
    if !caller_owned {
        (*file_obj_ptr).fcb = core::ptr::null_mut();
        (*file_obj_ptr).file_name = UnicodeString::new();
        (*file_obj_ptr).current_byte_offset = 0;
        (*file_obj_ptr).flags = 0;
    }

    let mut status = STATUS_SUCCESS as u32;
    // IoStatusBlock.Information for NtCreateFile: FILE_OPENED (0x01)
    // and FILE_CREATED (0x02) — wdm.h FILE_CREATE* result codes.
    let mut information: usize = 0x01;
    if let Some(path) = requested_path {
        let disposition = if !stack.is_null() {
            (*stack).parameters.create.disposition
        } else {
            0x0000_0001 // FILE_OPEN
        };
        let options = if !stack.is_null() {
            (*stack).parameters.create.options
        } else {
            0
        };

        let mut units: alloc::vec::Vec<u16> = path.encode_utf16().collect();
        units.push(0);
        let mut fcb_handle = crate::fs::ntfs::get_mounted_fs()
            .and_then(|filesystem| crate::fs::ntfs::open_file(filesystem, &units, None));

        if fcb_handle.is_none() {
            // The name does not exist yet. Create-capable dispositions
            // create it; open-only dispositions report the failure the
            // way NT does.
            let wants_create = matches!(disposition, 0x2 | 0x3 | 0x5);
            let wants_directory = (options & 0x0000_0001) != 0; // FILE_DIRECTORY_FILE
            if wants_create {
                let created = crate::fs::ntfs::get_mounted_fs().and_then(|filesystem| {
                    if wants_directory {
                        crate::fs::ntfs::create_directory(filesystem, &units).ok()
                    } else {
                        crate::fs::ntfs::create_file(filesystem, &units, &[]).ok()
                    }
                });
                if created.is_some() {
                    information = 0x02; // FILE_CREATED
                    fcb_handle = crate::fs::ntfs::get_mounted_fs().and_then(|filesystem| {
                        crate::fs::ntfs::open_file(filesystem, &units, None)
                    });
                }
            }
            if fcb_handle.is_none() {
                status = if disposition == 0x2 {
                    STATUS_OBJECT_NAME_COLLISION as u32
                } else {
                    STATUS_OBJECT_NAME_NOT_FOUND as u32
                };
            }
        } else if disposition == 0x2 {
            // FILE_CREATE on an existing name is a collision in NT.
            status = STATUS_OBJECT_NAME_COLLISION as u32;
            fcb_handle = None;
        }

        if status == STATUS_SUCCESS as u32 {
            if let Some(handle) = fcb_handle {
                let context = pool::allocate(
                    pool::PoolType::NonPaged,
                    core::mem::size_of::<crate::fs::ntfs::NtfsHandle>(),
                ) as *mut crate::fs::ntfs::NtfsHandle;
                if !context.is_null() {
                    unsafe { core::ptr::write(context, handle) };
                    (*file_obj_ptr).fcb = context as *mut ();
                } else {
                    status = STATUS_NO_MEMORY as u32;
                }
            }
        }
    }

    if status == STATUS_SUCCESS as u32 {
        if !caller_owned {
            // Own the FileObject independently of the CREATE IRP: the
            // stack location dies with its IRP, the file outlives it
            // until CLOSE. Caller-owned objects are tracked by their
            // issuer instead.
            OPEN_FILE_OBJECTS.lock().push(file_obj_ptr);
        }
    } else if !caller_owned {
        let _ = pool::free(file_obj_ptr as *mut u8);
    }

    (*irp).io_status.status = status;
    (*irp).io_status.information = information;
    io_complete_request(irp, 0);
    status as i32
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_READ dispatch for filesystem devices.
/// Reads data from an open file.
unsafe extern "C" fn fs_read_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the file object to access current byte offset. The CREATE
    // IRP's stack location died with its IRP, so fall back to the
    // open-file registry when this stack location carries no object.
    let file_obj = {
        let from_stack = (*stack).file_object;
        if !from_stack.is_null() {
            from_stack
        } else {
            let open = OPEN_FILE_OBJECTS.lock();
            open.first().copied().unwrap_or(null_mut())
        }
    };
    if file_obj.is_null() {
        (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
        (*irp).io_status.information = 0;
        io_complete_request(irp, 0);
        return STATUS_INVALID_PARAMETER;
    }

    let params = (*stack).parameters.read_write;
    // The data buffer travels in Irp::user_buffer (wdm.h UserBuffer,
    // the same convention as build_storage_request); the file byte
    // offset travels in Parameters.Read.ByteOffset, where 0 means
    // "use the current file position" (wdm.h
    // FILE_USE_FILE_POINTER_POSITION).
    let buffer = (*irp).user_buffer as *mut u8;
    let length = params.byte_count;
    if params.byte_offset != 0 {
        (*file_obj).current_byte_offset = params.byte_offset;
        if !(*file_obj).fcb.is_null() {
            let handle = (*file_obj).fcb as *mut crate::fs::ntfs::NtfsHandle;
            unsafe { (*handle).current_position = params.byte_offset };
        }
    }
    let byte_offset = (*file_obj).current_byte_offset;

    if buffer.is_null() || length == 0 {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
        io_complete_request(irp, 0);
        return STATUS_SUCCESS;
    }

    if !(*file_obj).fcb.is_null() {
        let handle = (*file_obj).fcb as *mut crate::fs::ntfs::NtfsHandle;
        let bytes_read;
        if crate::mm::user_copy::is_user_range(buffer as u64, length as usize) {
            if crate::mm::user_copy::probe_user_write(buffer as u64, length as usize).is_err() {
                (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
                (*irp).io_status.information = 0;
                io_complete_request(irp, 0);
                return STATUS_INVALID_PARAMETER;
            }
            let staging = pool::allocate(pool::PoolType::NonPaged, length as usize);
            if staging.is_null() {
                (*irp).io_status.status = STATUS_NO_MEMORY as u32;
                (*irp).io_status.information = 0;
                io_complete_request(irp, 0);
                return STATUS_NO_MEMORY;
            }
            let kernel_buffer =
                unsafe { core::slice::from_raw_parts_mut(staging, length as usize) };
            bytes_read = crate::fs::ntfs::get_mounted_fs()
                .and_then(|filesystem| {
                    crate::fs::ntfs::read_file(filesystem, unsafe { &mut *handle }, kernel_buffer)
                        .ok()
                })
                .unwrap_or(0);
            if bytes_read > 0 {
                let src = unsafe { core::slice::from_raw_parts(staging, bytes_read) };
                let _ = crate::mm::user_copy::copy_to_user(buffer as u64, src);
            }
            pool::free(staging);
        } else {
            let kernel_buffer = unsafe { core::slice::from_raw_parts_mut(buffer, length as usize) };
            bytes_read = crate::fs::ntfs::get_mounted_fs()
                .and_then(|filesystem| {
                    crate::fs::ntfs::read_file(filesystem, unsafe { &mut *handle }, kernel_buffer)
                        .ok()
                })
                .unwrap_or(0);
        }
        if bytes_read > 0 {
            unsafe { (*handle).current_position += bytes_read as u64 };
            (*file_obj).current_byte_offset += bytes_read as u64;
        }
        {
            let mut stats = IO_STATS.lock();
            stats.bytes_read += bytes_read as u64;
            stats.reads += 1;
        }
        let status = if bytes_read > 0 || length == 0 {
            STATUS_SUCCESS
        } else {
            // A read of a non-zero length that transferred nothing is
            // an end-of-file condition in NT, not a parameter error.
            STATUS_END_OF_FILE
        };
        (*irp).io_status.status = status as u32;
        (*irp).io_status.information = bytes_read;
        io_complete_request(irp, 0);
        return status;
    }

    // The read buffer may be a user-mode address; user buffers are never
    // dereferenced directly. Stage the transfer through a kernel buffer.
    let result = if crate::mm::user_copy::is_user_range(buffer as u64, length as usize) {
        if crate::mm::user_copy::probe_user_write(buffer as u64, length as usize).is_err() {
            (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
            (*irp).io_status.information = 0;
            io_complete_request(irp, 0);
            return STATUS_INVALID_PARAMETER;
        }
        let staging = pool::allocate(pool::PoolType::NonPaged, length as usize);
        if staging.is_null() {
            (*irp).io_status.status = STATUS_NO_MEMORY as u32;
            (*irp).io_status.information = 0;
            io_complete_request(irp, 0);
            return STATUS_NO_MEMORY;
        }
        let kernel_buffer = unsafe { core::slice::from_raw_parts_mut(staging, length as usize) };
        let result = crate::fs::vfs::read_file_sectors_into(0, kernel_buffer, byte_offset);
        if result.status == 0 && result.bytes_read > 0 {
            let src = unsafe { core::slice::from_raw_parts(staging, result.bytes_read) };
            let _ = crate::mm::user_copy::copy_to_user(buffer as u64, src);
        }
        pool::free(staging);
        result
    } else {
        let kernel_buffer = unsafe { core::slice::from_raw_parts_mut(buffer, length as usize) };
        crate::fs::vfs::read_file_sectors_into(0, kernel_buffer, byte_offset)
    };

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
    io_complete_request(irp, 0);
    result.status as i32
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_WRITE dispatch for filesystem devices.
/// Writes data to an open file.
unsafe extern "C" fn fs_write_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let stack = (*irp).current_stack;
    if stack.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Get the file object to access current byte offset. The CREATE
    // IRP's stack location died with its IRP, so fall back to the
    // open-file registry when this stack location carries no object.
    let file_obj = {
        let from_stack = (*stack).file_object;
        if !from_stack.is_null() {
            from_stack
        } else {
            let open = OPEN_FILE_OBJECTS.lock();
            open.first().copied().unwrap_or(null_mut())
        }
    };
    if file_obj.is_null() {
        (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
        (*irp).io_status.information = 0;
        io_complete_request(irp, 0);
        return STATUS_INVALID_PARAMETER;
    }

    let params = (*stack).parameters.read_write;
    // Same buffer/offset conventions as the read dispatch: data in
    // Irp::user_buffer, byte offset in Parameters.Read.ByteOffset with
    // 0 meaning "use the current file position".
    let buffer = (*irp).user_buffer as *mut u8;
    let length = params.byte_count;

    if params.byte_offset != 0 {
        (*file_obj).current_byte_offset = params.byte_offset;
        if !(*file_obj).fcb.is_null() {
            let handle = (*file_obj).fcb as *mut crate::fs::ntfs::NtfsHandle;
            unsafe { (*handle).current_position = params.byte_offset };
        }
    }
    // Route to the underlying filesystem via the FCB handle
    let byte_offset = (*file_obj).current_byte_offset;

    if buffer.is_null() || length == 0 {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
        io_complete_request(irp, 0);
        return STATUS_SUCCESS;
    }

    // FCB-backed (NTFS) files are written through the mounted filesystem
    // rather than the raw sector fallback below.
    if !(*file_obj).fcb.is_null() {
        let handle = (*file_obj).fcb as *mut crate::fs::ntfs::NtfsHandle;
        let bytes_written;
        if crate::mm::user_copy::is_user_range(buffer as u64, length as usize) {
            if crate::mm::user_copy::probe_user_read(buffer as u64, length as usize).is_err() {
                (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
                (*irp).io_status.information = 0;
                io_complete_request(irp, 0);
                return STATUS_INVALID_PARAMETER;
            }
            let staging = pool::allocate(pool::PoolType::NonPaged, length as usize);
            if staging.is_null() {
                (*irp).io_status.status = STATUS_NO_MEMORY as u32;
                (*irp).io_status.information = 0;
                io_complete_request(irp, 0);
                return STATUS_NO_MEMORY;
            }
            {
                let kernel_buffer =
                    unsafe { core::slice::from_raw_parts_mut(staging, length as usize) };
                let _ = crate::mm::user_copy::copy_from_user(kernel_buffer, buffer as u64);
            }
            let kernel_buffer = unsafe { core::slice::from_raw_parts(staging, length as usize) };
            bytes_written = crate::fs::ntfs::get_mounted_fs()
                .and_then(|filesystem| {
                    crate::fs::ntfs::write_file(filesystem, unsafe { &mut *handle }, kernel_buffer)
                        .ok()
                })
                .unwrap_or(0);
            pool::free(staging);
        } else {
            let kernel_buffer = unsafe { core::slice::from_raw_parts(buffer, length as usize) };
            bytes_written = crate::fs::ntfs::get_mounted_fs()
                .and_then(|filesystem| {
                    crate::fs::ntfs::write_file(filesystem, unsafe { &mut *handle }, kernel_buffer)
                        .ok()
                })
                .unwrap_or(0);
        }
        if bytes_written > 0 {
            unsafe { (*handle).current_position += bytes_written as u64 };
            (*file_obj).current_byte_offset += bytes_written as u64;
        }
        {
            let mut stats = IO_STATS.lock();
            stats.bytes_written += bytes_written as u64;
            stats.writes += 1;
        }
        let status = if bytes_written > 0 {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_PARAMETER
        };
        (*irp).io_status.status = status as u32;
        (*irp).io_status.information = bytes_written;
        io_complete_request(irp, 0);
        return status;
    }

    // The write buffer may be a user-mode address; user buffers are never
    // dereferenced directly. Stage the transfer through a kernel buffer.
    let result = if crate::mm::user_copy::is_user_range(buffer as u64, length as usize) {
        if crate::mm::user_copy::probe_user_read(buffer as u64, length as usize).is_err() {
            (*irp).io_status.status = STATUS_INVALID_PARAMETER as u32;
            (*irp).io_status.information = 0;
            io_complete_request(irp, 0);
            return STATUS_INVALID_PARAMETER;
        }
        let staging = pool::allocate(pool::PoolType::NonPaged, length as usize);
        if staging.is_null() {
            (*irp).io_status.status = STATUS_NO_MEMORY as u32;
            (*irp).io_status.information = 0;
            io_complete_request(irp, 0);
            return STATUS_NO_MEMORY;
        }
        {
            let kernel_buffer =
                unsafe { core::slice::from_raw_parts_mut(staging, length as usize) };
            let _ = crate::mm::user_copy::copy_from_user(kernel_buffer, buffer as u64);
        }
        let kernel_buffer = unsafe { core::slice::from_raw_parts(staging, length as usize) };
        let result = crate::fs::vfs::write_file_sectors_from(0, kernel_buffer, byte_offset);
        pool::free(staging);
        result
    } else {
        let kernel_buffer = unsafe { core::slice::from_raw_parts(buffer, length as usize) };
        crate::fs::vfs::write_file_sectors_from(0, kernel_buffer, byte_offset)
    };

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
    io_complete_request(irp, 0);
    result.status as i32
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_CLOSE dispatch for filesystem devices.
/// Closes a file handle.
unsafe extern "C" fn fs_close_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    // Release the FileObjects created on this device. File identity per
    // close arrives with the syscall/IRP coupling work; until then CLOSE
    // is the only release point for the open-file registry.
    {
        let mut open = OPEN_FILE_OBJECTS.lock();
        for file_obj in open.drain(..) {
            pool::free(file_obj as *mut u8);
        }
    }
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_CLEANUP dispatch for filesystem devices.
/// Called when the last handle to a file is being closed.
unsafe extern "C" fn fs_cleanup_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = STATUS_SUCCESS as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_DEVICE_CONTROL dispatch for filesystem devices.
/// Handles IOCTL requests from user mode.
unsafe extern "C" fn fs_device_control_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        // Most IOCTLs are not supported in bootstrap
        (*irp).io_status.status = STATUS_INVALID_DEVICE_REQUEST as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_INVALID_DEVICE_REQUEST
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_PNP dispatch for filesystem devices.
/// Handles Plug and Play IRPs.
unsafe extern "C" fn fs_pnp_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
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
                    // IRP_MN_REMOVE_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x03 => {
                    // IRP_MN_CANCEL_REMOVE_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x04 => {
                    // IRP_MN_STOP_DEVICE
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                0x17 => {
                    // IRP_MN_SURPRISE_REMOVAL. The constant table declares
                    // 0x17 for surprise removal; without this arm the code
                    // fell into the wildcard arm and completed with
                    // STATUS_NOT_IMPLEMENTED instead.
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                _ => {
                    (*irp).io_status.status = STATUS_NOT_IMPLEMENTED as u32;
                }
            }
        }
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_POWER dispatch for filesystem devices.
/// Handles power management IRPs with full minor function dispatch.
unsafe extern "C" fn fs_power_dispatch(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if !irp.is_null() {
        let stack = (*irp).current_stack;
        if !stack.is_null() {
            let minor = (*stack).minor_function;
            match minor {
                power::IRP_MN_WAIT_WAKE => {
                    // Wait/Wake - device can wake the system
                    // // kprintln!("[I/O] power: IRP_MN_WAIT_WAKE");
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_POWER_SEQUENCE => {
                    // power Sequence - query power sequence counters
                    // // kprintln!("[I/O] power: IRP_MN_POWER_SEQUENCE");
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_SET_POWER => {
                    // Set power - transition device to new power state
                    // // kprintln!("[I/O] power: IRP_MN_SET_POWER");
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                power::IRP_MN_QUERY_POWER => {
                    // Query power - check if device can enter new power state
                    // // kprintln!("[I/O] power: IRP_MN_QUERY_POWER");
                    (*irp).io_status.status = STATUS_SUCCESS as u32;
                }
                _ => {
                    // // kprintln!("[I/O] power: unknown minor function 0x{:02x}", minor);
                    (*irp).io_status.status = STATUS_NOT_IMPLEMENTED as u32;
                }
            }
        }
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    STATUS_SUCCESS
}

/// Re-export of the I/O system smoke test. The full
/// implementation lives in the `smoke` submodule; this
/// re-export keeps the call site readable as `io::smoke_test()`
/// (matching the `mm::smoke_test()` / `ke::smoke_test()` /
/// `ob::smoke_test()` convention used by `kernel_main`).
pub fn smoke_test() -> bool {
    smoke::smoke_test()
}

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

impl Default for PnpEnumerationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Enumerate devices on a bus and start them.
/// This implements the NT PnP device start sequence:
/// 1. IRP_MN_QUERY_DEVICE_RELATIONS (BusRelations)
/// 2. IRP_MN_QUERY_CAPABILITIES for each child device
/// 3. IRP_MN_START_DEVICE for each child device
///
/// For the bootstrap, this simulates bus enumeration and starts
/// detected devices.
pub unsafe fn pnp_start_device(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        // Check if device is already started
        if (*device).pnp_state == DevicePnPState::Started {
            // // kprintln!("[I/O] PnP: device already started");
            return true;
        }

        // Query device capabilities first
        let cap_result = pnp_query_capabilities(device);
        if !cap_result {
            // // kprintln!("[I/O] PnP: device does not support required capabilities");
            return false;
        }

        // Start the device
        (*device).set_pnp_state(DevicePnPState::Started);
        // // kprintln!(
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
    // // kprintln!("[I/O] PnP: querying device capabilities");
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
    // // kprintln!("[I/O] PnP: querying device relations (no children in bootstrap)");
    0
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// handle device removal.
/// Transitions the device to the appropriate removal state.
pub unsafe fn pnp_remove_device(device: *mut DeviceObject) -> bool {
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
        // // kprintln!(
        // //             "[I/O] PnP: device removal pending (type={:?})",
        // //             (*device).device_type
        // //         );

        // In a full implementation, would send IRP_MN_REMOVE_DEVICE
        // to the device stack and clean up resources.

        (*device).set_pnp_state(DevicePnPState::Deleted);
        // // kprintln!("[I/O] PnP: device deleted");

        true
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// handle surprise removal of a device.
pub unsafe fn pnp_surprise_removal(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        (*device).set_pnp_state(DevicePnPState::SurpriseRemoved);
        // // kprintln!(
        // //             "[I/O] PnP: device surprise removed (type={:?})",
        // //             (*device).device_type
        // //         );
        true
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Stop a device (for rebalancing or resource reconfiguration).
pub unsafe fn pnp_stop_device(device: *mut DeviceObject) -> bool {
    if device.is_null() {
        return false;
    }

    unsafe {
        if (*device).pnp_state != DevicePnPState::Started {
            // // kprintln!(
            // //                 "[I/O] PnP: cannot stop device - not in Started state (current={:?})",
            // //                 (*device).pnp_state
            // //             );
            return false;
        }

        (*device).set_pnp_state(DevicePnPState::Stopped);
        // // kprintln!(
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

    // [DISABLED] // // kprintln!("[I/O] PnP enumerated: started={}, failed={}", started_count, failed_count);
    let _ = (&started_count, &failed_count);
}

/// Initialize the PnP manager.
/// Sets up the PnP state machine and prepares for device enumeration.
pub fn pnp_init() {
    // // kprintln!("[I/O] PnP manager initialized");
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
    /// create a new device stack with a base device.
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

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Attach a filter device above another device in the stack.
    /// The filter device will receive IRPs before the target device.
    pub unsafe fn attach_filter_device(&mut self, filter: *mut DeviceObject) -> bool {
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

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Detach a filter device from the stack.
    pub unsafe fn detach_filter_device(&mut self, filter: *mut DeviceObject) -> bool {
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
    pub fast_io_check_if_possible: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _byte_offset: u64,
            _length: u32,
            _lock: bool,
            _check_for_read: bool,
            _wait: bool,
            _alert: bool,
        ) -> bool,
    >,
    /// FastIoRead - read without creating an IRP.
    pub fast_io_read: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _buffer: *mut u8,
            _length: u32,
            _wait: bool,
        ) -> bool,
    >,
    /// FastIoWrite - write without creating an IRP.
    pub fast_io_write: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _buffer: *const u8,
            _length: u32,
            _wait: bool,
        ) -> bool,
    >,
    /// FastIoQueryBasicInfo - query basic file information.
    pub fast_io_query_basic_info: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _wait: bool,
        ) -> bool,
    >,
    /// FastIoQueryStandardInfo - query standard file information.
    pub fast_io_query_standard_info: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _wait: bool,
        ) -> bool,
    >,
    /// FastIoLock - lock a region of a file.
    pub fast_io_lock: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _byte_offset: u64,
            _length: u64,
            _wait: bool,
            _exclusive: bool,
        ) -> bool,
    >,
    /// FastIoUnlockSingle - unlock a single region.
    pub fast_io_unlock_single: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _byte_offset: u64,
            _length: u64,
        ) -> bool,
    >,
    /// FastIoUnlockAll - unlock all regions.
    pub fast_io_unlock_all:
        Option<unsafe extern "C" fn(_device: *mut DeviceObject, _file: *mut FileObject) -> bool>,
    /// FastIoUnlockAllByKey - unlock by key.
    pub fast_io_unlock_all_by_key: Option<
        unsafe extern "C" fn(_device: *mut DeviceObject, _file: *mut FileObject, _key: u64) -> bool,
    >,
    /// FastIoDeviceControl - device I/O control.
    pub fast_io_device_control: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _wait: bool,
            _input: bool,
        ) -> bool,
    >,
    /// FastIoAcquireForModWrite - acquire for modified write.
    pub fast_io_acquire_for_mod_write: Option<
        unsafe extern "C" fn(
            _device: *mut DeviceObject,
            _file: *mut FileObject,
            _byte_offset: u64,
            _length: u64,
        ) -> bool,
    >,
    /// FastIoReleaseForModWrite - release from modified write.
    pub fast_io_release_for_mod_write:
        Option<unsafe extern "C" fn(_device: *mut DeviceObject, _file: *mut FileObject) -> bool>,
    /// FastIoAcquireForCcFlush - acquire for cache flush.
    pub fast_io_acquire_for_cc_flush:
        Option<unsafe extern "C" fn(_device: *mut DeviceObject, _file: *mut FileObject) -> bool>,
    /// FastIoReleaseForCcFlush - release from cache flush.
    pub fast_io_release_for_cc_flush:
        Option<unsafe extern "C" fn(_device: *mut DeviceObject, _file: *mut FileObject) -> bool>,
}

impl FastIoDispatch {
    /// create a new FastIoDispatch with all fields set to None.
    pub fn new() -> Self {
        Self {
            size: core::mem::size_of::<Self>() as u32,
            ..Default::default()
        }
    }

    /// create a FastIoDispatch with basic read/write handlers populated.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Default Fast I/O query basic info handler.
unsafe extern "C" fn fast_io_query_basic_info_impl(
    _device: *mut DeviceObject,
    _file: *mut FileObject,
    _wait: bool,
) -> bool {
    false
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
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

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Cancel an IRP that is queued or in progress.
/// Returns true if the IRP was successfully cancelled.
pub unsafe fn cancel_irp(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return false;
    }

    unsafe {
        // Already cancelled (or completed through the cancel path):
        // cancelling twice must not run the routine again.
        if ((*irp).flags & IRP_CANCEL_INDICATED) != 0 {
            return false;
        }

        // Mark the IRP as cancelled in its flags and record the status the
        // requester will observe.
        (*irp).flags |= IRP_CANCEL_INDICATED;
        (*irp).io_status.status = cancel::STATUS_CANCELLED as u32;
        (*irp).io_status.information = 0;

        // Take the routine out before calling it so a routine that
        // completes the IRP itself cannot observe (or run) itself again.
        let routine = (*irp).cancel_routine.take();
        if let Some(routine) = routine {
            routine(irp);
            return true;
        }

        // No cancel routine registered: the IRP is marked cancelled (with
        // the status the requester will observe) and stays alive until its
        // owner completes it, matching NT's IoCancelIrp semantics.
        true
    }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Check if an IRP has been cancelled.
pub unsafe fn irp_is_cancelled(irp: *mut Irp) -> bool {
    if irp.is_null() {
        return true;
    }
    unsafe { ((*irp).flags & IRP_CANCEL_INDICATED) != 0 }
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Set cancel routine for an IRP.
/// This is called by the driver to set up cancellation support.
pub unsafe fn set_irp_cancel_routine(
    irp: *mut Irp,
    cancel_routine: Option<unsafe extern "C" fn(*mut Irp)>,
) {
    if irp.is_null() {
        return;
    }
    unsafe {
        (*irp).cancel_routine = cancel_routine;
    }
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
    /// create/Open
    pub create: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// close
    pub close: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// read
    pub read: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// write
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
    /// Directory control
    pub directory_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// File System control
    pub file_system_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Device I/O control
    pub device_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// internal Device control
    pub internal_device_control: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Cleanup
    pub cleanup: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// close for maintenance
    pub close_mc: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Plug and Play
    pub pnp: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// power
    pub power: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
    /// Others (schema/locked pages)
    pub others: Option<unsafe extern "C" fn(*mut DeviceObject, *mut Irp) -> i32>,
}

impl DriverDispatchTable {
    /// create a new dispatch table with all handlers set to None.
    pub fn new() -> Self {
        Self::default()
    }

    /// # Safety
    ///
    /// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
    /// Install this dispatch table into a driver object.
    pub unsafe fn install(&self, driver: *mut DriverObject) {
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
            if let Some(f) = self.query_information {
                (*driver).major_functions[major::IRP_MJ_QUERY_INFORMATION as usize] = Some(f);
            }
            if let Some(f) = self.set_information {
                (*driver).major_functions[major::IRP_MJ_SET_INFORMATION as usize] = Some(f);
            }
            if let Some(f) = self.query_ea {
                (*driver).major_functions[major::IRP_MJ_QUERY_EA as usize] = Some(f);
            }
            if let Some(f) = self.set_ea {
                (*driver).major_functions[major::IRP_MJ_SET_EA as usize] = Some(f);
            }
            if let Some(f) = self.flush_buffers {
                (*driver).major_functions[major::IRP_MJ_FLUSH_BUFFERS as usize] = Some(f);
            }
            if let Some(f) = self.query_volume_information {
                (*driver).major_functions[major::IRP_MJ_QUERY_VOLUME_INFORMATION as usize] =
                    Some(f);
            }
            if let Some(f) = self.set_volume_information {
                (*driver).major_functions[major::IRP_MJ_SET_VOLUME_INFORMATION as usize] = Some(f);
            }
            if let Some(f) = self.directory_control {
                (*driver).major_functions[major::IRP_MJ_DIRECTORY_CONTROL as usize] = Some(f);
            }
            if let Some(f) = self.file_system_control {
                (*driver).major_functions[major::IRP_MJ_FILE_SYSTEM_CONTROL as usize] = Some(f);
            }
            if let Some(f) = self.internal_device_control {
                (*driver).major_functions[major::IRP_MJ_INTERNAL_DEVICE_CONTROL as usize] = Some(f);
            }
        }
    }
}

pub mod apc;
pub mod cancel;
pub mod dispatch;
pub mod driver_loader;
pub mod fsctl;
pub mod iocomplete;
pub mod iocp;
pub mod irp_pool_complete;
pub mod irp_stack;
pub mod tests;
pub mod timeout;
pub mod transfer;
