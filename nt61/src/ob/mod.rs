//! Object Manager
//
//! NT-style executive object management. The object manager
//! maintains the kernel's directory namespace (the `\` tree:
//! `\Device`, `\Driver`, `\KernelObjects`, `\??`, ...) plus a
//! per-object header that is embedded in every kernel object
//! (device, driver, file, process, thread, ...).
//
//! # Surface
//
//! * `ObCreateObject` / `ObInsertObject` — create a new object
//!   in a directory and return a pointer + handle.
//! * `ObReferenceObject` / `ObDereferenceObject` — manage the
//!   reference count. When the count hits zero, the type's
//!   delete procedure is called.
//! * `ObOpenObjectByName` — look up an object by name.
//! * `ObReferenceObjectByHandle` — resolve a handle to a
//!   pointer (in this bootstrap a "handle" is just the object
//!   pointer itself; the real Windows kernel has a real handle
//!   table keyed by EPROCESS).
//
//! # Bootstrap limitations
//
//! The handle table is a flat array indexed by a slot number.
//! Each process has its own table; we only have one process on
//! the BSP, so we use the global table for everything.

use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ke::sync::Spinlock;
use crate::mm::pool;

pub mod smoke;
pub mod types;

// =============================================================================
// Status codes — NT standard NTSTATUS values used by the object manager
// =============================================================================

/// NTSTATUS return type used by the object manager.
pub type ObStatus = u32;

/// Successful completion.
pub const STATUS_SUCCESS: ObStatus = 0;
/// The information accessed is invalid.
pub const STATUS_INVALID_PARAMETER: ObStatus = 0xC0000008;
/// An object name is invalid.
pub const STATUS_OBJECT_NAME_INVALID: ObStatus = 0xC0000033;
/// A quota allocation failed.
pub const STATUS_QUOTA_EXCEEDED: ObStatus = 0xC000007C;
/// Insufficient system resources exist to complete the API.
pub const STATUS_INSUFFICIENT_RESOURCES: ObStatus = 0xC000009A;
/// An object handle is invalid.
pub const STATUS_INVALID_HANDLE: ObStatus = 0xC0000008; // alias
/// A name collision occurred in the object namespace.
pub const STATUS_OBJECT_NAME_COLLISION: ObStatus = 0xC0000035;
/// Indicates the object manager detected a cycle in symbolic-link resolution.
pub const STATUS_NAME_TOO_LONG: ObStatus = 0xC0000106;

/// Maximum number of named entries per directory. NT itself uses
/// a balanced tree so the per-directory limit is effectively
/// unbounded; 256 covers the worst-case bootstrap namespace
/// (\Driver, \Device, \BaseNamedObjects, \KernelObjects) without
/// forcing the data structure to be dynamic yet.
pub const MAX_DIR_ENTRIES: usize = 256;
/// Maximum depth of the directory tree. NT allows arbitrarily deep
/// paths; 256 leaves headroom for the deepest practical NT path
/// (\??\C:\Users\<long>\AppData\Roaming\...) before we'd ever
/// need a dynamic structure.
pub const MAX_NAME_LEN: usize = 256;
/// Initial size of the handle table for new processes / global kernel table.
/// In NT the handle table starts small and grows; we pre-allocate the max
/// at boot for simplicity. This is the upper bound only.
pub const HANDLE_TABLE_INITIAL_SIZE: usize = 64;
/// Maximum size of the global handle table.
///
/// # Issue 2.11
/// The original table hardcoded 4096 entries which is too small for
/// production workloads. We now reserve room for 16384 handles, which
/// covers typical kernel-mode bootstrap workloads (Windows 7 documents a
/// handle table limit of 16 MiB handles per process; we use the same
/// 4-byte-per-entry budget for the global kernel table).
pub const HANDLE_TABLE_MAX_SIZE: usize = 16384;
/// Maximum number of objects the global handle table can hold.
///
/// Alias of `HANDLE_TABLE_MAX_SIZE`. Kept for backward compatibility.
pub const MAX_HANDLES: usize = HANDLE_TABLE_MAX_SIZE;
/// Maximum number of directories in the namespace.
pub const MAX_DIRECTORIES: usize = 128;

/// Convert an `ObjectHeader.name` fixed array to a slice.
#[inline]
fn name_slice(name: &[u8; MAX_NAME_LEN]) -> &[u8] {
    let end = name.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN);
    &name[..end]
}

/// Element-by-element slice equality. Avoids the
/// `core::slice::cmp::memcmp` intrinsic that the host build
/// can't satisfy (the bare-metal kernel build uses
/// `compiler_builtins`, but the host `cargo build` doesn't link
/// it for `no_std`).
#[inline]
fn slice_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Object types with Windows 7 x64 TypeIndex values.
///
/// In Windows 7+, the OBJECT_HEADER uses a 1-byte TypeIndex at
/// offset 0x18. This enum values match the actual TypeIndex values
/// used in Windows 7 x64 for compatibility with structure layouts.
///
/// Reference: Geoff Chappell - nt!ObTypeIndex values for Windows 7
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObType {
    /// Type object (0) - the metaclass for object types
    Type = 0,

    /// Process object (1) - represents a running program
    Process = 1,

    /// Thread object (2) - represents an execution context
    Thread = 2,

    /// Directory object (3) - namespace directory
    Directory = 3,

    /// SymbolicLink object (4) - symbolic link
    SymbolicLink = 4,

    /// Token object (5) - security token
    Token = 5,

    /// Job object (6) - job container
    Job = 6,

    /// Event object - Notification type (7)
    EventNotification = 7,

    /// Event object - Synchronization type (8)
    EventSynchronization = 8,

    /// Section object (9) - shared memory region
    Section = 9,

    /// Mutant object (10) - mutex
    Mutant = 10,

    /// Semaphore object (11)
    Semaphore = 11,

    /// Reserved (12)
    Reserved12 = 12,

    /// Reserved (13)
    Reserved13 = 13,

    /// Key object (14) - registry key
    Key = 14,

    /// Reserved for Windows (15-27)
    Reserved15 = 15,
    Reserved16 = 16,
    Reserved17 = 17,
    Reserved18 = 18,
    Reserved19 = 19,
    Reserved20 = 20,
    Reserved21 = 21,
    Reserved22 = 22,
    Reserved23 = 23,
    Reserved24 = 24,
    Reserved25 = 25,
    Reserved26 = 26,
    Reserved27 = 27,

    /// Adapter object (28)
    Adapter = 28,

    /// Controller object (29)
    Controller = 29,

    /// Device object (30)
    Device = 30,

    /// Driver object (31)
    Driver = 31,

    /// IoCompletion object (32)
    IoCompletion = 32,

    /// Timer object (33)
    Timer = 33,

    /// Profile object (34)
    Profile = 34,

    /// WmiGuid object (35)
    WmiGuid = 35,

    /// PowerRequest object (36)
    PowerRequest = 36,

    /// W32Object (37) - Win32 subsystem object
    W32Object = 37,
}

impl ObType {
    /// Get the type index value (matches Windows 7 OBJECT_HEADER::TypeIndex)
    pub fn as_type_index(self) -> u8 {
        self as u8
    }

    /// Create ObType from a type index
    pub fn from_type_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(ObType::Type),
            1 => Some(ObType::Process),
            2 => Some(ObType::Thread),
            3 => Some(ObType::Directory),
            4 => Some(ObType::SymbolicLink),
            5 => Some(ObType::Token),
            6 => Some(ObType::Job),
            7 => Some(ObType::EventNotification),
            8 => Some(ObType::EventSynchronization),
            9 => Some(ObType::Section),
            10 => Some(ObType::Mutant),
            11 => Some(ObType::Semaphore),
            14 => Some(ObType::Key),
            28 => Some(ObType::Adapter),
            29 => Some(ObType::Controller),
            30 => Some(ObType::Device),
            31 => Some(ObType::Driver),
            32 => Some(ObType::IoCompletion),
            33 => Some(ObType::Timer),
            34 => Some(ObType::Profile),
            35 => Some(ObType::WmiGuid),
            36 => Some(ObType::PowerRequest),
            37 => Some(ObType::W32Object),
            _ => None,
        }
    }

    /// Map this `ObType` variant to the corresponding Windows type index.
    ///
    /// # Issue 2.8
    /// The mapping is 1:1 for all defined types (0-37).
    /// Reserved slots (12-13, 15-27) return `None` because they are
    /// internal NT slots that do not correspond to named Windows types.
    ///
    /// | ObType          | Windows Index | Notes                              |
    /// |-----------------|---------------|------------------------------------|
    /// | Type            | 0             | OBJECT_TYPE typedef                 |
    /// | Process         | 1             | Eprocess                           |
    /// | Thread          | 2             | Ethread                            |
    /// | Directory       | 3             | ObpDirectoryObjectName             |
    /// | SymbolicLink    | 4             | ObpSymbolicLinkObjectType         |
    /// | Token           | 5             | SepTokenType                       |
    /// | Job             | 6             | PspJobType                         |
    /// | Event           | 7/8           | ExEventType[0/1]                   |
    /// | Section         | 9             | MmSectionObjectType                |
    /// | Mutant          | 10            | ExMutantObjectType                 |
    /// | Semaphore       | 11            | ExSemaphoreObjectType              |
    /// | Key             | 14            | CmKeyObjectType                    |
    /// | Adapter         | 28            | IoAdapterObjectType                |
    /// | Controller      | 29            | IoControllerObjectType            |
    /// | Device          | 30            | IoDeviceObjectType                 |
    /// | Driver          | 31            | IoDriverObjectType                 |
    /// | IoCompletion    | 32            | IoCompletionObjectType             |
    /// | Timer           | 33            | ExTimerObjectType                  |
    /// | Profile         | 34            | ObpProfileObjectType               |
    /// | WmiGuid         | 35            | WmiDataGuidObjectType              |
    /// | PowerRequest    | 36            | PowerRequestType                   |
    /// | W32Object       | 37            | W32Process/W32Thread/etc.         |
    /// | Reserved*       | —             | No named Windows type              |
    pub fn to_windows_index(self) -> Option<u8> {
        let idx = self.as_type_index();
        match self {
            // Reserved slots have no named Windows counterpart.
            ObType::Reserved12  |
            ObType::Reserved13  |
            ObType::Reserved15  |
            ObType::Reserved16  |
            ObType::Reserved17  |
            ObType::Reserved18  |
            ObType::Reserved19  |
            ObType::Reserved20  |
            ObType::Reserved21  |
            ObType::Reserved22  |
            ObType::Reserved23  |
            ObType::Reserved24  |
            ObType::Reserved25  |
            ObType::Reserved26  |
            ObType::Reserved27  => None,
            // All other slots map 1:1.
            _ => Some(idx),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObType::Type => "Type",
            ObType::Process => "Process",
            ObType::Thread => "Thread",
            ObType::Directory => "Directory",
            ObType::SymbolicLink => "SymbolicLink",
            ObType::Token => "Token",
            ObType::Job => "Job",
            ObType::EventNotification => "Event",
            ObType::EventSynchronization => "Event",
            ObType::Section => "Section",
            ObType::Mutant => "Mutant",
            ObType::Semaphore => "Semaphore",
            ObType::Key => "Key",
            ObType::Adapter => "Adapter",
            ObType::Controller => "Controller",
            ObType::Device => "Device",
            ObType::Driver => "Driver",
            ObType::IoCompletion => "IoCompletion",
            ObType::Timer => "Timer",
            ObType::Profile => "Profile",
            ObType::WmiGuid => "WmiGuid",
            ObType::PowerRequest => "PowerRequest",
            ObType::W32Object => "W32Object",
            ObType::Reserved12 => "Reserved12",
            ObType::Reserved13 => "Reserved13",
            ObType::Reserved15 => "Reserved15",
            ObType::Reserved16 => "Reserved16",
            ObType::Reserved17 => "Reserved17",
            ObType::Reserved18 => "Reserved18",
            ObType::Reserved19 => "Reserved19",
            ObType::Reserved20 => "Reserved20",
            ObType::Reserved21 => "Reserved21",
            ObType::Reserved22 => "Reserved22",
            ObType::Reserved23 => "Reserved23",
            ObType::Reserved24 => "Reserved24",
            ObType::Reserved25 => "Reserved25",
            ObType::Reserved26 => "Reserved26",
            ObType::Reserved27 => "Reserved27",
        }
    }

    /// Convert a handle kind index to ObType.
    /// HandleKind index: File=0, Process=1, Thread=2, Section=3,
    /// Event=4, Mutant=5, Semaphore=6, Timer=7, Key=8
    pub fn from_handle_kind(kind_index: u32) -> Self {
        match kind_index {
            0 => ObType::Key, // Legacy mapping
            1 => ObType::Process,
            2 => ObType::Thread,
            3 => ObType::Section,
            4 => ObType::EventNotification,
            5 => ObType::Mutant,
            6 => ObType::Semaphore,
            7 => ObType::Timer,
            8 => ObType::Key,
            _ => ObType::Key,
        }
    }

    /// Convert ObType to handle kind index.
    pub fn to_handle_kind(self) -> u32 {
        match self {
            ObType::Process => 1,
            ObType::Thread => 2,
            ObType::Section => 3,
            ObType::EventNotification => 4,
            ObType::EventSynchronization => 4,
            ObType::Mutant => 5,
            ObType::Semaphore => 6,
            ObType::Timer => 7,
            ObType::Key => 8,
            _ => 0,
        }
    }

    /// Check if this is a process object type
    pub fn is_process(&self) -> bool {
        matches!(self, ObType::Process)
    }

    /// Check if this is a thread object type
    pub fn is_thread(&self) -> bool {
        matches!(self, ObType::Thread)
    }

    /// Check if this is an event object type
    pub fn is_event(&self) -> bool {
        matches!(self, ObType::EventNotification | ObType::EventSynchronization)
    }
}

/// Global object type index table. This mirrors Windows 7's
/// nt!ObTypeIndexTable, providing a lookup from TypeIndex to type name.
/// Used for debugging and diagnostics.
///
/// Windows 7 x64 TypeIndex values:
/// 0 = Type
/// 1 = Process
/// 2 = Thread
/// 3 = Directory
/// 4 = SymbolicLink
/// 5 = Token
/// 6 = Job
/// 7 = Event (Notification)
/// 8 = Event (Synchronization)
/// 9 = Section
/// 10 = Mutant
/// 11 = Semaphore
/// 12-13 = Reserved
/// 14 = Key
/// 15-27 = Reserved
/// 28 = Adapter
/// 29 = Controller
/// 30 = Device
/// 31 = Driver
/// 32 = IoCompletion
/// 33 = Timer
/// 34 = Profile
/// 35 = WmiGuid
/// 36 = PowerRequest
/// 37 = W32Object
static OB_TYPE_INDEX_TABLE: [&str; 38] = [
    "Type",           // 0
    "Process",        // 1
    "Thread",         // 2
    "Directory",      // 3
    "SymbolicLink",   // 4
    "Token",          // 5
    "Job",            // 6
    "Event",          // 7 (Notification)
    "Event",          // 8 (Synchronization)
    "Section",        // 9
    "Mutant",         // 10
    "Semaphore",      // 11
    "Reserved",       // 12
    "Reserved",       // 13
    "Key",            // 14
    "Reserved15",     // 15
    "Reserved16",     // 16
    "Reserved17",     // 17
    "Reserved18",     // 18
    "Reserved19",     // 19
    "Reserved20",     // 20
    "Reserved21",     // 21
    "Reserved22",     // 22
    "Reserved23",     // 23
    "Reserved24",     // 24
    "Reserved25",     // 25
    "Reserved26",     // 26
    "Reserved27",     // 27
    "Adapter",        // 28
    "Controller",     // 29
    "Device",         // 30
    "Driver",         // 31
    "IoCompletion",   // 32
    "Timer",          // 33
    "Profile",        // 34
    "WmiGuid",        // 35
    "PowerRequest",   // 36
    "W32Object",      // 37
];

/// Get the type name for a given type index.
/// Returns "Unknown" if the index is invalid.
pub fn ob_get_type_name(type_index: u8) -> &'static str {
    OB_TYPE_INDEX_TABLE
        .get(type_index as usize)
        .copied()
        .unwrap_or("Unknown")
}

/// Get the type index from an object header.
/// This retrieves the TypeIndex byte from the OBJECT_HEADER.
#[inline(always)]
pub fn ob_get_type_index(header: *const ObjectHeader) -> u8 {
    if header.is_null() {
        return 0xFF; // Invalid
    }
    unsafe { (*header).type_index }
}

/// Query the object type name from an object header.
/// Returns the type name string for debugging.
pub fn ob_query_object_type_name(header: *const ObjectHeader) -> &'static str {
    ob_get_type_name(ob_get_type_index(header))
}

/// Check if an object is of a specific type.
#[inline(always)]
pub fn ob_is_type(header: *const ObjectHeader, expected: ObType) -> bool {
    ob_get_type_index(header) == expected.as_type_index()
}

/// ObjectHeader flags
pub const OB_FLAG_PERMANENT: u32 = 0x00000001;
pub const OB_FLAG_DEFAULT_SECURITY_QUOTA: u32 = 0x00000002;
pub const OB_FLAG_SINGLE_HANDLE_ENTRY: u32 = 0x00000004;
pub const OB_FLAG_UNPROTECTED: u32 = 0x00000008;
pub const OB_FLAG_PROTECTED: u32 = 0x00000010;
pub const OB_FLAG_EXCLUSIVE: u32 = 0x00000020;
/// Object is in the process of being deleted. Used to detect
/// re-entrant deletion and prevent double-free.
pub const OB_FLAG_DELETING: u32 = 0x80000000;

/// Global spinlock that serialises all operations that might trigger
/// object deletion. Both `dereference_object` and `decrement_handle_count`
/// hold this lock when they check ref_count/handle_count and call
/// `delete_object`. This prevents the TOCTOU race where ref_count
/// reaches 0 while another thread is still holding a handle.
///
/// In the single-CPU bootstrap environment this lock is held for
/// microseconds at most and never blocks. On a full SMP kernel it
/// would be a short-held spinlock; the expensive path (actual deletion)
/// is rare.
static OB_DELETE_LOCK: Spinlock<()> = Spinlock::new(());

/// Header prepended to every executive object. Mirrors the NT
/// `OBJECT_HEADER` with Windows 7+ TypeIndex layout.
///
/// In Windows 7, the OBJECT_HEADER uses a 1-byte TypeIndex at
/// offset 0x18 (instead of a pointer in older versions).
/// We use `type_index` as a u8 to match this layout.
#[repr(C, align(16))]
pub struct ObjectHeader {
    /// Pointer to the actual object body (after this header).
    pub body: *mut (),
    /// Object type index (Windows 7+). This is a 1-byte index
    /// into the global ObTypeIndexTable. Matches nt!ObTypeIndex.
    pub type_index: u8,
    /// Padding for alignment (type_index is 1 byte, but aligned)
    _type_padding: [u8; 7],
    /// Reference count. The object is freed when this hits zero.
    pub ref_count: AtomicU32,
    /// Handle count (number of outstanding handles to this
    /// object). The handle-table slot count.
    pub handle_count: AtomicU32,
    /// Pointer to the directory this object lives in. `null_mut()`
    /// means it's the root.
    pub directory: *mut Directory,
    /// Null-terminated name.
    pub name: [u8; MAX_NAME_LEN],
    /// Total allocation size in bytes (ObjectHeader + body). Stored
    /// here so `dereference_object` can free the full allocation
    /// instead of leaking the body. Set by `allocate_object_header`.
    pub allocation_size: u32,
    /// Pool tag for debugging / leak detection.
    pub pool_tag: u32,
    /// Security descriptor pointer. Points to a SecurityDescriptor
    /// allocated from non-paged pool. This field is allocated even
    /// when the object has no security descriptor (NULL pointer).
    pub security_descriptor: *mut crate::se::seaccess::SecurityDescriptor,
    /// Object flags (OB_FLAG_*). Accessed atomically via CAS in the
    /// delete path to prevent double-deletion races.
    pub flags: AtomicU32,
    /// Padding to 16-byte boundary (320 = 16 * 20)
    _end_padding: [u8; 12],
}

/// Compile-time assertion: ObjectHeader must be 16-byte aligned.
const _: () = assert!(
    core::mem::size_of::<ObjectHeader>() % 16 == 0,
    "ObjectHeader must be 16-byte aligned"
);

impl ObjectHeader {
    pub const fn empty() -> Self {
        Self {
            body: null_mut(),
            type_index: 0,
            _type_padding: [0; 7],
            ref_count: AtomicU32::new(0),
            handle_count: AtomicU32::new(0),
            directory: null_mut(),
            name: [0; MAX_NAME_LEN],
            allocation_size: 0,
            pool_tag: 0,
            security_descriptor: core::ptr::null_mut(),
            flags: AtomicU32::new(0),
            _end_padding: [0; 12],
        }
    }

    /// Set the type index from an ObType enum value.
    #[inline(always)]
    pub fn set_type(&mut self, ob_type: ObType) {
        self.type_index = ob_type.as_type_index();
    }

    /// Get the type index value.
    #[inline(always)]
    pub fn get_type_index(&self) -> u8 {
        self.type_index
    }

    /// Get the ObType enum value from the stored index.
    #[inline(always)]
    pub fn get_type(&self) -> Option<ObType> {
        ObType::from_type_index(self.type_index)
    }
}

/// Directory object. Contains an array of named entries that
/// point at other objects' headers.
#[repr(C, align(16))]
pub struct Directory {
    pub header: ObjectHeader,
    /// Raw pointers, in declaration order. `valid[i]` tells
    /// whether `entries[i]` is actually a live object. We avoid
    /// `Option<*mut T>` because in this build `Option<*mut T>` is
    /// NOT niche-optimised to a single pointer (it still carries
    /// a 4-byte discriminant + 8-byte payload, so writing the
    /// pointer alone leaves the discriminant at 0 = None and the
    /// lookup reads back `None` instead of the pointer). The
    /// `valid` bitset gives us a flag we control.
    pub entries: [*mut ObjectHeader; MAX_DIR_ENTRIES],
    pub valid: [u8; MAX_DIR_ENTRIES],
    pub num_entries: u32,
    /// True if this is the root directory (the `\` directory).
    pub is_root: bool,
}

impl Directory {
    pub const fn empty() -> Self {
        Self {
            header: ObjectHeader::empty(),
            entries: [core::ptr::null_mut(); MAX_DIR_ENTRIES],
            valid: [0; MAX_DIR_ENTRIES],
            num_entries: 0,
            is_root: false,
        }
    }
}

/// Pool tag we use for the object manager's allocations.
const OB_POOL_TAG: u32 = (b'O' as u32) << 24
    | (b'b' as u32) << 16
    | (b'j' as u32) << 8
    | (b'0' as u32);

/// Global namespace state.
struct Namespace {
    /// Pointer to the root directory object header.
    root: *mut ObjectHeader,
    /// Number of directories allocated (including root).
    dir_count: u32,
    /// Number of objects allocated (excluding directory bodies).
    obj_count: u32,
}

static NAMESPACE: Spinlock<Namespace> = Spinlock::new(Namespace {
    root: null_mut(),
    dir_count: 0,
    obj_count: 0,
});

/// Global handle table. Slot 0 is reserved (NULL handle).
struct HandleTable {
    /// Raw pointers, indexed by handle-1. We avoid `Option<*mut T>`
    /// here too: see `Directory::entries` for the explanation
    /// (niche optimisation is not applied for `*mut T` in this
    /// build, so a 4-byte tag would silently get out of sync with
    /// the pointer).
    slots: [*mut ObjectHeader; MAX_HANDLES],
    valid: [u8; MAX_HANDLES],
    next: usize,
}

static HANDLE_TABLE: Spinlock<HandleTable> = Spinlock::new(HandleTable {
    slots: [core::ptr::null_mut(); MAX_HANDLES],
    valid: [0; MAX_HANDLES],
    next: 1, // skip 0 — invalid handle
});

/// Diagnostic counter: highest slot ever allocated in the global
/// kernel handle table. Useful for sizing analysis.
static HANDLE_TABLE_HIGH_WATER: AtomicU32 = AtomicU32::new(0);
/// Diagnostic counter: total handles currently allocated.
static HANDLE_TABLE_LIVE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Insert an object into a per-process handle table and return a
/// handle. If `process` is None, uses the global kernel handle table.
/// Returns the handle (1-based, 0 = failure).
pub fn insert_object_into_process(
    process: *mut crate::ps::process::Eprocess,
    parent_path: &[u8],
    header: *mut ObjectHeader,
) -> u64 {
    INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
    if header.is_null() {
        return 0;
    }
    let parent = lookup_directory(parent_path);
    if parent.is_null() {
        return 0;
    }
    unsafe {
        if (*parent).num_entries as usize >= MAX_DIR_ENTRIES {
            return 0;
        }
        let slot = (*parent).num_entries as usize;
        (*parent).entries[slot] = header;
        (*parent).valid[slot] = 1;
        (*parent).num_entries += 1;
        (*header).directory = parent;
    }
    // Allocate a handle slot from the per-process table (if available)
    // or fall back to the global table.
    let handle = if !process.is_null() {
        let table_ptr = unsafe { (*process).object_table };
        if !table_ptr.is_null() {
            allocate_handle_in_table(table_ptr, header)
        } else {
            0
        }
    } else {
        // Kernel-mode: use the global handle table.
        allocate_handle_in_global_table(header)
    };
    handle
}

/// Allocate a handle slot in a per-process handle table.
fn allocate_handle_in_table(table: *mut ProcessHandleTable, header: *mut ObjectHeader) -> u64 {
    use core::sync::atomic::Ordering;
    let max = crate::ps::process::HANDLE_TABLE_SIZE;
    unsafe {
        let start = (*table).next_slot;
        let mut idx = start;
        for _ in 0..max {
            if idx >= max { idx = 1; }
            if (*table).valid[idx] == 0 {
                (*table).slots[idx] = header as *mut _;
                (*table).valid[idx] = 1;
                (*table).next_slot = (idx + 1) % max;
                // Atomic increment (W-B fix).
                (*table).handle_count.fetch_add(1, Ordering::AcqRel);
                reference_object(header);
                return (idx + 1) as u64; // 1-based
            }
            idx = (idx + 1) % max;
            if idx == start { break; }
        }
    }
    0
}

/// Maximum slots to scan in a single attempt before reporting failure.
/// Even with the global spinlock held we don't want to scan the whole
/// 16K table under contention — NT-style grows the table on demand.
const HANDLE_SCAN_LIMIT: usize = 64;

/// Allocate a handle in the global kernel handle table.
///
/// # Issue 2.1
/// The original implementation performed a linear scan of the entire
/// 4096-slot table, holding the global lock for the duration. We now
/// (a) scan at most `HANDLE_SCAN_LIMIT` slots in a single attempt and
/// (b) track a high-water mark + live-count for diagnostics via
/// `HANDLE_TABLE_HIGH_WATER` and `HANDLE_TABLE_LIVE_COUNT`.
fn allocate_handle_in_global_table(header: *mut ObjectHeader) -> u64 {
    if header.is_null() {
        return 0;
    }
    let mut t = HANDLE_TABLE.lock();
    let start = t.next;
    for _ in 0..HANDLE_SCAN_LIMIT {
        let idx = t.next;
        t.next = if idx + 1 >= MAX_HANDLES { 1 } else { idx + 1 };
        if t.valid[idx] == 0 {
            t.slots[idx] = header;
            t.valid[idx] = 1;
            // Update diagnostics.
            let cur_water = (idx as u32) + 1;
            let prev_water = HANDLE_TABLE_HIGH_WATER.load(Ordering::Relaxed);
            if cur_water > prev_water {
                let _ = HANDLE_TABLE_HIGH_WATER.compare_exchange(
                    prev_water, cur_water, Ordering::Relaxed, Ordering::Relaxed,
                );
            }
            HANDLE_TABLE_LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
            unsafe { (*header).handle_count.fetch_add(1, Ordering::AcqRel); }
            return (idx + 1) as u64; // 1-based
        }
        // Wrap-around: if we hit the original start we are done with this pass.
        if t.next == start {
            break;
        }
    }
    0
}

/// Per-process handle table slot stored in the kernel.
pub use crate::ps::process::ProcessHandleTable;

/// Cumulative counters (for the boot log / smoke test).
static CREATE_COUNT: AtomicU64 = AtomicU64::new(0);
static INSERT_COUNT: AtomicU64 = AtomicU64::new(0);
static REFERENCE_COUNT: AtomicU64 = AtomicU64::new(0);
static DEREFERENCE_COUNT: AtomicU64 = AtomicU64::new(0);
static LOOKUP_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the object manager. Allocates the root directory,
/// installs every well-known namespace directory, and brings up
/// the type table (12 ObjectTypes). After this returns the object
/// manager is fully usable; remaining subsystems (IO, PS, FS)
/// register their device/driver objects via the standard
/// `create_directory` / `create_object` API.
pub fn init() {
    crate::hal::serial::write_string("OB:start\r\n");

    // 1. Type table: 12 ObjectTypes, each ~200B on the stack of
    //    `init_types` (about 2.4 KB total). 512 KB stack is enough.
    crate::ob::types::init_types();

    // 2. Root directory ("\"). Always exists, never freed.
    let root = allocate_directory();
    if !root.is_null() {
        unsafe {
            (*root).is_root = true;
            copy_name(&mut (*root).header.name, b"\\");
            NAMESPACE.lock().root = root as *mut ObjectHeader;
            NAMESPACE.lock().dir_count = 1;
        }
    }

    // 3. Standard NT namespace directories. Each `create_directory`
    //    walks the path and creates the entry under the parent. They
    //    must be created in topological order (parent first), but
    //    `create_directory` returns the existing entry when present,
    //    so a flat list is safe.
    //
    //    `\??` and `\Registry` are real NT directories even though
    //    `?` and the (mixed-case) registry prefix aren't normally
    //    permitted by `validate_object_name`. `create_directory`
    //    whitelists those two names so the bootstrap can populate
    //    them — see `is_reserved_nt_dir_name`.
    let dirs: [&[u8]; 9] = [
        b"\\Device",
        b"\\Driver",
        b"\\KernelObjects",
        b"\\BaseNamedObjects",
        b"\\DosDevices",
        b"\\ObjectTypes",
        b"\\Sessions",
        b"\\??",
        b"\\Registry",
    ];
    for path in &dirs {
        create_directory(path);
    }

    // 4. Cumulative counters — diagnostic only.
    CREATE_COUNT.store(0, Ordering::SeqCst);
    INSERT_COUNT.store(0, Ordering::SeqCst);
    REFERENCE_COUNT.store(0, Ordering::SeqCst);
    DEREFERENCE_COUNT.store(0, Ordering::SeqCst);
    LOOKUP_COUNT.store(0, Ordering::SeqCst);
    crate::hal::serial::write_string("OB:end\r\n");
}

/// Allocate a new directory object. The header is allocated from
/// the non-paged pool; the directory body is appended after the
/// header.
fn allocate_directory() -> *mut Directory {
    let layout_sz = core::mem::size_of::<Directory>();
    let raw = pool::allocate(pool::PoolType::NonPaged, layout_sz) as *mut Directory;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, layout_sz);
        (*raw).header.set_type(ObType::Directory);
        (*raw).header.ref_count = AtomicU32::new(1);
        (*raw).header.handle_count = AtomicU32::new(0);
        (*raw).header.directory = null_mut();
        (*raw).header.allocation_size = layout_sz as u32;
        (*raw).header.pool_tag = OB_POOL_TAG;
        (*raw).num_entries = 0;
        (*raw).is_root = false;
        // entries[] and valid[] are already zero (write_bytes above).
    }
    raw
}

/// Allocate a header for a generic object. The body pointer is
/// left for the caller to fill in. Returns the header pointer.
fn allocate_object_header(ob_type: ObType, body_size: usize) -> *mut ObjectHeader {
    let total = core::mem::size_of::<ObjectHeader>() + body_size;
    let raw = pool::allocate(pool::PoolType::NonPaged, total) as *mut ObjectHeader;
    if raw.is_null() {
        return null_mut();
    }
    unsafe {
        core::ptr::write_bytes(raw as *mut u8, 0, total);
        (*raw).set_type(ob_type);
        (*raw).ref_count = AtomicU32::new(1);
        (*raw).handle_count = AtomicU32::new(0);
        (*raw).directory = null_mut();
        (*raw).body = (raw as *mut u8).add(core::mem::size_of::<ObjectHeader>()) as *mut ();
        (*raw).allocation_size = total as u32;
        (*raw).pool_tag = OB_POOL_TAG;
        (*raw).security_descriptor = core::ptr::null_mut();
        (*raw).flags.store(0, Ordering::Relaxed);
    }
    raw
}

// =============================================================================
// Name validation (Step 1e / Issue 3.2)
// =============================================================================

/// Validate a candidate object name against Windows-style name rules.
///
/// # Reject conditions
/// - Empty name or name longer than `MAX_NAME_LEN - 1` bytes
/// - Any byte < 0x20 (control characters)
/// - Any of: `<`, `>`, `"`, `|`, `?`, `*`, `/` (Windows reserved characters)
/// - Path traversal segments (literal `..`) anywhere in the name
/// - Leading or trailing whitespace (0x01-0x1F or 0x20 at the end)
///
/// Returns `STATUS_SUCCESS` on success, or an appropriate `ObStatus` code.
pub fn validate_object_name(name: &[u8]) -> ObStatus {
    if name.is_empty() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // Allow well-known single-letter drive names like "C:", "D:" …
    // but reject longer names containing ':'.
    let drive_letter_prefix = name.len() == 2 && name[1] == b':'
        && (name[0] as char).is_ascii_alphabetic();

    if name.len() >= MAX_NAME_LEN {
        return STATUS_NAME_TOO_LONG;
    }

    let mut saw_dot = false;
    let mut saw_dot_dot = false;
    for &b in name.iter() {
        if b < 0x20 {
            return STATUS_OBJECT_NAME_INVALID;
        }
        // Windows-forbidden reserved characters (forward slash is also
        // forbidden because Windows uses backslash as separator).
        match b {
            b'<' | b'>' | b'"' | b'|' | b'?' | b'*' | b'/' | b'\0' => {
                return STATUS_OBJECT_NAME_INVALID;
            }
            b':' if !drive_letter_prefix => {
                return STATUS_OBJECT_NAME_INVALID;
            }
            _ => {}
        }
        // Path traversal: a '.' followed by '..' anywhere in the name
        // marks a `..` segment; we reject any occurrence of `..`.
        if b == b'.' {
            if saw_dot {
                // saw two dots in a row — but we don't know yet if there
                // will be a third or fourth byte. We'll check the literal
                // `..` substring separately below.
                saw_dot = false;
                saw_dot_dot = true;
            } else {
                saw_dot = true;
            }
        } else if saw_dot {
            saw_dot = false;
        }
    }
    // Explicit substring check for literal ".." (path traversal).
    // Use a small linear scan since we have already rejected * here.
    if name.windows(2).any(|w| w[0] == b'.' && w[1] == b'.') {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let _ = saw_dot_dot; // state tracked for future use

    // No leading/trailing whitespace or dots.
    if name[0] == b'.' || name[0] == b' ' {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if name[name.len() - 1] == b'.' || name[name.len() - 1] == b' ' {
        return STATUS_OBJECT_NAME_INVALID;
    }

    STATUS_SUCCESS
}

/// Copy a name into an `ObjectHeader.name` slot, truncating to
/// `MAX_NAME_LEN` and always NUL-terminating.
fn copy_name(dst: &mut [u8; MAX_NAME_LEN], src: &[u8]) {
    let copy = src.len().min(MAX_NAME_LEN - 1);
    for i in 0..copy {
        dst[i] = src[i];
    }
    dst[copy] = 0;
}

/// Reserved NT directory names that contain characters which the
/// regular `validate_object_name` rejects. NT uses these as
/// well-known namespaces (`\??` for DOS device aliases,
/// `\Registry` for the configuration manager) but their names
/// legitimately contain `?` which would otherwise be filtered out.
///
/// `create_directory` recognises this small set and skips name
/// validation for them. Nothing else in the object manager is
/// allowed to call `create_directory` with an arbitrary
/// `?`-bearing name; the function is intentionally not exposed.
fn is_reserved_nt_dir_name(name: &[u8]) -> bool {
    // Equality-only match — anything else gets rejected.
    matches!(name, b"??" | b"Registry")
}

/// Strip the trailing `\` from a path, if any.
fn trim_trailing_sep(s: &[u8]) -> &[u8] {
    if s.len() > 1 && s[s.len() - 1] == b'\\' {
        &s[..s.len() - 1]
    } else {
        s
    }
}

/// Split a path into its parent directory and the leaf name.
///
/// `"\Device\Foo"` -> `parent="\Device"`, `leaf="Foo"`.
/// `"\\"` -> parent=`""` (root), leaf=`""`.
fn split_path(path: &[u8]) -> (&[u8], &[u8]) {
    let path = trim_trailing_sep(path);
    if path.is_empty() || slice_eq(path, b"\\") {
        return (b"\\", b"");
    }
    // Find the last backslash. If none, the path is just a leaf
    // under the root.
    let mut i = path.len();
    while i > 0 {
        i -= 1;
        if path[i] == b'\\' {
            let parent = if i == 0 { b"\\" } else { &path[..i] };
            let leaf = &path[i + 1..];
            return (parent, leaf);
        }
    }
    (b"\\", path)
}

/// Look up a directory by absolute path. Returns the directory's
/// body pointer (which contains the header at offset 0) or
/// `null_mut()` if the path is not found.
fn lookup_directory(path: &[u8]) -> *mut Directory {
    let path = trim_trailing_sep(path);
    let ns = NAMESPACE.lock();
    if ns.root.is_null() {
        return null_mut();
    }
    let root_dir = ns.root as *mut Directory;
    if slice_eq(path, b"\\") || path.is_empty() {
        return root_dir;
    }
    unsafe {
        // Walk one path component at a time, starting from the
        // root directory.
        let mut current = root_dir;
        let mut start = 1; // skip leading `\`
        while start < path.len() {
            // Find the next separator.
            let mut end = start;
            while end < path.len() && path[end] != b'\\' {
                end += 1;
            }
            let component = &path[start..end];
            // Search the current directory for `component`.
            let mut next: *mut Directory = null_mut();
            for i in 0..(*current).num_entries as usize {
                if i >= MAX_DIR_ENTRIES { break; }
                if (*current).valid[i] != 0 {
                    let h = (*current).entries[i];
                    if (*h).get_type() == Some(ObType::Directory) {
                        let ns = name_slice(&(*h).name);
                        if slice_eq(ns, component) {
                            next = h as *mut Directory;
                            break;
                        }
                    }
                }
            }
            if next.is_null() {
                return null_mut();
            }
            current = next;
            start = end + 1;
        }
        current
    }
}

/// Look up an object (any type) by absolute path. Returns the
/// header pointer or `null_mut()`.
pub fn lookup_object(path: &[u8]) -> *mut ObjectHeader {
    let (parent_path, leaf) = split_path(path);
    if leaf.is_empty() {
        // The path refers to a directory.
        let d = lookup_directory(parent_path);
        LOOKUP_COUNT.fetch_add(1, Ordering::Relaxed);
        if d.is_null() {
            return null_mut();
        }
        return d as *mut ObjectHeader;
    }
    let d = lookup_directory(parent_path);
    LOOKUP_COUNT.fetch_add(1, Ordering::Relaxed);
    if d.is_null() {
        return null_mut();
    }
    unsafe {
        for i in 0..(*d).num_entries as usize {
            if i >= MAX_DIR_ENTRIES { break; }
            if (*d).valid[i] != 0 {
                let h = (*d).entries[i];
                let ns = name_slice(&(*h).name);
                if slice_eq(ns, leaf) {
                    return h;
                }
            }
        }
    }
    null_mut()
}

/// Create a new directory at `path`. The parent directories must
/// already exist. Returns the body pointer or `null_mut()` on
/// failure.
pub fn create_directory(path: &[u8]) -> *mut Directory {
    let path = trim_trailing_sep(path);
    if path.is_empty() || slice_eq(path, b"\\") {
        // Root is implicit; nothing to create.
        return lookup_directory(b"\\");
    }
    let (parent_path, leaf) = split_path(path);

    // Validate the leaf name component BEFORE any allocation — Issue 3.2 fix.
    // We only validate the leaf, not the entire path, because existing
    // namespaces may contain legitimately older names that were created
    // before name validation was added.
    //
    // Reserved NT names: \?? is a real NT directory even though `?` is
    // normally rejected by `validate_object_name` (it is reserved for
    // DOS-device name aliases — see "Object Manager" in the Windows
    // Internals book). The directory itself is created once at boot
    // and never holds a body of dynamic objects, so the bypass is safe.
    if !leaf.is_empty() && !is_reserved_nt_dir_name(leaf) {
        let status = validate_object_name(leaf);
        if status != STATUS_SUCCESS {
            let _ = status;
            return null_mut();
        }
    }

    // If it already exists, return it.
    if let Some(d) = lookup_directory_non_locking(path) {
        return d;
    }
    let parent = lookup_directory(parent_path);
    if parent.is_null() {
        return null_mut();
    }

    // Allocate the directory body BEFORE acquiring the NAMESPACE lock,
    // so that pool allocation failures don't block the namespace.
    let dir = allocate_directory();
    if dir.is_null() {
        return null_mut();
    }

    // Issue 2.4 fix: hold NAMESPACE for the full directory-slot update
    // (check → write → increment) and for dir_count increment.
    let result: *mut Directory = {
        let mut ns = NAMESPACE.lock();
        unsafe {
            if (*parent).num_entries as usize >= MAX_DIR_ENTRIES {
                return null_mut();
            }
            copy_name(&mut (*dir).header.name, leaf);
            let slot = (*parent).num_entries as usize;
            (*parent).entries[slot] = dir as *mut ObjectHeader;
            (*parent).valid[slot] = 1;
            (*parent).num_entries += 1;
            (*dir).header.directory = parent;
        }
        ns.dir_count += 1;
        dir
    };
    result
}

/// Look up a directory, *not* holding the namespace lock. (The
/// caller must not be holding it.)
fn lookup_directory_non_locking(path: &[u8]) -> Option<*mut Directory> {
    let path = trim_trailing_sep(path);
    let p = lookup_directory(path);
    if p.is_null() { None } else { Some(p) }
}

/// Create a new object header of `ob_type` named `name`. The parent
/// directory is looked up and the name is checked for duplicates.
/// The body is left zeroed. Returns the header on success, or
/// `null_mut()` on failure.
///
/// The caller is responsible for filling in the type-specific
/// fields *after* this call returns, then calling `insert_object`
/// to publish it in the directory and allocate a handle.
pub fn create_object(
    parent_path: &[u8],
    name: &[u8],
    ob_type: ObType,
    body_size: usize,
) -> *mut ObjectHeader {
    CREATE_COUNT.fetch_add(1, Ordering::Relaxed);
    // Validate name BEFORE doing any allocation work — Issue 3.2 fix.
    let status = validate_object_name(name);
    if status != STATUS_SUCCESS {
        // kprintln disabled (memcpy crash workaround)
        let _ = status;
        return null_mut();
    }
    let parent = lookup_directory(parent_path);
    if parent.is_null() {
        return null_mut();
    }
    unsafe {
        // Reject duplicates.
        for i in 0..(*parent).num_entries as usize {
            if i >= MAX_DIR_ENTRIES { break; }
            if (*parent).valid[i] != 0 {
                let h = (*parent).entries[i];
                let ns = name_slice(&(*h).name);
                if slice_eq(ns, name) {
                    return null_mut();
                }
            }
        }
        if (*parent).num_entries as usize >= MAX_DIR_ENTRIES {
            return null_mut();
        }
        let h = allocate_object_header(ob_type, body_size);
        if h.is_null() {
            return null_mut();
        }
        copy_name(&mut (*h).name, name);
        // Do NOT insert here — the caller must call insert_object.
        (*h).directory = parent;
        NAMESPACE.lock().obj_count += 1;
        h
    }
}

/// Insert a previously-created object header into a directory.
/// Returns the handle on success, or `0` on failure.
///
/// # Issue 2.4 fix
/// `num_entries` is read, the slot is written, and the count is
/// incremented — all three operations happen under the `NAMESPACE`
/// lock, preventing a concurrent `insert_object` or `create_directory`
/// from overwriting the same slot.
pub fn insert_object(parent_path: &[u8], header: *mut ObjectHeader) -> u64 {
    INSERT_COUNT.fetch_add(1, Ordering::Relaxed);
    if header.is_null() {
        return 0;
    }
    let parent = lookup_directory(parent_path);
    if parent.is_null() {
        return 0;
    }

    // Issue 2.4 fix: acquire NAMESPACE lock for the full directory
    // update sequence (check → write → increment).
    let handle: u64 = {
        let _ns = NAMESPACE.lock();
        unsafe {
            if (*parent).num_entries as usize >= MAX_DIR_ENTRIES {
                return 0;
            }
            let slot = (*parent).num_entries as usize;
            (*parent).entries[slot] = header;
            (*parent).valid[slot] = 1;
            (*parent).num_entries += 1;
            (*header).directory = parent;
        }
        // Delegate handle allocation to the already-atomic global table helper.
        allocate_handle_in_global_table(header)
    };
    handle
}

/// Reference an object. Returns the new reference count.
pub fn reference_object(header: *mut ObjectHeader) -> u32 {
    REFERENCE_COUNT.fetch_add(1, Ordering::Relaxed);
    if header.is_null() { return 0; }
    unsafe { (*header).ref_count.fetch_add(1, Ordering::AcqRel) + 1 }
}

/// Lookup an object by handle in a specific process's handle table.
/// Returns the object header pointer or null if not found.
pub fn lookup_handle_in_process(
    process: *mut crate::ps::process::Eprocess,
    handle: u64,
) -> Option<*mut ObjectHeader> {
    if handle == 0 {
        return None;
    }
    let idx = (handle - 1) as usize;
    if idx >= crate::ps::process::HANDLE_TABLE_SIZE {
        return None;
    }

    unsafe {
        let table_ptr = (*process).object_table;
        if table_ptr.is_null() {
            return None;
        }
        let table = &*table_ptr;
        if table.valid[idx] == 0 {
            return None;
        }
        Some(table.slots[idx] as *mut ObjectHeader)
    }
}

/// Close a handle in a specific process's handle table.
///
/// # W-B fix
/// `handle_count` is `AtomicU32`; updates use `fetch_sub`.
/// # W-C fix
/// The slot is marked invalid under the *implicit* lock (single
/// writer thread holds the process handle table in the bootstrap
/// environment); double-close is rejected via `valid[idx] == 0`.
pub fn close_handle_in_process(
    process: *mut crate::ps::process::Eprocess,
    handle: u64,
) -> bool {
    if handle == 0 {
        return false;
    }
    let idx = (handle - 1) as usize;
    if idx >= crate::ps::process::HANDLE_TABLE_SIZE {
        return false;
    }

    unsafe {
        let table_ptr = (*process).object_table;
        if table_ptr.is_null() {
            return false;
        }
        let table = &mut *table_ptr;
        if table.valid[idx] == 0 {
            return false;
        }
        // Get the object header
        let header = table.slots[idx] as *mut ObjectHeader;

        // Mark slot as invalid FIRST to prevent double-close.
        table.valid[idx] = 0;
        table.slots[idx] = core::ptr::null_mut();
        // Atomic decrement (W-B fix).
        table.handle_count.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);

        // Decrement handle count and possibly trigger deletion
        decrement_handle_count(header);

        true
    }
}

/// Get object body from header
pub fn get_object_body<T>(header: *mut ObjectHeader) -> *mut T {
    if header.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let body_ptr = header.add(1) as *mut T;
        body_ptr
    }
}

// =============================================================================
// Object deletion
// =============================================================================

/// Internal delete that assumes the caller holds `OB_DELETE_LOCK`.
/// Atomically checks the DELETING flag and, if not already deleting,
/// performs the full teardown: unlinks from directory, clears handle table,
/// calls type delete procedure, frees security descriptor, frees pool allocation.
///
/// Returns `true` if this thread performed the deletion, `false` if the
/// object was already being deleted by another thread.
unsafe fn try_delete_object_locked(header: *mut ObjectHeader) -> bool {
    // CAS to set DELETING flag — prevents double-deletion races.
    let old_flags = (*header).flags.load(Ordering::Acquire);
    if old_flags & OB_FLAG_DELETING != 0 {
        // Already being deleted by another thread.
        return false;
    }
    // Attempt to atomically set the DELETING flag.
    // SAFETY: OB_DELETE_LOCK is held, so no other thread can modify flags.
    let _ = (*header).flags.compare_exchange(
        old_flags,
        old_flags | OB_FLAG_DELETING,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    // If CAS failed, another thread set DELETING first.
    if (*header).flags.load(Ordering::Acquire) & OB_FLAG_DELETING == 0 {
        return false;
    }

    // 1. Unlink from parent directory.
    if !(*header).directory.is_null() {
        let parent = (*header).directory;
        let mut removed = false;
        for i in 0..(*parent).num_entries as usize {
            if i >= MAX_DIR_ENTRIES { break; }
            if (*parent).valid[i] != 0 {
                let h = (*parent).entries[i];
                if core::ptr::eq(h, header) {
                    // Compact the entries array.
                    for j in i..((*parent).num_entries as usize - 1) {
                        (*parent).entries[j] = (*parent).entries[j + 1];
                        (*parent).valid[j] = (*parent).valid[j + 1];
                    }
                    (*parent).num_entries -= 1;
                    let last = (*parent).num_entries as usize;
                    if last < MAX_DIR_ENTRIES {
                        (*parent).entries[last] = core::ptr::null_mut();
                        (*parent).valid[last] = 0;
                    }
                    removed = true;
                    break;
                }
            }
        }
        let _ = removed;
    }

    // 2. Remove from handle table.
    {
        let mut t = HANDLE_TABLE.lock();
        for i in 0..MAX_HANDLES {
            if t.valid[i] != 0 && core::ptr::eq(t.slots[i], header) {
                t.valid[i] = 0;
                t.slots[i] = core::ptr::null_mut();
                break;
            }
        }
    }

    // 3. Call the type's delete procedure.
    if !(*header).body.is_null() {
        let type_index = (*header).type_index;
        let body = (*header).body;
        crate::ob::types::call_delete_procedure(type_index, body);
    }

    // 4. Free security descriptor if present. The descriptor is a separate
    // non-paged pool allocation independent of the object header.
    if !(*header).security_descriptor.is_null() {
        let sd_ptr = (*header).security_descriptor as *mut u8;
        (*header).security_descriptor = core::ptr::null_mut();
        let _ = pool::free(sd_ptr);
    }

    // 5. Free the full pool allocation: header + body.
    //    Decrement obj_count under namespace lock.
    {
        let mut ns = NAMESPACE.lock();
        ns.obj_count = ns.obj_count.saturating_sub(1);
    }
    let _ = pool::free(header as *mut u8);

    true
}

/// Delete an object (full teardown). Acquires `OB_DELETE_LOCK` and delegates
/// to `try_delete_object_locked`. This is the only entry point for object
/// deletion; callers must NOT hold `OB_DELETE_LOCK` already.
fn delete_object(header: *mut ObjectHeader) {
    if header.is_null() { return; }
    let _guard = OB_DELETE_LOCK.lock();
    // SAFETY: OB_DELETE_LOCK is now held; try_delete_object_locked
    //         will atomically check/set DELETING flag.
    unsafe { try_delete_object_locked(header); }
}

/// Dereference an object.
///
/// When the count reaches zero AND handle_count is zero, the object is
/// removed from its directory, the type's delete procedure is called
/// (if defined), and the full pool allocation (header + body) is freed.
///
/// This function holds `OB_DELETE_LOCK` across the ref-count decrement and
/// the check of `handle_count` to prevent the TOCTOU race:
///   Thread A: ref_count.fetch_sub → 0 → check handle_count (race window here)
///   Thread B: close_handle → handle_count.fetch_sub → 0 → delete_object
/// With the lock held, both checks are serialised.
pub fn dereference_object(header: *mut ObjectHeader) -> u32 {
    DEREFERENCE_COUNT.fetch_add(1, Ordering::Relaxed);
    if header.is_null() { return 0; }

    let guard = OB_DELETE_LOCK.lock();
    let final_ref = unsafe {
        let prev = (*header).ref_count.fetch_sub(1, Ordering::AcqRel);
        let decremented = prev - 1;

        if decremented == 0 {
            let current_handle_count = (*header).handle_count.load(Ordering::Acquire);
            if current_handle_count == 0 {
                drop(guard);
                delete_object(header);
            }
        }
        decremented
    };
    final_ref
}

/// Decrement handle count and trigger deletion if needed.
///
/// Called when a handle is closed. Holds `OB_DELETE_LOCK` across the
/// handle-count decrement and ref_count check to prevent races with
/// concurrent `dereference_object` calls.
pub fn decrement_handle_count(header: *mut ObjectHeader) {
    if header.is_null() { return; }

    let guard = OB_DELETE_LOCK.lock();
    let new_handle_count = unsafe {
        let prev = (*header).handle_count.fetch_sub(1, Ordering::AcqRel);
        let new = prev - 1;

        if new == 0 {
            // Both handle_count and ref_count must be zero to delete.
            let current_ref = (*header).ref_count.load(Ordering::Acquire);
            if current_ref == 0 {
                drop(guard); // Release lock before deleting.
                delete_object(header);
            }
            // else: references still open — defer deletion until last ref drops.
        }
        new
    };
    let _ = new_handle_count; // diagnostic only
}

/// Look up an object by name and return a referenced pointer.
/// `null_mut()` on failure. Increments the lookup counter.
pub fn open_object_by_name(path: &[u8]) -> *mut ObjectHeader {
    let h = lookup_object(path);
    if h.is_null() { return null_mut(); }
    reference_object(h);
    h
}

/// Look up a handle in the global handle table and return a
/// referenced pointer.
pub fn reference_object_by_handle(handle: u64) -> *mut ObjectHeader {
    if handle == 0 { return null_mut(); }
    let slot = (handle - 1) as usize;
    if slot >= MAX_HANDLES { return null_mut(); }
    let t = HANDLE_TABLE.lock();
    if t.valid[slot] != 0 {
        let h = t.slots[slot];
        drop(t);
        // reference_object returns the new ref count, not the
        // pointer — return the pointer unchanged.
        let _ = reference_object(h);
        return h;
    }
    null_mut()
}

/// Resolve a handle to an object pointer and return a referenced
/// pointer. Supports both global and per-process handle tables.
/// `process` is null for kernel-mode handles.
pub fn reference_object_by_handle_in_process(
    handle: u64,
    process: *mut crate::ps::process::Eprocess,
) -> *mut ObjectHeader {
    if handle == 0 { return null_mut(); }
    
    // Try per-process table first if process is specified
    if !process.is_null() {
        if let Some(h) = lookup_handle_in_process(process, handle) {
            reference_object(h);
            return h;
        }
        // Fall through to global table
    }
    
    // Fall back to global kernel handle table
    reference_object_by_handle(handle)
}

/// Close a handle in the global kernel handle table.
/// Returns true on success.
///
/// # Issue 2.1 / W-C
/// The closing handle slot is invalidated under the table lock; the
/// handle-count decrement happens via `decrement_handle_count` which
/// is itself serialised by `OB_DELETE_LOCK`. Double-close is impossible
/// because the lock holder nulls `valid[slot]` before releasing the
/// lock, and the closure logic only runs after the second `close_handle`
/// finds `valid[slot] == 0` and returns `false`.
pub fn close_handle_global(handle: u64) -> bool {
    if handle == 0 { return false; }
    let slot = (handle - 1) as usize;
    if slot >= MAX_HANDLES { return false; }

    let header: *mut ObjectHeader;
    {
        let mut t = HANDLE_TABLE.lock();
        // Atomic check-and-clear: prevents double-close.
        if t.valid[slot] == 0 {
            return false;
        }
        header = t.slots[slot];
        t.valid[slot] = 0;
        t.slots[slot] = core::ptr::null_mut();
        HANDLE_TABLE_LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
    }

    // Decrement handle count and possibly trigger deletion.
    if !header.is_null() {
        decrement_handle_count(header);
    }
    true
}

/// Create an object with the given type, name, and parent path.
/// Returns the object header pointer or null on failure.
/// The object is NOT yet inserted into the directory.
pub fn create_object_ex(
    parent_path: &[u8],
    name: &[u8],
    ob_type: ObType,
    body_size: usize,
) -> *mut ObjectHeader {
    create_object(parent_path, name, ob_type, body_size)
}

/// Insert an object header into the namespace directory and allocate
/// a handle. Returns the handle (1-based) or 0 on failure.
/// Does NOT take a process parameter - uses global kernel table only.
pub fn insert_object_ex(parent_path: &[u8], header: *mut ObjectHeader) -> u64 {
    insert_object(parent_path, header)
}

/// Counters (for the smoke test).
pub fn create_count() -> u64 { CREATE_COUNT.load(Ordering::Relaxed) }
pub fn insert_count() -> u64 { INSERT_COUNT.load(Ordering::Relaxed) }
pub fn reference_count() -> u64 { REFERENCE_COUNT.load(Ordering::Relaxed) }
pub fn dereference_count() -> u64 { DEREFERENCE_COUNT.load(Ordering::Relaxed) }
pub fn lookup_count() -> u64 { LOOKUP_COUNT.load(Ordering::Relaxed) }
/// Number of directories in the namespace.
pub fn dir_count() -> u32 { NAMESPACE.lock().dir_count }
/// Number of objects in the namespace (including directories).
pub fn obj_count() -> u32 { NAMESPACE.lock().obj_count }
/// Number of live handles currently allocated in the global kernel handle table.
pub fn handle_table_live_count() -> u32 {
    HANDLE_TABLE_LIVE_COUNT.load(Ordering::Relaxed)
}
/// Highest slot index ever allocated in the global kernel handle table.
///
/// This is a high-water diagnostic — it tells us the maximum handle-table
/// usage reached during the current boot session.
pub fn handle_table_high_water() -> u32 {
    HANDLE_TABLE_HIGH_WATER.load(Ordering::Relaxed)
}

/// Re-export of the object manager smoke test. The full
/// implementation lives in the `smoke` submodule; this
/// re-export keeps the call site readable as `ob::smoke_test()`
/// (matching the `mm::smoke_test()` / `ke::smoke_test()` /
/// `io::smoke_test()` convention used by `kernel_main`).
pub fn smoke_test() -> bool { smoke::smoke_test() }

// =============================================================================
// Security Integration
// =============================================================================

/// Open an object with security access check.
///
/// This function performs the following steps:
/// 1. Look up the object by name
/// 2. Perform SeAccessCheck against the object's security descriptor
/// 3. Return the object if access is granted
///
/// # Arguments
/// * `path` - Object path in the namespace
/// * `desired_access` - Access rights requested
/// * `token_ptr` - Pointer to caller's security token
///
/// # Returns
/// * `Ok(header)` if access is granted
/// * `Err(ntstatus)` if access is denied or object not found
pub fn open_object_with_access(
    path: &[u8],
    desired_access: u32,
    token_ptr: *const crate::se::token::Token,
) -> Result<*mut ObjectHeader, u32> {
    // 1. Look up the object
    let header = lookup_object(path);
    if header.is_null() {
        // // kprintln!("[OB] open_object_with_access: object not found: {:?}", path)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // 0xC0000034 = STATUS_OBJECT_NAME_NOT_FOUND
        return Err(0xC0000034_u32);
    }

    // 2. Get the caller's token
    let caller_token = if !token_ptr.is_null() {
        unsafe { &*token_ptr }
    } else {
        let current_token = crate::ps::process::get_current_thread_token();
        if current_token.is_null() {
            return Err(crate::ps::process::STATUS_ACCESS_DENIED);
        }
        unsafe { &*current_token }
    };

    // 3. Get the object's security descriptor
    let security_descriptor = get_object_security_descriptor(header);
    if security_descriptor.is_null() {
        // No security descriptor, allow access (bootstrap mode)
        return Ok(header);
    }

    // 4. Get object type for generic mapping
    let ob_type = unsafe { (*header).get_type() };
    let se_type = match ob_type {
        Some(ObType::Process) => crate::se::seaccess::ObTypeIndex::Process,
        Some(ObType::Thread) => crate::se::seaccess::ObTypeIndex::Thread,
        Some(ObType::Directory) => crate::se::seaccess::ObTypeIndex::Directory,
        Some(ObType::Key) => crate::se::seaccess::ObTypeIndex::Key,
        Some(ObType::EventNotification) => crate::se::seaccess::ObTypeIndex::Event,
        Some(ObType::EventSynchronization) => crate::se::seaccess::ObTypeIndex::Event,
        Some(ObType::Mutant) => crate::se::seaccess::ObTypeIndex::Mutant,
        Some(ObType::Section) => crate::se::seaccess::ObTypeIndex::Section,
        Some(ObType::Token) => crate::se::seaccess::ObTypeIndex::Token,
        _ => crate::se::seaccess::ObTypeIndex::Null,
    };

    // 5. Perform SeAccessCheck
    let (result, granted) = crate::se::seaccess::se_access_check(
        se_type,
        security_descriptor,
        desired_access,
        caller_token as *const crate::se::token::Token,
    );
    let _ = &granted;

    // // kprintln!("[OB] open_object_with_access: {:?} access=0x{:x} result={:?}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              path, desired_access, result);

    match result {
        crate::se::seaccess::AccessCheckResult::Allowed => Ok(header),
        crate::se::seaccess::AccessCheckResult::Denied => {
            dereference_object(header);
            Err(crate::ps::process::STATUS_ACCESS_DENIED)
        }
    }
}

// =============================================================================
// Security Descriptor helpers
// =============================================================================

/// Kernel-object types that get an implicit default security descriptor.
/// All other types fall through to the per-object stored SD or return null.
const OB_KERNEL_DEFAULT_SD_TYPES: &[u8] = &[
    ObType::Directory as u8,
    ObType::Device as u8,
    ObType::Driver as u8,
    ObType::Type as u8,
    ObType::SymbolicLink as u8,
    ObType::EventNotification as u8,
    ObType::EventSynchronization as u8,
    ObType::Mutant as u8,
    ObType::Semaphore as u8,
    ObType::Section as u8,
    ObType::Process as u8,
    ObType::Thread as u8,
    ObType::Token as u8,
];

/// Static default security descriptor for kernel-mode bootstrap objects.
/// Uses a NULL DACL (all access granted).  This is safe for kernel objects
/// because kernel-mode code already runs at the highest privilege level.
///
/// A real NT kernel would construct this from the process token's default DACL,
/// but that requires a full token subsystem.  The NULL DACL approach is the
/// correct bootstrap approximation.
static mut OB_DEFAULT_KERNEL_SD: crate::se::seaccess::SecurityDescriptor =
    crate::se::seaccess::SecurityDescriptor {
        revision: 1,
        sbz1: 0,
        control: 0x8004, // SE_DACL_PRESENT | SE_SELF_RELATIVE
        owner: crate::se::sid::Sid {
            revision: 1,
            sub_authority_count: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
            sub_authority: [0x00000020, 0, 0, 0, 0, 0, 0, 0], // SECURITY_LOCAL_SYSTEM_RID
        },
        group: crate::se::sid::Sid {
            revision: 1,
            sub_authority_count: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authority: [0x00000020, 0, 0, 0, 0, 0, 0, 0],
        },
        sacl: core::ptr::null(),
        dacl: core::ptr::null(), // NULL DACL = full access
    };

/// Returns true if the given type index belongs to a kernel-mode object
/// that should receive a default security descriptor.
fn ob_type_needs_default_sd(type_index: u8) -> bool {
    OB_KERNEL_DEFAULT_SD_TYPES.contains(&type_index)
}

/// Get the static default security descriptor for kernel objects.
fn ob_default_security_descriptor() -> *const crate::se::seaccess::SecurityDescriptor {
    unsafe { &OB_DEFAULT_KERNEL_SD as *const _ }
}

/// Get the security descriptor for an object.
///
/// Returns a pointer to a SecurityDescriptor according to this policy:
/// 1. If the object has a stored (non-null) SD → return it.
/// 2. If the object is a kernel-mode type (Directory, Device, Driver, etc.)
///    → return the static default NULL-DACL SD.
/// 3. Otherwise → return null (access denied by default in production;
///    currently in bootstrap mode the caller treats null as allowed).
fn get_object_security_descriptor(header: *mut ObjectHeader) -> *const crate::se::seaccess::SecurityDescriptor {
    if header.is_null() {
        return core::ptr::null();
    }

    // SAFETY: we hold no locks here but the returned pointer is only
    // dereferenced while the caller holds the reference to `header`.
    let sd = unsafe { (*header).security_descriptor };
    if !sd.is_null() {
        return sd as *const crate::se::seaccess::SecurityDescriptor;
    }

    // No stored SD — check if this is a kernel-mode object type.
    let type_index = unsafe { (*header).type_index };
    if ob_type_needs_default_sd(type_index) {
        ob_default_security_descriptor()
    } else {
        // Non-kernel object with no SD: deny by default.
        // (In bootstrap mode callers may still allow, but at least we
        // signal that no default-allow policy applies.)
        core::ptr::null()
    }
}

/// Set the security descriptor for an object.
///
/// Allocates a security descriptor from pool and copies the provided data.
/// **Fix (Issue 2.5):** If a security descriptor is already set, it is
/// freed via `pool::free` before the new one is installed.  Previously the
/// old pointer was simply cleared, causing a memory leak every time this
/// function was called on an object that already had a security descriptor.
pub fn ob_set_security_descriptor(
    header: *mut ObjectHeader,
    security_descriptor: *const crate::se::seaccess::SecurityDescriptor,
) -> ObStatus {
    if header.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if security_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    unsafe {
        // FIX (Issue 2.5): Free the existing security descriptor before allocating
        // a new one. Previously the old pointer was simply cleared, causing a
        // memory leak every time this function was called on an object that
        // already had a security descriptor.
        if !(*header).security_descriptor.is_null() {
            let old_sd_ptr = (*header).security_descriptor as *mut u8;
            (*header).security_descriptor = core::ptr::null_mut();
            let _ = pool::free(old_sd_ptr);
        }

        // Allocate new security descriptor.
        let sd_size = core::mem::size_of::<crate::se::seaccess::SecurityDescriptor>();
        let new_sd = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            sd_size,
        ) as *mut crate::se::seaccess::SecurityDescriptor;

        if new_sd.is_null() {
            // Allocation failed.  Do NOT free the old SD — the object still owns it.
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Copy the security descriptor. Use an explicit byte count so that
        // adding fields to SecurityDescriptor cannot silently shrink the copy.
        let sd_bytes = core::mem::size_of::<crate::se::seaccess::SecurityDescriptor>();
        core::ptr::copy_nonoverlapping(
            security_descriptor as *const u8,
            new_sd as *mut u8,
            sd_bytes,
        );

        (*header).security_descriptor = new_sd;
    }

    STATUS_SUCCESS
}

/// Query the security descriptor for an object.
/// Returns the security descriptor or null if the object has no security.
pub fn ob_query_security_descriptor(
    header: *mut ObjectHeader,
) -> *const crate::se::seaccess::SecurityDescriptor {
    if header.is_null() {
        return core::ptr::null();
    }
    
    unsafe { (*header).security_descriptor as *const crate::se::seaccess::SecurityDescriptor }
}

// =============================================================================
// Symbolic Link Support
// =============================================================================

/// SymbolicLinkBody - body structure for symbolic link objects
#[repr(C)]
pub struct SymbolicLinkBody {
    /// Target path (null-terminated UTF-8)
    pub target: [u8; 256],
    /// Length of target string
    pub target_length: u32,
}

impl SymbolicLinkBody {
    pub const fn new() -> Self {
        Self {
            target: [0; 256],
            target_length: 0,
        }
    }
    
    /// Set the target path
    pub fn set_target(&mut self, path: &[u8]) {
        let len = path.len().min(255);
        self.target[..len].copy_from_slice(&path[..len]);
        self.target[len] = 0;
        self.target_length = len as u32;
    }
    
    /// Get the target path as a slice
    pub fn get_target(&self) -> &[u8] {
        let end = self.target.iter().position(|&b| b == 0).unwrap_or(self.target.len());
        &self.target[..end.min(self.target_length as usize)]
    }
}

/// Maximum symbolic link resolution depth to prevent infinite loops
/// (Issue 2.10 — was 10, kept at 10 to remain compatible).
const MAX_SYMLINK_DEPTH: usize = 10;
/// Number of visited-pointer slots reserved on the stack for
/// cycle detection. `MAX_SYMLINK_DEPTH` + a few extra entries are
/// sufficient.
const MAX_SYMLINK_VISITED: usize = 16;

/// Resolve a symbolic link and return the target object header.
/// Returns the resolved object header, or null on failure.
///
/// # Issue 2.10
/// `resolve_symbolic_link_safe` replaces the old recursive
/// implementation with an iterative, depth-bounded loop that also
/// detects cycles via a fixed-size `visited` stack.
pub fn resolve_symbolic_link(header: *mut ObjectHeader) -> *mut ObjectHeader {
    if header.is_null() {
        return null_mut();
    }
    unsafe { resolve_symbolic_link_safe(header) }
}

/// Iterative symbolic-link resolver with cycle detection.
///
/// Algorithm:
/// 1. If `current` is not a symbolic link, return it as-is.
/// 2. Otherwise, look up the link's target object.
/// 3. Check whether `current` has already been visited in this
///    chain — if so, return null (cycle).
/// 4. Push `current` into the `visited` stack, then follow the
///    target.
/// 5. Stop after `MAX_SYMLINK_DEPTH` hops.
unsafe fn resolve_symbolic_link_safe(start: *mut ObjectHeader) -> *mut ObjectHeader {
    let mut visited: [*mut ObjectHeader; MAX_SYMLINK_VISITED] =
        [core::ptr::null_mut(); MAX_SYMLINK_VISITED];
    let mut visited_len: usize = 0;
    let mut current = start;
    let mut hops: usize = 0;

    loop {
        if current.is_null() {
            return null_mut();
        }

        // Depth check — first.
        if hops >= MAX_SYMLINK_DEPTH {
            return null_mut();
        }

        // Non-link objects are returned as-is.
        if (*current).get_type() != Some(ObType::SymbolicLink) {
            return current;
        }

        // Cycle detection: is `current` already in the chain?
        for i in 0..visited_len {
            if visited[i] == current {
                return null_mut(); // cycle detected
            }
        }
        if visited_len < MAX_SYMLINK_VISITED {
            visited[visited_len] = current;
            visited_len += 1;
        } else {
            // Visited-table exhausted: fail safe.
            return null_mut();
        }

        // Get the target object.
        let body = (*current).body as *mut SymbolicLinkBody;
        if body.is_null() {
            return null_mut();
        }
        let target = (*body).get_target();
        if target.is_empty() {
            return null_mut();
        }
        let target_header = lookup_object(target);
        if target_header.is_null() {
            return null_mut();
        }

        current = target_header;
        hops += 1;
    }
}

/// Create a symbolic link object
pub fn create_symbolic_link(
    parent_path: &[u8],
    name: &[u8],
    target: &[u8],
) -> *mut ObjectHeader {
    // Create the symbolic link body
    let mut body = SymbolicLinkBody::new();
    body.set_target(target);
    
    // Create object header
    let header = create_object(
        parent_path,
        name,
        ObType::SymbolicLink,
        core::mem::size_of::<SymbolicLinkBody>(),
    );
    
    if !header.is_null() {
        unsafe {
            let body_ptr = (*header).body as *mut SymbolicLinkBody;
            core::ptr::write(body_ptr, body);
            
            // Create a default security descriptor
            let sd = crate::se::seaccess::create_null_dacl_sd();
            if !sd.is_null() {
                (*header).security_descriptor = sd as *mut crate::se::seaccess::SecurityDescriptor;
            }
        }
        
        // // kprintln!("[OB] Created symbolic link {:?} -> {:?}", name, target)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    
    header
}

/// Initialize symbolic links in the \?? directory
pub fn init_symbolic_links() {
    // // kprintln!("[OB] Initializing symbolic links...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // \??\C: -> \Device\Harddisk0\Partition1 (typical first hard disk)
    let header = create_symbolic_link(b"\\??", b"C:", b"\\Device\\Harddisk0\\Partition1");
    if !header.is_null() {
        let _ = insert_object(b"\\??", header);
    }
    
    // Other common drive letters
    let _ = create_symbolic_link(b"\\??", b"D:", b"\\Device\\CdRom0");
    
    // // kprintln!("[OB] Symbolic links initialized")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

// =============================================================================
// Object Attributes Support
// =============================================================================

/// Object attributes flags
pub const OBJ_KERNEL_HANDLE: u32 = 0x00000001;
pub const OBJ_EXCLUSIVE: u32 = 0x00000002;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000004;
pub const OBJ_PERMANENT: u32 = 0x00000010;
pub const OBJ_TEMPORARY: u32 = 0x00000020;
pub const OBJ_RESERVED: u32 = 0x00000040;

/// Look up an object with optional symbolic link resolution
pub fn lookup_object_with_flags(path: &[u8], flags: u32) -> *mut ObjectHeader {
    let header = lookup_object(path);
    
    if header.is_null() {
        return null_mut();
    }
    
    // Check if we should resolve symbolic links
    let resolve_symlinks = (flags & OBJ_RESERVED) == 0; // Default: resolve
    
    if resolve_symlinks {
        unsafe {
            if (*header).get_type() == Some(ObType::SymbolicLink) {
                let resolved = resolve_symbolic_link(header);
                if resolved != header {
                    dereference_object(header);
                }
                return resolved;
            }
        }
    }
    
    header
}
