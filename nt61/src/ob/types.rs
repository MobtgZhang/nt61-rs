//! Object Type Definitions
//
//! This module defines OBJECT_TYPE and OBJECT_TYPE_INITIALIZER structures
//! following the Windows NT design. Each object type (Directory, Device,
//! Driver, Event, etc.) has an OBJECT_TYPE_INITIALIZER that defines:
//
//! - Type name and attributes
//! - Generic mapping for access rights
//! - Valid access mask
//! - Delete, Security, Parse, Open, QueryName, and OkayToClose procedures
//
//! References:
//! - Windows Research Kernel (WRK)
//! - Geoff Chappell - nt!OBJECT_TYPE layout
//! - ReactOS obtype.c

use crate::mm::pool;
use crate::se::seaccess::GenericMapping;

// Maximum number of object types.  Bumped to 38 to match the ObType
// enum upper bound and match the Windows 7 NT type table size.
// Issue 2.3: the original value of 32 left 6 type slots (32-37) un-
// accounted for and uninitialised.
pub const MAX_OBJECT_TYPES: usize = 38;

// =============================================================================
// Object Type Initializer
// =============================================================================

/// Object type initializer flags
pub const OB_TYPE_INITIALIZER_FLAG1: u8 = 0x01;
pub const OB_TYPE_INITIALIZER_FLAG2: u8 = 0x02;

/// Invalid attributes for object types
pub const OB_INVALID_ATTRIBUTES: u32 = 0x00000001;

/// OBJECT_TYPE_INITIALIZER - defines the characteristics of an object type.
/// Size: 0x70 bytes on Windows 7 x64
#[repr(C)]
pub struct ObjectTypeInitializer {
    pub length: u16,
    pub object_type_flag: u8,
    pub invalid_attributes: u8,
    pub generic_mapping: GenericMapping,
    pub valid_access_mask: u32,
    pub retain_access: u32,
    pub pool_tag: u32,
    pub default_object: *mut (),
    pub parse_procedure: Option<ObParseProcedure>,
    pub open_procedure: Option<ObOpenProcedure>,
    pub delete_procedure: Option<ObDeleteProcedure>,
    pub security_procedure: Option<ObSecurityProcedure>,
    pub query_name_procedure: Option<ObQueryNameProcedure>,
    pub okay_to_close_procedure: Option<ObOkayToCloseProcedure>,
}

impl ObjectTypeInitializer {
    pub const fn new() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u16,
            object_type_flag: 0,
            invalid_attributes: OB_INVALID_ATTRIBUTES as u8,
            generic_mapping: GenericMapping::new(0, 0, 0, 0),
            valid_access_mask: 0,
            retain_access: 0,
            pool_tag: 0,
            default_object: core::ptr::null_mut(),
            parse_procedure: None,
            open_procedure: None,
            delete_procedure: None,
            security_procedure: None,
            query_name_procedure: None,
            okay_to_close_procedure: None,
        }
    }

    /// Set generic mapping
    pub fn with_generic_mapping(mut self, gm: GenericMapping) -> Self {
        self.generic_mapping = gm;
        self
    }

    /// Set valid access mask
    pub fn with_valid_access(mut self, mask: u32) -> Self {
        self.valid_access_mask = mask;
        self
    }

    /// Set delete procedure
    pub fn with_delete_procedure(mut self, proc: ObDeleteProcedure) -> Self {
        self.delete_procedure = Some(proc);
        self
    }

    /// Set security procedure
    pub fn with_security_procedure(mut self, proc: ObSecurityProcedure) -> Self {
        self.security_procedure = Some(proc);
        self
    }
}

// =============================================================================
// Callback Procedure Types
// =============================================================================

/// Parse procedure callback type
/// Called when parsing a path to an object
pub type ObParseProcedure = unsafe extern "C" fn(
    object: *mut (),
    access_mode: u8,
    attributes: u32,
    object_type: *mut (),
    path: *const u16,
    path_length: u32,
    context: *mut (),
    object_ptr: *mut *mut (),
) -> u32;

/// Open procedure callback type
/// Called when opening an object
pub type ObOpenProcedure = unsafe extern "C" fn(
    object: *mut (),
    access_mode: u8,
    attributes: u32,
    object_type: *mut (),
) -> u32;

/// Delete procedure callback type
/// Called when deleting an object of this type
pub type ObDeleteProcedure = unsafe extern "C" fn(object: *mut ());

/// Security procedure callback type
/// Called for security operations (query/set)
pub type ObSecurityProcedure = unsafe extern "C" fn(
    object: *mut (),
    operation: u32,
    buffer: *mut (),
    buffer_length: u32,
    extra_info: *mut (),
) -> u32;

/// Query name procedure callback type
/// Called when querying the name of an object
pub type ObQueryNameProcedure = unsafe extern "C" fn(
    object: *mut (),
    buffer: *mut (),
    buffer_length: u32,
    return_length: *mut u32,
) -> u32;

/// Okay to close procedure callback type
/// Called when checking if an object can be closed
pub type ObOkayToCloseProcedure = unsafe extern "C" fn(
    process: *mut (),
    object: *mut (),
    handle: *mut (),
) -> u32;

// =============================================================================
// Object Type
// =============================================================================

/// OBJECT_TYPE - represents an object type in the NT object manager.
/// Size: 0xB0 bytes on Windows 7 x64
#[repr(C)]
pub struct ObjectType {
    pub type_index: u8,
    _padding: [u8; 7],
    pub name: [u16; 32],          // Unicode type name (64 bytes)
    pub default_security: *mut (),
    pub pool_tag: u32,
    pub valid_access_mask: u32,
    pub pending_export_table: u64,
    pub absolute_pointer: u64,
    pub total_objects: AtomicU32,
    pub total_handles: AtomicU32,
    pub high_water_handle_count: u32,
    pub total_number_of_access_stats: u32,
    pub total_number_of_permanent_handle_stats: u32,
    pub obj_initializer: ObjectTypeInitializer,
    pub object_create_fn: Option<unsafe extern "C" fn(*mut (), *mut ()) -> u32>,
    pub quota_block_charged: u64,
    pub default_non_paged_pool_charge: u64,
    pub default_paged_pool_charge: u64,
}

use core::sync::atomic::{AtomicU32, Ordering};

impl ObjectType {
    pub const fn new() -> Self {
        Self {
            type_index: 0,
            _padding: [0; 7],
            name: [0; 32],
            default_security: core::ptr::null_mut(),
            pool_tag: 0,
            valid_access_mask: 0,
            pending_export_table: 0,
            absolute_pointer: 0,
            total_objects: AtomicU32::new(0),
            total_handles: AtomicU32::new(0),
            high_water_handle_count: 0,
            total_number_of_access_stats: 0,
            total_number_of_permanent_handle_stats: 0,
            obj_initializer: ObjectTypeInitializer::new(),
            object_create_fn: None,
            quota_block_charged: 0,
            default_non_paged_pool_charge: 0,
            default_paged_pool_charge: 0,
        }
    }

    /// Set the type name (ASCII only)
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(31);
        for i in 0..len {
            self.name[i] = bytes[i] as u16;
        }
        if len < 31 {
            self.name[len] = 0; // Null terminate
        }
    }

    /// Increment total object count
    pub fn increment_object_count(&self) {
        self.total_objects.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement total object count
    pub fn decrement_object_count(&self) {
        self.total_objects.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment total handle count
    pub fn increment_handle_count(&self) {
        self.total_handles.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement total handle count
    pub fn decrement_handle_count(&self) {
        self.total_handles.fetch_sub(1, Ordering::Relaxed);
    }
}

// =============================================================================
// Default Generic Mappings for Object Types
// =============================================================================

/// Directory object generic mapping
pub const DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001 | 0x0002,  // DIRECTORY_QUERY | DIRECTORY_TRAVERSE
    0x0001 | 0x0004,  // DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_ADD_FILE
    0x0001 | 0x0002,  // DIRECTORY_QUERY | DIRECTORY_TRAVERSE
    0x000F,          // DIRECTORY_ALL_ACCESS
);

/// Device object generic mapping
pub const DEVICE_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // DEVICE_READ
    0x0002,           // DEVICE_WRITE
    0x0004,           // DEVICE_EXECUTE
    0x000F,           // DEVICE_ALL_ACCESS
);

/// Driver object generic mapping
pub const DRIVER_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // DRIVER_QUERY
    0x0002,           // DRIVER_SET
    0x0004,           // DRIVER_EXECUTE
    0x000F,           // DRIVER_ALL_ACCESS
);

/// Event object generic mapping
pub const EVENT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // EVENT_QUERY_STATE
    0x0002,           // EVENT_MODIFY_STATE
    0x0001,           // EVENT_QUERY_STATE
    0x001F,           // EVENT_ALL_ACCESS
);

/// Mutant (mutex) object generic mapping
pub const MUTANT_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // MUTANT_QUERY_STATE
    0x0001,           // MUTANT_QUERY_STATE
    0x0001,           // MUTANT_QUERY_STATE
    0x001F,           // MUTANT_ALL_ACCESS
);

/// Semaphore object generic mapping
pub const SEMAPHORE_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // SEMAPHORE_QUERY_STATE
    0x0002 | 0x0004, // SEMAPHORE_MODIFY_STATE | SEMAPHORE_QUERY_STATE
    0x0001,           // SEMAPHORE_QUERY_STATE
    0x001F,           // SEMAPHORE_ALL_ACCESS
);

/// SymbolicLink object generic mapping
pub const SYMBOLIC_LINK_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0001,           // SYMBOLIC_LINK_QUERY
    0x0001,           // SYMBOLIC_LINK_QUERY (write via delete/recreate)
    0x0001,           // SYMBOLIC_LINK_QUERY
    0x0001,           // SYMBOLIC_LINK_ALL_ACCESS
);

/// Process object generic mapping
pub const PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0410,           // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    0x043F,           // PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | etc.
    0x0410,           // PROCESS_QUERY_LIMITED_INFORMATION
    0x1F0FFF,        // PROCESS_ALL_ACCESS
);

/// Thread object generic mapping
pub const THREAD_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0410,           // THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT
    0x043F,           // THREAD_SET_INFORMATION | THREAD_SET_CONTEXT | etc.
    0x0410,           // THREAD_QUERY_LIMITED_INFORMATION
    0x1F03FF,        // THREAD_ALL_ACCESS
);

/// Token object generic mapping
pub const TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0008,           // TOKEN_QUERY
    0x00E0,           // TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | etc.
    0x0008,           // TOKEN_QUERY
    0x00F07FF,        // TOKEN_ALL_ACCESS
);

/// Section object generic mapping
pub const SECTION_GENERIC_MAPPING: GenericMapping = GenericMapping::new(
    0x0005,           // SECTION_MAP_READ | SECTION_QUERY
    0x0006,           // SECTION_MAP_WRITE | SECTION_MAP_EXECUTE
    0x0004,           // SECTION_MAP_EXECUTE
    0x000F,           // SECTION_ALL_ACCESS
);

// =============================================================================
// Object Type Initializers Table
// =============================================================================

/// Type index to name mapping — all 38 slots covered.
/// The "Reserved" slots (12-13, 15-27) are real Windows type indices
/// that exist in the NT type table but are unused in this kernel.
pub fn get_type_name(type_index: u8) -> &'static str {
    match type_index {
        0  => "Type",
        1  => "Process",
        2  => "Thread",
        3  => "Directory",
        4  => "SymbolicLink",
        5  => "Token",
        6  => "Job",
        7  => "EventNotification",
        8  => "EventSynchronization",
        9  => "Section",
        10 => "Mutant",
        11 => "Semaphore",
        12 => "Reserved12",
        13 => "Reserved13",
        14 => "Key",
        15 => "Reserved15",
        16 => "Reserved16",
        17 => "Reserved17",
        18 => "Reserved18",
        19 => "Reserved19",
        20 => "Reserved20",
        21 => "Reserved21",
        22 => "Reserved22",
        23 => "Reserved23",
        24 => "Reserved24",
        25 => "Reserved25",
        26 => "Reserved26",
        27 => "Reserved27",
        28 => "Adapter",
        29 => "Controller",
        30 => "Device",
        31 => "Driver",
        32 => "IoCompletion",
        33 => "Timer",
        34 => "Profile",
        35 => "WmiGuid",
        36 => "PowerRequest",
        37 => "W32Object",
        _  => "Unknown",
    }
}

// =============================================================================
// Object Type Registry
// =============================================================================

/// Global registry of object types
static mut OB_TYPE_TABLE: [*mut ObjectType; MAX_OBJECT_TYPES] = 
    [core::ptr::null_mut(); MAX_OBJECT_TYPES];

/// Pool tag for object types
const OB_TYPE_POOL_TAG: u32 = (b'O' as u32) << 24
    | (b'b' as u32) << 16
    | (b'T' as u32) << 8
    | (b'y' as u32);

/// Initialize the object type system
pub fn init_types() {
    crate::hal::serial::write_string("OB_TYPES:start\r\n");

    // Create type objects for each object type
    unsafe {
        crate::hal::serial::write_string("OB_TYPES:dir_start\r\n");
        OB_TYPE_TABLE[3] = create_object_type(
            3, // TypeIndex
            "Directory",
            DIRECTORY_GENERIC_MAPPING,
            0x000F, // DIRECTORY_ALL_ACCESS
            Some(directory_delete_procedure),
        );
        crate::hal::serial::write_string("OB_TYPES:dir_done\r\n");

        // Device type
        OB_TYPE_TABLE[30] = create_object_type(
            30,
            "Device",
            DEVICE_GENERIC_MAPPING,
            0x000F, // DEVICE_ALL_ACCESS
            Some(device_delete_procedure),
        );

        // Driver type
        OB_TYPE_TABLE[31] = create_object_type(
            31,
            "Driver",
            DRIVER_GENERIC_MAPPING,
            0x000F, // DRIVER_ALL_ACCESS
            Some(driver_delete_procedure),
        );

        // Event type
        OB_TYPE_TABLE[7] = create_object_type(
            7,
            "Event",
            EVENT_GENERIC_MAPPING,
            0x001F, // EVENT_ALL_ACCESS
            None,
        );

        // Mutant type
        OB_TYPE_TABLE[10] = create_object_type(
            10,
            "Mutant",
            MUTANT_GENERIC_MAPPING,
            0x001F, // MUTANT_ALL_ACCESS
            None,
        );

        // Semaphore type
        OB_TYPE_TABLE[11] = create_object_type(
            11,
            "Semaphore",
            SEMAPHORE_GENERIC_MAPPING,
            0x001F, // SEMAPHORE_ALL_ACCESS
            None,
        );

        // SymbolicLink type
        OB_TYPE_TABLE[4] = create_object_type(
            4,
            "SymbolicLink",
            SYMBOLIC_LINK_GENERIC_MAPPING,
            0x0001, // SYMBOLIC_LINK_QUERY
            Some(symlink_delete_procedure),
        );

        // Token type
        OB_TYPE_TABLE[5] = create_object_type(
            5,
            "Token",
            TOKEN_GENERIC_MAPPING,
            0x00F07FF, // TOKEN_ALL_ACCESS
            Some(token_delete_procedure),
        );

        // Process type
        OB_TYPE_TABLE[1] = create_object_type(
            1,
            "Process",
            PROCESS_GENERIC_MAPPING,
            0x1F0FFF, // PROCESS_ALL_ACCESS
            None,
        );

        // Thread type
        OB_TYPE_TABLE[2] = create_object_type(
            2,
            "Thread",
            THREAD_GENERIC_MAPPING,
            0x1F03FF, // THREAD_ALL_ACCESS
            None,
        );

        // Section type
        OB_TYPE_TABLE[9] = create_object_type(
            9,
            "Section",
            SECTION_GENERIC_MAPPING,
            0x000F, // SECTION_ALL_ACCESS
            None,
        );

        // Issue 2.3: backfill all remaining type slots that are still null.
        // This ensures every slot in OB_TYPE_TABLE[0..MAX_OBJECT_TYPES)
        // is either a valid pointer or null — never uninitialised.
        for i in 0..MAX_OBJECT_TYPES {
            if OB_TYPE_TABLE[i].is_null() {
                let name = get_type_name(i as u8);
                OB_TYPE_TABLE[i] = create_object_type(
                    i as u8,
                    name,
                    GenericMapping::default(),
                    0,
                    None,
                );
                // If backfill creation itself fails, the serial output above
                // will have printed FATAL; keep trying the rest of the table.
            }
        }

        // Final sanity check: report any slots still null after backfill.
        let mut null_count = 0;
        for i in 0..MAX_OBJECT_TYPES {
            if OB_TYPE_TABLE[i].is_null() {
                null_count += 1;
            }
        }
        if null_count > 0 {
            crate::hal::serial::write_string("[OB] WARNING: null slots=");
            // `write_u32_hex` is currently only implemented on x86_64;
            // on other architectures we fall back to plain decimal.
            #[cfg(target_arch = "x86_64")]
            crate::hal::serial::write_u32_hex(null_count as u32);
            #[cfg(not(target_arch = "x86_64"))]
            crate::hal::serial::write_string("?");
            crate::hal::serial::write_string("\r\n");
        }
    }

    crate::hal::serial::write_string("[OB] types initialized\r\n");
}

/// Create an object type and register it
fn create_object_type(
    type_index: u8,
    name: &str,
    generic_mapping: GenericMapping,
    valid_access: u32,
    delete_procedure: Option<ObDeleteProcedure>,
) -> *mut ObjectType {
    let size = core::mem::size_of::<ObjectType>();

    let obj_type = pool::allocate(
        pool::PoolType::NonPaged,
        size,
    ) as *mut ObjectType;

    if obj_type.is_null() {
        crate::hal::serial::write_string("[OB] FATAL: alloc failed\r\n");
        return core::ptr::null_mut();
    }

    unsafe {
        core::ptr::write_bytes(obj_type as *mut u8, 0, size);
        (*obj_type).type_index = type_index;
        (*obj_type).set_name(name);
        (*obj_type).pool_tag = OB_TYPE_POOL_TAG;
        (*obj_type).valid_access_mask = valid_access;
        (*obj_type).obj_initializer = ObjectTypeInitializer::new()
            .with_generic_mapping(generic_mapping)
            .with_valid_access(valid_access);

        if let Some(proc) = delete_procedure {
            (*obj_type).obj_initializer.delete_procedure = Some(proc);
        }
    }

    obj_type
}

/// Get object type by type index
pub fn get_object_type(type_index: u8) -> *mut ObjectType {
    if type_index as usize >= MAX_OBJECT_TYPES {
        return core::ptr::null_mut();
    }
    unsafe { OB_TYPE_TABLE[type_index as usize] }
}

// =============================================================================
// Delete Procedures
// =============================================================================

/// Delete procedure for Directory objects
unsafe extern "C" fn directory_delete_procedure(_object: *mut ()) {
    // _object is intentionally unused - reserved for future debugging
    // // kprintln!("[OB] Deleting Directory object at {:016x}", _object as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Directory cleanup: nothing specific to do
}

/// Delete procedure for Device objects
unsafe extern "C" fn device_delete_procedure(_object: *mut ()) {
    // _object is intentionally unused - reserved for future debugging
    // // kprintln!("[OB] Deleting Device object at {:016x}", _object as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Device cleanup: nothing specific to do in bootstrap
}

/// Delete procedure for Driver objects
unsafe extern "C" fn driver_delete_procedure(_object: *mut ()) {
    // _object is intentionally unused - reserved for future debugging
    // // kprintln!("[OB] Deleting Driver object at {:016x}", _object as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Driver cleanup: nothing specific to do in bootstrap
}

/// Delete procedure for SymbolicLink objects
unsafe extern "C" fn symlink_delete_procedure(_object: *mut ()) {
    // _object is intentionally unused - reserved for future debugging
    // // kprintln!("[OB] Deleting SymbolicLink object at {:016x}", _object as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // SymbolicLink cleanup: nothing specific to do
}

/// Delete procedure for Token objects
unsafe extern "C" fn token_delete_procedure(_object: *mut ()) {
    // _object is intentionally unused - reserved for future debugging
    // // kprintln!("[OB] Deleting Token object at {:016x}", _object as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // Token cleanup: free the token memory
    // Note: In a full implementation, we'd decrement token reference count
    // and only free when it reaches zero
}

// =============================================================================
// Object Creation Helpers
// =============================================================================

/// Call the delete procedure for an object type
pub fn call_delete_procedure(object_type_index: u8, body: *mut ()) {
    let obj_type = get_object_type(object_type_index);
    if !obj_type.is_null() {
        unsafe {
            if let Some(proc) = (*obj_type).obj_initializer.delete_procedure {
                proc(body);
            }
        }
    }
}

/// Get the generic mapping for an object type
pub fn get_generic_mapping(object_type_index: u8) -> GenericMapping {
    let obj_type = get_object_type(object_type_index);
    if obj_type.is_null() {
        return GenericMapping::default();
    }
    unsafe { (*obj_type).obj_initializer.generic_mapping }
}

/// Get valid access mask for an object type
pub fn get_valid_access_mask(object_type_index: u8) -> u32 {
    let obj_type = get_object_type(object_type_index);
    if obj_type.is_null() {
        return 0;
    }
    unsafe { (*obj_type).valid_access_mask }
}
