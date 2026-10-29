//! ntdll Registry API
//
//! Implements Windows NT registry functions for in-memory registry storage.

use crate::kprintln;
use crate::libs::ntdll::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::libs::ntdll::types::{ObjectAttributes, UnicodeString, HANDLE, NTSTATUS, PVOID};
use crate::mm::user_copy::{
    copy_from_user, probe_user_write, read_user_object, read_user_unicode_string, write_user_object,
};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

/// Backslash character in UTF-16 encoding (0x5C).
const BACKSLASH_U16: u16 = 0x5C;

// KEY_* access rights (winnt.h).
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_SET_VALUE: u32 = 0x0002;
const KEY_CREATE_SUB_KEY: u32 = 0x0004;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
const DELETE_RIGHT: u32 = 0x0001_0000;

/// Maximum number of simultaneously open key handles.
const MAX_KEY_HANDLES: usize = 256;

/// Maximum length of a registry value name (in UTF-16 characters).
const MAX_VALUE_NAME_LEN: usize = 128;

/// Maximum size of registry value data (in bytes).
const MAX_VALUE_DATA_SIZE: usize = 256;

/// Registry key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Root = 0,
    Directory = 1,
    SymbolicLink = 2,
}

/// Registry value types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    None = 0,
    String = 1,
    ExpandString = 2,
    Binary = 3,
    DWord = 4,
    DWordBigEndian = 5,
    Link = 6,
    MultiString = 7,
    ResourceList = 9,
    FullResourceDescriptor = 10,
    ResourceRequirementsList = 11,
    QWord = 12,
}

/// Registry value with fixed-size buffers.
///
/// SECURITY: The `name` and `data` fields use fixed-size arrays.
/// All API functions validate that input lengths do not exceed
/// `MAX_VALUE_NAME_LEN` (128) and `MAX_VALUE_DATA_SIZE` (256).
/// Data exceeding these limits is rejected rather than silently truncated.
pub struct RegValue {
    pub name: [u16; MAX_VALUE_NAME_LEN],
    pub name_len: u16,
    pub value_type: ValueType,
    pub data: [u8; MAX_VALUE_DATA_SIZE],
    pub data_size: u32,
}

impl RegValue {
    /// create a new RegValue with bounds checking.
    ///
    /// If `name.len() > MAX_VALUE_NAME_LEN` or `data.len() > MAX_VALUE_DATA_SIZE`,
    /// returns `None` instead of silently truncating. Callers should validate
    /// lengths before constructing values.
    pub fn new(name: &[u16], vtype: ValueType, data: &[u8]) -> Option<Self> {
        // Reject oversized input rather than truncating silently.
        // This prevents data loss and makes security issues visible.
        if name.len() > MAX_VALUE_NAME_LEN {
            return None;
        }
        if data.len() > MAX_VALUE_DATA_SIZE {
            return None;
        }

        let mut result = Self {
            name: [0; MAX_VALUE_NAME_LEN],
            name_len: name.len() as u16,
            value_type: vtype,
            data: [0; MAX_VALUE_DATA_SIZE],
            data_size: data.len() as u32,
        };

        result.name[..name.len()].copy_from_slice(name);
        result.data[..data.len()].copy_from_slice(data);

        Some(result)
    }

    /// create a new RegValue with truncation (for internal use where
    /// the caller has already validated or knowingly accepts truncation).
    ///
    /// This is a fallback for scenarios where truncation is acceptable
    /// (e.g., the caller knows the data is bounded).
    #[doc(hidden)]
    pub fn new_truncate(name: &[u16], vtype: ValueType, data: &[u8]) -> Self {
        let mut result = Self {
            name: [0; MAX_VALUE_NAME_LEN],
            name_len: name.len().min(MAX_VALUE_NAME_LEN) as u16,
            value_type: vtype,
            data: [0; MAX_VALUE_DATA_SIZE],
            data_size: data.len().min(MAX_VALUE_DATA_SIZE) as u32,
        };

        let name_len = name.len().min(MAX_VALUE_NAME_LEN);
        result.name[..name_len].copy_from_slice(&name[..name_len]);

        let data_len = data.len().min(MAX_VALUE_DATA_SIZE);
        result.data[..data_len].copy_from_slice(&data[..data_len]);

        result
    }
}

/// Registry key structure
pub struct RegistryKey {
    pub name: [u16; 256],
    pub name_len: u16,
    pub key_type: KeyType,
    pub values: [Option<RegValue>; 64],
    pub value_count: usize,
    pub children: [Option<*mut RegistryKey>; 32],
    pub child_count: usize,
    pub parent: *mut RegistryKey,
    pub security: *const crate::se::seaccess::SecurityDescriptor,
}

impl RegistryKey {
    pub fn new(name: &[u16]) -> Self {
        let mut result = Self {
            name: [0; 256],
            name_len: 0,
            key_type: KeyType::Directory,
            values: [const { None }; 64],
            value_count: 0,
            children: [const { None }; 32],
            child_count: 0,
            parent: null_mut(),
            security: core::ptr::null(),
        };

        let len = name.len().min(255);
        result.name[..len].copy_from_slice(&name[..len]);
        result.name_len = len as u16;

        result
    }
}

/// Global registry state
static REGISTRY_ROOT: spin::Spinlock<Option<*mut RegistryKey>> = spin::Spinlock::new(None);

/// Key handle table — 256 slots, each holding an optional entry.
/// handle = slot_index + 1 (1-based, so 0 is an invalid handle).
/// Used by all Nt*Key functions to resolve HANDLE -> *mut RegistryKey.
static KEY_HANDLE_TABLE: spin::Spinlock<[Option<KeyHandleEntry>; MAX_KEY_HANDLES]> =
    spin::Spinlock::new([const { None }; MAX_KEY_HANDLES]);

const MAX_KEY_NOTIFICATIONS: usize = 32;

struct RegistryNotification {
    key_ptr: *mut RegistryKey,
    event_handle: HANDLE,
    watch_tree: bool,
}

static KEY_NOTIFICATIONS: spin::Spinlock<[Option<RegistryNotification>; MAX_KEY_NOTIFICATIONS]> =
    spin::Spinlock::new([const { None }; MAX_KEY_NOTIFICATIONS]);

/// Round-robin pointer for handle allocation. After a full scan fails,
/// the next allocation starts from this position to avoid always scanning
/// from slot 0. Only the high 32 bits of the slot index are stored so
/// this fits in AtomicU32 without separate LAST_SLOT.
static LAST_HANDLE_SLOT: AtomicU32 = AtomicU32::new(0);

pub struct KeyHandleEntry {
    pub key_ptr: *mut RegistryKey,
    pub ref_count: u32,
    /// Access rights the handle was opened with. Zero means "no access".
    pub desired_access: u32,
}

impl KeyHandleEntry {
    pub fn new(key: *mut RegistryKey) -> Self {
        Self {
            key_ptr: key,
            ref_count: 1,
            desired_access: 0,
        }
    }
}

mod spin {
    pub struct Spinlock<T> {
        data: core::cell::UnsafeCell<T>,
        flag: core::sync::atomic::AtomicU32,
    }

    unsafe impl<T> Send for Spinlock<T> {}
    unsafe impl<T> Sync for Spinlock<T> {}

    impl<T> Spinlock<T> {
        pub const fn new(data: T) -> Self {
            Self {
                data: core::cell::UnsafeCell::new(data),
                flag: core::sync::atomic::AtomicU32::new(0),
            }
        }
    }

    impl<T> Spinlock<T> {
        pub fn lock(&self) -> SpinlockGuard<'_, T> {
            while self
                .flag
                .compare_exchange(
                    0,
                    1,
                    core::sync::atomic::Ordering::SeqCst,
                    core::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
            {
                core::hint::spin_loop();
            }
            SpinlockGuard { lock: self }
        }
    }

    pub struct SpinlockGuard<'a, T: 'a> {
        lock: &'a Spinlock<T>,
    }

    impl<'a, T> core::ops::Deref for SpinlockGuard<'a, T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { &*self.lock.data.get() }
        }
    }

    impl<'a, T> core::ops::DerefMut for SpinlockGuard<'a, T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { &mut *self.lock.data.get() }
        }
    }

    impl<'a, T> Drop for SpinlockGuard<'a, T> {
        fn drop(&mut self) {
            self.lock
                .flag
                .store(0, core::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Allocate a handle in the key handle table using round-robin search.
///
/// Returns the slot index (0..255) if a free slot is found, or `None`
/// if the table is full. This implements round-robin by starting the
/// scan from `LAST_HANDLE_SLOT + 1` modulo 256.
fn allocate_handle_slot(key: *mut RegistryKey, desired_access: u32) -> Option<usize> {
    let start = LAST_HANDLE_SLOT.load(Ordering::Relaxed) as usize;
    let mut handle_table = KEY_HANDLE_TABLE.lock();

    // Round-robin: scan from (last_slot + 1) to (last_slot - 1), wrapping at 256.
    // We do at most two passes to cover all 256 slots.
    for offset in 0..MAX_KEY_HANDLES {
        let idx = (start + offset + 1) % MAX_KEY_HANDLES;
        if handle_table[idx].is_none() {
            let mut entry = KeyHandleEntry::new(key);
            entry.desired_access = desired_access;
            handle_table[idx] = Some(entry);
            // Update round-robin pointer to the slot we just used.
            LAST_HANDLE_SLOT.store(idx as u32, Ordering::Relaxed);
            return Some(idx);
        }
    }

    None
}

/// Deallocate a handle slot. Called by nt_reg_close_key.
pub fn deallocate_handle_slot(slot_index: usize) {
    if slot_index < MAX_KEY_HANDLES {
        let mut handle_table = KEY_HANDLE_TABLE.lock();
        handle_table[slot_index] = None;
    }
}

fn registry_key_is_descendant_or_same(key: *mut RegistryKey, ancestor: *mut RegistryKey) -> bool {
    if key.is_null() || ancestor.is_null() {
        return false;
    }
    let mut current = key;
    while !current.is_null() {
        if current == ancestor {
            return true;
        }
        current = unsafe { (*current).parent };
    }
    false
}

fn notify_registry_change(changed_key: *mut RegistryKey) {
    let mut notifications = KEY_NOTIFICATIONS.lock();
    for slot in notifications.iter_mut() {
        let Some(notification) = slot else { continue };
        let matches = notification.watch_tree
            && registry_key_is_descendant_or_same(changed_key, notification.key_ptr)
            || (!notification.watch_tree && changed_key == notification.key_ptr);
        if matches {
            let event_handle = notification.event_handle;
            unsafe {
                let _ = crate::libs::ntdll::sync::nt_set_event(event_handle, core::ptr::null_mut());
            }
            *slot = None;
        }
    }
}

/// Initialize the registry with a root key.
pub fn init() {
    let mut root = REGISTRY_ROOT.lock();
    if root.is_none() {
        let root_key = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<RegistryKey>(),
        ) as *mut RegistryKey;

        if !root_key.is_null() {
            unsafe {
                // Zero out the entire structure first
                let size = core::mem::size_of::<RegistryKey>();
                let ptr = root_key as *mut u8;
                for i in 0..size {
                    core::ptr::write(ptr.add(i), 0);
                }

                // Set name characters individually
                (*root_key).name[0] = b'\\' as u16;
                (*root_key).name[1] = b'R' as u16;
                (*root_key).name[2] = b'E' as u16;
                (*root_key).name[3] = b'G' as u16;
                (*root_key).name[4] = b'I' as u16;
                (*root_key).name[5] = b'S' as u16;
                (*root_key).name[6] = b'T' as u16;
                (*root_key).name[7] = b'R' as u16;
                (*root_key).name[8] = b'Y' as u16;
                (*root_key).name_len = 9;
                (*root_key).key_type = KeyType::Root;
                (*root_key).parent = null_mut();
                (*root_key).security = registry_default_security();
            }
            *root = Some(root_key);
        }
    }
}

/// create a subkey under the given parent.
pub fn create_subkey(parent: *mut RegistryKey, name: &[u16]) -> Option<*mut RegistryKey> {
    let key_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<RegistryKey>(),
    ) as *mut RegistryKey;

    if !key_ptr.is_null() {
        unsafe {
            // Zero out the entire structure
            for i in 0..256 {
                (*key_ptr).name[i] = 0;
            }
            // Copy name one element at a time (avoid copy_from_slice)
            let len = name.len().min(255);
            for i in 0..len {
                (*key_ptr).name[i] = name[i];
            }
            (*key_ptr).name_len = len as u16;
            (*key_ptr).key_type = KeyType::Directory;
            (*key_ptr).parent = parent;
            (*key_ptr).value_count = 0;
            (*key_ptr).child_count = 0;
            (*key_ptr).security = if parent.is_null() {
                registry_default_security()
            } else {
                (*parent).security
            };

            // Initialize arrays
            for i in 0..64 {
                (*key_ptr).values[i] = None;
            }
            for i in 0..32 {
                (*key_ptr).children[i] = None;
            }

            if !parent.is_null() && (*parent).child_count < 32 {
                let idx = (*parent).child_count as usize;
                (*parent).children[idx] = Some(key_ptr);
                (*parent).child_count += 1;
            }
        }
        return Some(key_ptr);
    }
    None
}

/// Create the shared default DACL for the in-memory registry shadow tree.
fn registry_default_security() -> *const crate::se::seaccess::SecurityDescriptor {
    use crate::se::acl::{AceFlags, Acl};
    use crate::se::seaccess::{SecurityDescriptor, ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ};
    use crate::se::sid::{sid, WellKnownSid};

    let acl_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Acl>(),
    ) as *mut Acl;
    let sd_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<SecurityDescriptor>(),
    ) as *mut SecurityDescriptor;
    if acl_ptr.is_null() || sd_ptr.is_null() {
        if !acl_ptr.is_null() {
            crate::mm::pool::free(acl_ptr as *mut u8);
        }
        if !sd_ptr.is_null() {
            crate::mm::pool::free(sd_ptr as *mut u8);
        }
        return core::ptr::null();
    }

    unsafe {
        core::ptr::write(acl_ptr, Acl::new());
        let acl = &mut *acl_ptr;
        if !acl.add_access_allowed(
            &sid::well_known(WellKnownSid::LocalSystem),
            ACCESS_GENERIC_ALL,
            AceFlags::NONE,
        ) || !acl.add_access_allowed(
            &sid::well_known(WellKnownSid::Administrators),
            ACCESS_GENERIC_ALL,
            AceFlags::NONE,
        ) || !acl.add_access_allowed(
            &sid::well_known(WellKnownSid::Users),
            ACCESS_GENERIC_READ,
            AceFlags::NONE,
        ) {
            crate::mm::pool::free(acl_ptr as *mut u8);
            crate::mm::pool::free(sd_ptr as *mut u8);
            return core::ptr::null();
        }

        core::ptr::write(
            sd_ptr,
            SecurityDescriptor {
                revision: 1,
                sbz1: 0,
                control: 0x8004,
                owner: sid::well_known(WellKnownSid::Administrators),
                group: sid::well_known(WellKnownSid::Administrators),
                sacl: core::ptr::null(),
                dacl: acl_ptr,
            },
        );
    }
    sd_ptr
}

/// Enforce the key object's DACL with the caller's process token.
fn registry_access_allowed(key: *mut RegistryKey, desired_access: u32) -> bool {
    use crate::se::seaccess::{se_access_check, AccessCheckResult, ObTypeIndex};

    if key.is_null() {
        return false;
    }
    let current_process = crate::arch::common::percpu::get_current_process();
    if current_process.is_null() {
        return false;
    }
    let token = unsafe { (*current_process).get_token() };
    if token.is_null() {
        return false;
    }

    let security = unsafe {
        if (*key).security.is_null() {
            (*key).security = registry_default_security();
        }
        (*key).security
    };
    if security.is_null() {
        return false;
    }

    let (result, granted) = se_access_check(ObTypeIndex::Key, security, desired_access, token);
    result == AccessCheckResult::Allowed && (granted & desired_access) == desired_access
}

/// Find a subkey by name (case-sensitive) under the given parent.
pub fn find_subkey(parent: *mut RegistryKey, name: &[u16]) -> Option<*mut RegistryKey> {
    if parent.is_null() {
        return None;
    }

    unsafe {
        for i in 0..(*parent).child_count {
            if let Some(child) = (*parent).children[i] {
                let child_name_len = (*child).name_len as usize;
                if child_name_len == name.len() {
                    let mut match_found = true;
                    for j in 0..child_name_len {
                        if (*child).name[j] != name[j] {
                            match_found = false;
                            break;
                        }
                    }
                    if match_found {
                        return Some(child);
                    }
                }
            }
        }
    }
    None
}

/// Set a value on a registry key. Returns `true` on success.
pub fn set_value(key: *mut RegistryKey, name: &[u16], vtype: ValueType, data: &[u8]) -> bool {
    if key.is_null() {
        return false;
    }

    // SECURITY: Reject oversized data before any copying.
    if name.len() > MAX_VALUE_NAME_LEN || data.len() > MAX_VALUE_DATA_SIZE {
        kprintln!(
            subsystem: "REG",
            "    [REG] set_value REJECTED: name_len={} data_len={} (max: {} / {})",
            name.len(),
            data.len(),
            MAX_VALUE_NAME_LEN,
            MAX_VALUE_DATA_SIZE
        );
        return false;
    }

    unsafe {
        // Try to update existing value with the same name first.
        for i in 0..(*key).value_count {
            if let Some(ref mut value) = (*key).values[i] {
                let value_name_len = value.name_len as usize;
                if value_name_len == name.len() {
                    let mut match_found = true;
                    for j in 0..value_name_len {
                        if value.name[j] != name[j] {
                            match_found = false;
                            break;
                        }
                    }
                    if match_found {
                        // Update existing value.
                        // SAFETY: name.len() <= MAX_VALUE_NAME_LEN, data.len() <= MAX_VALUE_DATA_SIZE
                        // (checked above), so this is safe.
                        value.value_type = vtype;
                        value.data[..data.len()].copy_from_slice(data);
                        value.data_size = data.len() as u32;
                        return true;
                    }
                }
            }
        }

        // Add as a new value if there's room.
        if (*key).value_count < 64 {
            let idx = (*key).value_count;
            // Use truncate variant since we already validated the bounds above.
            (*key).values[idx] = Some(RegValue::new_truncate(name, vtype, data));
            (*key).value_count += 1;
            return true;
        }

        kprintln!(
            subsystem: "REG",
            "    [REG] set_value: value count exhausted (max 64)"
        );
    }
    false
}

/// Get a value by name. Returns `(ValueType, value_index)` on success.
pub fn get_value(key: *mut RegistryKey, name: &[u16]) -> Option<(ValueType, usize)> {
    if key.is_null() {
        return None;
    }

    unsafe {
        for i in 0..(*key).value_count {
            if let Some(ref value) = (*key).values[i] {
                let value_name_len = value.name_len as usize;
                if value_name_len == name.len() {
                    let mut match_found = true;
                    for j in 0..value_name_len {
                        if value.name[j] != name[j] {
                            match_found = false;
                            break;
                        }
                    }
                    if match_found {
                        return Some((value.value_type, i));
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// ntdll Registry API Functions
// ============================================================================

/// nt_create_key — creates or opens a registry key and returns a handle.
///
/// handle semantics: slot_index + 1 (1-based), so 0 is invalid.
pub unsafe extern "C" fn nt_create_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
    title_index: u32,
    _class: *mut UnicodeString,
    create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    let _ = title_index;
    let _ = create_options;

    if key_handle.is_null() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if desired_access & KEY_CREATE_SUB_KEY == 0 {
        return STATUS_ACCESS_DENIED;
    }

    let attributes: ObjectAttributes = if !object_attributes.is_null() {
        match read_user_object(object_attributes as u64) {
            Ok(value) => value,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        }
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let path = if !attributes.object_name.is_null() {
        match read_user_unicode_string(attributes.object_name as u64, MAX_VALUE_NAME_LEN * 2) {
            Ok(value) => value,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        }
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };

    kprintln!(
        subsystem: "REG",
        "    [REG] NtCreateKey: path_len={}",
        path.len()
    );

    let root = REGISTRY_ROOT.lock();
    let mut current = match *root {
        Some(r) => r,
        None => return STATUS_OBJECT_NAME_NOT_FOUND,
    };

    // Skip leading backslashes.
    let mut start = 0;
    while start < path.len() && path[start] == BACKSLASH_U16 {
        start += 1;
    }

    // Walk path components.
    while start < path.len() {
        let mut end = start;
        while end < path.len() && path[end] != BACKSLASH_U16 {
            end += 1;
        }

        let component = &path[start..end];
        if !component.is_empty() {
            let found = find_subkey(current, component);
            if let Some(found_key) = found {
                current = found_key;
            } else {
                // create missing subkey.
                let new_key = match create_subkey(current, component) {
                    Some(k) => k,
                    None => return STATUS_OBJECT_NAME_NOT_FOUND,
                };
                current = new_key;
            }
        }
        start = end + 1;
    }

    drop(root);

    if !registry_access_allowed(current, desired_access) {
        return STATUS_ACCESS_DENIED;
    }

    // Allocate handle using round-robin.
    let slot_idx = match allocate_handle_slot(current, desired_access) {
        Some(idx) => idx,
        None => {
            kprintln!(
                subsystem: "REG",
                "    [REG] NtCreateKey: handle table FULL (256 slots)"
            );
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    };

    let handle = (slot_idx as u32 + 1) as HANDLE;
    if write_user_object(key_handle as u64, &handle).is_err() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if !disposition.is_null() {
        if write_user_object(disposition as u64, &1u32).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
    }

    kprintln!(
        subsystem: "REG",
        "    [REG] NtCreateKey: handle=0x{:x} (slot={})",
        *key_handle as u32,
        slot_idx
    );

    STATUS_SUCCESS
}

/// nt_open_key — opens an existing registry key.
pub unsafe extern "C" fn nt_open_key(
    key_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
) -> NTSTATUS {
    if key_handle.is_null() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    let attributes: ObjectAttributes = if !object_attributes.is_null() {
        match read_user_object(object_attributes as u64) {
            Ok(value) => value,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        }
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let path = if !attributes.object_name.is_null() {
        match read_user_unicode_string(attributes.object_name as u64, MAX_VALUE_NAME_LEN * 2) {
            Ok(value) => value,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        }
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };

    kprintln!(subsystem: "REG", "    [REG] NtOpenKey: path_len={}", path.len());

    let root = REGISTRY_ROOT.lock();
    let mut current = match *root {
        Some(r) => r,
        None => return STATUS_OBJECT_NAME_NOT_FOUND,
    };

    let mut start = 0;
    while start < path.len() && path[start] == BACKSLASH_U16 {
        start += 1;
    }

    while start < path.len() {
        let mut end = start;
        while end < path.len() && path[end] != BACKSLASH_U16 {
            end += 1;
        }

        let component = &path[start..end];
        if !component.is_empty() {
            let found = find_subkey(current, component);
            match found {
                Some(found_key) => current = found_key,
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            }
        }
        start = end + 1;
    }

    drop(root);

    if !registry_access_allowed(current, desired_access) {
        return STATUS_ACCESS_DENIED;
    }

    let slot_idx = match allocate_handle_slot(current, desired_access) {
        Some(idx) => idx,
        None => {
            kprintln!(subsystem: "REG", "    [REG] NtOpenKey: handle table FULL");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    };

    let handle = (slot_idx as u32 + 1) as HANDLE;
    if write_user_object(key_handle as u64, &handle).is_err() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    kprintln!(
        subsystem: "REG",
        "    [REG] NtOpenKey: handle=0x{:x} (slot={})",
        *key_handle as u32,
        slot_idx
    );

    STATUS_SUCCESS
}

/// nt_set_value_key — sets a value on an open key.
///
/// SECURITY: Validates data_size against MAX_VALUE_DATA_SIZE before copying.
pub unsafe extern "C" fn nt_set_value_key(
    key_handle: HANDLE,
    value_name: *mut UnicodeString,
    title_index: u32,
    value_type: u32,
    data: PVOID,
    data_size: u32,
) -> NTSTATUS {
    let _ = title_index;

    // handle = slot_index + 1. Validate range first.
    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_PARAMETER;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_INVALID_PARAMETER,
    };

    if entry.desired_access & KEY_SET_VALUE == 0 {
        return STATUS_ACCESS_DENIED;
    }

    if entry.desired_access & KEY_QUERY_VALUE == 0 {
        return STATUS_ACCESS_DENIED;
    }

    let key = entry.key_ptr;
    drop(handle_table);

    // Extract value name.
    let name = if !value_name.is_null() {
        match read_user_unicode_string(value_name as u64, MAX_VALUE_NAME_LEN * 2) {
            Ok(value) => value,
            Err(_) => return STATUS_INVALID_PARAMETER,
        }
    } else {
        return STATUS_INVALID_PARAMETER;
    };

    // SECURITY: Reject oversized value name and data.
    if name.len() > MAX_VALUE_NAME_LEN {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtSetValueKey: REJECTED name_len={} > {}",
            name.len(),
            MAX_VALUE_NAME_LEN
        );
        return STATUS_INVALID_PARAMETER;
    }
    if data_size as usize > MAX_VALUE_DATA_SIZE {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtSetValueKey: REJECTED data_size={} > {}",
            data_size,
            MAX_VALUE_DATA_SIZE
        );
        return STATUS_INVALID_PARAMETER;
    }

    let vtype = match value_type {
        1 => ValueType::String,
        3 => ValueType::Binary,
        4 => ValueType::DWord,
        7 => ValueType::MultiString,
        _ => ValueType::Binary,
    };

    let mut data_bytes = alloc::vec![0u8; data_size as usize];
    let data_slice = if !data.is_null() && data_size > 0 {
        if copy_from_user(&mut data_bytes, data as u64).is_err() {
            return STATUS_INVALID_PARAMETER;
        }
        data_bytes.as_slice()
    } else {
        &[]
    };

    kprintln!(
        subsystem: "REG",
        "    [REG] NtSetValueKey: value_name_len={} data_size={}",
        name.len(),
        data_size
    );

    if set_value(key, &name, vtype, data_slice) {
        notify_registry_change(key);
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// nt_query_value_key — queries a value's type and size.
pub unsafe extern "C" fn nt_query_value_key(
    key_handle: HANDLE,
    value_name: *mut UnicodeString,
    key_value_information_class: u32,
    key_value_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_OBJECT_NAME_NOT_FOUND,
    };

    let key = entry.key_ptr;
    drop(handle_table);

    let name = if !value_name.is_null() {
        match read_user_unicode_string(value_name as u64, MAX_VALUE_NAME_LEN * 2) {
            Ok(value) => value,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        }
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };

    // Find the value and its data directly from the key.
    let found = find_value(key, &name);
    let Some((vtype, data_slice)) = found else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let data_size = data_slice.len();

    // Per-class fixed header sizes, indexed by information class. Adding a
    // new class means adding a row here plus its payload writer below; the
    // validation path (required-size report, buffer-size check and user
    // probe) is shared so it cannot be forgotten per branch.
    const HEADER_SIZES: [usize; 3] = [
        KEY_VALUE_BASIC_INFORMATION_SIZE, // 0: KeyValueBasicInformation
        KEY_VALUE_FULL_INFORMATION_SIZE,  // 1: KeyValueFullInformation
        0x18,                             // 2: KeyValuePartialInformation
    ];

    let class = key_value_information_class as usize;
    let header_size = match HEADER_SIZES.get(class) {
        Some(h) => *h,
        None => return STATUS_INVALID_PARAMETER,
    };

    let name_bytes = name.len() * 2;
    let required = match class {
        0 => header_size + name_bytes,
        1 => header_size + name_bytes + data_size,
        _ => header_size + data_size,
    };

    // Unified validation entry: report the required size, then make sure
    // the caller's buffer is large enough and actually writable.
    let info_ptr = {
        if !write_result_length(result_length, required) {
            return STATUS_ACCESS_VIOLATION;
        }
        if (length as usize) < required || key_value_information.is_null() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if probe_user_write(key_value_information as u64, required).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
        key_value_information as *mut u8
    };

    unsafe {
        // TitleIndex (4 bytes) + Type (4 bytes): common to every class.
        let title_index = 0u32.to_le_bytes();
        core::ptr::copy_nonoverlapping(title_index.as_ptr(), info_ptr, 4);
        let vtype_bytes = (vtype as u32).to_le_bytes();
        core::ptr::copy_nonoverlapping(vtype_bytes.as_ptr(), info_ptr.add(4), 4);

        match class {
            0 => {
                // KeyValueBasicInformation: fixed 12-byte header followed by
                // the value name. Windows always returns the name here, so
                // callers that read NameLength and then the name bytes see
                // consistent data instead of stale user-buffer contents.
                let name_len_bytes = (name_bytes as u32).to_le_bytes();
                core::ptr::copy_nonoverlapping(name_len_bytes.as_ptr(), info_ptr.add(8), 4);
                copy_utf16_name(info_ptr.add(header_size), &name);
            }
            1 => {
                // KeyValueFullInformation: 20-byte header, then the value
                // name, then the value data. DataOffset points at the data
                // (immediately after the name), matching Windows NT 6.1.
                let data_offset = header_size + name_bytes;
                let data_offset_bytes = (data_offset as u32).to_le_bytes();
                core::ptr::copy_nonoverlapping(data_offset_bytes.as_ptr(), info_ptr.add(8), 4);
                let data_size_bytes = (data_size as u32).to_le_bytes();
                core::ptr::copy_nonoverlapping(data_size_bytes.as_ptr(), info_ptr.add(12), 4);
                let name_len_bytes = (name_bytes as u32).to_le_bytes();
                core::ptr::copy_nonoverlapping(name_len_bytes.as_ptr(), info_ptr.add(16), 4);
                copy_utf16_name(info_ptr.add(header_size), &name);
                core::ptr::copy_nonoverlapping(
                    data_slice.as_ptr(),
                    info_ptr.add(data_offset),
                    data_size,
                );
            }
            _ => {
                // KeyValuePartialInformation: TitleIndex (4 bytes) +
                // Type (4 bytes) + DataLength (4 bytes), then the data.
                let len_bytes = (data_size as u32).to_le_bytes();
                core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), info_ptr.add(8), 4);
                core::ptr::copy_nonoverlapping(
                    data_slice.as_ptr(),
                    info_ptr.add(header_size),
                    data_size,
                );
            }
        }
    }

    STATUS_SUCCESS
}

/// Copies a UTF-16LE value name into a user buffer at `dst`.
unsafe fn copy_utf16_name(dst: *mut u8, name: &[u16]) {
    for (index, unit) in name.iter().enumerate() {
        let bytes = unit.to_le_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.add(index * 2), 2);
    }
}

/// Finds a value by name and returns (type, data-slice).
fn find_value(key: *mut RegistryKey, name: &[u16]) -> Option<(ValueType, &[u8])> {
    if key.is_null() {
        return None;
    }
    unsafe {
        for i in 0..(*key).value_count {
            if let Some(ref value) = (*key).values[i] {
                let value_name_len = value.name_len as usize;
                if value_name_len == name.len() {
                    let mut match_found = true;
                    for j in 0..value_name_len {
                        if value.name[j] != name[j] {
                            match_found = false;
                            break;
                        }
                    }
                    if match_found {
                        let data_size = value.data_size as usize;
                        return Some((value.value_type, &value.data[..data_size]));
                    }
                }
            }
        }
    }
    None
}

/// nt_delete_key — deletes a key opened with DELETE access.
///
/// Honours NtDeleteKey semantics where the in-memory tree allows them:
/// the key must have no subkeys, its parent's child slot is cleared, and
/// every open handle and pending notification referencing it is
/// invalidated so no caller keeps using freed memory. Root keys cannot
/// be deleted.
pub unsafe extern "C" fn nt_delete_key(key_handle: HANDLE) -> NTSTATUS {
    const STATUS_CANNOT_DELETE: NTSTATUS = -1073741791;

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtDeleteKey: handle 0x{:x} out of range",
            key_handle as u64
        );
        return STATUS_INVALID_HANDLE;
    }

    let (key, parent) = {
        let handle_table = KEY_HANDLE_TABLE.lock();
        match &handle_table[handle_idx] {
            Some(entry) => {
                if entry.desired_access & DELETE_RIGHT == 0 {
                    kprintln!(
                        subsystem: "REG",
                        "    [REG] NtDeleteKey: handle 0x{:x} lacks DELETE access",
                        key_handle as u64
                    );
                    return STATUS_ACCESS_DENIED;
                }
                if entry.key_ptr.is_null() {
                    return STATUS_INVALID_HANDLE;
                }
                let key = entry.key_ptr;
                let parent = (*key).parent;
                (key, parent)
            }
            None => {
                kprintln!(
                    subsystem: "REG",
                    "    [REG] NtDeleteKey: handle 0x{:x} not found",
                    key_handle as u64
                );
                return STATUS_INVALID_HANDLE;
            }
        }
    };

    if parent.is_null() {
        kprintln!(subsystem: "REG", "    [REG] NtDeleteKey: cannot delete a root key");
        return STATUS_CANNOT_DELETE;
    }
    if (*key).child_count != 0 {
        kprintln!(subsystem: "REG", "    [REG] NtDeleteKey: key still has subkeys");
        return STATUS_CANNOT_DELETE;
    }

    // Remove the key from its parent's child list, compacting the slots.
    {
        let count = (*parent).child_count as usize;
        let mut found: Option<usize> = None;
        for i in 0..count {
            if (*parent).children[i] == Some(key) {
                found = Some(i);
                break;
            }
        }
        if let Some(idx) = found {
            for i in idx..count - 1 {
                (*parent).children[i] = (*parent).children[i + 1];
            }
            (*parent).children[count - 1] = None;
            (*parent).child_count -= 1;
        }
    }

    // Invalidate every open handle to the deleted key.
    {
        let mut handle_table = KEY_HANDLE_TABLE.lock();
        for slot in handle_table.iter_mut() {
            if let Some(entry) = slot {
                if entry.key_ptr == key {
                    *slot = None;
                }
            }
        }
    }

    // Drop pending notifications watching this key so they cannot touch
    // freed memory.
    {
        let mut notifications = KEY_NOTIFICATIONS.lock();
        for slot in notifications.iter_mut() {
            if let Some(notification) = slot {
                if notification.key_ptr == key {
                    *slot = None;
                }
            }
        }
    }

    crate::mm::pool::free(key as *mut u8);
    kprintln!(subsystem: "REG", "    [REG] NtDeleteKey: key deleted");
    STATUS_SUCCESS
}

/// nt_delete_value_key — deletes a named value from a key.
pub unsafe extern "C" fn nt_delete_value_key(
    key_handle: HANDLE,
    value_name: *mut UnicodeString,
) -> NTSTATUS {
    if value_name.is_null() {
        kprintln!(subsystem: "REG", "    [REG] NtDeleteValueKey: value_name is null");
        return STATUS_INVALID_PARAMETER;
    }

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtDeleteValueKey: handle 0x{:x} out of range",
            key_handle as u64
        );
        return STATUS_INVALID_HANDLE;
    }

    let key = {
        let handle_table = KEY_HANDLE_TABLE.lock();
        match &handle_table[handle_idx] {
            Some(entry) => {
                if entry.desired_access & (KEY_SET_VALUE | DELETE_RIGHT) == 0 {
                    return STATUS_ACCESS_DENIED;
                }
                entry.key_ptr
            }
            None => {
                kprintln!(
                    subsystem: "REG",
                    "    [REG] NtDeleteValueKey: handle 0x{:x} not found",
                    key_handle as u64
                );
                return STATUS_INVALID_HANDLE;
            }
        }
    };

    if key.is_null() {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtDeleteValueKey: handle 0x{:x} resolves to null key",
            key_handle as u64
        );
        return STATUS_INVALID_HANDLE;
    }

    // Extract ValueName UTF-16 string.
    let name_slice = match read_user_unicode_string(value_name as u64, MAX_VALUE_NAME_LEN * 2) {
        Ok(value) => value,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let name_len_u16 = name_slice.len();

    unsafe {
        let key_ref = &mut *key;
        let mut found_idx: Option<usize> = None;
        for i in 0..key_ref.value_count {
            if let Some(ref v) = key_ref.values[i] {
                let v_len = v.name_len as usize;
                if v_len == name_len_u16 {
                    let mut eq = true;
                    for j in 0..v_len {
                        if v.name[j] != name_slice[j] {
                            eq = false;
                            break;
                        }
                    }
                    if eq {
                        found_idx = Some(i);
                        break;
                    }
                }
            }
        }

        match found_idx {
            None => {
                kprintln!(
                    subsystem: "REG",
                    "    [REG] NtDeleteValueKey: value not found, name_len={}",
                    name_len_u16
                );
                STATUS_OBJECT_NAME_NOT_FOUND
            }
            Some(idx) => {
                // Swap-remove: the array stays compact.
                let last = key_ref.value_count - 1;
                if idx != last {
                    key_ref.values[idx] = key_ref.values[last].take();
                } else {
                    key_ref.values[idx] = None;
                }
                key_ref.value_count -= 1;
                notify_registry_change(key);
                kprintln!(
                    subsystem: "REG",
                    "    [REG] NtDeleteValueKey: deleted value at idx={}, count={}",
                    idx,
                    key_ref.value_count
                );
                STATUS_SUCCESS
            }
        }
    }
}

// ============================================================================
// KEY_INFORMATION structures (NT 6.1 compatible)
// ============================================================================

/// KEY_BASIC_INFORMATION — basic key information.
/// Total: 0x10 bytes fixed header + name (FAM).
#[repr(C)]
pub struct KeyBasicInformation {
    pub last_write_time: i64,
    pub title_index: u32,
    pub name_length: u32,
    pub name: [u16; 1], // Flexible array member
}

/// KEY_NODE_INFORMATION — detailed key information.
/// Total: 0x1C bytes fixed header + name (FAM).
#[repr(C)]
pub struct KeyNodeInformation {
    pub class_name_offset: u32,
    pub reserved: u32,
    pub last_write_time: i64,
    pub title_index: u32,
    pub class_name_length: u32,
    pub name_length: u32,
    pub name: [u16; 1], // Flexible array member
}

/// KEY_VALUE_BASIC_INFORMATION — basic value information.
/// Total: 0x08 bytes fixed header + name (FAM).
#[repr(C)]
pub struct KeyValueBasicInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub name_length: u32,
    pub data_size: u32,
    pub name: [u16; 1], // Flexible array member
}

/// KEY_VALUE_FULL_INFORMATION — full value information.
/// Total: 0x14 bytes fixed header + name + data (FAM).
#[repr(C)]
pub struct KeyValueFullInformation {
    pub title_index: u32,
    pub value_type: u32,
    pub data_offset: u32,
    pub data_size: u32,
    pub name_length: u32,
    pub class_name_offset: u32,
    pub class_name_length: u32,
    pub name: [u16; 1], // Flexible array member
}

/// Fixed header sizes
const KEY_BASIC_INFORMATION_SIZE: usize = 16;
const KEY_NODE_INFORMATION_SIZE: usize = 28;
const KEY_VALUE_BASIC_INFORMATION_SIZE: usize = 12;
const KEY_VALUE_FULL_INFORMATION_SIZE: usize = 20;

fn write_result_length(result_length: *mut u32, required: usize) -> bool {
    if result_length.is_null() {
        return true;
    }
    if probe_user_write(result_length as u64, core::mem::size_of::<u32>()).is_err() {
        return false;
    }
    unsafe {
        *result_length = required as u32;
    }
    true
}

/// nt_query_key — query information about a registry key.
pub unsafe extern "C" fn nt_query_key(
    key_handle: HANDLE,
    key_information_class: u32,
    key_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_HANDLE;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let key = entry.key_ptr;
    let requested_access = entry.desired_access | KEY_QUERY_VALUE;
    drop(handle_table);

    if !registry_access_allowed(key, requested_access) {
        return STATUS_ACCESS_DENIED;
    }

    let key_name_len = unsafe { (*key).name_len as usize };
    let key_name_bytes = key_name_len * 2;

    match key_information_class {
        0 => {
            // KeyBasicInformation
            let required = KEY_BASIC_INFORMATION_SIZE + key_name_bytes;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_information as *mut KeyBasicInformation);
            info.last_write_time = 0; // No timestamp tracking
            info.title_index = 0;
            info.name_length = key_name_bytes as u32;

            // Copy key name
            let name_ptr = &mut info.name as *mut u16 as *mut u8;
            core::ptr::copy_nonoverlapping(
                (*key).name.as_ptr() as *const u8,
                name_ptr,
                key_name_bytes,
            );

            kprintln!(subsystem: "REG", "    [REG] NtQueryKey: KeyBasicInformation (name_len={})", key_name_bytes);
            STATUS_SUCCESS
        }
        1 => {
            // KeyNodeInformation
            let required = KEY_NODE_INFORMATION_SIZE + key_name_bytes;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_information as *mut KeyNodeInformation);
            info.class_name_offset = 0;
            info.reserved = 0;
            info.last_write_time = 0;
            info.title_index = 0;
            info.class_name_length = 0;
            info.name_length = key_name_bytes as u32;

            // Copy key name
            let name_ptr = &mut info.name as *mut u16 as *mut u8;
            core::ptr::copy_nonoverlapping(
                (*key).name.as_ptr() as *const u8,
                name_ptr,
                key_name_bytes,
            );

            kprintln!(subsystem: "REG", "    [REG] NtQueryKey: KeyNodeInformation (name_len={})", key_name_bytes);
            STATUS_SUCCESS
        }
        // Unsupported information classes must not fake success: the
        // caller would read a half-initialised buffer. Windows returns
        // STATUS_INVALID_PARAMETER for an unknown class.
        _ => crate::libs::ntdll::status::STATUS_INVALID_PARAMETER,
    }
}

/// nt_enumerate_key — enumerate subkeys of a registry key.
pub unsafe extern "C" fn nt_enumerate_key(
    key_handle: HANDLE,
    index: u32,
    key_information_class: u32,
    key_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    use crate::libs::ntdll::status::STATUS_NO_MORE_ENTRIES;

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_HANDLE;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let key = entry.key_ptr;
    let requested_access = entry.desired_access | KEY_ENUMERATE_SUB_KEYS;
    drop(handle_table);

    if !registry_access_allowed(key, requested_access) {
        return STATUS_ACCESS_DENIED;
    }

    let child_count = unsafe { (*key).child_count };

    if index >= child_count as u32 {
        return STATUS_NO_MORE_ENTRIES;
    }

    // Get the child key
    let child = unsafe {
        if let Some(child_ptr) = (*key).children[index as usize] {
            child_ptr
        } else {
            return STATUS_NO_MORE_ENTRIES;
        }
    };

    let child_name_len = unsafe { (*child).name_len as usize };
    let child_name_bytes = child_name_len * 2;

    match key_information_class {
        0 => {
            // KeyBasicInformation
            let required = KEY_BASIC_INFORMATION_SIZE + child_name_bytes;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_information as *mut KeyBasicInformation);
            info.last_write_time = 0;
            info.title_index = 0;
            info.name_length = child_name_bytes as u32;

            // Copy child key name
            let name_ptr = &mut info.name as *mut u16 as *mut u8;
            core::ptr::copy_nonoverlapping(
                (*child).name.as_ptr() as *const u8,
                name_ptr,
                child_name_bytes,
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateKey: index={}, KeyBasicInformation", index);
            STATUS_SUCCESS
        }
        1 => {
            // KeyNodeInformation
            let required = KEY_NODE_INFORMATION_SIZE + child_name_bytes;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_information as *mut KeyNodeInformation);
            info.class_name_offset = 0;
            info.reserved = 0;
            info.last_write_time = 0;
            info.title_index = 0;
            info.class_name_length = 0;
            info.name_length = child_name_bytes as u32;

            // Copy child key name
            let name_ptr = &mut info.name as *mut u16 as *mut u8;
            core::ptr::copy_nonoverlapping(
                (*child).name.as_ptr() as *const u8,
                name_ptr,
                child_name_bytes,
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateKey: index={}, KeyNodeInformation", index);
            STATUS_SUCCESS
        }
        // Unsupported information classes must not fake success: the
        // caller would read a half-initialised buffer. Windows returns
        // STATUS_INVALID_PARAMETER for an unknown class.
        _ => crate::libs::ntdll::status::STATUS_INVALID_PARAMETER,
    }
}

/// nt_enumerate_value_key — enumerate values of a registry key.
pub unsafe extern "C" fn nt_enumerate_value_key(
    key_handle: HANDLE,
    index: u32,
    key_value_information_class: u32,
    key_value_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    use crate::libs::ntdll::status::STATUS_NO_MORE_ENTRIES;

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_HANDLE;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    let key = entry.key_ptr;
    let requested_access = entry.desired_access | KEY_QUERY_VALUE;
    drop(handle_table);

    if !registry_access_allowed(key, requested_access) {
        return STATUS_ACCESS_DENIED;
    }

    let value_count = unsafe { (*key).value_count };

    if index >= value_count as u32 {
        return STATUS_NO_MORE_ENTRIES;
    }

    // Get the value entry
    let value = unsafe {
        match &(*key).values[index as usize] {
            Some(v) => v,
            None => return STATUS_NO_MORE_ENTRIES,
        }
    };

    let value_name_len = value.name_len as usize;
    let value_name_bytes = value_name_len * 2;

    match key_value_information_class {
        0 => {
            // KeyValueBasicInformation
            let required = KEY_VALUE_BASIC_INFORMATION_SIZE + value_name_bytes;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_value_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_value_information as *mut KeyValueBasicInformation);
            info.title_index = 0;
            info.value_type = value.value_type as u32;
            info.name_length = value_name_bytes as u32;
            info.data_size = value.data_size;

            // Copy value name
            let name_ptr = &mut info.name as *mut u16 as *mut u8;
            core::ptr::copy_nonoverlapping(
                value.name.as_ptr() as *const u8,
                name_ptr,
                value_name_bytes,
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValueBasicInformation", index);
            STATUS_SUCCESS
        }
        1 => {
            // KeyValueFullInformation
            let data_size = value.data_size as usize;
            let required = KEY_VALUE_FULL_INFORMATION_SIZE + value_name_bytes + data_size;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_value_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            let info = &mut *(key_value_information as *mut KeyValueFullInformation);
            info.title_index = 0;
            info.value_type = value.value_type as u32;
            info.data_offset = (KEY_VALUE_FULL_INFORMATION_SIZE + value_name_bytes) as u32;
            info.data_size = value.data_size;
            info.name_length = value_name_bytes as u32;
            info.class_name_offset = 0;
            info.class_name_length = 0;

            // Copy value name
            let name_ptr = (&mut info.name as *mut u16 as *mut u8).add(0);
            core::ptr::copy_nonoverlapping(
                value.name.as_ptr() as *const u8,
                name_ptr,
                value_name_bytes,
            );

            // Copy value data
            let data_ptr = (key_value_information as *mut u8).add(info.data_offset as usize);
            core::ptr::copy_nonoverlapping(value.data.as_ptr(), data_ptr, data_size);

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValueFullInformation", index);
            STATUS_SUCCESS
        }
        2 => {
            // KeyValuePartialInformation
            let data_size = value.data_size as usize;
            // KeyValuePartialInformation: 0x18 bytes fixed + data
            let required = 0x18 + data_size;
            if !write_result_length(result_length, required) {
                return STATUS_ACCESS_VIOLATION;
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if probe_user_write(key_value_information as u64, required).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }

            // write KeyValuePartialInformation structure
            let info_ptr = key_value_information as *mut u8;
            core::ptr::write_unaligned(info_ptr as *mut u32, 0); // TitleIndex
            core::ptr::write_unaligned((info_ptr as *mut u32).add(1), value.value_type as u32); // r#type
            core::ptr::write_unaligned((info_ptr as *mut u32).add(2), value.data_size); // DataSize
            core::ptr::write_unaligned((info_ptr as *mut u64).add(1), 0); // Data (aligned)

            // Copy value data
            core::ptr::copy_nonoverlapping(value.data.as_ptr(), info_ptr.add(0x18), data_size);

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValuePartialInformation", index);
            STATUS_SUCCESS
        }
        // Unsupported information classes must not fake success: the
        // caller would read a half-initialised buffer. Windows returns
        // STATUS_INVALID_PARAMETER for an unknown class.
        _ => crate::libs::ntdll::status::STATUS_INVALID_PARAMETER,
    }
}

/// nt_reg_close_key — close a registry key handle.
pub unsafe extern "C" fn nt_reg_close_key(key_handle: HANDLE) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;

    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_HANDLE;
    }

    let mut handle_table = KEY_HANDLE_TABLE.lock();
    if handle_table[handle_idx].is_some() {
        handle_table[handle_idx] = None;
        kprintln!(
            subsystem: "REG",
            "    [REG] Closed key handle 0x{:x} (slot={})",
            key_handle as u32,
            handle_idx
        );
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

/// nt_flush_key — flush pending changes for a key.
///
/// The kernel registry cache in this build is written through on every
/// `nt_set_value_key`/`nt_delete_value_key` call, so there is nothing pending
/// to flush. The handle is still validated to match the real API's
/// error behaviour.
pub unsafe extern "C" fn nt_flush_key(key_handle: HANDLE) -> NTSTATUS {
    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES || KEY_HANDLE_TABLE.lock()[handle_idx].is_none() {
        return STATUS_INVALID_HANDLE;
    }
    STATUS_SUCCESS
}

/// nt_notify_change_key — register (or wait for) key change notifications.
///
/// Synchronous requests report success. Asynchronous requests register the
/// supplied event; value mutations signal it and remove the notification.
pub unsafe extern "C" fn nt_notify_change_key(
    key_handle: HANDLE,
    event_handle: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    _completion_list: PVOID,
    _completion_filter: u32,
    watch_tree: u32,
    _buffer: PVOID,
    _buffer_size: u32,
    asynchronous: u32,
) -> NTSTATUS {
    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES || KEY_HANDLE_TABLE.lock()[handle_idx].is_none() {
        return STATUS_INVALID_HANDLE;
    }

    if asynchronous == 0 {
        return STATUS_SUCCESS;
    }

    let mut notifications = KEY_NOTIFICATIONS.lock();
    if let Some(free_slot) = notifications.iter().position(|slot| slot.is_none()) {
        let key_ptr = KEY_HANDLE_TABLE.lock()[handle_idx]
            .as_ref()
            .map(|entry| entry.key_ptr)
            .unwrap_or(core::ptr::null_mut());
        notifications[free_slot] = Some(RegistryNotification {
            key_ptr,
            event_handle,
            watch_tree: watch_tree != 0,
        });
        return 0x40000003_u32 as i32;
    }
    STATUS_SUCCESS
}

/// Initialize default registry keys (SYSTEM, SOFTWARE, HARDWARE, SAM, SECURITY).
pub fn init_default_keys() {
    let root = REGISTRY_ROOT.lock();
    if let Some(root_key) = *root {
        // create SYSTEM hive key.
        let sys_path = [
            b'S' as u16,
            b'Y' as u16,
            b'S' as u16,
            b'T' as u16,
            b'E' as u16,
            b'M' as u16,
        ];
        let _ = create_subkey(root_key, &sys_path);

        // create SOFTWARE hive key with a version value.
        let soft_path = [
            b'S' as u16,
            b'O' as u16,
            b'F' as u16,
            b'T' as u16,
            b'W' as u16,
            b'A' as u16,
            b'R' as u16,
            b'E' as u16,
        ];
        let _ = create_subkey(root_key, &soft_path);

        // create HARDWARE hive key.
        let hw_path = [
            b'H' as u16,
            b'A' as u16,
            b'R' as u16,
            b'D' as u16,
            b'W' as u16,
            b'A' as u16,
            b'R' as u16,
            b'E' as u16,
        ];
        let _ = create_subkey(root_key, &hw_path);

        // create SAM hive key.
        let sam_path = [b'S' as u16, b'A' as u16, b'M' as u16];
        let _ = create_subkey(root_key, &sam_path);

        // create SECURITY hive key.
        let sec_path = [
            b'S' as u16,
            b'E' as u16,
            b'C' as u16,
            b'U' as u16,
            b'R' as u16,
            b'I' as u16,
            b'T' as u16,
            b'Y' as u16,
        ];
        let _ = create_subkey(root_key, &sec_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact code NtDeleteKey uses; kept local because the production
    // constant lives inside the function body.
    const STATUS_CANNOT_DELETE: i32 = -1073741791;

    // All tests in this module mutate the same process-global registry tree
    // (REGISTRY_ROOT, root child arrays, KEY_HANDLE_TABLE) through unsynchronized
    // read-modify-write sequences. Running them in parallel loses updates and
    // corrupts key structures, so serialize them explicitly.
    static REGISTRY_TEST_LOCK: spin::Spinlock<()> = spin::Spinlock::new(());

    // Under libtest the kernel heap is never initialised; configure a test
    // region so pool allocations for registry keys work.
    fn ensure_test_heap() {
        if crate::mm::heap::KERNEL_HEAP.configured_region().is_some() {
            return;
        }
        const TEST_HEAP_LEN: usize = 4 * 1024 * 1024;
        static mut TEST_HEAP: [u8; TEST_HEAP_LEN] = [0u8; TEST_HEAP_LEN];
        let base = core::ptr::addr_of_mut!(TEST_HEAP) as *mut u8;
        crate::mm::heap::KERNEL_HEAP.configure(base, TEST_HEAP_LEN);
    }

    fn name_of(s: &str) -> alloc::vec::Vec<u16> {
        s.chars().map(|c| c as u16).collect()
    }

    fn root_key() -> *mut RegistryKey {
        init();
        match *REGISTRY_ROOT.lock() {
            Some(root) => root,
            None => core::ptr::null_mut(),
        }
    }

    #[test]
    fn delete_key_removes_leaf_and_invalidates_handle() {
        let _guard = REGISTRY_TEST_LOCK.lock();
        ensure_test_heap();
        unsafe {
            let root = root_key();
            assert!(!root.is_null());

            let child = create_subkey(root, &name_of("DeleteLeafTest")).unwrap();
            let slot = allocate_handle_slot(child, DELETE_RIGHT).unwrap();
            let handle = (slot + 1) as HANDLE;

            let status = nt_delete_key(handle);
            assert_eq!(status, STATUS_SUCCESS);

            // Parent no longer lists the child.
            let still_listed = (0..(*root).child_count).any(|i| (*root).children[i] == Some(child));
            assert!(!still_listed);

            // The handle slot was invalidated.
            let handle_table = KEY_HANDLE_TABLE.lock();
            assert!(handle_table[slot].is_none());
            drop(handle_table);

            // Retrying through the now-dead handle must not succeed.
            assert_ne!(nt_delete_key(handle), STATUS_SUCCESS);
        }
    }

    #[test]
    fn delete_key_requires_delete_access() {
        let _guard = REGISTRY_TEST_LOCK.lock();
        ensure_test_heap();
        unsafe {
            let root = root_key();
            let child = create_subkey(root, &name_of("DeleteNoAccess")).unwrap();
            let slot = allocate_handle_slot(child, 0).unwrap();
            let handle = (slot + 1) as HANDLE;

            assert_eq!(nt_delete_key(handle), STATUS_ACCESS_DENIED);

            // Clean up the slot so other tests can reuse the table.
            deallocate_handle_slot(slot);
        }
    }

    #[test]
    fn delete_key_refuses_parent_with_children() {
        let _guard = REGISTRY_TEST_LOCK.lock();
        ensure_test_heap();
        unsafe {
            let root = root_key();
            let parent = create_subkey(root, &name_of("DeleteParentTest")).unwrap();
            let _child = create_subkey(parent, &name_of("DeleteParentTestChild")).unwrap();

            let slot = allocate_handle_slot(parent, DELETE_RIGHT).unwrap();
            let handle = (slot + 1) as HANDLE;

            assert_eq!(nt_delete_key(handle), STATUS_CANNOT_DELETE);
            assert_eq!((*parent).child_count, 1);
            deallocate_handle_slot(slot);
        }
    }

    #[test]
    fn delete_key_refuses_root() {
        let _guard = REGISTRY_TEST_LOCK.lock();
        ensure_test_heap();
        unsafe {
            let root = root_key();
            let slot = allocate_handle_slot(root, DELETE_RIGHT).unwrap();
            let handle = (slot + 1) as HANDLE;

            assert_eq!(nt_delete_key(handle), STATUS_CANNOT_DELETE);
            deallocate_handle_slot(slot);
        }
    }
}
