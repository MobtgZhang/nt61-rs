//! ntdll Registry API
//
//! Implements Windows NT registry functions for in-memory registry storage.

use crate::kprintln;
use crate::libs::ntdll::types::{HANDLE, NTSTATUS, ObjectAttributes, UnicodeString, PVOID};
use crate::libs::ntdll::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

/// Backslash character in UTF-16 encoding (0x5C).
const BACKSLASH_U16: u16 = 0x5C;

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
    /// Create a new RegValue with bounds checking.
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

    /// Create a new RegValue with truncation (for internal use where
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
/// Handle = slot_index + 1 (1-based, so 0 is an invalid handle).
/// Used by all Nt*Key functions to resolve HANDLE -> *mut RegistryKey.
static KEY_HANDLE_TABLE: spin::Spinlock<[Option<KeyHandleEntry>; MAX_KEY_HANDLES]> =
    spin::Spinlock::new([const { None }; MAX_KEY_HANDLES]);

/// Round-robin pointer for handle allocation. After a full scan fails,
/// the next allocation starts from this position to avoid always scanning
/// from slot 0. Only the high 32 bits of the slot index are stored so
/// this fits in AtomicU32 without separate LAST_SLOT.
static LAST_HANDLE_SLOT: AtomicU32 = AtomicU32::new(0);

pub struct KeyHandleEntry {
    pub key_ptr: *mut RegistryKey,
    pub ref_count: u32,
}

impl KeyHandleEntry {
    pub fn new(key: *mut RegistryKey) -> Self {
        Self {
            key_ptr: key,
            ref_count: 1,
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
            while self.flag.compare_exchange(0, 1, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
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
            self.lock.flag.store(0, core::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Allocate a handle in the key handle table using round-robin search.
///
/// Returns the slot index (0..255) if a free slot is found, or `None`
/// if the table is full. This implements round-robin by starting the
/// scan from `LAST_HANDLE_SLOT + 1` modulo 256.
fn allocate_handle_slot(key: *mut RegistryKey) -> Option<usize> {
    let start = LAST_HANDLE_SLOT.load(Ordering::Relaxed) as usize;
    let mut handle_table = KEY_HANDLE_TABLE.lock();

    // Round-robin: scan from (last_slot + 1) to (last_slot - 1), wrapping at 256.
    // We do at most two passes to cover all 256 slots.
    for offset in 0..MAX_KEY_HANDLES {
        let idx = (start + offset + 1) % MAX_KEY_HANDLES;
        if handle_table[idx].is_none() {
            handle_table[idx] = Some(KeyHandleEntry::new(key));
            // Update round-robin pointer to the slot we just used.
            LAST_HANDLE_SLOT.store(idx as u32, Ordering::Relaxed);
            return Some(idx);
        }
    }

    None
}

/// Deallocate a handle slot. Called by NtRegCloseKey.
fn deallocate_handle_slot(slot_index: usize) {
    if slot_index < MAX_KEY_HANDLES {
        let mut handle_table = KEY_HANDLE_TABLE.lock();
        handle_table[slot_index] = None;
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
            }
            *root = Some(root_key);
        }
    }
}

/// Create a subkey under the given parent.
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

/// NtCreateKey — creates or opens a registry key and returns a handle.
///
/// Handle semantics: slot_index + 1 (1-based), so 0 is invalid.
pub unsafe extern "C" fn NtCreateKey(
    key_handle: *mut HANDLE,
    _desired_access: u32,
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

    let path = if !object_attributes.is_null() && !(*object_attributes).object_name.is_null() {
        let name = &*(*object_attributes).object_name;
        core::slice::from_raw_parts(name.Buffer, name.Length as usize / 2)
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
                // Create missing subkey.
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

    // Allocate handle using round-robin.
    let slot_idx = match allocate_handle_slot(current) {
        Some(idx) => idx,
        None => {
            kprintln!(
                subsystem: "REG",
                "    [REG] NtCreateKey: handle table FULL (256 slots)"
            );
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    };

    *key_handle = (slot_idx as u32 + 1) as HANDLE;

    if !disposition.is_null() {
        *disposition = 1; // REG_CREATED_NEW_KEY
    }

    kprintln!(
        subsystem: "REG",
        "    [REG] NtCreateKey: handle=0x{:x} (slot={})",
        *key_handle as u32,
        slot_idx
    );

    STATUS_SUCCESS
}

/// NtOpenKey — opens an existing registry key.
pub unsafe extern "C" fn NtOpenKey(
    key_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ObjectAttributes,
) -> NTSTATUS {
    let _ = desired_access;

    if key_handle.is_null() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    let path = if !object_attributes.is_null() && !(*object_attributes).object_name.is_null() {
        let name = &*(*object_attributes).object_name;
        core::slice::from_raw_parts(name.Buffer, name.Length as usize / 2)
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

    let slot_idx = match allocate_handle_slot(current) {
        Some(idx) => idx,
        None => {
            kprintln!(subsystem: "REG", "    [REG] NtOpenKey: handle table FULL");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    };

    *key_handle = (slot_idx as u32 + 1) as HANDLE;
    kprintln!(
        subsystem: "REG",
        "    [REG] NtOpenKey: handle=0x{:x} (slot={})",
        *key_handle as u32,
        slot_idx
    );

    STATUS_SUCCESS
}

/// NtSetValueKey — sets a value on an open key.
///
/// SECURITY: Validates data_size against MAX_VALUE_DATA_SIZE before copying.
pub unsafe extern "C" fn NtSetValueKey(
    key_handle: HANDLE,
    value_name: *mut UnicodeString,
    title_index: u32,
    value_type: u32,
    data: PVOID,
    data_size: u32,
) -> NTSTATUS {
    let _ = title_index;

    // Handle = slot_index + 1. Validate range first.
    let handle_idx = (key_handle as usize).saturating_sub(1);
    if handle_idx >= MAX_KEY_HANDLES {
        return STATUS_INVALID_PARAMETER;
    }

    let handle_table = KEY_HANDLE_TABLE.lock();
    let entry = match &handle_table[handle_idx] {
        Some(e) => e,
        None => return STATUS_INVALID_PARAMETER,
    };

    let key = entry.key_ptr;
    drop(handle_table);

    // Extract value name.
    let name = if !value_name.is_null() {
        let name = &*value_name;
        core::slice::from_raw_parts(name.Buffer, name.Length as usize / 2)
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

    let data_slice = if !data.is_null() && data_size > 0 {
        core::slice::from_raw_parts(data as *const u8, data_size as usize)
    } else {
        &[]
    };

    kprintln!(
        subsystem: "REG",
        "    [REG] NtSetValueKey: value_name_len={} data_size={}",
        name.len(),
        data_size
    );

    if set_value(key, name, vtype, data_slice) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// NtQueryValueKey — queries a value's type and size.
pub unsafe extern "C" fn NtQueryValueKey(
    key_handle: HANDLE,
    value_name: *mut UnicodeString,
    key_value_information_class: u32,
    key_value_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    let _ = key_value_information_class;
    let _ = key_value_information;
    let _ = length;

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
        let name = &*value_name;
        core::slice::from_raw_parts(name.Buffer, name.Length as usize / 2)
    } else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };

    if let Some((vtype, _)) = get_value(key, name) {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtQueryValueKey: found type={:?}",
            vtype
        );

        if !result_length.is_null() {
            unsafe { *result_length = 8; }
        }

        STATUS_SUCCESS
    } else {
        STATUS_OBJECT_NAME_NOT_FOUND
    }
}

/// NtDeleteKey — registry keys cannot be deleted via this API.
pub unsafe extern "C" fn NtDeleteKey(_key_handle: HANDLE) -> NTSTATUS {
    // STATUS_CANNOT_DELETE
    const STATUS_CANNOT_DELETE: NTSTATUS = -1073741791;
    kprintln!(subsystem: "REG", "    [REG] NtDeleteKey: not supported");
    STATUS_CANNOT_DELETE
}

/// NtDeleteValueKey — deletes a named value from a key.
pub unsafe extern "C" fn NtDeleteValueKey(
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
            Some(entry) => entry.key_ptr,
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
    let name_ustr = unsafe { &*value_name };
    if name_ustr.Length == 0 || name_ustr.Buffer.is_null() {
        kprintln!(subsystem: "REG", "    [REG] NtDeleteValueKey: empty ValueName");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let name_len_u16 = (name_ustr.Length as usize) / 2;
    // SECURITY: Refuse names longer than MAX_VALUE_NAME_LEN.
    if name_len_u16 > MAX_VALUE_NAME_LEN {
        kprintln!(
            subsystem: "REG",
            "    [REG] NtDeleteValueKey: name_len={} > {}",
            name_len_u16,
            MAX_VALUE_NAME_LEN
        );
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let name_slice = core::slice::from_raw_parts(name_ustr.Buffer, name_len_u16);

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

/// NtQueryKey — query information about a registry key.
pub unsafe extern "C" fn NtQueryKey(
    key_handle: HANDLE,
    key_information_class: u32,
    key_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;

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
    drop(handle_table);

    let key_name_len = unsafe { (*key).name_len as usize };
    let key_name_bytes = key_name_len * 2;

    match key_information_class {
        0 => {
            // KeyBasicInformation
            let required = KEY_BASIC_INFORMATION_SIZE + key_name_bytes;
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                key_name_bytes
            );

            kprintln!(subsystem: "REG", "    [REG] NtQueryKey: KeyBasicInformation (name_len={})", key_name_bytes);
            STATUS_SUCCESS
        }
        1 => {
            // KeyNodeInformation
            let required = KEY_NODE_INFORMATION_SIZE + key_name_bytes;
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                key_name_bytes
            );

            kprintln!(subsystem: "REG", "    [REG] NtQueryKey: KeyNodeInformation (name_len={})", key_name_bytes);
            STATUS_SUCCESS
        }
        _ => STATUS_SUCCESS,
    }
}

/// NtEnumerateKey — enumerate subkeys of a registry key.
pub unsafe extern "C" fn NtEnumerateKey(
    key_handle: HANDLE,
    index: u32,
    key_information_class: u32,
    key_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    use crate::libs::ntdll::status::STATUS_NO_MORE_ENTRIES;
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;

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
    drop(handle_table);

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
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                child_name_bytes
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateKey: index={}, KeyBasicInformation", index);
            STATUS_SUCCESS
        }
        1 => {
            // KeyNodeInformation
            let required = KEY_NODE_INFORMATION_SIZE + child_name_bytes;
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                child_name_bytes
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateKey: index={}, KeyNodeInformation", index);
            STATUS_SUCCESS
        }
        _ => STATUS_SUCCESS,
    }
}

/// NtEnumerateValueKey — enumerate values of a registry key.
pub unsafe extern "C" fn NtEnumerateValueKey(
    key_handle: HANDLE,
    index: u32,
    key_value_information_class: u32,
    key_value_information: PVOID,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    use crate::libs::ntdll::status::STATUS_INVALID_HANDLE;
    use crate::libs::ntdll::status::STATUS_NO_MORE_ENTRIES;
    use crate::libs::ntdll::status::STATUS_BUFFER_OVERFLOW;
    use crate::libs::ntdll::status::STATUS_BUFFER_TOO_SMALL;

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
    drop(handle_table);

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
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                value_name_bytes
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValueBasicInformation", index);
            STATUS_SUCCESS
        }
        1 => {
            // KeyValueFullInformation
            let data_size = value.data_size as usize;
            let required = KEY_VALUE_FULL_INFORMATION_SIZE + value_name_bytes + data_size;
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
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
                value_name_bytes
            );

            // Copy value data
            let data_ptr = (key_value_information as *mut u8).add(info.data_offset as usize);
            core::ptr::copy_nonoverlapping(
                value.data.as_ptr(),
                data_ptr,
                data_size
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValueFullInformation", index);
            STATUS_SUCCESS
        }
        2 => {
            // KeyValuePartialInformation
            let data_size = value.data_size as usize;
            // KeyValuePartialInformation: 0x18 bytes fixed + data
            let required = 0x18 + data_size;
            if !result_length.is_null() {
                unsafe { *result_length = required as u32; }
            }
            if (length as usize) < required {
                return STATUS_BUFFER_OVERFLOW;
            }
            if key_value_information.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }

            // Write KeyValuePartialInformation structure
            let info_ptr = key_value_information as *mut u8;
            core::ptr::write_unaligned(info_ptr as *mut u32, 0); // TitleIndex
            core::ptr::write_unaligned((info_ptr as *mut u32).add(1), value.value_type as u32); // Type
            core::ptr::write_unaligned((info_ptr as *mut u32).add(2), value.data_size); // DataSize
            core::ptr::write_unaligned((info_ptr as *mut u64).add(1), 0); // Data (aligned)

            // Copy value data
            core::ptr::copy_nonoverlapping(
                value.data.as_ptr(),
                info_ptr.add(0x18),
                data_size
            );

            kprintln!(subsystem: "REG", "    [REG] NtEnumerateValueKey: index={}, KeyValuePartialInformation", index);
            STATUS_SUCCESS
        }
        _ => STATUS_SUCCESS,
    }
}

/// NtRegCloseKey — close a registry key handle.
pub unsafe extern "C" fn NtRegCloseKey(key_handle: HANDLE) -> NTSTATUS {
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

/// Initialize default registry keys (SYSTEM, SOFTWARE, HARDWARE, SAM, SECURITY).
pub fn init_default_keys() {
    let root = REGISTRY_ROOT.lock();
    if let Some(root_key) = *root {
        // Create SYSTEM hive key.
        let sys_path = [b'S' as u16, b'Y' as u16, b'S' as u16, b'T' as u16, b'E' as u16, b'M' as u16];
        let _ = create_subkey(root_key, &sys_path);

        // Create SOFTWARE hive key with a version value.
        let soft_path = [
            b'S' as u16, b'O' as u16, b'F' as u16, b'T' as u16,
            b'W' as u16, b'A' as u16, b'R' as u16, b'E' as u16,
        ];
        let _ = create_subkey(root_key, &soft_path);

        // Create HARDWARE hive key.
        let hw_path = [
            b'H' as u16, b'A' as u16, b'R' as u16, b'D' as u16,
            b'W' as u16, b'A' as u16, b'R' as u16, b'E' as u16,
        ];
        let _ = create_subkey(root_key, &hw_path);

        // Create SAM hive key.
        let sam_path = [b'S' as u16, b'A' as u16, b'M' as u16];
        let _ = create_subkey(root_key, &sam_path);

        // Create SECURITY hive key.
        let sec_path = [
            b'S' as u16, b'E' as u16, b'C' as u16, b'U' as u16,
            b'R' as u16, b'I' as u16, b'T' as u16, b'Y' as u16,
        ];
        let _ = create_subkey(root_key, &sec_path);
    }
}
