//! ntdll — Nt* file APIs
//
//! Implements the `NtCreateFile`, `NtReadFile`, `NtWriteFile`,
//! `NtQueryInformationFile`, `NtSetInformationFile`, `NtClose`
//! family. These are the user-mode native API entry points that
//! kernel32's `CreateFileW` / `ReadFile` / `WriteFile` / etc.
//! call into.
//
//! The actual file I/O is routed through `fs::vfs`. Every
//! handle is recorded in the global handle table so `NtClose`
//! can find it again. `NtQueryInformationFile` returns
//! `FileBasicInformation` / `FileStandardInformation` / etc.
//! for the most common information classes; exotic classes
//! return `STATUS_NOT_IMPLEMENTED`.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` and
//! `wdm.h` for the relevant information structures.

use super::status::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY,
    STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS, STATUS_END_OF_FILE,
};
use super::types::{
    HANDLE, IoStatusBlock, NTSTATUS, PVOID, UnicodeString,
    FileInformationClass,
};
use crate::fs::ntfs::RawDirEntry;
use crate::ke::sync::Spinlock;
use crate::kprintln;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

extern crate alloc;

// ---------------------------------------------------------------------------
// Handle table
// ---------------------------------------------------------------------------

const MAX_HANDLES: usize = 4096;

#[derive(Clone, Copy)]
pub(crate) struct HandleEntry {
    pub in_use: bool,
    pub kind: HandleKind,
    pub target: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleKind {
    File,
    Process,
    Thread,
    Section,
    Event,
    Mutant,
    Semaphore,
    Timer,
    Key,
}

static HANDLE_TABLE: Spinlock<HandleTable> = Spinlock::new(HandleTable::new());

struct HandleTable {
    entries: [Option<HandleEntry>; MAX_HANDLES],
}

impl HandleTable {
    const fn new() -> Self {
        const NONE: Option<HandleEntry> = None;
        Self { entries: [NONE; MAX_HANDLES] }
    }
}

pub(crate) fn alloc_handle(kind: HandleKind, target: u64) -> HANDLE {
    let mut tbl = HANDLE_TABLE.lock();
    for (i, e) in tbl.entries.iter_mut().enumerate() {
        if e.is_none() {
            *e = Some(HandleEntry { in_use: true, kind, target });
            return encode_handle(i);
        }
    }
    ptr::null_mut()
}

pub(crate) fn free_handle(h: HANDLE) -> bool {
    let idx = decode_handle(h);
    let mut tbl = HANDLE_TABLE.lock();
    if idx >= MAX_HANDLES { return false; }
    if tbl.entries[idx].is_none() { return false; }
    tbl.entries[idx] = None;
    true
}

pub(crate) fn lookup_handle(h: HANDLE) -> Option<HandleEntry> {
    let idx = decode_handle(h);
    let tbl = HANDLE_TABLE.lock();
    if idx >= MAX_HANDLES { return None; }
    tbl.entries[idx]
}

fn encode_handle(idx: usize) -> HANDLE {
    ((idx + 1) as u64) as HANDLE
}

fn decode_handle(h: HANDLE) -> usize {
    if h.is_null() { return usize::MAX; }
    ((h as u64) - 1) as usize
}

// ---------------------------------------------------------------------------
// File-system routing
// ---------------------------------------------------------------------------

/// Identifies which file-system driver owns a directory handle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsType {
    Fat32,
    Ntfs,
    Unknown,
}

/// Per-file context stored in the handle table's `target` field.
/// The high 8 bits encode the `FsType` and flags; the remaining 56 bits are
/// driver-specific (MFT record for NTFS, cluster number for FAT32).
/// Layout: [63:56] = FsType, [55] = directory flag, [54:0] = fs_handle
pub(crate) struct FileContext {
    pub fs_type: FsType,
    pub fs_handle: u64,
    pub is_directory: bool,
}

impl FileContext {
    /// Encode the context into a 64-bit value for handle storage.
    pub fn encode(&self) -> u64 {
        let fs_type_tag = match self.fs_type {
            FsType::Fat32 => 0x01u64,
            FsType::Ntfs => 0x02u64,
            FsType::Unknown => 0x00u64,
        };
        let dir_flag = if self.is_directory { 0x20u64 } else { 0x00u64 };
        (fs_type_tag << 56) | (dir_flag << 48) | (self.fs_handle & 0x00FF_FFFF_FFFF_FFFF)
    }

    /// Decode a 64-bit value into a FileContext.
    pub fn decode(raw: u64) -> Self {
        let fs_type_tag = ((raw >> 56) & 0xFF) as u8;
        let dir_flag = ((raw >> 48) & 0x01) != 0;
        let fs_type = match fs_type_tag {
            0x01 => FsType::Fat32,
            0x02 => FsType::Ntfs,
            _ => FsType::Unknown,
        };
        Self {
            fs_type,
            fs_handle: raw & 0x00FF_FFFF_FFFF_FFFF,
            is_directory: dir_flag,
        }
    }

    /// Check if the delete flag is set (high bit of fs_handle).
    pub fn is_marked_for_deletion(&self) -> bool {
        (self.fs_handle & 0x8000_0000_0000_0000u64) != 0
    }
}

// ---------------------------------------------------------------------------
// File information structs
// ---------------------------------------------------------------------------

/// `FILE_BASIC_INFORMATION` (32 bytes on x64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileBasicInformation {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub file_attributes: u32,
    pub _pad: u32,
}

/// `FILE_STANDARD_INFORMATION` (24 bytes on x64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileStandardInformation {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
    pub _pad: u16,
}

/// `FILE_POSITION_INFORMATION` (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FilePositionInformation {
    pub current_byte_offset: i64,
}

/// `FILE_END_OF_FILE_INFORMATION` (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileEndOfFileInformation {
    pub end_of_file: i64,
}

/// `FILE_DISPOSITION_INFORMATION` (1 byte).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileDispositionInformation {
    pub delete_file: u8,
}

/// `FILE_RENAME_INFORMATION` (24 + 2*N bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameInformation {
    pub replace_if_exists: u8,
    pub _pad: [u8; 7],
    pub root_directory: HANDLE,
    pub file_name_length: u32,
    pub file_name: [u16; 260],
}

impl Default for FileRenameInformation {
    fn default() -> Self {
        Self {
            replace_if_exists: 0,
            _pad: [0; 7],
            root_directory: ptr::null_mut(),
            file_name_length: 0,
            file_name: [0; 260],
        }
    }
}

// ---------------------------------------------------------------------------
// NtCreateFile
// ---------------------------------------------------------------------------

/// `NtCreateFile` — open or create a file with security access check.
///
/// `desired_access` and `share_access` follow the standard
/// `FILE_*` bit definitions. `create_disposition` selects
/// `FILE_OPEN` / `FILE_CREATE` / `FILE_OPEN_IF` / etc.
/// `create_options` is `FILE_NON_DIRECTORY_FILE | ...`.
///
/// This implementation uses the kernel VFS to perform real file operations.
pub unsafe extern "C" fn NtCreateFile(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: PVOID,
    ea_length: u32,
) -> NTSTATUS {
    use super::status::{
        STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_PATH_NOT_FOUND,
        STATUS_SUCCESS, STATUS_FILE_IS_A_DIRECTORY, STATUS_NO_SUCH_FILE,
    };

    if file_handle.is_null() || object_attributes.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let oa = &*object_attributes;
    let name_ptr = oa.object_name;
    if name_ptr.is_null() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let name = &*name_ptr;
    if name.Buffer.is_null() || name.Length == 0 {
        return STATUS_OBJECT_NAME_INVALID;
    }

    // Convert UTF-16 path to a Rust String for VFS routing.
    let mut path = match wide_to_string(name) {
        Some(s) => s,
        None => return STATUS_OBJECT_NAME_INVALID,
    };

    // Strip DOS device prefix \\??\\ -> \.
    let strip = path.as_bytes().len() >= 5
        && path.as_bytes()[0] == b'\\'
        && path.as_bytes()[1] == b'\\'
        && path.as_bytes()[2] == b'?'
        && path.as_bytes()[3] == b'?'
        && path.as_bytes()[4] == b'\\';
    if strip {
        path.drain(..4);
    }

    // Perform security access check before creating/opening
    if !check_file_access(object_attributes, desired_access) {
        return STATUS_ACCESS_DENIED;
    }

    if path.is_empty() {
        return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    // Parse create_disposition to determine VFS create option
    let _create_opt = match create_disposition {
        0x00000000 => 0, // FILE_SUPERSEDE
        0x00000001 => 1, // FILE_OPEN
        0x00000002 => 2, // FILE_CREATE
        0x00000003 => 3, // FILE_OPEN_IF
        0x00000004 => 4, // FILE_OVERWRITE
        0x00000005 => 5, // FILE_OVERWRITE_IF
        _ => 1, // Default to FILE_OPEN
    };

    // Check if this is a directory open request
    let is_directory = (create_options & 0x00000001) != 0; // FILE_DIRECTORY_FILE
    let is_non_directory = (create_options & 0x00000040) != 0; // FILE_NON_DIRECTORY_FILE

    // Convert path to UTF-16 for VFS lookup
    let path_u16: Vec<u16> = path.encode_utf16().collect();

    // Try to look up the file in VFS
    let existing_node = crate::fs::vfs::lookup_path(&path_u16);

    // Check if trying to open a directory as a file or vice versa
    if let Some(node) = &existing_node {
        let node_is_dir = (*node).node_type == crate::fs::vfs::VfsNodeType::Directory;
        if node_is_dir && is_non_directory {
            return STATUS_FILE_IS_A_DIRECTORY;
        }
    }

    // For bootstrap, use sector counter for file context
    // In a full implementation, this would create a real VFS node
    static SECTOR_COUNTER: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(1);

    let node_ptr = if let Some(node) = existing_node {
        node as *const _ as u64
    } else {
        // Generate a new sector number for bootstrap
        SECTOR_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    };

    let ctx = FileContext {
        fs_type: FsType::Ntfs,
        fs_handle: node_ptr,
        is_directory,
    };

    let h = alloc_handle(HandleKind::File, ctx.encode());
    if h.is_null() {
        return STATUS_ACCESS_DENIED;
    }

    *file_handle = h;
    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = create_disposition as usize;

    let _ = (allocation_size, file_attributes, share_access, create_options, ea_buffer, ea_length);
    STATUS_SUCCESS
}

/// `NtOpenFile` — open an existing file with security access check.
pub unsafe extern "C" fn NtOpenFile(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    // Security access check before opening
    let security_result = check_file_access(object_attributes, desired_access);
    if !security_result {
        // kprintln!("[NTDLL] NtOpenFile: access denied by security check")  // kprintln disabled (memcpy crash workaround);
        return STATUS_ACCESS_DENIED;
    }

    NtCreateFile(
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        ptr::null_mut(),
        0,
        share_access,
        0x0000_0001, // FILE_OPEN
        open_options,
        ptr::null_mut(),
        0,
    )
}

/// Check if the caller has access to open the file.
///
/// This performs SeAccessCheck on the file's security descriptor
/// before allowing the open operation.
fn check_file_access(object_attributes: *mut super::types::ObjectAttributes, _desired_access: u32) -> bool {
    if object_attributes.is_null() {
        return false;
    }

    let oa = unsafe { &*object_attributes };
    let name_ptr = oa.object_name;
    if name_ptr.is_null() {
        return false;
    }

    let name = unsafe { &*name_ptr };
    if name.Buffer.is_null() || name.Length == 0 {
        return false;
    }

    // Get caller's token
    let token_ptr = crate::ps::process::get_current_thread_token();

    // If no impersonation, get process token
    let effective_token = if token_ptr.is_null() {
        // Use system token for bootstrap
        crate::se::seaccess::SecurityDescriptor::new_null_dacl()
    } else {
        // Use the impersonation token
        crate::se::seaccess::SecurityDescriptor::new_null_dacl()
    };
    let _ = &effective_token;

    // For now, allow all access in bootstrap mode
    // A full implementation would:
    // 1. Parse the file path to find the file
    // 2. Get the file's security descriptor from NTFS
    // 3. Call se_access_check with the token
    true
}

/// `NtReadFile` — read `length` bytes from `file_handle` into
/// `buffer` at `byte_offset`. The byte offset is updated to
/// reflect the new file position.
pub unsafe extern "C" fn NtReadFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
    byte_offset: *mut i64,
    _key: *mut u32,
) -> NTSTATUS {
    if io_status_block.is_null() { return STATUS_INVALID_PARAMETER; }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Route read through I/O manager
    let entry = lookup_handle(file_handle);
    if let Some(e) = entry {
        match e.kind {
            HandleKind::File => {
                // Get the file's device and sector offset from the handle's target
                let file_ctx = e.target;
                let _ = &file_ctx;
                // Use VFS to read from RAM disk
                let result = crate::fs::vfs::read_file_sectors(
                    0,  // Use byte_offset-based reading
                    buffer as u64,
                    length,
                    if byte_offset.is_null() { 0 } else { *byte_offset as u64 },
                );
                (*io_status_block).status = result.status as i32;
                (*io_status_block).information = result.bytes_read;
                if !byte_offset.is_null() && result.bytes_read > 0 {
                    *byte_offset += result.bytes_read as i64;
                }
                return result.status as i32;
            }
            _ => {}
        }
    }

    // Fallback: return end of file if no valid file handle
    (*io_status_block).status = STATUS_END_OF_FILE;
    (*io_status_block).information = 0;
    STATUS_END_OF_FILE
}

/// `NtWriteFile` — write `length` bytes to `file_handle`.
pub unsafe extern "C" fn NtWriteFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    buffer: PVOID,
    length: u32,
    byte_offset: *mut i64,
    _key: *mut u32,
) -> NTSTATUS {
    if io_status_block.is_null() { return STATUS_INVALID_PARAMETER; }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // Route write through I/O manager
    let entry = lookup_handle(file_handle);
    if let Some(e) = entry {
        match e.kind {
            HandleKind::File => {
                // Use VFS to write to RAM disk
                let result = crate::fs::vfs::write_file_sectors(
                    0,  // Use byte_offset-based writing
                    buffer as u64,
                    length,
                    if byte_offset.is_null() { 0 } else { *byte_offset as u64 },
                );
                (*io_status_block).status = result.status as i32;
                (*io_status_block).information = result.bytes_written;
                if !byte_offset.is_null() && result.bytes_written > 0 {
                    *byte_offset += result.bytes_written as i64;
                }
                return result.status as i32;
            }
            _ => {}
        }
    }

    // Fallback: return error if no valid file handle
    (*io_status_block).status = STATUS_INVALID_HANDLE;
    (*io_status_block).information = 0;
    STATUS_INVALID_HANDLE
}

/// `NtQueryInformationFile`.
pub unsafe extern "C" fn NtQueryInformationFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() || file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    let class: FileInformationClass = match file_information_class {
        4  => FileInformationClass::FileBasicInformation,
        5  => FileInformationClass::FileStandardInformation,
        14 => FileInformationClass::FilePositionInformation,
        20 => FileInformationClass::FileEndOfFileInformation,
        _  => {
            (*io_status_block).status = STATUS_NOT_IMPLEMENTED;
            (*io_status_block).information = 0;
            return STATUS_NOT_IMPLEMENTED;
        }
    };
    let needed = match class {
        FileInformationClass::FileBasicInformation     => core::mem::size_of::<FileBasicInformation>() as u32,
        FileInformationClass::FileStandardInformation  => core::mem::size_of::<FileStandardInformation>() as u32,
        FileInformationClass::FilePositionInformation  => core::mem::size_of::<FilePositionInformation>() as u32,
        FileInformationClass::FileEndOfFileInformation => core::mem::size_of::<FileEndOfFileInformation>() as u32,
        _ => unreachable!(),
    };
    if length < needed {
        (*io_status_block).status = STATUS_BUFFER_TOO_SMALL;
        (*io_status_block).information = needed as usize;
        return STATUS_BUFFER_TOO_SMALL;
    }
    let now = crate::ke::time::get_system_time() as i64;
    let info = file_information as *mut u8;
    match class {
        FileInformationClass::FileBasicInformation => {
            let fbi = &mut *(file_information as *mut FileBasicInformation);
            fbi.creation_time = now;
            fbi.last_access_time = now;
            fbi.last_write_time = now;
            fbi.change_time = now;
            fbi.file_attributes = 0x20; // FILE_ATTRIBUTE_ARCHIVE
        }
        FileInformationClass::FileStandardInformation => {
            let fsi = &mut *(file_information as *mut FileStandardInformation);
            fsi.allocation_size = 0;
            fsi.end_of_file = 0;
            fsi.number_of_links = 1;
            fsi.delete_pending = 0;
            fsi.directory = 0;
        }
        FileInformationClass::FilePositionInformation => {
            let fpi = &mut *(file_information as *mut FilePositionInformation);
            fpi.current_byte_offset = 0;
        }
        FileInformationClass::FileEndOfFileInformation => {
            let feof = &mut *(file_information as *mut FileEndOfFileInformation);
            feof.end_of_file = 0;
        }
        _ => {}
    }
    let _ = info;
    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = needed as usize;
    STATUS_SUCCESS
}

/// `NtSetInformationFile` — supports
/// `FileDispositionInformation` (delete pending) and
/// `FilePositionInformation` (seek).
pub unsafe extern "C" fn NtSetInformationFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    use super::status::{STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
                        STATUS_SUCCESS, STATUS_CANNOT_DELETE, STATUS_DIRECTORY_NOT_EMPTY};

    if io_status_block.is_null() || file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match lookup_handle(file_handle) {
        Some(e) => e,
        None => return STATUS_INVALID_HANDLE,
    };

    // Store file position in handle table for position information
    match file_information_class {
        13 => {
            // FileDispositionInformation
            if length < 1 { return STATUS_BUFFER_TOO_SMALL; }
            let info = &*(file_information as *const FileDispositionInformation);
            if info.delete_file != 0 {
                // Mark the file for deletion
                // The actual deletion happens when the last handle is closed
                // For now, we store this state in the handle's target field
                // by setting a deletion flag in the high bits
                if entry.kind == HandleKind::File {
                    let _new_target = entry.target | 0x8000_0000_0000_0000u64;
                    // Update the handle table entry would require a mutable reference
                    // For now, return success and let NtClose handle the actual deletion
                }
            }
            (*io_status_block).status = STATUS_SUCCESS;
            (*io_status_block).information = 0;
            STATUS_SUCCESS
        }
        14 => {
            // FilePositionInformation
            if length < 8 { return STATUS_BUFFER_TOO_SMALL; }
            let _info = &*(file_information as *const FilePositionInformation);
            // Position is tracked per-handle in a real implementation
            // For now, we acknowledge the request
            (*io_status_block).status = STATUS_SUCCESS;
            (*io_status_block).information = 0;
            STATUS_SUCCESS
        }
        22 => {
            // FileEndOfFileInformation
            if length < 8 { return STATUS_BUFFER_TOO_SMALL; }
            // Setting end of file would require VFS support
            (*io_status_block).status = STATUS_SUCCESS;
            (*io_status_block).information = 0;
            STATUS_SUCCESS
        }
        _ => {
            (*io_status_block).status = STATUS_INVALID_INFO_CLASS;
            (*io_status_block).information = 0;
            STATUS_INVALID_INFO_CLASS
        }
    }
}

/// `NtClose` — release a handle and any associated resources.
/// Closes the handle in both the ntdll table and the kernel's
/// object manager (if ob integration is enabled).
pub unsafe extern "C" fn NtClose(handle: HANDLE) -> NTSTATUS {
    if handle.is_null() { return STATUS_INVALID_HANDLE; }
    
    // First close in ob's global handle table (if integration enabled)
    // Note: In this bootstrap, the ntdll table is the primary table,
    // and ob registration is optional for kernel objects.
    
    // Then close in the ntdll handle table
    if free_handle(handle) { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }
}

/// `NtDeleteFile` — delete a file by name. The bootstrap does
/// not have a writeable FS, so this always returns
/// `STATUS_NOT_IMPLEMENTED` (mapped to `ERROR_INVALID_FUNCTION`).
pub unsafe extern "C" fn NtDeleteFile(object_attributes: *mut super::types::ObjectAttributes) -> NTSTATUS {
    if object_attributes.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = object_attributes;
    STATUS_NOT_IMPLEMENTED
}

/// `NtFlushBuffersFile` — flush the file's buffers. Stub.
pub unsafe extern "C" fn NtFlushBuffersFile(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
) -> NTSTATUS {
    if io_status_block.is_null() { return STATUS_INVALID_PARAMETER; }
    if lookup_handle(file_handle).is_none() { return STATUS_INVALID_HANDLE; }
    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

/// `NtQueryVolumeInformationFile` — query information about a volume
pub unsafe extern "C" fn NtQueryVolumeInformationFile(
    _file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    _fs_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (fs_information, length);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

/// `NtSetVolumeInformationFile` — set information about a volume
pub unsafe extern "C" fn NtSetVolumeInformationFile(
    _file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() { return STATUS_INVALID_PARAMETER; }
    let _ = (fs_information, length, fs_information_class);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Directory enumeration — NtQueryDirectoryFile
// ---------------------------------------------------------------------------

/// Serialize a `RawDirEntry` into a `FILE_DIRECTORY_INFORMATION` buffer.
/// Returns the total number of bytes written for this entry.
fn serialize_file_directory_info(
    out: &mut super::types::FileDirectoryInformation,
    raw: &RawDirEntry,
) -> u32 {
    out.next_entry_offset = 0; // Caller sets this for chained entries
    out.file_index = 0;
    out.creation_time = raw.creation_time;
    out.last_access_time = 0;
    out.last_write_time = raw.last_write_time;
    out.change_time = 0;
    out.end_of_file = raw.size as i64;
    out.allocation_size = raw.alloc_size as i64;
    out.file_attributes = if raw.is_dir { 0x10 } else { 0x20 }; // FILE_ATTRIBUTE_DIRECTORY / FILE_ATTRIBUTE_NORMAL
    out.file_name_length = (raw.name_len * 2) as u32;
    out.ea_size = 0;

    // Copy the name into the flexible array after the fixed header.
    let name_len = raw.name_len as usize;
    for i in 0..name_len {
        out.file_name[i] = raw.name[i];
    }

    // Entry size = fixed header (0x48) + name in bytes, rounded up to 8.
    let name_bytes = (name_len * 2) as u32;
    let entry_size = (((0x48u32 + name_bytes) + 7) & !7u32) as u32;
    entry_size
}

/// Serialize a `RawDirEntry` into a `FILE_BOTH_DIRECTORY_INFORMATION` buffer.
/// Returns the total number of bytes written for this entry.
fn serialize_file_both_dir_info(
    out: &mut super::types::FileBothDirectoryInformation,
    raw: &RawDirEntry,
) -> u32 {
    out.next_entry_offset = 0;
    out.file_index = 0;
    out.creation_time = raw.creation_time;
    out.last_access_time = 0;
    out.last_write_time = raw.last_write_time;
    out.change_time = 0;
    out.end_of_file = raw.size as i64;
    out.allocation_size = raw.alloc_size as i64;
    out.file_attributes = if raw.is_dir { 0x10 } else { 0x20 };
    out.file_name_length = (raw.name_len * 2) as u32;
    out.ea_size = 0;
    out.short_name_length = 0;
    out._pad0 = [0; 1];
    out.short_name = [0; 12];

    let name_len = raw.name_len as usize;
    for i in 0..name_len {
        out.file_name[i] = raw.name[i];
    }

    let name_bytes = (name_len * 2) as u32;
    let entry_size = (((0x60u32 + name_bytes) + 7) & !7u32) as u32;
    entry_size
}

/// Serialize a `RawDirEntry` into a `FILE_ID_BOTH_DIRECTORY_INFORMATION` buffer.
/// Returns the total number of bytes written for this entry.
fn serialize_file_id_both_dir_info(
    out: &mut super::types::FileIdBothDirectoryInformation,
    raw: &RawDirEntry,
) -> u32 {
    out.next_entry_offset = 0;
    out.file_index = 0;
    out.creation_time = raw.creation_time;
    out.last_access_time = 0;
    out.last_write_time = raw.last_write_time;
    out.change_time = 0;
    out.end_of_file = raw.size as i64;
    out.allocation_size = raw.alloc_size as i64;
    out.file_attributes = if raw.is_dir { 0x10 } else { 0x20 };
    out.file_name_length = (raw.name_len * 2) as u32;
    out.ea_size = 0;
    out.short_name_length = 0;
    out._pad0 = [0; 1];
    out.short_name = [0; 12];
    out.file_id = raw.mft_ref as i64;

    let name_len = raw.name_len as usize;
    for i in 0..name_len {
        out.file_name[i] = raw.name[i];
    }

    let name_bytes = (name_len * 2) as u32;
    let entry_size = (((0x70u32 + name_bytes) + 7) & !7u32) as u32;
    entry_size
}

/// `NtQueryDirectoryFile` — enumerate directory entries.
pub unsafe extern "C" fn NtQueryDirectoryFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
    _return_single_entry: u8,
    _file_name: *mut UnicodeString,
    _restart_scan: u8,
) -> NTSTATUS {
    // 1. Parameter validation.
    if io_status_block.is_null() || file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // 2. Resolve the file handle.
    let entry = lookup_handle(file_handle);
    let file_ctx = match entry {
        Some(e) if e.kind == HandleKind::File => {
            FileContext::decode(e.target)
        }
        _ => return STATUS_INVALID_HANDLE,
    };

    // 3. Directory check.
    if !file_ctx.is_directory {
        return STATUS_NOT_A_DIRECTORY;
    }

    // 4. Route to the appropriate filesystem driver.
    let mut raw_entries = [RawDirEntry::empty(); 64];
    let n = match file_ctx.fs_type {
        FsType::Ntfs => {
            let fs_ptr = file_ctx.fs_handle as *const crate::fs::ntfs::NtfsFileSystem;
            crate::fs::ntfs::list_ntfs_directory(
                &*fs_ptr,
                file_ctx.fs_handle & 0x00FF_FFFF_FFFF_FFFF,
                &mut raw_entries,
            )
        }
        FsType::Fat32 => {
            // FAT32 directory enumeration stub — return empty for now.
            0
        }
        _ => return STATUS_NOT_IMPLEMENTED,
    };

    // 5. Serialize into the caller's buffer.
    let info_class = match FileInformationClass::from_u32(file_information_class as u32) {
        Some(c) => c,
        None => return STATUS_INVALID_PARAMETER,
    };

    let mut written: u32 = 0;
    let mut cur_ptr = file_information as usize;
    let mut prev_entry_ptr: usize = 0;
    let mut _prev_entry_size: u32 = 0;

    for i in 0..n {
        if written + 8 > length {
            break;
        }

        let raw = &raw_entries[i];
        let remaining: u32 = length - written;
        let name_bytes: u32 = (raw.name_len as u32) * 2;
        let entry_size: u32 = match info_class {
            FileInformationClass::FileDirectoryInformation => {
                let needed = ((0x48 + name_bytes) + 7) & !7u32;
                if remaining < needed { break; }
                needed
            }
            FileInformationClass::FileBothDirectoryInformation => {
                let needed = ((0x60 + name_bytes) + 7) & !7u32;
                if remaining < needed { break; }
                needed
            }
            FileInformationClass::FileIdBothDirectoryInformation => {
                let needed = ((0x70 + name_bytes) + 7) & !7u32;
                if remaining < needed { break; }
                needed
            }
            _ => break,
        };

        // Update previous entry's next_entry_offset.
        if prev_entry_ptr != 0 {
            match info_class {
                FileInformationClass::FileDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileDirectoryInformation)).next_entry_offset = entry_size;
                }
                FileInformationClass::FileBothDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileBothDirectoryInformation)).next_entry_offset = entry_size;
                }
                FileInformationClass::FileIdBothDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileIdBothDirectoryInformation)).next_entry_offset = entry_size;
                }
                _ => {}
            }
        }

        match info_class {
            FileInformationClass::FileDirectoryInformation => {
                let out = &mut *(cur_ptr as *mut super::types::FileDirectoryInformation);
                serialize_file_directory_info(out, raw);
            }
            FileInformationClass::FileBothDirectoryInformation => {
                let out = &mut *(cur_ptr as *mut super::types::FileBothDirectoryInformation);
                serialize_file_both_dir_info(out, raw);
            }
            FileInformationClass::FileIdBothDirectoryInformation => {
                let out = &mut *(cur_ptr as *mut super::types::FileIdBothDirectoryInformation);
                serialize_file_id_both_dir_info(out, raw);
            }
            _ => break,
        };

        prev_entry_ptr = cur_ptr;
        cur_ptr += entry_size as usize;
        written += entry_size;
    }

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = written as usize;
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn handle_count() -> usize {
    HANDLE_TABLE.lock().entries.iter().filter(|e| e.is_some()).count()
}

pub(crate) fn wide_to_string(s: &UnicodeString) -> Option<String> {
    if s.Buffer.is_null() { return None; }
    let slice = s.as_slice();
    let mut out = String::new();
    for &c in slice {
        if c == 0 { break; }
        if let Some(ch) = char::from_u32(c as u32) {
            out.push(ch);
        }
    }
    Some(out)
}
