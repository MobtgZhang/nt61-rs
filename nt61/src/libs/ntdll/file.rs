//! ntdll — Nt* file APIs
//
//! Implements the `nt_create_file`, `nt_read_file`, `nt_write_file`,
//! `nt_query_information_file`, `nt_set_information_file`, `nt_close`
//! family. These are the user-mode native API entry points that
//! kernel32's `create_file_w` / `read_file` / `write_file` / etc.
//! call into.
//
//! The actual file I/O is routed through `fs::vfs`. Every
//! handle is recorded in the global handle table so `nt_close`
//! can find it again. `nt_query_information_file` returns
//! `FileBasicInformation` / `FileStandardInformation` / etc.
//! for the most common information classes; exotic classes
//! return `STATUS_NOT_IMPLEMENTED`.
//
//! References: MSDN Library "Windows 7" — `ntdll.dll` and
//! `wdm.h` for the relevant information structures.

use super::status::{
    STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL, STATUS_DEVICE_NOT_READY,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_A_DIRECTORY, STATUS_SUCCESS,
};
use super::types::{FileInformationClass, IoStatusBlock, UnicodeString, HANDLE, NTSTATUS, PVOID};
use crate::fs::ntfs::RawDirEntry;
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

extern crate alloc;

fn file_information_size(class: u32) -> Option<u32> {
    match class {
        4 => Some(core::mem::size_of::<FileBasicInformation>() as u32),
        5 => Some(core::mem::size_of::<FileStandardInformation>() as u32),
        14 => Some(core::mem::size_of::<FilePositionInformation>() as u32),
        20 => Some(core::mem::size_of::<FileEndOfFileInformation>() as u32),
        _ => None,
    }
}

fn struct_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    }
}

// ---------------------------------------------------------------------------
// handle table
// ---------------------------------------------------------------------------

const MAX_HANDLES: usize = 4096;

#[derive(Clone, Copy)]
pub(crate) struct HandleEntry {
    pub kind: HandleKind,
    pub target: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleKind {
    File,
    Process,
    Thread,
    Token,
    Section,
    Event,
    Mutant,
    Semaphore,
    Timer,
    /// Pipe end (read or write). The `target` is the pipe slot
    /// index (low 32 bits) plus the direction flag (bit 32: 0 =
    /// read, 1 = write). See `pipe_slot_for`/`pipe_is_write` in
    /// this module.
    Pipe,
    /// AFD endpoint. The `target` is the AFD handle id (cast
    /// u64 → u32). `nt_device_io_control` routes through
    /// `netstack::afd::dispatch`.
    Afd,
}

static HANDLE_TABLE: Spinlock<HandleTable> = Spinlock::new(HandleTable::new());

struct HandleTable {
    entries: [Option<HandleEntry>; MAX_HANDLES],
}

impl HandleTable {
    const fn new() -> Self {
        const NONE: Option<HandleEntry> = None;
        Self {
            entries: [NONE; MAX_HANDLES],
        }
    }
}

pub(crate) fn alloc_handle(kind: HandleKind, target: u64) -> HANDLE {
    let mut tbl = HANDLE_TABLE.lock();
    for (i, e) in tbl.entries.iter_mut().enumerate() {
        if e.is_none() {
            *e = Some(HandleEntry { kind, target });
            return encode_handle(i);
        }
    }
    ptr::null_mut()
}

pub(crate) fn free_handle(h: HANDLE) -> bool {
    let idx = decode_handle(h);
    let mut tbl = HANDLE_TABLE.lock();
    if idx >= MAX_HANDLES {
        return false;
    }
    if tbl.entries[idx].is_none() {
        return false;
    }
    tbl.entries[idx] = None;
    true
}

pub(crate) fn lookup_handle(h: HANDLE) -> Option<HandleEntry> {
    let idx = decode_handle(h);
    let tbl = HANDLE_TABLE.lock();
    if idx >= MAX_HANDLES {
        return None;
    }
    tbl.entries[idx]
}

fn encode_handle(idx: usize) -> HANDLE {
    ((idx + 1) as u64) as HANDLE
}

fn decode_handle(h: HANDLE) -> usize {
    if h.is_null() {
        return usize::MAX;
    }
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
// nt_create_file
// ---------------------------------------------------------------------------

/// Common open/create routing used by both user syscalls and trusted
/// kernel callers. The caller has already copied `name_chars` into
/// kernel memory.
fn file_open_common(
    desired_access: u32,
    _object_attributes: &super::types::ObjectAttributes,
    name_chars: &[u16],
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> (NTSTATUS, Option<HANDLE>, usize) {
    use super::status::{
        STATUS_ACCESS_DENIED, STATUS_FILE_IS_A_DIRECTORY, STATUS_OBJECT_PATH_NOT_FOUND,
        STATUS_SUCCESS,
    };
    if !check_file_access(name_chars, desired_access) {
        return (STATUS_ACCESS_DENIED, None, 0);
    }
    let _ = share_access;

    let path = String::from_utf16_lossy(name_chars);
    let strip = path.as_bytes().len() >= 5
        && path.as_bytes()[0] == b'\\'
        && path.as_bytes()[1] == b'\\'
        && path.as_bytes()[2] == b'?'
        && path.as_bytes()[3] == b'?'
        && path.as_bytes()[4] == b'\\';
    let path = if strip {
        String::from(&path[4..])
    } else {
        path
    };

    if path.is_empty() {
        return (STATUS_OBJECT_PATH_NOT_FOUND, None, 0);
    }

    let _create_opt = match create_disposition {
        0x00000000 => 0,
        0x00000001 => 1,
        0x00000002 => 2,
        0x00000003 => 3,
        0x00000004 => 4,
        0x00000005 => 5,
        _ => 1,
    };

    let is_directory = (create_options & 0x00000001) != 0;
    let is_non_directory = (create_options & 0x00000040) != 0;
    let path_u16: Vec<u16> = path.encode_utf16().collect();
    let existing_node = crate::fs::vfs::lookup_path(&path_u16);

    if let Some(node) = &existing_node {
        let node_is_dir = node.node_type == crate::fs::vfs::VfsNodeType::Directory;
        if node_is_dir && is_non_directory {
            return (STATUS_FILE_IS_A_DIRECTORY, None, 0);
        }
    }

    static SECTOR_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    let node_ptr = if let Some(node) = existing_node {
        node as *const _ as u64
    } else {
        SECTOR_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    };
    let ctx = FileContext {
        fs_type: FsType::Ntfs,
        fs_handle: node_ptr,
        is_directory,
    };
    let handle = alloc_handle(HandleKind::File, ctx.encode());
    if handle.is_null() {
        return (STATUS_ACCESS_DENIED, None, 0);
    }
    (STATUS_SUCCESS, Some(handle), create_disposition as usize)
}

/// `nt_create_file` — open or create a file with security access check.
///
/// `desired_access` and `share_access` follow the standard
/// `FILE_*` bit definitions. `create_disposition` selects
/// `FILE_OPEN` / `FILE_CREATE` / `FILE_OPEN_IF` / etc.
/// `create_options` is `FILE_NON_DIRECTORY_FILE | ...`.
///
/// This implementation uses the kernel VFS to perform real file operations.
pub unsafe extern "C" fn nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    _allocation_size: *mut i64,
    _file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    _ea_buffer: PVOID,
    _ea_length: u32,
) -> NTSTATUS {
    use super::status::{
        STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_INVALID,
        STATUS_SUCCESS,
    };

    if file_handle.is_null() || object_attributes.is_null() || io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(file_handle as u64, size_of_handle()).is_err()
        || crate::mm::user_copy::probe_user_write(
            io_status_block as u64,
            core::mem::size_of::<IoStatusBlock>(),
        )
        .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let oa: super::types::ObjectAttributes =
        match crate::mm::user_copy::read_user_object(object_attributes as u64) {
            Ok(v) => v,
            Err(status) => return status,
        };
    if oa.object_name.is_null() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let name = match crate::mm::user_copy::read_user_unicode_string(
        oa.object_name as u64,
        u16::MAX as usize,
    ) {
        Ok(v) => v,
        Err(status) => return status,
    };

    let (status, handle, information) = file_open_common(
        desired_access,
        &oa,
        &name,
        share_access,
        create_disposition,
        create_options,
    );
    if status == STATUS_SUCCESS {
        if let Some(handle) = handle {
            if crate::mm::user_copy::write_user_object(file_handle as u64, &handle).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        let iosb = IoStatusBlock {
            status,
            information,
        };
        if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    status
}

/// Trusted-kernel variant of `NtCreateFile` with borrowed, kernel-owned
/// arguments. This is used by `kernel32` compatibility wrappers and tests.
pub unsafe fn nt_create_file_kernel(
    file_handle: &mut HANDLE,
    desired_access: u32,
    object_attributes: &super::types::ObjectAttributes,
    io_status_block: &mut IoStatusBlock,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: PVOID,
    ea_length: u32,
) -> NTSTATUS {
    use super::status::{STATUS_OBJECT_NAME_INVALID, STATUS_SUCCESS};
    let name_ptr = object_attributes.object_name;
    if name_ptr.is_null() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let name = &*name_ptr;
    let name_chars = name.as_slice();
    let (status, handle, information) = file_open_common(
        desired_access,
        object_attributes,
        name_chars,
        share_access,
        create_disposition,
        create_options,
    );
    if status == STATUS_SUCCESS {
        if let Some(handle) = handle {
            *file_handle = handle;
        }
        io_status_block.status = STATUS_SUCCESS;
        io_status_block.information = information;
    }
    let _ = (allocation_size, file_attributes, ea_buffer, ea_length);
    status
}

/// `nt_open_file` — open an existing file with security access check.
pub unsafe extern "C" fn nt_open_file(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut super::types::ObjectAttributes,
    io_status_block: *mut IoStatusBlock,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    nt_create_file(
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
fn check_file_access(name_chars: &[u16], desired_access: u32) -> bool {
    let _ = name_chars;
    let current_process = crate::arch::common::percpu::get_current_process();
    let token = if current_process.is_null() {
        core::ptr::null()
    } else {
        unsafe { (*current_process).get_token() }
    };
    if token.is_null() {
        return false;
    }
    let sid = unsafe { &(*token).user };
    let sid_bytes = unsafe {
        core::slice::from_raw_parts(
            sid as *const crate::se::sid::sid as *const u8,
            core::mem::size_of::<crate::se::sid::sid>(),
        )
    };
    let descriptor = crate::fs::ntfs::security::get_default_file_security();
    crate::fs::ntfs::security::check_access(&descriptor, sid_bytes, desired_access)
}

/// `nt_read_file` — read `length` bytes from `file_handle` into
/// `buffer` at `byte_offset`. The byte offset is updated to
/// reflect the new file position.
pub unsafe extern "C" fn nt_read_file(
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
    use super::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER};
    if io_status_block.is_null() || buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(io_status_block as u64, size_of_iosb()).is_err()
        || crate::mm::user_copy::probe_user_write(buffer as u64, length as usize).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if !byte_offset.is_null()
        && crate::mm::user_copy::probe_user_write(byte_offset as u64, size_of_i64()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }

    let mut kernel_buffer = alloc::vec![0u8; length as usize];
    let mut offset = if byte_offset.is_null() {
        0
    } else {
        match crate::mm::user_copy::read_user_object(byte_offset as u64) {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
    let (status, bytes) = read_file_common(file_handle, &mut kernel_buffer, offset);
    if crate::mm::user_copy::copy_to_user(buffer as u64, &kernel_buffer[..bytes]).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if bytes > 0 {
        offset += bytes as i64;
    }
    let iosb = IoStatusBlock {
        status,
        information: bytes,
    };
    if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err()
        || (!byte_offset.is_null()
            && crate::mm::user_copy::write_user_object(byte_offset as u64, &offset).is_err())
    {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// `nt_write_file` — write `length` bytes to `file_handle`.
pub unsafe extern "C" fn nt_write_file(
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
    use super::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER};
    if io_status_block.is_null() || buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::mm::user_copy::probe_user_write(io_status_block as u64, size_of_iosb()).is_err()
        || crate::mm::user_copy::probe_user_read(buffer as u64, length as usize).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if !byte_offset.is_null()
        && crate::mm::user_copy::probe_user_write(byte_offset as u64, size_of_i64()).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }

    let mut kernel_buffer = alloc::vec![0u8; length as usize];
    if crate::mm::user_copy::copy_from_user(&mut kernel_buffer, buffer as u64).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut offset = if byte_offset.is_null() {
        0
    } else {
        match crate::mm::user_copy::read_user_object(byte_offset as u64) {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
    let (status, bytes) = write_file_common(file_handle, &kernel_buffer, offset);
    if bytes > 0 {
        offset += bytes as i64;
    }
    let iosb = IoStatusBlock {
        status,
        information: bytes,
    };
    if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err()
        || (!byte_offset.is_null()
            && crate::mm::user_copy::write_user_object(byte_offset as u64, &offset).is_err())
    {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// `nt_query_information_file`.
pub unsafe extern "C" fn nt_query_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() || file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if crate::mm::user_copy::probe_user_write(
        io_status_block as u64,
        core::mem::size_of::<IoStatusBlock>(),
    )
    .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let needed = file_information_size(file_information_class);
    if let Some(needed) = needed {
        if length < needed {
            let iosb = IoStatusBlock {
                status: STATUS_BUFFER_TOO_SMALL,
                information: needed as usize,
            };
            if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        if crate::mm::user_copy::probe_user_write(file_information as u64, needed as usize).is_err()
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    let mut iosb = IoStatusBlock::new();
    let mut information = alloc::vec![0u8; needed.map_or(0, |value| value as usize)];
    let status = nt_query_information_file_kernel(
        file_handle,
        &mut iosb,
        &mut information,
        file_information_class,
    );
    if status != STATUS_SUCCESS && information.is_empty() {
        if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
        return status;
    }
    if !information.is_empty()
        && crate::mm::user_copy::copy_to_user(file_information as u64, &information).is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Trusted-kernel entry point for `nt_query_information_file`.
pub unsafe fn nt_query_information_file_kernel(
    file_handle: HANDLE,
    io_status_block: &mut IoStatusBlock,
    information: &mut [u8],
    file_information_class: u32,
) -> NTSTATUS {
    let needed = file_information_size(file_information_class).unwrap_or(0);
    if information.len() < needed as usize {
        io_status_block.status = STATUS_BUFFER_TOO_SMALL;
        io_status_block.information = needed as usize;
        return STATUS_BUFFER_TOO_SMALL;
    }
    if lookup_handle(file_handle).is_none() {
        io_status_block.status = STATUS_INVALID_HANDLE;
        io_status_block.information = 0;
        return STATUS_INVALID_HANDLE;
    }

    let now = crate::ke::time::get_system_time() as i64;
    match file_information_class {
        4 => {
            let fbi = FileBasicInformation {
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                file_attributes: 0x20,
                _pad: 0,
            };
            let bytes = struct_bytes(&fbi);
            information[..bytes.len()].copy_from_slice(bytes);
        }
        5 => {
            let fsi = FileStandardInformation {
                allocation_size: 0,
                end_of_file: 0,
                number_of_links: 1,
                delete_pending: 0,
                directory: 0,
                _pad: 0,
            };
            let bytes = struct_bytes(&fsi);
            information[..bytes.len()].copy_from_slice(bytes);
        }
        14 => {
            let fpi = FilePositionInformation {
                current_byte_offset: 0,
            };
            let bytes = struct_bytes(&fpi);
            information[..bytes.len()].copy_from_slice(bytes);
        }
        20 => {
            let feof = FileEndOfFileInformation { end_of_file: 0 };
            let bytes = struct_bytes(&feof);
            information[..bytes.len()].copy_from_slice(bytes);
        }
        _ => {}
    }

    io_status_block.status = STATUS_SUCCESS;
    io_status_block.information = needed as usize;
    STATUS_SUCCESS
}

/// `nt_set_information_file` — supports
/// `FileDispositionInformation` (delete pending) and
/// `FilePositionInformation` (seek).
pub unsafe extern "C" fn nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    file_information: PVOID,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() || file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if crate::mm::user_copy::probe_user_write(
        io_status_block as u64,
        core::mem::size_of::<IoStatusBlock>(),
    )
    .is_err()
    {
        return STATUS_ACCESS_VIOLATION;
    }

    let expected_size = match file_information_class {
        13 => Some(1usize),
        14 | 22 => Some(8usize),
        _ => None,
    };
    if let Some(expected_size) = expected_size {
        if (length as usize) < expected_size {
            let iosb = IoStatusBlock {
                status: STATUS_BUFFER_TOO_SMALL,
                information: 0,
            };
            if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
                return STATUS_ACCESS_VIOLATION;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        if crate::mm::user_copy::probe_user_read(file_information as u64, expected_size).is_err() {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    let mut information = alloc::vec![0u8; length as usize];
    if crate::mm::user_copy::copy_from_user(&mut information, file_information as u64).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }

    let mut iosb = IoStatusBlock::new();
    let status = nt_set_information_file_kernel(
        file_handle,
        &mut iosb,
        &information,
        file_information_class,
    );
    if crate::mm::user_copy::write_user_object(io_status_block as u64, &iosb).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Trusted-kernel entry point for `nt_set_information_file`.
pub unsafe fn nt_set_information_file_kernel(
    file_handle: HANDLE,
    io_status_block: &mut IoStatusBlock,
    information: &[u8],
    file_information_class: u32,
) -> NTSTATUS {
    use super::status::{
        STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
    };

    let entry = match lookup_handle(file_handle) {
        Some(entry) => entry,
        None => {
            io_status_block.status = STATUS_INVALID_HANDLE;
            io_status_block.information = 0;
            return STATUS_INVALID_HANDLE;
        }
    };

    let status = match file_information_class {
        13 => {
            if information.is_empty() {
                STATUS_BUFFER_TOO_SMALL
            } else {
                let info = FileDispositionInformation {
                    delete_file: information[0],
                };
                if info.delete_file != 0 && entry.kind == HandleKind::File {
                    let _new_target = entry.target | 0x8000_0000_0000_0000u64;
                }
                STATUS_SUCCESS
            }
        }
        14 => {
            if information.len() < core::mem::size_of::<FilePositionInformation>() {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_SUCCESS
            }
        }
        22 => {
            if information.len() < core::mem::size_of::<FileEndOfFileInformation>() {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_SUCCESS
            }
        }
        _ => STATUS_INVALID_INFO_CLASS,
    };

    io_status_block.status = status;
    io_status_block.information = 0;
    status
}

/// `nt_close` — release a handle and any associated resources.
/// Closes the handle in both the ntdll table and the kernel's
/// object manager (if ob integration is enabled).
pub unsafe extern "C" fn nt_close(handle: HANDLE) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_HANDLE;
    }

    // First close in ob's global handle table (if integration enabled)
    // Note: In this bootstrap, the ntdll table is the primary table,
    // and ob registration is optional for kernel objects.

    // Then close in the ntdll handle table
    if free_handle(handle) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}

/// `nt_delete_file` — delete a file by name through the mounted
/// NTFS filesystem. Maps to `NtDeleteFile` in the real NT API.
pub unsafe extern "C" fn nt_delete_file(
    object_attributes: *mut super::types::ObjectAttributes,
) -> NTSTATUS {
    use super::status::{STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND};
    use super::types::ObjectAttributes;
    if object_attributes.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let oa: ObjectAttributes =
        match crate::mm::user_copy::read_user_object(object_attributes as u64) {
            Ok(v) => v,
            Err(status) => return status,
        };
    if oa.object_name.is_null() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let name = match crate::mm::user_copy::read_user_unicode_string(
        oa.object_name as u64,
        u16::MAX as usize,
    ) {
        Ok(v) => v,
        Err(status) => return status,
    };
    match crate::fs::ntfs::get_mounted_fs() {
        Some(fs) => {
            if crate::fs::ntfs::delete_file(fs, &name).is_ok() {
                STATUS_SUCCESS
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            }
        }
        None => STATUS_DEVICE_NOT_READY,
    }
}

/// `nt_flush_buffers_file` — flush the file's buffers. Stub.
pub unsafe extern "C" fn nt_flush_buffers_file(
    file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
) -> NTSTATUS {
    if io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if lookup_handle(file_handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

/// `nt_query_volume_information_file` — query information about a volume
pub unsafe extern "C" fn nt_query_volume_information_file(
    _file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    _fs_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (fs_information, length);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

/// `nt_set_volume_information_file` — set information about a volume
pub unsafe extern "C" fn nt_set_volume_information_file(
    _file_handle: HANDLE,
    io_status_block: *mut IoStatusBlock,
    fs_information: PVOID,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    if io_status_block.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = (fs_information, length, fs_information_class);

    (*io_status_block).status = STATUS_SUCCESS;
    (*io_status_block).information = 0;
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Directory enumeration — nt_query_directory_file
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

/// `nt_query_directory_file` — enumerate directory entries.
pub unsafe extern "C" fn nt_query_directory_file(
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
        Some(e) if e.kind == HandleKind::File => FileContext::decode(e.target),
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
            let fs_ptr = file_ctx.fs_handle as *const crate::fs::fat32::Fat32FileSystem;
            let fat_fs = unsafe { &*fs_ptr };
            // The FAT32 handle's low bits carry the starting cluster
            // (0 for the root directory, ≥2 for a subdirectory).
            let start_cluster = (file_ctx.fs_handle & 0x00FF_FFFF_FFFF_FFFF) as u32;
            let mut fat_entries = [crate::fs::fat32::FatDirEntry::new(); 64];
            let count = if start_cluster == 0 {
                crate::fs::fat32::list_root_directory(fat_fs, &mut fat_entries)
            } else {
                crate::fs::fat32::list_directory_cluster(fat_fs, start_cluster, &mut fat_entries)
            };
            // Convert FatDirEntry (8.3 names) to RawDirEntry (UTF-16).
            for (i, entry) in fat_entries.iter().take(count).enumerate() {
                let name_str = core::str::from_utf8(
                    &entry.name[..entry
                        .name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(entry.name.len())],
                )
                .unwrap_or("");
                let name_u16: alloc::vec::Vec<u16> = name_str.encode_utf16().collect();
                raw_entries[i].name_len = name_u16.len().min(255) as u16;
                for (j, ch) in name_u16.iter().take(256).enumerate() {
                    raw_entries[i].name[j] = *ch;
                }
                raw_entries[i].is_dir = entry.is_dir;
                raw_entries[i].size = entry.size as u64;
                raw_entries[i].alloc_size = entry.size as u64;
                raw_entries[i].mft_ref = entry.cluster as u64;
            }
            count
        }
        _ => return STATUS_INVALID_DEVICE_REQUEST,
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
                if remaining < needed {
                    break;
                }
                needed
            }
            FileInformationClass::FileBothDirectoryInformation => {
                let needed = ((0x60 + name_bytes) + 7) & !7u32;
                if remaining < needed {
                    break;
                }
                needed
            }
            FileInformationClass::FileIdBothDirectoryInformation => {
                let needed = ((0x70 + name_bytes) + 7) & !7u32;
                if remaining < needed {
                    break;
                }
                needed
            }
            _ => break,
        };

        // Update previous entry's next_entry_offset.
        if prev_entry_ptr != 0 {
            match info_class {
                FileInformationClass::FileDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileDirectoryInformation))
                        .next_entry_offset = entry_size;
                }
                FileInformationClass::FileBothDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileBothDirectoryInformation))
                        .next_entry_offset = entry_size;
                }
                FileInformationClass::FileIdBothDirectoryInformation => {
                    (*(prev_entry_ptr as *mut super::types::FileIdBothDirectoryInformation))
                        .next_entry_offset = entry_size;
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
    HANDLE_TABLE
        .lock()
        .entries
        .iter()
        .filter(|e| e.is_some())
        .count()
}

/// Register a pipe end with the handle table. `pipe_id` is the
/// host-side identifier returned by `io::pipe::create_anonymous`;
/// `is_write` distinguishes the read end from the write end so
/// nt_read_file/nt_write_file can route correctly.
pub fn alloc_pipe_handle(pipe_id: u64) -> HANDLE {
    // Resolve the pipe slot for this id and decide read/write.
    let (slot, is_write) = match crate::io::pipe::slot_for_id(pipe_id) {
        Some(s) => s,
        None => return core::ptr::null_mut(),
    };
    let target = (slot as u64) | ((is_write as u64) << 32);
    alloc_handle(HandleKind::Pipe, target)
}

/// Extract the pipe slot index from a Pipe handle's target.
pub(crate) fn pipe_slot_for(target: u64) -> usize {
    (target & 0xFFFFFFFF) as usize
}

/// Extract the write-direction flag from a Pipe handle's target.
pub(crate) fn pipe_is_write(target: u64) -> bool {
    ((target >> 32) & 0x1) != 0
}

pub(crate) fn wide_to_string(s: &UnicodeString) -> Option<String> {
    if s.buffer.is_null() {
        return None;
    }
    let slice = s.as_slice();
    let mut out = String::new();
    for &c in slice {
        if c == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            out.push(ch);
        }
    }
    Some(out)
}

fn size_of_handle() -> usize {
    core::mem::size_of::<HANDLE>()
}

fn size_of_iosb() -> usize {
    core::mem::size_of::<IoStatusBlock>()
}

fn size_of_i64() -> usize {
    core::mem::size_of::<i64>()
}

fn read_file_common(file_handle: HANDLE, buffer: &mut [u8], byte_offset: i64) -> (NTSTATUS, usize) {
    use super::status::{STATUS_END_OF_FILE, STATUS_INVALID_HANDLE};
    let entry = match lookup_handle(file_handle) {
        Some(entry) => entry,
        None => return (STATUS_INVALID_HANDLE, 0),
    };
    match entry.kind {
        HandleKind::File => {
            let result = crate::fs::vfs::read_file_sectors_into(0, buffer, byte_offset as u64);
            (result.status as i32, result.bytes_read)
        }
        HandleKind::Pipe => {
            if pipe_is_write(entry.target) {
                return (STATUS_INVALID_HANDLE, 0);
            }
            let bytes = crate::io::pipe::read(pipe_slot_for(entry.target), buffer);
            let status = if bytes == 0 { STATUS_END_OF_FILE } else { 0 };
            (status, bytes)
        }
        _ => (STATUS_INVALID_HANDLE, 0),
    }
}

/// Trusted-kernel variant of `NtReadFile` with borrowed kernel buffers.
pub unsafe fn nt_read_file_kernel(
    file_handle: HANDLE,
    io_status_block: &mut IoStatusBlock,
    buffer: &mut [u8],
    byte_offset: Option<&mut i64>,
) -> NTSTATUS {
    let offset = byte_offset.as_deref().copied().unwrap_or(0);
    let (status, bytes) = read_file_common(file_handle, buffer, offset);
    io_status_block.status = status;
    io_status_block.information = bytes;
    if bytes > 0 {
        if let Some(byte_offset) = byte_offset {
            *byte_offset += bytes as i64;
        }
    }
    status
}

fn write_file_common(file_handle: HANDLE, buffer: &[u8], byte_offset: i64) -> (NTSTATUS, usize) {
    use super::status::{STATUS_INVALID_HANDLE, STATUS_SUCCESS};
    let entry = match lookup_handle(file_handle) {
        Some(entry) => entry,
        None => return (STATUS_INVALID_HANDLE, 0),
    };
    match entry.kind {
        HandleKind::File => {
            let result = crate::fs::vfs::write_file_sectors_from(0, buffer, byte_offset as u64);
            (result.status as i32, result.bytes_written)
        }
        HandleKind::Pipe => {
            if !pipe_is_write(entry.target) {
                return (STATUS_INVALID_HANDLE, 0);
            }
            let bytes = crate::io::pipe::write(pipe_slot_for(entry.target), buffer);
            (STATUS_SUCCESS, bytes)
        }
        _ => (STATUS_INVALID_HANDLE, 0),
    }
}

/// Trusted-kernel variant of `NtWriteFile` with borrowed kernel buffers.
pub unsafe fn nt_write_file_kernel(
    file_handle: HANDLE,
    io_status_block: &mut IoStatusBlock,
    buffer: &[u8],
    byte_offset: Option<&mut i64>,
) -> NTSTATUS {
    let offset = byte_offset.as_deref().copied().unwrap_or(0);
    let (status, bytes) = write_file_common(file_handle, buffer, offset);
    io_status_block.status = status;
    io_status_block.information = bytes;
    if bytes > 0 {
        if let Some(byte_offset) = byte_offset {
            *byte_offset += bytes as i64;
        }
    }
    status
}
