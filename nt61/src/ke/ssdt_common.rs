//! System Service Descriptor Table (SSDT) - Architecture-Independent Framework
//!
//! This module provides a unified system call dispatch framework that works
//! across all supported architectures (x86_64, aarch64, riscv64, loongarch64).
//!
//! # Architecture-Specific Implementation
//!
//! Each architecture implements:
//! - System call entry mechanism (SYSCALL/SVC/ECALL)
//! - Register saving/restoration
//! - System call number extraction
//! - Argument passing according to ABI
//!
//! # Task 4.1: Architecture-Independent SSDT Framework

use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of system calls supported
pub const MAX_SYSCALLS: usize = 1024;

/// Number of integer ABI slots used by the supported non-x86 architectures.
pub const INTEGER_REGISTER_ARGUMENTS: usize = 8;

/// Number of integer ABI slots used by RISC-V and LoongArch when the
/// seventh register holds the syscall number.
pub const SEVEN_REGISTER_ARCHITECTURES: usize = 7;

/// Uniform argument context passed to every SSDT handler.
///
/// `register_args` holds the architecture-independent integer ABI slots.
/// `stack_pointer` is the user-mode stack pointer captured by the trap
/// stub; handlers for calls with more than six parameters read their
/// trailing arguments from it.
#[derive(Clone, Copy, Debug)]
pub struct SyscallArguments {
    pub register_args: [usize; INTEGER_REGISTER_ARGUMENTS],
    pub integer_register_count: usize,
    pub stack_pointer: usize,
}

impl Default for SyscallArguments {
    fn default() -> Self {
        Self {
            register_args: [0; INTEGER_REGISTER_ARGUMENTS],
            integer_register_count: INTEGER_REGISTER_ARGUMENTS,
            stack_pointer: 0,
        }
    }
}

/// System call handler function pointer type
///
/// Takes a uniform argument context and returns an NTSTATUS.
pub type SyscallHandler = unsafe extern "C" fn(&SyscallArguments) -> u32;

/// System Service Descriptor Table Entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SsdtEntry {
    /// Pointer to the system call handler
    pub handler: SyscallHandler,

    /// Number of arguments this system call expects
    pub arg_count: u8,

    /// System call name (for debugging)
    pub name: [u8; 64],
}

impl SsdtEntry {
    /// create a new SSDT entry

    pub const fn new(handler: SyscallHandler, arg_count: u8, name: &str) -> Self {
        let mut name_bytes = [0u8; 64];
        let bytes = name.as_bytes();
        let len = if bytes.len() > 63 { 63 } else { bytes.len() };

        let mut i = 0;
        while i < len {
            name_bytes[i] = bytes[i];
            i += 1;
        }

        Self {
            handler,
            arg_count,
            name: name_bytes,
        }
    }

    /// Get the system call name as a string
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.name[..end]).unwrap_or("<invalid>")
    }
}

/// System Service Descriptor Table
pub struct Ssdt {
    /// Table of system call entries
    entries: Spinlock<[Option<SsdtEntry>; MAX_SYSCALLS]>,

    /// Number of registered system calls
    count: AtomicUsize,
}

impl Ssdt {
    /// create a new SSDT
    pub const fn new() -> Self {
        Self {
            entries: Spinlock::new([None; MAX_SYSCALLS]),
            count: AtomicUsize::new(0),
        }
    }

    /// Initialize the SSDT with the given capacity
    pub fn init(&self) {
        self.count.store(0, Ordering::Release);
    }

    /// Register a system call handler
    ///
    /// # Safety
    /// The handler must be a valid function pointer that follows the syscall ABI
    pub unsafe fn register(
        &self,
        syscall_number: usize,
        handler: SyscallHandler,
        arg_count: u8,
        name: &str,
    ) -> Result<(), &'static str> {
        if syscall_number >= MAX_SYSCALLS {
            return Err("System call number out of range");
        }

        let mut entries = self.entries.lock();
        let entry = SsdtEntry::new(handler, arg_count, name);
        entries[syscall_number] = Some(entry);
        self.count.fetch_add(1, Ordering::Release);

        Ok(())
    }

    /// Dispatch a system call
    ///
    /// # Safety
    /// This function must be called from a valid system call context with
    /// proper arguments
    pub unsafe fn dispatch(&self, syscall_number: usize, arguments: &SyscallArguments) -> u32 {
        let entries = self.entries.lock();

        if syscall_number >= MAX_SYSCALLS {
            return STATUS_INVALID_SYSTEM_SERVICE;
        }

        let entry = entries[syscall_number];
        match entry {
            Some(entry) => (entry.handler)(arguments),
            None => STATUS_INVALID_SYSTEM_SERVICE,
        }
    }

    /// Get the number of registered system calls
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Get information about a system call
    pub fn get_info(&self, syscall_number: usize) -> Option<SsdtEntry> {
        let entries = self.entries.lock();
        entries.get(syscall_number).and_then(|e| *e)
    }
}

/// Global SSDT instance
static GLOBAL_SSDT: Ssdt = Ssdt::new();

/// NTSTATUS codes
pub const STATUS_SUCCESS: u32 = 0x00000000;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000001C;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC0000002;

/// Registers the NT services shared by every architecture.
///
/// The handlers forward to the architecture-independent NTDLL
/// implementations. Architecture-specific code is only responsible
/// for adapting its trap frame to `dispatch_syscall`.
pub fn register_common_syscalls() {
    unsafe {
        let _ = register_syscall(0x0003, nt_read_file, 9, "NtReadFile");
        let _ = register_syscall(0x0005, nt_write_file, 9, "NtWriteFile");
        let _ = register_syscall(0x000C, nt_close, 1, "NtClose");
        let _ = register_syscall(
            0x000E,
            nt_query_information_file,
            5,
            "NtQueryInformationFile",
        );
        let _ = register_syscall(0x0024, nt_set_information_file, 5, "NtSetInformationFile");
        let _ = register_syscall(
            0x0015,
            nt_allocate_virtual_memory,
            6,
            "NtAllocateVirtualMemory",
        );
        let _ = register_syscall(0x001B, nt_free_virtual_memory, 4, "NtFreeVirtualMemory");
        let _ = register_syscall(0x0020, nt_query_virtual_memory, 6, "NtQueryVirtualMemory");
        let _ = register_syscall(0x0029, nt_terminate_process, 2, "NtTerminateProcess");
        let _ = register_syscall(
            0x0016,
            nt_query_information_process,
            5,
            "NtQueryInformationProcess",
        );
        let _ = register_syscall(
            0x0022,
            nt_query_information_thread,
            5,
            "NtQueryInformationThread",
        );
        let _ = register_syscall(0x0023, nt_open_process, 4, "NtOpenProcess");
        let _ = register_syscall(
            0x0033,
            nt_query_system_information,
            4,
            "NtQuerySystemInformation",
        );
        let _ = register_syscall(0x0030, nt_open_file, 6, "NtOpenFile");
        let _ = register_syscall(0x0031, nt_delay_execution, 2, "NtDelayExecution");
        let _ = register_syscall(0x004B, nt_create_thread, 9, "NtCreateThread");
        let _ = register_syscall(0x004F, nt_resume_thread, 2, "NtResumeThread");
        let _ = register_syscall(0x0050, nt_terminate_thread, 2, "NtTerminateThread");
        let _ = register_syscall(
            0x004D,
            nt_protect_virtual_memory,
            5,
            "NtProtectVirtualMemory",
        );
        let _ = register_syscall(0x00FE, nt_open_thread, 4, "NtOpenThread");
        let _ = register_syscall(0x017B, nt_suspend_thread, 2, "NtSuspendThread");
        let _ = register_syscall(0x0052, nt_create_file, 11, "NtCreateFile");
    }
}

unsafe extern "C" fn nt_read_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, event, apc_routine, apc_context, io_status_block, buffer, ..] =
        arguments.register_args;
    let [length, byte_offset, key] = match read_trailing_arguments(arguments) {
        Ok(values) => values,
        Err(status) => return status,
    };
    let status = crate::libs::ntdll::file::nt_read_file(
        file_handle as crate::libs::ntdll::types::HANDLE,
        event as crate::libs::ntdll::types::HANDLE,
        apc_routine as crate::libs::ntdll::types::PVOID,
        apc_context as crate::libs::ntdll::types::PVOID,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        buffer as crate::libs::ntdll::types::PVOID,
        length as u32,
        byte_offset as *mut i64,
        key as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_write_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, event, apc_routine, apc_context, io_status_block, buffer, ..] =
        arguments.register_args;
    let [length, byte_offset, key] = match read_trailing_arguments(arguments) {
        Ok(values) => values,
        Err(status) => return status,
    };
    let status = crate::libs::ntdll::file::nt_write_file(
        file_handle as crate::libs::ntdll::types::HANDLE,
        event as crate::libs::ntdll::types::HANDLE,
        apc_routine as crate::libs::ntdll::types::PVOID,
        apc_context as crate::libs::ntdll::types::PVOID,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        buffer as crate::libs::ntdll::types::PVOID,
        length as u32,
        byte_offset as *mut i64,
        key as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_query_information_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, io_status_block, file_information, length, file_information_class, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::file::nt_query_information_file(
        file_handle as crate::libs::ntdll::types::HANDLE,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        file_information as crate::libs::ntdll::types::PVOID,
        length as u32,
        file_information_class as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_set_information_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, io_status_block, file_information, length, file_information_class, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::file::nt_set_information_file(
        file_handle as crate::libs::ntdll::types::HANDLE,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        file_information as crate::libs::ntdll::types::PVOID,
        length as u32,
        file_information_class as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_allocate_virtual_memory(arguments: &SyscallArguments) -> u32 {
    let [process_handle, base_address, zero_bits, region_size, allocation_type, protect, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::virtual_mem::nt_allocate_virtual_memory(
        process_handle as crate::libs::ntdll::types::HANDLE,
        base_address as *mut crate::libs::ntdll::types::PVOID,
        zero_bits,
        region_size as *mut crate::libs::ntdll::types::SizeT,
        allocation_type as u32,
        protect as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_free_virtual_memory(arguments: &SyscallArguments) -> u32 {
    let [process_handle, base_address, region_size, free_type, ..] = arguments.register_args;
    let status = crate::libs::ntdll::virtual_mem::nt_free_virtual_memory(
        process_handle as crate::libs::ntdll::types::HANDLE,
        base_address as *mut crate::libs::ntdll::types::PVOID,
        region_size as *mut crate::libs::ntdll::types::SizeT,
        free_type as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_query_virtual_memory(arguments: &SyscallArguments) -> u32 {
    let [process_handle, base_address, memory_information_class, memory_information, memory_information_length, return_length, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::virtual_mem::nt_query_virtual_memory(
        process_handle as crate::libs::ntdll::types::HANDLE,
        base_address as crate::libs::ntdll::types::PVOID,
        memory_information_class as u32,
        memory_information as crate::libs::ntdll::types::PVOID,
        memory_information_length,
        return_length as *mut crate::libs::ntdll::types::SizeT,
    );
    status as u32
}

unsafe extern "C" fn nt_terminate_process(arguments: &SyscallArguments) -> u32 {
    let [process_handle, exit_status, ..] = arguments.register_args;
    let status = crate::libs::ntdll::process::nt_terminate_process(
        process_handle as crate::libs::ntdll::types::HANDLE,
        exit_status as i32,
    );
    status as u32
}

unsafe extern "C" fn nt_open_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, desired_access, object_attributes, io_status_block, share_access, open_options, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::file::nt_open_file(
        file_handle as *mut crate::libs::ntdll::types::HANDLE,
        desired_access as u32,
        object_attributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        share_access as u32,
        open_options as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_protect_virtual_memory(arguments: &SyscallArguments) -> u32 {
    let [process_handle, base_address, region_size, new_protect, old_protect, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::virtual_mem::nt_protect_virtual_memory(
        process_handle as crate::libs::ntdll::types::HANDLE,
        base_address as *mut crate::libs::ntdll::types::PVOID,
        region_size as *mut crate::libs::ntdll::types::SizeT,
        new_protect as u32,
        old_protect as *mut u32,
    );
    status as u32
}

/// Reads trailing integer arguments for the non-x86 integer ABI.
///
/// `index` is zero-based after the first six integer ABI slots. On
/// architectures whose seventh register carries the syscall number, this
/// helper reads the missing register slots from the user stack instead of
/// assuming eight integer registers.
fn read_trailing_arguments<const COUNT: usize>(
    arguments: &SyscallArguments,
) -> Result<[usize; COUNT], u32> {
    let mut values = [0usize; COUNT];
    for (index, value) in values.iter_mut().enumerate() {
        *value = read_trailing_argument(arguments, index)?;
    }
    Ok(values)
}

fn read_trailing_argument(arguments: &SyscallArguments, index: usize) -> Result<usize, u32> {
    let register_index = index + 6;
    if register_index < arguments.integer_register_count {
        return Ok(arguments.register_args[register_index]);
    }

    let stack_index = register_index - arguments.integer_register_count;
    let address = arguments
        .stack_pointer
        .wrapping_add(stack_index * core::mem::size_of::<usize>());
    match crate::mm::user_copy::read_user_object::<usize>(address as u64) {
        Ok(value) => Ok(value),
        Err(status) => Err(status as u32),
    }
}

unsafe extern "C" fn nt_close(arguments: &SyscallArguments) -> u32 {
    let status = crate::libs::ntdll::file::nt_close(
        arguments.register_args[0] as crate::libs::ntdll::types::HANDLE,
    );
    status as u32
}

unsafe extern "C" fn nt_query_information_process(arguments: &SyscallArguments) -> u32 {
    let [process_handle, process_information_class, process_information, process_information_length, return_length, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::process::nt_query_information_process(
        process_handle as crate::libs::ntdll::types::HANDLE,
        process_information_class as u32,
        process_information as crate::libs::ntdll::types::PVOID,
        process_information_length as u32,
        return_length as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_query_information_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, thread_information_class, thread_information, thread_information_length, return_length, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::thread::nt_query_information_thread(
        thread_handle as crate::libs::ntdll::types::HANDLE,
        thread_information_class as u32,
        thread_information as crate::libs::ntdll::types::PVOID,
        thread_information_length as u32,
        return_length as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_open_process(arguments: &SyscallArguments) -> u32 {
    let [process_handle, desired_access, object_attributes, client_id, ..] =
        arguments.register_args;
    let status = crate::libs::ntdll::process::nt_open_process(
        process_handle as *mut crate::libs::ntdll::types::HANDLE,
        desired_access as u32,
        object_attributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        client_id as *mut crate::libs::ntdll::types::client_id,
    );
    status as u32
}

unsafe extern "C" fn nt_delay_execution(arguments: &SyscallArguments) -> u32 {
    let [alertable, interval, ..] = arguments.register_args;
    let status =
        crate::libs::ntdll::sync::nt_delay_execution(alertable as u8, interval as *mut i64);
    status as u32
}

unsafe extern "C" fn nt_create_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, desired_access, object_attributes, process_handle, client_id, start_context, start_routine, ..] =
        arguments.register_args;
    let [stack_committed, stack_size] = match read_trailing_arguments(arguments) {
        Ok(values) => values,
        Err(status) => return status,
    };
    let status = crate::libs::ntdll::thread::nt_create_thread(
        thread_handle as *mut crate::libs::ntdll::types::HANDLE,
        desired_access as u32,
        object_attributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        process_handle as crate::libs::ntdll::types::HANDLE,
        client_id as *mut crate::libs::ntdll::types::client_id,
        start_context as crate::libs::ntdll::types::PVOID,
        start_routine as crate::libs::ntdll::types::PVOID,
        stack_committed,
        stack_size,
    );
    status as u32
}

unsafe extern "C" fn nt_resume_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, previous_suspend_count, ..] = arguments.register_args;
    let status = crate::libs::ntdll::thread::nt_resume_thread(
        thread_handle as crate::libs::ntdll::types::HANDLE,
        previous_suspend_count as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_terminate_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, exit_status, ..] = arguments.register_args;
    let status = crate::libs::ntdll::thread::nt_terminate_thread(
        thread_handle as crate::libs::ntdll::types::HANDLE,
        exit_status as u32,
    );
    status as u32
}

unsafe extern "C" fn nt_open_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, desired_access, object_attributes, client_id, ..] = arguments.register_args;
    let status = crate::libs::ntdll::thread::nt_open_thread(
        thread_handle as *mut crate::libs::ntdll::types::HANDLE,
        desired_access as u32,
        object_attributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        client_id as *mut crate::libs::ntdll::types::client_id,
    );
    status as u32
}

unsafe extern "C" fn nt_suspend_thread(arguments: &SyscallArguments) -> u32 {
    let [thread_handle, previous_suspend_count, ..] = arguments.register_args;
    let status = crate::libs::ntdll::thread::nt_suspend_thread(
        thread_handle as crate::libs::ntdll::types::HANDLE,
        previous_suspend_count as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_query_system_information(arguments: &SyscallArguments) -> u32 {
    let [information_class, information, length, return_length, ..] = arguments.register_args;
    let status = crate::libs::ntdll::info::nt_query_system_information(
        information_class as u32,
        information as crate::libs::ntdll::types::PVOID,
        length as u32,
        return_length as *mut u32,
    );
    status as u32
}

unsafe extern "C" fn nt_create_file(arguments: &SyscallArguments) -> u32 {
    let [file_handle, desired_access, object_attributes, io_status_block, allocation_size, file_attributes, ..] =
        arguments.register_args;
    let share_access = match read_trailing_argument(arguments, 0) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let create_disposition = match read_trailing_argument(arguments, 1) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let create_options = match read_trailing_argument(arguments, 2) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let ea_buffer = match read_trailing_argument(arguments, 3) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let ea_length = match read_trailing_argument(arguments, 4) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let status = crate::libs::ntdll::file::nt_create_file(
        file_handle as *mut crate::libs::ntdll::types::HANDLE,
        desired_access as u32,
        object_attributes as *mut crate::libs::ntdll::types::ObjectAttributes,
        io_status_block as *mut crate::libs::ntdll::types::IoStatusBlock,
        allocation_size as *mut i64,
        file_attributes as u32,
        share_access as u32,
        create_disposition as u32,
        create_options as u32,
        ea_buffer as crate::libs::ntdll::types::PVOID,
        ea_length as u32,
    );
    status as u32
}

/// Initialize the architecture-independent SSDT framework
pub fn init() {
    GLOBAL_SSDT.init();
    crate::hal::serial::write_string("[SSDT] Architecture-independent framework initialized\r\n");
    register_common_syscalls();
}

/// Register a system call in the global SSDT
///
/// # Safety
/// The handler must be a valid function pointer
pub unsafe fn register_syscall(
    number: usize,
    handler: SyscallHandler,
    arg_count: u8,
    name: &str,
) -> Result<(), &'static str> {
    GLOBAL_SSDT.register(number, handler, arg_count, name)
}

/// Dispatch a system call through the global SSDT
///
/// # Safety
/// Must be called from valid syscall context
pub unsafe fn dispatch_syscall(
    number: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> u32 {
    let arguments = SyscallArguments {
        register_args: [arg1, arg2, arg3, arg4, arg5, arg6, 0, 0],
        integer_register_count: INTEGER_REGISTER_ARGUMENTS,
        stack_pointer: 0,
    };
    GLOBAL_SSDT.dispatch(number, &arguments)
}

/// Dispatch a system call with the user stack pointer required by calls
/// that pass more than six parameters.
///
/// # Safety
/// Must be called from a valid syscall context and `stack_pointer` must
/// refer to the user-mode argument stack captured by the trap stub.
pub unsafe fn dispatch_syscall_with_stack(
    number: usize,
    register_args: [usize; INTEGER_REGISTER_ARGUMENTS],
    integer_register_count: usize,
    stack_pointer: usize,
) -> u32 {
    let arguments = SyscallArguments {
        register_args,
        integer_register_count,
        stack_pointer,
    };
    GLOBAL_SSDT.dispatch(number, &arguments)
}

/// Get SSDT statistics
pub fn get_stats() -> (usize, usize) {
    (GLOBAL_SSDT.count(), MAX_SYSCALLS)
}

/// Returns `true` when the global SSDT has a handler for `number`.
/// Used by architecture-specific trap handlers to decide whether to
/// route through the SSDT or fall back to a direct match.
pub fn has_entry(number: usize) -> bool {
    GLOBAL_SSDT.get_info(number).is_some()
}

/// Dispatch through the SSDT using pre-built arguments.
/// Returns `None` when no handler is registered for `number`, allowing
/// the caller to fall back to architecture-specific dispatch.
///
/// # Safety
/// Must be called from a valid syscall context.
pub unsafe fn try_dispatch(number: usize, arguments: &SyscallArguments) -> Option<u32> {
    if !has_entry(number) {
        return None;
    }
    Some(GLOBAL_SSDT.dispatch(number, arguments))
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn test_handler(_arguments: &SyscallArguments) -> u32 {
        STATUS_SUCCESS
    }

    #[test]
    fn test_ssdt_registration() {
        let ssdt = Ssdt::new();
        ssdt.init();

        unsafe {
            let result = ssdt.register(0, test_handler, 0, "TestSyscall");
            assert!(result.is_ok());
            assert_eq!(ssdt.count(), 1);
        }
    }

    #[test]
    fn test_ssdt_dispatch() {
        let ssdt = Ssdt::new();
        ssdt.init();

        unsafe {
            ssdt.register(42, test_handler, 0, "TestSyscall").unwrap();
            let result = ssdt.dispatch(42, &SyscallArguments::default());
            assert_eq!(result, STATUS_SUCCESS);
        }
    }
}
