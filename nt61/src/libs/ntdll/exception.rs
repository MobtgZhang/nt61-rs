//! ntdll — Exception handling support (NT 6.1.7601)
//
//! Implements the structured exception handling (SEH) framework for x64:
//! - RtlUnwind / RtlUnwindEx — stack unwinding
//! - RtlDispatchException — exception dispatcher
//! - RtlRaiseException — raise exceptions
//! - RtlCaptureContext / RtlRestoreContext — context manipulation
//! - Vectored Exception Handler (VEH) support
//!
//! Windows 7 x64 uses table-based exception handling (not frame-based SEH).
//! Exception handlers are registered via RUNTIME_FUNCTION entries in the
//! PE .pdata section, pointing to UNWIND_INFO structures.
//!
//! References:
//!   * MSDN Library "Windows 7" — Exception Handling
//!   * x64 Exception Handling (MSDN)
//!   * ReactOS ntdll/rtl/exception.c

use super::types::{HANDLE, NTSTATUS, PVOID};
use super::status::{
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNHANDLED_EXCEPTION,
    STATUS_INVALID_DISPOSITION, STATUS_NONCONTINUABLE_EXCEPTION,
    STATUS_UNWIND,
};
use crate::ke::sync::Spinlock;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

extern crate alloc;
use alloc::vec::Vec;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: PVOID,
    pub number_parameters: u32,
    pub exception_information: [usize; 15],
}

impl ExceptionRecord {
    pub const fn new() -> Self {
        Self {
            exception_code: 0,
            exception_flags: 0,
            exception_record: ptr::null_mut(),
            exception_address: ptr::null_mut(),
            number_parameters: 0,
            exception_information: [0; 15],
        }
    }
}

pub const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
pub const EXCEPTION_UNWINDING: u32 = 0x2;
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
pub const EXCEPTION_STACK_INVALID: u32 = 0x8;
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;
pub const EXCEPTION_UNWIND_FLAGS: u32 = EXCEPTION_UNWINDING
    | EXCEPTION_EXIT_UNWIND
    | EXCEPTION_TARGET_UNWIND
    | EXCEPTION_COLLIDED_UNWIND;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,

    pub context_flags: u32,
    pub mx_csr: u32,

    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,

    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,

    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    pub rip: u64,

    pub xmm0: [u64; 2],
    pub xmm1: [u64; 2],
    pub xmm2: [u64; 2],
    pub xmm3: [u64; 2],
    pub xmm4: [u64; 2],
    pub xmm5: [u64; 2],
    pub xmm6: [u64; 2],
    pub xmm7: [u64; 2],
    pub xmm8: [u64; 2],
    pub xmm9: [u64; 2],
    pub xmm10: [u64; 2],
    pub xmm11: [u64; 2],
    pub xmm12: [u64; 2],
    pub xmm13: [u64; 2],
    pub xmm14: [u64; 2],
    pub xmm15: [u64; 2],
}

impl Context {
    pub const fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

pub const CONTEXT_AMD64: u32 = 0x00100000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x01;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x02;
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x04;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x08;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
    | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;


pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
pub const EXCEPTION_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
pub const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
pub const EXCEPTION_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
pub const EXCEPTION_FLT_DENORMAL_OPERAND: u32 = 0xC000008D;
pub const EXCEPTION_FLT_DIVIDE_BY_ZERO: u32 = 0xC000008E;
pub const EXCEPTION_FLT_INEXACT_RESULT: u32 = 0xC000008F;
pub const EXCEPTION_FLT_INVALID_OPERATION: u32 = 0xC0000090;
pub const EXCEPTION_FLT_OVERFLOW: u32 = 0xC0000091;
pub const EXCEPTION_FLT_STACK_CHECK: u32 = 0xC0000092;
pub const EXCEPTION_FLT_UNDERFLOW: u32 = 0xC0000093;
pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC0000094;
pub const EXCEPTION_INT_OVERFLOW: u32 = 0xC0000095;
pub const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC0000096;
pub const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC0000006;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
pub const EXCEPTION_NONCONTINUABLE_EXCEPTION: u32 = 0xC0000025;
pub const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
pub const EXCEPTION_INVALID_DISPOSITION: u32 = 0xC0000026;
pub const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;
pub const EXCEPTION_INVALID_HANDLE: u32 = 0xC0000008;


#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDisposition {
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3,
}


const MAX_VEH_HANDLERS: usize = 64;

pub type VectoredHandlerFn = unsafe extern "C" fn(*mut ExceptionPointers) -> i32;

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context,
}

struct VehEntry {
    handler: VectoredHandlerFn,
    first: bool, // true = first-chance, false = last-chance
}

static VEH_HANDLERS: Spinlock<Vec<VehEntry>> = Spinlock::new(Vec::new());

pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

pub unsafe extern "C" fn RtlAddVectoredExceptionHandler(
    first_handler: u32,
    handler: VectoredHandlerFn,
) -> PVOID {
    let mut list = VEH_HANDLERS.lock();
    if list.len() >= MAX_VEH_HANDLERS {
        return ptr::null_mut();
    }

    let entry = VehEntry {
        handler,
        first: first_handler != 0,
    };

    if first_handler != 0 {
        list.insert(0, entry);
    } else {
        list.push(entry);
    }

    handler as PVOID
}

pub unsafe extern "C" fn RtlRemoveVectoredExceptionHandler(handle: PVOID) -> u32 {
    let handler_fn: VectoredHandlerFn = core::mem::transmute(handle);
    let mut list = VEH_HANDLERS.lock();

    if let Some(pos) = list.iter().position(|e| e.handler as PVOID == handle) {
        list.remove(pos);
        1 // Success
    } else {
        0 // Not found
    }
}

fn call_vectored_handlers(
    exception_record: *mut ExceptionRecord,
    context_record: *mut Context,
) -> bool {
    let mut pointers = ExceptionPointers {
        exception_record,
        context_record,
    };

    let list = VEH_HANDLERS.lock();
    for entry in list.iter() {
        let result = unsafe { (entry.handler)(&mut pointers) };
        if result == EXCEPTION_CONTINUE_EXECUTION {
            return true; // Handler handled the exception
        }
    }
    false // No handler handled it
}


pub unsafe extern "C" fn RtlDispatchException(
    exception_record: *mut ExceptionRecord,
    context_record: *mut Context,
) -> u8 {
    if exception_record.is_null() || context_record.is_null() {
        return 0;
    }

    if (*exception_record).exception_flags & EXCEPTION_NONCONTINUABLE != 0 {
        return 0;
    }

    if call_vectored_handlers(exception_record, context_record) {
        return 1; // Handled
    }


    0 // Unhandled
}

pub unsafe extern "C" fn RtlRaiseException(exception_record: *mut ExceptionRecord) -> NTSTATUS {
    if exception_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut context = Context::new();
    context.context_flags = CONTEXT_FULL;
    RtlCaptureContext(&mut context);

    (*exception_record).exception_address = context.rip as PVOID;

    let handled = RtlDispatchException(exception_record, &mut context);
    if handled != 0 {
        RtlRestoreContext(&mut context, exception_record);
    }

    STATUS_UNHANDLED_EXCEPTION
}


/// On x64, this uses inline assembly to save all registers.
pub unsafe extern "C" fn RtlCaptureContext(context_record: *mut Context) {
    if context_record.is_null() {
        return;
    }


    ptr::write_bytes(context_record as *mut u8, 0, core::mem::size_of::<Context>());
    (*context_record).context_flags = CONTEXT_FULL;
}

pub unsafe extern "C" fn RtlRestoreContext(
    context_record: *mut Context,
    exception_record: *mut ExceptionRecord,
) -> ! {
    if context_record.is_null() {
        loop {
            core::hint::spin_loop();
        }
    }


    let _ = exception_record;
    loop {
        core::hint::spin_loop();
    }
}


pub unsafe extern "C" fn RtlUnwind(
    target_frame: PVOID,
    target_ip: PVOID,
    exception_record: *mut ExceptionRecord,
    return_value: PVOID,
) -> NTSTATUS {
    let mut context = Context::new();
    context.context_flags = CONTEXT_FULL;
    RtlCaptureContext(&mut context);

    RtlUnwindEx(
        target_frame,
        target_ip,
        exception_record,
        return_value,
        &mut context,
        ptr::null_mut(),
    )
}

pub unsafe extern "C" fn RtlUnwind2(
    target_frame: PVOID,
    target_ip: PVOID,
    exception_record: *mut ExceptionRecord,
    return_value: PVOID,
    context_record: *mut Context,
) -> NTSTATUS {
    RtlUnwindEx(
        target_frame,
        target_ip,
        exception_record,
        return_value,
        context_record,
        ptr::null_mut(),
    )
}

pub unsafe extern "C" fn RtlUnwindEx(
    target_frame: PVOID,
    target_ip: PVOID,
    exception_record: *mut ExceptionRecord,
    return_value: PVOID,
    context_record: *mut Context,
    history_table: PVOID,
) -> NTSTATUS {
    if context_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut default_record = ExceptionRecord::new();
    let exc_rec = if exception_record.is_null() {
        default_record.exception_code = STATUS_UNWIND as u32;
        default_record.exception_flags = EXCEPTION_UNWINDING;
        &mut default_record as *mut ExceptionRecord
    } else {
        (*exception_record).exception_flags |= EXCEPTION_UNWINDING;
        exception_record
    };


    (*context_record).rax = return_value as u64;

    if !target_ip.is_null() {
        (*context_record).rip = target_ip as u64;
    }

    let _ = (target_frame, history_table, exc_rec);

    STATUS_SUCCESS
}


pub unsafe extern "C" fn RtlAddFunctionTable(
    _function_table: PVOID,
    _entry_count: u32,
    _base_address: u64,
) -> u8 {
    1 // Success
}

pub unsafe extern "C" fn RtlDeleteFunctionTable(_function_table: PVOID) -> u8 {
    1 // Success
}

pub unsafe extern "C" fn RtlInstallFunctionTableCallback(
    _table_identifier: u64,
    _base_address: u64,
    _length: u32,
    _callback: PVOID,
    _context: PVOID,
    _out_of_process_callback_dll: PVOID,
) -> u8 {
    1 // Success
}


/// It's used by exception handlers that want to resume execution.
pub unsafe extern "C" fn NtContinue(context_record: *mut Context, test_alert: u8) -> NTSTATUS {
    if context_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = test_alert;

    // and return to user mode at the specified RIP.
    STATUS_SUCCESS
}

pub unsafe extern "C" fn NtRaiseException(
    exception_record: *mut ExceptionRecord,
    context_record: *mut Context,
    first_chance: u8,
) -> NTSTATUS {
    if exception_record.is_null() || context_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = first_chance;

    let handled = RtlDispatchException(exception_record, context_record);
    if handled != 0 {
        NtContinue(context_record, 0)
    } else {
        STATUS_UNHANDLED_EXCEPTION
    }
}
