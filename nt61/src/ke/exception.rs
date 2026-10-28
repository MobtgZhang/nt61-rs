//! SEH/x64 Exception Handling
//
//! Implements Windows x64 exception handling including:
//!   - Exception record structure
//!   - Context frame
//!   - Exception dispatch
//!   - Unwinding support
//!   - RUNTIME_FUNCTION table parsing
//!   - Hardware exception handling (breakpoints, single step, etc.)

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

/// Exception codes (similar to NT STATUS codes)
pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
pub const EXCEPTION_DIVIDE_BY_ZERO: u32 = 0xC0000094;
pub const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
pub const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
pub const EXCEPTION_INVALID_HANDLE: u32 = 0xC0000008;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
pub const EXCEPTION_PRIVILEGED_INSTRUCTION: u32 = 0xC0000096;
pub const EXCEPTION_DATATYPE_MISALIGNMENT: u32 = 0xC0000093;
pub const EXCEPTION_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
pub const EXCEPTION_FLT_STACK_CHECK: u32 = 0xC0000092;
pub const EXCEPTION_POSSIBLE_DEADLOCK: u32 = 0xC0000194;
pub const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;
pub const EXCEPTION_INVALID_DISPOSITION: u32 = 0xC0000026;
pub const EXCEPTION_NONCONTINUABLE_EXCEPTION: u32 = 0xC0000025;

/// Unwind operation codes (x64)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnwindOperationCode {
    PushUnwindHandler = 0x00,
    CopyData = 0x01,
    PushMachFrame = 0x02,
    AllocaHomed = 0x03,
    SetFp = 0x04,
    SaveIntNonVol = 0x08,
    SaveFltNonVol = 0x09,
    SaveXMM128 = 0x0A,
    SaveXMM128Mask = 0x0B,
    AllocLarge = 0x10,
    AllocSmall = 0x11,
    PrologEpilog = 0x12,
}

impl UnwindOperationCode {
    /// Get the operation code from the packed byte
    pub fn from_packed(packed: u8) -> Self {
        // x64 UNWIND_CODE operation numbers (PE/x64 ABI: bits 4-7 of the
        // operation byte carry the operation, bits 0-3 the operation info).
        // Ops this module does not model (UWOP_SAVE_NONVOL_FAR, deprecated
        // UWOP_SAVE_XMM) decode to the reserved no-op so a walk never
        // fabricates register or stack changes from them.
        match packed >> 4 {
            0x0 => Self::PushUnwindHandler, // UWOP_PUSH_NONVOL
            0x1 => Self::AllocLarge,        // UWOP_ALLOC_LARGE
            0x2 => Self::AllocSmall,        // UWOP_ALLOC_SMALL
            0x3 => Self::SetFp,             // UWOP_SET_FPREG
            0x4 => Self::SaveIntNonVol,     // UWOP_SAVE_NONVOL
            0x6 => Self::PrologEpilog,      // UWOP_EPILOG
            0x7 => Self::CopyData,          // UWOP_SPARE_CODE (reserved)
            0x9 => Self::SaveFltNonVol,     // UWOP_SAVE_XMM_FAR
            0xA => Self::SaveXMM128,        // UWOP_SAVE_XMM128
            0xB => Self::SaveXMM128Mask,    // UWOP_SAVE_XMM128_FAR
            0xC => Self::PushMachFrame,     // UWOP_PUSH_MACHFRAME
            // 0x5 UWOP_SAVE_NONVOL_FAR, 0x8 UWOP_SAVE_XMM: unmodelled.
            _ => Self::CopyData,
        }
    }
}

/// Unwind flags constants
pub mod unwind_flags {
    pub const EXCEPTION_HANDLER: u8 = 0x00;
    pub const TERMINATION_HANDLER: u8 = 0x01;
    pub const CROSS_INSTANCE: u8 = 0x02;
    pub const UNWIND_RA_SEARCH: u8 = 0x04;
    pub const UNWIND_RA_SIGNED: u8 = 0x08;
}

/// RUNTIME_FUNCTION entry for unwind tables (PDATA section)
/// Each entry is 12 bytes on x64
/// In PE files, this is stored in the .pdata section
#[derive(Clone)]
#[repr(C)]
pub struct RuntimeFunction {
    pub begin_address: u32,       // Function start RVA
    pub end_address: u32,         // Function end RVA (packed with flags in some formats)
    pub unwind_info_address: u32, // Unwind info RVA (can have flags in high bits)
}

impl RuntimeFunction {
    pub const fn new(begin: u32, end: u32, unwind: u32) -> Self {
        Self {
            begin_address: begin,
            end_address: end,
            unwind_info_address: unwind,
        }
    }

    /// Check if IP falls within this function's range
    pub fn contains_ip(&self, ip: u64, image_base: u64) -> bool {
        let rel_ip = (ip - image_base) as u32;
        rel_ip >= self.begin_address && rel_ip < self.end_address
    }

    /// Get the end address (masking off flags if present)
    pub fn get_end_address(&self) -> u32 {
        self.end_address & 0x7FFF_FFFF
    }
}

/// UNWIND_INFO structure (variable size, min 4 bytes)
#[repr(C, packed)]
pub struct UnwindInfo {
    pub version_and_flags: u8, // Bits 0-2: version (must be 1), Bit 3: exception flag, Bits 4-7: flags
    pub size_of_prologue: u8,
    pub count_of_codes: u8,
    pub frame_register_and_offset: u8, // Frame register (4 bits) and scaled offset (4 bits)
}

impl UnwindInfo {
    pub fn version(&self) -> u8 {
        self.version_and_flags & 0x07
    }

    pub fn has_exception_handler(&self) -> bool {
        (self.version_and_flags & 0x08) != 0
    }

    pub fn flags(&self) -> u8 {
        (self.version_and_flags >> 4) & 0x0F
    }

    /// Get the frame register (0-15, or 0 if not used)
    pub fn frame_register(&self) -> u8 {
        self.frame_register_and_offset >> 4
    }

    /// Get the scaled frame offset (multiplied by 16)
    pub fn frame_offset(&self) -> u8 {
        self.frame_register_and_offset & 0x0F
    }
}

/// UNWIND_CODE entry (always 2 bytes, sometimes followed by immediate operands)
#[repr(C, packed)]
pub struct UnwindCode {
    pub offset_in_prologue: u8,
    pub unwind_op_and_op_info: u8, // Upper 4 bits: operation, Lower 4 bits: operation-specific info
    pub operation_info: u16,       // Optional immediate operand (2 bytes)
}

impl UnwindCode {
    pub fn operation(&self) -> UnwindOperationCode {
        // from_packed expects the full operation byte (high nibble = op,
        // low nibble = operation info); do not pre-shift it here.
        UnwindOperationCode::from_packed(self.unwind_op_and_op_info)
    }

    pub fn operation_info(&self) -> u8 {
        self.unwind_op_and_op_info & 0x0F
    }

    /// Get the size for this unwind code entry (1 or 3 based on operation type)
    pub fn entry_size(&self) -> usize {
        match self.operation() {
            UnwindOperationCode::AllocLarge => {
                // op_info == 0: one 16-bit immediate slot; op_info == 1:
                // two slots forming a 32-bit immediate.
                if self.operation_info() == 0 {
                    2
                } else {
                    3
                }
            }
            // One immediate slot after the code slot.
            UnwindOperationCode::SaveIntNonVol
            | UnwindOperationCode::SaveFltNonVol
            | UnwindOperationCode::SaveXMM128
            | UnwindOperationCode::SaveXMM128Mask => 2,
            _ => 1,
        }
    }
}

/// Exception record
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub exception_information: [u64; 15],
}

impl ExceptionRecord {
    pub fn new(code: u32, address: u64) -> Self {
        Self {
            exception_code: code,
            exception_flags: 0,
            exception_record: core::ptr::null_mut(),
            exception_address: address,
            number_parameters: 0,
            exception_information: [0; 15],
        }
    }

    pub fn with_info(code: u32, address: u64, info: &[u64]) -> Self {
        let mut rec = Self::new(code, address);
        let count = info.len().min(15);
        rec.number_parameters = count as u32;
        for i in 0..count {
            rec.exception_information[i] = info[i];
        }
        rec
    }
}

/// Exception frame for x64
#[repr(C)]
pub struct ExceptionFrame {
    pub frame_offset: u64,
    pub return_address: u64,
    pub handler: u64,
}

/// Initialize exception handling
pub fn init() {
    // Exception handling is ready
}

/// Set up the initial exception handlers for a thread
pub fn setup_handlers(ethread: *mut crate::ps::thread::Ethread) {
    if ethread.is_null() {
        return;
    }

    unsafe {
        // Initialize the thread's exception list
        // In x64 Windows, FS:[0] points to the TEB which contains the exception list
        let teb = (*ethread).kthread.teb;
        if !teb.is_null() {
            // Set up initial exception handler chain
            // The chain starts with a termination handler that calls rtl_unwind
            // // kprintln!("[EXCEPTION] Set up exception handlers for thread");
        }
    }
}

/// Dispatch an exception to the appropriate handler
///
/// This is the main entry point for exception dispatch. It tries various
/// handler types in order until one handles the exception or all are exhausted.
pub fn dispatch_exception(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> ExceptionDisposition {
    // // kprintln!(
    // //         "[EXCEPTION] Dispatching exception 0x{:08x} at address 0x{:016x}",
    // //         exception_record.exception_code,
    // //         exception_record.exception_address
    // //     );

    // 1. First, try the current thread's registered exception handlers
    if let Some(result) = try_current_thread_handler(exception_record, context_frame) {
        return result;
    }

    // 2. Try kernel-registered global handlers
    let result = dispatch_to_handlers(exception_record, context_frame);
    if result != ExceptionDisposition::ContinueSearch {
        return result;
    }

    // 3. Try to find a handler via RUNTIME_FUNCTION tables
    if let Some(result) = try_runtime_function_handler(exception_record, context_frame) {
        return result;
    }

    // 4. If this is a user-mode exception, terminate the process. Windows
    //    never resumes a user thread after an unhandled exception: doing so
    //    returns control to a fault that has no handler and repeats forever.
    if is_user_mode_exception(exception_record) {
        terminate_current_user_process(exception_record.exception_code);
    }

    // 5. Kernel-mode exception - trigger bugcheck
    // An unhandled kernel-mode exception is fatal. Returning
    // ContinueSearch here let the caller resume on a stack frame that
    // is already inconsistent with the faulting instruction, so the
    // kernel keeps running with corrupted state and the real damage
    // shows up later as an unrelated failure.
    //
    // Windows 7 raises KERNEL_MODE_EXCEPTION_NOT_HANDLED (0x8E) at
    // this point: param1 is the exception code, param2 the exception
    // address, and params 3-4 are unused.
    crate::ke::bugcheck::bugcheck_with(
        crate::ke::bugcheck::BugCheckCode::KernelModeExceptionNotHandled,
        exception_record.exception_code as u64,
        exception_record.exception_address,
        0,
        0,
    );
}

/// Check if an exception occurred in user mode
///
/// User-mode addresses are in the range 0x1000 to 0x7FFFFFFFFFFF
pub(crate) fn is_user_mode_exception(exception_record: &ExceptionRecord) -> bool {
    let addr = exception_record.exception_address;
    // User mode: not in kernel address space
    // Kernel addresses on x64 Windows typically start at 0xFFFF800000000000
    addr < 0xFFFF800000000000 && addr >= 0x1000
}

/// Terminate the current process after an unhandled user-mode exception.
///
/// This function deliberately never returns. If another ready thread can be
/// dispatched, the scheduler switches to it; otherwise the faulting CPU parks.
fn terminate_current_user_process(exception_code: u32) -> ! {
    let current_thread = crate::arch::common::percpu::get_current_thread();
    let current_process = if current_thread.is_null() {
        crate::arch::common::percpu::get_current_process()
    } else {
        unsafe { (*current_thread).threads_process }
    };

    if !current_process.is_null() {
        unsafe {
            (*current_process).exit_status = exception_code as i32;
        }
    }

    if !current_thread.is_null() {
        crate::ps::thread::terminate(current_thread, exception_code);
    }

    if !current_process.is_null() {
        let pid = unsafe { (*current_process).unique_process_id };
        let _ = crate::ps::process_mgmt::terminate_process_by_pid(pid, false);
    }

    crate::arch::common::percpu::set_current_process(core::ptr::null_mut());
    crate::ke::scheduler::schedule();

    loop {
        crate::arch::halt();
    }
}

/// Try the current thread's registered exception handler
fn try_current_thread_handler(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> Option<ExceptionDisposition> {
    // Delegate to the TEB exception list walker, which reads the
    // current thread's registered handler chain and invokes each
    // handler with the standard x64 calling convention.
    // SAFETY: exception_record is read-only here; walk_teb_exception_list
    // requires a mutable reference because handlers may update the record.
    let mut record = exception_record.clone();
    walk_teb_exception_list(&mut record, context_frame)
}

/// Try to find and invoke a handler via RUNTIME_FUNCTION tables
fn try_runtime_function_handler(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> Option<ExceptionDisposition> {
    let ip = exception_record.exception_address;

    // Find RUNTIME_FUNCTION for the current instruction pointer
    if let Some(func) = find_runtime_function_for_ip(ip) {
        // // kprintln!(
        // //             "[EXCEPTION] Found RUNTIME_FUNCTION for IP 0x{:016x}: [0x{:08x}-0x{:08x}]",
        // //             ip, func.begin_address, func.end_address
        // //         );

        // Get image base (would need proper implementation)
        let image_base = get_image_base_for_ip(ip)?;

        // Get unwind info
        let unwind_info_ptr = get_unwind_info_ptr(image_base, &func)?;

        // Check if there's an exception handler
        if has_exception_handler(unwind_info_ptr) {
            let handler_data = get_handler_data(unwind_info_ptr);

            // // kprintln!(
            // //                 "[EXCEPTION] Exception handler found, calling handler..."
            // //             );

            // Call the exception handler
            return Some(call_exception_handler(
                exception_record,
                context_frame,
                image_base,
                &func,
                handler_data,
            ));
        }
    }

    None
}

/// Call an exception handler with proper setup
fn call_exception_handler(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
    image_base: u64,
    _function_entry: &RuntimeFunction,
    handler_data: *const u8,
) -> ExceptionDisposition {
    // handler_data points to the handler RVA (a u32) followed by
    // handler-specific data. Read the RVA and compute the absolute
    // handler address.
    if handler_data.is_null() {
        return ExceptionDisposition::ContinueSearch;
    }
    let handler_rva = unsafe { core::ptr::read(handler_data as *const u32) };
    if handler_rva == 0 {
        return ExceptionDisposition::ContinueSearch;
    }
    let handler_addr = image_base + handler_rva as u64;

    // Build a minimal DispatcherContext on the stack. Language
    // exceptions that need full unwinding will receive a zeroed
    // context, which is sufficient for ContinueSearch / ExceptionHandled
    // semantics at this stage.
    #[repr(C)]
    struct DispatcherContext {
        control_pc: u64,
        image_base: u64,
        function_entry: u64,
        establisher_frame: u64,
        target_ip: u64,
        context: *mut ContextFrame,
        language_handler: u64,
        handler_data_ptr: u64,
    }
    let mut dispatch = DispatcherContext {
        control_pc: exception_record.exception_address,
        image_base,
        function_entry: 0,
        establisher_frame: 0,
        target_ip: 0,
        context: context_frame as *mut _,
        language_handler: 0,
        handler_data_ptr: handler_data as u64,
    };

    // The x64 handler signature:
    //   EXCEPTION_DISPOSITION (*handler)(
    //       PEXCEPTION_RECORD, u64 establisher,
    //       PCONTEXT, PDISPATCHER_CONTEXT)
    type HandlerFn = extern "C" fn(
        *mut ExceptionRecord,
        u64,
        *mut ContextFrame,
        *mut DispatcherContext,
    ) -> ExceptionDisposition;

    let result = unsafe {
        let handler_fn = core::mem::transmute::<u64, HandlerFn>(handler_addr);
        let mut record = exception_record.clone();
        handler_fn(
            &mut record as *mut ExceptionRecord,
            0,
            context_frame,
            &mut dispatch,
        )
    };

    if result != ExceptionDisposition::ContinueSearch {
        record_handler_invocation();
    }
    result
}

/// Perform stack unwinding
///
/// Walks the stack from `start_context` via the RUNTIME_FUNCTION tables,
/// applying each frame's UNWIND_CODE operations (register/stack restore)
/// with `rtl_virtual_unwind`, until the establisher frame reaches
/// `target_frame`.
///
/// This is a frame-walk unwind only: handler routines of the unwound frames
/// are not executed (this kernel cannot run user-mode handler code, matching
/// `ntdll::rtl_unwind_ex`'s documented limitation). The returned context is
/// the restored state at the target frame, ready for the caller to resume.
///
/// Returns `Err(())` when the walk cannot reach `target_frame`: unknown
/// instruction pointer, missing unwind metadata, unreadable return address,
/// or the frame-count guard tripping. Callers must not treat a fabricated
/// context as an unwind result.
pub fn unwind(
    start_context: &ContextFrame,
    target_frame: u64,
    _exception_record: Option<&ExceptionRecord>,
) -> Result<ContextFrame, ()> {
    let mut context = start_context.clone();
    const MAX_UNWIND_FRAMES: usize = 100;

    for _ in 0..MAX_UNWIND_FRAMES {
        // The walk stops at the target frame: the frame whose establisher
        // frame is `target_frame` receives the exception, so its prologue
        // effects are not reversed here.
        let function_entry = match find_runtime_function_for_ip(context.rip) {
            Some(entry) => entry,
            None => return Err(()),
        };
        let image_base = match get_image_base_for_ip(context.rip) {
            Some(base) => base,
            None => return Err(()),
        };

        let mut handler_data: *const u8 = core::ptr::null();
        let mut establisher_frame: u64 = 0;
        let return_pc = rtl_virtual_unwind(
            image_base,
            context.rip,
            &function_entry,
            &mut context,
            &mut handler_data,
            &mut establisher_frame,
        );
        if return_pc == 0 {
            return Err(());
        }
        context.rip = return_pc;

        if establisher_frame >= target_frame {
            return Ok(context);
        }
    }

    Err(())
}

/// Continue searching for an exception handler
pub fn continue_search() -> ExceptionDisposition {
    ExceptionDisposition::ContinueSearch
}

/// Exception disposition
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDisposition {
    ExceptionHandled = 0,
    ContinueSearch = 1,
    NestedException = 2,
    CollidedUnwind = 3,
}

/// Context frame for exception handling (mirrors CONTEXT from ntdll)
#[repr(C)]
#[derive(Clone)]
pub struct ContextFrame {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub cs: u16,
    pub efl: u16,
    pub gs: u16,
    pub fs: u16,
    pub es: u16,
    pub ds: u16,
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
}

impl ContextFrame {
    pub fn new() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0,
            mx_csr: 0,
            cs: 0x10,   // Kernel code segment
            efl: 0x202, // IF=1
            gs: 0,
            fs: 0,
            es: 0,
            ds: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
        }
    }
}

/// Raise a software exception
pub fn raise_exception(_code: u32, _address: u64) {
    // _code and _address are intentionally unused - reserved for future implementation
    // // kprintln!("[EXCEPTION] Software exception raised: code=0x{:08x}", code);

    // In a real implementation, this would:
    // 1. create an exception record
    // 2. Dispatch to the kernel's exception handler
    // 3. Either handle it or unwind
}

/// Check for breakpoint exception
pub fn is_breakpoint(exception_code: u32) -> bool {
    exception_code == EXCEPTION_BREAKPOINT
}

/// Check for access violation
pub fn is_access_violation(exception_code: u32) -> bool {
    exception_code == EXCEPTION_ACCESS_VIOLATION
}

/// Check for divide by zero
pub fn is_divide_by_zero(exception_code: u32) -> bool {
    exception_code == EXCEPTION_DIVIDE_BY_ZERO
}

// =============================================================================
// Exception Dispatcher (x64)
// =============================================================================

/// Exception handler function type
pub type ExceptionHandler = extern "C" fn(
    *mut ExceptionRecord,
    u64,
    *mut ContextFrame,
    *mut ContextFrame,
) -> ExceptionDisposition;

/// Exception registration record (linked list node)
#[repr(C)]
pub struct ExceptionRegistration {
    pub next: *mut ExceptionRegistration,
    pub handler: u64,
}

impl ExceptionRegistration {
    pub fn new(handler: u64) -> Self {
        Self {
            next: core::ptr::null_mut(),
            handler,
        }
    }
}

/// Global exception handler chain (for kernel)
static KERNEL_EXCEPTION_HANDLERS: Spinlock<Vec<ExceptionRegistration>> = Spinlock::new(Vec::new());

use crate::ke::sync::Spinlock;

pub use crate::arch::common::hardware_exception;

/// Register an exception handler
pub fn register_handler(handler: ExceptionHandler) {
    let mut handlers = KERNEL_EXCEPTION_HANDLERS.lock();
    let reg = ExceptionRegistration::new(handler as u64);
    handlers.push(reg);
    // // kprintln!("[EXCEPTION] Registered exception handler");
}

/// Unregister an exception handler
pub fn unregister_handler(handler: ExceptionHandler) {
    let mut handlers = KERNEL_EXCEPTION_HANDLERS.lock();
    handlers.retain(|r| r.handler != handler as u64);
    // // kprintln!("[EXCEPTION] Unregistered exception handler");
}

/// Dispatch exception to registered handlers
fn dispatch_to_handlers(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> ExceptionDisposition {
    let handlers = KERNEL_EXCEPTION_HANDLERS.lock();

    for reg in handlers.iter() {
        let handler_fn = unsafe { core::mem::transmute::<_, ExceptionHandler>(reg.handler) };
        let disp = handler_fn(
            exception_record as *const _ as *mut _,
            0, // EstablisherFrame
            context_frame as *const _ as *mut _,
            core::ptr::null_mut(), // DispatcherContext
        );

        if disp != ExceptionDisposition::ContinueSearch {
            return disp;
        }
    }

    ExceptionDisposition::ContinueSearch
}

/// Full exception dispatch with handler search
pub fn dispatch_exception_full(
    exception_record: &mut ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> ExceptionDisposition {
    // // kprintln!(
    // //         "[EXCEPTION] Full dispatch: code=0x{:08x} addr=0x{:016x}",
    // //         exception_record.exception_code,
    // //         exception_record.exception_address
    // //     );

    // First, try registered handlers
    let result = dispatch_to_handlers(exception_record, context_frame);
    if result != ExceptionDisposition::ContinueSearch {
        return result;
    }

    // Then, search the RUNTIME_FUNCTION tables
    // This would be implemented in a full PE loader integration
    // For now, return ContinueSearch which leads to process termination

    // // kprintln!("[EXCEPTION] No handler found, will terminate process");
    ExceptionDisposition::ContinueSearch
}

// =============================================================================
// Access Violation Handler
// =============================================================================

/// handle access violation with detailed information
pub fn handle_access_violation(_address: u64, _write: bool, _execute: bool) -> Option<u64> {
    // _address, _write, and _execute are intentionally unused - reserved for future logging
    // // kprintln!(
    // //         "[EXCEPTION] Access Violation at 0x{:016x} write={} execute={}",
    // //         _address, _write, _execute
    // //     );

    // In a real implementation:
    // 1. Check if address is in a valid VAD region
    // 2. If not committed, commit the page (demand zero)
    // 3. If guard page, handle guard page fault
    // 4. If in user space and no valid handler, terminate

    None // Cannot handle
}

// =============================================================================
// Debug Exception Support
// =============================================================================

/// Breakpoint handler (ContextFrame version)
pub fn handle_breakpoint_context(_context: &mut ContextFrame) {
    // _context is intentionally unused - reserved for future logging
    // // kprintln!("[EXCEPTION] Breakpoint at RIP=0x{:016x}", _context.rip);

    // Step over the breakpoint instruction
    // In real Windows, this decrements RIP to step back
    // For now, just continue
}

/// Single step handler
pub fn handle_single_step(context: &mut ContextFrame) {
    // // kprintln!("[EXCEPTION] Single step at RIP=0x{:016x}", context.rip);

    // Clear the trap flag in RFLAGS
    context.efl &= !(1 << 8);
}

// =============================================================================
// Exception Statistics
// =============================================================================

static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
static HANDLE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Get exception statistics
pub fn get_stats() -> (u64, u64) {
    (
        EXCEPTION_COUNT.load(Ordering::Relaxed),
        HANDLE_COUNT.load(Ordering::Relaxed),
    )
}

/// Increment exception count
pub fn record_exception() {
    EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Increment handler count
pub fn record_handler_invocation() {
    HANDLE_COUNT.fetch_add(1, Ordering::Relaxed);
}

// =============================================================================
// RUNTIME_FUNCTION Table Management (for PE images)
// =============================================================================

/// A loaded PE image's exception/unwind information
pub struct ImageExceptionInfo {
    pub image_base: u64,
    pub runtime_functions: Vec<RuntimeFunction>,
    pub unwind_info_base: u64,
}

impl ImageExceptionInfo {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            runtime_functions: Vec::new(),
            unwind_info_base: 0,
        }
    }

    /// Find the RUNTIME_FUNCTION entry containing the given instruction pointer
    pub fn find_function_for_ip(&self, ip: u64) -> Option<&RuntimeFunction> {
        let rel_ip = ip.checked_sub(self.image_base)? as u32;
        self.runtime_functions
            .iter()
            .find(|f| rel_ip >= f.begin_address && rel_ip < f.end_address)
    }
}

/// Global database of loaded images' exception information
static IMAGE_EXCEPTION_DB: Spinlock<Vec<ImageExceptionInfo>> = Spinlock::new(Vec::new());

/// Register a PE image's RUNTIME_FUNCTION table
pub fn register_image_runtime_functions(
    image_base: u64,
    functions: &[RuntimeFunction],
    unwind_base: u64,
) {
    let mut db = IMAGE_EXCEPTION_DB.lock();
    db.push(ImageExceptionInfo {
        image_base,
        runtime_functions: functions.to_vec(),
        unwind_info_base: unwind_base,
    });
    // // kprintln!(
    // //         "[EXCEPTION] Registered {} RUNTIME_FUNCTION entries for image @ 0x{:016x}",
    // //         functions.len(),
    // //         image_base
    // //     );
}

/// Unregister a PE image's exception information
pub fn unregister_image_exception_info(image_base: u64) {
    let mut db = IMAGE_EXCEPTION_DB.lock();
    db.retain(|info| info.image_base != image_base);
    // // kprintln!("[EXCEPTION] Unregistered exception info for image @ 0x{:016x}", image_base);
}

/// Find RUNTIME_FUNCTION for an IP across all loaded images
pub fn find_runtime_function_for_ip(ip: u64) -> Option<RuntimeFunction> {
    let db = IMAGE_EXCEPTION_DB.lock();
    for info in db.iter() {
        if ip >= info.image_base && ip < info.image_base + 0xFFFF_FFFF {
            if let Some(func) = info.find_function_for_ip(ip) {
                return Some(func.clone());
            }
        }
    }
    None
}

/// Get the unwind info for a RUNTIME_FUNCTION entry
pub fn get_unwind_info(func: &RuntimeFunction, image_base: u64) -> Option<&'static UnwindInfo> {
    // Mask off the UNW_FLAG_* chain flag bits (bits 31-30) to get
    // the actual RVA of the unwind info structure.
    let unwind_rva = func.unwind_info_address & 0x1FFF_FFFF;
    let unwind_ptr = (image_base + unwind_rva as u64) as *const UnwindInfo;
    unsafe {
        if unwind_ptr.is_null() {
            return None;
        }
        Some(&*unwind_ptr)
    }
}

/// Get the unwind info pointer for a RUNTIME_FUNCTION entry
fn get_unwind_info_ptr(image_base: u64, func: &RuntimeFunction) -> Option<*const UnwindInfo> {
    // Mask off the UNW_FLAG_* chain flag bits (bits 31-30) to get
    // the actual RVA of the unwind info structure.
    let unwind_rva = func.unwind_info_address & 0x1FFF_FFFF;
    let unwind_ptr = (image_base + unwind_rva as u64) as *const UnwindInfo;
    if unwind_ptr.is_null() {
        None
    } else {
        Some(unwind_ptr)
    }
}

/// Check if an unwind info has an exception handler
fn has_exception_handler(unwind_info_ptr: *const UnwindInfo) -> bool {
    if unwind_info_ptr.is_null() {
        return false;
    }
    unsafe { (*unwind_info_ptr).has_exception_handler() }
}

/// Get the exception handler data pointer from unwind info
fn get_handler_data(unwind_info_ptr: *const UnwindInfo) -> *const u8 {
    if unwind_info_ptr.is_null() {
        return core::ptr::null();
    }
    unsafe {
        let unwind_info = &*unwind_info_ptr;
        // Handler data comes after the UNWIND_CODE array
        // UNWIND_CODE is 2 bytes each, array is count_of_codes long
        let codes_size = (unwind_info.count_of_codes as usize) * 2;
        let data_ptr = (unwind_info_ptr as *const u8)
            .add(core::mem::size_of::<UnwindInfo>())
            .add(codes_size);
        data_ptr
    }
}

/// Get image base for an instruction pointer
///
/// This is a simplified version that searches the registered images.
fn get_image_base_for_ip(ip: u64) -> Option<u64> {
    let db = IMAGE_EXCEPTION_DB.lock();
    for info in db.iter() {
        // Require that the IP maps to an actual function entry in
        // this image's RUNTIME_FUNCTION table, not just a loose
        // address-range check.
        if info.find_function_for_ip(ip).is_some() {
            return Some(info.image_base);
        }
    }
    None
}

// =============================================================================
// RtlVirtualUnwind Implementation
// =============================================================================

/// RtlVirtualUnwind - Performs virtual stack unwinding for exception handling
///
/// This is the core x64 exception unwinding function. It reverses the effects
/// of a function's prologue to recover the caller's register state.
///
/// # Arguments
/// * `image_base` - Base address of the PE image
/// * `control_pc` - Current instruction pointer
/// * `function_entry` - RUNTIME_FUNCTION entry for this function
/// * `context_record` - Current context, updated with restored state
/// * `handler_data` - Output: pointer to exception handler data (if any)
/// * `establisher_frame` - Output: frame pointer of the function being unwound
///
/// # Returns
/// The instruction pointer of the caller (the return address)
pub fn rtl_virtual_unwind(
    image_base: u64,
    control_pc: u64,
    function_entry: &RuntimeFunction,
    context_record: &mut ContextFrame,
    handler_data: &mut *const u8,
    establisher_frame: &mut u64,
) -> u64 {
    // Calculate the RVA of the control PC
    let _rva = (control_pc - image_base) as u32;
    // _rva is intentionally unused - reserved for future logging

    // // kprintln!(
    // //         "[UNWIND] RtlVirtualUnwind: image_base=0x{:016x}, control_pc=0x{:016x}, rva=0x{:08x}",
    // //         image_base, control_pc, _rva
    // //     );

    // Get the unwind info for this function
    let unwind_info_ptr =
        (image_base + function_entry.unwind_info_address as u64) as *const UnwindInfo;

    if unwind_info_ptr.is_null() {
        // // kprintln!("[UNWIND] ERROR: null unwind info");
        return 0;
    }

    unsafe {
        let unwind_info = &*unwind_info_ptr;

        // // kprintln!(
        // //             "[UNWIND] UnwindInfo: version={}, prologue_size={}, codes={}, flags=0x{:x}",
        // //             unwind_info.version(),
        // //             unwind_info.size_of_prologue,
        // //             unwind_info.count_of_codes,
        // //             unwind_info.flags()
        // //         );

        // Calculate the establisher frame (the frame pointer for this function)
        // This is typically RSP at entry, or RBP if frame pointer is used
        let frame_reg = unwind_info.frame_register();
        if frame_reg == 0 {
            // No frame register - use RSP
            *establisher_frame = context_record.rsp;
        } else {
            // Frame register is set
            let offset = unwind_info.frame_offset() as u64 * 16;
            *establisher_frame = context_record.rsp + offset;
        }

        // Check for exception handler (has handler data)
        *handler_data = core::ptr::null();
        if unwind_info.has_exception_handler() {
            // Calculate handler data pointer (after UNWIND_CODE array)
            // UnwindInfo is 4 bytes, then UNWIND_CODE array (count * 2 bytes each)
            let codes_ptr = (unwind_info_ptr as *const u8).add(4);
            *handler_data = codes_ptr.add((unwind_info.count_of_codes as usize) * 2);
            // // kprintln!("[UNWIND] Exception handler present, data at {:p}", *handler_data);
        }

        // Process UNWIND_CODE array in REVERSE order
        // The codes are stored in reverse order in the array
        // UNWIND_INFO (4 bytes) + UNWIND_CODE[count] (2 bytes each)
        let codes_base = (unwind_info_ptr as *const u8).add(4) as *const UnwindCode;
        let mut code_index = unwind_info.count_of_codes as usize;
        while code_index > 0 {
            code_index -= 1;

            let code = &*codes_base.add(code_index);

            apply_unwind_code(
                context_record,
                code,
                *establisher_frame,
                unwind_info.size_of_prologue,
            );
        }

        // Get the return address from the stack
        let return_address = core::ptr::read(context_record.rsp as *const u64);

        // Update the stack pointer
        context_record.rsp += 8;

        // // kprintln!(
        // //             "[UNWIND] Unwound to return_addr=0x{:016x}, new_rsp=0x{:016x}",
        // //             return_address, context_record.rsp
        // //         );

        return_address
    }
}

/// Apply a single UNWIND_CODE operation to restore register state
///
/// This function reverses the effects of function prologue operations
/// to restore the caller's register state during stack unwinding.
fn apply_unwind_code(
    context: &mut ContextFrame,
    code: &UnwindCode,
    establisher_frame: u64,
    _prologue_size: u8,
) {
    let operation = code.operation();
    let op_info = code.operation_info();
    let _ = establisher_frame; // Reserved for future use

    match operation {
        UnwindOperationCode::PushUnwindHandler => {
            // UWOP_PUSH_NONVOL: the prologue pushed a nonvolatile register
            // (8 bytes); unwinding pops it back off the stack.
            context.rsp += 8;
        }

        UnwindOperationCode::CopyData => {
            // Reserved for special cases
            // // kprintln!("[UNWIND] CopyData (reserved)");
        }

        UnwindOperationCode::PushMachFrame => {
            // Machine frame was pushed on the stack
            // For unwind, we need to simulate popping this frame
            // // kprintln!("[UNWIND] PushMachFrame (reverse)");
            // The registers were saved by hardware, no unwind action needed
        }

        UnwindOperationCode::AllocaHomed => {
            // Stack was adjusted by alloca - need to read 16-bit offset
            let offset = unsafe { unwind_code_offset_16(code) } as u64;
            context.rsp += offset;
            // // kprintln!("[UNWIND] AllocaHomed: rsp += 0x{:x}", offset);
        }

        UnwindOperationCode::SetFp => {
            // Frame pointer was set to RSP + scaled offset
            // The actual frame pointer restoration is handled by establisher_frame
            let _offset = unwind_code_offset(code);
            // // kprintln!("[UNWIND] SetFp: frame_offset={}", _offset);
        }

        UnwindOperationCode::SaveIntNonVol => {
            // UWOP_SAVE_NONVOL: the slot after the code holds the save
            // offset divided by 8.
            let offset = (code.operation_info as u64) * 8;
            let sp = context.rsp + offset;
            let reg_val = unsafe { core::ptr::read(sp as *const u64) };

            match op_info {
                0 => context.rax = reg_val,
                1 => context.rcx = reg_val,
                2 => context.rdx = reg_val,
                3 => context.rbx = reg_val,
                4 => context.rsp = reg_val,
                5 => context.rbp = reg_val,
                6 => context.rsi = reg_val,
                7 => context.rdi = reg_val,
                8 => context.r8 = reg_val,
                9 => context.r9 = reg_val,
                10 => context.r10 = reg_val,
                11 => context.r11 = reg_val,
                12 => context.r12 = reg_val,
                13 => context.r13 = reg_val,
                14 => context.r14 = reg_val,
                15 => context.r15 = reg_val,
                _ => {}
            }
            // // kprintln!(
            // //                 "[UNWIND] SaveIntNonVol: restore reg{} = 0x{:016x} from [rsp+0x{:x}]",
            // //                 op_info, reg_val, offset
            // //             );
        }

        UnwindOperationCode::SaveFltNonVol => {
            // Restore non-volatile float register
            // Format: UNWIND_CODE (2 bytes) + offset (1 byte)
            let _offset = unsafe { read_int_nvol_offset(code) } as u64;
            let _reg_idx = op_info;
            // // kprintln!(
            // //                 "[UNWIND] SaveFltNonVol: would restore xmm{} from [rsp+0x{:x}]",
            // //                 _reg_idx + 6, _offset
            // //             );
            // Note: Full implementation would restore XMM6-XMM15
        }

        UnwindOperationCode::SaveXMM128 => {
            // Restore 128-bit XMM register
            // Format: UNWIND_CODE (2 bytes) + offset (2 bytes)
            let offset = unsafe { unwind_code_offset_16(code) } as u64;
            let _sp = context.rsp + offset;
            // // kprintln!(
            // //                 "[UNWIND] SaveXMM128: would restore xmm{} from [rsp+0x{:x}]",
            // //                 op_info, offset
            // //             );
            // Note: Full implementation would restore full 128-bit XMM register
        }

        UnwindOperationCode::SaveXMM128Mask => {
            // Save XMM registers with mask - rare operation
            // // kprintln!("[UNWIND] SaveXMM128Mask (rare, op_info={})", op_info);
        }

        UnwindOperationCode::AllocLarge => {
            // Large stack allocation (> 0xFF80 bytes)
            // UWOP_ALLOC_LARGE: with op_info == 0 the size divided by 8 is
            // a 16-bit value in the next slot; with op_info == 1 it is a
            // 32-bit value in the two following slots.
            let scaled_size = if op_info == 0 {
                (unsafe { code_ptr_read_16(code) }) as u64
            } else {
                (unsafe { code_ptr_read_32(code) }) as u64
            };
            context.rsp += scaled_size * 8;
            // // kprintln!("[UNWIND] AllocLarge: rsp += 0x{:x}", size);
        }

        UnwindOperationCode::AllocSmall => {
            // Small stack allocation: 8 * (op_info + 1) bytes
            let size = (op_info as u64 + 1) * 8;
            context.rsp += size;
            // // kprintln!("[UNWIND] AllocSmall: rsp += 0x{:x}", size);
        }

        UnwindOperationCode::PrologEpilog => {
            // Combined prolog/epilog - rare
            // // kprintln!("[UNWIND] PrologEpilog (combined, rare)");
        }
    }
}

/// read offset for SaveIntNonVol and SaveFltNonVol operations
/// These have a 1-byte offset following the UNWIND_CODE structure
///
/// # Safety
/// Caller must ensure the UNWIND_CODE is followed by at least 1 byte of valid memory
unsafe fn read_int_nvol_offset(code: &UnwindCode) -> u16 {
    // The offset byte follows the UNWIND_CODE structure at offset 2
    let code_ptr = (code as *const UnwindCode as *const u8).add(2);
    ptr::read(code_ptr) as u16
}

/// read a 16-bit value from the UNWIND_CODE's immediate field
fn unwind_code_offset(code: &UnwindCode) -> u8 {
    code.operation_info()
}

/// read a 16-bit immediate value following the UNWIND_CODE structure
///
/// UNWIND_CODE is a packed 2-byte structure. For operations that have
/// a 16-bit immediate following (AllocLarge, SaveXMM128), we need to
/// read from offset 2 within the operation info field.
///
/// # Safety
/// Caller must ensure the UNWIND_CODE is followed by at least 2 bytes of valid memory
unsafe fn unwind_code_offset_16(code: &UnwindCode) -> u16 {
    // For SaveXMM128 and similar: 16-bit offset follows the UNWIND_CODE
    // We use read_unaligned to handle potentially unaligned access
    let code_ptr = (code as *const UnwindCode as *const u8).add(2);
    core::ptr::read_unaligned(code_ptr as *const u16)
}

/// read a 16-bit value from the operation_info field
/// For operations like AllocSmall where size is encoded in op_info
///
/// Reads the 16-bit immediate that follows the operation byte. With the
/// packed `UnwindCode` layout this is the slot at +2 (the `operation_info`
/// field); the unaligned read handles packed-struct bases.
///
/// # Safety
/// Caller must ensure the two bytes after the UNWIND_CODE operation byte
/// are valid memory.
pub unsafe fn code_ptr_read_16(code: &UnwindCode) -> u16 {
    let code_ptr = (code as *const UnwindCode as *const u8).add(2);
    core::ptr::read_unaligned(code_ptr as *const u16)
}

/// read a 32-bit immediate value following the UNWIND_CODE structure
///
/// For AllocLarge operation, a 32-bit size follows the UNWIND_CODE.
///
/// # Safety
/// Caller must ensure the four bytes after the UNWIND_CODE operation byte
/// are valid memory.
pub unsafe fn code_ptr_read_32(code: &UnwindCode) -> u32 {
    let code_ptr = (code as *const UnwindCode as *const u8).add(2);
    core::ptr::read_unaligned(code_ptr as *const u32)
}

/// read a 32-bit value from a specific offset in the unwind info
/// This is the correct way to read extended data after UNWIND_CODE
///
/// # Safety
/// Caller must ensure the offset is within bounds of the unwind info
pub unsafe fn read_unwind_info_32(base: *const UnwindInfo, offset_bytes: usize) -> u32 {
    let ptr = (base as *const u8).add(offset_bytes) as *const u32;
    ptr.read_unaligned()
}

/// RtlLookupFunctionEntry - Find the RUNTIME_FUNCTION for an instruction pointer
///
/// Searches the registered image exception databases for a matching function entry.
pub fn rtl_lookup_function_entry(
    control_pc: u64,
    image_base: &mut u64,
    _handler_data: &mut *const u8,
) -> Option<RuntimeFunction> {
    let db = IMAGE_EXCEPTION_DB.lock();

    for info in db.iter() {
        // Check if control_pc is within this image's range
        if control_pc >= info.image_base && control_pc < info.image_base + 0x1_0000_0000 {
            *image_base = info.image_base;

            // Find the function containing this IP
            if let Some(func) = info.find_function_for_ip(control_pc) {
                // // kprintln!(
                // //                     "[UNWIND] RtlLookupFunctionEntry: found function [0x{:08x}-0x{:08x}] for IP 0x{:016x}",
                // //                     func.begin_address, func.end_address, control_pc
                // //                 );
                return Some(func.clone());
            }
        }
    }

    None
}

/// Apply UNWIND_INFO to a context frame
/// This reverses the effects of the function prologue
pub fn apply_unwind_info(info: &UnwindInfo, context: &mut ContextFrame) -> u64 {
    let frame_base = context.rsp;
    let frame_reg = info.frame_register();
    let frame_offset = info.frame_offset() as u64 * 16;

    if frame_reg != 0 {
        // Frame pointer is set to RSP + scaled offset
        match frame_reg {
            4 => context.rbp = frame_base + frame_offset,
            5 => context.rsi = frame_base + frame_offset,
            6 => context.rdi = frame_base + frame_offset,
            7 => context.r8 = frame_base + frame_offset,
            8 => context.r9 = frame_base + frame_offset,
            9 => context.r10 = frame_base + frame_offset,
            10 => context.r11 = frame_base + frame_offset,
            11 => context.r12 = frame_base + frame_offset,
            12 => context.r13 = frame_base + frame_offset,
            13 => context.r14 = frame_base + frame_offset,
            14 => context.r15 = frame_base + frame_offset,
            _ => {}
        }
    }

    // For compatibility, delegate to the main RtlVirtualUnwind path
    // // kprintln!(
    // //         "[EXCEPTION] apply_unwind_info: frame_reg={}, frame_offset=0x{:x}",
    // //         frame_reg, frame_offset
    // //     );
    0
}

// =============================================================================
// rtl_dispatch_exception Implementation
// =============================================================================

/// Exception handler callback function type
pub type ExceptionFilter = extern "C" fn(
    *mut ExceptionRecord,
    u64, // EstablisherFrame
    *mut ContextFrame,
    *mut ContextFrame, // DispatcherContext
) -> ExceptionDisposition;

/// rtl_dispatch_exception walks the handler chain and calls each handler
/// until one handles the exception or the chain is exhausted.
pub fn rtl_dispatch_exception(
    exception_record: &mut ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> ExceptionDisposition {
    record_exception();

    // // kprintln!(
    // //         "[EXCEPTION] rtl_dispatch_exception: code=0x{:08x} addr=0x{:016x}",
    // //         exception_record.exception_code,
    // //         exception_record.exception_address
    // //     );

    // 1. Try kernel-registered global handlers first
    let result = dispatch_to_handlers(exception_record, context_frame);
    if result != ExceptionDisposition::ContinueSearch {
        record_handler_invocation();
        return result;
    }

    // 2. Walk the stack using RUNTIME_FUNCTION tables
    let mut control_pc = context_frame.rip;
    // _establisher_frame tracks the frame pointer at each unwound function; reserved for future logging
    let mut _establisher_frame = context_frame.rsp;

    // Limit unwinding iterations to prevent infinite loops
    let mut unwind_count = 0;
    const MAX_UNWIND_FRAMES: usize = 100;

    loop {
        if unwind_count >= MAX_UNWIND_FRAMES {
            // // kprintln!("[EXCEPTION] Maximum unwind depth reached, stopping");
            break;
        }

        // Find RUNTIME_FUNCTION for current PC
        if let Some(func) = find_runtime_function_for_ip(control_pc) {
            // Get image base
            if let Some(image_base) = get_image_base_for_ip(control_pc) {
                // Get unwind info
                if let Some(unwind_info) = get_unwind_info(&func, image_base) {
                    // Check if this function has an exception handler
                    if unwind_info.has_exception_handler() {
                        // Get handler data
                        let handler_data = get_handler_data_for_function(image_base, &func);

                        // Call the exception handler
                        let result = call_exception_handler_with_unwind(
                            exception_record,
                            context_frame,
                            image_base,
                            &func,
                            unwind_info,
                            handler_data,
                        );

                        if result != ExceptionDisposition::ContinueSearch {
                            record_handler_invocation();
                            return result;
                        }
                    }

                    // Perform virtual unwind to get return address
                    let mut handler_data_ptr: *const u8 = core::ptr::null();
                    let mut handler_frame: u64 = 0;

                    let return_pc = rtl_virtual_unwind(
                        image_base,
                        control_pc,
                        &func,
                        context_frame,
                        &mut handler_data_ptr,
                        &mut handler_frame,
                    );

                    // Move to next frame
                    control_pc = return_pc;
                    _establisher_frame = handler_frame;

                    if control_pc == 0 {
                        break;
                    }
                }
            }
        } else {
            // No RUNTIME_FUNCTION found, check if we're at a leaf function
            // For leaf functions (no prologue), return address is on stack
            if context_frame.rsp < 0xFFFF800000000000 {
                // User-mode stack, try to read return address
                unsafe {
                    let ret_addr = core::ptr::read_volatile(context_frame.rsp as *const u64);
                    if ret_addr != 0 && ret_addr < 0xFFFF800000000000 {
                        control_pc = ret_addr;
                        context_frame.rsp += 8;
                        unwind_count += 1;
                        continue;
                    }
                }
            }
            break;
        }

        unwind_count += 1;
    }

    // 3. Walk the TEB exception list (for user-mode exceptions)
    if is_user_mode_exception(exception_record) {
        if let Some(result) = walk_teb_exception_list(exception_record, context_frame) {
            return result;
        }
    }

    // // kprintln!("[EXCEPTION] No handler found in chain");
    ExceptionDisposition::ContinueSearch
}

/// Get handler data for a RUNTIME_FUNCTION entry
fn get_handler_data_for_function(image_base: u64, func: &RuntimeFunction) -> *const u8 {
    if let Some(unwind_info) = get_unwind_info(func, image_base) {
        // Handler data follows the UNWIND_CODE array
        let codes_size = (unwind_info.count_of_codes as usize) * 2;
        // UnwindInfo is 4 bytes, then UNWIND_CODE array
        (image_base + func.unwind_info_address as u64 + 4 + codes_size as u64) as *const u8
    } else {
        core::ptr::null()
    }
}

/// Call exception handler with proper unwind context
fn call_exception_handler_with_unwind(
    exception_record: &ExceptionRecord,
    context_frame: &mut ContextFrame,
    image_base: u64,
    function_entry: &RuntimeFunction,
    _unwind_info: &UnwindInfo,
    handler_data: *const u8,
) -> ExceptionDisposition {
    // Delegate to the shared handler invocation which reads the
    // handler RVA and builds the dispatcher context.
    call_exception_handler(
        exception_record,
        context_frame,
        image_base,
        function_entry,
        handler_data,
    )
}

// =============================================================================
// TEB Exception List Integration
// =============================================================================

/// Get the TEB exception list pointer
/// In x64 Windows, this is stored at TEB + 0x00 (FS:[0])
pub fn get_teb_exception_list(teb_ptr: u64) -> u64 {
    if teb_ptr == 0 {
        return 0;
    }
    // read the first 8 bytes (exception_list field)
    unsafe { core::ptr::read(teb_ptr as *const u64) }
}

/// Set the TEB exception list pointer
pub fn set_teb_exception_list(teb_ptr: u64, exception_list: u64) {
    if teb_ptr == 0 {
        return;
    }
    // write to the first 8 bytes (exception_list field)
    unsafe { core::ptr::write(teb_ptr as *mut u64, exception_list) };
}

/// Walk the TEB exception list and call each handler
pub fn walk_exception_list(
    exception_list: u64,
    record: &mut ExceptionRecord,
    ctx: &mut ContextFrame,
) -> ExceptionDisposition {
    let mut current = exception_list;

    while current != 0 {
        // read the EXCEPTION_REGISTRATION structure
        // struct { PVOID Next; PVOID Handler; }
        let next: u64 = unsafe { core::ptr::read(current as *const u64) };
        let handler: u64 = unsafe { core::ptr::read((current + 8) as *const u64) };

        if handler == 0 {
            break;
        }

        // // kprintln!(
        // //             "[EXCEPTION] Calling handler at 0x{:016x} for exception 0x{:08x}",
        // //             handler, record.exception_code
        // //         );

        // Call the handler
        // The handler signature is:
        //   EXCEPTION_DISPOSITION (*handler)(
        //       PEXCEPTION_RECORD, ESTABLISHER_FRAME,
        //       PCONTEXT, DISPATCHER_CONTEXT
        //   );
        type HandlerFn = extern "C" fn(
            *mut ExceptionRecord,
            u64,
            *mut ContextFrame,
            u64,
        ) -> ExceptionDisposition;

        let result = unsafe {
            let handler_fn = core::mem::transmute::<_, HandlerFn>(handler);
            handler_fn(record, current, ctx, 0)
        };

        if result != ExceptionDisposition::ContinueSearch {
            record_handler_invocation();
            return result;
        }

        current = next;
    }

    ExceptionDisposition::ContinueSearch
}

fn walk_teb_exception_list(
    exception_record: &mut ExceptionRecord,
    context_frame: &mut ContextFrame,
) -> Option<ExceptionDisposition> {
    let teb = crate::arch::common::percpu::try_get_current()
        .map(|area| area.current_thread)
        .filter(|thread| !thread.is_null())
        .map(|thread| unsafe { (*thread).kthread.teb as u64 })?;

    if teb == 0 {
        return None;
    }

    // Get exception list from TEB + 0x00
    let exception_list = get_teb_exception_list(teb);

    if exception_list == 0 || exception_list == 0xFFFFFFFFFFFFFFFF {
        // // kprintln!("[EXCEPTION] TEB exception_list is empty or end marker");
        return None;
    }

    // // kprintln!(
    // //         "[EXCEPTION] Walking TEB exception_list @ 0x{:016x}",
    // //         exception_list
    // //     );

    // Walk the exception list
    let result = walk_exception_list(exception_list, exception_record, context_frame);

    Some(result)
}
// =============================================================================
// Extended init with handler setup
// =============================================================================

/// Initialize exception handling subsystem
pub fn extended_init() {
    // // kprintln!("[EXCEPTION] Extended exception handling initialization");

    // Initialize any per-CPU exception state
    // In a full implementation, this would set up per-CPU exception handlers

    // // kprintln!("[EXCEPTION]   - RUNTIME_FUNCTION database initialized");
    // // kprintln!("[EXCEPTION]   - Exception dispatcher initialized");
    // // kprintln!("[EXCEPTION]   - Hardware exception handlers registered");
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// View a byte buffer as a packed UnwindCode. The immediate slots live
    /// after the operation byte and may extend past the 4-byte struct,
    /// exactly as entries do inside a real unwind info array.
    fn code_from(bytes: &[u8]) -> &UnwindCode {
        unsafe { &*(bytes.as_ptr() as *const UnwindCode) }
    }

    #[test]
    fn from_packed_decodes_real_x64_operation_numbers() {
        assert_eq!(
            UnwindOperationCode::from_packed(0x00),
            UnwindOperationCode::PushUnwindHandler
        );
        assert_eq!(
            UnwindOperationCode::from_packed(0x10),
            UnwindOperationCode::AllocLarge
        );
        assert_eq!(
            UnwindOperationCode::from_packed(0x11),
            UnwindOperationCode::AllocLarge
        );
        assert_eq!(
            UnwindOperationCode::from_packed(0x22),
            UnwindOperationCode::AllocSmall
        );
        assert_eq!(UnwindOperationCode::from_packed(0x30), UnwindOperationCode::SetFp);
        assert_eq!(
            UnwindOperationCode::from_packed(0x43),
            UnwindOperationCode::SaveIntNonVol
        );
        assert_eq!(
            UnwindOperationCode::from_packed(0xC0),
            UnwindOperationCode::PushMachFrame
        );
        // Unmodelled ops (UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM) decode to the
        // reserved no-op so a walk never fabricates stack or register changes.
        assert_eq!(
            UnwindOperationCode::from_packed(0x50),
            UnwindOperationCode::CopyData
        );
        assert_eq!(
            UnwindOperationCode::from_packed(0x80),
            UnwindOperationCode::CopyData
        );
    }

    #[test]
    fn operation_reads_the_high_nibble_only_once() {
        // 0x34: operation = 3 (SetFp), operation info = 4.
        let bytes = [0x11u8, 0x34, 0x12, 0x78, 0x56, 0xAA, 0, 0];
        let code = code_from(&bytes);
        assert_eq!(code.operation(), UnwindOperationCode::SetFp);
        assert_eq!(code.operation_info(), 4);
    }

    #[test]
    fn code_ptr_reads_unpack_the_immediate_slots() {
        let bytes = [0x11u8, 0x34, 0x12, 0x78, 0x56, 0xAA, 0, 0];
        let code = code_from(&bytes);
        unsafe {
            assert_eq!(code_ptr_read_16(code), 0x7812);
            assert_eq!(code_ptr_read_32(code), 0xAA56_7812);
        }
    }

    #[test]
    fn alloc_large_size_honours_both_encodings() {
        let mut ctx = ContextFrame::new();
        ctx.rsp = 0x1000;

        // op_info == 0: the next slot holds the 16-bit scaled size.
        let small = [0x00u8, 0x10, 0x40, 0x00, 0, 0, 0, 0];
        let code = code_from(&small);
        assert_eq!(code.operation(), UnwindOperationCode::AllocLarge);
        assert_eq!(code.operation_info(), 0);
        assert_eq!(code.entry_size(), 2);
        let rsp = ctx.rsp;
        apply_unwind_code(&mut ctx, code, rsp, 0);
        assert_eq!(ctx.rsp, 0x1000 + 0x40 * 8);

        // op_info == 1: the two following slots hold the 32-bit size.
        let large = [0x00u8, 0x11, 0x00, 0x00, 0x01, 0x00, 0, 0];
        let code = code_from(&large);
        assert_eq!(code.operation(), UnwindOperationCode::AllocLarge);
        assert_eq!(code.operation_info(), 1);
        assert_eq!(code.entry_size(), 3);
        let rsp = ctx.rsp;
        unsafe { assert_eq!(code_ptr_read_32(code), 0x0001_0000) };
        apply_unwind_code(&mut ctx, code, rsp, 0);
        assert_eq!(ctx.rsp, 0x1000 + 0x40 * 8 + 0x0001_0000 * 8);
    }

    #[test]
    fn push_unwind_handler_pops_eight_bytes() {
        // 0x03: operation 0 (push nonvol), register rbx.
        let bytes = [0x00u8, 0x03, 0, 0, 0, 0, 0, 0];
        let code = code_from(&bytes);
        let mut ctx = ContextFrame::new();
        ctx.rsp = 0x2000;
        let rsp = ctx.rsp;
        apply_unwind_code(&mut ctx, code, rsp, 0);
        assert_eq!(ctx.rsp, 0x2008);
    }

    #[test]
    fn alloc_small_scales_by_operation_info() {
        // 0x25: operation 2 (AllocSmall), size = (5 + 1) * 8 = 48.
        let bytes = [0x00u8, 0x25, 0, 0, 0, 0, 0, 0];
        let code = code_from(&bytes);
        let mut ctx = ContextFrame::new();
        ctx.rsp = 0x3000;
        let rsp = ctx.rsp;
        apply_unwind_code(&mut ctx, code, rsp, 0);
        assert_eq!(ctx.rsp, 0x3000 + 48);
    }
}
