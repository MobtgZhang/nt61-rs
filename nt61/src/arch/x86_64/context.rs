//! Context Switching Support
//
//! Provides context save/restore functionality for thread switching

/// CPU context for context switching
#[repr(C)]
pub struct CpuContext {
    /// General purpose registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Instruction pointer
    pub rip: u64,
    /// RFLAGS register
    pub rflags: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
            rflags: 0,
        }
    }
}

/// Thread context including kernel stack
#[repr(C)]
pub struct ThreadContext {
    /// CPU registers
    pub cpu: CpuContext,
    /// Kernel stack pointer
    pub kernel_stack: u64,
    /// FPU state pointer (optional)
    pub fpu_state: *mut u8,
}

impl Default for ThreadContext {
    fn default() -> Self {
        Self {
            cpu: CpuContext::default(),
            kernel_stack: 0,
            fpu_state: core::ptr::null_mut(),
        }
    }
}
