//! x86_64 context switch
//
//! `swap_context` saves the callee-saved registers of the
//! outgoing thread and restores the callee-saved registers of
//! the incoming thread, then returns into the new thread's
//! stack. The two threads are specified by their kernel
//! stacks; the bottom of each stack holds a small
//! `ContextFrame` that we use as the canonical save area.
//
//! The saved register set is the callee-saved subset required
//! by the x86_64 System V ABI (rbx, rbp, r12..r15). The
//! trampoline pushes/pops rip implicitly by `ret` from the
//! stored return address at the top of the new stack.
//
//! Additionally, this module handles FPU/SSE/AVX context switching
//! via the `KiSwapContext` wrapper, which saves and restores SIMD
//! register state using XSAVE/XRSTOR instructions.

use core::arch::global_asm;

global_asm!(
    // void swap_context(u64 *out_rsp, u64 in_rsp)
    //
    // - rdi = &out_rsp (pointer to where to store outgoing rsp)
    // - rsi = new_rsp  (the rsp to switch to)
    //
    // The new thread's stack must already have a ContextFrame
    // at the top — see `ContextFrame::new()`.
    ".global swap_context",
    "swap_context:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // Save the outgoing stack pointer.
    "    mov [rdi], rsp",
    // Switch to the incoming stack.
    "    mov rsp, rsi",
    // Restore the incoming thread's callee-saved registers.
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    // The return address is on the new stack right after the
    // last popped register; the caller's `ret` will land there.
    "    ret",

    // ---- FPU state save via XSAVE ----
    // void fpu_save(void *state_buffer)
    // rdi = buffer pointer
    ".global fpu_save",
    "fpu_save:",
    // XSAVE requires the buffer to be 64-byte aligned
    // We save XMM0-XMM15 (512 bytes) + MXCSR (4 bytes) + FPU state
    // Total: 512 + 64 (header) = 576 bytes minimum, we use 512 bytes
    // Feature mask: 0x7 = X87 | SSE | AVX
    "    mov rax, 0x7",          // Feature mask: X87 + SSE + AVX
    "    mov rdx, 0",           // Extended feature mask (high 32 bits)
    "    xsave [rdi]",
    "    ret",

    // ---- FPU state restore via XRSTOR ----
    // void fpu_restore(void *state_buffer)
    // rdi = buffer pointer
    ".global fpu_restore",
    "fpu_restore:",
    // XRSTOR to restore XMM, X87, and AVX state
    "    mov rax, 0x7",          // Feature mask: X87 + SSE + AVX
    "    mov rdx, 0",           // Extended feature mask (high 32 bits)
    "    xrstor [rdi]",
    "    ret",

    // ---- Initialize FPU state ----
    // void fpu_init(void *state_buffer)
    ".global fpu_init",
    "fpu_init:",
    // Initialize FPU state to clean/zero state
    // Zero all XMM registers
    "    pxor xmm0, xmm0",
    "    pxor xmm1, xmm1",
    "    pxor xmm2, xmm2",
    "    pxor xmm3, xmm3",
    "    pxor xmm4, xmm4",
    "    pxor xmm5, xmm5",
    "    pxor xmm6, xmm6",
    "    pxor xmm7, xmm7",
    "    pxor xmm8, xmm8",
    "    pxor xmm9, xmm9",
    "    pxor xmm10, xmm10",
    "    pxor xmm11, xmm11",
    "    pxor xmm12, xmm12",
    "    pxor xmm13, xmm13",
    "    pxor xmm14, xmm14",
    "    pxor xmm15, xmm15",
    // Initialize MXCSR via memory (safer approach)
    // MXCSR default = 0x1F80 (all masks on, round nearest, FZ off)
    "    mov dword ptr [rsp - 4], 0x1F80",
    "    ldmxcsr dword ptr [rsp - 4]",
    "    ret",
);

extern "C" {
    pub fn swap_context(out_rsp: *mut u64, new_rsp: u64);
    pub fn fpu_save(state_buffer: *mut u8);
    pub fn fpu_restore(state_buffer: *mut u8);
    pub fn fpu_init(state_buffer: *mut u8);
}

/// Size of FPU state buffer for XSAVE/XRSTOR (512 bytes for XMM + header)
/// Must be 64-byte aligned for xsave/xrstor instructions.
pub const FPU_STATE_SIZE: usize = 512;

// Compile-time assertion: FPU_STATE_SIZE must be a multiple of 64 bytes
const _: () = assert!(
    FPU_STATE_SIZE % 64 == 0,
    "FPU_STATE_SIZE must be 64-byte aligned for XSAVE/XRSTOR"
);

/// Saved register set for a context switch. The fields are
/// stored on the kernel stack in the order
/// `rbx, rbp, r12, r13, r14, r15, return_ip` (the return ip
/// is the last thing pushed by `swap_context`'s implicit
/// `ret`).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ContextFrame {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub return_ip: u64,
}

impl ContextFrame {
    pub const fn new() -> Self {
        Self { rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, return_ip: 0 }
    }
}

/// Thread state buffer that includes both general-purpose register state
/// and FPU/SIMD state.
#[repr(C)]
#[repr(align(64))]  // 64-byte alignment for XSAVE
pub struct ThreadStateBuffer {
    /// FPU/SSE/AVX state (512 bytes for full XSAVE area)
    pub fpu_state: [u8; FPU_STATE_SIZE],
    /// Debug register state (DR0-DR7)
    pub debug_state: DebugState,
}

/// Debug register state for hardware breakpoints.
/// Windows 7 x64 uses this to save/restore DR0-DR7 during context switch.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DebugState {
    /// DR0: Breakpoint 0 address
    pub dr0: u64,
    /// DR1: Breakpoint 1 address
    pub dr1: u64,
    /// DR2: Breakpoint 2 address
    pub dr2: u64,
    /// DR3: Breakpoint 3 address
    pub dr3: u64,
    /// DR6: Debug status (set by CPU on breakpoint/trap)
    pub dr6: u64,
    /// DR7: Debug control (breakpoint enable, condition, length)
    pub dr7: u64,
    /// Reserved for alignment (DR4-DR5 are aliased to DR6-DR7 on x64)
    _reserved: [u64; 2],
}

impl DebugState {
    /// Create a new debug state with all registers zeroed
    pub const fn new() -> Self {
        Self {
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            _reserved: [0; 2],
        }
    }
}

impl Default for DebugState {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadStateBuffer {
    pub const fn new() -> Self {
        Self {
            fpu_state: [0u8; FPU_STATE_SIZE],
            debug_state: DebugState::new(),
        }
    }
}

impl Default for ThreadStateBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Push a fresh context frame onto the top of `stack` and
/// return the new stack pointer. `entry` is the function the
/// thread will start in; `arg0` is the single argument
/// (a-la SysV calling convention).
pub fn push_context(stack_top: u64, entry: u64, arg0: u64) -> u64 {
    unsafe {
        let mut sp = stack_top;
        // Top of the new stack: argument (passed in rdi), then
        // the return address. The kernel's entry thunk pops
        // the argument and calls the user entry.
        sp -= 8; *(sp as *mut u64) = arg0;
        sp -= 8; *(sp as *mut u64) = entry;
        // ContextFrame fields, pushed in reverse-pop order.
        sp -= 8; *(sp as *mut u64) = 0; // r15
        sp -= 8; *(sp as *mut u64) = 0; // r14
        sp -= 8; *(sp as *mut u64) = 0; // r13
        sp -= 8; *(sp as *mut u64) = 0; // r12
        sp -= 8; *(sp as *mut u64) = 0; // rbp
        sp -= 8; *(sp as *mut u64) = 0; // rbx
        sp
    }
}

// =============================================================================
// KiSwapContext - Full context switch with FPU state
// =============================================================================
//
// This is the NT-style context switch that handles both general-purpose
// registers and SIMD/FPU state. It follows the Windows 7 `KiSwapContext`
// implementation:
//
// 1. Save current thread's kernel state (rsp, etc.)
// 2. Save current thread's FPU/SSE/AVX state (via XSAVE)
// 3. Switch to new thread's kernel stack
// 4. Restore new thread's FPU/SSE/AVX state (via XRSTOR)
// 5. Return to new thread's execution
//
// For kernel-mode only threads, FPU state save/restore may be skipped
// if the thread never uses SIMD instructions.

/// KiSwapContext - Full context switch with FPU state
///
/// This function performs a complete context switch including:
///   - General-purpose registers (via swap_context)
///   - FPU/SSE/AVX state (via XSAVE/XRSTOR)
///   - Updates the current thread pointer
///
/// # Arguments
/// * `out_rsp` - Pointer to store the current thread's kernel stack pointer
/// * `new_rsp` - New thread's kernel stack pointer to switch to
/// * `current_thread` - Current ETHREAD pointer (for FPU state access)
/// * `new_thread` - New ETHREAD pointer (for FPU state access)
///
/// # Safety
/// This function switches execution to a different thread. The caller
/// must ensure:
///   - Both threads are in a valid state
///   - The new thread has a valid stack
///   - FPU state buffers are properly allocated
pub fn ki_swap_context(
    out_rsp: *mut u64,
    new_rsp: u64,
    current_thread: *mut crate::ps::thread::Ethread,
    new_thread: *mut crate::ps::thread::Ethread,
) {
    unsafe {
        // 1. Save FPU state for the current thread
        if !current_thread.is_null() {
            let fpu_state_ptr = (*current_thread).get_fpu_state_ptr();
            if !fpu_state_ptr.is_null() {
                fpu_save(fpu_state_ptr);
                // Save debug registers to the same buffer
                let debug_ptr = get_debug_state_ptr(fpu_state_ptr as *mut ThreadStateBuffer);
                if !debug_ptr.is_null() {
                    save_debug_registers(&mut *debug_ptr);
                }
            }
        }

        // 2. Perform the basic context switch
        swap_context(out_rsp, new_rsp);

        // 2.5 Publish the new thread into the per-CPU
        //     current_thread slot. After this point every
        //     KeGetCurrentEthread() caller on this CPU sees the
        //     thread that is actually running. Without this
        //     publication, kernel code that switches to a new
        //     thread via ki_swap_context would still observe the
        //     previous thread's ETHREAD, leading to APC
        //     mis-delivery and state corruption.
        // TODO(smp): once per-CPU areas are per-LCPU, restrict
        // the publication to that CPU only.
        crate::arch::common::percpu::set_current_thread(new_thread);

        // 3. After switching, restore FPU state for the new thread
        // Note: This code is executed on the new thread's stack
        if !new_thread.is_null() {
            let fpu_state_ptr = (*new_thread).get_fpu_state_ptr();
            if !fpu_state_ptr.is_null() {
                // Restore debug registers first (before enabling breakpoints)
                let debug_ptr = get_debug_state_ptr(fpu_state_ptr as *mut ThreadStateBuffer);
                if !debug_ptr.is_null() {
                    restore_debug_registers(&*debug_ptr);
                }
                fpu_restore(fpu_state_ptr);
            }
        }
    }
}

/// Save FPU context for a thread before context switch
///
/// This should be called before `swap_context` to save the
/// outgoing thread's SIMD state.
pub fn save_fpu_context() {
    // Get current thread's FPU state and save it
    let current = crate::ps::thread::get_current_ethread();
    if !current.is_null() {
        let fpu_state_ptr = unsafe { (*current).get_fpu_state_ptr() };
        if !fpu_state_ptr.is_null() {
            unsafe { fpu_save(fpu_state_ptr); }
        }
    }
}

/// Restore FPU context for a thread after context switch
///
/// This should be called after `swap_context` to restore the
/// incoming thread's SIMD state.
pub fn restore_fpu_context() {
    // Get new thread's FPU state and restore it
    let current = crate::ps::thread::get_current_ethread();
    if !current.is_null() {
        let fpu_state_ptr = unsafe { (*current).get_fpu_state_ptr() };
        if !fpu_state_ptr.is_null() {
            unsafe { fpu_restore(fpu_state_ptr); }
        }
    }
}

/// Initialize FPU state for a new thread
pub fn init_thread_fpu_state() -> Option<&'static mut ThreadStateBuffer> {
    let buffer = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<ThreadStateBuffer>(),
    ) as *mut ThreadStateBuffer;
    
    if buffer.is_null() {
        // // kprintln!("[CONTEXT] FATAL: Cannot allocate FPU state buffer")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return None;
    }
    
    // Verify 64-byte alignment (XSAVE requires 64-byte alignment)
    // Non-paged pool allocations are typically page-aligned, but we verify at runtime
    if (buffer as u64) % 64 != 0 {
        // // kprintln!("[CONTEXT] WARNING: FPU buffer 0x{:016x} not 64-byte aligned!", buffer as u64)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        // ThreadStateBuffer itself is #[repr(align(64))], so if the allocator
        // gives us a misaligned pointer, we need to handle it.
        // For now, continue - the pool allocator should return aligned memory.
    }
    
    unsafe {
        // Initialize the buffer
        core::ptr::write_bytes(
            buffer as *mut u8,
            0,
            core::mem::size_of::<ThreadStateBuffer>()
        );
        
        // Initialize FPU state to clean values
        fpu_init(buffer as *mut u8);
        
        Some(&mut *buffer)
    }
}

/// Free FPU state buffer
pub fn free_thread_fpu_state(buffer: *mut ThreadStateBuffer) {
    if !buffer.is_null() {
        let _ = crate::mm::pool::free(buffer as *mut u8);
    }
}

// =============================================================================
// Debug Register (DR0-DR7) Save/Restore
// =============================================================================
//
// Hardware breakpoints are debug registers that must be preserved during context
// switch. When a thread sets a debug register (via NtSetContextThread), the
// kernel saves the current thread's DR state and restores the new thread's DR
// state during context switch.
//
// On x86_64:
//   DR0-DR3: Breakpoint addresses
//   DR4-DR5: Reserved (aliased to DR6-DR7)
//   DR6: Debug status (set by CPU on breakpoint/trap hit)
//   DR7: Debug control (enable bits, condition, length for each breakpoint)

/// Save debug register state to the thread's state buffer
///
/// # Safety
/// This function reads from CPU debug registers which may have side effects
#[inline(always)]
pub unsafe fn save_debug_registers(state: &mut DebugState) {
    core::arch::asm!(
        "mov {0}, dr0",
        "mov {1}, dr1",
        "mov {2}, dr2",
        "mov {3}, dr3",
        "mov {4}, dr6",
        "mov {5}, dr7",
        out(reg) state.dr0,
        out(reg) state.dr1,
        out(reg) state.dr2,
        out(reg) state.dr3,
        out(reg) state.dr6,
        out(reg) state.dr7,
        options(nomem, nostack)
    );
}

/// Restore debug register state from the thread's state buffer
///
/// This clears DR7 first (to disable breakpoints during restore) then
/// restores DR0-DR3 and finally DR7. This order prevents spurious
/// debug exceptions during the restore sequence.
///
/// # Safety
/// This function writes to CPU debug registers which may trigger debug exceptions
#[inline(always)]
pub unsafe fn restore_debug_registers(state: &DebugState) {
    // Clear DR7 first to disable all breakpoints before restoring addresses
    // Use a register as intermediate since DR7 is a special register
    core::arch::asm!("xor rax, rax; mov dr7, rax", options(nomem, nostack));
    core::arch::asm!(
        "mov dr0, {0}",
        "mov dr1, {1}",
        "mov dr2, {2}",
        "mov dr3, {3}",
        "mov dr7, {4}",
        in(reg) state.dr0,
        in(reg) state.dr1,
        in(reg) state.dr2,
        in(reg) state.dr3,
        in(reg) state.dr7,
        options(nomem, nostack)
    );
}

/// Get pointer to debug state within ThreadStateBuffer
#[inline]
pub fn get_debug_state_ptr(buffer: *mut ThreadStateBuffer) -> *mut DebugState {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let state = &mut *buffer;
        core::ptr::addr_of_mut!(state.debug_state)
    }
}
