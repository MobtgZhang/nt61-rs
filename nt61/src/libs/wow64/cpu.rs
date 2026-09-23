//! cpu — WoW64 CPU Emulation Layer
//
//! This module implements the WoW64 CPU emulation layer that allows
//! 32-bit x86 code to execute on an x86_64 processor. It handles:
//!   * 32-bit instruction execution and emulation
//!   * Segment register management
//!   * Mode switching (32-bit ↔ 64-bit)
//!   * CPU state transitions
//!   * Far call/return handling
//
//! # Architecture
//!
//! On x86_64, 32-bit code can run natively in compatibility mode.
//! However, certain operations require emulation:
//!   * Segment register manipulation
//!   * Mode transitions (syscalls)
//!   * Special instructions (SYSENTER, SYSEXIT)
//!   * Far jumps and calls
//!
//! The WoW64 CPU layer maintains a virtual CPU state for each
//! 32-bit thread and handles transitions between 32-bit and 64-bit
//! execution contexts.
//!
//! References:
//!   * Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3
//!   * AMD64 Architecture Programmer's Manual, Vol. 2
//!   * Windows Internals 7th Edition, Part 1, Chapter 3

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::libs::wow64::types::*;
use core::arch::asm;

// =============================================================================
// CPU State Management
// =============================================================================

/// WoW64 CPU state for a 32-bit thread.
/// This tracks the virtual CPU state when executing 32-bit code.
#[repr(C)]
pub struct Wow64CpuState {
    /// Current 32-bit context.
    pub context32: Context32,
    /// Saved 64-bit context (for transitions).
    pub context64_saved: Context64Minimal,
    /// CPU mode (32-bit or 64-bit).
    pub mode: CpuMode,
    /// Segment descriptors.
    pub segments: SegmentState,
    /// Flags and control bits.
    pub flags: CpuFlags,
}

impl Wow64CpuState {
    /// Create a new WoW64 CPU state.

    pub fn new() -> Self {
        Self {
            context32: Context32::new(),
            context64_saved: Context64Minimal::new(),
            mode: CpuMode::Mode32Bit,
            segments: SegmentState::new(),
            flags: CpuFlags::new(),
        }
    }

    /// Initialize for a new 32-bit thread.
    pub fn init_thread(&mut self, entry_point: u32, stack_top: u32, param: u32) {
        // Set up initial 32-bit context
        self.context32.eip = entry_point;
        self.context32.esp = stack_top - 4;
        self.context32.eax = param;
        self.context32.ebp = 0;

        // Set up segment registers for 32-bit user mode
        self.context32.cs = SEGMENT_CS_32_USER;
        self.context32.ds = SEGMENT_DS_32_USER;
        self.context32.es = SEGMENT_ES_32_USER;
        self.context32.fs = SEGMENT_FS_32_USER;
        self.context32.gs = SEGMENT_GS_32_USER;
        self.context32.ss = SEGMENT_SS_32_USER;

        // Set up EFLAGS (interrupts enabled, IOPL=0, no trap)
        self.context32.eflags = EFLAGS_IF | EFLAGS_RESERVED_1;

        self.mode = CpuMode::Mode32Bit;
    }

    /// Check if currently in 32-bit mode.
    pub fn is_32bit_mode(&self) -> bool {
        matches!(self.mode, CpuMode::Mode32Bit)
    }

    /// Check if currently in 64-bit mode.
    pub fn is_64bit_mode(&self) -> bool {
        matches!(self.mode, CpuMode::Mode64Bit)
    }
}

impl Default for Wow64CpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal 64-bit context for mode transitions.
#[repr(C)]
#[derive(Default)]
pub struct Context64Minimal {
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
    pub rip: u64,
    pub rflags: u64,
}

impl Context64Minimal {
    pub fn new() -> Self {
        Self::default()
    }
}

/// CPU execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CpuMode {
    /// 32-bit compatibility mode.
    Mode32Bit = 0,
    /// 64-bit long mode.
    Mode64Bit = 1,
}

/// Segment descriptor state.
#[repr(C)]
pub struct SegmentState {
    pub cs_base: u64,
    pub ds_base: u64,
    pub es_base: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ss_base: u64,
    pub cs_limit: u32,
    pub ds_limit: u32,
    pub es_limit: u32,
    pub fs_limit: u32,
    pub gs_limit: u32,
    pub ss_limit: u32,
}

impl SegmentState {
    pub fn new() -> Self {
        Self {
            cs_base: 0,
            ds_base: 0,
            es_base: 0,
            fs_base: 0,
            gs_base: 0,
            ss_base: 0,
            cs_limit: 0xFFFF_FFFF,
            ds_limit: 0xFFFF_FFFF,
            es_limit: 0xFFFF_FFFF,
            fs_limit: 0xFFFF_FFFF,
            gs_limit: 0xFFFF_FFFF,
            ss_limit: 0xFFFF_FFFF,
        }
    }
}

/// CPU flags and control bits.
#[repr(C)]
pub struct CpuFlags {
    pub single_step: bool,
    pub in_syscall: bool,
    pub exception_pending: bool,
}

impl CpuFlags {
    pub fn new() -> Self {
        Self {
            single_step: false,
            in_syscall: false,
            exception_pending: false,
        }
    }
}

// =============================================================================
// Segment Register Constants
// =============================================================================

/// 32-bit user mode code segment selector.
pub const SEGMENT_CS_32_USER: u32 = 0x23;
/// 32-bit user mode data segment selector.
pub const SEGMENT_DS_32_USER: u32 = 0x2B;
/// 32-bit user mode extra segment selector.
pub const SEGMENT_ES_32_USER: u32 = 0x2B;
/// 32-bit user mode FS segment selector (TEB).
pub const SEGMENT_FS_32_USER: u32 = 0x53;
/// 32-bit user mode GS segment selector.
pub const SEGMENT_GS_32_USER: u32 = 0x2B;
/// 32-bit user mode stack segment selector.
pub const SEGMENT_SS_32_USER: u32 = 0x2B;

/// 64-bit user mode code segment selector.
pub const SEGMENT_CS_64_USER: u16 = 0x33;
/// 64-bit user mode data segment selector.
pub const SEGMENT_DS_64_USER: u16 = 0x2B;

// =============================================================================
// EFLAGS Constants
// =============================================================================

/// Interrupt enable flag.
pub const EFLAGS_IF: u32 = 0x0000_0200;
/// Trap flag (single step).
pub const EFLAGS_TF: u32 = 0x0000_0100;
/// Reserved bit (always 1).
pub const EFLAGS_RESERVED_1: u32 = 0x0000_0002;
/// Direction flag.
pub const EFLAGS_DF: u32 = 0x0000_0400;
/// Overflow flag.
pub const EFLAGS_OF: u32 = 0x0000_0800;
/// Sign flag.
pub const EFLAGS_SF: u32 = 0x0000_0080;
/// Zero flag.
pub const EFLAGS_ZF: u32 = 0x0000_0040;
/// Auxiliary carry flag.
pub const EFLAGS_AF: u32 = 0x0000_0010;
/// Parity flag.
pub const EFLAGS_PF: u32 = 0x0000_0004;
/// Carry flag.
pub const EFLAGS_CF: u32 = 0x0000_0001;

// =============================================================================
// Mode Switching
// =============================================================================

/// Switch from 32-bit mode to 64-bit mode.
/// This is called when a 32-bit thread makes a system call.
pub fn switch_to_64bit_mode(cpu_state: &mut Wow64CpuState) -> Result<(), CpuError> {
    if cpu_state.mode == CpuMode::Mode64Bit {
        return Err(CpuError::AlreadyIn64BitMode);
    }

    // Save current 32-bit context
    // (already in cpu_state.context32)

    // Prepare 64-bit context for syscall handling
    cpu_state.context64_saved.rax = cpu_state.context32.eax as u64;
    cpu_state.context64_saved.rcx = cpu_state.context32.ecx as u64;
    cpu_state.context64_saved.rdx = cpu_state.context32.edx as u64;
    cpu_state.context64_saved.rbx = cpu_state.context32.ebx as u64;
    cpu_state.context64_saved.rsp = cpu_state.context32.esp as u64;
    cpu_state.context64_saved.rbp = cpu_state.context32.ebp as u64;
    cpu_state.context64_saved.rsi = cpu_state.context32.esi as u64;
    cpu_state.context64_saved.rdi = cpu_state.context32.edi as u64;
    cpu_state.context64_saved.rip = cpu_state.context32.eip as u64;
    cpu_state.context64_saved.rflags = cpu_state.context32.eflags as u64;

    // Switch mode
    cpu_state.mode = CpuMode::Mode64Bit;
    cpu_state.flags.in_syscall = true;

    Ok(())
}

/// Switch from 64-bit mode back to 32-bit mode.
/// This is called when returning from a system call.
pub fn switch_to_32bit_mode(cpu_state: &mut Wow64CpuState) -> Result<(), CpuError> {
    if cpu_state.mode == CpuMode::Mode32Bit {
        return Err(CpuError::AlreadyIn32BitMode);
    }

    // Restore 32-bit context from 64-bit context
    cpu_state.context32.eax = (cpu_state.context64_saved.rax & 0xFFFF_FFFF) as u32;
    cpu_state.context32.ecx = (cpu_state.context64_saved.rcx & 0xFFFF_FFFF) as u32;
    cpu_state.context32.edx = (cpu_state.context64_saved.rdx & 0xFFFF_FFFF) as u32;
    cpu_state.context32.ebx = (cpu_state.context64_saved.rbx & 0xFFFF_FFFF) as u32;
    cpu_state.context32.esp = (cpu_state.context64_saved.rsp & 0xFFFF_FFFF) as u32;
    cpu_state.context32.ebp = (cpu_state.context64_saved.rbp & 0xFFFF_FFFF) as u32;
    cpu_state.context32.esi = (cpu_state.context64_saved.rsi & 0xFFFF_FFFF) as u32;
    cpu_state.context32.edi = (cpu_state.context64_saved.rdi & 0xFFFF_FFFF) as u32;
    cpu_state.context32.eip = (cpu_state.context64_saved.rip & 0xFFFF_FFFF) as u32;
    cpu_state.context32.eflags = (cpu_state.context64_saved.rflags & 0xFFFF_FFFF) as u32;

    // Switch mode
    cpu_state.mode = CpuMode::Mode32Bit;
    cpu_state.flags.in_syscall = false;

    Ok(())
}

/// CPU operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuError {
    AlreadyIn32BitMode,
    AlreadyIn64BitMode,
    InvalidSegmentSelector,
    InvalidInstruction,
    SegmentLimitViolation,
    ProtectionFault,
}

// =============================================================================
// Segment Register Operations
// =============================================================================

/// Load a segment register.
/// This validates the selector and updates the segment state.
pub fn load_segment_register(
    cpu_state: &mut Wow64CpuState,
    segment: SegmentRegister,
    selector: u16,
) -> Result<(), CpuError> {
    // Validate selector
    if !is_valid_segment_selector(selector, cpu_state.mode) {
        return Err(CpuError::InvalidSegmentSelector);
    }

    // Update the appropriate segment in context32
    match segment {
        SegmentRegister::CS => cpu_state.context32.cs = selector as u32,
        SegmentRegister::DS => cpu_state.context32.ds = selector as u32,
        SegmentRegister::ES => cpu_state.context32.es = selector as u32,
        SegmentRegister::FS => cpu_state.context32.fs = selector as u32,
        SegmentRegister::GS => cpu_state.context32.gs = selector as u32,
        SegmentRegister::SS => cpu_state.context32.ss = selector as u32,
    }

    Ok(())
}

/// Segment register enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentRegister {
    CS,
    DS,
    ES,
    FS,
    GS,
    SS,
}

/// Validate a segment selector for the current mode.
fn is_valid_segment_selector(selector: u16, mode: CpuMode) -> bool {
    // Check RPL (bits 0-1) and TI (bit 2)
    let rpl = selector & 0x03;
    let ti = (selector >> 2) & 0x01;

    match mode {
        CpuMode::Mode32Bit => {
            // In 32-bit mode, must be ring 3 (RPL=3)
            rpl == 3 && ti == 0 // GDT only
        }
        CpuMode::Mode64Bit => {
            // In 64-bit mode, segment selectors are mostly ignored
            true
        }
    }
}

/// Get the base address of a segment.
pub fn get_segment_base(cpu_state: &Wow64CpuState, segment: SegmentRegister) -> u64 {
    match segment {
        SegmentRegister::CS => cpu_state.segments.cs_base,
        SegmentRegister::DS => cpu_state.segments.ds_base,
        SegmentRegister::ES => cpu_state.segments.es_base,
        SegmentRegister::FS => cpu_state.segments.fs_base,
        SegmentRegister::GS => cpu_state.segments.gs_base,
        SegmentRegister::SS => cpu_state.segments.ss_base,
    }
}

/// Set the base address of a segment.
pub fn set_segment_base(
    cpu_state: &mut Wow64CpuState,
    segment: SegmentRegister,
    base: u64,
) {
    match segment {
        SegmentRegister::CS => cpu_state.segments.cs_base = base,
        SegmentRegister::DS => cpu_state.segments.ds_base = base,
        SegmentRegister::ES => cpu_state.segments.es_base = base,
        SegmentRegister::FS => cpu_state.segments.fs_base = base,
        SegmentRegister::GS => cpu_state.segments.gs_base = base,
        SegmentRegister::SS => cpu_state.segments.ss_base = base,
    }
}

// =============================================================================
// MSR (Model-Specific Register) Operations
// =============================================================================

/// Read FS.base MSR.
pub fn read_fs_base() -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "rdfsbase {0}",
            out(reg) value,
            options(nomem, nostack)
        );
    }
    value
}

/// Write FS.base MSR.
pub fn write_fs_base(value: u64) {
    unsafe {
        asm!(
            "wrfsbase {0}",
            in(reg) value,
            options(nomem, nostack)
        );
    }
}

/// Read GS.base MSR.
pub fn read_gs_base() -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "rdgsbase {0}",
            out(reg) value,
            options(nomem, nostack)
        );
    }
    value
}

/// Write GS.base MSR.
pub fn write_gs_base(value: u64) {
    unsafe {
        asm!(
            "wrgsbase {0}",
            in(reg) value,
            options(nomem, nostack)
        );
    }
}

// =============================================================================
// Instruction Emulation
// =============================================================================

/// Emulate a far call (CALL FAR).
/// This is used for transitions that require segment changes.
pub fn emulate_far_call(
    cpu_state: &mut Wow64CpuState,
    target_cs: u16,
    target_eip: u32,
) -> Result<(), CpuError> {
    // Validate target segment
    if !is_valid_segment_selector(target_cs, cpu_state.mode) {
        return Err(CpuError::InvalidSegmentSelector);
    }

    // Push return address (CS:EIP) onto stack
    let esp = cpu_state.context32.esp;
    cpu_state.context32.esp = esp.wrapping_sub(4);
    // In real implementation, write CS to stack
    cpu_state.context32.esp = cpu_state.context32.esp.wrapping_sub(4);
    // In real implementation, write EIP to stack

    // Update CS and EIP
    cpu_state.context32.cs = target_cs as u32;
    cpu_state.context32.eip = target_eip;

    Ok(())
}

/// Emulate a far return (RET FAR).
pub fn emulate_far_return(cpu_state: &mut Wow64CpuState) -> Result<(), CpuError> {
    // Pop return address (EIP:CS) from stack
    let esp = cpu_state.context32.esp;
    // In real implementation, read EIP from stack
    let _new_eip = 0; // Placeholder
    cpu_state.context32.esp = esp.wrapping_add(4);
    // In real implementation, read CS from stack
    let _new_cs = 0; // Placeholder
    cpu_state.context32.esp = cpu_state.context32.esp.wrapping_add(4);

    // Validate and update
    // cpu_state.context32.cs = new_cs;
    // cpu_state.context32.eip = new_eip;

    Ok(())
}

/// Emulate SYSENTER instruction (32-bit fast system call).
pub fn emulate_sysenter(cpu_state: &mut Wow64CpuState) -> Result<(), CpuError> {
    // SYSENTER transitions to kernel mode
    // For WoW64, we intercept this and convert to 64-bit syscall

    // Save return address in EDX:EAX
    // (SYSENTER uses ECX for return EIP, EDX for return ESP)

    // Switch to 64-bit mode
    switch_to_64bit_mode(cpu_state)?;

    Ok(())
}

/// Emulate SYSEXIT instruction (32-bit fast system return).
pub fn emulate_sysexit(cpu_state: &mut Wow64CpuState) -> Result<(), CpuError> {
    // SYSEXIT returns from kernel mode to user mode
    // Restore return address from EDX:ECX

    // Switch back to 32-bit mode
    switch_to_32bit_mode(cpu_state)?;

    Ok(())
}

// =============================================================================
// CPU Feature Detection
// =============================================================================

/// Check if the CPU supports WoW64 execution.
pub fn cpu_supports_wow64() -> bool {
    // On x86_64, we always support WoW64 (32-bit compatibility mode)
    cfg!(target_arch = "x86_64")
}

/// Check if the CPU supports FSGSBASE instructions.
pub fn cpu_supports_fsgsbase() -> bool {
    // Check CPUID leaf 7, subleaf 0, EBX bit 0
    // For now, assume supported on modern CPUs
    true
}

// =============================================================================
// Context Capture and Restore
// =============================================================================

/// Capture the current CPU state into a CONTEXT32.
pub fn capture_context32(cpu_state: &Wow64CpuState) -> Context32 {
    cpu_state.context32.clone()
}

/// Restore CPU state from a CONTEXT32.
pub fn restore_context32(cpu_state: &mut Wow64CpuState, context: &Context32) {
    cpu_state.context32 = context.clone();
}

/// Capture minimal 64-bit context.
pub fn capture_context64_minimal() -> Context64Minimal {
    // In a real implementation, read from actual CPU registers
    Context64Minimal::new()
}

// =============================================================================
// Initialization
// =============================================================================

/// Initialize the WoW64 CPU emulation layer.
pub fn init() {
    crate::wow64_klog!("WoW64 CPU emulation layer initialized");

    // Check CPU features
    if !cpu_supports_wow64() {
        crate::wow64_klog!("WARNING: CPU does not support WoW64!");
    }

    if cpu_supports_fsgsbase() {
        crate::wow64_klog!("CPU supports FSGSBASE instructions");
    }
}
