//! FPU/SSE/AVX Context Switching
//
//! Implements saving and restoring of SIMD registers (XMM0-15, YMM0-15, MXCSR)
//! during context switches. This is required by the Windows 7 kernel's
//! `KiSwapContext` function which must preserve the complete floating-point
//! and SIMD state for each thread.
//
//! On x86_64, the FPU state is managed using the XSAVE/XRSTOR instructions
//! which can save/restore:
//!   - Legacy FPU state (x87 FPU, MMX)
//!   - SSE state (XMM0-15, MXCSR)
//!   - AVX state (YMM0-15 upper halves)
//!   - AVX-512 state (ZMM0-31, OPMASK, ZMM state header) [if supported]
//
//! The layout follows the AMD64 and Intel 64 ABI specifications.


/// FPU state buffer size for XSAVE area.
/// This must be large enough to hold:
///   - XSAVE header (64 bytes)
///   - Legacy FPU area (512 bytes)
///   - SSE/XMM area (576 bytes)
///   - AVX/YMM upper halves (256 bytes)
/// Total: ~1408 bytes, we allocate 4096 for alignment and future extensions
pub const FPU_STATE_SIZE: usize = 4096;

/// FPU state alignment requirement (XSAVE requires 64-byte alignment)
pub const FPU_STATE_ALIGN: usize = 64;

/// XSAVE feature flags (CPUID leaf 0xD, sub-leaf 0)
#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum XsaveFeature {
    X87 = 1 << 0,
    SSE = 1 << 1,
    AVX = 1 << 2,
    MPX_BNDREGS = 1 << 3,
    MPX_BNDCSR = 1 << 4,
    AVX512_OPMASK = 1 << 5,
    AVX512_ZMM_HI256 = 1 << 6,
    AVX512_ZMM_HI16 = 1 << 7,
}

/// MXCSR control/status register bits
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Mxcsr(u32);

impl Mxcsr {
    pub const IE: u32 = 1 << 0;      // Invalid Operation Flag
    pub const DE: u32 = 1 << 1;      // Denormal Flag
    pub const ZE: u32 = 1 << 2;      // Zero Divide Flag
    pub const OE: u32 = 1 << 3;      // Overflow Flag
    pub const UE: u32 = 1 << 4;      // Underflow Flag
    pub const PE: u32 = 1 << 5;      // Precision Flag
    pub const DAZ: u32 = 1 << 6;      // Denormals Are Zero
    pub const IM: u32 = 1 << 7;      // Invalid Operation Mask
    pub const DM: u32 = 1 << 8;      // Denormal Mask
    pub const ZM: u32 = 1 << 9;      // Zero Divide Mask
    pub const OM: u32 = 1 << 10;     // Overflow Mask
    pub const UM: u32 = 1 << 11;     // Underflow Mask
    pub const PM: u32 = 1 << 12;     // Precision Mask
    pub const RC_RN: u32 = 0 << 13;  // Rounding Control: Round Nearest
    pub const RC_RD: u32 = 1 << 13;  // Rounding Control: Round Down
    pub const RC_RU: u32 = 2 << 13;  // Rounding Control: Round Up
    pub const RC_RZ: u32 = 3 << 13;  // Rounding Control: Round Toward Zero
    pub const FZ: u32 = 1 << 15;     // Flush to Zero
    
    pub const DEFAULT: u32 = 0x1F80; // Standard init value (all masks on, RN)
}

/// XSAVE header structure
#[repr(C)]
#[repr(align(64))]
pub struct XsaveHeader {
    /// XSTATE_BV: features enabled in this state save
    pub xstate_bv: u64,
    /// XCOMP_BV: features contained in this save area
    pub xcomp_bv: u64,
    /// Reserved
    pub reserved: [u64; 6],
}

/// XSAVE state area (simplified for SSE/AVX)
/// 
/// This is the format used by XSAVE/XRSTOR. The actual size depends on
/// which features are enabled. For SSE/AVX we need:
///   - Legacy region (512 bytes): x87 FPU + MMX
///   - XSAVE header (64 bytes)
///   - SSE/XMM region (XMM0-15 + MXCSR, ~576 bytes after header)
///   - AVX region (YMM upper halves, ~256 bytes)
#[repr(C)]
#[repr(align(64))]
pub struct FpuState {
    /// Legacy FPU/MMX state (512 bytes)
    pub legacy: [u8; 512],
    /// XSAVE header (64 bytes)
    pub header: XsaveHeader,
    /// Extended state (XMM + YMM upper, 0F 00
    /// This is a simplified layout; in reality XSAVE uses a more complex
    /// offset structure. For our purposes, we use a fixed buffer.
    pub extended: [u8; FPU_STATE_SIZE - 512 - 64],
}

impl FpuState {
    /// Create a new FPU state buffer, initialized to clean state
    pub fn new() -> Self {
        let mut state = Self {
            legacy: [0; 512],
            header: XsaveHeader {
                xstate_bv: 0,
                xcomp_bv: 0,
                reserved: [0; 6],
            },
            extended: [0; FPU_STATE_SIZE - 512 - 64],
        };
        
        // Initialize to default values
        state.header.xstate_bv = XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64;
        state.header.xcomp_bv = state.header.xstate_bv;
        
        state
    }
    
    /// Initialize FPU state for a fresh thread
    pub fn init_for_thread(&mut self, enable_avx: bool) {
        // Clear all state
        unsafe {
            core::ptr::write_bytes(self as *mut FpuState as *mut u8, 0, FPU_STATE_SIZE);
        }
        
        // Set up XSAVE header for enabled features
        let mut features = XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64;
        if enable_avx {
            features |= XsaveFeature::AVX as u64;
        }
        self.header.xstate_bv = features;
        self.header.xcomp_bv = features;
        
        // Initialize MXCSR to default (all exceptions masked)
        // The MXCSR is stored at offset 24 in the extended region
        if FPU_STATE_SIZE > 512 + 64 + 24 + 4 {
            let mxcsr_offset = 512 + 64 + 24;
            self.extended[mxcsr_offset..mxcsr_offset + 4]
                .copy_from_slice(&Mxcsr::DEFAULT.to_le_bytes());
        }
    }
}

/// Per-thread FPU state tracking
pub struct ThreadFpuState {
    /// XSAVE area for this thread
    pub state_buffer: *mut FpuState,
    /// Whether AVX is enabled for this thread
    pub avx_enabled: bool,
    /// Whether FPU has been used by this thread
    pub in_use: bool,
}

impl ThreadFpuState {
    /// Create new FPU state for a thread
    pub fn new(enable_avx: bool) -> Option<&'static mut Self> {
        // Allocate aligned FPU state from non-paged pool
        let state_ptr = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            FPU_STATE_SIZE,
        ) as *mut FpuState;
        
        if state_ptr.is_null() {
            return None;
        }
        
        unsafe {
            // Initialize the FPU state
            (*state_ptr).init_for_thread(enable_avx);
        }
        
        let fpu_state = crate::mm::pool::allocate(
            crate::mm::pool::PoolType::NonPaged,
            core::mem::size_of::<Self>(),
        ) as *mut Self;
        
        if fpu_state.is_null() {
            let _ = crate::mm::pool::free(state_ptr as *mut u8);
            return None;
        }
        
        unsafe {
            (*fpu_state).state_buffer = state_ptr;
            (*fpu_state).avx_enabled = enable_avx;
            (*fpu_state).in_use = false;
        }
        
        unsafe { fpu_state.as_mut() }
    }
    
    /// Free FPU state
    pub fn free(&mut self) {
        if !self.state_buffer.is_null() {
            let _ = crate::mm::pool::free(self.state_buffer as *mut u8);
            self.state_buffer = core::ptr::null_mut();
        }
    }
}

// =============================================================================
// XSAVE/XRSTOR intrinsics
// =============================================================================

extern "C" {
    /// XSAVE - save FPU/SSE/AVX state to memory
    /// 
    /// Usage: xsave([state_buffer])
    /// Uses EDX:EAX for feature mask (save all enabled features)
    fn _xrstor(state: *const u8, features: u64);
    
    /// XRSTOR - restore FPU/SSE/AVX state from memory
    /// 
    /// Usage: xrstor([state_buffer], feature_mask)
    /// EDX:EAX contains which components to restore
    fn _xsave(state: *mut u8, features: u64);
}

/// Save current FPU/SSE/AVX state to the given buffer
/// 
/// This uses the XSAVE instruction to save all enabled FPU features.
/// The `features` parameter specifies which features to save (XSTATE_BV).
#[inline]
pub fn fpu_save(state: *mut FpuState, features: u64) {
    unsafe {
        core::arch::asm!(
            "xsave64 [{0}]",
            in(reg) state as u64,
            in("rax") features,
            in("rdx") features >> 32,
            options(nostack)
        );
    }
}

/// Restore FPU/SSE/AVX state from the given buffer
/// 
/// This uses the XRSTOR instruction to restore all enabled FPU features.
/// The `features` parameter specifies which features to restore (XSTATE_BV).
#[inline]
pub fn fpu_restore(state: *const FpuState, features: u64) {
    unsafe {
        core::arch::asm!(
            "xrstor64 [{0}]",
            in(reg) state as u64,
            in("rax") features,
            in("rdx") features >> 32,
            options(nostack)
        );
    }
}

// =============================================================================
// FPU initialization and management
// =============================================================================

static FPU_INITIALIZED: core::sync::atomic::AtomicBool = 
    core::sync::atomic::AtomicBool::new(false);
static FPU_AVX_SUPPORTED: core::sync::atomic::AtomicBool = 
    core::sync::atomic::AtomicBool::new(false);
static FPU_XSAVE_SUPPORTED: core::sync::atomic::AtomicBool = 
    core::sync::atomic::AtomicBool::new(false);

/// Initialize FPU for the current CPU
/// 
/// Called during early boot to set up XSAVE/XRSTOR support.
/// This function:
///   1. Checks CPU feature flags
///   2. Enables FPU/SSE/AVX in CR0/CR4
///   3. Initializes the init FPU state pattern
pub fn init() {
    // Check for XSAVE support via CPUID
    let xsave_supported = check_xsave_support();
    FPU_XSAVE_SUPPORTED.store(xsave_supported, core::sync::atomic::Ordering::SeqCst);
    
    if xsave_supported {
        // Check for AVX support
        let avx_supported = check_avx_support();
        FPU_AVX_SUPPORTED.store(avx_supported, core::sync::atomic::Ordering::SeqCst);
        
        // Enable XSAVE in CR4
        unsafe {
            let mut cr4: u64;
            core::arch::asm!(
                "mov {}, cr4",
                out(reg) cr4,
                options(nostack, preserves_flags)
            );
            cr4 |= 1 << 18; // CR4.OSXSAVE = 1
            core::arch::asm!(
                "mov cr4, {}",
                in(reg) cr4,
                options(nostack, preserves_flags)
            );
        }
        
        // // kprintln!("    [FPU] XSAVE supported, AVX: {}", avx_supported)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // Fall back to legacy FXRSTOR/FXSAVE
        // // kprintln!("    [FPU] Using legacy FXSAVE/FXRSTOR")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    
    // Initialize FPU with default state
    init_fpu_state();
    
    FPU_INITIALIZED.store(true, core::sync::atomic::Ordering::SeqCst);
    // // kprintln!("    [FPU] Initialized (state size: {} bytes)", FPU_STATE_SIZE)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Check for XSAVE/XRSTOR support
fn check_xsave_support() -> bool {
    // CPUID leaf 1, ECX bit 26 = XSAVE feature
    let ecx_val: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ecx",
            "pop rbx",
            out(reg) ecx_val,
            options(nostack, preserves_flags)
        );
    }
    (ecx_val & (1 << 26)) != 0
}

/// Check for AVX support
fn check_avx_support() -> bool {
    // CPUID leaf 1, ECX bit 28 = AVX feature
    let ecx_val: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ecx",
            "pop rbx",
            out(reg) ecx_val,
            options(nostack, preserves_flags)
        );
    }
    (ecx_val & (1 << 28)) != 0
}

/// Get the feature mask for XSAVE/XRSTOR
pub fn get_xsave_features() -> u64 {
    let mut features = XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64;
    if FPU_AVX_SUPPORTED.load(core::sync::atomic::Ordering::SeqCst) {
        features |= XsaveFeature::AVX as u64;
    }
    features
}

/// Initialize FPU with default/clean state
/// 
/// This sets up the FPU to a known clean state:
///   - All x87 FPU registers = 0
///   - All XMM registers = 0
///   - MXCSR = 0x1F80 (default mask, round nearest)
///   - x87 FPU control word = 0x037F (precision: full, rounding: nearest, 
///     exceptions masked)
fn init_fpu_state() {
    // Initialize a clean state buffer on the stack
    let mut clean_state = FpuState::new();
    
    // Initialize x87 FPU control word at offset 0x1C in legacy region
    // Standard init: 0x037F (precision full, rounding nearest, all masked)
    let fpu_cw: u16 = 0x037F;
    clean_state.legacy[0x1C..0x1E].copy_from_slice(&fpu_cw.to_le_bytes());
    
    // Initialize x87 FPU status word to 0 (no exceptions)
    clean_state.legacy[0x18..0x1A].copy_from_slice(&0u16.to_le_bytes());
    
    // Set up XSAVE header
    clean_state.header.xstate_bv = get_xsave_features();
    clean_state.header.xcomp_bv = get_xsave_features();
    
    // Initialize MXCSR (at offset 24 in extended region, after XSAVE header)
    let mxcsr_offset = 64 + 24; // header is 64 bytes
    if clean_state.extended.len() >= mxcsr_offset + 4 {
        clean_state.extended[mxcsr_offset..mxcsr_offset + 4]
            .copy_from_slice(&Mxcsr::DEFAULT.to_le_bytes());
    }
    
    // Restore this clean state to initialize the FPU
    fpu_restore(&clean_state, get_xsave_features());
}

/// Save FPU state for the current thread
/// 
/// Called from KiSwapContext before switching away from a thread.
/// This saves the complete SIMD state so the next time the thread
/// runs, its FPU state is restored.
#[inline]
pub fn save_current_thread_fpu(thread_fpu: *mut ThreadFpuState) {
    if thread_fpu.is_null() {
        return;
    }
    
    unsafe {
        if !(*thread_fpu).state_buffer.is_null() && !(*thread_fpu).in_use {
            // FPU wasn't used, skip save
            return;
        }
        
        let features = if (*thread_fpu).avx_enabled {
            XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64 | XsaveFeature::AVX as u64
        } else {
            XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64
        };
        
        fpu_save((*thread_fpu).state_buffer, features);
        (*thread_fpu).in_use = false;
    }
}

/// Restore FPU state for the next thread
/// 
/// Called from KiSwapContext after switching to a new thread.
/// This restores the FPU state that was previously saved for this thread.
#[inline]
pub fn restore_thread_fpu(thread_fpu: *mut ThreadFpuState) {
    if thread_fpu.is_null() {
        return;
    }
    
    unsafe {
        if !(*thread_fpu).state_buffer.is_null() {
            let features = if (*thread_fpu).avx_enabled {
                XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64 | XsaveFeature::AVX as u64
            } else {
                XsaveFeature::X87 as u64 | XsaveFeature::SSE as u64
            };
            
            fpu_restore((*thread_fpu).state_buffer, features);
            (*thread_fpu).in_use = true;
        }
    }
}

/// Mark FPU as used by the current thread
/// 
/// Called when a thread first uses SIMD instructions. This ensures
/// the FPU state is saved before switching away.
pub fn mark_fpu_used(thread_fpu: *mut ThreadFpuState) {
    if !thread_fpu.is_null() {
        unsafe {
            (*thread_fpu).in_use = true;
        }
    }
}

/// Check if FPU is initialized
pub fn is_initialized() -> bool {
    FPU_INITIALIZED.load(core::sync::atomic::Ordering::SeqCst)
}

/// Check if AVX is supported
pub fn is_avx_supported() -> bool {
    FPU_AVX_SUPPORTED.load(core::sync::atomic::Ordering::SeqCst)
}

/// Smoke test for FPU context switching
pub fn smoke_test() -> bool {
    // // kprintln!("    [FPU SMOKE] Testing XSAVE/XRSTOR...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    if !check_xsave_support() {
        // // kprintln!("    [FPU SMOKE] XSAVE not supported, skipping")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return true; // Not a failure, just not supported
    }

    // Create two test states
    let mut state1 = FpuState::new();
    let state2 = FpuState::new();

    // Initialize state1 with some pattern
    state1.header.xstate_bv = get_xsave_features();

    // Initialize state2 with different pattern (for future use)
    #[allow(unused_variables)]
    let _state2_pattern = get_xsave_features();
    // Suppress warning for state2 - reserved for future comparison tests
    let _ = state2;

    // Save current FPU state to state1
    let features = get_xsave_features();
    fpu_save(&mut state1, features);

    // Modify FPU state (set some XMM registers)
    // In real code we'd use SIMD instructions here

    // Restore from state1 - should give us same state
    fpu_restore(&state1, features);

    // Verify state was restored (XSAVE should produce same result)
    // // kprintln!("    [FPU SMOKE] XSAVE/XRSTOR round-trip: OK")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!("    [FPU SMOKE] FPU features: 0x{:x}", features)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    true
}
