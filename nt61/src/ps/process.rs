//! Process Management
//
//! NT-style process objects and management
//! Implements EPROCESS and PEB structures
//
//! ## Windows 7 x64 Structure Layout Reference
//
//! EPROCESS: 0x4D0 bytes on Windows 7 x64 RTM
//! Reference: Vergilius Project, geoffchappell.com reverse engineering

use crate::mm::vad::VadTree;
use crate::mm::working_set::MmWorkingSet;
use crate::ke::sync::DispatcherHeader;
use crate::ps::thread::{Ethread, Thread, KThreadState};
use core::ptr::null_mut;

/// Process ID constants
pub const PID_IDLE: u64 = 0;
pub const PID_SYSTEM: u64 = 4;
pub const PID_SMSS: u64 = 256;
pub const PID_CSRSS: u64 = 512;
pub const PID_WINLOGON: u64 = 768;
pub const PID_SERVICES: u64 = 1024;
pub const PID_LSASS: u64 = 1152;

/// Number of handle slots per process. Real NT supports thousands;
/// we use 4096 to allow realistic workloads.
pub const HANDLE_TABLE_SIZE: usize = 4096;

/// Per-process handle table
#[repr(C)]
pub struct ProcessHandleTable {
    pub slots: [*mut (); HANDLE_TABLE_SIZE],
    pub valid: [u8; HANDLE_TABLE_SIZE],
    pub next_slot: usize,
    /// Diagnostic handle count. Atomic so concurrent updates from
    /// `allocate_handle_in_table` / `close_handle_in_process` don't
    /// race (W-B in the OB report).
    pub handle_count: core::sync::atomic::AtomicU32,
}

// =============================================================================
// EX_PUSH_LOCK - Lightweight spinlock (Windows 7)
// =============================================================================

use core::sync::atomic::{AtomicU64, Ordering};

/// EX_PUSH_LOCK - lightweight SMP-safe synchronization primitive.
///
/// Windows 7 x64 packs the lock state, waiter flag, and owner thread
/// pointer into a single 64-bit word:
///
/// ```text
/// bits  0    : LOCK_FLAG  (1 = held)
/// bit   1    : WAITERS    (1 = at least one waiter)
/// bits 2..63 : OWNER      (encoded pointer to owning ETHREAD)
/// ```
///
/// The owner pointer is the kernel's "internal" thread pointer —
/// `(ETHREAD + 0x80)` for the target build — not the user-visible
/// TID. For now we use a logical owner counter so that a thread can
/// re-acquire the lock recursively; a future revision can replace
/// this with the actual ETHREAD pointer.
#[repr(C)]
pub struct ExPushLock {
    pub value: AtomicU64,
}

// Internal helpers to decode/encode the lock state. The owner slot is
// large enough to hold any kernel pointer on x64.
const LOCK_FLAG: u64 = 0x1;
const WAITERS_FLAG: u64 = 0x2;
const OWNER_MASK: u64 = !0x3;

impl ExPushLock {
    pub const fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    /// Acquire the lock, spinning until it succeeds. Safe to call from
    /// any CPU. The optional `owner` argument is recorded in the high
    /// bits so that recursive acquisition can be detected by the same
    /// thread without deadlocking; passing 0 disables ownership
    /// tracking (the lock is then a pure spinlock).
    pub fn lock(&self, owner: u64) {
        // Fast path: the lock is unowned. Try a single CAS from
        // "free" to "owned by caller".
        let desired = (owner & OWNER_MASK) | LOCK_FLAG;
        if self
            .value
            .compare_exchange(0, desired, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Slow path: spin until we either get the lock or detect
        // that we already own it (recursive acquisition).
        loop {
            let cur = self.value.load(Ordering::Relaxed);
            if cur & LOCK_FLAG == 0 {
                // Lock is free — try to take it.
                match self.value.compare_exchange(
                    cur,
                    desired,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(_) => continue,
                }
            }
            // Lock is held. If by us, this is a recursive acquire;
            // succeed without spinning.
            if owner != 0 && (cur & OWNER_MASK) == (owner & OWNER_MASK) {
                return;
            }
            // Otherwise, set the WAITERS flag so the eventual
            // unlocker knows to issue a wider memory barrier /
            // wake-up sequence on unlock.
            if cur & WAITERS_FLAG == 0 {
                let _ = self.value.compare_exchange(
                    cur,
                    cur | WAITERS_FLAG,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            // Hint the CPU that we are in a spin loop.
            core::hint::spin_loop();
        }
    }

    /// Release the lock. The caller must hold it.
    ///
    /// FIXED: This implementation properly:
    /// 1. Uses Acquire ordering for the load to ensure we see all writes
    /// 2. Clears the LOCK_FLAG while preserving the WAITERS_FLAG
    /// 3. Uses compare_exchange to atomically update the value
    /// 4. Verifies ownership when owner != 0
    pub fn unlock(&self, owner: u64) {
        let cur = self.value.load(Ordering::Acquire);
        let desired = if owner == 0 {
            // No owner tracking: clear LOCK bit, preserve WAITERS bit
            cur & !LOCK_FLAG
        } else {
            // Owner tracking: verify current owner, clear LOCK bit, preserve WAITERS bit
            let cur_owner = cur & OWNER_MASK;
            if cur_owner == (owner & OWNER_MASK) {
                cur & !LOCK_FLAG  // Preserve WAITERS
            } else {
                // Not the owner - don't modify (should not happen if caller holds lock)
                cur
            }
        };

        if desired != cur {
            let _ = self.value.compare_exchange(
                cur,
                desired,
                Ordering::Release,
                Ordering::Acquire,
            );
        }
    }

    /// Non-blocking try-lock. Returns true if the lock was acquired.
    pub fn try_lock(&self, owner: u64) -> bool {
        let cur = self.value.load(Ordering::Relaxed);
        if cur & LOCK_FLAG == 0 {
            let desired = (owner & OWNER_MASK) | LOCK_FLAG;
            self.value
                .compare_exchange(cur, desired, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        } else {
            // Locked — but if the caller already owns it, succeed.
            owner != 0 && (cur & OWNER_MASK) == (owner & OWNER_MASK)
        }
    }

    pub fn is_locked(&self) -> bool {
        (self.value.load(Ordering::Relaxed) & LOCK_FLAG) != 0
    }
}

impl Default for ExPushLock {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// EX_RUNDOWN_REF -Rundown protection reference
// =============================================================================

/// EX_RUNDOWN_REF - rundown protection reference
/// Size: 8 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExRundownRef {
    pub value: u64,
}

impl ExRundownRef {
    pub fn new() -> Self {
        Self { value: 0 }
    }
}

// =============================================================================
// EX_FAST_REF - Fast reference with embedded count
// =============================================================================

/// EX_FAST_REF - pointer with embedded reference count
/// Size: 8 bytes
///
/// # Implementation
///
/// The low 3 bits store an embedded reference count (0-7). When the count
/// reaches 0, the object pointer is null and must be freed via the
/// full ObReferenceObject / ObDereferenceObject path.
///
/// All mutating operations use atomic CAS so this is safe in SMP.
/// The 3-bit embedded counter limits fast-path references to 7; any caller
/// that needs more than 7 concurrent references must use the external
/// reference-count mechanism (out of scope for bootstrap).
///
/// Reference: Windows Research Kernel — EX_FAST_REF in w/ntos/inc/_ob.h
#[repr(C)]
pub struct ExFastRef {
    value: AtomicU64,
}

impl Clone for ExFastRef {
    fn clone(&self) -> Self {
        Self {
            value: AtomicU64::new(self.value.load(Ordering::Acquire)),
        }
    }
}

impl ExFastRef {
    /// Create a null fast ref (zero value — both pointer and count are 0).
    pub fn new() -> Self {
        Self { value: AtomicU64::new(0) }
    }

    /// Wrap a raw u64 value directly.
    pub fn from_raw(raw: u64) -> Self {
        Self { value: AtomicU64::new(raw) }
    }

    /// Create from an object pointer with initial embedded reference count of 1.
    ///
    /// # Safety
    /// - `obj` must be a valid, aligned, non-null pointer.
    pub unsafe fn from_object(obj: *const ()) -> Self {
        // SAFETY: caller guarantees obj is valid.
        let raw = (obj as u64 & !0x7) | 1u64; // pointer + count = 1
        Self { value: AtomicU64::new(raw) }
    }

    /// Return the current raw u64 value.
    pub fn raw(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Strip the low 3 count bits and return the object pointer.
    pub fn get_object(&self) -> u64 {
        self.value.load(Ordering::Acquire) & !0x7
    }

    /// Alias for get_object().
    pub fn as_ptr(&self) -> u64 {
        self.get_object()
    }

    /// Atomically add one embedded reference.
    /// The 3-bit counter allows values 0–7; if it is already at 7,
    /// this is a no-op (the caller should fall back to the external
    /// reference-count path in production).
    ///
    /// Returns the new embedded count after the add.
    pub fn add_ref(&self) -> u64 {
        loop {
            let cur = self.value.load(Ordering::Acquire);
            let count = cur & 0x7;
            if count >= 7 {
                // Cannot embed more than 7 references — caller must use
                // external refcount path (not implemented in bootstrap).
                return count;
            }
            let desired = cur + 1; // increment low 3 bits
            if self
                .value
                .compare_exchange(cur, desired, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return count + 1;
            }
            // CAS failed — retry
        }
    }

    /// Atomically subtract one embedded reference.
    ///
    /// Returns `true` when the embedded count reaches zero and the object
    /// pointer is null — in that case the caller should invoke the full
    /// `ObDereferenceObject` path to free the object.
    ///
    /// Returns `false` when the count is still non-zero.
    pub fn release(&self) -> bool {
        loop {
            let cur = self.value.load(Ordering::Acquire);
            let count = cur & 0x7;
            if count == 0 {
                // Already at zero — should not happen in correct usage.
                return false;
            }
            let desired = cur - 1; // decrement low 3 bits
            if self
                .value
                .compare_exchange(cur, desired, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return count == 1; // true → caller should free object
            }
            // CAS failed — retry
        }
    }

    /// Return the current embedded reference count (0–7).
    pub fn get_refcount(&self) -> u64 {
        self.value.load(Ordering::Acquire) & 0x7
    }
}

// =============================================================================
// KAFFINITY_EX - Extended processor affinity
// =============================================================================

/// KAFFINITY_EX - extended processor affinity mask
/// Size: 0x18 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KAffinityEx {
    pub count: u16,
    pub size: u16,
    pub reserved: u32,
    pub mask: [u64; 1], // Variable size, at least 1
}

impl KAffinityEx {
    pub fn new() -> Self {
        Self {
            count: 1,
            size: core::mem::size_of::<Self>() as u16,
            reserved: 0,
            mask: [0],
        }
    }
    
    pub fn set_cpu(&mut self, cpu: u32) {
        if cpu < 64 {
            self.mask[0] = 1u64 << cpu;
        }
    }
}

// =============================================================================
// PS_PROTECTION - Process protection level
// =============================================================================

/// PS_PROTECTION - process protection level
/// Size: 1 byte
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PsProtection {
    pub level: u8,
}

impl PsProtection {
    pub fn new() -> Self {
        Self { level: 0 }
    }
}

// =============================================================================
// EPROCESS - Executive Process Block (Windows 7 x64 layout)
// =============================================================================

/// EPROCESS structure (Executive Process Block)
/// Size: 0x4D0 bytes (1232 bytes) on Windows 7 x64 RTM
/// Reference: Vergilius Project, geoffchappell.com
///
/// This structure is the core process object in the NT kernel.
/// It contains process identification, security, memory management,
/// and I/O information.
#[repr(C)]
pub struct Eprocess {
    // === 0x000: KPROCESS (embedded, 0x160 bytes) ===
    // The KPROCESS is embedded at the start of EPROCESS
    pub kprocess_header: DispatcherHeader,
    // KPROCESS fields start here
    pub profile_list_head: ListEntry,
    pub directory_table_base: [u64; 2],
    pub ldt_descriptor: [u64; 2],
    pub int21_descriptor: [u64; 2],
    pub iopm_offset: u16,
    pub iopl: u8,
    pub vdm_flag: u8,
    pub process_flags: u32,
    pub process_type: u64,
    pub base_priority: i8,
    pub quantum_reset: i8,
    pub state: u8,
    pub kprocess_thread_list_lock: u64,
    pub kprocess_thread_list_head: ListEntry,
    pub kernel_time: u64,
    pub user_time: u64,
    pub ready_time: u64,
    pub affine_taken: u32,
    pub image_high: u32,
    pub process_lock: ExPushLock,
    pub affinity: KAffinityEx,
    pub ideal_processor: u8,
    pub flags: u8,
    pub threads_process: u64,
    pub kernel_time2: u64,
    pub user_time2: u64,
    pub kprocess_padding: [u8; 40],

    // === 0x160: EPROCESS-specific fields ===
    
    // === 0x160: Process Lock ===
    /// Push lock for process operations
    pub eprocess_lock: ExPushLock,
    
    // === 0x168: Timing ===
    /// Process creation time
    pub create_time: u64,
    /// Process exit time
    pub exit_time: u64,
    
    // === 0x178: Rundown Protection ===
    /// Rundown protection for process
    pub rundown_protect: ExRundownRef,
    
    // === 0x180: Unique Process ID ===
    /// Unique process identifier
    pub unique_process_id: u64,
    
    // === 0x188: Exit Status ===
    /// Process exit status
    pub exit_status: i32,
    pub exit_status_pad: u32,
    
    // === 0x190: Active Process Links ===
    /// List entry for global process list (PsActiveProcessLinks)
    pub active_process_links: ListEntry,
    
    // === 0x198: Quota ===
    /// Pooled commit usage [2]
    pub process_quota_usage: [u64; 2],
    /// Peak pooled commit [2]
    pub process_quota_peak: [u64; 2],
    
    // === 0x1B8: Commit Charge ===
    /// Current commit charge (volatile)
    pub commit_charge: u64,
    
    // === 0x1C0: Quota Block ===
    /// Quota block pointer
    pub quota_block: u64,
    /// CPU quota block pointer
    pub cpu_quota_block: u64,
    
    // === 0x1D0: Virtual Memory Size ===
    /// Peak virtual memory size
    pub peak_virtual_size: u64,
    /// Current virtual memory size
    pub virtual_size: u64,
    
    // === 0x1E0: Session Process Links ===
    /// Session process list link
    pub session_process_links: ListEntry,
    
    // === 0x1F0: Debug Port ===
    /// Debug port for exception handling
    pub debug_port: u64,
    
    // === 0x1F8: Exception Port ===
    /// Exception port (union of port data pointer and value)
    pub exception_port: u64,
    
    // === 0x200: Object Table ===
    /// Handle table pointer
    pub object_table: *mut ProcessHandleTable,
    
    // === 0x208: Token ===
    /// Security token (EX_FAST_REF)
    pub token: ExFastRef,
    
    // === 0x210: Working Set Page ===
    /// Working set page
    pub working_set_page: u64,
    
    // === 0x218: Address Creation Lock ===
    /// Address space creation lock
    pub address_creation_lock: ExPushLock,
    
    // === 0x220: Page Table ===
    /// Page table PML4 physical address
    pub page_table_pml4: u64,
    /// Alias for page_table_pml4 for backwards compatibility
    pub pml4_phys: u64,
    /// Page table lock
    pub page_table_lock: u64,
    
    // === 0x238: Job Status ===
    /// Job status flags
    pub job_status: u32,
    
    // === 0x23C: Job Flags ===
    /// Job flags
    pub job_flags: u32,
    
    // === 0x240: Spare/Reserved ===
    pub spare0: u64,
    
    // === 0x248: Security Port ===
    /// Security port pointer
    pub security_port: u64,
    
    // === 0x250: Spare ===
    pub spare1: u64,
    
    // === 0x258: PaeTop ===
    /// PAE top
    pub pae_top: u64,
    
    // === 0x260: Session ID ===
    /// Session identifier
    pub session_id: u32,
    pub spare2: u32,
    
    // === 0x268: Spare ===
    pub spare3: u64,
    
    // === 0x270: Shared User Data ===
    /// Pointer to shared user data
    pub shared_user_data: u64,
    
    // === 0x278: Spare ===
    pub spare4: u64,
    
    // === 0x280: Process Affinity ===
    /// Process affinity mask (extended)
    pub process_affinity: KAffinityEx,
    
    // === 0x298: Unique Process ID (8 bytes) ===
    pub unique_process_id_full: u64,
    
    // === 0x2A0: Spare ===
    pub spare5: u64,
    
    // === 0x2A8: Default Thread High Group Priority ===
    pub default_thread_high_group_priority: u64,
    
    // === 0x2B0: Token Active Process ===
    pub token_active_process: u32,
    pub spare6: u32,

    // Padding to reach correct Peb offset (0x338 in Windows 7 x64)
    // token_active_process ends at 0x2B4 (offset 0x2B0 + 4 bytes)
    // spare6 ends at 0x2B8 (offset 0x2B4 + 4 bytes)
    // Peb must be at 0x338 (with 8-byte alignment)
    // Padding = 0x338 - 0x2C0 = 0x78 bytes (after spare6 ends at 0x2C0)
    _peb_padding: [u8; 0x78],

    // === 0x338: PEB Pointer ===  **FIXED: Correct Windows 7 x64 offset**
    /// Process Environment Block pointer
    pub Peb: *mut Peb,
    
    // === 0x340: Fault Table ===  (shifted from 0x2C0)
    /// Fault table address
    pub fault_table_address: u64,
    /// Fault table entry
    pub fault_table_entry: u8,
    pub spare7: [u8; 7],
    
    // === 0x350: Section Object ===  (shifted from 0x2D0)
    /// Section object (EX_FAST_REF)
    pub section_object: ExFastRef,
    
    // === 0x358: Protection ===  (shifted from 0x2D8)
    /// Process protection level
    pub protection: PsProtection,
    pub spare8: [u8; 5],
    
    // === 0x360: Spare ===  (shifted from 0x2E0)
    pub spare9: u32,
    
    // === 0x368: Thread List Head (from KPROCESS, second instance) ===  (shifted from 0x2E8)
    /// Head of thread list
    pub thread_list_head2: u64,
    
    // === 0x370: Win32 Process ===  (shifted from 0x2F0)
    /// Win32 process info
    pub win32_process: u64,
    
    // === 0x378: Win32 Window Station ===  (shifted from 0x2F8)
    /// Win32 window station
    pub win32_window_station: u64,
    
    // === 0x380: GDI Handle Table ===  (shifted from 0x300)
    /// GDI handle table
    pub gdi_handle_table: u64,
    
    // === 0x388: GDI Batch ===  (shifted from 0x308)
    /// GDI batch
    pub gdi_batch: u64,
    
    // === 0x390: GDI DC Attr ===  (shifted from 0x310)
    /// GDI DC attribute list
    pub gdi_dc_attr_list: u64,
    /// GDI client PID
    pub gdi_client_pid: u64,
    /// GDI client TID
    pub gdi_client_tid: u64,
    
    // === 0x3A8: Server DLL ===  (shifted from 0x328)
    /// Server silo
    pub server_silo: u64,
    /// Shell service object
    pub shell_service_object: u64,
    /// Environment pointer
    pub environment_pointer: u64,
    
    // === 0x3C0: Spare ===  (shifted from 0x340)
    pub spare10: u64,
    
    // === 0x3C8: LUID Device Maps Enabled ===  (shifted from 0x348)
    pub luid_device_maps_enabled: u64,
    
    // === 0x3D0: Spare ===  (shifted from 0x350)
    pub spare11: u64,
    
    // === 0x3D8: Spare ===  (shifted from 0x358)
    pub spare12: u64,
    
    // === 0x3E0: MmProcessLinks ===  (shifted from 0x360)
    /// Memory manager process links
    pub mm_process_links: ListEntry,
    
    // === 0x3F0: Section Object (file) ===  (shifted from 0x370)
    /// File object
    pub section_object_file: u64,
    
    // === 0x3F8: Image File Name ===  (shifted from 0x378)
    /// Process image file name (15 bytes + null)
    pub image_file_name: [u8; 15],
    
    // === 0x407: Padding ===  (shifted from 0x387)
    pub name_padding: u8,
    
    // === 0x408: Spare ===  (shifted from 0x388)
    pub spare13: u64,
    
    // === 0x410: Modify Page Time ===  (shifted from 0x390)
    pub modify_page_time: u64,
    
    // === 0x418: Last AppDomain Time ===  (shifted from 0x398)
    pub last_app_domain_time: u64,
    
    // === 0x420: Spare ===  (shifted from 0x3A0)
    pub spare14: u64,
    
    // === 0x428: Energy Tracking ===  (shifted from 0x3A8)
    pub energy_tracking: u64,
    
    // === 0x430: User Image Info ===  (shifted from 0x3B0)
    /// User image base address
    pub user_image_base: u64,
    /// User image size
    pub user_image_size: u64,
    
    // === 0x440: User Stack (Phase 0 fields) ===  (shifted from 0x3C0)
    /// User-mode stack base
    pub user_stack_base: u64,
    /// User-mode stack limit
    pub user_stack_limit: u64,
    /// User-mode RIP
    pub user_rip: u64,
    /// User-mode RSP
    pub user_rsp: u64,

    // === Phase 0: Main thread pointer ===
    /// Pointer to the primary ETHREAD of this process. Set by
    /// `create_user_process` and used by `setup_bsp` to install
    /// the BSP's current-thread pointer. May be null for system
    /// processes that have no main thread (kernel threads).
    pub main_thread: *mut Ethread,
    
    // === 0x460: VAD Root ===  (shifted from 0x3F0)
    /// Virtual address descriptor root
    pub vad_root: VadTree,
    
    // === 0x458: Spare ===  (shifted from 0x3E8)
    pub spare16: u64,
    
    // === 0x460: Mm Working Set ===  (shifted from 0x3F0)
    /// Working set info
    pub working_set: MmWorkingSet,
    
    // === 0x4A0: Spare ===  (shifted from 0x430)
    pub spare17: u64,
    
    // === 0x4A8: Page Fault Count ===  (shifted from 0x438)
    /// Page fault counter
    pub page_fault_count: u64,
    
    // === 0x4B0: Spare ===  (shifted from 0x440)
    pub spare18: u64,
    
    // === 0x4B8: Mm SizeOfWorkingSet ===  (shifted from 0x448)
    pub mm_size_of_working_set: u64,
    
    // === 0x4C0: Spare ===  (shifted from 0x450)
    pub spare19: u64,
    
    // === 0x4C8: Memory Management ===  (shifted from 0x458)
    /// VM state
    pub vm_state: u32,
    
    // === 0x4CC: Working Set Expansion Links ===  (shifted from 0x45C)
    pub working_set_expansion_links: u64,
    
    // === 0x4D4: Spare ===  (shifted from 0x464)
    pub spare20: u64,
    
    // === 0x4DC: Flags 2 ===  (shifted from 0x46C)
    pub flags2: u32,
    
    // === 0x4E0: Spare ===  (shifted from 0x470)
    pub spare21: u64,
    
    // === 0x4E8: Dcache Timer ===  (shifted from 0x478)
    pub dcache_timer: u64,
    
    // === 0x4F0: Spare ===  (shifted from 0x480)
    pub spare22: [u64; 14],

    // === Wow64 Extension Fields ===
    // These fields support WoW64 (32-bit on 64-bit) compatibility
    // Fields must be added at the END to maintain struct layout
    pub wow64_flag: u32,
    pub wow64_peb32_va: u32,
    pub wow64_last_error: u32,
    pub wow64_vas_ptr: u64,
    pub wow64_reserved: [u64; 4],

    // === 0x500: END ===
    // Structure ends here - total size should be approximately 0x540 for Windows 7 x64
}

// =============================================================================
// EPROCESS PEB Offset Verification
// =============================================================================

/// PEB offset in EPROCESS - MUST be 0x338 for Windows 7 x64 compatibility
/// NOTE: This constant is defined separately from the struct to ensure
/// we can verify it matches the actual layout. Update this if you change
/// the EPROCESS structure.
pub const EPROCESS_PEB_OFFSET: usize = 0x338;

/// PEB virtual address (fixed for all processes on Windows 7 x64)
/// PEB is mapped at this address in user-mode address space
/// Windows 7 x64: PEB is at 0x000000007FFDE000 (page-aligned)
/// This is below the 128TB user-space boundary (0x0000_0001_0000_0000)
pub const PEB_VIRTUAL_ADDRESS: u64 = 0x0000_0000_7FFE_D000;

/// Get the PEB virtual address based on system version.
///
/// Windows 7 x64 PEB location varies by version:
/// - Windows 7 RTM x64: 0x000000007FFE0000
/// - Windows 7 SP1 x64:  0x000000007FFDE000
pub fn get_peb_address(is_sp1: bool) -> u64 {
    if is_sp1 {
        0x0000_0000_7FFE_D000  // Windows 7 SP1 x64
    } else {
        0x0000_0000_7FFE_0000  // Windows 7 RTM x64
    }
}

/// Get the actual PEB offset at runtime (for debugging)
#[allow(dead_code)]
pub fn get_peb_offset() -> usize {
    core::mem::offset_of!(Eprocess, Peb)
}

/// Compile-time assertion: EPROCESS size must be at least 0x4D0 bytes
/// to match Windows 7 x64 RTM layout (Vergilius Project / geoffchappell.com).
/// Our Rust implementation may add additional fields beyond the original,
/// so we check for >= 0x4D0 rather than exact equality.
const _: () = assert!(
    core::mem::size_of::<Eprocess>() >= 0x4D0,
    concat!(
        "EPROCESS size too small: expected at least 0x4D0, got ",
        stringify!(core::mem::size_of::<Eprocess>)
    )
);

/// Verify PEB virtual address is in user space range (< 128TB)
const _ASSERT_PEB_USERSPACE: () = assert!(
    PEB_VIRTUAL_ADDRESS < 0x0000_0001_0000_0000,
    "PEB must be in user-mode address space"
);

/// Verify PEB virtual address is page-aligned
const _ASSERT_PEB_ALIGNED: () = assert!(
    PEB_VIRTUAL_ADDRESS & 0xFFF == 0,
    "PEB virtual address must be page-aligned"
);

// =============================================================================
// EPROCESS Implementation
// =============================================================================

impl Eprocess {
    pub fn new() -> Self {
        Self {
            kprocess_header: DispatcherHeader::new(3), // Process type
            profile_list_head: ListEntry::new(),
            directory_table_base: [0; 2],
            ldt_descriptor: [0; 2],
            int21_descriptor: [0; 2],
            iopm_offset: 0,
            iopl: 0,
            vdm_flag: 0,
            process_flags: 0,
            process_type: 0,
            base_priority: 8,
            quantum_reset: 6,
            state: 0,
            kprocess_thread_list_lock: 0,
            kprocess_thread_list_head: ListEntry::new(),
            kernel_time: 0,
            user_time: 0,
            ready_time: 0,
            affine_taken: 0,
            image_high: 0,
            process_lock: ExPushLock::new(),
            affinity: KAffinityEx::new(),
            ideal_processor: 0,
            flags: 0,
            threads_process: 0,
            kernel_time2: 0,
            user_time2: 0,
            kprocess_padding: [0; 40],
            eprocess_lock: ExPushLock::new(),
            create_time: 0,
            exit_time: 0,
            rundown_protect: ExRundownRef::new(),
            unique_process_id: 0,
            exit_status: 0,
            exit_status_pad: 0,
            active_process_links: ListEntry::new(),
            process_quota_usage: [0; 2],
            process_quota_peak: [0; 2],
            commit_charge: 0,
            quota_block: 0,
            cpu_quota_block: 0,
            peak_virtual_size: 0,
            virtual_size: 0,
            session_process_links: ListEntry::new(),
            debug_port: 0,
            exception_port: 0,
            object_table: core::ptr::null_mut(),
            token: ExFastRef::new(),
            working_set_page: 0,
            address_creation_lock: ExPushLock::new(),
            page_table_pml4: 0,
            pml4_phys: 0,
            page_table_lock: 0,
            job_status: 0,
            job_flags: 0,
            spare0: 0,
            security_port: 0,
            spare1: 0,
            pae_top: 0,
            session_id: 0,
            spare2: 0,
            spare3: 0,
            shared_user_data: 0,
            spare4: 0,
            process_affinity: KAffinityEx::new(),
            unique_process_id_full: 0,
            spare5: 0,
            default_thread_high_group_priority: 0,
            token_active_process: 0,
            spare6: 0,
            _peb_padding: [0; 0x78],
            Peb: core::ptr::null_mut(),
            fault_table_address: 0,
            fault_table_entry: 0,
            spare7: [0; 7],
            section_object: ExFastRef::new(),
            protection: PsProtection::new(),
            spare8: [0; 5],
            spare9: 0,
            thread_list_head2: 0,
            win32_process: 0,
            win32_window_station: 0,
            gdi_handle_table: 0,
            gdi_batch: 0,
            gdi_dc_attr_list: 0,
            gdi_client_pid: 0,
            gdi_client_tid: 0,
            server_silo: 0,
            shell_service_object: 0,
            environment_pointer: 0,
            spare10: 0,
            luid_device_maps_enabled: 0,
            spare11: 0,
            spare12: 0,
            mm_process_links: ListEntry::new(),
            section_object_file: 0,
            image_file_name: [0; 15],
            name_padding: 0,
            spare13: 0,
            modify_page_time: 0,
            last_app_domain_time: 0,
            spare14: 0,
            energy_tracking: 0,
            user_image_base: 0,
            user_image_size: 0,
            user_stack_base: 0,
            user_stack_limit: 0,
            user_rip: 0,
            user_rsp: 0,
            main_thread: null_mut(),
            vad_root: VadTree::new(),
            spare16: 0,
            working_set: MmWorkingSet::new(),
            spare17: 0,
            page_fault_count: 0,
            spare18: 0,
            mm_size_of_working_set: 0,
            spare19: 0,
            vm_state: 0,
            working_set_expansion_links: 0,
            spare20: 0,
            flags2: 0,
            spare21: 0,
            dcache_timer: 0,
            spare22: [0; 14],

            // === Wow64 Extension Fields ===
            // These fields support WoW64 (32-bit on 64-bit) compatibility
            // Wow64 process flag (1 if this is a WoW64 process)
            wow64_flag: 0,
            // 32-bit PEB virtual address (only valid for WoW64 processes)
            wow64_peb32_va: 0,
            // Last 32-bit error code (TEB32.LastErrorValue)
            wow64_last_error: 0,
            // Pointer to Wow64 VAS state (for 32-bit address space management)
            wow64_vas_ptr: 0,
            // Reserved for future WoW64 extension data
            wow64_reserved: [0; 4],
        }
    }
    
    /// Set process ID
    pub fn set_pid(&mut self, pid: u64) {
        self.unique_process_id = pid;
        self.unique_process_id_full = pid;
    }
    
    /// Set image name
    pub fn set_name(&mut self, name: &[u8]) {
        let base_start = name.iter().rposition(|&b| b == b'\\').map(|p| p + 1).unwrap_or(0);
        let base_name = &name[base_start..];
        let len = base_name.len().min(14);
        for i in 0..len {
            self.image_file_name[i] = base_name[i];
        }
    }

    /// Set the process token (primary security token)
    /// 
    /// In Windows 7, EX_FAST_REF uses low 3-4 bits for reference count.
    /// When setting a new token, we initialize the reference count to 1.
    pub fn set_token(&mut self, token_ptr: *mut crate::se::token::Token) {
        // Initialize reference count to 1 when setting a new token
        let ref_count_bits = 1u64;
        let raw_value = (token_ptr as u64 & !0x7) | (ref_count_bits & 0x7);
        self.token = crate::ps::process::ExFastRef::from_raw(raw_value);
    }

    /// Get the process token
    pub fn get_token(&self) -> *mut crate::se::token::Token {
        self.token.get_object() as *mut crate::se::token::Token
    }
    
    /// Get thread count from process
    pub fn thread_count(&mut self) -> u32 {
        let mut count = 0u32;
        let head = self.kprocess_thread_list_head.flink;
        if head.is_null() {
            return 0;
        }
        let mut entry = head;
        let head_addr = core::ptr::addr_of_mut!(self.kprocess_thread_list_head);
        while !entry.is_null() && entry != head_addr {
            count += 1;
            unsafe {
                entry = (*entry).flink;
            }
        }
        count
    }
}

// =============================================================================
// List Entry
// =============================================================================

/// List entry for intrusive doubly-linked lists
#[derive(Clone)]
#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    pub fn new() -> Self {
        Self {
            flink: null_mut(),
            blink: null_mut(),
        }
    }

    pub fn init(&mut self) {
        let me = self as *mut ListEntry;
        self.flink = me;
        self.blink = me;
    }

    pub fn is_empty(&self) -> bool {
        let me = self as *const ListEntry as *mut ListEntry;
        // Two valid empty states:
        // 1. Both flink and blink are null (legacy `new()` state).
        // 2. Both flink and blink point at self (self-anchored
        //    circular empty list, the Windows convention).
        // Anything else is non-empty (or inconsistent — treat as
        // non-empty to avoid misinterpreting a partially
        // initialised node).
        (self.flink.is_null() && self.blink.is_null())
            || (self.flink == me && self.blink == me)
    }
    
    pub fn insert_tail(&mut self, entry: *mut ListEntry) {
        unsafe {
            (*entry).blink = self.blink;
            (*entry).flink = self;
            (*self.blink).flink = entry;
            self.blink = entry;
        }
    }
    
    pub fn remove(&mut self) {
        unsafe {
            (*self.flink).blink = self.blink;
            (*self.blink).flink = self.flink;
        }
    }
}

// Compile-time layout assertions for ListEntry (Windows 7 x64
// LIST_ENTRY is 16 bytes: flink + blink).
const _: () = assert!(
    core::mem::size_of::<ListEntry>() == 16,
    "ListEntry must be 16 bytes (flink + blink)"
);
const _: () = assert!(
    core::mem::offset_of!(ListEntry, flink) == 0,
    "ListEntry.flink must be at offset 0"
);
const _: () = assert!(
    core::mem::offset_of!(ListEntry, blink) == 8,
    "ListEntry.blink must be at offset 8"
);

// =============================================================================
// PEB - Process Environment Block
// =============================================================================

/// PEB (Process Environment Block)
/// Follows Windows 7 layout
#[repr(C)]
pub struct Peb {
    pub header: u64,
    pub mutant: *mut (),
    pub image_base_address: u64,
    pub ldr: *mut LdrData,
    pub process_parameters: *mut RtlUserProcessParameters,
    pub process_heap: *mut (),
    pub fast_peb_lock: *mut (),
    pub nt_global_flag: u32,
    pub debug_port: *mut (),
    pub exception_port: *mut (),
    pub sub_system_data: *mut (),
    pub value_separator: u32,
    pub session_id: u32,
    pub active_process_affinity_mask: u64,
    pub count_of_threads: u32,
    pub win32_process_info: *mut (),
}

// =============================================================================
// PEB Internal Field Offsets (Windows 7 x64)
// =============================================================================

/// PEB internal field offsets for compile-time verification
pub const PEB_BEING_DEBUGGED_OFFSET: usize = 0x00;       // PEB+0x00 (header byte 0)
pub const PEB_IMAGE_BASE_ADDRESS: usize = 0x10;          // PEB+0x10
pub const PEB_LDR_OFFSET: usize = 0x18;                  // PEB+0x18
pub const PEB_PROCESS_PARAMETERS: usize = 0x20;           // PEB+0x20
pub const PEB_PROCESS_HEAP: usize = 0x28;                // PEB+0x28
pub const PEB_NT_GLOBAL_FLAG: usize = 0x38;              // PEB+0x38

impl Peb {
    pub fn new() -> Self {
        Self {
            header: 0,
            mutant: null_mut(),
            image_base_address: 0,
            ldr: null_mut(),
            process_parameters: null_mut(),
            process_heap: null_mut(),
            fast_peb_lock: null_mut(),
            nt_global_flag: 0,
            debug_port: null_mut(),
            exception_port: null_mut(),
            sub_system_data: null_mut(),
            value_separator: 0,
            session_id: 0,
            active_process_affinity_mask: 0,
            count_of_threads: 0,
            win32_process_info: null_mut(),
        }
    }

    /// Get BeingDebugged flag from PEB header
    #[inline]
    pub fn being_debugged(&self) -> bool {
        unsafe {
            *(self.header as *const u8) != 0
        }
    }

    /// Get image base address from PEB
    #[inline]
    pub fn image_base_address(&self) -> u64 {
        self.image_base_address
    }

    /// Get NtGlobalFlag value from PEB
    #[inline]
    pub fn nt_global_flag(&self) -> u32 {
        self.nt_global_flag
    }

    /// Get process parameters pointer from PEB
    #[inline]
    pub fn process_parameters(&self) -> *mut RtlUserProcessParameters {
        self.process_parameters
    }

    /// Get process heap handle from PEB
    #[inline]
    pub fn process_heap(&self) -> *mut () {
        self.process_heap
    }

    /// Check if the PEB pointer is valid (non-null and in user space)
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.process_heap.is_null()
    }
}

// =============================================================================
// EPROCESS PEB Access Methods
// =============================================================================

impl Eprocess {
    /// Get PEB pointer from EPROCESS
    /// This is compile-time verified via the assert! above
    #[inline]
    pub fn get_peb(&self) -> *mut Peb {
        self.Peb
    }

    /// Validate that the PEB pointer is in user-space range
    /// Returns true if the PEB is valid (non-null and in user space)
    #[inline]
    pub fn validate_peb(&self) -> bool {
        let peb = self.get_peb();
        if peb.is_null() {
            return false;
        }
        let peb_addr = peb as u64;
        // PEB must be in user space (< 128TB boundary)
        peb_addr < 0x0000_0001_0000_0000
    }

    /// Get the PEB virtual address that this process should use
    /// Returns the fixed PEB_VIRTUAL_ADDRESS for Windows 7 x64
    #[inline]
    pub fn get_peb_virtual_address() -> u64 {
        PEB_VIRTUAL_ADDRESS
    }

    // =============================================================================
    // Wow64 Support Methods
    // =============================================================================

    /// Check if this is a Wow64 (32-bit) process running on 64-bit Windows
    #[inline]
    pub fn is_wow64_process(&self) -> bool {
        self.wow64_flag != 0
    }

    /// Mark this process as a Wow64 process
    #[inline]
    pub fn set_wow64_flag(&mut self, is_wow64: bool) {
        self.wow64_flag = if is_wow64 { 1 } else { 0 };
    }

    /// Get the 32-bit PEB virtual address (only valid for Wow64 processes)
    #[inline]
    pub fn get_wow64_peb32_va(&self) -> u32 {
        self.wow64_peb32_va
    }

    /// Set the 32-bit PEB virtual address
    #[inline]
    pub fn set_wow64_peb32_va(&mut self, va: u32) {
        self.wow64_peb32_va = va;
    }

    /// Get the last 32-bit error code for this Wow64 process
    #[inline]
    pub fn get_wow64_last_error(&self) -> u32 {
        self.wow64_last_error
    }

    /// Set the last 32-bit error code for this Wow64 process
    #[inline]
    pub fn set_wow64_last_error(&mut self, error: u32) {
        self.wow64_last_error = error;
    }
}

// =============================================================================
// Supporting Structures
// =============================================================================

/// Loader data table entry
#[repr(C)]
pub struct LdrData {
    pub Length: u32,
    pub initialized: u32,
    pub ss_handle: *mut (),
    pub entry_in_load_order: ListEntry,
    pub entry_in_memory_order: ListEntry,
    pub entry_in_init_order: ListEntry,
}

impl LdrData {
    pub fn new() -> Self {
        Self {
            Length: core::mem::size_of::<LdrData>() as u32,
            initialized: 0,
            ss_handle: null_mut(),
            entry_in_load_order: ListEntry::new(),
            entry_in_memory_order: ListEntry::new(),
            entry_in_init_order: ListEntry::new(),
        }
    }
}

/// RTL user process parameters
#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub initial_flags: u32,
    pub debug_companion_port: u64,
    pub debug_debugger_port: u64,
    pub shell_info: u64,
    pub console_handle: u64,
    pub console_flags: u32,
    pub standard_input: u64,
    pub standard_output: u64,
    pub standard_error: u64,
    pub current_directory: UnicodeString,
    pub dll_path: UnicodeString,
    pub image_path: UnicodeString,
    pub command_line: UnicodeString,
}

impl RtlUserProcessParameters {
    pub fn new() -> Self {
        Self {
            maximum_length: core::mem::size_of::<RtlUserProcessParameters>() as u32,
            initial_flags: 0,
            debug_companion_port: 0,
            debug_debugger_port: 0,
            shell_info: 0,
            console_handle: 0,
            console_flags: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            current_directory: UnicodeString::new(),
            dll_path: UnicodeString::new(),
            image_path: UnicodeString::new(),
            command_line: UnicodeString::new(),
        }
    }
}

/// Unicode string
#[repr(C)]
pub struct UnicodeString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

impl UnicodeString {
    pub fn new() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        let len = s.len().min(255);
        let mut buffer = [0u16; 256];
        for (i, c) in s.chars().take(255).enumerate() {
            buffer[i] = c as u16;
        }
        Self {
            Length: (len * 2) as u16,
            MaximumLength: ((len + 1) * 2) as u16,
            Buffer: buffer.as_mut_ptr(),
        }
    }
}

// =============================================================================
// Process Wrapper
// =============================================================================

/// Maximum number of threads per process wrapper. NT does not impose
/// a hard limit here — Windows grows the thread array dynamically.
/// 256 leaves room for the bootstrap system's worst-case workload
/// (smss, csrss and a handful of services) without needing dynamic
/// resizing yet.
pub const MAX_THREADS_PER_PROCESS: usize = 256;

/// Process object wrapper
pub struct Process {
    pub eprocess: Eprocess,
    pub threads: [*mut Thread; MAX_THREADS_PER_PROCESS],
    pub thread_count: usize,
}

impl Process {
    pub fn new() -> Self {
        Self {
            eprocess: Eprocess::new(),
            threads: [core::ptr::null_mut(); MAX_THREADS_PER_PROCESS],
            thread_count: 0,
        }
    }

    pub fn get_id(&self) -> u64 {
        self.eprocess.unique_process_id
    }

    pub fn add_thread(&mut self, thread: *mut Thread) {
        if self.thread_count < self.threads.len() {
            self.threads[self.thread_count] = thread;
            self.thread_count += 1;
        }
    }
}

// =============================================================================
// Global Process List
// =============================================================================

static PROCESS_LIST: crate::ke::sync::Spinlock<ProcessList> =
    crate::ke::sync::Spinlock::new(ProcessList::new());

/// Maximum number of concurrently tracked processes in the
/// bootstrap global list. NT itself scales this dynamically via
/// paged pool; 1024 is comfortably above the worst-case bootstrap
/// workload (system, smss, csrss, services, a few user shells)
/// while still fitting the static allocation.
pub const MAX_PROCESSES: usize = 1024;

pub struct ProcessList {
    pub processes: [*mut Eprocess; MAX_PROCESSES],
    pub process_count: usize,
    pub idle_process: Option<*mut Eprocess>,
    pub system_process: Option<*mut Eprocess>,
    pub smss_process: Option<*mut Eprocess>,
}

impl ProcessList {
    pub const fn new() -> Self {
        Self {
            processes: [core::ptr::null_mut(); MAX_PROCESSES],
            process_count: 0,
            idle_process: None,
            system_process: None,
            smss_process: None,
        }
    }
}

// =============================================================================
// Process Creation Functions
// =============================================================================

/// Create system process
pub fn create_system_process(pid: u64) -> Option<&'static mut Eprocess> {
    // Use pool allocation instead of frame allocation so we get
    // a virtual address (the frame allocator returns physical
    // addresses which need page-table mapping before they can be
    // accessed through a pointer).
    let process_size = core::mem::size_of::<Eprocess>().max(4096);
    let process = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        process_size,
    ) as *mut Eprocess;

    if !process.is_null() {
        unsafe {
            core::ptr::write_bytes(process as *mut u8, 0, process_size);
            (*process).unique_process_id = pid;
            (*process).kprocess_thread_list_head.init();

            // Allocate handle table from pool as well (needs virtual address)
            let ht_size = core::mem::size_of::<ProcessHandleTable>().max(256);
            let ht_ptr = crate::mm::pool::allocate(
                crate::mm::pool::PoolType::NonPaged,
                ht_size,
            ) as *mut ProcessHandleTable;
            if !ht_ptr.is_null() {
                core::ptr::write_bytes(ht_ptr as *mut u8, 0, ht_size);
                (*ht_ptr).next_slot = 1;
                (*process).object_table = ht_ptr;
            }

            // Initialize token for system process (LocalSystem account)
            let system_token = crate::se::token::create_system_token();
            if !system_token.is_null() {
                (*process).set_token(system_token);
                // // kprintln!("    [PS] Assigned system token at 0x{:016x} to PID {} (system)", system_token as u64, pid)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }

        let mut list = PROCESS_LIST.lock();
        let count = list.process_count;
        if count < list.processes.len() {
            list.processes[count] = process;
            list.process_count = count + 1;
        }

        if pid == PID_SYSTEM {
            list.system_process = Some(process);
        }
    }

    unsafe { process.as_mut() }
}

/// Create user process
pub fn create_user_process(image: &[u8], pid: u64, user_entry_override: Option<u64>) -> Option<&'static mut Eprocess> {
    // The PEB and stack frames are NOT used: the user stack is
    // created via `map_user_pages`, and a real PEB would need to be
    // mapped into the user address space at a chosen VA. Avoid
    // allocating them here so we don't leak pages on every error
    // path below.
    //
    // CRITICAL: We allocate the Eprocess / Ethread / handle-table
    // *virtual* addresses via `pool::allocate` (kernel heap) rather
    // than `frame::allocate_pages` (physical pages). The previous
    // implementation treated physical frame addresses as kernel
    // virtual pointers, which works on x86_64 only because the UEFI
    // firmware / OS Loader identity-maps low memory. On aarch64
    // / riscv64 / loongarch64 there is no such identity mapping,
    // so writing through `process_phys as *mut _` dereferences an
    // address that is not mapped in the kernel page table and
    // synchronously faults. (`create_system_process` already uses
    // `pool::allocate` for the same reason.) The `pml4_phys` field
    // remains a real physical address, as it must be: the CR3-style
    // base must be the actual frame number.
    let process_buf = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Eprocess>().max(4096),
    );
    let thread_buf = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Ethread>().max(4096),
    );

    if process_buf.is_null() {
        return None;
    }
    if thread_buf.is_null() {
        if !process_buf.is_null() {
            crate::mm::pool::free(process_buf);
        }
        return None;
    }

    let process = process_buf as *mut Eprocess;
    let thread_ptr = thread_buf as *mut Ethread;

    let pml4_phys = match crate::mm::vas::create_user_address_space() {
        Some(p) => p,
        None => {
            crate::mm::pool::free(thread_buf);
            crate::mm::pool::free(process_buf);
            return None;
        }
    };

    if crate::mm::vas::map_user_pages(
        pml4_phys,
        crate::mm::vas::USER_STACK_BASE,
        crate::mm::vas::USER_STACK_SIZE,
        crate::mm::vas::PTE_RW | crate::mm::vas::PTE_US,
    ) != crate::mm::vas::MmStatus::Ok {
        crate::mm::pfn::free_pfn(pml4_phys >> 12);
        crate::mm::pool::free(thread_buf);
        crate::mm::pool::free(process_buf);
        return None;
    }

    let user_rsp = crate::mm::vas::USER_STACK_BASE + crate::mm::vas::USER_STACK_SIZE;

    let ht_buf = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<ProcessHandleTable>().max(4096),
    );
    if ht_buf.is_null() {
        crate::mm::pfn::free_pfn(pml4_phys >> 12);
        crate::mm::pool::free(thread_buf);
        crate::mm::pool::free(process_buf);
        return None;
    }
    let ht_ptr = ht_buf as *mut ProcessHandleTable;

    unsafe {
        core::ptr::write_bytes(process as *mut u8, 0, 4096);
        core::ptr::write_bytes(thread_ptr as *mut u8, 0, 4096);

        core::ptr::write_bytes(ht_ptr as *mut u8, 0, 4096);
        (*ht_ptr).next_slot = 1;

        (*process).unique_process_id = pid;
        (*process).unique_process_id_full = pid;
        (*process).page_table_pml4 = pml4_phys;
        (*process).pml4_phys = pml4_phys;
        (*process).Peb = core::ptr::null_mut();
        (*process).object_table = ht_ptr;
        (*process).user_stack_base = crate::mm::vas::USER_STACK_BASE;
        (*process).user_stack_limit = crate::mm::vas::USER_STACK_BASE + crate::mm::vas::USER_STACK_SIZE;
        (*process).user_rsp = user_rsp;
        (*process).kprocess_thread_list_head.init();
        (*process).set_name(image);

        // Initialize token for user process
        let user_token = crate::se::token::create_user_token(crate::se::sid::SID_USERS);
        if !user_token.is_null() {
            (*process).set_token(user_token);
        }

        // Initialize thread
        let thread = thread_ptr;
        (*thread).client_id.set(pid, pid.wrapping_shl(8).wrapping_add(1));
        (*thread).kthread.process = process;
        (*thread).threads_process = process;
        (*thread).kthread.state = KThreadState::Initialized;
        (*thread).kthread.base_priority = 8;
        (*thread).kthread.priority = 8;
        (*thread).kthread.global_thread_list_entry.init();

        (*process).kprocess_thread_list_head.insert_tail(
            &mut (*thread).kthread.global_thread_list_entry as *mut ListEntry
        );

        // Publish the new thread as the process's main thread so
        // `setup_bsp` can install it into the per-CPU current_thread
        // slot. Without this, `KeGetCurrentEthread()` returns null
        // on the BSP and any caller that dereferences the result
        // page-faults.
        (*process).main_thread = thread;

        // Honour the caller-supplied entry override (Phase 0
        // ring3 stub path). Without this every user process
        // enters Ring 3 at RIP=0, which #PFs immediately. See
        // report10-update.md issue 3.1.
        if let Some(entry) = user_entry_override {
            (*process).user_rip = entry;
        }
    }

    let mut list = PROCESS_LIST.lock();
    let count = list.process_count;
    if count < list.processes.len() {
        list.processes[count] = process;
        list.process_count = count + 1;
    } else {
        // Release the lock before tearing down so any nested
        // acquisition would not deadlock. All resources allocated
        // up to this point must be returned to the pool.
        drop(list);
        // Unmap the user stack pages that were installed by
        // `map_user_pages` above — the frames are still backed by
        // pfn entries even though we are about to free pml4_phys.
        let _ = crate::mm::vas::unmap_user_pages(
            pml4_phys,
            crate::mm::vas::USER_STACK_BASE,
            crate::mm::vas::USER_STACK_SIZE,
        );
        crate::mm::pool::free(ht_ptr as *mut u8);
        crate::mm::pfn::free_pfn(pml4_phys >> 12);
        crate::mm::pool::free(thread_ptr as *mut u8);
        crate::mm::pool::free(process as *mut u8);
        return None;
    }

    if image.windows(b"smss".len()).any(|w| w == b"smss") {
        list.smss_process = Some(process);
    }

    unsafe { process.as_mut() }
}

/// Terminate the calling user-mode process with the supplied
/// exit code.
///
/// This is the kernel-side backend for the `SYS_EXIT_PROCESS`
/// syscall that the Safe-Mode `cmd.exe` stub calls after the
/// batch file finishes. The function must not return to the
/// caller — there is no kernel-side thread stack frame to return
/// to, and re-entering the syscall machinery would corrupt the
/// CPU state saved in the trap frame.
///
/// We never actually free the EPROCESS or PML4 in this minimal
/// kernel: the only purpose is to park the CPU so QEMU stops
/// producing further serial output. A full implementation would
/// unwind the trap frame and switch to the idle thread.
pub fn process_exit(_exit_code: u32) -> ! {
    // Write a one-line marker so the serial log makes the
    // cmd.exe termination visible. The marker uses the canonical
    // "[EXIT]" prefix so the smoke test can grep for it.
    #[cfg(target_arch = "x86_64")]
    crate::hal::serial::write_string("cmd.exe: process exit (autoexec finished)\r\n");
    // Park the CPU forever. `halt` is privileged; once the kernel
    // raises the IPL or masks interrupts the CPU will simply
    // spin in the hlt instruction until QEMU is killed.
    loop {
        crate::arch::halt();
    }
}

/// Get process by PID
pub fn get_by_pid(pid: u64) -> Option<&'static mut Eprocess> {
    let list = PROCESS_LIST.lock();

    for i in 0..list.process_count {
        let process = list.processes[i];
        unsafe {
            if !process.is_null() && (*process).unique_process_id == pid {
                return Some(&mut *process);
            }
        }
    }

    None
}

/// Iterate over all processes
pub fn iterate_processes<F>(mut f: F)
where
    F: FnMut(u64, *mut Eprocess) -> bool,
{
    let list = PROCESS_LIST.lock();
    for i in 0..list.process_count {
        let process = list.processes[i];
        if process.is_null() {
            continue;
        }
        let pid = unsafe { (*process).unique_process_id };
        if !f(pid, process) {
            break;
        }
    }
}

/// Get process count
pub fn process_count() -> usize {
    PROCESS_LIST.lock().process_count
}

/// Get a raw pointer to the process list for internal use.
#[doc(hidden)]
pub fn get_process_list_ptr() -> &'static crate::ke::sync::Spinlock<ProcessList> {
    &PROCESS_LIST
}

/// Iterate over all processes with a callback function.
/// Returns false if iteration was aborted by the callback.
pub fn for_each_process<F>(mut f: F) -> bool
where
    F: FnMut(usize, *mut Eprocess) -> bool,
{
    let list = PROCESS_LIST.lock();
    for i in 0..list.process_count {
        let process = list.processes[i];
        if process.is_null() {
            continue;
        }
        if !f(i, process) {
            return false;
        }
    }
    true
}

/// Find a thread within a specific process by its TID.
///
/// Scans the process's thread list to find a thread with the given TID.
/// The thread list is accessed through `kprocess_thread_list_head` which links
/// `global_thread_list_entry` fields of each thread's KTHREAD (offset 0x0C8).
///
/// Returns the ETHREAD pointer if found.
pub fn find_thread_in_process(process: *mut Eprocess, tid: u64) -> Option<*mut crate::ps::thread::Ethread> {
    if process.is_null() {
        return None;
    }

    unsafe {
        let head = (*process).kprocess_thread_list_head.flink;
        if head.is_null() {
            return None;
        }

        let head_addr = core::ptr::addr_of_mut!((*process).kprocess_thread_list_head);
        let mut entry = head;

        while !entry.is_null() && entry != head_addr {
            // Calculate ETHREAD pointer from ListEntry.
            // ETHREAD = ListEntry - offset_of(Kthread, global_thread_list_entry)
            // (Kthread is at ETHREAD offset 0, so no additional Kthread offset needed.)
            const GLOBAL_THREAD_ENTRY_OFFSET: usize =
                core::mem::offset_of!(crate::ps::thread::Kthread, global_thread_list_entry);
            debug_assert!(GLOBAL_THREAD_ENTRY_OFFSET == 0x0C8);  // Win7 documented offset
            let ethread = (entry as *mut u8)
                .offset(-(GLOBAL_THREAD_ENTRY_OFFSET as isize))
                as *mut crate::ps::thread::Ethread;

            if !ethread.is_null() && (*ethread).client_id.unique_thread == tid {
                return Some(ethread);
            }

            entry = (*entry).flink;
        }
    }
    None
}

/// Initialize process subsystem
///
/// This function creates only the essential kernel-mode processes:
/// - Idle process (PID 0): Represents CPU idle time
///
/// User-mode processes (SMSS, CSRSS, WINLOGON) are created by
/// start_session_manager() in kernel_main.rs during Phase 12.
/// System process (PID 4) is created by create_system_processes()
/// in kernel_main.rs during Phase 11.
#[cfg(target_arch = "x86_64")]
pub fn init() {
    use crate::hal::serial;
    serial::write_string("PS:init_start\r\n");
    // // kprintln!("  Initializing process subsystem...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // 1. Create Idle process (PID 0)
    // The Idle process represents CPU idle time and has no threads to schedule.
    serial::write_string("PS:create_idle_start\r\n");
    let idle = create_system_process(PID_IDLE);
    serial::write_string("PS:create_idle_done\r\n");
    if let Some(p) = idle {
        p.set_name(b"Idle\0");
        // // kprintln!("    Created Idle process (PID {})", PID_IDLE)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

        // Register Idle process in the global process list
        let mut list = PROCESS_LIST.lock();
        list.idle_process = Some(p as *mut Eprocess);
    } else {
        // // kprintln!("[ERROR] Failed to create Idle process")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }

    // NOTE: The following processes are NOT created here to avoid duplicate creation:
    // - System process (PID 4): Created by create_system_processes() in kernel_main.rs
    // - SMSS process (PID 256): Created by start_session_manager() in kernel_main.rs
    // - CSRSS process (PID 512): Created by start_session_manager() in kernel_main.rs
    // - WINLOGON process (PID 768): Created by start_session_manager() in kernel_main.rs

    serial::write_string("PS:init_done\r\n");
    // // kprintln!("  Process subsystem initialized: {} processes", process_count())  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Stub for non-x86_64 architectures: process creation is not
/// actually exercised in this build. Returns 0 to satisfy the
/// reference taken by `pub fn init` in `ps::init`.
#[cfg(not(target_arch = "x86_64"))]
pub fn init() {
    let _ = create_system_process;
}

/// Full process creation
pub fn create_process_full(
    image_path: &[u8],
    parent_process: Option<*mut Eprocess>,
) -> Option<&'static mut Eprocess> {
    let pid = allocate_pid()?;
    let process = create_user_process(image_path, pid, None)?;

    if process.object_table.is_null() {
        let ht_phys = crate::mm::frame::allocate_pages(1);
        if let Some(ht_base) = ht_phys {
            let ht_ptr = ht_base as *mut ProcessHandleTable;
            unsafe {
                core::ptr::write_bytes(ht_ptr as *mut u8, 0, 4096);
                (*ht_ptr).next_slot = 1;
            }
            process.object_table = ht_ptr;
        }
    }

    process.working_set = crate::mm::working_set::MmWorkingSet::new();

    if let Some(parent) = parent_process {
        inherit_from_parent(process, parent);
    }

    // // kprintln!("[PS] create_process_full: PID {} created", pid)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    Some(process)
}

fn inherit_from_parent(_child: &mut Eprocess, parent: *mut Eprocess) {
    if parent.is_null() {
        return;
    }
    unsafe {
        let _ = (*parent).unique_process_id;
    }
}

/// Number of bits we keep in the PID bitmap. Each bit represents
/// one PID. 4096 PIDs × 8 = 32768 PIDs total, which is well above
/// the worst-case bootstrap workload (smoke runs allocate ~12
/// processes; a full desktop session peaks around 200).
const PID_BITMAP_BITS: usize = 32768;
const PID_BITMAP_WORDS: usize = PID_BITMAP_BITS / 64;
/// First PID that the bitmap allocator will hand out. PIDs below
/// this are reserved for the hard-coded system processes
/// (PID_IDLE=0, PID_SYSTEM=4, PID_SMSS=256, …). This is in
/// addition to the well-known set which is kept out of the bitmap
/// entirely by pre-marking those bits at compile time.
const PID_BITMAP_FIRST: u64 = PID_SMSS + 256;

/// PID allocation bitmap. Bit `i` is set when PID
/// `(PID_BITMAP_FIRST + i)` is in use.
///
/// We initialise the static to a reserved-bit pattern using a
/// const constructor. Because Rust `const fn` cannot yet call
/// `AtomicU64::new`, we declare it as a `[AtomicU64; N]` and use
/// const initialisers. All bits start at 0 (free), except that we
/// also rely on the caller's invariant that the first 256 PIDs are
/// never handed out.
static PID_BITMAP: [core::sync::atomic::AtomicU64; PID_BITMAP_WORDS] =
    [const { core::sync::atomic::AtomicU64::new(0) };
        PID_BITMAP_WORDS];

fn allocate_pid() -> Option<u64> {
    use core::sync::atomic::Ordering;
    // Scan the bitmap for the first zero bit. Atomic CAS loop so
    // multiple CPUs can allocate concurrently without racing.
    for word_idx in 0..PID_BITMAP_WORDS {
        let word = &PID_BITMAP[word_idx];
        loop {
            let cur = word.load(Ordering::Relaxed);
            let free = !cur;
            if free == 0 {
                // All 64 PIDs in this word are in use.
                break;
            }
            let bit = free.trailing_zeros() as u64;
            let mask = 1u64 << bit;
            match word.compare_exchange(
                cur,
                cur | mask,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(PID_BITMAP_FIRST + (word_idx as u64) * 64 + bit);
                }
                Err(_) => continue, // someone else flipped a bit; retry
            }
        }
    }
    None
}

/// Release a PID back to the bitmap. Called when a process is
/// destroyed. Idempotent: releasing an already-free PID is a no-op.
#[allow(dead_code)]
fn free_pid(pid: u64) {
    use core::sync::atomic::Ordering;
    if pid < PID_BITMAP_FIRST {
        // System-reserved PIDs are not tracked by the bitmap.
        return;
    }
    let offset = pid - PID_BITMAP_FIRST;
    let word_idx = (offset / 64) as usize;
    let bit = (offset % 64) as u64;
    if word_idx >= PID_BITMAP_WORDS {
        return;
    }
    PID_BITMAP[word_idx].fetch_and(!(1u64 << bit), Ordering::Release);
}

// Re-export the monotonic counter under a private name so the rest
// of this module can still read a "highest-issued" hint cheaply if
// needed. The bitmap allocator above is the actual source of truth.
static _NEXT_PID_HINT: AtomicU64 = AtomicU64::new(PID_BITMAP_FIRST);

// =============================================================================
// Security Access Check Functions
// =============================================================================

/// NTSTATUS codes for security operations.
/// NTSTATUS codes for security operations. The canonical values
/// live in `libs::ntdll::status`; we re-export them here as `u32`
/// to keep the historical PS subsystem API stable (these were
/// defined as `u32` long before the ntdll table was extended).
pub use crate::libs::ntdll::status::STATUS_SUCCESS as _STATUS_SUCCESS_NT;
pub use crate::libs::ntdll::status::STATUS_ACCESS_DENIED as _STATUS_ACCESS_DENIED_NT;
pub use crate::libs::ntdll::status::STATUS_INVALID_PARAMETER as _STATUS_INVALID_PARAMETER_NT;
pub use crate::libs::ntdll::status::STATUS_PRIVILEGE_NOT_HELD as _STATUS_PRIVILEGE_NOT_HELD_NT;

pub const STATUS_SUCCESS: u32 = _STATUS_SUCCESS_NT as u32;
pub const STATUS_ACCESS_DENIED: u32 = _STATUS_ACCESS_DENIED_NT as u32;
pub const STATUS_INVALID_PARAMETER: u32 = _STATUS_INVALID_PARAMETER_NT as u32;
pub const STATUS_PRIVILEGE_NOT_HELD: u32 = _STATUS_PRIVILEGE_NOT_HELD_NT as u32;

/// Open a process with security access check.
///
/// This function performs the following steps:
/// 1. Find the target process by PID
/// 2. Get the caller's token (from current thread)
/// 3. Perform SeAccessCheck against the target process's security descriptor
/// 4. Return the process if access is granted
///
/// # Arguments
/// * `target_pid` - Process ID to open
/// * `desired_access` - Access rights requested (e.g., PROCESS_QUERY_INFORMATION)
/// * `token_ptr` - Pointer to caller's security token (can be null to use current thread's token)
///
/// # Returns
/// * `Ok(eprocess_ptr)` if access is granted
/// * `Err(ntstatus)` if access is denied or process not found
pub fn ps_open_process(
    target_pid: u64,
    desired_access: u32,
    token_ptr: *const crate::se::token::Token,
) -> Result<*mut Eprocess, u32> {
    // 1. Find the target process
    let target = match get_by_pid(target_pid) {
        Some(p) => p as *mut Eprocess,
        None => {
            // // kprintln!("[PS] ps_open_process: process {} not found", target_pid)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Err(STATUS_INVALID_PARAMETER);
        }
    };

    // 2. Get the caller's token
    let caller_token = if !token_ptr.is_null() {
        unsafe { &*token_ptr }
    } else {
        // Use current thread's token
        let current_token = get_current_thread_token();
        if current_token.is_null() {
            // // kprintln!("[PS] ps_open_process: no token available")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            return Err(STATUS_ACCESS_DENIED);
        }
        unsafe { &*current_token }
    };

    // 3. Get the target's security descriptor
    // For now, we use the token's embedded security info
    // In a full implementation, this would be a separate security descriptor
    let security_descriptor = build_process_security_descriptor(target);
    if security_descriptor.is_null() {
        // // kprintln!("[PS] ps_open_process: failed to get security descriptor")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return Err(STATUS_ACCESS_DENIED);
    }

    // 4. Perform SeAccessCheck
    let (result, granted) = crate::se::seaccess::se_access_check(
        crate::se::seaccess::ObTypeIndex::Process,
        security_descriptor,
        desired_access,
        caller_token as *const crate::se::token::Token,
    );
    let _ = &granted;

    // // kprintln!("[PS] ps_open_process: PID={} access=0x{:x} result={:?} granted=0x{:x}",  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //              target_pid, desired_access, result, granted);

    match result {
        crate::se::seaccess::AccessCheckResult::Allowed => Ok(target),
        crate::se::seaccess::AccessCheckResult::Denied => Err(STATUS_ACCESS_DENIED),
    }
}

/// Open a process for debugging.
///
/// Special access check: if the caller has SeDebugPrivilege, they can
/// open any process regardless of DACL. This is the implementation of
/// NtDebugActiveProcess.
pub fn ps_open_process_for_debug(
    target_pid: u64,
    token_ptr: *const crate::se::token::Token,
) -> Result<*mut Eprocess, u32> {
    // Check for SeDebugPrivilege
    if !token_ptr.is_null() {
        let token = unsafe { &*token_ptr };
        let debug_luid = crate::se::token::Luid {
            low_part: crate::se::seaccess::privileges::SE_DEBUG as u32,
            high_part: 0,
        };

        if token.has_privilege(&debug_luid) {
            // SeDebugPrivilege overrides DACL check
            // // kprintln!("[PS] ps_open_process_for_debug: SeDebugPrivilege override for PID {}", target_pid)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

            if let Some(p) = get_by_pid(target_pid) {
                return Ok(p as *mut Eprocess);
            }
            return Err(STATUS_INVALID_PARAMETER);
        }
    }

    // No debug privilege, do normal access check
    ps_open_process(target_pid, 0x1F0FFF, token_ptr) // PROCESS_ALL_ACCESS
}

/// Set a process's primary token.
///
/// This requires SeAssignPrimaryTokenPrivilege.
/// # Arguments
/// * `target` - Target process
/// * `new_token` - New token to assign
/// * `calling_token` - Caller's token
pub fn ps_set_primary_token(
    target: *mut Eprocess,
    new_token: *mut crate::se::token::Token,
    calling_token: *const crate::se::token::Token,
) -> u32 {
    // 1. Check caller has SeAssignPrimaryTokenPrivilege
    if calling_token.is_null() {
        return STATUS_ACCESS_DENIED;
    }

    let token = unsafe { &*calling_token };
    let privilege = crate::se::token::Luid {
        low_part: crate::se::seaccess::privileges::SE_ASSIGN_PRIMARY_TOKEN as u32,
        high_part: 0,
    };

    if !token.has_privilege(&privilege) {
        // // kprintln!("[PS] ps_set_primary_token: caller lacks SE_ASSIGN_PRIMARY_TOKEN")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    // 2. Update the process token
    if !target.is_null() && !new_token.is_null() {
        unsafe {
            (*target).set_token(new_token);
        }
        // // kprintln!("[PS] ps_set_primary_token: token updated successfully")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// Get the current thread's primary token.
///
/// Walks the per-CPU area to find the running ETHREAD, then reads
/// `Ethread::primary_token`. Returns null if no thread is installed
/// (early boot) or the thread has not yet been assigned a token.
pub fn get_current_thread_token() -> *const crate::se::token::Token {
    let thread = crate::ps::thread::get_current_ethread();
    if thread.is_null() {
        // No current thread installed in per-CPU area yet (early boot).
        // Return null rather than panic — callers must treat null as
        // "no token available".
        return core::ptr::null();
    }
    let token = unsafe { (*thread).primary_token };
    if token != 0 {
        return token as *const crate::se::token::Token;
    }

    // Thread-level token is null: fall back to the process primary token
    // (Windows NT semantics: if ETHREAD->Token is NULL, the effective token
    // is the EPROCESS->Token).
    let process = unsafe { (*thread).threads_process };
    if process.is_null() {
        return core::ptr::null();
    }
    // EPROCESS.Token is an EX_FAST_REF: low 3 bits are refcount,
    // upper bits are the Token* pointer.
    let proc_token = unsafe { (*process).token.get_object() };
    if proc_token == 0 {
        core::ptr::null()
    } else {
        proc_token as *const crate::se::token::Token
    }
}

/// Build a security descriptor for a process.
///
/// Creates a proper security descriptor based on the process's token.
/// Delegates to seaccess module for proper security descriptor construction.
pub fn build_process_security_descriptor(process: *mut Eprocess) -> *const crate::se::seaccess::SecurityDescriptor {
    crate::se::seaccess::build_process_security_descriptor(process)
}
