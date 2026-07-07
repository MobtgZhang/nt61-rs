//! x86_64 interrupt dispatcher
//
//! Called from `int_common_dispatch` (in `idt_stubs.rs`). The
//! dispatcher saved all GPRs and passed us a `&TrapFrame` plus the
//! vector number.

use crate::mm::access_fault::{self, AccessFlags};

/// Registers saved by `int_common_dispatch`. The frame layout
/// matches the on-stack layout pushed by the stub:
///
///   offset 0x00..0x70 = 15 GPRs (rax..r15 in stack order)
///   offset 0x78      = vector (pushed explicitly by int_stub_N
///                              before the jmp into int_common_dispatch;
///                              this is what `int_stub_N` set rdi to)
///   offset 0x80      = error_code (CPU-pushed for vectors 8,10,11,
///                                12,13,14,17; zero for the others)
///   offset 0x88      = RIP (CPU-pushed)
///   offset 0x90      = CS  (CPU-pushed)
///   offset 0x98      = RFLAGS (CPU-pushed)
///   offset 0xa0      = RSP (CPU-pushed)
///   offset 0xa8      = SS  (CPU-pushed)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrapFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
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
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Extended KTRAP_FRAME for Windows 7 x64 compatibility.
///
/// Windows 7 x64 KTRAP_FRAME is approximately 0x2D8 bytes and includes:
/// - Segment registers (DS, ES, FS, GS)
/// - Debug registers (DR0-DR7)
/// - XMM registers (XMM0-XMM15) + MXCSR
/// - Temporary registers and exception frame
///
/// This structure provides full exception/interrupt context for x64 SEH.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KTrapFrame {
    // === Volatile registers (clobbered by syscall) ===
    pub rax: u64,
    pub rcx: u64,    // Syscall clobbers this -> contains user RIP
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,    // arg0 (RCX clobbered by syscall)
    pub r11: u64,

    // === Non-volatile integer registers ===
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // === Segment registers ===
    pub ds: u16,
    _ds_pad: u16,
    pub es: u16,
    _es_pad: u16,
    pub fs: u16,
    _fs_pad: u16,
    pub gs: u16,
    _gs_pad: u16,

    // === Control registers (from trap/interrupt) ===
    pub rip: u64,      // User RIP
    pub cs: u64,       // User CS
    pub rflags: u64,
    pub rsp: u64,      // User RSP
    pub ss: u64,       // User SS

    // === Exception/interrupt info ===
    pub vector: u64,
    pub error_code: u64,

    // === Debug registers ===
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,

    // === XMM registers (128-bit each) ===
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
    pub mxcsr: u32,
    _mxcsr_pad: u32,

    // === KTRAP_FRAME specific fields ===
    /// Temporary register (used during trap handling)
    pub temp: u64,
    /// Additional temporary space
    pub temp2: [u64; 4],
    /// Pointer to exception frame
    pub exception_frame: u64,
    /// Trap link (used by scheduler)
    pub trap_link: u64,

    // === V86/Guest state ===
    pub v86_es: u16,
    pub v86_ds: u16,
    pub v86_fs: u16,
    pub v86_gs: u16,
    _v86_pad: u16,

    // === Callback frame ===
    pub callback_type: u32,
    pub callback_stack: u64,
    pub callback_rip: u64,
}

impl KTrapFrame {
    /// Create a KTrapFrame from a basic TrapFrame
    pub fn from_trap_frame(tf: &TrapFrame) -> Self {
        let mut ktf = Self::default();
        ktf.rax = tf.rax;
        ktf.rcx = tf.rcx;
        ktf.rdx = tf.rdx;
        ktf.rbx = tf.rbx;
        ktf.rbp = tf.rbp;
        ktf.rsi = tf.rsi;
        ktf.rdi = tf.rdi;
        ktf.r8 = tf.r8;
        ktf.r9 = tf.r9;
        ktf.r10 = tf.r10;
        ktf.r11 = tf.r11;
        ktf.r12 = tf.r12;
        ktf.r13 = tf.r13;
        ktf.r14 = tf.r14;
        ktf.r15 = tf.r15;
        ktf.vector = tf.vector;
        ktf.error_code = tf.error_code;
        ktf.rip = tf.rip;
        ktf.cs = tf.cs;
        ktf.rflags = tf.rflags;
        ktf.rsp = tf.rsp;
        ktf.ss = tf.ss;
        ktf
    }

    /// Get the size of KTrapFrame in bytes
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

/// Vectors that the CPU pushes an error code for. For these
/// vectors, the CPU's error code sits in the stack frame at
/// `rip - 8` (i.e. the word immediately before the RIP slot).
pub fn vector_has_error_code(v: u64) -> bool {
    matches!(v, 8 | 10 | 11 | 12 | 13 | 14 | 17)
}

#[no_mangle]
pub extern "C" fn dispatch_trap_frame(vector: u64, tf: *mut TrapFrame) {
    if tf.is_null() { return; }
    crate::boot_println!("[DT] dispatch vector={} tf={:x}", vector, tf as u64);
    unsafe {
        // The stub passed the vector as a u64 (so its top bits are
        // already 0) — no `& 0xFF` mask needed for clarity, but
        // keep it because callers may still pass values > 0xFF when
        // we route spurious events.
        let vector = vector & 0xFF;
        // Intel CPU, after the 15 GPR pushes performed by the stub,
        // lays out the CPU-pushed iret frame at offsets [rsp + 0x78]
        // and above in our struct's address space. The frame layout
        // for the interrupt-then-iret path is:
        //   [rsp + 0x78] = error_code (only on 8/10/11/12/13/14/17)
        //   [rsp + 0x80] = RIP
        //   [rsp + 0x88] = CS
        //   [rsp + 0x90] = RFLAGS
        //   [rsp + 0x98] = RSP
        //   [rsp + 0xa0] = SS
        // So the error code lives at TF struct offset 0x78 (which is
        // the field called `vector` but is misleadingly named). For
        // vectors that do NOT push an error code, [rsp + 0x78] holds
        // RIP, which we still want to keep intact — the field-name
        // mismatch is a quirk of how the Rust struct and the CPU
        // frame overlap; the FIX is to use the correct offset here,
        // not to rename the field.
        let frame_top = (tf as *const u64).offset(15); // [rsp + 0x78]
        // After the int_stub's `push rdi` (which puts the vector at
        // offset 0x78) and the CPU-pushed iret frame, the actual
        // error_code lives at offset 0x80 and RIP at offset 0x88.
        let error_code_slot = (tf as *const u64).offset(16); // [rsp + 0x80]
        let error_code = if vector_has_error_code(vector) {
            *error_code_slot
        } else {
            0
        };
        // CRITICAL: DO NOT write to (*tf).vector or (*tf).error_code.
        // Those struct fields overlap with CPU-pushed trap frame slots
        // (offset 0x78 is the CPU's error_code slot for vectors that
        // push one, and offset 0x80 is the CPU's user RIP slot).
        // Writing to them would clobber the values the CPU needs to
        // resume via iretq. The `vector` value is recovered from the
        // function parameter, and the CPU-pushed error_code has been
        // saved into the local `error_code` variable above.

        match vector {
            // === CPU EXCEPTIONS (Vectors 0-31) ===
            0 => { /* #DE - Divide Error - handled by CPU */ }
            1 => { /* #DB - Debug - handled by CPU */ }
            2 => { /* #NMI - Non-Maskable Interrupt */ }
            3 => { /* #BP - Breakpoint (INT3) - could be debug or kernel panic */ }
            4 => { /* #OF - Overflow (INTO) */ }
            5 => { /* #BR - Bound Range Exceeded */ }
            6 => { /* #UD - Invalid Opcode */ handle_invalid_opcode(&*tf); return; }
            7 => { /* #NM - Device Not Available */ handle_device_not_available(&*tf); }
            8 => { /* #DF - Double Fault - CRITICAL */ handle_double_fault(error_code, &*tf); return; }
            9 => { /* Coprocessor Segment Overrun - deprecated, ignore */ }
            10 => { /* #TS - Invalid TSS */ handle_general_protection(error_code, &*tf); return; }
            11 => { /* #NP - Segment Not Present */ handle_segment_not_present(error_code, &*tf); return; }
            12 => { /* #SS - Stack Fault */ handle_stack_fault(error_code, &*tf); return; }
            13 => { /* #GP - General Protection Fault - CRITICAL */ handle_general_protection(error_code, &*tf); return; }
            14 => { /* #PF - Page Fault */ handle_page_fault(error_code, &*tf); }
            15 => { /* Reserved - Intel defined as 'Unknown' */ 
                // // crate::kprintln!("[FAULT] Vector 15 (Intel reserved)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
            16 => { /* #MF - x87 Floating Point Error */ }
            17 => { /* #AC - Alignment Check */ handle_alignment_check(error_code, &*tf); return; }
            18 => { /* #MC - Machine Check - CRITICAL */ handle_machine_check(&*tf); return; }
            19 => { /* #XM - SIMD Floating Point Error */ }
            20 => { /* #VE - Virtualization Exception */ }
            21..=31 => {
                // // crate::kprintln!("[FAULT] Reserved exception vector {}", vector)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
            
            // === PIT / HPET / keyboard / APIC timer vectors ===
            32 => {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::boot_println!("[DT32] before irq_dispatch");
                    crate::hal::x86_64::pic::irq_dispatch(0);
                    crate::boot_println!("[DT32] after irq_dispatch before tick");
                    crate::ke::scheduler::tick();
                    crate::boot_println!("[DT32] after tick");
                }
            }
            #[cfg(target_arch = "x86_64")]
            33 => crate::hal::x86_64::keyboard::irq_handler(),
            #[cfg(target_arch = "x86_64")]
            34 => crate::hal::x86_64::pic::irq_dispatch(2),
            #[cfg(target_arch = "x86_64")]
            35 => crate::hal::x86_64::pic::irq_dispatch(3),
            #[cfg(target_arch = "x86_64")]
            36 => crate::hal::x86_64::pic::irq_dispatch(4),
            #[cfg(target_arch = "x86_64")]
            37 => crate::hal::x86_64::pic::irq_dispatch(5),
            #[cfg(target_arch = "x86_64")]
            38 => crate::hal::x86_64::pic::irq_dispatch(6),
            #[cfg(target_arch = "x86_64")]
            39 => crate::hal::x86_64::pic::irq_dispatch(7),
            #[cfg(target_arch = "x86_64")]
            40 => crate::hal::x86_64::pic::irq_dispatch(8),
            #[cfg(target_arch = "x86_64")]
            41 => crate::hal::x86_64::pic::irq_dispatch(9),
            #[cfg(target_arch = "x86_64")]
            42 => crate::hal::x86_64::pic::irq_dispatch(10),
            #[cfg(target_arch = "x86_64")]
            43 => crate::hal::x86_64::pic::irq_dispatch(11),
            #[cfg(target_arch = "x86_64")]
            44 => crate::hal::x86_64::pic::irq_dispatch(12),
            #[cfg(target_arch = "x86_64")]
            45 => crate::hal::x86_64::pic::irq_dispatch(13),
            #[cfg(target_arch = "x86_64")]
            46 => crate::hal::x86_64::pic::irq_dispatch(14),
            #[cfg(target_arch = "x86_64")]
            47 => crate::hal::x86_64::pic::irq_dispatch(15),
            
            // === IPI vectors ===
            // The x86_64 architecture reserves 0xE0..0xEF for inter-processor interrupts
            0xE0 => crate::ke::dispatch::handle_ipi_reschedule(),
            0xE1 => crate::ke::dispatch::handle_ipi_intr_enter(),
            0xE2 => crate::ke::dispatch::handle_ipi_intr_exit(),
            0xE3 => crate::ke::dispatch::handle_ipi_panic_stop(),
            0xE4..=0xEF => crate::ke::dispatch::handle_ipi_dynamic(vector as u8),
            
            // === Spurious APIC ===
            0xFF => {}
            
            // === Unknown vectors ===
            _v => {
                // _v is intentionally unused - unknown vectors are logged/ignored
                // // crate::kprintln!("[FAULT] unhandled interrupt/exception vector {} (raw=0x{:x})", _v, _v)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }
}

fn handle_page_fault(error_code: u64, tf: &TrapFrame) {
    // Read CR2 immediately, before anything else that might fault.
    let cr2: u64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Move from control register CR2 directly into a general-purpose
        // register. Inline-asm register names like `cr2` aren't always
        // recognised by older rustc versions, so we go through rax.
        let tmp: u64;
        core::arch::asm!(
            "mov {tmp}, cr2",
            tmp = out(reg) tmp,
            options(nostack),
        );
        cr2 = tmp;
    }
    #[cfg(not(target_arch = "x86_64"))]
    let cr2 = 0;
    let actual_cr3: u64 = {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let tmp: u64;
            core::arch::asm!("mov {tmp}, cr3", tmp = out(reg) tmp, options(nostack));
            tmp
        }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    };
    let actual_cr0: u64 = {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let tmp: u64;
            core::arch::asm!("mov {tmp}, cr0", tmp = out(reg) tmp, options(nostack));
            tmp
        }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    };
    let actual_cr4: u64 = {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let tmp: u64;
            core::arch::asm!("mov {tmp}, cr4", tmp = out(reg) tmp, options(nostack));
            tmp
        }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    };
    let actual_efer: u64 = {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let tmp: u64;
            core::arch::asm!(
                "mov ecx, 0xc0000080",
                "rdmsr",
                "shl rdx, 32",
                "or rax, rdx",
                lateout("rax") tmp,
                out("rcx") _,
                out("rdx") _,
                options(nostack),
            );
            tmp
        }
        #[cfg(not(target_arch = "x86_64"))]
        { 0 }
    };
    crate::boot_println!("[PF] cr2=0x{:x} err=0x{:x} cr3=0x{:x} cr0=0x{:x} cr4=0x{:x} efer=0x{:x} tf.rip=0x{:x} tf.cs=0x{:x}", cr2, error_code, actual_cr3, actual_cr0, actual_cr4, actual_efer, tf.rip, tf.cs);

    // Dump the first 16 bytes at the faulting address from the kernel's
    // perspective (using physical-memory access via the system PML4,
    // which is at a DIFFERENT CR3 than what we're walking here).
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let pte_frame_pa = {
            let root = crate::mm::vas::current_root();
            let pml4_idx = ((cr2 >> 39) & 0x1FF) as usize;
            let pdpt_idx = ((cr2 >> 30) & 0x1FF) as usize;
            let pd_idx = ((cr2 >> 21) & 0x1FF) as usize;
            let pt_idx = ((cr2 >> 12) & 0x1FF) as usize;
            let pml4e = core::ptr::read_volatile((root as *const u64).add(pml4_idx));
            if pml4e & 1 != 0 {
                let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
                let pdpte = core::ptr::read_volatile((pdpt_phys as *const u64).add(pdpt_idx));
                if pdpte & 1 != 0 {
                    let pd_phys = pdpte & 0x000F_FFFF_FFFF_F000;
                    let pde = core::ptr::read_volatile((pd_phys as *const u64).add(pd_idx));
                    if pde & 1 != 0 {
                        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;
                        let pte = core::ptr::read_volatile((pt_phys as *const u64).add(pt_idx));
                        if pte & 1 != 0 {
                            pte & 0x000F_FFFF_FFFF_F000
                        } else { 0 }
                    } else { 0 }
                } else { 0 }
            } else { 0 }
        };
        if pte_frame_pa != 0 {
            let bytes = core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize));
            crate::boot_println!("[PF] bytes at faulting VA: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", bytes, core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 1)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 2)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 3)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 4)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 5)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 6)), core::ptr::read_volatile((pte_frame_pa as *const u8).add((cr2 & 0xFFF) as usize + 7)));
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Walk the page table for the faulting VA and dump the PTE so
        // we can see what permissions the page actually has.
        let root = crate::mm::vas::current_root();
        let pml4_idx = ((cr2 >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((cr2 >> 30) & 0x1FF) as usize;
        let pd_idx = ((cr2 >> 21) & 0x1FF) as usize;
        let pt_idx = ((cr2 >> 12) & 0x1FF) as usize;
        unsafe {
            let pml4e = core::ptr::read_volatile((root as *const u64).add(pml4_idx));
            crate::boot_println!("[PF]   PML4[{}]=0x{:x}", pml4_idx, pml4e);
            if pml4e & 1 != 0 {
                let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
                let pdpte = core::ptr::read_volatile((pdpt_phys as *const u64).add(pdpt_idx));
                crate::boot_println!("[PF]   PDPT[{}]=0x{:x}", pdpt_idx, pdpte);
                if pdpte & 1 != 0 {
                    let pd_phys = pdpte & 0x000F_FFFF_FFFF_F000;
                    let pde = core::ptr::read_volatile((pd_phys as *const u64).add(pd_idx));
                    crate::boot_println!("[PF]   PD[{}]=0x{:x}", pd_idx, pde);
                    if pde & 1 != 0 {
                        let pt_phys = pde & 0x000F_FFFF_FFFF_F000;
                        let pte = core::ptr::read_volatile((pt_phys as *const u64).add(pt_idx));
                        crate::boot_println!("[PF]   PT[{}]=0x{:x} NX={}", pt_idx, pte, (pte >> 63) & 1);
                    }
                }
            }
        }
        // Also dump ALL PML4 entries to see the full picture.
        unsafe {
            crate::boot_println!("[PF] DUMP ALL PML4 ENTRIES (root=0x{:x}):", root);
            for i in 0..512 {
                let e = core::ptr::read_volatile((root as *const u64).add(i));
                if e & 1 != 0 {
                    crate::boot_println!("[PF]   PML4[{}]=0x{:x}", i, e);
                }
            }
        }
    }

    // If we get a fault BEFORE the memory manager is initialised, the
    // PFN database won't be available and we can't resolve the fault.
    // We CANNOT use kprintln! or call any functions that might access
    // static variables (which might not have their pages committed).
    // Use early_pf_halt() instead.
    if !crate::mm::is_initialized() {
        #[cfg(target_arch = "x86_64")]
        {
            // CRITICAL: Use early_pf_halt to avoid triggering another PF.
            unsafe { early_pf_halt(); }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            loop {
                unsafe { core::arch::asm!("hlt", options(nostack)); }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    let access = AccessFlags {
        read: error_code & 0x1 == 0,
        write: error_code & 0x2 != 0,
        execute: error_code & 0x10 != 0,
        user: error_code & 0x4 != 0,
        reserved_bit: error_code & 0x8 != 0,
        instruction_fetch: error_code & 0x10 != 0,
    };
    let status = { access_fault::handle(cr2, access) };
    crate::boot_println!("[PF] access_fault status={:?}", status);
    match status {
        access_fault::FaultStatus::Handled => {
            // Fault resolved — iretq will retry the faulting instruction.
        }
        access_fault::FaultStatus::CheckVad => {
            // // crate::kprintln!("[PF] va=0x{:016x} CheckVad (VAD lookup needed)", cr2)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            // Kernel-mode VAD faults are typically fatal — halt.
            loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
        }
        access_fault::FaultStatus::AccessViolation => {
            // // crate::kprintln!("[PF] FATAL: AccessViolation at va=0x{:016x}", cr2)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
        }
        access_fault::FaultStatus::OutOfMemory => {
            // // crate::kprintln!("[PF] FATAL: OutOfMemory at va=0x{:016x}", cr2)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
            loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
        }
    }
}

/// Early halt for page faults before MM is initialized.
/// This MUST NOT call any functions or access any statics.
#[cfg(target_arch = "x86_64")]
unsafe fn early_pf_halt() {
    // We can't use serial::write_string here because that might trigger
    // another page fault. Just halt immediately.
    loop {
        core::arch::asm!("hlt", options(nostack));
    }
}

/// Handle #DF (Double Fault) - IST3 should be set but we handle gracefully
/// #DF is fatal in most cases, but we log for debugging
fn handle_double_fault(_error_code: u64, _tf: &TrapFrame) {
    // _error_code and _tf are intentionally unused - reserved for future logging
    // // crate::kprintln!("[FAULT] #DF (Double Fault) - fatal error")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x} RSP=0x{:016x}", _tf.rip, _tf.rsp)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RFLAGS=0x{:016x} CS=0x{:x}", _tf.rflags, _tf.cs)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // In a real kernel, this would trigger BugCheck or triple fault
    // For now, halt the system
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nostack));
        }
    }
}

/// Handle #GP (General Protection Fault)
/// This is critical - can be caused by bad selector, privilege violation, etc.
fn handle_general_protection(_error_code: u64, tf: &TrapFrame) {
    let _selector_id = _error_code & 0xFFFF;
    let _ext = (_error_code >> 16) & 1 != 0;
    crate::boot_println!("[GP] err=0x{:x} cs=0x{:x} rip=0x{:x} rsp=0x{:x} ss=0x{:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rdi=0x{:x} rsi=0x{:x} r8=0x{:x} r9=0x{:x} r10=0x{:x} r11=0x{:x}", _error_code, tf.cs, tf.rip, tf.rsp, tf.ss, tf.rax, tf.rbx, tf.rcx, tf.rdx, tf.rdi, tf.rsi, tf.r8, tf.r9, tf.r10, tf.r11);

    // Check if this is from user mode (shouldn't happen if selectors are correct)
    let user_mode = tf.cs & 3 != 0;

    // // crate::kprintln!("[FAULT] #GP (General Protection Fault)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  Error code: ID={} EXT={} Selector=0x{:04x}", _selector_id, _ext, _selector_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x} RSP=0x{:016x}", tf.rip, tf.rsp)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  CS=0x{:x} SS=0x{:x} RFLAGS=0x{:016x}", tf.cs, tf.ss, tf.rflags)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    if user_mode {
        // For user-mode #GP, return an exception code to user space
        // In Windows, this would typically result in access violation
        // // crate::kprintln!("[FAULT] #GP from user mode at 0x{:016x}", tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    } else {
        // Kernel mode #GP is more serious
        // // crate::kprintln!("[FAULT] #GP from kernel mode - system error!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
    
    // For now, halt if kernel mode GP
    if !user_mode {
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nostack));
            }
        }
    }
}

/// Handle #SS (Stack Segment Fault)
/// Usually caused by stack limit violation or bad stack selector
fn handle_stack_fault(error_code: u64, tf: &TrapFrame) {
    let selector_id = error_code & 0xFFFF;
    let ext = (error_code >> 16) & 1 != 0;
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags)); }
    crate::boot_println!("[FAULT] #SS id={} ext={} sel=0x{:04x} rip=0x{:016x} rsp=0x{:016x} cs=0x{:x} ss=0x{:x} cr3=0x{:x}",
        selector_id, ext, selector_id, tf.rip, tf.rsp, tf.cs, tf.ss, cr3);
    // Print a few bytes of code around RIP to identify the failing
    // instruction (the address itself isn't enough — it lives in the
    // relocated kernel image and we don't have symbols at runtime).
    unsafe {
        let p = tf.rip as *const u8;
        for off in (-16i64..16i64).step_by(1) {
            let addr = tf.rip.wrapping_add(off as u64);
            let byte: u8 = core::ptr::read_volatile(p.offset(off as isize));
            if off == 0 {
                crate::boot_println!("  code[{:+}] @ 0x{:016x} = 0x{:02x}  <-- RIP", off, addr, byte);
            } else {
                crate::boot_println!("  code[{:+}] @ 0x{:016x} = 0x{:02x}", off, addr, byte);
            }
        }
    }
    // Dump our saved GP registers so we can see what the
    // crashed frame was working with.
    crate::boot_println!("[FAULT-REGS] rax=0x{:016x} rcx=0x{:016x} rdx=0x{:016x}",
        tf.rax, tf.rcx, tf.rdx);
    crate::boot_println!("[FAULT-REGS] rbx=0x{:016x} rbp=0x{:016x} rsi=0x{:016x} rdi=0x{:016x}",
        tf.rbx, tf.rbp, tf.rsi, tf.rdi);
    crate::boot_println!("[FAULT-REGS] r8 =0x{:016x} r9 =0x{:016x} r10=0x{:016x} r11=0x{:016x}",
        tf.r8, tf.r9, tf.r10, tf.r11);
    crate::boot_println!("[FAULT-REGS] r12=0x{:016x} r13=0x{:016x} r14=0x{:016x} r15=0x{:016x}",
        tf.r12, tf.r13, tf.r14, tf.r15);
    // Print addresses of known kernel symbols so we can
    // locate the image base at runtime.
    crate::boot_println!("[FAULT-SYMS] handle_stack_fault=0x{:x}",
        handle_stack_fault as *const () as usize);
    crate::boot_println!("[FAULT-SYMS] kernel_main=0x{:x}",
        crate::kernel_main::kernel_main as *const () as usize);
    crate::boot_println!("[FAULT-SYMS] early_write_str=0x{:x}",
        crate::arch::boot::early_write_str as *const () as usize);
    crate::boot_println!("[FAULT-SYMS] write_early=0x{:x}",
        crate::rtl::klog::write_early as *const () as usize);
    // Dump 256 bytes around RIP to identify what we crashed into.
    let rip_p = tf.rip as *const u8;
    unsafe {
        for row in (-256i64..=0i64).step_by(16) {
            let mut bytes = [0u8; 16];
            for i in 0..16i64 {
                bytes[i as usize] = core::ptr::read_volatile(rip_p.offset((row + i) as isize));
            }
            let mut hex_buf = [0u8; 64];
            let mut idx = 0;
            for (i, b) in bytes.iter().enumerate() {
                let hi = (b >> 4) & 0xf;
                let lo = b & 0xf;
                let h = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let l = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                if idx + 2 < hex_buf.len() {
                    hex_buf[idx] = h;
                    hex_buf[idx + 1] = l;
                    if i < 15 && idx + 2 < hex_buf.len() - 1 {
                        hex_buf[idx + 2] = b' ';
                    }
                    idx += 3;
                }
            }
            let hex_str = core::str::from_utf8(&hex_buf[..idx.min(hex_buf.len()-1)]).unwrap_or("?");
            let addr = tf.rip.wrapping_add(row as u64);
            crate::boot_println!("[FAULT-MEM] +{:04x} @ 0x{:016x} = {}", row, addr, hex_str);
        }
        // Also dump 256 bytes BEFORE RIP-256 to identify the start of the image.
        let p256_before = tf.rip.wrapping_sub(0x200);
        let p_p = p256_before as *const u8;
        for row in (0i64..=0x1000i64).step_by(16) {
            let mut bytes = [0u8; 16];
            let mut valid = true;
            for i in 0..16i64 {
                bytes[i as usize] = core::ptr::read_volatile(p_p.offset((row + i) as isize));
            }
            let mut hex_buf = [0u8; 64];
            let mut idx = 0;
            for (i, b) in bytes.iter().enumerate() {
                let hi = (b >> 4) & 0xf;
                let lo = b & 0xf;
                let h = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let l = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                if idx + 2 < hex_buf.len() {
                    hex_buf[idx] = h;
                    hex_buf[idx + 1] = l;
                    if i < 15 && idx + 2 < hex_buf.len() - 1 {
                        hex_buf[idx + 2] = b' ';
                    }
                    idx += 3;
                }
            }
            let hex_str = core::str::from_utf8(&hex_buf[..idx.min(hex_buf.len()-1)]).unwrap_or("?");
            let addr = p256_before.wrapping_add(row as u64);
            crate::boot_println!("[FAULT-MEM] -{:#x}+{:04x} @ 0x{:016x} = {}",
                0x200u64, row, addr, hex_str);
        }
    }
    // Walk the RBP chain. With optimizations enabled RBP isn't
    // always a frame pointer, so we verify each candidate by
    // checking that the saved RBP looks like a stack address
    // (between rsp and our idea of the stack base).
    let stack_hi = tf.rsp.wrapping_add(0x40000);  // generous upper bound
    crate::boot_println!("[FAULT-RBP] walking rbp chain starting at rbp=0x{:016x} rsp=0x{:016x}", tf.rbp, tf.rsp);
    // Just dump raw stack bytes (no RBP walk which can fault on bogus memory)
    unsafe {
        let stack_top = tf.rsp;
        for offset in (0i64..=0x200i64).step_by(16) {
            let addr = stack_top.wrapping_add(offset as u64);
            let p = addr as *const u8;
            let mut bytes = [0u8; 16];
            let mut valid = true;
            for i in 0..16i64 {
                let pp = p.offset(i as isize);
                if pp < tf.rsp as *const u8 || pp > stack_hi as *const u8 {
                    valid = false;
                    break;
                }
                bytes[i as usize] = core::ptr::read_volatile(pp);
            }
            if !valid { break; }
            let mut hex_buf = [0u8; 80];
            let mut idx = 0;
            for (i, b) in bytes.iter().enumerate() {
                let hi = (b >> 4) & 0xf;
                let lo = b & 0xf;
                let h = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let l = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                if idx + 2 < hex_buf.len() {
                    hex_buf[idx] = h;
                    hex_buf[idx + 1] = l;
                    if i < 15 && idx + 2 < hex_buf.len() - 1 {
                        hex_buf[idx + 2] = b' ';
                    }
                    idx += 3;
                }
            }
            let hex_str = core::str::from_utf8(&hex_buf[..idx.min(hex_buf.len()-1)]).unwrap_or("?");
            crate::boot_println!("[FAULT-STK] +{:04x} @ 0x{:016x} = {}",
                offset, addr, hex_str);
        }
    }
    
    // // crate::kprintln!("[FAULT] #SS (Stack Fault)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  Error code: ID={} EXT={} Selector=0x{:04x}", selector_id, ext, selector_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x} RSP=0x{:016x}", tf.rip, tf.rsp)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    
    // Check if user mode
    let user_mode = tf.cs & 3 != 0;
    if !user_mode {
        // // crate::kprintln!("[FAULT] #SS from kernel mode - system error!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nostack));
            }
        }
    }
}

/// Handle #NP (Segment Not Present)
/// Usually caused by loading a non-present segment
fn handle_segment_not_present(_error_code: u64, _tf: &TrapFrame) {
    let _selector_id = _error_code & 0xFFFF;
    let _ext = (_error_code >> 16) & 1 != 0;
    let _ti = (_error_code >> 14) & 1 != 0; // TI bit: LDT vs GDT
    // _selector_id, _ext, _ti, and _tf are intentionally unused - reserved for future logging

    // // crate::kprintln!("[FAULT] #NP (Segment Not Present)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  Error code: ID={} EXT={} TI={} Selector=0x{:04x}", _selector_id, _ext, _ti, _selector_id)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x}", _tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
}

/// Handle #UD (Invalid Opcode)
/// Caused by executing invalid instructions or CS.limit exceeded
fn handle_invalid_opcode(tf: &TrapFrame) {
    crate::hal::x86_64::serial::write_string("[FAULT] #UD (Invalid Opcode)\r\n");
    crate::hal::x86_64::serial::write_string("[FAULT]   RIP=0x");
    crate::hal::x86_64::serial::write_u64_hex(tf.rip);
    crate::hal::x86_64::serial::write_string(" CS=0x");
    crate::hal::x86_64::serial::write_u64_hex(tf.cs);
    crate::hal::x86_64::serial::write_string("\r\n");
    // Read first 8 bytes at tf.rip
    unsafe {
        let mut buf = [0u8; 8];
        core::arch::asm!(
            "mov rsi, {src}\n\
             mov rdi, {dst}\n\
             mov rcx, 1\n\
             rep movsq",
            src = in(reg) tf.rip,
            dst = in(reg) buf.as_mut_ptr() as u64,
            options(nostack, preserves_flags),
        );
        crate::hal::x86_64::serial::write_string("[FAULT]   bytes at RIP: ");
        for &b in &buf {
            crate::hal::x86_64::serial::write_u32_hex(b as u32);
            crate::hal::x86_64::serial::write_string(" ");
        }
        crate::hal::x86_64::serial::write_string("\r\n");
    }
    // Check for CPUID instruction
    let code = unsafe {
        let ptr = tf.rip as *const u8;
        core::ptr::read(ptr)
    };
    
    if code == 0x0F {
        let code2 = unsafe {
            let ptr = (tf.rip + 1) as *const u8;
            core::ptr::read(ptr)
        };
        if code2 == 0xA2 {
            // // crate::kprintln!("[FAULT] CPUID instruction at 0x{:016x}", tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        }
    }
}

/// Handle #NM (Device Not Available)
/// Caused by executing x87/FPU instruction when CR0.TS=1
fn handle_device_not_available(_tf: &TrapFrame) {
    // _tf is intentionally unused - reserved for future logging
    // // crate::kprintln!("[FAULT] #NM (Device Not Available)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x}", _tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Clear the TS bit and restore FPU state
    unsafe {
        let cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack));
        core::arch::asm!("mov cr0, {}", in(reg) cr0 & !0x8, options(nostack));
        // In a real kernel, would restore FPU state here
        // // crate::kprintln!("[FAULT] #NM: cleared CR0.TS, FPU state would be restored")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Handle #MC (Machine Check)
/// Non-maskable hardware error
fn handle_machine_check(_tf: &TrapFrame) {
    // _tf is intentionally unused - reserved for future logging
    // // crate::kprintln!("[FAULT] #MC (Machine Check)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x}", _tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    // Machine check is typically fatal
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nostack));
        }
    }
}

/// Handle #AC (Alignment Check)
/// Memory access at misaligned address when CR0.AM=1 and EFLAGS.AC=1
fn handle_alignment_check(_error_code: u64, tf: &TrapFrame) {
    // _error_code is intentionally unused - reserved for future logging
    // // crate::kprintln!("[FAULT] #AC (Alignment Check)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  Error code: 0x{:016x}", _error_code)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // crate::kprintln!("  RIP=0x{:016x}", tf.rip)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);

    let user_mode = tf.cs & 3 != 0;
    if !user_mode {
        // // crate::kprintln!("[FAULT] #AC from kernel mode - system error!")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nostack));
            }
        }
    }
}
