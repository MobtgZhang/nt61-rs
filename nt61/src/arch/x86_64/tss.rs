//! TSS (Task State Segment)
//
//! x86_64 TSS for kernel stacks and IST (Interrupt Stack Table).
//! The TSS is a 104-byte structure whose 8 KiB-aligned portion
//! holds the IST stack pointers used by the hardware on certain
//! exceptions (double fault, NMI, machine check, ...).
//
//! Layout (per Intel SDM Vol 3, Figure 7-6):
//!   0x00  reserved1 (4 bytes)
//!   0x04  RSP0 (8 bytes)
//!   0x0C  RSP1 (8 bytes)
//!   0x14  RSP2 (8 bytes)
//!   0x1C  reserved2 (4 bytes) - Note: this is 4 bytes, not 8!
//!   0x20  IST1 (8 bytes)
//!   0x28  IST2 (8 bytes)
//!   0x30  IST3 (8 bytes)
//!   0x38  IST4 (8 bytes)
//!   0x40  IST5 (8 bytes)
//!   0x48  IST6 (8 bytes)
//!   0x50  IST7 (8 bytes)
//!   0x58  reserved3 (16 bytes)
//!   0x68  IO map base address (must be >= sizeof(TSS))
//
//! Total: 104 bytes minimum, IO bitmap follows if limit > 104

use core::mem::size_of;

/// One IST stack (64 KiB). Generously sized because nested
/// IRQs through the same IST1 can recurse deeply (each IRQ
/// uses ~300-500 bytes plus any printed strings), and a deeply
/// nested storm from an unprogrammed PIT produced enough
/// stack consumption to overflow an 8 KiB buffer and corrupt
/// adjacent memory; 64 KiB gives us ample headroom.
const IST_SIZE: usize = 65536;

/// x86_64 TSS structure matching Intel SDM Vol 3 Figure 7-6 exactly.
/// All offsets are verified against the Intel specification.
///
/// NOTE: Uses `#[repr(C, packed)]` because the Intel TSS layout has
/// RSP0 at offset 0x04 (not 8-byte aligned). The compiler would
/// normally insert 4 bytes of padding after _reserved0 to align rsp0
/// to offset 0x08. Using packed eliminates this padding and ensures
/// the exact layout required by the hardware.
#[repr(C, packed)]
pub struct Tss {
    pub _reserved0: u32,         // 0x00-0x03
    pub rsp0: u64,                // 0x04-0x0B
    pub rsp1: u64,               // 0x0C-0x13
    pub rsp2: u64,                // 0x14-0x1B
    pub _reserved1: u32,          // 0x1C-0x1F (4 bytes per Intel spec)
    pub ist1: u64,               // 0x20-0x27
    pub ist2: u64,               // 0x28-0x2F
    pub ist3: u64,               // 0x30-0x37
    pub ist4: u64,               // 0x38-0x3F
    pub ist5: u64,               // 0x40-0x47
    pub ist6: u64,               // 0x48-0x4F
    pub ist7: u64,               // 0x50-0x57
    pub _reserved2: [u8; 16],    // 0x58-0x67 (reserved per Intel)
    pub io_bitmap_base: u16,     // 0x68-0x69 (offset to I/O permission bitmap, or >= TSS limit)
}

impl Tss {
    pub const fn empty() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist1: 0, ist2: 0, ist3: 0, ist4: 0, ist5: 0, ist6: 0, ist7: 0,
            _reserved2: [0; 16],
            io_bitmap_base: size_of::<Tss>() as u16,
        }
    }
}

/// Compile-time assertion: verify Tss layout matches Intel SDM.
/// This catches any accidental changes to the structure that would break
/// the expected offsets.
const _: () = {
    assert!(core::mem::offset_of!(Tss, rsp0) == 0x04, "RSP0 must be at offset 0x04");
    assert!(core::mem::offset_of!(Tss, rsp1) == 0x0C, "RSP1 must be at offset 0x0C");
    assert!(core::mem::offset_of!(Tss, rsp2) == 0x14, "RSP2 must be at offset 0x14");
    assert!(core::mem::offset_of!(Tss, ist1) == 0x20, "IST1 must be at offset 0x20");
    assert!(core::mem::offset_of!(Tss, ist2) == 0x28, "IST2 must be at offset 0x28");
    assert!(core::mem::offset_of!(Tss, ist3) == 0x30, "IST3 must be at offset 0x30");
    assert!(core::mem::offset_of!(Tss, ist4) == 0x38, "IST4 must be at offset 0x38");
    assert!(core::mem::offset_of!(Tss, ist5) == 0x40, "IST5 must be at at offset 0x40");
    assert!(core::mem::offset_of!(Tss, ist6) == 0x48, "IST6 must be at offset 0x48");
    assert!(core::mem::offset_of!(Tss, ist7) == 0x50, "IST7 must be at offset 0x50");
    assert!(core::mem::offset_of!(Tss, io_bitmap_base) == 0x68, "IO bitmap base must be at offset 0x68");
    // Verify total size
    assert!(core::mem::size_of::<Tss>() >= 0x6A, "Tss must be at least 106 bytes");
};

#[repr(C, align(8))]
#[derive(Copy, Clone)]
struct IstStack([u8; IST_SIZE]);

// 8 IST stacks (one for each of IST1..IST7 plus a guard; IST1=DF
// IST2=NMI IST3=DF IST4=MC by convention).
static mut IST_STACKS: [IstStack; 8] = [IstStack([0; IST_SIZE]); 8];

/// TSS instance (a single one shared by all CPUs in the bootstrap).
static mut TSS: Tss = Tss::empty();

/// Pointer to the TSS (the GDT entry points at this).
pub fn tss_ptr() -> *mut Tss {
    unsafe { &mut TSS as *mut Tss }
}

/// Return (base, limit) for the BSP TSS so a GDT entry can be built
/// around it.
pub fn current_tss_base_limit() -> (u64, u32) {
    (tss_ptr() as u64, size_of::<Tss>() as u32)
}

/// Initialise the TSS and the IST stack pointers. Should be called
/// once during boot.
pub fn init() {
    // CRITICAL-008: install the IST stack pointers on the BSP TSS.
    // We compute the stack tops at runtime because `IST_STACKS` is
    // `static mut` (and a `static mut` cannot be referenced in a
    // `const` context). Each IST entry is a private 8 KiB stack that
    // is loaded by the hardware when the corresponding exception
    // fires.
    let tops: [u64; 7] = unsafe {
        [
            (&IST_STACKS[0].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[1].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[2].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[3].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[4].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[5].0 as *const u8 as u64) + IST_SIZE as u64,
            (&IST_STACKS[6].0 as *const u8 as u64) + IST_SIZE as u64,
        ]
    };
    install_ist_stack(tops);
}

/// CRITICAL-008: programmatic re-install of the IST stack pointers
/// on the current TSS. `ist_top` is an array of 7 IST stack *tops*
/// (the highest valid address on each stack). The hardware loads
/// the stack pointer from the IST field directly when the
/// corresponding exception fires, so the value must point at the
/// top-of-stack (high address), not the base.
///
/// `ist_top[0]` -> IST1 (#DB), `ist_top[1]` -> IST2 (NMI),
/// `ist_top[2]` -> IST3 (#DF), `ist_top[3]` -> IST4 (#MC),
/// `ist_top[4..6]` -> spare / future use.
///
/// Offsets are per Intel SDM Vol 3 Figure 7-6:
///   IST1: 0x20, IST2: 0x28, IST3: 0x30, IST4: 0x38
///   IST5: 0x40, IST6: 0x48, IST7: 0x50
pub fn install_ist_stack(ist_top: [u64; 7]) {
    unsafe {
        let tss_ptr = &mut TSS as *mut Tss as *mut u8;
        // IST1 at offset 0x20
        core::ptr::write_unaligned(tss_ptr.add(0x20) as *mut u64, ist_top[0]);
        // IST2 at offset 0x28
        core::ptr::write_unaligned(tss_ptr.add(0x28) as *mut u64, ist_top[1]);
        // IST3 at offset 0x30
        core::ptr::write_unaligned(tss_ptr.add(0x30) as *mut u64, ist_top[2]);
        // IST4 at offset 0x38
        core::ptr::write_unaligned(tss_ptr.add(0x38) as *mut u64, ist_top[3]);
        // IST5 at offset 0x40
        core::ptr::write_unaligned(tss_ptr.add(0x40) as *mut u64, ist_top[4]);
        // IST6 at offset 0x48
        core::ptr::write_unaligned(tss_ptr.add(0x48) as *mut u64, ist_top[5]);
        // IST7 at offset 0x50
        core::ptr::write_unaligned(tss_ptr.add(0x50) as *mut u64, ist_top[6]);
        // io_bitmap_base at offset 0x68 (must be >= sizeof(Tss) to indicate no I/O bitmap)
        core::ptr::write_unaligned(tss_ptr.add(0x68) as *mut u16,
            core::mem::size_of::<Tss>() as u16);
    }
}

/// Read the current TSS.RSP0 (kernel stack pointer used for the
/// next Ring 3 -> Ring 0 transition).
pub fn rsp0() -> u64 {
    get_rsp0()
}

/// Set the kernel stack pointer (RSP0) for the current CPU. The
/// next ring transition will switch to this stack.
pub fn set_rsp0(rsp: u64) {
    unsafe {
        let tss = &mut TSS;
        // Use a raw pointer write to avoid the packed-struct
        // misaligned-access check.
        let p = core::ptr::addr_of_mut!(tss.rsp0) as *mut u64;
        core::ptr::write_unaligned(p, rsp);
    }
}

/// CRITICAL-013: capture the current kernel stack pointer and store
/// it in `TSS.rsp0`. This must be called BEFORE the IDT is
/// configured with `IST=0` for any IRQ gate that could fire while
/// the CPU is still executing its early-boot kernel stack frame
/// (i.e. before `enter_first_user_thread` has run). Without it,
/// `TSS.rsp0` is 0 and an IRQ delivered to a non-IST vector would
/// push its iret frame at virtual address 0, which is a #PF / #SS.
///
/// Designed to be called once from `kernel_main` after
/// `arch::init_hardware()` and before any code path that might
/// enable interrupts or unmask a PIC line.
pub fn set_rsp0_during_init() {
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        set_rsp0(rsp);
    }
}

pub fn get_rsp0() -> u64 {
    unsafe {
        let tss = &TSS;
        let p = core::ptr::addr_of!(tss.rsp0) as *const u64;
        core::ptr::read_unaligned(p)
    }
}

// ---------------------------------------------------------------------------
// Per-CPU TSS
// ---------------------------------------------------------------------------
//
// `TSS` above is the BSP's TSS. Each AP needs its own TSS because
// `RSP0` is per-thread (it's where the CPU switches to when an IRQ
// or syscall returns to ring 0). We give the APs a static pool of
// per-CPU TSS structs. The pool size is `MAX_CPUS - 1` because
// slot 0 is the BSP.

/// Maximum number of APs we support.
pub const MAX_APS: usize = 31;

/// Per-CPU TSS pool. Slot `i` is the TSS for AP #i (BSP is in
/// `TSS` above).
#[repr(C, align(16))]
pub struct PerCpuTss {
    pub tss: Tss,
    /// Reserved IST stack area for this AP (8 KiB).
    pub ist_stack: [u8; IST_SIZE],
}

static mut AP_TSS: [PerCpuTss; MAX_APS] = [const {
    PerCpuTss {
        tss: Tss::empty(),
        ist_stack: [0; IST_SIZE],
    }
}; MAX_APS];

/// Return a pointer to the AP TSS for `ap_index` (0-based, BSP is
/// excluded).
pub fn ap_tss(ap_index: usize) -> *mut PerCpuTss {
    if ap_index >= MAX_APS { core::ptr::null_mut() } else { unsafe { &mut AP_TSS[ap_index] } }
}

/// Initialise an AP's TSS: set the IST stack pointer, return the
/// TSS address and limit so the per-CPU GDT can be built around it.
pub unsafe fn init_ap_tss(ap_index: usize, rsp0: u64) -> Option<(*mut Tss, u32)> {
    let slot = ap_tss(ap_index);
    if slot.is_null() { return None; }
    let tss = &mut (*slot).tss;
    let stack_top = (&(*slot).ist_stack as *const u8) as u64 + IST_SIZE as u64;
    tss.rsp0 = rsp0;
    tss.ist1 = stack_top;
    tss.ist2 = stack_top;
    tss.ist3 = stack_top;
    tss.io_bitmap_base = core::mem::size_of::<Tss>() as u16;
    Some((tss, core::mem::size_of::<Tss>() as u32))
}
