//! Global Descriptor Table (GDT)
//
//! x86_64 GDT layout (augmented over OVMF):
//!   slot 0 (selector 0x00): null
//!   slot 1 (selector 0x08): kernel CS  (OVMF, DPL=0)
//!   slot 2 (selector 0x10): kernel DS  (OVMF, DPL=0)
//!   slot 3 (selector 0x18): kernel SS  (OVMF, DPL=0)
//!   slot 4 (selector 0x20): user SS    (DPL=3, selector 0x23)
//!   slot 5 (selector 0x28): user CS    (DPL=3, selector 0x2b)
//!   slot 8 (selector 0x40): TSS (16 bytes)
//
//! NOTE: The GdtTable struct fields (e0-e7) are an 8-entry array at
//! 8 bytes each. The actual augmented slots use slots 4-5 (OVMF slots
//! are left untouched). The TSS is at slot 8.

/// Selector constants for the augmented OVMF GDT.
///
/// The IA32_STAR MSR encoding (per AMD64 manual):
///   STAR[47:32]      → SYSCALL CS base (actual = STAR[47:32] - 8)
///   STAR[63:48]      → SYSRET SS base  (actual = STAR[63:48])
///   SYSRET CS        = STAR[63:48] + 16 (with RPL=3)
///   SYSRET SS        = STAR[63:48] + 8  (with RPL=3)
///
/// Current STAR value: STAR[47:32]=0x18, STAR[63:48]=0x18
///   SYSCALL CS = 0x18 (slot 3 / KERNEL_DS — descriptor cache is
///                       overridden by the CPU with a 64-bit CS;
///                       this only sets the selector value used by
///                       interrupt returns that inspect CS).
///   SYSCALL SS = 0x18 + 8 = 0x20 (USER_DS slot — descriptor cache
///                                  overridden by CPU with 32-bit
///                                  data segment with DPL=0).
///   SYSRET CS  = 0x18 + 16 = 0x28 | RPL=3 = 0x2b (USER_CS) ✓
///   SYSRET SS  = 0x18 + 8  = 0x20 | RPL=3 = 0x23 (USER_SS) ✓
/// OVMF's 64-bit kernel CS is slot 7 (offset 0x38), NOT slot 2.
/// Slot 2 (0x10) is the legacy 32-bit code segment from the UEFI
/// boot environment. In long mode an interrupt gate whose target CS
/// is a 32-bit descriptor causes #GP during exception delivery,
/// which is what was producing the cascade #PF → #DF → #GP → triple
/// fault the very first time we tried to handle an exception from
/// Ring 3 (the Ring 3 #PF could not be delivered because its IDT
/// entry pointed at a 32-bit CS).
pub const KERNEL_CS: u16 = 0x38;
pub const KERNEL_DS: u16 = 0x18;
/// User code selector: SYSRET destination. Slot 5 (offset 0x28), RPL=3 → 0x2b.
/// Set by IA32_STAR hardware on SYSRET; must match STAR[63:48]+16.
pub const USER_CS: u16 = 0x28 | 3;   // 0x2b
/// User data/stack selector: SYSRET SS destination. Slot 4 (offset 0x20), RPL=3 → 0x23.
pub const USER_DS: u16 = 0x20 | 3;   // 0x23
/// TSS selector: slot 8 (offset 0x40).
pub const TSS_SEL: u16 = 0x40;

/// Re-export USER_DS as USER_SS for modules that use the SS naming convention.
pub use USER_DS as USER_SS;


/// 8-byte GDT entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags: u8,
    pub base_high: u8,
}

impl GdtEntry {
    pub const fn empty() -> Self {
        Self { limit_low: 0, base_low: 0, base_mid: 0, access: 0, flags: 0, base_high: 0 }
    }
    pub const fn kernel_code64() -> Self {
        Self { limit_low: 0xFFFF, base_low: 0, base_mid: 0, access: 0x9B, flags: 0xAF, base_high: 0 }
    }
    pub const fn kernel_data64() -> Self {
        Self { limit_low: 0xFFFF, base_low: 0, base_mid: 0, access: 0x93, flags: 0xCF, base_high: 0 }
    }
    pub const fn user_code64() -> Self {
        Self { limit_low: 0xFFFF, base_low: 0, base_mid: 0, access: 0xFB, flags: 0xAF, base_high: 0 }
    }
    pub const fn user_data64() -> Self {
        Self { limit_low: 0xFFFF, base_low: 0, base_mid: 0, access: 0xF3, flags: 0xCF, base_high: 0 }
    }
}

/// 16-byte TSS descriptor.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct TssDescriptor {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub flags: u8,
    pub base_high: u8,
    pub base_upper: u32,
    pub _reserved: u32,
}

impl TssDescriptor {
    pub const fn empty() -> Self {
        Self { limit_low: 0, base_low: 0, base_mid: 0, access: 0, flags: 0,
               base_high: 0, base_upper: 0, _reserved: 0 }
    }
    pub fn from_tss(base: u64, limit: u32) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access: 0x89,
            flags: 0x40,
            base_high: ((base >> 24) & 0xFF) as u8,
            base_upper: ((base >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        }
    }
}

/// GDT table matching the actual augmented slot layout (8 bytes/slot):
///   e0 @ 0x00: null
///   e1 @ 0x08: kernel CS  (OVMF)
///   e2 @ 0x10: kernel DS  (OVMF)
///   e3 @ 0x18: kernel SS  (OVMF)
///   e4 @ 0x20: user SS    (DPL=3) — selector 0x23  ← slot_offsets[0]
///   e5 @ 0x28: user CS    (DPL=3) — selector 0x2b  ← slot_offsets[1]
///   e6 @ 0x30: (unused, OVMF slot 6)
///   e7 @ 0x38: (unused, OVMF slot 7)
///   e8 @ 0x40: TSS descriptor (16 bytes)             ← slot_offsets[2]
///   e9 @ 0x48: TSS descriptor high (part of e8)     ← slot_offsets[3]
///   eA @ 0x50: (unused padding)
///   eB @ 0x58: (unused padding)
/// Total size: 96 bytes (slots 0..11).
///
/// NOTE: `init()` writes augmented descriptors at slots 4, 5, 8, 9.
/// The struct has entries e4..e7 at slots 4..7 (matching OVMF's
/// existing layout) plus extra entries e8..eB for the TSS.
#[repr(C, packed)]
pub struct GdtTable {
    pub e0: GdtEntry,           // slot 0: null
    pub e1: GdtEntry,           // slot 1: kernel CS (OVMF)
    pub e2: GdtEntry,           // slot 2: kernel DS (slot owned by us, kernel_data64)
    pub e3: GdtEntry,           // slot 3: kernel SS (slot owned by us, kernel_data64)
    pub e4: GdtEntry,           // slot 4: user SS (DPL=3, selector 0x23)
    pub e5: GdtEntry,           // slot 5: user CS (DPL=3, selector 0x2b)
    pub e6: GdtEntry,           // slot 6: (unused, OVMF)
    pub e7: GdtEntry,           // slot 7: (unused, OVMF)
    pub e8: TssDescriptor,      // slot 8: TSS (16 bytes)
    pub e9: GdtEntry,           // slot 9: (part of TSS, padding)
    pub eA: GdtEntry,           // slot 10: (unused)
    pub eB: GdtEntry,           // slot 11: (unused)
}

/// Compile-time assertions verifying the struct layout matches the
/// slot-based selector constants and actual GDT offsets.
const _: () = {
    // Verify each field lands at the correct GDT slot offset.
    assert!(core::mem::offset_of!(GdtTable, e0) == 0x00, "e0 must be at offset 0x00");
    assert!(core::mem::offset_of!(GdtTable, e1) == 0x08, "e1 must be at offset 0x08");
    assert!(core::mem::offset_of!(GdtTable, e2) == 0x10, "e2 must be at offset 0x10");
    assert!(core::mem::offset_of!(GdtTable, e3) == 0x18, "e3 must be at offset 0x18 (slot 3)");
    assert!(core::mem::offset_of!(GdtTable, e4) == 0x20, "e4 must be at offset 0x20 (slot 4)");
    assert!(core::mem::offset_of!(GdtTable, e5) == 0x28, "e5 must be at offset 0x28 (slot 5)");
    assert!(core::mem::offset_of!(GdtTable, e6) == 0x30, "e6 must be at offset 0x30 (slot 6)");
    assert!(core::mem::offset_of!(GdtTable, e7) == 0x38, "e7 must be at offset 0x38 (slot 7)");
    assert!(core::mem::offset_of!(GdtTable, e8) == 0x40, "e8 must be at offset 0x40 (slot 8, TSS)");
    assert!(core::mem::offset_of!(GdtTable, e9) == 0x50, "e9 must be at offset 0x50");
    assert!(core::mem::offset_of!(GdtTable, eA) == 0x58, "eA must be at offset 0x58");
    assert!(core::mem::offset_of!(GdtTable, eB) == 0x60, "eB must be at offset 0x60");

    // Verify GdtTable is large enough to cover the TSS (e8, 16 bytes).
    assert!(core::mem::size_of::<GdtTable>() >= 0x48 + 8, "GdtTable must cover slots 0..9");

    // Verify selector constants match their slot × 8 + RPL layout.
    assert!(USER_CS == (5 * 8 | 3), "USER_CS must be slot 5 with RPL=3 (0x2b)");
    assert!(USER_DS == (4 * 8 | 3), "USER_DS must be slot 4 with RPL=3 (0x23)");
    assert!(TSS_SEL == (8 * 8),         "TSS_SEL must be slot 8 (0x40)");
};

#[repr(C, packed)]
#[allow(dead_code)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

#[allow(dead_code)]
static mut GDT: GdtTable = GdtTable {
    e0: GdtEntry::empty(),
    e1: GdtEntry::kernel_code64(),
    e2: GdtEntry::kernel_data64(),
    e3: GdtEntry::kernel_data64(), // slot 3: kernel SS, DPL=0 — owned by this table, not OVMF
    e4: GdtEntry::empty(),            // slot 4: user SS (DPL=3) — written by init()
    e5: GdtEntry::empty(),            // slot 5: user CS (DPL=3) — written by init()
    e6: GdtEntry::empty(),            // slot 6: (unused, OVMF)
    e7: GdtEntry::empty(),            // slot 7: (unused, OVMF)
    e8: TssDescriptor::empty(),      // slot 8: TSS — written by init()
    e9: GdtEntry::empty(),            // slot 9: (part of TSS)
    eA: GdtEntry::empty(),            // slot 10: (unused)
    eB: GdtEntry::empty(),            // slot 11: (unused)
};



/// Initialise the GDT and load the TR.
///
/// The OVMF firmware already loaded a working GDT with kernel CS
/// at selector 0x10 and kernel DS at selector 0x18 (both DPL=0).
/// We extend the existing GDT by overwriting slots 4, 5, 8, and 9:
///
///   slot 4 (selector 0x20 | 3 = 0x23): user SS  (DPL=3, 64-bit data)
///   slot 5 (selector 0x28 | 3 = 0x2b): user CS  (DPL=3, 64-bit code)
///   slot 8 (selector 0x40):             TSS descriptor (16 bytes,
///                                         spans slots 8 and 9)
///
/// After this we extend the GDTR limit to cover slot 9 and load
/// the TR with the new TSS selector (0x40). The kernel is then
/// ready to `iretq` into Ring 3.

// ============================================================================
// Early UART debug output helpers (before MM is initialized)
// ============================================================================

/// CRITICAL: Early UART debug output helper for boot phases before MM is ready.
/// This function writes directly to the UART without any formatting overhead.
#[cfg(target_arch = "x86_64")]
fn early_uart_puts(s: &[u8]) {
    const COM1: u16 = 0x3F8;
    unsafe {
        for &c in s {
            let mut lsr: u8;
            core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
            while lsr & 0x20 == 0 {
                core::arch::asm!("in al, dx", in("dx") COM1 + 5, out("al") lsr, options(nostack, preserves_flags));
            }
            core::arch::asm!("out dx, al", in("dx") COM1, in("al") c, options(nostack, preserves_flags));
        }
    }
}

/// Write a 64-bit value as 16 hex digits to UART.
#[cfg(target_arch = "x86_64")]
fn early_uart_put_hex64(val: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for i in (0u8..16).rev() {
        let n = ((val >> (i * 4)) & 0xF) as usize;
        early_uart_puts(&[HEX[n]]);
    }
}

pub fn init() {
    // CRITICAL: Use raw UART output during early boot, before MM is fully initialized.
    // The kprintln! macro may have issues when LOG_EARLY_READY is false and the
    // formatted output path involves code/data that isn't yet properly mapped.
    #[cfg(target_arch = "x86_64")]
    {
        early_uart_puts(b"[HW] gdt_init_begin\r\n");
    }

    // User SS at slot 4 (selector 0x23): DPL=3, data, exec/read/write.
    // User CS at slot 5 (selector 0x2b): DPL=3, code, exec/read.
    // TSS at slot 8 (selector 0x40): 16-byte available 64-bit TSS.
    //
    // The descriptor layout (8 bytes per GDT entry) per Intel SDM
    // vol 3 Figure 3-8:
    //   bits  0..16  = limit_low  (16 bits)
    //   bits 16..32  = base_low   (16 bits)
    //   bits 32..40  = base_mid   (8 bits)
    //   bits 40..48  = access     (8 bits: P|DPL|S|Type)
    //   bits 48..52  = limit_hi   (4 bits)
    //   bits 52..56  = flags      (4 bits: G|D/B|L|AVL)
    //   bits 56..64  = base_high  (8 bits)
    let user_ss: u64 = {
        // access (bits 40..47) = 0xF3 → P=1 DPL=3 S=1 Type=3
        //   (data, R/W, expand-UP, accessed)
        // limit_high (bits 48..51) = 0xF
        // flags (bits 52..55) = G=1 D=1 L=0 AVL=0  → encoded as 0xC
        //   (binary 1100; bit0=G=1, bit1=D=1, bit2=L=0, bit3=AVL=0).
        //   iretq-style load of SS at CPL=3 must find a writable
        //   data segment with DPL=3 in long mode.
        (0x0000_FFFFu64)
            | (0xF3u64 << 40)
            | (0xFu64 << 48)
            | (0xCu64 << 52)
    };
    let user_cs: u64 = {
        // access (bits 40..47) = 0xFB → P=1 DPL=3 S=1 Type=B
        //   (code, exec/read, non-conforming, accessed)
        // limit_high (bits 48..51) = 0xF
        // flags (bits 52..55) = G=1 D=0 L=1 AVL=0
        //   L=1 marks this as a 64-bit code segment (required for
        //   Ring 3 code execution in long mode). Per Intel SDM
        //   vol 3 §3.4.5, D MUST be 0 when L=1 (D=1 L=1 is an
        //   illegal combination). With D=1 L=1 the CPU treats
        //   the descriptor as 32-bit and iretq pops only the
        //   low 32 bits of RSP/SS, leaving the high 32 bits
        //   zeroed — which is exactly the truncation we saw
        //   (`rsp=0x7fffde100000` → `rsp=0xde100000`).
        //   0xA = 0b1010 → bit0=G=1, bit1=D=0, bit2=L=1, bit3=AVL=0.
        (0x0000_FFFFu64)
            | (0xFBu64 << 40)
            | (0xFu64 << 48)
            | (0xAu64 << 52)
    };
    #[cfg(target_arch = "x86_64")]
    let tss = crate::arch::x86_64::tss::current_tss_base_limit();
    let (tss_lo, tss_hi) = {
        // Build the 16-byte TSS descriptor as two u64s.
        // GDT entry layout (per Intel SDM vol 3, Figure 3-8):
        //   bits  0..16  = limit_low  (16 bits)
        //   bits 16..32  = base_low   (16 bits)
        //   bits 32..40  = base_mid   (8 bits)
        //   bits 40..48  = access     (8 bits)
        //   bits 48..52  = limit_hi   (4 bits)
        //   bits 52..56  = flags      (4 bits: G/D/B/L/AVL)
        //   bits 56..64  = base_high  (8 bits)
        // The next 8 bytes of a TSS descriptor are:
        //   bits 64..96  = base_upper (32 bits)
        //   bits 96..128 = reserved   (32 bits, must be 0)
        let desc = TssDescriptor::from_tss(tss.0, tss.1);
        let lo: u64 = (desc.limit_low as u64)
                    | ((desc.base_low as u64) << 16)
                    | ((desc.base_mid as u64) << 32)
                    | ((desc.access as u64) << 40)
                    | (((desc.limit_low as u64 >> 16) & 0xF) << 48)
                    | (((desc.flags as u64) & 0xF) << 52)
                    | (((desc.base_high as u64) & 0xFF) << 56);
        let hi: u64 = desc.base_upper as u64;
        (lo, hi)
    };

    // Slots to augment (selector value / 8):
    //   slot 4 (offset 0x20): user SS  — overwrites OVMF slot 4.
    //   slot 5 (offset 0x28): user CS  — overwrites OVMF slot 5.
    //   slot 6 (offset 0x30): GS descriptor — must have DPL=3 so that
    //                            in kernel mode gs: accesses use
    //                            IA32_KERNEL_GS_BASE (loaded with
    //                            &PER_CPU_0), and in user mode gs:
    //                            accesses use IA32_GS_BASE. OVMF's
    //                            default slot 6 has DPL=0 which would
    //                            silently redirect every `gs:[off]`
    //                            write in kernel mode to IA32_GS_BASE
    //                            (=0) instead of &PER_CPU_0.
    //   slot 7 (offset 0x38): KERNEL_CS — overwrite OVMF slot 7 with
    //                            proper 64-bit code flags (G=1 D=0 L=1).
    //                            OVMF's slot 7 has D=1 L=1 (INVALID per
    //                            Intel SDM vol 3 §3.4.5). With the wrong
    //                            flags, pushq only pushes 4 bytes and
    //                            iretq loads user RSP from a 32-bit slot,
    //                            leaving the high 32 bits stripped.
    //   slot 8 (offset 0x40): TSS descriptor (16 bytes; spans 8..9).
    // We need to write slots 4, 5, 6, 7, 8, 9.
    let slot_offsets: [u64; 7] = [0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48];
    // KERNEL_DS at slot 3 (selector 0x18): DPL=0, expand-UP data, R/W.
    //   access (bits 40..47)  = 0x93 → P=1 DPL=0 S=1 Type=3 (data R/W, expand-UP, accessed)
    //   limit_high (bits 48..51) = 0xF (limit = 0x000F_FFFF)
    //   flags (bits 52..55) = G=1 D=1 L=0 AVL=1
    //     Encoded as 0xB (binary 1011; bit0=G, bit1=D, bit2=L=0, bit3=AVL).
    //     L must be 0 because L=1 marks a "64-bit code" descriptor, and
    //     loading such a descriptor into SS via iretq at CPL=0 is a #GP
    //     (the CPU rejects the descriptor because SS must be a writable
    //     data segment in long mode).
    //   base_high (bits 56..63) = 0 (flat)
    let kernel_ds: u64 =
        (0x0000_FFFFu64)       // bits 0..15 limit_low
        | (0x93u64 << 40)      // bits 40..47 access
        | (0xFu64 << 48)       // bits 48..51 limit_high
        | (0xCu64 << 52);      // bits 52..55 flags (G=1 D=1 L=0 AVL=0)
    // GS descriptor: 32-bit flat data, DPL=3, granularity=4 KiB.
    //   access = 0xF3 = P=1, DPL=3, S=1, Type=3 (data RW/accessed)
    //   limit  = 0x000FFFFF (G=1)
    //   flags  = 0xC       = G=1 D=1 L=0 AVL=0
    //   base   = 0
    // GS descriptor (slot 6, selector 0x30): DPL=0 (kernel-accessible),
    //   expand-UP 4-GiB data. We use a DPL=0 descriptor so the kernel's
    //   own `mov gs, 0x30` in `init()` does not trip the CPL ≤ DPL check.
    //   The GDT-side DPL does not influence how the `gs:` prefix
    //   resolves the GS base — the base comes from IA32_GS_BASE
    //   (kernel) or IA32_KERNEL_GS_BASE (user, after swapgs). The DPL
    //   only matters for explicit `mov gs, sel` / `pop gs` instructions.
    //   access (bits 40..47) = 0x93 → P=1 DPL=0 S=1 Type=3 (data R/W,
    //     expand-UP, accessed)
    //   limit_high = 0xF, flags = G=1 D=1 L=0 AVL=0  (0xC << 52)
    let gs_descriptor: u64 =
        (0x0000_FFFFu64)
        | (0x93u64 << 40)
        | (0xFu64 << 48)
        | (0xCu64 << 52);
    // KERNEL_CS at slot 7 (selector 0x38): proper 64-bit code descriptor.
    //   access (bits 40..47) = 0x9B → P=1 DPL=0 S=1 Type=B (code, exec/read, non-conforming, accessed)
    //   flags + limit_high (bits 48..55) = 0xAF → G=1 D=0 L=1 AVL=0 limit_high=0xF
    // OVMF's default slot 7 has D=1 L=1 which QEMU treats as 32-bit,
    // breaking pushq/iretq in the kernel.
    let kernel_cs: u64 =
        (0x0000_FFFFu64)       // bits 0..15: limit_low = 0xFFFF
        | (0x9Bu64 << 40)      // bits 40..47: access = 0x9B
        | (0xAFu64 << 48);     // bits 48..55: flags + limit_high = 0xAF (G=1 D=0 L=1 AVL=0 + limit_high=0xF)
    let data: [u64; 7] = [kernel_ds, user_ss, user_cs, gs_descriptor, kernel_cs, tss_lo, tss_hi];
    // NOTE: kprintln removed because MM is not initialized yet

    // Read GDTR, write the augmented slots directly from Rust, then
    // extend the GDTR limit. Rust has full visibility into the GDTR
    // via `sgdt`; doing the work in Rust instead of asm avoids
    // register-allocation surprises.
    let gdtr_base: u64;
    unsafe {
        let mut buf = [0u8; 16];
        core::arch::asm!(
            "sgdt [{buf}]",
            buf = in(reg) buf.as_mut_ptr(),
            options(nostack),
        );
        let limit = u16::from_le_bytes([buf[0], buf[1]]);
        gdtr_base = u64::from_le_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
        #[cfg(target_arch = "x86_64")]
        {
            early_uart_puts(b"[HW] gdtr=");
            early_uart_put_hex64(gdtr_base);
            early_uart_puts(b" limit=");
            early_uart_put_hex64(limit as u64);
            early_uart_puts(b"\r\n");
        }
    }
    unsafe {
        for i in 0..slot_offsets.len() as u64 {
            let addr = gdtr_base + slot_offsets[i as usize];
            core::ptr::write_volatile(addr as *mut u64, data[i as usize]);
        }
        // Dump the augmented slots so we can see the bytes (early UART output).
        #[cfg(target_arch = "x86_64")]
        {
            early_uart_puts(b"[HW] gdt_dump\r\n");
            for i in 0..10u64 {
                let addr = (gdtr_base + i * 8) as *const u64;
                let lo: u64 = core::ptr::read_unaligned(addr);
                early_uart_puts(b"slot ");
                early_uart_put_hex64(i);
                early_uart_puts(b" = ");
                early_uart_put_hex64(lo);
                early_uart_puts(b"\r\n");
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (gdtr_base, slot_offsets, data);
        }
        // Extend GDTR.limit to cover slot 9 (offset 0x48 + 7 = 0x4f).
        // This makes slots 0..9 addressable and includes the TSS.
        let mut gdt_ptr16 = [0u8; 16];
        gdt_ptr16[0] = 0x4f;
        gdt_ptr16[1] = 0x00;
        for (i, b) in gdtr_base.to_le_bytes().iter().enumerate() {
            gdt_ptr16[i + 2] = *b;
        }
        core::arch::asm!(
            "lgdt [{buf}]",
            buf = in(reg) gdt_ptr16.as_mut_ptr(),
            options(nostack),
        );
        #[cfg(target_arch = "x86_64")]
        {
            early_uart_puts(b"[HW] gdt_lgdt_done\r\n");
        }
        // Dump the current CS selector so we can see what the kernel
        // is actually running with. Far-jumping to 0x38 only makes
        // sense if that is the actual CS — if it's not, the far-jump
        // would re-enter the wrong segment.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let cs_val: u16;
            core::arch::asm!(
                "mov {cs:x}, cs",
                cs = out(reg) cs_val,
                options(nostack, preserves_flags),
            );
            early_uart_puts(b"[HW] cs_before_farjump=0x");
            early_uart_put_hex64(cs_val as u64);
            early_uart_puts(b"\r\n");
        }
        // Far-jump to slot 7 (selector 0x38) so the CPU reloads the CS
        // descriptor cache from the new GDT entry (which now has
        // proper 64-bit flags G=1 D=0 L=1). Without this reload, the
        // CPU keeps using the old slot 7 (D=1 L=1 = invalid 64-bit
        // encoding) and pushq only pushes 4 bytes, breaking iretq.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // 0x38 is KERNEL_CS; the far jump is to the *next*
            // instruction so we don't lose control flow.
            // We use a memory operand to avoid AX-routing surprises.
            core::arch::asm!(
                "push 0x38",
                "lea rax, [rip + 2f]",
                "push rax",
                "retfq",
                "2:",
                options(nostack),
            );
            // Sanity check: dump CS right after the far-jump so we
            // can confirm the descriptor cache reload happened.
            let cs_after: u16;
            core::arch::asm!(
                "mov {cs:x}, cs",
                cs = out(reg) cs_after,
                options(nostack, preserves_flags),
            );
            // Dump CS.L and CS.D by reading the GDT slot 7.
            let slot7_lo: u64;
            let slot7_hi: u64;
            core::arch::asm!(
                "mov {lo}, qword ptr [{gdtr} + 0x38]",
                lo = out(reg) slot7_lo,
                gdtr = in(reg) gdtr_base,
                options(nostack),
            );
            let _ = slot7_hi;
            let cs_dbg = cs_after;
            early_uart_puts(b"[HW] gdt_far_jump_done cs=0x");
            early_uart_put_hex64(cs_dbg as u64);
            early_uart_puts(b" slot7_lo=0x");
            early_uart_put_hex64(slot7_lo);
            early_uart_puts(b"\r\n");
            // DEBUG: Compare the GDT slot 7 in memory with what's in the
            // CPU's CS descriptor cache.
            // First, read slot 7 directly from GDT.
            let slot7_qword: u64;
            core::arch::asm!(
                "mov {v}, qword ptr [{gdtr} + 0x38]",
                v = out(reg) slot7_qword,
                gdtr = in(reg) gdtr_base,
                options(nostack),
            );
            let _ = slot7_qword;
            early_uart_puts(b"[HW] slot7 mem=0x");
            early_uart_put_hex64(slot7_qword);
            early_uart_puts(b"\r\n");
            // Now compare with what LAR reports.
            let cs_ar_eax: u32;
            core::arch::asm!(
                "mov eax, cs",
                "lar eax, ax",
                out("eax") cs_ar_eax,
                options(nostack, preserves_flags),
            );
            early_uart_puts(b"[HW] CS AR eax=0x");
            early_uart_put_hex64(cs_ar_eax as u64);
            early_uart_puts(b"\r\n");
            // Read the cache via the GDT slot 7 in memory so we can
            // see if the cache matches.
            let slot7_qword: u64;
            core::arch::asm!(
                "mov {v}, qword ptr [{gdtr} + 0x38]",
                v = out(reg) slot7_qword,
                gdtr = in(reg) gdtr_base,
                options(nostack),
            );
            let byte5 = ((slot7_qword >> 40) & 0xFF) as u8;
            let byte6 = ((slot7_qword >> 48) & 0xFF) as u8;
            early_uart_puts(b"[HW] slot7 byte5=0x");
            early_uart_put_hex64(byte5 as u64);
            early_uart_puts(b" byte6=0x");
            early_uart_put_hex64(byte6 as u64);
            early_uart_puts(b"\r\n");
        }
        // GS/SS reloads are skipped here because they were causing
        // the kernel to silently hang in QEMU. The far-jump above
        // is enough to fix the iretq issue (kernel CS descriptor
        // D=1 L=1 -> D=0 L=1).
    }

    // Now load the TR with the TSS selector.
    unsafe {
        core::arch::asm!(
            "ltr {sel:x}",
            sel = in(reg) (TSS_SEL as u64),
            options(nostack, preserves_flags),
        );
        #[cfg(target_arch = "x86_64")]
        {
            early_uart_puts(b"[HW] gdt_ltr_done\r\n");
        }
    }

    // Sanity check: verify that the user PML4 has a copy of the
    // kernel half so kernel code stays reachable after CR3 switch.
    #[cfg(target_arch = "x86_64")]
    {
        early_uart_puts(b"[HW] gdt_init_done\r\n");
    }
}

// ---------------------------------------------------------------------------
// Per-CPU GDT + TSS
// ---------------------------------------------------------------------------
//
// SMP requires a per-CPU TSS because RSP0 must point to the kernel
// stack of the *current* thread on the *current* CPU. The BSP keeps
// its own GDT (above) and its own TSS. Each AP allocates a GDT page
// and a TSS from the kernel pool and installs them in `ap_install`.

/// A per-CPU GDT in the same shape as the BSP GDT. Each AP gets
/// one of these. TSS is at slot 8 (offset 0x40, 16 bytes).
pub type PerCpuGdt = GdtTable;

/// Build a per-CPU GDT in `out` whose TSS descriptor points at
/// `tss_base` with limit `tss_limit`.
/// Slot layout: e0=slot0(null), e1=slot1(kernel CS), e2=slot2(kernel DS),
/// e3=slot3(kernel SS), e4=slot4(user SS), e5=slot5(user CS),
/// e8=slot8(TSS), e9/eA/eB=unused.
pub fn build_per_cpu_gdt(out: &mut PerCpuGdt, tss_base: u64, tss_limit: u32) {
    out.e0 = GdtEntry::empty();
    out.e1 = GdtEntry::kernel_code64();
    out.e2 = GdtEntry::kernel_data64();
    out.e3 = GdtEntry::kernel_data64(); // slot 3: kernel SS — owned by this GDT, not OVMF
    out.e4 = GdtEntry::empty();              // slot 4: user SS — written by init()
    out.e5 = GdtEntry::empty();              // slot 5: user CS — written by init()
    out.e6 = GdtEntry::empty();              // slot 6: (unused)
    out.e7 = GdtEntry::empty();              // slot 7: (unused)
    out.e8 = TssDescriptor::from_tss(tss_base, tss_limit); // slot 8: TSS
    out.e9 = GdtEntry::empty();              // slot 9: (TSS high)
    out.eA = GdtEntry::empty();              // slot 10: (unused)
    out.eB = GdtEntry::empty();              // slot 11: (unused)
}

/// Dump the current GDT to the serial console. Used during the
/// Phase 0 Ring 0/3 bring-up to confirm the OVMF-provided
/// selectors that the iretq/sysretq paths will use.
pub fn dump_gdt_for_debug() {
    // GDTR layout: 2-byte limit + 8-byte base = 10 bytes total.
    // Inline asm operands only accept integer/float/pointer types, so we
    // allocate a writable 16-byte buffer on the stack and parse the bytes
    // back out in Rust.
    let limit: u16;
    let base: u64;
    unsafe {
        let mut buf = [0u8; 16];
        core::arch::asm!(
            "sgdt [{buf}]",
            buf = in(reg) buf.as_mut_ptr(),
            options(nostack),
        );
        limit = u16::from_le_bytes([buf[0], buf[1]]);
        base = u64::from_le_bytes([
            buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
        ]);
    }
//     // // // crate::kprintln!("[GDT-DBG] GDTR: limit=0x{:x} base=0x{:x}", limit, base)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
    // Walk the GDT entries. Each entry is 8 bytes (16 if it's a
    // TSS descriptor; we report every 8-byte slot as a single
    // entry for simplicity).
    let num_entries = (limit as usize + 1) / 8;
    for i in 0..num_entries {
        let entry_addr = unsafe { (base as *const u64).add(i) };
        let lo: u64 = unsafe { core::ptr::read_unaligned(entry_addr) };
        let hi: u64 = unsafe { core::ptr::read_unaligned(entry_addr.add(1)) };
        let access = (lo >> 40) & 0xFF;
        let flags = (lo >> 52) & 0x0F;
        let present = (access & 0x80) != 0;
        let dpl = (access >> 5) & 0x3;
        let is_code_or_data = present && (access & 0x10) != 0;
        if present && is_code_or_data {
            // kprintln disabled (memcpy crash workaround)
            let _ = (i, access, flags, dpl, hi);
        }
    }
}

/// Install the supplied per-CPU GDT on the *current* CPU and load
/// the TR with the TSS descriptor at selector `TSS_SEL`. After this
/// returns, the calling AP is using its own GDT/TSS pair and is
/// ready to receive IPIs.
pub fn ap_install(gdt: &PerCpuGdt) {
    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of::<PerCpuGdt>() - 1) as u16,
        base: gdt as *const PerCpuGdt as u64,
    };
    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            // Reload the data segment registers. CS stays
            // cached; everything else must be reloaded from
            // the new GDT.
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            // Load the TR with the TSS descriptor. ltr wants
            // a 16-bit register operand.
            "ltr cx",
            ptr = in(reg) &gdt_ptr,
            in("ax") KERNEL_DS,
            in("cx") TSS_SEL,
            options(nostack, preserves_flags),
        );
    }
}
