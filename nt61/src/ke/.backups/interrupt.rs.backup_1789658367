//! Interrupt Management
//
//! Hardware interrupt handling. On the bootstrap we register a tiny
//! set of IDT vector stubs (the PIC, the IPI range, and the spurious
//! vector) and install the high-level dispatch table the kernel
//! executive uses to route interrupts to ISR / DPC / worker-thread
//! paths. The interrupt controller (PIC / IOAPIC / LAPIC) is
//! configured in `arch::x86_64` and `hal::x86_64`; this module owns
//! the kernel-side *software* view of interrupts.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};


/// Maximum number of IDT vectors the kernel is willing to route.
pub const MAX_IDT_VECTORS: usize = 256;

/// Types of interrupt handlers we can register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerKind {
    /// No handler installed; the default spurious vector fires.
    None,
    /// Standard ISR — runs at IRQL >= DIRQL, must finish quickly and
    /// queue a DPC for any real work.
    Isr,
    /// Interrupt Service Routine wrapper installed by a driver
    /// (`IoConnectInterrupt` analogue).
    ConnectedIsr,
    /// IPI-style handler. Lives in the IPI vector range.
    Ipi,
}

/// Bookkeeping for one IDT vector. We don't store the ISR function
/// pointer here — the architecture layer keeps the real IDT in
/// sync — but we do track the *kernel*'s view: which subsystem
/// owns the vector, how many times it fired, and what kind of
/// handler we expect.
#[derive(Debug, Clone, Copy)]
pub struct VectorInfo {
    pub vector: u8,
    pub kind: HandlerKind,
    pub owner: &'static str,
    pub fire_count: u64,
    pub last_fire_tsc: u64,
}

impl VectorInfo {
    pub const fn empty(vector: u8) -> Self {
        Self {
            vector,
            kind: HandlerKind::None,
            owner: "<unused>",
            fire_count: 0,
            last_fire_tsc: 0,
        }
    }
}

static VECTOR_TABLE: [AtomicU32; MAX_IDT_VECTORS] = {
    // AtomicU32 is not `Copy`, so we have to use `[const { ... }; N]`
    // is not possible without `Default`. We construct it through a
    // function below; this array is only the placeholder.
    [const { AtomicU32::new(0) }; MAX_IDT_VECTORS]
};

/// Per-vector state. We can't put a full `VectorInfo` array in a
/// `static` because of the `&'static str` field, so we keep the
/// `kind`, `owner`, and counters in a parallel structure.
static mut VECTOR_INFO: [VectorInfo; MAX_IDT_VECTORS] = {
    const EMPTY: VectorInfo = VectorInfo::empty(0);
    [EMPTY; MAX_IDT_VECTORS]
};

#[allow(dead_code)]
static mut VECTOR_INFO_INITIALISED: bool = false;

/// Aggregate counters.
static TOTAL_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_INTERRUPTS: AtomicU64 = AtomicU64::new(0);

/// Initialise the interrupt subsystem.
///
/// On the bootstrap the arch layer has already programmed the LAPIC
/// and the 8259 PIC, so we only need to:
///   1. Zero our per-vector bookkeeping.
///   2. Mark the IPI vector range (0xE0..0xEF) as IPI kind, owned
///      by the kernel dispatcher (`ke::dispatch`).
///   3. Mark the clock vector (typically 0x30 on x86_64) as
///      `ConnectedIsr`, owned by the HAL timer.
///   4. Mark the spurious vector 0xFF as `None`.
///
/// The real IDT is owned by `arch::x86_64::idt`; this function only
/// prints the configuration.
pub fn init() {
    crate::hal::serial::write_string("[ke.interrupt] enter\r\n");
    // The static initialiser already zero-fills VECTOR_INFO. We
    // just need to make sure the IPI range and the spurious
    // vector are correctly tagged.
    for v in 0xE0u8..=0xEFu8 {
        if (v as usize) < MAX_IDT_VECTORS {
            register_vector(v, HandlerKind::Ipi, "ke::dispatch");
        }
    }
    register_vector(0xFF, HandlerKind::None, "<spurious>");

    let _ipi_base = 0xE0u8;
    let _ipi_end = 0xEFu8;
    // _ipi_base and _ipi_end are intentionally unused - reserved for future logging
    // // kprintln!("    Interrupt subsystem: IDT ({} vectors) ready", MAX_IDT_VECTORS)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
    // //         "      IPI vectors: 0x{:02x}..0x{:02x} (dispatcher-owned)",
    // //         _ipi_base, _ipi_end
    // //     );
    // // kprintln!("      Spurious vector: 0xFF (masked)")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
    // //         "      Total interrupts observed: {} (spurious: {})",
    // //         TOTAL_INTERRUPTS.load(Ordering::Relaxed),
    // //         SPURIOUS_INTERRUPTS.load(Ordering::Relaxed)
    // //     );
}

/// Register an owner for a vector. Idempotent.
pub fn register_vector(vector: u8, kind: HandlerKind, owner: &'static str) {
    if (vector as usize) >= MAX_IDT_VECTORS {
        return;
    }
    unsafe {
        let info = &mut VECTOR_INFO[vector as usize];
        info.vector = vector;
        info.kind = kind;
        info.owner = owner;
        VECTOR_TABLE[vector as usize].store(kind as u32, Ordering::Release);
    }
}

/// Look up the current owner of `vector`.
pub fn vector_owner(vector: u8) -> Option<(&'static str, HandlerKind)> {
    if (vector as usize) >= MAX_IDT_VECTORS {
        return None;
    }
    unsafe {
        let info = &VECTOR_INFO[vector as usize];
        if info.kind == HandlerKind::None {
            None
        } else {
            Some((info.owner, info.kind))
        }
    }
}

/// Record an interrupt fire. Called by the high-level ISR wrapper
/// (the real one is in `arch::x86_64::idt`, but we expose a
/// software-side hook so the boot-time smoke test can drive it).
pub fn record_fire(vector: u8) {
    if (vector as usize) >= MAX_IDT_VECTORS {
        return;
    }
    TOTAL_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
    if vector == 0xFF {
        SPURIOUS_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    unsafe {
        let info = &mut VECTOR_INFO[vector as usize];
        info.fire_count = info.fire_count.wrapping_add(1);
    }
}

/// Read the global fire counter. Useful for the boot log.
pub fn total_interrupt_count() -> u64 {
    TOTAL_INTERRUPTS.load(Ordering::Relaxed)
}

/// Trigger DPC processing after an interrupt.
/// This should be called at the end of each ISR to request
/// DPC processing at DISPATCH_LEVEL.
pub fn request_dpc() {
    // Use the DPC subsystem's insert function
    if let Some(_idx) = crate::ke::dpc::insert(
        dpc_dummy_routine,
        core::ptr::null_mut(),
        "interrupt_dpc",
    ) {
        // DPC queued successfully
    }
}

fn dpc_dummy_routine(_ctx: *mut u8) {
    // This is a placeholder DPC routine
}

/// Smoke test for the interrupt subsystem.
///
/// * Registers a fake ISR for a test vector (0x80, in the
///   user-interrupt range).
/// * Records a handful of fires.
/// * Verifies that the per-vector counter advanced and the global
///   counter advanced.
/// * Verifies that the spurious vector 0xFF does not bump the per-
///   vector counter (only the spurious counter).
pub fn smoke_test() -> bool {
    let test_vector: u8 = 0x80;
    let owner = "smoke_test";
    register_vector(test_vector, HandlerKind::ConnectedIsr, owner);
    let before = unsafe { VECTOR_INFO[test_vector as usize].fire_count };
    let total_before = total_interrupt_count();
    for _ in 0..5 {
        record_fire(test_vector);
    }
    // A spurious fire must NOT increment the per-vector counter.
    record_fire(0xFF);
    let after = unsafe { VECTOR_INFO[test_vector as usize].fire_count };
    let total_after = total_interrupt_count();
    let spurious_after = SPURIOUS_INTERRUPTS.load(Ordering::Relaxed);
    if after != before + 5 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [INTERRUPT SMOKE FAIL] fire count: before={} after={}",
// //             before, after
// //         );
        return false;
    }
    if total_after != total_before + 6 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [INTERRUPT SMOKE FAIL] total: before={} after={}",
// //             total_before, total_after
// //         );
        return false;
    }
    if spurious_after < 1 {
        // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //             "    [INTERRUPT SMOKE FAIL] spurious counter did not advance: {}",
// //             spurious_after
// //         );
        return false;
    }
    if vector_owner(test_vector) != Some((owner, HandlerKind::ConnectedIsr)) {
        // // kprintln!("    [INTERRUPT SMOKE FAIL] owner mismatch")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
        return false;
    }
    // // kprintln!(  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)
// //         "    [INTERRUPT SMOKE OK] test_vector=0x{:02x} fires={} total={} spurious={}",
// //         test_vector, after, total_after, spurious_after
// //     );
    true
}
