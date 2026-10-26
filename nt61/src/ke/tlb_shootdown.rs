//! Cross-core TLB shootdown.
//!
//! A page-table change (COW copy, protection downgrade, unmap) is only
//! complete once every CPU that may hold a stale translation has
//! dropped it. A local `invlpg` / `tlbi VAE1` leaves the other cores'
//! TLBs untouched, so on SMP a thread on another core can keep writing
//! through an old writable (or reading a removed) mapping after the
//! PTE was rewritten.
//!
//! ## Protocol
//!
//! The kernel uses a generation-counter protocol, which needs no
//! per-IPI payload and is immune to a delayed IPI being credited to
//! the wrong shootdown:
//!
//! 1. The shooting CPU takes `SHOOTDOWN_LOCK` (senders are serialized,
//!    so at most one generation is in flight) and bumps `GENERATION`.
//! 2. It performs its own local flush, then asks the architecture to
//!    interrupt every other online CPU.
//! 3. Each target CPU services the interrupt with a *full* local TLB
//!    flush and publishes its per-CPU progress: `DONE[cpu] = GENERATION`.
//!    A full flush (rather than a per-VA flush) means a CPU that
//!    services generation N implicitly also drops everything older.
//! 4. The shooter waits until every remote CPU reports `DONE >= gen`,
//!    with a bounded spin so a CPU stuck with interrupts disabled
//!    cannot deadlock the shooter.
//! 5. A CPU that services the IPI late (or never) is caught by the
//!    lazy fallback: every timer tick, a CPU whose `DONE[cpu] <`
//!    `GENERATION` performs the flush itself. This bounds staleness
//!    for a CPU that was inside a critical section when the IPI
//!    arrived.
//!
//! Single-CPU systems short-circuit: the local flush is the whole
//! job, no IPI is sent.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ke::sync::Spinlock;

/// Maximum CPUs tracked for shootdown acknowledgement. Matches
/// `arch::common::percpu::MAX_PER_CPU`.
const MAX_SHOOTDOWN_CPUS: usize = 64;

/// Serialises senders. Only one generation may be in flight at a
/// time; two concurrent senders with different flush requirements
/// would otherwise race on the remote acknowledgement accounting.
static SHOOTDOWN_LOCK: Spinlock<()> = Spinlock::new(());

/// Current shootdown generation. Bumped by the sender while holding
/// `SHOOTDOWN_LOCK`, read by targets to publish their progress.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Highest generation each CPU has fully flushed. Indexed by the
/// per-CPU id (`percpu::get_current_cpu_id()`), which is stable for
/// the life of a CPU.
static DONE: [AtomicU64; MAX_SHOOTDOWN_CPUS] = [const { AtomicU64::new(0) }; MAX_SHOOTDOWN_CPUS];

/// How long the sender spins waiting for a remote acknowledgement
/// before falling back to the lazy tick flush. Generous, but bounded
/// so a wedge target cannot hang the shooter forever.
const ACK_SPIN_LIMIT: u64 = 20_000_000;

/// Statistics for diagnostics.
static SHOOTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);

fn this_cpu_index() -> usize {
    let idx = crate::arch::common::percpu::get_current_cpu_id() as usize;
    if idx >= MAX_SHOOTDOWN_CPUS {
        0
    } else {
        idx
    }
}

/// Full local TLB flush plus per-CPU progress publication. This is
/// the body both the IPI handler and the lazy tick fallback run.
fn local_flush_and_publish() {
    crate::arch::flush_tlb();
    let idx = this_cpu_index();
    let gen = GENERATION.load(Ordering::Acquire);
    // Store the observed generation; a late handler may observe a
    // newer generation than the IPI it is servicing, which is fine:
    // a full flush performed now covers every PTE change that
    // preceded this point.
    DONE[idx].fetch_max(gen, Ordering::AcqRel);
}

/// Called from the architecture IPI/SGI handler. Flushes this CPU's
/// TLB and acknowledges the shootdown.
pub fn handle_shootdown_interrupt() {
    local_flush_and_publish();
}

/// Called from the timer tick on every CPU. If this CPU has not yet
/// acknowledged the current generation (e.g. it was inside a
/// critical section when the IPI arrived), catch up now.
pub fn lazy_flush_if_pending() {
    let idx = this_cpu_index();
    if DONE[idx].load(Ordering::Acquire) < GENERATION.load(Ordering::Acquire) {
        local_flush_and_publish();
    }
}

/// Invalidate `va` on every CPU: local entry invalidation plus a
/// cross-core shootdown with acknowledgement.
///
/// Use this at every point where a PTE is rewritten in a way other
/// CPUs could observe stale state: COW PTE replacement, protection
/// downgrades, and unmaps. Plain allocation-time map-ins do not need
/// it (a stale "not present" entry just re-faults).
pub fn invalidate_va_all_cpus(va: u64) {
    // Local entry first: the calling CPU is about to keep running
    // with the new PTE.
    crate::arch::invalidate_tlb(va);

    let cpu_count = crate::arch::common::smp::cpu_count() as usize;
    if cpu_count <= 1 {
        return;
    }

    SHOOTDOWN_LOCK.lock();
    let gen = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    // Publish our target before the IPI goes out so a target that
    // services the interrupt immediately can observe the generation.
    core::sync::atomic::fence(Ordering::SeqCst);
    crate::arch::send_tlb_shootdown_ipi();

    let expected = cpu_count - 1;
    let mut spin = 0u64;
    loop {
        let mut acked = 0;
        for idx in 0..MAX_SHOOTDOWN_CPUS {
            if DONE[idx].load(Ordering::Acquire) >= gen {
                acked += 1;
            }
        }
        // `DONE` starts at zero for every CPU, and the local CPU has
        // already published via the IPI path or will publish through
        // `lazy_flush_if_pending`; count the CPUs that reached `gen`.
        if acked >= cpu_count {
            SHOOTDOWN_COUNT.fetch_add(1, Ordering::Relaxed);
            return;
        }
        spin += 1;
        if spin >= ACK_SPIN_LIMIT {
            TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
            // One or more CPUs are still behind. Do not spin forever:
            // their next timer tick runs `lazy_flush_if_pending` and
            // completes the flush. Bounded staleness beats a hang.
            return;
        }
        core::hint::spin_loop();
    }
}

/// Diagnostics: (successful shootdowns, senders that timed out).
pub fn stats() -> (u64, u64) {
    (
        SHOOTDOWN_COUNT.load(Ordering::Relaxed),
        TIMEOUT_COUNT.load(Ordering::Relaxed),
    )
}
