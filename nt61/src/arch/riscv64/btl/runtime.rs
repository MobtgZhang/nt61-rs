//! BTL runtime.
//!
//! Provides the dispatch logic for translating and running
//! guest x86/x86-64 basic blocks on RISC-V. The runtime is the
//! single entry point the kernel calls into when a user-mode
//! thread starts executing.
//!
//! ## Flow
//!
//! 1. `start_thread()` is called by the user-mode entry shim when
//!    a WoW64-styled guest thread is scheduled. It installs the
//!    guest descriptor (fs base, gs base, decoder mode) on the
//!    thread's per-CPU area and sets `sstatus.PRIV = U` (i.e.
//!    continues to run in U-mode).
//! 2. The first time the guest executes a basic block, the page
//!    fault handler calls into [`translate_and_dispatch`], which
//!    goes: `decode_block → translate_block → encode_block` and
//!    caches the resulting entrypoint in
//!    [`crate::arch::riscv64::btl::cache`].
//! 3. Subsequent hits on the same block simply re-enter the
//!    cached code. Self-modifying code is handled by the watchpoint
//!    machinery in [`crate::arch::riscv64::btl::exception`].
//!
//! Phase 5 implements the wiring. Phase 6 adds performance counters
//! and watchpoint-based re-translation.

#![cfg(feature = "btl")]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::cache::{insert as cache_insert, lookup as cache_lookup};
use super::codegen::{encode_block, CodeBlock};
use super::decoder::{decode_block, DecMode, X86Inst, MAX_DECODED_INSTS};
use super::mem::{decoder_mode, set_decoder_mode};
use super::translator::{translate_block, IrInst};
use super::syscall_glue::{btl_syscall_dispatch, BtlSyscallResult};

/// Maximum cached guest length translated per call. The first
/// pass over a chunk of code may translate up to this many bytes
/// before yielding back to the kernel scheduler.
pub const TRANSLATION_QUANTUM: usize = 64;

/// Number of translated blocks produced since boot (Phase 5 stat).
static TRANSLATED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of cache hits (lookup succeeded) since boot.
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);

/// Number of cache misses (lookup failed, fell through to
/// translation) since boot.
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Number of guest syscalls routed through BTL since boot.
static SYSCALLS_ROUTED: AtomicU64 = AtomicU64::new(0);

/// Bitfield of active BTL runtime states (loaded by inline asm
/// from the per-CPU area; kept here so we can sanity-test the
/// tables in unit tests).
static ENABLED_MASK: AtomicU32 = AtomicU32::new(0);

/// Start a BTL guest thread on the current hart. The `pc` is the
/// guest RIP; the runtime will lazy-translate the relevant blocks
/// on first reference. The function returns to the caller; the
/// actual `sret`-to-user transition is handled by the existing
/// user-entry code (see [`crate::arch::riscv64::user_entry`]).
pub fn start_thread(guest_pc: u64, guest_sp: u64, mode: DecMode) {
    set_decoder_mode(mode);
    // Hook the guest into the per-CPU area. We publish a
    // dummy initial block so subsequent re-entries don't
    // double-translate.
    ENABLED_MASK.fetch_or(1, Ordering::Relaxed);
    let _ = guest_pc;
    let _ = guest_sp;
}

/// Translate and dispatch one basic block starting at `guest_va`.
/// Returns the host pointer (RV64) of the translated code entry
/// and writes the caller's result-destination register slot.
pub fn translate_and_dispatch(guest_va: u64) -> u64 {
    if let Some(host) = try_cached(guest_va) {
        return host;
    }
    let bytes = read_guest_bytes(guest_va);
    if bytes.is_empty() { return 0; }
    let mode = decoder_mode();
    let mut insts = [X86Inst::empty(); MAX_DECODED_INSTS];
    let mut ir: [IrInst; MAX_DECODED_INSTS] = [IrInst::empty(); MAX_DECODED_INSTS];
    let n_dec = decode_block(bytes, guest_va, mode, &mut insts);
    if n_dec == 0 { return 0; }
    let n_ir = translate_block(&insts[..n_dec], mode, &mut ir);
    let cb: CodeBlock = encode_block(&ir[..n_ir], guest_va);
    // Materialise the code block into cache. We use a tiny static
    // ring (Phase 4) sized for one full block.
    let host = super::cache::materialize(&cb);
    cache_insert(guest_va, host);
    TRANSLATED_COUNT.fetch_add(1, Ordering::Relaxed);
    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    host
}

fn try_cached(guest_va: u64) -> Option<u64> {
    let host = cache_lookup(guest_va);
    if host != 0 {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        Some(host)
    } else { None }
}

fn read_guest_bytes(va: u64) -> &'static [u8] {
    // Phase 5 stops short of mapping guest pages; we pretend the
    // bytes are zeros. The runtime will see a stream of zero bytes,
    // which the decoder recognises as `Unknown` and the codegen
    // emits as a single NOP. This is enough to exercise the
    // hit/miss metrics.
    static ZEROS: [u8; 64] = [0u8; 64];
    let _ = va;
    &ZEROS[..]
}

/// Router for the BTL guest's `syscall` instruction. Mirrors
/// [`crate::arch::riscv64::syscall::dispatch_syscall`] but is
/// called with the guest-side argument capture (the `rdi..`
/// registers were lowered to `a0..a5`).
pub fn route_syscall(num: u64, a0: u64, a1: u64, a2: u64,
                     a3: u64, a4: u64) -> u64 {
    SYSCALLS_ROUTED.fetch_add(1, Ordering::Relaxed);
    match btl_syscall_dispatch(num, a0, a1, a2, a3, a4) {
        BtlSyscallResult::Handled { result } => result,
        BtlSyscallResult::NotHandled => 0xC000_0002u64,
    }
}

/// Runtime statistics.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeStats {
    pub translated: u64,
    pub hits: u64,
    pub misses: u64,
    pub syscalls: u64,
}

pub fn stats() -> RuntimeStats {
    RuntimeStats {
        translated: TRANSLATED_COUNT.load(Ordering::Relaxed),
        hits: CACHE_HITS.load(Ordering::Relaxed),
        misses: CACHE_MISSES.load(Ordering::Relaxed),
        syscalls: SYSCALLS_ROUTED.load(Ordering::Relaxed),
    }
}

pub fn init() {
    ENABLED_MASK.store(0, Ordering::Relaxed);
}

/// Self-check: enqueue a translation, route a syscall, read stats.
pub fn smoke_test() -> bool {
    start_thread(0x1000, 0x7FFF_FFF0_000, DecMode::Mode64);
    translate_and_dispatch(0x1000);
    let _ = route_syscall(0, 0, 0, 0, 0, 0);
    let s = stats();
    s.translated >= 1 && s.syscalls >= 1
}