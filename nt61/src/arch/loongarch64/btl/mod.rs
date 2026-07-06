//! Binary Translation Layer (BTL) — directory layout.
//!
//! The BTL lets the LoongArch kernel run x86 (32-bit and 64-bit) binaries
//! without leaving Ring 3. When a thread starts executing an x86 binary,
//! `btl::dispatch` walks translation-cache entries and falls back to the
//! decoder/emitter when a cache miss occurs.
//!
//! Modules:
//!   * `common` — shared helpers (instr-table lookup, bitfield macros).
//!   * `cpu`    — x86 CPU state, register file, flags helpers.
//!   * `decoder`— x86 instruction decoder (32-bit and 64-bit).
//!   * `emit`   — LoongArch instruction emitter.
//!   * `translate` — x86→LA64 instruction translation rules.
//!   * `cache`  — translation cache (TC) management.
//!   * `syscall`— NT/Win32 system call bridging.
//!   * `tests`  — unit tests for the translation rules.
//!
//! References:
//!   * WoW64 internals (geoffchappell.com)
//!   * QEMU TCG (QEMU docs/TCG.html)
//!   * DynamoRIO / DynamoSem
//!   * LoongArch Reference Manual

#![cfg(target_arch = "loongarch64")]

pub mod common;
pub mod cpu;
pub mod cache;
pub mod decoder;
pub mod emit;
pub mod syscall;
pub mod translate;

/// Boot-time initialisation hook for the BTL. Wires up the syscall
/// bridge and translation-cache allocator.
pub fn init() {
    common::init();
    cache::init();
    syscall::init();
    // decoder / translate / emit are pure code modules; their
    // tables are `const`, so no extra runtime wiring is required.
}

pub use cache::{TranslationCache, TranslationCacheEntry};
pub use cpu::{GuestRegs, GuestFlags};
pub use translate::{TranslateError, translate_block, translate_instruction};
