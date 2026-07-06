//! RISC-V Binary Translation Layer (BTL) — module root.
//!
//! Translates x86/x86-64 guest code (Windows PE/COFF or user-mode
//! ELF) into RISC-V instructions at runtime, similar in spirit to
//! Windows 11's WoW64 on ARM64. The translation pipeline:
//!
//! ```text
//!   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
//!   │ Decode  │ →  │ IR /   │ →  │ Codegen │ →  │ Code   │
//!   │ (x86)   │    │ Semantic│    │ (RV64)  │    │ Cache  │
//!   └─────────┘    └─────────┘    └─────────┘    └─────────┘
//!        ↑                                           │
//!        └────────────────  patch  ─────────────────┘
//! ```
//!
//! ## Architecture
//!
//! * Sub-modules are isolated so they can be tested independently
//!   when QEMU emulation is not available.
//! * Translation is *ahead-of-time* per basic block (no trace
//!   scheduling yet); we re-translate on self-modifying code via
//!   a 3-stage cache (hot/warm/cold).
//! * Syscalls are routed through [`syscall_glue`] which decides
//!   between native (rv64 kernel) and emulated NT calls based on
//!   the guest descriptor. The NT call mapping mirrors the one used
//!   by Windows ARM64 WoW64 (`xtajit64.dll`, `wowarm64.dll`).
//!
//! ## Files
//!
//! | File              | Purpose                                |
//! |-------------------|----------------------------------------|
//! | `mod.rs`          | this file                              |
//! | `decoder.rs`      | x86 instruction decoder                |
//! | `translator.rs`   | IR + lowering to RV64                  |
//! | `codegen.rs`      | RV64 encoder                           |
//! | `cache.rs`        | basic-block cache                      |
//! | `mem.rs`          | guest memory model                     |
//! | `exception.rs`    | fault → re-translation hooks           |
//! | `syscall_glue.rs` | NT call dispatch from guest ECALLs     |
//!
//! ## Limits
//!
//! Phase 4 ships scaffolding only. Phase 5 wires the runtime and
//! Phase 6 adds performance counters and self-modifying code
//! detection.

#![cfg(feature = "btl")]

pub mod cache;
pub mod codegen;
pub mod decoder;
pub mod exception;
pub mod mem;
pub mod perf;
pub mod runtime;
pub mod syscall_glue;
pub mod translator;

/// Kernel-mode entry point. Brings the BTL's subsystems online
/// in dependency order. Called by [`crate::arch::riscv64::init`].
pub fn init() {
    mem::init();
    cache::init();
    translator::init();
    codegen::init();
    decoder::init();
    runtime::init();
    syscall_glue::init();
    perf::init();
    exception::init();
}

/// Smoke test — Phase 4 ships a no-op validator that returns
/// `true` for every platform.
pub fn smoke_test() -> bool { true }