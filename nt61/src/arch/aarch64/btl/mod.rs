//! AArch64 Binary Translation Layer (BTL).
//!
//! Provides the framework for translating non-native binaries
//! (currently x86_64, with AArch32 planned) into AArch64 code that
//! the kernel can execute directly.
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────┐
//!  │                       AArch64 NT6.1.7601 kernel                   │
//!  │                                                                  │
//!  │   ┌──────────────────────────┐   ┌──────────────────────────┐   │
//!  │   │   Translation Manager    │   │      Code Cache          │   │
//!  │   │   - load region          │   │   - WX memory            │   │
//!  │   │   - hot-spot detection   │   │   - hash table           │   │
//!  │   └──────────────────────────┘   └──────────────────────────┘   │
//!  │   ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐   │
//!  │   │  Decoder     │→│      IR      │→│   CodeGen (AArch64)   │   │
//!  │   │ (x86_64/A32) │ │              │ │  - reg allocate       │   │
//!  │   └──────────────┘ └──────────────┘ └──────────────────────┘   │
//!  │   ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐   │
//!  │   │   State      │ │  Exceptions  │ │    Syscall bridge     │   │
//!  │   │   (regs)     │ │  (signals)   │ │   (x86 → NT ARM64)    │   │
//!  │   └──────────────┘ └──────────────┘ └──────────────────────┘   │
//!  └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Submodule layout
//!
//! * `mod.rs` (this file) — public API and configuration
//! * `translation_manager.rs` — top-level translation manager
//! * `code_cache.rs`           — WX memory region + hash table
//! * `decoder`                 — x86_64/AArch32 instruction decoder
//! * `ir`                      — Intermediate Representation
//! * `codegen`                 — AArch64 code generation
//! * `state`                   — Translated-state management
//! * `syscall_bridge`          — NT / Win32 syscall bridging
//!
//! ## Current status
//!
//! The shared x86_64 decoder and per-architecture code generators are fully wired.
//! The first usable translation path (simple x86_64 arithmetic and
//! control flow into AArch64) is gated behind `cfg(feature = "btl")`.

pub mod code_cache;
pub mod translation_manager;

pub use crate::arch::common::btl::abi::{normalize_syscall_args, GuestAbi};
pub use crate::arch::common::btl::exec::{
    execute_block, GuestState, SyscallHook,
};
pub use crate::arch::common::btl::memory::{GuestAddressSpace, GuestMemory};

#[cfg(feature = "btl")]
pub mod codegen;
#[cfg(feature = "btl")]
pub mod decoder;
#[cfg(feature = "btl")]
pub mod ir;
#[cfg(feature = "btl")]
pub mod state;
#[cfg(any(feature = "btl", test))]
pub mod syscall_bridge;

pub use code_cache::{CodeCache, TranslationUnit};
pub use translation_manager::{TranslationManager, TranslationRequest};

/// Initialise the BTL subsystem. Currently a no-op; the code cache
/// and translation manager are self-contained statics.
pub fn init() {}

/// Feature bits reported by the BTL interface.
pub const BTL_FEATURE_X86_64_TRANSLATION: u32 = 1 << 0;
pub const BTL_FEATURE_SYSCALL_BRIDGE: u32 = 1 << 1;
pub const BTL_FEATURE_ARM32_TRANSLATION: u32 = 1 << 2;

/// BTL feature flag shared with `Cargo.toml`.
///
/// x86_64 translation and the shared NT syscall bridge are enabled;
/// ARM32 translation remains off until its ABI is fully modelled.
pub const BTL_FEATURES: u32 = BTL_FEATURE_X86_64_TRANSLATION
    | BTL_FEATURE_SYSCALL_BRIDGE;

/// Compile-time gate for the BTL subsystem. Set `feature = "btl"`
/// to enable the heavy components (decoder, IR, codegen). Until
/// then the BTL API is exposed but some entry points may return Unsupported
/// that returns `BtlError::Disabled`.
pub const ENABLED: bool = cfg!(feature = "btl");

/// BTL errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtlError {
    /// `feature = "btl"` is off; the call is a no-op.
    Disabled = -1,
    /// Architecture not yet supported (e.g. ARM32).
    UnsupportedArch = -2,
    /// Decoder ran past the end of the source buffer.
    OutOfBounds = -3,
    /// Invalid instruction encoding.
    InvalidInstruction = -4,
    /// Code cache full; cannot allocate a new translation unit.
    CacheFull = -5,
    /// Disassembly produced an instruction we cannot translate.
    Untranslatable = -6,
    /// Resource exhaustion (memory pool exhausted).
    OutOfMemory = -7,
}

pub type BtlResult<T> = Result<T, BtlError>;

/// Smoke test: verify the BTL is wired up and reachable.
pub fn smoke_test() -> bool {
    code_cache::smoke_test() && translation_manager::smoke_test()
}
