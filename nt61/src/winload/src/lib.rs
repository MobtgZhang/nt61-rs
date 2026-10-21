//! winload library crate.
//!
//! All implementation lives in `main.rs` (the UEFI binary entry point)
//! and the per-arch modules under `arch/`. This stub exists so that
//! `Cargo.toml`'s `[[bin]] path = "src/main.rs"` can coexist with the
//! loader's target-specific dependency configuration. Without an
//! empty `#![no_std]` lib here, cargo treats this package as `std`
//! by default and bare-metal targets refuse the build.
//
// Permitted under MIT. See repository LICENSE.

#![no_std]
