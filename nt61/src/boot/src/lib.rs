//! NT6.1.7601 Boot Manager library crate.
//!
//! The actual `efi_main` entry point lives in `main.rs`; this stub
//! library exists so the crate has a library target (Cargo looks
//! for `src/lib.rs` before falling back to `src/main.rs` only for
//! binary-only crates, and the workspace CI checks `cargo build
//! --lib` for the kernel).

#![no_std]