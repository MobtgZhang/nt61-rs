//! HAL / NTOS export-name registry
//!
//! **As of the winload-to-disk-ntoskrnl handoff refactor** this
//! module is a stub. The export lists previously lived here as a
//! build-time cross-check against `system_image::build_hal` and
//! `system_image::build_ntoskrnl`. Both of those builder functions
//! are gone — `tools/src/fs/build.rs` owns the canonical PE
//! generator now, and its own inline export tables (see
//! `build_ntoskrnl_pe` / `build_hal_pe`) are the single source of
//! truth.
//!
//! The stub below keeps the file in place so anything that still
//! references `hal_export::HAL_EXPORTS` / `NTOS_EXPORTS` /
//! `hal_export_names` / `ntos_export_names` compiles. New code
//! should NOT take a dependency on those constants — they will be
//! removed in a follow-up cleanup.
#![allow(dead_code, unused_imports)]

/// Empty placeholder list. The canonical lists live in
/// `tools/src/fs/build.rs`.
pub const HAL_EXPORTS: &[&str] = &[];

/// Empty placeholder list. See [`HAL_EXPORTS`].
pub const NTOS_EXPORTS: &[&str] = &[];

/// Returns the canonical HAL export list. Currently always empty;
/// kept for source compatibility with older call sites.
pub fn hal_export_names() -> &'static [&'static str] {
    HAL_EXPORTS
}

/// Returns the canonical NTOS export list. Currently always empty;
/// kept for source compatibility with older call sites.
pub fn ntos_export_names() -> &'static [&'static str] {
    NTOS_EXPORTS
}
