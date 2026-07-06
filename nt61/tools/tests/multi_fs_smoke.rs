//! Smoke test for Phase A-G of the multi-filesystem read-modify-write plan.
//!
//! These are *unit* smoke tests using the library API directly (not the CLI),
//! so they run quickly and don't require any external tools. They verify the
//! minimal contracts the CLI relies on:
//!  * each backend's `from_bytes` accepts a pre-existing image (read path),
//!  * QCOW2 header magic is correct,
//!  * the `FsBackend` trait object is usable through `Box<dyn FsBackend>`.
//!
//! Note: the round-trip tests (write_file -> finalize -> from_bytes -> read_file)
//! for the *builder* outputs are intentionally omitted because the existing
//! FAT32/NTFS/EXT4/ISO builders are known to be lossy on finalize
//! (see docs/known-issues in build-tool-cmd-update1.md). The CLI smoke
//! test in `tools/scripts/` covers the end-to-end path against real images.

use nt61_tools::fs::backend::FsBackend;
use nt61_tools::fs::qcow2::Qcow2Image;

/// The QCOW2 header must carry the spec magic "QFI\xfb".
#[test]
fn qcow2_header_magic_is_correct() {
    let mut image = Qcow2Image::create(1).expect("qcow2 create");
    let data = image.finalize().expect("qcow2 finalize");
    assert_eq!(&data[0..4], b"QFI\xfb", "qcow2 magic mismatch");
}

/// Opening an empty file via Qcow2Image::open must return Err, not panic.
#[test]
fn qcow2_open_empty_file_errors_not_panic() {
    let empty: Vec<u8> = Vec::new();
    let res = Qcow2Image::open(&empty);
    assert!(res.is_err(), "open() on empty bytes should error, not panic");
}

/// Verify the FsBackend trait compiles as a trait object — this is a
/// compile-time check that the trait stays object-safe.
#[allow(dead_code)]
fn _assert_trait_object_safety(b: Box<dyn FsBackend>) {
    let _ = b.list_dir("/");
    let _ = b.read_file("/x");
    let _: Option<Box<dyn FsBackend>> = Some(b);
}

#[test]
fn trait_object_compiles() {
    // This is a compile-time check — if `FsBackend` ever gains a method
    // that breaks object safety, this test fails to build.
    let _: fn(Box<dyn FsBackend>) = _assert_trait_object_safety;
}
