//! Build script for `nt61-boot`.
//
//! Resolves the TTF font paths to embed into the boot manager binary
//! and copies the selected files into `OUT_DIR` so that
//! `font_ttf.rs` can `include_bytes!(env!("NT61_BOOT_FONT_REGULAR_PATH"))`
//! them at compile time. This avoids hardcoding a path inside the
//! source — the user can override the font at build time.
//
//! Resolution order (first non-empty wins):
//
//! 1. `NT61_BOOT_FONT_REGULAR` / `NT61_BOOT_FONT_BOLD` — paths to
//!    individual TTF files, absolute or relative to `CARGO_MANIFEST_DIR`.
//! 2. `NT61_BOOT_FONT_DIR` — a directory containing
//!    `OpenSans-Regular.ttf` and `OpenSans-Bold.ttf`.
//! 3. The default tree at `$CARGO_MANIFEST_DIR/../../resources/fonts/open-sans/`,
//!    relative to the manifest (`nt61/src/boot/Cargo.toml` → `nt61/resources/fonts/open-sans/`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../resources/fonts/open-sans/OpenSans-Regular.ttf");
    println!("cargo:rerun-if-changed=../../resources/fonts/open-sans/OpenSans-Bold.ttf");
    println!("cargo:rerun-if-env-changed=NT61_BOOT_FONT_REGULAR");
    println!("cargo:rerun-if-env-changed=NT61_BOOT_FONT_BOLD");
    println!("cargo:rerun-if-env-changed=NT61_BOOT_FONT_DIR");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo"));
    let out_dir = PathBuf::from(env::var("OUT_DIR")
        .expect("OUT_DIR is set by cargo"));

    let default_regular = manifest_dir
        .join("..")
        .join("..")
        .join("resources")
        .join("fonts")
        .join("open-sans")
        .join("OpenSans-Regular.ttf");
    let default_bold = manifest_dir
        .join("..")
        .join("..")
        .join("resources")
        .join("fonts")
        .join("open-sans")
        .join("OpenSans-Bold.ttf");

    let regular_src = resolve_font(
        "NT61_BOOT_FONT_REGULAR",
        "NT61_BOOT_FONT_DIR",
        "OpenSans-Regular.ttf",
        &default_regular,
    );
    let bold_src = resolve_font(
        "NT61_BOOT_FONT_BOLD",
        "NT61_BOOT_FONT_DIR",
        "OpenSans-Bold.ttf",
        &default_bold,
    );

    let regular_out = out_dir.join("OpenSans-Regular.ttf");
    let bold_out = out_dir.join("OpenSans-Bold.ttf");

    copy_into(&regular_src, &regular_out, "OpenSans-Regular.ttf");
    copy_into(&bold_src, &bold_out, "OpenSans-Bold.ttf");

    println!("cargo:rustc-env=NT61_BOOT_FONT_REGULAR_PATH={}",
        regular_out.display());
    println!("cargo:rustc-env=NT61_BOOT_FONT_BOLD_PATH={}",
        bold_out.display());
}

/// Resolve a font path from the environment.
///
/// - If `single_env` is set, use it (relative paths are taken from
///   `CARGO_MANIFEST_DIR`).
/// - Otherwise, look inside the directory given by `dir_env` for a
///   file named `default_name`.
/// - Otherwise, fall back to `default_path`.
fn resolve_font(single_env: &str, dir_env: &str, default_name: &str,
                default_path: &Path) -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo"));

    if let Ok(p) = env::var(single_env) {
        let p = PathBuf::from(p);
        let resolved = if p.is_absolute() {
            p
        } else {
            manifest_dir.join(p)
        };
        if !resolved.exists() {
            panic!("{} points to {} but that file does not exist",
                single_env, resolved.display());
        }
        return resolved;
    }

    if let Ok(dir) = env::var(dir_env) {
        let dir = PathBuf::from(dir);
        let resolved = if dir.is_absolute() {
            dir.join(default_name)
        } else {
            manifest_dir.join(dir).join(default_name)
        };
        if resolved.exists() {
            return resolved;
        }
        // If the env var is set but the file is missing, fall through
        // to the default rather than panicking — the user might have
        // been experimenting.
        eprintln!("warning: {} is set but {} not found, falling back",
            dir_env, resolved.display());
    }

    if !default_path.exists() {
        panic!("default font not found at {}", default_path.display());
    }
    default_path.to_path_buf()
}

fn copy_into(src: &Path, dst: &Path, name: &str) {
    let bytes = fs::read(src).unwrap_or_else(|e| {
        panic!("failed to read font {} from {}: {}",
            name, src.display(), e)
    });
    fs::write(dst, &bytes).unwrap_or_else(|e| {
        panic!("failed to write font {} to {}: {}",
            name, dst.display(), e)
    });
}
