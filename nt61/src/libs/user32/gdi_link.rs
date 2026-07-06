//! user32 → gdi32 forwarders
//
//! The user32 API exposes a handful of GDI calls. The
//! user32 stub just forward-declares them; the actual
//! implementation lives in the `gdi32` module.

extern crate alloc;

use crate::ke::sync::Spinlock;
use alloc::string::String;

/// Symbol table of forwarder names. Each entry maps a
/// user32!Gdi* symbol to its gdi32!Gdi* target.
pub static GDI_LINK: Spinlock<alloc::vec::Vec<(String, String)>> =
    Spinlock::new(alloc::vec::Vec::new());

/// Add a forwarder entry; the smoke test uses this to
/// verify the table is populated.
pub fn add(name: &str, target: &str) {
    GDI_LINK.lock().push((String::from(name), String::from(target)));
}

/// Look up a forwarder; returns `Some(target)` if registered.
pub fn lookup(name: &str) -> Option<String> {
    GDI_LINK.lock().iter().find(|(n, _)| n == name).map(|(_, t)| t.clone())
}
