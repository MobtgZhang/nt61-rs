//! Memory Descriptor List (MDL) support.
//!
//! The canonical NT MDL is owned by the I/O transfer module because it
//! participates in DIRECT I/O, probing, and system-address mapping. Re-export
//! it here so MM callers use the same NT-compatible structure instead of a
//! parallel, incomplete definition.

pub use crate::io::transfer::{
    allocate_mdl, free_mdl, get_system_address_for_mdl, map_locked_pages, probe_and_lock_pages,
    unlock_pages, unmap_locked_pages, Mdl,
};
