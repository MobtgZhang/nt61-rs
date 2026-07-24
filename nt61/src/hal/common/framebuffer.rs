//! Architecture-agnostic framebuffer support.
//!
//! The actual pixel writer is the cross-arch `framebuffer_impl`
//! module. On x86_64 we keep the historic name (`init_from_bootinfo`
//! returning the info) for backwards-compat with the existing call
//! sites; on the other architectures the same shared implementation
//! is exposed through the same public API.

pub use crate::hal::common::framebuffer_impl::*;
