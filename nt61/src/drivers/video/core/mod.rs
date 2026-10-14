//! GPU Core Shared Infrastructure
//
//! This module provides the shared infrastructure for all GPU drivers:
//
//! - `gpu_common` - GPU device traits, PCI discovery, vendor IDs
//! - `vram` - VRAM memory management
//! - `irq` - GPU interrupt handling
//! - `dpc` - Deferred Procedure Calls
//! - `power` - Power management

extern crate alloc;

pub mod dpc;
pub mod gpu_common;
pub mod irq;
pub mod power;
pub mod vram;

// MMIO guard with bounds checking and spinlock synchronization
pub mod mmio_guard;

pub use dpc::*;
pub use gpu_common::*;
pub use irq::*;
pub use mmio_guard::*;
pub use power::*;
pub use vram::*;
