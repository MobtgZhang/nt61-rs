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

pub mod gpu_common;
pub mod vram;
pub mod irq;
pub mod dpc;
pub mod power;

// MMIO guard with bounds checking and spinlock synchronization
pub mod mmio_guard;

pub use gpu_common::*;
pub use vram::*;
pub use irq::*;
pub use dpc::*;
pub use power::*;
pub use mmio_guard::*;
