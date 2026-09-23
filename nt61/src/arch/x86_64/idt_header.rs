//! Interrupt Descriptor Table (IDT)
//!
//! 256-entry IDT for the x86_64 exception and interrupt vectors.
//! The first 32 are CPU-defined exceptions; the rest are user-
//! defined IRQ handlers, dispatched through the APIC or the legacy
//! 8259 PIC.
//!
//! Each entry uses the `GateDescriptor` format (16 bytes): handler
//! address, segment selector (always `KERNEL_CS`), IST field, type
//! and DPL, plus the upper 32 bits of the handler address.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};
use core::arch::asm;
