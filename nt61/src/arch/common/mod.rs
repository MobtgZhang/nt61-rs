//! Architecture-common code shared by all ISA targets.
//
//! This module contains canonical structures and interfaces that are
//! shared across all supported architectures (x86_64, aarch64, riscv64,
//! loongarch64). Architecture-specific implementations live in the
//! respective `arch/*/` directories.

pub mod percpu;
pub mod paging;
pub mod user_entry;
pub mod smp;
pub mod trap_frame;
