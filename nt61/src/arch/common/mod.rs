//! Architecture-common code shared by all ISA targets.
//
//! This module contains canonical structures and interfaces that are
//! shared across all supported architectures (x86_64, aarch64, riscv64,
//! loongarch64). Architecture-specific implementations live in the
//! respective `arch/*/` directories.

pub mod btl;
pub mod cmd_host;
pub mod counter;
pub mod device_tree;
pub mod hardware_exception;
pub mod line_edit;
pub mod machine;
pub mod paging;
#[cfg(all(not(test), feature = "binary_panic"))]
pub mod panic;
pub mod percpu;
pub mod self_map;
pub mod smp;
pub mod syscall_frame;
pub mod trap_frame;
pub mod user_entry;
pub mod user_memory;
pub mod user_syscall;
