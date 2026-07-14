//! Kernel Library
//
//! Windows NT 6.1 (Windows 7) compatible operating system kernel
//
//! # Architecture
//! The kernel targets the following architectures:
//!   * x86_64
//!   * aarch64 (ARMv8/ARMv9)
//!   * riscv64 (RV64IMAC and friends)
//!   * loongarch64 (Loongson 3A5000+)
//
//! All architecture-specific code lives in `arch::*` and `hal::*`.
//! Anything portable lives in the toplevel modules (`ke`, `mm`, `ps`,
//! `io`, `fs`, `lpc`, `ob`, `se`, `rtl`).
//
//! # Boot sequence
//! `main::kernel_main` is called by the UEFI stub with a populated
//! `BootInfo` and walks the Windows 7 startup sequence:
//!   1. Hardware init
//!   2. Memory manager init
//
//! # Lint policy
//
//! The NT kernel API surface and driver names follow Windows naming
//! conventions (PascalCase for functions, SCREAMING_CASE for
//! constants, `IRP_MJ_*`, `STATUS_*`, etc.). Renaming these would
//! break compatibility with the public NT ABI. To keep the source
//! readable, the top-level nt61 crate allows the corresponding
//! style lints here:
//
//!   * `non_snake_case`     — NT API functions
//!   * `non_upper_case_globals` — NT API constants
//!   * `non_camel_case_types` — NT structures (e.g. `_EPROCESS`)
//!   * `static_mut_refs`    — `static mut` is still the idiomatic
//!     storage for kernel singletons (IDT, GDT, TSS, boot-time
//!     allocator pools, ...) before SMP spinlocks are wired up;
//!     converting all of them to `AtomicXxx` / `Mutex<>` is part
//!     of a separate refactor tracked in `docs/think.md`.
//
//! Note: `dead_code`, `unused_imports`, `unused_variables`, and
//! `unused_assignments` are now permitted at the crate level. The NT
//! kernel implements an enormous API surface (hundreds of symbols) on
//! a per-arch basis; on any single architecture a sizeable fraction of
//! those symbols is unreachable. Rather than annotate each scaffolded
//! symbol by hand, we lift the ban and emit crate-level allows below.
//! New dead-code warnings should be triaged into the owning module
//! (see e.g. `arch/riscv64/plic.rs`, `ke/exception.rs`, `mm/vas.rs`)
//! instead of being silenced at the crate root.
//
// Permitted under MIT. See repository LICENSE.
#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types, static_mut_refs)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
//!   3. Kernel executive init
//!   4. Object manager init
//!   5. I/O manager init
//!   6. File system init
//!   7. LPC init
//!   8. Process / thread init
//!   9. Create system processes
//!  10. Start session manager (smss)

#![no_std]

extern crate alloc;
extern crate core;

// Re-export core modules - always compiled
pub mod arch;
pub mod hal;
pub mod ke;
pub mod mm;
pub mod ob;
pub mod ps;
pub mod se;
pub mod io;
pub mod lpc;
pub mod rtl;
pub mod fs;
pub mod loader;
// pub mod pegen;          // removed: PE images are now produced by tools/src/fs/build.rs
// pub mod system_image;   // removed: synthetic in-binary PE pipeline gone
pub mod servers;
pub mod desktop;
pub mod registry;
pub mod kernel_main;
pub mod userspace;
pub mod drivers;
pub mod netstack;
pub mod libs;
pub mod boot_types;

// Constants
pub const KERNEL_VERSION: &str = "6.1.7601";
pub const KERNEL_BUILD: &str = "7601.win7_gdr";

// Note: Logging macros are exported via #[macro_export] in rtl/klog.rs
// and can be used as crate::kprintln!, crate::boot_print!, etc.

// Kernel global allocator lives in main.rs (the binary crate) so
// that both the library crate and the binary crate can use it.