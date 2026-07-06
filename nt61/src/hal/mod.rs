//! Hardware Abstraction Layer
//
//! Provides architecture-independent hardware interfaces
//
//! # Top-level API
//
//! `init()` is the bootstrap entry point. It is called by
//! `kernel_main` during Phase 0 and re-routes to the
//! architecture-specific implementation.
//
//! `hal_init_system(loader_block)` mirrors the Windows 6.1
//! `hal.dll` `HalInitSystem` entry. The OS Loader calls it
//! after the kernel and `hal.dll` are mapped.

pub mod common;
pub mod hal_export;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

// Common HAL submodules
pub mod pit {
    //! Timer interface
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::pit::*;
    #[cfg(not(target_arch = "x86_64"))]
    pub use crate::hal::common::pit::*;
}

pub mod serial {
    //! Serial interface
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::serial::*;
    #[cfg(target_arch = "aarch64")]
    pub use crate::hal::aarch64::serial::*;
    #[cfg(target_arch = "riscv64")]
    pub use crate::hal::riscv64::serial::*;
    // LoongArch64: the canonical serial implementation lives in
    // `crate::arch::loongarch64::serial` (mirrors `crate::hal::loongarch64`
    // for the basic init/write helpers). Re-export from the arch path so
    // the `read_char` / `write_u32_hex` helpers are also visible through
    // the unified `crate::hal::serial` facade.
    #[cfg(target_arch = "loongarch64")]
    pub use crate::arch::loongarch64::serial::*;
}

pub mod io_port {
    //! I/O port interface
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::io_port::*;
    #[cfg(not(target_arch = "x86_64"))]
    pub use crate::hal::common::io_port::*;
}

pub mod framebuffer {
    //! Framebuffer interface
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::framebuffer::*;
    #[cfg(not(target_arch = "x86_64"))]
    pub use crate::hal::common::framebuffer::*;
}

// Architecture-specific HAL submodules. These exist only on x86_64;
// on other architectures the call sites in non-arch modules should
// route through the `arch::*` facade instead. The wrappers here keep
// the unified API discoverable from `crate::hal::*`.
pub mod pic {
    //! 8259A PIC (Programmable Interrupt Controller).
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::pic::*;
}

pub mod cmos {
    //! CMOS / RTC (Real-Time Clock).
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::cmos::*;
}

pub mod hpet {
    //! HPET (High Precision Event Timer).
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::hpet::*;
}

pub mod keyboard {
    //! PS/2 keyboard controller.
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::keyboard::*;
}

pub mod keyboard_unified {
    //! Unified PS/2 + USB-HID ring buffer.
    #[cfg(target_arch = "x86_64")]
    pub use crate::hal::x86_64::keyboard_unified::*;
}

pub mod text_console {
    //! Cross-architecture text console facade.
    //!
    //! The unified interface used by the SafeBootMode CMD shell,
    //! the kernel log view, and the user-facing prompt. On x86_64
    //! this routes to the canonical VGA / bootvid module; on the
    //! other architectures it routes to a serial + log-ring
    //! backend that has the same API.
    pub use crate::hal::common::text_console::*;
}

pub mod keyboard_input {
    //! Cross-architecture polled keyboard input facade.
    //!
    //! SafeBootMode runs with interrupts disabled, so the CMD
    //! shell can't rely on the keyboard ISR. Instead it polls a
    //! backend (PS/2 controller on x86_64, PL011/NS16550A UART on
    //! the other architectures) for new characters. The same
    //! API is used everywhere so the shell code is portable.
    pub use crate::hal::common::keyboard_input::*;
}

/// Initialize HAL — runs the per-architecture `init()` once.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
//         // // // crate::kprintln!("  Initializing x86_64 HAL...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        x86_64::init();
    }

    #[cfg(target_arch = "aarch64")]
    {
        crate::hal::serial::write_string("hal_mod_init:about_to_call_aarch64\r\n");
        aarch64::init();
    }

    #[cfg(target_arch = "riscv64")]
    {
//         // // // crate::kprintln!("  Initializing RISC-V64 HAL...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        riscv64::init();
    }

    #[cfg(target_arch = "loongarch64")]
    {
//         // // // crate::kprintln!("  Initializing LoongArch64 HAL...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);  // kprintln disabled (memcpy crash workaround)
        loongarch64::init();
    }
}

/// `HalInitSystem` — the public `hal.dll` entry point. `loader_block`
/// is a pointer to the OS Loader's parameter block; the value is
/// opaque to us. Returns 0 on success, NTSTATUS-style negative on
/// failure.
pub fn hal_init_system(loader_block: *const u8) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::HalInitSystem(loader_block)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = loader_block;
        crate::hal::aarch64::init();
        0
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = loader_block;
        crate::hal::riscv64::init();
        0
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = loader_block;
        crate::hal::loongarch64::init();
        0
    }
}

/// `HalInitializeProcessor` — per-CPU entry. Returns 0 on success.
pub fn hal_initialize_processor(cpu_id: u32, alloc_ist: bool) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_arch = "x86_64")]
        crate::hal::x86_64::HalInitializeProcessor(cpu_id, alloc_ist)
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        let _ = (cpu_id, alloc_ist);
        0
    }
}

/// Shutdown hardware
pub fn shutdown() {
    // Clean up hardware
}
