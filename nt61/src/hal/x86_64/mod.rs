//! x86_64 Hardware Abstraction Layer
//
//! x86_64-specific hardware interfaces.
//
//! This module is the *user-facing* HAL surface: every function
//! that maps to a `hal.dll` export lives here, plus an
//! `init()` orchestrator that drives the bootstrap in the same
//! order the Windows 6.1 kernel does. The actual hardware
//! drivers live in `arch::x86_64`; the HAL just composes them
//! and exposes the documented API.
//
//! # Module map
//
//! | Module             | Public surface                                           |
//! |--------------------|----------------------------------------------------------|
//! | [serial]           | UART I/O (`init`, `write_char`, `write_string`)          |
//! | [pic]              | 8259A PIC + `HalEnable/DisableSystemInterrupt`           |
//! | [apic]             | LAPIC / I/O APIC + IPIs                                  |
//! | [pit]              | 8253/8254 PIT + `HalMakeBeep`                            |
//! | [hpet]             | HPET + `HalQueryPerformanceCounter/Frequency`            |
//! | [keyboard]         | 8042 PS/2 + scancode decode + `HalDisplayString`         |
//! | [framebuffer]      | LFB / VGA text + bugcheck screen                         |
//! | [text_console]     | 80×25 VGA text console + `gui_print!` / `gui_println!`   |
//! | [io_port]          | `READ_PORT_*` / `WRITE_PORT_*` inline helpers            |
//! | [cmos]             | CMOS RTC + `HalQueryRealTimeClock/SetRealTimeClock`      |
//! | [dma]              | 8237 DMA + `HalGetAdapter/AllocateCommonBuffer`          |
//! | [halt]             | `HalReturnToFirmware` + reboot / shutdown paths         |
//
//! # Public init API
//
//! The Windows 6.1 `hal.dll` exposes a `HalInitSystem(LoaderBlock)`
//! entry point called by the OS Loader after the kernel and
//! `hal.dll` are mapped. We mirror that signature here so
//! `winload` and the bare-metal stub can both call it.

pub mod apic;
pub mod pic;
pub mod pit;
pub mod hpet;
pub mod keyboard;
pub mod keyboard_unified;
pub mod framebuffer;
pub mod text_console;
pub mod serial;
pub mod io_port;
pub mod cmos;
pub mod dma;
pub mod halt;

pub mod console {
// //! Simple console output

    /// VGA text mode console
    pub const VGA_WIDTH: usize = 80;
    pub const VGA_HEIGHT: usize = 25;

    /// VGA color
    #[derive(Debug, Clone, Copy)]
    pub enum Color {
        Black = 0,
        Blue = 1,
        Green = 2,
        Cyan = 3,
        Red = 4,
        Magenta = 5,
        Brown = 6,
        LightGray = 7,
        DarkGray = 8,
        LightBlue = 9,
        LightGreen = 10,
        LightCyan = 11,
        LightRed = 12,
        Pink = 13,
        Yellow = 14,
        White = 15,
    }

    /// Console character
    #[derive(Debug, Clone, Copy)]
    pub struct ConsoleChar {
        pub character: u8,
        pub color: u8,
    }

    /// Print character
    pub fn put_char(_c: char) {
        // Print to console
    }

    /// Print string
    pub fn puts(_s: &str) {
        // Print to console
    }
}

use core::sync::atomic::{AtomicBool, Ordering};

static HAL_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HAL_ARCH_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HAL_SERIAL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Mark the BSP arch layer as having already been initialised.
/// Called by `arch::x86_64::init_hardware()` so the HAL knows not
/// to redo the BSP's setup of the PIC, PIT, APIC, HPET, and
/// keyboard controller.
pub fn mark_arch_initialized() {
    HAL_ARCH_INITIALIZED.store(true, Ordering::Release);
    HAL_SERIAL_INITIALIZED.store(true, Ordering::Release);
}

/// Mark the serial port as initialised (called from
/// `hal::x86_64::serial::init`).
pub fn mark_serial_initialized() {
    HAL_SERIAL_INITIALIZED.store(true, Ordering::Release);
}

/// Bootstrap init. Idempotent — every call after the first is a
/// no-op. This matches the Windows 6.1 `hal.dll` behaviour
/// where `HalInitSystem` may be called more than once.
///
/// # Important
///
/// When this function is called from `kernel_main` *after*
/// `arch::x86_64::init_hardware()` has run, the BSP's PIC, PIT,
/// HPET, keyboard, and LAPIC are already configured. Calling
/// the corresponding hal initialisers a second time would (a)
/// remask the PIC and break the keyboard's IRQ1, (b) remap the
/// LAPIC page and conflict with the arch layer's virtual
/// mapping, and (c) rewrite the PIT divisor while the legacy
/// timer is still in use.
///
/// We therefore probe the `HAL_ARCH_INITIALIZED` flag and skip
/// the hardware-touching steps when the arch layer has already
/// done the work. The HAL still *exposes* the corresponding
/// functions (so user code can call `pic::unmask_irq` etc.)
/// even if `init` did not configure them — the underlying
/// hardware state is the arch layer's responsibility.
pub fn init() {
    if HAL_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Serial port: cheap to repeat, but skip if already done to
    // avoid touching UART divisor registers that the arch
    // layer's console output path depends on.
    if !HAL_SERIAL_INITIALIZED.load(Ordering::Acquire) {
        serial::init();
        HAL_SERIAL_INITIALIZED.store(true, Ordering::Release);
    }

    // The remaining steps are only safe in a clean-slate
    // environment (e.g. when `HalInitSystem` is invoked from
    // winload on a freshly built image, before the kernel's
    // arch bootstrap has run). In the bare-metal stub path
    // `arch::x86_64::init_hardware()` is the one that owns
    // these devices, so we skip and let the arch layer's
    // configuration stand.
    if !HAL_ARCH_INITIALIZED.load(Ordering::Acquire) {
        // 1. The 8259A PIC: remap, mask, ready for vectored IRQs.
        let _ = pic::i8259_init();

        // 2. The LAPIC: software-enable, spurious vector 0xFF.
        let _ = apic::init();

        // 3. The PIT: 100 Hz default rate generator on channel 0.
        let _ = pit::init(100);

        // 4. The HPET: probe the ACPI table if one was registered.
        if let Some(hpet_phys) = find_hpet_phys() {
            let _ = hpet::init(hpet_phys);
        }

        // 5. The 8042 keyboard controller.
        keyboard::init();

        // 6. Framebuffer: only fall back to the VGA text-mode
        //    buffer if no LFB has been published yet. The kernel
        //    bootstrap calls `framebuffer::init_from_bootinfo()`
        //    from `kernel_main` before `hal::init()`, so by the
        //    time we reach this line the LFB atomics are already
        //    populated. Passing `None` here would silently throw
        //    that LFB away and drop the boot screen back to
        //    80x25 text mode.
        if framebuffer::info().address == 0 {
            framebuffer::init(None);
        }

        // 7. PCI enumeration: side-effect-free, safe to run.
        crate::hal::common::pci::init();

        // 8. ACPI: probe for the RSDP and cache the location so
        // that `find_table` works for the rest of the boot.
        crate::hal::common::acpi::init();
    }
}

/// `HalInitSystem` — the public entry point of the Windows
/// `hal.dll`. `loader_block` is a pointer to the OS Loader's
/// parameter block; we accept it as `*const u8` for type
/// neutrality and ignore it for now (the real `hal.dll` reads
/// the loader block to learn ACPI / I/O APIC base addresses).
///
/// Returns 0 on success, NTSTATUS-style negative values on
/// failure.
pub fn HalInitSystem(_loader_block: *const u8) -> i32 {
    init();
    0
}

/// `HalInitializeProcessor` — per-CPU initialisation called by
/// the kernel when bringing up application processors. We only
/// initialise the BSP today; the AP entry point lives in
/// `arch::x86_64::smp`.
pub fn HalInitializeProcessor(cpu_id: u32, alloc_ist: bool) -> i32 {
    let _ = cpu_id;
    let _ = alloc_ist;
    0
}

/// Look up the HPET table's physical address in the ACPI tables.
/// Returns `None` if the table is missing or the ACPI subsystem
/// has not been initialised.
fn find_hpet_phys() -> Option<u64> {
    let hpet_sig: [u8; 4] = *b"HPET";
    let ptr = crate::hal::common::acpi::find_table(&hpet_sig)?;
    unsafe {
        let header_va = ptr as *const u8;
        // HPET-specific layout: 36 bytes of standard ACPI
        // header, then 4 bytes event_block_id, 8 bytes
        // base_address.
        let lo = core::ptr::read_unaligned(header_va.add(36 + 4) as *const u32);
        let hi = core::ptr::read_unaligned(header_va.add(36 + 8) as *const u32);
        Some(((hi as u64) << 32) | (lo as u64))
    }
}
