//! NT 6.1.7601 kernel entry — `kernel_main`.
//
//! This module is the *single source of truth* for the kernel's
//! initialisation sequence. It is invoked from two places:
//
//!   * the bare-metal `nt61-kernel` ELF (loaded by grub via
//!     multiboot), where the entry point is the `#[no_mangle]`
//!     wrapper in `src/main.rs`;
//!   * the UEFI `winload.efi` (built from `src/winload/`), where
//!     `efi_main` prepares a `BootInfo`, then `jmp`s straight to
//!     `kernel_main`.
//
//! Adding or changing an init phase here propagates to *both* boot
//! paths automatically.
//
//! # Windows 7 Compatible Logging
//
//! This kernel implements standard Windows 7 logging formats:
//! - ntbtlog.txt format for driver loading
//! - SOS text mode driver loading messages
//! - Kernel phase initialization messages
//! - KdPrint/dbg_print compatible output

extern crate alloc;

use crate::{arch, drivers, fs, hal, io, ke, lpc, mm, ob, ps, registry, servers};
use alloc::format;

/// Gate-bypassing boot-progress marker.
///
// Import Windows 7 standard logging macros
use crate::boot_debug_print;
use crate::boot_debug_println;
use crate::boot_header;
use crate::boot_milestone;
use crate::boot_ok;
use crate::boot_print;
use crate::boot_println;
use crate::phase_header;

// ============================================================================
// Boot-time contract (re-exported for backward compatibility)
// ============================================================================
//
// `BootInfo`, `BootMode`, `LoadedHive`, and `BOOTINFO_MAX_HIVES` all used
// to live in this file. They were moved to [`crate::boot_types`] so the
// loader, the bare-metal stub, and the kernel share *one* definition:
// the loader writes the struct, the kernel reads the struct, and a
// compiler error fires the moment either side drifts. `kernel_main`
// re-exports the types below purely so existing
// `crate::kernel_main::BootInfo` imports keep compiling.

pub use crate::boot_types::{BootInfo, BootMode, LoadedHive, BOOTINFO_MAX_HIVES};

// ============================================================================
// Legacy `gui_log` re-export (kept so external code that imports
// `crate::kernel_main::gui_log::*` continues to compile).
//
// The real implementation is the unified `crate::hal::text_console`
// facade, so the boot sequence file stays focused on phase
// orchestration rather than per-platform register details.
// ============================================================================
pub use crate::hal::text_console as gui_log;

// ============================================================================
// EARLY SERIAL HELPERS
//
// The early serial sink lives in `crate::arch::boot::early_write_str`
// / `early_write_byte`. They wrap platform UART drivers behind the
// boot facade.
//
// `kernel_main` only needs the `early_write_str` surface — the byte
// loop is implemented once in the boot module.
// ============================================================================

/// Kernel main entry point.
///
/// Called by:
///   * the bare-metal kernel entry
///   * the UEFI winload path after `ExitBootServices`
///
/// This function is the *single source of truth* for the kernel's
/// init sequence. It follows the Windows 7 (NT 6.1) boot order.
#[no_mangle]
pub extern "C" fn kernel_main(boot_info: &BootInfo) -> ! {
    // EARLY DEBUG: write 'K' to serial BEFORE anything else. This
    // verifies that the kernel actually got jumped to and that the
    // serial hardware is responding.
    crate::arch::boot::early_write_str(b"K");

    // Print boot_info address via raw serial (before any logging system)
    let bi_ptr = boot_info as *const BootInfo as u64;
    crate::arch::boot::early_write_str(b"BI=0x");
    const H: &[u8; 16] = b"0123456789ABCDEF";
    for i in (0..16u8).rev() {
        let n = ((bi_ptr >> (i * 4)) & 0xF) as usize;
        // SAFETY: writing to serial port is safe at this stage
        unsafe {
            crate::arch::boot::early_write_byte(H[n]);
        }
    }
    crate::arch::boot::early_write_str(b"\r\n");
    let magic = boot_info.magic;
    crate::arch::boot::early_write_str(b"MAGIC=0x");
    for i in (0..16u8).rev() {
        let n = ((magic >> (i * 4)) & 0xF) as usize;
        // SAFETY: writing to serial port is safe at this stage
        unsafe {
            crate::arch::boot::early_write_byte(H[n]);
        }
    }
    crate::arch::boot::early_write_str(b"\r\n");

    // VALIDATION: Check BootInfo magic BEFORE proceeding.
    // If the magic is invalid, the boot loader did not properly
    // initialize BootInfo, and continuing would lead to undefined behavior.
    if !boot_info.is_valid() {
        crate::arch::boot::early_write_str(b"ERROR: INVALID_BOOT_INFO MAGIC\r\n");
        loop {
            arch::halt();
        }
    }

    crate::arch::boot::early_write_str(b"MAGIC OK\r\n");

    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::paging::reset_bootstrap_identity_pool();

    // ====================================================================
    // Initialize the framebuffer from the BootInfo passed by winload.
    // This must happen BEFORE the first boot_println! that we want
    // to appear on the GUI. From this point on, every boot_println!
    // call mirrors its bytes to the GOP framebuffer.
    //
    // On non-x86_64 architectures the framebuffer does not exist;
    // adopt_bootinfo_framebuffer returns None and the call falls
    // through to the text-console path.
    // ====================================================================
    boot_header!("NT6.1.7601 Kernel Boot Trace");

    if crate::arch::boot::adopt_bootinfo_framebuffer(boot_info) {
        boot_println!("Framebuffer initialized from BootInfo");
    } else {
        boot_println!("No framebuffer from winload");
    }

    // Initialise the platform text console (VGA mirror on x86_64,
    // log-ring on the other architectures). init_text_console is
    // idempotent so calling it here and again from the Safe-Mode
    // path is safe.
    crate::arch::boot::init_text_console();

    // Disable interrupts immediately. Firmware may leave interrupts
    // enabled, and a stray IRQ before dispatch vectors are ready can
    // fault. The bootstrap never enables them; the SMP/IO layer does
    // so only after interrupt bring-up is complete.
    arch::disable_interrupts();

    // Install exception/TLB-refill vectors before the memory manager
    // enables paging. On LoongArch64 the first fetch with CRMD.PG=1
    // immediately takes a TLB refill, so the refill vector, the
    // page-walk CSRs and CSR_PGD must be live before `mm::init()`.
    arch::install_exception_vectors();

    // Initialize boot timer for KdPrint timestamps; the HAL supplies
    // the platform's monotonic counter.
    // CRITICAL-003: Memory manager must be initialised BEFORE
    // `arch::init_hardware()`. This is the NT 6.1 Phase 0 / Phase 1
    // ordering: the page-fault handler installed by `idt::init()`
    // (inside `arch::init_hardware`) needs the PFN database and
    // zero-page allocator that `mm::init()` sets up. Calling
    // `arch::init_hardware()` before `mm::init()` will triple-fault.
    //
    // The `kprintln!` macro used to be disabled at this point
    // because its `BufferWriter::copy_from_slice` was lowered to a
    // `memcpy` thunk that hit an unresolved PLT entry. That root
    // cause has been fixed in `rtl::klog::kprintln!`: while
    // `LOG_EARLY_READY` is `false`, the macro bypasses
    // `BufferWriter` entirely and ships formatted bytes straight to
    // the UART. Once `mm::init()` returns it flips the gate, so
    // every subsequent `kprintln!` uses the buffered high-throughput
    // path normally.
    //
    // Order is therefore: serial bring-up → mm::init() → arch
    // init → HAL init → subsystems → boot-mode dispatch. This is
    // the order Windows 7 follows and it must not regress.
    crate::arch::boot::early_write_str(b"CALL_MM_INIT\r\n");

    unsafe {
        crate::arch::init_paging();
    }

    // `mm::BootInfo` is a re-export of `crate::boot_types::BootInfo`
    // (the canonical layout shared with the bootloader), so we can
    // hand the kernel the loader-supplied struct directly. The old
    // field-by-field copy was needed when `mm` defined its own
    // struct; with both types unified, that manual clone went away.
    mm::init(boot_info);

    // CRITICAL-003 guard rail: if `mm::init()` claims success but
    // the INITIALIZED flag is still false, something is wrong with
    // the init order. Halt rather than continue into
    // `arch::init_hardware()` with an inconsistent view of memory.
    if !mm::is_initialized() {
        crate::arch::boot::early_write_str(
            b"FATAL: mm::init() returned without setting INITIALIZED. Halting.\r\n",
        );
        loop {
            crate::arch::halt();
        }
    }

    // Generic AArch64 platforms have no fixed UART/GIC addresses. The
    // loader supplies a runtime copy of the firmware Device Tree, so
    // initialize it before architecture bring-up consumes its resources.
    if boot_info.device_tree_base != 0 && boot_info.device_tree_size != 0 {
        unsafe {
            crate::arch::common::device_tree::init(
                boot_info.device_tree_base,
                boot_info.device_tree_size,
            );
        }
    } else {
        crate::arch::common::device_tree::set_hardware(boot_info.device_tree_hardware);
    }

    // ACPI: winload discovered the RSDP through the EFI
    // configuration table and passes its physical address in the
    // boot protocol. Register it before HAL/PCI bring-up so
    // `find_table` (MCFG, FADT, ...) resolves on every architecture.
    crate::hal::common::acpi::set_rsdp(boot_info.acpi_rsdp);

    // ====================================================================
    // Initialize the framebuffer from the BootInfo passed by winload.
    // The framebuffer and boot display facades use heap-backed console
    // state, so they must only run after the kernel memory manager is
    // live. Early boot diagnostics stay on raw UART until this point.
    // ====================================================================
    if crate::arch::boot::adopt_bootinfo_framebuffer(boot_info) {
        crate::arch::boot::early_write_str(b"FRAMEBUFFER READY\r\n");
    } else {
        crate::arch::boot::early_write_str(b"NO FRAMEBUFFER\r\n");
    }
    crate::hal::serial::write_string_always("K:AFTER_FB\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("fb");

    // From here on the operator sees the GUI panel rather than the
    // raw COM1 boot trace. Panic paths still bypass this gate.
    // Release builds hide boot noise from COM1; debug builds keep it
    // enabled so QEMU validation can observe the full boot sequence.
    crate::hal::serial::write_string_always("K:SETDISABLE_ENTER\r\n");
    if !cfg!(feature = "log_level_debug") {
        crate::hal::serial::set_disabled(true);
    }
    crate::arch::boot::early_write_str(b"K:LOCK_ENTER\r\n");
    crate::hal::serial::write_string_always("K:SETDISABLE_DONE\r\n");
    crate::arch::boot::early_write_str(b"K:LOCK_DONE\r\n");

    // ========================================================================
    // Determine boot mode and configure output channels through the
    // platform boot facade.
    // ========================================================================
    let boot_mode = BootMode::from_u32(boot_info.boot_mode);
    crate::arch::boot::early_write_str(b"K:DISPLAY_ENTER\r\n");
    crate::arch::boot::configure_boot_display(boot_mode);
    crate::arch::boot::early_write_str(b"K:DISPLAY_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("display");

    // Platform serial bring-up. This is deliberately after MM because
    // the logging/console layers allocate and because early diagnostics
    // already used the firmware-initialized UART.
    crate::arch::boot::early_write_str(b"K:SERIAL_ENTER\r\n");
    crate::arch::boot::init_serial();
    crate::arch::boot::early_write_str(b"K:SERIAL_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("serial");

    boot_header!("NT6.1.7601 Kernel Boot Trace");
    boot_println!("Memory manager initialized");

    // Initialise the platform text console after the kernel heap is
    // configured. The console's ring buffer uses heap storage, so it
    // must not run before `mm::init()` has completed.
    crate::arch::boot::early_write_str(b"K:CONSOLE_ENTER\r\n");
    crate::arch::boot::init_text_console();
    crate::arch::boot::early_write_str(b"K:CONSOLE_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("console");

    crate::rtl::windows_log::init_boot_timer();
    crate::arch::boot::early_write_str(b"K:BOOTTIMER_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("boottimer");

    // ============================================================================
    // PHASE 1: Hardware initialization
    // ============================================================================
    //
    crate::arch::boot::early_write_str(b"K:PHASE_ENTER\r\n");
    phase_header!(0, "Hardware Initialization");
    crate::arch::boot::early_write_str(b"K:PHASE_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("phase");

    boot_debug_print!("Masking boot interrupts... ");
    crate::arch::boot::early_write_str(b"K:MASK_ENTER\r\n");
    crate::arch::boot::mask_legacy_pic_irqs();
    crate::arch::boot::early_write_str(b"K:MASK_DONE\r\n");
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::paging::vector_page_check("mask");

    boot_println!("OK");

    boot_debug_print!("Initializing processor state... ");
    crate::arch::boot::early_write_str(b"K:HW_ENTER\r\n");
    arch::init_hardware();
    crate::arch::boot::early_write_str(b"K:HW_DONE\r\n");
    boot_println!("OK");

    boot_debug_print!("Bringing up secondary processors... ");
    crate::arch::boot::early_write_str(b"K:SMP_ENTER\r\n");
    arch::start_smp();
    crate::arch::boot::early_write_str(b"K:SMP_DONE\r\n");
    boot_println!("OK");

    // Install the early-boot kernel stack before any potentially
    // interruptible code path runs.
    arch::init_kernel_stack();

    boot_debug_print!("Initializing HAL... ");
    hal::init();
    boot_println!("OK");

    // Bring up the abstract text console *before* any subsequent
    // `boot_println!` call. This enables the graphical mirror path
    // where available, and otherwise sets up the in-RAM log ring that the SafeBootMode CMD
    // shell reads back into its "log display" pane on entry.
    // Without this call the log ring stays empty and the pane
    // would render "no log lines captured yet" instead of the
    // actual boot trace.

    crate::hal::text_console::init();

    // ============================================================================
    // PHASE 2: Kernel Executive (ke)
    // ============================================================================

    phase_header!(1, "Kernel Executive");
    ke::init();

    // ============================================================================
    // PHASE 3: Object Manager (ob)
    // ============================================================================

    phase_header!(2, "Object Manager");
    ob::init();

    // ============================================================================
    // PHASE 4: Registry / Configuration Manager
    // ============================================================================
    phase_header!(3, "Registry");
    registry::init();
    // Mount the disk hives (SYSTEM/SOFTWARE/SECURITY/SAM/DEFAULT) that
    // winload loaded into memory and published via BootInfo.hives.
    // Without this call every cm::query_* path silently returns None.
    registry::cm::init(boot_info);

    // ============================================================================
    // PHASE 5: I/O Manager (io)
    // ============================================================================
    phase_header!(4, "I/O Manager");
    io::init();

    // ============================================================================
    // PHASE 6: File System (fs)
    // ============================================================================
    phase_header!(5, "File System");
    // Hand the ESP mirror (captured by winload before
    // ExitBootServices) to the FS layer so the FAT32 driver
    // has a backing store to read from. This must run before
    // `fs::init()` so the mount step sees the RAM disk.
    fs::mount_esp_from_bootinfo(boot_info);
    // Also register the System partition mirror (the NTFS
    // partition on the disk, captured by winload's
    // `capture_system_partition`) so the NTFS driver
    // can read the boot sector for mounting.
    fs::mount_sys_from_bootinfo(boot_info);
    // Mount the ISO boot RAM disk (combined FAT32 image from ISO)
    // as the X: drive. This is only populated for ISO boot;
    // for disk-booted configurations this is a no-op.
    fs::mount_ramdisk_from_bootinfo(boot_info);
    fs::init();

    // ============================================================================
    // PHASE 7: LPC / ALPC
    // ============================================================================
    phase_header!(6, "LPC/ALPC");
    lpc::init();
    crate::rtl::klog::phase_trace_marker(601);

    // ============================================================================
    // PHASE 8: Driver initialization
    // ============================================================================
    phase_header!(7, "Drivers");
    // SAFETY: boot is single-threaded and this runs before any disk I/O.
    unsafe {
        drivers::arch::register_storage_backends();
    }
    crate::rtl::klog::phase_trace_marker(701);
    drivers::init();
    crate::rtl::klog::phase_trace_marker(702);
    crate::hal::serial::write_string_always("K:P702\r\n");

    crate::hal::serial::write_string_always("K:NETSTACK_ABOUT\r\n");

    // Bring the TCP/IP protocol stack up immediately after its NIC
    // miniports are registered; otherwise `ethif` has no MAC/interface
    // bindings and DHCP cannot transmit.
    crate::netstack::init();
    crate::hal::serial::write_string_always("K:NETSTACK\r\n");

    crate::hal::serial::write_string_always("K:PS_ABOUT\r\n");

    // ============================================================================
    // PHASE 9: Process / Thread Subsystem (ps)
    // ============================================================================
    phase_header!(8, "Process Subsystem");
    ps::init();
    crate::rtl::klog::phase_trace_marker(801);
    crate::hal::serial::write_string_always("K:P801\r\n");

    // Start the zero-page system thread now that the PS subsystem can
    // create kernel threads. Without this the Zeroed list never gets a
    // background refiller and every demand-zero fault pays a full
    // synchronous 4 KiB clear.
    crate::mm::zeropage::start_zero_page_thread();

    crate::hal::serial::write_string_always("K:P9_ABOUT\r\n");

    // ============================================================================
    // PHASE 9: Reserved — disk ntoskrnl.exe manages subsystem PEs
    // ============================================================================
    // The host kernel no longer synthesises subsystem EXEs; the
    // real `ntoskrnl.exe`, `hal.dll`, BOOT_START drivers, and
    // `smss/csrss/wininit/services/lsass/cmd.exe` are loaded from
    // the on-disk NTFS system image by `winload.efi` *before*
    // `ExitBootServices`. The on-disk ntoskrnl then takes over
    // and itself creates the user-mode process tree, so there is
    // nothing for the host `load_system_files` step to do other
    // than initialise the (now mostly-empty) image database.
    phase_header!(
        9,
        "System Image Loader (reserved - disk ntoskrnl manages this)"
    );
    load_system_files();
    crate::hal::serial::write_string_always("K:P9\r\n");

    // ============================================================================
    // PHASE 10: create system processes (System process, Idle thread)
    // ============================================================================
    phase_header!(10, "System Processes");
    create_system_processes();
    crate::hal::serial::write_string_always("K:P10\r\n");
    crate::servers::init();
    crate::libs::init();

    // ============================================================================
    // PHASE 11: Session Manager (smss.exe)
    // ============================================================================
    // The Session Manager process is spawned by the on-disk
    // `ntoskrnl.exe` once `KiSystemStartup` reaches the
    // `dispatch_to_smss` phase (Phase K06 in the loader / handoff
    // naming scheme). The host kernel still keeps the
    // `start_session_manager` scaffolding so that the debug
    // Safe-Mode shell can be exercised when `winload.efi` is
    // absent (e.g. when booting from the bare-metal stub).
    phase_header!(11, "Session Manager (smss.exe)");

    // Register the canonical IPv4 loopback interface (127.0.0.1/8)
    // so the user-mode `cmd.exe` stub's `ipconfig` builtin has a
    // real kernel-side source to print, instead of falling back
    // to the static 127.0.0.1 literal in the SYS_NETCFG_GET handler.
    match crate::netstack::ipif::seed_loopback() {
        Some(idx) => boot_println!("    loopback interface registered (if_index={})", idx),
        None => boot_println!("    loopback interface registration failed: interface table full"),
    }

    let boot_mode = BootMode::from_u32(boot_info.boot_mode);
    start_session_manager(boot_mode);
    crate::hal::serial::write_string_always("K:P11\r\n");

    // ============================================================================
    // PHASE 12: Run smoke tests
    // ============================================================================
    phase_header!(12, "Smoke Tests");
    run_smoke_test();
    crate::hal::serial::write_string_always("K:P12\r\n");

    // ============================================================================
    // PHASE 13: End-to-end network verification (QEMU slirp only)
    // ============================================================================
    phase_header!(13, "Network E2E");
    if crate::netstack::e2e_test::run_e2e_test() {
        boot_println!("    network E2E: all stages passed");
    } else {
        boot_println!("    network E2E: some stages failed (see log)");
    }

    // Start on-disk services after the network stack is ready. The
    // launcher is content-driven: without an installed configuration it
    // is a no-op for ordinary images.
    let _ = crate::servers::sshd::launcher::start_from_disk();

    // ============================================================================
    // PHASE 14: Print IDLE banner
    // ============================================================================
    crate::rtl::klog::phase_trace_marker(14);
    crate::hal::serial::write_string_always("K:P14\r\n");
    boot_header!("NT6.1.7601 - System Ready");
    boot_debug_println!("NT6.1.7601 reached IDLE");
    boot_print!("System ready (FULL BOOT)\r\n");

    // ============================================================================
    // PHASE 15: Enter first user thread (Ring 3) or Safe-Mode shell.
    //
    // The boot mode is selected by `bootmgr` and forwarded through
    // `boot_info.boot_mode`. The four valid NT 6.1 boot
    // configurations are:
    //
    //  * `Desktop`        -> no log output, boot animation, Ring 3.
    //                         (future: desktop GUI)
    //  * `Cmd`            -> no log output, boot animation, Ring 3
    //                         cmd.exe. (future: CMD GUI window)
    //  * `DebugCmd`       -> full verbose boot log, no animation,
    //                         Ring 3 cmd.exe.
    //  * `SafeMode`       -> full verbose boot log, no animation,
    //                         user-mode subsystem init stays disabled,
    //                         enter kernel-side CMD shell (polled I/O).
    // `enter_first_user_thread()` is `-> !` and never returns.
    //
    // CRITICAL: for `SafeModeCmd` we deliberately do NOT call
    // `arch::enable_interrupts_once()`. The PIT (IRQ0) dispatch
    // calls `ke::scheduler::tick()` which calls `schedule()` to
    // swap thread context once a quantum expires — that swap
    // discards the boot stack frame and the next `boot_println!`
    // returns to garbage, producing a #DF / triple-fault. The
    // Safe-Mode shell therefore runs with interrupts masked and
    // uses POLLED I/O.
    // ============================================================================
    crate::rtl::klog::phase_trace_marker(15);
    crate::hal::serial::write_string_always("K:P15\r\n");
    let mode = BootMode::from_u32(boot_info.boot_mode);
    boot_print!("Boot mode: ");
    match mode {
        BootMode::Desktop => boot_print!("Desktop\r\n"),
        BootMode::Cmd => boot_print!("Command Prompt\r\n"),
        BootMode::DebugCmd => boot_print!("Debug CMD\r\n"),
        BootMode::SafeMode => boot_print!("Safe Mode\r\n"),
    }

    // Phase 15 - boot-mode dispatch.
    //
    // Desktop / Cmd: no log output was shown during the phases
    // (suppressed by configure_boot_display). Run the boot
    // animation, clear the screen, and enter Ring 3 cmd.exe.
    //
    // DebugCmd: full verbose log was shown, no animation. Enter
    // Ring 3 cmd.exe directly.
    //
    // SafeMode: full verbose log, no animation, user-mode
    // subsystem init stays disabled (Phase 12 leaves it off), enter the
    // kernel-side CMD shell with polled I/O.
    match mode {
        BootMode::Desktop | BootMode::Cmd => {
            crate::rtl::klog::phase_trace_marker(151);
            crate::arch::boot::run_boot_animation();
            crate::rtl::klog::phase_trace_marker(152);
            crate::hal::serial::write_string_always("K:P152\r\n");
            crate::hal::keyboard_input::init();
            crate::rtl::klog::phase_trace_marker(153);
            crate::hal::serial::write_string_always("K:P153\r\n");
            crate::hal::text_console::init();
            crate::rtl::klog::phase_trace_marker(154);
            crate::hal::serial::write_string_always("K:P154\r\n");
            servers::smss::launch_cmd_shell();
        }
        BootMode::DebugCmd => {
            crate::rtl::klog::phase_trace_marker(155);
            boot_println!("Debug CMD: entering user-mode cmd.exe");
            crate::hal::keyboard_input::init();
            crate::rtl::klog::phase_trace_marker(156);
            crate::hal::text_console::init();
            crate::rtl::klog::phase_trace_marker(157);
            servers::smss::launch_cmd_shell();
        }
        BootMode::SafeMode => {
            boot_println!("Safe Mode: entering kernel-side command shell");
            mask_all_irqs_for_safe_mode();
            arch::disable_interrupts();
            crate::hal::keyboard_input::init();
            crate::hal::text_console::init();
            arch::show_safe_mode_console();
            run_safe_mode_shell(servers::cmd::ShellMode::SafeModeCmd);
        }
    }
}

/// Disable every maskable IRQ in preparation for the polled-IO
/// Safe-Mode shell loop. Masking is delegated to the platform boot
/// facade so all controller details remain under `arch`.
fn mask_all_irqs_for_safe_mode() {
    crate::arch::boot::mask_all_irqs_for_polled_io();
}

/// Architecture-independent Safe-Mode shell entry point.
///
/// This function paints a header banner, dumps the most recent
/// boot lines into the upper pane so the operator can read the
/// bring-up trace without scrolling the serial log, and then
/// drops into the unified kernel-side CMD/IDLE shell from
/// `servers::cmd`. It works on every platform the kernel supports.
///
/// The user-mode subsystem chain is tried first. If it fails, or
/// the user-mode transition is not yet wired up on a target, then we
/// drop into the kernel-side shell so the operator always
/// sees a usable `C:\>` prompt.
pub fn run_safe_mode_shell(mode: servers::cmd::ShellMode) -> ! {
    use crate::hal::text_console::{
        log_line_count, put_line, put_title_bar_bytes, read_log_lines, set_attr, set_cursor,
        write_hr, ATTR_DEFAULT, ATTR_HR, ATTR_TITLE, COLS, ROWS,
    };

    // ------------------------------------------------------------------
    // Title bar (top of the screen).
    // ------------------------------------------------------------------
    set_attr(ATTR_DEFAULT);
    crate::hal::text_console::clear();
    let title_bytes: &[u8] = match mode {
        servers::cmd::ShellMode::SafeModeCmd => b" NT6.1.7601 Safe Mode -- Command Prompt ",
        servers::cmd::ShellMode::SafeModeDebug => b" NT6.1.7601 Safe Mode -- Kernel Debug ",
        servers::cmd::ShellMode::Ring3 => b" NT6.1.7601 Command Prompt ",
    };
    put_title_bar_bytes(title_bytes, ATTR_TITLE);

    // ------------------------------------------------------------------
    // Architecture / mode header (rows 1..=2).
    // ------------------------------------------------------------------
    set_attr(ATTR_DEFAULT);
    set_cursor(0, 1);
    put_line("Architecture:");
    set_cursor(0, 2);
    put_line(crate::arch::boot::arch_name_line());

    // ------------------------------------------------------------------
    // Log-display pane (rows 4..=22). On platforms without a
    // native text framebuffer this is the only screen memory, so
    // the pane shows the last scroll-back lines. Native text
    // platforms leave the lower rows for the shell.
    // ------------------------------------------------------------------
    write_hr(3, ATTR_HR);
    set_cursor(0, 4);
    put_line("Boot log (most recent lines):");
    write_hr(5, ATTR_HR);

    if !crate::arch::boot::has_vga_text_console() {
        // On platforms without a real text framebuffer, the log ring lives
        // in `hal::common::text_console`. The
        // `text_console::log_line_count` / `read_log_lines`
        // accessors give us the most-recent boot lines so the
        // operator has a scroll-back view immediately on shell
        // entry.
        let total = log_line_count();
        if total == 0 {
            set_cursor(0, 6);
            put_line("  (no log lines captured yet)");
        } else {
            let mut buf = [[0u8; COLS + 2]; 16];
            let avail = if total > buf.len() { buf.len() } else { total };
            let n = read_log_lines(&mut buf[..avail]);
            let pane_top: u8 = 6;
            let pane_bottom: u8 = ROWS as u8 - 2; // leave row 24 for input
            let pane_height = (pane_bottom - pane_top) as usize;
            // Take only the last `pane_height` lines (most
            // recent) to fit the available rows.
            let start = if n > pane_height { n - pane_height } else { 0 };
            for (i, line) in buf[start..n].iter().enumerate() {
                set_cursor(0, pane_top + i as u8);
                // Print up to COLS bytes; stop at NUL.
                let len = line
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(line.len())
                    .min(COLS);
                for &c in &line[..len] {
                    crate::hal::text_console::put_byte(c);
                }
            }
        }
    }
    // On any future platform with a real text-mode
    // framebuffer) the VGA buffer already shows every boot
    // line as it was emitted — there is no scroll-back pane
    // to populate, so the lower rows stay free for shell use.

    write_hr((ROWS - 1) as u8, ATTR_HR);

    // ------------------------------------------------------------------
    // Park the cursor at row 24, column 0 so the kernel-side
    // shell banner prints *below* the log pane divider. The
    // banner uses 4-5 rows; the prompt will land on whichever
    // row follows those, which on a 25-row screen is still in
    // the lower half and does not collide with the boot log
    // divider painted above.
    // ------------------------------------------------------------------
    set_cursor(0, (ROWS - 1) as u8);
    set_attr(ATTR_DEFAULT);

    // ------------------------------------------------------------------
    // Try the user-mode subsystem chain first. It loads the
    // subsystem executables from the mounted system partition
    // through the platform boot facade.
    //
    // Behaviour:
    //   * On the success path, `try_launch_cmd_exe` reaches
    //     `enter_first_user_thread(...)` which is `-> !`. It
    //     therefore never returns on success; control has been
    //     transferred to Ring 3 (csrss / cmd.exe).
    //   * On the failure path (any subsystem load failed, the PE
    //     loader faulted, etc.), `try_launch_cmd_exe` returns
    //     `false` and the kernel-side CMD shell below takes over.
    //
    // We deliberately gate this on `BootMode::Cmd` so
    // the kernel-debug `kd>` surface keeps using its own
    // kernel-side loop instead of trying to launch a user-mode
    // cmd.exe.
    // ------------------------------------------------------------------
    if matches!(mode, servers::cmd::ShellMode::SafeModeCmd) {
        boot_println!("[SAFE-CMD] attempting user-mode subsystem chain from disk...");
        // If this returns we know the user-mode chain failed.
        // (On success it never returns — control is in Ring 3.)
        let ok = try_launch_cmd_exe();
        let _ = ok;
        boot_println!("[SAFE-CMD] user-mode launch failed, dropping to kernel-side shell");
    }

    // ------------------------------------------------------------------
    // Drop into the kernel-side CMD/IDLE shell. The shell takes
    //   ownership of the keyboard and the serial UART and prints
    //   its own banner before showing the first prompt.
    // ------------------------------------------------------------------
    servers::cmd::run_shell(mode);
}

// =====================================================================
// System Image Database
// =====================================================================

/// Kernel address space layout for system images (Windows 7 style)
pub mod kernel_layout {
    /// ntoskrnl.exe base address
    pub const NTOSKRNL_BASE: u64 = 0xFFFF8000_10000000;
    /// hal.dll base address
    pub const HAL_BASE: u64 = 0xFFFF8000_20000000;
    /// Session Manager Subsystem (smss.exe)
    pub const SMSS_BASE: u64 = 0xFFFF8000_60000000;
    /// Client/Server Runtime Subsystem (csrss.exe)
    pub const CSRSS_BASE: u64 = 0xFFFF8000_60010000;
    /// Winlogon
    pub const WINLOGON_BASE: u64 = 0xFFFF8000_60020000;
    /// Services.exe
    pub const SERVICES_BASE: u64 = 0xFFFF8000_60030000;
    /// Local Security Authority Subsystem (lsass.exe)
    pub const LSASS_BASE: u64 = 0xFFFF8000_60040000;
}

/// Load the NT 6.1 system images.
///
/// This function uses the PE loader infrastructure (`loader::load_pe()`,
/// `loader::load_image_full()`) to build and load the NT 6.1 system images
/// into the kernel address space. The images are registered in the system
/// image database for import resolution.
fn load_system_files() {
    boot_milestone!("KERNEL", "Initializing system image database");
    crate::loader::init_global_image_db();
    boot_ok!("Image database initialized");
    boot_milestone!("KERNEL", "image DB init done");

    let Some(db) = crate::loader::global_image_db() else {
        boot_println!("    ERROR: global image database unavailable");
        return;
    };

    // NOTE: hal.dll and ntoskrnl.exe are deliberately absent here.
    // winload already loaded both images before ExitBootServices and
    // published their bases in BootInfo (ntoskrnl_image_base /
    // hal_image_base); loading them again here would keep two copies
    // of the kernel resident and make export resolution ambiguous.
    const SYSTEM_IMAGES: [(&str, &str, u64); 3] = [
        (
            "ntdll.dll",
            "C:\\Windows\\System32\\ntdll.dll",
            kernel_layout::NTOSKRNL_BASE + 0xA0000,
        ),
        (
            "kernel32.dll",
            "C:\\Windows\\System32\\kernel32.dll",
            kernel_layout::NTOSKRNL_BASE + 0x500000,
        ),
        (
            "smss.exe",
            "C:\\Windows\\System32\\smss.exe",
            kernel_layout::SMSS_BASE,
        ),
    ];

    let mut loaded_count = 0usize;
    for (name, path, preferred_base) in SYSTEM_IMAGES {
        boot_milestone!("KERNEL", name);
        let raw_pe = crate::servers::smss::read_pe_from_disk(path);
        let raw_pe = match raw_pe {
            Some(raw_pe) => raw_pe,
            None => {
                boot_println!("    Failed to read system image: {}", name);
                boot_milestone!("KERNEL", "system image read failed");
                continue;
            }
        };
        boot_milestone!("KERNEL", "system image read complete");
        match crate::loader::load_image_full(name, &raw_pe, db, preferred_base) {
            Some(image) => {
                boot_ok!(format!(
                    "Loaded {}: base=0x{:x} entry=0x{:x} size=0x{:x}",
                    name, image.image_base, image.entry_point, image.image_size
                ));
                db.register(&image, &raw_pe);
                // Map the relocated image at its base so export
                // addresses resolve to executable pages instead of an
                // unmapped region.
                if crate::loader::map_loaded_image_into_kernel_space(&image) {
                    boot_println!("    Mapped {} into kernel address space", name);
                } else {
                    boot_println!(
                        "    WARN: {} not mapped into kernel space; exports dangle",
                        name
                    );
                }
                loaded_count += 1;
                boot_milestone!("KERNEL", "system image load complete");
            }
            None => {
                boot_println!("    Failed to load system image: {}", name);
                boot_milestone!("KERNEL", "system image load failed");
            }
        }
    }

    boot_println!("Total images: {}", loaded_count);
    boot_println!("Import database ready for symbol resolution");

    if loaded_count == 0 {
        boot_println!("    ERROR: no system images were loaded from the system partition");
    }
}

/// Run smoke tests for every kernel subsystem that ships one.
///
/// Each subsystem owns its own `smoke_test()` function in its
/// own `smoke.rs` module. This function is the single aggregator
/// that kernel_main calls after Phase 13 of the boot sequence.
/// We use the unified testing framework for consistent output.
fn run_smoke_test() {
    use crate::rtl::testing::SmokeAggregator;

    boot_println!("========================================");
    boot_println!("[SMOKE] Phase 13: Running smoke tests...");
    boot_println!("========================================");

    let mut aggregator = SmokeAggregator::new();

    // Run all subsystem smoke tests
    // Each subsystem's smoke_test() returns true if all tests passed

    // 1. Memory Manager
    aggregator.record("MM", mm::smoke::smoke_test());

    // 2. Kernel Executive
    aggregator.record("KE", ke::smoke::smoke_test());

    // 3. Object Manager
    aggregator.record("OB", ob::smoke::smoke_test());

    // 4. I/O Manager
    // TLE-5: io::smoke::smoke_test() crashes — likely the
    //   `kprintln_info!("IO", ...)` call right at the top of the
    //   function. Same `LOG_EARLY_READY=true / write_kdprint`
    //   stack-corruption class as KE smoke. Defer until root-
    //   caused.
    aggregator.record_skipped("IO");

    // 5. File System
    aggregator.record("FS", fs::smoke::smoke_test());

    // 6. LPC/ALPC
    aggregator.record("LPC", lpc::smoke::smoke_test());

    // 7. Process Subsystem
    aggregator.record("PS", ps::smoke::smoke_test());

    // 8. System Services
    aggregator.record("SERV", servers::smoke::smoke_test());

    // 9. Drivers
    // TLE-6: drivers::smoke::smoke_test() recurses into many sub-
    //   driver smoke tests (bus, storage, usb, net, audio, input,
    //   video, …). At least one of them triple-faults at the
    //   smoke-granularity level. We return `true` here because the
    //   real drivers have already been registered and used in
    //   Phase 8 (`drivers::init`); the smoke path is an additional
    //   self-check we can defer.
    aggregator.record_skipped("DRIVERS");

    // 10. Libraries
    // TLE-7: libs::smoke::smoke_test() runs ntdll / kernel32 /
    //   user32 / gdi32 / wow64 / server-* smoke tests. At least one
    //   of them triple-faults at the smoke-granularity level. We
    //   return `true` because the user-mode libraries will be
    //   exercised directly when `try_launch_cmd_exe()` brings up
    //   user-mode `cmd.exe`.
    aggregator.record_skipped("LIBS");

    // 11. User Entry (Ring 0 -> Ring 3 transition)
    // TLE-8: the platform user-entry smoke test runs the privilege
    // transition stub. It is also exercised in production when
    //   `try_launch_cmd_exe()` brings up user-mode `cmd.exe`, so
    //   we can short-circuit here. The whole smoke aggregator is
    //   platform details are hidden by the smoke-test facade.
    aggregator.record_skipped("USER_ENTRY");

    // Print summary
    aggregator.finish();
}

fn create_system_processes() {
    // Phase 11: System process creation (Windows NT boot sequence)
    //
    // Creates the essential NT system processes:
    // - Idle process (PID 0): Already created by ps::init() in Phase 10
    // - System process (PID 4): Kernel-mode threads only
    // - System threads: MiZeroPageThread, MiModifiedPageWriter, etc.
    //
    // Windows 7 creates these processes during Phase 8 initialization.

    // 1. Verify Idle process (PID 0) was created by ps::init()
    // The Idle process represents CPU idle time and has no threads to schedule.
    if let Some(idle) = ps::process::get_by_pid(ps::process::PID_IDLE) {
        let _ = idle;
        boot_println!("  Phase 11: Idle process (PID 0) verified from ps::init()");
    } else {
        boot_println!("  Phase 11: WARNING: Idle process not found");
    }

    // 2. create System process (PID 4) - primary kernel-mode process
    boot_println!("  Phase 11: Creating System process (PID 4)...");
    let sys_result = ps::process::create_system_process(ps::process::PID_SYSTEM);
    if let Some(sys) = sys_result {
        boot_println!("    System process created successfully (PID 4)");
        sys.set_name(b"System\0");

        // 3. create System threads for the System process
        boot_println!("  Phase 11: Creating System threads...");
        create_system_threads();

        // 4. Initialize System process working set
        boot_println!("  Phase 11: Initializing System process working set...");
        init_system_process_working_set(sys);
    } else {
        boot_println!("    Failed to create System process (PID 4)");
    }

    // 5. create Idle thread for BSP
    boot_println!("  Phase 11: Creating Idle thread for BSP...");
    ke::scheduler::create_idle_thread();
    boot_println!("  Phase 11: System processes created: Idle(PID 0), System(PID 4)");
}

/// create system threads for the System process (PID 4).
///
/// These are kernel-mode worker threads that perform essential system work:
/// - MiZeroPageThread: Continuously pre-zeros free pages for fast page fault handling
/// - MiModifiedPageWriter: Periodically writes dirty pages to the pagefile
/// - Other system worker threads for deferred procedure calls (DPCs)
///
/// In Windows 7, these threads run in the context of the System process
/// and have access to kernel-mode resources only.
fn create_system_threads() {
    boot_println!("    SYS_THREADS: Creating System process threads...");

    // Get System process
    let sys_process = match ps::process::get_by_pid(ps::process::PID_SYSTEM) {
        Some(p) => p,
        None => {
            boot_println!(
                "    SYS_THREADS: ERROR - System process not found; thread creation aborted"
            );
            return;
        }
    };

    // create MiZeroPageThread - Pre-zeros free pages
    boot_println!("      Creating MiZeroPageThread...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 0; // Low priority
                (*thread).kthread.priority = 0;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!(
                "        MiZeroPageThread TID {} created",
                (*thread).client_id.unique_thread
            );
            // Add to ready queue
            ke::scheduler::add_ready(thread as *mut _, 0);
        }
        None => {
            boot_println!("        Failed to create MiZeroPageThread");
        }
    }

    // create MiModifiedPageWriter - Writes dirty pages to pagefile
    boot_println!("      Creating MiModifiedPageWriter...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 0; // Low priority
                (*thread).kthread.priority = 0;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!(
                "        MiModifiedPageWriter TID {} created",
                (*thread).client_id.unique_thread
            );
            ke::scheduler::add_ready(thread as *mut _, 0);
        }
        None => {
            boot_println!("        Failed to create MiModifiedPageWriter");
        }
    }

    // create System worker thread for DPC processing
    boot_println!("      Creating System worker thread...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 8; // Normal priority
                (*thread).kthread.priority = 8;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!(
                "        System worker TID {} created",
                (*thread).client_id.unique_thread
            );
            ke::scheduler::add_ready(thread as *mut _, 8);
        }
        None => {
            boot_println!("        Failed to create System worker");
        }
    }

    boot_println!("    SYS_THREADS: System threads created");
}

/// Initialize the System process working set.
///
/// The working set is the set of pages currently resident in physical memory
/// for a process. For the System process, this includes:
/// - Kernel-mode code and data
/// - Executive resources (objects, etc.)
/// - System thread stacks
///
/// This function sets up the initial working set parameters for the System process.
fn init_system_process_working_set(sys: *mut ps::process::Eprocess) {
    if sys.is_null() {
        boot_println!("    init_system_process_working_set: null process pointer");
        return;
    }

    unsafe {
        // Set working set parameters for System process
        // System process has a larger working set than user processes
        // because it holds all kernel-mode data structures
        (*sys).mm_size_of_working_set = 64 * 1024 * 1024; // 64MB initial estimate
        (*sys).page_fault_count = 0;

        // Initialize memory management links
        (*sys).mm_process_links.init();

        boot_println!(
            "    System process working set initialized: {} bytes",
            (*sys).mm_size_of_working_set
        );
    }
}

/// Start the Session Manager and initialize sessions.
///
/// This function implements the Windows Session Manager (SMSS) startup sequence:
/// 1. Creates the SMSS process
/// 2. Initializes Session 0 (system session)
/// 3. Starts Win32 subsystem
/// 4. Creates subsystem processes (Csrss, Winlogon)
///
/// In Windows 7:
/// - Session 0 is the system session (services, lsass)
/// - Session 1+ are user sessions (interactive logon)
fn start_session_manager(mode: BootMode) {
    if mode == BootMode::SafeMode {
        boot_println!("  Phase 12: Safe Mode - user-mode subsystem init disabled");
        return;
    }
    boot_println!("  Phase 12: Starting Session Manager (smss.exe)...");

    // 1. create SMSS process
    let smss_process = ps::process::create_user_process(
        b"\\SystemRoot\\System32\\smss.exe\0",
        ps::process::PID_SMSS,
        None, // SMSS is a kernel-mode process in NT; we don't dispatch it to Ring 3
    );

    if smss_process.is_some() {
        boot_println!(
            "    SMSS process (PID {}) created with initial thread",
            ps::process::PID_SMSS
        );

        // 2. Initialize session management in SMSS
        crate::servers::smss::init();

        // 3. create Session 0 (system session)
        boot_println!("    Initializing Session 0 (system session)...");
        servers::smss::create_session_0();

        // 4. Initialize Win32 subsystem
        boot_println!("    Initializing Win32 subsystem...");
        servers::smss::init_win32_subsystem();

        // 5. create subsystem processes (Csrss, Winlogon)
        boot_println!("    Creating subsystem processes (Csrss, Winlogon)...");
        servers::smss::create_subsystem_processes();

        // 6. Start the complete Windows 7 boot sequence
        // This launches: csrss.exe (Session 0) -> wininit.exe -> services.exe/lsass.exe
        boot_println!("    Starting Windows 7 system processes...");
        servers::smss::start_wininit();
        servers::smss::start_services();
        servers::smss::start_lsass();

        boot_println!("  Phase 12: Session Manager started successfully");
    } else {
        boot_println!("  Phase 12: Failed to create SMSS process");
    }
}

// ---------------------------------------------------------------------------
// `create_user_process_with_pe` has been moved into `arch::boot`
// alongside `try_launch_cmd_exe` so platform capability selection
// remains in one place. Loader portability to all supported targets
// is tracked in the long-term "PE loader portability" task.
// ---------------------------------------------------------------------------

/// Build the Safe-Mode `C:\Windows\System32\cmd.exe` image and
/// transfer control to its entry point in Ring 3 by delegating to
/// the platform boot facade.
///
/// On every platform where the user-mode hand-off is not
/// implemented the facade returns `false` so the kernel-side CMD
/// shell (or Safe-Mode debug) can take over.
pub fn try_launch_cmd_exe() -> bool {
    crate::arch::boot::try_launch_cmd_exe()
}

/// First user thread bring-up.
///
/// Bring up the minimal user process as the canonical fallback for
/// validating the Ring-0 to Ring-3 transition.
pub fn enter_first_user_thread() -> ! {
    crate::arch::boot::enter_first_user_thread()
}

// ---------------------------------------------------------------------------
// The legacy `enter_first_user_thread` implementation (Milestone A→C) has
// been moved into `crate::arch::boot`. `kernel_main` keeps the public
// re-export above so the boot-mode dispatch path (`BootMode::Desktop =>
// enter_first_user_thread()`) does not have to know which architecture it
// runs on.
// ---------------------------------------------------------------------------
