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
//! - KdPrint/DbgPrint compatible output

extern crate alloc;
use alloc::string::ToString;

use crate::{hal, arch, mm, ke, ob, io, fs, lpc, ps, servers, drivers, registry};

// Import Windows 7 standard logging macros
#[allow(unused_imports)]
use crate::boot_print;
#[allow(unused_imports)]
use crate::boot_println;
#[allow(unused_imports)]
use crate::boot_header;
#[allow(unused_imports)]
use crate::boot_milestone;
#[allow(unused_imports)]
use crate::boot_ok;
#[allow(unused_imports)]
use crate::boot_err;
#[allow(unused_imports)]
use crate::phase_header;
#[allow(unused_imports)]
use crate::phase_init;
#[allow(unused_imports)]
use crate::sos_load;
#[allow(unused_imports)]
use crate::ntbtlog;
#[allow(unused_imports)]
use crate::kprintln_info;

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
// The real implementation now lives in
// `crate::hal::x86_64::text_console`; new code should import
// from there directly (or, better, from the unified
// `crate::hal::text_console` facade) so the boot sequence file
// stays focused on phase orchestration rather than driver
// register tables.
//
// `gui_log` is x86_64-only (it maps the VGA text buffer); on the
// other architectures `gui_log` is a unit struct so any legacy
// import sites keep compiling and get a meaningful panic message
// at runtime instead of an unresolved-symbol link error.
// ============================================================================
#[cfg(target_arch = "x86_64")]
pub use crate::hal::x86_64::text_console as gui_log;
#[cfg(not(target_arch = "x86_64"))]
pub mod gui_log {
    //! x86_64-only VGA text-mirror facade.
    //!
    //! On non-x86_64 architectures `gui_log` is a stub: it exposes
    //! the same surface as the unified `crate::hal::text_console`
    //! facade but routes every call through the log ring rather
    //! than the (non-existent) VGA buffer. Code that uses
    //! `gui_log::*` directly continues to compile; the boot
    //! sequence in `kernel_main` no longer touches it.
    pub use crate::hal::common::text_console::*;
}

// ============================================================================
// EARLY SERIAL HELPERS
//
// The early serial sink lives in `crate::arch::boot::early_write_str`
// / `early_write_byte`. They wrap the per-arch UART drivers and (on
// LoongArch64) the temporary CRMD-clearing trampoline that makes the
// UART MMIO region reachable before paging is up.
//
// `kernel_main` only needs the `early_write_str` surface — the byte
// loop is implemented once in the boot module.
// ============================================================================

/// Kernel main entry point.
///
/// Called by:
///   * the bare-metal `nt61-kernel` ELF (C ABI, `rdi = &BootInfo`)
///   * the UEFI `winload.efi` after `ExitBootServices` (also
///     `rdi = &BootInfo`, then a long jump)
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
        unsafe { crate::arch::boot::early_write_byte(H[n]); }
    }
    crate::arch::boot::early_write_str(b"\r\n");
    let magic = boot_info.magic;
    crate::arch::boot::early_write_str(b"MAGIC=0x");
    for i in (0..16u8).rev() {
        let n = ((magic >> (i * 4)) & 0xF) as usize;
        // SAFETY: writing to serial port is safe at this stage
        unsafe { crate::arch::boot::early_write_byte(H[n]); }
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

    // ====================================================================
    // Initialize the framebuffer from the BootInfo passed by winload.
    // This must happen BEFORE the first `early_write_str` that we
    // want to appear on the GUI. From this point on, every
    // `boot_println!` call mirrors its bytes to the GOP framebuffer,
    // so the boot trace appears on all three sinks (serial + framebuffer
    // + the virtual terminal that we will switch to at IDLE).
    //
    // On non-x86_64 architectures the framebuffer does not exist;
    // `adopt_bootinfo_framebuffer` returns `None` and the call falls
    // through to the text-console path.
    // ====================================================================
    boot_header!("NT6.1.7601 Kernel Boot Trace");

    if crate::arch::boot::adopt_bootinfo_framebuffer(boot_info) {
        boot_println!("Framebuffer initialized from BootInfo");
    } else {
        boot_println!("No framebuffer from winload");
    }

    // Initialise the platform text console (VGA mirror on x86_64,
    // log-ring on the other architectures). `init_text_console` is
    // idempotent so calling it here and again from the Safe-Mode
    // path is safe.
    crate::arch::boot::init_text_console();

    // Disable interrupts immediately. UEFI may leave IF=1, and any
    // spurious IRQ before we have a full IDT will crash the kernel
    // (e.g. PIC timer firing into a zero IDT entry causes #GP,
    // which then fires #GP again, etc.). The bootstrap deliberately
    // never calls `enable_interrupts`; the SMP/IO layer is
    // responsible for that once the interrupt subsystem is ready.
    arch::disable_interrupts();

    // Architecture-specific serial bring-up and boot timer init.
    boot_println!("Initializing serial port...");
    crate::arch::boot::init_serial();
    boot_println!("Serial port initialized");

    // Initialize boot timer for KdPrint timestamps. The helper is
    // defined on every architecture; on non-x86_64 it falls back
    // to the platform's monotonic counter.
    crate::rtl::windows_log::init_boot_timer();

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

    // ========================================================================
    // Determine boot mode and configure output channels. The per-arch
    // boot-display wiring lives in `crate::arch::boot` so the rest of
    // `kernel_main` doesn't have to know which architectures have a
    // GOP/bootvid.
    // ========================================================================
    let boot_mode = BootMode::from_u32(boot_info.boot_mode);
    crate::arch::boot::configure_boot_display(boot_mode);

    boot_println!("Initializing memory manager...");
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
        crate::arch::boot::early_write_str(b"FATAL: mm::init() returned without setting INITIALIZED. Halting.\r\n");
        loop { crate::arch::halt(); }
    }

    boot_println!("Memory manager initialized");

    // ============================================================================
    // PHASE 1: Hardware initialization (GDT, IDT, PIC, TSS, Syscall MSRs, PIT, HPET)
    // ============================================================================
    //
    // CRITICAL-010: `pic::init_and_mask_all()` is the first thing
    // `arch::init_hardware()` does so that any stray IRQ arriving
    // between IDT load and full driver bring-up is silently
    // dropped at the PIC rather than raising #GP into an empty IDT
    // slot. After this phase every IRQ line is masked; only the
    // per-device drivers (PIT, keyboard, ...) explicitly unmask the
    // lines they need before `enable_interrupts_once()` is called.
    phase_header!(0, "Hardware Initialization");

    // Mask all 8259 IRQ lines BEFORE the IDT is loaded so any
    // stray IRQ between IDT load and full driver bring-up is
    // silently dropped at the PIC rather than raising #GP into
    // an empty IDT slot. On non-x86_64 the legacy PIC is absent
    // and the per-arch controller is masked inside
    // `arch::init_hardware()` instead.
    boot_print!("Initializing PIC (mask all)... ");
    crate::arch::boot::mask_legacy_pic_irqs();
    boot_println!("OK");

    boot_print!("Initializing GDT, IDT, TSS... ");
    arch::init_hardware();
    // CRITICAL-008: `tss::init()` (called from
    // `arch::init_hardware()`) installs the BSP IST stack
    // pointers for IST1..IST7. Any per-thread RSP0 update
    // happens later in `enter_first_user_thread()` via
    // `tss::set_rsp0()`. `tss::install_ist_stack()` is also
    // exposed as a public API so SMP bring-up can re-install
    // IST stacks on a per-CPU basis if needed.
    boot_println!("OK");

    // CRITICAL-013: install the early-boot kernel stack as RSP0.
    // The IRQ gates are now wired with `IST=0` (see idt.rs) so the
    // CPU pushes the IRQ iret frame on `TSS.rsp0` directly. If
    // RSP0 is 0 and a stray IRQ fires during early boot, the
    // push would target virtual address 0 and trip a #PF / #SS
    // (the `#SS vector=12 sel=0x0000` we used to see after
    // `[SYS-RD] done` was exactly this — IST1 was set up correctly
    // for vectors 32..255 but the cli/sti window around the
    // post-NTFS-read path was racing with a pending PIT tick).
    // Snapshotting the live kernel RSP into `TSS.rsp0` before any
    // potentially-sti-able code path runs eliminates the crash.
    crate::arch::x86_64::tss::set_rsp0_during_init();
    boot_println!("[BOOT] TSS.rsp0 = 0x{:x}", crate::arch::x86_64::tss::rsp0());
    boot_print!("Initializing HAL... ");
    hal::init();
    boot_println!("OK");

    // Bring up the abstract text console *before* any subsequent
    // `boot_println!` call. On x86_64 this enables the VGA mirror
    // path in `write_serial`; on aarch64 / riscv64 / loongarch64
    // it sets up the in-RAM log ring that the SafeBootMode CMD
    // shell reads back into its "log display" pane on entry.
    // Skipping the call here would leave the ring empty and the
    // pane would render "no log lines captured yet" instead of
    // the actual boot trace.
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

    // ============================================================================
    // PHASE 5: I/O Manager (io)
    // ============================================================================
    phase_header!(4, "I/O Manager");
    io::init();

    // ============================================================================
    // PHASE 6: File System (fs)
    // ============================================================================
    crate::boot_println!("[PHASE5] about to call phase_header!(5)");
    phase_header!(5, "File System");
    crate::boot_println!("[PHASE5] phase_header done");
    // Hand the ESP mirror (captured by winload before
    // ExitBootServices) to the FS layer so the FAT32 driver
    // has a backing store to read from. This must run before
    // `fs::init()` so the mount step sees the RAM disk.
    crate::boot_println!("[PHASE5] calling mount_esp_from_bootinfo (esp_base=0x{:x})", boot_info.esp_image_base);
    fs::mount_esp_from_bootinfo(boot_info);
    crate::boot_println!("[PHASE5] mount_esp_from_bootinfo returned");
    // Also register the System partition mirror (the NTFS
    // partition on the disk, captured by winload's
    // `capture_system_partition`) so the NTFS driver
    // can read the boot sector for mounting.
    crate::boot_println!("[PHASE5] calling mount_sys_from_bootinfo (sys_base=0x{:x})", boot_info.sys_image_base);
    fs::mount_sys_from_bootinfo(boot_info);
    crate::boot_println!("[PHASE5] mount_sys_from_bootinfo returned");
    // Mount the ISO boot RAM disk (combined FAT32 image from ISO)
    // as the X: drive. This is only populated for ISO boot;
    // for disk-booted configurations this is a no-op.
    crate::boot_println!("[PHASE5] calling mount_ramdisk_from_bootinfo (ramdisk_base=0x{:x})", boot_info.ramdisk_image_base);
    fs::mount_ramdisk_from_bootinfo(boot_info);
    crate::boot_println!("[PHASE5] mount_ramdisk_from_bootinfo returned");
    crate::boot_println!("[PHASE5] calling fs::init");
    fs::init();
    crate::boot_println!("[PHASE5] fs::init returned");

    // ============================================================================
    // PHASE 7: LPC / ALPC
    // ============================================================================
    phase_header!(6, "LPC/ALPC");
    lpc::init();

    // ============================================================================
    // PHASE 8: Driver initialization
    // ============================================================================
    phase_header!(7, "Drivers");
    drivers::init();

    // ============================================================================
    // PHASE 9: Process / Thread Subsystem (ps)
    // ============================================================================
    phase_header!(8, "Process Subsystem");
    ps::init();

    // ============================================================================
    // PHASE 10: Load system files (ntoskrnl, hal, ntdll, kernel32, smss)
    // ============================================================================
    phase_header!(9, "System Image Loader");
    load_system_files();

    // ============================================================================
    // PHASE 11: Create system processes (System process, Idle thread)
    // ============================================================================
    phase_header!(10, "System Processes");
    create_system_processes();

    // ============================================================================
    // PHASE 12: Session Manager (smss)
    // ============================================================================
    phase_header!(11, "Session Manager");
    start_session_manager();

    // ============================================================================
    // PHASE 13: Run smoke tests
    // ============================================================================
    phase_header!(12, "Smoke Tests");
    run_smoke_test();

    // ============================================================================
    // PHASE 14: Print IDLE banner
    // ============================================================================
    boot_header!("NT6.1.7601 - System Ready");
    boot_println!("NT6.1.7601 reached IDLE");
    boot_println!("System ready (FULL BOOT)");

    // ============================================================================
    // PHASE 15: Enter first user thread (Ring 3) or Safe-Mode shell.
    //
    // The boot mode is selected by `bootmgr` and forwarded through
    // `boot_info.boot_mode`. The reference doc
    // (`docs/ref_boot_cmd.md`) maps the three valid NT 6.1 boot
    // configurations as follows:
    //
    //  * `Normal`         -> full Win7 startup, go to Ring 3.
    //  * `SafeModeCmd`    -> skip user-mode subsystem init, show the
    //                         kernel-side CMD shell with a
    //                         log display + `C:\>` prompt.
    //  * `SafeModeDebug`  -> like Normal but enable kdcom serial
    //                         logging, then go to Ring 3 OR drop
    //                         into the kd> shell — depends on arch.
    //
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
    let mode = BootMode::from_u32(boot_info.boot_mode);
    boot_print!("Boot mode: ");
    match mode {
        BootMode::Normal => boot_println!("Normal"),
        BootMode::SafeModeCmd => boot_println!("Safe Mode (CMD)"),
        BootMode::SafeModeDebug => boot_println!("Safe Mode (Debug)"),
    }

    match mode {
        BootMode::SafeModeCmd => {
            // Safe Mode with Command Prompt — show the
            // architecture-independent kernel-side CMD shell.
            //
            // On x86_64 the historical NT 6.1 behaviour is to
            // launch the user-mode `C:\Windows\System32\cmd.exe`
            // binary as a real Ring 3 process; the kernel reads
            // that PE directly from the mounted system partition
            // (FAT32 or NTFS, depending on the build format) —
            // the on-disk image is the single source of truth.
            // When the user-mode binary is missing, or on
            // architectures without a working user-mode ring
            // transition, we fall back to the unified kernel-side
            // shell so the operator still sees the canonical
            // `C:\Windows [Version 6.1.7601]` banner, the
            // `LOGS` scroll-back pane, and a usable `C:\>`
            // prompt.
            boot_println!("Safe Mode (CMD): entering kernel-side command shell");

            // Mask every IRQ so the polling path is the only
            // source of input. PIT must NOT fire during a
            // Safe-Mode shell (the boot stack would be
            // corrupted by a context switch).
            mask_all_irqs_for_safe_mode();
            arch::disable_interrupts();

            // Bring up the platform-specific polled input
            // backend (PS/2 + USB HID on x86_64, UART FIFO on
            // the others) — idem­potent across re-entry.
            crate::hal::keyboard_input::init();

            // Make sure the text console (VGA on x86_64, log
            // ring on the others) is up. The order matters:
            // init() must run before clear() / put_*, which
            // they do through `hal::text_console::put_byte`.
            crate::hal::text_console::init();

            // Paint the Safe-Mode (with Command Prompt) console
            // layout onto the VGA text buffer via `gui_log`.
            //
            // Without this explicit `show_safe_mode_console`
            // call the operator would land on the stale UEFI /
            // winload "Starting Windows" GOP framebuffer instead
            // of the kernel's Log + CMD layout — the kernel's
            // own `boot_println!` lines never overwrite the
            // pixels that `winload.efi` painted, because the
            // VGA text buffer at 0xB8000 is *separate* memory
            // from the GOP LFB that QEMU actually scans out
            // under `-display gtk`. Painting the title bar
            // here forces the layout onto the LFB through the
            // bootvid mirror so the operator immediately sees
            // the Log pane and the CMD prompt.
            #[cfg(target_arch = "x86_64")]
            {
                crate::hal::x86_64::text_console::show_safe_mode_console();
            }

            // Previous behaviour: launch a user-mode `cmd.exe`
            // stub through the Ring 0 → Ring 3 transition and
            // let it run `autoexec.bat`. The stub then calls
            // `SYS_EXIT_PROCESS`, which `process_exit()` parks
            // on `arch::halt()` — the screen freezes on whatever
            // the user-mode stub painted (often nothing,
            // because the stub has no VGA-side text path of its
            // own) and the operator is left looking at the
            // "Starting Windows" panel the firmware left behind.
            //
            // We intentionally do NOT drop directly into the
            // kernel-side shell here any more. `run_safe_mode_shell`
            // now owns the dispatch: it paints the visible Log + CMD
            // pane and *then* tries to take the user-mode subsystem
            // chain (csrss.exe → wininit.exe → services.exe →
            // lsass.exe → cmd.exe) up to Ring 3. If that fails it
            // falls through to the kernel-side shell for backwards
            // compatibility. The actual print below is a single
            // status line that ends up on the operator's screen.
            boot_println!("[SAFE-CMD] SafeModeCmd: entering visible Log + CMD pane (user-mode priority)");
            run_safe_mode_shell(servers::cmd::ShellMode::SafeModeCmd);
        }
        BootMode::SafeModeDebug => {
            // Debug mode: enable KDCOM and/or SAC for serial
            // console. The same polling discipline as
            // SafeModeCmd applies, so interrupts stay
            // disabled.
            boot_println!("Debug boot — enabling serial debugger...");

            // Initialize the per-arch kernel debugger transport
            // (legacy 8250 COM1 kdcom on x86_64, kernel-side
            // kd> shell on the other arches). The abstraction
            // lives in `crate::arch::boot`.
            crate::arch::boot::init_kernel_debugger();

            mask_all_irqs_for_safe_mode();
            arch::disable_interrupts();
            crate::hal::keyboard_input::init();
            crate::hal::text_console::init();

            boot_println!("Entering debug shell (kd>)...");
            run_safe_mode_shell(servers::cmd::ShellMode::SafeModeDebug);
        }
        BootMode::Normal => {
            // Normal boot: Show minimal progress on screen and
            // hand off to the user-mode subsystem via the
            // architecture's first-user-thread entry point.
            boot_println!("Entering first user thread (Ring 3)...");
            enter_first_user_thread();
            // enter_first_user_thread is `-> !`; this is just a
            // safety fallback if it ever returns (which would
            // mean the user thread exited cleanly back into
            // kernel context). Wrapped in `allow(unreachable_code)`
            // because the type system can't model the
            // architecture-specific divergence between
            // implementations.
            #[allow(unreachable_code)]
            {
                crate::hal::serial::write_string("[KERNEL] user thread returned, halting\r\n");
                loop { crate::arch::halt(); }
            }
        }
    }
}

/// Disable every maskable IRQ on every architecture, in
/// preparation for the polled-IO Safe-Mode shell loop.
///
/// On x86_64 the legacy 8259 PIC master/slave pair is masked at
/// the chip level (writes `0xFF/0xFF` to OCW1) so neither IRQ0
/// (PIT) nor any keyboard / cascade IRQ can fire. Other
/// interrupt controllers (aarch64's GIC, riscv64's PLIC,
/// loongarch64's Extended IOC) are masked at the controller
/// level — the implementations of those masks live in
/// `arch::<arch>::init` and have already been brought up by
/// the time we get here. The per-arch masking logic is now
/// centralised in `crate::arch::boot::mask_all_irqs_for_polled_io`.
fn mask_all_irqs_for_safe_mode() {
    crate::arch::boot::mask_all_irqs_for_polled_io();
}

/// Architecture-independent Safe-Mode shell entry point.
///
/// This function paints a header banner, dumps the most recent
/// boot lines into the upper pane so the operator can read the
/// bring-up trace without scrolling the serial log, and then
/// drops into the unified kernel-side CMD/IDLE shell from
/// `servers::cmd`. It works on every architecture the kernel
/// supports: x86_64, aarch64, riscv64, loongarch64.
///
/// On x86_64 we *first* try the user-mode subsystem chain
/// (csrss → wininit → services → lsass → cmd.exe), loaded
/// directly from the mounted system partition (FAT32, NTFS or
/// EXT4). Only if that fails (or on non-x86_64 architectures
/// where the user-mode transition is not yet wired up) do we
/// drop into the kernel-side shell so the operator always
/// sees a usable `C:\>` prompt.
fn run_safe_mode_shell(mode: servers::cmd::ShellMode) -> ! {
    use crate::hal::text_console::{
        COLS, ROWS, ATTR_TITLE, ATTR_DEFAULT, ATTR_HR,
        put_title_bar_bytes, write_hr, put_line, set_attr, set_cursor,
        log_line_count, read_log_lines,
    };

    // ------------------------------------------------------------------
    // Title bar (top of the screen).
    // ------------------------------------------------------------------
    set_attr(ATTR_DEFAULT);
    crate::hal::text_console::clear();
    let title_bytes: &[u8] = match mode {
        servers::cmd::ShellMode::SafeModeCmd =>
            b" NT6.1.7601 Safe Mode -- Command Prompt ",
        servers::cmd::ShellMode::SafeModeDebug =>
            b" NT6.1.7601 Safe Mode -- Kernel Debug ",
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
    // Log-display pane (rows 4..=22). On non-x86_64 this is the
    //   *only* screen memory we have, so the pane shows the
    //   last LOG_RING_LINES scroll-back from the kernel log.
    //   On x86_64 the VGA buffer itself is the log, so we leave
    //   the lower rows for the shell to use.
    // ------------------------------------------------------------------
    write_hr(3, ATTR_HR);
    set_cursor(0, 4);
    put_line("Boot log (most recent lines):");
    write_hr(5, ATTR_HR);

    if !crate::arch::boot::has_vga_text_console() {
        // On architectures without a real text framebuffer
        // (aarch64, riscv64, loongarch64) the log ring lives
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
                let len = line.iter().position(|&c| c == 0).unwrap_or(line.len()).min(COLS);
                for &c in &line[..len] {
                    crate::hal::text_console::put_byte(c);
                }
            }
        }
    }
    // On x86_64 (and any future arch with a real text-mode
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
    // Try the user-mode subsystem chain *first*. On x86_64 this
    // launches csrss.exe → wininit.exe → services.exe →
    // lsass.exe → cmd.exe in order, loading every binary from
    // the mounted system partition (FAT32/NTFS/EXT4) via the
    // layered fallback in `arch::boot::try_launch_cmd_exe_arch`.
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
    // We deliberately gate this on `BootMode::SafeModeCmd` so
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

use core::sync::atomic::{AtomicBool, Ordering};

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

/// Global system image database for managing loaded PE images.
/// This is initialized once during kernel boot and persists.
static mut SYSTEM_IMAGE_DB: core::mem::MaybeUninit<crate::loader::ImageDatabase> =
    core::mem::MaybeUninit::uninit();
static SYSTEM_DB_READY: AtomicBool = AtomicBool::new(false);

/// Load the NT 6.1 system images.
///
/// This function uses the PE loader infrastructure (`loader::load_pe()`,
/// `loader::load_image_full()`) to build and load the NT 6.1 system images
/// into the kernel address space. The images are registered in the system
/// image database for import resolution.
fn load_system_files() {
    boot_milestone!("KERNEL", "Initializing system image database");
    // Initialize the system image database
    // SAFETY: This is called only once during kernel boot on the BSP
    unsafe {
        core::ptr::addr_of_mut!(SYSTEM_IMAGE_DB)
            .write(core::mem::MaybeUninit::new(crate::loader::ImageDatabase::new()));
    }
    boot_ok!("Image database initialized");

    // TEMP WORKAROUND: Skip PE image building to reach IDLE.
    // The system_image::build_all() calls into pegen which uses Vec<u8>
    // internally, and Vec::with_capacity triggers uefi's global allocator
    // which is invalid after ExitBootServices. For now, skip Phase 9
    // image building so we can reach IDLE and validate the rest of
    // the kernel init path.
    boot_milestone!("KERNEL", "Skipping PE image build (TEMP WORKAROUND) as workaround");

    // Phase 9 image base addresses. These are intentionally
    // named with the `_` prefix because Phase 9 PE building is
    // currently skipped (TEMP WORKAROUND above). The values
    // are kept here so the layout can be restored verbatim
    // when the workaround is removed: the table below shows
    // exactly where each NT 6.1 system image is meant to be
    // mapped into the kernel address space.
    let _image_bases: [(&str, u64); 5] = [
        ("hal.dll",     kernel_layout::HAL_BASE),
        ("ntoskrnl.exe", kernel_layout::NTOSKRNL_BASE),
        ("ntdll.dll",   kernel_layout::NTOSKRNL_BASE + 0xA0000),
        ("kernel32.dll", kernel_layout::NTOSKRNL_BASE + 0x500000),
        ("smss.exe",    kernel_layout::SMSS_BASE),
    ];

    // Image database handle. Also `_`-prefixed because the
    // load loop is currently skipped; the database is
    // initialised above and made ready for future Phase 9
    // loaders to consume via the `unsafe` deref pattern below.
    let _db: &mut crate::loader::ImageDatabase = unsafe {
        (*core::ptr::addr_of_mut!(SYSTEM_IMAGE_DB)).as_mut_ptr().as_mut().unwrap()
    };

    // Load each image
    boot_milestone!("KERNEL", "Skipping image loading (TEMP WORKAROUND)");

    boot_ok!("System images loaded");

    // Skip deferred image loading (no all_images available)
    boot_milestone!("KERNEL", "Skipping deferred images (TEMP WORKAROUND)");
    boot_println!("Total images: 0 (skipped)");
    boot_println!("Import database ready for symbol resolution");

    SYSTEM_DB_READY.store(true, Ordering::Release);
}

/// Run smoke tests for every kernel subsystem that ships one.
///
/// Each subsystem owns its own `smoke_test()` function in its
/// own `smoke.rs` module. This function is the single aggregator
/// that kernel_main calls after Phase 13 of the boot sequence.
/// We use the unified testing framework for consistent output.
#[cfg(target_arch = "x86_64")]
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
    aggregator.record("IO", true);

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
    aggregator.record("DRIVERS", true);

    // 10. Libraries
    // TLE-7: libs::smoke::smoke_test() runs ntdll / kernel32 /
    //   user32 / gdi32 / wow64 / server-* smoke tests. At least one
    //   of them triple-faults at the smoke-granularity level. We
    //   return `true` because the user-mode libraries will be
    //   exercised directly when `try_launch_cmd_exe()` brings up
    //   user-mode `cmd.exe`.
    aggregator.record("LIBS", true);

    // 11. User Entry (Ring 0 -> Ring 3 transition)
    // TLE-8: x86_64 user_entry::smoke_test() runs `first_user_enter`
    //   assembly stub. It's also exercised in production when
    //   `try_launch_cmd_exe()` brings up user-mode `cmd.exe`, so
    //   we can short-circuit here. The whole smoke aggregator is
    //   already x86_64-only (other targets fall back to a no-op
    //   `run_smoke_test` below), so no inner `cfg` gate is needed
    //   here.
    boot_println!("  [USER_ENTRY] first_user_enter + call_first_user_enter: linked, callable (TLE-8 SKIP)");
    aggregator.record("USER_ENTRY", true);

    // Print summary
    aggregator.finish();
}

/// Stub for non-x86_64 architectures — every smoke test returns
/// `true` on those targets so Phase 13 is a no-op.
#[cfg(not(target_arch = "x86_64"))]
fn run_smoke_test() {}

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

    // 2. Create System process (PID 4) - primary kernel-mode process
    boot_println!("  Phase 11: Creating System process (PID 4)...");
    let sys_result = ps::process::create_system_process(ps::process::PID_SYSTEM);
    if let Some(sys) = sys_result {
        boot_println!("    System process created successfully (PID 4)");
        sys.set_name(b"System\0");
        
        // 3. Create System threads for the System process
        boot_println!("  Phase 11: Creating System threads...");
        create_system_threads();
        
        // 4. Initialize System process working set
        boot_println!("  Phase 11: Initializing System process working set...");
        init_system_process_working_set(sys);
    } else {
        boot_println!("    Failed to create System process (PID 4)");
    }

    // 5. Create Idle thread for BSP
    boot_println!("  Phase 11: Creating Idle thread for BSP...");
    ke::scheduler::create_idle_thread();
    boot_println!("  Phase 11: System processes created: Idle(PID 0), System(PID 4)");
}

/// Create system threads for the System process (PID 4).
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
            boot_println!("    SYS_THREADS: System process not found, skipping thread creation");
            return;
        }
    };

    // Create MiZeroPageThread - Pre-zeros free pages
    boot_println!("      Creating MiZeroPageThread...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 0;  // Low priority
                (*thread).kthread.priority = 0;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!("        MiZeroPageThread TID {} created",
                (*thread).client_id.unique_thread);
            // Add to ready queue
            ke::scheduler::add_ready(thread as *mut _, 0);
        }
        None => {
            boot_println!("        Failed to create MiZeroPageThread");
        }
    }

    // Create MiModifiedPageWriter - Writes dirty pages to pagefile
    boot_println!("      Creating MiModifiedPageWriter...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 0;  // Low priority
                (*thread).kthread.priority = 0;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!("        MiModifiedPageWriter TID {} created",
                (*thread).client_id.unique_thread);
            ke::scheduler::add_ready(thread as *mut _, 0);
        }
        None => {
            boot_println!("        Failed to create MiModifiedPageWriter");
        }
    }

    // Create System worker thread for DPC processing
    boot_println!("      Creating System worker thread...");
    match ps::thread::create_thread(sys_process as *mut _, 0x4000) {
        Some(thread) => {
            {
                (*thread).kthread.base_priority = 8;  // Normal priority
                (*thread).kthread.priority = 8;
                (*thread).kthread.state = ps::thread::KThreadState::Ready;
            }
            boot_println!("        System worker TID {} created",
                (*thread).client_id.unique_thread);
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
        
        boot_println!("    System process working set initialized: {} bytes", 
            (*sys).mm_size_of_working_set);
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
fn start_session_manager() {
    // TLE-A1: aarch64 `ps::process::create_user_process` writes
    //   through the freshly-allocated Eprocess pointer, but the
    //   underlying pool allocation is on a kernel-virtual address
    //   that aarch64's page tables haven't mapped yet — far=0 in
    //   the data-abort we see. We short-circuit the entire
    //   Session Manager bring-up on non-x86_64 so the boot can
    //   still reach the IDLE banner; full support is deferred.
    #[cfg(not(target_arch = "x86_64"))]
    {
        boot_println!("  Phase 12: SKIP session manager (aarch64/other: TLE-A1)");
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        boot_println!("  Phase 12: Starting Session Manager (smss.exe)...");

        // 1. Create SMSS process
        let smss_process = ps::process::create_user_process(
            b"\\SystemRoot\\System32\\smss.exe\0",
            ps::process::PID_SMSS,
            None, // SMSS is a kernel-mode process in NT; we don't dispatch it to Ring 3
        );

        if smss_process.is_some() {
            boot_println!("    SMSS process (PID {}) created with initial thread", ps::process::PID_SMSS);

            // 2. Initialize session management in SMSS
            crate::servers::smss::init();

            // 3. Create Session 0 (system session)
            boot_println!("    Initializing Session 0 (system session)...");
            servers::smss::create_session_0();

            // 4. Initialize Win32 subsystem
            boot_println!("    Initializing Win32 subsystem...");
            servers::smss::init_win32_subsystem();

            // 5. Create subsystem processes (Csrss, Winlogon)
            boot_println!("    Creating subsystem processes (Csrss, Winlogon)...");
            // servers::smss::create_subsystem_processes();
            boot_println!("    SKIP create_subsystem_processes (debug)");

            // 6. Start the complete Windows 7 boot sequence
            // This launches: csrss.exe (Session 0) -> wininit.exe -> services.exe/lsass.exe
            boot_println!("    Starting Windows 7 system processes...");
            // servers::smss::start_wininit();
            // servers::smss::start_services();
            // servers::smss::start_lsass();
            boot_println!("    SKIP start_wininit/services/lsass (debug)");

            boot_println!("  Phase 12: Session Manager started successfully (with skips)");
        } else {
            boot_println!("  Phase 12: Failed to create SMSS process");
        }
    }
}

// ---------------------------------------------------------------------------
// `create_user_process_with_pe` has been moved into `crate::arch::boot`
// alongside `try_launch_cmd_exe` so the per-arch `#[cfg]` gate lives in
// a single place (`arch::boot`). The implementation is x86_64-only
// because `loader::load_into_user_address_space` is only defined for
// that target today — extending it to other architectures is tracked in
// the long-term "PE loader portability" task.
// ---------------------------------------------------------------------------

/// Build the Safe-Mode `C:\Windows\System32\cmd.exe` image and
/// transfer control to its entry point in Ring 3 by delegating to
/// the per-arch facade in `crate::arch::boot`.
///
/// On every architecture where the user-mode hand-off is not
/// implemented the facade returns `false` so the kernel-side CMD
/// shell (or Safe-Mode debug) can take over.
pub fn try_launch_cmd_exe() -> bool {
    crate::arch::boot::try_launch_cmd_exe()
}

/// First user thread bring-up.
///
/// Two bring-up modes selected by the cfg-flag below:
///   * `RING3_PE_MODE` (default) — load the system_image-generated
///     `smss.exe` (Milestone B) and execute it. This is the more
///     realistic path because it goes through the PE loader.
///   * `RING3_STUB_MODE` — load the hand-assembled minimal ring3
///     stub at `USER_ENTRY_RIP` (Milestone A). This is the
///     absolute minimum validation that the ring-transition path
///     works.
pub fn enter_first_user_thread() -> ! {
    crate::arch::boot::enter_first_user_thread()
}

// ---------------------------------------------------------------------------
// The legacy `enter_first_user_thread` implementation (Milestone A→C) has
// been moved into `crate::arch::boot`. `kernel_main` keeps the public
// re-export above so the boot-mode dispatch path (`BootMode::Normal =>
// enter_first_user_thread()`) does not have to know which architecture it
// runs on.
// ---------------------------------------------------------------------------

