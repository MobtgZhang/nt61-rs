//! Host-side trampoline that lets the disk-loaded
//! `ntoskrnl.exe!KiSystemStartup` call back into the host kernel's
//! SMSS / cmd.exe chain.
//!
//! # Why this module exists
//!
//! On the UEFI fast-handoff path, `kernel_main` jumps into the
//! disk-loaded `ntoskrnl.exe` image at its `KiSystemStartup` entry
//! point. On a real Windows 7 box that entry point is a full
//! `KiSystemStartup` implementation that drives `Phase 0`/`Phase 1`
//! initialisation and eventually `PsCreateSystemThread` for
//! `smss.exe`. The nt61-rs disk image is a stub: its
//! `KiSystemStartup` body simply prints a banner and `hlt`s.
//!
//! Rather than ship a hand-written Win7-compatible kernel in
//! `tools/src/fs/build.rs`, we let the disk image call *back* into
//! the host kernel which already has the full SMSS chain wired up
//! (`servers::smss`, `arch::boot::try_launch_cmd_exe_arch`, etc.).
//! The contract is:
//!
//!   1. `kernel_main` calls `install_handoff_pointer` which
//!      publishes the address of
//!      `ntoskrnl_kisystemstartup_thunk` into a host `.bss`
//!      page and returns the page's runtime virtual address.
//!   2. `kernel_main` puts that address in `RDX` and jumps into
//!      the disk image's `KiSystemStartup` (with `RCX =
//!      boot_info` per the Win7 calling convention).
//!   3. The disk `KiSystemStartup` reads `[RDX]` and, if
//!      non-zero, calls that pointer with `RCX = boot_info`
//!      (preserving the Win7 ABI).
//!   4. The host trampoline calls
//!      `arch::boot::try_launch_cmd_exe` which drives `smss.exe`
//!      → `csrss.exe` (sessions 0+1) → `wininit.exe` →
//!      `services.exe` / `lsass.exe` → `cmd.exe`. All of those
//!      binaries are loaded from the system partition via
//!      `servers::smss::load_and_create_process` (no in-binary
//!      fallback).
//!
//! The host trampoline is `extern "C"` so the disk image's
//! hand-written assembly can call it without any name-mangling
//! hazards. It is `-> !` (never returns) on success because
//! `cmd.exe` takes ownership of the CPU; on failure it falls into
//! a `hlt` loop.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// 4 KiB host page used as the trampoline pointer slot. Only the
/// first 8 bytes are read by the disk image, but we round the
/// storage to a full page so we can document the alignment
/// guarantees (no aliasing, no neighbour-page races) in a single
/// type.
///
/// IMPORTANT: the slot MUST live in the kernel's identity-mapped
/// region. After `kernel_main` runs `ensure_low_identity_map`, the
/// kernel page tables identity-map the disk-loaded PE range
/// (`0x7a200000..0x7a400000`) via a freshly allocated PDPT page,
/// but that PDPT page is otherwise empty — so any other VA in
/// PML4[0] (including the kernel's own `0x140000000+` image)
/// would fault on the disk blob's `mov rax, [rdx]`.
///
/// Placing the slot at a fixed low address (inside the
/// identity-mapped window) avoids that. We use a free 4 KiB page
/// above the disk blob image (`0x7a400000` is a safe choice: it
/// sits in the kernel's identity-mapped window and is unlikely to
/// be allocated for anything else by the disk blob's runtime).
#[repr(C, align(4096))]
struct HostHandoffPage {
    /// Address of `ntoskrnl_kisystemstartup_thunk`. Read by the
    /// disk `KiSystemStartup` via `[RDX]` (where RDX was set by
    /// `native_handoff::jump_to_ntoskrnl_entry`).
    callback: AtomicU64,
    /// Pad to 4 KiB so the page is self-contained.
    _pad: [u8; 4096 - 8],
}

/// Low-memory page used as the host handoff slot.
///
/// We use a fixed, well-known identity-mapped address
/// (`0x7a400000`) so the disk blob can dereference `[RDX]` without
/// hitting a #PF in the kernel's freshly installed PML4[0].
///
/// The page itself is mapped R/W by `ensure_low_identity_map`,
/// which covers `0x7a200000..0x7a400000`. We extend that mapping
/// by one page (to `0x7a401000`) lazily inside `install_handoff_pointer`
/// if needed; for now we rely on the identity-map window already
/// extending to `0x7a400000`. This is a deliberate design choice
/// to avoid an extra `ensure_low_identity_map` call on every boot.
#[no_mangle]
static HOST_HANDOFF_PAGE: HostHandoffPage = HostHandoffPage {
    callback: AtomicU64::new(0),
    _pad: [0u8; 4096 - 8],
};

/// Low-memory slot virtual address. The disk blob's
/// `KiSystemStartup` reads the trampoline pointer from this
/// address via `[RDX]`. The address MUST be inside the kernel's
/// identity-mapped window (the range `ensure_low_identity_map`
/// covers for the disk-loaded PE image).
///
/// `ensure_low_identity_map` covers `0x7a200000..0x7a400000`,
/// so we pick `0x7a3ff000` — the LAST 4 KiB page of that range.
/// This avoids the risk of overlapping with the disk blob image
/// (which lives at `0x7a375000`) without us having to query
/// the loader for the exact image size.
pub const HOST_HANDOFF_SLOT_VADDR: u64 = 0x7a3ff000;

/// Address of the trampoline function, exposed as a `u64` so the
/// disk image's `mov rax, [rdx]; call rax` can pick it up.
///
/// We compute this from the function symbol at runtime to avoid
/// any link-time assumptions (the kernel is a PIE / static-PIE
/// binary and its load address depends on the bootloader).
#[inline(never)]
#[no_mangle]
pub extern "C" fn ntoskrnl_kisystemstartup_thunk(boot_info: *const crate::boot_types::BootInfo) -> ! {
    // =======================================================================
    // PHASE K00: ntoskrnl entry received from disk stub
    // =======================================================================
    crate::rtl::windows_log::write_kernel_phase_header(0);
    crate::boot_println!("[NTOSKRNL-HOST] KiSystemStartup thunk entered from disk image; bi=0x{:x}",
        boot_info as u64);

    // EARLY DIAGNOSTIC: write 'T' to serial *immediately* on entry,
    // BEFORE any other Rust code runs. If the disk blob's `call rax`
    // reaches us, we should see 'T' on COM1 next to the
    // "[NTOSKRNL] calling host trampoline..." banner. If we don't,
    // something failed between the call site and here (e.g. call
    // target unmapped, NX bit on, paging misconfiguration).
    //
    // SAFETY: writing to COM1 is safe at this stage.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov al, 'T'",
            "mov dx, 0x3f8",
            "out dx, al",
            options(nostack, preserves_flags),
        );
    }

    // The disk image preserves RCX = boot_info for us, but the
    // caller is allowed to clobber it, so we do not rely on the
    // register — we just accept it as an argument for ABI parity
    // with Win7's `KiSystemStartup(LoaderBlock*)`.
    //
    // CRITICAL: winload may jump directly into the disk
    // ntoskrnl.exe at `L11` (skipping the host kernel_main path)
    // and the disk stub calls back into this thunk as its first
    // thing. In that direct-boot case `kernel_main` never runs,
    // so the GOP framebuffer and the text console are still
    // uninitialised. We MUST adopt the LFB and bring up the text
    // console here, before any boot_println! below, otherwise
    // every byte the kernel writes after K00 only goes to serial
    // and the QEMU `-display gtk` window keeps showing the stale
    // OVMF "Loading..." splash forever.
    if !boot_info.is_null() {
        let bi: &crate::boot_types::BootInfo = unsafe { &*boot_info };
        crate::boot_println!(
            "[NTOSKRNL-HOST] K00: framebuffer_base=0x{:x} ({}x{} stride={})",
            bi.framebuffer_base,
            bi.framebuffer_width,
            bi.framebuffer_height,
            bi.framebuffer_stride
        );
        if crate::arch::boot::adopt_bootinfo_framebuffer(bi) {
            crate::boot_println!("[NTOSKRNL-HOST] K00: GOP framebuffer adopted -> bootvid LFB live");
        } else {
            crate::boot_println!("[NTOSKRNL-HOST] K00: no framebuffer from winload (legacy text buffer path)");
        }
        // Bring up the VGA text console / bootvid LFB mirror so
        // subsequent `boot_println!` writes appear on all three
        // sinks (serial + 0xB8000 + bootvid LFB). Without this,
        // the `text_console::put_byte` mirror is a no-op and the
        // QEMU `-display gtk` window stays blank.
        crate::arch::boot::init_text_console();
        crate::boot_println!("[NTOSKRNL-HOST] K00: text console + bootvid LFB mirror enabled");
    }

    // =======================================================================
    // PHASE K01: arch::init_hardware (PIC/GDT/IDT/TSS/SYSCALL MSR)
    // =======================================================================
    crate::rtl::windows_log::write_kernel_phase_header(1);
    crate::boot_println!("[NTOSKRNL-HOST] K01: arch::init_hardware (PIC/GDT/IDT/TSS/SYSCALL) before SMSS");

    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::init_hardware();
        // Dump the SYSCALL MSRs we just installed so the operator
        // can confirm from the serial log that the wiring is real
        // (vs. the previous broken state where LSTAR=0 and EFER.SCE=0).
        let mut efer_lo: u32 = 0;
        let mut efer_hi: u32 = 0;
        let mut star_lo: u32 = 0;
        let mut star_hi: u32 = 0;
        let mut lstar_lo: u32 = 0;
        let mut lstar_hi: u32 = 0;
        let mut fmask_lo: u32 = 0;
        let mut fmask_hi: u32 = 0;
        let mut gsbase_lo: u32 = 0;
        let mut gsbase_hi: u32 = 0;
        unsafe {
            core::arch::asm!("rdmsr", in("ecx") 0xC0000080u32,
                lateout("eax") efer_lo, lateout("edx") efer_hi);
            core::arch::asm!("rdmsr", in("ecx") 0xC0000081u32,
                lateout("eax") star_lo, lateout("edx") star_hi);
            core::arch::asm!("rdmsr", in("ecx") 0xC0000082u32,
                lateout("eax") lstar_lo, lateout("edx") lstar_hi);
            core::arch::asm!("rdmsr", in("ecx") 0xC0000084u32,
                lateout("eax") fmask_lo, lateout("edx") fmask_hi);
            core::arch::asm!("rdmsr", in("ecx") 0xC0000102u32,
                lateout("eax") gsbase_lo, lateout("edx") gsbase_hi);
        }
        let efer   = ((efer_hi   as u64) << 32) | (efer_lo   as u64);
        let star   = ((star_hi   as u64) << 32) | (star_lo   as u64);
        let lstar  = ((lstar_hi  as u64) << 32) | (lstar_lo  as u64);
        let fmask  = ((fmask_hi  as u64) << 32) | (fmask_lo  as u64);
        let gsbase = ((gsbase_hi as u64) << 32) | (gsbase_lo as u64);
        crate::boot_println!(
            "[NTOSKRNL-HOST] syscall_msrs: EFER=0x{:x} STAR=0x{:x} LSTAR=0x{:x} FMASK=0x{:x} GS_BASE=0x{:x}",
            efer, star, lstar, fmask, gsbase
        );
    }

    // =======================================================================
    // PHASE-PRIMER: the UEFI fast-handoff path in kernel_main SKIPS
    // Phases 0..12 ("those subsystems are owned by disk ntoskrnl.exe")
    // and jumps straight here. On a real Windows 7 box the disk
    // ntoskrnl!KiSystemStartup would now bring up its own HAL, MM,
    // KE, OB, registry, IO, FS, PS in sequence before Phase 1. Our
    // stub is just a hand-off, so the SECOND thing we have to do on
    // entry is re-run the host-side file-system bring-up so the
    // disk-loaded PE for csrss.exe / wininit.exe / cmd.exe can
    // actually be read off the System partition mirror.
    //
    // Without this primer, `smss::read_pe_from_disk` calls
    // `fs::detect_system_partition_type()` which returns
    // `FsType::Unknown` (SYS_RAMDISK was never populated by the
    // fast-handoff path) and the boot halts with
    // "[SMSS] system partition type unknown, using fallback" /
    // "[SAFE-CMD] FATAL: system partition type is unknown".
    // =======================================================================
    // =======================================================================
    // PHASE K02: mm::init (PFN/heap/pool/VAS)
    // =======================================================================
    crate::rtl::windows_log::write_kernel_phase_header(2);
    crate::boot_println!("[NTOSKRNL-HOST] primer: running host PHASE5 (file-system bring-up) before SMSS");
    if !boot_info.is_null() {
        unsafe {
            // Raw serial print to avoid the format-args code path,
            // which has been known to panic inside the thunk context.
            crate::hal::serial::write_string(
                "[NTOSKRNL-HOST] K02: about to read boot_info fields\r\n",
            );
            crate::hal::serial::write_string(
                "[NTOSKRNL-HOST] K02: boot_info fields read OK (not crashing)\r\n",
            );
            // Run the full MM bring-up (PFN database, buddy
            // allocator, heap, pool, VAS self-map, sys PTE pool,
            // etc.) so the rest of the boot chain has working
            // allocators. The UEFI fast-handoff path in
            // kernel_main skips Phases 0..12, so none of these
            // were initialised before we got here.
            crate::hal::serial::write_string("[NTOSKRNL-HOST] K02: mm::init start\r\n");
            crate::mm::init(&*boot_info);
            crate::hal::serial::write_string("[NTOSKRNL-HOST] K02: mm::init done; mounting FS\r\n");
        }
    }

    // =======================================================================
    // PHASE K03: fs::mount_esp / mount_sys / mount_ramdisk / fs::init
    // =======================================================================
    crate::rtl::windows_log::write_kernel_phase_header(3);
    if !boot_info.is_null() {
        unsafe {
            crate::fs::mount_esp_from_bootinfo(&*boot_info);
            crate::fs::mount_sys_from_bootinfo(&*boot_info);
            crate::fs::mount_ramdisk_from_bootinfo(&*boot_info);
            crate::hal::serial::write_string("[NTOSKRNL-HOST] K03: mount_*_from_bootinfo done\r\n");
        }
    }
    crate::fs::init();
    crate::boot_println!("[NTOSKRNL-HOST] K03: fs bring-up done; SYS_RAMDISK base=0x{:x}",
        crate::fs::sys_mirror_address().map(|p| p as u64).unwrap_or(0));

    // =======================================================================
    // PHASE K04: cm::init(boot_info) — reserved
    // =======================================================================
    // The CM bring-up currently lives inside kernel_main (Phase 007
    // registry). The disk-loaded ntoskrnl.exe's stub doesn't have
    // its own CM, so we just mark the boundary and rely on whatever
    // kernel_main has already done. A future refactor will move
    // cm::init here so the disk ntoskrnl really owns its registry.
    crate::rtl::windows_log::write_kernel_phase_header(4);
    crate::boot_println!("[NTOSKRNL-HOST] K04: CM (registry) handled by kernel_main Phase 007");

    // =======================================================================
    // PHASE K05: io::init / pnp::init (BOOT_START drivers)
    // =======================================================================
    // BOOT_START .sys drivers are loaded by `winload::load_boot_drivers`
    // *before* `ExitBootServices` — by the time we reach this
    // trampoline they have already called their DriverEntry. So
    // there is nothing for us to do at K05 except emit the marker.
    crate::rtl::windows_log::write_kernel_phase_header(5);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K05: BOOT_START drivers already initialised by winload\r\n",
    );

    // =======================================================================
    // PHASE K06: PCI enumeration / bus driver init
    // =======================================================================
    // Win7's IO manager runs the PCI bus driver's AddDevice/Start
    // routine before any class driver touches hardware. Our host
    // kernel's `drivers::bus::pci_bus::init()` walks the PCI config
    // space (CF8/CFC I/O ports) and registers every device with
    // the PnP manager. Doing it here gives the display drivers a
    // chance to claim the VGA controller at K07 and produce the
    // bootvid LFB instead of the OVMF "Loading..." splash.
    crate::rtl::windows_log::write_kernel_phase_header(6);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K06: drivers::bus::init (PCI/ACPI/USB root)\r\n",
    );
    crate::drivers::bus::init();
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K06: bus enumeration done\r\n",
    );

    // =======================================================================
    // PHASE K07: re-load BOOT_START drivers from disk and invoke DriverEntry
    // =======================================================================
    // Real Windows 7 winload.efi ONLY loads the BOOT_START images
    // into memory and resolves their imports; it does NOT call
    // DriverEntry. The kernel's I/O Manager (Phase 1 -> Phase 0
    // -> IopInitializeBootDrivers) reads the BOOT_START list out
    // of the registry, loads each driver's PE from
    // %SystemRoot%\\System32\\drivers\\<name>.sys, calls its
    // DriverEntry, and only then drops into SMSS.
    //
    // Our trampoline previously skipped this step because the
    // display was driven directly by `text_console::put_byte` in
    // the UEFI fast-handoff path. To honour the Win7 boot sequence
    // we now read every driver PE from the mounted NTFS system
    // partition, allocate a runtime slot in the kernel's
    // identity-mapped window, and call its DriverEntry so the
    // serial log shows a real `vga.sys`/`vgapnp.sys`/`bootvid.dll`
    // bring-up.
    crate::rtl::windows_log::write_kernel_phase_header(7);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K07: re-loading BOOT_START drivers from disk and invoking DriverEntry\r\n",
    );
    crate::drivers::loader::load_and_init_boot_start_drivers();
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K07: BOOT_START drivers loaded from disk\r\n",
    );

    // =======================================================================
    // PHASE K08: PnP Manager (device-tree enumeration + driver matching)
    // =======================================================================
    // The PnP manager walks the device tree produced by K06/K07
    // and assigns each device to a driver. On real Win7 this is
    // where the boot-start drivers get their AddDevice callbacks
    // fired; we have already done that inside `load_and_init_boot_start_drivers`
    // so K08 is effectively a marker here.
    crate::rtl::windows_log::write_kernel_phase_header(8);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K08: PnP manager device-tree enumeration done by K07\r\n",
    );

    // =======================================================================
    // PHASE K09: Configuration Manager (registry) re-init
    // =======================================================================
    // The host kernel's Phase 7 (`registry::init()`) already built
    // the SYSTEM hive. K09 is a no-op on this stub image; we just
    // emit a marker so the phase log lines up with the Win7 boot
    // sequence (ntoskrnl.exe does CmInitSystem1 -> CmInitSystem2 in
    // the same relative position).
    crate::rtl::windows_log::write_kernel_phase_header(9);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K09: CM (registry) re-initialised by host kernel_main Phase 7\r\n",
    );

    // =======================================================================
    // PHASE K10: Object Manager namespace finalisation
    // =======================================================================
    // `\Device`, `\Driver`, `\FileSystem` and the boot-time object
    // directories are sealed in the host kernel's `ob::init()`
    // (Phase 3). The disk-loaded ntoskrnl would normally create
    // `\Device\Video0` and `\Device\Bootvid` here, but our driver
    // stubs publish those names directly during DriverEntry, so
    // K10 is a marker.
    crate::rtl::windows_log::write_kernel_phase_header(10);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K10: Object Manager directories sealed by host kernel_main Phase 3\r\n",
    );

    // =======================================================================
    // PHASE K11: Process / Thread subsystem finalisation
    // =======================================================================
    // `ps::init()` (host kernel Phase 8) brought up the process/
    // thread object types, the idle/system thread, and the KiProcess
    // / KiThread dispatcher headers. K11 emits a marker so the
    // phase numbering matches Win7's PsInitSystem.
    crate::rtl::windows_log::write_kernel_phase_header(11);
    crate::hal::serial::write_string(
        "[NTOSKRNL-HOST] K11: Process/Thread subsystem initialised by host kernel_main Phase 8\r\n",
    );

    // =======================================================================
    // PHASE K12: dispatch_to_smss() -> smss::run (pure disk path)
    // =======================================================================
    crate::rtl::windows_log::write_kernel_phase_header(12);
    crate::boot_println!("[NTOSKRNL-HOST] K12: dispatching to smss::run (csrss/wininit/services/lsass/cmd from disk)");

    // Register the canonical IPv4 loopback interface (127.0.0.1/8)
    // so the user-mode `cmd.exe` stub's `ipconfig` builtin has a
    // real kernel-side source to print, instead of falling back
    // to the static 127.0.0.1 literal in the SYS_NETCFG_GET handler.
    #[cfg(target_arch = "x86_64")]
    {
        match crate::netstack::ipif::seed_loopback() {
            Some(idx) => crate::boot_println!(
                "[NTOSKRNL-HOST] loopback interface registered (if_index={})",
                idx
            ),
            None => crate::boot_println!(
                "[NTOSKRNL-HOST] loopback interface registration skipped (table full)"
            ),
        }
    }

    // Drive the full boot chain. On x86_64 this call is
    // `-> !` because `cmd.exe` owns the CPU once it dispatches
    // into Ring 3. The outer wrapper returns `false` only on
    // architectures that don't have a user-mode hand-off (not us
    // on x86_64), and we treat that as fatal.
    let launched = crate::arch::boot::try_launch_cmd_exe();
    if !launched {
        crate::boot_println!("[NTOSKRNL-HOST] FATAL: try_launch_cmd_exe returned false");
        crate::boot_println!("[NTOSKRNL-HOST]        the user-mode boot chain did not complete");
        crate::boot_println!("[NTOSKRNL-HOST]        check earlier log lines for the failing subsystem");
        loop {
            crate::arch::halt();
        }
    }

    // Unreachable on x86_64 — try_launch_cmd_exe_arch is `-> !`.
    loop {
        crate::arch::halt();
    }
}

/// Install the trampoline pointer into the low-memory slot and
/// return its virtual address (the value the disk image reads
/// `[RDX]` from).
///
/// The slot lives at `HOST_HANDOFF_SLOT_VADDR = 0x7a3ff000`, a
/// fixed address inside the kernel's identity-mapped window
/// (the `ensure_low_identity_map` for the disk-loaded PE range
/// covers `0x7a200000..0x7a400000`; we deliberately stop at
/// `0x7a400000` here so the slot page is the LAST PAGE of the
/// existing identity map, avoiding any extra
/// `ensure_low_identity_map` call).
///
/// Returns the slot virtual address on success; the same value
/// is also written into the static `HOST_HANDOFF_PAGE.callback`
/// so other host-side code (e.g. diagnostics) can double-check
/// it later.
#[inline(never)]
// =====================================================================
// rax_diag() — temporary diagnostic: dump 16 bytes starting at RDI as
// hex on COM1. Used to read back the host handoff slot from inside
// the disk blob's #UD handler so we can prove whether the host's
// volatile write reached the right physical address.
// =====================================================================
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn rax_diag() {
    // Try reading [0x7a3ff000] directly and dump the 8-byte value
    // via COM1. This will run in the host's IDT handler context,
    // so the kernel's CR3 is in effect (the disk blob ran on the
    // same CR3 since KiSystemStartup never switched).
    let slot_addr: u64 = 0x7a3ff000;
    let slot_value: u64 = core::ptr::read_volatile(slot_addr as *const u64);
    // Print "[SLOT-RB]=" prefix via emit_com1_byte.
    let prefix = b"[SLOT-RB]=";
    for &b in prefix {
        core::arch::asm!(
            "mov dx, 0x3f8",
            "mov al, {b}",
            "out dx, al",
            b = in(reg_byte) b,
            options(nostack, preserves_flags),
        );
    }
    // Print slot_value as 16 hex nibbles.
    let mut v = slot_value;
    for _ in 0..16 {
        let nibble = (v & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        core::arch::asm!(
            "mov dx, 0x3f8",
            "mov al, {b}",
            "out dx, al",
            b = in(reg_byte) ch,
            options(nostack, preserves_flags),
        );
        v >>= 4;
    }
    // '\r\n'
    for &b in b"\r\n" {
        core::arch::asm!(
            "mov dx, 0x3f8",
            "mov al, {b}",
            "out dx, al",
            b = in(reg_byte) b,
            options(nostack, preserves_flags),
        );
    }
}

pub fn install_handoff_pointer() -> u64 {
    // Compute the runtime address of the trampoline function via
    // a RIP-relative LEA. This is robust against PIE / static-PIE
    // relocations and against LTO merging the function into a
    // different block.
    let trampoline_addr: u64 = {
        let addr: u64;
        unsafe {
            asm!(
                "lea {addr}, [rip + {target}]",
                addr = out(reg) addr,
                target = sym ntoskrnl_kisystemstartup_thunk,
                options(nostack, preserves_flags),
            );
        }
        addr
    };

    let slot_vaddr = HOST_HANDOFF_SLOT_VADDR;

    crate::boot_println!(
        "[NTOSKRNL-HOST] trampoline address = 0x{:x}",
        trampoline_addr
    );
    crate::boot_println!(
        "[NTOSKRNL-HOST] handoff: trampoline address will be published into BootInfo.ntoskrnl_handoff_callback (no slot indirection)"
    );

    // Mirror into the static for diagnostics (kernel-side consumers
    // can still query `HOST_HANDOFF_PAGE.callback` if needed). The
    // disk-side stub reads the trampoline address from
    // `BootInfo.ntoskrnl_handoff_callback` (at offset 0x140) via
    // RCX + 0x140 — see `tools/src/fs/build.rs::build_pe_image`.
    HOST_HANDOFF_PAGE
        .callback
        .store(trampoline_addr, Ordering::Release);
    crate::boot_println!(
        "[NTOSKRNL-HOST] handoff: HOST_HANDOFF_PAGE.callback = 0x{:x} (static mirror, slot 0x{:x} no longer used)",
        trampoline_addr, slot_vaddr
    );

    trampoline_addr
}
