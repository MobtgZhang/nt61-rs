//! Architecture-neutral boot helpers.
//!
//! `kernel_main` historically hand-coded per-arch sequences for
//! framebuffer setup, PIC masking, display-mode switching, Windows
//! logo blitting, and the very-early serial writes that run *before*
//! `mm::init()`. That broke two rules:
//!
//!   * `kernel_main.rs` should read like the Windows 7 boot order,
//!     not like an ISA-specific bring-up checklist;
//!   * the same bootstrap code paths must work on every supported
//!     architecture (x86_64, aarch64, riscv64, loongarch64).
//!
//! This module folds those per-arch bring-up primitives behind a
//! single API. Each call is a no-op on architectures that don't
//! have the underlying hardware (e.g. `mask_legacy_pic_irqs` is a
//! no-op on aarch64/riscv64/loongarch64 where there is no legacy
//! 8259 pair), so `kernel_main` can call every helper unconditionally.

#[allow(unused_imports)]
use crate::{boot_print, boot_println};
use crate::boot_types::BootInfo;

/// Re-export of the kernel's `BootMode` so callers don't need to
/// import the canonical definition from two places.
pub use crate::boot_types::BootMode;

/// Write one byte to the platform's debug serial sink.
///
/// Safe to call from any context — including before
/// `mm::init()`/`hal::init()`. On LoongArch64 the trampoline also
/// makes the UART MMIO region reachable by clearing CRMD.PG, see
/// `arch_early_ensure_serial_ready`.
#[inline]
pub unsafe fn early_write_byte(c: u8) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = crate::hal::x86_64::serial::write_char(c);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = crate::hal::aarch64::serial::write_char(c);
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = crate::hal::riscv64::serial::write_char(c);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = crate::hal::loongarch64::serial::write_char(c);
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )))]
    {
        let _ = c;
    }
}

/// Write a byte slice to the early serial console. On LoongArch64
/// this disables paging so the first MMIO access doesn't trap;
/// on every other architecture it is a plain wrapper around
/// `early_write_byte`.
pub fn early_write_str(s: &[u8]) {
    arch_early_ensure_serial_ready();
    // LoongArch64-specific dependency pin: keep the call site
    // alive so the trampoline above is never DCE'd.
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = ARCH_EARLY_LAST_CRMD.load(core::sync::atomic::Ordering::Relaxed);
    }
    for &c in s {
        unsafe { early_write_byte(c) };
    }
}

/// Per-arch early serial sink readiness trampoline.
///
/// On LoongArch64 the firmware leaves the UART MMIO region
/// unreachable while paging is on, so we briefly clear CRMD.PG.
/// On every other architecture the firmware already provides an
/// identity-mapped UART window, so this is a no-op. The
/// `#[inline(never)]` + `static mut` dependencies ensure the LTO
/// pass cannot eliminate the call.
#[inline(never)]
pub fn arch_early_ensure_serial_ready() {
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        let prev = arch_early_ensure_serial_ready_loongarch();
        ARCH_EARLY_LAST_CRMD.store(prev, core::sync::atomic::Ordering::Relaxed);
    }
    // x86_64 / aarch64 / riscv64: nothing to do.
}

#[cfg(target_arch = "loongarch64")]
#[inline(never)]
fn arch_early_ensure_serial_ready_loongarch() -> u64 {
    static mut GUARD: u64 = 0;
    unsafe {
        let mut crmd: u64;
        core::arch::asm!("csrrd {}, 0x0", out(reg) crmd, options(nostack));
        let prev = crmd;
        crmd &= !(1u64 << 4); // clear PG (direct-mapped mode)
        GUARD = GUARD.wrapping_add(1);
        core::arch::asm!("csrwr {}, 0x0", in(reg) crmd, options(nostack));
        GUARD = GUARD.wrapping_add(crmd ^ prev);
        prev
    }
}

#[cfg(target_arch = "loongarch64")]
static ARCH_EARLY_LAST_CRMD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Adopt the GOP / firmware-provided framebuffer that `winload`
/// published in `BootInfo`. On x86_64 this initialises the LFB
/// and the `bootvid` driver; on architectures that have no LFB
/// (aarch64 / riscv64 / loongarch64) this is a no-op and returns
/// `false`. Returns `true` if a framebuffer was brought up
/// successfully, so the caller can log a status line without
/// reaching into `FramebufferInfo` itself.
#[cfg(target_arch = "x86_64")]
pub fn adopt_bootinfo_framebuffer(boot: &BootInfo) -> bool {
    if boot.framebuffer_base == 0 || boot.framebuffer_width == 0 {
        return false;
    }
    let info = crate::hal::x86_64::framebuffer::init_from_bootinfo(
        boot.framebuffer_base,
        boot.framebuffer_width,
        boot.framebuffer_height,
        boot.framebuffer_stride,
        boot.framebuffer_format,
    );
    crate::drivers::bootvid::init_from_framebuffer(
        info.address,
        info.width,
        info.height,
        info.pitch,
    );
    crate::drivers::bootvid::init();
    true
}

#[cfg(not(target_arch = "x86_64"))]
pub fn adopt_bootinfo_framebuffer(_boot: &BootInfo) -> bool {
    false
}

/// Bring up the platform's text console (VGA mirror on x86_64,
/// log-ring on the other architectures). Idempotent across
/// re-entry.
pub fn init_text_console() {
    #[cfg(target_arch = "x86_64")]
    {
        // gui_log is the VGA mirror; it's only defined on x86_64.
        crate::hal::x86_64::text_console::init();
    }
    // The unified log-ring lives in hal::common; harmless to call
    // on every arch.
    crate::hal::common::text_console::init();
}

/// Initialise the platform serial port. Idempotent.
pub fn init_serial() {
    crate::hal::serial::init();
}

/// Mask every legacy 8259 IRQ line. On x86_64 this writes the
/// OCW1 mask to the master/slave pair; on every other
/// architecture the legacy PIC is absent and the per-arch
/// interrupt controller is handled inside `arch::init_hardware()`,
/// so this is a no-op.
pub fn mask_legacy_pic_irqs() {
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::pic::init_and_mask_all();
}

/// Belt-and-braces mask used by the Safe-Mode polling shell:
/// every maskable IRQ is dropped at the controller so the
/// PIT/IRQ keyboard cannot fire while the shell owns the CPU.
///
/// On x86_64 we mask the legacy 8259 with the OCW1 mask
/// `0xFF/0xFF` (all 16 lines). The other architectures mask at
/// the platform controller inside `arch::init_hardware()` already;
/// we still call into the per-arch helper to leave room for
/// future per-arch masks.
pub fn mask_all_irqs_for_polled_io() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::x86_64::pic::write_mask(0xFFFF);
    }
    // The other architectures have already masked their
    // respective controllers in `arch::init_hardware()`, so no
    // additional action is needed here.
}

/// Configure the boot-time display mode (logo, SOS, ...).
///
/// `Normal`           -> standard Windows logo.
/// `SafeModeCmd`      -> plain text mode.
/// `SafeModeDebug`    -> SOS mode (driver-load verbose) + ntbtlog.
pub fn configure_boot_display(mode: BootMode) {
    #[cfg(target_arch = "x86_64")]
    {
        use crate::drivers::bootvid::{set_boot_mode, display_windows_logo, BootDisplayMode};
        match mode {
            BootMode::Normal => {
                set_boot_mode(BootDisplayMode::Normal);
                display_windows_logo();
            }
            BootMode::SafeModeCmd => {
                set_boot_mode(BootDisplayMode::Normal);
            }
            BootMode::SafeModeDebug => {
                set_boot_mode(BootDisplayMode::Sos);
                crate::rtl::ntbtlog::enable_boot_log();
                crate::rtl::ntbtlog::begin_boot_sequence();
                crate::rtl::ntbtlog::log_ntoskrnl();
            }
        }
    }
    // The non-x86_64 targets have no GOP/bootvid; the visible
    // boot progress comes from the serial UART instead. Nothing
    // to do here.
}

/// Initialise the platform's kernel debugger transport. On x86_64
/// we drive the legacy 8250 COM1 kdcom stub; on the other
/// architectures the kernel-side `kd>` shell in `servers::cmd`
/// is the equivalent debug surface. Returns `true` if a debugger
/// is actually attached on COM1 (x86_64 only).
pub fn init_kernel_debugger() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::drivers::kdcom::KdInitSystem();
        let connected = crate::drivers::kdcom::KdIsConnected();
        if !connected {
            crate::boot_println!("No debugger connected, enabling SAC...");
            crate::rtl::sac::enable();
            crate::rtl::sac::start_sac_loop();
        } else {
            crate::boot_println!("Kernel debugger connected on COM1");
            crate::boot_println!("Type 'g' in WinDbg to continue boot...");
        }
        #[cfg(target_arch = "x86_64")]
        {
            crate::rtl::ntbtlog::end_boot_sequence();
        }
        connected
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::boot_println!("No kdcom transport on this arch, using kernel-side kd> shell");
        // SAC is not wired up on the non-x86_64 arches yet; the
        // shell in servers::cmd is the equivalent debug surface.
        false
    }
}

/// True if the platform has a legacy COM1 8250 port that can be
/// used as a kdcom transport. The kernel debugger stack is only
/// built on x86_64 today.
pub const fn has_kdcom_transport() -> bool {
    cfg!(target_arch = "x86_64")
}

/// True if the platform supports a user-mode `cmd.exe` style
/// handover (Ring 0 → Ring 3 + `iretq`-style). Only x86_64 has a
/// working user-mode ring transition today; the other arches
/// fall back to the kernel-side CMD shell.
pub const fn has_user_mode_hand_off() -> bool {
    cfg!(target_arch = "x86_64")
}

/// Human-readable architecture / QEMU machine name printed in
/// the Safe-Mode shell title pane.
///
/// Lives in `arch::boot` because every architecture has the same
/// representation (the same string the operator types into QEMU's
/// `-machine` flag), and the kernel-side shell wants to display
/// it without an architecture-specific `cfg` block.
pub const fn arch_name_line() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { "  x86_64  (QEMU: -machine pc)" }
    #[cfg(target_arch = "aarch64")]
    { "  aarch64  (QEMU: -machine virt)" }
    #[cfg(target_arch = "riscv64")]
    { "  riscv64  (QEMU: -machine virt)" }
    #[cfg(target_arch = "loongarch64")]
    { "  loongarch64 (QEMU: -machine virt)" }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    )))]
    { "  unknown architecture" }
}

/// True if the platform exposes a real text-mode framebuffer
/// (VGA / bootvid on x86_64) that already shows every boot line.
/// The Safe-Mode shell uses this to decide whether to render the
/// scroll-back log pane.
pub const fn has_vga_text_console() -> bool {
    cfg!(target_arch = "x86_64")
}

/// Build the Safe-Mode `C:\Windows\System32\cmd.exe` image and
/// transfer control to its entry point in Ring 3.
///
/// On every architecture where the user-mode hand-off is not
/// implemented this returns `false` so the kernel-side CMD shell
/// (or Safe-Mode debug) can take over.
pub fn try_launch_cmd_exe() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        try_launch_cmd_exe_arch()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn try_launch_cmd_exe_arch() -> bool {
    use crate::ps::process::Eprocess;
    
    boot_println!("[SAFE-CMD] ============================================");
    boot_println!("[SAFE-CMD] Windows 7 Boot Sequence (No Desktop Mode)");
    boot_println!("[SAFE-CMD] ============================================");
    
    // Phase 1: Initialize Session Manager
    boot_println!("[SAFE-CMD] Phase 1: Initializing Session Manager...");
    crate::servers::smss::init();
    
    // Phase 2: Create sessions
    boot_println!("[SAFE-CMD] Phase 2: Creating Sessions...");
    crate::servers::smss::create_session_0();
    crate::servers::smss::create_session_1();
    
    // Phase 3: Start subsystems (CSRSS for Session 0 and Session 1)
    boot_println!("[SAFE-CMD] Phase 3: Starting Subsystems...");
    if let Err(e) = launch_csrss_session_0() {
        boot_println!("[SAFE-CMD] Warning: Failed to launch CSRSS Session 0: {:?}", e);
    }
    if let Err(e) = launch_csrss_session_1() {
        boot_println!("[SAFE-CMD] Warning: Failed to launch CSRSS Session 1: {:?}", e);
    }
    
    // Phase 4: Start WinInit (which starts Services and LSASS)
    boot_println!("[SAFE-CMD] Phase 4: Starting WinInit...");
    if let Err(e) = launch_wininit_exe() {
        boot_println!("[SAFE-CMD] Warning: Failed to launch wininit.exe: {:?}", e);
    }
    
    boot_println!("[SAFE-CMD] ============================================");
    boot_println!("[SAFE-CMD] Boot sequence complete, launching CMD...");
    boot_println!("[SAFE-CMD] ============================================");
    
    // Now load and launch cmd.exe
    boot_println!("[SAFE-CMD] Loading cmd.exe from disk...");
    let cmd_image: core::mem::ManuallyDrop<alloc::vec::Vec<u8>> = match load_cmd_exe_from_disk() {
        Ok(img) => img,
        Err(e) => {
            boot_println!("[SAFE-CMD] could not load cmd.exe from disk: {}", e);
            return false;
        }
    };
    boot_println!("[SAFE-CMD] Loaded cmd.exe: {} bytes", cmd_image.len());
    
    let pid: u64 = 0x1F10;
    let process = match create_user_process_with_pe(&cmd_image, pid) {
        Some(p) => p,
        None => {
            boot_println!("[SAFE-CMD] create_user_process_with_pe failed for cmd.exe");
            return false;
        }
    };
    
    let pml4_phys = unsafe { (*process).pml4_phys };
    let user_rip = unsafe { (*process).user_rip };
    let user_rsp = unsafe { (*process).user_rsp };
    let main_thread = unsafe { (*process).main_thread };
    
    boot_println!("[SAFE-CMD] cmd.exe process: PML4=0x{:x} RIP=0x{:x} RSP=0x{:x}",
                  pml4_phys, user_rip, user_rsp);
                  
    if !main_thread.is_null() {
        crate::ke::scheduler::setup_bsp(main_thread);
    } else {
        boot_println!("[SAFE-CMD] cmd.exe process has no main_thread");
        return false;
    }
    
    boot_println!("[SAFE-CMD] Dispatching cmd.exe into Ring 3...");
    crate::arch::x86_64::user_entry::enter_first_user_thread(pml4_phys, user_rip, user_rsp);
}

/// Launch CSRSS for Session 0
#[cfg(target_arch = "x86_64")]
fn launch_csrss_session_0() -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
    boot_println!("[SAFE-CMD] Launching CSRSS for Session 0...");
    crate::servers::smss::load_and_create_process(
        "C:\\Windows\\System32\\csrss.exe",
        "csrss.exe",
        0,
        0x200,
    )
}

/// Launch CSRSS for Session 1
#[cfg(target_arch = "x86_64")]
fn launch_csrss_session_1() -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
    boot_println!("[SAFE-CMD] Launching CSRSS for Session 1...");
    crate::servers::smss::load_and_create_process(
        "C:\\Windows\\System32\\csrss.exe",
        "csrss.exe",
        1,
        0x300,
    )
}

/// Launch wininit.exe
#[cfg(target_arch = "x86_64")]
fn launch_wininit_exe() -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
    boot_println!("[SAFE-CMD] Launching wininit.exe...");
    let result = crate::servers::smss::load_and_create_process(
        "C:\\Windows\\System32\\wininit.exe",
        "wininit.exe",
        0,
        0x400,
    )?;
    
    // wininit.exe should start services.exe and lsass.exe
    // We start them directly from here to ensure they're launched
    boot_println!("[SAFE-CMD] Launching services.exe...");
    let _ = crate::servers::smss::load_and_create_process(
        "C:\\Windows\\System32\\services.exe",
        "services.exe",
        0,
        0x500,
    );
    
    boot_println!("[SAFE-CMD] Launching lsass.exe...");
    let _ = crate::servers::smss::load_and_create_process(
        "C:\\Windows\\System32\\lsass.exe",
        "lsass.exe",
        0,
        0x600,
    );
    
    Ok(result)
}

/// Canonical Windows-7 on-disk path for the user-mode command host:
/// `C:\Windows\System32\cmd.exe`.
const CMD_EXE_DISK_PATH: &str = "C:\\Windows\\System32\\cmd.exe";

/// Load the Safe-Mode `cmd.exe` user-mode image directly from the
/// mounted system partition. The correct filesystem driver is selected
/// at runtime by probing the system partition's boot sector (not by
/// guessing from the build variant), matching how `mount_system_partition`
/// works during `fs::init`.
///
/// Returns the raw file bytes wrapped in a `Vec<u8>`. The image must
/// be a valid PE32+ — the loader will reject it otherwise.
fn load_cmd_exe_from_disk() -> Result<core::mem::ManuallyDrop<alloc::vec::Vec<u8>>, &'static str> {
    boot_println!("[SAFE-CMD] load_cmd_exe_from_disk: target = {}", CMD_EXE_DISK_PATH);

    // Probe the system partition to pick the right FS driver.
    // This handles all three build variants correctly:
    //   FAT32 build → C: is FAT32
    //   NTFS  build → C: is NTFS
    //   EXT4  build → C: is ext2/ext4
    match crate::fs::detect_system_partition_type() {
        crate::fs::FsType::Fat32 => {
            if !crate::fs::fat32::is_mounted() {
                boot_println!("[SAFE-CMD] System partition is FAT32 but no FAT32 fs is mounted");
                return Err("system FAT32 not mounted");
            }
            let fs = match crate::fs::fat32::get_mounted_fs() {
                Some(f) => f,
                None => return Err("system FAT32 get_mounted_fs returned None"),
            };
            // CRITICAL: make sure FAT32 sector reads target the system
            // partition mirror. Without this, FAT32 read_sector would
            // fall back to the ESP mirror (or to nothing) and the
            // directory walk would silently miss cmd.exe.
            let prev_active = crate::fs::active_partition_ramdisk();
            if let Some(sys_base) = crate::fs::sys_mirror_address() {
                crate::fs::set_active_partition_ramdisk(Some(sys_base));
            }
            boot_println!("[SAFE-CMD] system partition = FAT32, trying find_file_at_path");
            let cmd_result = match crate::fs::fat32::find_file_at_path(fs, CMD_EXE_DISK_PATH) {
                Some(entry) => {
                    let cluster = entry.first_cluster();
                    let size = entry.file_size() as usize;
                    if size == 0 {
                        boot_println!("[SAFE-CMD] FAT32 cmd.exe entry is zero-length");
                        Err("zero-length cmd.exe entry")
                    } else {
                        boot_println!("[SAFE-CMD] FAT32 cmd.exe entry: cluster={} size={}", cluster, size);
                        // Allocate via the kernel pool instead of KernelHeap so
                        // we side-step the same SIMD-alignment / Stack-Fault
                        // class of issues we hit with the system exes. We
                        // reuse the trick from `read_pe_from_fat32_impl`:
                        // grab a pool buffer, hand it to the FAT32 read
                        // routine, and return it wrapped in `ManuallyDrop`
                        // so the kernel heap never sees a free() for it.
                        let ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, size);
                        if ptr.is_null() {
                            boot_println!("[SAFE-CMD] pool alloc failed for cmd.exe ({} bytes)", size);
                            return Err("pool alloc failed");
                        }
                        let mut buf_slice = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
                        match crate::fs::fat32::read_file(fs, cluster, size as u32, &mut buf_slice) {
                            Ok(n) if n >= 2 && buf_slice[0] == b'M' && buf_slice[1] == b'Z' => {
                                boot_println!("[SAFE-CMD] FAT32 cmd.exe read OK ({} bytes)", n);
                                let mut v = unsafe {
                                    alloc::vec::Vec::from_raw_parts(ptr, n, size)
                                };
                                v.truncate(n);
                                return Ok(core::mem::ManuallyDrop::new(v));
                            }
                            Ok(n) => {
                                boot_println!("[SAFE-CMD] FAT32 cmd.exe {} bytes but MZ mismatch", n);
                                return Err("FAT32 cmd.exe MZ mismatch");
                            }
                            Err(_) => {
                                boot_println!("[SAFE-CMD] FAT32 read_file returned Err");
                                return Err("FAT32 read_file failed");
                            }
                        }
                    }
                }
                None => {
                    boot_println!("[SAFE-CMD] FAT32 find_file_at_path returned None for cmd.exe");
                    Err("cmd.exe not found on FAT32 system")
                }
            };
            // Restore the previous active partition so subsequent
            // callers don't accidentally keep using the system mirror.
            crate::fs::set_active_partition_ramdisk(prev_active);
            return cmd_result;
        }
        crate::fs::FsType::Ntfs => {
            if !crate::fs::ntfs::is_mounted() {
                boot_println!("[SAFE-CMD] System partition is NTFS but not mounted");
                return Err("system NTFS not mounted");
            }
            boot_println!("[SAFE-CMD] system partition = NTFS");
            match try_load_cmd_exe_from_ntfs() {
                Ok(img) => return Ok(img),
                Err(e) => {
                    boot_println!("[SAFE-CMD] NTFS load failed: {}, using fallback", e);
                    // Fall through to system_image fallback
                }
            }
        }
        // EXT2/3/4 system partition — load cmd.exe through the
        // ext driver. The "pre-flight guard" that used to skip
        // this path with `Err(known to fault)` has been removed;
        // the disk read goes through `read_whole_file` which the
        // ext2 driver handles directly.
        crate::fs::FsType::Ext2 | crate::fs::FsType::Ext3 | crate::fs::FsType::Ext4 => {
            if !crate::fs::ext2::is_mounted() {
                boot_println!("[SAFE-CMD] System partition is EXT but no EXT fs is mounted");
                return Err("system EXT not mounted");
            }
            let fs = match crate::fs::ext2::get_mounted_fs() {
                Some(f) => f,
                None => return Err("system EXT get_mounted_fs returned None"),
            };
            match crate::fs::ext2::read_whole_file(fs, CMD_EXE_DISK_PATH) {
                Ok(data) => {
                    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
                        boot_println!("[SAFE-CMD] EXT cmd.exe read OK ({} bytes)", data.len());
                        return Ok(core::mem::ManuallyDrop::new(data));
                    } else {
                        boot_println!("[SAFE-CMD] EXT cmd.exe MZ mismatch ({} bytes)", data.len());
                        return Err("EXT cmd.exe MZ mismatch");
                    }
                }
                Err(e) => {
                    boot_println!("[SAFE-CMD] EXT read_whole_file({}) failed: {}", CMD_EXE_DISK_PATH, e);
                    return Err("EXT cmd.exe read failed");
                }
            }
        }
        // Fallback for all filesystems: use in-memory cmd.exe from system_image
        crate::fs::FsType::Unknown => {
            boot_println!("[SAFE-CMD] system partition type is unknown, using fallback");
        }
    }
    
    // Fallback: use in-memory cmd.exe from system_image
    // This ensures boot can always complete even if filesystem driver is broken
    boot_println!("[SAFE-CMD] Loading cmd.exe from system_image fallback...");
    let cmd_image = crate::system_image::build_cmd_exe_for_machine(0x8664);
    boot_println!("[SAFE-CMD] system_image fallback: {} bytes", cmd_image.len());
    Ok(cmd_image)
}

/// Helper: try to load cmd.exe from the NTFS system partition.
///
/// Implements the layered NTFS read path:
///   1. Set the active partition to the system mirror so
///      `read_sector` hits the C: drive contents.
///   2. Build the UTF-16 path for `cmd.exe`.
///   3. Call `ntfs::open_file` → `ntfs::read_file`.
///   4. Restore the active partition to its prior value.
///
/// Returns `Ok(vec)` on success and `Err(&'static str)` on any
/// failure so the caller can fall through to the in-memory
/// `system_image` cmd.exe stub.
fn try_load_cmd_exe_from_ntfs() -> Result<core::mem::ManuallyDrop<alloc::vec::Vec<u8>>, &'static str> {
    if !crate::fs::ntfs::is_mounted() {
        return Err("NTFS not mounted");
    }
    // Switch the active mirror to the system partition so
    // every `read_sector` call inside the NTFS driver hits the
    // C: image, not the ESP.
    let prev_active = crate::fs::active_partition_ramdisk();
    if let Some(sys_base) = crate::fs::sys_mirror_address() {
        crate::fs::set_active_partition_ramdisk(Some(sys_base));
    }
    let fs = match crate::fs::ntfs::get_mounted_fs() {
        Some(f) => f,
        None => {
            crate::fs::set_active_partition_ramdisk(prev_active);
            return Err("NTFS get_mounted_fs returned None");
        }
    };

    // Build the UTF-16 path for `C:\Windows\System32\cmd.exe`.
    let ascii = CMD_EXE_DISK_PATH.as_bytes();
    let mut path_utf16 = [0u16; 256];
    let len = core::cmp::min(ascii.len(), path_utf16.len() - 1);
    for i in 0..len {
        path_utf16[i] = ascii[i] as u16;
    }
    path_utf16[len] = 0;

    let mut handle = match crate::fs::ntfs::open_file(fs, &path_utf16[..len + 1], None) {
        Some(h) => h,
        None => {
            crate::fs::set_active_partition_ramdisk(prev_active);
            return Err("NTFS open_file for cmd.exe returned None");
        }
    };

    let total_size = (handle.file_size as usize).min(64 * 1024);
    if total_size < 2 {
        crate::fs::set_active_partition_ramdisk(prev_active);
        return Err("NTFS cmd.exe too small");
    }
    // Allocate via the kernel pool to avoid the KernelHeap
    // alignment class of stack faults that has been known to
    // occur during very early SMSS-style PE reads.
    let ptr = crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, total_size);
    if ptr.is_null() {
        crate::fs::set_active_partition_ramdisk(prev_active);
        return Err("NTFS cmd.exe pool alloc failed");
    }
    let mut read_total = 0usize;
    let mut iter = 0usize;
    loop {
        if read_total >= total_size || iter >= 16 {
            break;
        }
        let remaining = total_size - read_total;
        let cap = remaining.min(8192);
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(ptr.add(read_total), cap) };
        match crate::fs::ntfs::read_file(fs, &mut handle, buf_slice) {
            Ok(0) => break,
            Ok(n) => {
                read_total += n;
                iter += 1;
            }
            Err(_) => {
                crate::fs::set_active_partition_ramdisk(prev_active);
                return Err("NTFS read_file for cmd.exe returned Err");
            }
        }
    }
    crate::fs::set_active_partition_ramdisk(prev_active);
    if read_total < 2
        || unsafe { *ptr } != b'M'
        || unsafe { *ptr.add(1) } != b'Z'
    {
        return Err("NTFS cmd.exe MZ mismatch");
    }
    let mut v = unsafe {
        alloc::vec::Vec::from_raw_parts(ptr, read_total, total_size)
    };
    v.truncate(read_total);
    Ok(core::mem::ManuallyDrop::new(v))
}

/// Create a user-mode process and load a PE image into its per-process
/// PML4 in one step.
///
/// On x86_64 the implementation actually drives the full PE-loader path
/// (`loader::load_into_user_address_space`). On the other
/// architectures PE loading is not implemented yet, so this returns
/// `None` — which is the contract `try_launch_cmd_exe` already
/// expects.
#[allow(dead_code)]
pub fn create_user_process_with_pe(
    image: &[u8],
    pid: u64,
) -> Option<*mut crate::ps::process::Eprocess> {
    #[cfg(target_arch = "x86_64")]
    {
        create_user_process_with_pe_x86_64(image, pid)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (image, pid);
        None
    }
}

#[cfg(target_arch = "x86_64")]
fn create_user_process_with_pe_x86_64(
    image: &[u8],
    pid: u64,
) -> Option<*mut crate::ps::process::Eprocess> {
    boot_println!("[SAFE-CMD] create_user_process_with_pe: A (calling create_user_process)");
    let process = match crate::ps::process::create_user_process(image, pid, None) {
        Some(p) => p as *mut crate::ps::process::Eprocess,
        None => {
            boot_println!("[SAFE-CMD] create_user_process returned None");
            return None;
        }
    };
    boot_println!("[SAFE-CMD] create_user_process_with_pe: B (process created)");
    let pml4_phys = unsafe { (*process).pml4_phys };
    if pml4_phys == 0 {
        boot_println!("[SAFE-CMD] create_user_process_with_pe: pml4_phys=0");
        return None;
    }
    boot_println!("[SAFE-CMD] create_user_process_with_pe: C (pml4=0x{:x}, calling load_into_user_address_space)", pml4_phys);
    let mapping = match crate::loader::load_into_user_address_space(pml4_phys, image) {
        Some(m) => m,
        None => {
            boot_println!("[SAFE-CMD] load_into_user_address_space returned None");
            return None;
        }
    };
    boot_println!("[SAFE-CMD] create_user_process_with_pe: D (PE loaded, entry=0x{:x})", mapping.entry_point);
    unsafe {
        (*process).user_rip = mapping.entry_point;
        (*process).user_image_base = mapping.image_base;
        (*process).user_image_size = mapping.image_size;
    }
    boot_println!("[SAFE-CMD] PE loaded: image_base=0x{:x} entry=0x{:x} size=0x{:x}",
                  mapping.image_base, mapping.entry_point, mapping.image_size);
    Some(process)
}

/// First user thread bring-up.
///
/// Two bring-up modes (selected at compile time by the constants
/// below):
///   * `RING3_PE_MODE` — load the system_image-generated `smss.exe`
///     (Milestone B) and execute it. This is the more realistic
///     path because it goes through the PE loader.
///   * `RING3_STUB_MODE` — load the hand-assembled minimal ring3
///     stub at `USER_ENTRY_RIP` (Milestone A). This is the
///     absolute minimum validation that the ring-transition path
///     works.
///
/// On non-x86_64 architectures the function never returns; it
/// prints a message and parks the CPU because the user-mode ring
/// transition has not been implemented for those targets yet.
pub fn enter_first_user_thread() -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        enter_first_user_thread_x86_64()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        boot_println!("[enter_first_user_thread] not implemented for this architecture");
        loop { crate::arch::halt(); }
    }
}

/// Set to `true` to use the Milestone B path (real PE loading).
/// Set to `false` to use the Milestone A path (hand-assembled stub).
const RING3_PE_MODE: bool = false;
/// Set to `true` to fall back to the Milestone A stub if PE
/// loading fails for any reason (this is the safe default).
const RING3_STUB_FALLBACK: bool = true;

#[cfg(target_arch = "x86_64")]
fn enter_first_user_thread_x86_64() -> ! {
    use crate::ps::process::Eprocess;
    boot_println!("");
    boot_println!("========================================");
    boot_println!("FIRST USER THREAD BRING-UP");
    boot_println!("========================================");

    let mut process: *mut Eprocess = core::ptr::null_mut();
    if RING3_PE_MODE {
        let machine: u16 = 0x8664;
        let smss_image: alloc::vec::Vec<u8> =
            crate::system_image::build_smss_for_machine(machine);
        boot_println!("Built smss.exe: {} bytes (machine=0x{:x})",
                      smss_image.len(), machine);
        process = create_user_process_with_pe(&smss_image, 0x1F01)
            .unwrap_or(core::ptr::null_mut());
        let _second = create_user_process_with_pe(&smss_image, 0x1F02)
            .unwrap_or(core::ptr::null_mut());
        boot_println!("Created {} ring3 process(es)",
                      if _second.is_null() { 1 } else { 2 });
    }
    if process.is_null() && RING3_STUB_FALLBACK {
        boot_println!("Creating ring3 stub process");
        let pid: u64 = 0x1F00;
        let image: &[u8] = b"\\SystemRoot\\System32\\ring3_stub.exe";
        let p = crate::ps::process::create_user_process(
            image,
            pid,
            Some(crate::userspace::minimal_stub::USER_ENTRY_RIP),
        )
        .unwrap_or_else(|| {
            boot_println!("FATAL: create_user_process (stub) returned None");
            loop { crate::arch::halt(); }
        });
        process = p as *mut Eprocess;
        if !crate::userspace::minimal_stub::install_into_pml4(unsafe { (*process).pml4_phys }) {
            boot_println!("FATAL: install_into_pml4 failed");
            loop { crate::arch::halt(); }
        }
    }
    if process.is_null() {
        boot_println!("FATAL: no user process was created");
        loop { crate::arch::halt(); }
    }

    let pml4_phys = unsafe { (*process).pml4_phys };
    let user_rip = unsafe { (*process).user_rip };
    let user_rsp = unsafe { (*process).user_rsp };
    let main_thread = unsafe { (*process).main_thread };
    boot_println!("User process: PML4=0x{:x} RIP=0x{:x} RSP=0x{:x}",
                  pml4_phys, user_rip, user_rsp);

    if !main_thread.is_null() {
        crate::ke::scheduler::setup_bsp(main_thread);
        let cur = crate::ps::thread::KeGetCurrentEthread();
        boot_println!("setup_bsp done; KeGetCurrentEthread=0x{:x}", cur as u64);
    } else {
        boot_println!("WARNING: process has no main_thread");
    }

    boot_println!("Dispatching into Ring 3...");
    crate::arch::x86_64::user_entry::enter_first_user_thread(pml4_phys, user_rip, user_rsp);
}

