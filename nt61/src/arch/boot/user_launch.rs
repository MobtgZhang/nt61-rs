//! Ring-3 user-mode launch path (SMSS / CSRSS / wininit / cmd.exe).

use crate::boot_println;

/// Build the Safe-Mode `C:\Windows\System32\cmd.exe` image and
/// transfer control to its entry point in Ring 3.
///
/// On every architecture where the user-mode hand-off is not
/// implemented this returns `false` so the kernel-side CMD shell
/// (or Safe-Mode debug) can take over.
pub fn try_launch_cmd_exe() -> bool {
    boot_println!("[SAFE-CMD] Windows 7 Boot Sequence (No Desktop Mode)");
    crate::servers::smss::run();
    boot_println!("[SAFE-CMD] smss::run() returned without entering Ring 3");
    false
}

/// Launch CSRSS for Session 0
#[cfg(target_arch = "x86_64")]
pub fn launch_csrss_session_0(
) -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
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
pub fn launch_csrss_session_1(
) -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
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
pub fn launch_wininit_exe(
) -> Result<crate::servers::smss::SystemExeLoadResult, crate::servers::smss::ExeLoadError> {
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
pub const CMD_EXE_DISK_PATH: &str = "C:\\Windows\\System32\\cmd.exe";

/// Load the Safe-Mode `cmd.exe` user-mode image directly from the
/// mounted system partition. The correct filesystem driver is selected
/// at runtime by probing the system partition's boot sector (not by
/// guessing from the build variant), matching how `mount_system_partition`
/// works during `fs::init`.
///
/// Returns the raw file bytes wrapped in a `Vec<u8>`. The image must
/// be a valid PE32+ — the loader will reject it otherwise.
pub fn load_cmd_exe_from_disk() -> Result<core::mem::ManuallyDrop<alloc::vec::Vec<u8>>, &'static str>
{
    boot_println!(
        "[SAFE-CMD] load_cmd_exe_from_disk: target = {}",
        CMD_EXE_DISK_PATH
    );

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
                        boot_println!(
                            "[SAFE-CMD] FAT32 cmd.exe entry: cluster={} size={}",
                            cluster,
                            size
                        );
                        // Allocate via the kernel pool instead of KernelHeap so
                        // we side-step the same SIMD-alignment / Stack-Fault
                        // class of issues we hit with the system exes. We
                        // reuse the trick from `read_pe_from_fat32_impl`:
                        // grab a pool buffer, hand it to the FAT32 read
                        // routine, and return it wrapped in `ManuallyDrop`
                        // so the kernel heap never sees a free() for it.
                        let ptr =
                            crate::mm::pool::allocate(crate::mm::pool::PoolType::NonPaged, size);
                        if ptr.is_null() {
                            boot_println!(
                                "[SAFE-CMD] pool alloc failed for cmd.exe ({} bytes)",
                                size
                            );
                            return Err("pool alloc failed");
                        }
                        let mut buf_slice = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
                        match crate::fs::fat32::read_file(fs, cluster, size as u32, &mut buf_slice)
                        {
                            Ok(n) if n >= 2 && buf_slice[0] == b'M' && buf_slice[1] == b'Z' => {
                                boot_println!("[SAFE-CMD] FAT32 cmd.exe read OK ({} bytes)", n);
                                let mut v =
                                    unsafe { alloc::vec::Vec::from_raw_parts(ptr, n, size) };
                                v.truncate(n);
                                return Ok(core::mem::ManuallyDrop::new(v));
                            }
                            Ok(n) => {
                                boot_println!(
                                    "[SAFE-CMD] FAT32 cmd.exe {} bytes but MZ mismatch",
                                    n
                                );
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
                    boot_println!(
                        "[SAFE-CMD] NTFS load failed: {} (no fallback — cmd.exe must live on disk)",
                        e
                    );
                    return Err(e);
                }
            }
        }
        // EXT2/3/4 system partition — load cmd.exe through the
        // ext driver. The "pre-flight guard" that used to skip
        // this path with `Err(known to fault)` has been removed;
        // the disk read goes through `read_whole_file` which the
        // ext2 driver handles directly.
        //
        // The ext2 filesystem driver ships only on x86_64 right
        // now (the storage stack that bridges ramdisk reads is
        // still being ported). On aarch64 / riscv64 /
        // loongarch64 the kernel reaches the cmd.exe via NTFS
        // or FAT32 (the Makefile images are produced on the
        // host, which is x86_64, and the ext2 driver runs there).
        #[cfg(target_arch = "x86_64")]
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
                    boot_println!(
                        "[SAFE-CMD] EXT read_whole_file({}) failed: {}",
                        CMD_EXE_DISK_PATH,
                        e
                    );
                    return Err("EXT cmd.exe read failed");
                }
            }
        }
        // On non-x86_64 builds the ext2 driver is not compiled in,
        // so the FsType::Ext* variants above are absent. The
        // wildcard arm lets the match stay exhaustive without
        // dragging the ext2/3/4 paths onto architectures where
        // the driver doesn't exist yet.
        #[cfg(not(target_arch = "x86_64"))]
        crate::fs::FsType::Ext2 | crate::fs::FsType::Ext3 | crate::fs::FsType::Ext4 => {
            boot_println!("[SAFE-CMD] EXT cmd.exe load not supported on this arch");
        }
        // Fallback for all filesystems: cmd.exe must be on disk.
        // No in-binary / system_image fallback path remains.
        crate::fs::FsType::Unknown => {
            boot_println!("[SAFE-CMD] system partition type is unknown, refusing fallback");
        }
    }

    boot_println!("[SAFE-CMD] FATAL: no cmd.exe loaded from disk; refusing fallback");
    Err("cmd.exe not loaded from any filesystem")
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
/// failure. cmd.exe MUST come from the on-disk NTFS partition —
/// there is no longer an in-memory fallback path.
pub fn try_load_cmd_exe_from_ntfs(
) -> Result<core::mem::ManuallyDrop<alloc::vec::Vec<u8>>, &'static str> {
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
    if read_total < 2 || unsafe { *ptr } != b'M' || unsafe { *ptr.add(1) } != b'Z' {
        return Err("NTFS cmd.exe MZ mismatch");
    }
    let mut v = unsafe { alloc::vec::Vec::from_raw_parts(ptr, read_total, total_size) };
    v.truncate(read_total);
    Ok(core::mem::ManuallyDrop::new(v))
}

/// create a user-mode process and load a PE image into its per-process
/// PML4 in one step.
///
/// Drives the architecture-common PE-loader path
/// (`loader::load_into_user_address_space`). The process and page-root
/// types are shared by all supported architectures; the actual
/// privilege transition is delegated to `arch::common::user_entry`.
pub fn create_user_process_with_pe(
    image: &[u8],
    pid: u64,
) -> Option<*mut crate::ps::process::Eprocess> {
    {
        boot_println!("[SAFE-CMD] create_user_process_with_pe: A (calling create_user_process)");
        let process = match crate::ps::process::create_user_process(image, pid, None) {
            Some(process) => process as *mut crate::ps::process::Eprocess,
            None => {
                boot_println!("[SAFE-CMD] create_user_process returned None");
                return None;
            }
        };
        let root_table_phys = unsafe { (*process).pml4_phys };
        if root_table_phys == 0 {
            boot_println!("[SAFE-CMD] create_user_process_with_pe: root_table_phys=0");
            return None;
        }
        let mapping = match crate::loader::load_into_user_address_space(root_table_phys, image) {
            Some(mapping) => mapping,
            None => {
                boot_println!("[SAFE-CMD] load_into_user_address_space returned None");
                return None;
            }
        };
        unsafe {
            (*process).user_rip = mapping.entry_point;
            (*process).user_image_base = mapping.image_base;
            (*process).user_image_size = mapping.image_size;
        }
        Some(process)
    }
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
/// The function dispatches to the per-arch implementation
/// (`arch::<arch>::user_entry::enter_first_user_thread`) which
/// performs the actual EL0/U-mode/PLV0 transition via `eret` /
/// `sret` / `ertn` (or `iretq` on x86_64).
pub fn enter_first_user_thread() -> ! {
    crate::arch::common::user_entry::enter_first_stub_process()
}
