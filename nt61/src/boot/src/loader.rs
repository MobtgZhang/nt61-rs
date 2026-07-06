//! Kernel Loader
//
//! Loads the kernel image (ntoskrnl.exe) from the EFI System Partition
//! and starts it. In the real Windows 7 boot sequence, BOOTMGR loads
//! winload.efi, which in turn parses BCD and loads ntoskrnl.exe.
//! For our bootstrap we combine the responsibilities: the bootmgr
//! reads the kernel file directly off the FAT32 ESP and jumps to
//! its entry point.

use uefi::prelude::*;
use uefi::proto::console::text::Output;
use uefi::proto::media::file::{File, FileAttribute, FileMode, FileSystem};
use uefi::table::boot::*;
use crate::bcd::BootEntry;

/// Errors raised by the loader.
#[derive(Debug)]
pub enum BootError {
    FileNotFound,
    InvalidFormat,
    LoadFailed,
    MemoryAllocationFailed,
    ProtocolNotFound,
    ImageStartFailed,
}

/// Number of pages we reserve for the kernel heap. The kernel itself
/// uses a few MB during early boot; we keep headroom for the file
/// system cache, the pool, and the MFT.
const KERNEL_PAGES: usize = 1024;

/// Load and start the kernel.
///
/// `boot_services` is needed to allocate pages and to start the image.
/// `output` is the console output protocol so we can print a banner.
pub fn load_and_boot_kernel(
    boot_services: &BootServices,
    output: &mut Output,
    entry: &BootEntry,
) -> Result<(), BootError> {
    let _ = output;
    let _ = entry;

    // Locate the file system protocol.
    let handles = boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&FileSystem::GUID))
        .map_err(|_| BootError::ProtocolNotFound)?;

    let mut found_image: Option<alloc::vec::Vec<u8>> = None;

    for handle in handles.iter() {
        if let Ok(fs) = boot_services.open_protocol::<FileSystem>(
            *handle,
            Handle::current(),
            Attributes::ENUMERATE,
        ) {
            if let Ok(root) = fs.open_volume() {
                // Try several well-known paths for ntoskrnl.exe.
                let paths = ["\\EFI\\Boot\\ntoskrnl.exe", "\\Windows\\System32\\ntoskrnl.exe"];
                for path in &paths {
                    let name = match uefi::CString16::try_from(*path) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if let Ok(mut file) = root.open(name, FileMode::Read, FileAttribute::READ_ONLY) {
                        let mut data = alloc::vec::Vec::new();
                        if file.read_to_end(&mut data).is_ok() && !data.is_empty() {
                            found_image = Some(data);
                            break;
                        }
                    }
                }
            }
        }
        if found_image.is_some() {
            break;
        }
    }

    let image = found_image.ok_or(BootError::FileNotFound)?;
    log::info_print(output, "Loaded ntoskrnl.exe image");

    // Allocate pages for the kernel.
    let pages = boot_services
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, KERNEL_PAGES)
        .map_err(|_| BootError::MemoryAllocationFailed)?;

    // Copy the image into the allocated pages (header validation is
    // skipped - the production loader is a real PE parser).
    let dst = pages as *mut u8;
    for (i, b) in image.iter().enumerate() {
        unsafe { core::ptr::write_volatile(dst.add(i), *b) };
    }

    // Drop file system protocols before ExitBootServices - the UEFI
    // spec is strict about this.
    drop(handles);

    // Handoff to the kernel. We just spin here because a real
    // `ExitBootServices` would invalidate every UEFI handle we hold.
    log::info_print(output, "Jumping to kernel entry");
    unsafe {
        let entry_point: extern "C" fn() -> ! = core::mem::transmute(dst);
        entry_point();
    }
}

mod log {
    use uefi::proto::console::text::Output;
    pub fn info_print(out: &mut Output, msg: &str) {
        let _ = out.output_string(alloc::string::String::from(msg).as_str());
    }
}
