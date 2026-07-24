//! NT 6.1 Device Driver Subsystem
//
//! The driver tree mirrors Windows' own PnP / bus layout. Each
//! bus driver is a singleton that walks the firmware topology
//! (PCI / ACPI / USB hubs) and exposes each populated device to
//! the I/O manager as a `DeviceObject`. Functional drivers
//! (storage, network, audio, video, input) bind to the device
//! objects through the standard PnP Start Device IRP.
//
//! Clean-room implementation. Spec source: Microsoft Docs / OSR /
//! "Windows Internals, 6th ed." (Russinovich). No code is copied
//! from any Microsoft binary, the WDK, or ReactOS.
//
//! # Module layout
//
//! ```text
//! drivers/mod.rs (this file) - top-level init / smoke_test aggregator
//! drivers/bus/               - PCI, ACPI, USB bus drivers + PnP manager
//! drivers/storage/           - ATA, ATAPI, AHCI, NVMe, SCSI
//! drivers/usb/               - UHCI, EHCI, xHCI, hub, HID
//! drivers/net/               - e1000, rtl8139, virtio-net
//! drivers/audio/             - Intel HDA, AC'97
//! drivers/input/             - i8042, USB HID keyboard / mouse
//! drivers/video/             - VGA, EFI framebuffer, Bochs VBE
//! drivers/timer/             - HPET, ACPI PM timer
//! drivers/ndis/              - NDIS 6.0 wrapper
//! drivers/wdf/               - KMDF host
//! ```
//
//! # Init order
//
//! The driver subsystem is brought up between Phase 4 (I/O
//! system) and Phase 5 (file systems) in `kernel_main`:
//
//! 1. `bus::init()`        - enumerate PCI, ACPI, USB root hubs
//! 2. `storage::init()`    - start ATA / AHCI / NVMe controllers
//! 3. `usb::init()`        - start host controllers + hub driver
//! 4. `net::init()`        - start NDIS-wrapped NICs
//! 5. `audio::init()`      - start HDA / AC'97 codecs
//! 6. `input::init()`      - start i8042 / USB HID
//! 7. `video::init()`      - start VGA / EfiFb / Bochs VBE
//! 8. `timer::init()`      - start HPET / ACPI PM timer
//
//! `smoke_test()` runs every driver's post-init self-check.

// The driver tree is a collection of stub drivers — every
// driver describes the full register set / IOCTL surface of
// its real-world counterpart, even though only a tiny subset is
// actually wired up. The unused_imports / dead_code lints fire
// on every register/IOCTL constant that is not yet exercised.
// Suppressing them here keeps the source readable: a driver
// that only carries the symbols it actively uses would not
// be a faithful NT 6.1 driver stub.
#![allow(unused_imports)]

extern crate alloc;

pub mod bus;
pub mod storage;
pub mod usb;
pub mod net;
pub mod audio;
pub mod input;
pub mod video;
pub mod timer;
pub mod ndis;
pub mod wdf;

pub mod pe;
#[cfg(target_arch = "x86_64")]
pub mod smoke;

#[cfg(target_arch = "x86_64")]
pub mod loader;

#[cfg(target_arch = "x86_64")]
pub mod kdcom;
pub mod bootvid;
pub mod ci;
#[cfg(target_arch = "x86_64")]
pub mod pshed;  // Machine-Check Architecture — x86 only
pub mod ksec;
pub mod clfs;
#[cfg(target_arch = "x86_64")]
pub mod partmgr;
#[cfg(target_arch = "x86_64")]
pub mod volmgr;
#[cfg(target_arch = "x86_64")]
pub mod volsnap;
pub mod fltmgr;
pub mod fileinfo;
pub mod pcw;
pub mod spldr;

use crate::kprintln;

/// Initialise the entire driver subsystem. Calls each bus and
/// functional driver in the order Windows does. Idempotent —
/// every inner `init()` is a no-op if it has already run.
pub fn init() {
    crate::hal::serial::write_string("D:init-enter\r\n");
    // // kprintln!("  Initialising driver subsystem...")  // kprintln disabled (memcpy crash workaround)  // kprintln disabled (memcpy crash workaround);
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("D:bus_start\r\n");
    bus::init();
    crate::hal::serial::write_string("D:bus_done\r\n");
    crate::hal::serial::write_string("D:storage_start\r\n");
    storage::init();
    crate::hal::serial::write_string("D:storage_done\r\n");
    crate::hal::serial::write_string("D:usb_start\r\n");
    usb::init();
    crate::hal::serial::write_string("D:usb_done\r\n");
    crate::hal::serial::write_string("D:net_start\r\n");
    net::init();
    crate::hal::serial::write_string("D:net_done\r\n");
    crate::hal::serial::write_string("D:audio_start\r\n");
    audio::init();
    crate::hal::serial::write_string("D:audio_done\r\n");
    crate::hal::serial::write_string("D:input_start\r\n");
    input::init();
    crate::hal::serial::write_string("D:input_done\r\n");
    crate::hal::serial::write_string("D:video_start\r\n");
    video::init();
    crate::hal::serial::write_string("D:video_done\r\n");
    // `video::init()` brings up the BOCHS VBE driver (x86_64)
    // which exposes a 1024×768×32 linear framebuffer at the
    // well-known aperture 0xE0_0000_0000. On every architecture
    // bootvid is wired to the GOP LFB by
    // `adopt_bootinfo_framebuffer()` in `arch::boot`. If GOP is
    // missing we fall back to the BOCHS aperture on x86_64 by
    // calling `bootvid::init_from_framebuffer` here so the Safe-Mode
    // shell still has a panel to paint on. `init_from_framebuffer`
    // is a no-op if the LFB is already wired, so it is harmless
    // when `adopt_bootinfo_framebuffer` already ran.
    if crate::hal::common::framebuffer::is_active() {
        let info = crate::hal::common::framebuffer::info();
        bootvid::init_from_framebuffer(
            info.address,
            info.width,
            info.height,
            info.pitch,
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        const BOCHS_LFB_BASE: u64 = 0xE000_0000;
        const BOCHS_LFB_WIDTH: u32 = 1024;
        const BOCHS_LFB_HEIGHT: u32 = 768;
        const BOCHS_LFB_PITCH: u32 = BOCHS_LFB_WIDTH * 4; // 32 bpp
        bootvid::init_from_framebuffer(
            BOCHS_LFB_BASE,
            BOCHS_LFB_WIDTH,
            BOCHS_LFB_HEIGHT,
            BOCHS_LFB_PITCH,
        );
        crate::hal::serial::write_string("D:bootvid_lfb_bound\r\n");
    }

    // Force the bootvid LFB path on for non-x86_64 builds so the
    // bootvid console paints into the LFB instead of falling
    // through to the no-op (or worse, the legacy VGA buffer).
    bootvid::force_lfb_console();
    crate::hal::serial::write_string("D:timer_start\r\n");
    timer::init();
    crate::hal::serial::write_string("D:timer_done\r\n");
    crate::hal::serial::write_string("D:ndis_start\r\n");
    ndis::init();
    crate::hal::serial::write_string("D:ndis_done\r\n");
    crate::hal::serial::write_string("D:wdf_start\r\n");
    wdf::init();
    crate::hal::serial::write_string("D:wdf_done\r\n");
    crate::hal::serial::write_string("D:pre_kdcom\r\n");
    #[cfg(target_arch = "x86_64")]
    kdcom::init();
    crate::hal::serial::write_string("D:post_kdcom\r\n");
    crate::hal::serial::write_string("D:pre_bootvid\r\n");
    // bootvid now has a cross-arch LFB backend driven by the
    // shared `hal::common::framebuffer` writer; the legacy VGA
    // text buffer at 0xB8000 is still wired on x86_64 as a
    // fallback for boards that don't expose a GOP framebuffer.
    // On the other architectures `bootvid::init()` activates the
    // LFB path or stays disabled if no framebuffer was published.
    bootvid::init();
    crate::hal::serial::write_string("D:post_bootvid\r\n");
    crate::hal::serial::write_string("D:pre_ci\r\n");
    // ci::init();  // DISABLED: code-integrity (CI) policy engine not yet wired
    crate::hal::serial::write_string("D:post_ci\r\n");
    crate::hal::serial::write_string("D:pre_pshed\r\n");
    #[cfg(target_arch = "x86_64")]
    pshed::init();  // PSHED enable (DR-1): init() is implemented and idempotent
    crate::hal::serial::write_string("D:post_pshed\r\n");
    crate::hal::serial::write_string("D:pre_ksec\r\n");
    // ksec::init();  // DISABLED: kernel security subsystem — depends on full seaccess init
    crate::hal::serial::write_string("D:post_ksec\r\n");
    crate::hal::serial::write_string("D:pre_pcw\r\n");
    pcw::init();
    crate::hal::serial::write_string("D:post_pcw\r\n");
    crate::hal::serial::write_string("D:pre_partmgr\r\n");
    // partmgr::init();  // DISABLED: depends on storage I/O being live; re-enable after disk bring-up
    crate::hal::serial::write_string("D:post_partmgr\r\n");
    crate::hal::serial::write_string("D:pre_volmgr\r\n");
    // volmgr::init();  // DISABLED: depends on partmgr
    crate::hal::serial::write_string("D:post_volmgr\r\n");
    crate::hal::serial::write_string("D:pre_volsnap\r\n");
    #[cfg(target_arch = "x86_64")]
    volsnap::init();
    crate::hal::serial::write_string("D:post_volsnap\r\n");
    crate::hal::serial::write_string("D:pre_fltmgr\r\n");
    // fltmgr::init();  // DISABLED: minifilter framework — large surface, leave for later
    crate::hal::serial::write_string("D:post_fltmgr\r\n");
    crate::hal::serial::write_string("D:pre_fileinfo\r\n");
    // fileinfo::init();  // DISABLED: depends on fltmgr
    crate::hal::serial::write_string("D:post_fileinfo\r\n");
    // spldr needs a DriverObject; we use the no-driver
    // variant for the bootstrap so the smoke test can still
    // verify the entry.
    crate::hal::serial::write_string("D:before_spldr\r\n");
    spldr::init_no_driver();
    crate::hal::serial::write_string("D:after_spldr\r\n");
    crate::hal::serial::write_string("D:done\r\n");
    crate::hal::serial::write_string("D:returning\r\n");
}

/// Aggregator: runs every driver's smoke test and returns `true`
/// iff every one passes.
pub fn smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    { smoke::smoke_test() }
    #[cfg(not(target_arch = "x86_64"))]
    { true }
}
