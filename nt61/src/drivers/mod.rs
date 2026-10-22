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

extern crate alloc;

pub mod arch;

pub mod audio;
pub mod bus;
pub mod input;
pub mod ndis;
pub mod net;
pub mod storage;
pub mod timer;
pub mod usb;
pub mod video;
pub mod virtio;
pub mod wdf;

pub mod pe;

pub mod bootvid;
pub mod ci;
pub mod clfs;
pub mod fileinfo;
pub mod fltmgr;
pub mod ksec;
pub mod partmgr;
pub mod pcw;
pub mod spldr;
pub mod volmgr;
pub mod volsnap;

/// Initialise the entire driver subsystem. Calls each bus and
/// functional driver in the order Windows does. Idempotent —
/// every inner `init()` is a no-op if it has already run.
pub fn init() {
    crate::hal::serial::write_string_always("D:init-enter\r\n");
    // // kprintln!("  Initialising driver subsystem...");
    bus::init();
    crate::hal::serial::write_string_always("D:bus_done\r\n");
    crate::hal::serial::write_string_always("D:storage_start\r\n");
    storage::init();
    crate::hal::serial::write_string_always("D:storage_done\r\n");
    crate::hal::serial::write_string_always("D:usb_start\r\n");
    usb::init();
    crate::hal::serial::write_string_always("D:usb_done\r\n");
    crate::hal::serial::write_string_always("D:net_start\r\n");
    net::init();
    crate::hal::serial::write_string_always("D:net_done\r\n");
    crate::hal::serial::write_string_always("D:audio_start\r\n");
    audio::init();
    crate::hal::serial::write_string_always("D:audio_done\r\n");
    crate::hal::serial::write_string_always("D:input_start\r\n");
    input::init();
    crate::hal::serial::write_string_always("D:input_done\r\n");
    crate::hal::serial::write_string_always("D:video_start\r\n");
    video::init();
    crate::hal::serial::write_string_always("D:video_done\r\n");
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
        bootvid::init_from_framebuffer(info.address, info.width, info.height, info.pitch);
    }
    arch::init_machine_specific_drivers();

    // Force the bootvid LFB path on for non-x86_64 builds so the
    // bootvid console paints into the LFB instead of falling
    // through to the no-op (or worse, the legacy VGA buffer).
    bootvid::force_lfb_console();
    crate::hal::serial::write_string_always("D:timer_start\r\n");
    timer::init();
    crate::hal::serial::write_string_always("D:timer_done\r\n");
    crate::hal::serial::write_string_always("D:ndis_start\r\n");
    ndis::init();
    crate::hal::serial::write_string_always("D:ndis_done\r\n");
    crate::hal::serial::write_string_always("D:wdf_start\r\n");
    wdf::init();
    crate::hal::serial::write_string_always("D:wdf_done\r\n");
    crate::hal::serial::write_string_always("D:pre_kdcom\r\n");
    crate::hal::serial::write_string_always("D:post_kdcom\r\n");
    crate::hal::serial::write_string_always("D:pre_bootvid\r\n");
    // bootvid now has a cross-arch LFB backend driven by the
    // shared `hal::common::framebuffer` writer; the legacy VGA
    // text buffer at 0xB8000 is still wired on x86_64 as a
    // fallback for boards that don't expose a GOP framebuffer.
    // On the other architectures `bootvid::init()` activates the
    // LFB path or stays disabled if no framebuffer was published.
    bootvid::init();
    crate::hal::serial::write_string_always("D:post_bootvid\r\n");
    crate::hal::serial::write_string_always("D:pre_ci\r\n");
    // ci::init();  // DISABLED: code-integrity (CI) policy engine not yet wired
    crate::hal::serial::write_string_always("D:post_ci\r\n");
    crate::hal::serial::write_string_always("D:pre_pshed\r\n");
    crate::hal::serial::write_string_always("D:post_pshed\r\n");
    crate::hal::serial::write_string_always("D:pre_ksec\r\n");
    // ksec::init();  // DISABLED: kernel security subsystem — depends on full seaccess init
    crate::hal::serial::write_string_always("D:post_ksec\r\n");
    crate::hal::serial::write_string_always("D:pre_pcw\r\n");
    pcw::init();
    crate::hal::serial::write_string_always("D:post_pcw\r\n");
    crate::hal::serial::write_string_always("D:pre_partmgr\r\n");
    // partmgr::init();  // DISABLED: depends on storage I/O being live; re-enable after disk bring-up
    crate::hal::serial::write_string_always("D:post_partmgr\r\n");
    crate::hal::serial::write_string_always("D:pre_volmgr\r\n");
    // volmgr::init();  // DISABLED: depends on partmgr
    crate::hal::serial::write_string_always("D:post_volmgr\r\n");
    crate::hal::serial::write_string_always("D:pre_volsnap\r\n");
    crate::hal::serial::write_string_always("D:post_volsnap\r\n");
    crate::hal::serial::write_string_always("D:pre_fltmgr\r\n");
    // fltmgr::init();  // DISABLED: minifilter framework — large surface, leave for later
    crate::hal::serial::write_string_always("D:post_fltmgr\r\n");
    crate::hal::serial::write_string_always("D:pre_fileinfo\r\n");
    // fileinfo::init();  // DISABLED: depends on fltmgr
    crate::hal::serial::write_string_always("D:post_fileinfo\r\n");
    // spldr needs a DriverObject; we use the no-driver
    // variant for the bootstrap so the smoke test can still
    // verify the entry.
    crate::hal::serial::write_string_always("D:before_spldr\r\n");
    spldr::init_no_driver();
    crate::hal::serial::write_string_always("D:after_spldr\r\n");
    crate::hal::serial::write_string_always("D:done\r\n");
    crate::hal::serial::write_string_always("D:returning\r\n");
}

/// Aggregator: runs every driver's smoke test and returns `true`
/// iff every one passes.
pub fn smoke_test() -> bool {
    arch::smoke_test()
}

pub mod acpi;
pub mod common;
pub mod dispatch;
pub mod keyboard;
pub mod mouse;
pub mod ntfs;
pub mod pci;
pub mod serial;
pub mod tcpip;
