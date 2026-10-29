//! NT6.1.7601 UEFI Boot Manager
//
//! Renders a faithful Windows 7 bootmgr-style graphical UI via GOP:
//
//!   * full-screen black background with two horizontal gray bars
//!     (top: "Windows Boot Manager" / bottom: ENTER / TAB / ESC hints)
//!   * GOP graphics mode at 1024x768 (or highest available)
//!   * boot entries with highlight bar, selected row inverts to blue-on-white
//!     and prepends a ">" chevron
//!   * an F8 key switches to the "Advanced Boot Options" submenu
//!   * keyboard input handled via Console Text Protocol while rendering via GOP

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

/// Boot-manager global allocator.
///
/// The `uefi` crate's `global_allocator` feature must stay disabled in this
/// workspace: the same `uefi` build is shared with `nt61-winload`, which
/// registers its own `HybridAllocator`. With feature unification the uefi
/// helper allocator would conflict with it (two `#[global_allocator]`s in the
/// final binary). This thin wrapper forwards to the uefi pool allocator
/// directly, keeping identical semantics (UEFI boot-services pool
/// allocations) without the feature-level registration.
#[cfg(not(test))]
struct BootmgrAllocator;

#[cfg(not(test))]
#[global_allocator]
static BOOTMGR_ALLOCATOR: BootmgrAllocator = BootmgrAllocator;

#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for BootmgrAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        uefi::allocator::Allocator.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        uefi::allocator::Allocator.dealloc(ptr, layout)
    }
}

/// Host builds (`cargo check/test` on the developer Linux target) link
/// `std` anyway — workspace feature unification pulls it in through
/// `uefi → bitflags ← rustix` when dev-dependencies are built alongside
/// `--all-targets`. Link it explicitly here so the build is deterministic
/// in both modes and `std` provides the `panic_impl` lang item.
#[cfg(all(not(test), target_os = "linux"))]
extern crate std;

/// Boot-manager-local panic policy.  Real firmware targets have no `std`,
/// so the panic handler must live in this crate there. A boot-manager panic
/// is a firmware-session failure: write a minimal crash line to the
/// platform serial port (no allocation, no console state, no locks)
/// before halting, so panics remain observable on real hardware.
#[cfg(all(not(test), not(target_os = "linux")))]
#[panic_handler]
fn bootmgr_panic(info: &core::panic::PanicInfo) -> ! {
    // Minimal crash log before halting: write straight to the
    // platform serial port through the crate's existing raw sink.
    // The sink itself may be feature-gated (e.g. `log_level_debug`
    // on some architectures); the halt below is unconditional.
    use core::fmt::Write as _;

    struct PanicSerial;
    impl core::fmt::Write for PanicSerial {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            crate::arch::current::write_com1_marker(s.as_bytes());
            Ok(())
        }
    }

    let mut sink = PanicSerial;
    let _ = sink.write_str("\r\n[BOOTMGR-PANIC] ");
    let _ = sink.write_fmt(core::format_args!("{}\r\n", info));

    loop {
        core::hint::spin_loop();
    }
}

#[macro_export]
macro_rules! debug_println {
    ($fmt:expr $(, $arg:expr)*) => {{
        use ::alloc::format;
        crate::arch::current::write_com1_marker(
            format!("{}\r\n", format!($fmt, $($arg),*)).as_bytes(),
        );
        #[cfg(not(feature = "log_level_debug"))]
        if false {
            uefi::println!($fmt, $($arg),*);
        }
        #[cfg(feature = "log_level_debug")]
        {
            uefi::println!($fmt, $($arg),*);
        }
    }};
}

mod acpi;
mod arch;
mod bcd;
mod bcd_parser;
mod bcd_registry;
mod ext4_boot;
mod fat32_boot;
mod fat_lfn;
mod font;
mod graphics;
mod input;
mod loader;
mod menu;
mod renderer;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bcd::BcdStore;
use menu::BootMenu;
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::console::text::{Key, ScanCode};
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::CString16;

use crate::font::BitmapFont;
use crate::graphics::FramebufferInfo;
use crate::renderer::Framebuffer;

/// Allocate a zero-initialized byte buffer of `len` bytes, returning
/// `None` instead of panicking when the UEFI allocator cannot satisfy
/// the request. Callers either degrade or report an explicit failure.
fn try_alloc_zeroed(len: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(len).ok()?;
    buf.resize(len, 0u8);
    Some(buf)
}

// =====================================================================
// Partition-type probe (used by the file dispatchers below)
// =====================================================================

/// Filesystem type detected by [`probe_partition_type`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PartitionType {
    /// NTFS — VBR OEM ID or a GPT entry with the Windows basic-data
    /// GUID. `partition_start_lba` is the disk-relative LBA of the NTFS
    /// partition's first sector (0 for a partition-level handle, the
    /// GPT-supplied start LBA for a disk-level handle).
    Ntfs { partition_start_lba: u64 },
    /// EXT4 — superblock magic `0xEF53` or a GPT entry with the Linux
    /// filesystem GUID. `partition_start_lba` has the same semantics as
    /// the NTFS case.
    Ext4 { partition_start_lba: u64 },
    /// FAT12/16/32 — the firmware exposes a working `SimpleFileSystem`
    /// protocol on this handle. The boot manager reads ESP files via
    /// the standard EFI file API, and serves a FAT32 System partition
    /// through the in-tree reader (symmetric with NTFS / EXT4).
    Fat,
    /// Anything else. The dispatcher skips these handles.
    Unknown,
}

/// EXT4 superblock magic at offset 56 within the superblock (= byte 1080
/// from the start of the partition, since the superblock itself sits at
/// partition byte 1024).
const EXT4_MAGIC: u16 = 0xEF53;

/// Try to open a `SimpleFileSystem` protocol on `handle`. Used by
/// [`probe_partition_type`] to decide whether a handle is FAT (i.e. the
/// firmware understands it natively).
///
/// Returns `true` if the firmware exposes a working SFS protocol on
/// this handle, `false` otherwise. We never return the protocol itself
/// — UEFI protocol wrappers are not `Clone`, and the probe only needs
/// a yes/no answer.
fn has_sfs_protocol(handle: uefi::Handle) -> bool {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    let r = unsafe {
        boot::open_protocol::<uefi::proto::media::fs::SimpleFileSystem>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    matches!(r, Ok(_))
}

// =====================================================================
// BCD Mailbox Constants
// =====================================================================

/// Physical address where BCD mailbox is located.
/// Boot manager writes the selected entry GUID here, and winload reads it.
/// On x86_64 we use a fixed low address (works because the firmware
/// permits access to low memory); on architectures with stricter
/// memory protections (aarch64, riscv64) we allocate a page from the
/// firmware and install its address as a UEFI Configuration Table.
const BCD_MAILBOX_PHYS: u64 = 0x10_100;

/// UEFI Configuration Table GUID that carries the BCD mailbox's
/// physical address. Winload reads this table to discover where
/// the boot manager placed the mailbox. The GUID value is
/// `8BC9C6A0-5B47-4DCA-8E40-DB22CA1D5A6B`, chosen to be distinct
/// from any standard UEFI / NT61 GUID.
const BCD_MAILBOX_TABLE_GUID: uefi::Guid = uefi::Guid::from_bytes([
    0x8B, 0xC9, 0xC6, 0xA0, 0x5B, 0x47, 0x4D, 0xCA, 0x8E, 0x40, 0xDB, 0x22, 0xCA, 0x1D, 0x5A, 0x6B,
]);

/// BCD mailbox signature "BCDE"
const BCD_MAILBOX_SIGNATURE: [u8; 4] = [b'B', b'C', b'D', b'E'];

/// BCD mailbox version for Windows 7
const BCD_MAILBOX_VERSION: u32 = 0x00000003;

/// Vendor GUID for the framebuffer hand-off variable.
const FB_VARIABLE_VENDOR: VariableVendor =
    VariableVendor(uefi::guid!("9d0f7e8a-8d21-4f7f-987f-3c9d0c5f4b61"));
const FB_VARIABLE_NAME: &uefi::CStr16 = uefi::cstr16!("NT61FB");

/// GUID used to expose the framebuffer mailbox through the UEFI
/// Configuration Table. A table entry survives image chain-loading without
/// relying on runtime variable services, which is important for the
/// generic ARM64/RISC-V/LoongArch firmware paths.
const FB_MAILBOX_TABLE_GUID: uefi::Guid = uefi::Guid::from_bytes([
    0x9d, 0x0f, 0x7e, 0x8a, 0x8d, 0x21, 0x4f, 0x7f, 0x98, 0x7f, 0x3c, 0x9d, 0x0c, 0x5f, 0x4b, 0x61,
]);

fn get_boot_entry_descriptions(bcd: &BcdStore) -> alloc::vec::Vec<String> {
    let mut entries = alloc::vec::Vec::new();
    for index in 0..bcd.entry_count {
        if let Some(entry) = bcd.get_entry(index) {
            let description = entry
                .description
                .as_slice()
                .iter()
                .filter(|&&code| code != 0 && code != 0xFF)
                .filter_map(|&code| char::from_u32(code as u32))
                .collect::<String>();
            entries.push(if description.is_empty() {
                String::from("Unknown Entry")
            } else {
                description
            });
        }
    }
    entries
}

fn write_fb_mailbox(info: &FramebufferInfo) {
    let mut payload = [0u8; 40];
    payload[0..4].copy_from_slice(b"FBHM");
    payload[4..8].copy_from_slice(&1u32.to_le_bytes());
    payload[8..16].copy_from_slice(&info.base.to_le_bytes());
    payload[16..24].copy_from_slice(&info.size.to_le_bytes());
    payload[24..28].copy_from_slice(&info.width.to_le_bytes());
    payload[28..32].copy_from_slice(&info.height.to_le_bytes());
    payload[32..36].copy_from_slice(&info.stride.to_le_bytes());
    payload[36..40].copy_from_slice(&1u32.to_le_bytes());

    if let Ok(page) = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::BOOT_SERVICES_DATA,
        1,
    ) {
        let mailbox = page.as_ptr() as *mut u8;
        unsafe {
            core::ptr::write_volatile(mailbox.add(0) as *mut [u8; 40], payload);
            let status = uefi::boot::install_configuration_table(
                &FB_MAILBOX_TABLE_GUID,
                mailbox as *mut core::ffi::c_void,
            );
            uefi::println!(
                "[BOOTMGR] framebuffer mailbox: page=0x{:x} install={:?}",
                mailbox as u64,
                status
            );
        }
    } else {
        uefi::println!("[BOOTMGR] framebuffer mailbox allocation failed");
    }

    let attributes = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;
    let result =
        uefi::runtime::set_variable(FB_VARIABLE_NAME, &FB_VARIABLE_VENDOR, attributes, &payload);
    if let Err(status) = result {
        debug_println!(
            "  [BOOTMGR] framebuffer variable write failed: {:?}",
            status
        );
    }
    debug_println!(
        "  [BOOTMGR] Framebuffer mailbox written: base=0x{:x} {}x{} stride={}",
        info.base,
        info.width,
        info.height,
        info.stride
    );
}

#[derive(Debug)]
enum GraphicsScreen {
    Main { tools_selected: bool },
    Advanced { selected: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdvancedAction {
    Repair,
    SafeMode,
    SafeModeNetworking,
    SafeModeCommandPrompt,
    BootLogging,
    LowResolution,
    LastKnownGood,
    DirectoryServices,
    Debugging,
    DisableAutoRestart,
    DisableDriverSignature,
}

impl AdvancedAction {
    fn boot_options(self) -> Option<&'static str> {
        match self {
            AdvancedAction::SafeMode => Some("/safeboot:minimal"),
            AdvancedAction::SafeModeNetworking => Some("/safeboot:network"),
            AdvancedAction::SafeModeCommandPrompt => Some("/safeboot:minimal /safeboot:shell"),
            AdvancedAction::BootLogging => Some("/bootlog"),
            AdvancedAction::LowResolution => Some("/safeboot:minimal /lowres"),
            AdvancedAction::DirectoryServices => Some("/safeboot:dsrepair"),
            AdvancedAction::Debugging => Some("/debug /debugport=COM1 /baudrate=115200"),
            _ => None,
        }
    }
}

mod colors {
    use crate::renderer::Color;

    pub const BG: Color = Color(0xFF_00_00_00);
    pub const FG: Color = Color(0xFF_C0_C0_C0);
    pub const BAR_BG: Color = Color(0xFF_C0_C0_C0);
    pub const BAR_FG: Color = Color(0xFF_00_00_00);
    pub const SEL_BG: Color = Color(0xFF_C0_C0_C0);
    pub const SEL_FG: Color = Color(0xFF_00_00_00);
}

// =====================================================================
// Low-level text rendering helpers
// =====================================================================

fn draw_gop_main_screen(
    fb: &mut Framebuffer,
    font: &mut BitmapFont,
    entries: &[String],
    selected: usize,
    countdown: u32,
    tools_selected: bool,
) {
    let width = fb.width();
    let height = fb.height();

    fb.fill_rect_fast(0, 0, width, height, colors::BG);

    let title_top = (height as f32 * 0.026) as u32;
    let title_left = (width as f32 * 0.15) as u32;
    let title_right_margin = (width as f32 * 0.147) as u32;
    let title_right = width - title_right_margin;
    let title_height = 32u32;

    fb.fill_rect_fast(
        title_left,
        title_top,
        title_right - title_left,
        title_height,
        colors::BAR_BG,
    );

    let title_text = "Windows Boot Manager";
    let title_y_offset = (title_height - font.line_height()) / 2;
    font.draw_text_centered(
        fb,
        title_text,
        (width / 2) as i32,
        (title_top + title_y_offset) as i32,
        colors::BAR_FG,
        None,
    );

    let body_top = (height as f32 * 0.095) as u32;
    let body_left = (width as f32 * 0.147) as u32;

    let prompt_text = "Choose an operating system to start, or press TAB to select a tool:";
    font.draw_text(
        fb,
        prompt_text,
        body_left as i32,
        body_top as i32,
        colors::FG,
        None,
    );

    let line_height = font.line_height();
    let hint_y = body_top + line_height + 8;
    let hint_text = "(Use the arrow keys to highlight your choice, then press ENTER.)";
    font.draw_text(
        fb,
        hint_text,
        body_left as i32,
        hint_y as i32,
        colors::FG,
        None,
    );

    // === OS LIST ===
    // Width: 78% of available space
    let os_list_top = hint_y + line_height + 16;
    let item_height = line_height + 12;

    for (i, entry) in entries.iter().enumerate() {
        let y = os_list_top + (i as u32) * item_height;
        let is_selected = i == selected && !tools_selected;
        let text_y_offset = (item_height - font.line_height()) / 2;

        if is_selected {
            // Selected: gray background
            let item_width = ((width as f32 * 0.78) - body_left as f32) as u32;
            fb.fill_rect_fast(body_left, y, item_width, item_height - 1, colors::SEL_BG);
            // Chevron ">"
            font.draw_text(
                fb,
                "> ",
                (body_left + 6) as i32,
                (y + text_y_offset) as i32,
                colors::SEL_FG,
                None,
            );
            // Entry text
            font.draw_text(
                fb,
                entry,
                (body_left + 24) as i32,
                (y + text_y_offset) as i32,
                colors::SEL_FG,
                None,
            );
        } else {
            // Not selected: just text
            font.draw_text(
                fb,
                "  ",
                (body_left + 6) as i32,
                (y + text_y_offset) as i32,
                colors::FG,
                None,
            );
            font.draw_text(
                fb,
                entry,
                (body_left + 24) as i32,
                (y + text_y_offset) as i32,
                colors::FG,
                None,
            );
        }
    }

    // === MIDBLOCK ===
    // Position: top: 49%
    let mid_top = (height as f32 * 0.49) as u32;

    // F8 hint
    let f8_text = "To specify an advanced option for this choice, press F8.";
    font.draw_text(
        fb,
        f8_text,
        body_left as i32,
        mid_top as i32,
        colors::FG,
        None,
    );

    // Countdown line - make it prominent
    let count_y = mid_top + line_height + 8;

    // Build countdown string
    let count_text = alloc::format!(
        "Seconds until the highlighted choice will be started: {}",
        countdown
    );
    font.draw_text(
        fb,
        &count_text,
        body_left as i32,
        count_y as i32,
        colors::FG,
        None,
    );

    // === TOOLS SECTION ===
    // Position: below countdown
    let tools_top = count_y + line_height + 24;

    // Tools label
    let tools_label = "Tools:";
    font.draw_text(
        fb,
        tools_label,
        body_left as i32,
        tools_top as i32,
        colors::FG,
        None,
    );

    // Tool item
    let tool_y = tools_top + line_height + 8;
    let tool_text = "Windows Memory Diagnostic";
    let tool_x = body_left + 48; // margin-left: 3em = ~48 pixels at this scale
    let tool_text_y_offset = (line_height + 4 - line_height) / 2;

    if tools_selected {
        let (tool_text_w, _) = font.measure(tool_text);
        fb.fill_rect_fast(
            tool_x - 6,
            tool_y,
            tool_text_w + 12,
            item_height - 1,
            colors::SEL_BG,
        );
        font.draw_text(
            fb,
            tool_text,
            tool_x as i32,
            (tool_y + tool_text_y_offset) as i32,
            colors::SEL_FG,
            None,
        );
    } else {
        font.draw_text(
            fb,
            tool_text,
            tool_x as i32,
            (tool_y + tool_text_y_offset) as i32,
            colors::FG,
            None,
        );
    }

    // === STATUS BAR ===
    // Position: bottom with 3% margin, taller bar
    let margin_bottom = (height as f32 * 0.03) as u32; // 3% bottom margin
    let status_height = 32u32; // Larger status bar
    let status_bottom = height - margin_bottom - status_height;
    let status_left = (width as f32 * 0.15) as u32;
    let status_right = width - title_right_margin;

    fb.fill_rect_fast(
        status_left,
        status_bottom,
        status_right - status_left,
        status_height,
        colors::BAR_BG,
    );

    // Status text: "ENTER=Choose  TAB=Menu  ESC=Cancel"
    let status_left_text = "ENTER=Choose";
    let status_mid_text = "TAB=Menu";
    let status_right_text = "ESC=Cancel";

    let text_y_offset = (status_height - font.line_height()) / 2;
    font.draw_text(
        fb,
        status_left_text,
        (status_left + 10) as i32,
        (status_bottom + text_y_offset) as i32,
        colors::BAR_FG,
        None,
    );
    font.draw_text_centered(
        fb,
        status_mid_text,
        (width / 2) as i32,
        (status_bottom + text_y_offset) as i32,
        colors::BAR_FG,
        None,
    );
    // Right-align the last text
    let (right_text_width, _) = font.measure(status_right_text);
    font.draw_text(
        fb,
        status_right_text,
        (status_right - right_text_width - 10) as i32,
        (status_bottom + text_y_offset) as i32,
        colors::BAR_FG,
        None,
    );
}

/// Windows 7 Advanced Boot Options screen
/// Matches exactly the HTML layout
fn draw_gop_advanced_screen(
    fb: &mut Framebuffer,
    font: &mut BitmapFont,
    entries: &[(AdvancedAction, &str, &str)], // (action, label, description)
    selected: usize,
) {
    let width = fb.width();
    let height = fb.height();

    // Clear to black
    fb.fill_rect_fast(0, 0, width, height, colors::BG);

    // === TITLE BAR ===
    // Position: top: 1.6%, left: 8%, right: 8%
    let title_top = (height as f32 * 0.016) as u32;
    let title_left = (width as f32 * 0.08) as u32;
    let title_right = width - title_left;
    let title_height = font.line_height() + 16;

    fb.fill_rect_fast(
        title_left,
        title_top,
        title_right - title_left,
        title_height,
        colors::BAR_BG,
    );

    let title_text = "Advanced Boot Options";
    let title_y_offset = (title_height - font.line_height()) / 2;
    // Use regular bitmap font for title
    font.draw_text_centered(
        fb,
        title_text,
        (width / 2) as i32,
        (title_top + title_y_offset) as i32,
        colors::BAR_FG,
        None,
    );

    // === HEADER ===
    // Position: top: 9%
    let line_height = font.line_height();
    let header_top = (height as f32 * 0.09) as u32;
    let header_left = (width as f32 * 0.08) as u32;

    let header1 = "Choose Advanced Options for: Windows 7";
    let header2 = "(Use the arrow keys to highlight your choice.)";
    font.draw_text(
        fb,
        header1,
        header_left as i32,
        header_top as i32,
        colors::FG,
        None,
    );
    font.draw_text(
        fb,
        header2,
        header_left as i32,
        (header_top + line_height + 4) as i32,
        colors::FG,
        None,
    );

    // === MENU ITEMS ===
    // Position: top: 20%
    let menu_top = header_top + line_height * 2 + 16;
    let menu_left = (width as f32 * 0.08) as u32;
    let item_height = line_height + 8;

    let mut y = menu_top;
    for (i, (_, label, _desc)) in entries.iter().enumerate() {
        // Gap before certain items (like "Enable Boot Logging" and "Start Windows Normally")
        let has_gap_before = *label == "Enable Boot Logging"
            || *label == "Start Windows Normally"
            || *label == "Disable automatic restart on system failure"
            || *label == "Disable Driver Signature Enforcement";

        if has_gap_before && i > 0 {
            y += line_height; // Add gap
        }

        let is_selected = i == selected;
        let text_y_offset = (item_height - font.line_height()) / 2;

        if is_selected {
            // Selected item: gray background
            // Note: The HTML uses padding-left: 3.4em for text alignment
            let text_x = menu_left + 32; // ~3.4em
            let (text_w, _) = font.measure(label);
            fb.fill_rect_fast(menu_left, y, text_w + 32 + 16, item_height, colors::SEL_BG);
            font.draw_text(
                fb,
                label,
                text_x as i32,
                (y + text_y_offset) as i32,
                colors::SEL_FG,
                None,
            );
        } else {
            let text_x = menu_left + 32;
            font.draw_text(
                fb,
                label,
                text_x as i32,
                (y + text_y_offset) as i32,
                colors::FG,
                None,
            );
        }

        y += item_height;
    }

    // === STATUS BAR === (defined before description panel)
    let margin_bottom = (height as f32 * 0.03) as u32;
    let status_height = 32u32;
    let status_bottom = height - margin_bottom - status_height;
    let desc_left = (width as f32 * 0.08) as u32;
    let desc_right = width - (width as f32 * 0.06) as u32;

    // === DESCRIPTION PANEL ===
    // Position: bottom area, above status bar
    // Two rows: label + text (stacked vertically)
    let char_h = font.line_height() as i32;
    let desc_label_y = (status_bottom as i32 - status_height as i32 - 16 - char_h * 2 - 8) as u32;
    let desc_text_y = desc_label_y + font.line_height() + 4;

    // Clear description area completely (in case old text was longer)
    let desc_area_height =
        (status_bottom as i32 - status_height as i32 - 16 - desc_label_y as i32 + 4) as u32;
    fb.fill_rect_fast(
        desc_left,
        desc_label_y.saturating_sub(4),
        desc_right - desc_left,
        desc_area_height,
        colors::BG,
    );

    // Description label
    let desc_label = "Description:";
    font.draw_text(
        fb,
        desc_label,
        desc_left as i32,
        desc_label_y as i32,
        colors::FG,
        None,
    );

    // Description text with proper word wrapping
    if let Some((_, _, desc)) = entries.get(selected) {
        // Approximate avg char width for word-wrap. With TTF we can
        // measure exact width per word, but that would require a
        // measurement-only pass. A simpler approach: just emit the
        // description across as many lines as we can fit, each line
        // broken on whitespace. We compute the max pixel width per
        // line by assuming a per-glyph width based on font.line_height.
        // TTF characters average around 0.55x the line height for
        // proportional fonts, so use that as a rough heuristic.
        let char_w = ((font.line_height() as f32) * 0.55) as u32;
        let max_chars_per_line = ((desc_right - desc_left - 96) / char_w.max(1)) as usize;
        let mut lines: alloc::vec::Vec<alloc::string::String> = alloc::vec![];
        let mut current_line = alloc::string::String::new();

        for word in desc.split_whitespace() {
            let test_line = if current_line.is_empty() {
                alloc::string::String::from(word)
            } else {
                alloc::format!("{} {}", current_line, word)
            };

            if test_line.chars().count() > max_chars_per_line {
                if !current_line.is_empty() {
                    lines.push(core::mem::take(&mut current_line));
                }
                // Handle long words by wrapping them
                let mut remaining = word;
                while remaining.chars().count() > max_chars_per_line {
                    let wrap_point = remaining
                        .char_indices()
                        .nth(max_chars_per_line)
                        .map(|(i, _)| i)
                        .unwrap_or(remaining.len());
                    lines.push(remaining[..wrap_point].to_string());
                    remaining = &remaining[wrap_point..];
                }
                current_line = remaining.to_string();
            } else {
                current_line = test_line;
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }

        // Draw the lines
        let mut y_pos = desc_text_y as i32;
        let line_spacing = font.line_height() as i32 + 2;
        let max_y = (status_bottom as i32 - status_height as i32 - 16) as i32;
        for line in lines {
            if y_pos + font.line_height() as i32 > max_y {
                // Add ellipsis if no more room
                let ellipsis_line = if line.chars().count() > max_chars_per_line {
                    line.chars()
                        .take(max_chars_per_line.saturating_sub(1))
                        .collect::<alloc::string::String>()
                        + ".."
                } else {
                    line
                };
                font.draw_text(
                    fb,
                    &ellipsis_line,
                    (desc_left + 96) as i32,
                    y_pos,
                    colors::FG,
                    None,
                );
                break;
            }
            font.draw_text(fb, &line, (desc_left + 96) as i32, y_pos, colors::FG, None);
            y_pos += line_spacing;
        }
    }

    // === STATUS BAR ===
    // Position: bottom: 3% margin, total height ~32px
    let margin_bottom = (height as f32 * 0.03) as u32; // 3% bottom margin
    let status_height = 32u32; // Larger status bar
    let status_bottom = height - margin_bottom - status_height; // Top of status bar
    let status_left = (width as f32 * 0.08) as u32;
    let status_right = width - (width as f32 * 0.08) as u32;

    fb.fill_rect_fast(
        status_left,
        status_bottom,
        status_right - status_left,
        status_height,
        colors::BAR_BG,
    );

    let status_left_text = "ENTER=Choose";
    let status_right_text = "ESC=Cancel";

    font.draw_text(
        fb,
        status_left_text,
        (status_left + 10) as i32,
        (status_bottom + 8) as i32,
        colors::BAR_FG,
        None,
    );
    let (right_text_width, _) = font.measure(status_right_text);
    font.draw_text(
        fb,
        status_right_text,
        (status_right - right_text_width - 10) as i32,
        (status_bottom + 8) as i32,
        colors::BAR_FG,
        None,
    );
}

// =====================================================================
// Entry point - GOP Graphics Mode
// =====================================================================

/// Firmware-supplied UEFI image handle, captured at `efi_main` entry so
/// we can re-establish the UEFI calling convention when chaining to
/// `winload.efi`. Storing this in a `static mut` is safe because:
///   1. It is written exactly once at the start of `efi_main`, before
///      any other code path runs.
///   2. It is only read at the very end of the boot flow, just before
///      transferring control to winload, and the read is atomic for our
///      purposes (a torn 64-bit value would still give a usable but
///      stale handle — see comments around the jump site).
///
/// We store the raw `*mut c_void` so we can hand it back to winload
/// unmodified in `%rcx`. The `Handle` wrapper around this pointer has
/// no public accessor for its inner value, so we keep both the raw
/// pointer (for the chain-load) and the `Handle` (for any other code
/// that needs the typed value).
pub static mut BOOT_IMAGE_HANDLE_PTR: *mut core::ffi::c_void = core::ptr::null_mut();

/// Boot options string (e.g. "/safeboot:minimal") set by the F8 advanced
/// boot menu and written into the BCD mailbox by write_bcd_mailbox().
/// UEFI boot is single-threaded so a plain static is safe here.
static mut BOOT_OPTIONS_OVERRIDE: Option<&'static str> = None;

/// Firmware-supplied UEFI system-table pointer. Same rationale as
/// `BOOT_IMAGE_HANDLE_PTR`. The pointer is opaque to us — we just
/// hand it back to winload unmodified so winload can dereference the
/// firmware services it needs.
pub static mut BOOT_SYSTEM_TABLE: u64 = 0;

/// UEFI entry point. The `#[entry]` attribute from the `uefi` crate
/// auto-injects two parameters (`internal_image_handle: Handle` and
/// `internal_system_table: *const c_void`) and captures them into
/// the global system-table pointer so `uefi::boot::*` works for the
/// rest of the boot flow. We additionally stash the firmware-supplied
/// values in the `BOOT_IMAGE_HANDLE_PTR` / `BOOT_SYSTEM_TABLE` statics
/// so we can re-establish the UEFI calling convention when chaining
/// to `winload.efi` at the very end of the boot flow.
#[entry]
fn efi_main() -> Status {
    // The macro inserts `internal_image_handle: Handle` and
    // `internal_system_table: *const c_void` into our parameter list.
    // We need the raw `EFI_HANDLE` pointer (a `*mut c_void`) so we
    // can hand it back to winload in `%rcx`. The `Handle` wrapper is
    // a transparent `NonNull<c_void>` newtype, so `transmute_copy`
    // gives us the inner pointer without any layout assumption.
    unsafe {
        BOOT_IMAGE_HANDLE_PTR = core::mem::transmute_copy::<uefi::Handle, *mut core::ffi::c_void>(
            &internal_image_handle,
        );
        BOOT_SYSTEM_TABLE = internal_system_table as u64;
    }
    efi_main_inner()
}

fn efi_main_inner() -> Status {
    // UEFI Boot Manager entry point - unique signature
    debug_println!("===========================================");
    debug_println!("NT6.1.7601 BOOT MANAGER v1.0 DEBUG");
    debug_println!("===========================================");
    debug_println!("[MAIN] efi_main entered successfully!");
    let ih = unsafe { BOOT_IMAGE_HANDLE_PTR } as u64;
    let st = unsafe { BOOT_SYSTEM_TABLE };
    debug_println!("[MAIN] ImageHandle=0x{:x} SystemTable=0x{:x}", ih, st);

    if let Err(e) = uefi::helpers::init() {
        debug_println!("Warning: helpers init failed: {:?}", e);
    }

    match acpi::parse_firmware_tables() {
        Some(summary) => debug_println!("[ACPI] {}", summary.describe()),
        None => debug_println!("[ACPI] firmware did not publish a valid RSDP"),
    }

    // Expose bootx64.efi through the EFI_LOAD_FILE_PROTOCOL so bootmgfw
    // (or the firmware BDS) can chain-load this boot manager through the
    // standard UEFI LoadFile resolution path. Safe to skip: the direct
    // launch path does not depend on the protocol.
    unsafe {
        let _ = install_bootmgr_load_file_protocol();
    }

    // Invalidate any stale framebuffer hand-off from a previous boot.
    // A fresh value is published only when this boot selects a linear
    // GOP mode, so text-mode fallbacks must not reuse old GPU mappings.
    let _ = uefi::runtime::delete_variable(FB_VARIABLE_NAME, &FB_VARIABLE_VENDOR);

    // Load BCD store from ESP partition - this is a real Windows BCD file
    // written at build time, not a hardcoded in-memory store. The BCD
    // tells bootmgr which winload.efi to chain-load and on which device.
    debug_println!("[BCD] Loading BCD store from ESP...");
    let bcd_store = match load_bcd_from_esp() {
        Ok(store) => {
            debug_println!("[BCD] BCD store loaded successfully");
            store
        }
        Err(e) => {
            debug_println!("[BCD] Failed to load BCD from ESP: {}", e);
            debug_println!("[BCD] Falling back to default in-memory store");
            BcdStore::with_defaults()
        }
    };
    let mut menu = BootMenu::new(&bcd_store);
    debug_println!("[DEBUG] Boot menu created, countdown: {}", menu.countdown());
    let entries = get_boot_entry_descriptions(&bcd_store);
    debug_println!("[DEBUG] Got {} boot entries", entries.len());

    // Initialize GOP graphics mode
    //
    // On most firmwares (x86_64 OVMF, aarch64 ArmVirtQemu) the GOP
    // protocol handle is published during DXE dispatch — usually
    // before BDS calls our boot manager image. Some firmware
    // configurations register GOP later, in particular QEMU's
    // `virt` machine with the VirtioGpuDxe driver: on aarch64 the
    // GOP handle becomes available only after VirtioGpuDxe finishes
    // its PCI enumeration, which can be a few hundred milliseconds
    // after boot.efi runs.
    //
    // We poll here so the aarch64 path goes through the
    // *same* graphics-mode boot menu as x86_64 rather than falling
    // back to the text-mode menu. The polling budget (300 ms × 50
    // = 15 s max) is generous enough for slow emulators (aarch64
    // QEMU's MonolithicFirmware dispatches QemuRamfbDxe lazily).
    // On hardware where GOP is truly unavailable the original
    // fallback path kicks in within that window.
    use uefi::boot as ub;
    debug_println!("[DEBUG] Initializing GOP...");

    let mut gop = None;
    let mut gop_handles = ub::find_handles::<GraphicsOutput>().ok();
    for attempt in 0u32..50 {
        match gop_handles.as_ref() {
            Some(h) if !h.is_empty() => match ub::open_protocol_exclusive::<GraphicsOutput>(h[0]) {
                Ok(g) => {
                    gop = Some(g);
                    if attempt > 0 {
                        debug_println!(
                            "[GOP] GraphicsOutput handle became available after {} polls",
                            attempt
                        );
                    }
                    break;
                }
                Err(e) => {
                    debug_println!(
                        "[GOP] open_protocol_exclusive failed (attempt {}): {:?}",
                        attempt,
                        e
                    );
                }
            },
            Some(_) => {
                if attempt == 0 {
                    debug_println!("[GOP] No GraphicsOutput handles found, polling...");
                }
            }
            None => {
                if attempt == 0 {
                    debug_println!("[BOOT] find_handles returned None, polling for GOP...");
                }
            }
        }
        // Wait ~300ms before retrying — VirtioGpuDxe / QemuRamfbDxe
        // run synchronously inside DXE dispatch and typically finish
        // within the first few hundred ms on x86_64 OVMF, but on
        // aarch64 ArmVirtQemu the MonolithicFirmware dispatches the
        // Ramfb device lazily, so allow up to ~15 s of headroom.
        ub::stall(core::time::Duration::from_millis(300));
        gop_handles = ub::find_handles::<GraphicsOutput>().ok();
    }
    let mut gop = match gop {
        Some(g) => g,
        None => {
            debug_println!(
                "[BOOT] No GOP available after polling - falling back to text mode auto-boot"
            );
            return text_mode_auto_boot(&bcd_store, &entries);
        }
    };

    // Set graphics mode
    let target_modes = [(1024, 768), (800, 600), (640, 480)];
    let mut selected_mode = None;
    for &(tw, th) in &target_modes {
        for mode in gop.modes() {
            let info = mode.info();
            let (w, h) = info.resolution();
            if w == tw && h == th {
                selected_mode = Some(mode);
                break;
            }
        }
        if selected_mode.is_some() {
            break;
        }
    }
    if selected_mode.is_none() {
        selected_mode = gop.modes().next();
    }
    if let Some(mode) = selected_mode {
        let _ = gop.set_mode(&mode);
    }

    // Some EDK2 platforms (notably ArmVirtQemu on aarch64) report a GOP
    // pixel format of `BltOnly`, which means the firmware refuses to expose
    // a linear framebuffer pointer. `frame_buffer()` asserts (panics) in
    // that situation, so we have to inspect the pixel format *before*
    // touching the framebuffer. When the platform only supports Blt, the
    // boot manager falls back to text mode, which never touches GOP.
    if gop.current_mode_info().pixel_format() == PixelFormat::BltOnly {
        debug_println!("[GOP] Framebuffer in Blt-only mode — falling back to text mode");
        return text_mode_auto_boot(&bcd_store, &entries);
    }

    let fb_size = gop.frame_buffer().size();
    let fb_ptr = gop.frame_buffer().as_mut_ptr();
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let stride = info.stride() * 4;

    debug_println!(
        "[GOP] Mode: {}x{} format={:?}",
        width,
        height,
        info.pixel_format()
    );
    debug_println!("[GOP] Framebuffer: {:016x} size={}", fb_ptr as u64, fb_size);

    let fb_info = FramebufferInfo {
        base: fb_ptr as u64,
        size: fb_size as u64,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
    };
    let mut fb = Framebuffer::with_ptr(fb_info, fb_ptr);
    debug_println!("[DEBUG] GOP initialized, fb created");

    // Publish the framebuffer info at a fixed physical address
    // (`FB_MAILBOX_PHYS`) so winload can recover it. Without
    // this, winload fails to open GOP (`ACCESS_DENIED` because
    // bootmgr already opened it exclusively) and the kernel
    // has no way to know the LFB address.
    write_fb_mailbox(&fb_info);

    // After entering graphics mode, suppress all text output

    // Calculate font size based on resolution
    let screen_height = fb.height() as f32;
    debug_println!("[DEBUG] screen_height = {}", screen_height);

    // Use bitmap font - reliable and consistent
    let mut font = BitmapFont::new();
    font.set_size(16);
    debug_println!(
        "[DEBUG] Using bitmap font, char_height = {}",
        font.char_height()
    );

    // Windows 7 advanced boot options. Every item has an explicit action
    // instead of relying on its menu position. Unsupported recovery paths
    // return to the menu with a clear notice rather than booting a normal OS
    // entry by mistake.
    let adv_options: [(AdvancedAction, &str, &str); 11] = [
        (AdvancedAction::Repair, "Repair Your Computer", "View a list of system recovery tools you can use to repair startup problems, run diagnostics, or restore your system."),
        (AdvancedAction::SafeMode, "Safe Mode", "Start Windows with only the core drivers and services. Use when you cannot boot after installing a new device or driver."),
        (AdvancedAction::SafeModeNetworking, "Safe Mode with Networking", "Start Windows in safe mode along with the network drivers and services needed to access the Internet or other computers on your network."),
        (AdvancedAction::SafeModeCommandPrompt, "Safe Mode with Command Prompt", "Start Windows in safe mode with a command prompt window instead of the usual Windows interface. For advanced users only."),
        (AdvancedAction::BootLogging, "Enable Boot Logging", "Create a file (ntbtlog.txt) that lists all the drivers that are installed during startup and that might be useful for advanced troubleshooting."),
        (AdvancedAction::LowResolution, "Enable low resolution video 640x480", "Start Windows using your current video driver and low resolution and refresh rate settings. You can use this mode to reset your display settings."),
        (AdvancedAction::LastKnownGood, "Last Known Good Configuration advanced", "Start Windows with the last registry and driver configuration that worked successfully."),
        (AdvancedAction::DirectoryServices, "Directory Services Restore Mode", "Start Windows domain controller running Active Directory so that the directory service can be restored. For advanced users and IT pros only."),
        (AdvancedAction::Debugging, "Debugging Mode", "Start Windows in an advanced troubleshooting mode intended for IT professionals and system administrators."),
        (AdvancedAction::DisableAutoRestart, "Disable automatic restart on system failure", "Prevent Windows from automatically restarting if an error causes Windows to fail."),
        (AdvancedAction::DisableDriverSignature, "Disable Driver Signature Enforcement", "Allows drivers containing improper signatures to be installed."),
    ];

    let mut screen = GraphicsScreen::Main {
        tools_selected: false,
    };
    let mut tick_counter: u32 = 0;

    // Initial draw
    debug_println!("[DEBUG] About to draw main screen...");
    draw_gop_main_screen(
        &mut fb,
        &mut font,
        &entries,
        menu.selected_index(),
        menu.countdown(),
        false,
    );
    debug_println!("[DEBUG] Main screen drawn");

    // Initialize console input for keyboard reading
    let mut con_in = crate::input::Keyboard::new();
    debug_println!(
        "[DEBUG] Console input initialized, con_in.is_some() = {}",
        con_in.is_some()
    );
    debug_println!("[DEBUG] Entering main event loop");

    // Main event loop - use text console for keyboard input
    loop {
        // Read keyboard input from text console (non-blocking check)
        let mut read = None;
        if let Some(ref mut stdin) = con_in {
            read = stdin.wait_for_key(core::time::Duration::from_millis(100));
        }

        // Handle countdown tick
        let mut auto_boot = false;
        let mut countdown_changed = false;
        if let GraphicsScreen::Main { tools_selected: _ } = screen {
            if menu.is_counting() {
                tick_counter += 1;
                if tick_counter >= 10 {
                    // 10 * 100ms = 1 second
                    tick_counter = 0;
                    if menu.tick() {
                        auto_boot = true;
                    }
                    countdown_changed = true;
                }
            }
        }

        // Handle key press
        if let Some(key) = read {
            // Cancel countdown on any key
            if let GraphicsScreen::Main { .. } = screen {
                menu.cancel_auto();
            }

            match key {
                Key::Special(ScanCode::UP) => match &mut screen {
                    GraphicsScreen::Main { tools_selected } => {
                        *tools_selected = false;
                        menu.move_up();
                    }
                    GraphicsScreen::Advanced { selected } => {
                        if *selected > 0 {
                            *selected -= 1;
                        }
                    }
                },
                Key::Special(ScanCode::DOWN) => match &mut screen {
                    GraphicsScreen::Main { .. } => {
                        menu.move_down();
                    }
                    GraphicsScreen::Advanced { selected } => {
                        if *selected < adv_options.len() - 1 {
                            *selected += 1;
                        }
                    }
                },
                Key::Special(ScanCode::FUNCTION_8) => match screen {
                    GraphicsScreen::Main { .. } => {
                        screen = GraphicsScreen::Advanced { selected: 0 };
                        draw_gop_advanced_screen(&mut fb, &mut font, &adv_options, 0);
                    }
                    GraphicsScreen::Advanced { .. } => {
                        screen = GraphicsScreen::Main {
                            tools_selected: false,
                        };
                        draw_gop_main_screen(
                            &mut fb,
                            &mut font,
                            &entries,
                            menu.selected_index(),
                            menu.countdown(),
                            false,
                        );
                    }
                },
                Key::Special(ScanCode::ESCAPE) => match screen {
                    GraphicsScreen::Advanced { .. } => {
                        screen = GraphicsScreen::Main {
                            tools_selected: false,
                        };
                        draw_gop_main_screen(
                            &mut fb,
                            &mut font,
                            &entries,
                            menu.selected_index(),
                            menu.countdown(),
                            false,
                        );
                    }
                    _ => {}
                },
                // Handle Enter key as printable '\r' or '\n'
                Key::Printable(c)
                    if c == uefi::Char16::try_from('\r' as u16).unwrap()
                        || c == uefi::Char16::try_from('\n' as u16).unwrap() =>
                {
                    // Boot selected entry
                    match &screen {
                        GraphicsScreen::Main { tools_selected } => {
                            if !entries.is_empty() {
                                // Get screen dimensions first
                                let w = fb.width();
                                let h = fb.height();
                                // Clear screen using GOP
                                fb.fill_rect_fast(0, 0, w, h, colors::BG);
                                if *tools_selected {
                                    run_memory_diagnostic(&mut fb, &mut font, con_in.as_mut());
                                } else {
                                    // Draw loading text
                                    font.draw_text_centered(
                                        &mut fb,
                                        "Loading...",
                                        (w / 2) as i32,
                                        (h / 2) as i32,
                                        colors::FG,
                                        None,
                                    );
                                    match launch_selected(&menu) {
                                        Ok(()) => {} // Does not return
                                        Err(e) => {
                                            // Boot failed - cancel the auto-boot countdown
                                            // and show an error message before returning to
                                            // the menu. This prevents the "system keeps
                                            // rebooting" behaviour caused by the auto-boot
                                            // timer re-firing on the same failing entry.
                                            debug_println!("[BOOT] launch_selected failed: {}", e);
                                            menu.cancel_auto();
                                            let w = fb.width();
                                            let h = fb.height();
                                            fb.fill_rect_fast(0, 0, w, h, colors::BG);
                                            font.draw_text_centered(
                                                &mut fb,
                                                "Windows failed to start",
                                                (w / 2) as i32,
                                                (h / 2 - 30) as i32,
                                                colors::FG,
                                                None,
                                            );
                                            let line2 = alloc::format!("Error: {}", e);
                                            font.draw_text_centered(
                                                &mut fb,
                                                &line2,
                                                (w / 2) as i32,
                                                (h / 2) as i32,
                                                colors::FG,
                                                None,
                                            );
                                            font.draw_text_centered(
                                                &mut fb,
                                                "Press any key to return to the boot menu",
                                                (w / 2) as i32,
                                                (h / 2 + 40) as i32,
                                                colors::FG,
                                                None,
                                            );
                                            if let Some(ref mut stdin) = con_in {
                                                loop {
                                                    match stdin.read_key() {
                                                        Some(_) => break,
                                                        _ => {
                                                            uefi::boot::stall(
                                                                core::time::Duration::from_millis(
                                                                    50,
                                                                ),
                                                            );
                                                        }
                                                    }
                                                }
                                            } else {
                                                uefi::boot::stall(core::time::Duration::from_secs(
                                                    3,
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        GraphicsScreen::Advanced { selected } => {
                            let action = adv_options[*selected].0;
                            match action {
                                AdvancedAction::SafeMode
                                | AdvancedAction::SafeModeNetworking
                                | AdvancedAction::DirectoryServices => {
                                    launch_advanced_action(
                                        &bcd_store,
                                        bcd::wellknown::ENTRY_SAFE_MODE,
                                        action.boot_options(),
                                    );
                                }
                                AdvancedAction::SafeModeCommandPrompt => {
                                    launch_advanced_action(
                                        &bcd_store,
                                        bcd::wellknown::ENTRY_SAFE_MODE,
                                        action.boot_options(),
                                    );
                                }
                                AdvancedAction::BootLogging | AdvancedAction::Debugging => {
                                    launch_advanced_action(
                                        &bcd_store,
                                        if action == AdvancedAction::Debugging {
                                            bcd::wellknown::ENTRY_DEBUG_CMD
                                        } else {
                                            bcd::wellknown::ENTRY_WINDOWS_7
                                        },
                                        action.boot_options(),
                                    );
                                }
                                AdvancedAction::Repair
                                | AdvancedAction::LowResolution
                                | AdvancedAction::LastKnownGood
                                | AdvancedAction::DisableAutoRestart
                                | AdvancedAction::DisableDriverSignature => {
                                    show_advanced_notice(
                                        &mut fb,
                                        &mut font,
                                        con_in.as_mut(),
                                        "This option is not available in this build.",
                                    );
                                }
                            }
                        }
                    }
                }
                // Handle Tab key (0x09) - switch between OS list and Tools
                Key::Printable(c) if c == uefi::Char16::try_from('\t' as u16).unwrap() => {
                    if let GraphicsScreen::Main { tools_selected } = &mut screen {
                        *tools_selected = !*tools_selected;
                    }
                }
                _ => {}
            }

            // Redraw after key handling
            match &screen {
                GraphicsScreen::Main { tools_selected } => {
                    draw_gop_main_screen(
                        &mut fb,
                        &mut font,
                        &entries,
                        menu.selected_index(),
                        menu.countdown(),
                        *tools_selected,
                    );
                }
                GraphicsScreen::Advanced { selected } => {
                    draw_gop_advanced_screen(&mut fb, &mut font, &adv_options, *selected);
                }
            }
        } else if auto_boot {
            // Auto-boot when countdown reaches zero
            debug_println!("[DEBUG] Auto-boot triggered!");
            if !entries.is_empty() {
                // Get screen dimensions first
                let w = fb.width();
                let h = fb.height();
                // Clear screen using GOP
                fb.fill_rect_fast(0, 0, w, h, colors::BG);
                font.draw_text_centered(
                    &mut fb,
                    "Loading...",
                    (w / 2) as i32,
                    (h / 2) as i32,
                    colors::FG,
                    None,
                );
                match launch_selected(&menu) {
                    Ok(()) => {} // Does not return
                    Err(e) => {
                        // Boot failed - cancel the auto-boot countdown so we
                        // don't immediately re-trigger the same failing boot,
                        // then display a clear error and wait for a keypress
                        // before redrawing the menu. This is the difference
                        // between "system reboots repeatedly" (when the
                        // countdown keeps re-firing every N seconds) and
                        // "system reports a boot error and stops".
                        debug_println!("[BOOT] launch_selected failed: {}", e);
                        menu.cancel_auto();
                        fb.fill_rect_fast(0, 0, w, h, colors::BG);
                        font.draw_text_centered(
                            &mut fb,
                            "Windows failed to start",
                            (w / 2) as i32,
                            (h / 2 - 30) as i32,
                            colors::FG,
                            None,
                        );
                        let line2 = alloc::format!("Error: {}", e);
                        font.draw_text_centered(
                            &mut fb,
                            &line2,
                            (w / 2) as i32,
                            (h / 2) as i32,
                            colors::FG,
                            None,
                        );
                        font.draw_text_centered(
                            &mut fb,
                            "Press any key to return to the boot menu",
                            (w / 2) as i32,
                            (h / 2 + 40) as i32,
                            colors::FG,
                            None,
                        );
                        // Drain any pending input, then block until a key is pressed.
                        if let Some(ref mut stdin) = con_in {
                            loop {
                                match stdin.read_key() {
                                    Some(_) => {
                                        // Got a key - exit the drain loop and redraw menu
                                        break;
                                    }
                                    _ => {
                                        // Try again after a short stall
                                        uefi::boot::stall(core::time::Duration::from_millis(50));
                                    }
                                }
                            }
                        } else {
                            // No input device - just stall briefly so the message is visible
                            uefi::boot::stall(core::time::Duration::from_secs(3));
                        }
                    }
                }
            }
        } else if countdown_changed {
            // Redraw only when countdown changes (every second)
            match screen {
                GraphicsScreen::Main { tools_selected } => {
                    draw_gop_main_screen(
                        &mut fb,
                        &mut font,
                        &entries,
                        menu.selected_index(),
                        menu.countdown(),
                        tools_selected,
                    );
                }
                _ => {}
            }
        }

        // Stall to prevent busy spinning (100ms per iteration)
        use uefi::boot as ub;
        ub::stall(core::time::Duration::from_millis(100)); // 100ms
    }
}

/// Read a UCS-2 (UTF-16) buffer up to the first NUL into a Rust `String`.
/// Returns an empty string for an all-zero buffer.
fn ucs2_to_string(buf: &[u16]) -> String {
    let mut s = String::new();
    for &c in buf {
        if c == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            s.push(ch);
        }
    }
    s
}

/// Read the entire contents of a file on the (only) ESP into a `Vec<u8>`.
///
/// We deliberately do **not** call `uefi::fs::FileSystem::read` because
/// it pre-sizes the `Vec` from `EFI_FILE_INFO.FileSize`, which on
/// OVMF's FAT32 driver is wrong (it reports the on-disk extent
/// without the trailing sector-padding that mcopy writes, e.g.
/// `557568 - 1536 = 556032` bytes for our `winload.efi`). The
/// truncated buffer is then passed to `LoadImage`, which loads a
/// half-broken PE image that crashes during relocation. We instead
/// read in fixed-size chunks until the file returns 0 bytes (EOF).
///
/// ## Partition-type probe
///
/// The disk has up to two partitions: a FAT32 ESP and a System partition
/// (NTFS or EXT4). EFI's `BlockIO` protocol may expose any combination
/// of:
///
///   * **disk-level** handles — one per physical/virtual disk; LBA 0
///     is the protective MBR and LBA 1 is the GPT header
///   * **partition-level** handles — one per GPT entry; LBA 0 is the
///     partition start (i.e. its VBR / superblock)
///   * **SFS-attached** handles — the FAT32 ESP carries a working
///     `SimpleFileSystem` protocol in addition to `BlockIO`
///
/// To pick the right reader, classify the handle into one of:
///
///   * `Ntfs`  — either partition-level handle whose VBR carries the
///               `NTFS    ` OEM ID, **or** a disk-level handle whose
///               GPT lists an NTFS partition entry as the *first*
///               data partition
///   * `Ext4`  — same shape but for the EXT4 superblock magic
///               (`0xEF53` at offset 56 within the superblock, which
///               lives 1024 bytes into the partition = LBA 2 of a
///               partition-scoped handle)
///   * `Fat`   — partition-level handle with a working SFS protocol
///   * `Unknown` — the handle is openable but does not match any of
///               the above; the dispatcher skips it
///
/// The disk-level handle is *the* entry point on QEMU/OVMF where
/// no partition-level handle is exposed for the non-FAT System
/// partition — which is why the probe has to descend into GPT
/// when it sees a whole-disk BlockIO.
fn probe_partition_type(handle: uefi::Handle) -> PartitionType {
    use core::mem::ManuallyDrop;
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let sp = unsafe {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let Ok(block) = sp else {
        return PartitionType::Unknown;
    };
    let block = ManuallyDrop::new(block);
    let block_ref = block.get().expect("BlockIO protocol");
    let media = block_ref.media();

    if media.block_size() != 512 {
        return PartitionType::Unknown;
    }
    let is_partition = media.is_logical_partition();
    let media_id = media.media_id();

    if is_partition {
        // ----- Partition-level handle -----
        //
        // Probe the VBR / superblock directly.
        let mut sb = [0u8; 64];
        if block_ref.read_blocks(media_id, 2u64, &mut sb).is_ok() {
            let magic = u16::from_le_bytes([sb[56], sb[57]]);
            if magic == EXT4_MAGIC {
                return PartitionType::Ext4 {
                    partition_start_lba: 0,
                };
            }
        }
        let mut first = [0u8; 512];
        if block_ref.read_blocks(media_id, 0u64, &mut first).is_ok() {
            if &first[3..11] == b"NTFS    " {
                return PartitionType::Ntfs {
                    partition_start_lba: 0,
                };
            }
        }
        if has_sfs_protocol(handle) {
            return PartitionType::Fat;
        }
        return PartitionType::Unknown;
    }

    // ----- Disk-level handle -----
    //
    // OVMF exposes the raw disk here. Read the GPT header at LBA 1
    // and walk the partition entries to find the first filesystem
    // we recognise. We do not synthesise separate partition-type
    // results per partition entry; the dispatcher's caller only
    // needs to know "this disk has an NTFS or EXT4 system volume",
    // and the partition-type-specific reader then re-walks GPT to
    // locate the right LBA range when it is actually invoked.
    let mut gpt_header = [0u8; 512];
    if block_ref
        .read_blocks(media_id, 1u64, &mut gpt_header)
        .is_err()
    {
        return PartitionType::Unknown;
    }
    if &gpt_header[0..8] != b"EFI PART" {
        return PartitionType::Unknown;
    }
    let partition_entry_count = u32::from_le_bytes([
        gpt_header[80],
        gpt_header[81],
        gpt_header[82],
        gpt_header[83],
    ]) as usize;
    let partition_entry_size = u32::from_le_bytes([
        gpt_header[84],
        gpt_header[85],
        gpt_header[86],
        gpt_header[87],
    ]) as usize;
    let partition_entries_lba = u64::from_le_bytes([
        gpt_header[72],
        gpt_header[73],
        gpt_header[74],
        gpt_header[75],
        gpt_header[76],
        gpt_header[77],
        gpt_header[78],
        gpt_header[79],
    ]);
    let Some(mut entries_buf) =
        try_alloc_zeroed(partition_entry_size * partition_entry_count.min(128))
    else {
        return PartitionType::Unknown;
    };
    if block_ref
        .read_blocks(media_id, partition_entries_lba, &mut entries_buf)
        .is_err()
    {
        return PartitionType::Unknown;
    }

    // The disk image we build puts the System partition (NTFS or
    // EXT4) as the second GPT entry, after the FAT ESP. Walk the
    // entries and prefer the *non*-FAT system partition — that
    // way the dispatcher invokes the matching reader directly,
    // without spending time on the FAT entry (which the SFS
    // loop already failed on).
    let fat_guid = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0x4B, 0xBA, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    let ntfs_guid = [
        0xA0, 0x88, 0x2D, 0x83, 0xEB, 0xD1, 0xCD, 0x41, 0xB7, 0x96, 0x21, 0xE3, 0x66, 0x65, 0xFF,
        0xCC,
    ];
    let ext4_guid = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    let mut prefer_ext4: Option<u64> = None;
    let mut prefer_ntfs: Option<u64> = None;
    for i in 0..partition_entry_count.min(128) {
        let entry_off = i * partition_entry_size;
        if entry_off + 48 > entries_buf.len() {
            break;
        }
        let g = &entries_buf[entry_off..entry_off + 16];
        let start_lba = u64::from_le_bytes([
            entries_buf[entry_off + 32],
            entries_buf[entry_off + 33],
            entries_buf[entry_off + 34],
            entries_buf[entry_off + 35],
            entries_buf[entry_off + 36],
            entries_buf[entry_off + 37],
            entries_buf[entry_off + 38],
            entries_buf[entry_off + 39],
        ]);
        if g == fat_guid {
            continue;
        }
        if g == ntfs_guid && prefer_ntfs.is_none() {
            prefer_ntfs = Some(start_lba);
            debug_println!("[PT]   disk GPT: NTFS partition at LBA {}", start_lba);
        }
        if g == ext4_guid && prefer_ext4.is_none() {
            prefer_ext4 = Some(start_lba);
            debug_println!("[PT]   disk GPT: EXT4 partition at LBA {}", start_lba);
        }
    }
    if prefer_ext4.is_some() {
        return PartitionType::Ext4 {
            partition_start_lba: prefer_ext4.unwrap(),
        };
    }
    if prefer_ntfs.is_some() {
        return PartitionType::Ntfs {
            partition_start_lba: prefer_ntfs.unwrap(),
        };
    }
    PartitionType::Unknown
}

/// ## LFN Workaround
///
// =====================================================================
// EFI_LOADED_IMAGE_PROTOCOL / EFI_LOAD_FILE_PROTOCOL chain-load support
// =====================================================================
// doc8 §1.1: bootmgr previously ignored both protocols. The block below
// adds the missing entry recognition:
//
//   * EFI_LOADED_IMAGE_PROTOCOL — when bootmgfw (or the firmware BDS)
//     chain-loads this boot manager, the firmware-supplied image handle
//     resolves to the authoritative ESP device handle via LoadedImage.
//     `read_boot_file` prefers that handle when reading BCD / boot files.
//
//   * EFI_LOAD_FILE_PROTOCOL — the boot manager installs the protocol on
//     a fresh handle serving its own PE bytes, so bootmgfw can chain-load
//     it through the standard UEFI LoadFile resolution path instead of
//     raw block reads.

/// Pool buffer holding the boot manager's own PE bytes, served through
/// the EFI_LOAD_FILE_PROTOCOL below.
static mut BOOTMGR_LOAD_FILE_IMAGE_BASE: u64 = 0;
static mut BOOTMGR_LOAD_FILE_IMAGE_SIZE: u64 = 0;

static mut BOOTMGR_LOAD_FILE_PROTOCOL: uefi_raw::protocol::media::LoadFileProtocol =
    uefi_raw::protocol::media::LoadFileProtocol {
        load_file: bootmgr_load_file_callback,
    };

/// EFI_LOAD_FILE_PROTOCOL callback: serves the boot manager image bytes
/// so bootmgfw (or the firmware BDS) can chain-load this image via
/// LoadFile resolution instead of raw block reads.
extern "efiapi" fn bootmgr_load_file_callback(
    _this: *mut uefi_raw::protocol::media::LoadFileProtocol,
    _file_path: *const uefi_raw::protocol::device_path::DevicePathProtocol,
    _boot_policy: uefi_raw::Boolean,
    buffer_size: *mut usize,
    buffer: *mut core::ffi::c_void,
) -> uefi::Status {
    let (base, size) = unsafe { (BOOTMGR_LOAD_FILE_IMAGE_BASE, BOOTMGR_LOAD_FILE_IMAGE_SIZE) };
    if base == 0 || size == 0 {
        return uefi::Status::UNSUPPORTED;
    }
    unsafe {
        let requested = &mut *buffer_size;
        if buffer.is_null() || *requested < size as usize {
            *requested = size as usize;
            return uefi::Status::BUFFER_TOO_SMALL;
        }
        core::ptr::copy_nonoverlapping(base as *const u8, buffer.cast::<u8>(), size as usize);
    }
    uefi::Status::SUCCESS
}

/// Capture the boot manager's own PE image bytes into a boot-services
/// pool buffer and install the EFI_LOAD_FILE_PROTOCOL on a fresh
/// handle. Returns the new handle on success. Safe to skip: the direct
/// launch path does not depend on the protocol.
unsafe fn install_bootmgr_load_file_protocol() -> Option<uefi::Handle> {
    const SELF_PATHS: [&str; 2] = [
        "\\EFI\\Boot\\bootx64.efi",
        "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
    ];
    let mut image: Option<Vec<u8>> = None;
    for path in SELF_PATHS {
        if let Ok(data) = read_boot_file(path) {
            image = Some(data);
            break;
        }
    }
    let image = image?;
    let pool = uefi::boot::allocate_pool(uefi::boot::MemoryType::LOADER_DATA, image.len()).ok()?;
    core::ptr::copy_nonoverlapping(image.as_ptr(), pool.as_ptr(), image.len());
    unsafe {
        BOOTMGR_LOAD_FILE_IMAGE_BASE = pool.as_ptr() as u64;
        BOOTMGR_LOAD_FILE_IMAGE_SIZE = image.len() as u64;
    }
    let handle = unsafe {
        uefi::boot::install_protocol_interface(
            None,
            &uefi_raw::protocol::media::LoadFileProtocol::GUID,
            core::ptr::addr_of!(BOOTMGR_LOAD_FILE_PROTOCOL).cast(),
        )
    }
    .ok()?;
    debug_println!(
        "[BOOTMGR] EFI_LOAD_FILE_PROTOCOL installed on handle 0x{:x}",
        handle.as_ptr() as u64
    );
    Some(handle)
}

/// The device handle this boot manager itself was loaded from, obtained
/// via the EFI_LOADED_IMAGE_PROTOCOL. When bootmgfw chain-loads the boot
/// manager, this is the authoritative ESP handle; no handle-order
/// guessing needed.
fn chain_loaded_device_handle() -> Option<uefi::Handle> {
    let raw = unsafe { BOOT_IMAGE_HANDLE_PTR };
    if raw.is_null() {
        return None;
    }
    let image = unsafe { uefi::Handle::from_ptr(raw) }?;
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::loaded_image::LoadedImage;
    let loaded = unsafe {
        uefi::boot::open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let device = loaded.get().and_then(|loaded_image| loaded_image.device());
    drop(loaded);
    device
}

/// True when `handle` exposes the SimpleFileSystem protocol.
fn device_has_simple_filesystem(handle: uefi::Handle) -> bool {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    match unsafe {
        uefi::boot::open_protocol::<SimpleFileSystem>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(scoped) => {
            let ok = scoped.get().is_some();
            drop(scoped);
            ok
        }
        Err(_) => false,
    }
}

/// Some OVMF FAT32 drivers do not properly resolve long filenames (LFN)
/// when using `EFI_FILE_PROTOCOL.Open()`. The UEFI spec says `open()` should
/// match by LFN, but OVMF sometimes only matches by the 8.3 short name.
/// To work around this, when `open()` fails with NOT_FOUND, we enumerate
/// the directory entries and find the canonical (LFN) name, then re-open with it.
fn read_boot_file(rel_path: &str) -> Result<Vec<u8>, &'static str> {
    use core::mem::ManuallyDrop;

    // Path-classified dispatch. Windows 7 boot paths fall into two
    // disjoint buckets:
    //   * ESP paths start with `\EFI\...` or are bare names like `BCD`.
    //     UEFI's SimpleFileSystem protocol is FAT-only, so these must
    //     be read through the SFS loop below.
    //   * System partition paths start with `\Windows\...`. UEFI cannot
    //     open these via SFS (NTFS has no SFS binding), so we must go
    //     through the in-tree NTFS/EXT4/FAT32 reader. Skipping the FAT
    //     loop here avoids the noisy "Trying FAT handle 0 / Failed to
    //     open directory: Windows / dispatching by partition type"
    //     sequence that the previous always-try-FAT-first code emitted
    //     for every winload.efi read.
    let normalized = rel_path.replace('\\', "/");
    let is_esp_path = {
        let lower = normalized.to_ascii_lowercase();
        lower == "bcd"
            || lower.starts_with("efi/")
            || lower.starts_with("/efi/")
            || lower.starts_with("efi\\")
    };

    if !is_esp_path {
        // Probe the BlockIO handles *before* claiming success in the
        // log. If the platform truly has no NTFS/EXT4 partition we
        // want the operator to see "no System partition found",
        // not "dispatching directly to NTFS/EXT4" followed by a
        // silent fallthrough to `None`.
        let system_partition_present = probe_system_partition_present();
        if system_partition_present {
            debug_println!(
                "[FILE] System-partition path '{}' - dispatching directly to NTFS/EXT4",
                rel_path
            );
        } else {
            debug_println!(
                "[FILE] System-partition path '{}' - no NTFS/EXT4/FAT32 partition present; \
                 cannot dispatch",
                rel_path
            );
            debug_println!("[FILE] All methods failed for '{}'", rel_path);
            return Err("no System partition (NTFS/EXT4/FAT32) on this platform");
        }

        // Strip a leading '/' or '\' before handing the path to the
        // System-partition reader: BCD paths use the form
        // `\Windows\System32\winload.efi` (with a backslash and a
        // leading root-separator), but the NTFS reader's
        // `resolve_mft_record` treats the input as a path relative to
        // the volume root and would otherwise try to match an entry
        // literally named `/Windows/...` and never find it.
        let stripped = normalized
            .trim_start_matches(|c| c == '/' || c == '\\')
            .to_string();
        if let Some(data) = read_system_partition_file(&stripped) {
            debug_println!(
                "[FILE] System-partition read succeeded: {} bytes",
                data.len()
            );
            return Ok(data);
        }
        debug_println!("[FILE] All methods failed for '{}'", rel_path);
        return Err("failed to load file from System partition");
    }

    let sfs_handles = boot::find_handles::<SimpleFileSystem>().map_err(|_| "no SFS handles")?;
    if sfs_handles.is_empty() {
        return Err("no SimpleFileSystem on this platform");
    }
    // Shadow the previous name to keep the FAT loop below unchanged.
    let mut handles = sfs_handles;
    // When bootmgfw (or another EFI image) chain-loaded this boot
    // manager, the EFI_LOADED_IMAGE_PROTOCOL device handle is the
    // authoritative ESP. Try it first so BCD / boot files are read
    // from the volume the boot manager actually lives on.
    if let Some(device) = chain_loaded_device_handle() {
        if device_has_simple_filesystem(device) {
            if let Some(pos) = handles.iter().position(|h| *h == device) {
                let chosen = handles.remove(pos);
                handles.insert(0, chosen);
                debug_println!("[FILE] Using chain-loaded device handle first");
            }
        }
    }

    // Split path into parts
    let normalized = rel_path.replace('\\', "/");
    let parts: alloc::vec::Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();

    if parts.is_empty() {
        return Err("empty path");
    }

    // Try each handle
    for (idx, handle) in handles.iter().enumerate() {
        // Skip non-FAT partitions when reading BCD/boot files from ESP.
        // NTFS and EXT4 are only used for winload.efi on the System
        // partition; the dispatcher below (after the FAT loop) reads
        // those. If we tried to open_volume on them, the firmware
        // would return UNSUPPORTED because EFI's SFS protocol is
        // FAT-only.
        let pt = probe_partition_type(*handle);
        if pt != PartitionType::Fat {
            debug_println!(
                "[FILE] Skipping non-FAT handle {} (type={:?}, BCD path)",
                idx,
                pt
            );
            continue;
        }

        debug_println!("[FILE] Trying FAT handle {}...", idx);
        let mut sfs = match boot::open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            Ok(s) => ManuallyDrop::new(s),
            Err(_) => continue,
        };

        let root = match sfs.open_volume() {
            Ok(r) => {
                debug_println!("[FILE] Opened volume from handle {}", idx);
                r
            }
            Err(_) => continue,
        };

        // Navigate through directories one by one
        let file_name = parts[parts.len() - 1];
        let dir_parts = &parts[..parts.len() - 1];

        let mut current_dir = root;
        let mut navigation_failed = false;

        for part in dir_parts.iter() {
            match open_dir_component(&mut current_dir, part) {
                Some(dir) => current_dir = dir,
                None => {
                    debug_println!("[FILE] Failed to open directory: {}", part);
                    navigation_failed = true;
                    break;
                }
            }
        }

        if navigation_failed {
            continue;
        }

        // Open the file itself
        debug_println!("[FILE] Trying to open: {}", file_name);
        if let Some(mut handle) = open_file_component(&mut current_dir, file_name) {
            let info = handle
                .get_boxed_info::<FileInfo>()
                .map_err(|_| "get info")?;
            let total = info.file_size() as usize;
            let Some(mut out) = try_alloc_zeroed(total) else {
                return Err("allocation failed");
            };
            let mut off: usize = 0;
            const CHUNK: usize = 64 * 1024;
            while off < total {
                let want = (total - off).min(CHUNK);
                let n = handle
                    .read(&mut out[off..off + want])
                    .map_err(|_| "read failed")?;
                if n == 0 {
                    break;
                }
                off += n;
            }
            out.truncate(off);
            debug_println!("[FILE] Read {} bytes from: {}", total, rel_path);
            return Ok(out);
        }
        // Try the next SFS handle
        let _ = idx;
    }

    // FAT32 ESP did not contain the file. Per Windows 7 layout, winload.efi
    // lives on the System partition (NTFS or EXT4). Dispatch by
    // partition type instead of blindly trying NTFS on every handle.
    debug_println!(
        "[FILE] FAT read failed for '{}', dispatching by partition type",
        rel_path
    );
    if let Some(data) = read_system_partition_file(rel_path) {
        debug_println!(
            "[FILE] System-partition read succeeded: {} bytes",
            data.len()
        );
        debug_println!(
            "[FILE] >>> Returning from read_boot_file via System partition - SUCCESS <<<"
        );
        return Ok(data);
    }

    debug_println!("[FILE] All methods failed for '{}'", rel_path);
    Err("failed to load file from any SFS handle")
}

/// Dispatch to the correct in-tree filesystem reader for the System
/// partition. Walks every `BlockIO` handle exactly once, classifies it
/// via [`probe_partition_type`], and:
///   * on `Ntfs` -> [`read_ntfs_boot_file_for`]
///   * on `Ext4` -> `ext4_boot::read_ext4_system_file`
///   * on `Fat`  -> `fat32_boot::read_fat32_system_file` (in-tree reader,
///     symmetric with the winload-side FAT32 reader)
///   * on `Unknown` -> skip
///
/// Returns the first successful read. The probe-then-dispatch shape
/// avoids the previous bug where every handle ran a full NTFS GPT
/// parse and a path that was actually EXT4 was misclassified as
/// "no NTFS partition found".
/// Walk the BlockIO handles once and report whether the platform has
/// any partition that the System-partition reader can consume (NTFS
/// EXT4 or FAT32). Used by `read_boot_file` to keep its log honest: it
/// must not claim "dispatching directly to NTFS/EXT4/FAT32" if no such
/// partition exists.
fn probe_system_partition_present() -> bool {
    use uefi::proto::media::block::BlockIO;
    let Ok(handles) = boot::find_handles::<BlockIO>() else {
        return false;
    };
    for handle in handles.iter() {
        if matches!(
            probe_partition_type(*handle),
            PartitionType::Ntfs { .. } | PartitionType::Ext4 { .. } | PartitionType::Fat
        ) {
            return true;
        }
    }
    false
}

fn read_system_partition_file(rel_path: &str) -> Option<Vec<u8>> {
    use core::mem::ManuallyDrop;
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let handles = boot::find_handles::<BlockIO>().ok()?;
    debug_println!("[PT] probing {} BlockIO handle(s)", handles.len());

    for (idx, handle) in handles.iter().enumerate() {
        let pt = probe_partition_type(*handle);
        debug_println!("[PT] handle {}: type={:?}", idx, pt);

        match pt {
            PartitionType::Ntfs {
                partition_start_lba,
            } => {
                let sp = unsafe {
                    boot::open_protocol::<BlockIO>(
                        OpenProtocolParams {
                            handle: *handle,
                            agent: boot::image_handle(),
                            controller: None,
                        },
                        OpenProtocolAttributes::GetProtocol,
                    )
                };
                let Ok(block) = sp else { continue };
                let block = ManuallyDrop::new(block);
                let Some(block_ref) = block.get() else {
                    core::mem::forget(block);
                    continue;
                };
                let media = block_ref.media();
                if media.block_size() != 512 {
                    core::mem::forget(block);
                    continue;
                }
                let r = read_ntfs_boot_file_for(rel_path, block_ref, partition_start_lba);
                core::mem::forget(block);
                if r.is_some() {
                    return r;
                }
            }
            PartitionType::Ext4 {
                partition_start_lba,
            } => {
                let sp = unsafe {
                    boot::open_protocol::<BlockIO>(
                        OpenProtocolParams {
                            handle: *handle,
                            agent: boot::image_handle(),
                            controller: None,
                        },
                        OpenProtocolAttributes::GetProtocol,
                    )
                };
                let Ok(block) = sp else { continue };
                let block = ManuallyDrop::new(block);
                let Some(block_ref) = block.get() else {
                    core::mem::forget(block);
                    continue;
                };
                let media = block_ref.media();
                if media.block_size() != 512 {
                    core::mem::forget(block);
                    continue;
                }
                let r = ext4_boot::read_ext4_with_block(
                    rel_path,
                    block_ref,
                    media.media_id(),
                    partition_start_lba,
                );
                core::mem::forget(block);
                if r.is_some() {
                    return r;
                }
            }
            PartitionType::Fat => {
                // A FAT32 System partition is served by the in-tree
                // reader (nt61_bootfs), exactly like the winload-side
                // reader: walk the GPT for the basic-data FAT32
                // partition and resolve the path through the FAT32
                // on-disk structures. The firmware SFS loop above only
                // covers ESP paths, so without this arm a
                // (ESP=FAT32, sys=FAT32) layout could not load
                // winload.efi at all.
                let r = fat32_boot::read_fat32_system_file(rel_path);
                if r.is_some() {
                    return r;
                }
            }
            PartitionType::Unknown => continue,
        }
    }
    None
}

/// Open a directory component by name.
///
/// Tries in order:
///   1. `open()` with the original name (covers the happy path on good firmware)
///   2. LFN enumeration + `open()` with the LFN (for firmware that needs the
///      canonical name)
///   3. LFN enumeration + `open()` with derived 8.3 SFN candidates (for
///      OVMF, which only resolves short names in `open()`)
///
/// Returns `Some(Directory)` on success, `None` on failure. No error logging
/// unless every strategy fails.
fn open_dir_component(current_dir: &mut Directory, part: &str) -> Option<Directory> {
    let cpart = CString16::try_from(part).ok()?;

    // Strategy 1: direct open with the original name
    if let Ok(entry) = current_dir.open(cpart.as_ref(), FileMode::Read, FileAttribute::empty()) {
        if let Some(dir) = entry.into_directory() {
            return Some(dir);
        }
    }

    // Strategy 2: LFN enumeration + LFN/SFN fallback
    if let Some(lookup) = fat_lfn::find_entry_by_name(current_dir, part) {
        // Try LFN first
        if let Ok(entry) =
            current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty())
        {
            if let Some(dir) = entry.into_directory() {
                return Some(dir);
            }
        }
        // Then try SFN candidates
        for sfn in &lookup.sfn_candidates {
            if let Ok(entry) =
                current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty())
            {
                if let Some(dir) = entry.into_directory() {
                    return Some(dir);
                }
            }
        }
    }

    None
}

/// Open a file component by name. Same fallback strategy as `open_dir_component`.
fn open_file_component(current_dir: &mut Directory, file_name: &str) -> Option<RegularFile> {
    let cfile = CString16::try_from(file_name).ok()?;

    // Strategy 1: direct open with the original name
    if let Ok(file) = current_dir.open(cfile.as_ref(), FileMode::Read, FileAttribute::empty()) {
        if let Some(h) = file.into_regular_file() {
            return Some(h);
        }
    }

    // Strategy 2: LFN enumeration + LFN/SFN fallback
    if let Some(lookup) = fat_lfn::find_entry_by_name(current_dir, file_name) {
        // Try LFN first
        if let Ok(file) =
            current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty())
        {
            if let Some(h) = file.into_regular_file() {
                return Some(h);
            }
        }
        // Then try SFN candidates
        for sfn in &lookup.sfn_candidates {
            if let Ok(file) = current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty())
            {
                if let Some(h) = file.into_regular_file() {
                    return Some(h);
                }
            }
        }
    }

    None
}

/// In a real Windows 7 install, `EFI\Microsoft\Boot\BCD` is a
/// registry-format hive written by `bcdedit` during OS installation.
/// Bootmgr parses this file to discover boot entries (Windows,
/// Safe-Mode, Memtest, …) and the device path / filename of each
/// entry's loader (typically `winload.efi`).
///
/// We follow the same model here: the build tool writes a real
/// (minimal) BCD hive into the ESP at image-build time, and the
/// boot manager reads it back via this function. If the read fails
/// (e.g. the BCD file is missing or corrupt) the caller falls back
/// to an in-memory default store so the UI is still usable for
/// debugging.
fn load_bcd_from_esp() -> core::result::Result<BcdStore, &'static str> {
    // Try several paths for the BCD store. The boot manager is loaded
    // by UEFI and may set the current directory to the volume root or
    // to the directory containing the boot manager (EFI/Boot/).
    //
    // With our build layout (BCD is in \EFI\Microsoft\Boot\BCD):
    //   ESP/EFI/Microsoft/Boot/BCD <- standard Windows path (PRIORITY!)
    //   ESP/BCD                   <- BCD at volume root (fallback)
    //   ESP/EFI/Boot/BCD          <- BCD next to boot manager (fallback)
    const BCD_PATHS: [&str; 3] = ["EFI/Microsoft/Boot/BCD", "BCD", "EFI/Boot/BCD"];

    for bcd_path in BCD_PATHS {
        debug_println!("[BCD] Trying path: {}", bcd_path);
        if let Ok(bytes) = read_boot_file(bcd_path) {
            debug_println!("[BCD] Read {} bytes from: {}", bytes.len(), bcd_path);
            // Parse the BCD hive.
            use crate::bcd_parser::BcdHive;
            match BcdHive::parse(&bytes) {
                Ok(hive) => {
                    let store = hive.into_store();
                    debug_println!("[BCD] Parsed {} entries", store.entry_count);
                    return Ok(store);
                }
                Err(e) => {
                    debug_println!("[BCD] Parse error for {}: {:?}", bcd_path, e);
                }
            }
        }
    }

    Err("failed to load BCD from any path")
}

fn launch_advanced_action(
    bcd_store: &BcdStore,
    requested_guid: bcd::Guid,
    boot_options: Option<&'static str>,
) {
    let mut menu = BootMenu::new(bcd_store);
    for _ in 0..bcd_store.entry_count {
        if menu.select().map(|entry| entry.guid) == Some(requested_guid) {
            // Store the boot options so write_bcd_mailbox can pick them up
            // when launch_selected writes the mailbox before loading the
            // target image.
            unsafe { BOOT_OPTIONS_OVERRIDE = boot_options };
            let _ = launch_selected(&menu);
            return;
        }
        menu.move_down();
    }

    debug_println!(
        "[BOOT] Advanced action requested unknown BCD entry {:02x}{:02x}{:02x}{:02x}",
        requested_guid.0[0],
        requested_guid.0[1],
        requested_guid.0[2],
        requested_guid.0[3]
    );
}

/// Wait for any key so a diagnostic/notice screen is visible. If no input
/// device is available, leave the text on screen briefly instead.
fn wait_for_any_key(con_in: Option<&mut crate::input::Keyboard>) {
    if let Some(stdin) = con_in {
        loop {
            match stdin.read_key() {
                Some(_) => break,
                _ => uefi::boot::stall(core::time::Duration::from_millis(50)),
            }
        }
    } else {
        uefi::boot::stall(core::time::Duration::from_secs(3));
    }
}

/// Show a centered Windows 7 style notice and return after a keypress.
fn show_advanced_notice(
    fb: &mut Framebuffer,
    font: &mut BitmapFont,
    con_in: Option<&mut crate::input::Keyboard>,
    message: &str,
) {
    let width = fb.width();
    let height = fb.height();
    fb.fill_rect_fast(0, 0, width, height, colors::BG);
    font.draw_text_centered(
        fb,
        "Windows Boot Manager",
        (width / 2) as i32,
        (height / 2 - 40) as i32,
        colors::FG,
        None,
    );
    font.draw_text_centered(
        fb,
        message,
        (width / 2) as i32,
        (height / 2) as i32,
        colors::FG,
        None,
    );
    font.draw_text_centered(
        fb,
        "Press any key to continue",
        (width / 2) as i32,
        (height / 2 + 40) as i32,
        colors::FG,
        None,
    );
    wait_for_any_key(con_in);
}

/// Test one page of conventional UEFI memory with alternating bit patterns,
/// restoring the original value so the firmware boot environment is unchanged.
/// Returns the number of bytes successfully tested or the failing address.
fn test_conventional_memory_page(base: u64, page: u64) -> Result<u64, u64> {
    let pointer = (base + page * 4096) as *mut u64;
    let original = unsafe { pointer.read_volatile() };

    unsafe {
        pointer.write_volatile(0x5555_5555_5555_5555);
        if pointer.read_volatile() != 0x5555_5555_5555_5555 {
            return Err(base + page * 4096);
        }
        pointer.write_volatile(0xAAAA_AAAA_AAAA_AAAA);
        if pointer.read_volatile() != 0xAAAA_AAAA_AAAA_AAAA {
            return Err(base + page * 4096);
        }
        pointer.write_volatile(original);
    }

    Ok(4096)
}

/// Run Windows Memory Diagnostic directly from the boot manager. This uses the
/// real UEFI memory map and only probes ranges firmware reports as
/// conventional (free) memory; loader/runtime/firmware-owned memory is skipped.
fn run_memory_diagnostic(
    fb: &mut Framebuffer,
    font: &mut BitmapFont,
    con_in: Option<&mut crate::input::Keyboard>,
) {
    use uefi::boot::MemoryType;
    use uefi::mem::memory_map::MemoryMap;

    let width = fb.width();
    let height = fb.height();
    fb.fill_rect_fast(0, 0, width, height, colors::BG);
    font.draw_text_centered(
        fb,
        "Windows Memory Diagnostic",
        (width / 2) as i32,
        (height / 2 - 40) as i32,
        colors::FG,
        None,
    );
    font.draw_text_centered(
        fb,
        "Testing conventional memory...",
        (width / 2) as i32,
        (height / 2) as i32,
        colors::FG,
        None,
    );

    let memory_map = match uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA) {
        Ok(map) => map,
        Err(_) => {
            show_advanced_notice(fb, font, con_in, "Could not read the UEFI memory map.");
            return;
        }
    };

    let mut bytes_tested = 0u64;
    for descriptor in memory_map.entries() {
        if descriptor.ty != MemoryType::CONVENTIONAL || descriptor.page_count == 0 {
            continue;
        }

        let status = alloc::format!(
            "Testing 0x{:016x} ({} pages)",
            descriptor.phys_start,
            descriptor.page_count
        );
        fb.fill_rect_fast(0, 0, width, height, colors::BG);
        font.draw_text_centered(
            fb,
            "Windows Memory Diagnostic",
            (width / 2) as i32,
            (height / 2 - 40) as i32,
            colors::FG,
            None,
        );
        font.draw_text_centered(
            fb,
            &status,
            (width / 2) as i32,
            (height / 2) as i32,
            colors::FG,
            None,
        );

        for page in 0..descriptor.page_count {
            match test_conventional_memory_page(descriptor.phys_start, page) {
                Ok(tested) => bytes_tested += tested,
                Err(address) => {
                    let failure = alloc::format!("Memory test failed at 0x{:016x}", address);
                    show_advanced_notice(fb, font, con_in, &failure);
                    return;
                }
            }
        }
    }

    let summary = alloc::format!("Tested {} bytes", bytes_tested);
    show_advanced_notice(fb, font, con_in, &summary);
}

/// Load and start the UEFI image referenced by the currently-selected
/// BCD entry. On success this function does not return — control is
/// handed to the new image via direct jump.
///
/// ## PE Loading Strategy
///
/// UEFI's LoadImage cannot load from NTFS partitions (no SimpleFileSystem).
fn launch_selected(menu: &BootMenu) -> core::result::Result<(), &'static str> {
    debug_println!("[LAUNCH] launch_selected() - using manual PE loader");
    let entry = menu.select().ok_or("no entry selected")?;
    let path = ucs2_to_string(entry.application.as_slice());
    debug_println!("[LAUNCH] Selected entry: {}", path);
    if path.is_empty() {
        return Err("entry has no application path");
    }
    debug_println!("[LAUNCH] Reading file...");
    let bytes = match read_boot_file(&path) {
        Ok(b) => b,
        Err(e) => {
            debug_println!("[LAUNCH] Read failed: {}", e);
            return Err(e);
        }
    };
    debug_println!("[LAUNCH] Read {} bytes from {}", bytes.len(), path);

    debug_println!("[LAUNCH] Writing BCD mailbox...");
    // Write BCD mailbox first
    write_bcd_mailbox(&entry.guid.0);
    debug_println!("[LAUNCH] BCD mailbox written");

    // Now use manual PE loader
    use loader::{read_section_headers, PeHeaderInfo, SECTION_ALIGNMENT};

    debug_println!("[LAUNCH] Parsing PE headers...");
    let opt = match PeHeaderInfo::parse(&bytes) {
        Some(o) => o,
        None => {
            debug_println!("[LAUNCH] ERROR: Invalid PE image - PeHeaderInfo::parse returned None");
            return Err("invalid PE image");
        }
    };

    debug_println!(
        "[LAUNCH] PE32+ image: base=0x{:016x} entry=0x{:08x} sections={}",
        opt.image_base,
        opt.entry_point_rva,
        opt.number_of_sections
    );

    // Read section headers
    let sections = read_section_headers(&bytes, &opt);
    debug_println!("[LAUNCH] Got {} sections", sections.len());
    for (i, sec) in sections.iter().enumerate() {
        let name = sec.name_str();
        debug_println!(
            "[LAUNCH]   Section {}: {} VAddr=0x{:08x} VSize=0x{:08x} RPtr=0x{:08x} RSize=0x{:08x}",
            i,
            name,
            sec.virtual_address,
            sec.virtual_size,
            sec.pointer_to_raw_data,
            sec.size_of_raw_data
        );
    }

    // Calculate total image size
    let mut total_size = opt.size_of_headers;
    for sec in &sections {
        let end = sec.virtual_address + sec.virtual_size;
        if end > total_size {
            total_size = end;
        }
    }
    let aligned_size = (total_size + SECTION_ALIGNMENT - 1) & !(SECTION_ALIGNMENT - 1);
    debug_println!("[LAUNCH] Total image size: 0x{:08x} bytes", aligned_size);

    // Use the PE header's preferred image_base so all RIP-relative
    // references resolve correctly. If the firmware cannot honor it,
    // apply the relocations table.
    let load_base: u64 = opt.image_base;
    let image_size = aligned_size as usize;

    debug_println!(
        "[LAUNCH] Loading image to 0x{:016x} ({} bytes)",
        load_base,
        image_size
    );

    // CRITICAL: the PE's preferred ImageBase (0x180000000 for our
    // winload.efi) is in the high half of the address space and is
    // *never* allocated by the firmware by default. We must call
    // allocate_pages to create a writable mapping there BEFORE we
    // try to copy headers/sections into it — otherwise every write
    // silently goes to a non-existent page, the entry point stays
    // all-zeros (0x00 0x00 = ADD [RAX], AL on most encodings or HLT
    // on the rare alignment), and winload's "WINL>" banner never
    // appears in the serial log.
    //
    // The catch: the OVMF firmware has a hard cap on how many pages
    // it will hand back in a single allocate_pages call (around
    // 256 KiB / 64 pages in our testing — anything beyond that
    // returns "success" but only maps the first N pages and the
    // remaining pages stay not-present). We therefore allocate in
    // small chunks and re-verify after each one.
    use uefi::boot as ub;
    use uefi::boot::{AllocateType, MemoryType};
    const EFI_PAGE_SIZE: usize = 4096;
    const CHUNK_PAGES: usize = 16; // 64 KiB per chunk — safely under OVMF's cap.
    let total_pages = (image_size + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE;
    let mut allocated_base_holder: Option<u64> = None;
    // Use BOOT_SERVICES_DATA: the firmware reserves this memory for our
    // exclusive use until ExitBootServices.  We deliberately do NOT use
    // LOADER_DATA because the firmware is allowed to reclaim LOADER_DATA
    // pages and reuse them for other boot-services allocations — and in
    // practice OVMF DOES reclaim them, stomping the bytes we just wrote
    // into the winload image (we observed `fb ff ff 0f` overwriting our
    // carefully-written `66 ba f8 03` bytes).
    //
    // We try AllocateType::Address first so the winload image lands at
    // its preferred ImageBase (0x180000000); if the firmware rejects
    // that, we fall back to AnyPages and apply relocations later.
    // The OS loader is executable, so it must live in a UEFI code
    // allocation. Data allocations are mapped non-executable on AArch64,
    // which makes the first instruction fetch fault as a permission
    // error.
    let mem_type = MemoryType::LOADER_CODE;
    debug_println!(
        "[LAUNCH] Allocating {} pages ({} bytes) at 0x{:016x}, in chunks of {}",
        total_pages,
        total_pages * EFI_PAGE_SIZE,
        load_base,
        CHUNK_PAGES
    );
    let mut chunk_base = load_base;
    let mut remaining = total_pages;
    let mut address_alloc_ok = true;
    while remaining > 0 {
        let this_chunk = core::cmp::min(remaining, CHUNK_PAGES);
        match ub::allocate_pages(AllocateType::Address(chunk_base), mem_type, this_chunk) {
            Ok(p) => {
                let allocated = p.as_ptr() as u64;
                if allocated != chunk_base {
                    debug_println!(
                        "[LAUNCH] WARN: Address allocate returned 0x{:016x} (asked 0x{:016x})",
                        allocated,
                        chunk_base
                    );
                    address_alloc_ok = false;
                    break;
                }
                // Verify the *last* page of the chunk is actually writable
                // — the firmware may say OK but only map the first page.
                let verify_addr = allocated + (this_chunk as u64 - 1) * EFI_PAGE_SIZE as u64;
                let probe = unsafe { arch::probe_memory(verify_addr) };
                debug_println!(
                    "[LAUNCH]   chunk at 0x{:016x}..0x{:016x} last-page probe = 0x{:02x}",
                    chunk_base,
                    chunk_base + (this_chunk as u64) * EFI_PAGE_SIZE as u64,
                    probe
                );
                if probe != 0xAA {
                    debug_println!(
                        "[LAUNCH] FATAL: chunk last-page write/readback failed (got 0x{:02x})",
                        probe
                    );
                    return Err("allocate_pages phantom chunk");
                }
                chunk_base += this_chunk as u64 * EFI_PAGE_SIZE as u64;
                remaining -= this_chunk;
            }
            Err(e) => {
                debug_println!(
                    "[LAUNCH] Address allocation at 0x{:016x} rejected: {:?}",
                    chunk_base,
                    e
                );
                address_alloc_ok = false;
                break;
            }
        }
    }
    if !address_alloc_ok {
        // Fall back to AnyPages allocation. We'll need to apply relocations.
        debug_println!("[LAUNCH] Falling back to AnyPages allocation for winload image");
        // Allocate the entire image as ONE big chunk. Some firmwares return
        // non-contiguous chunks when we ask for many small ones, but a single
        // big allocate_pages call is honoured.
        let new_base = match ub::allocate_pages(AllocateType::AnyPages, mem_type, total_pages) {
            Ok(p) => p.as_ptr() as u64,
            Err(e) => {
                debug_println!("[LAUNCH] FATAL: AnyPages allocate failed: {:?}", e);
                return Err("AnyPages allocate failed");
            }
        };
        let verify_addr = new_base + (total_pages as u64 - 1) * EFI_PAGE_SIZE as u64;
        let probe = unsafe { arch::probe_memory(verify_addr) };
        debug_println!(
            "[LAUNCH]   AnyPages chunk at 0x{:016x}..0x{:016x} probe = 0x{:02x}",
            new_base,
            new_base + (total_pages as u64) * EFI_PAGE_SIZE as u64,
            probe
        );
        if probe != 0xAA {
            debug_println!(
                "[LAUNCH] FATAL: AnyPages chunk last-page write/readback failed (got 0x{:02x})",
                probe
            );
            return Err("AnyPages phantom chunk");
        }
        allocated_base_holder = Some(new_base);
        debug_println!(
            "[LAUNCH] AnyPages allocation succeeded at 0x{:016x}",
            new_base
        );
    }
    let load_base = allocated_base_holder.unwrap_or(load_base);
    let relocation_delta = (load_base as i128) - (opt.image_base as i128);
    let needs_relocation = load_base != opt.image_base;
    debug_println!(
        "[LAUNCH] load_base = 0x{:016x}, delta = {}, relocations = {}",
        load_base,
        relocation_delta,
        if needs_relocation {
            "REQUIRED"
        } else {
            "NOT REQUIRED"
        }
    );

    // Copy the PE headers to the base of the image (these contain the
    // section table the loader itself consults in its own prologue,
    // plus the import-directory pointer).
    let header_size = (opt.size_of_headers as usize).min(bytes.len());
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), load_base as *mut u8, header_size);
    }
    debug_println!("[LAUNCH] Copied headers ({} bytes)", header_size);

    // Probe the source bytes at offset 0x466a0 (where efi_main body lives)
    // to verify the read data is correct.
    debug_println!("[LAUNCH] Source bytes at offset 0x466a0: {:02x} {:02x} {:02x} {:02x} (expected 66 ba f8 03)",
        bytes[0x466a0], bytes[0x466a1], bytes[0x466a2], bytes[0x466a3]);

    // Copy sections. Two things to remember:
    //   1. raw data lives in `bytes[pointer_to_raw_data ..
    //      pointer_to_raw_data + size_of_raw_data]`
    //      and should be copied to `load_base + virtual_address`
    //   2. the area between the end of the raw data and the end
    //      of `virtual_size` is *uninitialised* — i.e. it is
    //      **BSS** and MUST be zero-filled before any code in the
    //      new image is allowed to run. Without the BSS zero-fill,
    //      any `static mut X: u32 = 0` in winload.efi reads random
    //      garbage from the freshly allocated LOADER_DATA pages,
    //      and any early function that touches one of those statics
    //      faulted the very first call after `efi_main` returned.
    for sec in &sections {
        let src_off = sec.pointer_to_raw_data as usize;
        let rsize = sec.size_of_raw_data as usize;
        let vsize = sec.virtual_size as usize;
        let dst_off = sec.virtual_address as usize;

        if src_off + rsize > bytes.len() || dst_off + vsize > image_size {
            debug_println!(
                "[LAUNCH]   skip section '{}': rsize/range out of bounds",
                sec.name_str()
            );
            continue;
        }

        // 1. Copy the on-disk raw data (may be zero-length for BSS-only
        //    sections — skip the rep movsb).
        let dst_raw_ptr = unsafe { (load_base as *mut u8).add(dst_off) };
        if rsize > 0 {
            let src_ptr = unsafe { bytes.as_ptr().add(src_off) };
            unsafe { core::ptr::copy_nonoverlapping(src_ptr, dst_raw_ptr, rsize) };
            debug_println!(
                "[LAUNCH]   section '{}': copied {} bytes of raw data to 0x{:016x}",
                sec.name_str(),
                rsize,
                dst_raw_ptr as u64
            );
        }

        // 2. Zero-fill BSS: the area from raw size to virtual size.
        //    PE convention is to zero up to the next file-aligned boundary
        //    of the *next* section, but in practice zeroing exactly
        //    `vsize - rsize` bytes is sufficient and self-contained.
        if vsize > rsize {
            let bss_size = vsize - rsize;
            let bss_dst = unsafe { (load_base as *mut u8).add(dst_off + rsize) };
            unsafe { bss_dst.write_bytes(0, bss_size) };
            debug_println!(
                "[LAUNCH]   section '{}': zero-filled {} bytes of BSS at 0x{:016x}",
                sec.name_str(),
                bss_size,
                bss_dst as u64
            );
        }
    }

    // Apply base relocations if the image was loaded somewhere other
    // than its preferred base. Without this step, every absolute
    // address inside winload still points at `image_base + offset`,
    // which is unmapped memory when we allocated via AnyPages, and
    // the very first `movabs $imm64, %reg` or `mov %rsp, %rbx`
    // reads back a garbage pointer and faults.
    if needs_relocation {
        debug_println!(
            "[LAUNCH] Applying base relocations: rva=0x{:x} size=0x{:x} delta=0x{:x}",
            opt.base_reloc_rva,
            opt.base_reloc_size,
            relocation_delta
        );
        match loader::apply_relocations_in_place(
            &bytes,
            &sections,
            &opt,
            load_base as *mut u8,
            opt.image_base,
            load_base,
        ) {
            Ok(n) => debug_println!("[LAUNCH] Applied {} DIR64 relocations", n),
            Err(e) => {
                debug_println!("[LAUNCH] FATAL: relocation apply failed: {}", e);
                return Err("relocation apply failed");
            }
        }
    }

    // Calculate entry point
    let entry_point = load_base + opt.entry_point_rva as u64;
    debug_println!("[LAUNCH] Entry point: 0x{:016x}", entry_point);

    // The PE's `AddressOfEntryPoint` already points straight at the body
    // of `efi_main` (the linker script groups .text.efi_main and uses
    // ENTRY(efi_main)). So we don't need a hardcoded VMA constant that
    // breaks every time the surrounding code shifts the `WINL>` prologue
    // — we read it straight out of the parsed PE entry-point RVA.
    let efi_main_vma: u64 = entry_point;

    // Verify the entry point really has the expected opcode (0x53 = push %rbx).
    // If it is still zero, the allocate_pages / copy failed silently.
    unsafe {
        let p = entry_point as *const u8;
        let b0 = core::ptr::read_volatile(p);
        let b1 = core::ptr::read_volatile(p.add(1));
        let b2 = core::ptr::read_volatile(p.add(2));
        let b3 = core::ptr::read_volatile(p.add(3));
        debug_println!(
            "[LAUNCH] Entry-point probe bytes: {:02x} {:02x} {:02x} {:02x}",
            b0,
            b1,
            b2,
            b3
        );
    }
    // Also probe the efi_main body VMA that we're actually going to jmp to.
    unsafe {
        let p = efi_main_vma as *const u8;
        let b0 = core::ptr::read_volatile(p);
        let b1 = core::ptr::read_volatile(p.add(1));
        let b2 = core::ptr::read_volatile(p.add(2));
        let b3 = core::ptr::read_volatile(p.add(3));
        debug_println!(
            "[LAUNCH] efi_main-body probe bytes: {:02x} {:02x} {:02x} {:02x}",
            b0,
            b1,
            b2,
            b3
        );
    }
    let probe_byte = unsafe { *(entry_point as *const u8) };
    debug_println!(
        "[LAUNCH] Entry-point probe byte = 0x{:02x} (expected 0x53)",
        probe_byte
    );
    if probe_byte == 0x00 {
        debug_println!("[LAUNCH] FATAL: entry point is still zero — memory not mapped");
        return Err("entry point not mapped");
    }

    // Probe RIGHT BEFORE the jmp: read 4 bytes at efi_main body.
    unsafe {
        let p = efi_main_vma as *const u8;
        let b0 = core::ptr::read_volatile(p);
        let b1 = core::ptr::read_volatile(p.add(1));
        let b2 = core::ptr::read_volatile(p.add(2));
        let b3 = core::ptr::read_volatile(p.add(3));
        debug_println!(
            "[LAUNCH] PRE-JMP probe at 0x{:x}: {:02x} {:02x} {:02x} {:02x}",
            efi_main_vma,
            b0,
            b1,
            b2,
            b3
        );
    }

    // For UEFI PE32+, the entry point is called with:
    //   RCX = ImageHandle
    //   RDX = SystemTable*
    // Both registers are passed by the firmware when the boot manager
    // was launched. We re-use those values by reading them with inline
    // asm and then jumping to winload.efi's entry point directly.
    debug_println!("[LAUNCH] Jumping to winload.efi entry point...");
    debug_println!("[LAUNCH] =========================================");
    debug_println!("[LAUNCH] Winload should now take over boot!");
    debug_println!("[LAUNCH] =========================================");

    // Jump to the entry point. The UEFI calling convention for an
    // EFI image's entry point is:
    //     RCX = EFI_HANDLE ImageHandle
    //     RDX = EFI_SYSTEM_TABLE *SystemTable
    // winload.efi expects these to be the *firmware-supplied* values,
    // not the values left over from boot's own bookkeeping — otherwise
    // it dereferences random pointers and crashes before printing its
    // banner. We captured the firmware values in
    // `BOOT_IMAGE_HANDLE_PTR` / `BOOT_SYSTEM_TABLE` at the start of
    // `efi_main`; restore them here and then tail-call the entry
    // point.
    let image_handle: u64;
    let system_table: u64;
    unsafe {
        image_handle = BOOT_IMAGE_HANDLE_PTR as u64;
        system_table = BOOT_SYSTEM_TABLE;
    }
    debug_println!("[LAUNCH] Restoring UEFI calling convention:");
    debug_println!("[LAUNCH]   ImageHandle  = 0x{:016x}", image_handle);
    debug_println!("[LAUNCH]   SystemTable = 0x{:016x}", system_table);

    // Write a marker to the architecture's debug UART to confirm we
    // reached this code.
    arch::current::write_com1_marker(b"KL\r\n");

    // The PE entry point at 0x180001000 is a UEFI startup stub:
    //     mov [%rdi], %rsp   ; save old RSP → [ImageHandle]
    //     mov %rsi, %rsp     ; new RSP = RSI value (firmware tricks)
    //     <pop 6 regs>
    //     ret
    // The stub expects RSI to be the SystemTable pointer AND a freshly
    // allocated stack with the right return layout. When we manually
    // jump into the loaded image, the stub's RSI-as-stack assumption
    // is what panics the second `uefi::println!` — there is no valid
    // stack frame for the image's efi_main to inherit.
    //
    // SOLUTION: skip the entry stub entirely and jump straight into
    // the body of `efi_main` at VMA 0x1800472a0 (the second `mov
    // $0x3f8,%dx; mov $0x57,%al; out %dx` pattern — see the file
    // offset 0x466a4 the disassembly confirms). This body uses the
    // System V AMD64 ABI (rdi / rsi) and only touches serial I/O
    // before any TLS / panic-personality access, so a bare jump is
    // safe as long as we hand it a proper stack.
    //
    // The body itself reads image_handle/SystemTable from the
    // caller-saved registers (rdi/rsi in System V) so we just need
    // to provide a private stack with a halt-address on top — and
    // because efi_main is `-> !` it never returns.
    use uefi::boot as ub2;

    // The PE's `AddressOfEntryPoint` already points straight at the body
    // of `efi_main` (the linker script groups .text.efi_main and uses
    // ENTRY(efi_main)). So we don't need a hardcoded VMA constant that
    // breaks every time the surrounding code shifts the `WINL>` prologue
    // — `efi_main_vma` was already computed above from the parsed PE.

    // Allocate 4 MiB of stack space for winload.efi. The loader and
    // kernel driver bring-up use recursive-looking allocations and
    // verbose diagnostics; 64 KiB is insufficient and overflows before
    // virtio queue setup completes.
    let stack_base = ub2::allocate_pages(
        ub2::AllocateType::AnyPages,
        ub2::MemoryType::BOOT_SERVICES_DATA,
        1024, // 4 MiB
    )
    .map_err(|_e| -> &'static str { "allocate winload stack" })?;
    let stack_top = stack_base.as_ptr() as u64 + 16 * 1024 * 1024;

    // Write a tiny halt stub at (stack_top - 16). If efi_main ever
    // returns (it shouldn't, since it's `-> !`), control goes here
    // and the machine simply halts.
    //
    // Encoding: `hlt; jmp $-2` = `0xF4 0xEB 0xFE`.
    let halt_addr = unsafe { arch::current::write_halt_stub(stack_top) };

    debug_println!(
        "[LAUNCH] Winload stack base=0x{:x} top=0x{:x} halt=0x{:x}",
        stack_base.as_ptr() as u64,
        stack_top,
        halt_addr
    );
    debug_println!("[LAUNCH] efi_main body VMA = 0x{:x}", efi_main_vma);
    debug_println!("[LAUNCH] =========================================");
    debug_println!("[LAUNCH] Winload should now take over boot!");
    debug_println!("[LAUNCH] =========================================");

    // Jump to efi_main. The body itself uses the Microsoft x64 ABI:
    // RCX = ImageHandle, RDX = SystemTable (per UEFI calling convention
    // for EFI image entry points). R8, R9 are free to clobber.
    //
    // Jump to efi_main. The body itself uses the Microsoft x64 ABI:
    // RCX = ImageHandle, RDX = SystemTable (per UEFI calling convention
    // for EFI image entry points). R8, R9 are free to clobber.
    unsafe { arch::current::launch_efi_main(image_handle, system_table, stack_top, efi_main_vma) }
}

/// Text-mode boot menu used when no GOP handle is available
/// (e.g. on QEMU virt machine for aarch64/riscv64). Prints the
/// list of boot entries to the UEFI console and auto-boots the
/// default selection after a brief countdown. Keyboard input is
/// honoured via Simple Text Input so the user can still pick a
/// different entry with arrow keys + ENTER.
fn text_mode_auto_boot(bcd_store: &BcdStore, entries: &[String]) -> Status {
    use uefi::boot as ub;

    uefi::println!("[BOOTMGR] text mode boot: GOP unavailable");
    debug_println!("[TEXT-BOOT] No graphics output - using text mode boot menu");
    debug_println!("===========================================");
    debug_println!("Windows Boot Manager (Text Mode)");
    debug_println!("===========================================");
    for (i, desc) in entries.iter().enumerate() {
        debug_println!("  [{}] {}", i + 1, desc);
    }
    debug_println!("");
    debug_println!("Auto-booting default entry in 5 seconds...");
    debug_println!("(Use UP/DOWN arrow keys to choose, ENTER to boot immediately.)");

    let mut menu = BootMenu::new(bcd_store);
    let mut selected = menu.selected_index();

    // Try to open the Simple Text Input protocol for arrow-key support
    let mut con_in = crate::input::Keyboard::new();

    let mut seconds_remaining: u32 = 5;
    loop {
        // Print current selection and countdown once per second
        debug_println!(
            "[TEXT-BOOT] Selected: [{}] {} ({}s)",
            selected + 1,
            entries.get(selected).map(|s| s.as_str()).unwrap_or("?"),
            seconds_remaining
        );

        // Wait up to 1 second for a key press
        if let Some(ref mut stdin) = con_in {
            // Poll for ~1 second (10 * 100ms)
            for _ in 0..10 {
                if let Some(key) = stdin.read_key() {
                    match key {
                        Key::Special(ScanCode::UP) => {
                            if selected > 0 {
                                selected -= 1;
                                menu.cancel_auto();
                                seconds_remaining = 5;
                                debug_println!(
                                    "[TEXT-BOOT] -> [{}] {}",
                                    selected + 1,
                                    entries.get(selected).map(|s| s.as_str()).unwrap_or("?")
                                );
                            }
                        }
                        Key::Special(ScanCode::DOWN) => {
                            if selected + 1 < entries.len() {
                                selected += 1;
                                menu.cancel_auto();
                                seconds_remaining = 5;
                                debug_println!(
                                    "[TEXT-BOOT] -> [{}] {}",
                                    selected + 1,
                                    entries.get(selected).map(|s| s.as_str()).unwrap_or("?")
                                );
                            }
                        }
                        Key::Printable(c)
                            if c == uefi::Char16::try_from('\r' as u16).unwrap()
                                || c == uefi::Char16::try_from('\n' as u16).unwrap() =>
                        {
                            debug_println!(
                                "[TEXT-BOOT] ENTER - booting [{}] {}",
                                selected + 1,
                                entries.get(selected).map(|s| s.as_str()).unwrap_or("?")
                            );
                            seconds_remaining = 0;
                            break;
                        }
                        _ => {}
                    }
                }
                ub::stall(core::time::Duration::from_millis(100));
            }
        } else {
            // No keyboard - just wait the full countdown
            ub::stall(core::time::Duration::from_secs(1));
        }

        if seconds_remaining == 0 {
            break;
        }
        seconds_remaining = seconds_remaining.saturating_sub(1);
    }

    // Re-create the BootMenu at the user's chosen index and launch it.
    // (BootMenu::new always picks index 1 by default; we move up/down to
    // match the user's selection.)
    let mut final_menu = BootMenu::new(bcd_store);
    let default_idx = final_menu.selected_index();
    if selected >= default_idx {
        for _ in 0..(selected - default_idx) {
            final_menu.move_down();
        }
    } else {
        for _ in 0..(default_idx - selected) {
            final_menu.move_up();
        }
    }

    match launch_selected(&final_menu) {
        Ok(()) => Status::SUCCESS,
        Err(e) => {
            debug_println!("[TEXT-BOOT] launch_selected failed: {}", e);
            Status::ABORTED
        }
    }
}

/// Write the BCD mailbox.
///
/// This follows the Windows 7 boot manager specification:
/// - Signature: "BCDE"
/// - Version: 0x00000003
/// - Length: 256 bytes
/// - Entry GUID: 16 bytes
/// - Boot options: variable
///
/// On architectures that permit low-memory access (x86_64), the
/// mailbox is written to a fixed physical address (`BCD_MAILBOX_PHYS`).
/// On architectures with stricter UEFI memory protections (aarch64,
/// riscv64), we allocate one page from the firmware, write the
/// mailbox there, and install the physical address as a UEFI
/// Configuration Table so winload can discover it.
fn write_bcd_mailbox(guid: &[u8; 16]) {
    use uefi::boot as ub;

    // Decide whether to use the fixed low address or a freshly
    // allocated page. We probe by trying to map the fixed address;
    // if the probe faults we fall back to allocation. Since we
    // can't catch a memory fault in UEFI directly, we instead
    // always use the safer allocation path on architectures that
    // we know have stricter protections. We identify those by
    // compiling in a target-specific constant below.
    let use_allocated = cfg!(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    ));

    let mailbox_phys: u64 = if use_allocated {
        // Allocate a single page for the mailbox.
        let page = ub::allocate_pages(
            ub::AllocateType::AnyPages,
            ub::MemoryType::BOOT_SERVICES_DATA,
            1,
        )
        .expect("[BCD] Failed to allocate page for BCD mailbox");
        page.as_ptr() as u64
    } else {
        BCD_MAILBOX_PHYS
    };

    let mailbox = mailbox_phys as *mut u8;

    unsafe {
        // Write signature
        core::ptr::write_volatile(mailbox.add(0) as *mut [u8; 4], BCD_MAILBOX_SIGNATURE);
        // Write version
        core::ptr::write_volatile(mailbox.add(4) as *mut u32, BCD_MAILBOX_VERSION);
        // Write length (256 bytes total)
        core::ptr::write_volatile(mailbox.add(8) as *mut u32, 256u32);
        // Write entry GUID (16 bytes starting at offset 0x0C)
        core::ptr::copy_nonoverlapping(guid.as_ptr(), mailbox.add(0x0C), 16);
        // Write boot options (e.g. "/safeboot:minimal") or clear the area.
        // The area is 224 bytes from offset 0x1C, NUL-terminated.
        let opts = BOOT_OPTIONS_OVERRIDE;
        if let Some(opts_str) = opts {
            let bytes = opts_str.as_bytes();
            let len = core::cmp::min(bytes.len(), 223);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), mailbox.add(0x1C), len);
            core::ptr::write_volatile(mailbox.add(0x1C + len), 0);
            for i in (len + 1)..224 {
                core::ptr::write_volatile(mailbox.add(0x1C + i), 0);
            }
        } else {
            for i in 0..224 {
                core::ptr::write_volatile(mailbox.add(0x1C + i), 0);
            }
        }
    }

    if use_allocated {
        // Publish the mailbox's physical address as a Configuration
        // Table entry. Winload looks for this GUID to find the
        // mailbox at runtime.
        let addr_bytes = mailbox_phys.to_le_bytes();
        let ptr = addr_bytes.as_ptr() as *const core::ffi::c_void;
        unsafe {
            let _ = ub::install_configuration_table(&BCD_MAILBOX_TABLE_GUID, ptr);
        }
        debug_println!(
            "[BCD] Mailbox written at allocated page 0x{:x}; ConfigTable GUID installed",
            mailbox_phys
        );
    } else {
        debug_println!(
            "[BCD] Mailbox written at fixed address 0x{:x}: sig=BCDE ver=0x{:08x} guid={:02x?}",
            mailbox_phys,
            BCD_MAILBOX_VERSION,
            guid
        );
    }
}

// =================================================================
// Minimal NTFS Reader
// =================================================================
//
// Per the Windows 7 on-disk layout, winload.efi lives on the System
// partition (NTFS or EXT4) at `C:\Windows\System32\winload.efi`. The
// UEFI firmware's native SimpleFileSystem protocol only understands
// FAT12/16/32, so the boot manager cannot read the System partition
// through the standard `OpenVolume` path.
//
// The implementation below is a *minimal* NTFS reader specialised
// for the boot-manager-only job of loading one file. It reads raw
// sectors through the Block I/O protocol and walks the MFT to
// resolve a single path to a `$DATA` stream. The reader supports:
//   - 512-byte sectors
//   - small directories that fit in a single $INDEX_ROOT entry
//   - resident and non-resident $DATA attributes
//
// The reader is deliberately small so the boot manager's BCD/BCD
// discovery path stays in a fixed 32 MiB ESP footprint. It is *not*
// a general-purpose NTFS implementation.

/// NTFS boot sector parameters extracted from the first sector.
struct NtfsBoot {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
    /// MFT start LCN — the raw value from the BPB at offset 0x30.
    /// This is a partition-relative LCN (cluster index from the start of
    /// the NTFS volume). To convert to a disk LBA, add `hidden_sectors`
    /// (the starting LBA of the partition) and multiply by `sectors_per_cluster`.
    mft_start_lcn: u64,
    mft_record_size: u32,
    /// Starting LBA of the NTFS partition on the disk. Read from the GPT
    /// partition table or the hidden_sectors field in the BPB.
    partition_start_lba: u64,
    /// Raw pointer to the BlockIO protocol for reading from this partition.
    /// This ensures we use the same protocol instance for all reads.
    block_io_ptr: usize,
}

impl NtfsBoot {
    /// Parse the NTFS boot sector (first 512 bytes of the partition).
    fn parse(
        buf: &[u8; 512],
        partition_start_lba: u64,
        block_io: *const uefi::proto::media::block::BlockIO,
    ) -> Option<Self> {
        // OEMID = "NTFS    " at offset 3
        if &buf[3..11] != b"NTFS    " {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let total_sectors = u64::from_le_bytes([
            buf[0x28], buf[0x29], buf[0x2A], buf[0x2B], buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F],
        ]);
        let mft_start_lcn = u64::from_le_bytes([
            buf[0x30], buf[0x31], buf[0x32], buf[0x33], buf[0x34], buf[0x35], buf[0x36], buf[0x37],
        ]);
        // MFT record size: byte 0x40 holds a signed value. Positive
        // value = 2^val clusters. Negative = 2^|val| bytes. For our
        // image builder, the value is 0xF6 = -10, which means
        // 2^10 = 1024 bytes per MFT record.
        let mft_raw = buf[0x40] as i8;
        let mft_record_size: u32 = if mft_raw >= 0 {
            (sectors_per_cluster as u32) * (bytes_per_sector as u32) << mft_raw
        } else {
            1u32 << (-mft_raw as u32)
        };
        Some(NtfsBoot {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_start_lcn,
            mft_record_size,
            partition_start_lba,
            block_io_ptr: block_io as usize,
        })
    }
}

/// Read `count` sectors starting at `disk_lba` (absolute disk LBA).
/// If `verify_ntfs_boot` is true, verifies the sector contains NTFS boot sector.
/// Returns the buffer.
fn read_mft_record(ntfs: &NtfsBoot, record_num: u64) -> Option<Vec<u8>> {
    use uefi::proto::media::block::BlockIO;

    // SAFETY: ntfs.block_io_ptr is a valid pointer to a BlockIO protocol
    // that was opened with Exclusive access and won't be closed until
    // read_ntfs_boot_file explicitly drops it.
    let block = unsafe { &*(ntfs.block_io_ptr as *const BlockIO) };
    let media = block.media();

    // The MFT LCN (cluster number) in the boot sector is partition-relative.
    // To compute the on-disk LBA of the MFT record:
    //   1. MFT partition-relative LBA = mft_start_lcn * sectors_per_cluster
    //   2. MFT disk LBA = partition_start_lba + MFT partition-relative LBA
    //   3. Record disk LBA = MFT disk LBA + record_num * records_per_sector
    let mft_partition_lba = ntfs.mft_start_lcn * (ntfs.sectors_per_cluster as u64);
    let mft_disk_lba = ntfs.partition_start_lba + mft_partition_lba;
    let sectors_per_record = ((ntfs.mft_record_size as u64 + 511) / 512) as u32;
    let record_rel_lba = record_num * (ntfs.mft_record_size as u64) / 512;
    let disk_lba = mft_disk_lba + record_rel_lba;

    let Some(mut buf) = try_alloc_zeroed((sectors_per_record as usize) * 512) else {
        debug_println!(
            "[NTFS] read_mft_record: allocation failed for LBA {}",
            disk_lba
        );
        return None;
    };
    if block
        .read_blocks(media.media_id(), disk_lba, &mut buf)
        .is_err()
    {
        debug_println!("[NTFS] read_mft_record: failed to read LBA {}", disk_lba);
        return None;
    }

    if buf.len() < ntfs.mft_record_size as usize {
        return None;
    }

    // Print first 16 bytes of MFT record for debugging
    let sig = &buf[0..4];
    debug_println!(
        "[NTFS] read_mft_record({}) disk_lba={} sig={:?} buf_len={}",
        record_num,
        disk_lba,
        sig,
        buf.len()
    );

    // Walk attributes and print types/lengths to help debug INDEX_ROOT lookup failures.
    let first_attr = u16::from_le_bytes([buf[0x14], buf[0x15]]) as usize;
    let mut off = first_attr;
    debug_println!("[NTFS]   first_attr_off={}", first_attr);
    let n = buf.len().min(512);
    while off + 8 <= n {
        let atype = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if atype == 0xFFFFFFFF {
            break;
        }
        let alen = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        if alen == 0 {
            break;
        }
        debug_println!("[NTFS]   attr 0x{:02x} off={} len={}", atype, off, alen);
        if atype == 0x90 {
            let body = off + 0x18;
            let ih_base = body + 0x0C;
            let e_off_rel = u32::from_le_bytes([
                buf[ih_base + 0x00],
                buf[ih_base + 0x01],
                buf[ih_base + 0x02],
                buf[ih_base + 0x03],
            ]);
            let total = u32::from_le_bytes([
                buf[ih_base + 0x04],
                buf[ih_base + 0x05],
                buf[ih_base + 0x06],
                buf[ih_base + 0x07],
            ]);
            let ih_flags = u32::from_le_bytes([
                buf[ih_base + 0x0C],
                buf[ih_base + 0x0D],
                buf[ih_base + 0x0E],
                buf[ih_base + 0x0F],
            ]);
            debug_println!(
                "[NTFS]     INDEX_ROOT body={} ih_base={} e_off_rel={} total={} ih_flags=0x{:x}",
                body,
                ih_base,
                e_off_rel,
                total,
                ih_flags
            );
        }
        off += alen as usize;
        if off > n {
            break;
        }
    }

    Some(buf)
}

/// Decode a UTF-16LE filename attribute (0x30) into a Rust `String`.
/// `off` is the byte offset of the FILE_NAME attribute's VALUE (not its
/// header) within the MFT record. The value layout is:
///   0x00: parent_ref (8)
///   0x08: creation_time (8)
///   0x10: last_data_change_time (8)
///   0x18: last_mft_change_time (8)
///   0x20: last_access_time (8)
///   0x28: allocated_size (8)
///   0x30: data_size (8)
///   0x38: file_attributes (4)
///   0x3C: reparse/ea (4) per [MS-FSCC] §2.6
///   0x40: name_length (1)
///   0x41: name_namespace (1)
///   0x42+: filename (UTF-16LE)
const DEBUG_NTFS: bool = false;

fn resolve_mft_record(ntfs: &NtfsBoot, path: &str) -> Option<u64> {
    if DEBUG_NTFS {
        debug_println!("[NTFS] resolve_mft_record: path='{}'", path);
    }
    // Windows paths use backslash (e.g. `\Windows\System32\winload.efi`)
    // but the `read_boot_file` dispatcher normalises incoming
    // `\` to `/` before calling us, so a path can arrive as
    // `Windows/System32/winload.efi`. Split on either separator
    // so the BCD's `\Windows\...` form AND the FAT-normalised
    // `Windows/...` form both recurse correctly through
    // Windows -> System32 -> winload.efi.
    let parts: alloc::vec::Vec<&str> = path
        .trim_start_matches(|c| c == '\\' || c == '/')
        .split(|c| c == '\\' || c == '/')
        .filter(|s| !s.is_empty())
        .collect();
    if DEBUG_NTFS {
        debug_println!("[NTFS]   parts={:?}", parts);
    }
    let mut current = 5u64; // Root directory
    for part in &parts {
        if DEBUG_NTFS {
            debug_println!("[NTFS]   resolving part '{}' from record {}", part, current);
        }
        current = find_child_in_index(ntfs, current, part)?;
    }
    Some(current)
}

/// Scan the `$INDEX_ROOT` of `parent_record` for an entry whose
/// filename matches `name`. Returns the child's MFT record number.
fn find_child_in_index(ntfs: &NtfsBoot, parent_record: u64, name: &str) -> Option<u64> {
    if DEBUG_NTFS {
        debug_println!(
            "[NTFS] find_child_in_index entered: parent={} name='{}'",
            parent_record,
            name
        );
    }
    let record = match read_mft_record(ntfs, parent_record) {
        Some(r) => r,
        None => {
            debug_println!("[NTFS]   read_mft_record({}) returned None", parent_record);
            return None;
        }
    };
    if &record[0..4] != b"FILE" {
        debug_println!(
            "[NTFS]   bad signature: {}",
            core::str::from_utf8(&record[0..4]).unwrap_or("?")
        );
        return None;
    }

    // Walk attributes. The first attribute offset is at byte 0x14
    // (relative to the start of the MFT record).
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    while off + 8 <= end {
        let attr_type = u32::from_le_bytes([
            record[off],
            record[off + 1],
            record[off + 2],
            record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4],
            record[off + 5],
            record[off + 6],
            record[off + 7],
        ]) as usize;
        if attr_len == 0 {
            break;
        }
        if off + attr_len > end {
            // Attribute runs past end of record. Skip rather than
            // abort the whole scan — some MFT records (especially
            // the root directory when it has a long INDEX_ROOT)
            // legitimately have attributes whose declared length
            // exceeds the record size because they were sized for
            // a larger record template. The kernel walks attributes
            // forward anyway, so we do the same.
            debug_println!(
                "[NTFS]   skipping attr 0x{:02x} at off={} len={} (>record end={})",
                attr_type,
                off,
                attr_len,
                end
            );
            off += attr_len;
            continue;
        }

        if attr_type == 0x90 {
            // $INDEX_ROOT attribute. The attribute header is 24 bytes, so the
            // value starts at off + 24 = off + 0x18 = `body`.
            // The INDEX_ROOT value layout is:
            //   value offset 0x00: indexed attribute type (0x30 = FILE_NAME)
            //   value offset 0x04: collation rule (0 = FILE_NAME collation)
            //   value offset 0x08: bytes per index record
            //   value offset 0x0C: clusters per index record
            //   value offset 0x10+: INDEX_HEADER (16 bytes):
            //     +0x00: first_entry_offset (relative to INDEX_HEADER start)
            //     +0x04: total_size
            //     +0x08: allocated_size
            //     +0x0C: flags
            //   value offset 0x20+: first index entry
            let body = off + 0x18; // skip 24-byte attr header
            if body + 0x20 > end {
                off += attr_len;
                continue;
            }
            // The NTFS-3G `index.c` / `layout.h` defines INDEX_HEADER fields
            // at relative offsets 0x00, 0x04, 0x08, 0x0C from the INDEX_HEADER start.
            // The NTFS spec places INDEX_HEADER at value offset 0x10, but the
            // builder actually places it at value offset 0x10 (the bytes_per_index_record
            // and clusters_per_index_record are between the indexed attr type and
            // INDEX_HEADER, not part of it). The boot code therefore reads
            // first_entry_offset from body + 0x10 + 0x00 = body + 0x10.
            let ih_base = body + 0x10;
            let first_entry_offset = u32::from_le_bytes([
                record[ih_base + 0x00],
                record[ih_base + 0x01],
                record[ih_base + 0x02],
                record[ih_base + 0x03],
            ]) as usize;
            let total_size = u32::from_le_bytes([
                record[ih_base + 0x04],
                record[ih_base + 0x05],
                record[ih_base + 0x06],
                record[ih_base + 0x07],
            ]) as usize;
            // Index entries start at ih_base + first_entry_offset.
            let entries_off = ih_base + first_entry_offset;
            if entries_off >= end {
                off += attr_len;
                continue;
            }
            // Walk index entries.
            let mut p = entries_off;
            let end_p = entries_off + total_size;
            // The outer `end` is the MFT record boundary (e.g. 1024 bytes).
            // `total_size` can be larger than the actual data due to padding,
            // so we must guard reads against the record boundary `end`.
            if DEBUG_NTFS {
                debug_println!("[NTFS] find_child_in_index: parent_record={} name='{}' entries_off={} total_size={} record_end={}", parent_record, name, entries_off, total_size, end);
            }
            // Loop condition: must have room for INDEX_ENTRY header (16 bytes)
            // AND stay within both the index-block boundary (end_p) and the
            // record boundary (end).
            while p + 16 <= end_p && p + 16 <= end {
                // ALWAYS print loop top so we can see whether the loop runs.
                debug_println!(
                    "[NTFS] LOOP: p=0x{:x} p+16=0x{:x} end_p=0x{:x} end=0x{:x}",
                    p,
                    p + 16,
                    end_p,
                    end
                );
                // Read entry_len at offset +0x08 (u16 LE).
                if p + 10 > end {
                    break;
                }
                let entry_len = u16::from_le_bytes([record[p + 8], record[p + 9]]) as usize;
                debug_println!(
                    "[NTFS]   entry_len raw at p+8: 0x{:02x}{:02x}",
                    record[p + 9],
                    record[p + 8]
                );
                if entry_len == 0 {
                    break;
                }
                if entry_len < 16 {
                    break;
                }

                // Guard the full entry against the RECORD boundary `end`.
                if p + entry_len > end {
                    break;
                }

                // flags at offset +0x0C (2 bytes)
                if p + 14 > end {
                    break;
                }
                let entry_flags = u16::from_le_bytes([record[p + 12], record[p + 13]]);

                // INDEX_ENTRY_END (0x0002): no key data follows — stop.
                if (entry_flags & 0x0002) != 0 {
                    if DEBUG_NTFS {
                        debug_println!(
                            "[NTFS]   STOP: END marker at p=0x{:x} flags=0x{:x}",
                            p,
                            entry_flags
                        );
                    }
                    break;
                }

                // key_length is at offset +0x0A of the INDEX_ENTRY.
                let key_len = u16::from_le_bytes([record[p + 10], record[p + 11]]) as usize;
                if DEBUG_NTFS {
                    debug_println!(
                        "[NTFS]   entry at p=0x{:x} len={} key_len={} flags=0x{:x}",
                        p,
                        entry_len,
                        key_len,
                        entry_flags
                    );
                }
                if key_len < 66 {
                    if DEBUG_NTFS {
                        debug_println!("[NTFS]   SKIP: key_len {} < 66", key_len);
                    }
                    p += entry_len;
                    continue;
                }

                // A `$INDEX_ROOT` key is not a resident attribute: the
                // `FILE_NAME` value itself begins at `p + 0x10` (after the
                // 16-byte `INDEX_ENTRY` header). There is no 24-byte
                // attribute header in this context.
                // The FILE_NAME value layout:
                //   +0x00: parent_ref (8 bytes)
                //   +0x08: creation_time (8 bytes)
                //   +0x10: last_data_change_time (8 bytes)
                //   +0x18: last_mft_change_time (8 bytes)
                //   +0x20: last_access_time (8 bytes)
                //   +0x28: allocated_size (8 bytes)
                //   +0x30: data_size (8 bytes)
                //   +0x38: file_attributes (4 bytes)
                //   +0x3C: reparse/ea (4 bytes) per [MS-FSCC] §2.6
                //   +0x40: name_length (1 byte)
                //   +0x41: name_namespace (1 byte)
                //   +0x42+: filename (UTF-16LE)
                //
                // The previous layout in this function treated the
                // 0x3C..0x40 range as `packed_ea_size (2) + reserved (2)`
                // and put `name_length` at value+0x3E. That matches the
                // layout the kernel emits in MFT records only when the
                // build-tool's FILE_NAME attribute writer uses 0x3E,
                // which it does not — it writes `name_length` at +0x40,
                // so the kernel sees the byte at +0x3E as a padding
                // zero. Fixing both offsets here aligns this code
                // path with what winload.efi's `walk_index_entries`
                // already does after the same bug was repaired there.
                let fname_value_off = p + 0x10;

                // name_length is at FILE_NAME value offset +0x40.
                let name_len_offset = fname_value_off + 0x40;
                let name_len_chars = record[name_len_offset] as usize;
                if DEBUG_NTFS {
                    debug_println!(
                        "[NTFS]   file_name_value=0x{:x} name_len_chars={}",
                        fname_value_off,
                        name_len_chars
                    );
                }
                if name_len_chars == 0 || name_len_chars > 255 {
                    // Step to next entry
                    p += entry_len;
                    continue;
                }

                // name starts at FILE_NAME value offset +0x42.
                let name_start = fname_value_off + 0x42;
                // Show first few bytes of filename area for debugging
                if DEBUG_NTFS {
                    debug_println!("[NTFS]   name_start=0x{:x}", name_start);
                }
                // Ensure name fits within the record boundary `end`.
                if name_start + name_len_chars * 2 > end {
                    debug_println!("[NTFS]   SKIP: name_start + name_len*2 > end");
                    p += entry_len;
                    continue;
                }

                // Decode the UTF-16LE filename.
                // `buf` is the full record (1024 bytes), `fname_off` is a record offset,
                // so `buf.len()` is the record length.
                let mut decoded_name = alloc::string::String::new();
                for i in 0..name_len_chars {
                    let c = u16::from_le_bytes([
                        record[name_start + i * 2],
                        record[name_start + i * 2 + 1],
                    ]);
                    if c == 0 {
                        continue;
                    }
                    if let Some(ch) = char::from_u32(c as u32) {
                        decoded_name.push(ch);
                    }
                }
                debug_println!("[NTFS]   decoded name='{}'", decoded_name);

                if DEBUG_NTFS {
                    let child_ref = u64::from_le_bytes([
                        record[p],
                        record[p + 1],
                        record[p + 2],
                        record[p + 3],
                        record[p + 4],
                        record[p + 5],
                        record[p + 6],
                        record[p + 7],
                    ]);
                    debug_println!(
                        "[NTFS]   entry: ref=0x{:x} fname='{}' key_len={}",
                        child_ref,
                        decoded_name,
                        key_len
                    );
                }

                // Case-insensitive compare: convert both to lowercase ASCII for comparison.
                let decoded_lower: alloc::string::String = decoded_name
                    .chars()
                    .map(|c| {
                        if c >= 'A' && c <= 'Z' {
                            (c as u8 + 0x20) as char
                        } else {
                            c
                        }
                    })
                    .collect();
                let name_lower: alloc::string::String = name
                    .chars()
                    .map(|c| {
                        if c >= 'A' && c <= 'Z' {
                            (c as u8 + 0x20) as char
                        } else {
                            c
                        }
                    })
                    .collect();
                if DEBUG_NTFS {
                    debug_println!(
                        "[NTFS]     comparing '{}' vs '{}'",
                        decoded_lower,
                        name_lower
                    );
                }
                if decoded_lower == name_lower {
                    let child_ref = u64::from_le_bytes([
                        record[p],
                        record[p + 1],
                        record[p + 2],
                        record[p + 3],
                        record[p + 4],
                        record[p + 5],
                        record[p + 6],
                        record[p + 7],
                    ]);
                    return Some(child_ref & 0x0000_FFFF_FFFF_FFFF);
                }

                p += entry_len;
            }
        }

        off += attr_len;
    }
    debug_println!("[NTFS]   no match for '{}'", name);
    None
}

/// Read the `$DATA` stream of `record_num` and return its contents.
fn read_data_stream(ntfs: &NtfsBoot, record_num: u64) -> Option<Vec<u8>> {
    let record = read_mft_record(ntfs, record_num)?;
    if &record[0..4] != b"FILE" {
        return None;
    }
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off],
            record[off + 1],
            record[off + 2],
            record[off + 3],
        ]);
        if attr_type == 0xFFFFFFFF {
            break;
        }
        let attr_len = u32::from_le_bytes([
            record[off + 4],
            record[off + 5],
            record[off + 6],
            record[off + 7],
        ]) as usize;
        if attr_len == 0 || off + attr_len > end {
            break;
        }
        let non_resident = record[off + 8];
        if attr_type == 0x80 {
            if non_resident == 0 {
                // Resident: data lives at off + 0x18.
                let content_size = u32::from_le_bytes([
                    record[off + 0x10],
                    record[off + 0x11],
                    record[off + 0x12],
                    record[off + 0x13],
                ]) as usize;
                let content_off =
                    u16::from_le_bytes([record[off + 0x14], record[off + 0x15]]) as usize;
                if off + content_off + content_size <= end {
                    return Some(
                        record[off + content_off..off + content_off + content_size].to_vec(),
                    );
                }
            } else {
                // Run-list walk for non-resident $DATA.
                //
                // We emit a single contiguous run in the builder, so
                // the run list should normally contain exactly one
                // entry. We still walk defensively in case the on-disk
                // MFT record has more. The run's LCN translates to a
                // partition-relative LBA, and the run's clusters map
                // 1:1 to bytes at the file-relative cursor
                // (`out_cursor`).
                let real_size = u64::from_le_bytes([
                    record[off + 0x30],
                    record[off + 0x31],
                    record[off + 0x32],
                    record[off + 0x33],
                    record[off + 0x34],
                    record[off + 0x35],
                    record[off + 0x36],
                    record[off + 0x37],
                ]);
                let alloc_size = u64::from_le_bytes([
                    record[off + 0x28],
                    record[off + 0x29],
                    record[off + 0x2A],
                    record[off + 0x2B],
                    record[off + 0x2C],
                    record[off + 0x2D],
                    record[off + 0x2E],
                    record[off + 0x2F],
                ]);
                let _init_size = u64::from_le_bytes([
                    record[off + 0x38],
                    record[off + 0x39],
                    record[off + 0x3A],
                    record[off + 0x3B],
                    record[off + 0x3C],
                    record[off + 0x3D],
                    record[off + 0x3E],
                    record[off + 0x3F],
                ]);
                // RunList offset lives at attribute + 0x20 for non-resident
                // $DATA, matching `build_non_resident_data_attr`:
                //   0x10  StartingVCN (8)
                //   0x18  LastVCN     (8)
                //   0x20  RunListOffset (2)
                //   0x28  AllocSize   (8)
                //   0x30  RealSize    (8)
                //   0x38  InitSize    (8)
                // An earlier version of this routine read the offset from
                // off+0x38 (the initialized-size field), so it skipped the
                // run list entirely and returned an all-zero image.
                let run_off = u16::from_le_bytes([record[off + 0x20], record[off + 0x21]]) as usize;
                let mut p = off + run_off;
                let mut out: Vec<u8> = alloc::vec![0u8; alloc_size as usize];
                let mut prev_lcn: i64 = 0;
                let mut out_cursor: usize = 0;
                while p < off + attr_len {
                    let header = record[p];
                    if header == 0 {
                        break;
                    }
                    let len_len = (header & 0x0F) as usize;
                    let off_len = ((header >> 4) & 0x0F) as usize;
                    p += 1;
                    if p + len_len + off_len > off + attr_len {
                        break;
                    }
                    let mut run_clusters: u64 = 0;
                    for i in 0..len_len {
                        run_clusters |= (record[p + i] as u64) << (8 * i);
                    }
                    p += len_len;
                    let mut lcn_delta: i64 = 0;
                    for i in 0..off_len {
                        lcn_delta |= (record[p + i] as i64) << (8 * i);
                    }
                    if off_len > 0 && (record[p + off_len - 1] & 0x80) != 0 {
                        lcn_delta |= -1i64 << (8 * off_len);
                    }
                    p += off_len;
                    let lcn = (prev_lcn + lcn_delta) as u64;
                    prev_lcn += lcn_delta;
                    let sector_size = (ntfs.sectors_per_cluster as u64) * 512;
                    // Run-list LCNs are partition-relative. Convert to absolute disk LBA.
                    let partition_rel_lba = lcn * (ntfs.sectors_per_cluster as u64);
                    let disk_lba = ntfs.partition_start_lba + partition_rel_lba;
                    let byte_count = run_clusters * sector_size;
                    let cluster_count = run_clusters as u32;
                    debug_println!("[NTFS-RUN] run_clusters={} lcn_delta={} lcn={} disk_lba={} byte_count={} cluster_count={}",
                        run_clusters, lcn_delta, lcn, disk_lba, byte_count, cluster_count);
                    // Use the persistent BlockIO protocol from ntfs.block_io_ptr
                    // instead of opening a new one each time. This avoids
                    // close_protocol panics.
                    use uefi::proto::media::block::BlockIO;
                    let block = unsafe { &*(ntfs.block_io_ptr as *const BlockIO) };
                    let media = block.media();
                    // BUGFIX: the buffer MUST be sized to the *whole run*
                    // (`byte_count` == `run_clusters * sector_size`), not
                    // `run_clusters * 512`. The old formula only fetched
                    // `sectors_per_cluster==1` worth of bytes per cluster
                    // and silently left the tail of the file filled with
                    // zeros — that is why winload's `.rdata`/`.data`/...
                    // sections were zero in RAM even though the on-disk
                    // bytes were valid.
                    let alloc_size_usize =
                        core::cmp::min(byte_count as usize, out.len() - out_cursor);
                    let mut data = alloc::vec![0u8; alloc_size_usize];
                    // write a marker so we can detect whether read_blocks
                    // actually wrote anything to the buffer.
                    for i in 0..alloc_size_usize {
                        data[i] = 0xfe;
                    }
                    let mut copy_len: usize = 0;
                    if block
                        .read_blocks(media.media_id(), disk_lba, &mut data)
                        .is_ok()
                    {
                        copy_len = data.len().min(out.len() - out_cursor);
                        // Verify read_blocks actually wrote real data
                        // (not 0xfe placeholder).
                        let mut non_fe_count = 0;
                        for i in 0..alloc_size_usize.min(4096) {
                            if data[i] != 0xfe {
                                non_fe_count += 1;
                            }
                        }
                        debug_println!("[NTFS-RUN]   first 4096 bytes: {} non-placeholder (verify={:02x} {:02x} {:02x} {:02x})",
                            non_fe_count, data[0], data[1], data[2], data[3]);
                        out[out_cursor..out_cursor + copy_len].copy_from_slice(&data[..copy_len]);
                        debug_println!(
                            "[NTFS-RUN]   copied {} bytes to out_cursor={}",
                            copy_len,
                            out_cursor
                        );
                    } else {
                        debug_println!("[NTFS-RUN]   read_blocks FAILED for disk_lba={}", disk_lba);
                    }
                    out_cursor += copy_len;
                    // SAFETY: do NOT advance by byte_count here, because
                    // the *last* run of the file is usually shorter than
                    // a full run (`byte_count` rounds up to sector_size).
                    // The next run-list entry will simply not exist; the
                    // caller truncates to `real_size` afterwards.
                }
                // Trim to real_size so the caller sees the exact file length.
                out.truncate(real_size as usize);
                return Some(out);
            }
        }
        off += attr_len;
    }
    None
}

/// Public entry point: try to read `rel_path` (Windows-style, e.g.
/// Parse GPT partition table to find the starting LBA of the NTFS partition.
/// Returns (partition_start_lba, partition_sectors) or None if not found.
fn read_ntfs_boot_file_for(
    rel_path: &str,
    block_io: &uefi::proto::media::block::BlockIO,
    partition_start_lba: u64,
) -> Option<Vec<u8>> {
    let media = block_io.media();
    let media_id = media.media_id();
    debug_println!(
        "[NTFS] read_ntfs_boot_file_for: block_size={} media_id={} part_lba={}",
        media.block_size(),
        media_id,
        partition_start_lba
    );

    // Read the NTFS boot sector from `partition_start_lba`. For
    // partition-scoped handles that is just 0; for disk-scoped handles
    // it is the GPT-reported start of the NTFS entry.
    let mut boot_sector = [0u8; 512];
    if block_io
        .read_blocks(media_id, partition_start_lba, &mut boot_sector)
        .is_err()
    {
        debug_println!(
            "[NTFS] Failed to read boot sector at LBA {}",
            partition_start_lba
        );
        return None;
    }
    if &boot_sector[3..11] != b"NTFS    " {
        debug_println!(
            "[NTFS] Probe said NTFS but LBA {} OEM ID is {:?} — bailing",
            partition_start_lba,
            core::str::from_utf8(&boot_sector[3..11]).unwrap_or("?")
        );
        return None;
    }

    let ntfs = match NtfsBoot::parse(&boot_sector, partition_start_lba, block_io as *const _) {
        Some(n) => n,
        None => {
            debug_println!("[NTFS] NTFS boot sector parse failed");
            return None;
        }
    };

    debug_println!(
        "[NTFS] mount: bps={} spc={} mft_lcn={} mft_rec_sz={} total_sectors={}",
        ntfs.bytes_per_sector,
        ntfs.sectors_per_cluster,
        ntfs.mft_start_lcn,
        ntfs.mft_record_size,
        ntfs.total_sectors
    );

    let record = match resolve_mft_record(&ntfs, rel_path) {
        Some(r) => r,
        None => {
            debug_println!("[NTFS] resolve_mft_record FAILED for {}", rel_path);
            return None;
        }
    };
    debug_println!("[NTFS] {} -> MFT record {}", rel_path, record);

    let data_opt = read_data_stream(&ntfs, record);
    if let Some(ref d) = data_opt {
        debug_println!(
            "[NTFS] read_data_stream returned {} bytes, first 32 bytes: {:02x?}",
            d.len(),
            &d[..32.min(d.len())]
        );
    } else {
        debug_println!("[NTFS] read_data_stream returned None");
    }
    data_opt
}
