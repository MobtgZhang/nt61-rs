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

#![no_std]
#![no_main]
#![allow(dead_code)]

extern crate alloc;

mod bcd;
mod bcd_parser;
mod bcd_registry;
mod bcd_types;
mod bcd_mailbox;
mod fat_lfn;
mod file;
mod font;
mod font_ttf;
mod graphics;
mod renderer;
mod menu;
mod boot_ui;
mod loading;
mod memdiag_ui;
mod nvram;

use bcd::BcdStore;
use menu::BootMenu;
use uefi::prelude::*;
use uefi::proto::console::text::{Color, Key, ScanCode};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode, RegularFile};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use uefi::CString16;

use crate::graphics::FramebufferInfo;
use crate::renderer::Framebuffer;
use crate::font::BitmapFont;

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
const BCD_MAILBOX_TABLE_GUID: uefi::Guid =
    uefi::Guid::from_bytes([0x8B, 0xC9, 0xC6, 0xA0, 0x5B, 0x47, 0x4D, 0xCA,
                            0x8E, 0x40, 0xDB, 0x22, 0xCA, 0x1D, 0x5A, 0x6B]);

/// BCD mailbox signature "BCDE"
const BCD_MAILBOX_SIGNATURE: [u8; 4] = [b'B', b'C', b'D', b'E'];

/// BCD mailbox version for Windows 7
const BCD_MAILBOX_VERSION: u32 = 0x00000003;

/// Physical address of the framebuffer handoff mailbox.
/// Boot manager writes the GOP framebuffer info here before
/// `StartImage` hands control to winload. Winload reads the
/// same address to recover the framebuffer pointer — UEFI
/// `StartImage` does not pass arguments from bootmgr to the
/// loaded image, so anything we want to forward has to live
/// at a known PA.
const FB_MAILBOX_PHYS: u64 = 0x10_200;

/// Framebuffer mailbox signature "FBHM" (FrameBuffer Hand-off Mailbox)
const FB_MAILBOX_SIGNATURE: [u8; 4] = [b'F', b'B', b'H', b'M'];

/// Framebuffer mailbox version
const FB_MAILBOX_VERSION: u32 = 0x00000001;

// =====================================================================
// Low-level text rendering helpers
// =====================================================================

/// Convert a Rust string to UCS-2 encoded u16 array with null terminator.
fn to_cstr16(s: &str) -> alloc::vec::Vec<u16> {
    let mut buf: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    buf.push(0);
    buf
}

/// Fill a row with `ch` in the given colour, starting at column `start`
/// and writing `count` cells. The fill is clamped to `[start, columns)`
/// so a too-large `count` cannot wrap onto the next row.
fn fill_row_chars(
    stdout: &mut uefi::proto::console::text::Output,
    row: usize,
    ch: u16,
    start: usize,
    count: usize,
    columns: usize,
    fg: Color,
    bg: Color,
) {
    let _ = stdout.set_color(fg, bg);
    let buf: [u16; 2] = [ch, 0];
    let cstr = uefi::CStr16::from_u16_with_nul(&buf).unwrap();
    let s = start.min(columns);
    let end = s.saturating_add(count).min(columns);
    for x in s..end {
        let _ = stdout.set_cursor_position(x, row);
        let _ = stdout.output_string(&cstr);
    }
}

/// Print a string starting at column `col`, truncated to fit in
/// `columns` columns. If truncated, adds ".." at the end.
fn print_at(
    stdout: &mut uefi::proto::console::text::Output,
    col: usize,
    row: usize,
    text: &str,
    columns: usize,
) {
    let max_cols = columns.saturating_sub(col);
    if max_cols < 3 {
        return;
    }

    // Count characters, not bytes, and leave room for truncation indicator
    let available = max_cols - 2;
    let mut char_count = 0;
    let mut last_valid_end = 0;

    for (byte_idx, c) in text.char_indices() {
        if char_count >= available {
            break;
        }
        char_count += 1;
        last_valid_end = byte_idx + c.len_utf8();
    }

    let slice: String = if last_valid_end < text.len() {
        // Text was truncated - append ".."
        let mut s = String::from(&text[..last_valid_end]);
        s.push_str("..");
        s
    } else {
        text.to_string()
    };

    let buf = to_cstr16(&slice);
    let _ = stdout.set_cursor_position(col, row);
    let _ = stdout.output_string(&uefi::CStr16::from_u16_with_nul(&buf).unwrap());
}

/// Center a string within `[start, end)`. Returns the starting column.
fn centre_text(text: &str, start: usize, end: usize) -> usize {
    let len = text.chars().count();
    let width = end.saturating_sub(start);
    if len >= width {
        start
    } else {
        start + (width - len) / 2
    }
}

/// Hard-wrap a string into lines that fit in `width` columns. The first
/// line is prefixed with `first_prefix`; continuation lines are prefixed
/// with `cont_prefix` (the "hanging indent" used in the Advanced menu's
/// description). Whitespace is collapsed.
/// Word-wrap `text` into lines no wider than `width` characters
/// (counted in Unicode scalar values, not bytes). Returns at least one
/// line (which may be empty).
///
/// `first_prefix` and `cont_prefix` are prepended to the first /
/// subsequent lines respectively, and are accounted for in the width
/// budget. Pass `""` for both if you just want raw wrap.
///
/// The implementation is intentionally straightforward: split on
/// whitespace, accumulate words into the current line, flush when the
/// next word would not fit.
fn wrap_text(
    text: &str,
    width: usize,
    first_prefix: &str,
    cont_prefix: &str,
) -> alloc::vec::Vec<String> {
    let mut out: alloc::vec::Vec<String> = alloc::vec::Vec::new();

    if width == 0 {
        out.push(String::from(first_prefix));
        return out;
    }
    if first_prefix.chars().count() >= width {
        out.push(String::from(first_prefix));
        return out;
    }

    // Collect words once.
    let words: alloc::vec::Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        out.push(String::from(first_prefix));
        return out;
    }

    let mut line = String::from(first_prefix);
    let mut is_first = true;

    for word in words {
        // Pick the active prefix/budget for this line.
        let prefix_len = if is_first {
            first_prefix.chars().count()
        } else {
            cont_prefix.chars().count()
        };
        let _budget = width.saturating_sub(prefix_len);
        let cur_len = line.chars().count();
        let wlen = word.chars().count();

        // If the word itself is longer than the whole line budget, we
        // have to hard-break it. Flush whatever is in `line` first if
        // non-empty, then emit the word in chunks of `width` chars
        // (each on its own line).
        if wlen >= width {
            if !line.is_empty() {
                out.push(line);
                line = String::from(cont_prefix);
            }
            let mut remaining = word;
            while remaining.chars().count() > width {
                let (chunk, rest) = remaining.split_at(
                    remaining
                        .char_indices()
                        .nth(width)
                        .map(|(i, _)| i)
                        .unwrap_or(remaining.len()),
                );
                if !line.is_empty() {
                    out.push(line);
                }
                out.push(String::from(chunk));
                line = String::from(cont_prefix);
                remaining = rest;
                let _ = remaining;
            }
            // Append whatever is left of the word to the current line.
            line.push_str(remaining);
            is_first = false;
            continue;
        }

        // Decide whether the word fits on the current line. We need at
        // least 1 separator space if the line already has content.
        let need_space = cur_len > prefix_len;
        let need = wlen + if need_space { 1 } else { 0 };
        if cur_len + need > width {
            // Flush and start a new line.
            out.push(line);
            line = String::from(cont_prefix);
            line.push_str(word);
        } else {
            if need_space {
                line.push(' ');
            }
            line.push_str(word);
        }
        is_first = false;
    }

    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::from(first_prefix));
    }
    out
}

// =====================================================================
// Layout
// =====================================================================

/// All row numbers needed to draw the screen. Filled in at startup once
/// the text mode is known.
struct Geometry {
    columns: usize,
    rows: usize,
    /// Bar left/right margins (8% on each side, matching the HTML).
    bar_left: usize,
    bar_right: usize,
    /// Body left/right margin.
    body_left: usize,
    body_right_col: usize,
    /// Rows.
    title_row: usize,
    prompt_row: usize,
    hint_row: usize,
    /// First entry row.
    entries_start: usize,
    f8_row: usize,
    countdown_row: usize,
    tools_label_row: usize,
    tools_entry_row: usize,
    /// Description label row (Advanced screen).
    desc_label_row: usize,
    /// First description text row.
    desc_text_start: usize,
    /// Number of rows available for wrapped description text.
    desc_text_rows: usize,
    footer_row: usize,
}

impl Geometry {
    fn compute(columns: usize, rows: usize, entry_count: usize) -> Self {
        // Bars span from 8% to 92% of the screen width (matching
        // `.titlebar` / `.statusbar` `left:8% right:8%` in the
        // reference HTML).
        let bar_margin = (columns * 8) / 100;
        let bar_left = bar_margin;
        let bar_right = columns.saturating_sub(bar_margin);
        // Body content left margin = 8% (HTML: left:8%), right
        // margin = 4% (HTML: right:4% on .header/.menu).
        let body_left = (columns * 8) / 100;
        let body_right = (columns * 4) / 100;
        let body_right_col = columns.saturating_sub(body_right);

        // Title and footer are pinned to the absolute top/bottom edges.
        let title_row = 0;
        let footer_row = rows.saturating_sub(1);

        // Body sections are placed at fixed *percentage* rows of the
        // screen so the layout matches the reference HTML (where
        // .body sits at top:9.5%, .midblock at top:49%, .tools at
        // top:68%). Vertical *gaps* between sections mirror the
        // 1.4-1.6em `margin-bottom` rules in `windows-boot-manager.html`
        // (hint→os-list 1.6em, tools-label→tool-item 1.4em) — one
        // blank row in text mode is the closest analogue.
        let prompt_row = (rows * 10) / 100; // ~10%
        let hint_row = prompt_row + 1; // immediately below
        // 1 blank row between the hint-line and the first boot entry
        // (HTML: `.hint-line { margin-bottom: 1.6em }`).
        let entries_start = hint_row + 2;
        let f8_row = (rows * 49) / 100; // ~49%
        let countdown_row = f8_row + 1; // immediately below
        let tools_label_row = (rows * 68) / 100; // ~68%
        // 1 blank row between the "Tools:" label and the tool item
        // (HTML: `.tools-label { margin-bottom: 1.4em }`).
        let tools_entry_row = tools_label_row + 2;
        let _ = entry_count; // entries flow from entries_start downward

        // Description region on the Advanced screen. The label sits
        // 5 rows above the bottom bar (one row higher than before, so
        // the whole description panel reads as closer to the middle of
        // the screen and matches the `bottom:9.5%` of `.description`
        // in `advanced-boot-options.html`). The wrapped text fills
        // the rows between the label and the bottom bar.
        let desc_label_row = rows.saturating_sub(5);
        let desc_text_start = desc_label_row + 1;
        // Cap the wrapped text so it cannot bleed into the bottom
        // bar, but allow up to 3 rows of text on taller screens.
        let desc_text_rows = rows
            .saturating_sub(1) // bottom bar
            .saturating_sub(desc_text_start)
            .min(3);

        Self {
            columns,
            rows,
            bar_left,
            bar_right,
            body_left,
            body_right_col,
            title_row,
            prompt_row,
            hint_row,
            entries_start,
            f8_row,
            countdown_row,
            tools_label_row,
            tools_entry_row,
            desc_label_row,
            desc_text_start,
            desc_text_rows,
            footer_row,
        }
    }
}

// =====================================================================
// Video mode selection
// =====================================================================

/// Pick the text mode with the most columns. Returns (columns, rows).
fn pick_largest_mode(stdout: &mut uefi::proto::console::text::Output) -> (usize, usize) {
    let mut best: Option<uefi::proto::console::text::OutputMode> = None;
    for mode in stdout.modes() {
        best = Some(match best {
            None => mode,
            Some(prev) => {
                if mode.columns() > prev.columns() {
                    mode
                } else {
                    prev
                }
            }
        });
    }
    if let Some(mode) = best {
        let _ = stdout.set_mode(mode);
        (mode.columns(), mode.rows())
    } else {
        (80, 25)
    }
}

// =====================================================================
// Boot entry list
// =====================================================================

fn get_boot_entry_descriptions(bcd: &BcdStore) -> alloc::vec::Vec<String> {
    let mut entries = alloc::vec::Vec::new();
    for i in 0..bcd.entry_count {
        if let Some(entry) = bcd.get_entry(i) {
            let desc_slice = entry.description.as_slice();
            let mut desc_str = String::new();
            for &ch in desc_slice {
                if ch != 0 && ch != 0xFF {
                    if let Some(c) = char::from_u32(ch as u32) {
                        desc_str.push(c);
                    }
                }
            }
            if desc_str.is_empty() {
                desc_str = String::from("Unknown Entry");
            }
            entries.push(desc_str);
        }
    }
    entries
}

// =====================================================================
// Primitives
// =====================================================================

fn clear_screen(stdout: &mut uefi::proto::console::text::Output, geo: &Geometry) {
    for y in 0..geo.rows {
        paint_black(stdout, y, 0, geo.columns);
    }
}

/// Draw a gray bar across `[bar_left, bar_right)` on `row`, with `text`
/// centred in black on light-gray. Outside the bar is left untouched.
fn draw_gray_bar(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    row: usize,
    text: &str,
) {
    let n = geo.bar_right.saturating_sub(geo.bar_left);
    fill_row_chars(
        stdout,
        row,
        b' ' as u16,
        geo.bar_left,
        n,
        geo.columns,
        Color::Black,
        Color::LightGray,
    );
    if !text.is_empty() {
        let col = centre_text(text, geo.bar_left, geo.bar_right);
        let _ = stdout.set_color(Color::Black, Color::LightGray);
        print_at(stdout, col, row, text, geo.columns);
    }
    park_cursor(stdout);
}

/// Paint a horizontal highlight segment on `row` between `[start, end)`.
/// The bar is fully filled with the bg colour (no full-row redraw).
/// CRITICAL: Always park cursor after drawing to prevent cursor artifacts.
fn paint_bar(
    stdout: &mut uefi::proto::console::text::Output,
    row: usize,
    start: usize,
    end: usize,
    fg: Color,
    bg: Color,
) {
    let _ = stdout.set_color(fg, bg);
    let buf: [u16; 2] = [b' ' as u16, 0];
    let cstr = uefi::CStr16::from_u16_with_nul(&buf).unwrap();
    for x in start..end {
        let _ = stdout.set_cursor_position(x, row);
        let _ = stdout.output_string(&cstr);
    }
    // CRITICAL: Park cursor at known-safe position to prevent artifacts
    park_cursor(stdout);
}

/// Park the cursor at a known-invisible position. With the caret hidden
/// (`enable_cursor(false)`) the firmware still keeps the *position* and
/// will redraw the reverse-video block on the next set_cursor_position.
/// On some firmwares the cursor is implicitly rendered as soon as
/// `output_string` finishes, so we always re-home the cursor to (0, 0)
/// after the last visible string of a draw. Calling this on top of
/// the top bar's centred title hides the cursor behind already-painted
/// cells (the title is in the centre, not at column 0).
fn park_cursor(stdout: &mut uefi::proto::console::text::Output) {
    // Set a palette of (black, black) and then move the cursor to
    // column 0 of row 0. With the caret hidden by enable_cursor(false)
    // this guarantees the firmware's internal cursor position is in a
    // safe place and no stray reverse-video block is rendered on the
    // last drawn cell.
    let _ = stdout.set_color(Color::Black, Color::Black);
    let _ = stdout.set_cursor_position(0, 0);
}

/// Paint a row in solid black by writing spaces in fg=Black, bg=Black.
fn paint_black(
    stdout: &mut uefi::proto::console::text::Output,
    row: usize,
    start: usize,
    end: usize,
) {
    paint_bar(stdout, row, start, end, Color::Black, Color::Black);
}

/// Draw a body line that starts at the left body margin. The cells
/// between `body_left` and the right body margin are first re-painted
/// BLACK (no white bars) so the line wipes any leftover content from a
/// previous frame. Text is white-on-black.
fn draw_body_line(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    row: usize,
    text: &str,
) {
    paint_black(stdout, row, geo.body_left, geo.body_right_col);
    let _ = stdout.set_color(Color::White, Color::Black);
    print_at(stdout, geo.body_left, row, text, geo.columns);
    park_cursor(stdout);
}

// =====================================================================
// Main screen drawing
// =====================================================================

/// Draw a single boot entry on `row`. Paints the full row in the
/// appropriate palette and writes the label (with a leading ">" for the
/// selected row).
/// Compute the column range of the entry highlight bar (matches the
/// `width: 78%` of `.os-item` in the reference HTML — roughly 4/5 of
/// the screen width starting at the left body margin).
fn entry_bar_range(geo: &Geometry) -> (usize, usize) {
    let width = (geo.columns * 78) / 100;
    let start = geo.body_left;
    let end = (start + width).min(geo.columns);
    (start, end)
}

/// Draw a single boot entry on `row`. The selected row is rendered with
/// an inverted (black-on-light-gray) highlight bar that spans ~78% of the
/// screen width starting at the left body margin. Unselected rows are
/// written in white-on-black with no surrounding bar.
fn draw_entry_row(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    row: usize,
    text: &str,
    selected: bool,
) {
    let (bar_start, bar_end) = entry_bar_range(geo);
    if selected {
        // Paint the highlight bar first, then write the text in the
        // inverted palette.
        paint_bar(stdout, row, bar_start, bar_end, Color::Black, Color::LightGray);
        let _ = stdout.set_color(Color::Black, Color::LightGray);
        print_at(stdout, bar_start, row, ">", geo.columns);
        print_at(stdout, bar_start + 2, row, text, geo.columns);
    } else {
        // Wipe the bar region (in case the row was selected last frame)
        // and write the label in white-on-black.
        paint_black(stdout, row, bar_start, bar_end);
        let _ = stdout.set_color(Color::White, Color::Black);
        print_at(stdout, bar_start + 2, row, text, geo.columns);
    }
    park_cursor(stdout);
}

/// Draw the single "Windows Memory Diagnostic" entry on the tools row.
/// Mirrors `draw_entry_row` (same 78%-width highlight bar starting at
/// the left body margin) so the highlight jumps seamlessly between
/// the OS list and the Tools entry on Tab.
fn draw_tool_row(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    row: usize,
    text: &str,
    selected: bool,
) {
    let (bar_start, bar_end) = entry_bar_range(geo);
    if selected {
        paint_bar(stdout, row, bar_start, bar_end, Color::Black, Color::LightGray);
        let _ = stdout.set_color(Color::Black, Color::LightGray);
        print_at(stdout, bar_start, row, ">", geo.columns);
        print_at(stdout, bar_start + 2, row, text, geo.columns);
    } else {
        // Wipe the bar region in case the row was selected last frame.
        paint_black(stdout, row, bar_start, bar_end);
        let _ = stdout.set_color(Color::White, Color::Black);
        print_at(stdout, bar_start + 2, row, text, geo.columns);
    }
    park_cursor(stdout);
}

fn draw_main_screen(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    entries: &[String],
    selected: usize,
    countdown: u32,
    focus: menu::FocusArea,
) {
    clear_screen(stdout, geo);

    // Top gray bar.
    draw_gray_bar(stdout, geo, geo.title_row, "Windows Boot Manager");

    // Body text.
    draw_body_line(
        stdout,
        geo,
        geo.prompt_row,
        "Choose an operating system to start, or press TAB to select a tool:",
    );
    draw_body_line(
        stdout,
        geo,
        geo.hint_row,
        "(Use the arrow keys to highlight your choice, then press ENTER.)",
    );

    // OS entries — the highlight only follows `selected` when the
    // user is focused on the OS list. When the focus is on the Tool,
    // all entries render unselected (plain white-on-black) so the
    // OS list reads as dimmed and the eye is drawn to the Tools row.
    let os_focus = focus == menu::FocusArea::Os;
    for (i, entry) in entries.iter().enumerate() {
        let row = geo.entries_start + i;
        if row + 1 >= geo.footer_row {
            break;
        }
        draw_entry_row(stdout, geo, row, entry, os_focus && i == selected);
    }

    // F8 hint and countdown.
    if geo.f8_row < geo.footer_row {
        draw_body_line(
            stdout,
            geo,
            geo.f8_row,
            "To specify an advanced option for this choice, press F8.",
        );
    }
    if geo.countdown_row < geo.footer_row {
        let text = if countdown > 0 {
            alloc::format!(
                "Seconds until the highlighted choice will be started automatically: {}",
                countdown
            )
        } else {
            String::from("Auto-boot cancelled. Press ENTER to choose.")
        };
        draw_body_line(stdout, geo, geo.countdown_row, &text);
    }

    // Tools block. The label is always plain; the row below it gets
    // the highlight bar when the user is focused on the Tools area.
    if geo.tools_label_row < geo.footer_row {
        draw_body_line(stdout, geo, geo.tools_label_row, "Tools:");
    }
    if geo.tools_entry_row < geo.footer_row {
        draw_tool_row(
            stdout,
            geo,
            geo.tools_entry_row,
            "    Windows Memory Diagnostic",
            focus == menu::FocusArea::Tool,
        );
    }

    // The bottom bar is drawn separately by the caller via
    // draw_footer_labels, which is also responsible for parking the
    // cursor at the end of the frame.
}

/// Draw the labels (ENTER / TAB / ESC) inside the bottom gray bar.
/// No countdown is shown here — the countdown lives in the body region.
fn draw_footer_labels(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    show_tab: bool,
) {
    let n = geo.bar_right.saturating_sub(geo.bar_left);
    fill_row_chars(
        stdout,
        geo.footer_row,
        b' ' as u16,
        geo.bar_left,
        n,
        geo.columns,
        Color::Black,
        Color::LightGray,
    );
    let _ = stdout.set_color(Color::Black, Color::LightGray);

    let enter = "ENTER=Choose";
    let tab = "TAB=Menu";
    let esc = "ESC=Cancel";

    // Match the reference HTML's `display:flex; justify-content:space-between`
    // (with the same 1-column padding on the inside of the bar on both sides):
    // ENTER sits at the left, ESC at the right, and TAB is centred in the
    // *gap between them* (so the white-space to TAB's left and right is
    // visually equal) — not just centred within the bar's overall width.
    let enter_len = enter.chars().count();
    let tab_len = tab.chars().count();
    let esc_len = esc.chars().count();

    // LEFT: ENTER — 1 column of padding from the bar's left edge.
    let enter_col = geo.bar_left + 1;
    print_at(stdout, enter_col, geo.footer_row, enter, geo.columns);
    if show_tab {
        // MIDDLE: TAB — centred in the gap [enter_end, esc_start).
        let enter_end = enter_col + enter_len;
        let esc_start = geo.bar_right.saturating_sub(esc_len + 1);
        // Average the two endpoints (integer division) so the leftover
        // column (if any) lands on TAB's right side, matching HTML where
        // the rightmost span hugs the right padding.
        let mid = enter_end.saturating_add(esc_start) / 2;
        let tab_col = mid.saturating_sub(tab_len / 2);
        print_at(stdout, tab_col, geo.footer_row, tab, geo.columns);
    }
    // RIGHT: ESC — 1 column of padding before the right edge of the bar.
    let esc_col = geo.bar_right.saturating_sub(esc_len + 1);
    print_at(stdout, esc_col, geo.footer_row, esc, geo.columns);
    park_cursor(stdout);
}

// =====================================================================
// Advanced Boot Options (F8) screen
// =====================================================================

#[derive(Clone, Copy)]
struct AdvOption {
    label: &'static str,
    desc: &'static str,
    gap_before: bool,
}

const ADV_OPTIONS: &[AdvOption] = &[
    AdvOption {
        label: "Repair Your Computer",
        desc: "View a list of system recovery tools you can use to repair startup problems, run diagnostics, or restore your system.",
        gap_before: false,
    },
    AdvOption {
        label: "Safe Mode",
        desc: "Start Windows with only the core drivers and services. Use when you cannot boot after installing a new device or driver.",
        gap_before: false,
    },
    AdvOption {
        label: "Safe Mode with Networking",
        desc: "Start Windows in safe mode along with the network drivers and services needed to access the Internet or other computers on your network.",
        gap_before: false,
    },
    AdvOption {
        label: "Safe Mode with Command Prompt",
        desc: "Start Windows in safe mode with a command prompt window instead of the usual Windows interface. For advanced users only.",
        gap_before: false,
    },
    AdvOption {
        label: "Enable Boot Logging",
        desc: "Create a file (ntbtlog.txt) that lists all the drivers that are installed during startup and that might be useful for advanced troubleshooting.",
        gap_before: true,
    },
    AdvOption {
        label: "Enable low-resolution video (640x480)",
        desc: "Start Windows using your current video driver and low resolution and refresh rate settings. You can use this mode to reset your display settings.",
        gap_before: false,
    },
    AdvOption {
        label: "Last Known Good Configuration (advanced)",
        desc: "Start Windows with the last registry and driver configuration that worked successfully.",
        gap_before: false,
    },
    AdvOption {
        label: "Directory Services Restore Mode",
        desc: "Start Windows domain controller running Active Directory so that the directory service can be restored. For advanced users and IT pros only.",
        gap_before: false,
    },
    AdvOption {
        label: "Debugging Mode",
        desc: "Start Windows in an advanced troubleshooting mode intended for IT professionals and system administrators.",
        gap_before: false,
    },
    AdvOption {
        label: "Disable automatic restart on system failure",
        desc: "Prevent Windows from automatically restarting if an error causes Windows to fail. Choose this option only if Windows is stuck in a loop where Windows fails, attempts to restart, and fails again repeatedly.",
        gap_before: false,
    },
    AdvOption {
        label: "Disable Driver Signature Enforcement",
        desc: "Allows drivers containing improper signatures to be installed.",
        gap_before: false,
    },
    AdvOption {
        label: "Start Windows Normally",
        desc: "Start Windows with its normal settings.",
        gap_before: true,
    },
];

/// Compute the y row for a given option index, accounting for gap rows.
///
/// The algorithm is the *single source of truth* for "where is option
/// idx on the Advanced screen". `draw_advanced_screen` and
/// `draw_advanced_row` MUST both derive their row from this function
/// — otherwise a row wipe (in `draw_advanced_selection_change`) can
/// target a different row than the row the label was originally drawn
/// on, leaving the previous label in place. That is exactly the bug
/// that caused "Start Windows Normally appears twice" on arrow-key
/// navigation: the label was originally drawn at row 17, but the
/// wipe was issued at row 15 because the two functions disagreed on
/// the row count.
///
/// Formula: rows_used(idx) = idx (one row per item 0..=idx)
///                          + (count of gap_before=true among items 0..idx-1)
///                          + (1 if item idx itself has gap_before=true)
///
/// For the current `ADV_OPTIONS` (12 items, with gaps before idx 4
/// and idx 11) this yields:
///
///   idx  rows_used  start_row(4)+  rendered row
///   0    0           4
///   4    5           9
///  11   13          17
fn adv_option_row(idx: usize) -> usize {
    let mut row = idx;
    if idx > 0 {
        for i in 0..idx {
            if ADV_OPTIONS[i].gap_before {
                row += 1;
            }
        }
    }
    if idx < ADV_OPTIONS.len() && ADV_OPTIONS[idx].gap_before {
        row += 1;
    }
    row
}

/// Paint the description panel for the Advanced screen. The function
/// first WIPES the entire description area to solid black — this is
/// essential because the previous selection's wrapped text may have
/// been longer than the new one, leaving stray characters behind
/// (which is what caused the "Start Windows Normally appears twice"
/// bug — the previous label was actually still on screen, the new
/// redraw just painted over it without clearing).
///
/// Then it writes the "Description:" label on the label row and
/// renders the wrapped desc text starting on the next row, never
/// exceeding `desc_text_rows` rows so it cannot bleed into the
/// bottom bar.
fn draw_description_panel(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    selected: usize,
) {
    // CRITICAL: Ensure we never write on or past the footer bar
    if geo.desc_label_row >= geo.footer_row {
        return; // No room for description
    }

    // Wipe the row just above the description label (blank separator)
    draw_body_line(stdout, geo, geo.desc_label_row.saturating_sub(1), "");

    // Wipe the description label row
    draw_body_line(stdout, geo, geo.desc_label_row, "");

    // Print "Description:" label
    let _ = stdout.set_color(Color::White, Color::Black);
    let desc_label = "Description:";
    print_at(stdout, geo.body_left, geo.desc_label_row, desc_label, geo.columns);
    park_cursor(stdout);

    // Calculate how many rows we have for description text
    // Available rows = footer_row - desc_text_start - 1 (leave 1 row gap before footer)
    let available_rows = (geo.footer_row.saturating_sub(1))
        .saturating_sub(geo.desc_text_start);

    // Wrap the description text
    let width = geo
        .body_right_col
        .saturating_sub(geo.body_left + 1)
        .max(10);
    let desc = ADV_OPTIONS
        .get(selected)
        .map(|o| o.desc)
        .unwrap_or("");
    let lines = wrap_text(desc, width, &String::new(), &String::new());

    // Draw description lines, strictly limited to available space
    let max_lines = available_rows.min(lines.len());
    for i in 0..max_lines {
        let row = geo.desc_text_start + i;
        // Double-check: never write on footer bar
        if row >= geo.footer_row {
            break;
        }
        let line = &lines[i];
        draw_body_line(stdout, geo, row, line);
    }

    // Wipe any remaining rows that might have old text
    for row in (geo.desc_text_start + max_lines)..geo.footer_row {
        draw_body_line(stdout, geo, row, "");
    }
    park_cursor(stdout);
}

/// Redraw only the previously selected and the new selected option row
/// on the Advanced screen. The description panel is also refreshed in
/// full because the new description might be a different length. This
/// keeps the screen from flashing on every arrow-key press.
fn draw_advanced_row(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    idx: usize,
    sel: bool,
) {
    if idx >= ADV_OPTIONS.len() {
        return;
    }
    let opt = &ADV_OPTIONS[idx];
    // Options start 1 row below the hint (matches the ~11% vertical
    // gap between `.header` (top:9%) and `.menu` (top:20%) in
    // `advanced-boot-options.html`, i.e. about 2-3 rows on a 25-row
    // screen, but we have the description panel below to fit in too).
    let start_row = geo.hint_row + 1;
    let (bar_start, bar_end) = entry_bar_range(geo);
    let row = start_row + adv_option_row(idx);
    if row + 1 >= geo.footer_row {
        return;
    }
    // Always wipe the full body width of the row first, so a long
    // previous label (e.g. "Disable automatic restart on system
    // failure") cannot leave stray characters behind when the new
    // label is shorter (e.g. "Safe Mode").
    paint_black(stdout, row, bar_start, geo.body_right_col);
    if sel {
        paint_bar(stdout, row, bar_start, bar_end, Color::Black, Color::LightGray);
        let _ = stdout.set_color(Color::Black, Color::LightGray);
        print_at(stdout, bar_start, row, ">", geo.columns);
        print_at(stdout, bar_start + 2, row, opt.label, geo.columns);
    } else {
        let _ = stdout.set_color(Color::White, Color::Black);
        print_at(stdout, bar_start + 2, row, opt.label, geo.columns);
    }
}

fn draw_advanced_selection_change(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    prev: usize,
    new: usize,
) {
    draw_advanced_row(stdout, geo, prev, false);
    draw_advanced_row(stdout, geo, new, true);
    draw_description_panel(stdout, geo, new);
    park_cursor(stdout);
}

fn draw_advanced_screen(
    stdout: &mut uefi::proto::console::text::Output,
    geo: &Geometry,
    selected: usize,
    target_name: &str,
) {
    clear_screen(stdout, geo);

    // Top bar.
    draw_gray_bar(stdout, geo, geo.title_row, "Advanced Boot Options");

    // Header (two lines).
    draw_body_line(
        stdout,
        geo,
        geo.prompt_row,
        &alloc::format!("Choose Advanced Options for: {}", target_name),
    );
    draw_body_line(
        stdout,
        geo,
        geo.hint_row,
        "(Use the arrow keys to highlight your choice.)",
    );

    // Options. We must leave room for the description panel.
    // The description panel needs at least 3 rows (label + 1 text + 1 gap before footer).
    // Calculate the last row available for options.
    let start_row = geo.hint_row + 1;
    let options_area_end = geo.footer_row.saturating_sub(4); // Reserve 4 rows for description + gap
    let (bar_start, bar_end) = entry_bar_range(geo);

    for (i, opt) in ADV_OPTIONS.iter().enumerate() {
        let row = start_row + adv_option_row(i);
        // Safety: never write past the options area end
        if row >= options_area_end {
            break;
        }
        if i == selected {
            paint_bar(stdout, row, bar_start, bar_end, Color::Black, Color::LightGray);
            let _ = stdout.set_color(Color::Black, Color::LightGray);
            print_at(stdout, bar_start, row, ">", geo.columns);
            print_at(stdout, bar_start + 2, row, opt.label, geo.columns);
        } else {
            paint_black(stdout, row, bar_start, geo.body_right_col);
            let _ = stdout.set_color(Color::White, Color::Black);
            print_at(stdout, bar_start + 2, row, opt.label, geo.columns);
        }
        park_cursor(stdout);
    }

    draw_description_panel(stdout, geo, selected);

    // Bottom bar.
    draw_footer_labels(stdout, geo, false);
    park_cursor(stdout);
}

// =====================================================================
// Key handling
// =====================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Main,
    Advanced,
}

/// Result of consuming a key. The main loop reads this and decides
/// whether to keep iterating or break out so the launch code can take
/// over the firmware.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    /// Stay in the menu, redraw as needed.
    Continue,
    /// User pressed ENTER (or the auto-boot countdown reached zero) —
    /// the main loop must exit and run `launch_selected`.
    Launch,
    /// User wants to reboot the firmware (ESC on the main screen, no
    /// real OS to chain to). Mirrors the real bootmgr behaviour when
    /// the user cancels out.
    Reboot,
}

/// Raw scancode value for the PS/2 "Enter" (main keyboard) key.
/// Defined here because the uefi 0.37 `ScanCode` enum does not
/// expose an `ENTER` variant (the EFI scan-code set leaves
/// 0x18-0x67 reserved for OEM extension and the standard doesn't
/// assign a typed alias). When the OVMF HII keyboard driver
/// converts a PS/2 make-code 0x1C it hands the InputKey to
/// `Key::from` with `scan_code = 0x1C, unicode = 0`, which the
/// `From<InputKey>` impl turns into `Key::Special(ScanCode(0x1C))`
/// — *not* `Key::Printable('\r')`. We need to match on the raw
/// value, not the typed variant, to see it.
const SCAN_ENTER: u16 = 0x1C;

fn handle_key(
    key: Key,
    screen: &mut Screen,
    menu: &mut BootMenu,
    adv_selected: &mut usize,
) -> KeyAction {
    // ENTER short-circuits everything: the user has made their pick.
    //
    // We accept THREE shapes because OVMF / different keyboard
    // drivers report it differently:
    //   1. `Key::Special(ScanCode(0x1C))` — most common: PS/2
    //      make-code from the HII keyboard driver. The typed
    //      ScanCode enum has no ENTER variant, so we match on
    //      the raw value.
    //   2. `Key::Printable('\r')` — USB / non-redirected console
    //      input can deliver a CR unicode instead of a scan
    //      code. The `From<InputKey>` impl uses `ScanCode::NULL`
    //      (0) as the discriminator for the printable branch.
    //   3. `Key::Printable('\n')` — line-discipline coercion on
    //      some firmware builds.
    match key {
        Key::Special(s) if s.0 == SCAN_ENTER => {
            return KeyAction::Launch;
        }
        Key::Printable(c) if c == '\r' || c == '\n' => {
            return KeyAction::Launch;
        }
        _ => {}
    }

    match key {
        Key::Special(ScanCode::UP) => match *screen {
            Screen::Main => {
                // UP/DOWN only navigate WITHIN the OS list. The
                // Tools entry is a separate region that can only
                // be reached via Tab (and left via Tab again) —
                // arrow keys must not cross the boundary.
                menu.move_up();
            }
            Screen::Advanced => {
                if *adv_selected > 0 {
                    *adv_selected -= 1;
                }
            }
        },
        Key::Special(ScanCode::DOWN) => match *screen {
            Screen::Main => {
                // See UP arm above: DOWN stays inside the OS list.
                menu.move_down();
            }
            Screen::Advanced => {
                if *adv_selected + 1 < ADV_OPTIONS.len() {
                    *adv_selected += 1;
                }
            }
        },
        Key::Printable(c) if c == '\t' => match *screen {
            // The Tab key — Tab is delivered as `Key::Printable('\t')`
            // (Unicode U+0009) by the UEFI firmware, not as a
            // `ScanCode`, because the UEFI scan-code set does not
            // include a Tab variant. This is the only arm that
            // actually fires for Tab in practice.
            Screen::Main => menu.toggle_focus(),
            Screen::Advanced => {}
        },
        Key::Special(ScanCode::ESCAPE) => match *screen {
            // The countdown was already cancelled by the main
            // loop's input handler (see "ANY key press must
            // cancel" comment there) — we just need to switch
            // back to the main screen from Advanced, or do
            // nothing on the main screen.
            Screen::Main => return KeyAction::Reboot,
            Screen::Advanced => *screen = Screen::Main,
        },
        Key::Special(ScanCode::FUNCTION_8) => match *screen {
            Screen::Main => {
                *screen = Screen::Advanced;
                *adv_selected = 0;
            }
            Screen::Advanced => *screen = Screen::Main,
        },
        _ => {}
    }
    KeyAction::Continue
}

// =====================================================================
// GOP Graphics Initialization
// =====================================================================

/// GOP Graphics context
struct GopContext {
    info: FramebufferInfo,
    fb: Framebuffer,
}

/// Initialize GOP graphics mode. Tries 1024x768 first, then falls back
/// to the highest available resolution.
fn init_gop_graphics() -> Option<GopContext> {
    use uefi::boot as ub;

    let handles = ub::find_handles::<GraphicsOutput>().ok()?;
    if handles.is_empty() {
        uefi::println!("[GOP] No GraphicsOutput handles found");
        return None;
    }

    let mut gop = match ub::open_protocol_exclusive::<GraphicsOutput>(handles[0]) {
        Ok(g) => g,
        Err(e) => {
            uefi::println!("[GOP] Failed to open GraphicsOutput: {:?}", e);
            return None;
        }
    };

    // Try to set a good resolution. Prefer 1024x768, then 800x600.
    let target_modes = [
        (1024, 768),
        (800, 600),
        (640, 480),
    ];

    let mut selected_mode = None;
    for &(target_w, target_h) in &target_modes {
        for mode in gop.modes() {
            let info = mode.info();
            let (w, h) = info.resolution();
            if w == target_w && h == target_h {
                selected_mode = Some(mode);
                break;
            }
        }
        if selected_mode.is_some() {
            break;
        }
    }

    // If target modes not found, use the current mode or first available
    if selected_mode.is_none() {
        selected_mode = gop.modes().next();
    }

    if let Some(mode) = selected_mode {
        if gop.set_mode(&mode).is_err() {
            uefi::println!("[GOP] Warning: failed to set mode");
        }
    }

    // Some EDK2 platforms (notably ArmVirtQemu on aarch64) report a GOP
    // pixel format of `BltOnly`, which means the firmware refuses to expose
    // a linear framebuffer pointer. `frame_buffer()` asserts (panics) in
    // that situation, so we have to inspect the pixel format *before*
    // touching the framebuffer. When the platform only supports Blt, the
    // boot manager falls back to text mode, which never touches GOP.
    if gop.current_mode_info().pixel_format() == PixelFormat::BltOnly {
        uefi::println!("[GOP] Framebuffer in Blt-only mode — skipping framebuffer setup");
        return None;
    }

    let fb_size = gop.frame_buffer().size();
    let fb_ptr = gop.frame_buffer().as_mut_ptr();
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    // For PixelFormat::Bgr/Rgb, pixels are 4 bytes (BGRA)
    // stride() returns pixels per scanline, multiply by 4 for bytes
    let stride = info.stride() * 4;

    uefi::println!("[GOP] Mode: {}x{} format={:?}", width, height, info.pixel_format());
    uefi::println!("[GOP] Framebuffer: {:016x} size={}", fb_ptr as u64, fb_size);
    let fb_info = FramebufferInfo {
        base: fb_ptr as u64,
        size: fb_size as u64,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
    };

    let fb = Framebuffer::with_ptr(fb_info, fb_ptr);

    // Publish the framebuffer info at a fixed physical address
    // (`FB_MAILBOX_PHYS`) so winload can recover it after
    // `StartImage`. UEFI does not pass arguments from the boot
    // manager to a chain-loaded image, so any hand-off data has
    // to live in a known memory region that survives `ExitBootServices`.
    write_fb_mailbox(&fb_info);

    Some(GopContext { info: fb_info, fb })
}

/// Write the framebuffer hand-off mailbox at `FB_MAILBOX_PHYS`.
///
/// Layout (32 bytes total):
///   Offset 0x00: signature `FBHM` (4 bytes)
///   Offset 0x04: version (u32)
///   Offset 0x08: base address (u64)
///   Offset 0x10: size in bytes (u64)
///   Offset 0x18: width (u32)
///   Offset 0x1C: height (u32)
///   Offset 0x20: stride (u32)
fn write_fb_mailbox(info: &FramebufferInfo) {
    let p = FB_MAILBOX_PHYS as *mut u8;
    unsafe {
        // Signature
        let sig = FB_MAILBOX_SIGNATURE;
        core::ptr::copy_nonoverlapping(sig.as_ptr(), p, 4);
        // Version
        core::ptr::write_volatile(p.add(4) as *mut u32, FB_MAILBOX_VERSION);
        // Base address (u64)
        core::ptr::write_volatile(p.add(8) as *mut u64, info.base);
        // Size in bytes (u64)
        core::ptr::write_volatile(p.add(16) as *mut u64, info.size);
        // Width (u32)
        core::ptr::write_volatile(p.add(24) as *mut u32, info.width);
        // Height (u32)
        core::ptr::write_volatile(p.add(28) as *mut u32, info.height);
        // Stride (u32)
        core::ptr::write_volatile(p.add(32) as *mut u32, info.stride);
        // Format: 1 = BGRA (the only format QEMU's OVMF GOP produces)
        core::ptr::write_volatile(p.add(36) as *mut u32, 1u32);
    }
    // Use the EFI console *before* we lock down the SystemTable — after
    // graphics mode takes over, `uefi::println!` is still functional but
    // we may want to fall back to raw output in case con_out gets clobbered.
    uefi::println!(
        "  [BOOTMGR] Framebuffer mailbox written: base=0x{:x} {}x{} stride={}",
        info.base, info.width, info.height, info.stride
    );
}

// =====================================================================
// Graphics-mode screen types
// =====================================================================

#[derive(Debug)]
enum GraphicsScreen {
    Main { tools_selected: bool },
    Advanced { selected: usize },
}

// =====================================================================
// Graphics-mode rendering - Windows 7 Boot Manager Style
// =====================================================================

/// Windows 7 Boot Manager colors (from HTML CSS)
mod colors {
    use crate::renderer::Color;
    
    pub const BG:         Color = Color(0xFF_00_00_00);  // #000000 - pure black
    pub const FG:         Color = Color(0xFF_C0_C0_C0);  // #c0c0c0 - light gray
    pub const BAR_BG:     Color = Color(0xFF_C0_C0_C0);  // #c0c0c0 - gray bar
    pub const BAR_FG:     Color = Color(0xFF_00_00_00);  // #000000 - black on gray
    pub const SEL_BG:     Color = Color(0xFF_C0_C0_C0);  // #c0c0c0 - selected bg
    pub const SEL_FG:     Color = Color(0xFF_00_00_00);  // #000000 - selected fg
}

/// Windows 7 Boot Manager main screen
/// Matches exactly the HTML layout:
/// - Title bar at top
/// - Prompt text
/// - OS list with chevron
/// - F8 hint and countdown
/// - Tools section
/// - Status bar at bottom
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

    // Clear to black
    fb.fill_rect_fast(0, 0, width, height, colors::BG);

    // === TITLE BAR ===
    // Position: top: 2.6%, left: 15%, right: 14.7%
    let title_top = (height as f32 * 0.026) as u32;
    let title_left = (width as f32 * 0.15) as u32;
    let title_right_margin = (width as f32 * 0.147) as u32;
    let title_right = width - title_right_margin;
    let title_height = 32u32;

    fb.fill_rect_fast(title_left, title_top, title_right - title_left, title_height, colors::BAR_BG);

    // Title text "Windows Boot Manager" centered in bar
    let title_text = "Windows Boot Manager";
    let title_y_offset = (title_height - font.line_height()) / 2;
    // Use regular bitmap font for title (bold not available in bitmap)
    font.draw_text_centered(fb, title_text, (width / 2) as i32, (title_top + title_y_offset) as i32, colors::BAR_FG, None);

    // === BODY CONTENT ===
    // Position: top: 9.5%, left: 14.7%
    let body_top = (height as f32 * 0.095) as u32;
    let body_left = (width as f32 * 0.147) as u32;

    // Prompt line
    let prompt_text = "Choose an operating system to start, or press TAB to select a tool:";
    font.draw_text(fb, prompt_text, body_left as i32, body_top as i32, colors::FG, None);

    // Hint line
    let line_height = font.line_height();
    let hint_y = body_top + line_height + 8;
    let hint_text = "(Use the arrow keys to highlight your choice, then press ENTER.)";
    font.draw_text(fb, hint_text, body_left as i32, hint_y as i32, colors::FG, None);

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
            font.draw_text(fb, "> ", (body_left + 6) as i32, (y + text_y_offset) as i32, colors::SEL_FG, None);
            // Entry text
            font.draw_text(fb, entry, (body_left + 24) as i32, (y + text_y_offset) as i32, colors::SEL_FG, None);
        } else {
            // Not selected: just text
            font.draw_text(fb, "  ", (body_left + 6) as i32, (y + text_y_offset) as i32, colors::FG, None);
            font.draw_text(fb, entry, (body_left + 24) as i32, (y + text_y_offset) as i32, colors::FG, None);
        }
    }

    // === MIDBLOCK ===
    // Position: top: 49%
    let mid_top = (height as f32 * 0.49) as u32;

    // F8 hint
    let f8_text = "To specify an advanced option for this choice, press F8.";
    font.draw_text(fb, f8_text, body_left as i32, mid_top as i32, colors::FG, None);

    // Countdown line - make it prominent
    let count_y = mid_top + line_height + 8;

    // Build countdown string
    let count_text = alloc::format!("Seconds until the highlighted choice will be started: {}", countdown);
    font.draw_text(fb, &count_text, body_left as i32, count_y as i32, colors::FG, None);

    // === TOOLS SECTION ===
    // Position: below countdown
    let tools_top = count_y + line_height + 24;

    // Tools label
    let tools_label = "Tools:";
    font.draw_text(fb, tools_label, body_left as i32, tools_top as i32, colors::FG, None);

    // Tool item
    let tool_y = tools_top + line_height + 8;
    let tool_text = "Windows Memory Diagnostic";
    let tool_x = body_left + 48; // margin-left: 3em = ~48 pixels at this scale
    let tool_text_y_offset = (line_height + 4 - line_height) / 2;

    if tools_selected {
        let (tool_text_w, _) = font.measure(tool_text);
        fb.fill_rect_fast(tool_x - 6, tool_y, tool_text_w + 12, item_height - 1, colors::SEL_BG);
        font.draw_text(fb, tool_text, tool_x as i32, (tool_y + tool_text_y_offset) as i32, colors::SEL_FG, None);
    } else {
        font.draw_text(fb, tool_text, tool_x as i32, (tool_y + tool_text_y_offset) as i32, colors::FG, None);
    }

    // === STATUS BAR ===
    // Position: bottom with 3% margin, taller bar
    let margin_bottom = (height as f32 * 0.03) as u32;  // 3% bottom margin
    let status_height = 32u32;  // Larger status bar
    let status_bottom = height - margin_bottom - status_height;
    let status_left = (width as f32 * 0.15) as u32;
    let status_right = width - title_right_margin;

    fb.fill_rect_fast(status_left, status_bottom, status_right - status_left, status_height, colors::BAR_BG);

    // Status text: "ENTER=Choose  TAB=Menu  ESC=Cancel"
    let status_left_text = "ENTER=Choose";
    let status_mid_text = "TAB=Menu";
    let status_right_text = "ESC=Cancel";

    let text_y_offset = (status_height - font.line_height()) / 2;
    font.draw_text(fb, status_left_text, (status_left + 10) as i32, (status_bottom + text_y_offset) as i32, colors::BAR_FG, None);
    font.draw_text_centered(fb, status_mid_text, (width / 2) as i32, (status_bottom + text_y_offset) as i32, colors::BAR_FG, None);
    // Right-align the last text
    let (right_text_width, _) = font.measure(status_right_text);
    font.draw_text(fb, status_right_text, (status_right - right_text_width - 10) as i32, (status_bottom + text_y_offset) as i32, colors::BAR_FG, None);
}

/// Windows 7 Advanced Boot Options screen
/// Matches exactly the HTML layout
fn draw_gop_advanced_screen(
    fb: &mut Framebuffer,
    font: &mut BitmapFont,
    entries: &[(&str, &str)],  // (label, description)
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

    fb.fill_rect_fast(title_left, title_top, title_right - title_left, title_height, colors::BAR_BG);

    let title_text = "Advanced Boot Options";
    let title_y_offset = (title_height - font.line_height()) / 2;
    // Use regular bitmap font for title
    font.draw_text_centered(fb, title_text, (width / 2) as i32, (title_top + title_y_offset) as i32, colors::BAR_FG, None);

    // === HEADER ===
    // Position: top: 9%
    let line_height = font.line_height();
    let header_top = (height as f32 * 0.09) as u32;
    let header_left = (width as f32 * 0.08) as u32;

    let header1 = "Choose Advanced Options for: Windows 7";
    let header2 = "(Use the arrow keys to highlight your choice.)";
    font.draw_text(fb, header1, header_left as i32, header_top as i32, colors::FG, None);
    font.draw_text(fb, header2, header_left as i32, (header_top + line_height + 4) as i32, colors::FG, None);

    // === MENU ITEMS ===
    // Position: top: 20%
    let menu_top = header_top + line_height * 2 + 16;
    let menu_left = (width as f32 * 0.08) as u32;
    let item_height = line_height + 8;

    let mut y = menu_top;
    for (i, (label, _desc)) in entries.iter().enumerate() {
        // Gap before certain items (like "Enable Boot Logging" and "Start Windows Normally")
        let has_gap_before = *label == "Enable Boot Logging" ||
                           *label == "Start Windows Normally" ||
                           *label == "Disable automatic restart on system failure" ||
                           *label == "Disable Driver Signature Enforcement";

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
            font.draw_text(fb, label, text_x as i32, (y + text_y_offset) as i32, colors::SEL_FG, None);
        } else {
            let text_x = menu_left + 32;
            font.draw_text(fb, label, text_x as i32, (y + text_y_offset) as i32, colors::FG, None);
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
    let desc_area_height = (status_bottom as i32 - status_height as i32 - 16 - desc_label_y as i32 + 4) as u32;
    fb.fill_rect_fast(desc_left, desc_label_y.saturating_sub(4), desc_right - desc_left, desc_area_height, colors::BG);

    // Description label
    let desc_label = "Description:";
    font.draw_text(fb, desc_label, desc_left as i32, desc_label_y as i32, colors::FG, None);

    // Description text with proper word wrapping
    if let Some((_, desc)) = entries.get(selected) {
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
                    let wrap_point = remaining.char_indices()
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
                    line.chars().take(max_chars_per_line.saturating_sub(1)).collect::<alloc::string::String>() + ".."
                } else {
                    line
                };
                font.draw_text(fb, &ellipsis_line, (desc_left + 96) as i32, y_pos, colors::FG, None);
                break;
            }
            font.draw_text(fb, &line, (desc_left + 96) as i32, y_pos, colors::FG, None);
            y_pos += line_spacing;
        }
    }

    // === STATUS BAR ===
    // Position: bottom: 3% margin, total height ~32px
    let margin_bottom = (height as f32 * 0.03) as u32;  // 3% bottom margin
    let status_height = 32u32;  // Larger status bar
    let status_bottom = height - margin_bottom - status_height;  // Top of status bar
    let status_left = (width as f32 * 0.08) as u32;
    let status_right = width - (width as f32 * 0.08) as u32;

    fb.fill_rect_fast(status_left, status_bottom, status_right - status_left, status_height, colors::BAR_BG);

    let status_left_text = "ENTER=Choose";
    let status_right_text = "ESC=Cancel";

    font.draw_text(fb, status_left_text, (status_left + 10) as i32, (status_bottom + 8) as i32, colors::BAR_FG, None);
    let (right_text_width, _) = font.measure(status_right_text);
    font.draw_text(fb, status_right_text, (status_right - right_text_width - 10) as i32, (status_bottom + 8) as i32, colors::BAR_FG, None);
}

// =====================================================================
// Entry point - GOP Graphics Mode
// =====================================================================

#[entry]
fn efi_main() -> Status {
    // UEFI Boot Manager entry point - unique signature
    uefi::println!("===========================================");
    uefi::println!("NT6.1.7601 BOOT MANAGER v1.0 DEBUG");
    uefi::println!("===========================================");
    uefi::println!("[MAIN] efi_main entered successfully!");
    
    if let Err(e) = uefi::helpers::init() {
        uefi::println!("Warning: helpers init failed: {:?}", e);
    }

    // Load BCD store from ESP partition - this is a real Windows BCD file
    // written at build time, not a hardcoded in-memory store. The BCD
    // tells bootmgr which winload.efi to chain-load and on which device.
    uefi::println!("[BCD] Loading BCD store from ESP...");
    let bcd_store = match load_bcd_from_esp() {
        Ok(store) => {
            uefi::println!("[BCD] BCD store loaded successfully");
            store
        }
        Err(e) => {
            uefi::println!("[BCD] Failed to load BCD from ESP: {}", e);
            uefi::println!("[BCD] Falling back to default in-memory store");
            BcdStore::with_defaults()
        }
    };
    let mut menu = BootMenu::new(&bcd_store);
    uefi::println!("[DEBUG] Boot menu created, countdown: {}", menu.countdown());
    let entries = get_boot_entry_descriptions(&bcd_store);
    uefi::println!("[DEBUG] Got {} boot entries", entries.len());
    
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
    uefi::println!("[DEBUG] Initializing GOP...");

    let mut gop = None;
    let mut gop_handles = ub::find_handles::<GraphicsOutput>().ok();
    for attempt in 0u32..50 {
        match gop_handles.as_ref() {
            Some(h) if !h.is_empty() => {
                match ub::open_protocol_exclusive::<GraphicsOutput>(h[0]) {
                    Ok(g) => {
                        gop = Some(g);
                        if attempt > 0 {
                            uefi::println!("[GOP] GraphicsOutput handle became available after {} polls", attempt);
                        }
                        break;
                    }
                    Err(e) => {
                        uefi::println!("[GOP] open_protocol_exclusive failed (attempt {}): {:?}", attempt, e);
                    }
                }
            }
            Some(_) => {
                if attempt == 0 {
                    uefi::println!("[GOP] No GraphicsOutput handles found, polling...");
                }
            }
            None => {
                if attempt == 0 {
                    uefi::println!("[BOOT] find_handles returned None, polling for GOP...");
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
            uefi::println!("[BOOT] No GOP available after polling - falling back to text mode auto-boot");
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
        if selected_mode.is_some() { break; }
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
        uefi::println!("[GOP] Framebuffer in Blt-only mode — falling back to text mode");
        return text_mode_auto_boot(&bcd_store, &entries);
    }

    let fb_size = gop.frame_buffer().size();
    let fb_ptr = gop.frame_buffer().as_mut_ptr();
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let stride = info.stride() * 4;
    
    uefi::println!("[GOP] Mode: {}x{} format={:?}", width, height, info.pixel_format());
    uefi::println!("[GOP] Framebuffer: {:016x} size={}", fb_ptr as u64, fb_size);
    
    let fb_info = FramebufferInfo {
        base: fb_ptr as u64,
        size: fb_size as u64,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
    };
    let mut fb = Framebuffer::with_ptr(fb_info, fb_ptr);
    uefi::println!("[DEBUG] GOP initialized, fb created");

    // Publish the framebuffer info at a fixed physical address
    // (`FB_MAILBOX_PHYS`) so winload can recover it. Without
    // this, winload fails to open GOP (`ACCESS_DENIED` because
    // bootmgr already opened it exclusively) and the kernel
    // has no way to know the LFB address.
    write_fb_mailbox(&fb_info);
    
    // After entering graphics mode, suppress all text output
    
    // Calculate font size based on resolution
    let screen_height = fb.height() as f32;
    uefi::println!("[DEBUG] screen_height = {}", screen_height);

    // Use bitmap font - reliable and consistent
    let mut font = BitmapFont::new();
    font.set_size(16);
    uefi::println!("[DEBUG] Using bitmap font, char_height = {}", font.char_height());
    
    // Advanced boot options - fixed text without special characters
    let adv_options: [(&str, &str); 11] = [
        ("Repair Your Computer", "View a list of system recovery tools you can use to repair startup problems, run diagnostics, or restore your system."),
        ("Safe Mode", "Start Windows with only the core drivers and services. Use when you cannot boot after installing a new device or driver."),
        ("Safe Mode with Networking", "Start Windows in safe mode along with the network drivers and services needed to access the Internet or other computers on your network."),
        ("Safe Mode with Command Prompt", "Start Windows in safe mode with a command prompt window instead of the usual Windows interface. For advanced users only."),
        ("Enable Boot Logging", "Create a file (ntbtlog.txt) that lists all the drivers that are installed during startup and that might be useful for advanced troubleshooting."),
        ("Enable low resolution video 640x480", "Start Windows using your current video driver and low resolution and refresh rate settings. You can use this mode to reset your display settings."),
        ("Last Known Good Configuration advanced", "Start Windows with the last registry and driver configuration that worked successfully."),
        ("Directory Services Restore Mode", "Start Windows domain controller running Active Directory so that the directory service can be restored. For advanced users and IT pros only."),
        ("Debugging Mode", "Start Windows in an advanced troubleshooting mode intended for IT professionals and system administrators."),
        ("Disable automatic restart on system failure", "Prevent Windows from automatically restarting if an error causes Windows to fail."),
        ("Disable Driver Signature Enforcement", "Allows drivers containing improper signatures to be installed."),
    ];
    
    let mut screen = GraphicsScreen::Main { tools_selected: false };
    let mut tick_counter: u32 = 0;
    
    // Initial draw
    uefi::println!("[DEBUG] About to draw main screen...");
    draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), false);
    uefi::println!("[DEBUG] Main screen drawn");

    // Initialize console input for keyboard reading
    let con_in_handles = ub::find_handles::<uefi::proto::console::text::Input>().unwrap_or_default();
    let mut con_in = None;
    if let Some(handle) = con_in_handles.first() {
        if let Ok(ci) = ub::open_protocol_exclusive::<uefi::proto::console::text::Input>(*handle) {
            con_in = Some(ci);
        }
    }
    uefi::println!("[DEBUG] Console input initialized, con_in.is_some() = {}", con_in.is_some());
    uefi::println!("[DEBUG] Entering main event loop");

    // Main event loop - use text console for keyboard input
    loop {
        // Read keyboard input from text console (non-blocking check)
        let mut read = None;
        if let Some(ref mut stdin) = con_in {
            // Try to read key without blocking
            read = stdin.read_key().ok().flatten();
        }

        // Handle countdown tick
        let mut auto_boot = false;
        let mut countdown_changed = false;
        if let GraphicsScreen::Main { tools_selected: _ } = screen {
            if menu.is_counting() {
                tick_counter += 1;
                if tick_counter >= 10 {  // 10 * 100ms = 1 second
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
                Key::Special(ScanCode::UP) => {
                    match &mut screen {
                        GraphicsScreen::Main { tools_selected } => {
                            *tools_selected = false;
                            menu.move_up();
                        }
                        GraphicsScreen::Advanced { selected } => {
                            if *selected > 0 {
                                *selected -= 1;
                            }
                        }
                    }
                }
                Key::Special(ScanCode::DOWN) => {
                    match &mut screen {
                        GraphicsScreen::Main { .. } => {
                            menu.move_down();
                        }
                        GraphicsScreen::Advanced { selected } => {
                            if *selected < adv_options.len() - 1 {
                                *selected += 1;
                            }
                        }
                    }
                }
                Key::Special(ScanCode::FUNCTION_8) => {
                    match screen {
                        GraphicsScreen::Main { .. } => {
                            screen = GraphicsScreen::Advanced { selected: 0 };
                            draw_gop_advanced_screen(&mut fb, &mut font, &adv_options, 0);
                        }
                        GraphicsScreen::Advanced { .. } => {
                            screen = GraphicsScreen::Main { tools_selected: false };
                            draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), false);
                        }
                    }
                }
                Key::Special(ScanCode::ESCAPE) => {
                    match screen {
                        GraphicsScreen::Advanced { .. } => {
                            screen = GraphicsScreen::Main { tools_selected: false };
                            draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), false);
                        }
                        _ => {}
                    }
                }
                // Handle Enter key as printable '\r' or '\n'
                Key::Printable(c) if c == uefi::Char16::try_from('\r' as u16).unwrap()
                                  || c == uefi::Char16::try_from('\n' as u16).unwrap() => {
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
                                    // Draw loading text
                                    font.draw_text_centered(&mut fb, "Loading Windows Memory Diagnostic...", (w / 2) as i32, (h / 2) as i32, colors::FG, None);
                                } else {
                                    // Draw loading text
                                    font.draw_text_centered(&mut fb, "Loading...", (w / 2) as i32, (h / 2) as i32, colors::FG, None);
                                }
                                match launch_selected(&menu) {
                                    Ok(()) => {} // Does not return
                                    Err(e) => {
                                        // Boot failed - cancel the auto-boot countdown
                                        // and show an error message before returning to
                                        // the menu. This prevents the "system keeps
                                        // rebooting" behaviour caused by the auto-boot
                                        // timer re-firing on the same failing entry.
                                        uefi::println!("[BOOT] launch_selected failed: {}", e);
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
                                        font.draw_text_centered(&mut fb, &line2, (w / 2) as i32, (h / 2) as i32, colors::FG, None);
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
                                                    Ok(Some(_)) => break,
                                                    _ => {
                                                        uefi::boot::stall(core::time::Duration::from_millis(50));
                                                    }
                                                }
                                            }
                                        } else {
                                            uefi::boot::stall(core::time::Duration::from_secs(3));
                                        }
                                    }
                                }
                            }
                        }
                        GraphicsScreen::Advanced { .. } => {
                            // Go back to main
                            screen = GraphicsScreen::Main { tools_selected: false };
                            draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), false);
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
                    draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), *tools_selected);
                }
                GraphicsScreen::Advanced { selected } => {
                    draw_gop_advanced_screen(&mut fb, &mut font, &adv_options, *selected);
                }
            }
        } else if auto_boot {
            // Auto-boot when countdown reaches zero
            uefi::println!("[DEBUG] Auto-boot triggered!");
            if !entries.is_empty() {
                // Get screen dimensions first
                let w = fb.width();
                let h = fb.height();
                // Clear screen using GOP
                fb.fill_rect_fast(0, 0, w, h, colors::BG);
                font.draw_text_centered(&mut fb, "Loading...", (w / 2) as i32, (h / 2) as i32, colors::FG, None);
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
                        uefi::println!("[BOOT] launch_selected failed: {}", e);
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
                        font.draw_text_centered(&mut fb, &line2, (w / 2) as i32, (h / 2) as i32, colors::FG, None);
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
                                    Ok(Some(_)) => {
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
                    draw_gop_main_screen(&mut fb, &mut font, &entries, menu.selected_index(), menu.countdown(), tools_selected);
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
        if c == 0 { break; }
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
    /// ## NTFS Skip
    ///
    /// The disk has two partitions: a FAT32 ESP and an NTFS system partition.
    /// EFI's SimpleFileSystem protocol only natively supports FAT12/16/32.
    /// When the boot manager encounters an NTFS partition, it cannot read it.
    /// We detect NTFS by reading the boot sector and checking for the "NTFS    "
    /// signature at byte offset 3. If found, we skip that handle and move on.
    fn is_ntfs_partition(handle: uefi::Handle) -> bool {
        use uefi::boot::OpenProtocolAttributes;
        use uefi::boot::OpenProtocolParams;
        use uefi::proto::media::block::BlockIO;

        // Try to open BlockIO on this handle to read the partition boot sector.
        // SAFETY: we use GetProtocol (not AffectedBootPath) so the lifetime is fine.
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

        let block = match sp {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Read the first sector (boot sector).
        let mut buf = [0u8; 512];
        let media = block.media();
        if media.block_size() != 512 {
            return false; // Only handle 512-byte sectors for now.
        }
        let lba_offset = 0u64;
        if block.read_blocks(media.media_id(), lba_offset, &mut buf).is_err() {
            return false;
        }

        // NTFS boot sector signature at bytes 3-10.
        buf[3] == b'N' && buf[4] == b'T' && buf[5] == b'F' && buf[6] == b'S'
    }

    /// Dump the root directory of a SimpleFileSystem volume for debugging.
    #[allow(dead_code)]
    fn dump_root_directory(sfs: &mut uefi::proto::media::fs::SimpleFileSystem) {
        let mut root = match sfs.open_volume() {
            Ok(r) => r,
            Err(_) => return,
        };
        uefi::println!("  Dumping root directory:");
        let mut buf = alloc::vec![0u8; 512];
        loop {
            let res = root.read_entry(&mut buf);
            match res {
                Ok(Some(info)) => {
                    // Convert CStr16 file_name (UTF-16) to a printable string.
                    let name_cstr = info.file_name();
                    let mut name_bytes = alloc::vec::Vec::with_capacity(64);
                    for c in name_cstr.iter() {
                        let code: u16 = (*c).into();
                        if code == 0 { break; }
                        if let Some(ch) = char::from_u32(code as u32) {
                            let mut buf_ch = [0u8; 4];
                            let s = ch.encode_utf8(&mut buf_ch);
                            name_bytes.extend_from_slice(s.as_bytes());
                        }
                    }
                    let name = core::str::from_utf8(&name_bytes).unwrap_or("<invalid>");
                    uefi::println!("    {}", name);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

/// ## LFN Workaround
///
/// Some OVMF FAT32 drivers do not properly resolve long filenames (LFN)
/// when using `EFI_FILE_PROTOCOL.Open()`. The UEFI spec says `open()` should
/// match by LFN, but OVMF sometimes only matches by the 8.3 short name.
/// To work around this, when `open()` fails with NOT_FOUND, we enumerate
/// the directory entries and find the canonical (LFN) name, then re-open with it.
fn read_boot_file(rel_path: &str) -> Result<Vec<u8>, &'static str> {
    let handles = boot::find_handles::<SimpleFileSystem>().map_err(|_| "no SFS handles")?;
    if handles.is_empty() {
        return Err("no SimpleFileSystem on this platform");
    }

    // Split path into parts
    let normalized = rel_path.replace('\\', "/");
    let parts: alloc::vec::Vec<&str> = normalized
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        return Err("empty path");
    }

    // Try each handle
    for (idx, handle) in handles.iter().enumerate() {
        // Skip NTFS partitions when reading BCD/boot files from ESP.
        // NTFS is only used for winload.efi on the System partition.
        if is_ntfs_partition(*handle) {
            uefi::println!("[FILE] Skipping NTFS handle {} (BCD path)", idx);
            continue;
        }

        uefi::println!("[FILE] Trying FAT handle {}...", idx);
        let mut sfs = match boot::open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let root = match sfs.open_volume() {
            Ok(r) => {
                uefi::println!("[FILE] Opened volume from handle {}", idx);
                r
            },
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
                    uefi::println!("[FILE] Failed to open directory: {}", part);
                    navigation_failed = true;
                    break;
                }
            }
        }

        if navigation_failed {
            continue;
        }

        // Open the file itself
        uefi::println!("[FILE] Trying to open: {}", file_name);
        if let Some(mut handle) = open_file_component(&mut current_dir, file_name) {
            let info = handle.get_boxed_info::<FileInfo>().map_err(|_| "get info")?;
            let total = info.file_size() as usize;
            let mut out: Vec<u8> = alloc::vec![0u8; total];
            let mut off: usize = 0;
            const CHUNK: usize = 64 * 1024;
            while off < total {
                let want = (total - off).min(CHUNK);
                let n = handle.read(&mut out[off..off + want]).map_err(|_| "read failed")?;
                if n == 0 {
                    break;
                }
                off += n;
            }
            out.truncate(off);
            uefi::println!("[FILE] Read {} bytes from: {}", total, rel_path);
            return Ok(out);
        }
        // Try the next SFS handle
        let _ = idx;
    }

    // FAT32 ESP did not contain the file. Per Windows 7 layout, winload.efi
    // lives on the System partition (NTFS/EXT4), so fall back to reading it
    // through a minimal in-tree NTFS reader when the path looks like a
    // Windows-side path.
    if let Some(data) = read_ntfs_boot_file(rel_path) {
        return Ok(data);
    }

    Err("failed to load file from any SFS handle")
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
        if let Ok(entry) = current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
            if let Some(dir) = entry.into_directory() {
                return Some(dir);
            }
        }
        // Then try SFN candidates (MICROS~1, MICROS~2, ...)
        for sfn in &lookup.sfn_candidates {
            if let Ok(entry) = current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
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
        if let Ok(file) = current_dir.open(lookup.lfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
            if let Some(h) = file.into_regular_file() {
                return Some(h);
            }
        }
        // Then try SFN candidates
        for sfn in &lookup.sfn_candidates {
            if let Ok(file) = current_dir.open(sfn.as_ref(), FileMode::Read, FileAttribute::empty()) {
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
    // With our build layout:
    //   ESP/EFI/Boot/BCD        <- BCD (next to boot manager)
    //   ESP/BCD                <- BCD at volume root (fallback)
    //   ESP/EFI/Microsoft/Boot/BCD <- standard Windows path (fallback)
    const BCD_PATHS: [&str; 3] = [
        "EFI/Boot/BCD",
        "BCD",
        "EFI/Microsoft/Boot/BCD",
    ];
    
    for bcd_path in BCD_PATHS {
        uefi::println!("[BCD] Trying path: {}", bcd_path);
        if let Ok(bytes) = read_boot_file(bcd_path) {
            uefi::println!("[BCD] Read {} bytes from: {}", bytes.len(), bcd_path);
            // Parse the BCD hive.
            use crate::bcd_parser::BcdHive;
            match BcdHive::parse(&bytes) {
                Ok(hive) => {
                    let store = hive.into_store();
                    uefi::println!("[BCD] Parsed {} entries", store.entry_count);
                    return Ok(store);
                }
                Err(e) => {
                    uefi::println!("[BCD] Parse error for {}: {:?}", bcd_path, e);
                }
            }
        }
    }
    
    Err("failed to load BCD from any path")
}

/// Load a file from the ESP filesystem
/// Load and start the UEFI image referenced by the currently-selected
/// BCD entry. On success this function does not return — control is
/// handed to the new image via `StartImage`.
fn launch_selected(menu: &BootMenu) -> core::result::Result<(), &'static str> {
    let entry = menu.select().ok_or("no entry selected")?;
    let path = ucs2_to_string(entry.application.as_slice());
    uefi::println!("[LAUNCH] Selected entry: {}", path);
    if path.is_empty() {
        return Err("entry has no application path");
    }
    uefi::println!("[LAUNCH] Reading file...");
    let bytes = match read_boot_file(&path) {
        Ok(b) => b,
        Err(e) => {
            uefi::println!("[LAUNCH] Read failed: {}", e);
            return Err(e);
        }
    };
    uefi::println!("[LAUNCH] Read {} bytes", bytes.len());

    // ----------------------------------------------------------------
    // Write the BCD mailbox at physical address 0x10_100.
    // This is the standard Windows 7 boot manager -> winload handoff.
    //
    // Mailbox format:
    //   Offset 0x00: Signature "BCDE" (4 bytes)
    //   Offset 0x04: Version 0x00000003 (4 bytes)
    //   Offset 0x08: Length (4 bytes)
    //   Offset 0x0C: Entry GUID (16 bytes)
    //   Offset 0x1C: Boot options (variable, up to 224 bytes)
    //
    // Using a fixed physical address is the simplest handoff across
    // `StartImage` — UEFI does not pass arguments from bootmgr to a
    // chain-loaded image, so anything we want winload to know has to
    // be visible at a known PA.
    // ----------------------------------------------------------------
    write_bcd_mailbox(&entry.guid.0);
    uefi::println!("  boot entry GUID -> 0x{:x}: {:02x?}", BCD_MAILBOX_PHYS, &entry.guid.0);

    let parent = boot::image_handle();
    let source = boot::LoadImageSource::FromBuffer {
        buffer: &bytes,
        file_path: None,
    };
    let image = boot::load_image(parent, source).map_err(|e| {
        uefi::println!("  load_image failed: {:?}", e);
        "load_image failed"
    })?;
    // From here on, StartImage does not return on success — the
    // firmware tears down boot services and jumps to the entry point.
    boot::start_image(image).map_err(|e| {
        uefi::println!("  start_image failed: {:?}", e);
        "start_image failed"
    })
}

/// Text-mode boot menu used when no GOP handle is available
/// (e.g. on QEMU virt machine for aarch64/riscv64). Prints the
/// list of boot entries to the UEFI console and auto-boots the
/// default selection after a brief countdown. Keyboard input is
/// honoured via Simple Text Input so the user can still pick a
/// different entry with arrow keys + ENTER.
fn text_mode_auto_boot(bcd_store: &BcdStore, entries: &[String]) -> Status {
    use uefi::boot as ub;

    uefi::println!("[TEXT-BOOT] No graphics output - using text mode boot menu");
    uefi::println!("===========================================");
    uefi::println!("Windows Boot Manager (Text Mode)");
    uefi::println!("===========================================");
    for (i, desc) in entries.iter().enumerate() {
        uefi::println!("  [{}] {}", i + 1, desc);
    }
    uefi::println!("");
    uefi::println!("Auto-booting default entry in 5 seconds...");
    uefi::println!("(Use UP/DOWN arrow keys to choose, ENTER to boot immediately.)");

    let mut menu = BootMenu::new(bcd_store);
    let mut selected = menu.selected_index();

    // Try to open the Simple Text Input protocol for arrow-key support
    let con_in_handles = ub::find_handles::<uefi::proto::console::text::Input>()
        .unwrap_or_default();
    let mut con_in = None;
    if let Some(handle) = con_in_handles.first() {
        if let Ok(ci) = ub::open_protocol_exclusive::<uefi::proto::console::text::Input>(*handle) {
            con_in = Some(ci);
        }
    }

    let mut seconds_remaining: u32 = 5;
    loop {
        // Print current selection and countdown once per second
        uefi::println!(
            "[TEXT-BOOT] Selected: [{}] {} ({}s)",
            selected + 1,
            entries.get(selected).map(|s| s.as_str()).unwrap_or("?"),
            seconds_remaining
        );

        // Wait up to 1 second for a key press
        if let Some(ref mut stdin) = con_in {
            // Poll for ~1 second (10 * 100ms)
            for _ in 0..10 {
                if let Ok(Some(key)) = stdin.read_key() {
                    match key {
                        Key::Special(ScanCode::UP) => {
                            if selected > 0 {
                                selected -= 1;
                                menu.cancel_auto();
                                seconds_remaining = 5;
                                uefi::println!("[TEXT-BOOT] -> [{}] {}",
                                    selected + 1,
                                    entries.get(selected).map(|s| s.as_str()).unwrap_or("?"));
                            }
                        }
                        Key::Special(ScanCode::DOWN) => {
                            if selected + 1 < entries.len() {
                                selected += 1;
                                menu.cancel_auto();
                                seconds_remaining = 5;
                                uefi::println!("[TEXT-BOOT] -> [{}] {}",
                                    selected + 1,
                                    entries.get(selected).map(|s| s.as_str()).unwrap_or("?"));
                            }
                        }
                        Key::Printable(c)
                            if c == uefi::Char16::try_from('\r' as u16).unwrap()
                                || c == uefi::Char16::try_from('\n' as u16).unwrap() =>
                        {
                            uefi::println!("[TEXT-BOOT] ENTER - booting [{}] {}",
                                selected + 1,
                                entries.get(selected).map(|s| s.as_str()).unwrap_or("?"));
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
            uefi::println!("[TEXT-BOOT] launch_selected failed: {}", e);
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
    use core::ffi::c_void;

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
        core::ptr::write_volatile(mailbox.add(0) as *mut [u8; 4],
                                  BCD_MAILBOX_SIGNATURE);
        // Write version
        core::ptr::write_volatile(mailbox.add(4) as *mut u32,
                                  BCD_MAILBOX_VERSION);
        // Write length (256 bytes total)
        core::ptr::write_volatile(mailbox.add(8) as *mut u32, 256u32);
        // Write entry GUID (16 bytes starting at offset 0x0C)
        core::ptr::copy_nonoverlapping(guid.as_ptr(), mailbox.add(0x0C), 16);
        // Clear boot options area (224 bytes from offset 0x1C)
        for i in 0..224 {
            core::ptr::write_volatile(mailbox.add(0x1C + i), 0);
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
        uefi::println!(
            "[BCD] Mailbox written at allocated page 0x{:x}; ConfigTable GUID installed",
            mailbox_phys
        );
    } else {
        uefi::println!(
            "[BCD] Mailbox written at fixed address 0x{:x}: sig=BCDE ver=0x{:08x} guid={:02x?}",
            mailbox_phys, BCD_MAILBOX_VERSION, guid
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
    mft_start_lcn: u64,
    mft_record_size: u32,
    index_record_size: u32,
    serial_number: u64,
}

impl NtfsBoot {
    /// Parse the NTFS boot sector (first 512 bytes of the partition).
    fn parse(buf: &[u8; 512]) -> Option<Self> {
        // OEMID = "NTFS    " at offset 3
        if &buf[3..11] != b"NTFS    " {
            return None;
        }
        let bytes_per_sector = u16::from_le_bytes([buf[0x0B], buf[0x0C]]);
        let sectors_per_cluster = buf[0x0D];
        let total_sectors = u64::from_le_bytes([
            buf[0x28], buf[0x29], buf[0x2A], buf[0x2B],
            buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F],
        ]);
        let mft_start_lcn = u64::from_le_bytes([
            buf[0x30], buf[0x31], buf[0x32], buf[0x33],
            buf[0x34], buf[0x35], buf[0x36], buf[0x37],
        ]);
        // MFT record size: byte 0x40 holds a signed value. Positive
        // value = 2^val clusters. Negative = 2^|val| bytes. For our
        // image builder, the value is 0x400 bytes (1024).
        let mft_raw = buf[0x40] as i8;
        let mft_record_size: u32 = if mft_raw >= 0 {
            (sectors_per_cluster as u32) * (bytes_per_sector as u32) << mft_raw
        } else {
            1u32 << (-mft_raw as u32)
        };
        let index_raw = buf[0x44] as i8;
        let index_record_size: u32 = if index_raw >= 0 {
            (sectors_per_cluster as u32) * (bytes_per_sector as u32) << index_raw
        } else {
            1u32 << (-index_raw as u32)
        };
        let serial_number = u64::from_le_bytes([
            buf[0x48], buf[0x49], buf[0x4A], buf[0x4B],
            buf[0x4C], buf[0x4D], buf[0x4E], buf[0x4F],
        ]);
        Some(NtfsBoot {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_start_lcn,
            mft_record_size,
            index_record_size,
            serial_number,
        })
    }
}

/// Read `count` sectors starting at `lba` from the partition whose
/// first handle exposes an NTFS boot sector. Returns the buffer and
/// the on-disk LBA where the NTFS partition begins.
fn read_ntfs_partition_sectors(start_lba: u64, count: u32) -> Option<(Vec<u8>, u64)> {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    let handles = boot::find_handles::<BlockIO>().ok()?;
    for handle in handles.iter() {
        // SAFETY: GetProtocol is non-destructive.
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
        let Ok(block) = sp else { continue; };
        let media = block.media();
        if media.block_size() != 512 { continue; }
        let mut boot_sector = [0u8; 512];
        if block.read_blocks(media.media_id(), 0u64, &mut boot_sector).is_err() {
            continue;
        }
        if &boot_sector[3..11] != b"NTFS    " {
            continue;
        }
        // Found the NTFS partition. Read `count` sectors from `lba`.
        let mut buf = alloc::vec![0u8; (count as usize) * 512];
        if block.read_blocks(media.media_id(), start_lba, &mut buf).is_err() {
            uefi::println!("[NTFS] read_blocks failed at LBA {}", start_lba);
            return None;
        }
        return Some((buf, 0u64));
    }
    None
}

/// Read a single MFT record (`record_num`) into a fresh buffer.
fn read_mft_record(ntfs: &NtfsBoot, record_num: u64) -> Option<Vec<u8>> {
    let lcn = ntfs.mft_start_lcn;
    let sectors_per_record = ((ntfs.mft_record_size as u64 + 511) / 512) as u32;
    let lba = lcn * (ntfs.sectors_per_cluster as u64) + record_num * (ntfs.mft_record_size as u64) / 512;
    let (buf, _) = read_ntfs_partition_sectors(lba, sectors_per_record)?;
    if buf.len() < ntfs.mft_record_size as usize { return None; }
    if record_num <= 11 && false {
        let n = buf.len().min(512);
        // Walk attributes and print types/lengths to help debug
        // INDEX_ROOT lookup failures.
        let first_attr = u16::from_le_bytes([buf[0x14], buf[0x15]]) as usize;
        let mut off = first_attr;
        uefi::println!("[NTFS] read_mft_record({}) lba={} first_attr_off={}", record_num, lba, first_attr);
        while off + 8 <= n {
            let atype = u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
            if atype == 0xFFFFFFFF { break; }
            let alen = u32::from_le_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
            if alen == 0 { break; }
            uefi::println!("[NTFS]   attr 0x{:02x} off={} len={}", atype, off, alen);
            if atype == 0x90 {
                let body = off + 0x18;
                let e_off_rel = u32::from_le_bytes([buf[body+0x10], buf[body+0x11], buf[body+0x12], buf[body+0x13]]);
                let total = u32::from_le_bytes([buf[body+0x14], buf[body+0x15], buf[body+0x16], buf[body+0x17]]);
                uefi::println!("[NTFS]     INDEX_ROOT body={} e_off_rel={} total={}", body, e_off_rel, total);
            }
            off += alen as usize;
            if off > n { break; }
        }
    }
    Some(buf)
}

/// Decode a UTF-16LE filename attribute (0x30) into a Rust `String`.
fn decode_filename_attr(buf: &[u8], off: usize) -> Option<(String, u64)> {
    if off + 66 > buf.len() { return None; }
    // FILE_NAME attribute body layout:
    //   0x00: parent dir MFT reference (8 bytes)
    //   0x08: timestamps (32 bytes)
    //   0x28: allocated size (8)
    //   0x30: real size (8)
    //   0x38: flags (4)
    //   0x3C: EA/reparse (4)
    //   0x40: name length in chars (1)
    //   0x41: name namespace (1)
    //   0x42: name (UTF-16LE)
    let name_chars = buf[off + 0x40] as usize;
    if off + 0x42 + name_chars * 2 > buf.len() { return None; }
    let mut name = String::new();
    for i in 0..name_chars {
        let c = u16::from_le_bytes([buf[off + 0x42 + i*2], buf[off + 0x42 + i*2 + 1]]);
        if c == 0 { continue; } // skip embedded NULs — they confuse UEFI console output
        if let Some(ch) = char::from_u32(c as u32) { name.push(ch); }
    }
    let parent_ref = u64::from_le_bytes([
        buf[off], buf[off+1], buf[off+2], buf[off+3],
        buf[off+4], buf[off+5], buf[off+6], buf[off+7],
    ]);
    Some((name, parent_ref & 0x0000_FFFF_FFFF_FFFF))
}

/// Resolve the MFT record number for a file at `path` rooted at MFT
/// record 5 (root directory). Each step walks the index entries in
/// the parent directory's $INDEX_ROOT attribute.
fn resolve_mft_record(ntfs: &NtfsBoot, path: &str) -> Option<u64> {
    if false { uefi::println!("[NTFS] resolve_mft_record: path='{}'", path); }
    let parts: alloc::vec::Vec<&str> = path
        .trim_start_matches('\\')
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();
    if false { uefi::println!("[NTFS]   parts={:?}", parts); }
    let mut current = 5u64; // Root directory
    for part in &parts {
        if false { uefi::println!("[NTFS]   resolving part '{}' from record {}", part, current); }
        current = find_child_in_index(ntfs, current, part)?;
    }
    Some(current)
}

/// Scan the `$INDEX_ROOT` of `parent_record` for an entry whose
/// filename matches `name`. Returns the child's MFT record number.
fn find_child_in_index(ntfs: &NtfsBoot, parent_record: u64, name: &str) -> Option<u64> {
    if false { uefi::println!("[NTFS] find_child_in_index entered: parent={} name='{}'", parent_record, name); }
    let record = match read_mft_record(ntfs, parent_record) {
        Some(r) => r,
        None => {
            uefi::println!("[NTFS]   read_mft_record({}) returned None", parent_record);
            return None;
        }
    };
    if &record[0..4] != b"FILE" {
        uefi::println!("[NTFS]   bad signature: {}", core::str::from_utf8(&record[0..4]).unwrap_or("?"));
        return None;
    }

    // Walk attributes. The first attribute offset is at byte 0x14
    // (relative to the start of the MFT record).
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    let mut found_index_root = false;
    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off], record[off+1], record[off+2], record[off+3],
        ]);
        if attr_type == 0xFFFFFFFF { break; }
        let attr_len = u32::from_le_bytes([
            record[off+4], record[off+5], record[off+6], record[off+7],
        ]) as usize;
        if attr_len == 0 { break; }
        if off + attr_len > end {
            // Attribute runs past end of record. Skip rather than
            // abort the whole scan — some MFT records (especially
            // the root directory when it has a long INDEX_ROOT)
            // legitimately have attributes whose declared length
            // exceeds the record size because they were sized for
            // a larger record template. The kernel walks attributes
            // forward anyway, so we do the same.
            uefi::println!("[NTFS]   skipping attr 0x{:02x} at off={} len={} (>record end={})", attr_type, off, attr_len, end);
            off += attr_len;
            continue;
        }

        if attr_type == 0x90 {
            found_index_root = true;
            // $INDEX_ROOT attribute. The full attribute is 24 bytes
            // of resident header followed by the value:
            //   value offset 0x00: indexed attribute type (0x30)
            //   value offset 0x04: collation rule
            //   value offset 0x08: bytes per index record
            //   value offset 0x0C: clusters per index record
            //   value offset 0x10: INDEX_HEADER (16 bytes)
            //     +0x00: first_entry_offset (u32)
            //     +0x04: total_size (u32)
            //     +0x08: allocated_size (u32)
            //     +0x0C: flags (u32)
            //   value offset 0x20: index entries start
            let body = off + 0x18; // skip 24-byte attr header
            if body + 0x20 > end { off += attr_len; continue; }
            // Index header: 0x00 entries_offset(4) total_size(4)
            // allocated_size(4) flags(4) ...
            let entries_off = body + 0x10
                + u32::from_le_bytes([
                    record[body + 0x10], record[body + 0x11],
                    record[body + 0x12], record[body + 0x13],
                ]) as usize;
            let total_size = u32::from_le_bytes([
                record[body + 0x10 + 4], record[body + 0x10 + 5],
                record[body + 0x10 + 6], record[body + 0x10 + 7],
            ]) as usize;
            if entries_off >= end { off += attr_len; continue; }
            // Walk index entries.
            let mut p = entries_off;
            let end_p = entries_off + total_size;
            if false { uefi::println!("[NTFS] find_child_in_index: parent_record={} name='{}' entries_off={} total_size={}", parent_record, name, entries_off, total_size); }
            while p + 16 < end_p && p + 16 <= end {
                let entry_len = u16::from_le_bytes([
                    record[p + 8], record[p + 9],
                ]) as usize;
                let stream_len = u16::from_le_bytes([
                    record[p + 0x10], record[p + 0x11],
                ]) as usize;
                if entry_len == 0 { break; }
                // Stream starts at p + 0x10. The stream is itself an
                // attribute structure: type 0x30 with $FILE_NAME body.
                let fname_off = p + 0x10;
                if stream_len >= 24 && fname_off + 24 < end {
                    let inner_type = u32::from_le_bytes([
                        record[fname_off], record[fname_off+1],
                        record[fname_off+2], record[fname_off+3],
                    ]);
                    let inner_len = u32::from_le_bytes([
                        record[fname_off+4], record[fname_off+5],
                        record[fname_off+6], record[fname_off+7],
                    ]) as usize;
                    if inner_type == 0x30 && inner_len >= 0x42 {
                        if let Some((fname, _)) = decode_filename_attr(&record, fname_off + 0x18) {
                            if false { uefi::println!("[NTFS]   entry: child_ref=0x{:x} fname='{}'", u64::from_le_bytes([record[p],record[p+1],record[p+2],record[p+3],record[p+4],record[p+5],record[p+6],record[p+7]]), fname); }
                            if fname.eq_ignore_ascii_case(name) {
                                let child_ref = u64::from_le_bytes([
                                    record[p], record[p+1], record[p+2], record[p+3],
                                    record[p+4], record[p+5], record[p+6], record[p+7],
                                ]);
                                return Some(child_ref & 0x0000_FFFF_FFFF_FFFF);
                            }
                        }
                    }
                }
                p += entry_len;
            }
        }

        off += attr_len;
    }
    uefi::println!("[NTFS]   no match for '{}'", name);
    None
}

/// Read the `$DATA` stream of `record_num` and return its contents.
fn read_data_stream(ntfs: &NtfsBoot, record_num: u64) -> Option<Vec<u8>> {
    let record = read_mft_record(ntfs, record_num)?;
    if &record[0..4] != b"FILE" { return None; }
    let mut off = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;
    let end = ntfs.mft_record_size as usize;
    while off + 4 < end {
        let attr_type = u32::from_le_bytes([
            record[off], record[off+1], record[off+2], record[off+3],
        ]);
        if attr_type == 0xFFFFFFFF { break; }
        let attr_len = u32::from_le_bytes([
            record[off+4], record[off+5], record[off+6], record[off+7],
        ]) as usize;
        if attr_len == 0 || off + attr_len > end { break; }
        let non_resident = record[off + 8];
        if attr_type == 0x80 {
            if non_resident == 0 {
                // Resident: data lives at off + 0x18.
                let content_size = u32::from_le_bytes([
                    record[off + 0x10], record[off + 0x11],
                    record[off + 0x12], record[off + 0x13],
                ]) as usize;
                let content_off = u16::from_le_bytes([
                    record[off + 0x14], record[off + 0x15],
                ]) as usize;
                if off + content_off + content_size <= end {
                    return Some(record[off + content_off..off + content_off + content_size].to_vec());
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
                    record[off + 0x30], record[off + 0x31], record[off + 0x32], record[off + 0x33],
                    record[off + 0x34], record[off + 0x35], record[off + 0x36], record[off + 0x37],
                ]);
                let alloc_size = u64::from_le_bytes([
                    record[off + 0x28], record[off + 0x29], record[off + 0x2A], record[off + 0x2B],
                    record[off + 0x2C], record[off + 0x2D], record[off + 0x2E], record[off + 0x2F],
                ]);
                let _init_size = u64::from_le_bytes([
                    record[off + 0x38], record[off + 0x39], record[off + 0x3A], record[off + 0x3B],
                    record[off + 0x3C], record[off + 0x3D], record[off + 0x3E], record[off + 0x3F],
                ]);
                // RunList offset lives at attribute + 0x38 for non-resident
                // $DATA — see NTFS $DATA non-resident attribute layout:
                //   0x10  LowestVCN  (8)
                //   0x18  HighestVCN (8)
                //   0x20  AllocSize  (8)
                //   0x28  RealSize   (8)
                //   0x30  InitSize   (8)
                //   0x38  RunListOffset (2)
                // An earlier version of this routine read the offset from
                // off+0x20 (the lowest VCN field) which produced a
                // garbage run list; the loader still returned 851456 bytes
                // because the read-N-sectors fallback fetched whatever
                // the LCNs happened to point at, but the resulting buffer
                // was the *wrong* bytes of winload.efi. That's why
                // UEFI's `LoadImage` then rejected the image with
                // `EFI_LOAD_ERROR` (its PE-COFF validator saw bytes that
                // no longer formed a valid EFI Application).
                let run_off = u16::from_le_bytes([
                    record[off + 0x38], record[off + 0x39],
                ]) as usize;
                let mut p = off + run_off;
                let mut out: Vec<u8> = alloc::vec![0u8; alloc_size as usize];
                let mut prev_lcn: i64 = 0;
                let mut out_cursor: usize = 0;
                while p < off + attr_len {
                    let header = record[p];
                    if header == 0 { break; }
                    let len_len = (header & 0x0F) as usize;
                    let off_len = ((header >> 4) & 0x0F) as usize;
                    p += 1;
                    if p + len_len + off_len > off + attr_len { break; }
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
                    let lba = lcn * (ntfs.sectors_per_cluster as u64);
                    let byte_count = run_clusters * sector_size;
                    let cluster_count = run_clusters as u32;
                    if let Some((data, _)) = read_ntfs_partition_sectors(lba, cluster_count) {
                        let copy_len = data.len().min(out.len() - out_cursor);
                        out[out_cursor..out_cursor + copy_len]
                            .copy_from_slice(&data[..copy_len]);
                        out_cursor += byte_count as usize;
                    }
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
/// `\Windows\System32\winload.efi`) from the NTFS System partition.
fn read_ntfs_boot_file(rel_path: &str) -> Option<Vec<u8>> {
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::proto::media::block::BlockIO;

    // Find the NTFS partition handle and read its boot sector.
    let handles = boot::find_handles::<BlockIO>().ok()?;
    let mut ntfs_handle: Option<uefi::Handle> = None;
    let mut boot_sector = [0u8; 512];
    for handle in handles.iter() {
        // SAFETY: GetProtocol is non-destructive.
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
        let Ok(block) = sp else { continue; };
        let media = block.media();
        if media.block_size() != 512 { continue; }
        if block.read_blocks(media.media_id(), 0u64, &mut boot_sector).is_err() { continue; }
        if &boot_sector[3..11] == b"NTFS    " {
            ntfs_handle = Some(*handle);
            break;
        }
    }
    let ntfs = match NtfsBoot::parse(&boot_sector) {
        Some(n) => n,
        None => {
            uefi::println!("[NTFS] no NTFS partition found");
            return None;
        }
    };
    let _ = ntfs_handle;
    uefi::println!(
        "[NTFS] mount: bps={} spc={} mft_lcn={} mft_rec_sz={} total_sectors={}",
        ntfs.bytes_per_sector, ntfs.sectors_per_cluster,
        ntfs.mft_start_lcn, ntfs.mft_record_size, ntfs.total_sectors
    );
    let record = match resolve_mft_record(&ntfs, rel_path) {
        Some(r) => r,
        None => {
            uefi::println!("[NTFS] resolve_mft_record FAILED for {}", rel_path);
            return None;
        }
    };
    uefi::println!("[NTFS] {} -> MFT record {}", rel_path, record);
    read_data_stream(&ntfs, record)
}
