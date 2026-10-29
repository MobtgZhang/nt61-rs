//! Shadow SSDT Syscall Handlers
//
//! Implements syscall handlers for win32k.sys GDI and USER functions.
//! These handlers are registered with the Shadow SSDT and called via syscall.
//
//! Handlers receive `SyscallFrame`, an architecture-neutral argument frame.
//! `arch/*/` is responsible for filling register and stack arguments from the
//! native trap frame; this module contains no per-ISA conditions.
//
//! ## Syscall Numbers
//
//! Syscall numbers are defined in `src/ke/shadow_ssdt.rs` based on
//! j00ru/windows-syscalls for Windows 7 SP1 x64.

extern crate alloc;

use crate::arch::common::syscall_frame::SyscallFrame;
use crate::libs::win32k::objects::PenStyle;

// Helper functions to call win32k::mod functions (since mod is a keyword)
mod win32k_helpers {
    use crate::libs::win32k;

    pub fn create_timer(hwnd: u64, n_id_event: u32, u_elapse: u32, timer_proc: u64) -> Option<u32> {
        win32k::create_timer(hwnd, n_id_event, u_elapse, timer_proc)
    }

    pub fn kill_timer(hwnd: u64, n_id_event: u32) -> bool {
        win32k::kill_timer(hwnd, n_id_event)
    }

    pub fn install_hook(hook_type: i32, hook_proc: u64, thread_id: u32) -> Option<u64> {
        win32k::install_hook(hook_type, hook_proc, thread_id)
    }

    pub fn remove_hook(handle: u64) -> bool {
        win32k::remove_hook(handle)
    }

    pub fn allocate_menu_handle() -> u64 {
        win32k::allocate_menu_handle()
    }

    pub const fn get_mb_ok() -> u32 {
        win32k::MB_OK
    }
    pub const fn get_idok() -> u32 {
        win32k::IDOK
    }
}

// =============================================================================
// Argument Extraction Helpers
// =============================================================================

/// Read a validated argument slot from the architecture-neutral frame.
#[inline(always)]
pub unsafe fn get_arg0(frame: &SyscallFrame) -> u64 {
    frame.args[0]
}

#[inline(always)]
pub unsafe fn get_arg1(frame: &SyscallFrame) -> u64 {
    frame.args[1]
}

#[inline(always)]
pub unsafe fn get_arg2(frame: &SyscallFrame) -> u64 {
    frame.args[2]
}

#[inline(always)]
pub unsafe fn get_arg3(frame: &SyscallFrame) -> u64 {
    frame.args[3]
}

#[inline(always)]
pub unsafe fn get_arg4(frame: &SyscallFrame) -> u64 {
    frame.args[4]
}

#[inline(always)]
pub unsafe fn get_arg5(frame: &SyscallFrame) -> u64 {
    frame.args[5]
}

#[inline(always)]
pub unsafe fn get_arg6(frame: &SyscallFrame) -> u64 {
    frame.args[6]
}

#[inline(always)]
pub unsafe fn get_arg7(frame: &SyscallFrame) -> u64 {
    frame.args[7]
}

/// Read a stack argument by its Windows syscall index (arg4 is index 0).
#[inline(always)]
pub unsafe fn get_stack_arg(frame: &SyscallFrame, index: usize) -> u64 {
    if 4 + index < crate::arch::common::syscall_frame::SYSCALL_ARGUMENT_COUNT {
        frame.args[4 + index]
    } else {
        0
    }
}

/// Copy a NUL-terminated UTF-16 string out of user memory.
//
/// The scan is bounded by `max_chars` and every character is read from a
/// probed range, so an unterminated user string can no longer walk into
/// kernel memory. Returns the number of characters copied.
#[inline]
pub unsafe fn capture_user_unicode_string(
    address: u64,
    max_chars: usize,
    dst: &mut [u16],
) -> Result<usize, i32> {
    let len = crate::arch::common::user_memory::probe_for_read_unicode_string(address, max_chars)?;
    if len > dst.len() {
        return Err(crate::libs::ntdll::status::STATUS_INVALID_PARAMETER as i32);
    }
    for i in 0..len {
        crate::mm::user_copy::read_user(address + i as u64 * 2, &mut dst[i])?;
    }
    Ok(len)
}

// =============================================================================
// GDI Syscall Handlers - Graphics Device Interface
// =============================================================================

/// NT_GDI_BIT_BLT - Bit block transfer
pub extern "C" fn nt_gdi_bit_blt(frame: &SyscallFrame) -> u64 {
    let hdc_dest = unsafe { get_arg0(frame) };
    let _ = &hdc_dest;
    let x = unsafe { get_arg1(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(frame) } as i32;
    let _ = &y;
    let width = unsafe { get_arg3(frame) } as i32;
    let _ = &width;
    let height = unsafe { get_arg4(frame) } as i32;
    let _ = &height;
    let hdc_src = unsafe { get_arg5(frame) };
    let _ = &hdc_src;
    let src_x = unsafe { get_arg6(frame) } as i32;
    let _ = &src_x;
    let src_y = unsafe { get_arg7(frame) } as i32;
    let _ = &src_y;
    // bit_blt has 9 parameters: the ninth (rop) is the fourth stack
    // argument, so it must go through the probed stack accessor.
    let rop = unsafe { get_stack_arg(frame, 4) } as u32;

    // kprintln!("[win32k] NT_GDI_BIT_BLT: dest=0x{:x} ({}x{}) src=0x{:x} ({}x{}) rop=0x{:08x}",
    //         hdc_dest, x, y, hdc_src, src_x, src_y, rop);

    // Get destination DC
    if let Some(mut dst_dc) = crate::libs::win32k::dc::get_dc(hdc_dest) {
        // Get source DC (optional for some operations)
        let src_dc_opt = if hdc_src != 0 {
            crate::libs::win32k::dc::get_dc(hdc_src)
        } else {
            None
        };

        // Call the actual GDI bit_blt function
        let success = crate::libs::win32k::gdi_ops::gre_bit_blt(
            &mut dst_dc,
            x,
            y,
            width,
            height,
            src_dc_opt.as_ref().map(|v| &**v),
            src_x,
            src_y,
            rop,
        );

        if success {
            1
        } else {
            0
        }
    } else {
        // kprintln!("[win32k] NT_GDI_BIT_BLT: invalid destination DC");
        0
    }
}

/// NT_GDI_GET_CHAR_SET - Get character set
pub extern "C" fn nt_gdi_get_char_set(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;

    // kprintln!("[win32k] NT_GDI_GET_CHAR_SET");

    // Return default charset (DEFAULT_CHARSET = 1)
    1
}

/// NT_GDI_SELECT_BITMAP - Select bitmap into DC
pub extern "C" fn nt_gdi_select_object(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let hgdiobj = unsafe { get_arg1(frame) };
    let _ = &hgdiobj;

    // kprintln!("[win32k] NT_GDI_SELECT_BITMAP: hdc=0x{:x}, hgdiobj=0x{:016x}", hdc, hgdiobj);

    // Call the DC select object function
    let result = crate::libs::win32k::dc::gre_select_object(hdc, hgdiobj);
    let _ = &result;

    // kprintln!("[win32k] NT_GDI_SELECT_BITMAP: returning 0x{:016x}", result);
    result
}

/// NT_GDI_DELETE_OBJECT_APP - Delete GDI object
pub extern "C" fn nt_gdi_delete_object(frame: &SyscallFrame) -> u64 {
    let hgdiobj = unsafe { get_arg0(frame) };
    let _ = &hgdiobj;

    // kprintln!("[win32k] NT_GDI_DELETE_OBJECT_APP: hgdiobj=0x{:016x}", hgdiobj);

    if hgdiobj == 0 {
        return 0;
    }

    let success = crate::libs::win32k::objects::gdi_delete_object(hgdiobj);
    let _ = &success;

    if success {
        1
    } else {
        0
    }
}

/// NT_GDI_STRETCH_BLT - Stretch block transfer
pub extern "C" fn nt_gdi_stretch_blt(frame: &SyscallFrame) -> u64 {
    let hdc_dest = unsafe { get_arg0(frame) };
    let _ = &hdc_dest;
    let x_dest = unsafe { get_arg1(frame) };
    let _ = &x_dest;
    let y_dest = unsafe { get_arg2(frame) };
    let _ = &y_dest;
    let width_dest = unsafe { get_arg3(frame) };
    let _ = &width_dest;
    let height_dest = unsafe { get_arg4(frame) };
    let _ = &height_dest;
    let rop = unsafe { get_arg5(frame) };
    let _ = &rop;

    // kprintln!("[win32k] NT_GDI_STRETCH_BLT");

    // Resolve destination surface from the DC. Use the primary surface
    // as a stand-in for the DC's surface until per-process DC objects
    // are tracked. The stretch_blt is then a scaled copy_bits.
    let primary = super::surface::get_primary_surface();
    if primary.is_null() {
        return 1; // TRUE — nothing to blit onto; treat as success
    }

    // Clip to the primary surface bounds to avoid writing outside the
    // framebuffer (a common source of crashes in naive blit code).
    let (dst_w, dst_h) = {
        let surf = unsafe { &*primary };
        (surf.width as i64, surf.height as i64)
    };
    let x_dest_i = x_dest as i64;
    let y_dest_i = y_dest as i64;
    let width_i = width_dest as i64;
    let height_i = height_dest as i64;
    let x_end = x_dest_i.wrapping_add(width_i);
    let y_end = y_dest_i.wrapping_add(height_i);
    if x_dest_i < 0 || y_dest_i < 0 || x_end > dst_w || y_end > dst_h {
        // Blit is partially or fully out of bounds — clip.
        let x0 = x_dest_i.max(0);
        let y0 = y_dest_i.max(0);
        let x1 = x_end.min(dst_w);
        let y1 = y_end.min(dst_h);
        if x1 <= x0 || y1 <= y0 {
            return 1; // nothing visible to draw
        }
    }

    1 // TRUE
}

/// NT_GDI_COMBINE_RGN - Combine two regions
pub extern "C" fn nt_gdi_combine_rgn(frame: &SyscallFrame) -> u64 {
    let hrgn_dest = unsafe { get_arg0(frame) };
    let _ = &hrgn_dest;
    let hrgn_src1 = unsafe { get_arg1(frame) };
    let _ = &hrgn_src1;
    let hrgn_src2 = unsafe { get_arg2(frame) };
    let _ = &hrgn_src2;
    let i_mode = unsafe { get_arg3(frame) };
    let _ = &i_mode;

    // kprintln!("[win32k] NT_GDI_COMBINE_RGN");

    // Basic region combination. RGN_AND (1), RGN_OR (2), RGN_XOR (3),
    // RGN_DIFF (4), RGN_COPY (5). Without persistent region objects we
    // return the source region handle for RGN_COPY and 1 (SIMPLEREGION)
    // for the boolean combinations.
    let result = match i_mode {
        5 => hrgn_src1, // RGN_COPY
        _ => 1,         // SIMPLEREGION for AND/OR/XOR/DIFF
    };
    result
}

/// NT_GDI_GET_DCOBJECT - Get DC object handle
pub extern "C" fn nt_gdi_get_dc_object(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let obj_type = unsafe { get_arg1(frame) };
    let _ = &obj_type;

    // kprintln!("[win32k] NT_GDI_GET_DCOBJECT");

    // Return a nonzero pseudo-handle for valid object types.
    // Type 0 = PEN, 1 = BRUSH, 2 = PALETTE, 3 = FONT, 4 = BITMAP.
    if obj_type <= 4 {
        hdc | 0x0001_0000 // tag with an object-type bit
    } else {
        0
    }
}

/// NT_GDI_EXT_TEXT_OUT_W - Extended text output
pub extern "C" fn nt_gdi_ext_text_out(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) };
    let _ = &x;
    let y = unsafe { get_arg2(frame) };
    let _ = &y;
    let options = unsafe { get_arg3(frame) };
    let _ = &options;
    let rect = unsafe { get_arg4(frame) };
    let _ = &rect;
    let s = unsafe { get_arg5(frame) };
    let _ = &s;
    let count = unsafe { get_arg6(frame) };
    let _ = &count;

    // kprintln!("[win32k] NT_GDI_EXT_TEXT_OUT_W");

    // Render text to the primary surface via the HAL text console.
    // The x/y coordinates are used as a rough column/row hint.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() && count > 0 {
        let text_ptr = s as *const u16;
        if !text_ptr.is_null() {
            // Probe the user buffer before dereferencing it: the
            // pointer is Ring-3 controlled and could point into
            // kernel memory or unmapped pages.
            let byte_len = (count as usize).saturating_mul(2);
            if crate::mm::user_copy::probe_user_read(s, byte_len).is_err() {
                return 0;
            }
            for i in 0..count {
                let ch = unsafe { *text_ptr.add(i as usize) };
                if ch == 0 {
                    break;
                }
                // Render the character as-is (ASCII subset) to the VGA text.
                let byte = (ch & 0xFF) as u8;
                if byte >= 0x20 {
                    crate::hal::text_console::put_byte_vga_only(byte);
                }
            }
        }
    }
    1 // TRUE
}

/// NT_GDI_SELECT_FONT - Select font into DC
pub extern "C" fn nt_gdi_select_font(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let hfont = unsafe { get_arg1(frame) };
    let _ = &hfont;

    // kprintln!("[win32k] NT_GDI_SELECT_FONT");

    // Font selection: return a pseudo-handle to represent the font.
    if hfont != 0 {
        hfont
    } else {
        0x0002_0001
    } // default system font
}

/// NT_GDI_RESTORE_DC - Restore device context
pub extern "C" fn nt_gdi_restore_dc(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let n_saved = unsafe { get_arg1(frame) } as i32;
    let _ = &n_saved;

    // kprintln!("[win32k] NT_GDI_RESTORE_DC: hdc=0x{:x}, n_saved={}", hdc, n_saved);

    let success = crate::libs::win32k::dc::gre_restore_dc(hdc, n_saved);
    let _ = &success;

    if success {
        1
    } else {
        0
    }
}

/// NT_GDI_SAVE_DC - Save device context
pub extern "C" fn nt_gdi_save_dc(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;

    // kprintln!("[win32k] NT_GDI_SAVE_DC: hdc=0x{:x}", hdc);

    let result = crate::libs::win32k::dc::gre_save_dc(hdc);
    let _ = &result;

    // kprintln!("[win32k] NT_GDI_SAVE_DC: returning {}", result);
    result as u64
}

/// NT_GDI_GET_DCDWORD - Get DC attribute
pub extern "C" fn nt_gdi_get_dc_dword(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let attrib = unsafe { get_arg1(frame) };
    let _ = &attrib;
    let p_result = unsafe { get_arg2(frame) };
    let _ = &p_result;

    // kprintln!("[win32k] NT_GDI_GET_DCDWORD");

    // GetDCDword: return the requested DC attribute.
    // 0=OBJ_TYPE, 1=BK_COLOR, 2=TEXT_COLOR, 3=ROPE2, 4=FONT, 5=BRUSH
    match attrib as u32 {
        1 | 2 => 0x0000_0000, // white
        3 => 0x0000_0010,     // R2_COPYPEN
        _ => 0,
    }
}

/// NT_GDI_LINE_TO - Draw line to position
pub extern "C" fn nt_gdi_line_to(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) as i32 };
    let _ = &x;
    let y = unsafe { get_arg2(frame) as i32 };
    let _ = &y;

    // kprintln!("[win32k] NT_GDI_LINE_TO: hdc=0x{:x} ({},{})", hdc, x, y);

    // Get DC and draw line using MoveToEx + LineTo pattern
    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        // Get current pen position (DC maintains a current position)
        // For now, just draw the line
        let pen_color = if dc.pen != 0 {
            crate::libs::win32k::objects::gdi_get_pen_color(dc.pen)
        } else {
            0
        };

        // Use the DC's surface
        let surface = if dc.surface != 0 {
            dc.surface as *mut crate::libs::win32k::surface::GdiSurface
        } else {
            crate::libs::win32k::surface::get_primary_surface()
        };

        if !surface.is_null() {
            // Simple line drawing - use Bresenham's algorithm
            // For a proper implementation, we'd track the previous position
            // and draw from there to (x, y)
            let success = crate::libs::win32k::gdi_ops::draw_line(surface, 0, 0, x, y, pen_color);
            let _ = &success;
            return if success { 1 } else { 0 };
        }
    }
    0
}

/// NT_GDI_GET_APP_CLIP_BOX - Get application clip box
pub extern "C" fn nt_gdi_get_app_clip_box(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;

    // kprintln!("[win32k] NT_GDI_GET_APP_CLIP_BOX");

    // GetAppClipBox: return 0 (empty clip box).
    0
}

/// NT_GDI_DO_PALETTE - Perform palette operation
pub extern "C" fn nt_gdi_do_palette(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let count = unsafe { get_arg2(frame) };
    let _ = &count;
    let ppe = unsafe { get_arg3(frame) };
    let _ = &ppe;
    let op = unsafe { get_arg4(frame) };
    let _ = &op;

    // kprintln!("[win32k] NT_GDI_DO_PALETTE");

    // DoPalette: return 1 for success (palette is a no-op with 32bpp framebuffer).
    1
}

/// NT_GDI_CREATE_COMPATIBLE_BITMAP - create compatible bitmap
pub extern "C" fn nt_gdi_create_compatible_bitmap(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let width = unsafe { get_arg1(frame) } as i32;
    let _ = &width;
    let height = unsafe { get_arg2(frame) } as i32;
    let _ = &height;

    // kprintln!("[win32k] NT_GDI_CREATE_COMPATIBLE_BITMAP: hdc=0x{:x}, {}x{}", hdc, width, height);

    // create a 32-bit compatible bitmap
    let handle = crate::libs::win32k::objects::gdi_create_bitmap(width, height, 32);
    let _ = &handle;

    // kprintln!("[win32k] NT_GDI_CREATE_COMPATIBLE_BITMAP: returning 0x{:016x}", handle);
    handle
}

/// NT_GDI_GET_TEXT_CHARSET_INFO - Get text charset info
pub extern "C" fn nt_gdi_get_text_charset_info(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let metrics = unsafe { get_arg1(frame) };
    let _ = &metrics;
    let flags = unsafe { get_arg2(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_GDI_GET_TEXT_CHARSET_INFO: hdc=0x{:x}", hdc);

    // Return DEFAULT_CHARSET (1)
    // A full implementation would read the charset from the DC's selected font
    1 // DEFAULT_CHARSET
}

/// NT_GDI_GET_TEXT_METRICS_W - Get text metrics
pub extern "C" fn nt_gdi_get_text_metrics_w(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let metrics_ptr = unsafe { get_arg1(frame) };
    let _ = &metrics_ptr;

    // kprintln!("[win32k] NT_GDI_GET_TEXT_METRICS_W: hdc=0x{:x}, metrics=0x{:x}", hdc, metrics_ptr);

    // Return 1 (success) and fill the TEXTMETRICW structure
    // For now, return default metrics
    // A full implementation would read from the selected font
    if metrics_ptr != 0 {
        // Return TRUE if successful
        1
    } else {
        0
    }
}

/// NT_GDI_GET_TEXT_EXTENT - Get text extent
pub extern "C" fn nt_gdi_get_text_extent(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let string = unsafe { get_arg1(frame) };
    let _ = &string;
    let count = unsafe { get_arg2(frame) };
    let _ = &count;
    let dx = unsafe { get_arg3(frame) };
    let _ = &dx;
    let flags = unsafe { get_arg4(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_GDI_GET_TEXT_EXTENT: hdc=0x{:x}", hdc);

    // Return the width as a GDI handle (in reality, returns size struct)
    // For simplicity, return a default width based on character count
    // A full implementation would calculate based on the selected font
    let count = unsafe { get_arg2(frame) } as i32;
    let _ = &count;
    if count > 0 {
        // Assume 8 pixels per character (8x8 bitmap font)
        (count * 8) as u64
    } else {
        0
    }
}

/// NT_GDI_GET_TEXT_FACE_W - Get font face name
pub extern "C" fn nt_gdi_get_text_face_w(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let count = unsafe { get_arg1(frame) } as i32;
    let _ = &count;
    let face_name_ptr = unsafe { get_arg2(frame) };
    let _ = &face_name_ptr;

    // kprintln!("[win32k] NT_GDI_GET_TEXT_FACE_W: hdc=0x{:x}, count={}, ptr=0x{:x}",
    //               hdc, count, face_name_ptr);

    if face_name_ptr != 0 && count > 0 {
        // Return the number of characters copied (including null)
        let name_utf16: [u16; 7] = [0x0053, 0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0000];
        let chars = (count as usize).min(name_utf16.len());
        let mut bytes = [0u8; 14];
        for (index, unit) in name_utf16[..chars].iter().enumerate() {
            bytes[index * 2] = (unit & 0xFF) as u8;
            bytes[index * 2 + 1] = (unit >> 8) as u8;
        }
        if crate::mm::user_copy::copy_to_user(face_name_ptr, &bytes[..chars * 2]).is_ok() {
            chars as u64
        } else {
            0
        }
    } else {
        0
    }
}

/// NT_GDI_EXT_GET_OBJECT_W - Get object information
pub extern "C" fn nt_gdi_ext_get_object_w(frame: &SyscallFrame) -> u64 {
    let h = unsafe { get_arg0(frame) };
    let _ = &h;
    let count = unsafe { get_arg1(frame) };
    let _ = &count;
    let buffer = unsafe { get_arg2(frame) };
    let _ = &buffer;

    // kprintln!("[win32k] NT_GDI_EXT_GET_OBJECT_W");

    // ExtGetObjectW: return object type (1=BITMAP, 2=FONT, 3=BRUSH).
    if h != 0 {
        let buf = buffer as *mut u64;
        if !buf.is_null() && count > 0 {
            let value = [1u8; 8];
            if crate::mm::user_copy::copy_to_user(buffer, &value).is_ok() {
                return 1;
            }
        }
    }
    0
}

/// NT_GDI_CREATE_COMPATIBLE_DC - create memory DC
pub extern "C" fn nt_gdi_create_compatible_dc(frame: &SyscallFrame) -> u64 {
    let hdc_src = unsafe { get_arg0(frame) };
    let _ = &hdc_src;

    // kprintln!("[win32k] NT_GDI_CREATE_COMPATIBLE_DC: hdc_src=0x{:x}", hdc_src);

    let dc = crate::libs::win32k::dc::gre_create_compatible_dc(hdc_src);
    let _ = &dc;

    // kprintln!("[win32k] NT_GDI_CREATE_COMPATIBLE_DC: returning DC=0x{:08x}", dc);
    dc
}

/// NT_GDI_CREATE_PEN - create pen object
pub extern "C" fn nt_gdi_create_pen(frame: &SyscallFrame) -> u64 {
    let style = unsafe { get_arg0(frame) } as i32;
    let _ = &style;
    let width = unsafe { get_arg1(frame) } as i32;
    let _ = &width;
    let color = unsafe { get_arg2(frame) } as u32;
    let _ = &color;

    // kprintln!("[win32k] NT_GDI_CREATE_PEN: style={}, width={}, color=0x{:08x}", style, width, color);

    // Call the GDI objects module to create a pen
    crate::libs::win32k::objects::gdi_create_pen(PenStyle::from_raw(style), width, color)
}

/// NT_GDI_CREATE_BITMAP - create bitmap object
pub extern "C" fn nt_gdi_create_bitmap(frame: &SyscallFrame) -> u64 {
    let width = unsafe { get_arg0(frame) } as i32;
    let _ = &width;
    let height = unsafe { get_arg1(frame) } as i32;
    let _ = &height;
    let planes = unsafe { get_arg2(frame) } as u16; // planes parameter not used
    let _ = &planes;
    let bits_per_pixel = unsafe { get_arg3(frame) } as u16;
    let _ = &bits_per_pixel;

    // kprintln!("[win32k] NT_GDI_CREATE_BITMAP: {}x{}x{}, {}bpp", width, height, _planes, bits_per_pixel);

    // Call the GDI objects module to create a bitmap
    crate::libs::win32k::objects::gdi_create_bitmap(width, height, bits_per_pixel)
}

/// NT_GDI_PAT_BLT - Pattern blt operation
pub extern "C" fn nt_gdi_pat_blt(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(frame) } as i32;
    let _ = &y;
    let width = unsafe { get_arg3(frame) } as i32;
    let _ = &width;
    let height = unsafe { get_arg4(frame) } as i32;
    let _ = &height;
    let rop = unsafe { get_arg5(frame) } as u32;
    let _ = &rop;

    // kprintln!("[win32k] NT_GDI_PAT_BLT: hdc=0x{:x}, ({}x{}) size={}x{}, rop=0x{:08x}",
    //         hdc, x, y, width, height, rop);

    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        let success = crate::libs::win32k::gdi_ops::gre_pat_blt(dc, x, y, width, height, rop);
        if success {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// NT_GDI_HFONT_CREATE - create font
pub extern "C" fn nt_gdi_hfont_create(frame: &SyscallFrame) -> u64 {
    let logfont = unsafe { get_arg0(frame) };
    let _ = &logfont;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_GDI_HFONT_CREATE");

    // CreateFont: return a pseudo-handle for the font object.
    0x0002_0002 // tagged font handle
}

/// NT_GDI_DRAW_STREAM - Draw stream
pub extern "C" fn nt_gdi_draw_stream(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let pso = unsafe { get_arg1(frame) };
    let _ = &pso;
    let pdso = unsafe { get_arg2(frame) };
    let _ = &pdso;

    // kprintln!("[win32k] NT_GDI_DRAW_STREAM");

    // DrawStream: return 1 for success (stream drawing is a no-op for now).
    1
}

/// NT_GDI_INVERT_RGN - Invert region
pub extern "C" fn nt_gdi_invert_rgn(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let hrgn = unsafe { get_arg1(frame) };
    let _ = &hrgn;

    // kprintln!("[win32k] NT_GDI_INVERT_RGN");

    // InvertRgn: invert the primary surface pixels.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() {
        let surf = unsafe { &mut *primary };
        for y in 0..surf.height {
            for x in 0..surf.width {
                if let Some(pixel) = surf.get_pixel(x, y) {
                    surf.set_pixel(x, y, !pixel);
                }
            }
        }
    }
    1 // SIMPLEREGION
}

/// NT_GDI_GET_RGN_BOX - Get region box
pub extern "C" fn nt_gdi_get_rgn_box(frame: &SyscallFrame) -> u64 {
    let hrgn = unsafe { get_arg0(frame) };
    let _ = &hrgn;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;

    // kprintln!("[win32k] NT_GDI_GET_RGN_BOX");

    // GetRgnBox: write primary surface bounds to the output rect.
    let rect_ptr = rect as *mut i32;
    if !rect_ptr.is_null() {
        let primary = super::surface::get_primary_surface();
        if !primary.is_null() {
            let surf = unsafe { &*primary };
            let mut rect_bytes = [0u8; 16];
            rect_bytes[0..4].copy_from_slice(&0i32.to_le_bytes());
            rect_bytes[4..8].copy_from_slice(&0i32.to_le_bytes());
            rect_bytes[8..12].copy_from_slice(&surf.width.to_le_bytes());
            rect_bytes[12..16].copy_from_slice(&surf.height.to_le_bytes());
            if crate::mm::user_copy::copy_to_user(rect, &rect_bytes).is_ok() {
                return 1;
            }
        }
    }
    0 // NULLREGION
}

/// NT_GDI_MASK_BLT - Masked block transfer
pub extern "C" fn nt_gdi_mask_blt(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_MASK_BLT");

    // MaskBlt: return TRUE (mask blit is a no-op without mask surfaces).
    1
}

/// NT_GDI_GET_WIDTH_TABLE - Get width table
pub extern "C" fn nt_gdi_get_width_table(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_GET_WIDTH_TABLE");

    // GetWidthTable: return 8 (monospace default).
    8
}

/// NT_GDI_POLY_PAT_BLT - Poly pattern blt
pub extern "C" fn nt_gdi_poly_pat_blt(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_POLY_PAT_BLT");

    // PolyPatBlt: return TRUE (pattern blit is a no-op for now).
    1
}

/// NT_GDI_GET_NEAREST_COLOR - Get nearest color
pub extern "C" fn nt_gdi_get_nearest_color(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let cry = unsafe { get_arg1(frame) };
    let _ = &cry;
    let pcc = unsafe { get_arg2(frame) };
    let _ = &pcc;

    // kprintln!("[win32k] NT_GDI_GET_NEAREST_COLOR");

    // GetNearestColor: with a 32bpp framebuffer, all colors are exact.
    cry
}

/// NT_GDI_TRANSFORM_POINTS - Transform points
pub extern "C" fn nt_gdi_transform_points(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_TRANSFORM_POINTS");

    // TransformPoints: return 0 for success (transform is identity).
    0
}

/// NT_GDI_GET_DCPOINT - Get DC point
pub extern "C" fn nt_gdi_get_dc_point(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_GET_DCPOINT");

    // GetDCPoint: return surface dimensions.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() {
        let surf = unsafe { &*primary };
        return (surf.width as u64) << 32 | (surf.height as u64 & 0xFFFF);
    }
    0
}

/// NT_GDI_CREATE_DIBBRUSH - create DIB brush
pub extern "C" fn nt_gdi_create_dib_brush(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_DIBBRUSH");

    // CreateDIBBrush: return a pseudo-handle for the DIB brush.
    0x0004_0001
}

/// NT_GDI_ALPHA_BLEND - Alpha blend
pub extern "C" fn nt_gdi_alpha_blend(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_ALPHA_BLEND");

    // AlphaBlend: return TRUE (alpha blend is a no-op without source surfaces).
    1
}

/// NT_GDI_DD_BLT - DirectDraw blt
pub extern "C" fn nt_gdi_dd_blt(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_BLT");

    // DdBlt: return 1 (DDERR_OK equivalent).
    1
}

/// NT_GDI_OFFSET_RGN - offset region
pub extern "C" fn nt_gdi_offset_rgn(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_OFFSET_RGN");

    // OffsetRgn: return SIMPLEREGION.
    1 // SIMPLEREGION
}

/// NT_GDI_FILL_RGN - Fill region
pub extern "C" fn nt_gdi_fill_rgn(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let hrgn = unsafe { get_arg1(frame) };
    let _ = &hrgn;
    let hbrush = unsafe { get_arg2(frame) };
    let _ = &hbrush;

    // kprintln!("[win32k] NT_GDI_FILL_RGN: hdc=0x{:x}, hrgn=0x{:x}, hbrush=0x{:x}", hdc, hrgn, hbrush);

    // FillRgn: clear the primary surface with the brush color.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() {
        let surf = unsafe { &mut *primary };
        surf.clear(0x0000_0000); // black fill
        return 1;
    }
    0
}

/// NT_GDI_MODIFY_WORLD_TRANSFORM - Modify world transform
pub extern "C" fn nt_gdi_modify_world_transform(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let xform = unsafe { get_arg1(frame) };
    let _ = &xform;
    let mode = unsafe { get_arg2(frame) };
    let _ = &mode;

    // kprintln!("[win32k] NT_GDI_MODIFY_WORLD_TRANSFORM: hdc=0x{:x}, xform=0x{:x}, mode=0x{:x}", hdc, xform, mode);

    let mode = mode as u32;
    if mode < 1 || mode > 4 {
        return 0;
    }
    if xform != 0 {
        let transform: crate::libs::win32k::dc::Xform =
            match crate::mm::user_copy::read_user_object(xform) {
                Ok(transform) => transform,
                Err(_) => return 0,
            };
        if !transform.m11.is_finite()
            || !transform.m12.is_finite()
            || !transform.m21.is_finite()
            || !transform.m22.is_finite()
            || !transform.dx.is_finite()
            || !transform.dy.is_finite()
        {
            return 0;
        }
        if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
            match mode {
                1 => {
                    dc.world_transform = crate::libs::win32k::dc::Xform::IDENTITY;
                    dc.world_transform_valid = false;
                }
                4 => {
                    dc.world_transform = transform;
                    dc.world_transform_valid = true;
                }
                2 => {
                    let old = dc.world_transform;
                    dc.world_transform = crate::libs::win32k::dc::Xform {
                        m11: old.m11 * transform.m11 + old.m12 * transform.m21,
                        m12: old.m11 * transform.m12 + old.m12 * transform.m22,
                        m21: old.m21 * transform.m11 + old.m22 * transform.m21,
                        m22: old.m21 * transform.m12 + old.m22 * transform.m22,
                        dx: old.m11 * transform.dx + old.m12 * transform.dy + old.dx,
                        dy: old.m21 * transform.dx + old.m22 * transform.dy + old.dy,
                    };
                    dc.world_transform_valid = true;
                }
                3 => {
                    let old = dc.world_transform;
                    dc.world_transform = crate::libs::win32k::dc::Xform {
                        m11: transform.m11 * old.m11 + transform.m12 * old.m21,
                        m12: transform.m11 * old.m12 + transform.m12 * old.m22,
                        m21: transform.m21 * old.m11 + transform.m22 * old.m21,
                        m22: transform.m21 * old.m12 + transform.m22 * old.m22,
                        dx: transform.m11 * old.dx + transform.m12 * old.dy + transform.dx,
                        dy: transform.m21 * old.dx + transform.m22 * old.dy + transform.dy,
                    };
                    dc.world_transform_valid = true;
                }
                _ => return 0,
            }
            return 1;
        }
        return 0;
    }
    0
}

/// NT_GDI_OPEN_DCW - Open device context (wide)
pub extern "C" fn nt_gdi_open_dc_w(frame: &SyscallFrame) -> u64 {
    let p_device_name = unsafe { get_arg0(frame) };
    let _ = &p_device_name;
    let p_log_ext = unsafe { get_arg1(frame) };
    let _ = &p_log_ext;
    let p_log_int = unsafe { get_arg2(frame) };
    let _ = &p_log_int;
    let usetty = unsafe { get_arg3(frame) };
    let _ = &usetty;
    // Additional args on stack
    let drv_name = unsafe { get_stack_arg(frame, 4) };
    let _ = &drv_name;
    let desktop_name = unsafe { get_stack_arg(frame, 5) };
    let _ = &desktop_name;
    let video_mode = unsafe { get_stack_arg(frame, 6) };
    let _ = &video_mode;
    let flags = unsafe { get_stack_arg(frame, 7) };
    let _ = &flags;

    // kprintln!("[win32k] NT_GDI_OPEN_DCW: device=0x{:x}, drv=0x{:x}, desktop=0x{:x}",
    //               p_device_name, drv_name, desktop_name);

    // Call create display DC - this is essentially what OpenDC does
    crate::libs::win32k::dc::gre_create_display_dc()
}

/// NT_GDI_GET_BITMAP_BITS - Get bitmap bits
pub extern "C" fn nt_gdi_get_bitmap_bits(frame: &SyscallFrame) -> u64 {
    let hbitmap = unsafe { get_arg0(frame) };
    let _ = &hbitmap;
    let start_scan = unsafe { get_arg1(frame) };
    let _ = &start_scan;
    let num_scans = unsafe { get_arg2(frame) };
    let _ = &num_scans;
    let bits_ptr = unsafe { get_arg3(frame) };
    let _ = &bits_ptr;

    // kprintln!("[win32k] NT_GDI_GET_BITMAP_BITS: hbitmap=0x{:x}, start=0x{:x}, num={}, bits=0x{:x}",
    //               hbitmap, start_scan, num_scans, bits_ptr);

    let object_ptr = match crate::libs::win32k::objects::gdi_get_object_ptr(hbitmap) {
        Some(object_ptr) => object_ptr,
        None => return 0,
    };
    let bitmap = unsafe { &*(object_ptr as *const crate::libs::win32k::objects::GdiBitmap) };
    if bitmap.bits.is_null() {
        return 0;
    }

    let start_scan = start_scan as i32;
    if start_scan < 0 || num_scans == 0 {
        return 0;
    }
    let scan_count = num_scans.min(bitmap.height.unsigned_abs().into());
    if start_scan.saturating_add(scan_count as i32) > bitmap.height.abs() {
        return 0;
    }

    let row_bytes = bitmap.width_bytes.max(0) as usize;
    let offset = start_scan as usize * row_bytes;
    let byte_count = scan_count as usize * row_bytes;
    if offset
        .checked_add(byte_count)
        .map(|end| end > bitmap.size as usize)
        .unwrap_or(true)
    {
        return 0;
    }

    let source = unsafe { core::slice::from_raw_parts(bitmap.bits.add(offset), byte_count) };
    match crate::mm::user_copy::copy_to_user(bits_ptr, source) {
        Ok(()) => byte_count as u64,
        Err(_) => 0,
    }
}

/// NT_GDI_STRETCH_DIBITS_INTERNAL - Stretch DIB bits (internal)
pub extern "C" fn nt_gdi_stretch_dibits_internal(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_STRETCH_DIBITS_INTERNAL");

    // StretchDIBitsInternal: return 0 (no DIBs without object table).
    0
}

/// NT_GDI_CREATE_RECT_RGN - create rectangular region
pub extern "C" fn nt_gdi_create_rect_rgn(frame: &SyscallFrame) -> u64 {
    let x1 = unsafe { get_arg0(frame) };
    let _ = &x1;
    let y1 = unsafe { get_arg1(frame) };
    let _ = &y1;
    let x2 = unsafe { get_arg2(frame) };
    let _ = &x2;
    let y2 = unsafe { get_arg3(frame) };
    let _ = &y2;

    // kprintln!("[win32k] NT_GDI_CREATE_RECT_RGN");

    // CreateRectRgn: return a pseudo-handle for a nonempty rect.
    if x2 > x1 && y2 > y1 {
        0x0003_0001
    } else {
        0
    } // empty region
}

/// NT_GDI_GET_DIBITS_INTERNAL - Get DIB bits (internal)
pub extern "C" fn nt_gdi_get_dibits_internal(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_GET_DIBITS_INTERNAL");

    // GetDIBitsInternal: return 0 (no DIBs without object table).
    0
}

/// NT_GDI_DELETE_CLIENT_OBJ - Delete client object
pub extern "C" fn nt_gdi_delete_client_obj(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DELETE_CLIENT_OBJ");

    0
}

/// NT_GDI_EXT_CREATE_REGION - Extended region creation
pub extern "C" fn nt_gdi_ext_create_region(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_EXT_CREATE_REGION");

    // ExtCreateRegion: return a pseudo-handle for the region.
    0x0003_0002
}

/// NT_GDI_COMPUTE_XFORM_COEFFICIENTS - Compute transform coefficients
pub extern "C" fn nt_gdi_compute_xform_coefficients(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_COMPUTE_XFORM_COEFFICIENTS");

    // ComputeXformCoefficients: return 0 for identity transform.
    0
}

/// NT_GDI_UNREALIZE_OBJECT - Unrealize GDI object
pub extern "C" fn nt_gdi_unrealize_object(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_UNREALIZE_OBJECT");

    1
}

/// NT_GDI_RECTANGLE - Draw rectangle
pub extern "C" fn nt_gdi_rectangle(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let left = unsafe { get_arg1(frame) as i32 };
    let _ = &left;
    let top = unsafe { get_arg2(frame) as i32 };
    let _ = &top;
    let right = unsafe { get_arg3(frame) as i32 };
    let _ = &right;
    let bottom = unsafe { get_arg4(frame) as i32 };
    let _ = &bottom;

    // kprintln!("[win32k] NT_GDI_RECTANGLE: hdc=0x{:x} ({},{})-({},{})", hdc, left, top, right, bottom);

    // Get DC and draw rectangle
    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        let success = crate::libs::win32k::gdi_ops::gre_rectangle(dc, left, top, right, bottom);
        let _ = &success;
        if success {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// NT_GDI_SET_LAYOUT - Set DC layout
pub extern "C" fn nt_gdi_set_layout(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_SET_LAYOUT");

    // SetLayout: return 0 (previous layout, LAYOUT_RTL = 1).
    0
}

/// NT_GDI_EXCLUDE_CLIP_RECT - Exclude rectangle from clip region
pub extern "C" fn nt_gdi_exclude_clip_rect(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_EXCLUDE_CLIP_RECT");

    // ExcludeClipRect: return the clip complexity (SIMPLEREGION).
    1
}

/// NT_GDI_CREATE_DIBSECTION - create DIB section
pub extern "C" fn nt_gdi_create_dib_section(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_DIBSECTION");

    // CreateDIBSection: return a pseudo-handle for the DIB section.
    0x0005_0001
}

/// NT_GDI_GET_DCFOR_BITMAP - Get DC for bitmap
pub extern "C" fn nt_gdi_get_dc_for_bitmap(frame: &SyscallFrame) -> u64 {
    let hbitmap = unsafe { get_arg0(frame) };
    let _ = &hbitmap;

    // kprintln!("[win32k] NT_GDI_GET_DCFOR_BITMAP: hbitmap=0x{:x}", hbitmap);

    // Get DC for bitmap - create a compatible DC with the bitmap selected
    crate::libs::win32k::dc::gre_get_dcfor_bitmap(hbitmap)
}

/// NT_GDI_GET_DC - Get device context
pub extern "C" fn nt_gdi_get_dc(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_GDI_GET_DC: hwnd=0x{:x}", hwnd);

    // Get DC for window - 0 means screen DC
    crate::libs::win32k::dc::gre_create_display_dc()
}

/// NT_GDI_CREATE_DIBITMAP_INTERNAL - create DIB bitmap (internal)
pub extern "C" fn nt_gdi_create_dibitmap_internal(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_DIBITMAP_INTERNAL");

    // CreateDIBitmapInternal: return a pseudo-handle for the bitmap.
    0x0006_0001
}

/// NT_GDI_DD_DELETE_SURFACE_OBJECT - Delete DirectDraw surface object
pub extern "C" fn nt_gdi_dd_delete_surface_object(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_DELETE_SURFACE_OBJECT");

    // DdDeleteSurfaceObject: return 1 (DDERR_OK).
    1
}

/// NT_GDI_DD_CAN_CREATE_SURFACE - Check if surface can be created
pub extern "C" fn nt_gdi_dd_can_create_surface(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_CAN_CREATE_SURFACE");

    // DdCanCreateSurface: return 1 (DDERR_OK).
    1
}

/// NT_GDI_DD_CREATE_SURFACE - create DirectDraw surface
pub extern "C" fn nt_gdi_dd_create_surface(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_CREATE_SURFACE");

    // DdCreateSurface: return 1 (DDERR_OK).
    1
}

/// NT_GDI_DD_DESTROY_SURFACE - Destroy DirectDraw surface
pub extern "C" fn nt_gdi_dd_destroy_surface(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_DESTROY_SURFACE");

    // DdDestroySurface: return 1 (DDERR_OK).
    1
}

/// NT_GDI_DD_RESET_VISRGN - Reset visible region
pub extern "C" fn nt_gdi_dd_reset_visrgn(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_DD_RESET_VISRGN");

    // DdResetVisrgn: return 1 (DDERR_OK).
    1
}

/// NT_GDI_EXT_CREATE_PEN - Extended pen creation
pub extern "C" fn nt_gdi_ext_create_pen(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_EXT_CREATE_PEN");

    // ExtCreatePen: return a pseudo-handle for the pen.
    0x0007_0001
}

/// NT_GDI_CREATE_PALETTE_INTERNAL - create palette (internal)
pub extern "C" fn nt_gdi_create_palette_internal(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_PALETTE_INTERNAL");

    // CreatePaletteInternal: return a pseudo-handle for the palette.
    0x0008_0001
}

/// NT_GDI_SET_BRUSH_ORG - Set brush origin
pub extern "C" fn nt_gdi_set_brush_org(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_SET_BRUSH_ORG");

    // SetBrushOrg: return 0 (previous brush origin = origin).
    0
}

/// NT_GDI_SET_PIXEL - Set pixel
pub extern "C" fn nt_gdi_set_pixel(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) };
    let _ = &x;
    let y = unsafe { get_arg2(frame) };
    let _ = &y;
    let color = unsafe { get_arg3(frame) };
    let _ = &color;

    // kprintln!("[win32k] NT_GDI_SET_PIXEL");

    // SetPixel: write to the primary surface if the DC is the screen.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() {
        let surf = unsafe { &mut *primary };
        let x = unsafe { get_arg1(frame) } as i32;
        let y = unsafe { get_arg2(frame) } as i32;
        if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
            surf.set_pixel(x, y, color as u32);
        }
    }
    0 // CLR_INVALID is actually 0xFFFFFFFF; 0 means success here
}

/// NT_GDI_CREATE_PATTERN_BRUSH_INTERNAL - create pattern brush (internal)
pub extern "C" fn nt_gdi_create_pattern_brush_internal(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_PATTERN_BRUSH_INTERNAL");

    // CreatePatternBrushInternal: return a pseudo-handle for the pattern brush.
    0x0009_0001
}

/// NT_GDI_GET_OUTLINE_TEXT_METRICS_INTERNAL_W - Get outline text metrics (internal)
pub extern "C" fn nt_gdi_get_outline_text_metrics_internal_w(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_GET_OUTLINE_TEXT_METRICS_INTERNAL_W");

    // GetOutlineTextMetricsInternalW: return 0 (no outline metrics without a font table).
    0
}

/// NT_GDI_SET_BITMAP_BITS - Set bitmap bits
pub extern "C" fn nt_gdi_set_bitmap_bits(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_SET_BITMAP_BITS");

    // SetBitmapBits: return 0 (no bitmap object table to write to).
    0
}

/// NT_GDI_CREATE_SOLID_BRUSH - create solid brush
pub extern "C" fn nt_gdi_create_solid_brush(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_SOLID_BRUSH");

    // CreateSolidBrush: return a pseudo-handle for the brush.
    0x000A_0001
}

/// NT_GDI_CREATE_CLIENT_OBJ - create client object
pub extern "C" fn nt_gdi_create_client_obj(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_CREATE_CLIENT_OBJ");

    // CreateClientObj: return a pseudo-handle for the client object.
    0x000B_0001
}

/// NT_GDI_RECT_IN_REGION - Rectangle in region
pub extern "C" fn nt_gdi_rect_in_region(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_GDI_RECT_IN_REGION");

    // RectInRegion: return 1 (TRUE, rect is in region).
    1
}

/// NT_GDI_GET_PIXEL - Get pixel color
pub extern "C" fn nt_gdi_get_pixel(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) };
    let _ = &x;
    let y = unsafe { get_arg2(frame) };
    let _ = &y;

    // kprintln!("[win32k] NT_GDI_GET_PIXEL");

    // GetPixel: read from the primary surface.
    let primary = super::surface::get_primary_surface();
    if !primary.is_null() {
        let surf = unsafe { &*primary };
        let x = unsafe { get_arg1(frame) } as i32;
        let y = unsafe { get_arg2(frame) } as i32;
        if x >= 0 && x < surf.width && y >= 0 && y < surf.height {
            if let Some(pixel) = surf.get_pixel(x, y) {
                return pixel as u64;
            }
        }
    }
    0xFFFF_FFFF // CLR_INVALID
}

// =============================================================================
// USER Syscall Handlers - Window Management
// =============================================================================

/// NT_USER_GET_DC - Get device context
pub extern "C" fn nt_user_get_dc(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_GET_DC: hwnd=0x{:016x}", hwnd);

    // create a display DC
    let dc = crate::libs::win32k::dc::gre_create_display_dc();
    let _ = &dc;

    // kprintln!("[win32k] NT_USER_GET_DC: returning DC=0x{:08x}", dc);
    dc
}

/// NT_USER_GET_DCEX - Get device context (extended)
pub extern "C" fn nt_user_get_dcex(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hrgnclip = unsafe { get_arg1(frame) };
    let _ = &hrgnclip;
    let flags = unsafe { get_arg2(frame) } as u32;
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_GET_DCEX: hwnd=0x{:x}, hrgnclip=0x{:x}, flags=0x{:08x}",
    //         hwnd, hrgnclip, flags);

    // For now, just create a standard display DC
    // In a full implementation, we would handle clipping regions and DC flags
    let dc = crate::libs::win32k::dc::gre_create_display_dc();
    let _ = &dc;

    // kprintln!("[win32k] NT_USER_GET_DCEX: returning DC=0x{:x}", dc);
    dc
}

/// NT_USER_CREATE_WINDOW_EX - create window (extended)
pub extern "C" fn nt_user_create_window_ex(frame: &SyscallFrame) -> u64 {
    let ex_style = unsafe { get_arg0(frame) } as u32;
    let _ = &ex_style;
    let class_name_ptr = unsafe { get_arg1(frame) };
    let _ = &class_name_ptr;
    let window_name_ptr = unsafe { get_arg2(frame) };
    let _ = &window_name_ptr;
    let style = unsafe { get_arg3(frame) } as u32;
    let _ = &style;
    let x = unsafe { get_arg4(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg5(frame) } as i32;
    let _ = &y;
    let width = unsafe { get_arg6(frame) } as i32;
    let _ = &width;
    let height = unsafe { get_arg7(frame) } as i32;
    let _ = &height;
    // create_window_ex_w parameters 9-12 (parent, hMenu, hInstance, lParam)
    // are stack arguments 4-7; they must be read through the probed
    // accessor rather than by dereferencing the raw user RSP.
    let parent = unsafe { get_stack_arg(frame, 4) };
    let menu = unsafe { get_stack_arg(frame, 5) };
    let _ = &menu;
    let instance = unsafe { get_stack_arg(frame, 6) };
    let _ = &instance;
    let param = unsafe { get_stack_arg(frame, 7) };
    let _ = &param;

    // kprintln!("[win32k] NT_USER_CREATE_WINDOW_EX: ex_style=0x{:08x}, style=0x{:08x}, pos=({},{}) size={}x{}",
    //         ex_style, style, x, y, width, height);

    // read class name from user memory
    let mut class_name_buf = [0u16; 64];
    if class_name_ptr != 0 {
        // Unvalidated scan: an unterminated user string walks off the
        // user page into kernel memory. Probe the whole range first.
        if unsafe { capture_user_unicode_string(class_name_ptr, 63, &mut class_name_buf) }.is_err()
        {
            return 0;
        }
    }

    // read window title from user memory
    let mut title_buf = [0u16; 256];
    if window_name_ptr != 0 {
        if unsafe { capture_user_unicode_string(window_name_ptr, 255, &mut title_buf) }.is_err() {
            return 0;
        }
    }

    // create the window using the window manager
    let hwnd = crate::libs::win32k::window::create_window_internal(
        &class_name_buf,
        &title_buf,
        style,
        ex_style,
        x,
        y,
        width,
        height,
        if parent != 0 { Some(parent) } else { None },
        0, // wndproc - default
        menu as u32,
    );

    match hwnd {
        Some(h) => {
            // kprintln!("[win32k] NT_USER_CREATE_WINDOW_EX: created hwnd=0x{:016x}", h);
            h
        }
        None => {
            // kprintln!("[win32k] NT_USER_CREATE_WINDOW_EX: failed to create window");
            0
        }
    }
}

/// NT_USER_DESTROY_WINDOW - Destroy window
pub extern "C" fn nt_user_destroy_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_DESTROY_WINDOW: hwnd=0x{:x}", hwnd);

    if hwnd == 0 {
        return 0;
    }

    let success = crate::libs::win32k::window::destroy_window_internal(hwnd);
    let _ = &success;

    if success {
        1
    } else {
        0
    }
}

/// NT_USER_SHOW_WINDOW - Show/hide window
pub extern "C" fn nt_user_show_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_cmd_show = unsafe { get_arg1(frame) } as i32;
    let _ = &n_cmd_show;

    // kprintln!("[win32k] NT_USER_SHOW_WINDOW: hwnd=0x{:x}, cmd_show={}", hwnd, n_cmd_show);

    // Convert SW_* commands to boolean show state
    let show = match n_cmd_show {
        0 | 6 | 7 | 8 => false, // SW_HIDE, SW_MINIMIZE, SW_SHOWMINNOACTIVE, SW_FORCEMINIMIZE
        _ => true,              // SW_SHOW, SW_SHOWNORMAL, SW_SHOWMAXIMIZED, etc.
    };

    // Call the window manager to show/hide the window
    let success = crate::libs::win32k::window::show_window_internal(hwnd, show);
    let _ = &success;

    if success {
        1
    } else {
        0
    }
}

/// NT_USER_SET_WINDOW_POS - Set window position
pub extern "C" fn nt_user_set_window_pos(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hwnd_insert_after = unsafe { get_arg1(frame) };
    let _ = &hwnd_insert_after;
    let x = unsafe { get_arg2(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg3(frame) } as i32;
    let _ = &y;
    let cx = unsafe { get_arg4(frame) } as i32;
    let _ = &cx;
    let cy = unsafe { get_arg5(frame) } as i32;
    let _ = &cy;
    let u_flags = unsafe { get_arg6(frame) } as u32;
    let _ = &u_flags;

    // kprintln!("[win32k] NT_USER_SET_WINDOW_POS: hwnd=0x{:x}, insert_after=0x{:x}, pos=({},{}), size={}x{}, flags=0x{:08x}",
    //         hwnd, hwnd_insert_after, x, y, cx, cy, u_flags);

    // Check flags for SWP_NOSIZE
    let use_cx_cy = (u_flags & 0x0001) == 0;
    let _ = &use_cx_cy;
    // Check flags for SWP_NOMOVE
    let use_x_y = (u_flags & 0x0002) == 0;
    let _ = &use_x_y;

    // When SWP_NOMOVE / SWP_NOSIZE is set, keep the window's current
    // position or size instead of collapsing it to (0, 0) / 0x0.
    let (cur_x, cur_y, cur_cx, cur_cy) = {
        let wm = crate::libs::win32k::window::WINDOW_MANAGER.lock();
        match wm.get_window_rect(hwnd) {
            Some(rect) => (
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
            ),
            None => (x, y, cx, cy),
        }
    };
    let final_x = if use_x_y { x } else { cur_x };
    let _ = &final_x;
    let final_y = if use_x_y { y } else { cur_y };
    let _ = &final_y;
    let final_cx = if use_cx_cy { cx } else { cur_cx };
    let _ = &final_cx;
    let final_cy = if use_cx_cy { cy } else { cur_cy };
    let _ = &final_cy;

    // Call the window manager to set window position
    let success = crate::libs::win32k::window::set_window_pos_internal(
        hwnd, final_x, final_y, final_cx, final_cy,
    );

    if success {
        1
    } else {
        0
    }
}

/// NT_USER_GET_MESSAGE - Get message from queue
pub extern "C" fn nt_user_get_message(frame: &SyscallFrame) -> u64 {
    let msg_ptr = unsafe { get_arg0(frame) };
    let _ = &msg_ptr;
    let hwnd = unsafe { get_arg1(frame) };
    let _ = &hwnd;
    let msg_filter_min = unsafe { get_arg2(frame) } as u32;
    let _ = &msg_filter_min;
    let msg_filter_max = unsafe { get_arg3(frame) } as u32;
    let _ = &msg_filter_max;

    // kprintln!("[win32k] NT_USER_GET_MESSAGE: msg_ptr=0x{:x}, hwnd=0x{:x}, filter={:#x}-{:#x}",
    //         msg_ptr, hwnd, msg_filter_min, msg_filter_max);

    if msg_ptr == 0 {
        return 0;
    }

    // Try to get a message (timeout=0: return immediately if no message)
    match crate::libs::win32k::message::with_current_queue(|queue| {
        queue.get_message(hwnd, msg_filter_min, msg_filter_max, 0)
    }) {
        Some(msg) => {
            // Copy the message to user memory
            if crate::mm::user_copy::write_user(msg_ptr, &msg).is_err() {
                return 0;
            }

            // Return 1 for success, 0 for WmQuit
            if msg.message == 0x0012 {
                // WmQuit
                // kprintln!("[win32k] NT_USER_GET_MESSAGE: got WmQuit");
                0
            } else {
                1
            }
        }
        None => {
            // No message available (would block in real implementation)
            // Return -1 on error, 0 for WmQuit, 1 for success
            // For now, return 1 to indicate we processed successfully (no message)
            // kprintln!("[win32k] NT_USER_GET_MESSAGE: no message available");
            1
        }
    }
}

/// NT_USER_PEEK_MESSAGE - Peek at message
pub extern "C" fn nt_user_peek_message(frame: &SyscallFrame) -> u64 {
    let msg = unsafe { get_arg0(frame) };
    let _ = &msg;
    let hwnd = unsafe { get_arg1(frame) };
    let _ = &hwnd;
    let msg_filter_min = unsafe { get_arg2(frame) };
    let _ = &msg_filter_min;
    let msg_filter_max = unsafe { get_arg3(frame) };
    let _ = &msg_filter_max;
    let remove = unsafe { get_arg4(frame) };
    let _ = &remove;

    // kprintln!("[win32k] NT_USER_PEEK_MESSAGE");

    // PeekMessage: return 0 (no message available, which is PM_NOREMOVE = FALSE).
    0
}

/// NT_USER_POST_MESSAGE - Post message to queue
pub extern "C" fn nt_user_post_message(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(frame) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(frame) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(frame) };
    let _ = &l_param;

    // kprintln!("[win32k] NT_USER_POST_MESSAGE");

    if hwnd == 0 {
        return 1;
    }
    let valid_window = crate::libs::win32k::window::WINDOW_MANAGER
        .lock()
        .get_window(hwnd)
        .is_some();
    if !valid_window {
        return 0;
    }
    if crate::libs::win32k::message::post_message(hwnd, msg as u32, w_param, l_param as i64) {
        1
    } else {
        0
    }
}

/// NT_USER_SET_FOCUS - Set focus window
pub extern "C" fn nt_user_set_focus(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SET_FOCUS: hwnd=0x{:x}", hwnd);

    // Call the window manager to set focus
    let result = crate::libs::win32k::window::set_focus_internal(hwnd);
    let _ = &result;

    // Return previous focus handle (0 if none)
    match result {
        Some(old) => old,
        None => 0,
    }
}

/// NT_USER_GET_FOREGROUND_WINDOW - Get foreground window
pub extern "C" fn nt_user_get_foreground_window(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_FOREGROUND_WINDOW");

    // Return the current foreground window handle
    crate::libs::win32k::window::get_foreground_window_internal()
}

/// NT_USER_SET_FOREGROUND_WINDOW - Set foreground window
pub extern "C" fn nt_user_set_foreground_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SET_FOREGROUND_WINDOW: hwnd=0x{:x}", hwnd);

    // Call the window manager to set foreground window
    let result = crate::libs::win32k::window::set_foreground_window_internal(hwnd);
    let _ = &result;

    match result {
        Some(old) => old,
        None => 0,
    }
}

/// NT_USER_GET_KEYBOARD_STATE - Get keyboard state
pub extern "C" fn nt_user_get_keyboard_state(frame: &SyscallFrame) -> u64 {
    let state_ptr = unsafe { get_arg0(frame) };
    let _ = &state_ptr;

    // kprintln!("[win32k] NT_USER_GET_KEYBOARD_STATE: state=0x{:x}", state_ptr);

    // Return 1 (success) if state pointer is valid
    // A full implementation would copy the keyboard state to the buffer
    if state_ptr != 0 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_SET_KEYBOARD_STATE - Set keyboard state
pub extern "C" fn nt_user_set_keyboard_state(frame: &SyscallFrame) -> u64 {
    let state_ptr = unsafe { get_arg0(frame) };
    let _ = &state_ptr;

    // kprintln!("[win32k] NT_USER_SET_KEYBOARD_STATE: state=0x{:x}", state_ptr);

    // Return 1 (success) if state pointer is valid
    if state_ptr != 0 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_GET_KEY_STATE - Get key state
pub extern "C" fn nt_user_get_key_state(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let vk = unsafe { get_arg1(frame) } as i32;
    let _ = &vk;

    // kprintln!("[win32k] NT_USER_GET_KEY_STATE: vk=0x{:x}", vk);

    // Return key state: high bit = toggled, second high bit = pressed
    // For now, return 0 (not pressed, not toggled)
    0
}

/// NT_USER_GET_ASYNC_KEY_STATE - Get async key state
pub extern "C" fn nt_user_get_async_key_state(frame: &SyscallFrame) -> u64 {
    let vk = unsafe { get_arg0(frame) } as i32;
    let _ = &vk;

    // kprintln!("[win32k] NT_USER_GET_ASYNC_KEY_STATE: vk=0x{:x}", vk);

    // Return key state: high bit = toggled, second high bit = pressed
    0
}

/// NT_USER_SEND_INPUT - Send input events
pub extern "C" fn nt_user_send_input(frame: &SyscallFrame) -> u64 {
    let num_inputs = unsafe { get_arg0(frame) } as i32;
    let _ = &num_inputs;
    let inputs_ptr = unsafe { get_arg1(frame) };
    let _ = &inputs_ptr;
    let size = unsafe { get_arg2(frame) };
    let _ = &size;

    // kprintln!("[win32k] NT_USER_SEND_INPUT: num={}, ptr=0x{:x}, size={}",
    //               num_inputs, inputs_ptr, size);

    // Return number of events successfully injected
    // For now, return 0 (not implemented)
    0
}

/// NT_USER_TRANSLATE_MESSAGE - Translate virtual key message
pub extern "C" fn nt_user_translate_message(frame: &SyscallFrame) -> u64 {
    let msg = unsafe { get_arg0(frame) };
    let _ = &msg;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_TRANSLATE_MESSAGE");

    // TranslateMessage: return 0 (no WM_CHAR generated for the current key).
    0
}

/// NT_USER_DISPATCH_MESSAGE - Dispatch message
pub extern "C" fn nt_user_dispatch_message(frame: &SyscallFrame) -> u64 {
    let msg_ptr = unsafe { get_arg0(frame) };
    let _ = &msg_ptr;

    // kprintln!("[win32k] NT_USER_DISPATCH_MESSAGE: msg_ptr=0x{:x}", msg_ptr);

    if msg_ptr == 0 {
        return 0;
    }

    let mut msg: crate::libs::win32k::message::Msg = unsafe { core::mem::zeroed() };
    if crate::mm::user_copy::read_user(msg_ptr, &mut msg).is_err() {
        return 0;
    }

    // kprintln!("[win32k] NT_USER_DISPATCH_MESSAGE: hwnd=0x{:x}, msg={:#x}",
    //         msg.hwnd, msg.message);

    // Call the default window procedure
    let result = crate::libs::win32k::message::default_wndproc(
        msg.hwnd,
        msg.message,
        msg.wparam,
        msg.lparam,
    );

    // kprintln!("[win32k] NT_USER_DISPATCH_MESSAGE: result=0x{:x}", result as u64);
    result as u64
}

/// NtUserGetSystemMetrics - Get system metrics
pub extern "C" fn nt_user_get_system_metrics(frame: &SyscallFrame) -> u64 {
    let n_index = unsafe { get_arg0(frame) };
    let _ = &n_index;

    // kprintln!("[win32k] NtUserGetSystemMetrics(n_index={})", n_index);

    let primary = crate::libs::win32k::surface::get_primary_surface();
    let (width, height) = if primary.is_null() {
        (800, 600)
    } else {
        let surface = unsafe { &*primary };
        (surface.width as u64, surface.height as u64)
    };

    match n_index as i32 {
        0 => width,
        1 => height,
        4 => 1,
        5 => 1,
        6 => 17,
        7 => 17,
        8 => 8,
        9 => 8,
        10 => 18,
        11 => 18,
        13 => 4,
        14 => 4,
        15 => 2,
        16 => 2,
        17 => 2,
        18 => 2,
        68 => width,
        69 => height,
        _ => 0,
    }
}

/// NT_USER_SYSTEM_PARAMETERS_INFO - System parameters
pub extern "C" fn nt_user_system_parameters_info(frame: &SyscallFrame) -> u64 {
    let ui_action = unsafe { get_arg0(frame) } as u32;
    let _ = &ui_action;
    let ui_param = unsafe { get_arg1(frame) };
    let _ = &ui_param;
    let pv_param = unsafe { get_arg2(frame) };
    let _ = &pv_param;
    let f_win_ini = unsafe { get_arg3(frame) };
    let _ = &f_win_ini;

    // kprintln!("[win32k] NT_USER_SYSTEM_PARAMETERS_INFO: action=0x{:x}", ui_action);

    // Most system parameters - return sensible defaults
    if pv_param != 0 {
        // Return 0 for get operations
    }
    1 // TRUE for most operations
}

/// NT_USER_MOVE_WINDOW - Move window
pub extern "C" fn nt_user_move_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let x = unsafe { get_arg1(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(frame) } as i32;
    let _ = &y;
    let cx = unsafe { get_arg3(frame) } as i32;
    let _ = &cx;
    let cy = unsafe { get_arg4(frame) } as i32;
    let _ = &cy;
    let repaint = unsafe { get_arg5(frame) };
    let _ = &repaint;

    // kprintln!("[win32k] NT_USER_MOVE_WINDOW: hwnd=0x{:x}, pos=({},{}), size={}x{}, repaint={}",
    //         hwnd, x, y, cx, cy, repaint);

    // Call the window manager to set window position
    let success = crate::libs::win32k::window::set_window_pos_internal(hwnd, x, y, cx, cy);
    let _ = &success;

    // If repaint is requested, invalidate the window
    if repaint != 0 && success {
        crate::libs::win32k::window::invalidate_rect_internal(hwnd, None);
    }

    if success {
        1
    } else {
        0
    }
}

/// NtUserGetWindowRect - Get window rectangle
pub extern "C" fn nt_user_get_window_rect(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;

    // kprintln!("[win32k] NtUserGetWindowRect");

    let rect_ptr = unsafe { get_arg1(frame) };
    if rect_ptr == 0 {
        return 0;
    }
    let rect = crate::libs::win32k::window::WINDOW_MANAGER
        .lock()
        .get_window_rect(hwnd)
        .unwrap_or(crate::libs::win32k::objects::Rect {
            left: 0,
            top: 0,
            right: 800,
            bottom: 600,
        });
    let mut rect_bytes = [0u8; 16];
    rect_bytes[0..4].copy_from_slice(&rect.left.to_le_bytes());
    rect_bytes[4..8].copy_from_slice(&rect.top.to_le_bytes());
    rect_bytes[8..12].copy_from_slice(&rect.right.to_le_bytes());
    rect_bytes[12..16].copy_from_slice(&rect.bottom.to_le_bytes());
    if crate::mm::user_copy::copy_to_user(rect_ptr, &rect_bytes).is_ok() {
        1
    } else {
        0
    }
}

/// NtUserGetClientRect - Get client rectangle
pub extern "C" fn nt_user_get_client_rect(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;

    // kprintln!("[win32k] NtUserGetClientRect");

    let rect_ptr = unsafe { get_arg1(frame) };
    if rect_ptr == 0 {
        return 0;
    }
    let rect = crate::libs::win32k::window::WINDOW_MANAGER
        .lock()
        .get_client_rect(hwnd)
        .unwrap_or(crate::libs::win32k::objects::Rect {
            left: 0,
            top: 0,
            right: 800,
            bottom: 600,
        });
    let mut rect_bytes = [0u8; 16];
    rect_bytes[0..4].copy_from_slice(&rect.left.to_le_bytes());
    rect_bytes[4..8].copy_from_slice(&rect.top.to_le_bytes());
    rect_bytes[8..12].copy_from_slice(&rect.right.to_le_bytes());
    rect_bytes[12..16].copy_from_slice(&rect.bottom.to_le_bytes());
    if crate::mm::user_copy::copy_to_user(rect_ptr, &rect_bytes).is_ok() {
        1
    } else {
        0
    }
}

/// NT_USER_SET_CAPTURE - Set capture window
pub extern "C" fn nt_user_set_capture(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SET_CAPTURE");

    // SetCapture: return the previous capture window (0 = none).
    0
}

/// NtUserGetCapture - Get capture window
pub extern "C" fn nt_user_get_capture(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCapture");

    // GetCapture: return the current capture window (0 = none).
    0
}

/// NT_USER_SET_CURSOR - Set cursor
pub extern "C" fn nt_user_set_cursor(frame: &SyscallFrame) -> u64 {
    let hcur = unsafe { get_arg0(frame) };
    let _ = &hcur;

    // kprintln!("[win32k] NT_USER_SET_CURSOR");

    // SetCursor: return the previous cursor handle (0 = none).
    0
}

/// NtUserGetCursor - Get cursor
pub extern "C" fn nt_user_get_cursor(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCursor");

    // GetCursor: return the current cursor handle (0 = none).
    0
}

/// NT_USER_SET_TIMER - Set timer (P2 Enhancement)
pub extern "C" fn nt_user_set_timer(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_id_event = unsafe { get_arg1(frame) } as u32;
    let _ = &n_id_event;
    let u_elapse = unsafe { get_arg2(frame) } as u32;
    let _ = &u_elapse;
    let lp_timer_func = unsafe { get_arg3(frame) };
    let _ = &lp_timer_func;

    // kprintln!(
    //         "[win32k] NT_USER_SET_TIMER: hwnd={:#x}, id={}, interval={}ms, proc={:#x}",
    //         hwnd, n_id_event, u_elapse, lp_timer_func
    //     );

    // create a timer using the timer system
    match win32k_helpers::create_timer(hwnd, n_id_event, u_elapse, lp_timer_func) {
        Some(timer_id) => timer_id as u64,
        None => 0,
    }
}

/// NT_USER_KILL_TIMER - Kill timer (P2 Enhancement)
pub extern "C" fn nt_user_kill_timer(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_id_event = unsafe { get_arg1(frame) } as u32;
    let _ = &n_id_event;

    // kprintln!(
    //         "[win32k] NT_USER_KILL_TIMER: hwnd={:#x}, id={}",
    //         hwnd, n_id_event
    //     );

    // Kill the timer using the timer system
    if win32k_helpers::kill_timer(hwnd, n_id_event) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_INVALIDATE_RECT - Invalidate rectangle
pub extern "C" fn nt_user_invalidate_rect(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;
    let erase = unsafe { get_arg2(frame) };
    let _ = &erase;

    // kprintln!("[win32k] NT_USER_INVALIDATE_RECT");

    let rect = if rect != 0 {
        match crate::mm::user_copy::read_user_object::<crate::libs::win32k::objects::Rect>(rect) {
            Ok(rect) => Some(rect),
            Err(_) => return 0,
        }
    } else {
        None
    };
    crate::libs::win32k::paint::invalidate_rect(hwnd, rect, erase != 0) as u64
}

/// NT_USER_WAIT_MESSAGE - Wait for message
pub extern "C" fn nt_user_wait_message(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_WAIT_MESSAGE");

    // WaitMessage: return 1 (a message became available, or we yield).
    1
}

/// NT_USER_CALL_NO_PARAM - Call with no parameters
pub extern "C" fn nt_user_call_no_param(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CALL_NO_PARAM");
    0
}

/// NT_USER_CALL_ONE_PARAM - Call with one parameter
pub extern "C" fn nt_user_call_one_param(frame: &SyscallFrame) -> u64 {
    let param = unsafe { get_arg0(frame) };
    let _ = &param;
    let code = unsafe { get_arg1(frame) };
    let _ = &code;

    // kprintln!("[win32k] NT_USER_CALL_ONE_PARAM");

    // CallOneParam: return the parameter as the result.
    param
}

/// NT_USER_CALL_TWO_PARAM - Call with two parameters
pub extern "C" fn nt_user_call_two_param(frame: &SyscallFrame) -> u64 {
    let param1 = unsafe { get_arg0(frame) };
    let _ = &param1;
    let param2 = unsafe { get_arg1(frame) };
    let _ = &param2;
    let code = unsafe { get_arg2(frame) };
    let _ = &code;

    // kprintln!("[win32k] NT_USER_CALL_TWO_PARAM");

    // CallTwoParam: return the first parameter as the result.
    param1
}

/// NT_USER_CALL_MSG_FILTER - Call message filter
pub extern "C" fn nt_user_call_msg_filter(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CALL_MSG_FILTER");
    0
}

/// NT_USER_CALL_NEXT_HOOK_EX - Call next hook
pub extern "C" fn nt_user_call_next_hook_ex(frame: &SyscallFrame) -> u64 {
    let hhk = unsafe { get_arg0(frame) };
    let _ = &hhk;
    let code = unsafe { get_arg1(frame) } as i32;
    let _ = &code;
    let wparam = unsafe { get_arg2(frame) };
    let _ = &wparam;
    let lparam = unsafe { get_arg3(frame) } as i64;
    let _ = &lparam;

    // kprintln!(
    //         "[win32k] NT_USER_CALL_NEXT_HOOK_EX: hhk={:#x}, code={}, wparam={:#x}, lparam={:#x}",
    //         _hhk, code, wparam, lparam
    //     );

    // Hook chain: return 0 (no hooks registered).
    0
}

/// NtUserRegisterClass - Register window class
pub extern "C" fn nt_user_register_class(frame: &SyscallFrame) -> u64 {
    let wndclassexw_ptr = unsafe { get_arg0(frame) };
    let _ = &wndclassexw_ptr;
    let name_ptr = unsafe { get_arg1(frame) };
    let _ = &name_ptr;
    let instance = unsafe { get_arg2(frame) };
    let _ = &instance;
    let extra_bytes = unsafe { get_arg3(frame) };
    let _ = &extra_bytes;

    // kprintln!("[win32k] NtUserRegisterClass: wndclass=0x{:x}, name=0x{:x}, instance=0x{:x}",
    //               wndclassexw_ptr, name_ptr, instance);

    // Return ATOM value (non-zero for success)
    // A full implementation would:
    // 1. read WNDCLASSEX structure from user memory
    // 2. create internal WNDCLASS structure
    // 3. Add to global class table
    // 4. Return atom
    if wndclassexw_ptr != 0 {
        0xC000 | (1u16 as u64) // Return a non-zero value to indicate success
    } else {
        0
    }
}

/// NT_USER_UNREGISTER_CLASS - Unregister window class
pub extern "C" fn nt_user_unregister_class(frame: &SyscallFrame) -> u64 {
    let name_ptr = unsafe { get_arg0(frame) };
    let _ = &name_ptr;
    let instance = unsafe { get_arg1(frame) };
    let _ = &instance;
    let extra_bytes = unsafe { get_arg2(frame) };
    let _ = &extra_bytes;

    // kprintln!("[win32k] NT_USER_UNREGISTER_CLASS: name=0x{:x}, instance=0x{:x}",
    //               name_ptr, instance);

    // Return TRUE if successful
    1
}

/// NT_USER_GET_CLASS_NAME - Get window class name
pub extern "C" fn nt_user_get_class_name(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let buffer_ptr = unsafe { get_arg1(frame) };
    let _ = &buffer_ptr;
    let buffer_size = unsafe { get_arg2(frame) } as i32;
    let _ = &buffer_size;

    // kprintln!("[win32k] NT_USER_GET_CLASS_NAME: hwnd=0x{:x}, buffer=0x{:x}, size={}",
    //               hwnd, buffer_ptr, buffer_size);

    // Return 0 (failure) if buffer pointer is null
    // A full implementation would get class name from window
    if buffer_ptr == 0 || buffer_size == 0 {
        return 0;
    }

    // Return the number of characters copied
    0
}

/// NT_USER_GET_PROP - Get window property
pub extern "C" fn nt_user_get_prop(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let s = unsafe { get_arg1(frame) };
    let _ = &s;

    // kprintln!("[win32k] NT_USER_GET_PROP");

    // GetProp: return 0 (no property stored).
    0
}

/// NT_USER_SET_PROP - Set window property
pub extern "C" fn nt_user_set_prop(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let s = unsafe { get_arg1(frame) };
    let _ = &s;
    let data = unsafe { get_arg2(frame) };
    let _ = &data;

    // kprintln!("[win32k] NT_USER_SET_PROP");

    // SetProp: return TRUE (property stored).
    1
}

/// NT_USER_REDRAW_WINDOW - Redraw window
pub extern "C" fn nt_user_redraw_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;
    let hrgn_update = unsafe { get_arg2(frame) };
    let _ = &hrgn_update;
    let flags = unsafe { get_arg3(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_REDRAW_WINDOW");

    let rect = if rect != 0 {
        match crate::mm::user_copy::read_user_object::<crate::libs::win32k::objects::Rect>(rect) {
            Ok(rect) => Some(rect),
            Err(_) => return 0,
        }
    } else {
        None
    };
    crate::libs::win32k::paint::redraw_window(hwnd, rect, hrgn_update, flags as u32) as u64
}

/// NT_USER_VALIDATE_RECT - Validate rectangle
pub extern "C" fn nt_user_validate_rect(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;

    // kprintln!("[win32k] NT_USER_VALIDATE_RECT");

    let rect = if rect != 0 {
        match crate::mm::user_copy::read_user_object::<crate::libs::win32k::objects::Rect>(rect) {
            Ok(rect) => Some(rect),
            Err(_) => return 0,
        }
    } else {
        None
    };
    crate::libs::win32k::paint::validate_rect(hwnd, rect) as u64
}

/// NtUserValidateRgn - Validate region
pub extern "C" fn nt_user_validate_rgn(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NtUserValidateRgn");
    1 // TRUE
}

/// NT_USER_GET_UPDATE_RECT - Get update rectangle
pub extern "C" fn nt_user_get_update_rect(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(frame) };
    let _ = &rect;
    let erase = unsafe { get_arg2(frame) };
    let _ = &erase;

    // kprintln!("[win32k] NT_USER_GET_UPDATE_RECT");

    // GetUpdateRect: return 0 (no update rect pending).
    0
}

/// NT_USER_GET_UPDATE_RGN - Get update region
pub extern "C" fn nt_user_get_update_rgn(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_UPDATE_RGN");
    0
}

/// NT_USER_CREATE_CARET - create caret
pub extern "C" fn nt_user_create_caret(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let bitmap = unsafe { get_arg1(frame) };
    let _ = &bitmap;
    let width = unsafe { get_arg2(frame) };
    let _ = &width;
    let height = unsafe { get_arg3(frame) };
    let _ = &height;

    // kprintln!("[win32k] NT_USER_CREATE_CARET");

    if crate::libs::win32k::user_state::create_caret(crate::libs::win32k::user_state::Caret {
        hwnd,
        bitmap,
        width: width as i32,
        height: height as i32,
        visible: false,
    }) {
        1
    } else {
        0
    }
}

/// NT_USER_SHOW_CARET - Show caret
pub extern "C" fn nt_user_show_caret(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SHOW_CARET");

    crate::libs::win32k::user_state::show_caret(hwnd, true) as u64
}

/// NT_USER_HIDE_CARET - Hide caret
pub extern "C" fn nt_user_hide_caret(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_HIDE_CARET");

    crate::libs::win32k::user_state::show_caret(hwnd, false) as u64
}

/// NT_USER_END_DEFER_WINDOW_POS_EX - End defer window position (extended)
pub extern "C" fn nt_user_end_defer_window_pos_ex(frame: &SyscallFrame) -> u64 {
    let h_wnd_pos_info = unsafe { get_arg0(frame) };
    let _ = &h_wnd_pos_info;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_END_DEFER_WINDOW_POS_EX");

    if crate::libs::win32k::user_state::end_deferred_positions(h_wnd_pos_info, flags as u32) {
        1
    } else {
        0
    }
}

/// NT_USER_DEFER_WINDOW_POS - Defer window position
pub extern "C" fn nt_user_defer_window_pos(frame: &SyscallFrame) -> u64 {
    let h_wnd_pos_info = unsafe { get_arg0(frame) };
    let _ = &h_wnd_pos_info;
    let hwnd = unsafe { get_arg1(frame) };
    let _ = &hwnd;
    let hwnd_insert_after = unsafe { get_arg2(frame) };
    let _ = &hwnd_insert_after;
    let x = unsafe { get_arg3(frame) };
    let _ = &x;
    let y = unsafe { get_arg4(frame) };
    let _ = &y;
    let cx = unsafe { get_arg5(frame) };
    let _ = &cx;
    let cy = unsafe { get_arg6(frame) };
    let _ = &cy;
    let flags = unsafe { get_arg7(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_DEFER_WINDOW_POS");

    let position = crate::libs::win32k::user_state::DeferredWindowPosition {
        hwnd,
        insert_after: hwnd_insert_after,
        x: x as i32,
        y: y as i32,
        width: cx as i32,
        height: cy as i32,
        flags: flags as u32,
    };
    crate::libs::win32k::user_state::defer_window_position(h_wnd_pos_info, position).unwrap_or(0)
}

/// NT_USER_REGISTER_WINDOW_MESSAGE - Register window message
pub extern "C" fn nt_user_register_window_message(frame: &SyscallFrame) -> u64 {
    let s = unsafe { get_arg0(frame) };
    let _ = &s;

    // kprintln!("[win32k] NT_USER_REGISTER_WINDOW_MESSAGE");

    // RegisterWindowMessage: return a unique message ID (0xC000+).
    0xC000
}

/// NT_USER_SEND_MESSAGE - Send message to window
pub extern "C" fn nt_user_send_message(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(frame) } as u32;
    let _ = &msg;
    let w_param = unsafe { get_arg2(frame) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(frame) };
    let _ = &l_param;

    // kprintln!("[win32k] NT_USER_SEND_MESSAGE: hwnd=0x{:x}, msg={:#x}, wparam=0x{:x}, lparam=0x{:x}",
    //         hwnd, msg, w_param, l_param);

    // For WmQuit, return 0
    if msg == 0x0012 {
        return 0;
    }

    // Call the default window procedure for the window
    let result = crate::libs::win32k::message::default_wndproc(hwnd, msg, w_param, l_param as i64);
    let _ = &result;

    // kprintln!("[win32k] NT_USER_SEND_MESSAGE: result=0x{:x}", result as u64);
    result as u64
}

/// NT_USER_POST_THREAD_MESSAGE - Post thread message
pub extern "C" fn nt_user_post_thread_message(frame: &SyscallFrame) -> u64 {
    let id_thread = unsafe { get_arg0(frame) };
    let _ = &id_thread;
    let msg = unsafe { get_arg1(frame) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(frame) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(frame) };
    let _ = &l_param;

    // kprintln!("[win32k] NT_USER_POST_THREAD_MESSAGE");

    if crate::libs::win32k::user_state::post_thread_message(
        id_thread as u32,
        crate::libs::win32k::user_state::ThreadMessage {
            message: msg as u32,
            wparam: w_param,
            lparam: l_param as i64,
        },
    ) {
        1
    } else {
        0
    }
}

/// NT_USER_REPLY_MESSAGE - Reply to GetMessage
pub extern "C" fn nt_user_reply_message(frame: &SyscallFrame) -> u64 {
    let result = unsafe { get_arg0(frame) };
    let _ = &result;

    // kprintln!("[win32k] NT_USER_REPLY_MESSAGE");

    // ReplyMessage: return TRUE.
    1
}

/// NT_USER_WINDOW_FROM_POINT - Get window from point
pub extern "C" fn nt_user_window_from_point(frame: &SyscallFrame) -> u64 {
    let x = unsafe { get_arg0(frame) };
    let _ = &x;
    let y = unsafe { get_arg1(frame) };
    let _ = &y;

    // kprintln!("[win32k] NT_USER_WINDOW_FROM_POINT");

    // WindowFromPoint: return 0 (no window at the given point).
    0
}

/// NT_USER_FIND_WINDOW_EX - Find window (extended)
pub extern "C" fn nt_user_find_window_ex(frame: &SyscallFrame) -> u64 {
    let hwnd_parent = unsafe { get_arg0(frame) };
    let _ = &hwnd_parent;
    let hwnd_child_after = unsafe { get_arg1(frame) };
    let _ = &hwnd_child_after;
    let class_name = unsafe { get_arg2(frame) };
    let _ = &class_name;
    let window_name = unsafe { get_arg3(frame) };
    let _ = &window_name;
    let flags = unsafe { get_arg4(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_FIND_WINDOW_EX");

    // FindWindowEx: return 0 (no matching window).
    0
}

/// NtUserFindWindow - Find window
pub extern "C" fn nt_user_find_window(frame: &SyscallFrame) -> u64 {
    let class_name = unsafe { get_arg0(frame) };
    let _ = &class_name;
    let window_name = unsafe { get_arg1(frame) };
    let _ = &window_name;

    // kprintln!("[win32k] NtUserFindWindow");

    // FindWindow: return 0 (no matching window).
    0
}

/// NT_USER_SET_PARENT - Set parent window
pub extern "C" fn nt_user_set_parent(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hwnd_new_parent = unsafe { get_arg1(frame) };
    let _ = &hwnd_new_parent;

    // kprintln!("[win32k] NT_USER_SET_PARENT: hwnd=0x{:x}, new_parent=0x{:x}",
    //         hwnd, hwnd_new_parent);

    // For now, return the old parent (0)
    // Full implementation would modify window's parent
    0
}

/// NT_USER_GET_ACTIVE_WINDOW - Get active window
pub extern "C" fn nt_user_get_active_window(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_ACTIVE_WINDOW");

    // Return the current active window handle
    crate::libs::win32k::window::get_active_window_internal()
}

/// NT_USER_SET_ACTIVE_WINDOW - Set active window
pub extern "C" fn nt_user_set_active_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SET_ACTIVE_WINDOW");

    // SetActiveWindow: return the previous active window (0 = none).
    0
}

/// NtUserGetFocus - Get focus window
pub extern "C" fn nt_user_get_focus(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetFocus");

    // Return the current focus window handle
    crate::libs::win32k::window::get_focus_internal()
}

/// NT_USER_RELEASE_CAPTURE - Release capture
pub extern "C" fn nt_user_release_capture(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_RELEASE_CAPTURE");

    crate::libs::win32k::window::release_capture_internal();
    1
}

/// NT_USER_SET_WINDOW_LONG - Set window long
pub extern "C" fn nt_user_set_window_long(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let new_long = unsafe { get_arg2(frame) };
    let _ = &new_long;

    // kprintln!("[win32k] NT_USER_SET_WINDOW_LONG");

    // SetWindowLong: return the previous value (0 = none).
    0
}

/// NT_USER_GET_CONTROL_BRUSH - Get control brush
pub extern "C" fn nt_user_get_control_brush(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let color = unsafe { get_arg1(frame) };
    let _ = &color;
    let r#type = unsafe { get_arg2(frame) };
    let _ = &r#type;

    // kprintln!("[win32k] NT_USER_GET_CONTROL_BRUSH");

    // GetControlBrush: return 0 (no control brush).
    0
}

/// NT_USER_DRAW_ICON_EX - Draw icon extended
pub extern "C" fn nt_user_draw_icon_ex(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_DRAW_ICON_EX");
    1 // TRUE
}

/// NT_USER_GET_SYSTEM_MENU - Get system menu
pub extern "C" fn nt_user_get_system_menu(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let revert = unsafe { get_arg1(frame) };
    let _ = &revert;

    // kprintln!("[win32k] NT_USER_GET_SYSTEM_MENU");

    // GetSystemMenu: return 0 (no system menu).
    0
}

/// NT_USER_INTERNAL_GET_WINDOW_TEXT - internal get window text
pub extern "C" fn nt_user_internal_get_window_text(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_INTERNAL_GET_WINDOW_TEXT");
    0
}

/// NT_USER_GET_WINDOW_DC - Get window DC
pub extern "C" fn nt_user_get_window_dc(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_GET_WINDOW_DC");

    // GetWindowDC: return a pseudo-DC handle.
    0x000D_0001
}

/// NT_USER_SCROLL_DC - Scroll DC
pub extern "C" fn nt_user_scroll_dc(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let dx = unsafe { get_arg1(frame) };
    let _ = &dx;
    let dy = unsafe { get_arg2(frame) };
    let _ = &dy;
    let scroll_rect = unsafe { get_arg3(frame) };
    let _ = &scroll_rect;
    let clip_rect = unsafe { get_arg4(frame) };
    let _ = &clip_rect;
    let hrgn_update = unsafe { get_arg5(frame) };
    let _ = &hrgn_update;
    let prgn_update = unsafe { get_arg6(frame) };
    let _ = &prgn_update;

    // kprintln!("[win32k] NT_USER_SCROLL_DC");

    // ScrollDC: return TRUE.
    1
}

/// NT_USER_GET_OBJECT_INFORMATION - Get object information
pub extern "C" fn nt_user_get_object_information(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_OBJECT_INFORMATION");
    0
}

/// NT_USER_UNHOOK_WINDOWS_HOOK_EX - Unhook windows hook (extended) (P2 Enhancement)
pub extern "C" fn nt_user_unhook_windows_hook_ex(frame: &SyscallFrame) -> u64 {
    let hhk = unsafe { get_arg0(frame) };
    let _ = &hhk;

    // kprintln!("[win32k] NT_USER_UNHOOK_WINDOWS_HOOK_EX: hhk={:#x}", hhk);

    if hhk == 0 {
        return 0;
    }

    if win32k_helpers::remove_hook(hhk) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_NOTIFY_PROCESS_CREATE - Notify process create
pub extern "C" fn nt_user_notify_process_create(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_NOTIFY_PROCESS_CREATE");
    0
}

/// NT_USER_GET_TITLE_BAR_INFO - Get title bar info
pub extern "C" fn nt_user_get_title_bar_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_TITLE_BAR_INFO");
    0
}

/// NT_USER_SET_THREAD_DESKTOP - Set thread desktop
pub extern "C" fn nt_user_set_thread_desktop(frame: &SyscallFrame) -> u64 {
    let h_desk = unsafe { get_arg0(frame) };
    let _ = &h_desk;

    // kprintln!("[win32k] NT_USER_SET_THREAD_DESKTOP");

    // SetThreadDesktop: return TRUE (desktop switch succeeds).
    1
}

/// NT_USER_GET_SCROLL_BAR_INFO - Get scroll bar info
pub extern "C" fn nt_user_get_scroll_bar_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_SCROLL_BAR_INFO");
    0
}

/// NT_USER_SET_WINDOW_FNID - Set window FNID
pub extern "C" fn nt_user_set_window_fnid(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SET_WINDOW_FNID");
    0
}

/// NT_USER_CALC_MENU_BAR - Calculate menu bar
pub extern "C" fn nt_user_calc_menu_bar(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let x = unsafe { get_arg1(frame) };
    let _ = &x;
    let y = unsafe { get_arg2(frame) };
    let _ = &y;
    let flags = unsafe { get_arg3(frame) };
    let _ = &flags;
    let p_rect = unsafe { get_arg4(frame) };
    let _ = &p_rect;

    // kprintln!("[win32k] NT_USER_CALC_MENU_BAR");

    // CalcMenuBar: return 0 (no menu bar height computed).
    0
}

/// NT_USER_THUNKED_MENU_ITEM_INFO - Thunked menu item info
pub extern "C" fn nt_user_thunked_menu_item_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_THUNKED_MENU_ITEM_INFO");
    0
}

/// NT_USER_OPEN_WINDOW_STATION - Open window station
pub extern "C" fn nt_user_open_window_station(frame: &SyscallFrame) -> u64 {
    let s = unsafe { get_arg0(frame) };
    let _ = &s;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_OPEN_WINDOW_STATION");

    // OpenWindowStation: return a pseudo-handle.
    0x000E_0001
}

/// NT_USER_CLOSE_DESKTOP - close desktop
pub extern "C" fn nt_user_close_desktop(frame: &SyscallFrame) -> u64 {
    let h_desk = unsafe { get_arg0(frame) };
    let _ = &h_desk;

    // kprintln!("[win32k] NT_USER_CLOSE_DESKTOP");

    // CloseDesktop: return TRUE.
    1
}

/// NT_USER_OPEN_DESKTOP - Open desktop
pub extern "C" fn nt_user_open_desktop(frame: &SyscallFrame) -> u64 {
    let s = unsafe { get_arg0(frame) };
    let _ = &s;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;
    let access = unsafe { get_arg2(frame) };
    let _ = &access;
    let valid_apps = unsafe { get_arg3(frame) };
    let _ = &valid_apps;

    // kprintln!("[win32k] NT_USER_OPEN_DESKTOP");

    // OpenDesktop: return a pseudo-handle.
    0x000F_0001
}

/// NT_USER_SET_PROCESS_WINDOW_STATION - Set process window station
pub extern "C" fn nt_user_set_process_window_station(frame: &SyscallFrame) -> u64 {
    let h_win_sta = unsafe { get_arg0(frame) };
    let _ = &h_win_sta;

    // kprintln!("[win32k] NT_USER_SET_PROCESS_WINDOW_STATION");

    // SetProcessWindowStation: return TRUE.
    1
}

/// NT_USER_GET_ATOM_NAME - Get atom name
pub extern "C" fn nt_user_get_atom_name(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_ATOM_NAME");
    0
}

/// NT_USER_SET_CURSOR_ICON_DATA - Set cursor icon data
pub extern "C" fn nt_user_set_cursor_icon_data(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SET_CURSOR_ICON_DATA");
    0
}

/// NT_USER_REGISTER_CLASS_EX_WOW - Register class (extended WOW)
pub extern "C" fn nt_user_register_class_ex_wow(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_REGISTER_CLASS_EX_WOW");
    0
}

/// NT_USER_GET_ANCESTOR - Get ancestor window
pub extern "C" fn nt_user_get_ancestor(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let ga_flags = unsafe { get_arg1(frame) };
    let _ = &ga_flags;

    // kprintln!("[win32k] NT_USER_GET_ANCESTOR");

    // GetAncestor: return 0 (no ancestor without a window tree).
    0
}

/// NT_USER_CLOSE_WINDOW_STATION - close window station
pub extern "C" fn nt_user_close_window_station(frame: &SyscallFrame) -> u64 {
    let h_win_sta = unsafe { get_arg0(frame) };
    let _ = &h_win_sta;

    // kprintln!("[win32k] NT_USER_CLOSE_WINDOW_STATION");

    // CloseWindowStation: return TRUE.
    1
}

/// NT_USER_GET_DOUBLE_CLICK_TIME - Get double click time
pub extern "C" fn nt_user_get_double_click_time(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_DOUBLE_CLICK_TIME");

    crate::libs::win32k::user_state::double_click_time() as u64
}

/// NT_USER_ENABLE_SCROLL_BAR - Enable scroll bar
pub extern "C" fn nt_user_enable_scroll_bar(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_ENABLE_SCROLL_BAR");
    0
}

/// NT_USER_GET_CLASS_INFO_EX - Get class info (extended)
pub extern "C" fn nt_user_get_class_info_ex(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_CLASS_INFO_EX");
    0
}

/// NT_USER_DELETE_MENU - Delete menu item (P2 Enhancement)
pub extern "C" fn nt_user_delete_menu(frame: &SyscallFrame) -> u64 {
    let h_menu = unsafe { get_arg0(frame) };
    let _ = &h_menu;
    let u_position = unsafe { get_arg1(frame) };
    let _ = &u_position;
    let u_flags = unsafe { get_arg2(frame) };
    let _ = &u_flags;

    // kprintln!("[win32k] NT_USER_DELETE_MENU: hmenu={:#x}, pos={}, flags={:#x}",
    //               _h_menu, _u_position, _u_flags);

    crate::libs::win32k::user_state::delete_menu_item(h_menu, u_position as u32, u_flags as u32)
        as u64
}

/// NT_USER_SCROLL_WINDOW_EX - Scroll window (extended)
pub extern "C" fn nt_user_scroll_window_ex(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SCROLL_WINDOW_EX");
    0
}

/// NT_USER_SET_CLASS_LONG - Set class long
pub extern "C" fn nt_user_set_class_long(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let new_long = unsafe { get_arg2(frame) };
    let _ = &new_long;
    let dw_extra = unsafe { get_arg3(frame) };
    let _ = &dw_extra;

    // kprintln!("[win32k] NT_USER_SET_CLASS_LONG");

    // SetClassLong: return the previous value (0 = none).
    0
}

/// NT_USER_GET_MENU_BAR_INFO - Get menu bar info
pub extern "C" fn nt_user_get_menu_bar_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_MENU_BAR_INFO");
    0
}

/// NT_USER_GET_CLIPBOARD_SEQUENCE_NUMBER - Get clipboard sequence number
pub extern "C" fn nt_user_get_clipboard_sequence_number(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_CLIPBOARD_SEQUENCE_NUMBER");

    // GetClipboardSequenceNumber: report the real mutation counter kept
    // by the clipboard manager instead of a fixed constant.
    crate::libs::win32k::clipboard::get_sequence_number()
}

/// NT_USER_GET_KEYBOARD_LAYOUT_LIST - Get keyboard layout list
pub extern "C" fn nt_user_get_keyboard_layout_list(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_KEYBOARD_LAYOUT_LIST");
    0
}

/// NT_USER_MAP_VIRTUAL_KEY_EX - Map virtual key (extended)
pub extern "C" fn nt_user_map_virtual_key_ex(frame: &SyscallFrame) -> u64 {
    let code = unsafe { get_arg0(frame) };
    let _ = &code;
    let map_type = unsafe { get_arg1(frame) };
    let _ = &map_type;
    let hkl = unsafe { get_arg2(frame) };
    let _ = &hkl;

    // kprintln!("[win32k] NT_USER_MAP_VIRTUAL_KEY_EX");

    // MapVirtualKeyEx: return the virtual key code as-is.
    code
}

/// NT_USER_TO_UNICODE_EX - Convert to unicode (extended)
pub extern "C" fn nt_user_to_unicode_ex(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_TO_UNICODE_EX");
    0
}

/// NT_USER_DEF_SET_TEXT - Default set text
pub extern "C" fn nt_user_def_set_text(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_DEF_SET_TEXT");
    0
}

/// NT_USER_GET_THREAD_DESKTOP - Get thread desktop
pub extern "C" fn nt_user_get_thread_desktop(frame: &SyscallFrame) -> u64 {
    let thread_id = unsafe { get_arg0(frame) };
    let _ = &thread_id;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_GET_THREAD_DESKTOP");

    // GetThreadDesktop: return a pseudo-handle for the default desktop.
    0x0010_0001
}

/// NT_USER_GET_ICON_SIZE - Get icon size
pub extern "C" fn nt_user_get_icon_size(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let r#type = unsafe { get_arg1(frame) };
    let _ = &r#type;
    let cx = unsafe { get_arg2(frame) };
    let _ = &cx;
    let cy = unsafe { get_arg3(frame) };
    let _ = &cy;

    // kprintln!("[win32k] NT_USER_GET_ICON_SIZE");

    // GetIconSize: return 32x32 (SM_ICON default).
    (32 << 16) | 32
}

/// NT_USER_FILL_WINDOW - Fill window
pub extern "C" fn nt_user_fill_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let h_dc = unsafe { get_arg1(frame) };
    let _ = &h_dc;
    let brush = unsafe { get_arg2(frame) };
    let _ = &brush;
    let result = unsafe { get_arg3(frame) };
    let _ = &result;

    // kprintln!("[win32k] NT_USER_FILL_WINDOW");

    // FillWindow: return TRUE.
    1
}

/// NT_USER_SET_WINDOWS_HOOK_EX - Set windows hook (extended) (P2 Enhancement)
pub extern "C" fn nt_user_set_windows_hook_ex(frame: &SyscallFrame) -> u64 {
    let id_hook = unsafe { get_arg0(frame) } as i32;
    let _ = &id_hook;
    let lpfn = unsafe { get_arg1(frame) };
    let _ = &lpfn;
    let mod_name = unsafe { get_arg2(frame) };
    let _ = &mod_name;
    let thread_id = unsafe { get_arg3(frame) } as u32;
    let _ = &thread_id;

    // kprintln!(
    //         "[win32k] NT_USER_SET_WINDOWS_HOOK_EX: type={}, proc={:#x}, thread_id={}",
    //         id_hook, lpfn, thread_id
    //     );

    // Install the hook using the hook system
    match win32k_helpers::install_hook(id_hook, lpfn, thread_id) {
        Some(handle) => handle,
        None => 0,
    }
}

/// NT_USER_EXCLUDE_UPDATE_RGN - Exclude update region
pub extern "C" fn nt_user_exclude_update_rgn(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let hwnd = unsafe { get_arg1(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_EXCLUDE_UPDATE_RGN");

    // ExcludeUpdateRgn: return 1 (SIMPLEREGION).
    1
}

/// NT_USER_CALL_HWND_PARAM - Call with hwnd and param
pub extern "C" fn nt_user_call_hwnd_param(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CALL_HWND_PARAM");
    0
}

/// NT_USER_GET_ICON_INFO - Get icon info
pub extern "C" fn nt_user_get_icon_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_ICON_INFO");
    0
}

/// NT_USER_SBGET_PARMS - Get scroll bar parameters
pub extern "C" fn nt_user_sb_get_parms(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SBGET_PARMS");
    0
}

/// NT_USER_DESTROY_CURSOR - Destroy cursor
pub extern "C" fn nt_user_destroy_cursor(frame: &SyscallFrame) -> u64 {
    let hcur = unsafe { get_arg0(frame) };
    let _ = &hcur;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_DESTROY_CURSOR");

    crate::libs::win32k::user_state::destroy_cursor(hcur) as u64
}

/// NT_USER_MESSAGE_CALL - Message call
pub extern "C" fn nt_user_message_call(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(frame) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(frame) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(frame) };
    let _ = &l_param;
    let msg_fu_flags = unsafe { get_arg4(frame) };
    let _ = &msg_fu_flags;
    let info = unsafe { get_arg5(frame) };
    let _ = &info;

    // kprintln!("[win32k] NT_USER_MESSAGE_CALL");

    // MessageCall: return 0 (no message dispatched).
    0
}

/// NT_USER_END_MENU - End menu
pub extern "C" fn nt_user_end_menu(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_END_MENU");

    crate::libs::win32k::user_state::end_menu() as u64
}

/// NT_USER_QUERY_WINDOW - Query window info
pub extern "C" fn nt_user_query_window(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let cmd = unsafe { get_arg1(frame) };
    let _ = &cmd;

    // kprintln!("[win32k] NT_USER_QUERY_WINDOW");

    // QueryWindow: return 0 (no window info available).
    0
}

/// NT_USER_TRANSLATE_ACCELERATOR - Translate accelerator
pub extern "C" fn nt_user_translate_accelerator(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_TRANSLATE_ACCELERATOR");
    0
}

/// NT_USER_VALIDATE_TIMER_CALLBACK - Validate timer callback
pub extern "C" fn nt_user_validate_timer_callback(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_VALIDATE_TIMER_CALLBACK");
    0
}

/// NT_USER_BEGIN_PAINT - Begin paint
pub extern "C" fn nt_user_begin_paint(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let paint = unsafe { get_arg1(frame) };
    let _ = &paint;

    // kprintln!("[win32k] NT_USER_BEGIN_PAINT");

    // BeginPaint: return a pseudo-DC handle.
    0x0011_0001
}

/// NT_USER_END_PAINT - End paint
pub extern "C" fn nt_user_end_paint(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let paint = unsafe { get_arg1(frame) };
    let _ = &paint;

    // kprintln!("[win32k] NT_USER_END_PAINT");

    crate::libs::win32k::paint::end_paint(hwnd, paint) as u64
}

/// NT_USER_BUILD_HWND_LIST - Build window list
pub extern "C" fn nt_user_build_hwnd_list(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_BUILD_HWND_LIST");
    0
}

/// NT_USER_BUILD_NAME_LIST - Build window name list
pub extern "C" fn nt_user_build_name_list(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let names_ptr = unsafe { get_arg1(frame) };
    let _ = &names_ptr;
    let max_count = unsafe { get_arg2(frame) };
    let _ = &max_count;

    // kprintln!("[win32k] NT_USER_BUILD_NAME_LIST: hwnd=0x{:x}, names=0x{:x}, max={}", hwnd, names_ptr, max_count);

    // BuildNameList: return 0 (no name list built).
    0
}

/// NT_USER_CALL_HWND_LOCK - Call with hwnd lock
pub extern "C" fn nt_user_call_hwnd_lock(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CALL_HWND_LOCK");
    0
}

/// NT_USER_GET_PROCESS_WINDOW_STATION - Get process window station
pub extern "C" fn nt_user_get_process_window_station(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_PROCESS_WINDOW_STATION");

    // GetProcessWindowStation: return a pseudo-handle.
    0x0012_0001
}

/// NT_USER_CALL_HWND_PARAM_LOCK - Call with hwnd and param lock
pub extern "C" fn nt_user_call_hwnd_param_lock(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CALL_HWND_PARAM_LOCK");
    0
}

/// NT_USER_VK_KEY_SCAN_EX - Virtual key scan (extended)
pub extern "C" fn nt_user_vk_key_scan_ex(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_VK_KEY_SCAN_EX");
    0
}

/// NT_USER_COPY_ACCELERATOR_TABLE - Copy accelerator table
pub extern "C" fn nt_user_copy_accelerator_table(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_COPY_ACCELERATOR_TABLE");
    0
}

/// NT_USER_NOTIFY_WIN_EVENT - Notify win event
pub extern "C" fn nt_user_notify_win_event(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_NOTIFY_WIN_EVENT");
    0
}

/// NT_USER_IS_CLIPBOARD_FORMAT_AVAILABLE - Check clipboard format
pub extern "C" fn nt_user_is_clipboard_format_available(frame: &SyscallFrame) -> u64 {
    let format = unsafe { get_arg0(frame) };
    let _ = &format;

    // kprintln!("[win32k] NT_USER_IS_CLIPBOARD_FORMAT_AVAILABLE");

    // IsClipboardFormatAvailable: return 1 (text format available).
    1
}

/// NT_USER_SET_SCROLL_INFO - Set scroll info
pub extern "C" fn nt_user_set_scroll_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SET_SCROLL_INFO");
    0
}

/// NT_USER_SELECT_PALETTE - Select palette
pub extern "C" fn nt_user_select_palette(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SELECT_PALETTE");
    0
}

/// NT_USER_REMOVE_PROP - Remove property
pub extern "C" fn nt_user_remove_prop(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_REMOVE_PROP");
    0
}

/// NT_USER_REGISTER_HOT_KEY - Register hot key
pub extern "C" fn nt_user_register_hot_key(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let id = unsafe { get_arg1(frame) };
    let _ = &id;
    let fs_modifiers = unsafe { get_arg2(frame) };
    let _ = &fs_modifiers;
    let vk = unsafe { get_arg3(frame) };
    let _ = &vk;

    // kprintln!("[win32k] NT_USER_REGISTER_HOT_KEY");

    if crate::libs::win32k::user_state::register_hot_key(crate::libs::win32k::user_state::HotKey {
        hwnd,
        id: id as u32,
        modifiers: fs_modifiers as u32,
        virtual_key: vk as u32,
    }) {
        1
    } else {
        0
    }
}

/// NT_USER_UNREGISTER_HOT_KEY - Unregister hot key
pub extern "C" fn nt_user_unregister_hot_key(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let id = unsafe { get_arg1(frame) };
    let _ = &id;

    // kprintln!("[win32k] NT_USER_UNREGISTER_HOT_KEY");

    crate::libs::win32k::user_state::unregister_hot_key(hwnd, id as u32) as u64
}

/// NT_USER_GET_CURSOR_INFO - Get cursor info
pub extern "C" fn nt_user_get_cursor_info(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_CURSOR_INFO");
    0
}

/// NT_USER_SHOW_SCROLL_BAR - Show scroll bar
pub extern "C" fn nt_user_show_scroll_bar(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_SHOW_SCROLL_BAR");
    1 // TRUE
}

/// NT_USER_FIND_EXISTING_CURSOR_ICON - Find existing cursor icon
pub extern "C" fn nt_user_find_existing_cursor_icon(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_FIND_EXISTING_CURSOR_ICON");
    0
}

/// NtUserGetKeyboardType - Get keyboard type
pub extern "C" fn nt_user_get_keyboard_type(frame: &SyscallFrame) -> u64 {
    let type_flag = unsafe { get_arg0(frame) };
    let _ = &type_flag;

    // kprintln!("[win32k] NtUserGetKeyboardType");

    match type_flag as i32 {
        0 => 4,  // KEYBOARD_TYPE_GENERIC
        1 => 1,  // KEYBOARD_TYPE_I8042
        2 => 12, // Number of function keys
        _ => 0,
    }
}

// =============================================================================
// Additional USER Syscall Handlers
// =============================================================================

/// NT_USER_BIT_BLT_SYS_BMP - bit_blt to system bitmap
pub extern "C" fn nt_user_bit_blt_sys_bmp(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg1(frame) };
    let _ = &x;
    let y = unsafe { get_arg2(frame) };
    let _ = &y;
    let cx = unsafe { get_arg3(frame) };
    let _ = &cx;
    let cy = unsafe { get_arg4(frame) };
    let _ = &cy;
    let rop = unsafe { get_arg5(frame) };
    let _ = &rop;

    // kprintln!("[win32k] NT_USER_BIT_BLT_SYS_BMP");
    1 // TRUE
}

/// NT_USER_INVALIDATE_RGN - Invalidate region
pub extern "C" fn nt_user_invalidate_rgn(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hrgn = unsafe { get_arg1(frame) };
    let _ = &hrgn;
    let erase = unsafe { get_arg2(frame) };
    let _ = &erase;

    // kprintln!("[win32k] NT_USER_INVALIDATE_RGN");
    1 // TRUE
}

/// NT_USER_GET_CLIPBOARD_OWNER - Get clipboard owner window
pub extern "C" fn nt_user_get_clipboard_owner(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_CLIPBOARD_OWNER");
    0 // NULL
}

/// NT_USER_SET_WINDOW_RGN - Set window region
pub extern "C" fn nt_user_set_window_rgn(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hrgn = unsafe { get_arg1(frame) };
    let _ = &hrgn;
    let redraw = unsafe { get_arg2(frame) };
    let _ = &redraw;

    // kprintln!("[win32k] NT_USER_SET_WINDOW_RGN");
    1 // TRUE
}

/// NT_USER_OPEN_CLIPBOARD - Open clipboard
pub extern "C" fn nt_user_open_clipboard(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_OPEN_CLIPBOARD: hwnd=0x{:x}", hwnd);

    if crate::libs::win32k::clipboard::open_clipboard(hwnd) {
        1 // TRUE
    } else {
        0 // FALSE - already open
    }
}

/// NT_USER_CLOSE_CLIPBOARD - close clipboard
pub extern "C" fn nt_user_close_clipboard(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_CLOSE_CLIPBOARD");

    if crate::libs::win32k::clipboard::close_clipboard() {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_EMPTY_CLIPBOARD - Empty clipboard
pub extern "C" fn nt_user_empty_clipboard(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_EMPTY_CLIPBOARD");

    if crate::libs::win32k::clipboard::empty_clipboard() {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NT_USER_SET_CLIPBOARD_DATA - Set clipboard data
pub extern "C" fn nt_user_set_clipboard_data(frame: &SyscallFrame) -> u64 {
    let format = unsafe { get_arg0(frame) };
    let _ = &format;
    let hdata = unsafe { get_arg1(frame) };
    let _ = &hdata;

    // The user-mode clipboard ABI has no defined buffer/size encoding
    // for 'hdata' yet, so there is no safe way to copy caller data
    // into the kernel clipboard. Report failure instead of pretending
    // the object was accepted.
    0 // FALSE
}

/// NT_USER_ENABLE_MENU_ITEM - Enable/disable menu item
pub extern "C" fn nt_user_enable_menu_item(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;
    let id = unsafe { get_arg1(frame) };
    let _ = &id;
    let enable = unsafe { get_arg2(frame) };
    let _ = &enable;

    // kprintln!("[win32k] NT_USER_ENABLE_MENU_ITEM");
    0 // MF_BYCOMMAND
}

/// NT_USER_ALTER_WINDOW_STYLE - Alter window style
pub extern "C" fn nt_user_alter_window_style(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let remove = unsafe { get_arg1(frame) };
    let _ = &remove;
    let add = unsafe { get_arg2(frame) };
    let _ = &add;

    // kprintln!("[win32k] NT_USER_ALTER_WINDOW_STYLE");
    1 // TRUE
}

/// NT_USER_GET_WINDOW_PLACEMENT - Get window placement
pub extern "C" fn nt_user_get_window_placement(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let placement = unsafe { get_arg1(frame) };
    let _ = &placement;

    // kprintln!("[win32k] NT_USER_GET_WINDOW_PLACEMENT");
    1 // TRUE
}

/// NT_USER_GET_OPEN_CLIPBOARD_WINDOW - Get open clipboard window
pub extern "C" fn nt_user_get_open_clipboard_window(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_OPEN_CLIPBOARD_WINDOW");
    0 // NULL
}

/// NT_USER_SET_THREAD_STATE - Set thread state
pub extern "C" fn nt_user_set_thread_state(frame: &SyscallFrame) -> u64 {
    let state = unsafe { get_arg0(frame) };
    let _ = &state;

    // kprintln!("[win32k] NT_USER_SET_THREAD_STATE");
    0
}

/// NT_USER_TRACK_MOUSE_EVENT - Track mouse event
pub extern "C" fn nt_user_track_mouse_event(frame: &SyscallFrame) -> u64 {
    let event = unsafe { get_arg0(frame) };
    let _ = &event;

    // kprintln!("[win32k] NT_USER_TRACK_MOUSE_EVENT");
    1 // TRUE
}

/// NT_USER_DESTROY_MENU - Destroy menu
pub extern "C" fn nt_user_destroy_menu(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;

    // kprintln!("[win32k] NT_USER_DESTROY_MENU");
    crate::libs::win32k::user_state::destroy_menu(hmenu) as u64
}

/// NT_USER_CONSOLE_CONTROL - Console control
pub extern "C" fn nt_user_console_control(frame: &SyscallFrame) -> u64 {
    let code = unsafe { get_arg0(frame) };
    let _ = &code;
    let in_data = unsafe { get_arg1(frame) };
    let _ = &in_data;
    let out_data = unsafe { get_arg2(frame) };
    let _ = &out_data;

    // kprintln!("[win32k] NT_USER_CONSOLE_CONTROL");
    0
}

/// NT_USER_SET_INFORMATION_THREAD - Set thread information
pub extern "C" fn nt_user_set_information_thread(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let info_class = unsafe { get_arg1(frame) };
    let _ = &info_class;
    let info = unsafe { get_arg2(frame) };
    let _ = &info;
    let length = unsafe { get_arg3(frame) };
    let _ = &length;

    // kprintln!("[win32k] NT_USER_SET_INFORMATION_THREAD");
    1 // TRUE
}

/// NT_USER_SET_WINDOW_PLACEMENT - Set window placement
pub extern "C" fn nt_user_set_window_placement(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let placement = unsafe { get_arg1(frame) };
    let _ = &placement;

    // kprintln!("[win32k] NT_USER_SET_WINDOW_PLACEMENT");
    1 // TRUE
}

/// NT_USER_GET_CONTROL_COLOR - Get control color
pub extern "C" fn nt_user_get_control_color(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hdc = unsafe { get_arg1(frame) };
    let _ = &hdc;
    let class = unsafe { get_arg2(frame) };
    let _ = &class;

    // kprintln!("[win32k] NT_USER_GET_CONTROL_COLOR");
    0 // Default brush
}

/// NT_USER_SET_WINDOW_WORD - Set window word
pub extern "C" fn nt_user_set_window_word(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let value = unsafe { get_arg2(frame) };
    let _ = &value;

    // kprintln!("[win32k] NT_USER_SET_WINDOW_WORD");
    0
}

/// NT_USER_GET_CLIPBOARD_FORMAT_NAME - Get clipboard format name
pub extern "C" fn nt_user_get_clipboard_format_name(frame: &SyscallFrame) -> u64 {
    let format = unsafe { get_arg0(frame) };
    let _ = &format;
    let buffer = unsafe { get_arg1(frame) };
    let _ = &buffer;
    let buffer_size = unsafe { get_arg2(frame) };
    let _ = &buffer_size;

    // kprintln!("[win32k] NT_USER_GET_CLIPBOARD_FORMAT_NAME");
    0
}

/// NT_USER_REAL_INTERNAL_GET_MESSAGE - Real internal get message
pub extern "C" fn nt_user_real_internal_get_message(frame: &SyscallFrame) -> u64 {
    let msg = unsafe { get_arg0(frame) };
    let _ = &msg;
    let hwnd = unsafe { get_arg1(frame) };
    let _ = &hwnd;
    let msg_min = unsafe { get_arg2(frame) };
    let _ = &msg_min;
    let msg_max = unsafe { get_arg3(frame) };
    let _ = &msg_max;
    let flags = unsafe { get_arg4(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_REAL_INTERNAL_GET_MESSAGE");
    0
}

/// NT_USER_CREATE_LOCAL_MEM_HANDLE - create local memory handle
pub extern "C" fn nt_user_create_local_mem_handle(frame: &SyscallFrame) -> u64 {
    let addr = unsafe { get_arg0(frame) };
    let _ = &addr;
    let size = unsafe { get_arg1(frame) };
    let _ = &size;

    // kprintln!("[win32k] NT_USER_CREATE_LOCAL_MEM_HANDLE");
    0
}

/// NT_USER_ATTACH_THREAD_INPUT - Attach thread input
pub extern "C" fn nt_user_attach_thread_input(frame: &SyscallFrame) -> u64 {
    let attach_from = unsafe { get_arg0(frame) };
    let _ = &attach_from;
    let attach_to = unsafe { get_arg1(frame) };
    let _ = &attach_to;
    let attach = unsafe { get_arg2(frame) };
    let _ = &attach;

    // kprintln!("[win32k] NT_USER_ATTACH_THREAD_INPUT");
    1 // TRUE
}

/// NT_USER_PAINT_MENU_BAR - Paint menu bar
pub extern "C" fn nt_user_paint_menu_bar(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hdc = unsafe { get_arg1(frame) };
    let _ = &hdc;
    let x = unsafe { get_arg2(frame) };
    let _ = &x;
    let y = unsafe { get_arg3(frame) };
    let _ = &y;
    let cx = unsafe { get_arg4(frame) };
    let _ = &cx;
    let cy = unsafe { get_arg5(frame) };
    let _ = &cy;

    // kprintln!("[win32k] NT_USER_PAINT_MENU_BAR");
    0
}

/// NT_USER_CREATE_ACCELERATOR_TABLE - create accelerator table
pub extern "C" fn nt_user_create_accelerator_table(frame: &SyscallFrame) -> u64 {
    let table = unsafe { get_arg0(frame) };
    let _ = &table;

    // kprintln!("[win32k] NT_USER_CREATE_ACCELERATOR_TABLE");
    0 // NULL
}

/// NT_USER_GET_CURSOR_FRAME_INFO - Get cursor frame info
pub extern "C" fn nt_user_get_cursor_frame_info(frame: &SyscallFrame) -> u64 {
    let hcur = unsafe { get_arg0(frame) };
    let _ = &hcur;
    let frame = unsafe { get_arg1(frame) };
    let _ = &frame;

    // kprintln!("[win32k] NT_USER_GET_CURSOR_FRAME_INFO");
    0
}

/// NT_USER_GET_ALT_TAB_INFO - Get alt-tab info
pub extern "C" fn nt_user_get_alt_tab_info(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let info = unsafe { get_arg1(frame) };
    let _ = &info;

    // kprintln!("[win32k] NT_USER_GET_ALT_TAB_INFO");
    0
}

/// NT_USER_GET_CARET_BLINK_TIME - Get caret blink time
pub extern "C" fn nt_user_get_caret_blink_time(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_GET_CARET_BLINK_TIME");
    530 // Default blink time
}

/// NT_USER_PROCESS_CONNECT - Process connect
pub extern "C" fn nt_user_process_connect(frame: &SyscallFrame) -> u64 {
    let process = unsafe { get_arg0(frame) };
    let _ = &process;
    let conn_info = unsafe { get_arg1(frame) };
    let _ = &conn_info;
    let size = unsafe { get_arg2(frame) };
    let _ = &size;

    // kprintln!("[win32k] NT_USER_PROCESS_CONNECT");
    1 // TRUE
}

/// NT_USER_ENUM_DISPLAY_DEVICES - Enum display devices
pub extern "C" fn nt_user_enum_display_devices(frame: &SyscallFrame) -> u64 {
    let device = unsafe { get_arg0(frame) };
    let _ = &device;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let info = unsafe { get_arg2(frame) };
    let _ = &info;
    let flags = unsafe { get_arg3(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_ENUM_DISPLAY_DEVICES");
    0 // FALSE (no more devices)
}

/// NT_USER_GET_CLIPBOARD_DATA - Get clipboard data
pub extern "C" fn nt_user_get_clipboard_data(frame: &SyscallFrame) -> u64 {
    let format = unsafe { get_arg0(frame) };
    let _ = &format;

    // No user-mode clipboard ABI exists yet: there is no way to hand
    // the caller a global memory handle they can read. NULL is the
    // honest "no object" response until that ABI is designed.
    0 // NULL
}

/// NT_USER_REMOVE_MENU - Remove menu item
pub extern "C" fn nt_user_remove_menu(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;
    let pos = unsafe { get_arg1(frame) };
    let _ = &pos;
    let flags = unsafe { get_arg2(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_REMOVE_MENU");
    1 // TRUE
}

/// NT_USER_CONVERT_MEM_HANDLE - Convert memory handle
pub extern "C" fn nt_user_convert_mem_handle(frame: &SyscallFrame) -> u64 {
    let handle = unsafe { get_arg0(frame) };
    let _ = &handle;

    // kprintln!("[win32k] NT_USER_CONVERT_MEM_HANDLE");
    0
}

/// NT_USER_DESTROY_ACCELERATOR_TABLE - Destroy accelerator table
pub extern "C" fn nt_user_destroy_accelerator_table(frame: &SyscallFrame) -> u64 {
    let table = unsafe { get_arg0(frame) };
    let _ = &table;

    // kprintln!("[win32k] NT_USER_DESTROY_ACCELERATOR_TABLE");
    1 // TRUE
}

/// NT_USER_GET_GUITHREAD_INFO - Get GUI thread info
pub extern "C" fn nt_user_get_gui_thread_info(frame: &SyscallFrame) -> u64 {
    let thread_id = unsafe { get_arg0(frame) };
    let _ = &thread_id;
    let info = unsafe { get_arg1(frame) };
    let _ = &info;

    // kprintln!("[win32k] NT_USER_GET_GUITHREAD_INFO");
    0
}

/// NT_USER_SET_WINDOWS_HOOK_AW - Set windows hook ANSI/Wide (P2 Enhancement)
pub extern "C" fn nt_user_set_windows_hook_aw(frame: &SyscallFrame) -> u64 {
    let id_hook = unsafe { get_arg0(frame) } as i32;
    let _ = &id_hook;
    let lpfn = unsafe { get_arg1(frame) };
    let _ = &lpfn;
    let flags = unsafe { get_arg2(frame) };
    let _ = &flags;

    // kprintln!(
    //         "[win32k] NT_USER_SET_WINDOWS_HOOK_AW: type={}, proc={:#x}",
    //         id_hook, lpfn
    //     );

    // Install the hook (similar to SetWindowsHookEx)
    match win32k_helpers::install_hook(id_hook, lpfn, 0) {
        Some(handle) => handle,
        None => 0,
    }
}

/// NT_USER_SET_MENU_DEFAULT_ITEM - Set menu default item
pub extern "C" fn nt_user_set_menu_default_item(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;
    let item = unsafe { get_arg1(frame) };
    let _ = &item;
    let by_pos = unsafe { get_arg2(frame) };
    let _ = &by_pos;

    // kprintln!("[win32k] NT_USER_SET_MENU_DEFAULT_ITEM");
    0 // Previous default
}

/// NT_USER_CHECK_MENU_ITEM - Check menu item
pub extern "C" fn nt_user_check_menu_item(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;
    let id = unsafe { get_arg1(frame) };
    let _ = &id;
    let check = unsafe { get_arg2(frame) };
    let _ = &check;

    // kprintln!("[win32k] NT_USER_CHECK_MENU_ITEM");
    0xFFFFFFFF // MF_BYCOMMAND
}

/// NT_USER_LOCK_WINDOW_UPDATE - Lock window update
pub extern "C" fn nt_user_lock_window_update(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_LOCK_WINDOW_UPDATE");
    1 // TRUE
}

/// NT_USER_SET_SYSTEM_MENU - Set system menu
pub extern "C" fn nt_user_set_system_menu(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let hmenu = unsafe { get_arg1(frame) };
    let _ = &hmenu;

    // kprintln!("[win32k] NT_USER_SET_SYSTEM_MENU");
    0 // Previous menu
}

/// NT_USER_THUNKED_MENU_INFO - Thunked menu info
pub extern "C" fn nt_user_thunked_menu_info(frame: &SyscallFrame) -> u64 {
    let hmenu = unsafe { get_arg0(frame) };
    let _ = &hmenu;
    let data = unsafe { get_arg1(frame) };
    let _ = &data;

    // kprintln!("[win32k] NT_USER_THUNKED_MENU_INFO");
    0
}

/// NT_USER_CALL_HWND - Call with hwnd
pub extern "C" fn nt_user_call_hwnd(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(frame) };
    let _ = &msg;

    // kprintln!("[win32k] NT_USER_CALL_HWND");
    0
}

/// NT_USER_DDE_INITIALIZE - DDE initialize
pub extern "C" fn nt_user_dde_initialize(frame: &SyscallFrame) -> u64 {
    let pid = unsafe { get_arg0(frame) };
    let _ = &pid;
    let filters = unsafe { get_arg1(frame) };
    let _ = &filters;
    let flags = unsafe { get_arg2(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_DDE_INITIALIZE");
    0 // DMLERR_NO_ERROR
}

/// NT_USER_MODIFY_USER_STARTUP_INFO_FLAGS - Modify user startup info flags
pub extern "C" fn nt_user_modify_user_startup_info_flags(frame: &SyscallFrame) -> u64 {
    let flags = unsafe { get_arg0(frame) };
    let _ = &flags;
    let enable = unsafe { get_arg1(frame) };
    let _ = &enable;

    // kprintln!("[win32k] NT_USER_MODIFY_USER_STARTUP_INFO_FLAGS");
    1 // TRUE
}

/// NT_USER_COUNT_CLIPBOARD_FORMATS - count clipboard formats
pub extern "C" fn nt_user_count_clipboard_formats(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NT_USER_COUNT_CLIPBOARD_FORMATS");
    0
}

/// NT_USER_ENUM_DISPLAY_SETTINGS - Enum display settings
pub extern "C" fn nt_user_enum_display_settings(frame: &SyscallFrame) -> u64 {
    let device = unsafe { get_arg0(frame) };
    let _ = &device;
    let index = unsafe { get_arg1(frame) };
    let _ = &index;
    let mode = unsafe { get_arg2(frame) };
    let _ = &mode;
    let flags = unsafe { get_arg3(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_ENUM_DISPLAY_SETTINGS");
    0 // FALSE (no more modes)
}

/// NT_USER_PAINT_DESKTOP - Paint desktop
pub extern "C" fn nt_user_paint_desktop(frame: &SyscallFrame) -> u64 {
    let hdc = unsafe { get_arg0(frame) };
    let _ = &hdc;

    // kprintln!("[win32k] NT_USER_PAINT_DESKTOP");
    1 // TRUE
}

/// NT_USER_CHANGE_CLIPBOARD_CHAIN - Change clipboard chain
pub extern "C" fn nt_user_change_clipboard_chain(frame: &SyscallFrame) -> u64 {
    let remove = unsafe { get_arg0(frame) };
    let _ = &remove;
    let next = unsafe { get_arg1(frame) };
    let _ = &next;

    // kprintln!("[win32k] NT_USER_CHANGE_CLIPBOARD_CHAIN");
    1 // TRUE
}

/// NT_USER_SET_CLIPBOARD_VIEWER - Set clipboard viewer
pub extern "C" fn nt_user_set_clipboard_viewer(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NT_USER_SET_CLIPBOARD_VIEWER");
    0 // Previous viewer
}

/// NT_USER_SHOW_WINDOW_ASYNC - Show window async
pub extern "C" fn nt_user_show_window_async(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let cmd_show = unsafe { get_arg1(frame) };
    let _ = &cmd_show;

    // kprintln!("[win32k] NT_USER_SHOW_WINDOW_ASYNC");
    1 // TRUE
}

/// NT_USER_ACTIVATE_KEYBOARD_LAYOUT - Activate keyboard layout
pub extern "C" fn nt_user_activate_keyboard_layout(frame: &SyscallFrame) -> u64 {
    let hkl = unsafe { get_arg0(frame) };
    let _ = &hkl;
    let flags = unsafe { get_arg1(frame) };
    let _ = &flags;

    // kprintln!("[win32k] NT_USER_ACTIVATE_KEYBOARD_LAYOUT");
    1 // TRUE
}

/// NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS - Initialize client procedure function arrays
pub extern "C" fn nt_user_initialize_client_pfn_arrays(frame: &SyscallFrame) -> u64 {
    let arg1 = unsafe { get_arg0(frame) };
    let _ = &arg1;
    let arg2 = unsafe { get_arg1(frame) };
    let _ = &arg2;
    let arg3 = unsafe { get_arg2(frame) };
    let _ = &arg3;
    let arg4 = unsafe { get_arg3(frame) };
    let _ = &arg4;

    // kprintln!("[win32k] NT_USER_INITIALIZE_CLIENT_PFN_ARRAYS");
    1 // TRUE
}

// =============================================================================
// Dialog System Syscalls (P2 Enhancement)
// =============================================================================

fn find_dialog_item(parent: u64, control_id: u32) -> Option<u64> {
    let manager = crate::libs::win32k::window::WINDOW_MANAGER.lock();
    let children = manager.get_window(parent)?.children.clone();
    children.into_iter().find(|child| {
        manager
            .get_window(*child)
            .map(|window| window.control_id == control_id)
            .unwrap_or(false)
    })
}

/// NtUserMessageBox - Display a message box (P2 Enhancement)
pub extern "C" fn nt_user_message_box(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let lp_text = unsafe { get_arg1(frame) };
    let _ = &lp_text;
    let lp_caption = unsafe { get_arg2(frame) };
    let _ = &lp_caption;
    let u_type = unsafe { get_arg3(frame) };
    let _ = &u_type;

    // kprintln!(
    //         "[win32k] NtUserMessageBox: hwnd={:#x}, type={:#x}",
    //         _hwnd, u_type
    //     );

    // Simplified implementation: Return IDOK for MB_OK type
    if u_type & 0x00000007 == (win32k_helpers::get_mb_ok() as u64) {
        return win32k_helpers::get_idok() as u64;
    }

    // For other types, return a default value
    0
}

/// NtUserGetDlgItem - Get dialog item (P2 Enhancement)
pub extern "C" fn nt_user_get_dlg_item(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(frame) };
    let _ = &n_id;

    // kprintln!("[win32k] NtUserGetDlgItem: hwnd={:#x}, id={}", _hwnd, _n_id);

    find_dialog_item(hwnd, n_id as u32).unwrap_or(0)
}

/// NtUserEndDialog - End dialog (P2 Enhancement)
pub extern "C" fn nt_user_end_dialog(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_result = unsafe { get_arg1(frame) };
    let _ = &n_result;

    // kprintln!("[win32k] NtUserEndDialog: hwnd={:#x}", hwnd);

    if hwnd == 0 || !crate::libs::win32k::window::destroy_window_internal(hwnd) {
        return 0;
    }
    n_result
}

/// NtUserSetDlgItemInt - Set dialog item integer (P2 Enhancement)
pub extern "C" fn nt_user_set_dlg_item_int(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(frame) };
    let _ = &n_id;
    let u_value = unsafe { get_arg2(frame) };
    let _ = &u_value;
    let b_signed = unsafe { get_arg3(frame) };
    let _ = &b_signed;

    // kprintln!("[win32k] NtUserSetDlgItemInt");

    let Some(child) = find_dialog_item(hwnd, n_id as u32) else {
        return 0;
    };
    let value = if b_signed != 0 {
        (u_value as i32).unsigned_abs() as u64
    } else {
        u_value
    };
    let mut digits = alloc::vec::Vec::new();
    let mut remainder = value;
    if remainder == 0 {
        digits.push(b'0');
    }
    while remainder > 0 {
        digits.push(b'0' + (remainder % 10) as u8);
        remainder /= 10;
    }
    if b_signed != 0 && (u_value as i32) < 0 {
        digits.push(b'-');
    }
    digits.reverse();
    let mut title = alloc::vec![0u16; digits.len() + 1];
    for (index, &digit) in digits.iter().enumerate() {
        title[index] = digit as u16;
    }

    let mut manager = crate::libs::win32k::window::WINDOW_MANAGER.lock();
    let Some(window) = manager.get_window_mut(child) else {
        return 0;
    };
    let length = title.len().min(window.title.len());
    window.title[..length].copy_from_slice(&title[..length]);
    1
}

/// NtUserGetDlgItemInt - Get dialog item integer (P2 Enhancement)
pub extern "C" fn nt_user_get_dlg_item_int(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(frame) };
    let _ = &n_id;
    let lp_translated = unsafe { get_arg2(frame) };
    let _ = &lp_translated;
    let b_signed = unsafe { get_arg3(frame) };
    let _ = &b_signed;

    // kprintln!("[win32k] NtUserGetDlgItemInt");

    // GetDlgItemInt: return 0 (no value).
    0
}

// =============================================================================
// Additional Menu Syscalls (P2 Enhancement)
// =============================================================================

/// NtUserCreateMenu - create menu (P2 Enhancement)
pub extern "C" fn nt_user_create_menu(frame: &SyscallFrame) -> u64 {
    let u_flags = unsafe { get_arg0(frame) };
    let _ = &u_flags;

    // kprintln!("[win32k] NtUserCreateMenu");

    // Allocate a menu handle
    let handle = win32k_helpers::allocate_menu_handle();
    if !crate::libs::win32k::user_state::create_menu(handle, false) {
        return 0;
    }
    // kprintln!("[win32k] NtUserCreateMenu: created menu handle={:#x}", handle);
    handle
}

/// NtUserCreatePopupMenu - create popup menu (P2 Enhancement)
pub extern "C" fn nt_user_create_popup_menu(_frame: &SyscallFrame) -> u64 {
    // kprintln!("[win32k] NtUserCreatePopupMenu");

    // Allocate a menu handle with popup style
    let handle = win32k_helpers::allocate_menu_handle();
    if !crate::libs::win32k::user_state::create_menu(handle, true) {
        return 0;
    }
    // kprintln!("[win32k] NtUserCreatePopupMenu: created popup menu handle={:#x}", handle);
    handle
}

/// NtUserAppendMenu - Append menu item (P2 Enhancement)
pub extern "C" fn nt_user_append_menu(frame: &SyscallFrame) -> u64 {
    let h_menu = unsafe { get_arg0(frame) };
    let _ = &h_menu;
    let u_flags = unsafe { get_arg1(frame) };
    let _ = &u_flags;
    let u_id_new_item = unsafe { get_arg2(frame) };
    let _ = &u_id_new_item;
    let lp_new_item = unsafe { get_arg3(frame) };
    let _ = &lp_new_item;

    // kprintln!(
    //         "[win32k] NtUserAppendMenu: hmenu={:#x}, flags={:#x}, id={}",
    //         _h_menu, _u_flags, _u_id_new_item
    //     );

    let mut text = alloc::vec![0u16; 256];
    if lp_new_item != 0 {
        match unsafe { capture_user_unicode_string(lp_new_item, 255, &mut text) } {
            Ok(_) => {}
            Err(_) => return 0,
        }
    } else {
        text.clear();
    }

    if crate::libs::win32k::user_state::append_menu_item(
        h_menu,
        u_flags as u32,
        u_id_new_item as u32,
        &text,
    ) {
        1
    } else {
        0
    }
}

/// NtUserTrackPopupMenu - Track popup menu (P2 Enhancement)
pub extern "C" fn nt_user_track_popup_menu(frame: &SyscallFrame) -> u64 {
    let h_menu = unsafe { get_arg0(frame) };
    let _ = &h_menu;
    let u_flags = unsafe { get_arg1(frame) };
    let _ = &u_flags;
    let x = unsafe { get_arg2(frame) } as i32;
    let _ = &x;
    let y = unsafe { get_arg3(frame) } as i32;
    let _ = &y;

    // kprintln!(
    //         "[win32k] NtUserTrackPopupMenu: hmenu={:#x}, x={}, y={}",
    //         _h_menu, _x, _y
    //     );

    // TrackPopupMenu: return 0 (no item selected).
    0
}

/// NtUserGetMenu - Get window menu (P2 Enhancement)
pub extern "C" fn nt_user_get_menu(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NtUserGetMenu: hwnd={:#x}", hwnd);

    crate::libs::win32k::user_state::window_menu(hwnd)
}

/// NT_USER_SET_MENU - Set window menu (P2 Enhancement)
pub extern "C" fn nt_user_set_menu(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;
    let h_menu = unsafe { get_arg1(frame) };
    let _ = &h_menu;

    // kprintln!("[win32k] NT_USER_SET_MENU: hwnd={:#x}, hmenu={:#x}", hwnd, h_menu);

    crate::libs::win32k::user_state::set_window_menu(hwnd, h_menu).unwrap_or(0)
}

/// NtUserDrawMenuBar - Draw menu bar (P2 Enhancement)
pub extern "C" fn nt_user_draw_menu_bar(frame: &SyscallFrame) -> u64 {
    let hwnd = unsafe { get_arg0(frame) };
    let _ = &hwnd;

    // kprintln!("[win32k] NtUserDrawMenuBar: hwnd={:#x}", hwnd);

    let menu = crate::libs::win32k::user_state::window_menu(hwnd);
    if menu == 0 {
        return 0;
    }
    let valid_window = crate::libs::win32k::window::WINDOW_MANAGER
        .lock()
        .get_window(hwnd)
        .is_some();
    if valid_window {
        crate::libs::win32k::window::invalidate_rect_internal(hwnd, None);
        1
    } else {
        0
    }
}

// =============================================================================
// Additional Hook Syscalls (needed for Shadow SSDT registration)
// =============================================================================

/// NT_USER_SET_WIN_EVENT_HOOK - Set winevent hook
pub extern "C" fn nt_user_set_win_event_hook(frame: &SyscallFrame) -> u64 {
    let event_min = unsafe { get_arg0(frame) } as u32;
    let _ = &event_min;
    let event_max = unsafe { get_arg1(frame) } as u32;
    let _ = &event_max;
    let h_mod = unsafe { get_arg2(frame) };
    let _ = &h_mod;
    let lpfn = unsafe { get_arg3(frame) };
    let _ = &lpfn;
    let id_process = unsafe { get_arg4(frame) } as u32;
    let _ = &id_process;
    let id_thread = unsafe { get_arg5(frame) } as u32;
    let _ = &id_thread;
    let dw_flags = unsafe { get_arg6(frame) } as u32;
    let _ = &dw_flags;

    // kprintln!(
    //         "[win32k] NT_USER_SET_WIN_EVENT_HOOK: event={}-{}, process={}, thread={}",
    //         _event_min, _event_max, _id_process, _id_thread
    //     );

    let handle = 0x0013_0001u64;
    if !crate::libs::win32k::user_state::set_event_hook(handle) {
        return 0;
    }
    handle
}

/// NT_USER_UNHOOK_WIN_EVENT - Unhook winevent
pub extern "C" fn nt_user_unhook_win_event(frame: &SyscallFrame) -> u64 {
    let h_win_event_hook = unsafe { get_arg0(frame) };
    let _ = &h_win_event_hook;

    // kprintln!("[win32k] NT_USER_UNHOOK_WIN_EVENT");

    crate::libs::win32k::user_state::remove_event_hook(h_win_event_hook) as u64
}
