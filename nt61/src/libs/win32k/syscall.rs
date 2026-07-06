//! Shadow SSDT Syscall Handlers
//
//! Implements syscall handlers for win32k.sys GDI and USER functions.
//! These handlers are registered with the Shadow SSDT and called via syscall.
//
//! ## Windows x64 Syscall Convention
//
//! Arguments are passed in:
//!   RCX = arg0 (on syscall entry, RCX is clobbered, so R10 holds original value)
//!   RDX = arg1
//!   R8  = arg2
//!   R9  = arg3
//!   Stack[0] = arg4
//!   Stack[8] = arg5
//
//! Return value in RAX.
//
//! ## Syscall Numbers
//
//! Syscall numbers are defined in `src/ke/shadow_ssdt.rs` based on
//! j00ru/windows-syscalls for Windows 7 SP1 x64.

extern crate alloc;

use crate::kprintln;
#[cfg(target_arch = "x86_64")]
use crate::arch::common::trap_frame::TrapFrame;
use crate::libs::win32k::objects::PenStyle;
use alloc::vec::Vec;

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

    pub const fn get_mb_ok() -> u32 { win32k::MB_OK }
    pub const fn get_idok() -> u32 { win32k::IDOK }
}

// =============================================================================
// Argument Extraction Helpers
// =============================================================================

/// x64 Windows Syscall Calling Convention:
/// - Arguments 0-3: RCX, RDX, R8, R9 (read from trap frame registers)
/// - Arguments 4+: Stack (after shadow space + return address)
/// - Shadow space: 32 bytes (allocated by caller for register spill)
/// - Stack layout at syscall entry:
///   [rsp + 0]  = Return address (8 bytes)
///   [rsp + 8]  = Shadow space slot 1 (caller's rsp + 8, unused by syscall)
///   [rsp + 16] = Shadow space slot 2 (caller's rsp + 16, unused by syscall)
///   [rsp + 24] = Shadow space slot 3 (caller's rsp + 24, unused by syscall)
///   [rsp + 32] = Shadow space slot 4 (caller's rsp + 32, unused by syscall)
///   [rsp + 40] = arg4 (first stack argument)
///   [rsp + 48] = arg5
///   [rsp + 56] = arg6
///   [rsp + 64] = arg7

/// Offset of first stack argument from rsp (shadow space + return address)
const STACK_ARGS_OFFSET: u64 = 40;

/// Get argument 0 from trap frame (RCX / R10 after syscall entry)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg0(tf: *const TrapFrame) -> u64 {
    (*tf).rcx
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg0(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 1 from trap frame (RDX)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg1(tf: *const TrapFrame) -> u64 {
    (*tf).rdx
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg1(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 2 from trap frame (R8)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg2(tf: *const TrapFrame) -> u64 {
    (*tf).r8
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg2(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 3 from trap frame (R9)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg3(tf: *const TrapFrame) -> u64 {
    (*tf).r9
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg3(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 4 from trap frame (first stack argument, after shadow space + return)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg4(tf: *const TrapFrame) -> u64 {
    let rsp = (*tf).rsp;
    let _ = &rsp;
    *((rsp + STACK_ARGS_OFFSET) as *const u64)
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg4(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 5 from trap frame (second stack argument)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg5(tf: *const TrapFrame) -> u64 {
    let rsp = (*tf).rsp;
    let _ = &rsp;
    *((rsp + STACK_ARGS_OFFSET + 8) as *const u64)
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg5(_tf: *const TrapFrame) -> u64 {
    0
}

/// Get argument 6 from trap frame (third stack argument)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg6(tf: *const TrapFrame) -> u64 {
    let rsp = (*tf).rsp;
    let _ = &rsp;
    *((rsp + STACK_ARGS_OFFSET + 16) as *const u64)
}

/// Get argument 7 from trap frame (fourth stack argument)
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_arg7(tf: *const TrapFrame) -> u64 {
    let rsp = (*tf).rsp;
    let _ = &rsp;
    *((rsp + STACK_ARGS_OFFSET + 24) as *const u64)
}

/// Get a stack argument from trap frame by index (0 = arg4, 1 = arg5, etc.)
/// This is the canonical way to get stack arguments in x64 Windows
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_stack_arg(tf: *const TrapFrame, index: usize) -> u64 {
    let rsp = (*tf).rsp;
    let _ = &rsp;
    *((rsp + STACK_ARGS_OFFSET + (index as u64 * 8)) as *const u64)
}

// =============================================================================
// GDI Syscall Handlers - Graphics Device Interface
// =============================================================================

/// NtGdiBitBlt - Bit block transfer
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_bit_blt(tf: *mut TrapFrame) -> u64 {
    let hdc_dest = unsafe { get_arg0(tf) };
    let _ = &hdc_dest;
    let x = unsafe { get_arg1(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(tf) } as i32;
    let _ = &y;
    let width = unsafe { get_arg3(tf) } as i32;
    let _ = &width;
    let height = unsafe { get_arg4(tf) } as i32;
    let _ = &height;
    let hdc_src = unsafe { get_arg5(tf) };
    let _ = &hdc_src;
    let src_x = unsafe { get_arg6(tf) } as i32;
    let _ = &src_x;
    let src_y = unsafe { get_arg7(tf) } as i32;
    let _ = &src_y;
    let rop = unsafe {
        let rsp = (*tf).rsp;
        let _ = &rsp;
        *((rsp + 32) as *const u64)
    } as u32;
    
    // kprintln!("[win32k] NtGdiBitBlt: dest=0x{:x} ({}x{}) src=0x{:x} ({}x{}) rop=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//         hdc_dest, x, y, hdc_src, src_x, src_y, rop);
    
    // Get destination DC
    if let Some(mut dst_dc) = crate::libs::win32k::dc::get_dc(hdc_dest) {
        // Get source DC (optional for some operations)
        let src_dc_opt = if hdc_src != 0 {
            crate::libs::win32k::dc::get_dc(hdc_src)
        } else {
            None
        };
        
        // Call the actual GDI BitBlt function
        let success = crate::libs::win32k::gdi_ops::GreBitBlt(
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
        
        if success { 1 } else { 0 }
    } else {
        // kprintln!("[win32k] NtGdiBitBlt: invalid destination DC")  // kprintln disabled (memcpy crash workaround);
        0
    }
}

/// NtGdiGetCharSet - Get character set
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_char_set(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    
    // kprintln!("[win32k] NtGdiGetCharSet")  // kprintln disabled (memcpy crash workaround);
    
    // Return default charset (DEFAULT_CHARSET = 1)
    1
}

/// NtGdiSelectBitmap - Select bitmap into DC
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_select_object(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let hgdiobj = unsafe { get_arg1(tf) };
    let _ = &hgdiobj;
    
    // kprintln!("[win32k] NtGdiSelectBitmap: hdc=0x{:x}, hgdiobj=0x{:016x}", hdc, hgdiobj)  // kprintln disabled (memcpy crash workaround);
    
    // Call the DC select object function
    let result = crate::libs::win32k::dc::GreSelectObject(hdc, hgdiobj);
    let _ = &result;
    
    // kprintln!("[win32k] NtGdiSelectBitmap: returning 0x{:016x}", result)  // kprintln disabled (memcpy crash workaround);
    result
}

/// NtGdiDeleteObjectApp - Delete GDI object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_delete_object(tf: *mut TrapFrame) -> u64 {
    let hgdiobj = unsafe { get_arg0(tf) };
    let _ = &hgdiobj;
    
    // kprintln!("[win32k] NtGdiDeleteObjectApp: hgdiobj=0x{:016x}", hgdiobj)  // kprintln disabled (memcpy crash workaround);
    
    if hgdiobj == 0 {
        return 0;
    }
    
    let success = crate::libs::win32k::objects::GdiDeleteObject(hgdiobj);
    let _ = &success;
    
    if success { 1 } else { 0 }
}

/// NtGdiStretchBlt - Stretch block transfer
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_stretch_blt(tf: *mut TrapFrame) -> u64 {
    let hdc_dest = unsafe { get_arg0(tf) };
    let _ = &hdc_dest;
    let x_dest = unsafe { get_arg1(tf) };
    let _ = &x_dest;
    let y_dest = unsafe { get_arg2(tf) };
    let _ = &y_dest;
    let width_dest = unsafe { get_arg3(tf) };
    let _ = &width_dest;
    let height_dest = unsafe { get_arg4(tf) };
    let _ = &height_dest;
    let rop = unsafe { get_arg5(tf) };
    let _ = &rop;
    
    // kprintln!("[win32k] NtGdiStretchBlt")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual StretchBlt operation
    1 // TRUE
}

/// NtGdiCombineRgn - Combine two regions
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_combine_rgn(tf: *mut TrapFrame) -> u64 {
    let hrgn_dest = unsafe { get_arg0(tf) };
    let _ = &hrgn_dest;
    let hrgn_src1 = unsafe { get_arg1(tf) };
    let _ = &hrgn_src1;
    let hrgn_src2 = unsafe { get_arg2(tf) };
    let _ = &hrgn_src2;
    let i_mode = unsafe { get_arg3(tf) };
    let _ = &i_mode;
    
    // kprintln!("[win32k] NtGdiCombineRgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CombineRgn
    0 // NULLREGION
}

/// NtGdiGetDCObject - Get DC object handle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dc_object(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let obj_type = unsafe { get_arg1(tf) };
    let _ = &obj_type;
    
    // kprintln!("[win32k] NtGdiGetDCObject")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetDCObject
    0
}

/// NtGdiExtTextOutW - Extended text output
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_ext_text_out(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) };
    let _ = &x;
    let y = unsafe { get_arg2(tf) };
    let _ = &y;
    let options = unsafe { get_arg3(tf) };
    let _ = &options;
    let rect = unsafe { get_arg4(tf) };
    let _ = &rect;
    let s = unsafe { get_arg5(tf) };
    let _ = &s;
    let count = unsafe { get_arg6(tf) };
    let _ = &count;
    
    // kprintln!("[win32k] NtGdiExtTextOutW")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExtTextOutW
    1 // TRUE
}

/// NtGdiSelectFont - Select font into DC
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_select_font(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let hfont = unsafe { get_arg1(tf) };
    let _ = &hfont;
    
    // kprintln!("[win32k] NtGdiSelectFont")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SelectFont
    0
}

/// NtGdiRestoreDC - Restore device context
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_restore_dc(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let n_saved = unsafe { get_arg1(tf) } as i32;
    let _ = &n_saved;
    
    // kprintln!("[win32k] NtGdiRestoreDC: hdc=0x{:x}, n_saved={}", hdc, n_saved)  // kprintln disabled (memcpy crash workaround);
    
    let success = crate::libs::win32k::dc::GreRestoreDC(hdc, n_saved);
    let _ = &success;
    
    if success { 1 } else { 0 }
}

/// NtGdiSaveDC - Save device context
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_save_dc(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    
    // kprintln!("[win32k] NtGdiSaveDC: hdc=0x{:x}", hdc)  // kprintln disabled (memcpy crash workaround);
    
    let result = crate::libs::win32k::dc::GreSaveDC(hdc);
    let _ = &result;
    
    // kprintln!("[win32k] NtGdiSaveDC: returning {}", result)  // kprintln disabled (memcpy crash workaround);
    result as u64
}

/// NtGdiGetDCDword - Get DC attribute
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dc_dword(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let attrib = unsafe { get_arg1(tf) };
    let _ = &attrib;
    let p_result = unsafe { get_arg2(tf) };
    let _ = &p_result;
    
    // kprintln!("[win32k] NtGdiGetDCDword")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetDCDword
    0
}

/// NtGdiLineTo - Draw line to position
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_line_to(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) as i32 };
    let _ = &x;
    let y = unsafe { get_arg2(tf) as i32 };
    let _ = &y;

    // kprintln!("[win32k] NtGdiLineTo: hdc=0x{:x} ({},{})", hdc, x, y)  // kprintln disabled (memcpy crash workaround);

    // Get DC and draw line using MoveToEx + LineTo pattern
    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        // Get current pen position (DC maintains a current position)
        // For now, just draw the line
        let pen_color = if dc.pen != 0 {
            crate::libs::win32k::objects::GdiGetPenColor(dc.pen)
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

/// NtGdiGetAppClipBox - Get application clip box
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_app_clip_box(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    
    // kprintln!("[win32k] NtGdiGetAppClipBox")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetAppClipBox
    0
}

/// NtGdiDoPalette - Perform palette operation
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_do_palette(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let count = unsafe { get_arg2(tf) };
    let _ = &count;
    let ppe = unsafe { get_arg3(tf) };
    let _ = &ppe;
    let op = unsafe { get_arg4(tf) };
    let _ = &op;
    
    // kprintln!("[win32k] NtGdiDoPalette")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DoPalette
    0
}

/// NtGdiCreateCompatibleBitmap - Create compatible bitmap
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_compatible_bitmap(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let width = unsafe { get_arg1(tf) } as i32;
    let _ = &width;
    let height = unsafe { get_arg2(tf) } as i32;
    let _ = &height;
    
    // kprintln!("[win32k] NtGdiCreateCompatibleBitmap: hdc=0x{:x}, {}x{}", hdc, width, height)  // kprintln disabled (memcpy crash workaround);
    
    // Create a 32-bit compatible bitmap
    let handle = crate::libs::win32k::objects::GdiCreateBitmap(width, height, 32);
    let _ = &handle;
    
    // kprintln!("[win32k] NtGdiCreateCompatibleBitmap: returning 0x{:016x}", handle)  // kprintln disabled (memcpy crash workaround);
    handle
}

/// NtGdiGetTextCharsetInfo - Get text charset info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_text_charset_info(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let metrics = unsafe { get_arg1(tf) };
    let _ = &metrics;
    let flags = unsafe { get_arg2(tf) };
    let _ = &flags;

    // kprintln!("[win32k] NtGdiGetTextCharsetInfo: hdc=0x{:x}", hdc)  // kprintln disabled (memcpy crash workaround);

    // Return DEFAULT_CHARSET (1)
    // A full implementation would read the charset from the DC's selected font
    1 // DEFAULT_CHARSET
}

/// NtGdiGetTextMetricsW - Get text metrics
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_text_metrics_w(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let metrics_ptr = unsafe { get_arg1(tf) };
    let _ = &metrics_ptr;

    // kprintln!("[win32k] NtGdiGetTextMetricsW: hdc=0x{:x}, metrics=0x{:x}", hdc, metrics_ptr)  // kprintln disabled (memcpy crash workaround);

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

/// NtGdiGetTextExtent - Get text extent
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_text_extent(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let string = unsafe { get_arg1(tf) };
    let _ = &string;
    let count = unsafe { get_arg2(tf) };
    let _ = &count;
    let dx = unsafe { get_arg3(tf) };
    let _ = &dx;
    let flags = unsafe { get_arg4(tf) };
    let _ = &flags;

    // kprintln!("[win32k] NtGdiGetTextExtent: hdc=0x{:x}", hdc)  // kprintln disabled (memcpy crash workaround);

    // Return the width as a GDI handle (in reality, returns size struct)
    // For simplicity, return a default width based on character count
    // A full implementation would calculate based on the selected font
    let count = unsafe { get_arg2(tf) } as i32;
    let _ = &count;
    if count > 0 {
        // Assume 8 pixels per character (8x8 bitmap font)
        (count * 8) as u64
    } else {
        0
    }
}

/// NtGdiGetTextFaceW - Get font face name
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_text_face_w(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let count = unsafe { get_arg1(tf) } as i32;
    let _ = &count;
    let face_name_ptr = unsafe { get_arg2(tf) };
    let _ = &face_name_ptr;

    // kprintln!("[win32k] NtGdiGetTextFaceW: hdc=0x{:x}, count={}, ptr=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//               hdc, count, face_name_ptr);

    // Return the face name length (excluding null terminator)
    // A full implementation would copy the font name to the buffer
    if face_name_ptr != 0 && count > 0 {
        // Return the number of characters copied (including null)
        // For now, return a placeholder
        let name = "System\0";
        let _ = &name;
        let len = name.len().min(count as usize).min(32);
        let _ = &len;
        // Copy to user buffer would go here
        len as u64
    } else {
        0
    }
}

/// NtGdiExtGetObjectW - Get object information
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_ext_get_object_w(tf: *mut TrapFrame) -> u64 {
    let h = unsafe { get_arg0(tf) };
    let _ = &h;
    let count = unsafe { get_arg1(tf) };
    let _ = &count;
    let buffer = unsafe { get_arg2(tf) };
    let _ = &buffer;
    
    // kprintln!("[win32k] NtGdiExtGetObjectW")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExtGetObjectW
    0
}

/// NtGdiCreateCompatibleDC - Create memory DC
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_compatible_dc(tf: *mut TrapFrame) -> u64 {
    let hdc_src = unsafe { get_arg0(tf) };
    let _ = &hdc_src;
    
    // kprintln!("[win32k] NtGdiCreateCompatibleDC: hdc_src=0x{:x}", hdc_src)  // kprintln disabled (memcpy crash workaround);
    
    let dc = crate::libs::win32k::dc::GreCreateCompatibleDC(hdc_src);
    let _ = &dc;
    
    // kprintln!("[win32k] NtGdiCreateCompatibleDC: returning DC=0x{:08x}", dc)  // kprintln disabled (memcpy crash workaround);
    dc
}

/// NtGdiCreatePen - Create pen object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_pen(tf: *mut TrapFrame) -> u64 {
    let style = unsafe { get_arg0(tf) } as i32;
    let _ = &style;
    let width = unsafe { get_arg1(tf) } as i32;
    let _ = &width;
    let color = unsafe { get_arg2(tf) } as u32;
    let _ = &color;
    
    // kprintln!("[win32k] NtGdiCreatePen: style={}, width={}, color=0x{:08x}", style, width, color)  // kprintln disabled (memcpy crash workaround);
    
    // Call the GDI objects module to create a pen
    crate::libs::win32k::objects::GdiCreatePen(PenStyle::from_raw(style), width, color)
}

/// NtGdiCreateBitmap - Create bitmap object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_bitmap(tf: *mut TrapFrame) -> u64 {
    let width = unsafe { get_arg0(tf) } as i32;
    let _ = &width;
    let height = unsafe { get_arg1(tf) } as i32;
    let _ = &height;
    let planes = unsafe { get_arg2(tf) } as u16; // planes parameter not used
    let _ = &planes;
    let bits_per_pixel = unsafe { get_arg3(tf) } as u16;
    let _ = &bits_per_pixel;
    
    // kprintln!("[win32k] NtGdiCreateBitmap: {}x{}x{}, {}bpp", width, height, _planes, bits_per_pixel)  // kprintln disabled (memcpy crash workaround);
    
    // Call the GDI objects module to create a bitmap
    crate::libs::win32k::objects::GdiCreateBitmap(width, height, bits_per_pixel)
}

/// NtGdiPatBlt - Pattern blt operation
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_pat_blt(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(tf) } as i32;
    let _ = &y;
    let width = unsafe { get_arg3(tf) } as i32;
    let _ = &width;
    let height = unsafe { get_arg4(tf) } as i32;
    let _ = &height;
    let rop = unsafe { get_arg5(tf) } as u32;
    let _ = &rop;
    
    // kprintln!("[win32k] NtGdiPatBlt: hdc=0x{:x}, ({}x{}) size={}x{}, rop=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//         hdc, x, y, width, height, rop);
    
    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        let success = crate::libs::win32k::gdi_ops::GrePatBlt(
            dc,
            x,
            y,
            width,
            height,
            rop,
        );
        if success { 1 } else { 0 }
    } else {
        0
    }
}

/// NtGdiHfontCreate - Create font
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_hfont_create(tf: *mut TrapFrame) -> u64 {
    let logfont = unsafe { get_arg0(tf) };
    let _ = &logfont;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtGdiHfontCreate")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateFont
    0
}

/// NtGdiDrawStream - Draw stream
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_draw_stream(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let pso = unsafe { get_arg1(tf) };
    let _ = &pso;
    let pdso = unsafe { get_arg2(tf) };
    let _ = &pdso;
    
    // kprintln!("[win32k] NtGdiDrawStream")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DrawStream
    0
}

/// NtGdiInvertRgn - Invert region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_invert_rgn(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let hrgn = unsafe { get_arg1(tf) };
    let _ = &hrgn;
    
    // kprintln!("[win32k] NtGdiInvertRgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual InvertRgn
    0
}

/// NtGdiGetRgnBox - Get region box
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_rgn_box(tf: *mut TrapFrame) -> u64 {
    let hrgn = unsafe { get_arg0(tf) };
    let _ = &hrgn;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    
    // kprintln!("[win32k] NtGdiGetRgnBox")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetRgnBox
    0
}

/// NtGdiMaskBlt - Masked block transfer
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_mask_blt(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiMaskBlt")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual MaskBlt
    1 // TRUE
}

/// NtGdiGetWidthTable - Get width table
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_width_table(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiGetWidthTable")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetWidthTable
    0
}

/// NtGdiPolyPatBlt - Poly pattern blt
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_poly_pat_blt(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiPolyPatBlt")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual PolyPatBlt
    1 // TRUE
}

/// NtGdiGetNearestColor - Get nearest color
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_nearest_color(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let cry = unsafe { get_arg1(tf) };
    let _ = &cry;
    let pcc = unsafe { get_arg2(tf) };
    let _ = &pcc;
    
    // kprintln!("[win32k] NtGdiGetNearestColor")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetNearestColor
    0
}

/// NtGdiTransformPoints - Transform points
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_transform_points(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiTransformPoints")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual TransformPoints
    0
}

/// NtGdiGetDCPoint - Get DC point
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dc_point(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiGetDCPoint")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetDCPoint
    0
}

/// NtGdiCreateDIBBrush - Create DIB brush
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_dib_brush(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreateDIBBrush")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual CreateDIBBrush
    0
}

/// NtGdiAlphaBlend - Alpha blend
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_alpha_blend(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiAlphaBlend")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual AlphaBlend
    1 // TRUE
}

/// NtGdiDdBlt - DirectDraw blt
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_blt(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdBlt")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdBlt
    0
}

/// NtGdiOffsetRgn - Offset region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_offset_rgn(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiOffsetRgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual OffsetRgn
    0
}

/// NtGdiFillRgn - Fill region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_fill_rgn(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let hrgn = unsafe { get_arg1(tf) };
    let _ = &hrgn;
    let hbrush = unsafe { get_arg2(tf) };
    let _ = &hbrush;
    
    // kprintln!("[win32k] NtGdiFillRgn: hdc=0x{:x}, hrgn=0x{:x}, hbrush=0x{:x}", hdc, hrgn, hbrush)  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual FillRgn
    // Would need to: get DC, get region, get brush, fill region with brush pattern
    1 // Return success for now
}

/// NtGdiModifyWorldTransform - Modify world transform
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_modify_world_transform(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let xform = unsafe { get_arg1(tf) };
    let _ = &xform;
    let mode = unsafe { get_arg2(tf) };
    let _ = &mode;
    
    // kprintln!("[win32k] NtGdiModifyWorldTransform: hdc=0x{:x}, xform=0x{:x}, mode=0x{:x}", hdc, xform, mode)  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ModifyWorldTransform
    // Mode: MWT_IDENTITY (1), MWT_LEFTMULTIPLY (2), MWT_RIGHTMULTIPLY (3), MWT_SET (4)
    1 // Return success for now
}

/// NtGdiOpenDCW - Open device context (wide)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_open_dc_w(tf: *mut TrapFrame) -> u64 {
    let p_device_name = unsafe { get_arg0(tf) };
    let _ = &p_device_name;
    let p_log_ext = unsafe { get_arg1(tf) };
    let _ = &p_log_ext;
    let p_log_int = unsafe { get_arg2(tf) };
    let _ = &p_log_int;
    let usetty = unsafe { get_arg3(tf) };
    let _ = &usetty;
    // Additional args on stack
    let drv_name = unsafe { get_stack_arg(tf, 4) };
    let _ = &drv_name;
    let desktop_name = unsafe { get_stack_arg(tf, 5) };
    let _ = &desktop_name;
    let video_mode = unsafe { get_stack_arg(tf, 6) };
    let _ = &video_mode;
    let flags = unsafe { get_stack_arg(tf, 7) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtGdiOpenDCW: device=0x{:x}, drv=0x{:x}, desktop=0x{:x}",   // kprintln disabled (memcpy crash workaround)
//               p_device_name, drv_name, desktop_name);
    
    // Call create display DC - this is essentially what OpenDC does
    crate::libs::win32k::dc::GreCreateDisplayDC()
}

/// NtGdiGetBitmapBits - Get bitmap bits
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_bitmap_bits(tf: *mut TrapFrame) -> u64 {
    let hbitmap = unsafe { get_arg0(tf) };
    let _ = &hbitmap;
    let start_scan = unsafe { get_arg1(tf) };
    let _ = &start_scan;
    let num_scans = unsafe { get_arg2(tf) };
    let _ = &num_scans;
    let bits_ptr = unsafe { get_arg3(tf) };
    let _ = &bits_ptr;

    // kprintln!("[win32k] NtGdiGetBitmapBits: hbitmap=0x{:x}, start=0x{:x}, num={}, bits=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//               hbitmap, start_scan, num_scans, bits_ptr);

    // TODO: Implement actual GetBitmapBits
    // Would need to: get bitmap object, copy pixel data to user buffer
    0 // Return 0 bytes copied for now
}

/// NtGdiStretchDIBitsInternal - Stretch DIB bits (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_stretch_dibits_internal(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiStretchDIBitsInternal")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual StretchDIBitsInternal
    0
}

/// NtGdiCreateRectRgn - Create rectangular region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_rect_rgn(tf: *mut TrapFrame) -> u64 {
    let x1 = unsafe { get_arg0(tf) };
    let _ = &x1;
    let y1 = unsafe { get_arg1(tf) };
    let _ = &y1;
    let x2 = unsafe { get_arg2(tf) };
    let _ = &x2;
    let y2 = unsafe { get_arg3(tf) };
    let _ = &y2;
    
    // kprintln!("[win32k] NtGdiCreateRectRgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateRectRgn
    0
}

/// NtGdiGetDIBitsInternal - Get DIB bits (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dibits_internal(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiGetDIBitsInternal")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetDIBitsInternal
    0
}

/// NtGdiDeleteClientObj - Delete client object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_delete_client_obj(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDeleteClientObj")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DeleteClientObj
    1 // TRUE
}

/// NtGdiExtCreateRegion - Extended region creation
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_ext_create_region(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiExtCreateRegion")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExtCreateRegion
    0
}

/// NtGdiComputeXformCoefficients - Compute transform coefficients
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_compute_xform_coefficients(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiComputeXformCoefficients")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ComputeXformCoefficients
    0
}

/// NtGdiUnrealizeObject - Unrealize GDI object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_unrealize_object(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiUnrealizeObject")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual UnrealizeObject
    1 // TRUE
}

/// NtGdiRectangle - Draw rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_rectangle(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let left = unsafe { get_arg1(tf) as i32 };
    let _ = &left;
    let top = unsafe { get_arg2(tf) as i32 };
    let _ = &top;
    let right = unsafe { get_arg3(tf) as i32 };
    let _ = &right;
    let bottom = unsafe { get_arg4(tf) as i32 };
    let _ = &bottom;

    // kprintln!("[win32k] NtGdiRectangle: hdc=0x{:x} ({},{})-({},{})", hdc, left, top, right, bottom)  // kprintln disabled (memcpy crash workaround);

    // Get DC and draw rectangle
    if let Some(dc) = crate::libs::win32k::dc::get_dc(hdc) {
        let success = crate::libs::win32k::gdi_ops::GreRectangle(dc, left, top, right, bottom);
        let _ = &success;
        if success { 1 } else { 0 }
    } else {
        0
    }
}

/// NtGdiSetLayout - Set DC layout
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_set_layout(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiSetLayout")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetLayout
    0
}

/// NtGdiExcludeClipRect - Exclude rectangle from clip region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_exclude_clip_rect(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiExcludeClipRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExcludeClipRect
    0
}

/// NtGdiCreateDIBSection - Create DIB section
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_dib_section(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreateDIBSection")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateDIBSection
    0
}

/// NtGdiGetDCforBitmap - Get DC for bitmap
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dc_for_bitmap(tf: *mut TrapFrame) -> u64 {
    let hbitmap = unsafe { get_arg0(tf) };
    let _ = &hbitmap;
    
    // kprintln!("[win32k] NtGdiGetDCforBitmap: hbitmap=0x{:x}", hbitmap)  // kprintln disabled (memcpy crash workaround);
    
    // Get DC for bitmap - create a compatible DC with the bitmap selected
    crate::libs::win32k::dc::GreGetDCForBitmap(hbitmap)
}

/// NtGdiGetDC - Get device context
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_dc(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtGdiGetDC: hwnd=0x{:x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    
    // Get DC for window - 0 means screen DC
    crate::libs::win32k::dc::GreCreateDisplayDC()
}

/// NtGdiCreateDIBitmapInternal - Create DIB bitmap (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_dibitmap_internal(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreateDIBitmapInternal")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateDIBitmapInternal
    0
}

/// NtGdiDdDeleteSurfaceObject - Delete DirectDraw surface object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_delete_surface_object(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdDeleteSurfaceObject")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdDeleteSurfaceObject
    0
}

/// NtGdiDdCanCreateSurface - Check if surface can be created
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_can_create_surface(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdCanCreateSurface")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdCanCreateSurface
    0
}

/// NtGdiDdCreateSurface - Create DirectDraw surface
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_create_surface(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdCreateSurface")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdCreateSurface
    0
}

/// NtGdiDdDestroySurface - Destroy DirectDraw surface
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_destroy_surface(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdDestroySurface")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdDestroySurface
    0
}

/// NtGdiDdResetVisrgn - Reset visible region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_dd_reset_visrgn(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiDdResetVisrgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DdResetVisrgn
    0
}

/// NtGdiExtCreatePen - Extended pen creation
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_ext_create_pen(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiExtCreatePen")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExtCreatePen
    0
}

/// NtGdiCreatePaletteInternal - Create palette (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_palette_internal(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreatePaletteInternal")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreatePaletteInternal
    0
}

/// NtGdiSetBrushOrg - Set brush origin
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_set_brush_org(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiSetBrushOrg")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetBrushOrg
    0
}

/// NtGdiSetPixel - Set pixel
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_set_pixel(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) };
    let _ = &x;
    let y = unsafe { get_arg2(tf) };
    let _ = &y;
    let color = unsafe { get_arg3(tf) };
    let _ = &color;
    
    // kprintln!("[win32k] NtGdiSetPixel")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetPixel
    0
}

/// NtGdiCreatePatternBrushInternal - Create pattern brush (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_pattern_brush_internal(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreatePatternBrushInternal")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreatePatternBrushInternal
    0
}

/// NtGdiGetOutlineTextMetricsInternalW - Get outline text metrics (internal)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_outline_text_metrics_internal_w(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiGetOutlineTextMetricsInternalW")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetOutlineTextMetricsInternalW
    0
}

/// NtGdiSetBitmapBits - Set bitmap bits
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_set_bitmap_bits(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiSetBitmapBits")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetBitmapBits
    0
}

/// NtGdiCreateSolidBrush - Create solid brush
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_solid_brush(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreateSolidBrush")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateSolidBrush
    0
}

/// NtGdiCreateClientObj - Create client object
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_create_client_obj(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiCreateClientObj")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateClientObj
    0
}

/// NtGdiRectInRegion - Rectangle in region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_rect_in_region(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtGdiRectInRegion")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual RectInRegion
    0
}

/// NtGdiGetPixel - Get pixel color
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_gdi_get_pixel(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) };
    let _ = &x;
    let y = unsafe { get_arg2(tf) };
    let _ = &y;
    
    // kprintln!("[win32k] NtGdiGetPixel")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetPixel - return CLR_INVALID
    0xFFFFFFFF
}

// =============================================================================
// USER Syscall Handlers - Window Management
// =============================================================================

/// NtUserGetDC - Get device context
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_dc(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserGetDC: hwnd=0x{:016x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    
    // Create a display DC
    let dc = crate::libs::win32k::dc::GreCreateDisplayDC();
    let _ = &dc;
    
    // kprintln!("[win32k] NtUserGetDC: returning DC=0x{:08x}", dc)  // kprintln disabled (memcpy crash workaround);
    dc
}

/// NtUserGetDCEx - Get device context (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_dcex(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hrgnclip = unsafe { get_arg1(tf) };
    let _ = &hrgnclip;
    let flags = unsafe { get_arg2(tf) } as u32;
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserGetDCEx: hwnd=0x{:x}, hrgnclip=0x{:x}, flags=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, hrgnclip, flags);
    
    // For now, just create a standard display DC
    // In a full implementation, we would handle clipping regions and DC flags
    let dc = crate::libs::win32k::dc::GreCreateDisplayDC();
    let _ = &dc;
    
    // kprintln!("[win32k] NtUserGetDCEx: returning DC=0x{:x}", dc)  // kprintln disabled (memcpy crash workaround);
    dc
}

/// NtUserCreateWindowEx - Create window (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_window_ex(tf: *mut TrapFrame) -> u64 {
    let ex_style = unsafe { get_arg0(tf) } as u32;
    let _ = &ex_style;
    let class_name_ptr = unsafe { get_arg1(tf) };
    let _ = &class_name_ptr;
    let window_name_ptr = unsafe { get_arg2(tf) };
    let _ = &window_name_ptr;
    let style = unsafe { get_arg3(tf) } as u32;
    let _ = &style;
    let x = unsafe { get_arg4(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg5(tf) } as i32;
    let _ = &y;
    let width = unsafe { get_arg6(tf) } as i32;
    let _ = &width;
    let height = unsafe { get_arg7(tf) } as i32;
    let _ = &height;
    let parent = unsafe {
        let rsp = (*tf).rsp;
        let _ = &rsp;
        *(rsp as *const u64)
    };
    let menu = unsafe {
        let rsp = (*tf).rsp;
        let _ = &rsp;
        *((rsp + 8) as *const u64)
    };
    let _ = &menu;
    let instance = unsafe {
        let rsp = (*tf).rsp;
        let _ = &rsp;
        *((rsp + 16) as *const u64)
    };
    let _ = &instance;
    let param = unsafe {
        let rsp = (*tf).rsp;
        let _ = &rsp;
        *((rsp + 24) as *const u64)
    };
    let _ = &param;
    
    // kprintln!("[win32k] NtUserCreateWindowEx: ex_style=0x{:08x}, style=0x{:08x}, pos=({},{}) size={}x{}",  // kprintln disabled (memcpy crash workaround)
//         ex_style, style, x, y, width, height);
    
    // Read class name from user memory
    let mut class_name_buf = [0u16; 64];
    if class_name_ptr != 0 {
        for i in 0..63 {
            let char_ptr = (class_name_ptr + (i as u64) * 2) as *const u16;
            let _ = &char_ptr;
            let ch = unsafe { *char_ptr };
            let _ = &ch;
            class_name_buf[i] = ch;
            if ch == 0 { break; }
        }
    }
    
    // Read window title from user memory
    let mut title_buf = [0u16; 256];
    if window_name_ptr != 0 {
        for i in 0..255 {
            let char_ptr = (window_name_ptr + (i as u64) * 2) as *const u16;
            let _ = &char_ptr;
            let ch = unsafe { *char_ptr };
            let _ = &ch;
            title_buf[i] = ch;
            if ch == 0 { break; }
        }
    }
    
    // Create the window using the window manager
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
    );
    
    match hwnd {
        Some(h) => {
            // kprintln!("[win32k] NtUserCreateWindowEx: created hwnd=0x{:016x}", h)  // kprintln disabled (memcpy crash workaround);
            h
        }
        None => {
            // kprintln!("[win32k] NtUserCreateWindowEx: failed to create window")  // kprintln disabled (memcpy crash workaround);
            0
        }
    }
}

/// NtUserDestroyWindow - Destroy window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_destroy_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserDestroyWindow: hwnd=0x{:x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    
    if hwnd == 0 {
        return 0;
    }
    
    let success = crate::libs::win32k::window::destroy_window_internal(hwnd);
    let _ = &success;
    
    if success { 1 } else { 0 }
}

/// NtUserShowWindow - Show/hide window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_show_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_cmd_show = unsafe { get_arg1(tf) } as i32;
    let _ = &n_cmd_show;
    
    // kprintln!("[win32k] NtUserShowWindow: hwnd=0x{:x}, cmd_show={}", hwnd, n_cmd_show)  // kprintln disabled (memcpy crash workaround);
    
    // Convert SW_* commands to boolean show state
    let show = match n_cmd_show {
        0 | 6 | 7 | 8 => false,  // SW_HIDE, SW_MINIMIZE, SW_SHOWMINNOACTIVE, SW_FORCEMINIMIZE
        _ => true,              // SW_SHOW, SW_SHOWNORMAL, SW_SHOWMAXIMIZED, etc.
    };
    
    // Call the window manager to show/hide the window
    let success = crate::libs::win32k::window::show_window_internal(hwnd, show);
    let _ = &success;
    
    if success { 1 } else { 0 }
}

/// NtUserSetWindowPos - Set window position
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_pos(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hwnd_insert_after = unsafe { get_arg1(tf) };
    let _ = &hwnd_insert_after;
    let x = unsafe { get_arg2(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg3(tf) } as i32;
    let _ = &y;
    let cx = unsafe { get_arg4(tf) } as i32;
    let _ = &cx;
    let cy = unsafe { get_arg5(tf) } as i32;
    let _ = &cy;
    let u_flags = unsafe { get_arg6(tf) } as u32;
    let _ = &u_flags;
    
    // kprintln!("[win32k] NtUserSetWindowPos: hwnd=0x{:x}, insert_after=0x{:x}, pos=({},{}), size={}x{}, flags=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, hwnd_insert_after, x, y, cx, cy, u_flags);
    
    // Check flags for SWP_NOSIZE
    let use_cx_cy = (u_flags & 0x0001) == 0;
    let _ = &use_cx_cy;
    // Check flags for SWP_NOMOVE
    let use_x_y = (u_flags & 0x0002) == 0;
    let _ = &use_x_y;
    
    let final_x = if use_x_y { x } else { 0 };
    let _ = &final_x;
    let final_y = if use_x_y { y } else { 0 };
    let _ = &final_y;
    let final_cx = if use_cx_cy { cx } else { 0 };
    let _ = &final_cx;
    let final_cy = if use_cx_cy { cy } else { 0 };
    let _ = &final_cy;
    
    // Call the window manager to set window position
    let success = crate::libs::win32k::window::set_window_pos_internal(
        hwnd,
        final_x,
        final_y,
        final_cx,
        final_cy,
    );
    
    if success { 1 } else { 0 }
}

/// NtUserGetMessage - Get message from queue
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_message(tf: *mut TrapFrame) -> u64 {
    let msg_ptr = unsafe { get_arg0(tf) };
    let _ = &msg_ptr;
    let hwnd = unsafe { get_arg1(tf) };
    let _ = &hwnd;
    let msg_filter_min = unsafe { get_arg2(tf) } as u32;
    let _ = &msg_filter_min;
    let msg_filter_max = unsafe { get_arg3(tf) } as u32;
    let _ = &msg_filter_max;
    
    // kprintln!("[win32k] NtUserGetMessage: msg_ptr=0x{:x}, hwnd=0x{:x}, filter={:#x}-{:#x}",  // kprintln disabled (memcpy crash workaround)
//         msg_ptr, hwnd, msg_filter_min, msg_filter_max);
    
    if msg_ptr == 0 {
        return 0;
    }
    
    // Get the current thread's message queue
    let queue = crate::libs::win32k::message::get_current_queue();
    let _ = &queue;
    
    // Try to get a message (timeout=0: return immediately if no message)
    match queue.get_message(hwnd, msg_filter_min, msg_filter_max, 0) {
        Some(msg) => {
            // Copy the message to user memory
            unsafe {
                let p_msg = msg_ptr as *mut crate::libs::win32k::message::Msg;
                let _ = &p_msg;
                (*p_msg).hwnd = msg.hwnd;
                (*p_msg).message = msg.message;
                (*p_msg).wparam = msg.wparam;
                (*p_msg).lparam = msg.lparam;
                (*p_msg).time = msg.time;
                (*p_msg).pt_x = msg.pt_x;
                (*p_msg).pt_y = msg.pt_y;
            }
            
            // Return 1 for success, 0 for WM_QUIT
            if msg.message == 0x0012 { // WM_QUIT
                // kprintln!("[win32k] NtUserGetMessage: got WM_QUIT")  // kprintln disabled (memcpy crash workaround);
                0
            } else {
                1
            }
        }
        None => {
            // No message available (would block in real implementation)
            // Return -1 on error, 0 for WM_QUIT, 1 for success
            // For now, return 1 to indicate we processed successfully (no message)
            // kprintln!("[win32k] NtUserGetMessage: no message available")  // kprintln disabled (memcpy crash workaround);
            1
        }
    }
}

/// NtUserPeekMessage - Peek at message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_peek_message(tf: *mut TrapFrame) -> u64 {
    let msg = unsafe { get_arg0(tf) };
    let _ = &msg;
    let hwnd = unsafe { get_arg1(tf) };
    let _ = &hwnd;
    let msg_filter_min = unsafe { get_arg2(tf) };
    let _ = &msg_filter_min;
    let msg_filter_max = unsafe { get_arg3(tf) };
    let _ = &msg_filter_max;
    let remove = unsafe { get_arg4(tf) };
    let _ = &remove;

    // kprintln!("[win32k] NtUserPeekMessage")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual PeekMessage
    0
}

/// NtUserPostMessage - Post message to queue
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_post_message(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(tf) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(tf) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(tf) };
    let _ = &l_param;
    
    // kprintln!("[win32k] NtUserPostMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual PostMessage
    1 // TRUE
}

/// NtUserSetFocus - Set focus window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_focus(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserSetFocus: hwnd=0x{:x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    
    // Call the window manager to set focus
    let result = crate::libs::win32k::window::set_focus_internal(hwnd);
    let _ = &result;
    
    // Return previous focus handle (0 if none)
    match result {
        Some(old) => old,
        None => 0,
    }
}

/// NtUserGetForegroundWindow - Get foreground window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_foreground_window(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetForegroundWindow")  // kprintln disabled (memcpy crash workaround);
    
    // Return the current foreground window handle
    crate::libs::win32k::window::get_foreground_window_internal()
}

/// NtUserSetForegroundWindow - Set foreground window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_foreground_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserSetForegroundWindow: hwnd=0x{:x}", hwnd)  // kprintln disabled (memcpy crash workaround);
    
    // Call the window manager to set foreground window
    let result = crate::libs::win32k::window::set_foreground_window_internal(hwnd);
    let _ = &result;
    
    match result {
        Some(old) => old,
        None => 0,
    }
}

/// NtUserGetKeyboardState - Get keyboard state
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_keyboard_state(tf: *mut TrapFrame) -> u64 {
    let state_ptr = unsafe { get_arg0(tf) };
    let _ = &state_ptr;

    // kprintln!("[win32k] NtUserGetKeyboardState: state=0x{:x}", state_ptr)  // kprintln disabled (memcpy crash workaround);

    // Return 1 (success) if state pointer is valid
    // A full implementation would copy the keyboard state to the buffer
    if state_ptr != 0 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserSetKeyboardState - Set keyboard state
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_keyboard_state(tf: *mut TrapFrame) -> u64 {
    let state_ptr = unsafe { get_arg0(tf) };
    let _ = &state_ptr;

    // kprintln!("[win32k] NtUserSetKeyboardState: state=0x{:x}", state_ptr)  // kprintln disabled (memcpy crash workaround);

    // Return 1 (success) if state pointer is valid
    if state_ptr != 0 {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserGetKeyState - Get key state
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_key_state(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let vk = unsafe { get_arg1(tf) } as i32;
    let _ = &vk;

    // kprintln!("[win32k] NtUserGetKeyState: vk=0x{:x}", vk)  // kprintln disabled (memcpy crash workaround);

    // Return key state: high bit = toggled, second high bit = pressed
    // For now, return 0 (not pressed, not toggled)
    0
}

/// NtUserGetAsyncKeyState - Get async key state
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_async_key_state(tf: *mut TrapFrame) -> u64 {
    let vk = unsafe { get_arg0(tf) } as i32;
    let _ = &vk;

    // kprintln!("[win32k] NtUserGetAsyncKeyState: vk=0x{:x}", vk)  // kprintln disabled (memcpy crash workaround);

    // Return key state: high bit = toggled, second high bit = pressed
    0
}

/// NtUserSendInput - Send input events
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_send_input(tf: *mut TrapFrame) -> u64 {
    let num_inputs = unsafe { get_arg0(tf) } as i32;
    let _ = &num_inputs;
    let inputs_ptr = unsafe { get_arg1(tf) };
    let _ = &inputs_ptr;
    let size = unsafe { get_arg2(tf) };
    let _ = &size;

    // kprintln!("[win32k] NtUserSendInput: num={}, ptr=0x{:x}, size={}",  // kprintln disabled (memcpy crash workaround)
//               num_inputs, inputs_ptr, size);

    // Return number of events successfully injected
    // For now, return 0 (not implemented)
    0
}

/// NtUserTranslateMessage - Translate virtual key message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_translate_message(tf: *mut TrapFrame) -> u64 {
    let msg = unsafe { get_arg0(tf) };
    let _ = &msg;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserTranslateMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual TranslateMessage
    0
}

/// NtUserDispatchMessage - Dispatch message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_dispatch_message(tf: *mut TrapFrame) -> u64 {
    let msg_ptr = unsafe { get_arg0(tf) };
    let _ = &msg_ptr;
    
    // kprintln!("[win32k] NtUserDispatchMessage: msg_ptr=0x{:x}", msg_ptr)  // kprintln disabled (memcpy crash workaround);
    
    if msg_ptr == 0 {
        return 0;
    }
    
    // Read the message from user memory
    let msg: crate::libs::win32k::message::Msg = unsafe {
        let p_msg = msg_ptr as *const crate::libs::win32k::message::Msg;
        let _ = &p_msg;
        *p_msg
    };
    
    // kprintln!("[win32k] NtUserDispatchMessage: hwnd=0x{:x}, msg={:#x}",  // kprintln disabled (memcpy crash workaround)
//         msg.hwnd, msg.message);
    
    // Call the default window procedure
    let result = crate::libs::win32k::message::default_wndproc(
        msg.hwnd,
        msg.message,
        msg.wparam,
        msg.lparam,
    );
    
    // kprintln!("[win32k] NtUserDispatchMessage: result=0x{:x}", result as u64)  // kprintln disabled (memcpy crash workaround);
    result as u64
}

/// NtUserGetSystemMetrics - Get system metrics
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_system_metrics(tf: *mut TrapFrame) -> u64 {
    let n_index = unsafe { get_arg0(tf) };
    let _ = &n_index;
    
    // kprintln!("[win32k] NtUserGetSystemMetrics(n_index={})", n_index)  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetSystemMetrics
    match n_index as i32 {
        0 => 0,    // SM_CXSCREEN
        1 => 0,    // SM_CYSCREEN
        _ => 0,
    }
}

/// NtUserSystemParametersInfo - System parameters
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_system_parameters_info(tf: *mut TrapFrame) -> u64 {
    let ui_action = unsafe { get_arg0(tf) } as u32;
    let _ = &ui_action;
    let ui_param = unsafe { get_arg1(tf) };
    let _ = &ui_param;
    let pv_param = unsafe { get_arg2(tf) };
    let _ = &pv_param;
    let f_win_ini = unsafe { get_arg3(tf) };
    let _ = &f_win_ini;

    // kprintln!("[win32k] NtUserSystemParametersInfo: action=0x{:x}", ui_action)  // kprintln disabled (memcpy crash workaround);

    // Most system parameters - return sensible defaults
    if pv_param != 0 {
        // Return 0 for get operations
    }
    1 // TRUE for most operations
}

/// NtUserMoveWindow - Move window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_move_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let x = unsafe { get_arg1(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg2(tf) } as i32;
    let _ = &y;
    let cx = unsafe { get_arg3(tf) } as i32;
    let _ = &cx;
    let cy = unsafe { get_arg4(tf) } as i32;
    let _ = &cy;
    let repaint = unsafe { get_arg5(tf) };
    let _ = &repaint;
    
    // kprintln!("[win32k] NtUserMoveWindow: hwnd=0x{:x}, pos=({},{}), size={}x{}, repaint={}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, x, y, cx, cy, repaint);
    
    // Call the window manager to set window position
    let success = crate::libs::win32k::window::set_window_pos_internal(hwnd, x, y, cx, cy);
    let _ = &success;
    
    // If repaint is requested, invalidate the window
    if repaint != 0 && success {
        crate::libs::win32k::window::invalidate_rect_internal(hwnd, None);
    }
    
    if success { 1 } else { 0 }
}

/// NtUserGetWindowRect - Get window rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_window_rect(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    
    // kprintln!("[win32k] NtUserGetWindowRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetWindowRect
    0
}

/// NtUserGetClientRect - Get client rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_client_rect(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    
    // kprintln!("[win32k] NtUserGetClientRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetClientRect
    0
}

/// NtUserSetCapture - Set capture window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_capture(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserSetCapture")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetCapture
    0
}

/// NtUserGetCapture - Get capture window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_capture(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCapture")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetCapture
    0
}

/// NtUserSetCursor - Set cursor
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_cursor(tf: *mut TrapFrame) -> u64 {
    let hcur = unsafe { get_arg0(tf) };
    let _ = &hcur;
    
    // kprintln!("[win32k] NtUserSetCursor")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetCursor
    0
}

/// NtUserGetCursor - Get cursor
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_cursor(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCursor")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual GetCursor
    0
}

/// NtUserSetTimer - Set timer (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_timer(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_id_event = unsafe { get_arg1(tf) } as u32;
    let _ = &n_id_event;
    let u_elapse = unsafe { get_arg2(tf) } as u32;
    let _ = &u_elapse;
    let lp_timer_func = unsafe { get_arg3(tf) };
    let _ = &lp_timer_func;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserSetTimer: hwnd={:#x}, id={}, interval={}ms, proc={:#x}",
//         hwnd, n_id_event, u_elapse, lp_timer_func
//     );

    // Create a timer using the timer system
    match win32k_helpers::create_timer(hwnd, n_id_event, u_elapse, lp_timer_func) {
        Some(timer_id) => timer_id as u64,
        None => 0,
    }
}

/// NtUserKillTimer - Kill timer (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_kill_timer(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_id_event = unsafe { get_arg1(tf) } as u32;
    let _ = &n_id_event;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserKillTimer: hwnd={:#x}, id={}",
//         hwnd, n_id_event
//     );

    // Kill the timer using the timer system
    if win32k_helpers::kill_timer(hwnd, n_id_event) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserInvalidateRect - Invalidate rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_invalidate_rect(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    let erase = unsafe { get_arg2(tf) };
    let _ = &erase;
    
    // kprintln!("[win32k] NtUserInvalidateRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual InvalidateRect
    1 // TRUE
}

/// NtUserWaitMessage - Wait for message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_wait_message(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserWaitMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual WaitMessage
    0
}

/// NtUserCallNoParam - Call with no parameters
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_no_param(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCallNoParam")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCallOneParam - Call with one parameter
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_one_param(tf: *mut TrapFrame) -> u64 {
    let param = unsafe { get_arg0(tf) };
    let _ = &param;
    let code = unsafe { get_arg1(tf) };
    let _ = &code;
    
    // kprintln!("[win32k] NtUserCallOneParam")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CallOneParam
    0
}

/// NtUserCallTwoParam - Call with two parameters
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_two_param(tf: *mut TrapFrame) -> u64 {
    let param1 = unsafe { get_arg0(tf) };
    let _ = &param1;
    let param2 = unsafe { get_arg1(tf) };
    let _ = &param2;
    let code = unsafe { get_arg2(tf) };
    let _ = &code;
    
    // kprintln!("[win32k] NtUserCallTwoParam")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CallTwoParam
    0
}

/// NtUserCallMsgFilter - Call message filter
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_msg_filter(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCallMsgFilter")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCallNextHookEx - Call next hook
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_next_hook_ex(tf: *mut TrapFrame) -> u64 {
    let hhk = unsafe { get_arg0(tf) };
    let _ = &hhk;
    let code = unsafe { get_arg1(tf) } as i32;
    let _ = &code;
    let wparam = unsafe { get_arg2(tf) };
    let _ = &wparam;
    let lparam = unsafe { get_arg3(tf) } as i64;
    let _ = &lparam;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserCallNextHookEx: hhk={:#x}, code={}, wparam={:#x}, lparam={:#x}",
//         _hhk, code, wparam, lparam
//     );

    // TODO: Implement actual hook chain calling
    0
}

/// NtUserRegisterClass - Register window class
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_register_class(tf: *mut TrapFrame) -> u64 {
    let wndclassexw_ptr = unsafe { get_arg0(tf) };
    let _ = &wndclassexw_ptr;
    let name_ptr = unsafe { get_arg1(tf) };
    let _ = &name_ptr;
    let instance = unsafe { get_arg2(tf) };
    let _ = &instance;
    let extra_bytes = unsafe { get_arg3(tf) };
    let _ = &extra_bytes;

    // kprintln!("[win32k] NtUserRegisterClass: wndclass=0x{:x}, name=0x{:x}, instance=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//               wndclassexw_ptr, name_ptr, instance);

    // Return ATOM value (non-zero for success)
    // A full implementation would:
    // 1. Read WNDCLASSEX structure from user memory
    // 2. Create internal WNDCLASS structure
    // 3. Add to global class table
    // 4. Return atom
    if wndclassexw_ptr != 0 {
        0xC000 | (1u16 as u64) // Return a non-zero value to indicate success
    } else {
        0
    }
}

/// NtUserUnregisterClass - Unregister window class
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_unregister_class(tf: *mut TrapFrame) -> u64 {
    let name_ptr = unsafe { get_arg0(tf) };
    let _ = &name_ptr;
    let instance = unsafe { get_arg1(tf) };
    let _ = &instance;
    let extra_bytes = unsafe { get_arg2(tf) };
    let _ = &extra_bytes;

    // kprintln!("[win32k] NtUserUnregisterClass: name=0x{:x}, instance=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//               name_ptr, instance);

    // Return TRUE if successful
    1
}

/// NtUserGetClassName - Get window class name
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_class_name(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let buffer_ptr = unsafe { get_arg1(tf) };
    let _ = &buffer_ptr;
    let buffer_size = unsafe { get_arg2(tf) } as i32;
    let _ = &buffer_size;

    // kprintln!("[win32k] NtUserGetClassName: hwnd=0x{:x}, buffer=0x{:x}, size={}",  // kprintln disabled (memcpy crash workaround)
//               hwnd, buffer_ptr, buffer_size);

    // Return 0 (failure) if buffer pointer is null
    // A full implementation would get class name from window
    if buffer_ptr == 0 || buffer_size == 0 {
        return 0;
    }

    // Return the number of characters copied
    0
}

/// NtUserGetProp - Get window property
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_prop(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let s = unsafe { get_arg1(tf) };
    let _ = &s;
    
    // kprintln!("[win32k] NtUserGetProp")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetProp
    0
}

/// NtUserSetProp - Set window property
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_prop(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let s = unsafe { get_arg1(tf) };
    let _ = &s;
    let data = unsafe { get_arg2(tf) };
    let _ = &data;
    
    // kprintln!("[win32k] NtUserSetProp")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetProp
    0
}

/// NtUserRedrawWindow - Redraw window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_redraw_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    let hrgn_update = unsafe { get_arg2(tf) };
    let _ = &hrgn_update;
    let flags = unsafe { get_arg3(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserRedrawWindow")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual RedrawWindow
    1 // TRUE
}

/// NtUserValidateRect - Validate rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_validate_rect(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    
    // kprintln!("[win32k] NtUserValidateRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ValidateRect
    1 // TRUE
}

/// NtUserValidateRgn - Validate region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_validate_rgn(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserValidateRgn")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetUpdateRect - Get update rectangle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_update_rect(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let rect = unsafe { get_arg1(tf) };
    let _ = &rect;
    let erase = unsafe { get_arg2(tf) };
    let _ = &erase;
    
    // kprintln!("[win32k] NtUserGetUpdateRect")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetUpdateRect
    0
}

/// NtUserGetUpdateRgn - Get update region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_update_rgn(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetUpdateRgn")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCreateCaret - Create caret
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_caret(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let bitmap = unsafe { get_arg1(tf) };
    let _ = &bitmap;
    let width = unsafe { get_arg2(tf) };
    let _ = &width;
    let height = unsafe { get_arg3(tf) };
    let _ = &height;
    
    // kprintln!("[win32k] NtUserCreateCaret")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CreateCaret
    1 // TRUE
}

/// NtUserShowCaret - Show caret
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_show_caret(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserShowCaret")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ShowCaret
    1 // TRUE
}

/// NtUserHideCaret - Hide caret
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_hide_caret(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserHideCaret")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual HideCaret
    1 // TRUE
}

/// NtUserEndDeferWindowPosEx - End defer window position (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_end_defer_window_pos_ex(tf: *mut TrapFrame) -> u64 {
    let h_wnd_pos_info = unsafe { get_arg0(tf) };
    let _ = &h_wnd_pos_info;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserEndDeferWindowPosEx")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual EndDeferWindowPosEx
    1 // TRUE
}

/// NtUserDeferWindowPos - Defer window position
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_defer_window_pos(tf: *mut TrapFrame) -> u64 {
    let h_wnd_pos_info = unsafe { get_arg0(tf) };
    let _ = &h_wnd_pos_info;
    let hwnd = unsafe { get_arg1(tf) };
    let _ = &hwnd;
    let hwnd_insert_after = unsafe { get_arg2(tf) };
    let _ = &hwnd_insert_after;
    let x = unsafe { get_arg3(tf) };
    let _ = &x;
    let y = unsafe { get_arg4(tf) };
    let _ = &y;
    let cx = unsafe { get_arg5(tf) };
    let _ = &cx;
    let cy = unsafe { get_arg6(tf) };
    let _ = &cy;
    let flags = unsafe { get_arg7(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserDeferWindowPos")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DeferWindowPos
    0
}

/// NtUserRegisterWindowMessage - Register window message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_register_window_message(tf: *mut TrapFrame) -> u64 {
    let s = unsafe { get_arg0(tf) };
    let _ = &s;
    
    // kprintln!("[win32k] NtUserRegisterWindowMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual RegisterWindowMessage
    0
}

/// NtUserSendMessage - Send message to window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_send_message(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(tf) } as u32;
    let _ = &msg;
    let w_param = unsafe { get_arg2(tf) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(tf) };
    let _ = &l_param;
    
    // kprintln!("[win32k] NtUserSendMessage: hwnd=0x{:x}, msg={:#x}, wparam=0x{:x}, lparam=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, msg, w_param, l_param);
    
    // For WM_QUIT, return 0
    if msg == 0x0012 {
        return 0;
    }
    
    // Call the default window procedure for the window
    let result = crate::libs::win32k::message::default_wndproc(hwnd, msg, w_param, l_param as i64);
    let _ = &result;
    
    // kprintln!("[win32k] NtUserSendMessage: result=0x{:x}", result as u64)  // kprintln disabled (memcpy crash workaround);
    result as u64
}

/// NtUserPostThreadMessage - Post thread message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_post_thread_message(tf: *mut TrapFrame) -> u64 {
    let id_thread = unsafe { get_arg0(tf) };
    let _ = &id_thread;
    let msg = unsafe { get_arg1(tf) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(tf) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(tf) };
    let _ = &l_param;
    
    // kprintln!("[win32k] NtUserPostThreadMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual PostThreadMessage
    1 // TRUE
}

/// NtUserReplyMessage - Reply to GetMessage
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_reply_message(tf: *mut TrapFrame) -> u64 {
    let result = unsafe { get_arg0(tf) };
    let _ = &result;
    
    // kprintln!("[win32k] NtUserReplyMessage")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ReplyMessage
    0
}

/// NtUserWindowFromPoint - Get window from point
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_window_from_point(tf: *mut TrapFrame) -> u64 {
    let x = unsafe { get_arg0(tf) };
    let _ = &x;
    let y = unsafe { get_arg1(tf) };
    let _ = &y;
    
    // kprintln!("[win32k] NtUserWindowFromPoint")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual WindowFromPoint
    0
}

/// NtUserFindWindowEx - Find window (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_find_window_ex(tf: *mut TrapFrame) -> u64 {
    let hwnd_parent = unsafe { get_arg0(tf) };
    let _ = &hwnd_parent;
    let hwnd_child_after = unsafe { get_arg1(tf) };
    let _ = &hwnd_child_after;
    let class_name = unsafe { get_arg2(tf) };
    let _ = &class_name;
    let window_name = unsafe { get_arg3(tf) };
    let _ = &window_name;
    let flags = unsafe { get_arg4(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserFindWindowEx")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual FindWindowEx
    0
}

/// NtUserFindWindow - Find window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_find_window(tf: *mut TrapFrame) -> u64 {
    let class_name = unsafe { get_arg0(tf) };
    let _ = &class_name;
    let window_name = unsafe { get_arg1(tf) };
    let _ = &window_name;
    
    // kprintln!("[win32k] NtUserFindWindow")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual FindWindow
    0
}

/// NtUserSetParent - Set parent window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_parent(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hwnd_new_parent = unsafe { get_arg1(tf) };
    let _ = &hwnd_new_parent;
    
    // kprintln!("[win32k] NtUserSetParent: hwnd=0x{:x}, new_parent=0x{:x}",  // kprintln disabled (memcpy crash workaround)
//         hwnd, hwnd_new_parent);
    
    // For now, return the old parent (0)
    // Full implementation would modify window's parent
    0
}

/// NtUserGetActiveWindow - Get active window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_active_window(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetActiveWindow")  // kprintln disabled (memcpy crash workaround);
    
    // Return the current active window handle
    crate::libs::win32k::window::get_active_window_internal()
}

/// NtUserSetActiveWindow - Set active window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_active_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserSetActiveWindow")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetActiveWindow
    0
}

/// NtUserGetFocus - Get focus window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_focus(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetFocus")  // kprintln disabled (memcpy crash workaround);
    
    // Return the current focus window handle
    crate::libs::win32k::window::get_focus_internal()
}

/// NtUserReleaseCapture - Release capture
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_release_capture(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserReleaseCapture")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ReleaseCapture
    1 // TRUE
}

/// NtUserSetWindowLong - Set window long
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_long(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let new_long = unsafe { get_arg2(tf) };
    let _ = &new_long;
    
    // kprintln!("[win32k] NtUserSetWindowLong")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetWindowLong
    0
}

/// NtUserGetControlBrush - Get control brush
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_control_brush(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let color = unsafe { get_arg1(tf) };
    let _ = &color;
    let r#type = unsafe { get_arg2(tf) };
    let _ = &r#type;
    
    // kprintln!("[win32k] NtUserGetControlBrush")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetControlBrush
    0
}

/// NtUserDrawIconEx - Draw icon extended
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_draw_icon_ex(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserDrawIconEx")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetSystemMenu - Get system menu
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_system_menu(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let revert = unsafe { get_arg1(tf) };
    let _ = &revert;
    
    // kprintln!("[win32k] NtUserGetSystemMenu")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetSystemMenu
    0
}

/// NtUserInternalGetWindowText - Internal get window text
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_internal_get_window_text(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserInternalGetWindowText")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetWindowDC - Get window DC
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_window_dc(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserGetWindowDC")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetWindowDC
    0
}

/// NtUserScrollDC - Scroll DC
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_scroll_dc(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let dx = unsafe { get_arg1(tf) };
    let _ = &dx;
    let dy = unsafe { get_arg2(tf) };
    let _ = &dy;
    let scroll_rect = unsafe { get_arg3(tf) };
    let _ = &scroll_rect;
    let clip_rect = unsafe { get_arg4(tf) };
    let _ = &clip_rect;
    let hrgn_update = unsafe { get_arg5(tf) };
    let _ = &hrgn_update;
    let prgn_update = unsafe { get_arg6(tf) };
    let _ = &prgn_update;
    
    // kprintln!("[win32k] NtUserScrollDC")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ScrollDC
    0
}

/// NtUserGetObjectInformation - Get object information
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_object_information(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetObjectInformation")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserUnhookWindowsHookEx - Unhook windows hook (extended) (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_unhook_windows_hook_ex(tf: *mut TrapFrame) -> u64 {
    let hhk = unsafe { get_arg0(tf) };
    let _ = &hhk;

    // kprintln!("[win32k] NtUserUnhookWindowsHookEx: hhk={:#x}", hhk)  // kprintln disabled (memcpy crash workaround);

    if hhk == 0 {
        return 0;
    }

    if win32k_helpers::remove_hook(hhk) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserNotifyProcessCreate - Notify process create
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_notify_process_create(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserNotifyProcessCreate")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetTitleBarInfo - Get title bar info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_title_bar_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetTitleBarInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetThreadDesktop - Set thread desktop
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_thread_desktop(tf: *mut TrapFrame) -> u64 {
    let h_desk = unsafe { get_arg0(tf) };
    let _ = &h_desk;
    
    // kprintln!("[win32k] NtUserSetThreadDesktop")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetThreadDesktop
    0
}

/// NtUserGetScrollBarInfo - Get scroll bar info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_scroll_bar_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetScrollBarInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetWindowFNID - Set window FNID
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_fnid(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserSetWindowFNID")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCalcMenuBar - Calculate menu bar
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_calc_menu_bar(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let x = unsafe { get_arg1(tf) };
    let _ = &x;
    let y = unsafe { get_arg2(tf) };
    let _ = &y;
    let flags = unsafe { get_arg3(tf) };
    let _ = &flags;
    let p_rect = unsafe { get_arg4(tf) };
    let _ = &p_rect;
    
    // kprintln!("[win32k] NtUserCalcMenuBar")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CalcMenuBar
    0
}

/// NtUserThunkedMenuItemInfo - Thunked menu item info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_thunked_menu_item_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserThunkedMenuItemInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserOpenWindowStation - Open window station
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_open_window_station(tf: *mut TrapFrame) -> u64 {
    let s = unsafe { get_arg0(tf) };
    let _ = &s;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserOpenWindowStation")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual OpenWindowStation
    0
}

/// NtUserCloseDesktop - Close desktop
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_close_desktop(tf: *mut TrapFrame) -> u64 {
    let h_desk = unsafe { get_arg0(tf) };
    let _ = &h_desk;
    
    // kprintln!("[win32k] NtUserCloseDesktop")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CloseDesktop
    0
}

/// NtUserOpenDesktop - Open desktop
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_open_desktop(tf: *mut TrapFrame) -> u64 {
    let s = unsafe { get_arg0(tf) };
    let _ = &s;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    let access = unsafe { get_arg2(tf) };
    let _ = &access;
    let valid_apps = unsafe { get_arg3(tf) };
    let _ = &valid_apps;
    
    // kprintln!("[win32k] NtUserOpenDesktop")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual OpenDesktop
    0
}

/// NtUserSetProcessWindowStation - Set process window station
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_process_window_station(tf: *mut TrapFrame) -> u64 {
    let h_win_sta = unsafe { get_arg0(tf) };
    let _ = &h_win_sta;
    
    // kprintln!("[win32k] NtUserSetProcessWindowStation")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetProcessWindowStation
    0
}

/// NtUserGetAtomName - Get atom name
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_atom_name(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetAtomName")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetCursorIconData - Set cursor icon data
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_cursor_icon_data(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserSetCursorIconData")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserRegisterClassExWOW - Register class (extended WOW)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_register_class_ex_wow(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserRegisterClassExWOW")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetAncestor - Get ancestor window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_ancestor(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let ga_flags = unsafe { get_arg1(tf) };
    let _ = &ga_flags;
    
    // kprintln!("[win32k] NtUserGetAncestor")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetAncestor
    0
}

/// NtUserCloseWindowStation - Close window station
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_close_window_station(tf: *mut TrapFrame) -> u64 {
    let h_win_sta = unsafe { get_arg0(tf) };
    let _ = &h_win_sta;
    
    // kprintln!("[win32k] NtUserCloseWindowStation")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual CloseWindowStation
    0
}

/// NtUserGetDoubleClickTime - Get double click time
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_double_click_time(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetDoubleClickTime")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetDoubleClickTime
    500 // Default double-click time
}

/// NtUserEnableScrollBar - Enable scroll bar
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_enable_scroll_bar(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserEnableScrollBar")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetClassInfoEx - Get class info (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_class_info_ex(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetClassInfoEx")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserDeleteMenu - Delete menu item (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_delete_menu(tf: *mut TrapFrame) -> u64 {
    let h_menu = unsafe { get_arg0(tf) };
    let _ = &h_menu;
    let u_position = unsafe { get_arg1(tf) };
    let _ = &u_position;
    let u_flags = unsafe { get_arg2(tf) };
    let _ = &u_flags;

    // kprintln!("[win32k] NtUserDeleteMenu: hmenu={:#x}, pos={}, flags={:#x}",  // kprintln disabled (memcpy crash workaround)
//               _h_menu, _u_position, _u_flags);

    // TODO: Implement actual DeleteMenu (remove item from menu)
    1 // TRUE
}

/// NtUserScrollWindowEx - Scroll window (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_scroll_window_ex(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserScrollWindowEx")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetClassLong - Set class long
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_class_long(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let new_long = unsafe { get_arg2(tf) };
    let _ = &new_long;
    let dw_extra = unsafe { get_arg3(tf) };
    let _ = &dw_extra;
    
    // kprintln!("[win32k] NtUserSetClassLong")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual SetClassLong
    0
}

/// NtUserGetMenuBarInfo - Get menu bar info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_menu_bar_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetMenuBarInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetClipboardSequenceNumber - Get clipboard sequence number
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_clipboard_sequence_number(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetClipboardSequenceNumber")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetClipboardSequenceNumber
    0
}

/// NtUserGetKeyboardLayoutList - Get keyboard layout list
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_keyboard_layout_list(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetKeyboardLayoutList")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserMapVirtualKeyEx - Map virtual key (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_map_virtual_key_ex(tf: *mut TrapFrame) -> u64 {
    let code = unsafe { get_arg0(tf) };
    let _ = &code;
    let map_type = unsafe { get_arg1(tf) };
    let _ = &map_type;
    let hkl = unsafe { get_arg2(tf) };
    let _ = &hkl;
    
    // kprintln!("[win32k] NtUserMapVirtualKeyEx")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual MapVirtualKeyEx
    0
}

/// NtUserToUnicodeEx - Convert to unicode (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_to_unicode_ex(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserToUnicodeEx")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserDefSetText - Default set text
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_def_set_text(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserDefSetText")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetThreadDesktop - Get thread desktop
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_thread_desktop(tf: *mut TrapFrame) -> u64 {
    let thread_id = unsafe { get_arg0(tf) };
    let _ = &thread_id;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserGetThreadDesktop")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetThreadDesktop
    0
}

/// NtUserGetIconSize - Get icon size
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_icon_size(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let r#type = unsafe { get_arg1(tf) };
    let _ = &r#type;
    let cx = unsafe { get_arg2(tf) };
    let _ = &cx;
    let cy = unsafe { get_arg3(tf) };
    let _ = &cy;
    
    // kprintln!("[win32k] NtUserGetIconSize")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetIconSize
    0
}

/// NtUserFillWindow - Fill window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_fill_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let h_dc = unsafe { get_arg1(tf) };
    let _ = &h_dc;
    let brush = unsafe { get_arg2(tf) };
    let _ = &brush;
    let result = unsafe { get_arg3(tf) };
    let _ = &result;
    
    // kprintln!("[win32k] NtUserFillWindow")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual FillWindow
    0
}

/// NtUserSetWindowsHookEx - Set windows hook (extended) (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_windows_hook_ex(tf: *mut TrapFrame) -> u64 {
    let id_hook = unsafe { get_arg0(tf) } as i32;
    let _ = &id_hook;
    let lpfn = unsafe { get_arg1(tf) };
    let _ = &lpfn;
    let mod_name = unsafe { get_arg2(tf) };
    let _ = &mod_name;
    let thread_id = unsafe { get_arg3(tf) } as u32;
    let _ = &thread_id;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserSetWindowsHookEx: type={}, proc={:#x}, thread_id={}",
//         id_hook, lpfn, thread_id
//     );

    // Install the hook using the hook system
    match win32k_helpers::install_hook(id_hook, lpfn, thread_id) {
        Some(handle) => handle,
        None => 0,
    }
}

/// NtUserExcludeUpdateRgn - Exclude update region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_exclude_update_rgn(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let hwnd = unsafe { get_arg1(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserExcludeUpdateRgn")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual ExcludeUpdateRgn
    0
}

/// NtUserCallHwndParam - Call with hwnd and param
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_hwnd_param(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCallHwndParam")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetIconInfo - Get icon info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_icon_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetIconInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSBGetParms - Get scroll bar parameters
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_sb_get_parms(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserSBGetParms")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserDestroyCursor - Destroy cursor
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_destroy_cursor(tf: *mut TrapFrame) -> u64 {
    let hcur = unsafe { get_arg0(tf) };
    let _ = &hcur;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserDestroyCursor")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual DestroyCursor
    1 // TRUE
}

/// NtUserMessageCall - Message call
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_message_call(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(tf) };
    let _ = &msg;
    let w_param = unsafe { get_arg2(tf) };
    let _ = &w_param;
    let l_param = unsafe { get_arg3(tf) };
    let _ = &l_param;
    let msg_fu_flags = unsafe { get_arg4(tf) };
    let _ = &msg_fu_flags;
    let info = unsafe { get_arg5(tf) };
    let _ = &info;
    
    // kprintln!("[win32k] NtUserMessageCall")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual MessageCall
    0
}

/// NtUserEndMenu - End menu
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_end_menu(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserEndMenu")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual EndMenu
    1 // TRUE
}

/// NtUserQueryWindow - Query window info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_query_window(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let cmd = unsafe { get_arg1(tf) };
    let _ = &cmd;
    
    // kprintln!("[win32k] NtUserQueryWindow")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual QueryWindow
    0
}

/// NtUserTranslateAccelerator - Translate accelerator
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_translate_accelerator(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserTranslateAccelerator")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserValidateTimerCallback - Validate timer callback
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_validate_timer_callback(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserValidateTimerCallback")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserBeginPaint - Begin paint
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_begin_paint(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let paint = unsafe { get_arg1(tf) };
    let _ = &paint;
    
    // kprintln!("[win32k] NtUserBeginPaint")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual BeginPaint
    0
}

/// NtUserEndPaint - End paint
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_end_paint(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let paint = unsafe { get_arg1(tf) };
    let _ = &paint;
    
    // kprintln!("[win32k] NtUserEndPaint")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual EndPaint
    1 // TRUE
}

/// NtUserBuildHwndList - Build window list
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_build_hwnd_list(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserBuildHwndList")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserBuildNameList - Build window name list
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_build_name_list(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let names_ptr = unsafe { get_arg1(tf) };
    let _ = &names_ptr;
    let max_count = unsafe { get_arg2(tf) };
    let _ = &max_count;
    
    // kprintln!("[win32k] NtUserBuildNameList: hwnd=0x{:x}, names=0x{:x}, max={}", hwnd, names_ptr, max_count)  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual BuildNameList
    0
}

/// NtUserCallHwndLock - Call with hwnd lock
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_hwnd_lock(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCallHwndLock")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetProcessWindowStation - Get process window station
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_process_window_station(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetProcessWindowStation")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetProcessWindowStation
    0
}

/// NtUserCallHwndParamLock - Call with hwnd and param lock
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_hwnd_param_lock(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCallHwndParamLock")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserVkKeyScanEx - Virtual key scan (extended)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_vk_key_scan_ex(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserVkKeyScanEx")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCopyAcceleratorTable - Copy accelerator table
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_copy_accelerator_table(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCopyAcceleratorTable")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserNotifyWinEvent - Notify win event
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_notify_win_event(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserNotifyWinEvent")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserIsClipboardFormatAvailable - Check clipboard format
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_is_clipboard_format_available(tf: *mut TrapFrame) -> u64 {
    let format = unsafe { get_arg0(tf) };
    let _ = &format;
    
    // kprintln!("[win32k] NtUserIsClipboardFormatAvailable")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual IsClipboardFormatAvailable
    0
}

/// NtUserSetScrollInfo - Set scroll info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_scroll_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserSetScrollInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSelectPalette - Select palette
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_select_palette(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserSelectPalette")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserRemoveProp - Remove property
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_remove_prop(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserRemoveProp")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserRegisterHotKey - Register hot key
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_register_hot_key(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let id = unsafe { get_arg1(tf) };
    let _ = &id;
    let fs_modifiers = unsafe { get_arg2(tf) };
    let _ = &fs_modifiers;
    let vk = unsafe { get_arg3(tf) };
    let _ = &vk;
    
    // kprintln!("[win32k] NtUserRegisterHotKey")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual RegisterHotKey
    0
}

/// NtUserUnregisterHotKey - Unregister hot key
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_unregister_hot_key(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let id = unsafe { get_arg1(tf) };
    let _ = &id;
    
    // kprintln!("[win32k] NtUserUnregisterHotKey")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual UnregisterHotKey
    1 // TRUE
}

/// NtUserGetCursorInfo - Get cursor info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_cursor_info(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCursorInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserShowScrollBar - Show scroll bar
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_show_scroll_bar(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserShowScrollBar")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserFindExistingCursorIcon - Find existing cursor icon
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_find_existing_cursor_icon(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserFindExistingCursorIcon")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetKeyboardType - Get keyboard type
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_keyboard_type(tf: *mut TrapFrame) -> u64 {
    let type_flag = unsafe { get_arg0(tf) };
    let _ = &type_flag;
    
    // kprintln!("[win32k] NtUserGetKeyboardType")  // kprintln disabled (memcpy crash workaround);
    
    // TODO: Implement actual GetKeyboardType
    match type_flag as i32 {
        0 => 4, // KEYBOARD_TYPE_GENERIC
        1 => 1, // KEYBOARD_TYPE_I8042
        2 => 4, // KEYBOARD_TYPE_XLATE
        _ => 0,
    }
}

// =============================================================================
// Additional USER Syscall Handlers
// =============================================================================

/// NtUserBitBltSysBmp - BitBlt to system bitmap
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_bit_blt_sys_bmp(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg1(tf) };
    let _ = &x;
    let y = unsafe { get_arg2(tf) };
    let _ = &y;
    let cx = unsafe { get_arg3(tf) };
    let _ = &cx;
    let cy = unsafe { get_arg4(tf) };
    let _ = &cy;
    let rop = unsafe { get_arg5(tf) };
    let _ = &rop;
    
    // kprintln!("[win32k] NtUserBitBltSysBmp")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserInvalidateRgn - Invalidate region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_invalidate_rgn(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hrgn = unsafe { get_arg1(tf) };
    let _ = &hrgn;
    let erase = unsafe { get_arg2(tf) };
    let _ = &erase;
    
    // kprintln!("[win32k] NtUserInvalidateRgn")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetClipboardOwner - Get clipboard owner window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_clipboard_owner(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetClipboardOwner")  // kprintln disabled (memcpy crash workaround);
    0 // NULL
}

/// NtUserSetWindowRgn - Set window region
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_rgn(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hrgn = unsafe { get_arg1(tf) };
    let _ = &hrgn;
    let redraw = unsafe { get_arg2(tf) };
    let _ = &redraw;
    
    // kprintln!("[win32k] NtUserSetWindowRgn")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserOpenClipboard - Open clipboard
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_open_clipboard(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;

    // kprintln!("[win32k] NtUserOpenClipboard: hwnd=0x{:x}", hwnd)  // kprintln disabled (memcpy crash workaround);

    if crate::libs::win32k::clipboard::open_clipboard(hwnd) {
        1 // TRUE
    } else {
        0 // FALSE - already open
    }
}

/// NtUserCloseClipboard - Close clipboard
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_close_clipboard(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCloseClipboard")  // kprintln disabled (memcpy crash workaround);

    if crate::libs::win32k::clipboard::close_clipboard() {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserEmptyClipboard - Empty clipboard
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_empty_clipboard(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserEmptyClipboard")  // kprintln disabled (memcpy crash workaround);

    if crate::libs::win32k::clipboard::empty_clipboard() {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

/// NtUserSetClipboardData - Set clipboard data
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_clipboard_data(tf: *mut TrapFrame) -> u64 {
    let format = unsafe { get_arg0(tf) };
    let _ = &format;
    let hdata = unsafe { get_arg1(tf) };
    let _ = &hdata;
    
    // kprintln!("[win32k] NtUserSetClipboardData")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserEnableMenuItem - Enable/disable menu item
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_enable_menu_item(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    let id = unsafe { get_arg1(tf) };
    let _ = &id;
    let enable = unsafe { get_arg2(tf) };
    let _ = &enable;
    
    // kprintln!("[win32k] NtUserEnableMenuItem")  // kprintln disabled (memcpy crash workaround);
    0 // MF_BYCOMMAND
}

/// NtUserAlterWindowStyle - Alter window style
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_alter_window_style(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let remove = unsafe { get_arg1(tf) };
    let _ = &remove;
    let add = unsafe { get_arg2(tf) };
    let _ = &add;
    
    // kprintln!("[win32k] NtUserAlterWindowStyle")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetWindowPlacement - Get window placement
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_window_placement(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let placement = unsafe { get_arg1(tf) };
    let _ = &placement;
    
    // kprintln!("[win32k] NtUserGetWindowPlacement")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetOpenClipboardWindow - Get open clipboard window
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_open_clipboard_window(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetOpenClipboardWindow")  // kprintln disabled (memcpy crash workaround);
    0 // NULL
}

/// NtUserSetThreadState - Set thread state
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_thread_state(tf: *mut TrapFrame) -> u64 {
    let state = unsafe { get_arg0(tf) };
    let _ = &state;
    
    // kprintln!("[win32k] NtUserSetThreadState")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserTrackMouseEvent - Track mouse event
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_track_mouse_event(tf: *mut TrapFrame) -> u64 {
    let event = unsafe { get_arg0(tf) };
    let _ = &event;
    
    // kprintln!("[win32k] NtUserTrackMouseEvent")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserDestroyMenu - Destroy menu
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_destroy_menu(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    
    // kprintln!("[win32k] NtUserDestroyMenu")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserConsoleControl - Console control
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_console_control(tf: *mut TrapFrame) -> u64 {
    let code = unsafe { get_arg0(tf) };
    let _ = &code;
    let in_data = unsafe { get_arg1(tf) };
    let _ = &in_data;
    let out_data = unsafe { get_arg2(tf) };
    let _ = &out_data;
    
    // kprintln!("[win32k] NtUserConsoleControl")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetInformationThread - Set thread information
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_information_thread(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let info_class = unsafe { get_arg1(tf) };
    let _ = &info_class;
    let info = unsafe { get_arg2(tf) };
    let _ = &info;
    let length = unsafe { get_arg3(tf) };
    let _ = &length;
    
    // kprintln!("[win32k] NtUserSetInformationThread")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserSetWindowPlacement - Set window placement
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_placement(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let placement = unsafe { get_arg1(tf) };
    let _ = &placement;
    
    // kprintln!("[win32k] NtUserSetWindowPlacement")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetControlColor - Get control color
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_control_color(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hdc = unsafe { get_arg1(tf) };
    let _ = &hdc;
    let class = unsafe { get_arg2(tf) };
    let _ = &class;
    
    // kprintln!("[win32k] NtUserGetControlColor")  // kprintln disabled (memcpy crash workaround);
    0 // Default brush
}

/// NtUserSetWindowWord - Set window word
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_window_word(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let value = unsafe { get_arg2(tf) };
    let _ = &value;
    
    // kprintln!("[win32k] NtUserSetWindowWord")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetClipboardFormatName - Get clipboard format name
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_clipboard_format_name(tf: *mut TrapFrame) -> u64 {
    let format = unsafe { get_arg0(tf) };
    let _ = &format;
    let buffer = unsafe { get_arg1(tf) };
    let _ = &buffer;
    let buffer_size = unsafe { get_arg2(tf) };
    let _ = &buffer_size;
    
    // kprintln!("[win32k] NtUserGetClipboardFormatName")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserRealInternalGetMessage - Real internal get message
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_real_internal_get_message(tf: *mut TrapFrame) -> u64 {
    let msg = unsafe { get_arg0(tf) };
    let _ = &msg;
    let hwnd = unsafe { get_arg1(tf) };
    let _ = &hwnd;
    let msg_min = unsafe { get_arg2(tf) };
    let _ = &msg_min;
    let msg_max = unsafe { get_arg3(tf) };
    let _ = &msg_max;
    let flags = unsafe { get_arg4(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserRealInternalGetMessage")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCreateLocalMemHandle - Create local memory handle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_local_mem_handle(tf: *mut TrapFrame) -> u64 {
    let addr = unsafe { get_arg0(tf) };
    let _ = &addr;
    let size = unsafe { get_arg1(tf) };
    let _ = &size;
    
    // kprintln!("[win32k] NtUserCreateLocalMemHandle")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserAttachThreadInput - Attach thread input
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_attach_thread_input(tf: *mut TrapFrame) -> u64 {
    let attach_from = unsafe { get_arg0(tf) };
    let _ = &attach_from;
    let attach_to = unsafe { get_arg1(tf) };
    let _ = &attach_to;
    let attach = unsafe { get_arg2(tf) };
    let _ = &attach;
    
    // kprintln!("[win32k] NtUserAttachThreadInput")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserPaintMenuBar - Paint menu bar
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_paint_menu_bar(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hdc = unsafe { get_arg1(tf) };
    let _ = &hdc;
    let x = unsafe { get_arg2(tf) };
    let _ = &x;
    let y = unsafe { get_arg3(tf) };
    let _ = &y;
    let cx = unsafe { get_arg4(tf) };
    let _ = &cx;
    let cy = unsafe { get_arg5(tf) };
    let _ = &cy;
    
    // kprintln!("[win32k] NtUserPaintMenuBar")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCreateAcceleratorTable - Create accelerator table
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_accelerator_table(tf: *mut TrapFrame) -> u64 {
    let table = unsafe { get_arg0(tf) };
    let _ = &table;
    
    // kprintln!("[win32k] NtUserCreateAcceleratorTable")  // kprintln disabled (memcpy crash workaround);
    0 // NULL
}

/// NtUserGetCursorFrameInfo - Get cursor frame info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_cursor_frame_info(tf: *mut TrapFrame) -> u64 {
    let hcur = unsafe { get_arg0(tf) };
    let _ = &hcur;
    let frame = unsafe { get_arg1(tf) };
    let _ = &frame;
    
    // kprintln!("[win32k] NtUserGetCursorFrameInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetAltTabInfo - Get alt-tab info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_alt_tab_info(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let info = unsafe { get_arg1(tf) };
    let _ = &info;
    
    // kprintln!("[win32k] NtUserGetAltTabInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserGetCaretBlinkTime - Get caret blink time
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_caret_blink_time(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserGetCaretBlinkTime")  // kprintln disabled (memcpy crash workaround);
    530 // Default blink time
}

/// NtUserProcessConnect - Process connect
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_process_connect(tf: *mut TrapFrame) -> u64 {
    let process = unsafe { get_arg0(tf) };
    let _ = &process;
    let conn_info = unsafe { get_arg1(tf) };
    let _ = &conn_info;
    let size = unsafe { get_arg2(tf) };
    let _ = &size;
    
    // kprintln!("[win32k] NtUserProcessConnect")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserEnumDisplayDevices - Enum display devices
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_enum_display_devices(tf: *mut TrapFrame) -> u64 {
    let device = unsafe { get_arg0(tf) };
    let _ = &device;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let info = unsafe { get_arg2(tf) };
    let _ = &info;
    let flags = unsafe { get_arg3(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserEnumDisplayDevices")  // kprintln disabled (memcpy crash workaround);
    0 // FALSE (no more devices)
}

/// NtUserGetClipboardData - Get clipboard data
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_clipboard_data(tf: *mut TrapFrame) -> u64 {
    let format = unsafe { get_arg0(tf) };
    let _ = &format;
    
    // kprintln!("[win32k] NtUserGetClipboardData")  // kprintln disabled (memcpy crash workaround);
    0 // NULL
}

/// NtUserRemoveMenu - Remove menu item
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_remove_menu(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    let pos = unsafe { get_arg1(tf) };
    let _ = &pos;
    let flags = unsafe { get_arg2(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserRemoveMenu")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserConvertMemHandle - Convert memory handle
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_convert_mem_handle(tf: *mut TrapFrame) -> u64 {
    let handle = unsafe { get_arg0(tf) };
    let _ = &handle;
    
    // kprintln!("[win32k] NtUserConvertMemHandle")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserDestroyAcceleratorTable - Destroy accelerator table
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_destroy_accelerator_table(tf: *mut TrapFrame) -> u64 {
    let table = unsafe { get_arg0(tf) };
    let _ = &table;
    
    // kprintln!("[win32k] NtUserDestroyAcceleratorTable")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserGetGUIThreadInfo - Get GUI thread info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_gui_thread_info(tf: *mut TrapFrame) -> u64 {
    let thread_id = unsafe { get_arg0(tf) };
    let _ = &thread_id;
    let info = unsafe { get_arg1(tf) };
    let _ = &info;
    
    // kprintln!("[win32k] NtUserGetGUIThreadInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserSetWindowsHookAW - Set windows hook ANSI/Wide (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_windows_hook_aw(tf: *mut TrapFrame) -> u64 {
    let id_hook = unsafe { get_arg0(tf) } as i32;
    let _ = &id_hook;
    let lpfn = unsafe { get_arg1(tf) };
    let _ = &lpfn;
    let flags = unsafe { get_arg2(tf) };
    let _ = &flags;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserSetWindowsHookAW: type={}, proc={:#x}",
//         id_hook, lpfn
//     );

    // Install the hook (similar to SetWindowsHookEx)
    match win32k_helpers::install_hook(id_hook, lpfn, 0) {
        Some(handle) => handle,
        None => 0,
    }
}

/// NtUserSetMenuDefaultItem - Set menu default item
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_menu_default_item(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    let item = unsafe { get_arg1(tf) };
    let _ = &item;
    let by_pos = unsafe { get_arg2(tf) };
    let _ = &by_pos;

    // kprintln!("[win32k] NtUserSetMenuDefaultItem")  // kprintln disabled (memcpy crash workaround);
    0 // Previous default
}

/// NtUserCheckMenuItem - Check menu item
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_check_menu_item(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    let id = unsafe { get_arg1(tf) };
    let _ = &id;
    let check = unsafe { get_arg2(tf) };
    let _ = &check;

    // kprintln!("[win32k] NtUserCheckMenuItem")  // kprintln disabled (memcpy crash workaround);
    0xFFFFFFFF // MF_BYCOMMAND
}

/// NtUserLockWindowUpdate - Lock window update
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_lock_window_update(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserLockWindowUpdate")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserSetSystemMenu - Set system menu
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_system_menu(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let hmenu = unsafe { get_arg1(tf) };
    let _ = &hmenu;
    
    // kprintln!("[win32k] NtUserSetSystemMenu")  // kprintln disabled (memcpy crash workaround);
    0 // Previous menu
}

/// NtUserThunkedMenuInfo - Thunked menu info
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_thunked_menu_info(tf: *mut TrapFrame) -> u64 {
    let hmenu = unsafe { get_arg0(tf) };
    let _ = &hmenu;
    let data = unsafe { get_arg1(tf) };
    let _ = &data;
    
    // kprintln!("[win32k] NtUserThunkedMenuInfo")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserCallHwnd - Call with hwnd
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_call_hwnd(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let msg = unsafe { get_arg1(tf) };
    let _ = &msg;
    
    // kprintln!("[win32k] NtUserCallHwnd")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserDdeInitialize - DDE initialize
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_dde_initialize(tf: *mut TrapFrame) -> u64 {
    let pid = unsafe { get_arg0(tf) };
    let _ = &pid;
    let filters = unsafe { get_arg1(tf) };
    let _ = &filters;
    let flags = unsafe { get_arg2(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserDdeInitialize")  // kprintln disabled (memcpy crash workaround);
    0 // DMLERR_NO_ERROR
}

/// NtUserModifyUserStartupInfoFlags - Modify user startup info flags
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_modify_user_startup_info_flags(tf: *mut TrapFrame) -> u64 {
    let flags = unsafe { get_arg0(tf) };
    let _ = &flags;
    let enable = unsafe { get_arg1(tf) };
    let _ = &enable;
    
    // kprintln!("[win32k] NtUserModifyUserStartupInfoFlags")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserCountClipboardFormats - Count clipboard formats
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_count_clipboard_formats(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCountClipboardFormats")  // kprintln disabled (memcpy crash workaround);
    0
}

/// NtUserEnumDisplaySettings - Enum display settings
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_enum_display_settings(tf: *mut TrapFrame) -> u64 {
    let device = unsafe { get_arg0(tf) };
    let _ = &device;
    let index = unsafe { get_arg1(tf) };
    let _ = &index;
    let mode = unsafe { get_arg2(tf) };
    let _ = &mode;
    let flags = unsafe { get_arg3(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserEnumDisplaySettings")  // kprintln disabled (memcpy crash workaround);
    0 // FALSE (no more modes)
}

/// NtUserPaintDesktop - Paint desktop
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_paint_desktop(tf: *mut TrapFrame) -> u64 {
    let hdc = unsafe { get_arg0(tf) };
    let _ = &hdc;
    
    // kprintln!("[win32k] NtUserPaintDesktop")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserChangeClipboardChain - Change clipboard chain
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_change_clipboard_chain(tf: *mut TrapFrame) -> u64 {
    let remove = unsafe { get_arg0(tf) };
    let _ = &remove;
    let next = unsafe { get_arg1(tf) };
    let _ = &next;
    
    // kprintln!("[win32k] NtUserChangeClipboardChain")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserSetClipboardViewer - Set clipboard viewer
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_clipboard_viewer(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    
    // kprintln!("[win32k] NtUserSetClipboardViewer")  // kprintln disabled (memcpy crash workaround);
    0 // Previous viewer
}

/// NtUserShowWindowAsync - Show window async
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_show_window_async(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let cmd_show = unsafe { get_arg1(tf) };
    let _ = &cmd_show;
    
    // kprintln!("[win32k] NtUserShowWindowAsync")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserActivateKeyboardLayout - Activate keyboard layout
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_activate_keyboard_layout(tf: *mut TrapFrame) -> u64 {
    let hkl = unsafe { get_arg0(tf) };
    let _ = &hkl;
    let flags = unsafe { get_arg1(tf) };
    let _ = &flags;
    
    // kprintln!("[win32k] NtUserActivateKeyboardLayout")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

/// NtUserInitializeClientPfnArrays - Initialize client procedure function arrays
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_initialize_client_pfn_arrays(tf: *mut TrapFrame) -> u64 {
    let arg1 = unsafe { get_arg0(tf) };
    let _ = &arg1;
    let arg2 = unsafe { get_arg1(tf) };
    let _ = &arg2;
    let arg3 = unsafe { get_arg2(tf) };
    let _ = &arg3;
    let arg4 = unsafe { get_arg3(tf) };
    let _ = &arg4;

    // kprintln!("[win32k] NtUserInitializeClientPfnArrays")  // kprintln disabled (memcpy crash workaround);
    1 // TRUE
}

// =============================================================================
// Dialog System Syscalls (P2 Enhancement)
// =============================================================================

/// NtUserMessageBox - Display a message box (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_message_box(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let lp_text = unsafe { get_arg1(tf) };
    let _ = &lp_text;
    let lp_caption = unsafe { get_arg2(tf) };
    let _ = &lp_caption;
    let u_type = unsafe { get_arg3(tf) };
    let _ = &u_type;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
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
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_dlg_item(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(tf) };
    let _ = &n_id;

    // kprintln!("[win32k] NtUserGetDlgItem: hwnd={:#x}, id={}", _hwnd, _n_id)  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual GetDlgItem (search child windows by ID)
    0
}

/// NtUserEndDialog - End dialog (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_end_dialog(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_result = unsafe { get_arg1(tf) };
    let _ = &n_result;

    // kprintln!("[win32k] NtUserEndDialog: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual EndDialog (destroy dialog window)
    1 // TRUE
}

/// NtUserSetDlgItemInt - Set dialog item integer (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_dlg_item_int(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(tf) };
    let _ = &n_id;
    let u_value = unsafe { get_arg2(tf) };
    let _ = &u_value;
    let b_signed = unsafe { get_arg3(tf) };
    let _ = &b_signed;

    // kprintln!("[win32k] NtUserSetDlgItemInt")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual SetDlgItemInt
    1 // TRUE
}

/// NtUserGetDlgItemInt - Get dialog item integer (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_dlg_item_int(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let n_id = unsafe { get_arg1(tf) };
    let _ = &n_id;
    let lp_translated = unsafe { get_arg2(tf) };
    let _ = &lp_translated;
    let b_signed = unsafe { get_arg3(tf) };
    let _ = &b_signed;

    // kprintln!("[win32k] NtUserGetDlgItemInt")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual GetDlgItemInt
    0
}

// =============================================================================
// Additional Menu Syscalls (P2 Enhancement)
// =============================================================================

/// NtUserCreateMenu - Create menu (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_menu(tf: *mut TrapFrame) -> u64 {
    let u_flags = unsafe { get_arg0(tf) };
    let _ = &u_flags;

    // kprintln!("[win32k] NtUserCreateMenu")  // kprintln disabled (memcpy crash workaround);

    // Allocate a menu handle
    let handle = win32k_helpers::allocate_menu_handle();
    let _ = &handle;
    // kprintln!("[win32k] NtUserCreateMenu: created menu handle={:#x}", handle)  // kprintln disabled (memcpy crash workaround);
    handle
}

/// NtUserCreatePopupMenu - Create popup menu (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_create_popup_menu(_tf: *mut TrapFrame) -> u64 {
    // kprintln!("[win32k] NtUserCreatePopupMenu")  // kprintln disabled (memcpy crash workaround);

    // Allocate a menu handle with popup style
    let handle = win32k_helpers::allocate_menu_handle();
    let _ = &handle;
    // kprintln!("[win32k] NtUserCreatePopupMenu: created popup menu handle={:#x}", handle)  // kprintln disabled (memcpy crash workaround);
    handle
}

/// NtUserAppendMenu - Append menu item (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_append_menu(tf: *mut TrapFrame) -> u64 {
    let h_menu = unsafe { get_arg0(tf) };
    let _ = &h_menu;
    let u_flags = unsafe { get_arg1(tf) };
    let _ = &u_flags;
    let u_id_new_item = unsafe { get_arg2(tf) };
    let _ = &u_id_new_item;
    let lp_new_item = unsafe { get_arg3(tf) };
    let _ = &lp_new_item;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserAppendMenu: hmenu={:#x}, flags={:#x}, id={}",
//         _h_menu, _u_flags, _u_id_new_item
//     );

    // TODO: Implement actual AppendMenu (add item to menu)
    1 // TRUE
}

/// NtUserTrackPopupMenu - Track popup menu (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_track_popup_menu(tf: *mut TrapFrame) -> u64 {
    let h_menu = unsafe { get_arg0(tf) };
    let _ = &h_menu;
    let u_flags = unsafe { get_arg1(tf) };
    let _ = &u_flags;
    let x = unsafe { get_arg2(tf) } as i32;
    let _ = &x;
    let y = unsafe { get_arg3(tf) } as i32;
    let _ = &y;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserTrackPopupMenu: hmenu={:#x}, x={}, y={}",
//         _h_menu, _x, _y
//     );

    // TODO: Implement actual TrackPopupMenu (display popup menu)
    0
}

/// NtUserGetMenu - Get window menu (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_get_menu(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;

    // kprintln!("[win32k] NtUserGetMenu: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual GetMenu (get menu from window)
    0
}

/// NtUserSetMenu - Set window menu (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_menu(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;
    let h_menu = unsafe { get_arg1(tf) };
    let _ = &h_menu;

    // kprintln!("[win32k] NtUserSetMenu: hwnd={:#x}, hmenu={:#x}", hwnd, h_menu)  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual SetMenu (set menu on window)
    1 // TRUE (return previous menu, 0 if none)
}

/// NtUserDrawMenuBar - Draw menu bar (P2 Enhancement)
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_draw_menu_bar(tf: *mut TrapFrame) -> u64 {
    let hwnd = unsafe { get_arg0(tf) };
    let _ = &hwnd;

    // kprintln!("[win32k] NtUserDrawMenuBar: hwnd={:#x}", hwnd)  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual DrawMenuBar
    1 // TRUE
}

// =============================================================================
// Additional Hook Syscalls (needed for Shadow SSDT registration)
// =============================================================================

/// NtUserSetWinEventHook - Set winevent hook
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_set_win_event_hook(tf: *mut TrapFrame) -> u64 {
    let event_min = unsafe { get_arg0(tf) } as u32;
    let _ = &event_min;
    let event_max = unsafe { get_arg1(tf) } as u32;
    let _ = &event_max;
    let h_mod = unsafe { get_arg2(tf) };
    let _ = &h_mod;
    let lpfn = unsafe { get_arg3(tf) };
    let _ = &lpfn;
    let id_process = unsafe { get_arg4(tf) } as u32;
    let _ = &id_process;
    let id_thread = unsafe { get_arg5(tf) } as u32;
    let _ = &id_thread;
    let dw_flags = unsafe { get_arg6(tf) } as u32;
    let _ = &dw_flags;

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] NtUserSetWinEventHook: event={}-{}, process={}, thread={}",
//         _event_min, _event_max, _id_process, _id_thread
//     );

    // TODO: Implement actual SetWinEventHook
    0
}

/// NtUserUnhookWinEvent - Unhook winevent
#[cfg(target_arch = "x86_64")]
pub extern "C" fn nt_user_unhook_win_event(tf: *mut TrapFrame) -> u64 {
    let h_win_event_hook = unsafe { get_arg0(tf) };
    let _ = &h_win_event_hook;

    // kprintln!("[win32k] NtUserUnhookWinEvent")  // kprintln disabled (memcpy crash workaround);

    // TODO: Implement actual UnhookWinEvent
    1 // TRUE
}
