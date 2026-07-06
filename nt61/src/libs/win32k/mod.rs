//! win32k.sys — Windows Subsystem Kernel Driver
//
//! win32k.sys is the kernel-mode part of the Win32 subsystem. It provides:
//!   - GDI (Graphics Device Interface) functions
//!   - USER (Window/Input Management) functions
//!   - Graphics rendering via GDI handles
//!   - Window management and message processing
//
//! This is the bridge between the user-mode Win32 API (kernel32, gdi32, user32)
//! and the kernel graphics subsystem.
//
//! **Note:** Win32k is x86_64-only in this build.
#![cfg(target_arch = "x86_64")]

//! ## Architecture
//
//! ```text
//! user32.dll/gdi32.dll
//!      |
//!      v
//! win32k.sys (kernel-mode)
//!      |
//!      +-- GDI handles (pens, brushes, bitmaps, DCs)
//!      +-- USER handles (windows, menus, classes)
//!      +-- Graphics engine (Eng* functions)
//!      +-- Display drivers (video miniport)
//! ```
//
//! ## Logging Convention
//
//! All `kprintln!` calls use a consistent format:
//
//! | Component | Format | Example |
//! |-----------|--------|---------|
//! | Win32k module | `[win32k]` | `[win32k] CreateWindow: hwnd=0x100` |
//! | GDI sub-system | `[win32k GDI]` | `[win32k GDI] CreatePen: ...` |
//! | USER sub-system | `[win32k USER]` | `[win32k USER] CreateWindow: ...` |
//! | Message queue | `[msgq]` | `[msgq] PostMessage: msg=0x0100` |
//
//! All handles are printed as hex: `0x{:016x}`
//! All colors are printed as hex: `0x{:08x}`
//! Status indicators: `[OK]`, `[FAIL]`, `[DEBUG]`
//
//! ## Module Structure
//
//! - `objects.rs` - GDI object management (pens, brushes, fonts, bitmaps, regions)
//! - `dc.rs` - Device Context management
//! - `surface.rs` - Surface/bitmap management
//! - `gdi_ops.rs` - GDI operations (BitBlt, FillRect, etc.)
//! - `text.rs` - Text rendering with fonts
//! - `region.rs` - Region and clipping operations
//! - `syscall.rs` - Shadow SSDT syscall handlers

extern crate alloc;

use crate::kprintln;
use alloc::vec::Vec;

// Submodules
pub mod objects;
pub mod dc;
pub mod surface;
pub mod gdi_ops;
pub mod text;
pub mod region;
pub mod syscall;
pub mod window;
pub mod message;
pub mod paint;
pub mod clipboard;

/// win32k.sys version
pub const WIN32K_VERSION: u32 = 0x0601_0001;

/// GDI handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdiHandleType {
    DC = 1,
    Bitmap = 2,
    Palette = 3,
    Font = 4,
    Pen = 5,
    ExtPen = 6,
    Brushed = 7,
    Region = 8,
    Metafile = 9,
    MetafileDC = 10,
    EnhancedMetafileDC = 11,
}

/// USER handle types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserHandleType {
    Window = 1,
    Menu = 2,
    Cursor = 3,
    Class = 4,
    Desktop = 5,
    Hook = 6,
    DataTable = 7,
    Process = 8,
    Thread = 9,
    Task = 10,
    InputMethod = 11,
    Timer = 12,
    Icon = 13,
}

/// GDI handle entry
#[repr(C)]
pub struct GdiHandleEntry {
    pub handle_type: u8,
    pub flags: u8,
    pub process_id: u32,
    pub thread_id: u32,
    pub kernel_address: u64,
}

impl GdiHandleEntry {
    pub fn new(htype: GdiHandleType, pid: u32, tid: u32) -> Self {    let _ = (&htype, &pid, &tid,);

        Self {
            handle_type: htype as u8,
            flags: 0,
            process_id: pid,
            thread_id: tid,
            kernel_address: 0,
        }
    }
}

/// USER handle entry
#[repr(C)]
pub struct UserHandleEntry {
    pub handle_type: u8,
    pub flags: u8,
    pub process_id: u32,
    pub thread_id: u32,
    pub kernel_address: u64,
}

impl UserHandleEntry {
    pub fn new(htype: UserHandleType, pid: u32, tid: u32) -> Self {    let _ = (&htype, &pid, &tid,);

        Self {
            handle_type: htype as u8,
            flags: 0,
            process_id: pid,
            thread_id: tid,
            kernel_address: 0,
        }
    }
}

// =============================================================================
// GDI Subsystem (Graphics Device Interface)
// =============================================================================

/// Device Context (DC) state
#[derive(Debug, Clone, Copy)]
pub struct DCState {
    /// DC type (DC, memDC, etc.)
    pub dc_type: GdiHandleType,
    /// Surface/bitmap associated with this DC
    pub surface: u64,
    /// Clipping region
    pub clip_region: u64,
    /// Current pen
    pub pen: u64,
    /// Current brush
    pub brush: u64,
    /// Current palette
    pub palette: u64,
    /// Current font
    pub font: u64,
    /// Background color (BGR)
    pub background_color: u32,
    /// Text color (BGR)
    pub text_color: u32,
    /// ROP (Raster Operation) mode
    pub rop_mode: u32,
    /// Stretch mode
    pub stretch_mode: u32,
}

impl DCState {
    pub fn new() -> Self {
        Self {
            dc_type: GdiHandleType::DC,
            surface: 0,
            clip_region: 0,
            pen: 0,
            brush: 0,
            palette: 0,
            font: 0,
            background_color: 0x00FFFFFF, // White
            text_color: 0x00000000,      // Black
            rop_mode: 0xCC,             // SRCCOPY
            stretch_mode: 0,             // BLACKONWHITE
        }
    }
}

/// Bitmap info header (BITMAPINFOHEADER)
#[repr(C)]
pub struct BitmapInfoHeader {
    pub size: u32,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    pub compression: u32,
    pub image_size: u32,
    pub x_pels_per_meter: i32,
    pub y_pels_per_meter: i32,
    pub colors_used: u32,
    pub colors_important: u32,
}

impl BitmapInfoHeader {
    pub fn new(width: i32, height: i32, bit_count: u16) -> Self {    let _ = (&width, &height, &bit_count,);

        Self {
            size: 40,
            width,
            height,
            planes: 1,
            bit_count,
            compression: 0, // BI_RGB
            image_size: ((width.abs() * height.abs() * bit_count as i32) / 8) as u32,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            colors_used: 0,
            colors_important: 0,
        }
    }
}

/// Palette entry
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PaletteEntry {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub flags: u8,
}

// =============================================================================
// USER Subsystem (Window/Input Management)
// =============================================================================

/// Window message types - re-exported from window.rs
pub use crate::libs::win32k::window::WindowMessage;

/// Window class styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum WindowClassStyle {
    VREDRAW = 0x0001,
    HREDRAW = 0x0002,
    OWNDC = 0x0020,
    CLASSDCE = 0x0040,
    PARENTDC = 0x0080,
    NOKEYBOARD = 0x0100,
    NESTEDATAPIC = 0x0200,
    GLOBALCLASS = 0x0400,
}

/// Window styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum WindowStyle {
    OVERLAPPED = 0x00000000,
    POPUP = 0x80000000,
    CHILD = 0x40000000,
    MINIMIZE = 0x20000000,
    VISIBLE = 0x10000000,
    DISABLED = 0x08000000,
    CLIPSIBLINGS = 0x04000000,
    CLIPCHILDREN = 0x02000000,
    MAXIMIZE = 0x01000000,
    CAPTION = 0x00C00000,
    SYSMENU = 0x00080000,
    THICKFRAME = 0x00040000,
    MINIMIZEBOX = 0x00020000,
    MAXIMIZEBOX = 0x00010000,
}

/// Window info
#[derive(Debug, Clone, Copy)]
pub struct WindowInfo {
    pub handle: u64,
    pub parent: u64,
    pub owner: u64,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub client_x: i32,
    pub client_y: i32,
    pub client_width: i32,
    pub client_height: i32,
}

impl WindowInfo {
    pub fn new(hwnd: u64) -> Self {    let _ = (&hwnd,);

        Self {
            handle: hwnd,
            parent: 0,
            owner: 0,
            style: 0,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            client_x: 0,
            client_y: 0,
            client_width: 800,
            client_height: 600,
        }
    }
}

/// Window class info
#[derive(Debug, Clone, Copy)]
pub struct WindowClass {
    pub name: [u16; 256],
    pub style: u32,
    pub proc: u64,
    pub instance: u64,
    pub background: u64,
    pub cursor: u64,
    pub icon: u64,
}

impl WindowClass {
    pub fn new() -> Self {
        Self {
            name: [0; 256],
            style: 0,
            proc: 0,
            instance: 0,
            background: 0,
            cursor: 0,
            icon: 0,
        }
    }
}

// =============================================================================
// Graphics Engine (Eng* functions)
// =============================================================================

/// Surface description
#[repr(C)]
pub struct EngSurface {
    pub width: i32,
    pub height: i32,
    pub format: u32,
    pub pitch: i32,
    pub bits: *mut u8,
}

impl EngSurface {
    pub fn new(width: i32, height: i32, format: u32) -> Self {    let _ = (&width, &height, &format,);

        let pitch = (width + 3) & !3; // 4-byte aligned
        let _ = &pitch;
        Self {
            width,
            height,
            format,
            pitch,
            bits: core::ptr::null_mut(),
        }
    }
}

/// Driver functions table (DRIVERFN)
pub struct DriverFunctions {
    pub version: u32,
    pub caps: u32,
}

// =============================================================================
// Initialization
// =============================================================================

static WIN32K_INITIALIZED: core::sync::atomic::AtomicBool = 
    core::sync::atomic::AtomicBool::new(false);

/// Initialize win32k.sys
pub fn init() {
    // kprintln!("    [win32k] Initializing win32k.sys...")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("      version: 0x{:08x}", WIN32K_VERSION)  // kprintln disabled (memcpy crash workaround);

    // Initialize surface management (primary framebuffer)
    surface::init_primary_surface();
    // kprintln!("      Surface management initialized")  // kprintln disabled (memcpy crash workaround);

    // Initialize GDI objects
    objects::init_stock_objects();
    // kprintln!("      Stock GDI objects initialized")  // kprintln disabled (memcpy crash workaround);

    // Initialize display driver
    surface::DrvEnableDriver();
    // kprintln!("      Display driver enabled")  // kprintln disabled (memcpy crash workaround);

    // Initialize window management
    window::init();
    // kprintln!("      Window manager initialized")  // kprintln disabled (memcpy crash workaround);

    // Message queue subsystem uses thread-local initialization
    // kprintln!("      Message queue subsystem ready")  // kprintln disabled (memcpy crash workaround);

    // Register Shadow SSDT services (using correct masked indices)
    unsafe { crate::ke::shadow_ssdt::init_shadow_services() };

    // kprintln!("      Shadow SSDT services registered")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    [win32k] win32k.sys ready")  // kprintln disabled (memcpy crash workaround);
    WIN32K_INITIALIZED.store(true, core::sync::atomic::Ordering::SeqCst);
}

/// Check if win32k is initialized
pub fn is_initialized() -> bool {
    WIN32K_INITIALIZED.load(core::sync::atomic::Ordering::SeqCst)
}

/// Register win32k system services with the Shadow SSDT
///
/// This function registers all GDI and USER service handlers
/// with the kernel's Shadow SSDT so they can be called via syscall.
/// The service indices are masked (service_number & 0xFFF) before registration
/// because dispatch_shadow_service extracts the low 12 bits as the service index.
pub fn register_services() {
    use crate::ke::shadow_ssdt;

    // kprintln!("[win32k] Registering Shadow SSDT services...")  // kprintln disabled (memcpy crash workaround);

    // Register GDI services (0x1000-0x10FF)
    // Windows 7 SP1 x64 GDI syscall numbers from j00ru/windows-syscalls
    // NOTE: We use indices masked by 0xFFF since dispatch_shadow_service extracts low 12 bits
    unsafe {
        // DC functions (using service index = syscall_number & 0xFFF)
        shadow_ssdt::register_shadow_service(0x000, syscall::nt_gdi_get_dc as *const (), 8);      // NtGdiGetDC - hdc=arg0
        shadow_ssdt::register_shadow_service(0x001, syscall::nt_user_peek_message as *const (), 16); // NtUserPeekMessage
        shadow_ssdt::register_shadow_service(0x002, syscall::nt_user_call_one_param as *const (), 8); // NtUserCallOneParam
        shadow_ssdt::register_shadow_service(0x003, syscall::nt_user_get_key_state as *const (), 8); // NtUserGetKeyState
        shadow_ssdt::register_shadow_service(0x004, syscall::nt_user_invalidate_rect as *const (), 12); // NtUserInvalidateRect
        shadow_ssdt::register_shadow_service(0x005, syscall::nt_user_call_no_param as *const (), 4); // NtUserCallNoParam
        shadow_ssdt::register_shadow_service(0x006, syscall::nt_user_get_message as *const (), 16); // NtUserGetMessage
        shadow_ssdt::register_shadow_service(0x007, syscall::nt_user_message_call as *const (), 24); // NtUserMessageCall
        shadow_ssdt::register_shadow_service(0x008, syscall::nt_gdi_bit_blt as *const (), 48);     // NtGdiBitBlt
        shadow_ssdt::register_shadow_service(0x009, syscall::nt_gdi_get_char_set as *const (), 4); // NtGdiGetCharSet
        shadow_ssdt::register_shadow_service(0x00a, syscall::nt_user_get_dc as *const (), 8);       // NtUserGetDC
        shadow_ssdt::register_shadow_service(0x00b, syscall::nt_gdi_select_object as *const (), 8); // NtGdiSelectBitmap
        shadow_ssdt::register_shadow_service(0x00c, syscall::nt_user_wait_message as *const (), 4);  // NtUserWaitMessage
        shadow_ssdt::register_shadow_service(0x00d, syscall::nt_user_translate_message as *const (), 8); // NtUserTranslateMessage
        shadow_ssdt::register_shadow_service(0x00e, syscall::nt_user_get_prop as *const (), 8);      // NtUserGetProp
        shadow_ssdt::register_shadow_service(0x00f, syscall::nt_user_post_message as *const (), 16);  // NtUserPostMessage
        
        // More DC functions
        shadow_ssdt::register_shadow_service(0x01a, syscall::nt_user_set_cursor as *const (), 8);    // NtUserSetCursor
        shadow_ssdt::register_shadow_service(0x01b, syscall::nt_user_kill_timer as *const (), 8);    // NtUserKillTimer
        shadow_ssdt::register_shadow_service(0x023, syscall::nt_gdi_delete_object as *const (), 4); // NtGdiDeleteObjectApp
        shadow_ssdt::register_shadow_service(0x024, syscall::nt_user_set_window_pos as *const (), 32); // NtUserSetWindowPos
        shadow_ssdt::register_shadow_service(0x025, syscall::nt_user_show_caret as *const (), 4);    // NtUserShowCaret
        shadow_ssdt::register_shadow_service(0x026, syscall::nt_user_end_defer_window_pos_ex as *const (), 8); // NtUserEndDeferWindowPosEx
        
        // Drawing functions
        shadow_ssdt::register_shadow_service(0x031, syscall::nt_gdi_stretch_blt as *const (), 44);   // NtGdiStretchBlt
        shadow_ssdt::register_shadow_service(0x032, syscall::nt_user_create_caret as *const (), 16); // NtUserCreateCaret
        shadow_ssdt::register_shadow_service(0x034, syscall::nt_gdi_combine_rgn as *const (), 16);   // NtGdiCombineRgn
        shadow_ssdt::register_shadow_service(0x035, syscall::nt_gdi_get_dc_object as *const (), 8);  // NtGdiGetDCObject
        shadow_ssdt::register_shadow_service(0x036, syscall::nt_user_dispatch_message as *const (), 8); // NtUserDispatchMessage
        shadow_ssdt::register_shadow_service(0x037, syscall::nt_user_register_window_message as *const (), 8); // NtUserRegisterWindowMessage
        shadow_ssdt::register_shadow_service(0x038, syscall::nt_gdi_ext_text_out as *const (), 32);   // NtGdiExtTextOutW
        shadow_ssdt::register_shadow_service(0x039, syscall::nt_gdi_select_font as *const (), 8);      // NtGdiSelectFont
        shadow_ssdt::register_shadow_service(0x03a, syscall::nt_gdi_restore_dc as *const (), 8);       // NtGdiRestoreDC
        shadow_ssdt::register_shadow_service(0x03b, syscall::nt_gdi_save_dc as *const (), 4);          // NtGdiSaveDC
        shadow_ssdt::register_shadow_service(0x03c, syscall::nt_user_get_foreground_window as *const (), 4); // NtUserGetForegroundWindow
        shadow_ssdt::register_shadow_service(0x03f, syscall::nt_gdi_get_dc_dword as *const (), 12);    // NtGdiGetDCDword
        shadow_ssdt::register_shadow_service(0x041, syscall::nt_gdi_line_to as *const (), 12);         // NtGdiLineTo
        shadow_ssdt::register_shadow_service(0x042, syscall::nt_user_system_parameters_info as *const (), 16); // NtUserSystemParametersInfo
        shadow_ssdt::register_shadow_service(0x043, syscall::nt_gdi_get_app_clip_box as *const (), 8); // NtGdiGetAppClipBox
        shadow_ssdt::register_shadow_service(0x044, syscall::nt_user_get_async_key_state as *const (), 8); // NtUserGetAsyncKeyState
        
        // More GDI/USER functions
        shadow_ssdt::register_shadow_service(0x047, syscall::nt_gdi_do_palette as *const (), 20);      // NtGdiDoPalette
        shadow_ssdt::register_shadow_service(0x049, syscall::nt_user_set_capture as *const (), 8);     // NtUserSetCapture
        shadow_ssdt::register_shadow_service(0x04b, syscall::nt_gdi_create_compatible_bitmap as *const (), 16); // NtGdiCreateCompatibleBitmap
        shadow_ssdt::register_shadow_service(0x04c, syscall::nt_user_set_prop as *const (), 12);       // NtUserSetProp
        shadow_ssdt::register_shadow_service(0x04d, syscall::nt_gdi_get_text_charset_info as *const (), 12); // NtGdiGetTextCharsetInfo
        shadow_ssdt::register_shadow_service(0x04e, syscall::nt_user_sb_get_parms as *const (), 8);   // NtUserSBGetParms
        shadow_ssdt::register_shadow_service(0x04f, syscall::nt_user_get_icon_info as *const (), 8);   // NtUserGetIconInfo
        shadow_ssdt::register_shadow_service(0x050, syscall::nt_user_exclude_update_rgn as *const (), 12); // NtUserExcludeUpdateRgn
        shadow_ssdt::register_shadow_service(0x051, syscall::nt_user_set_focus as *const (), 8);     // NtUserSetFocus
        shadow_ssdt::register_shadow_service(0x052, syscall::nt_gdi_ext_get_object_w as *const (), 12); // NtGdiExtGetObjectW
        shadow_ssdt::register_shadow_service(0x053, syscall::nt_user_defer_window_pos as *const (), 32); // NtUserDeferWindowPos
        shadow_ssdt::register_shadow_service(0x054, syscall::nt_user_get_update_rect as *const (), 12); // NtUserGetUpdateRect
        shadow_ssdt::register_shadow_service(0x055, syscall::nt_gdi_create_compatible_dc as *const (), 8); // NtGdiCreateCompatibleDC
        shadow_ssdt::register_shadow_service(0x056, syscall::nt_user_get_clipboard_sequence_number as *const (), 4); // NtUserGetClipboardSequenceNumber
        shadow_ssdt::register_shadow_service(0x057, syscall::nt_gdi_create_pen as *const (), 16);      // NtGdiCreatePen
        shadow_ssdt::register_shadow_service(0x058, syscall::nt_user_show_window as *const (), 8);     // NtUserShowWindow
        shadow_ssdt::register_shadow_service(0x059, syscall::nt_user_get_keyboard_layout_list as *const (), 8); // NtUserGetKeyboardLayoutList
        shadow_ssdt::register_shadow_service(0x05a, syscall::nt_gdi_pat_blt as *const (), 32);         // NtGdiPatBlt
        shadow_ssdt::register_shadow_service(0x05b, syscall::nt_user_map_virtual_key_ex as *const (), 16); // NtUserMapVirtualKeyEx
        shadow_ssdt::register_shadow_service(0x05c, syscall::nt_user_set_window_long as *const (), 16); // NtUserSetWindowLong
        shadow_ssdt::register_shadow_service(0x05d, syscall::nt_gdi_hfont_create as *const (), 16);    // NtGdiHfontCreate
        shadow_ssdt::register_shadow_service(0x05e, syscall::nt_user_move_window as *const (), 24);   // NtUserMoveWindow
        shadow_ssdt::register_shadow_service(0x05f, syscall::nt_user_post_thread_message as *const (), 16); // NtUserPostThreadMessage
        shadow_ssdt::register_shadow_service(0x060, syscall::nt_user_draw_icon_ex as *const (), 40);   // NtUserDrawIconEx
        shadow_ssdt::register_shadow_service(0x061, syscall::nt_user_get_system_menu as *const (), 8);   // NtUserGetSystemMenu
        shadow_ssdt::register_shadow_service(0x062, syscall::nt_gdi_draw_stream as *const (), 24);    // NtGdiDrawStream
        shadow_ssdt::register_shadow_service(0x063, syscall::nt_user_internal_get_window_text as *const (), 12); // NtUserInternalGetWindowText
        shadow_ssdt::register_shadow_service(0x064, syscall::nt_user_get_window_dc as *const (), 8);   // NtUserGetWindowDC
        shadow_ssdt::register_shadow_service(0x066, syscall::nt_gdi_invert_rgn as *const (), 12);    // NtGdiInvertRgn
        shadow_ssdt::register_shadow_service(0x067, syscall::nt_gdi_get_rgn_box as *const (), 8);      // NtGdiGetRgnBox
        shadow_ssdt::register_shadow_service(0x069, syscall::nt_gdi_mask_blt as *const (), 44);       // NtGdiMaskBlt
        shadow_ssdt::register_shadow_service(0x06a, syscall::nt_gdi_get_width_table as *const (), 20); // NtGdiGetWidthTable
        shadow_ssdt::register_shadow_service(0x06b, syscall::nt_user_scroll_dc as *const (), 28);     // NtUserScrollDC
        shadow_ssdt::register_shadow_service(0x06c, syscall::nt_user_get_object_information as *const (), 16); // NtUserGetObjectInformation
        shadow_ssdt::register_shadow_service(0x06d, syscall::nt_gdi_create_bitmap as *const (), 16);   // NtGdiCreateBitmap
        shadow_ssdt::register_shadow_service(0x06e, syscall::nt_user_find_window_ex as *const (), 24); // NtUserFindWindowEx
        shadow_ssdt::register_shadow_service(0x06f, syscall::nt_gdi_poly_pat_blt as *const (), 24);   // NtGdiPolyPatBlt
        shadow_ssdt::register_shadow_service(0x070, syscall::nt_user_unhook_windows_hook_ex as *const (), 8); // NtUserUnhookWindowsHookEx
        shadow_ssdt::register_shadow_service(0x071, syscall::nt_gdi_get_nearest_color as *const (), 12); // NtGdiGetNearestColor
        shadow_ssdt::register_shadow_service(0x072, syscall::nt_gdi_transform_points as *const (), 20); // NtGdiTransformPoints
        shadow_ssdt::register_shadow_service(0x073, syscall::nt_gdi_get_dc_point as *const (), 8);   // NtGdiGetDCPoint
        shadow_ssdt::register_shadow_service(0x074, syscall::nt_gdi_create_dib_brush as *const (), 20); // NtGdiCreateDIBBrush
        shadow_ssdt::register_shadow_service(0x075, syscall::nt_gdi_get_text_metrics_w as *const (), 8); // NtGdiGetTextMetricsW
        shadow_ssdt::register_shadow_service(0x076, syscall::nt_user_create_window_ex as *const (), 44); // NtUserCreateWindowEx
        shadow_ssdt::register_shadow_service(0x077, syscall::nt_user_set_parent as *const (), 12);    // NtUserSetParent
        shadow_ssdt::register_shadow_service(0x078, syscall::nt_user_get_keyboard_state as *const (), 8); // NtUserGetKeyboardState
        shadow_ssdt::register_shadow_service(0x079, syscall::nt_user_to_unicode_ex as *const (), 24);  // NtUserToUnicodeEx
        shadow_ssdt::register_shadow_service(0x07a, syscall::nt_user_get_control_brush as *const (), 12); // NtUserGetControlBrush
        shadow_ssdt::register_shadow_service(0x07b, syscall::nt_user_get_class_name as *const (), 12);  // NtUserGetClassName
        shadow_ssdt::register_shadow_service(0x07c, syscall::nt_gdi_alpha_blend as *const (), 40);    // NtGdiAlphaBlend
        shadow_ssdt::register_shadow_service(0x07d, syscall::nt_gdi_dd_blt as *const (), 48);         // NtGdiDdBlt
        shadow_ssdt::register_shadow_service(0x07e, syscall::nt_gdi_offset_rgn as *const (), 8);      // NtGdiOffsetRgn
        shadow_ssdt::register_shadow_service(0x07f, syscall::nt_user_def_set_text as *const (), 12);   // NtUserDefSetText
        shadow_ssdt::register_shadow_service(0x080, syscall::nt_gdi_get_text_face_w as *const (), 12); // NtGdiGetTextFaceW
        shadow_ssdt::register_shadow_service(0x081, syscall::nt_gdi_stretch_dibits_internal as *const (), 44); // NtGdiStretchDIBitsInternal
        shadow_ssdt::register_shadow_service(0x082, syscall::nt_user_send_input as *const (), 16);    // NtUserSendInput
        shadow_ssdt::register_shadow_service(0x083, syscall::nt_user_get_thread_desktop as *const (), 8); // NtUserGetThreadDesktop
        shadow_ssdt::register_shadow_service(0x084, syscall::nt_gdi_create_rect_rgn as *const (), 20); // NtGdiCreateRectRgn
        shadow_ssdt::register_shadow_service(0x085, syscall::nt_gdi_get_dibits_internal as *const (), 28); // NtGdiGetDIBitsInternal
        shadow_ssdt::register_shadow_service(0x086, syscall::nt_user_get_update_rgn as *const (), 12); // NtUserGetUpdateRgn
        shadow_ssdt::register_shadow_service(0x087, syscall::nt_gdi_delete_client_obj as *const (), 4); // NtGdiDeleteClientObj
        shadow_ssdt::register_shadow_service(0x088, syscall::nt_user_get_icon_size as *const (), 16);  // NtUserGetIconSize
        shadow_ssdt::register_shadow_service(0x089, syscall::nt_user_fill_window as *const (), 16);   // NtUserFillWindow
        shadow_ssdt::register_shadow_service(0x08a, syscall::nt_gdi_ext_create_region as *const (), 20); // NtGdiExtCreateRegion
        shadow_ssdt::register_shadow_service(0x08b, syscall::nt_gdi_compute_xform_coefficients as *const (), 8); // NtGdiComputeXformCoefficients
        shadow_ssdt::register_shadow_service(0x08c, syscall::nt_user_set_windows_hook_ex as *const (), 24); // NtUserSetWindowsHookEx
        shadow_ssdt::register_shadow_service(0x08d, syscall::nt_user_notify_process_create as *const (), 16); // NtUserNotifyProcessCreate
        shadow_ssdt::register_shadow_service(0x08e, syscall::nt_gdi_unrealize_object as *const (), 4); // NtGdiUnrealizeObject
        shadow_ssdt::register_shadow_service(0x08f, syscall::nt_user_get_title_bar_info as *const (), 8); // NtUserGetTitleBarInfo
        shadow_ssdt::register_shadow_service(0x090, syscall::nt_gdi_rectangle as *const (), 24);     // NtGdiRectangle
        shadow_ssdt::register_shadow_service(0x091, syscall::nt_user_set_thread_desktop as *const (), 8); // NtUserSetThreadDesktop
        shadow_ssdt::register_shadow_service(0x092, syscall::nt_user_get_dcex as *const (), 16);      // NtUserGetDCEx
        shadow_ssdt::register_shadow_service(0x093, syscall::nt_user_get_scroll_bar_info as *const (), 8); // NtUserGetScrollBarInfo
        shadow_ssdt::register_shadow_service(0x094, syscall::nt_gdi_get_text_extent as *const (), 16); // NtGdiGetTextExtent
        shadow_ssdt::register_shadow_service(0x095, syscall::nt_user_set_window_fnid as *const (), 8); // NtUserSetWindowFNID
        shadow_ssdt::register_shadow_service(0x096, syscall::nt_gdi_set_layout as *const (), 8);      // NtGdiSetLayout
        shadow_ssdt::register_shadow_service(0x097, syscall::nt_user_calc_menu_bar as *const (), 20);  // NtUserCalcMenuBar
        shadow_ssdt::register_shadow_service(0x098, syscall::nt_user_thunked_menu_item_info as *const (), 24); // NtUserThunkedMenuItemInfo
        shadow_ssdt::register_shadow_service(0x099, syscall::nt_gdi_exclude_clip_rect as *const (), 24); // NtGdiExcludeClipRect
        shadow_ssdt::register_shadow_service(0x09a, syscall::nt_gdi_create_dib_section as *const (), 28); // NtGdiCreateDIBSection
        shadow_ssdt::register_shadow_service(0x09b, syscall::nt_gdi_get_dc_for_bitmap as *const (), 4); // NtGdiGetDCforBitmap
        shadow_ssdt::register_shadow_service(0x09c, syscall::nt_user_destroy_cursor as *const (), 8);  // NtUserDestroyCursor
        shadow_ssdt::register_shadow_service(0x09d, syscall::nt_user_destroy_window as *const (), 4);   // NtUserDestroyWindow
        shadow_ssdt::register_shadow_service(0x09e, syscall::nt_user_call_hwnd_param as *const (), 12); // NtUserCallHwndParam
        shadow_ssdt::register_shadow_service(0x09f, syscall::nt_gdi_create_dibitmap_internal as *const (), 24); // NtGdiCreateDIBitmapInternal
        shadow_ssdt::register_shadow_service(0x0a0, syscall::nt_user_open_window_station as *const (), 12); // NtUserOpenWindowStation
        shadow_ssdt::register_shadow_service(0x0a1, syscall::nt_gdi_dd_delete_surface_object as *const (), 4); // NtGdiDdDeleteSurfaceObject
        shadow_ssdt::register_shadow_service(0x0a2, syscall::nt_gdi_dd_can_create_surface as *const (), 8); // NtGdiDdCanCreateSurface
        shadow_ssdt::register_shadow_service(0x0a3, syscall::nt_gdi_dd_create_surface as *const (), 32); // NtGdiDdCreateSurface
        shadow_ssdt::register_shadow_service(0x0a4, syscall::nt_user_set_cursor_icon_data as *const (), 24); // NtUserSetCursorIconData
        shadow_ssdt::register_shadow_service(0x0a5, syscall::nt_gdi_dd_destroy_surface as *const (), 4); // NtGdiDdDestroySurface
        shadow_ssdt::register_shadow_service(0x0a6, syscall::nt_user_close_desktop as *const (), 8);    // NtUserCloseDesktop
        shadow_ssdt::register_shadow_service(0x0a7, syscall::nt_user_open_desktop as *const (), 28);   // NtUserOpenDesktop
        shadow_ssdt::register_shadow_service(0x0a8, syscall::nt_user_set_process_window_station as *const (), 8); // NtUserSetProcessWindowStation
        shadow_ssdt::register_shadow_service(0x0a9, syscall::nt_user_get_atom_name as *const (), 8);   // NtUserGetAtomName
        shadow_ssdt::register_shadow_service(0x0aa, syscall::nt_gdi_dd_reset_visrgn as *const (), 4);  // NtGdiDdResetVisrgn
        shadow_ssdt::register_shadow_service(0x0ab, syscall::nt_gdi_ext_create_pen as *const (), 32);  // NtGdiExtCreatePen
        shadow_ssdt::register_shadow_service(0x0ac, syscall::nt_gdi_create_palette_internal as *const (), 8); // NtGdiCreatePaletteInternal
        shadow_ssdt::register_shadow_service(0x0ad, syscall::nt_gdi_set_brush_org as *const (), 8);    // NtGdiSetBrushOrg
        shadow_ssdt::register_shadow_service(0x0ae, syscall::nt_user_build_name_list as *const (), 12); // NtUserBuildNameList
        shadow_ssdt::register_shadow_service(0x0af, syscall::nt_gdi_set_pixel as *const (), 16);      // NtGdiSetPixel
        shadow_ssdt::register_shadow_service(0x0b0, syscall::nt_user_register_class_ex_wow as *const (), 32); // NtUserRegisterClassExWOW
        shadow_ssdt::register_shadow_service(0x0b1, syscall::nt_gdi_create_pattern_brush_internal as *const (), 16); // NtGdiCreatePatternBrushInternal
        shadow_ssdt::register_shadow_service(0x0b2, syscall::nt_user_get_ancestor as *const (), 8);   // NtUserGetAncestor
        shadow_ssdt::register_shadow_service(0x0b3, syscall::nt_gdi_get_outline_text_metrics_internal_w as *const (), 12); // NtGdiGetOutlineTextMetricsInternalW
        shadow_ssdt::register_shadow_service(0x0b4, syscall::nt_gdi_set_bitmap_bits as *const (), 12); // NtGdiSetBitmapBits
        shadow_ssdt::register_shadow_service(0x0b5, syscall::nt_user_close_window_station as *const (), 8); // NtUserCloseWindowStation
        shadow_ssdt::register_shadow_service(0x0b6, syscall::nt_user_get_double_click_time as *const (), 4); // NtUserGetDoubleClickTime
        shadow_ssdt::register_shadow_service(0x0b7, syscall::nt_user_enable_scroll_bar as *const (), 12); // NtUserEnableScrollBar
        shadow_ssdt::register_shadow_service(0x0b8, syscall::nt_gdi_create_solid_brush as *const (), 4); // NtGdiCreateSolidBrush
        shadow_ssdt::register_shadow_service(0x0b9, syscall::nt_user_get_class_info_ex as *const (), 16); // NtUserGetClassInfoEx
        shadow_ssdt::register_shadow_service(0x0ba, syscall::nt_gdi_create_client_obj as *const (), 8);  // NtGdiCreateClientObj
        shadow_ssdt::register_shadow_service(0x0bb, syscall::nt_user_unregister_class as *const (), 12); // NtUserUnregisterClass
        shadow_ssdt::register_shadow_service(0x0bc, syscall::nt_user_delete_menu as *const (), 8);       // NtUserDeleteMenu
        shadow_ssdt::register_shadow_service(0x0bd, syscall::nt_gdi_rect_in_region as *const (), 8);    // NtGdiRectInRegion
        shadow_ssdt::register_shadow_service(0x0be, syscall::nt_user_scroll_window_ex as *const (), 32); // NtUserScrollWindowEx
        shadow_ssdt::register_shadow_service(0x0bf, syscall::nt_gdi_get_pixel as *const (), 12);        // NtGdiGetPixel
        shadow_ssdt::register_shadow_service(0x0c0, syscall::nt_user_set_class_long as *const (), 12);  // NtUserSetClassLong
        shadow_ssdt::register_shadow_service(0x0c1, syscall::nt_user_get_menu_bar_info as *const (), 12); // NtUserGetMenuBarInfo
        
        // Additional USER functions
        shadow_ssdt::register_shadow_service(0x0c8, syscall::nt_user_invalidate_rgn as *const (), 12);  // NtUserInvalidateRgn
        shadow_ssdt::register_shadow_service(0x0c9, syscall::nt_user_get_clipboard_owner as *const (), 4);  // NtUserGetClipboardOwner
        shadow_ssdt::register_shadow_service(0x0ca, syscall::nt_user_set_window_rgn as *const (), 12);   // NtUserSetWindowRgn
        shadow_ssdt::register_shadow_service(0x0cb, syscall::nt_user_bit_blt_sys_bmp as *const (), 24);  // NtUserBitBltSysBmp
        shadow_ssdt::register_shadow_service(0x0cd, syscall::nt_user_validate_rect as *const (), 8);   // NtUserValidateRect
        shadow_ssdt::register_shadow_service(0x0ce, syscall::nt_user_close_clipboard as *const (), 4);  // NtUserCloseClipboard
        shadow_ssdt::register_shadow_service(0x0cf, syscall::nt_user_open_clipboard as *const (), 8);   // NtUserOpenClipboard
        shadow_ssdt::register_shadow_service(0x0d1, syscall::nt_user_set_clipboard_data as *const (), 12); // NtUserSetClipboardData
        shadow_ssdt::register_shadow_service(0x0d2, syscall::nt_user_enable_menu_item as *const (), 12); // NtUserEnableMenuItem
        shadow_ssdt::register_shadow_service(0x0d3, syscall::nt_user_alter_window_style as *const (), 16); // NtUserAlterWindowStyle
        shadow_ssdt::register_shadow_service(0x0d5, syscall::nt_user_get_window_placement as *const (), 8);  // NtUserGetWindowPlacement
        shadow_ssdt::register_shadow_service(0x0d8, syscall::nt_user_get_open_clipboard_window as *const (), 4); // NtUserGetOpenClipboardWindow
        shadow_ssdt::register_shadow_service(0x0d9, syscall::nt_user_set_thread_state as *const (), 8);   // NtUserSetThreadState
        shadow_ssdt::register_shadow_service(0x0da, syscall::nt_user_track_mouse_event as *const (), 16);  // NtUserTrackMouseEvent
        shadow_ssdt::register_shadow_service(0x0dd, syscall::nt_user_destroy_menu as *const (), 4);    // NtUserDestroyMenu
        shadow_ssdt::register_shadow_service(0x0df, syscall::nt_user_console_control as *const (), 16);  // NtUserConsoleControl
        shadow_ssdt::register_shadow_service(0x0e0, syscall::nt_user_set_active_window as *const (), 8);   // NtUserSetActiveWindow
        shadow_ssdt::register_shadow_service(0x0e1, syscall::nt_user_set_information_thread as *const (), 16); // NtUserSetInformationThread
        shadow_ssdt::register_shadow_service(0x0e2, syscall::nt_user_set_window_placement as *const (), 8);  // NtUserSetWindowPlacement
        shadow_ssdt::register_shadow_service(0x0e3, syscall::nt_user_get_control_color as *const (), 12); // NtUserGetControlColor
        shadow_ssdt::register_shadow_service(0x0e8, syscall::nt_user_set_window_word as *const (), 12);  // NtUserSetWindowWord
        shadow_ssdt::register_shadow_service(0x0e9, syscall::nt_user_get_clipboard_format_name as *const (), 12); // NtUserGetClipboardFormatName
        shadow_ssdt::register_shadow_service(0x0ea, syscall::nt_user_real_internal_get_message as *const (), 24); // NtUserRealInternalGetMessage
        shadow_ssdt::register_shadow_service(0x0eb, syscall::nt_user_create_local_mem_handle as *const (), 12); // NtUserCreateLocalMemHandle
        shadow_ssdt::register_shadow_service(0x0ec, syscall::nt_user_attach_thread_input as *const (), 12);  // NtUserAttachThreadInput
        shadow_ssdt::register_shadow_service(0x0ee, syscall::nt_user_paint_menu_bar as *const (), 20);   // NtUserPaintMenuBar
        shadow_ssdt::register_shadow_service(0x0ef, syscall::nt_user_set_keyboard_state as *const (), 8);  // NtUserSetKeyboardState
        shadow_ssdt::register_shadow_service(0x0f1, syscall::nt_user_create_accelerator_table as *const (), 8); // NtUserCreateAcceleratorTable
        shadow_ssdt::register_shadow_service(0x0f2, syscall::nt_user_get_cursor_frame_info as *const (), 12); // NtUserGetCursorFrameInfo
        shadow_ssdt::register_shadow_service(0x0f3, syscall::nt_user_get_alt_tab_info as *const (), 16);  // NtUserGetAltTabInfo
        shadow_ssdt::register_shadow_service(0x0f4, syscall::nt_user_get_caret_blink_time as *const (), 4);  // NtUserGetCaretBlinkTime
        shadow_ssdt::register_shadow_service(0x0f6, syscall::nt_user_process_connect as *const (), 16);   // NtUserProcessConnect
        shadow_ssdt::register_shadow_service(0x0f7, syscall::nt_user_enum_display_devices as *const (), 16);  // NtUserEnumDisplayDevices
        shadow_ssdt::register_shadow_service(0x0f8, syscall::nt_user_empty_clipboard as *const (), 4);   // NtUserEmptyClipboard
        shadow_ssdt::register_shadow_service(0x0f9, syscall::nt_user_get_clipboard_data as *const (), 8);   // NtUserGetClipboardData
        shadow_ssdt::register_shadow_service(0x0fa, syscall::nt_user_remove_menu as *const (), 8);    // NtUserRemoveMenu
        shadow_ssdt::register_shadow_service(0x0fd, syscall::nt_user_convert_mem_handle as *const (), 8);  // NtUserConvertMemHandle
        shadow_ssdt::register_shadow_service(0x0fe, syscall::nt_user_destroy_accelerator_table as *const (), 4); // NtUserDestroyAcceleratorTable
        shadow_ssdt::register_shadow_service(0x0ff, syscall::nt_user_get_gui_thread_info as *const (), 8);   // NtUserGetGUIThreadInfo
        
        // Additional USER syscalls (0x1100-0x11FF)
        shadow_ssdt::register_shadow_service(0x101, syscall::nt_user_set_windows_hook_aw as *const (), 16); // NtUserSetWindowsHookAW
        shadow_ssdt::register_shadow_service(0x102, syscall::nt_user_set_menu_default_item as *const (), 8); // NtUserSetMenuDefaultItem
        shadow_ssdt::register_shadow_service(0x103, syscall::nt_user_check_menu_item as *const (), 12);  // NtUserCheckMenuItem
        shadow_ssdt::register_shadow_service(0x104, syscall::nt_user_set_win_event_hook as *const (), 24); // NtUserSetWinEventHook
        shadow_ssdt::register_shadow_service(0x105, syscall::nt_user_unhook_win_event as *const (), 4);  // NtUserUnhookWinEvent
        shadow_ssdt::register_shadow_service(0x106, syscall::nt_user_lock_window_update as *const (), 4);  // NtUserLockWindowUpdate
        shadow_ssdt::register_shadow_service(0x107, syscall::nt_user_set_system_menu as *const (), 8);   // NtUserSetSystemMenu
        shadow_ssdt::register_shadow_service(0x108, syscall::nt_user_thunked_menu_info as *const (), 8);   // NtUserThunkedMenuInfo
        shadow_ssdt::register_shadow_service(0x10c, syscall::nt_user_call_hwnd as *const (), 8);     // NtUserCallHwnd
        shadow_ssdt::register_shadow_service(0x10d, syscall::nt_user_dde_initialize as *const (), 12);  // NtUserDdeInitialize
        shadow_ssdt::register_shadow_service(0x10e, syscall::nt_user_modify_user_startup_info_flags as *const (), 8); // NtUserModifyUserStartupInfoFlags
        shadow_ssdt::register_shadow_service(0x10f, syscall::nt_user_count_clipboard_formats as *const (), 4); // NtUserCountClipboardFormats
        shadow_ssdt::register_shadow_service(0x114, syscall::nt_user_enum_display_settings as *const (), 16); // NtUserEnumDisplaySettings
        shadow_ssdt::register_shadow_service(0x115, syscall::nt_user_paint_desktop as *const (), 4);    // NtUserPaintDesktop
        shadow_ssdt::register_shadow_service(0x119, syscall::nt_user_change_clipboard_chain as *const (), 8);  // NtUserChangeClipboardChain
        shadow_ssdt::register_shadow_service(0x11a, syscall::nt_user_set_clipboard_viewer as *const (), 8);  // NtUserSetClipboardViewer
        shadow_ssdt::register_shadow_service(0x11b, syscall::nt_user_show_window_async as *const (), 8);  // NtUserShowWindowAsync
        
        // Additional GDI syscalls (0x1200-0x12FF)
        shadow_ssdt::register_shadow_service(0x11c, syscall::nt_user_activate_keyboard_layout as *const (), 12); // NtUserActivateKeyboardLayout
        shadow_ssdt::register_shadow_service(0x11f, syscall::nt_user_initialize_client_pfn_arrays as *const (), 16); // NtUserInitializeClientPfnArrays
    }

    // kprintln!("[win32k] Shadow SSDT services registered successfully")  // kprintln disabled (memcpy crash workaround);
}

// =============================================================================
// GDI Functions
// =============================================================================

/// Create a device context
pub fn create_dc() -> Option<DCState> {
    let mut dc = DCState::new();
    dc.dc_type = GdiHandleType::DC;
    Some(dc)
}

/// Create a compatible DC
pub fn create_compatible_dc() -> Option<DCState> {
    let mut dc = DCState::new();
    dc.dc_type = GdiHandleType::EnhancedMetafileDC;
    Some(dc)
}

/// Delete a DC
pub fn delete_dc(dc: &DCState) -> bool {    let _ = (&dc,);

    // In a full implementation, this would free DC resources
    true
}

// =============================================================================
// GDI Object Management (Simplified for Bootstrap)
// =============================================================================

/// Allocate a GDI handle (simplified)
pub fn allocate_gdi_handle(htype: GdiHandleType, pid: u32) -> u64 {    let _ = (&htype, &pid,);

    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x4000_0000);
    
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let _ = &handle;
    // kprintln!("[win32k] Allocated GDI handle 0x{:x} type={:?} pid={}", handle, htype, pid)  // kprintln disabled (memcpy crash workaround);
    handle
}

/// Free a GDI handle (simplified)
pub fn free_gdi_handle(handle: u64) -> bool {    let _ = (&handle,);

    // kprintln!("[win32k] Freed GDI handle 0x{:x}", handle)  // kprintln disabled (memcpy crash workaround);
    true
}

// =============================================================================
// Bitmap Functions
// =============================================================================

/// Create a bitmap
pub fn create_bitmap_info(width: i32, height: i32, bit_count: u16) -> BitmapInfoHeader {    let _ = (&width, &height, &bit_count,);

    BitmapInfoHeader::new(width, height, bit_count)
}

// =============================================================================
// Pen Functions
// =============================================================================

/// Pen styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum PenStyle {
    Solid = 0,
    Dash = 1,
    Dot = 2,
    DashDot = 3,
    DashDotDot = 4,
}

/// Create a pen
pub fn create_pen(style: PenStyle, width: i32, color: u32) -> bool {    let _ = (&style, &width, &color,);

    // kprintln!("[win32k] CreatePen style={:?} width={} color=0x{:08x}", style, width, color)  // kprintln disabled (memcpy crash workaround);
    true
}

/// Select a pen into DC
pub fn select_pen(dc: &mut DCState, pen: u64) -> u64 {    let _ = (&dc, &pen,);

    let old_pen = dc.pen;
    let _ = &old_pen;
    dc.pen = pen;
    old_pen
}

// =============================================================================
// Brush Functions
// =============================================================================

/// Hatch styles
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum HatchStyle {
    Horizontal = 0,
    Vertical = 1,
    FDiagonal = 2,
    BDiagonal = 3,
    Cross = 4,
    DiagonalCross = 5,
}

/// Create a solid brush
pub fn create_solid_brush(color: u32) -> bool {    let _ = (&color,);

    // kprintln!("[win32k] CreateSolidBrush color=0x{:08x}", color)  // kprintln disabled (memcpy crash workaround);
    true
}

/// Create a hatched brush
pub fn create_hatch_brush(style: HatchStyle, color: u32) -> bool {    let _ = (&style, &color,);

    // kprintln!("[win32k] CreateHatchBrush style={:?} color=0x{:08x}", style, color)  // kprintln disabled (memcpy crash workaround);
    true
}

/// Select a brush into DC
pub fn select_brush(dc: &mut DCState, brush: u64) -> u64 {    let _ = (&dc, &brush,);

    let old_brush = dc.brush;
    let _ = &old_brush;
    dc.brush = brush;
    old_brush
}

// =============================================================================
// Surface Functions
// =============================================================================

/// Allocate a surface (bitmap buffer)
pub fn allocate_surface(width: i32, height: i32, format: u32) -> Option<EngSurface> {    let _ = (&width, &height, &format,);

    let mut surface = EngSurface::new(width, height, format);
    let pitch = (width + 3) & !3;
    let _ = &pitch;
    let size = (pitch * height.abs()) as usize;
    let _ = &size;
    
    // Allocate buffer from pool
    let buffer = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        size,
    );
    
    if buffer.is_null() {
        return None;
    }
    
    surface.bits = buffer;
    surface.pitch = pitch;
    
    // kprintln!("[win32k] Allocated surface {}x{} format=0x{:x}", width, height, format)  // kprintln disabled (memcpy crash workaround);
    Some(surface)
}

/// Free a surface
pub fn free_surface(surface: &EngSurface) {    let _ = (&surface,);

    if !surface.bits.is_null() {
        let _ = crate::mm::pool::free(surface.bits);
    }
}

/// Copy bits between surfaces (Eng* style)
pub fn eng_bit_blt(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {    let _ = (&dst_surface, &dst_x, &dst_y, &width, &height, &src_surface, &src_x, &src_y, &rop,);

    if dst_surface.bits.is_null() || src_surface.bits.is_null() {
        return false;
    }
    
    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surface.pitch;
    let _ = &src_pitch;
    
    for y in 0..height {
        let dst_row = unsafe { dst_surface.bits.add(((dst_y + y) * dst_pitch) as usize) };
        let _ = &dst_row;
        let src_row = unsafe { src_surface.bits.add(((src_y + y) * src_pitch) as usize) };
        let _ = &src_row;
        
        unsafe {
            core::ptr::copy_nonoverlapping(
                src_row.add(src_x as usize),
                dst_row.add(dst_x as usize),
                width as usize,
            );
        }
    }
    
    // kprintln!("[win32k] EngBitBlt surface {}x{} from ({},{}) to ({},{}) rop=0x{:08x}",   // kprintln disabled (memcpy crash workaround)
//         width, height, src_x, src_y, dst_x, dst_y, rop);
    true
}

/// Create a bitmap info structure
pub fn create_bitmap(width: i32, height: i32, bit_count: u16) -> Option<BitmapInfoHeader> {    let _ = (&width, &height, &bit_count,);

    if width <= 0 || height == 0 {
        return None;
    }
    Some(BitmapInfoHeader::new(width, height, bit_count))
}

// =============================================================================
// USER Functions
// =============================================================================

/// Create a window
pub fn create_window(class_name: &[u16], title: &[u16], x: i32, y: i32, width: i32, height: i32) -> WindowInfo {    let _ = (&class_name, &title, &x, &y, &width, &height,);

    let mut info = WindowInfo::new(0);
    info.x = x;
    info.y = y;
    info.width = width;
    info.height = height;
    info.client_width = width;
    info.client_height = height;
    info.style = WindowStyle::CAPTION as u32 | WindowStyle::THICKFRAME as u32 | 
                 WindowStyle::MINIMIZEBOX as u32 | WindowStyle::MAXIMIZEBOX as u32;
    info
}

// =============================================================================
// Smoke Test
// =============================================================================

/// Run win32k.sys smoke test
pub fn smoke_test() -> bool {
    let mut all_ok = true;

    // kprintln!("    [win32k SMOKE] Testing GDI subsystem...")  // kprintln disabled (memcpy crash workaround);

    // Test DC creation
    let dc = create_dc();
    let _ = &dc;
    if dc.is_some() {
        // kprintln!("      [OK] CreateDC")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("      [FAIL] CreateDC")  // kprintln disabled (memcpy crash workaround);
        all_ok = false;
    }

    // Test CompatibleDC creation
    let comp_dc = create_compatible_dc();
    let _ = &comp_dc;
    if comp_dc.is_some() {
        // kprintln!("      [OK] CreateCompatibleDC")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("      [FAIL] CreateCompatibleDC")  // kprintln disabled (memcpy crash workaround);
        all_ok = false;
    }

    // Test bitmap creation
    let _bitmap = create_bitmap_info(800, 600, 32);
    let _ = &_bitmap;
    // kprintln!("      [OK] CreateBitmapInfo")  // kprintln disabled (memcpy crash workaround);

    // Test surface allocation
    let surface = allocate_surface(640, 480, 0x263);
    let _ = &surface;
    if surface.is_some() {
        // kprintln!("      [OK] AllocateSurface")  // kprintln disabled (memcpy crash workaround);
        // Free the surface
        if let Some(s) = surface {
            free_surface(&s);
            // kprintln!("      [OK] FreeSurface")  // kprintln disabled (memcpy crash workaround);
        }
    } else {
        // kprintln!("      [FAIL] AllocateSurface")  // kprintln disabled (memcpy crash workaround);
        all_ok = false;
    }

    // Test surface operations
    let test_surface = allocate_surface(100, 100, 0x263);
    let _ = &test_surface;
    if let Some(ref surf) = test_surface {
        // Clear surface
        clear_surface(surf, 0x00000000);
        // kprintln!("      [OK] ClearSurface")  // kprintln disabled (memcpy crash workaround);

        // Fill rectangle
        fill_rect_solid(surf, 10, 10, 90, 90, 0x00FF0000);
        // kprintln!("      [OK] FillRectSolid")  // kprintln disabled (memcpy crash workaround);

        // Draw line
        draw_line_bresenham(surf, 0, 0, 99, 99, 0x0000FF00);
        // kprintln!("      [OK] DrawLineBresenham")  // kprintln disabled (memcpy crash workaround);

        // Draw ellipse
        draw_ellipse(surf, 50, 50, 30, 20, 0x000000FF);
        // kprintln!("      [OK] DrawEllipse")  // kprintln disabled (memcpy crash workaround);

        // Test get/set pixel
        set_pixel_on_surface(surf, 5, 5, 0x00FF00FF);
        if let Some(pixel) = get_pixel_from_surface(surf, 5, 5) {
            if pixel == 0x00FF00FF {
                // kprintln!("      [OK] GetSetPixel")  // kprintln disabled (memcpy crash workaround);
            } else {
                // kprintln!("      [FAIL] GetSetPixel (got 0x{:08x})", pixel)  // kprintln disabled (memcpy crash workaround);
            }
        }

        // Test text rendering
        draw_text(surf, 5, 5, b"Hello", 0x00FFFFFF, 0x00000000);
        // kprintln!("      [OK] DrawText")  // kprintln disabled (memcpy crash workaround);

        // Free the surface
        free_surface(surf);
    }

    // Test GDI handle allocation
    let handle = allocate_gdi_handle(GdiHandleType::DC, 0);
    let _ = &handle;
    if handle != 0 {
        // kprintln!("      [OK] AllocateGdiHandle")  // kprintln disabled (memcpy crash workaround);
        free_gdi_handle(handle);
        // kprintln!("      [OK] FreeGdiHandle")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("      [FAIL] AllocateGdiHandle")  // kprintln disabled (memcpy crash workaround);
        all_ok = false;
    }

    // Test hatch brush
    let _ = create_hatch_brush(HatchStyle::Cross, 0x00FF00);
    // kprintln!("      [OK] CreateHatchBrush")  // kprintln disabled (memcpy crash workaround);

    // kprintln!("    [win32k SMOKE] Testing USER subsystem...")  // kprintln disabled (memcpy crash workaround);

    // Test window creation
    let window = create_window(&[0u16, 0], &[0u16, 0], 100, 100, 640, 480);
    let _ = &window;
    if window.width == 640 && window.height == 480 {
        // kprintln!("      [OK] CreateWindow")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("      [FAIL] CreateWindow")  // kprintln disabled (memcpy crash workaround);
        all_ok = false;
    }

    // Test ROP operations
    let _ = apply_rop(0x12345678, 0xABCDEF00, RasterOp::SRCCOPY as u32);
    // kprintln!("      [OK] RasterOps")  // kprintln disabled (memcpy crash workaround);

    if all_ok {
        // kprintln!("    [win32k SMOKE] ALL PASSED")  // kprintln disabled (memcpy crash workaround);
    } else {
        // kprintln!("    [win32k SMOKE] SOME FAILED")  // kprintln disabled (memcpy crash workaround);
    }

    all_ok
}

// =============================================================================
// Graphics Engine Functions (Eng*)
// =============================================================================

/// Graphics engine function table.
pub struct GraphicsEngine {
    pub version: u32,
}

impl GraphicsEngine {
    pub fn new() -> Self {
        Self {
            version: WIN32K_VERSION,
        }
    }
}

/// Line drawing mode.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum LineMode {
    Solid = 0,
    Dash = 1,
    Dot = 2,
    DashDot = 3,
    DashDotDot = 4,
}

/// Point structure for graphics operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Rectangle structure - unified from objects.rs
pub use crate::libs::win32k::objects::Rect;

/// Draw a line between two points.
pub fn draw_line(dc: u64, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) {    let _ = (&dc, &x1, &y1, &x2, &y2, &color,);

    // For actual rendering, we would need the DC's associated surface
    // For now, use Bresenham line drawing directly
    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngLine: DC=0x{:x} ({},{}) -> ({},{}) color=0x{:x}",
//         dc, x1, y1, x2, y2, color
//     );
    // If surface is associated with DC, draw on it
    // This is a simplified version that just logs for kernel boot testing
}

/// Draw a line on a surface
pub fn draw_line_on_surface(surface: &EngSurface, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) {    let _ = (&surface, &x1, &y1, &x2, &y2, &color,);

    draw_line_bresenham(surface, x1, y1, x2, y2, color);
}

/// Fill a rectangle.
pub fn fill_rect(dc: u64, rect: &Rect, color: u32) {    let _ = (&dc, &rect, &color,);

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngFillRect: DC=0x{:x} rect={:?} color=0x{:x}",
//         dc, rect, color
//     );
}

/// Fill a rectangle on a surface
pub fn fill_rect_on_surface(surface: &EngSurface, left: i32, top: i32, right: i32, bottom: i32, color: u32) {    let _ = (&surface, &left, &top, &right, &bottom, &color,);

    fill_rect_solid(surface, left, top, right, bottom, color);
}

/// Bit block transfer (Blt) - USER/GDI style.
pub fn bit_blt(
    dst_dc: u64,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_dc: u64,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {    let _ = (&dst_dc, &dst_x, &dst_y, &width, &height, &src_dc, &src_x, &src_y, &rop,);

    // For actual rendering, we would look up the DC's surface
    // This is a simplified version for kernel boot testing
    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] BitBlt: dst=0x{:x} ({},{}) {}x{} <- src=0x{:x} ({},{}) rop=0x{:08x}",
//         dst_dc, dst_x, dst_y, width, height, src_dc, src_x, src_y, rop
//     );
    true
}

/// BitBlt with surface pointers (internal use)
pub fn bit_blt_surfaces(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {    let _ = (&dst_surface, &dst_x, &dst_y, &width, &height, &src_surface, &src_x, &src_y, &rop,);

    bit_blt_with_rop(dst_surface, dst_x, dst_y, width, height, src_surface, src_x, src_y, rop)
}

/// Stretch blt.
pub fn stretch_blt(
    dst_dc: u64,
    dst_rect: &Rect,
    src_dc: u64,
    src_rect: &Rect,
    rop: u32,
) -> bool {    let _ = (&dst_dc, &dst_rect, &src_dc, &src_rect, &rop,);

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngStretchBlt: dst=0x{:x} {:?} <- src=0x{:x} {:?} rop=0x{:x}",
//         dst_dc, dst_rect, src_dc, src_rect, rop
//     );
    true
}

/// PlgBlt (parallelogram block transfer).
pub fn plg_blt(
    dst_dc: u64,
    dst_points: &[Point; 3],
    src_dc: u64,
    src_rect: &Rect,
    rop: u32,
) -> bool {    let _ = (&dst_dc, &dst_points, &src_dc, &src_rect, &rop,);

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngPlgBlt: dst=0x{:x} <- src=0x{:x} rop=0x{:x}",
//         dst_dc, src_dc, rop
//     );
    true
}

/// Text out.
pub fn text_out(dc: u64, x: i32, y: i32, text: &[u16]) {    let _ = (&dc, &x, &y, &text,);

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngTextOut: DC=0x{:x} ({},{}) text_len={}",
//         dc, x, y, text.len()
//     );
}

// =============================================================================
// Pixel Operations
// =============================================================================

/// Pixel format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Indexed1 = 1,
    Indexed4 = 4,
    Indexed8 = 8,
    Rgb16 = 16,
    Rgb24 = 24,
    Rgb32 = 32,
}

/// Convert RGB to BGR (Windows color format)
#[inline(always)]
pub fn rgb_to_bgr(r: u8, g: u8, b: u8) -> u32 {    let _ = (&r, &g, &b,);

    ((b as u32) << 16) | ((g as u32) << 8) | (r as u32)
}

/// Get pixel from surface at (x, y)
pub fn get_pixel_from_surface(surface: &EngSurface, x: i32, y: i32) -> Option<u32> {    let _ = (&surface, &x, &y,);

    if surface.bits.is_null() {
        return None;
    }
    if x < 0 || x >= surface.width || y < 0 || y >= surface.height {
        return None;
    }

    let offset = (y * surface.pitch + x * 4) as isize;
    let _ = &offset;
    unsafe {
        let pixel = *(surface.bits.offset(offset) as *const u32);
        let _ = &pixel;
        Some(pixel)
    }
}

/// Set pixel on surface at (x, y)
pub fn set_pixel_on_surface(surface: &EngSurface, x: i32, y: i32, color: u32) -> bool {    let _ = (&surface, &x, &y, &color,);

    if surface.bits.is_null() {
        return false;
    }
    if x < 0 || x >= surface.width || y < 0 || y >= surface.height {
        return false;
    }

    let offset = (y * surface.pitch + x * 4) as isize;
    let _ = &offset;
    unsafe {
        *(surface.bits.offset(offset) as *mut u32) = color;
    }
    true
}

/// Clear surface to a solid color
pub fn clear_surface(surface: &EngSurface, color: u32) {    let _ = (&surface, &color,);

    if surface.bits.is_null() {
        return;
    }

    let size = (surface.pitch * surface.height.abs()) as usize;
    let _ = &size;
    let color_bytes = color.to_le_bytes();
    let _ = &color_bytes;

    unsafe {
        let mut i = 0usize;
        // Fill 4 bytes at a time for efficiency
        while i + 4 <= size {
            core::ptr::write_unaligned(
                surface.bits.add(i) as *mut u32,
                color
            );
            i += 4;
        }
        // Handle remaining bytes
        while i < size {
            core::ptr::write(surface.bits.add(i), color_bytes[i % 4]);
            i += 1;
        }
    }
}

/// Copy rectangle from source to destination surface
pub fn copy_rect(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    width: i32,
    height: i32,
) -> bool {    let _ = (&dst_surface, &dst_x, &dst_y, &src_surface, &src_x, &src_y, &width, &height,);

    if dst_surface.bits.is_null() || src_surface.bits.is_null() {
        return false;
    }

    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = src_surface.pitch;
    let _ = &src_pitch;

    for y in 0..height {
        let dst_row_ptr = unsafe { dst_surface.bits.add(((dst_y + y) * dst_pitch) as usize) };
        let _ = &dst_row_ptr;
        let src_row_ptr = unsafe { src_surface.bits.add(((src_y + y) * src_pitch) as usize) };
        let _ = &src_row_ptr;

        unsafe {
            core::ptr::copy_nonoverlapping(
                src_row_ptr.add((src_x * 4) as usize),
                dst_row_ptr.add((dst_x * 4) as usize),
                (width * 4) as usize,
            );
        }
    }
    true
}

// =============================================================================
// Raster Operations (ROP)
// =============================================================================

/// Raster operation codes
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum RasterOp {
    SRCCOPY = 0x00CC0020,     // dest = source
    SRCPAINT = 0x00EE0086,    // dest = source OR dest
    SRCAND = 0x008800C6,       // dest = source AND dest
    SRCINVERT = 0x00660046,   // dest = source XOR dest
    DSTINVERT = 0x00550009,   // dest = NOT dest
    BLACKNESS = 0x00000042,   // dest = BLACK
    WHITENESS = 0x00FF0062,   // dest = WHITE
}

/// Apply raster operation to a single pixel
#[inline(always)]
pub fn apply_rop(pixel: u32, color: u32, rop: u32) -> u32 {    let _ = (&pixel, &color, &rop,);

    match rop {
        0x00CC0020 => color,                       // SRCCOPY
        0x00EE0086 => pixel | color,               // SRCPAINT
        0x008800C6 => pixel & color,               // SRCAND
        0x00660046 => pixel ^ color,               // SRCINVERT
        0x00550009 => !pixel,                     // DSTINVERT
        0x00000042 => 0,                          // BLACKNESS
        0x00FF0062 => 0x00FFFFFF,                 // WHITENESS
        _ => color,                                // Default to SRCCOPY
    }
}

/// Perform BitBlt with ROP support
pub fn bit_blt_with_rop(
    dst_surface: &EngSurface,
    dst_x: i32,
    dst_y: i32,
    width: i32,
    height: i32,
    src_surface: &EngSurface,
    src_x: i32,
    src_y: i32,
    rop: u32,
) -> bool {    let _ = (&dst_surface, &dst_x, &dst_y, &width, &height, &src_surface, &src_x, &src_y, &rop,);

    if dst_surface.bits.is_null() {
        return false;
    }
    if !src_surface.bits.is_null() && rop == RasterOp::SRCCOPY as u32 {
        return copy_rect(dst_surface, dst_x, dst_y, src_surface, src_x, src_y, width, height);
    }

    let dst_pitch = dst_surface.pitch;
    let _ = &dst_pitch;
    let src_pitch = if src_surface.bits.is_null() { 0 } else { src_surface.pitch };
    let _ = &src_pitch;

    for y in 0..height {
        for x in 0..width {
            let dst_offset = ((dst_y + y) * dst_pitch + (dst_x + x) * 4) as isize;
            let _ = &dst_offset;
            let dst_pixel = if src_surface.bits.is_null() {
                0
            } else {
                let src_offset = ((src_y + y) * src_pitch + (src_x + x) * 4) as isize;
                let _ = &src_offset;
                unsafe { *(src_surface.bits.offset(src_offset) as *const u32) }
            };

            let result = if src_surface.bits.is_null() {
                // For operations that don't need source (BLACKNESS, WHITENESS, DSTINVERT)
                apply_rop(0, 0, rop)
            } else {
                unsafe {
                    let current = *(dst_surface.bits.offset(dst_offset) as *const u32);
                    let _ = &current;
                    apply_rop(current, dst_pixel, rop)
                }
            };

            unsafe {
                *(dst_surface.bits.offset(dst_offset) as *mut u32) = result;
            }
        }
    }

    // kprintln!("[win32k] BitBltWithROP {}x{} from ({},{}) to ({},{}) rop=0x{:08x}",  // kprintln disabled (memcpy crash workaround)
//         width, height, src_x, src_y, dst_x, dst_y, rop);
    true
}

// =============================================================================
// Bresenham Line Drawing Algorithm
// =============================================================================

/// Draw a line using Bresenham's algorithm
pub fn draw_line_bresenham(surface: &EngSurface, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {    let _ = (&surface, &x0, &y0, &x1, &y1, &color,);

    if surface.bits.is_null() {
        return;
    }

    let dx = (x1 - x0).abs();
    let _ = &dx;
    let dy = -(y1 - y0).abs();
    let _ = &dy;
    let sx = if x0 < x1 { 1 } else { -1 };
    let _ = &sx;
    let sy = if y0 < y1 { 1 } else { -1 };
    let _ = &sy;
    let mut err = dx + dy;
    let mut x = x0;
    let mut y = y0;

    loop {
        set_pixel_on_surface(surface, x, y, color);

        if x == x1 && y == y1 {
            break;
        }

        let e2 = 2 * err;
        let _ = &e2;
        if e2 >= dy {
            if x == x1 {
                break;
            }
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            if y == y1 {
                break;
            }
            err += dx;
            y += sy;
        }
    }
}

/// Draw anti-aliased line (Wu's algorithm - simplified)
pub fn draw_line_antialiased(surface: &EngSurface, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) {    let _ = (&surface, &x0, &y0, &x1, &y1, &color,);

    // For simplicity, use Bresenham with intensity variation
    draw_line_bresenham(surface, x0, y0, x1, y1, color);
}

// =============================================================================
// Rectangle Filling
// =============================================================================

/// Fill a rectangle with a solid color
pub fn fill_rect_solid(surface: &EngSurface, left: i32, top: i32, right: i32, bottom: i32, color: u32) {    let _ = (&surface, &left, &top, &right, &bottom, &color,);

    if surface.bits.is_null() {
        return;
    }

    let pitch = surface.pitch;
    let _ = &pitch;

    // Clip to surface bounds
    let left = left.max(0);
    let _ = &left;
    let top = top.max(0);
    let _ = &top;
    let right = right.min(surface.width);
    let _ = &right;
    let bottom = bottom.min(surface.height);
    let _ = &bottom;

    if left >= right || top >= bottom {
        return;
    }

    for y in top..bottom {
        let row_ptr = unsafe { surface.bits.add((y * pitch) as usize) };
        let _ = &row_ptr;
        for x in left..right {
            unsafe {
                core::ptr::write_unaligned(
                    row_ptr.add((x * 4) as usize) as *mut u32,
                    color
                );
            }
        }
    }
}

/// Fill rectangle using brush pattern
pub fn fill_rect_with_brush(
    surface: &EngSurface,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: u32,
    hatch_style: HatchStyle,
) {    let _ = (&surface, &left, &top, &right, &bottom, &color, &hatch_style,);

    if surface.bits.is_null() {
        return;
    }

    let width = right - left;
    let _ = &width;
    let height = bottom - top;
    let _ = &height;

    for y in 0..height {
        for x in 0..width {
            let should_fill = match hatch_style {
                HatchStyle::Horizontal => y % 2 == 0,
                HatchStyle::Vertical => x % 2 == 0,
                HatchStyle::FDiagonal => (x + y) % 2 == 0,
                HatchStyle::BDiagonal => (x + y) % 2 == 0,
                HatchStyle::Cross => x % 2 == 0 || y % 2 == 0,
                HatchStyle::DiagonalCross => x % 2 == 0 && y % 2 == 0,
            };

            if should_fill {
                set_pixel_on_surface(surface, left + x, top + y, color);
            }
        }
    }
}

// =============================================================================
// Text Rendering (Basic Bitmap Font)
// =============================================================================

/// Simple 8x8 bitmap font data (5x7 printable ASCII characters 32-126)
/// Each character is 7 bytes (rows), bit 7 is padding
/// Data format: MSB first, each row is one byte
const FONT_DATA: &[u8] = &[
    // Space ' '
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // '!' (exclamation)
    0x18, 0x3E, 0x3E, 0x3E, 0x18, 0x00, 0x18,
    // '"' (quote)
    0x6C, 0x6C, 0x24, 0x00, 0x00, 0x00, 0x00,
    // '#'
    0x24, 0x7E, 0x24, 0x24, 0x7E, 0x24, 0x00,
    // '$'
    0x04, 0x2E, 0x68, 0x3C, 0x0E, 0x7B, 0x00,
    // '%'
    0x60, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x06,
    // '&'
    0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F,
    // '''
    0x18, 0x18, 0x08, 0x00, 0x00, 0x00, 0x00,
    // '('
    0x08, 0x10, 0x20, 0x20, 0x20, 0x10, 0x08,
    // ')'
    0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08,
    // '*'
    0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00,
    // '+'
    0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00,
    // ','
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10,
    // '-'
    0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00,
    // '.'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18,
    // '/'
    0x00, 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60,
    // '0'
    0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C,
    // '1'
    0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E,
    // '2'
    0x3C, 0x66, 0x06, 0x1C, 0x30, 0x60, 0x7E,
    // '3'
    0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C,
    // '4'
    0x06, 0x0E, 0x1E, 0x66, 0x7F, 0x06, 0x06,
    // '5'
    0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C,
    // '6'
    0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C,
    // '7'
    0x7E, 0x66, 0x0C, 0x18, 0x18, 0x18, 0x18,
    // '8'
    0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C,
    // '9'
    0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38,
    // ':'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00,
    // ';'
    0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x10,
    // '<'
    0x08, 0x10, 0x20, 0x40, 0x20, 0x10, 0x08,
    // '='
    0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00,
    // '>'
    0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08,
    // '?'
    0x3C, 0x66, 0x06, 0x1C, 0x18, 0x00, 0x18,
    // '@'
    0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C,
    // 'A'
    0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42,
    // 'B'
    0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C,
    // 'C'
    0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C,
    // 'D'
    0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78,
    // 'E'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E,
    // 'F'
    0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60,
    // 'G'
    0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E,
    // 'H'
    0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66,
    // 'I'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E,
    // 'J'
    0x1F, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38,
    // 'K'
    0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66,
    // 'L'
    0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E,
    // 'M'
    0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63,
    // 'N'
    0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66,
    // 'O'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C,
    // 'P'
    0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60,
    // 'Q'
    0x3C, 0x66, 0x66, 0x66, 0x66, 0x6F, 0x3D,
    // 'R'
    0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66,
    // 'S'
    0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C,
    // 'T'
    0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
    // 'U'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C,
    // 'V'
    0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18,
    // 'W'
    0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63,
    // 'X'
    0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66,
    // 'Y'
    0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18,
    // 'Z'
    0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E,
    // '['
    0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C,
    // '\'
    0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00,
    // ']'
    0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C,
    // '^'
    0x18, 0x24, 0x42, 0x00, 0x00, 0x00, 0x00,
    // '_'
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7E,
    // 'a'
    0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E,
    // 'b'
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C,
    // 'c'
    0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C,
    // 'd'
    0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E,
    // 'e'
    0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C,
    // 'f'
    0x0C, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x18,
    // 'g'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C,
    // 'h'
    0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66,
    // 'i'
    0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C,
    // 'j'
    0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0x6C, 0x38,
    // 'k'
    0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66,
    // 'l'
    0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C,
    // 'm'
    0x00, 0x00, 0x6E, 0x7F, 0x6B, 0x63, 0x63,
    // 'n'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66,
    // 'o'
    0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C,
    // 'p'
    0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60,
    // 'q'
    0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06,
    // 'r'
    0x00, 0x00, 0x6E, 0x76, 0x60, 0x60, 0x60,
    // 's'
    0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C,
    // 't'
    0x18, 0x18, 0x3C, 0x18, 0x18, 0x1A, 0x0C,
    // 'u'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E,
    // 'v'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18,
    // 'w'
    0x00, 0x00, 0x63, 0x6B, 0x7F, 0x77, 0x63,
    // 'x'
    0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66,
    // 'y'
    0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C,
    // 'z'
    0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E,
    // '{'
    0x0E, 0x18, 0x18, 0x30, 0x18, 0x18, 0x0E,
    // '|'
    0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
    // '}'
    0x70, 0x18, 0x18, 0x0C, 0x18, 0x18, 0x70,
    // '~'
    0x00, 0x76, 0x3C, 0x00, 0x00, 0x00, 0x00,
];

/// Number of characters in the font
const FONT_CHAR_COUNT: usize = 95;

/// Bytes per character in font data
const FONT_CHAR_SIZE: usize = 7;

/// Draw a single character using bitmap font
pub fn draw_char(surface: &EngSurface, x: i32, y: i32, ch: u8, color: u32, bg_color: u32) {    let _ = (&surface, &x, &y, &ch, &color, &bg_color,);

    if surface.bits.is_null() {
        return;
    }

    // Convert ASCII to font index (space to tilde = 0-94)
    let idx = ch.wrapping_sub(b' ') as usize;
    let _ = &idx;
    if idx >= FONT_CHAR_COUNT {
        return;
    }

    let char_base = idx * FONT_CHAR_SIZE;
    let _ = &char_base;

    for row in 0i32..8 {
        let row_data = if row < FONT_CHAR_SIZE as i32 {
            FONT_DATA[char_base + row as usize]
        } else {
            0
        };

        for col in 0i32..8 {
            let bit = (row_data >> (7 - col)) & 1;
            let _ = &bit;
            let pixel_color = if bit != 0 { color } else { bg_color };
            let _ = &pixel_color;
            set_pixel_on_surface(surface, x + col, y + row, pixel_color);
        }
    }
}

/// Draw text string
pub fn draw_text(surface: &EngSurface, x: i32, y: i32, text: &[u8], color: u32, bg_color: u32) -> i32 {    let _ = (&surface, &x, &y, &text, &color, &bg_color,);

    let mut cursor_x = x;

    for &ch in text {
        draw_char(surface, cursor_x, y, ch, color, bg_color);
        cursor_x += 8; // 8 pixels per character
    }

    cursor_x - x
}

// =============================================================================
// Ellipse and Circle Drawing
// =============================================================================

/// Draw an ellipse using midpoint algorithm (simplified, integer-only)
pub fn draw_ellipse(surface: &EngSurface, cx: i32, cy: i32, rx: i32, ry: i32, color: u32) {    let _ = (&surface, &cx, &cy, &rx, &ry, &color,);

    if surface.bits.is_null() || rx <= 0 || ry <= 0 {
        return;
    }

    // Simplified circle algorithm using Bresenham's method
    // For true ellipse, we'll approximate with symmetric circles
    let mut x = 0i32;
    let mut y = ry as i32;
    let mut d1 = (ry as i32) * (ry as i32) - (rx as i32) * (rx as i32) * (ry as i32) + ((rx as i32) * (rx as i32) / 4);

    while (ry as i32) * (ry as i32) * x <= (rx as i32) * (rx as i32) * y {
        // Draw symmetric points
        set_pixel_on_surface(surface, cx + x, cy + y, color);
        set_pixel_on_surface(surface, cx - x, cy + y, color);
        set_pixel_on_surface(surface, cx + x, cy - y, color);
        set_pixel_on_surface(surface, cx - x, cy - y, color);

        x += 1;
        if d1 < 0 {
            d1 += (ry as i32) * (ry as i32) * (2 * x + 1);
        } else {
            y -= 1;
            d1 += (ry as i32) * (ry as i32) * (2 * x + 1) - 2 * (rx as i32) * (rx as i32) * y;
        }
    }

    let mut d2 = ((ry as i32) * (ry as i32)) * ((x - 1) * (x - 1))
        + ((rx as i32) * (rx as i32)) * ((y - 1) * (y - 1))
        - ((rx as i32) * (rx as i32)) * ((ry as i32) * (ry as i32));

    while y >= 0 {
        set_pixel_on_surface(surface, cx + x, cy + y, color);
        set_pixel_on_surface(surface, cx - x, cy + y, color);
        set_pixel_on_surface(surface, cx + x, cy - y, color);
        set_pixel_on_surface(surface, cx - x, cy - y, color);

        y -= 1;
        if d2 > 0 {
            d2 += (rx as i32) * (rx as i32) - 2 * (rx as i32) * (rx as i32) * y;
        } else {
            x += 1;
            d2 += (ry as i32) * (ry as i32) * (2 * x - 1) - 2 * (rx as i32) * (rx as i32) * y;
        }
    }
}

/// Draw a circle (special case of ellipse)
pub fn draw_circle(surface: &EngSurface, cx: i32, cy: i32, r: i32, color: u32) {    let _ = (&surface, &cx, &cy, &r, &color,);

    draw_ellipse(surface, cx, cy, r, r, color);
}

// =============================================================================
// Arc and Pie Drawing (Simplified)
// =============================================================================

/// Draw a horizontal line (arc approximation)
pub fn draw_arc_horizontal(surface: &EngSurface, x1: i32, x2: i32, y: i32, color: u32) {    let _ = (&surface, &x1, &x2, &y, &color,);

    if surface.bits.is_null() {
        return;
    }
    for x in x1..=x2 {
        set_pixel_on_surface(surface, x, y, color);
    }
}

/// Draw a vertical line (arc approximation)
pub fn draw_arc_vertical(surface: &EngSurface, x: i32, y1: i32, y2: i32, color: u32) {    let _ = (&surface, &x, &y1, &y2, &color,);

    if surface.bits.is_null() {
        return;
    }
    for y in y1..=y2 {
        set_pixel_on_surface(surface, x, y, color);
    }
}

/// Fill a triangle (simple scanline fill)
fn fill_triangle(surface: &EngSurface, x1: i32, y1: i32, x2: i32, y2: i32, x3: i32, y3: i32, color: u32) {    let _ = (&surface, &x1, &y1, &x2, &y2, &x3, &y3, &color,);

    // Find bounding box
    let min_y = y1.min(y2).min(y3);
    let _ = &min_y;
    let max_y = y1.max(y2).max(y3);
    let _ = &max_y;

    for y in min_y..=max_y {
        // Find intersections with each edge
        let mut intersections = Vec::new();

        // Edge 1-2
        if let Some(x) = line_intersection_y(y, x1, y1, x2, y2) {
            intersections.push(x);
        }
        // Edge 2-3
        if let Some(x) = line_intersection_y(y, x2, y2, x3, y3) {
            intersections.push(x);
        }
        // Edge 3-1
        if let Some(x) = line_intersection_y(y, x3, y3, x1, y1) {
            intersections.push(x);
        }

        // Sort and fill between pairs
        if intersections.len() >= 2 {
            intersections.sort();
            for x in intersections[0]..=intersections[1] {
                set_pixel_on_surface(surface, x, y, color);
            }
        }
    }
}

/// Find x intersection of a line with a horizontal line at y
fn line_intersection_y(y: i32, x1: i32, y1: i32, x2: i32, y2: i32) -> Option<i32> {    let _ = (&y, &x1, &y1, &x2, &y2,);

    if y1 == y2 {
        return None; // Horizontal line
    }

    if y < y1.min(y2) || y > y1.max(y2) {
        return None;
    }

    // Linear interpolation
    let t = (y - y1) as f64 / (y2 - y1) as f64;
    let _ = &t;
    Some((x1 as f64 + t * (x2 - x1) as f64) as i32)
}

// =============================================================================
// Polygon Filling
// =============================================================================

/// Fill a polygon using scanline algorithm
pub fn fill_polygon(surface: &EngSurface, points: &[(i32, i32)], color: u32) {
    if surface.bits.is_null() || points.len() < 3 {
        return;
    }

    // Find bounding box
    let min_y = points.iter().map(|p| p.1).min().unwrap_or(0);
    let _ = &min_y;
    let max_y = points.iter().map(|p| p.1).max().unwrap_or(0);
    let _ = &max_y;

    for y in min_y..=max_y {
        let mut intersections = Vec::new();

        // Find intersections with each edge
        for i in 0..points.len() {
            let j = (i + 1) % points.len();
            let _ = &j;
            let (x1, y1) = points[i];
            let (x2, y2) = points[j];

            if let Some(x) = line_intersection_y(y, x1, y1, x2, y2) {
                intersections.push(x);
            }
        }

        // Sort intersections and fill between pairs
        if intersections.len() >= 2 {
            intersections.sort();
            let mut i = 0;
            while i + 1 < intersections.len() {
                for x in intersections[i]..=intersections[i + 1] {
                    set_pixel_on_surface(surface, x, y, color);
                }
                i += 2;
            }
        }
    }
}

// =============================================================================
// Gradient Filling
// =============================================================================

/// Fill rectangle with horizontal gradient
pub fn fill_rect_gradient_horizontal(surface: &EngSurface, left: i32, top: i32, right: i32, bottom: i32, color1: u32, color2: u32) {    let _ = (&surface, &left, &top, &right, &bottom, &color1, &color2,);

    if surface.bits.is_null() {
        return;
    }

    let width = right - left;
    let _ = &width;

    for y in top..bottom {
        for x in left..right {
            let t = (x - left) as f32 / width as f32;
            let _ = &t;
            let color = lerp_color(color1, color2, t);
            let _ = &color;
            set_pixel_on_surface(surface, x, y, color);
        }
    }
}

/// Fill rectangle with vertical gradient
pub fn fill_rect_gradient_vertical(surface: &EngSurface, left: i32, top: i32, right: i32, bottom: i32, color1: u32, color2: u32) {    let _ = (&surface, &left, &top, &right, &bottom, &color1, &color2,);

    if surface.bits.is_null() {
        return;
    }

    let height = bottom - top;
    let _ = &height;

    for y in top..bottom {
        for x in left..right {
            let t = (y - top) as f32 / height as f32;
            let _ = &t;
            let color = lerp_color(color1, color2, t);
            let _ = &color;
            set_pixel_on_surface(surface, x, y, color);
        }
    }
}

/// Linear interpolation between two colors
fn lerp_color(c1: u32, c2: u32, t: f32) -> u32 {    let _ = (&c1, &c2, &t,);

    let r1 = (c1 >> 16) & 0xFF;
    let _ = &r1;
    let g1 = (c1 >> 8) & 0xFF;
    let _ = &g1;
    let b1 = c1 & 0xFF;
    let _ = &b1;

    let r2 = (c2 >> 16) & 0xFF;
    let _ = &r2;
    let g2 = (c2 >> 8) & 0xFF;
    let _ = &g2;
    let b2 = c2 & 0xFF;
    let _ = &b2;

    let r = ((r1 as f32 + (r2 as f32 - r1 as f32) * t) as u8) as u32;
    let _ = &r;
    let g = ((g1 as f32 + (g2 as f32 - g1 as f32) * t) as u8) as u32;
    let _ = &g;
    let b = ((b1 as f32 + (b2 as f32 - b1 as f32) * t) as u8) as u32;
    let _ = &b;

    (r << 16) | (g << 8) | b
}

/// Get pixel.
pub fn get_pixel(dc: u64, x: i32, y: i32) -> u32 {    let _ = (&dc, &x, &y,);

    // kprintln!("[win32k] EngGetPixel: DC=0x{:x} ({},{})", dc, x, y)  // kprintln disabled (memcpy crash workaround);
    0
}

/// Set pixel.
pub fn set_pixel(dc: u64, x: i32, y: i32, color: u32) -> u32 {    let _ = (&dc, &x, &y, &color,);

    // kprintln!(  // kprintln disabled (memcpy crash workaround)
//         "[win32k] EngSetPixel: DC=0x{:x} ({},{}) = 0x{:x}",
//         dc, x, y, color
//     );
    color
}

// =============================================================================
// Shadow SSDT Service Handlers
// =============================================================================
//
// These are the syscall handlers registered with the Shadow SSDT.
// They follow the Windows x64 calling convention and receive
// arguments via registers/stack as passed by the syscall dispatcher.

#[cfg(target_arch = "x86_64")]
use crate::arch::common::trap_frame::TrapFrame;

/// GDI: GetDC handler
#[cfg(target_arch = "x86_64")]
extern "C" fn gdi_get_dc_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtGdiGetDC called")  // kprintln disabled (memcpy crash workaround);
    0 // Return NULL DC for now
}

/// GDI: ReleaseDC handler
#[cfg(target_arch = "x86_64")]
extern "C" fn gdi_release_dc_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtGdiReleaseDC called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// GDI: DeleteObject handler
#[cfg(target_arch = "x86_64")]
extern "C" fn gdi_delete_object_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtGdiDeleteObject called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// GDI: BitBlt handler
#[cfg(target_arch = "x86_64")]
extern "C" fn gdi_bit_blt_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtGdiBitBlt called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// GDI: Rectangle handler
#[cfg(target_arch = "x86_64")]
extern "C" fn gdi_rectangle_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtGdiRectangle called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// USER: CreateWindow handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_create_window_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserCreateWindow called")  // kprintln disabled (memcpy crash workaround);
    0 // Return NULL HWND for now
}

/// USER: DestroyWindow handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_destroy_window_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserDestroyWindow called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// USER: ShowWindow handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_show_window_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserShowWindow called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// USER: SetWindowPos handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_set_window_pos_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserSetWindowPos called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

/// USER: GetMessage handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_get_message_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserGetMessage called")  // kprintln disabled (memcpy crash workaround);
    0 // Return WM_QUIT = 0
}

/// USER: PostMessage handler
#[cfg(target_arch = "x86_64")]
extern "C" fn user_post_message_handler(tf: *mut TrapFrame) -> u64 {    let _ = (&tf,);

    // kprintln!("[win32k] NtUserPostMessage called")  // kprintln disabled (memcpy crash workaround);
    1 // Return TRUE
}

// =============================================================================
// Menu System (P2 Enhancement)
// =============================================================================

/// Menu item type constants
pub const MFT_STRING: u32 = 0x00000000;
pub const MFT_BITMAP: u32 = 0x00000004;
pub const MFT_MENUBARBREAK: u32 = 0x00000020;
pub const MFT_MENUBREAK: u32 = 0x00000040;
pub const MFT_OWNERDRAW: u32 = 0x00000100;
pub const MFT_POPUP: u32 = 0x00000010;
pub const MFT_SEPARATOR: u32 = 0x00000800;
pub const MFT_RADIOCHECK: u32 = 0x00000002;

/// Menu item state constants
pub const MFS_GRAYED: u32 = 0x00000003;
pub const MFS_DISABLED: u32 = 0x00000003;
pub const MFS_ENABLED: u32 = 0x00000000;
pub const MFS_CHECKED: u32 = 0x00000008;
pub const MFS_UNCHECKED: u32 = 0x00000000;
pub const MFS_DEFAULT: u32 = 0x00001000;

/// Menu flags
pub const MF_BYCOMMAND: u32 = 0x00000000;
pub const MF_BYPOSITION: u32 = 0x00000400;
pub const MF_ENABLED: u32 = 0x00000000;
pub const MF_GRAYED: u32 = 0x00000001;
pub const MF_DISABLED: u32 = 0x00000002;
pub const MF_CHECKED: u32 = 0x00000008;
pub const MF_UNCHECKED: u32 = 0x00000000;
pub const MF_POPUP: u32 = 0x00000010;
pub const MF_SEPARATOR: u32 = 0x00000800;
pub const MF_STRING: u32 = 0x00000000;
pub const MF_OWNERDRAW: u32 = 0x00000100;

/// Menu item structure (simplified)
#[repr(C)]
#[derive(Clone, Debug)]
pub struct MenuItem {
    pub fmask: u32,
    pub itype: u32,
    pub state: u32,
    pub id: u32,
    pub submenu: u64,
    pub hbmp_checked: u64,
    pub hbmp_unchecked: u64,
    pub dw_item_data: u64,
    pub text: alloc::vec::Vec<u16>,
    pub hbmp_item: u64,
}

impl MenuItem {
    pub fn new() -> Self {
        Self {
            fmask: 0,
            itype: MFT_STRING,
            state: MFS_ENABLED,
            id: 0,
            submenu: 0,
            hbmp_checked: 0,
            hbmp_unchecked: 0,
            dw_item_data: 0,
            text: alloc::vec::Vec::new(),
            hbmp_item: 0,
        }
    }
}

/// Menu structure (simplified)
#[derive(Clone, Debug)]
pub struct Menu {
    pub style: u32,
    pub flags: u32,
    pub id: u32,
    pub window: u64,
    pub items: alloc::vec::Vec<MenuItem>,
    pub help_id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Menu {
    pub fn new(style: u32) -> Self {    let _ = (&style,);

        Self {
            style,
            flags: 0,
            id: 0,
            window: 0,
            items: alloc::vec::Vec::new(),
            help_id: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }
    }
}

/// Menu handle table
use core::sync::atomic::{AtomicU64, Ordering};
static MENU_NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x00010000);
use core::sync::atomic::AtomicUsize;
static MENU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Allocate a menu handle
pub fn allocate_menu_handle() -> u64 {
    MENU_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

/// Get menu item count
pub fn get_menu_item_count(menu: &Menu) -> u32 {    let _ = (&menu,);

    menu.items.len() as u32
}

/// Find menu item by position or ID
pub fn find_menu_item(menu: &Menu, id_or_pos: u32, by_position: bool) -> Option<usize> {    let _ = (&menu, &id_or_pos, &by_position,);

    if by_position {
        let pos = id_or_pos as usize;
        let _ = &pos;
        if pos < menu.items.len() {
            Some(pos)
        } else {
            None
        }
    } else {
        menu.items.iter().position(|item| item.id == id_or_pos)
    }
}

// =============================================================================
// Dialog System (P2 Enhancement)
// =============================================================================

/// Dialog constants
pub const IDOK: u32 = 1;
pub const IDCANCEL: u32 = 2;
pub const IDABORT: u32 = 3;
pub const IDRETRY: u32 = 4;
pub const IDIGNORE: u32 = 5;
pub const IDYES: u32 = 6;
pub const IDNO: u32 = 7;
pub const IDCLOSE: u32 = 8;
pub const IDHELP: u32 = 9;

/// MessageBox types
pub const MB_OK: u32 = 0x00000000;
pub const MB_OKCANCEL: u32 = 0x00000001;
pub const MB_ABORTRETRYIGNORE: u32 = 0x00000002;
pub const MB_YESNOCANCEL: u32 = 0x00000003;
pub const MB_YESNO: u32 = 0x00000004;
pub const MB_RETRYCANCEL: u32 = 0x00000005;
pub const MB_ICONHAND: u32 = 0x00000010;
pub const MB_ICONQUESTION: u32 = 0x00000020;
pub const MB_ICONEXCLAMATION: u32 = 0x00000030;
pub const MB_ICONINFORMATION: u32 = 0x00000040;

/// Dialog box template header (simplified)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlgTemplate {
    pub style: u32,
    pub dw_extended_style: u32,
    pub cdit: i16,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
}

impl DlgTemplate {
    pub fn new() -> Self {
        Self {
            style: 0,
            dw_extended_style: 0,
            cdit: 0,
            x: 0,
            y: 0,
            cx: 0,
            cy: 0,
        }
    }
}

/// Dialog structure
#[derive(Clone, Debug)]
pub struct Dialog {
    pub hwnd_owner: u64,
    pub hwnd_template: u64,
    pub instance: u64,
    pub proc: u64,
    pub data: Vec<u8>,
    pub result: i64,
}

impl Dialog {
    pub fn new() -> Self {
        Self {
            hwnd_owner: 0,
            hwnd_template: 0,
            instance: 0,
            proc: 0,
            data: Vec::new(),
            result: 0,
        }
    }
}

// =============================================================================
// Hook System (P2 Enhancement)
// =============================================================================

/// Hook type constants
pub const WH_MIN: i32 = -1;
pub const WH_MSGFILTER: i32 = -1;
pub const WH_JOURNALRECORD: i32 = 0;
pub const WH_JOURNALPLAYBACK: i32 = 1;
pub const WH_KEYBOARD: i32 = 2;
pub const WH_GETMESSAGE: i32 = 3;
pub const WH_CALLWNDPROC: i32 = 4;
pub const WH_CBT: i32 = 5;
pub const WH_SYSMSGFILTER: i32 = 6;
pub const WH_MOUSE: i32 = 7;
pub const WH_HARDWARE: i32 = 8;
pub const WH_DEBUG: i32 = 9;
pub const WH_SHELL: i32 = 10;
pub const WH_FOREGROUNDIDLE: i32 = 11;
pub const WH_CALLWNDPROCRET: i32 = 12;
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WH_MOUSE_LL: i32 = 14;
pub const WH_MAX: i32 = 14;

/// Hook flags
pub const HF_GLOBAL: u32 = 0x0001;
pub const HF_ANCHOR: u32 = 0x0010;
pub const HF_HOOKED: u32 = 0x0004;

/// Hook structure
#[derive(Clone, Debug)]
pub struct Hook {
    pub hook_type: i32,
    pub hook_proc: u64,
    pub module: u64,
    pub thread_id: u32,
    pub flags: u32,
    pub next: u64,
}

impl Hook {
    pub fn new(hook_type: i32, hook_proc: u64, thread_id: u32) -> Self {    let _ = (&hook_type, &hook_proc, &thread_id,);

        Self {
            hook_type,
            hook_proc,
            module: 0,
            thread_id,
            flags: if thread_id == 0 { HF_GLOBAL } else { 0 },
            next: 0,
        }
    }
}

/// Hook handle table
static HOOK_NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x00020000);
use spin::RwLock;
use alloc::boxed::Box;

/// Global hook chains (one per hook type) - initialized empty, expanded on demand
static HOOK_CHAINS: RwLock<alloc::vec::Vec<alloc::vec::Vec<u64>>> = RwLock::new(alloc::vec::Vec::new());

/// Hook handle map
static HOOK_HANDLES: RwLock<Vec<Option<Box<Hook>>>> = RwLock::new(Vec::new());

/// Allocate a hook handle
pub fn allocate_hook_handle() -> u64 {
    HOOK_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

/// Install a hook
pub fn install_hook(hook_type: i32, hook_proc: u64, thread_id: u32) -> Option<u64> {    let _ = (&hook_type, &hook_proc, &thread_id,);

    if hook_type < WH_MIN || hook_type > WH_MAX {
        return None;
    }

    let mut handles = HOOK_HANDLES.write();
    let handle = allocate_hook_handle();
    let _ = &handle;
    let idx = handles.len();
    let _ = &idx;

    let hook = Box::new(Hook::new(hook_type, hook_proc, thread_id));
    let _ = &hook;
    handles.push(Some(hook));

    // Add to chain
    let chain_idx = (hook_type - WH_MIN) as usize;
    let _ = &chain_idx;
    let mut chains = HOOK_CHAINS.write();
    // Ensure we have enough capacity
    while chains.len() <= chain_idx {
        chains.push(alloc::vec::Vec::new());
    }
    chains[chain_idx].push(handle);

    // kprintln!("[win32k] Installed hook type={}, handle={:#x}", hook_type, handle)  // kprintln disabled (memcpy crash workaround);
    Some(handle)
}

/// Remove a hook
pub fn remove_hook(handle: u64) -> bool {    let _ = (&handle,);

    let handles = HOOK_HANDLES.read();
    let _ = &handles;
    let mut found_idx = None;

    for i in 0..handles.len() {
        if let Some(ref hook) = handles[i] {
            if hook.hook_proc != 0 {
                found_idx = Some((i, (hook.hook_type - WH_MIN) as usize));
                break;
            }
        }
    }
    drop(handles);

    if let Some((idx, chain_idx)) = found_idx {
        // Remove from handle map
        let mut handles = HOOK_HANDLES.write();
        handles[idx] = None;

        // Remove from chain
        let mut chains = HOOK_CHAINS.write();
        if chain_idx < chains.len() {
            chains[chain_idx].retain(|&h| h != handle);
        }

        // kprintln!("[win32k] Removed hook handle={:#x}", handle)  // kprintln disabled (memcpy crash workaround);
        true
    } else {
        false
    }
}

/// Call hook chain
pub fn call_hook_chain(hook_type: i32, code: i32, wparam: u64, lparam: i64) -> i64 {    let _ = (&hook_type, &code, &wparam, &lparam,);

    if hook_type < WH_MIN || hook_type > WH_MAX {
        return 0;
    }

    let chain_idx = (hook_type - WH_MIN) as usize;
    let _ = &chain_idx;
    let handles = HOOK_HANDLES.read();
    let _ = &handles;
    let chains = HOOK_CHAINS.read();
    let _ = &chains;
    
    if chain_idx >= chains.len() {
        return 0;
    }

    for &handle in chains[chain_idx].iter() {
        if let Some(Some(ref hook)) = handles.get(handle as usize & 0xFFFF) {
            if hook.hook_proc != 0 {
                // Call the hook procedure
                // In a full implementation, this would call the actual hook procedure
                // kprintln!("[win32k] Calling hook type={}, proc={:#x}", hook_type, hook.hook_proc)  // kprintln disabled (memcpy crash workaround);
            }
        }
    }

    0
}

// =============================================================================
// Timer System (P2 Enhancement)
// =============================================================================

/// Timer flags
pub const TMR_TIMER: u32 = 0x0001;
pub const TMR_PERIODIC: u32 = 0x0002;

/// Timer structure
#[derive(Clone, Debug)]
pub struct UserTimer {
    pub hwnd: u64,
    pub n_id: u32,
    pub u_elapse: u32,
    pub timer_proc: u64,
    pub flags: u32,
}

impl UserTimer {
    pub fn new(hwnd: u64, n_id: u32, u_elapse: u32, timer_proc: u64) -> Self {    let _ = (&hwnd, &n_id, &u_elapse, &timer_proc,);

        Self {
            hwnd,
            n_id,
            u_elapse,
            timer_proc,
            flags: TMR_TIMER,
        }
    }
}

/// Timer handle table
static TIMER_NEXT_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
static TIMER_HANDLES: RwLock<Vec<Option<UserTimer>>> = RwLock::new(Vec::new());
static WINDOW_TIMERS: RwLock<alloc::collections::BTreeMap<u64, Vec<u32>>> = RwLock::new(alloc::collections::BTreeMap::new());

/// Allocate a timer ID
pub fn allocate_timer_id() -> u32 {
    TIMER_NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

/// Create a timer
pub fn create_timer(hwnd: u64, n_id_event: u32, u_elapse: u32, timer_proc: u64) -> Option<u32> {    let _ = (&hwnd, &n_id_event, &u_elapse, &timer_proc,);

    let timer_id = if n_id_event == 0 {
        allocate_timer_id()
    } else {
        n_id_event
    };

    let mut handles = TIMER_HANDLES.write();
    let idx = handles.len();
    let _ = &idx;

    let timer = UserTimer::new(hwnd, timer_id, u_elapse, timer_proc);
    let _ = &timer;
    handles.push(Some(timer));

    // Add to window's timer list
    if hwnd != 0 {
        let mut window_timers = WINDOW_TIMERS.write();
        window_timers.entry(hwnd).or_insert_with(Vec::new).push(timer_id);
    }

    // kprintln!("[win32k] Created timer id={}, hwnd={:#x}, interval={}ms", timer_id, hwnd, u_elapse)  // kprintln disabled (memcpy crash workaround);
    Some(timer_id)
}

/// Kill a timer
pub fn kill_timer(hwnd: u64, n_id_event: u32) -> bool {    let _ = (&hwnd, &n_id_event,);

    let mut handles = TIMER_HANDLES.write();

    for i in 0..handles.len() {
        if let Some(ref timer) = handles[i] {
            if timer.hwnd == hwnd && (n_id_event == 0 || timer.n_id == n_id_event) {
                let timer_n_id = timer.n_id;
                let _ = &timer_n_id;
                handles[i] = None;

                // Remove from window's timer list
                if hwnd != 0 {
                    let mut window_timers = WINDOW_TIMERS.write();
                    if let Some(ids) = window_timers.get_mut(&hwnd) {
                        ids.retain(|&id| id != timer_n_id);
                    }
                }

                // kprintln!("[win32k] Killed timer id={}", timer_n_id)  // kprintln disabled (memcpy crash workaround);
                return true;
            }
        }
    }

    false
}

/// Get timer info
pub fn get_timer(timer_id: u32) -> Option<UserTimer> {    let _ = (&timer_id,);

    let handles = TIMER_HANDLES.read();
    let _ = &handles;
    for timer in handles.iter() {
        if let Some(ref t) = timer {
            if t.n_id == timer_id {
                return Some(t.clone());
            }
        }
    }
    None
}

/// Timer DPC callback (for DPC-based timer implementation)
pub fn timer_dpc_callback(context: *mut u8) {    let _ = (&context,);

    let timer_id = context as u32;
    let _ = &timer_id;
    if let Some(timer) = get_timer(timer_id) {
        if timer.hwnd != 0 && timer.timer_proc != 0 {
            // Send WM_TIMER message
            // kprintln!("[win32k] Timer callback: id={}, hwnd={:#x}", timer_id, timer.hwnd)  // kprintln disabled (memcpy crash workaround);
            // In a full implementation, this would queue a message to the window
        }
    }
}
