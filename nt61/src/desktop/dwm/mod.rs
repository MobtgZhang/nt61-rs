//! Desktop Window Manager (DWM)
//!
//! Composition, occlusion, and Aero Glass rendering.
//!
//! DWM is responsible for: blitting each visible window into an offscreen
//! surface, then compositing the surfaces into the screen framebuffer.
//! Composition off (= Classic theme) draws directly to GDI. Composition on
//! (= Aero) draws into offscreen surfaces and uses alpha-blended glass.
use crate::desktop::desktop;

/// Number of surfaces in the DWM scratch pool. Win7 DWM keeps ~12 surfaces
/// for the active windows.
const DWM_SURFACE_POOL_SIZE: usize = 16;

/// Per-window surface attributes (stand-in for the real DXGI/D2D pipeline).
#[derive(Clone, Copy, Default)]
pub struct WindowSurface {
    /// Surface handle id (0 = unallocated).
    pub id: u64,
    /// Surface width in pixels.
    pub width: u32,
    /// Surface height in pixels.
    pub height: u32,
    /// Native window handle (HWND) that owns this surface.
    pub hwnd: u64,
    /// Whether this surface is currently visible (not occluded).
    pub visible: bool,
    /// Whether this surface is the active foreground window.
    pub active: bool,
    /// Glass blur radius (0 = no glass, 8 = strong glass).
    pub glass_radius: u8,
    /// Glass opacity (0 = transparent, 100 = opaque).
    pub glass_opacity: u8,
}

/// Pinned scratch pool keyed by index.
fn scratch_pool() -> [WindowSurface; DWM_SURFACE_POOL_SIZE] {
    [WindowSurface::default(); DWM_SURFACE_POOL_SIZE]
}

/// Initialise DWM.
pub fn init() {
    crate::hal::serial::write_string("[dwm] init\r\n");
    let _ = scratch_pool();
}

/// Compose a frame using the in-kernel software path.
///
/// Returns `true` if the frame was rendered. Win7 DWM can run on software
/// when no D3D adapter is available (the dwm.exe itself starts and falls
/// back to GDI direct draw).
pub fn compose_frame() -> bool {
    if !desktop().composition_enabled.load(core::sync::atomic::Ordering::Acquire) {
        return false;
    }
    // The actual pixel-blit happens via the graphics::display::present()
    // path; we just acknowledge that a frame should be presented.
    true
}

/// Allocate a window surface for `hwnd`.
pub fn alloc_surface(hwnd: u64, width: u32, height: u32) -> Option<u64> {
    let mut pool = scratch_pool();
    for (i, slot) in pool.iter_mut().enumerate() {
        if slot.id == 0 {
            slot.id = (i as u64) + 1;
            slot.hwnd = hwnd;
            slot.width = width;
            slot.height = height;
            slot.visible = true;
            slot.active = false;
            slot.glass_radius = 8;
            slot.glass_opacity = 80;
            return Some(slot.id);
        }
    }
    None
}

/// Deallocate a window surface.
pub fn free_surface(surface_id: u64) {
    let mut pool = scratch_pool();
    for slot in pool.iter_mut() {
        if slot.id == surface_id {
            *slot = WindowSurface::default();
            return;
        }
    }
}

/// Set the visibility of a surface.
pub fn set_surface_visible(surface_id: u64, visible: bool) {
    let mut pool = scratch_pool();
    for slot in pool.iter_mut() {
        if slot.id == surface_id {
            slot.visible = visible;
            return;
        }
    }
}

/// Set the active surface (the foreground window).
pub fn set_active_surface(surface_id: u64) {
    let mut pool = scratch_pool();
    for slot in pool.iter_mut() {
        if slot.id == surface_id {
            slot.active = true;
        } else {
            slot.active = false;
        }
    }
}

/// Apply glass parameters to a surface.
pub fn set_glass(surface_id: u64, radius: u8, opacity: u8) {
    let mut pool = scratch_pool();
    for slot in pool.iter_mut() {
        if slot.id == surface_id {
            slot.glass_radius = radius;
            slot.glass_opacity = opacity;
            return;
        }
    }
}

/// Calculate a blended RGB sample using alpha compositing.
///
/// # Arguments
/// * `bg`     - background RGB (0x00RRGGBB)
/// * `fg`     - foreground RGB (0x00RRGGBB)
/// * `alpha`  - alpha value 0..=255
///
/// Returns the composited RGB value.
pub fn blend(bg: u32, fg: u32, alpha: u8) -> u32 {
    let a = alpha as u32;
    let inv = 255 - a;
    let br = (bg >> 16) & 0xFF;
    let bg_g = (bg >> 8) & 0xFF;
    let bb = bg & 0xFF;
    let fr = (fg >> 16) & 0xFF;
    let fg_g = (fg >> 8) & 0xFF;
    let fb = fg & 0xFF;
    let r = (br * a + fr * inv + 127) / 255;
    let g = (bg_g * a + fg_g * inv + 127) / 255;
    let b = (bb * a + fb * inv + 127) / 255;
    (r << 16) | (g << 8) | b
}
