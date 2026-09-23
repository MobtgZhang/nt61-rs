//! Desktop Module
//!
//! Desktop Window Manager (DWM), Aero Glass, and desktop applications.
//!
//! This implements the user-visible desktop environment: compositing, glass
//! effects, window management, and shell applications (calc.exe, notepad.exe,
//! explorer.exe, taskbar, etc.). It builds on top of the `win32k`/GDI stack
//! and the `graphics` subsystem for actual rendering.
//!
//! Architecture:
//! - `dwm`     : Window compositor + glass effects
//! - `aero`    : Glass blur, glass reflection, colorization
//! - `applications` : Built-in shell apps (calc, notepad, clock, taskbar)

pub mod dwm;
pub mod aero;
pub mod applications;

// =====================================================================
// Desktop state — uses OnceLock so the spin is removed.
// =====================================================================
use crate::ke::sync::OnceLock;

/// Desktop subsystem.
pub struct Desktop {
    /// Whether DWM (composition) is on.
    pub composition_enabled: core::sync::atomic::AtomicBool,
    /// Whether Aero Glass is on.
    pub aero_enabled: core::sync::atomic::AtomicBool,
    /// Number of virtual desktops (Win7 default 1).
    pub virtual_desktop_count: core::sync::atomic::AtomicU32,
    /// Current "active" workspace id (0-based).
    pub active_workspace: core::sync::atomic::AtomicU32,
}

impl Desktop {
    const fn new() -> Self {
        Self {
            composition_enabled: core::sync::atomic::AtomicBool::new(false),
            aero_enabled: core::sync::atomic::AtomicBool::new(false),
            virtual_desktop_count: core::sync::atomic::AtomicU32::new(1),
            active_workspace: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

/// Global desktop instance, lazily initialised.
static DESKTOP: OnceLock<Desktop> = OnceLock::new();

/// Get (or initialise) the global desktop.
pub fn desktop() -> &'static Desktop {
    DESKTOP.get_or_init(Desktop::new)
}

/// Toggle DWM composition.
pub fn set_composition_enabled(on: bool) {
    desktop().composition_enabled.store(on, core::sync::atomic::Ordering::Release);
}

/// Toggle Aero Glass effects.
pub fn set_aero_enabled(on: bool) {
    desktop().aero_enabled.store(on, core::sync::atomic::Ordering::Release);
}

/// Switch the active virtual desktop.
pub fn switch_to_workspace(id: u32) {
    desktop().active_workspace.store(id, core::sync::atomic::Ordering::Release);
}

/// Allocate a virtual desktop id.
pub fn allocate_workspace() -> Option<u32> {
    let d = desktop();
    let prev = d.virtual_desktop_count.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    if prev < 256 {
        Some(prev)
    } else {
        None
    }
}

/// Initialise the desktop subsystem.
///
/// Must be called after `win32k::init()` and `graphics::init()`.
pub fn init() {
    boot_desktop();
    // Default desktop is set up lazily via OnceLock; nothing else to do.
    dwm::init();
    aero::init();
    applications::init();
    set_composition_enabled(true);
    set_aero_enabled(true);
    crate::hal::serial::write_string("[desktop] initialized\r\n");
}

/// Pre-init hook, called during early boot from the kernel mainline.
pub fn early_init() {
    crate::hal::serial::write_string("[desktop] early_init\r\n");
}
