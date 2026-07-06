//! Loongson PCI ID Database
//
//! Contains the PCI vendor and device IDs for Loongson display controllers.

/// Loongson Technology vendor ID
pub const LOONGSON_VENDOR_ID: u16 = 0x0014;

// =====================================================================
// Loongson Display Controller Device IDs
// =====================================================================

/// Loongson DC device ID for LS7A chipset
pub const LS7A_DC_DEVICE_ID: u16 = 0x7A05;

/// Loongson DC device ID for 3A5000 integrated display
pub const LS3A5000_DC_DEVICE_ID: u16 = 0x7A0A;

/// Loongson DC device ID for 2K2000 integrated display
pub const LS2K2000_DC_DEVICE_ID: u16 = 0x7A1A;

/// Loongson DC device ID for 2K3000 integrated display
pub const LS2K3000_DC_DEVICE_ID: u16 = 0x7A2A;

/// All known Loongson DC device IDs
pub const LOONGSON_DC_DEVICE_IDS: &[u16] = &[
    LS7A_DC_DEVICE_ID,
    LS3A5000_DC_DEVICE_ID,
    LS2K2000_DC_DEVICE_ID,
    LS2K3000_DC_DEVICE_ID,
];

/// Check if a device ID is a known Loongson DC
pub fn is_loongson_dc(device_id: u16) -> bool {
    LOONGSON_DC_DEVICE_IDS.contains(&device_id)
}

/// Get chip name from device ID
pub fn chip_name(device_id: u16) -> &'static str {
    match device_id {
        LS7A_DC_DEVICE_ID => "LS7A",
        LS3A5000_DC_DEVICE_ID => "3A5000",
        LS2K2000_DC_DEVICE_ID => "2K2000",
        LS2K3000_DC_DEVICE_ID => "2K3000",
        _ => "Unknown",
    }
}

/// Get chip type from device ID
pub fn chip_from_device_id(device_id: u16) -> crate::drivers::video::core::gpu_common::LoongsonChip {
    match device_id {
        LS7A_DC_DEVICE_ID => crate::drivers::video::core::gpu_common::LoongsonChip::Ls7A,
        LS3A5000_DC_DEVICE_ID => crate::drivers::video::core::gpu_common::LoongsonChip::Ls3A5000,
        LS2K2000_DC_DEVICE_ID => crate::drivers::video::core::gpu_common::LoongsonChip::Ls2K2000,
        LS2K3000_DC_DEVICE_ID => crate::drivers::video::core::gpu_common::LoongsonChip::Ls2K3000,
        _ => crate::drivers::video::core::gpu_common::LoongsonChip::Unknown,
    }
}

/// Common display resolutions supported by Loongson DC
pub mod resolutions {
    /// 640x480 @ 60Hz
    pub const VGA: (u32, u32) = (640, 480);
    /// 800x600 @ 60Hz
    pub const SVGA: (u32, u32) = (800, 600);
    /// 1024x768 @ 60Hz
    pub const XGA: (u32, u32) = (1024, 768);
    /// 1280x720 @ 60Hz
    pub const HD_720P: (u32, u32) = (1280, 720);
    /// 1280x800 @ 60Hz
    pub const WXGA: (u32, u32) = (1280, 800);
    /// 1280x1024 @ 60Hz
    pub const SXGA: (u32, u32) = (1280, 1024);
    /// 1366x768 @ 60Hz
    pub const HD_768P: (u32, u32) = (1366, 768);
    /// 1440x900 @ 60Hz
    pub const WXGA_PLUS: (u32, u32) = (1440, 900);
    /// 1600x900 @ 60Hz
    pub const HD_PLUS: (u32, u32) = (1600, 900);
    /// 1600x1200 @ 60Hz
    pub const UXGA: (u32, u32) = (1600, 1200);
    /// 1920x1080 @ 60Hz
    pub const FHD: (u32, u32) = (1920, 1080);
    /// 1920x1200 @ 60Hz
    pub const WUXGA: (u32, u32) = (1920, 1200);
    /// 2560x1440 @ 60Hz
    pub const QHD: (u32, u32) = (2560, 1440);
    /// 2560x1600 @ 60Hz
    pub const WQXGA: (u32, u32) = (2560, 1600);
    /// 3840x2160 @ 60Hz
    pub const UHD_4K: (u32, u32) = (3840, 2160);
}
