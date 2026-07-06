//! Zhaoxin and Glenfly PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for Zhaoxin
//! and Glenfly graphics adapters found in Chinese x86 processors.
//
//! Hardware support:
//! - Zhaoxin ZX-Chrome 9 (ZX-D/KX-6000 integrated)
//! - Zhaoxin ZX-E (KX-6000G with Glenfly GT-10C0)
//! - Zhaoxin ZX-F (KX-7000 enhanced integrated)
//
//! Clean-room implementation based on public specifications.

/// Zhaoxin Electronics vendor ID
pub const ZHAOXIN_VENDOR_ID: u16 = 0x1D17;

/// Glenfly Technology vendor ID
pub const GLENFLY_VENDOR_ID: u16 = 0x1F31;

// =====================================================================
// Zhaoxin ZX-Chrome 9 Device IDs (ZX-D generation, KX-5000/KX-6000)
// =====================================================================

/// ZX-Chrome 9 integrated graphics device IDs
pub const ZX_CHROME_9_DEVICE_IDS: &[u16] = &[
    0x0101, // ZX-Chrome 9 (ZX-D) variant 1
    0x0102, // ZX-Chrome 9 (ZX-D) variant 2
    0x0103, // ZX-Chrome 9 (ZX-D) variant 3
    0x0104, // ZX-Chrome 9 (ZX-D) variant 4
    0x0105, // ZX-Chrome 9 (KX-6000) variant 1
    0x0106, // ZX-Chrome 9 (KX-6000) variant 2
    0x0107, // ZX-Chrome 9 (KX-6000) variant 3
    0x0108, // ZX-Chrome 9 (KX-6000) variant 4
];

// =====================================================================
// Zhaoxin ZX-D Device IDs
// =====================================================================

/// ZX-D display controller device IDs (Zhangjiang architecture)
pub const ZX_D_DEVICE_IDS: &[u16] = &[
    0x0151, // ZX-D variant 1
    0x0152, // ZX-D variant 2
    0x0153, // ZX-D variant 3
    0x0154, // ZX-D variant 4
    0x0B00, // ZX-D series variant 5
    0x0B01, // ZX-D series variant 6
    0x1B00, // ZX-D series (KX-6000) variant 7
    0x1B01, // ZX-D series (KX-6000) variant 8
];

// =====================================================================
// Zhaoxin ZX-E Device IDs (KX-6000 series)
// =====================================================================

/// ZX-E / KX-6000 series display controller device IDs
pub const ZX_E_DEVICE_IDS: &[u16] = &[
    0x0161, // ZX-E KX-6000G variant 1
    0x0162, // ZX-E KX-6000G variant 2
    0x0163, // ZX-E KX-6000G variant 3
    0x0164, // ZX-E KX-6000G variant 4
    0x1C00, // KX-6000 series variant 5
    0x1C01, // KX-6000 series variant 6
    0x1C02, // KX-6000 series variant 7
];

// =====================================================================
// Zhaoxin ZX-F Device IDs (KX-7000 series)
// =====================================================================

/// ZX-F / KX-7000 display controller device IDs (Shijidadao architecture)
pub const ZX_F_DEVICE_IDS: &[u16] = &[
    0x0171, // ZX-F KX-7000 variant 1
    0x0172, // ZX-F KX-7000 variant 2
    0x0173, // ZX-F KX-7000 variant 3
    0x0174, // ZX-F KX-7000 variant 4
    0x1D00, // KX-7000 series variant 5
    0x1D01, // KX-7000 series variant 6
];

// =====================================================================
// Glenfly GT-10C0 Device IDs
// =====================================================================

/// Glenfly GT-10C0 device ID (used in KX-6000G)
pub const GLENFLY_GT10C0_DEVICE_ID: u16 = 0x000A;

/// Glenfly GT-11C0 device ID (used in KX-7000)
pub const GLENFLY_GT11C0_DEVICE_ID: u16 = 0x000B;

/// Glenfly graphics device IDs
pub const GLENFLY_DEVICE_IDS: &[u16] = &[
    GLENFLY_GT10C0_DEVICE_ID,
    GLENFLY_GT11C0_DEVICE_ID,
    0x000C, // GT-12C0
    0x000D, // GT-13C0
];

// =====================================================================
// Device Name Database
// =====================================================================

/// Get device name from device ID
pub fn device_name(vendor_id: u16, device_id: u16) -> &'static str {
    if vendor_id == ZHAOXIN_VENDOR_ID {
        match device_id {
            0x0101..=0x0108 => "Zhaoxin ZX-Chrome 9",
            0x0151..=0x0154 => "Zhaoxin ZX-D Display Controller",
            0x0B00 | 0x0B01 => "Zhaoxin ZX-D Series",
            0x1B00 | 0x1B01 => "Zhaoxin ZX-D (KX-6000) Display Controller",
            0x0161..=0x0164 => "Zhaoxin ZX-E / KX-6000G",
            0x1C00 | 0x1C01 | 0x1C02 => "Zhaoxin KX-6000 Series Display",
            0x0171..=0x0174 => "Zhaoxin ZX-F / KX-7000",
            0x1D00 | 0x1D01 => "Zhaoxin KX-7000 Series Display",
            _ => "Unknown Zhaoxin Device",
        }
    } else if vendor_id == GLENFLY_VENDOR_ID {
        match device_id {
            0x000A => "Glenfly GT-10C0",
            0x000B => "Glenfly GT-11C0",
            0x000C => "Glenfly GT-12C0",
            0x000D => "Glenfly GT-13C0",
            _ => "Unknown Glenfly Device",
        }
    } else {
        "Unknown Device"
    }
}

// =====================================================================
// Zhaoxin Variant Classification
// =====================================================================

/// Zhaoxin integrated graphics variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZhaoxinVariant {
    /// ZX-Chrome 9 (S3 Graphics Chrome based)
    ZXChrome9,
    /// ZX-D generation display controller
    ZXD,
    /// ZX-E / KX-6000G display controller
    ZXE,
    /// Glenfly GT-10C0 discrete/integrated graphics
    GlenflyGT10C0,
    /// Glenfly GT-11C0 and newer
    GlenflyGT11C0,
    /// Unknown variant
    Unknown,
}

impl ZhaoxinVariant {
    /// Get variant name for logging
    pub fn name(&self) -> &'static str {
        match self {
            ZhaoxinVariant::ZXChrome9 => "ZX-Chrome 9",
            ZhaoxinVariant::ZXD => "ZX-D",
            ZhaoxinVariant::ZXE => "ZX-E / KX-6000G",
            ZhaoxinVariant::GlenflyGT10C0 => "Glenfly GT-10C0",
            ZhaoxinVariant::GlenflyGT11C0 => "Glenfly GT-11C0+",
            ZhaoxinVariant::Unknown => "Unknown",
        }
    }

    /// Check if this is a Glenfly device
    pub fn is_glenfly(&self) -> bool {
        matches!(
            self,
            ZhaoxinVariant::GlenflyGT10C0 | ZhaoxinVariant::GlenflyGT11C0
        )
    }
}

/// Determine Zhaoxin variant from device ID
pub fn variant_from_device_id(vendor_id: u16, device_id: u16) -> ZhaoxinVariant {
    if vendor_id == GLENFLY_VENDOR_ID {
        match device_id {
            0x000A => ZhaoxinVariant::GlenflyGT10C0,
            0x000B..=0x00FF => ZhaoxinVariant::GlenflyGT11C0,
            _ => ZhaoxinVariant::Unknown,
        }
    } else if vendor_id == ZHAOXIN_VENDOR_ID {
        if ZX_CHROME_9_DEVICE_IDS.contains(&device_id) {
            ZhaoxinVariant::ZXChrome9
        } else if ZX_D_DEVICE_IDS.contains(&device_id) {
            ZhaoxinVariant::ZXD
        } else if ZX_E_DEVICE_IDS.contains(&device_id) {
            ZhaoxinVariant::ZXE
        } else if ZX_F_DEVICE_IDS.contains(&device_id) {
            ZhaoxinVariant::ZXE // ZX-F uses similar architecture
        } else {
            ZhaoxinVariant::Unknown
        }
    } else {
        ZhaoxinVariant::Unknown
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Zhaoxin variants
#[derive(Debug, Clone, Copy)]
pub struct ZhaoxinFeatures {
    /// Maximum display width
    pub max_width: u32,
    /// Maximum display height
    pub max_height: u32,
    /// Number of displays supported
    pub num_displays: u8,
    /// Hardware cursor support
    pub has_cursor: bool,
    /// Cursor size in pixels
    pub cursor_size: u8,
    /// 2D acceleration support
    pub has_2d_accel: bool,
    /// 3D acceleration support (limited)
    pub has_3d_accel: bool,
    /// DirectX 11.1 support (Chrome 9)
    pub has_dx11: bool,
    /// Video decode support
    pub has_video_decode: bool,
    /// Hardware overlay planes
    pub num_overlay_planes: u8,
}

impl ZhaoxinFeatures {
    /// Get features for ZX-Chrome 9
    pub fn chrome_9() -> Self {
        Self {
            max_width: 4096,
            max_height: 2304,
            num_displays: 2,
            has_cursor: true,
            cursor_size: 64,
            has_2d_accel: true,
            has_3d_accel: true,
            has_dx11: true,
            has_video_decode: true,
            num_overlay_planes: 1,
        }
    }

    /// Get features for ZX-D
    pub fn zxd() -> Self {
        Self {
            max_width: 3840,
            max_height: 2160,
            num_displays: 2,
            has_cursor: true,
            cursor_size: 64,
            has_2d_accel: true,
            has_3d_accel: false,
            has_dx11: false,
            has_video_decode: true,
            num_overlay_planes: 1,
        }
    }

    /// Get features for ZX-E / KX-6000G
    pub fn zxe() -> Self {
        Self {
            max_width: 4096,
            max_height: 2304,
            num_displays: 2,
            has_cursor: true,
            cursor_size: 64,
            has_2d_accel: true,
            has_3d_accel: true,
            has_dx11: true,
            has_video_decode: true,
            num_overlay_planes: 2,
        }
    }

    /// Get features for Glenfly GT-10C0
    pub fn glenfly_gt10c0() -> Self {
        Self {
            max_width: 4096,
            max_height: 2304,
            num_displays: 2,
            has_cursor: true,
            cursor_size: 64,
            has_2d_accel: true,
            has_3d_accel: true,
            has_dx11: true,
            has_video_decode: true,
            num_overlay_planes: 2,
        }
    }
}

/// Get features for a Zhaoxin variant
pub fn features_for_variant(variant: ZhaoxinVariant) -> ZhaoxinFeatures {
    match variant {
        ZhaoxinVariant::ZXChrome9 => ZhaoxinFeatures::chrome_9(),
        ZhaoxinVariant::ZXD => ZhaoxinFeatures::zxd(),
        ZhaoxinVariant::ZXE => ZhaoxinFeatures::zxe(),
        ZhaoxinVariant::GlenflyGT10C0 | ZhaoxinVariant::GlenflyGT11C0 => {
            ZhaoxinFeatures::glenfly_gt10c0()
        }
        ZhaoxinVariant::Unknown => ZhaoxinFeatures::zxd(),
    }
}

// =====================================================================
// Display Mode Database
// =====================================================================

/// Standard display modes supported by Zhaoxin graphics
#[derive(Debug, Clone, Copy)]
pub struct SupportedMode {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Refresh rate in Hz
    pub refresh: u32,
    /// Pixel format
    pub format: DisplayFormat,
}

/// Display format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayFormat {
    /// 16-bit RGB (5-6-5)
    Rgb565,
    /// 24-bit RGB (8-8-8)
    Rgb888,
    /// 32-bit ARGB (8-8-8-8)
    Argb8888,
    /// 32-bit BGRA (8-8-8-8) - preferred
    Bgra8888,
}

impl DisplayFormat {
    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> u32 {
        match self {
            DisplayFormat::Rgb565 => 2,
            DisplayFormat::Rgb888 => 3,
            DisplayFormat::Argb8888 | DisplayFormat::Bgra8888 => 4,
        }
    }
}

/// Standard supported display modes
pub const STANDARD_MODES: &[SupportedMode] = &[
    // VESA modes
    SupportedMode {
        width: 640,
        height: 480,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 800,
        height: 600,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1024,
        height: 768,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1280,
        height: 720,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1280,
        height: 800,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1280,
        height: 1024,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1366,
        height: 768,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1440,
        height: 900,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1600,
        height: 900,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1680,
        height: 1050,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1920,
        height: 1080,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 1920,
        height: 1200,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 2560,
        height: 1440,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 2560,
        height: 1600,
        refresh: 60,
        format: DisplayFormat::Bgra8888,
    },
    SupportedMode {
        width: 3840,
        height: 2160,
        refresh: 30,
        format: DisplayFormat::Bgra8888,
    },
];
