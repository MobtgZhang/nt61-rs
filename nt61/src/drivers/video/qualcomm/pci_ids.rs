//! Qualcomm Adreno PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for Qualcomm
//! Adreno graphics processors found in Snapdragon SoCs.
//
//! Hardware support:
//! - Adreno 3xx (Snapdragon S4)
//! - Adreno 4xx (Snapdragon 800/801)
//! - Adreno 5xx (Snapdragon 820/835)
//! - Adreno 6xx (Snapdragon 845+)
//
//! Clean-room implementation based on public specifications.

/// Qualcomm vendor ID
pub const QUALCOMM_VENDOR_ID: u16 = 0x5143;

// =====================================================================
// Adreno 3xx Device IDs
// =====================================================================

/// Adreno 3xx device IDs
pub const ADRENO_A3XX_IDS: &[u16] = &[
    0x0300, // Adreno 302
    0x0302, // Adreno 305
    0x0304, // Adreno 320
    0x0306, // Adreno 330
    0x0307, // Adreno 330
    0x0308, // Adreno 330
];

// =====================================================================
// Adreno 4xx Device IDs
// =====================================================================

/// Adreno 4xx device IDs
pub const ADRENO_A4XX_IDS: &[u16] = &[
    0x0400, // Adreno 405
    0x0401, // Adreno 418
    0x0402, // Adreno 420
    0x0403, // Adreno 430
    0x0404, // Adreno 430
];

// =====================================================================
// Adreno 5xx Device IDs
// =====================================================================

/// Adreno 5xx device IDs
pub const ADRENO_A5XX_IDS: &[u16] = &[
    0x0500, // Adreno 506
    0x0501, // Adreno 512
    0x0502, // Adreno 530
    0x0503, // Adreno 530
    0x0504, // Adreno 540
    0x0505, // Adreno 540
];

// =====================================================================
// Adreno 6xx Device IDs
// =====================================================================

/// Adreno 6xx device IDs
pub const ADRENO_A6XX_IDS: &[u16] = &[
    0x0600, // Adreno 610
    0x0601, // Adreno 612
    0x0602, // Adreno 615
    0x0603, // Adreno 618
    0x0604, // Adreno 620
    0x0605, // Adreno 630
    0x0606, // Adreno 630
    0x0607, // Adreno 630
    0x0608, // Adreno 630
    0x0609, // Adreno 630
    0x0610, // Adreno 640
    0x0611, // Adreno 640
    0x0612, // Adreno 642
    0x0613, // Adreno 642
    0x0614, // Adreno 650
    0x0615, // Adreno 650
    0x0616, // Adreno 660
    0x0617, // Adreno 660
    0x0618, // Adreno 680
    0x0619, // Adreno 680
    0x0620, // Adreno 690
];

// =====================================================================
// Device Name Database
// =====================================================================

/// Get device name from device ID
pub fn device_name(device_id: u16) -> &'static str {
    match device_id {
        // Adreno 3xx
        0x0300 => "Adreno 302",
        0x0302 => "Adreno 305",
        0x0304 => "Adreno 320",
        0x0306 | 0x0307 | 0x0308 => "Adreno 330",
        // Adreno 4xx
        0x0400 => "Adreno 405",
        0x0401 => "Adreno 418",
        0x0402 => "Adreno 420",
        0x0403 | 0x0404 => "Adreno 430",
        // Adreno 5xx
        0x0500 => "Adreno 506",
        0x0501 => "Adreno 512",
        0x0502 | 0x0503 => "Adreno 530",
        0x0504 | 0x0505 => "Adreno 540",
        // Adreno 6xx
        0x0600 => "Adreno 610",
        0x0601 => "Adreno 612",
        0x0602 => "Adreno 615",
        0x0603 => "Adreno 618",
        0x0604 => "Adreno 620",
        0x0605 | 0x0606 | 0x0607 | 0x0608 | 0x0609 => "Adreno 630",
        0x0610 | 0x0611 => "Adreno 640",
        0x0612 | 0x0613 => "Adreno 642",
        0x0614 | 0x0615 => "Adreno 650",
        0x0616 | 0x0617 => "Adreno 660",
        0x0618 | 0x0619 => "Adreno 680",
        0x0620 => "Adreno 690",
        _ => "Unknown Adreno GPU",
    }
}

// =====================================================================
// Architecture Classification
// =====================================================================

/// Adreno GPU generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdrenoGeneration {
    /// Adreno 3xx (Snapdragon S4)
    A3XX,
    /// Adreno 4xx (Snapdragon 800/801)
    A4XX,
    /// Adreno 5xx (Snapdragon 820/835)
    A5XX,
    /// Adreno 6xx (Snapdragon 845+)
    A6XX,
    /// Unknown generation
    Unknown,
}

impl AdrenoGeneration {
    /// Get generation name
    pub fn name(&self) -> &'static str {
        match self {
            AdrenoGeneration::A3XX => "Adreno 3xx",
            AdrenoGeneration::A4XX => "Adreno 4xx",
            AdrenoGeneration::A5XX => "Adreno 5xx",
            AdrenoGeneration::A6XX => "Adreno 6xx",
            AdrenoGeneration::Unknown => "Unknown",
        }
    }
}

/// Determine generation from device ID
pub fn generation_from_device_id(device_id: u16) -> AdrenoGeneration {
    if ADRENO_A3XX_IDS.contains(&device_id) {
        AdrenoGeneration::A3XX
    } else if ADRENO_A4XX_IDS.contains(&device_id) {
        AdrenoGeneration::A4XX
    } else if ADRENO_A5XX_IDS.contains(&device_id) {
        AdrenoGeneration::A5XX
    } else if ADRENO_A6XX_IDS.contains(&device_id) {
        AdrenoGeneration::A6XX
    } else {
        AdrenoGeneration::Unknown
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Adreno generations
#[derive(Debug, Clone, Copy)]
pub struct AdrenoFeatures {
    /// Has 2D acceleration
    pub has_2d_accel: bool,
    /// Has 3D acceleration
    pub has_3d_accel: bool,
    /// Has video decode
    pub has_video_decode: bool,
    /// Has compute capability
    pub has_compute: bool,
    /// Maximum texture size
    pub max_texture_size: u32,
    /// Hardware cursor support
    pub has_cursor: bool,
    /// GPU version
    pub version: u32,
}

impl AdrenoFeatures {
    /// Features for Adreno 3xx
    pub fn a3xx() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: false,
            max_texture_size: 4096,
            has_cursor: true,
            version: 3,
        }
    }

    /// Features for Adreno 4xx
    pub fn a4xx() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            max_texture_size: 8192,
            has_cursor: true,
            version: 4,
        }
    }

    /// Features for Adreno 5xx
    pub fn a5xx() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            max_texture_size: 16384,
            has_cursor: true,
            version: 5,
        }
    }

    /// Features for Adreno 6xx
    pub fn a6xx() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            max_texture_size: 16384,
            has_cursor: true,
            version: 6,
        }
    }
}

/// Get features for a generation
pub fn features_for_generation(gen: AdrenoGeneration) -> AdrenoFeatures {
    match gen {
        AdrenoGeneration::A3XX => AdrenoFeatures::a3xx(),
        AdrenoGeneration::A4XX => AdrenoFeatures::a4xx(),
        AdrenoGeneration::A5XX => AdrenoFeatures::a5xx(),
        AdrenoGeneration::A6XX => AdrenoFeatures::a6xx(),
        AdrenoGeneration::Unknown => AdrenoFeatures::a3xx(),
    }
}
