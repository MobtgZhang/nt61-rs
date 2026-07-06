//! NVIDIA PCI ID Database
//
//! This module provides PCI vendor and device ID definitions for NVIDIA
//! graphics adapters, including legacy and modern GPUs.
//
//! Hardware support:
//! - NV50/Tesla (GeForce 8xxx-9xxx)
//! - NVA0/NVC0/Fermi (GeForce GTX 260-600)
//! - NVD0/Kepler (GeForce GTX 600-700)
//! - NV110/Maxwell (GeForce GTX 900)
//! - NV120/Pascal (GeForce GTX 1000)
//! - NV140/Turing (GeForce RTX 2000)
//
//! Clean-room implementation based on public specifications.

/// NVIDIA vendor ID
pub const NVIDIA_VENDOR_ID: u16 = 0x10DE;

// =====================================================================
// NV50 (Tesla) Device IDs - GeForce 8xxx/9xxx
// =====================================================================

/// NV50/Tesla architecture device IDs
pub const NV50_DEVICE_IDS: &[u16] = &[
    0x0191, // GeForce 8800 GTS 320M
    0x0193, // GeForce 8800 GTX
    0x0194, // GeForce 8800 GTS
    0x0195, // GeForce 8800 Ultra
    0x0400, // GeForce 8600 GTS
    0x0401, // GeForce 8600 GT
    0x0402, // GeForce 8500 GT
    0x0403, // GeForce 8400 GS
    0x0404, // GeForce 8400 SE
    0x0600, // GeForce 9800 GT
    0x0601, // GeForce 9800 GTX
    0x0602, // GeForce 9800 GX2
    0x0603, // GeForce 9800 GT
    0x0611, // GeForce 9600 GSO
    0x0612, // GeForce 9600 GT
    0x0622, // GeForce 9500 GT
    0x0623, // GeForce 9400 GT
];

// =====================================================================
// NVC0 (Fermi) Device IDs - GeForce GTX 400/500
// =====================================================================

/// NVC0/Fermi architecture device IDs
pub const NVC0_DEVICE_IDS: &[u16] = &[
    0x0CA0, // GeForce GTX 460
    0x0CA2, // GeForce GTX 460 SE
    0x0CA3, // GeForce GTX 460M
    0x0CA4, // GeForce GTX 465
    0x0CA5, // GeForce GTX 470
    0x0CA7, // GeForce GTX 480
    0x0CA8, // GeForce GTX 480M
    0x0CA9, // GeForce GTX 470M
    0x0DC0, // GeForce GTX 460
    0x0DC4, // GeForce GTX 465
    0x0DC5, // GeForce GTX 470
    0x0DC6, // GeForce GTX 470M
    0x0DC7, // GeForce GTX 460M
    0x0DC8, // GeForce GTX 480M
    0x0DCD, // GeForce GTX 460M
    0x0DCE, // GeForce GTX 460 SE
    0x0DD1, // GeForce GTX 460
    0x0DD2, // GeForce GTX 460 SE
    0x0DD3, // GeForce GT 440
    0x0DD6, // GeForce GT 430
    0x0DDA, // GeForce GT 420
    0x0DE0, // GeForce GTX 560
    0x0DE1, // GeForce GTX 560 SE
    0x0DE2, // GeForce GTX 560M
    0x0DE3, // GeForce GTX 555
    0x0DE4, // GeForce GTX 550 Ti
    0x0DE5, // GeForce GT 640M
    0x0DE7, // GeForce GT 630M
    0x0DE8, // GeForce GT 620M
    0x0DEA, // GeForce GT 640M LE
    0x0DEE, // GeForce GT 635M
];

// =====================================================================
// NVD0 (Kepler) Device IDs - GeForce GTX 600/700
// =====================================================================

/// NVD0/Kepler architecture device IDs
pub const NVD0_DEVICE_IDS: &[u16] = &[
    0x0E23, // GeForce GT 705A
    0x0E24, // GeForce GT 705M
    0x1000, // GeForce GT 720M
    0x1001, // GeForce GT 720M
    0x1003, // GeForce 710M
    0x1005, // GeForce GT 620M
    0x100A, // GeForce GT 640M
    0x100C, // GeForce GT 650M
    0x100D, // GeForce GTX 660M
    0x100F, // GeForce GT 650M
    0x1010, // GeForce GTX 660M
    0x1015, // GeForce GT 640M LE
    0x1017, // GeForce GT 645M
    0x1018, // GeForce GT 640M LE
    0x1020, // GeForce GTX 680M
    0x1021, // GeForce GTX 680M
    0x1022, // GeForce GTX 670MX
    0x1023, // GeForce GTX 675MX
    0x1024, // GeForce GTX 680MX
    0x1025, // GeForce GTX 660
    0x1026, // GeForce GTX 650
    0x1027, // GeForce GT 740M
    0x1028, // GeForce GTX 660 Ti
    0x1029, // GeForce GT 755M
    0x102A, // GeForce GTX 760M
    0x102B, // GeForce GTX 765M
    0x102C, // GeForce GTX 770M
    0x102D, // GeForce GTX 780M
    0x102E, // GeForce GTX 775M
    0x102F, // GeForce GTX 780M
    0x1030, // GeForce GT 730M
    0x1031, // GeForce GT 745M
    0x1032, // GeForce GT 745M
    0x1033, // GeForce GT 735M
    0x1034, // GeForce 710M
    0x1035, // GeForce GT 735M
    0x1036, // GeForce GTX 660
    0x1037, // GeForce GT 720M
    0x1038, // GeForce GTX 760
    0x1039, // GeForce GTX 760
    0x103A, // GeForce GTX 750
    0x103B, // GeForce GTX 750 Ti
    0x103C, // GeForce GT 740A
    0x1040, // GeForce GTX 770
    0x1041, // GeForce GTX 760
    0x1042, // GeForce GTX 760
    0x1043, // GeForce GTX 760
    0x1044, // GeForce GTX 760 Ti
    0x1045, // GeForce GTX 780
    0x1046, // GeForce GTX 780
    0x1047, // GeForce GTX 780
    0x1048, // GeForce GTX 780
    0x1049, // GeForce GTX TITAN
    0x104A, // GeForce GTX TITAN Black
    0x104B, // GeForce GTX TITAN
    0x104C, // GeForce GTX 750 Ti
    0x104D, // GeForce GTX 750
    0x1050, // GeForce GTX 660
    0x1051, // GeForce GTX 650
    0x1052, // GeForce GT 640
    0x1054, // GeForce GT 630
    0x1055, // GeForce GT 720
    0x1056, // GeForce GT 620
    0x1057, // GeForce GT 610
    0x1058, // GeForce GT 625
    0x1059, // GeForce GT 720
    0x105A, // GeForce GT 720
    0x105B, // GeForce GT 730
    0x1080, // GeForce GTX 660
    0x1180, // GeForce GTX 660
    0x1181, // GeForce GTX 660
    0x1182, // GeForce GTX 660
    0x1183, // GeForce GTX 660
    0x1184, // GeForce GTX 670
    0x1185, // GeForce GTX 660 Ti
    0x1186, // GeForce GTX 660
    0x1187, // GeForce GTX 660
    0x1188, // GeForce GTX 660
    0x1189, // GeForce GTX 660
    0x118A, // GeForce GTX 660
    0x118F, // GeForce GTX 760
    0x1193, // GeForce GTX 760
    0x1194, // GeForce GTX 760
    0x1195, // GeForce GTX 760
    0x1197, // GeForce GTX 760
    0x1198, // GeForce GTX 760
    0x1199, // GeForce GTX 760
    0x119A, // GeForce GTX 760
    0x119D, // GeForce GTX 760
    0x119F, // GeForce GTX 760
    0x11A1, // GeForce GTX 760
    0x11A3, // GeForce GTX 760
    0x11A7, // GeForce GTX 760
];

// =====================================================================
// NV110 (Maxwell) Device IDs - GeForce GTX 900
// =====================================================================

/// NV110/Maxwell architecture device IDs
pub const NV110_DEVICE_IDS: &[u16] = &[
    0x13C0, // GeForce GTX 970
    0x13C2, // GeForce GTX 970
    0x13C3, // GeForce GTX 970
    0x13C4, // GeForce GTX 960
    0x13C5, // GeForce GTX 960
    0x13D7, // GeForce GTX 950
    0x13D8, // GeForce GTX 950
    0x13D9, // GeForce GTX 950
    0x13DA, // GeForce GTX 950
    0x13F0, // GeForce GTX 980
    0x13F1, // GeForce GTX 980
    0x13F2, // GeForce GTX 980
    0x13F3, // GeForce GTX 980
    0x13F8, // GeForce GTX 980
    0x13F9, // GeForce GTX 980
    0x13FA, // GeForce GTX 980
    0x13FB, // GeForce GTX 980
    0x1400, // GeForce GTX 750 Ti
    0x1401, // GeForce GTX 750
    0x1402, // GeForce GTX 750
    0x1403, // GeForce GT 1030
    0x1404, // GeForce GTX 750
    0x1405, // GeForce GTX 750 Ti
    0x1406, // GeForce GTX 750
];

// =====================================================================
// NV120 (Pascal) Device IDs - GeForce GTX 1000
// =====================================================================

/// NV120/Pascal architecture device IDs
pub const NV120_DEVICE_IDS: &[u16] = &[
    0x1B00, // GeForce GTX 1080
    0x1B01, // GeForce GTX 1080
    0x1B02, // GeForce GTX 1080
    0x1B03, // GeForce GTX 1080
    0x1B04, // GeForce GTX 1070
    0x1B06, // GeForce GTX 1070
    0x1B07, // GeForce GTX 1070
    0x1B08, // GeForce GTX 1070
    0x1B0A, // GeForce GTX 1070
    0x1B0C, // GeForce GTX 1060
    0x1B0D, // GeForce GTX 1060
    0x1B0E, // GeForce GTX 1060
    0x1B0F, // GeForce GTX 1060
    0x1B30, // GeForce GTX 1080
    0x1B80, // GeForce GTX 1050 Ti
    0x1B81, // GeForce GTX 1050
    0x1B82, // GeForce GTX 1050
    0x1B83, // GeForce GTX 1050
    0x1B84, // GeForce GTX 1050 Ti
    0x1B86, // GeForce GTX 1050
    0x1C01, // GeForce GTX 1060
    0x1C02, // GeForce GTX 1060
    0x1C03, // GeForce GTX 1060
    0x1C04, // GeForce GTX 1060
    0x1C06, // GeForce GTX 1060
    0x1C07, // GeForce GTX 1060
    0x1C09, // GeForce GTX 1060
    0x1C60, // GeForce GTX 1060
    0x1C70, // GeForce GTX 1060
    0x1C81, // GeForce GTX 1050
    0x1C82, // GeForce GTX 1050
    0x1C83, // GeForce GTX 1050
    0x1C90, // GeForce GTX 1050
    0x1C91, // GeForce GTX 1050
    0x1C92, // GeForce GTX 1050
    0x1C93, // GeForce GTX 1050 Ti
];

// =====================================================================
// NV140 (Turing) Device IDs - GeForce RTX 2000
// =====================================================================

/// NV140/Turing architecture device IDs
pub const NV140_DEVICE_IDS: &[u16] = &[
    0x1E04, // GeForce RTX 2080 Ti
    0x1E07, // GeForce RTX 2080
    0x1E0C, // GeForce RTX 2080
    0x1E3D, // GeForce RTX 2070
    0x1E3E, // GeForce RTX 2070
    0x1E81, // GeForce RTX 2060
    0x1E82, // GeForce RTX 2060
    0x1E83, // GeForce RTX 2060
    0x1E84, // GeForce RTX 2060
    0x1E87, // GeForce RTX 2060
    0x1E89, // GeForce RTX 2060
    0x1E90, // GeForce RTX 2060 SUPER
    0x1F02, // GeForce GTX 1660 Ti
    0x1F03, // GeForce GTX 1660
    0x1F06, // GeForce GTX 1660
    0x1F07, // GeForce GTX 1660
    0x1F08, // GeForce GTX 1660
    0x1F0A, // GeForce GTX 1660 Ti
    0x1F0C, // GeForce GTX 1660
    0x1F1A, // GeForce GTX 1650
    0x1F82, // GeForce GTX 1650
    0x1F83, // GeForce GTX 1650
    0x1F91, // GeForce GTX 1650
    0x1F94, // GeForce GTX 1650
    0x1F95, // GeForce GTX 1650
    0x1F96, // GeForce GTX 1650
];

// =====================================================================
// NV1A0 / NV150 (Ampere) Device IDs - GeForce RTX 3000
// =====================================================================

/// NV1A0/NV150/Ampere architecture device IDs
pub const NV150_DEVICE_IDS: &[u16] = &[
    0x2204, // GeForce RTX 3090
    0x2206, // GeForce RTX 3090
    0x2212, // GeForce RTX 3080 Ti
    0x2216, // GeForce RTX 3080
    0x2235, // GeForce RTX 3070 Ti
    0x2236, // GeForce RTX 3070
    0x2484, // GeForce RTX 3060 Ti
    0x2504, // GeForce RTX 3060
    0x2520, // GeForce RTX 3050
];

// =====================================================================
// NV250 / NV250 (Ada Lovelace) Device IDs - GeForce RTX 4000
// =====================================================================

/// NV250/Ada Lovelace architecture device IDs
pub const NV250_DEVICE_IDS: &[u16] = &[
    0x2504, // GeForce RTX 4070
    0x25B0, // GeForce RTX 4080
    0x25B5, // GeForce RTX 4080
    0x25F9, // GeForce RTX 4090
    0x25FA, // GeForce RTX 4090
    0x2704, // GeForce RTX 4060
    0x2782, // GeForce RTX 4060 Ti
    0x27B8, // GeForce RTX 4070 Ti
];

// =====================================================================
// Device Name Database
// =====================================================================

/// Get device name from device ID
pub fn device_name(device_id: u16) -> &'static str {
    match device_id {
        // NV50 (Tesla)
        0x0191 => "GeForce 8800 GTS 320M",
        0x0193 => "GeForce 8800 GTX",
        0x0194 => "GeForce 8800 GTS",
        0x0195 => "GeForce 8800 Ultra",
        0x0400 => "GeForce 8600 GTS",
        0x0401 => "GeForce 8600 GT",
        0x0402 => "GeForce 8500 GT",
        0x0403 => "GeForce 8400 GS",
        0x0600 => "GeForce 9800 GT",
        0x0601 => "GeForce 9800 GTX",
        0x0602 => "GeForce 9800 GX2",
        0x0603 => "GeForce 9800 GT",
        0x0611 => "GeForce 9600 GSO",
        0x0612 => "GeForce 9600 GT",
        0x0622 => "GeForce 9500 GT",
        0x0623 => "GeForce 9400 GT",
        // NVC0 (Fermi)
        0x0CA0 | 0x0DC0 | 0x0DD1 => "GeForce GTX 460",
        0x0CA3 => "GeForce GTX 460M",
        0x0CA4 | 0x0DC4 => "GeForce GTX 465",
        0x0CA5 | 0x0DC5 => "GeForce GTX 470",
        0x0CA7 => "GeForce GTX 480",
        0x0CA8 => "GeForce GTX 480M",
        0x0DC7 | 0x0DCD => "GeForce GTX 460M",
        // NVD0 (Kepler)
        0x1180..=0x1183 | 0x1050 | 0x1080 => "GeForce GTX 660",
        0x1184 => "GeForce GTX 670",
        0x1185 => "GeForce GTX 660 Ti",
        0x1038 | 0x1039 | 0x103A => "GeForce GTX 760",
        0x1040 => "GeForce GTX 770",
        0x1045 | 0x1046 | 0x1047 => "GeForce GTX 780",
        0x1049 => "GeForce GTX TITAN",
        0x1051 => "GeForce GTX 650",
        0x1052 => "GeForce GT 640",
        0x1054 => "GeForce GT 630",
        // NV110 (Maxwell)
        0x13C0 | 0x13C2 => "GeForce GTX 970",
        0x13C3 => "GeForce GTX 970",
        0x13C4 | 0x13C5 => "GeForce GTX 960",
        0x13D7 | 0x13D8 => "GeForce GTX 950",
        0x13F0 | 0x13F8 => "GeForce GTX 980",
        0x1400 => "GeForce GTX 750 Ti",
        0x1401 | 0x1402 | 0x1404 => "GeForce GTX 750",
        // NV120 (Pascal)
        0x1B00 | 0x1B01 | 0x1B02 => "GeForce GTX 1080",
        0x1B04 | 0x1B06 => "GeForce GTX 1070",
        0x1B0C | 0x1C03 => "GeForce GTX 1060",
        0x1B80 => "GeForce GTX 1050 Ti",
        0x1B81 | 0x1B82 => "GeForce GTX 1050",
        // NV140 (Turing)
        0x1E04 => "GeForce RTX 2080 Ti",
        0x1E07 => "GeForce RTX 2080",
        0x1E3D => "GeForce RTX 2070",
        0x1E81 | 0x1E82 => "GeForce RTX 2060",
        0x1E89 => "GeForce RTX 2060",
        0x1E90 => "GeForce RTX 2060 SUPER",
        0x1F02 => "GeForce GTX 1660 Ti",
        0x1F03 | 0x1F06 => "GeForce GTX 1660",
        0x1F82 => "GeForce GTX 1650",
        // NV150 (Ampere)
        0x2204 => "GeForce RTX 3090",
        0x2206 => "GeForce RTX 3090",
        0x2212 => "GeForce RTX 3080 Ti",
        0x2216 => "GeForce RTX 3080",
        0x2235 => "GeForce RTX 3070 Ti",
        0x2236 => "GeForce RTX 3070",
        0x2484 => "GeForce RTX 3060 Ti",
        0x2504 => "GeForce RTX 3060",
        // NV250 (Ada Lovelace)
        0x25B0 => "GeForce RTX 4080",
        0x25F9 | 0x25FA => "GeForce RTX 4090",
        0x2704 => "GeForce RTX 4060",
        0x2782 => "GeForce RTX 4060 Ti",
        0x27B8 => "GeForce RTX 4070 Ti",
        _ => "Unknown NVIDIA GPU",
    }
}

// =====================================================================
// Architecture Classification
// =====================================================================

/// NVIDIA GPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NouveauArchitecture {
    /// NV50 (Tesla) - GeForce 8xxx/9xxx
    NV50,
    /// NVC0 (Fermi) - GeForce GTX 400/500
    NVC0,
    /// NVD0 (Kepler) - GeForce GTX 600/700
    NVD0,
    /// NV110 (Maxwell) - GeForce GTX 900
    NV110,
    /// NV120 (Pascal) - GeForce GTX 1000
    NV120,
    /// NV140 (Turing) - GeForce RTX 2000
    NV140,
    /// NV150 (Ampere) - GeForce RTX 3000
    NV150,
    /// NV250 (Ada Lovelace) - GeForce RTX 4000
    NV250,
    /// Unknown architecture
    Unknown,
}

impl NouveauArchitecture {
    /// Get architecture name
    pub fn name(&self) -> &'static str {
        match self {
            NouveauArchitecture::NV50 => "Tesla (NV50)",
            NouveauArchitecture::NVC0 => "Fermi (NVC0)",
            NouveauArchitecture::NVD0 => "Kepler (NVD0)",
            NouveauArchitecture::NV110 => "Maxwell (NV110)",
            NouveauArchitecture::NV120 => "Pascal (NV120)",
            NouveauArchitecture::NV140 => "Turing (NV140)",
            NouveauArchitecture::NV150 => "Ampere (NV150)",
            NouveauArchitecture::NV250 => "Ada Lovelace (NV250)",
            NouveauArchitecture::Unknown => "Unknown",
        }
    }
}

/// Determine architecture from device ID
pub fn architecture_from_device_id(device_id: u16) -> NouveauArchitecture {
    arch_from_device_id(device_id)
}

/// Alias for architecture_from_device_id
pub fn arch_from_device_id(device_id: u16) -> NouveauArchitecture {
    if NV50_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV50
    } else if NVC0_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NVC0
    } else if NVD0_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NVD0
    } else if NV110_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV110
    } else if NV120_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV120
    } else if NV140_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV140
    } else if NV150_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV150
    } else if NV250_DEVICE_IDS.contains(&device_id) {
        NouveauArchitecture::NV250
    } else {
        NouveauArchitecture::Unknown
    }
}

// =====================================================================
// Feature Support
// =====================================================================

/// Feature flags for Nouveau architectures
#[derive(Debug, Clone, Copy)]
pub struct NouveauFeatures {
    /// Has 2D acceleration
    pub has_2d_accel: bool,
    /// Has 3D acceleration
    pub has_3d_accel: bool,
    /// Has video decode
    pub has_video_decode: bool,
    /// Has compute capability
    pub has_compute: bool,
    /// Has reclocking support
    pub has_reclock: bool,
    /// VRAM size support
    pub max_vram_mb: u32,
    /// Maximum texture size
    pub max_texture_size: u32,
    /// Hardware cursor support
    pub has_cursor: bool,
    /// Cursor size in pixels
    pub cursor_size: u8,
}

impl NouveauFeatures {
    /// Features for NV50 (Tesla)
    pub fn nv50() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: false,
            has_reclock: false,
            max_vram_mb: 1536,
            max_texture_size: 4096,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NVC0 (Fermi)
    pub fn nvc0() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 4096,
            max_texture_size: 4096,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NVD0 (Kepler)
    pub fn nvd0() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 6144,
            max_texture_size: 16384,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NV110 (Maxwell)
    pub fn nv110() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 8192,
            max_texture_size: 16384,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NV120 (Pascal)
    pub fn nv120() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 16384,
            max_texture_size: 16384,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NV140 (Turing)
    pub fn nv140() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 24576,
            max_texture_size: 16384,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NV150 (Ampere)
    pub fn nv150() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 49152,
            max_texture_size: 32768,
            has_cursor: true,
            cursor_size: 64,
        }
    }

    /// Features for NV250 (Ada Lovelace)
    pub fn nv250() -> Self {
        Self {
            has_2d_accel: true,
            has_3d_accel: true,
            has_video_decode: true,
            has_compute: true,
            has_reclock: true,
            max_vram_mb: 98304,
            max_texture_size: 32768,
            has_cursor: true,
            cursor_size: 64,
        }
    }
}

/// Get features for an architecture
pub fn features_for_architecture(arch: NouveauArchitecture) -> NouveauFeatures {
    match arch {
        NouveauArchitecture::NV50 => NouveauFeatures::nv50(),
        NouveauArchitecture::NVC0 => NouveauFeatures::nvc0(),
        NouveauArchitecture::NVD0 => NouveauFeatures::nvd0(),
        NouveauArchitecture::NV110 => NouveauFeatures::nv110(),
        NouveauArchitecture::NV120 => NouveauFeatures::nv120(),
        NouveauArchitecture::NV140 => NouveauFeatures::nv140(),
        NouveauArchitecture::NV150 => NouveauFeatures::nv150(),
        NouveauArchitecture::NV250 => NouveauFeatures::nv250(),
        NouveauArchitecture::Unknown => NouveauFeatures::nv50(),
    }
}
