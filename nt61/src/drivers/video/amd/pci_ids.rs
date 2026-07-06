//! AMD PCI ID Database
//
//! Contains the PCI vendor and device IDs for AMD graphics.

/// AMD vendor ID
pub const AMD_VENDOR_ID: u16 = 0x1002;

// =====================================================================
// R600 Family (HD 2000-4000)
// =====================================================================

/// R600 device IDs
pub const R600_DEVICE_IDS: &[u16] = &[
    0x9440, 0x9441, 0x9442, 0x9443, // HD 3400
    0x94C8, 0x94C9, // HD 3600
    0x9505, 0x9507, // HD 3800
    0x954F, // HD 4200
    0x9552, 0x9553, // HD 4300
    0x9555, 0x9557, 0x955F, // HD 4350/4550
    0x9581, 0x9583, // HD 4500
    0x9588, 0x9589, // HD 4600
    0x9598, 0x9599, // HD 4700
    0x95C0, 0x95C5, 0x95C7, // HD 4800
];

// =====================================================================
// Evergreen Family (HD 5000-6000)
// =====================================================================

/// Evergreen device IDs
pub const EVERGREEN_DEVICE_IDS: &[u16] = &[
    0x68BE, 0x68BF, // HD 5000
    0x68D8, 0x68D9, // HD 5500
    0x68DA, 0x68DE, // HD 5600
    0x68E0, 0x68E4, 0x68E5, // HD 5700
    0x68F1, 0x68F2, 0x68F8, 0x68F9, // HD 5800
    0x68FF, // HD 5900
    0x694C, 0x694D, // HD 6300
    0x694E, 0x694F, // HD 6400
    0x6980, 0x6981, 0x6985, 0x6986, // HD 6500/6600
    0x6987, 0x698A, 0x698F, // HD 6700
    0x6995, 0x6997, 0x699F, // HD 6800
    0x69A0, 0x69A1, 0x69A2, 0x69A3, // HD 6900
];

// =====================================================================
// Northern Islands Family (HD 6000-7000)
// =====================================================================

/// Northern Islands device IDs
pub const NORTHERN_ISLANDS_DEVICE_IDS: &[u16] = &[
    0x6738, 0x6739, // HD 6000
    0x6740, 0x6741, 0x6742, // HD 6300
    0x6743, 0x6744, 0x6745, 0x6746, // HD 6400
    0x6747, 0x6748, 0x6749, 0x674A, // HD 6500
    0x674C, 0x674D, 0x674E, // HD 6600
    0x6750, 0x6751, 0x6758, 0x6759, // HD 6700
    0x675B, 0x675D, 0x675F, // HD 6800
    0x6760, 0x6761, 0x6762, // HD 6900
];

// =====================================================================
// Southern Islands / GCN 1.x (HD 7000)
// =====================================================================

/// Southern Islands device IDs
pub const SOUTHERN_ISLANDS_DEVICE_IDS: &[u16] = &[
    0x6760, 0x6761, 0x6762, // HD 7700
    0x6764, 0x6765, 0x6766, 0x6767, // HD 7700
    0x6768, 0x6769, // HD 7730
    0x6770, 0x6771, 0x6772, // HD 7750/7770
    0x6778, 0x6779, 0x677B, // HD 7790
    0x6780, 0x6784, 0x6788, // HD 7800
    0x6790, 0x6791, 0x6792, // HD 7900
    0x6798, 0x6799, // HD 7970
    0x67B0, 0x67B1, 0x67B2, 0x67B3, // HD 7990
];

// =====================================================================
// Sea Islands / GCN 2.x (R9 200/300)
// =====================================================================

/// Sea Islands device IDs
pub const SEA_ISLANDS_DEVICE_IDS: &[u16] = &[
    0x6600, 0x6601, 0x6602, 0x6603, // R7 260/260X
    0x6604, 0x6605, 0x6606, 0x6607, // R7 250
    0x6610, 0x6611, 0x6613, // R7 370
    0x6630, 0x6631, // R9 380
    0x6640, 0x6641, 0x6646, 0x6647, // R9 285
    0x6650, 0x6651, 0x6658, // R9 390
    0x6660, 0x6663, 0x6665, // R9 Fury
    0x6670, // R9 Nano
    0x67B8, 0x67B9, 0x67BA, 0x67BB, // R9 280
    0x67E0, 0x67E1, 0x67E3, // R9 380
    0x67FF, // R9 Fury X
];

// =====================================================================
// Volcanic Islands / GCN 3.x (R9 300/Fury)
// =====================================================================

/// Volcanic Islands device IDs
pub const VOLCANIC_ISLANDS_DEVICE_IDS: &[u16] = &[
    0x67C0, 0x67C1, 0x67C2, 0x67C4, 0x67C7, // R9 270
    0x67C8, 0x67C9, 0x67CA, 0x67CC, 0x67CF, // R9 370
    0x67D0, 0x67D1, 0x67D2, 0x67D4, 0x67D7, // R9 380
    0x67DF, // R9 380X
    0x6920, 0x6921, // R9 390
    0x6929, 0x692B, // R9 390X
    0x6930, 0x6938, // R9 Fury
    0x6939, // R9 Fury X
];

// =====================================================================
// Polaris / GCN 4.x (RX 400/500)
// =====================================================================

/// Polaris device IDs
pub const POLARIS_DEVICE_IDS: &[u16] = &[
    0x67C0, 0x67C1, 0x67C2, 0x67C4, 0x67C7, // RX 470
    0x67D0, 0x67D1, 0x67D2, 0x67D4, 0x67D7, // RX 480
    0x69C0, 0x69C1, 0x69C2, // RX 550
    0x69E0, 0x69E1, 0x69E3, 0x69E4, // RX 560
    0x69F0, 0x69F1, // RX 570
    0x6FDF, // RX 580
    0x6FB0, 0x6FB5, // RX 590
];

// =====================================================================
// Vega
// =====================================================================

/// Vega device IDs
pub const VEGA_DEVICE_IDS: &[u16] = &[
    0x687F, // RX Vega 56
    0x6863, // RX Vega 64
    0x6864, // RX Vega 64 Liquid
    0x6867, // Vega FE
    0x686C, // Vega 12
    0x66AF, // Vega 20 (Radeon Instinct MI50/MI60)
];

// =====================================================================
// GCN 5 / Vega 20 (Radeon VII)
// =====================================================================

/// GCN 5 / Vega 20 device IDs
pub const GCN5_DEVICE_IDS: &[u16] = &[
    0x6863, // Vega 20 variant (Radeon VII)
];

// =====================================================================
// Navi / RDNA
// =====================================================================

/// Navi device IDs
pub const NAVI_DEVICE_IDS: &[u16] = &[
    0x7310, 0x7312, 0x7314, // RX 5500
    0x731F, // RX 5500 XT
    0x7340, 0x7341, 0x7347, // RX 5600
    0x73A0, 0x73A1, 0x73A3, // RX 5700
    0x73AB, 0x73AE, 0x73AF, // RX 5700 XT
];

// =====================================================================
// RDNA 2 (Navi 2x) - RX 6000 series
// =====================================================================

/// RDNA 2 / Navi 2x device IDs
pub const RDNA2_DEVICE_IDS: &[u16] = &[
    0x73DF, // RX 6600 XT
    0x73FF, // RX 6600
    0x73EF, // RX 6650 XT
];

// =====================================================================
// RDNA 3 (Navi 3x) - RX 7000 series
// =====================================================================

/// RDNA 3 / Navi 3x device IDs
pub const RDNA3_DEVICE_IDS: &[u16] = &[
    0x7470, // RX 7700 XT
    0x747E, // RX 7800 XT
    0x7480, // RX 7800 GRE
    0x748B, // RX 7900 GRE
];

// =====================================================================
// Helper Functions
// =====================================================================

/// Get GPU family from device ID
pub fn family_from_device_id(device_id: u16) -> crate::drivers::video::core::gpu_common::AmdFamily {
    if R600_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::R600
    } else if EVERGREEN_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Evergreen
    } else if NORTHERN_ISLANDS_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Northern
    } else if SOUTHERN_ISLANDS_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Southern
    } else if SEA_ISLANDS_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Sea
    } else if VOLCANIC_ISLANDS_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Volcanic
    } else if POLARIS_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Polaris
    } else if VEGA_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Vega
    } else if NAVI_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Navi
    } else if RDNA2_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Rdna2
    } else if RDNA3_DEVICE_IDS.contains(&device_id) {
        crate::drivers::video::core::gpu_common::AmdFamily::Rdna3
    } else {
        crate::drivers::video::core::gpu_common::AmdFamily::Unknown
    }
}

/// Get family name
pub fn family_name(family: crate::drivers::video::core::gpu_common::AmdFamily) -> &'static str {
    match family {
        crate::drivers::video::core::gpu_common::AmdFamily::R600 => "R600",
        crate::drivers::video::core::gpu_common::AmdFamily::Evergreen => "Evergreen",
        crate::drivers::video::core::gpu_common::AmdFamily::Northern => "Northern Islands",
        crate::drivers::video::core::gpu_common::AmdFamily::Southern => "Southern Islands (GCN 1)",
        crate::drivers::video::core::gpu_common::AmdFamily::Sea => "Sea Islands (GCN 2)",
        crate::drivers::video::core::gpu_common::AmdFamily::Volcanic => "Volcanic Islands (GCN 3)",
        crate::drivers::video::core::gpu_common::AmdFamily::Polaris => "Polaris (GCN 4)",
        crate::drivers::video::core::gpu_common::AmdFamily::Vega => "Vega (GCN 5)",
        crate::drivers::video::core::gpu_common::AmdFamily::Navi => "Navi (RDNA 1)",
        crate::drivers::video::core::gpu_common::AmdFamily::Rdna2 => "RDNA 2 (Navi 2x)",
        crate::drivers::video::core::gpu_common::AmdFamily::Rdna3 => "RDNA 3 (Navi 3x)",
        crate::drivers::video::core::gpu_common::AmdFamily::Unknown => "Unknown",
    }
}
