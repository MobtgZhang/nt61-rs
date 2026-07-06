//! Intel PCI ID Database
//
//! Contains the PCI vendor and device IDs for Intel integrated graphics.

/// Intel vendor ID
pub const INTEL_VENDOR_ID: u16 = 0x8086;

// =====================================================================
// Ironlake (Clarkdale/Arrandale) - 1st Gen
// =====================================================================

/// Ironlake desktop
pub const ILK_DESKTOP: u16 = 0x0042;

/// Ironlake mobile
pub const ILK_MOBILE: u16 = 0x0046;

// =====================================================================
// Sandy Bridge (2nd Gen) - HD Graphics 2000/3000
// =====================================================================

/// Sandy Bridge desktop GT1
pub const SNB_DESKTOP_GT1: u16 = 0x0102;

/// Sandy Bridge desktop GT2
pub const SNB_DESKTOP_GT2: u16 = 0x0112;

/// Sandy Bridge desktop GT2+
pub const SNB_DESKTOP_GT2_PLUS: u16 = 0x0122;

/// Sandy Bridge mobile GT1
pub const SNB_MOBILE_GT1: u16 = 0x0106;

/// Sandy Bridge mobile GT2
pub const SNB_MOBILE_GT2: u16 = 0x0116;

/// Sandy Bridge mobile GT2+
pub const SNB_MOBILE_GT2_PLUS: u16 = 0x0126;

// =====================================================================
// Ivy Bridge (3rd Gen) - HD Graphics 2500/4000
// =====================================================================

/// Ivy Bridge desktop GT1
pub const IVB_DESKTOP_GT1: u16 = 0x0152;

/// Ivy Bridge desktop GT2
pub const IVB_DESKTOP_GT2: u16 = 0x0162;

/// Ivy Bridge mobile GT1
pub const IVB_MOBILE_GT1: u16 = 0x0156;

/// Ivy Bridge mobile GT2
pub const IVB_MOBILE_GT2: u16 = 0x0166;

// =====================================================================
// Haswell (4th Gen) - HD Graphics 4200-5200
// =====================================================================

/// Haswell desktop GT1
pub const HSW_DESKTOP_GT1: u16 = 0x0402;

/// Haswell desktop GT2
pub const HSW_DESKTOP_GT2: u16 = 0x0412;

/// Haswell desktop GT2+
pub const HSW_DESKTOP_GT2_PLUS: u16 = 0x0422;

/// Haswell mobile GT1
pub const HSW_MOBILE_GT1: u16 = 0x0406;

/// Haswell mobile GT2
pub const HSW_MOBILE_GT2: u16 = 0x0416;

/// Haswell mobile GT2+
pub const HSW_MOBILE_GT2_PLUS: u16 = 0x0426;

/// Haswell GT3 desktop
pub const HSW_DESKTOP_GT3: u16 = 0x042A;

/// Haswell GT3 mobile
pub const HSW_MOBILE_GT3: u16 = 0x042E;

// =====================================================================
// Broadwell (5th Gen) - HD Graphics 5300-6300
// =====================================================================

/// Broadwell desktop GT1
pub const BDW_DESKTOP_GT1: u16 = 0x1602;

/// Broadwell desktop GT2
pub const BDW_DESKTOP_GT2: u16 = 0x1612;

/// Broadwell desktop GT3
pub const BDW_DESKTOP_GT3: u16 = 0x1622;

/// Broadwell mobile GT1
pub const BDW_MOBILE_GT1: u16 = 0x1606;

/// Broadwell mobile GT2
pub const BDW_MOBILE_GT2: u16 = 0x1616;

/// Broadwell mobile GT3
pub const BDW_MOBILE_GT3: u16 = 0x1626;

/// Broadwell ULX GT1
pub const BDW_ULX_GT1: u16 = 0x160E;

/// Broadwell ULX GT2
pub const BDW_ULX_GT2: u16 = 0x161E;

// =====================================================================
// Skylake (6th Gen) - HD Graphics 510-580
// =====================================================================

/// Skylake desktop GT1
pub const SKL_DESKTOP_GT1: u16 = 0x1902;

/// Skylake desktop GT2
pub const SKL_DESKTOP_GT2: u16 = 0x1912;

/// Skylake desktop GT3
pub const SKL_DESKTOP_GT3: u16 = 0x1922;

/// Skylake desktop GT4
pub const SKL_DESKTOP_GT4: u16 = 0x1932;

/// Skylake mobile GT1
pub const SKL_MOBILE_GT1: u16 = 0x1906;

/// Skylake mobile GT2
pub const SKL_MOBILE_GT2: u16 = 0x1916;

/// Skylake mobile GT3
pub const SKL_MOBILE_GT3: u16 = 0x1926;

/// Skylake ULX GT1
pub const SKL_ULX_GT1: u16 = 0x190E;

/// Skylake ULX GT2
pub const SKL_ULX_GT2: u16 = 0x191E;

/// Skylake ULT GT1
pub const SKL_ULT_GT1: u16 = 0x1916;

/// Skylake ULT GT2
pub const SKL_ULT_GT2: u16 = 0x1926;

// =====================================================================
// Kaby Lake (7th Gen) - HD Graphics 610-650
// =====================================================================

/// Kaby Lake desktop GT1
pub const KBL_DESKTOP_GT1: u16 = 0x5902;

/// Kaby Lake desktop GT2
pub const KBL_DESKTOP_GT2: u16 = 0x5912;

/// Kaby Lake desktop GT2+
pub const KBL_DESKTOP_GT2_PLUS: u16 = 0x5916;

/// Kaby Lake mobile GT1
pub const KBL_MOBILE_GT1: u16 = 0x5906;

/// Kaby Lake mobile GT2
pub const KBL_MOBILE_GT2: u16 = 0x5916;

/// Kaby Lake mobile GT2+
pub const KBL_MOBILE_GT2_PLUS: u16 = 0x591E;

/// Kaby Lake ULT GT1
pub const KBL_ULT_GT1: u16 = 0x5916;

/// Kaby Lake ULT GT2
pub const KBL_ULT_GT2: u16 = 0x5926;

/// Kaby Lake ULT GT2F
pub const KBL_ULT_GT2F: u16 = 0x5936;

// =====================================================================
// Coffee Lake (8th Gen+) - UHD Graphics 630
// =====================================================================

/// Coffee Lake GT1
pub const CFL_DESKTOP_GT1: u16 = 0x3E02;

/// Coffee Lake GT2
pub const CFL_DESKTOP_GT2: u16 = 0x3E12;

/// Coffee Lake GT3
pub const CFL_DESKTOP_GT3: u16 = 0x3E22;

/// Coffee Lake mobile GT1
pub const CFL_MOBILE_GT1: u16 = 0x3EA2;

/// Coffee Lake mobile GT2
pub const CFL_MOBILE_GT2: u16 = 0x3EB2;

/// Coffee Lake mobile GT3
pub const CFL_MOBILE_GT3: u16 = 0x3EC2;

/// Coffee Lake ULT GT1
pub const CFL_ULT_GT1: u16 = 0x3EA6;

/// Coffee Lake ULT GT2
pub const CFL_ULT_GT2: u16 = 0x3EB6;

/// Coffee Lake ULT GT3
pub const CFL_ULT_GT3: u16 = 0x3EC6;

/// Coffee Lake ULX GT1
pub const CFL_ULX_GT1: u16 = 0x3EAE;

/// Coffee Lake ULX GT2
pub const CFL_ULX_GT2: u16 = 0x3EBE;

/// Coffee Lake S GT1
pub const CFL_S_GT1: u16 = 0x3E32;

/// Coffee Lake S GT2
pub const CFL_S_GT2: u16 = 0x3E42;

/// Coffee Lake S GT3
pub const CFL_S_GT3: u16 = 0x3E52;

/// =====================================================================
// Comet Lake
// =====================================================================

/// Comet Lake U GT1
pub const CML_U_GT1: u16 = 0x9BA0;

/// Comet Lake U GT2
pub const CML_U_GT2: u16 = 0x9BB0;

/// Comet Lake U GT3
pub const CML_U_GT3: u16 = 0x9BC0;

/// Comet Lake S GT1
pub const CML_S_GT1: u16 = 0x9BA2;

/// Comet Lake S GT2
pub const CML_S_GT2: u16 = 0x9BB2;

/// Comet Lake S GT3
pub const CML_S_GT3: u16 = 0x9BC2;

/// =====================================================================
// Ice Lake
// =====================================================================

/// Ice Lake GT1
pub const ICL_GT1: u16 = 0x8A50;

/// Ice Lake GT2
pub const ICL_GT2: u16 = 0x8A51;

/// Ice Lake GT3
pub const ICL_GT3: u16 = 0x8A52;

/// Ice Lake GT1F
pub const ICL_GT1F: u16 = 0x8A53;

/// Ice Lake U GT1
pub const ICL_U_GT1: u16 = 0x8A50;

/// Ice Lake U GT2
pub const ICL_U_GT2: u16 = 0x8A51;

/// Ice Lake Y GT1
pub const ICL_Y_GT1: u16 = 0x8A50;

/// Ice Lake Y GT2
pub const ICL_Y_GT2: u16 = 0x8A51;

/// =====================================================================
// Tiger Lake
// =====================================================================

/// Tiger Lake GT1
pub const TGL_GT1: u16 = 0x9A40;

/// Tiger Lake GT2
pub const TGL_GT2: u16 = 0x9A41;

/// Tiger Lake GT3
pub const TGL_GT3: u16 = 0x9A42;

/// Tiger Lake U GT1
pub const TGL_U_GT1: u16 = 0x9A40;

/// Tiger Lake U GT2
pub const TGL_U_GT2: u16 = 0x9A41;

/// Tiger Lake U GT3
pub const TGL_U_GT3: u16 = 0x9A42;

/// Tiger Lake U GT1F
pub const TGL_U_GT1F: u16 = 0x9A60;

/// Tiger Lake UP3 GT2
pub const TGL_UP3_GT2: u16 = 0x9A49;

/// Tiger Lake UP4 GT1
pub const TGL_UP4_GT1: u16 = 0x9A59;

/// Tiger Lake UP4 GT2
pub const TGL_UP4_GT2: u16 = 0x9A70;

// =====================================================================
// Rocket Lake (11th Gen)
// =====================================================================

/// Rocket Lake GT1
pub const RKL_GT1: u16 = 0x4C8A;

/// Rocket Lake GT2
pub const RKL_GT2: u16 = 0x4C8B;

/// Rocket Lake GT3
pub const RKL_GT3: u16 = 0x4C90;

/// Rocket Lake U GT2
pub const RKL_U_GT2: u16 = 0x4C9A;

// =====================================================================
// Alder Lake (12th Gen Desktop)
// =====================================================================

/// Alder Lake-S GT1
pub const ADL_S_GT1: u16 = 0x4680;

/// Alder Lake-S GT2
pub const ADL_S_GT2: u16 = 0x4672;

/// Alder Lake-S GT4
pub const ADL_S_GT4: u16 = 0x4688;

/// Alder Lake-S GT5
pub const ADL_S_GT5: u16 = 0x4682;

// =====================================================================
// Raptor Lake (13th Gen)
// =====================================================================

/// Raptor Lake-S GT1
pub const RPL_S_GT1: u16 = 0xA780;

/// Raptor Lake-S GT2
pub const RPL_S_GT2: u16 = 0xA788;

/// Raptor Lake-S GT3
pub const RPL_S_GT3: u16 = 0xA720;

// =====================================================================
// Arc GPUs (DG2/Alchemist)
// =====================================================================

/// DG2 / Arc A750
pub const DG2_G10: u16 = 0x5690;

/// DG2 / Arc A750 variant
pub const DG2_G10_VARIANT: u16 = 0x5692;

/// DG2 / Arc A770 8GB
pub const DG2_G10_A770: u16 = 0x56A0;

/// DG2 / Arc A770 16GB
pub const DG2_G10_A770_16G: u16 = 0x56A2;

/// DG2 / Arc A770 LE
pub const DG2_G10_A770_LE: u16 = 0x56A5;

/// DG2 / Arc A580
pub const DG2_G10_A580: u16 = 0x5694;

/// DG2 / Arc A380
pub const DG2_G10_A380: u16 = 0x5698;

// =====================================================================
// Meteor Lake
// =====================================================================

/// Meteor Lake U GT2
pub const MTL_U_GT2: u16 = 0x7D67;

/// Meteor Lake U GT1
pub const MTL_U_GT1: u16 = 0x7D55;

// =====================================================================
// Generation Detection
// =====================================================================

/// Get generation from device ID
pub fn generation_from_device_id(device_id: u16) -> crate::drivers::video::core::gpu_common::IntelGeneration {
    // Ironlake
    if matches!(device_id, ILK_DESKTOP | ILK_MOBILE) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::Ironlake;
    }

    // Sandy Bridge
    if matches!(
        device_id,
        SNB_DESKTOP_GT1 | SNB_DESKTOP_GT2 | SNB_DESKTOP_GT2_PLUS
            | SNB_MOBILE_GT1 | SNB_MOBILE_GT2 | SNB_MOBILE_GT2_PLUS
    ) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::SandyBridge;
    }

    // Ivy Bridge
    if matches!(
        device_id,
        IVB_DESKTOP_GT1 | IVB_DESKTOP_GT2 | IVB_MOBILE_GT1 | IVB_MOBILE_GT2
    ) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::IvyBridge;
    }

    // Haswell
    if (0x0402..=0x042F).contains(&device_id) || (0x0A02..=0x0A2F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::Haswell;
    }

    // Broadwell
    if (0x1602..=0x162F).contains(&device_id) || (0x0A02..=0x0A2F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::Broadwell;
    }

    // Skylake
    if (0x1902..=0x193F).contains(&device_id) || (0x0902..=0x093F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::Skylake;
    }

    // Kaby Lake
    if (0x5902..=0x593F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::KabyLake;
    }

    // Coffee Lake
    if (0x3E02..=0x3E5F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::CoffeeLake;
    }

    // Comet Lake
    if (0x9BA0..=0x9BCF).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::CometLake;
    }

    // Ice Lake
    if (0x8A50..=0x8A7F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::IceLake;
    }

    // Rocket Lake (11th Gen) - 0x4C8x
    if (0x4C8A..=0x4C9F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::RocketLake;
    }

    // Tiger Lake (12th Gen) - 0x9A4x
    if (0x9A40..=0x9A7F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::TigerLake;
    }

    // Alder Lake (12th Gen Desktop) - 0x46xx
    if (0x4600..=0x46FF).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::AlderLake;
    }

    // Raptor Lake (13th Gen) - 0xA7xx
    if (0xA780..=0xA79F).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::RaptorLake;
    }

    // Arc GPUs (DG2/Alchemist) - 0x56xx
    if (0x5690..=0x56AF).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::Arc;
    }

    // Meteor Lake - 0x7Dxx
    if (0x7D00..=0x7DFF).contains(&device_id) {
        return crate::drivers::video::core::gpu_common::IntelGeneration::MeteorLake;
    }

    crate::drivers::video::core::gpu_common::IntelGeneration::Unknown
}

/// Get generation name
pub fn generation_name(gen: crate::drivers::video::core::gpu_common::IntelGeneration) -> &'static str {
    match gen {
        crate::drivers::video::core::gpu_common::IntelGeneration::Ironlake => "Ironlake",
        crate::drivers::video::core::gpu_common::IntelGeneration::SandyBridge => "Sandy Bridge",
        crate::drivers::video::core::gpu_common::IntelGeneration::IvyBridge => "Ivy Bridge",
        crate::drivers::video::core::gpu_common::IntelGeneration::Haswell => "Haswell",
        crate::drivers::video::core::gpu_common::IntelGeneration::Broadwell => "Broadwell",
        crate::drivers::video::core::gpu_common::IntelGeneration::Skylake => "Skylake",
        crate::drivers::video::core::gpu_common::IntelGeneration::KabyLake => "Kaby Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::CoffeeLake => "Coffee Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::CometLake => "Comet Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::IceLake => "Ice Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::TigerLake => "Tiger Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::RocketLake => "Rocket Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::AlderLake => "Alder Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::RaptorLake => "Raptor Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::Arc => "Arc (DG2/Alchemist)",
        crate::drivers::video::core::gpu_common::IntelGeneration::MeteorLake => "Meteor Lake",
        crate::drivers::video::core::gpu_common::IntelGeneration::Unknown => "Unknown",
    }
}
