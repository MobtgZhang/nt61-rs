//! CedarX Video Codec Register Definitions
//
//! This module defines registers for the CedarX video codec found in Allwinner SoCs.
//
//! Clean-room implementation based on public specifications.

/// CedarX base address
pub const CEDARX_BASE: u64 = 0x01C0_0000;

/// CedarX registers
pub const CEDARX_VERSION: u32 = 0x0000;
pub const CEDARX_CTRL: u32 = 0x0004;
pub const CEDARX_STATUS: u32 = 0x0008;

/// Decoder registers
pub const CEDARX_DEC_BASE: u32 = 0x0100;
pub const CEDARX_DEC_SIZE: u32 = 0x0104;
pub const CEDARX_DEC_STRIDE: u32 = 0x0108;
pub const CEDARX_DEC_FORMAT: u32 = 0x010C;

/// Decoder status
pub const CEDARX_DEC_STATUS: u32 = 0x0200;
pub const CEDARX_DEC_INT: u32 = 0x0204;

/// Format constants
pub const FORMAT_H264: u32 = 0x01;
pub const FORMAT_HEVC: u32 = 0x02;
pub const FORMAT_VP9: u32 = 0x04;
pub const FORMAT_MPEG4: u32 = 0x08;
pub const FORMAT_MPEG2: u32 = 0x10;
