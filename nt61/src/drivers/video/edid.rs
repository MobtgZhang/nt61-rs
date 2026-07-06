//! EDID (Extended Display Identification Data) Parser
//
//! Implements EDID parsing according to the VESA E-EDID standard.
//! EDID data is read from the display through the DDC (Display Data Channel)
//! which uses I2C to communicate with the monitor's internal EEPROM.
//
//! Clean-room implementation. Spec sources: VESA E-EDID Standard A2,
//! VESA Display Monitor Timing (DMT) Standard.

use crate::drivers::video::log;

// ============================================================================
// Constants
// ============================================================================

/// EDID I2C slave address
pub const EDID_I2C_ADDR: u8 = 0x50;

/// EDID header bytes (should match 00 FF FF FF FF FF FF 00)
const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// EDID block size
pub const EDID_BLOCK_SIZE: usize = 128;

/// EDID extension blocks offset
pub const EDID_EXTENSION_FLAG_OFFSET: usize = 0x7E;

/// EDID checksum offset
pub const EDID_CHECKSUM_OFFSET: usize = 0x7F;

// ============================================================================
// EDID Data Structures
// ============================================================================

/// EDID errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdidError {
    InvalidHeader,
    ChecksumMismatch,
    NoExtensionBlocks,
    ExtensionNotSupported,
    InvalidDescriptor,
    ReadError,
}

/// EDID base block (128 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidBaseBlock {
    /// Header (always 00 FF FF FF FF FF FF 00)
    pub header: [u8; 8],
    /// Manufacturer ID (EISA 3-letter code)
    pub manufacturer_id: u16,
    /// Product ID code (manufacturer-specified)
    pub product_id: u16,
    /// Serial number (ASCII, 0 if unused)
    pub serial_number: u32,
    /// Week of manufacture (1-54, or 0x00 for unknown)
    pub week: u8,
    /// Year of manufacture (offset from 1990, so 10 = 2000)
    pub year: u8,
    /// EDID version (typically 1)
    pub version: u8,
    /// EDID revision (typically 3 or 4)
    pub revision: u8,
    /// Video input parameters
    pub input_video: EdidVideoInput,
    /// Screen size (cm, 0 if unknown)
    pub screen_width_cm: u8,
    /// Screen height (cm, 0 if unknown)
    pub screen_height_cm: u8,
    /// Gamma (0x72 = 1.0 + 0.1*(gamma*10), or 0xFF if unknown)
    pub gamma: u8,
    /// Feature support flags
    pub features: EdidFeatures,
    /// Chromaticity coordinates
    pub chromaticity: EdidChromaticity,
    /// Established timings
    pub established_timings: EdidEstablishedTimings,
    /// Standard timing information
    pub standard_timings: [EdidStandardTiming; 8],
    /// Detailed timing descriptors
    pub descriptors: [EdidDescriptor; 4],
    /// Number of extension blocks
    pub extensions: u8,
    /// Checksum
    pub checksum: u8,
}

/// Video input definition
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidVideoInput {
    /// Digital vs Analog (bit 7)
    pub is_digital: bool,
    /// For digital: color bit depth (bits 0-2)
    pub color_depth: u8,
    /// For digital: interface type (bits 3-6)
    pub interface_type: u8,
    /// For analog: signal level standard (bits 0-3)
    pub signal_level: u8,
    /// Blank-to-black setup expected
    pub blank_to_black: bool,
    /// Separate syncs supported
    pub separate_syncs: bool,
    /// Composite sync supported
    pub composite_sync: bool,
    /// Sync on green supported
    pub sync_on_green: bool,
    /// VSync serrated when composite or sync-on-green
    pub vsync_serrated: bool,
}

/// EDID feature support flags
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidFeatures {
    /// GTF supported (0) or default (1)
    pub uses_gtf: bool,
    /// Preferred timing mode specified
    pub has_preferred_timing: bool,
    /// Continuous frequency display (1) or single frequency (0)
    pub continuous_frequency: bool,
    /// Display type: 00 = monochrome/GRB, 01 = unknown, 10 = non-RGB, 11 = RGB
    pub display_type: u8,
    /// sRGB standard used as default color space
    pub srgb_default: bool,
    /// Has preferred timing mode that includes native pixel format
    pub preferred_timing_native: bool,
    /// (X: 1 = GTF supported from [0], 0 = no GTF)
    pub gtf_supported: bool,
}

/// Chromaticity coordinates (8-bit unsigned, scaled by 10000)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidChromaticity {
    /// Red x (0.0000 to 0.9999)
    pub red_x: u16,
    /// Red y
    pub red_y: u16,
    /// Green x
    pub green_x: u16,
    /// Green y
    pub green_y: u16,
    /// Blue x
    pub blue_x: u16,
    /// Blue y
    pub blue_y: u16,
    /// White x (default)
    pub white_x: u16,
    /// White y (default)
    pub white_y: u16,
}

/// Established timing bytes
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidEstablishedTimings {
    pub timing_720_400_70: bool,  // 720x400 @ 70 Hz
    pub timing_720_400_88: bool,  // 720x400 @ 88 Hz
    pub timing_640_480_60: bool,  // 640x480 @ 60 Hz
    pub timing_640_480_67: bool,  // 640x480 @ 67 Hz
    pub timing_640_480_72: bool,  // 640x480 @ 72 Hz
    pub timing_640_480_75: bool,  // 640x480 @ 75 Hz
    pub timing_800_600_56: bool,  // 800x600 @ 56 Hz
    pub timing_800_600_60: bool,  // 800x600 @ 60 Hz
    pub timing_800_600_72: bool,  // 800x600 @ 72 Hz
    pub timing_800_600_75: bool,  // 800x600 @ 75 Hz
    pub timing_832_624_75: bool,  // 832x624 @ 75 Hz
    pub timing_1024_768_87: bool, // 1024x768 @ 87 Hz (interlaced)
    pub timing_1024_768_60: bool, // 1024x768 @ 60 Hz
    pub timing_1024_768_70: bool, // 1024x768 @ 70 Hz
    pub timing_1024_768_75: bool, // 1024x768 @ 75 Hz
    pub timing_1280_1024_75: bool, // 1280x1024 @ 75 Hz
    pub timing_1152_870_75: bool, // 1152x870 @ 75 Hz
    pub timing_640_400_85: bool,  // 640x400 @ 85 Hz
    pub timing_1152_864_75: bool, // 1152x864 @ 75 Hz
}

/// Standard timing descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidStandardTiming {
    /// Horizontal active pixels (horz_freq = value + 31)
    pub horz_pixels_div_8_minus_31: u8,
    /// Fields: bit 7 = aspect ratio (0=16:9, 1=4:3), bits 6-0 = vertical frequency - 60
    pub refresh_minus_60_and_aspect: u8,
}

impl EdidStandardTiming {
    /// Get horizontal resolution
    pub fn horizontal_resolution(&self) -> u16 {
        (self.horz_pixels_div_8_minus_31 as u16 + 31) * 8
    }
    
    /// Get vertical resolution
    pub fn vertical_resolution(&self) -> u16 {
        let aspect_ratio = (self.refresh_minus_60_and_aspect >> 7) != 0;
        let horz = self.horizontal_resolution();
        if aspect_ratio {
            // 16:9
            (horz as f32 * 9.0 / 16.0) as u16
        } else {
            // 4:3
            (horz as f32 * 3.0 / 4.0) as u16
        }
    }
    
    /// Get refresh rate
    pub fn refresh_rate(&self) -> u8 {
        (self.refresh_minus_60_and_aspect & 0x7F) + 60
    }
}

/// EDID descriptor types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    DisplayProductSerialNumber,
    AlphanumericDataString,
    DisplayProductName,
    DisplayRangeLimits,
    EstablishedTimingsIII,
    StandardTimingCodes,
    ColorPointData,
    TimingData,
    Dummy,
    Unknown,
}

/// EDID detailed timing descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EdidDescriptor {
    /// Pixel clock (MHz * 100, so 1075 = 10.75 MHz)
    pub pixel_clock_100khz: u16,
    /// Horizontal active (pixels)
    pub horz_active: u16,
    /// Horizontal blanking (pixels)
    pub horz_blanking: u16,
    /// Vertical active (lines)
    pub vert_active: u16,
    /// Vertical blanking (lines)
    pub vert_blanking: u16,
    /// Horizontal sync offset (pixels)
    pub horz_sync_offset: u16,
    /// Horizontal sync pulse width (pixels)
    pub horz_sync_pulse: u16,
    /// Vertical sync offset (lines)
    pub vert_sync_offset: u16,
    /// Vertical sync pulse width (lines)
    pub vert_sync_pulse: u16,
    /// Horizontal display size (mm)
    pub horz_display_size: u16,
    /// Vertical display size (mm)
    pub vert_display_size: u16,
    /// Horizontal border (pixels)
    pub horz_border: u8,
    /// Vertical border (lines)
    pub vert_border: u8,
    /// Interlaced and polarity flags
    pub flags: u8,
    /// Descriptor type tag or text data
    pub tag_or_text: [u8; 14],
}

impl EdidDescriptor {
    /// Get descriptor type
    pub fn descriptor_type(&self) -> DescriptorType {
        if self.pixel_clock_100khz == 0 {
            // This is a display descriptor, not a timing
            if &self.tag_or_text[0..4] == b"\x00\x00\x00\xFC" {
                DescriptorType::DisplayProductName
            } else if &self.tag_or_text[0..4] == b"\x00\x00\x00\xFF" {
                DescriptorType::DisplayProductSerialNumber
            } else if &self.tag_or_text[0..4] == b"\x00\x00\x00\xFE" {
                DescriptorType::AlphanumericDataString
            } else if &self.tag_or_text[0..4] == b"\x00\x00\x00\xFD" {
                DescriptorType::DisplayRangeLimits
            } else if &self.tag_or_text[0..4] == b"\x00\x00\x00\x00" {
                DescriptorType::Dummy
            } else {
                DescriptorType::Unknown
            }
        } else {
            DescriptorType::TimingData
        }
    }

    /// Check if this is an interlaced timing
    pub fn is_interlaced(&self) -> bool {
        (self.flags & 0x80) != 0
    }

    /// Get horizontal sync polarity (true = positive)
    pub fn horz_sync_polarity(&self) -> bool {
        (self.flags & 0x04) != 0
    }

    /// Get vertical sync polarity (true = positive)
    pub fn vert_sync_polarity(&self) -> bool {
        (self.flags & 0x08) != 0
    }

    /// Calculate horizontal frequency in kHz
    pub fn horizontal_frequency(&self) -> u32 {
        let pixel_mhz = self.pixel_clock_100khz as u32 * 10_000;
        let total_pixels = self.horz_active as u32 + self.horz_blanking as u32;
        pixel_mhz / total_pixels
    }

    /// Calculate vertical frequency in Hz
    pub fn vertical_frequency(&self) -> u32 {
        let hz = self.horizontal_frequency();
        let total_lines = self.vert_active as u32 + self.vert_blanking as u32;
        hz / total_lines
    }
}

// ============================================================================
// EDID Parsing
// ============================================================================

impl EdidBaseBlock {
    /// Parse EDID from a raw 128-byte buffer
    pub fn parse(buffer: &[u8; EDID_BLOCK_SIZE]) -> Result<Self, EdidError> {
        // Verify header
        if &buffer[0..8] != &EDID_HEADER {
            return Err(EdidError::InvalidHeader);
        }

        // Verify checksum
        let sum: u8 = buffer.iter().sum();
        if sum != 0 {
            return Err(EdidError::ChecksumMismatch);
        }

        // Parse manufacturer ID (3-letter code)
        let mfg_hi = (buffer[8] as u16) << 8;
        let mfg_lo = buffer[9] as u16;
        let manufacturer_id = ((mfg_hi >> 2) & 0x1F) as u16
            | ((mfg_hi << 3) & 0xE0) as u16
            | ((mfg_lo >> 5) & 0x18) as u16;
        let manufacturer_letters = [
            ((manufacturer_id >> 10) & 0x1F) as u8,
            ((manufacturer_id >> 5) & 0x1F) as u8,
            (manufacturer_id & 0x1F) as u8,
        ];
        // Publish the parsed manufacturer letters for diagnostics.
        LAST_MFG_L0.store(manufacturer_letters[0] as u32, core::sync::atomic::Ordering::Relaxed);
        LAST_MFG_L1.store(manufacturer_letters[1] as u32, core::sync::atomic::Ordering::Relaxed);
        LAST_MFG_L2.store(manufacturer_letters[2] as u32, core::sync::atomic::Ordering::Relaxed);
        MFG_PARSES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        // Parse product ID
        let product_id = u16::from_le_bytes([buffer[10], buffer[11]]);

        // Parse serial number
        let serial_number = u32::from_le_bytes([
            buffer[12], buffer[13], buffer[14], buffer[15]
        ]);

        // Parse week and year
        let week = buffer[16];
        let year = buffer[17];

        // Parse version/revision
        let version = buffer[18];
        let revision = buffer[19];

        // Parse video input
        let input_byte = buffer[20];
        let is_digital = (input_byte & 0x80) != 0;
        let video_input = EdidVideoInput {
            is_digital,
            color_depth: (input_byte >> 4) & 0x07,
            interface_type: input_byte & 0x0F,
            signal_level: input_byte & 0x0F,
            blank_to_black: (input_byte & 0x40) != 0,
            separate_syncs: (input_byte & 0x10) != 0,
            composite_sync: (input_byte & 0x08) != 0,
            sync_on_green: (input_byte & 0x04) != 0,
            vsync_serrated: (input_byte & 0x02) != 0,
        };

        // Parse screen size
        let screen_width_cm = buffer[21];
        let screen_height_cm = buffer[22];

        // Parse gamma
        let gamma = buffer[23];

        // Parse features
        let features_byte = buffer[24];
        let features = EdidFeatures {
            uses_gtf: (features_byte & 0x80) != 0,
            has_preferred_timing: (features_byte & 0x40) != 0,
            continuous_frequency: (features_byte & 0x20) != 0,
            display_type: (features_byte >> 3) & 0x03,
            srgb_default: (features_byte & 0x04) != 0,
            preferred_timing_native: (features_byte & 0x02) != 0,
            gtf_supported: (features_byte & 0x01) != 0,
        };

        // Parse chromaticity
        let chromaticity = parse_chromaticity(&buffer[25..38]);

        // Parse established timings (bytes 35-37: two bitmap bytes + byte 37)
        let established = parse_established_timings(&buffer[35..38]);

        // Parse standard timings (bytes 38-53)
        let mut standard_timings = [EdidStandardTiming::default(); 8];
        for i in 0..8 {
            let offset = 38 + i * 2;
            standard_timings[i] = EdidStandardTiming {
                horz_pixels_div_8_minus_31: buffer[offset],
                refresh_minus_60_and_aspect: buffer[offset + 1],
            };
        }

        // Parse detailed timing descriptors
        let mut descriptors = [EdidDescriptor::default(); 4];
        for i in 0..4 {
            let offset = 54 + i * 18;
            descriptors[i] = parse_descriptor(&buffer[offset..offset + 18]);
        }

        // Parse extensions
        let extensions = buffer[EDID_EXTENSION_FLAG_OFFSET];
        let checksum = buffer[EDID_CHECKSUM_OFFSET];

        Ok(Self {
            header: [0; 8],
            manufacturer_id,
            product_id,
            serial_number,
            week,
            year,
            version,
            revision,
            input_video: video_input,
            screen_width_cm,
            screen_height_cm,
            gamma,
            features,
            chromaticity,
            established_timings: established,
            standard_timings,
            descriptors,
            extensions,
            checksum,
        })
    }

    /// Get manufacturer name as ASCII string
    pub fn manufacturer_name(&self) -> [u8; 3] {
        let mut name = [0u8; 3];
        let chars = [
            ((self.manufacturer_id >> 10) & 0x1F) as u8 + b'A' - 1,
            ((self.manufacturer_id >> 5) & 0x1F) as u8 + b'A' - 1,
            (self.manufacturer_id & 0x1F) as u8 + b'A' - 1,
        ];
        name.copy_from_slice(&chars);
        name
    }

    /// Check if EDID version is valid
    pub fn is_valid_version(&self) -> bool {
        self.version == 1 && self.revision >= 3
    }

    /// Get preferred timing descriptor
    pub fn preferred_timing(&self) -> Option<EdidDescriptor> {
        if self.features.has_preferred_timing {
            Some(self.descriptors[0])
        } else {
            None
        }
    }
}

/// Parse chromaticity coordinates
fn parse_chromaticity(buffer: &[u8]) -> EdidChromaticity {
    EdidChromaticity {
        red_x: ((buffer[0] as u16) << 2) | ((buffer[4] >> 6) & 0x03) as u16,
        red_y: ((buffer[1] as u16) << 2) | ((buffer[4] >> 4) & 0x03) as u16,
        green_x: ((buffer[2] as u16) << 2) | ((buffer[5] >> 6) & 0x03) as u16,
        green_y: ((buffer[3] as u16) << 2) | ((buffer[5] >> 4) & 0x03) as u16,
        blue_x: ((buffer[6] as u16) << 2) | ((buffer[7] >> 6) & 0x03) as u16,
        blue_y: ((buffer[8] as u16) << 2) | ((buffer[7] >> 4) & 0x03) as u16,
        white_x: ((buffer[10] as u16) << 2) | ((buffer[11] >> 6) & 0x03) as u16,
        white_y: ((buffer[12] as u16) << 2) | ((buffer[11] >> 4) & 0x03) as u16,
    }
}

/// Parse established timing bits.
///
/// Per the VESA EDID 1.3/1.4 standard:
/// - `mj[0]` = byte 35: 720x400@70Hz (bit 0) through 800x600@60Hz (bit 7)
/// - `mj[1]` = byte 36: 800x600@72Hz (bit 0) through 1280x1024@75Hz (bit 7)
/// - `mj[2]` = byte 37: 1152x864@75Hz (bit 0), 1152x870@75Hz (bit 7), 640x400@85Hz (bit 6)
fn parse_established_timings(mj: &[u8]) -> EdidEstablishedTimings {
    let mj0 = mj[0];
    let mj1 = mj[1];
    let mj2 = mj[2];

    EdidEstablishedTimings {
        // Byte 35 (mj0)
        timing_720_400_70: (mj0 & 0x01) != 0,
        timing_720_400_88: (mj0 & 0x02) != 0,
        timing_640_480_60: (mj0 & 0x04) != 0,
        timing_640_480_67: (mj0 & 0x08) != 0,
        timing_640_480_72: (mj0 & 0x10) != 0,
        timing_640_480_75: (mj0 & 0x20) != 0,
        timing_800_600_56: (mj0 & 0x40) != 0,
        timing_800_600_60: (mj0 & 0x80) != 0,
        // Byte 36 (mj1)
        timing_800_600_72: (mj1 & 0x01) != 0,
        timing_800_600_75: (mj1 & 0x02) != 0,
        timing_832_624_75: (mj1 & 0x04) != 0,
        timing_1024_768_87: (mj1 & 0x08) != 0,
        timing_1024_768_60: (mj1 & 0x10) != 0,
        timing_1024_768_70: (mj1 & 0x20) != 0,
        timing_1024_768_75: (mj1 & 0x40) != 0,
        timing_1280_1024_75: (mj1 & 0x80) != 0,
        // Byte 37 (mj2) — the bits that were previously `mj0 & 0x00` (always 0)!
        timing_1152_864_75: (mj2 & 0x01) != 0,
        timing_640_400_85: (mj2 & 0x40) != 0,
        timing_1152_870_75: (mj2 & 0x80) != 0,
    }
}

/// Parse a detailed timing descriptor
fn parse_descriptor(buffer: &[u8]) -> EdidDescriptor {
    let pixel_clock = u16::from_le_bytes([buffer[0], buffer[1]]);
    
    EdidDescriptor {
        pixel_clock_100khz: pixel_clock,
        horz_active: ((buffer[2] as u16) << 8) | (buffer[4] as u16),
        horz_blanking: ((buffer[3] as u16) << 8) | (buffer[5] as u16),
        vert_active: ((buffer[5] as u16) << 4) | ((buffer[7] >> 4) as u16),
        vert_blanking: ((buffer[6] as u16) << 8) | ((buffer[7] & 0x0F) as u16),
        horz_sync_offset: ((buffer[8] as u16) << 8) | ((buffer[11] >> 2) & 0x30) as u16,
        horz_sync_pulse: ((buffer[9] as u16) << 8) | (((buffer[11] >> 4) & 0xC0) as u16),
        vert_sync_offset: (((buffer[10] as u16) << 4) & 0xF0) | (((buffer[11] >> 2) & 0x03) as u16),
        vert_sync_pulse: (((buffer[10] as u16) << 8) & 0x0F00) | (((buffer[11] >> 0) & 0xC0) as u16),
        horz_display_size: ((buffer[12] as u16) << 8) | (buffer[14] as u16),
        vert_display_size: ((buffer[13] as u16) << 8) | (buffer[15] as u16),
        horz_border: buffer[16],
        vert_border: buffer[17],
        flags: buffer[17] & 0xC0,
        tag_or_text: [buffer[0], buffer[1], buffer[2], buffer[3], 
                      buffer[4], buffer[5], buffer[6], buffer[7],
                      buffer[8], buffer[9], buffer[10], buffer[11],
                      buffer[12], buffer[13]],
    }
}

// ============================================================================
// DDC/I2C Interface (Platform-Specific)
// ============================================================================

/// Trait for DDC/I2C master implementations
pub trait DdcMaster {
    /// Read EDID block from the display
    fn read_edid_block(&mut self, block: u8, buffer: &mut [u8; 128]) -> Result<(), EdidError>;
}

/// Read EDID using a platform-specific I2C master
pub fn read_edid<M: DdcMaster>(master: &mut M) -> Result<EdidBaseBlock, EdidError> {
    // Read first EDID block
    let mut buffer = [0u8; 128];
    master.read_edid_block(0, &mut buffer)?;
    
    // Parse the block
    EdidBaseBlock::parse(&buffer)
}

// ============================================================================
// Display Information
// ============================================================================

/// Parsed display information
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    /// Manufacturer name (3 letters)
    pub manufacturer: [u8; 3],
    /// Product ID
    pub product_id: u16,
    /// Serial number
    pub serial_number: u32,
    /// Year of manufacture
    pub year: u16,
    /// Screen size in cm
    pub screen_width_cm: u8,
    pub screen_height_cm: u8,
    /// Preferred resolution
    pub preferred_width: u16,
    pub preferred_height: u16,
    /// Preferred refresh rate in Hz
    pub preferred_refresh_hz: u32,
    /// Native resolution if different from preferred
    pub native_width: u16,
    pub native_height: u16,
}

impl From<EdidBaseBlock> for DisplayInfo {
    fn from(edid: EdidBaseBlock) -> Self {
        let preferred = edid.preferred_timing();
        
        DisplayInfo {
            manufacturer: edid.manufacturer_name(),
            product_id: edid.product_id,
            serial_number: edid.serial_number,
            year: (1990 + edid.year as u16) as u16,
            screen_width_cm: edid.screen_width_cm,
            screen_height_cm: edid.screen_height_cm,
            preferred_width: preferred.map(|p| p.horz_active).unwrap_or(0),
            preferred_height: preferred.map(|p| p.vert_active).unwrap_or(0),
            preferred_refresh_hz: preferred.map(|p| p.vertical_frequency()).unwrap_or(0),
            native_width: preferred.map(|p| p.horz_active).unwrap_or(0),
            native_height: preferred.map(|p| p.vert_active).unwrap_or(0),
        }
    }
}

// ============================================================================
// EDID Initialization
// ============================================================================

/// Initialize EDID parsing support
pub fn init() {
    log::video_ok("edid", "display identification parser initialized");
}

/// Parse EDID from a raw buffer (for testing/debugging)
pub fn parse_from_buffer(buffer: &[u8]) -> Result<EdidBaseBlock, EdidError> {
    if buffer.len() < 128 {
        return Err(EdidError::InvalidHeader);
    }

    let mut block = [0u8; 128];
    block.copy_from_slice(&buffer[..128]);
    EdidBaseBlock::parse(&block)
}

static LAST_MFG_L0: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static LAST_MFG_L1: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static LAST_MFG_L2: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static MFG_PARSES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Return the most recent 3-letter manufacturer code, packed as
/// `[letter0, letter1, letter2]` in the low 24 bits of a u32.
pub fn last_manufacturer_code() -> u32 {
    let l0 = LAST_MFG_L0.load(core::sync::atomic::Ordering::Relaxed) & 0xFF;
    let l1 = LAST_MFG_L1.load(core::sync::atomic::Ordering::Relaxed) & 0xFF;
    let l2 = LAST_MFG_L2.load(core::sync::atomic::Ordering::Relaxed) & 0xFF;
    (l0 << 16) | (l1 << 8) | l2
}

/// Return the cumulative number of manufacturer-ID parses.
pub fn manufacturer_parses() -> u32 {
    MFG_PARSES.load(core::sync::atomic::Ordering::Relaxed)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// QEMU EDID block from i2c_ddc.rs - exactly 128 bytes
    const QEMU_EDID_BLOCK: [u8; 128] = [
        // Header (8 bytes)
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        // Vendor/Product ID (4 bytes): "QMU\0" packed
        0x51, 0x4D, 0x00, 0x00,
        // Serial number (4 bytes)
        0x00, 0x00, 0x00, 0x00,
        // Week and Year (2 bytes): Week 1, Year 2003
        0x01, 0x03,
        // Version and Revision (2 bytes): 1.3
        0x01, 0x03,
        // Video input (1 byte): Digital 8-bit, RGB 4:4:4
        0x80,
        // Max horizontal size (1 byte)
        0x00,
        // Max vertical size (1 byte)
        0x00,
        // Gamma (1 byte): 2.2
        0x78,
        // Feature support (1 byte): GTF not supported, preferred timing specified
        0x0E,
        // Chromaticity (10 bytes): standard sRGB
        0x0C, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
        0x20, 0x16,
        // Established timings (3 bytes): none
        0x00, 0x00, 0x00,
        // Standard timings (16 bytes): none - filled with 0x01
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        // Descriptor 1: 1024x768 preferred timing (18 bytes)
        0x01, 0x1D, 0x00, 0x72, 0x51, 0xD0, 0x1E, 0x20, 0x6E, 0x28, 0x55, 0x00,
        0xC4, 0x18, 0x00, 0x00, 0x00, 0x1E,
        // Descriptor 2: Display name "QEMU" (18 bytes)
        0x00, 0x00, 0x00, 0xFC, 0x00, 0x51, 0x45, 0x4D, 0x55, 0x0A, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        // Descriptor 3: Display range limits (18 bytes)
        0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0xC8, 0x00, 0x30, 0x00, 0x0A, 0x0A,
        0x0A, 0x0A, 0x0A, 0x0A, 0x00, 0x00,
        // Descriptor 4: Empty (18 bytes)
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Extension flag (1 byte): 0
        0x00,
        // Checksum (1 byte)
        0x5B,
    ];

    #[test]
    fn test_edid_parse_qemu() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        // Verify manufacturer is "QMU"
        let name = block.manufacturer_name();
        assert_eq!(name[0], b'Q');
        assert_eq!(name[1], b'M');
        assert_eq!(name[2], b'U');
    }

    #[test]
    fn test_edid_preferred_timing() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        let preferred = block.preferred_timing();
        assert!(preferred.is_some());
        let timing = preferred.unwrap();
        // QEMU EDID has 1024x768 preferred timing
        assert_eq!(timing.horz_active, 1024);
        assert_eq!(timing.vert_active, 768);
    }

    #[test]
    fn test_edid_checksum() {
        // Verify the QEMU EDID block has valid checksum
        let sum: u8 = QEMU_EDID_BLOCK.iter().sum();
        assert_eq!(sum, 0, "QEMU EDID checksum should be valid");
    }

    #[test]
    fn test_edid_invalid_header() {
        let mut data = QEMU_EDID_BLOCK;
        data[0] = 0x01; // Wrong header byte
        let result = EdidBaseBlock::parse(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), EdidError::InvalidHeader);
    }

    #[test]
    fn test_edid_invalid_checksum() {
        let mut data = QEMU_EDID_BLOCK;
        data[127] = 0x00; // Corrupt checksum
        let result = EdidBaseBlock::parse(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), EdidError::ChecksumMismatch);
    }

    #[test]
    fn test_edid_version() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        assert!(block.is_valid_version());
        assert_eq!(block.version, 1);
        assert_eq!(block.revision, 3);
    }

    #[test]
    fn test_edid_descriptor_type() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        // First descriptor should be timing data
        assert_eq!(block.descriptors[0].descriptor_type(), DescriptorType::TimingData);
        // Second descriptor should be display name
        assert_eq!(block.descriptors[1].descriptor_type(), DescriptorType::DisplayProductName);
        // Third descriptor should be display range limits
        assert_eq!(block.descriptors[2].descriptor_type(), DescriptorType::DisplayRangeLimits);
        // Fourth descriptor is empty/dummy
        assert_eq!(block.descriptors[3].descriptor_type(), DescriptorType::Dummy);
    }

    #[test]
    fn test_edid_display_name() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        let name_desc = &block.descriptors[1];
        // Display name should be "QEMU\n"
        let name_bytes = &name_desc.tag_or_text[5..10];
        assert_eq!(name_bytes, &[0x51, 0x45, 0x4D, 0x55, 0x0A]); // "QEMU\n"
    }

    #[test]
    fn test_edid_established_timings_none() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        // QEMU EDID has no established timings (all zero)
        assert!(!block.established_timings.timing_640_480_60);
        assert!(!block.established_timings.timing_800_600_60);
        assert!(!block.established_timings.timing_1024_768_60);
    }

    #[test]
    fn test_edid_is_interlaced() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        let preferred = block.preferred_timing().unwrap();
        // 1024x768 preferred timing should not be interlaced
        assert!(!preferred.is_interlaced());
    }

    #[test]
    fn test_edid_horizontal_frequency() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        let preferred = block.preferred_timing().unwrap();
        let hz = preferred.horizontal_frequency();
        // 1024x768@60Hz has a specific horizontal frequency
        assert!(hz > 0);
    }

    #[test]
    fn test_display_info_from_edid() {
        let block = EdidBaseBlock::parse(&QEMU_EDID_BLOCK).unwrap();
        let info: DisplayInfo = block.into();
        assert_eq!(info.manufacturer, [b'Q', b'M', b'U']);
        assert_eq!(info.preferred_width, 1024);
        assert_eq!(info.preferred_height, 768);
        assert!(info.preferred_refresh_hz > 0);
    }

    #[test]
    fn test_parse_from_buffer() {
        let result = parse_from_buffer(&QEMU_EDID_BLOCK);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_from_buffer_too_short() {
        let short_data = [0u8; 64];
        let result = parse_from_buffer(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_manufacturer_parses_increment() {
        let initial = manufacturer_parses();
        let _ = EdidBaseBlock::parse(&QEMU_EDID_BLOCK);
        let after = manufacturer_parses();
        assert_eq!(after, initial + 1);
    }

    #[test]
    fn test_last_manufacturer_code() {
        let _ = EdidBaseBlock::parse(&QEMU_EDID_BLOCK);
        let code = last_manufacturer_code();
        // QMU packed as 0x51, 0x4D, 0x55
        assert_eq!((code >> 16) & 0xFF, 0x51); // Q
        assert_eq!((code >> 8) & 0xFF, 0x4D);  // M
        assert_eq!(code & 0xFF, 0x55);          // U
    }
}
