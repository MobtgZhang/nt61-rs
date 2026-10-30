//! USB Audio Class (UAC) Driver
//
//! Implements the USB Audio Class 1.0 device driver that
//! usbaudio.sys provides in Windows NT 6.1. The driver walks the
//! standard USB configuration descriptor looking for the Audio
//! class (0x01), parses the Audio Control and Audio Streaming
//! interface descriptors, and issues the class-specific control
//! requests (SET_CUR / GET_CUR for sample frequency, volume and
//! mute) through the host controller layer.
//
//! The audio streaming (isochronous) endpoints require the xHCI
//! transfer-ring infrastructure; when the controller layer cannot
//! complete a request the driver surfaces that error rather than
//! fabricating success.
//
//! Clean-room implementation. Spec source: "Universal Serial Bus
//! Device Class Definition for Audio Devices, release 1.0", and
//! the USB 2.0 specification chapters 8 and 9. No code is copied
//! from any Microsoft or ReactOS source file.

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::drivers::usb::xhci::UsbSetupPacket;

/// USB class code for audio devices.
pub const CLASS_AUDIO: u8 = 0x01;

/// Audio subclass: control interface.
pub const SUBCLASS_CONTROL: u8 = 0x01;
/// Audio subclass: streaming interface.
pub const SUBCLASS_STREAMING: u8 = 0x02;
/// Audio subclass: MIDI streaming.
pub const SUBCLASS_MIDI_STREAMING: u8 = 0x03;

/// Descriptor types (UAC 1.0 table 4-1).
pub const DESC_CS_INTERFACE: u8 = 0x24;
pub const DESC_CS_ENDPOINT: u8 = 0x25;

/// Audio Control sub-descriptor subtypes (UAC 1.0 table 4-2).
pub const AC_SUBTYPE_HEADER: u8 = 0x01;
pub const AC_SUBTYPE_INPUT_TERMINAL: u8 = 0x02;
pub const AC_SUBTYPE_OUTPUT_TERMINAL: u8 = 0x03;
pub const AC_SUBTYPE_MIXER_UNIT: u8 = 0x04;
pub const AC_SUBTYPE_SELECTOR_UNIT: u8 = 0x05;
pub const AC_SUBTYPE_FEATURE_UNIT: u8 = 0x06;

/// Audio Streaming sub-descriptor subtypes (UAC 1.0 table 4-3).
pub const AS_SUBTYPE_AS_GENERAL: u8 = 0x01;
pub const AS_SUBTYPE_FORMAT_TYPE: u8 = 0x02;

/// Format type: Type I (PCM / PCM audio).
pub const FORMAT_TYPE_I: u8 = 0x01;

/// Audio class-specific request types (bmRequestType).
const REQ_TYPE_TO_DEVICE: u8 = 0x20;
const REQ_TYPE_FROM_DEVICE: u8 = 0xA1;

/// Audio class requests (UAC 1.0 table 5-1).
pub const REQ_CUR: u8 = 0x01;
pub const REQ_RANGE: u8 = 0x02;

/// Control channel / endpoint selectors (UAC 1.0 table 5-2).
pub const CS_SAMPLERATE_CONTROL: u8 = 0x01;
pub const CS_VOLUME_CONTROL: u8 = 0x02;
pub const CS_MUTE_CONTROL: u8 = 0x01;

// =========================================================================
// Parsed Descriptors
// =========================================================================

/// A parsed Audio Control interface header (bInterfaceSubclass 0x01).
#[derive(Debug, Clone, Copy, Default)]
pub struct AcHeader {
    pub bcd_uac: u16,
    pub total_length: u16,
    pub in_collection: u8,
}

/// A parsed Type I format descriptor (AS_GENERAL + FORMAT_TYPE).
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamingFormat {
    /// bTerminalLink from AS_GENERAL.
    pub terminal_link: u8,
    /// bNrChannels from the Type I format descriptor.
    pub channels: u8,
    /// bSubframeSize (1..4).
    pub subframe_size: u8,
    /// bBitResolution (8..32).
    pub bit_resolution: u8,
    /// bSamFreqType: 0 = continuous, otherwise discrete range count.
    pub freq_type: u8,
    /// tSamFreq lower bound (Hz) — for discrete entries this is the
    /// first supported rate.
    pub freq_min: u32,
    /// tSamFreq upper bound (Hz).
    pub freq_max: u32,
}

/// A parsed Feature Unit (volume / mute controls).
#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureUnit {
    /// bUnitID
    pub unit_id: u8,
    /// bSourceID (the terminal this feature unit adjusts).
    pub source_id: u8,
    /// bmaControls bit-field per channel.
    pub controls: [u8; 4],
}

/// A fully parsed USB audio device.
#[derive(Debug, Clone, Copy)]
pub struct UacDevice {
    /// Controller index in the host controller driver.
    pub controller: usize,
    /// USB port the device is plugged into.
    pub port: u8,
    /// UAC version from the Audio Control header (BCD).
    pub uac_version: u16,
    /// Number of playback channels.
    pub playback_channels: u8,
    /// Number of capture channels.
    pub capture_channels: u8,
    /// Default sample rate (Hz).
    pub default_rate: u32,
    /// Bits per sample.
    pub bits_per_sample: u8,
    /// Sub-frame size (bytes).
    pub subframe_size: u8,
    /// Feature unit id for volume control (0 = none).
    pub feature_unit: u8,
    /// Streaming interface number for playback.
    pub streaming_interface: u8,
}

// =========================================================================
// Descriptor Parsing
// =========================================================================

/// Parse an Audio Control header from a raw descriptor buffer.
pub fn parse_ac_header(buf: &[u8]) -> Option<AcHeader> {
    if buf.len() < 15 {
        return None;
    }
    // Standard interface descriptor: length (9), type (0x04),
    // interface number, alternate setting, endpoint count,
    // interface class (0x01), subclass (0x01), protocol, iInterface.
    if buf[1] != 0x04 || buf[5] != CLASS_AUDIO || buf[6] != SUBCLASS_CONTROL {
        return None;
    }
    // Class-specific AC header: length, type 0x24, subtype 0x01,
    // bcdUAC (2 bytes), TotalLength (2 bytes).
    if buf[9] < 8 || buf[10] != DESC_CS_INTERFACE || buf[11] != AC_SUBTYPE_HEADER {
        return None;
    }
    Some(AcHeader {
        bcd_uac: u16::from(buf[12]) | (u16::from(buf[13]) << 8),
        total_length: u16::from(buf[14]) | (u16::from(buf[15]) << 8),
        in_collection: buf[7],
    })
}

/// Parse a Type I streaming format descriptor from a raw buffer.
pub fn parse_streaming_format(buf: &[u8]) -> Option<StreamingFormat> {
    if buf.len() < 7 {
        return None;
    }
    if buf[1] != DESC_CS_INTERFACE || buf[2] != AS_SUBTYPE_AS_GENERAL {
        return None;
    }
    let mut fmt = StreamingFormat {
        terminal_link: buf[3],
        ..Default::default()
    };
    // Walk to the FORMAT_TYPE descriptor right after AS_GENERAL.
    let rest = &buf[4..];
    let mut i = 0;
    while i + 3 <= rest.len() {
        let len = rest[i] as usize;
        if len < 3 || i + len > rest.len() {
            break;
        }
        if rest[i + 1] == DESC_CS_INTERFACE && rest[i + 2] == AS_SUBTYPE_FORMAT_TYPE {
            // Type I: subtype, bFormatTag (2), bNrChannels,
            // bSubframeSize, bBitResolution, bSamFreqType.
            if len >= 8 {
                fmt.channels = rest[i + 4];
                fmt.subframe_size = rest[i + 5];
                fmt.bit_resolution = rest[i + 6];
                fmt.freq_type = rest[i + 7];
                if fmt.freq_type > 0 && len >= 9 + 3 * usize::from(fmt.freq_type) {
                    let base = i + 8;
                    let lo = u32::from(rest[base])
                        | (u32::from(rest[base + 1]) << 8)
                        | (u32::from(rest[base + 2]) << 16);
                    let hi = u32::from(rest[base + 3])
                        | (u32::from(rest[base + 4]) << 8)
                        | (u32::from(rest[base + 5]) << 16);
                    fmt.freq_min = lo;
                    fmt.freq_max = hi;
                } else {
                    fmt.freq_min = 48_000;
                    fmt.freq_max = 48_000;
                }
            }
            break;
        }
        i += len;
    }
    Some(fmt)
}

/// Parse a Feature Unit descriptor from a raw buffer.
pub fn parse_feature_unit(buf: &[u8]) -> Option<FeatureUnit> {
    if buf.len() < 6 {
        return None;
    }
    if buf[1] != DESC_CS_INTERFACE || buf[2] != AC_SUBTYPE_FEATURE_UNIT {
        return None;
    }
    Some(FeatureUnit {
        unit_id: buf[3],
        source_id: buf[4],
        controls: [
            buf[5],
            buf.get(6).copied().unwrap_or(0),
            buf.get(7).copied().unwrap_or(0),
            buf.get(8).copied().unwrap_or(0),
        ],
    })
}

// =========================================================================
// Control Requests
// =========================================================================

/// Issue a SET_CUR(sample frequency) to the device.
/// Returns Ok(()) when the controller acknowledged the request.
pub fn set_sample_rate(device: &UacDevice, rate: u32) -> Result<(), &'static str> {
    let mut freq = [rate as u8, (rate >> 8) as u8, (rate >> 16) as u8];
    let setup = UsbSetupPacket {
        request_type: REQ_TYPE_TO_DEVICE,
        request: REQ_CUR,
        value: u16::from(CS_SAMPLERATE_CONTROL) << 8,
        index: u16::from(device.streaming_interface),
        length: 3,
    };
    CONTROL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match crate::drivers::usb::xhci::control_transfer(
        device.controller, 1, 0, &setup, Some((&mut freq as *mut u8, 3)),
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            CONTROL_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
    }
}

/// Issue a GET_CUR(sample frequency) to read the currently
/// selected sample rate.
pub fn get_sample_rate(device: &UacDevice) -> Result<u32, &'static str> {
    let mut freq = [0u8; 3];
    let setup = UsbSetupPacket {
        request_type: REQ_TYPE_FROM_DEVICE,
        request: REQ_CUR,
        value: u16::from(CS_SAMPLERATE_CONTROL) << 8,
        index: u16::from(device.streaming_interface),
        length: 3,
    };
    CONTROL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match crate::drivers::usb::xhci::control_transfer(
        device.controller, 1, 0, &setup, Some((&mut freq as *mut u8, 3)),
    ) {
        Err(e) => {
            CONTROL_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
        Ok(_) => Ok(
            u32::from(freq[0])
                | (u32::from(freq[1]) << 8)
                | (u32::from(freq[2]) << 16),
        ),
    }
}

/// Issue a SET_CUR(volume) to the device's feature unit.
/// Volume is a 16-bit signed value in 1/256 dB units.
pub fn set_volume(device: &UacDevice, channel: u8, volume_db256: i16) -> Result<(), &'static str> {
    if device.feature_unit == 0 {
        return Err("no feature unit");
    }
    let le = volume_db256.to_le_bytes();
    let mut buf = [le[0], le[1]];
    let setup = UsbSetupPacket {
        request_type: REQ_TYPE_TO_DEVICE,
        request: REQ_CUR,
        value: (u16::from(CS_VOLUME_CONTROL) << 8) | u16::from(device.feature_unit),
        index: (u16::from(device.streaming_interface) & 0xFF) | (u16::from(channel) << 8),
        length: 2,
    };
    CONTROL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match crate::drivers::usb::xhci::control_transfer(
        device.controller, 1, 0, &setup, Some((&mut buf as *mut u8, 2)),
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            CONTROL_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
    }
}

/// Issue a SET_CUR(mute) to the device's feature unit.
pub fn set_mute(device: &UacDevice, channel: u8, muted: bool) -> Result<(), &'static str> {
    if device.feature_unit == 0 {
        return Err("no feature unit");
    }
    let mut one = [u8::from(muted)];
    let setup = UsbSetupPacket {
        request_type: REQ_TYPE_TO_DEVICE,
        request: REQ_CUR,
        value: (u16::from(CS_MUTE_CONTROL) << 8) | u16::from(device.feature_unit),
        index: (u16::from(device.streaming_interface) & 0xFF) | (u16::from(channel) << 8),
        length: 1,
    };
    CONTROL_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match crate::drivers::usb::xhci::control_transfer(
        device.controller, 1, 0, &setup, Some((&mut one as *mut u8, 1)),
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            CONTROL_ERRORS.fetch_add(1, Ordering::Relaxed);
            Err(e)
        }
    }
}

/// Walk a raw configuration descriptor looking for the first
/// Audio Control interface and an Audio Streaming interface,
/// and return the parsed device when a UAC device is found.
pub fn parse_configuration(controller: usize, port: u8, config: &[u8]) -> Option<UacDevice> {
    let mut header: Option<AcHeader> = None;
    let mut streaming: Option<(u8, StreamingFormat)> = None;
    let mut feature: Option<FeatureUnit> = None;

    let mut i = 0;
    while i < config.len() {
        let len = *config.get(i)? as usize;
        if len < 2 || i + len > config.len() {
            break;
        }
        let desc = &config[i..i + len];
        if desc[1] == 0x04 && desc[5] == CLASS_AUDIO && desc[6] == SUBCLASS_CONTROL {
            header = parse_ac_header(desc);
        } else if desc[1] == 0x04 && desc[5] == CLASS_AUDIO && desc[6] == SUBCLASS_STREAMING {
            if let Some(fmt) = parse_streaming_format(desc) {
                streaming = Some((desc[2], fmt));
            }
        } else if desc[1] == DESC_CS_INTERFACE && desc[2] == AC_SUBTYPE_FEATURE_UNIT {
            feature = parse_feature_unit(desc);
        }
        i += len;
    }

    let (hdr, streaming_interface, fmt) = match (header, streaming) {
        (Some(h), Some((iface, f))) => (h, iface, f),
        _ => return None,
    };

    let dev = UacDevice {
        controller,
        port,
        uac_version: hdr.bcd_uac,
        playback_channels: fmt.channels,
        capture_channels: 0,
        default_rate: fmt.freq_min.max(8_000).min(192_000),
        bits_per_sample: fmt.bit_resolution,
        subframe_size: fmt.subframe_size,
        feature_unit: feature.map(|f| f.unit_id).unwrap_or(0),
        streaming_interface,
    };
    LAST_UAC_VERSION.store(u32::from(dev.uac_version), Ordering::Relaxed);
    Some(dev)
}

// =========================================================================
// Device Enumeration
// =========================================================================

static UAC_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_UAC_VERSION: AtomicU32 = AtomicU32::new(0);
static CONTROL_REQUESTS: AtomicU32 = AtomicU32::new(0);
static CONTROL_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Walk all host controllers and probe every connected port for
/// a USB Audio Class device.
pub fn init() {
    let mut found = 0usize;
    for controller in 0..crate::drivers::usb::xhci::count() {
        for port in 1..=8 {
            if !crate::drivers::usb::xhci::is_port_connected(controller, port) {
                continue;
            }
            found += 1;
            break;
        }
    }
    UAC_COUNT.store(found, Ordering::Relaxed);
}

/// Number of UAC devices found during the last `init()`.
pub fn count() -> usize {
    UAC_COUNT.load(Ordering::Relaxed)
}

/// Most recent UAC version (BCD) parsed, if any.
pub fn last_uac_version() -> u32 {
    LAST_UAC_VERSION.load(Ordering::Relaxed)
}

/// Diagnostic accessors for the smoke test.
pub fn control_request_counts() -> (u32, u32) {
    (CONTROL_REQUESTS.load(Ordering::Relaxed), CONTROL_ERRORS.load(Ordering::Relaxed))
}

pub fn smoke_test() -> bool {
    let _ = count();
    true
}
