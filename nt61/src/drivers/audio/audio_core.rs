//! Audio Core Abstraction Layer
//!
//! Provides a unified interface for audio devices, regardless of the
//! underlying hardware (HD Audio, AC'97, USB Audio, etc.).
//!
//! This layer implements:
//! - Device enumeration and management
//! - Audio format conversion
//! - Volume control abstraction
//! - Stream management
//! - Buffer management

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// Audio device types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDeviceType {
    /// HD Audio (Intel HDA)
    HdAudio,
    /// AC'97 Audio
    Ac97,
    /// USB Audio
    UsbAudio,
    /// Bluetooth Audio
    BluetoothAudio,
    /// Virtual Audio Device
    Virtual,
}

/// Audio device capabilities
#[derive(Debug, Clone, Copy)]
pub struct AudioCapabilities {
    /// Supports playback
    pub playback: bool,
    /// Supports capture
    pub capture: bool,
    /// Maximum number of output channels
    pub max_output_channels: u8,
    /// Maximum number of input channels
    pub max_input_channels: u8,
    /// Supported sample rates (bitmask)
    pub sample_rates: u32,
    /// Supported bit depths (bitmask)
    pub bit_depths: u16,
    /// Supports hardware mixing
    pub hardware_mixing: bool,
    /// Supports hardware volume control
    pub hardware_volume: bool,
}

impl AudioCapabilities {
    /// Check if a sample rate is supported

    pub fn supports_sample_rate(&self, rate: u32) -> bool {
        let bit = match rate {
            8000 => 0,
            11025 => 1,
            16000 => 2,
            22050 => 3,
            32000 => 4,
            44100 => 5,
            48000 => 6,
            88200 => 7,
            96000 => 8,
            176400 => 9,
            192000 => 10,
            _ => return false,
        };
        (self.sample_rates & (1 << bit)) != 0
    }

    /// Check if a bit depth is supported
    pub fn supports_bit_depth(&self, bits: u8) -> bool {
        let bit = match bits {
            8 => 0,
            16 => 1,
            20 => 2,
            24 => 3,
            32 => 4,
            _ => return false,
        };
        (self.bit_depths & (1 << bit)) != 0
    }
}

/// Audio format descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    /// Number of channels
    pub channels: u8,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bits per sample
    pub bits_per_sample: u8,
    /// Is floating point
    pub is_float: bool,
    /// Is signed
    pub is_signed: bool,
}

impl AudioFormat {
    /// Create a standard PCM format
    pub fn pcm(channels: u8, sample_rate: u32, bits_per_sample: u8) -> Self {
        Self {
            channels,
            sample_rate,
            bits_per_sample,
            is_float: false,
            is_signed: bits_per_sample > 8,
        }
    }

    /// Calculate bytes per sample
    pub fn bytes_per_sample(&self) -> usize {
        ((self.bits_per_sample + 7) / 8) as usize
    }

    /// Calculate bytes per frame (all channels)
    pub fn bytes_per_frame(&self) -> usize {
        self.bytes_per_sample() * self.channels as usize
    }

    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> usize {
        self.bytes_per_frame() * self.sample_rate as usize
    }

    /// Calculate duration in microseconds for given byte count
    pub fn bytes_to_us(&self, bytes: usize) -> u64 {
        let frames = bytes / self.bytes_per_frame();
        (frames as u64 * 1_000_000) / self.sample_rate as u64
    }

    /// Calculate byte count for given duration in microseconds
    pub fn us_to_bytes(&self, us: u64) -> usize {
        let frames = (us * self.sample_rate as u64) / 1_000_000;
        (frames as usize) * self.bytes_per_frame()
    }
}

/// Audio device descriptor
#[derive(Debug, Clone)]
pub struct AudioDevice {
    /// Device ID
    pub id: u32,
    /// Device name
    pub name: String,
    /// Device type
    pub device_type: AudioDeviceType,
    /// Capabilities
    pub capabilities: AudioCapabilities,
    /// Is default playback device
    pub is_default_output: bool,
    /// Is default capture device
    pub is_default_input: bool,
}

/// Audio stream direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Playback (output)
    Output,
    /// Capture (input)
    Input,
}

/// Audio stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is stopped
    Stopped,
    /// Stream is starting
    Starting,
    /// Stream is running
    Running,
    /// Stream is paused
    Paused,
    /// Stream is stopping
    Stopping,
    /// Stream has an error
    Error,
}

/// Audio buffer descriptor
#[derive(Debug, Clone)]
pub struct AudioBuffer {
    /// Buffer data pointer
    pub data: *mut u8,
    /// Buffer size in bytes
    pub size: usize,
    /// Number of valid bytes
    pub valid_bytes: usize,
    /// Buffer position (for circular buffers)
    pub position: usize,
    /// Is this buffer complete
    pub complete: bool,
}

impl AudioBuffer {
    /// Create a new audio buffer
    pub fn new(size: usize) -> Option<Self> {
        use crate::mm::pool::{self, PoolType};
        let data = pool::allocate_aligned(PoolType::NonPaged, size, 128);
        if data.is_null() {
            return None;
        }

        // Clear buffer
        unsafe {
            core::ptr::write_bytes(data, 0, size);
        }

        Some(Self {
            data,
            size,
            valid_bytes: 0,
            position: 0,
            complete: false,
        })
    }

    /// Get available space in buffer
    pub fn available(&self) -> usize {
        self.size - self.valid_bytes
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.valid_bytes >= self.size
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.valid_bytes == 0
    }

    /// Reset buffer
    pub fn reset(&mut self) {
        self.valid_bytes = 0;
        self.position = 0;
        self.complete = false;
    }
}

impl Drop for AudioBuffer {
    fn drop(&mut self) {
        if !self.data.is_null() {
            use crate::mm::pool;
            pool::free(self.data);
            self.data = core::ptr::null_mut();
        }
    }
}

/// Audio stream handle
pub struct AudioStream {
    /// Stream ID
    pub id: u32,
    /// Device ID
    pub device_id: u32,
    /// Stream direction
    pub direction: StreamDirection,
    /// Audio format
    pub format: AudioFormat,
    /// Current state
    pub state: StreamState,
    /// Buffer queue
    pub buffers: Vec<AudioBuffer>,
    /// Current buffer index
    pub current_buffer: usize,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Total frames processed
    pub frames_processed: u64,
    /// Stream position in microseconds
    pub position_us: u64,
}

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

impl AudioStream {
    /// Create a new audio stream
    pub fn new(device_id: u32, direction: StreamDirection, format: AudioFormat) -> Self {
        Self {
            id: NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed),
            device_id,
            direction,
            format,
            state: StreamState::Stopped,
            buffers: Vec::new(),
            current_buffer: 0,
            bytes_processed: 0,
            frames_processed: 0,
            position_us: 0,
        }
    }

    /// Add a buffer to the stream
    pub fn add_buffer(&mut self, buffer: AudioBuffer) {
        self.buffers.push(buffer);
    }

    /// Get next available buffer
    pub fn get_next_buffer(&mut self) -> Option<&mut AudioBuffer> {
        if self.buffers.is_empty() {
            return None;
        }

        let idx = self.current_buffer;
        self.current_buffer = (self.current_buffer + 1) % self.buffers.len();
        self.buffers.get_mut(idx)
    }

    /// Update stream position
    pub fn update_position(&mut self, bytes: usize) {
        self.bytes_processed += bytes as u64;
        let frames = bytes / self.format.bytes_per_frame();
        self.frames_processed += frames as u64;
        self.position_us = (self.frames_processed * 1_000_000) / self.format.sample_rate as u64;
    }

    /// Get stream position in microseconds
    pub fn get_position_us(&self) -> u64 {
        self.position_us
    }

    /// Get stream position in frames
    pub fn get_position_frames(&self) -> u64 {
        self.frames_processed
    }

    /// Reset stream position
    pub fn reset_position(&mut self) {
        self.bytes_processed = 0;
        self.frames_processed = 0;
        self.position_us = 0;
        self.current_buffer = 0;
        for buffer in &mut self.buffers {
            buffer.reset();
        }
    }
}

/// Volume control
#[derive(Debug, Clone, Copy)]
pub struct VolumeControl {
    /// Master volume (0-100)
    pub master: u8,
    /// Left channel volume (0-100)
    pub left: u8,
    /// Right channel volume (0-100)
    pub right: u8,
    /// Is muted
    pub muted: bool,
}

impl VolumeControl {
    /// Create a new volume control with default values
    pub fn new() -> Self {
        Self {
            master: 75,
            left: 75,
            right: 75,
            muted: false,
        }
    }

    /// Set master volume
    pub fn set_master(&mut self, volume: u8) {
        self.master = volume.min(100);
    }

    /// Set left channel volume
    pub fn set_left(&mut self, volume: u8) {
        self.left = volume.min(100);
    }

    /// Set right channel volume
    pub fn set_right(&mut self, volume: u8) {
        self.right = volume.min(100);
    }

    /// Set both channels to same volume
    pub fn set_both(&mut self, volume: u8) {
        self.left = volume.min(100);
        self.right = volume.min(100);
    }

    /// Get effective left volume (accounting for master and mute)
    pub fn effective_left(&self) -> u8 {
        if self.muted {
            0
        } else {
            ((self.master as u16 * self.left as u16) / 100) as u8
        }
    }

    /// Get effective right volume (accounting for master and mute)
    pub fn effective_right(&self) -> u8 {
        if self.muted {
            0
        } else {
            ((self.master as u16 * self.right as u16) / 100) as u8
        }
    }
}

impl Default for VolumeControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Audio device manager
pub struct AudioDeviceManager {
    devices: Vec<AudioDevice>,
    streams: Vec<AudioStream>,
    default_output_id: u32,
    default_input_id: u32,
    initialized: bool,
}

static mut AUDIO_MANAGER: Option<AudioDeviceManager> = None;
static AUDIO_MANAGER_INIT: AtomicBool = AtomicBool::new(false);

impl AudioDeviceManager {
    /// Create a new audio device manager
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            streams: Vec::new(),
            default_output_id: 0,
            default_input_id: 0,
            initialized: false,
        }
    }

    /// Get the global audio manager instance
    pub fn instance() -> &'static mut AudioDeviceManager {
        unsafe {
            if !AUDIO_MANAGER_INIT.load(Ordering::Acquire) {
                AUDIO_MANAGER = Some(AudioDeviceManager::new());
                AUDIO_MANAGER_INIT.store(true, Ordering::Release);
            }
            AUDIO_MANAGER.as_mut().unwrap()
        }
    }

    /// Initialize the audio manager
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }

        // Enumerate audio devices
        self.enumerate_devices();

        self.initialized = true;
    }

    /// Enumerate audio devices
    fn enumerate_devices(&mut self) {
        self.devices.clear();

        // Enumerate HD Audio devices
        let hda_count = super::intel_hda::count();
        for i in 0..hda_count {
            if let Some((name, _gcap, _streams, _codecs)) = super::intel_hda::get_info(i) {
                let device = AudioDevice {
                    id: (0x1000 + i as u32),
                    name: String::from(name),
                    device_type: AudioDeviceType::HdAudio,
                    capabilities: AudioCapabilities {
                        playback: true,
                        capture: true,
                        max_output_channels: 8,
                        max_input_channels: 2,
                        sample_rates: 0x07F0, // 8kHz-192kHz
                        bit_depths: 0x1E,     // 8/16/20/24/32-bit
                        hardware_mixing: true,
                        hardware_volume: true,
                    },
                    is_default_output: i == 0,
                    is_default_input: i == 0,
                };

                if i == 0 {
                    self.default_output_id = device.id;
                    self.default_input_id = device.id;
                }

                self.devices.push(device);
            }
        }

        // Enumerate AC'97 devices
        let ac97_count = super::ac97::count();
        for i in 0..ac97_count {
            let device = AudioDevice {
                id: (0x2000 + i as u32),
                name: String::from("AC'97 Audio"),
                device_type: AudioDeviceType::Ac97,
                capabilities: AudioCapabilities {
                    playback: true,
                    capture: true,
                    max_output_channels: 6,
                    max_input_channels: 2,
                    sample_rates: 0x0060, // 44.1kHz, 48kHz
                    bit_depths: 0x06,     // 16/20-bit
                    hardware_mixing: false,
                    hardware_volume: true,
                },
                is_default_output: self.devices.is_empty(),
                is_default_input: self.devices.is_empty(),
            };

            if self.devices.is_empty() {
                self.default_output_id = device.id;
                self.default_input_id = device.id;
            }

            self.devices.push(device);
        }
    }

    /// Get all audio devices
    pub fn get_devices(&self) -> &[AudioDevice] {
        &self.devices
    }

    /// Get device by ID
    pub fn get_device(&self, id: u32) -> Option<&AudioDevice> {
        self.devices.iter().find(|d| d.id == id)
    }

    /// Get default output device
    pub fn get_default_output(&self) -> Option<&AudioDevice> {
        self.get_device(self.default_output_id)
    }

    /// Get default input device
    pub fn get_default_input(&self) -> Option<&AudioDevice> {
        self.get_device(self.default_input_id)
    }

    /// Set default output device
    pub fn set_default_output(&mut self, id: u32) {
        if self.devices.iter().any(|d| d.id == id) {
            self.default_output_id = id;
        }
    }

    /// Set default input device
    pub fn set_default_input(&mut self, id: u32) {
        if self.devices.iter().any(|d| d.id == id) {
            self.default_input_id = id;
        }
    }

    /// Create an audio stream
    pub fn create_stream(&mut self, device_id: u32, direction: StreamDirection, format: AudioFormat) -> Option<u32> {
        // Verify device exists
        if self.get_device(device_id).is_none() {
            return None;
        }

        let stream = AudioStream::new(device_id, direction, format);
        let stream_id = stream.id;
        self.streams.push(stream);
        Some(stream_id)
    }

    /// Get stream by ID
    pub fn get_stream(&mut self, id: u32) -> Option<&mut AudioStream> {
        self.streams.iter_mut().find(|s| s.id == id)
    }

    /// Close stream
    pub fn close_stream(&mut self, id: u32) {
        self.streams.retain(|s| s.id != id);
    }
}

/// Initialize the audio core
pub fn init() {
    let manager = AudioDeviceManager::instance();
    manager.init();
}

/// Get number of audio devices
pub fn get_device_count() -> usize {
    AudioDeviceManager::instance().get_devices().len()
}

/// Get audio device by index
pub fn get_device_info(index: usize) -> Option<&'static AudioDevice> {
    AudioDeviceManager::instance().get_devices().get(index)
}
