//! Windows Multimedia Wave Audio API (waveOut/waveIn/mixer)
//!
//! This module implements the Windows wave audio APIs:
//! - waveOut* - Audio playback functions
//! - waveIn* - Audio capture functions
//! - mixer* - Mixer control functions
//!
//! These APIs are used by legacy Windows applications for audio I/O.

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

use crate::drivers::audio::{
    AudioDeviceManager, AudioFormat as CoreAudioFormat, StreamDirection,
    StreamState, AudioBuffer, VolumeControl,
};

/// Wave format tags
pub const WAVE_FORMAT_PCM: u16 = 0x0001;
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 0x0003;
pub const WAVE_FORMAT_ALAW: u16 = 0x0006;
pub const WAVE_FORMAT_MULAW: u16 = 0x0007;
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;

/// Wave error codes
pub const MMSYSERR_NOERROR: u32 = 0;
pub const MMSYSERR_ERROR: u32 = 1;
pub const MMSYSERR_BADDEVICEID: u32 = 2;
pub const MMSYSERR_NOTENABLED: u32 = 3;
pub const MMSYSERR_ALLOCATED: u32 = 4;
pub const MMSYSERR_INVALHANDLE: u32 = 5;
pub const MMSYSERR_NODRIVER: u32 = 6;
pub const MMSYSERR_NOMEM: u32 = 7;
pub const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub const MMSYSERR_BADERRNUM: u32 = 9;
pub const MMSYSERR_INVALFLAG: u32 = 10;
pub const MMSYSERR_INVALPARAM: u32 = 11;
pub const MMSYSERR_HANDLEBUSY: u32 = 12;
pub const MMSYSERR_INVALIDALIAS: u32 = 13;
pub const MMSYSERR_BADDB: u32 = 14;
pub const MMSYSERR_KEYNOTFOUND: u32 = 15;
pub const MMSYSERR_READERROR: u32 = 16;
pub const MMSYSERR_WRITEERROR: u32 = 17;
pub const MMSYSERR_DELETEERROR: u32 = 18;
pub const MMSYSERR_VALNOTFOUND: u32 = 19;
pub const MMSYSERR_NODRIVERCB: u32 = 20;
pub const WAVERR_BADFORMAT: u32 = 32;
pub const WAVERR_STILLPLAYING: u32 = 33;
pub const WAVERR_UNPREPARED: u32 = 34;
pub const WAVERR_SYNC: u32 = 35;

/// Wave open flags
pub const WAVE_FORMAT_QUERY: u32 = 0x0001;
pub const WAVE_ALLOWSYNC: u32 = 0x0002;
pub const WAVE_MAPPED: u32 = 0x0004;
pub const WAVE_FORMAT_DIRECT: u32 = 0x0008;

/// Wave header flags

pub const WHDR_DONE: u32 = 0x00000001;
pub const WHDR_PREPARED: u32 = 0x00000002;
pub const WHDR_BEGINLOOP: u32 = 0x00000004;
pub const WHDR_ENDLOOP: u32 = 0x00000008;
pub const WHDR_INQUEUE: u32 = 0x00000010;

/// WAVEFORMATEX structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WaveFormatEx {
    /// Format tag (WAVE_FORMAT_PCM, etc.)
    pub format_tag: u16,
    /// Number of channels
    pub channels: u16,
    /// Sample rate
    pub samples_per_sec: u32,
    /// Average bytes per second
    pub avg_bytes_per_sec: u32,
    /// Block alignment
    pub block_align: u16,
    /// Bits per sample
    pub bits_per_sample: u16,
    /// Size of extra format information
    pub cb_size: u16,
}

impl WaveFormatEx {
    /// Create a PCM format
    pub fn pcm(channels: u16, sample_rate: u32, bits_per_sample: u16) -> Self {
        let block_align = (channels * bits_per_sample) / 8;
        let avg_bytes_per_sec = sample_rate * block_align as u32;

        Self {
            format_tag: WAVE_FORMAT_PCM,
            channels,
            samples_per_sec: sample_rate,
            avg_bytes_per_sec,
            block_align,
            bits_per_sample,
            cb_size: 0,
        }
    }

    /// Convert to core audio format
    pub fn to_core_format(&self) -> CoreAudioFormat {
        CoreAudioFormat {
            channels: self.channels as u8,
            sample_rate: self.samples_per_sec,
            bits_per_sample: self.bits_per_sample as u8,
            is_float: self.format_tag == WAVE_FORMAT_IEEE_FLOAT,
            is_signed: self.bits_per_sample > 8,
        }
    }

    /// Validate format
    pub fn is_valid(&self) -> bool {
        self.channels > 0 && self.channels <= 8 &&
        self.samples_per_sec >= 8000 && self.samples_per_sec <= 192000 &&
        (self.bits_per_sample == 8 || self.bits_per_sample == 16 ||
         self.bits_per_sample == 20 || self.bits_per_sample == 24 ||
         self.bits_per_sample == 32)
    }
}

/// WAVEHDR structure
#[repr(C)]
pub struct WaveHdr {
    /// Pointer to wave data
    pub data: *mut u8,
    /// Length of data in bytes
    pub buffer_length: u32,
    /// Bytes actually recorded/played
    pub bytes_recorded: u32,
    /// User data
    pub user_data: usize,
    /// Flags (WHDR_*)
    pub flags: u32,
    /// Number of times to loop
    pub loops: u32,
    /// Reserved for driver
    pub next: *mut WaveHdr,
    /// Reserved for driver
    pub reserved: usize,
}

impl WaveHdr {
    /// Create a new wave header
    pub fn new(data: *mut u8, length: u32) -> Self {
        Self {
            data,
            buffer_length: length,
            bytes_recorded: 0,
            user_data: 0,
            flags: 0,
            loops: 0,
            next: core::ptr::null_mut(),
            reserved: 0,
        }
    }

    /// Check if buffer is done
    pub fn is_done(&self) -> bool {
        (self.flags & WHDR_DONE) != 0
    }

    /// Check if buffer is prepared
    pub fn is_prepared(&self) -> bool {
        (self.flags & WHDR_PREPARED) != 0
    }

    /// Check if buffer is in queue
    pub fn is_in_queue(&self) -> bool {
        (self.flags & WHDR_INQUEUE) != 0
    }
}

/// WAVEOUTCAPS structure
#[repr(C)]
pub struct WaveOutCaps {
    /// Manufacturer ID
    pub manufacturer_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Driver version
    pub driver_version: u32,
    /// Product name (32 chars)
    pub product_name: [u8; 32],
    /// Supported formats
    pub formats: u32,
    /// Number of channels
    pub channels: u16,
    /// Reserved
    pub reserved: u16,
    /// Support flags
    pub support: u32,
}

impl WaveOutCaps {
    /// Create capabilities for a device
    pub fn new(name: &str, channels: u16, formats: u32) -> Self {
        let mut product_name = [0u8; 32];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(31);
        product_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        Self {
            manufacturer_id: 0x0001,
            product_id: 0x0001,
            driver_version: 0x0100,
            product_name,
            formats,
            channels,
            reserved: 0,
            support: 0x0001, // WAVECAPS_VOLUME
        }
    }
}

/// WAVEINCAPS structure
#[repr(C)]
pub struct WaveInCaps {
    /// Manufacturer ID
    pub manufacturer_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Driver version
    pub driver_version: u32,
    /// Product name (32 chars)
    pub product_name: [u8; 32],
    /// Supported formats
    pub formats: u32,
    /// Number of channels
    pub channels: u16,
    /// Reserved
    pub reserved: u16,
}

impl WaveInCaps {
    /// Create capabilities for a device
    pub fn new(name: &str, channels: u16, formats: u32) -> Self {
        let mut product_name = [0u8; 32];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(31);
        product_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        Self {
            manufacturer_id: 0x0001,
            product_id: 0x0001,
            driver_version: 0x0100,
            product_name,
            formats,
            channels,
            reserved: 0,
        }
    }
}

/// Wave output device handle
pub struct WaveOutHandle {
    /// Handle ID
    pub id: u32,
    /// Device ID
    pub device_id: u32,
    /// Stream ID
    pub stream_id: u32,
    /// Format
    pub format: WaveFormatEx,
    /// Is playing
    pub playing: bool,
    /// Is paused
    pub paused: bool,
    /// Pending buffers
    pub pending_buffers: Vec<*mut WaveHdr>,
    /// Volume control
    pub volume: VolumeControl,
}

/// Wave input device handle
pub struct WaveInHandle {
    /// Handle ID
    pub id: u32,
    /// Device ID
    pub device_id: u32,
    /// Stream ID
    pub stream_id: u32,
    /// Format
    pub format: WaveFormatEx,
    /// Is recording
    pub recording: bool,
    /// Pending buffers
    pub pending_buffers: Vec<*mut WaveHdr>,
}

/// Wave device manager
pub struct WaveDeviceManager {
    /// Output handles
    out_handles: Vec<WaveOutHandle>,
    /// Input handles
    in_handles: Vec<WaveInHandle>,
    /// Next handle ID
    next_handle_id: u32,
    /// Initialized flag
    initialized: bool,
}

static mut WAVE_MANAGER: Option<WaveDeviceManager> = None;
static WAVE_MANAGER_INIT: AtomicBool = AtomicBool::new(false);

impl WaveDeviceManager {
    /// Create a new wave device manager
    fn new() -> Self {
        Self {
            out_handles: Vec::new(),
            in_handles: Vec::new(),
            next_handle_id: 1,
            initialized: false,
        }
    }

    /// Get the global wave manager instance
    pub fn instance() -> &'static mut WaveDeviceManager {
        unsafe {
            if !WAVE_MANAGER_INIT.load(Ordering::Acquire) {
                WAVE_MANAGER = Some(WaveDeviceManager::new());
                WAVE_MANAGER_INIT.store(true, Ordering::Release);
            }
            WAVE_MANAGER.as_mut().unwrap()
        }
    }

    /// Initialize the wave manager
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Allocate a new handle ID
    fn alloc_handle_id(&mut self) -> u32 {
        let id = self.next_handle_id;
        self.next_handle_id = self.next_handle_id.wrapping_add(1);
        id
    }

    /// Get output handle
    pub fn get_out_handle(&mut self, handle: u32) -> Option<&mut WaveOutHandle> {
        self.out_handles.iter_mut().find(|h| h.id == handle)
    }

    /// Get input handle
    pub fn get_in_handle(&mut self, handle: u32) -> Option<&mut WaveInHandle> {
        self.in_handles.iter_mut().find(|h| h.id == handle)
    }

    /// Remove output handle
    pub fn remove_out_handle(&mut self, handle: u32) {
        self.out_handles.retain(|h| h.id != handle);
    }

    /// Remove input handle
    pub fn remove_in_handle(&mut self, handle: u32) {
        self.in_handles.retain(|h| h.id != handle);
    }
}

/// Get number of wave output devices
pub fn wave_out_get_num_devs() -> u32 {
    let manager = AudioDeviceManager::instance();
    let devices = manager.get_devices();
    devices.iter().filter(|d| d.capabilities.playback).count() as u32
}

/// Get wave output device capabilities
pub fn wave_out_get_dev_caps(device_id: u32, caps: &mut WaveOutCaps) -> u32 {
    let manager = AudioDeviceManager::instance();
    let devices = manager.get_devices();

    let playback_devices: Vec<_> = devices.iter().filter(|d| d.capabilities.playback).collect();

    if (device_id as usize) >= playback_devices.len() {
        return MMSYSERR_BADDEVICEID;
    }

    let device = playback_devices[device_id as usize];
    *caps = WaveOutCaps::new(
        &device.name,
        device.capabilities.max_output_channels as u16,
        device.capabilities.sample_rates,
    );

    MMSYSERR_NOERROR
}

/// Open wave output device
pub fn wave_out_open(
    device_id: u32,
    format: &WaveFormatEx,
    callback: usize,
    instance: usize,
    flags: u32,
) -> Result<u32, u32> {
    // Validate format
    if !format.is_valid() {
        return Err(WAVERR_BADFORMAT);
    }

    // Query mode - just validate without opening
    if (flags & WAVE_FORMAT_QUERY) != 0 {
        return Ok(0);
    }

    let manager = AudioDeviceManager::instance();

    // Get device ID first (without holding a borrow)
    let device_id_actual = {
        let devices = manager.get_devices();
        let playback_devices: Vec<_> = devices.iter().filter(|d| d.capabilities.playback).collect();

        if (device_id as usize) >= playback_devices.len() {
            return Err(MMSYSERR_BADDEVICEID);
        }

        playback_devices[device_id as usize].id
    };

    // Create audio stream
    let core_format = format.to_core_format();
    let stream_id = manager.create_stream(device_id_actual, StreamDirection::Output, core_format)
        .ok_or(MMSYSERR_NOMEM)?;

    // Create wave handle
    let wave_manager = WaveDeviceManager::instance();
    let handle_id = wave_manager.alloc_handle_id();

    let handle = WaveOutHandle {
        id: handle_id,
        device_id: device_id_actual,
        stream_id,
        format: *format,
        playing: false,
        paused: false,
        pending_buffers: Vec::new(),
        volume: VolumeControl::new(),
    };

    wave_manager.out_handles.push(handle);

    Ok(handle_id)
}

/// Close wave output device
pub fn wave_out_close(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();

    if let Some(out_handle) = wave_manager.get_out_handle(handle) {
        // Stop playback if still playing
        if out_handle.playing {
            let _ = wave_out_reset(handle);
        }

        // Close the stream
        let audio_manager = AudioDeviceManager::instance();
        audio_manager.close_stream(out_handle.stream_id);

        // Remove handle
        wave_manager.remove_out_handle(handle);

        MMSYSERR_NOERROR
    } else {
        MMSYSERR_INVALHANDLE
    }
}

/// Prepare wave header
pub fn wave_out_prepare_header(handle: u32, header: *mut WaveHdr) -> u32 {
    if header.is_null() {
        return MMSYSERR_INVALPARAM;
    }

    let wave_manager = WaveDeviceManager::instance();
    if wave_manager.get_out_handle(handle).is_none() {
        return MMSYSERR_INVALHANDLE;
    }

    unsafe {
        (*header).flags |= WHDR_PREPARED;
        (*header).flags &= !WHDR_DONE;
    }

    MMSYSERR_NOERROR
}

/// Unprepare wave header
pub fn wave_out_unprepare_header(handle: u32, header: *mut WaveHdr) -> u32 {
    if header.is_null() {
        return MMSYSERR_INVALPARAM;
    }

    let wave_manager = WaveDeviceManager::instance();
    if wave_manager.get_out_handle(handle).is_none() {
        return MMSYSERR_INVALHANDLE;
    }

    unsafe {
        if ((*header).flags & WHDR_INQUEUE) != 0 {
            return WAVERR_STILLPLAYING;
        }
        (*header).flags &= !WHDR_PREPARED;
    }

    MMSYSERR_NOERROR
}

/// Write data to wave output device
pub fn wave_out_write(handle: u32, header: *mut WaveHdr) -> u32 {
    if header.is_null() {
        return MMSYSERR_INVALPARAM;
    }

    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    unsafe {
        if ((*header).flags & WHDR_PREPARED) == 0 {
            return WAVERR_UNPREPARED;
        }

        // Mark as in queue
        (*header).flags |= WHDR_INQUEUE;
        (*header).flags &= !WHDR_DONE;

        // Add to pending buffers
        out_handle.pending_buffers.push(header);

        // Start playback if not already playing
        if !out_handle.playing {
            out_handle.playing = true;

            // Start the underlying AC'97/HDA stream
            crate::drivers::audio::start_playback();
        }

        // Write data to audio driver
        let data_slice = core::slice::from_raw_parts(
            (*header).data,
            (*header).buffer_length as usize,
        );

        // Convert to i16 samples for AC'97
        if out_handle.format.bits_per_sample == 16 {
            let samples = core::slice::from_raw_parts(
                (*header).data as *const i16,
                (*header).buffer_length as usize / 2,
            );
            let written = crate::drivers::audio::write_pcm_samples(
                samples,
                out_handle.format.channels as u8,
            );
            (*header).bytes_recorded = (written * 2) as u32;
        }

        // Mark as done (in a real implementation, this would be done by interrupt)
        (*header).flags &= !WHDR_INQUEUE;
        (*header).flags |= WHDR_DONE;
    }

    MMSYSERR_NOERROR
}

/// Start wave output playback
pub fn wave_out_restart(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    if out_handle.paused {
        out_handle.paused = false;
        out_handle.playing = true;
        crate::drivers::audio::start_playback();
    }

    MMSYSERR_NOERROR
}

/// Pause wave output playback
pub fn wave_out_pause(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    if out_handle.playing && !out_handle.paused {
        out_handle.paused = true;
        crate::drivers::audio::stop_playback();
    }

    MMSYSERR_NOERROR
}

/// Reset wave output device
pub fn wave_out_reset(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    // Stop playback
    if out_handle.playing {
        out_handle.playing = false;
        crate::drivers::audio::stop_playback();
    }

    // Mark all pending buffers as done
    unsafe {
        for header_ptr in &out_handle.pending_buffers {
            if !header_ptr.is_null() {
                (**header_ptr).flags &= !WHDR_INQUEUE;
                (**header_ptr).flags |= WHDR_DONE;
            }
        }
    }
    out_handle.pending_buffers.clear();

    MMSYSERR_NOERROR
}

/// Get wave output position
pub fn wave_out_get_position(handle: u32, time: &mut u32, time_type: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    // Get position from audio driver
    let position = crate::drivers::audio::get_playback_position();
    *time = position;

    MMSYSERR_NOERROR
}

/// Set wave output volume
pub fn wave_out_set_volume(handle: u32, volume: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    // Volume is 16-bit left + 16-bit right
    let left = ((volume & 0xFFFF) * 100 / 0xFFFF) as u8;
    let right = (((volume >> 16) & 0xFFFF) * 100 / 0xFFFF) as u8;

    out_handle.volume.set_left(left);
    out_handle.volume.set_right(right);

    // Apply to hardware
    crate::drivers::audio::set_master_volume((left + right) / 2);

    MMSYSERR_NOERROR
}

/// Get wave output volume
pub fn wave_out_get_volume(handle: u32, volume: &mut u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let out_handle = match wave_manager.get_out_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    let left = (out_handle.volume.left as u32 * 0xFFFF) / 100;
    let right = (out_handle.volume.right as u32 * 0xFFFF) / 100;
    *volume = (right << 16) | left;

    MMSYSERR_NOERROR
}

/// Get number of wave input devices
pub fn wave_in_get_num_devs() -> u32 {
    let manager = AudioDeviceManager::instance();
    let devices = manager.get_devices();
    devices.iter().filter(|d| d.capabilities.capture).count() as u32
}

/// Get wave input device capabilities
pub fn wave_in_get_dev_caps(device_id: u32, caps: &mut WaveInCaps) -> u32 {
    let manager = AudioDeviceManager::instance();
    let devices = manager.get_devices();

    let capture_devices: Vec<_> = devices.iter().filter(|d| d.capabilities.capture).collect();

    if (device_id as usize) >= capture_devices.len() {
        return MMSYSERR_BADDEVICEID;
    }

    let device = capture_devices[device_id as usize];
    *caps = WaveInCaps::new(
        &device.name,
        device.capabilities.max_input_channels as u16,
        device.capabilities.sample_rates,
    );

    MMSYSERR_NOERROR
}

/// Open wave input device
pub fn wave_in_open(
    device_id: u32,
    format: &WaveFormatEx,
    callback: usize,
    instance: usize,
    flags: u32,
) -> Result<u32, u32> {
    // Validate format
    if !format.is_valid() {
        return Err(WAVERR_BADFORMAT);
    }

    // Query mode - just validate without opening
    if (flags & WAVE_FORMAT_QUERY) != 0 {
        return Ok(0);
    }

    let manager = AudioDeviceManager::instance();

    // Get device ID first (without holding a borrow)
    let device_id_actual = {
        let devices = manager.get_devices();
        let capture_devices: Vec<_> = devices.iter().filter(|d| d.capabilities.capture).collect();

        if (device_id as usize) >= capture_devices.len() {
            return Err(MMSYSERR_BADDEVICEID);
        }

        capture_devices[device_id as usize].id
    };

    // Create audio stream
    let core_format = format.to_core_format();
    let stream_id = manager.create_stream(device_id_actual, StreamDirection::Input, core_format)
        .ok_or(MMSYSERR_NOMEM)?;

    // Create wave handle
    let wave_manager = WaveDeviceManager::instance();
    let handle_id = wave_manager.alloc_handle_id();

    let handle = WaveInHandle {
        id: handle_id,
        device_id: device_id_actual,
        stream_id,
        format: *format,
        recording: false,
        pending_buffers: Vec::new(),
    };

    wave_manager.in_handles.push(handle);

    Ok(handle_id)
}

/// Close wave input device
pub fn wave_in_close(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();

    if let Some(in_handle) = wave_manager.get_in_handle(handle) {
        // Stop recording if still active
        if in_handle.recording {
            let _ = wave_in_reset(handle);
        }

        // Close the stream
        let audio_manager = AudioDeviceManager::instance();
        audio_manager.close_stream(in_handle.stream_id);

        // Remove handle
        wave_manager.remove_in_handle(handle);

        MMSYSERR_NOERROR
    } else {
        MMSYSERR_INVALHANDLE
    }
}

/// Start wave input recording
pub fn wave_in_start(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let in_handle = match wave_manager.get_in_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    if !in_handle.recording {
        in_handle.recording = true;
        // Start capture in hardware
    }

    MMSYSERR_NOERROR
}

/// Stop wave input recording
pub fn wave_in_stop(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let in_handle = match wave_manager.get_in_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    if in_handle.recording {
        in_handle.recording = false;
        // Stop capture in hardware
    }

    MMSYSERR_NOERROR
}

/// Reset wave input device
pub fn wave_in_reset(handle: u32) -> u32 {
    let wave_manager = WaveDeviceManager::instance();
    let in_handle = match wave_manager.get_in_handle(handle) {
        Some(h) => h,
        None => return MMSYSERR_INVALHANDLE,
    };

    // Stop recording
    if in_handle.recording {
        in_handle.recording = false;
    }

    // Mark all pending buffers as done
    unsafe {
        for header_ptr in &in_handle.pending_buffers {
            if !header_ptr.is_null() {
                (**header_ptr).flags &= !WHDR_INQUEUE;
                (**header_ptr).flags |= WHDR_DONE;
            }
        }
    }
    in_handle.pending_buffers.clear();

    MMSYSERR_NOERROR
}

/// Initialize the wave API
pub fn init() {
    let manager = WaveDeviceManager::instance();
    manager.init();
}
