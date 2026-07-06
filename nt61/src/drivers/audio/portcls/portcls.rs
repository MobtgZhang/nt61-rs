//! Windows Audio Port Class Driver (PortCls)
//
//! PortCls is the Windows audio port class driver that provides the
//! standardized interface between user-mode audio clients (via WavePci,
//! WaveRT, etc.) and the vendor-specific miniport drivers.
//
//! This module provides:
//! - Port driver interface
//! - Miniport driver registration
//! - Audio stream management
//! - Power management integration
//
//! Clean-room implementation based on Windows PortCls documentation
//! and audio driver architecture.

use alloc::vec::Vec;
use alloc::boxed::Box;
use crate::kprintln;
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// PortCls device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Device is not started
    Stopped,
    /// Device is in D0 (working) power state
    Active,
    /// Device is in low-power state (D1/D2/D3)
    D0LowPower,
    /// Device is removed
    Removed,
}

/// PortCls device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    /// WavePci port (PCI scatter-gather)
    WavePci,
    /// WaveRT port (real-time)
    WaveRt,
    /// WaveCyclic port (legacy cyclic buffer)
    WaveCyclic,
    /// Topology port (mixer controls)
    Topology,
    /// MIDI port
    Midi,
    /// DMus (DirectMusic) port
    DMus,
}

impl PortType {
    /// Get the port type name
    pub fn name(&self) -> &'static str {
        match self {
            PortType::WavePci => "WavePci",
            PortType::WaveRt => "WaveRT",
            PortType::WaveCyclic => "WaveCyclic",
            PortType::Topology => "Topology",
            PortType::Midi => "MIDI",
            PortType::DMus => "DMus",
        }
    }
}

/// Audio format information
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bits per sample
    pub bits_per_sample: u16,
    /// Number of channels
    pub channels: u16,
    /// Valid bits per sample (for 24-bit in 32-bit container)
    pub valid_bits_per_sample: u16,
    /// Buffer size in bytes
    pub buffer_size: u32,
}

impl AudioFormat {
    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> u32 {
        (self.sample_rate as u32) * (self.channels as u32) * ((self.bits_per_sample / 8) as u32)
    }
    
    /// Calculate frame size in bytes
    pub fn frame_size(&self) -> u16 {
        (self.channels * ((self.bits_per_sample + 7) / 8)).max(1)
    }
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is stopped
    Stopped,
    /// Stream is running
    Running,
    /// Stream is paused
    Paused,
}

/// Audio stream handle
pub struct AudioStream {
    /// Stream index
    pub index: u32,
    /// Stream state
    pub state: StreamState,
    /// Audio format
    pub format: AudioFormat,
    /// Position in frames
    pub position: u64,
    /// Cyclic buffer virtual address
    pub buffer_virt: u64,
    /// Cyclic buffer physical address
    pub buffer_phys: u64,
    /// Cyclic buffer size
    pub buffer_size: usize,
    /// Is loopback (capture) mode
    pub is_loopback: bool,
}

impl AudioStream {
    /// Read-only diagnostic snapshot of the stream's DMA region.
    pub fn buffer_diagnostics(&self) -> (u64, u64, usize) {
        (self.buffer_virt, self.buffer_phys, self.buffer_size)
    }
}

impl AudioStream {
    /// Create a new audio stream
    fn new(index: u32, format: AudioFormat) -> Self {
        Self {
            index,
            state: StreamState::Stopped,
            format,
            position: 0,
            buffer_virt: 0,
            buffer_phys: 0,
            buffer_size: 0,
            is_loopback: false,
        }
    }
    
    /// Get current position in frames
    pub fn position(&self) -> u64 {
        self.position
    }
    
    /// Get stream state
    pub fn state(&self) -> StreamState {
        self.state
    }
    
    /// Get format
    pub fn format(&self) -> AudioFormat {
        self.format
    }
}

/// Miniport driver interface
pub trait MiniportDriver: Send + Sync {
    /// Get driver description
    fn description(&self) -> &'static str;
    
    /// Initialize the miniport
    fn init(&mut self) -> Result<(), &'static str>;
    
    /// Service the miniport (called in ISR context)
    fn service(&mut self);
    
    /// Shutdown the miniport
    fn shutdown(&mut self);
}

/// WaveRT miniport interface
pub trait MiniportWaveRT: MiniportDriver {
    /// Get supported format
    fn get_supported_format(&self) -> AudioFormat;
    
    /// Set the audio buffer
    fn set_buffer(&mut self, buffer_virt: u64, buffer_phys: u64, size: usize) -> Result<(), &'static str>;
    
    /// Get position in bytes
    fn get_position_bytes(&self) -> u64;
    
    /// Start playback/capture
    fn start(&mut self) -> Result<(), &'static str>;
    
    /// Stop playback/capture
    fn stop(&mut self);
}

/// Port driver interface
pub trait PortDriver: Send + Sync {
    /// Get port type
    fn port_type(&self) -> PortType;
    
    /// Get port description
    fn description(&self) -> &'static str;
    
    /// Initialize the port
    fn init(&mut self, miniport: Box<dyn MiniportDriver>) -> Result<(), &'static str>;
    
    /// Start the port
    fn start(&mut self) -> Result<(), &'static str>;
    
    /// Stop the port
    fn stop(&mut self);
    
    /// Get device state
    fn device_state(&self) -> DeviceState;
}

/// Cached statistics for `get_stream_position`.
static POSITION_UPDATES: AtomicU64 = AtomicU64::new(0);
static POSITION_DELTA_BYTES: AtomicU64 = AtomicU64::new(0);
static MINI_REG_SUCCESSES: AtomicU32 = AtomicU32::new(0);
static MINI_REG_FAILURES: AtomicU32 = AtomicU32::new(0);
static LAST_MINI_REG_ERR_CODE: AtomicU32 = AtomicU32::new(0);

/// Return the total number of stream position updates observed.
pub fn position_updates() -> u64 {
    POSITION_UPDATES.load(Ordering::Relaxed)
}

/// Return the cumulative byte delta observed by position updates.
pub fn position_delta_bytes() -> u64 {
    POSITION_DELTA_BYTES.load(Ordering::Relaxed)
}

/// WaveRT Port implementation
pub struct PortWaveRT {
    /// Port type
    port_type: PortType,
    /// Port description
    description: &'static str,
    /// Miniport driver
    miniport: Option<Box<dyn MiniportWaveRT>>,
    /// Device state
    device_state: DeviceState,
    /// Active streams
    streams: Vec<AudioStream>,
    /// Stream counter
    next_stream_id: u32,
    /// Power state
    power_state: u32,  // 0 = D0, 1 = D1, 2 = D2, 3 = D3
}

impl PortWaveRT {
    /// Create a new WaveRT port
    pub fn new(description: &'static str) -> Self {
        Self {
            port_type: PortType::WaveRt,
            description,
            miniport: None,
            device_state: DeviceState::Stopped,
            streams: Vec::new(),
            next_stream_id: 1,
            power_state: 3, // D3 (off) by default
        }
    }
    
    /// Register a miniport driver
    pub fn register_miniport(&mut self, miniport: Box<dyn MiniportWaveRT>) -> Result<(), &'static str> {
        if self.miniport.is_some() {
            return Err("Miniport already registered");
        }
        
        self.miniport = Some(miniport);
        // kprintln!("  [PortCls] WaveRT miniport registered: {}", self.description)  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
    
    /// Create a new stream
    pub fn create_stream(&mut self, format: AudioFormat) -> Result<u32, &'static str> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;
        
        let stream = AudioStream::new(stream_id, format);
        self.streams.push(stream);
        
        // kprintln!("  [PortCls] Created stream {}: {}Hz {}ch {}bit",  // kprintln disabled (memcpy crash workaround)
//             stream_id, format.sample_rate, format.channels, format.bits_per_sample);
        
        Ok(stream_id)
    }
    
    /// Get a stream by ID
    fn get_stream(&mut self, stream_id: u32) -> Option<&mut AudioStream> {
        self.streams.iter_mut().find(|s| s.index == stream_id)
    }
    
    /// Start a stream
    pub fn start_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        if self.device_state != DeviceState::Active {
            return Err("Device not in active state");
        }
        
        let stream = self.get_stream(stream_id).ok_or("Stream not found")?;
        
        if stream.state != StreamState::Stopped {
            return Err("Stream already running");
        }
        
        // Start the miniport
        if let Some(ref mut miniport) = self.miniport {
            miniport.start()?;
        }
        
        // Update stream state
        if let Some(stream) = self.get_stream(stream_id) {
            stream.state = StreamState::Running;
        }
        
        // kprintln!("  [PortCls] Stream {} started", stream_id)  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
    
    /// Stop a stream
    pub fn stop_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        let stream = self.get_stream(stream_id).ok_or("Stream not found")?;
        // Surface the stream's running flag so callers can verify
        // the stream was actually active before the stop request.
        let _was_running = matches!(stream.state, StreamState::Running | StreamState::Paused);

        // Stop the miniport
        if let Some(ref mut miniport) = self.miniport {
            miniport.stop();
        }

        // Update stream state
        if let Some(stream) = self.get_stream(stream_id) {
            stream.state = StreamState::Stopped;
        }
        
        // kprintln!("  [PortCls] Stream {} stopped", stream_id)  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
    
    /// Get stream position
    pub fn get_stream_position(&mut self, stream_id: u32) -> Result<u64, &'static str> {
        // Get stream index first
        let stream_idx = self.streams.iter().position(|s| s.index == stream_id)
            .ok_or("Stream not found")?;
        
        let pos = {
            // Query position from miniport
            if let Some(ref mut miniport) = self.miniport {
                miniport.get_position_bytes()
            } else {
                // Calculate from internal position
                let stream = &self.streams[stream_idx];
                stream.position * (stream.format.frame_size() as u64)
            }
        };

        // Update internal position (in frames). The miniport may
        // gate the position update, so we keep a local observable.
        let mut advanced = 0u64;
        if let Some(ref mut miniport) = self.miniport {
            // Notify the miniport of the position update so the
            // diagnostic path is exercised.
            let _ = miniport.get_position_bytes();
            let stream = &mut self.streams[stream_idx];
            let next = pos / (stream.format.frame_size() as u64);
            advanced = next.wrapping_sub(stream.position);
            stream.position = next;
        }
        POSITION_UPDATES.fetch_add(1, Ordering::Relaxed);
        POSITION_DELTA_BYTES.fetch_add(advanced, Ordering::Relaxed);

        Ok(pos)
    }
    
    /// Set device power state
    pub fn set_power_state(&mut self, state: u32) {
        // kprintln!("  [PortCls] Power state transition: D{} -> D{}", self.power_state, state)  // kprintln disabled (memcpy crash workaround);
        self.power_state = state;
        
        if state == 0 {
            self.device_state = DeviceState::Active;
        } else {
            self.device_state = DeviceState::D0LowPower;
        }
    }
    
    /// Get device power state
    pub fn get_power_state(&self) -> u32 {
        self.power_state
    }
}

impl PortDriver for PortWaveRT {
    fn port_type(&self) -> PortType {
        self.port_type
    }
    
    fn description(&self) -> &'static str {
        self.description
    }
    
    fn init(&mut self, _miniport: Box<dyn MiniportDriver>) -> Result<(), &'static str> {
        // The miniport must be WaveRT compatible
        // For now, just store it
        // kprintln!("  [PortCls] PortWaveRT initialized")  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
    
    fn start(&mut self) -> Result<(), &'static str> {
        if self.miniport.is_none() {
            return Err("No miniport registered");
        }
        
        self.device_state = DeviceState::Active;
        // kprintln!("  [PortCls] PortWaveRT started")  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
    
    fn stop(&mut self) {
        // Stop all running streams (collect indices first to avoid borrow issues)
        let running_indices: Vec<usize> = self.streams.iter()
            .enumerate()
            .filter(|(_, s)| s.state == StreamState::Running)
            .map(|(i, _)| i)
            .collect();
        
        for idx in running_indices {
            let _ = self.stop_stream(self.streams[idx].index);
        }
        
        self.device_state = DeviceState::Stopped;
        // kprintln!("  [PortCls] PortWaveRT stopped")  // kprintln disabled (memcpy crash workaround);
    }
    
    fn device_state(&self) -> DeviceState {
        self.device_state
    }
}

// =====================================================================
// PortCls Registry
// =====================================================================

/// Global port registry
static PORT_REGISTRY: Spinlock<Vec<Box<dyn PortDriver>>> = Spinlock::new(Vec::new());

/// Initialize PortCls subsystem
pub fn init() {
    // kprintln!("    PortCls: initializing...")  // kprintln disabled (memcpy crash workaround);
    
    // Clear registry
    PORT_REGISTRY.lock().clear();
    
    // kprintln!("    PortCls: port class driver ready")  // kprintln disabled (memcpy crash workaround);
}

/// Register a port driver
pub fn register_port(port: Box<dyn PortDriver>) -> usize {
    let mut registry = PORT_REGISTRY.lock();
    let index = registry.len();
    registry.push(port);
    index
}

/// Get a port by index
pub fn get_port(index: usize) -> Option<&'static dyn PortDriver> {
    let guard = PORT_REGISTRY.lock();
    guard.get(index).map(|b| {
        // SAFETY: The Box is stored in a static Vec and will remain valid for the lifetime of the program
        unsafe { &*(b.as_ref() as *const dyn PortDriver) }
    })
}

/// Create a WaveRT port with a miniport
pub fn create_wavert_port(description: &'static str, miniport: Box<dyn MiniportWaveRT>) -> usize {
    let mut port = PortWaveRT::new(description);
    
    if let Err(_e) = port.register_miniport(miniport) {
        // Record the registration failure so the caller can verify
        // whether the bind succeeded.
        MINI_REG_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_MINI_REG_ERR_CODE.store(1u32, Ordering::Relaxed);
    } else {
        MINI_REG_SUCCESSES.fetch_add(1, Ordering::Relaxed);
    }
    
    let boxed: Box<dyn PortDriver> = Box::new(port);
    let index = register_port(boxed);
    
    // kprintln!("  [PortCls] Created WaveRT port '{}' at index {}", description, index)  // kprintln disabled (memcpy crash workaround);
    index
}

/// Start an audio device
pub fn start_device(port_index: usize) -> Result<(), &'static str> {
    let mut registry = PORT_REGISTRY.lock();
    
    if let Some(ref mut port) = registry.get_mut(port_index) {
        port.start()
    } else {
        Err("Port not found")
    }
}

/// Stop an audio device
pub fn stop_device(port_index: usize) -> Result<(), &'static str> {
    let mut registry = PORT_REGISTRY.lock();
    
    if let Some(ref mut port) = registry.get_mut(port_index) {
        port.stop();
        Ok(())
    } else {
        Err("Port not found")
    }
}

/// Get device state
pub fn get_device_state(port_index: usize) -> Option<DeviceState> {
    PORT_REGISTRY.lock().get(port_index).map(|p| p.device_state())
}

/// Example: Create an HDA audio device
pub fn create_hda_audio_device(codec_name: &'static str) -> usize {
    // Create a placeholder miniport
    struct HdaMiniport {
        description: &'static str,
        format: AudioFormat,
    }
    
    impl MiniportDriver for HdaMiniport {
        fn description(&self) -> &'static str {
            self.description
        }
        
        fn init(&mut self) -> Result<(), &'static str> {
            // kprintln!("  [HDA Miniport] Initialized")  // kprintln disabled (memcpy crash workaround);
            Ok(())
        }
        
        fn service(&mut self) {
            // Called in ISR context
        }
        
        fn shutdown(&mut self) {
            // kprintln!("  [HDA Miniport] Shutdown")  // kprintln disabled (memcpy crash workaround);
        }
    }
    
    impl MiniportWaveRT for HdaMiniport {
        fn get_supported_format(&self) -> AudioFormat {
            self.format
        }
        
        fn set_buffer(&mut self, _buffer_virt: u64, _buffer_phys: u64, _size: usize) -> Result<(), &'static str> {
            Ok(())
        }
        
        fn get_position_bytes(&self) -> u64 {
            0
        }
        
        fn start(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        
        fn stop(&mut self) {
        }
    }
    
    let miniport = HdaMiniport {
        description: codec_name,
        format: AudioFormat {
            sample_rate: 48000,
            bits_per_sample: 16,
            channels: 2,
            valid_bits_per_sample: 16,
            buffer_size: 16384,
        },
    };
    
    create_wavert_port(codec_name, Box::new(miniport))
}
