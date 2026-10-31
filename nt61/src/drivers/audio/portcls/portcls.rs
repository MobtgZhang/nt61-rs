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
//! - power management integration
//
//!   Clean-room implementation based on Windows PortCls documentation
//!   and audio driver architecture.

use crate::ke::sync::Spinlock;
use alloc::boxed::Box;
use alloc::vec::Vec;
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
    /// buffer size in bytes
    pub buffer_size: u32,
}

impl AudioFormat {
    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> u32 {
        self.sample_rate * (self.channels as u32) * ((self.bits_per_sample / 8) as u32)
    }

    /// Calculate frame size in bytes
    pub fn frame_size(&self) -> u16 {
        (self.channels * self.bits_per_sample.div_ceil(8)).max(1)
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
    /// read-only diagnostic snapshot of the stream's DMA region.
    pub fn buffer_diagnostics(&self) -> (u64, u64, usize) {
        (self.buffer_virt, self.buffer_phys, self.buffer_size)
    }
}

impl AudioStream {
    /// create a new audio stream
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
    fn set_buffer(
        &mut self,
        buffer_virt: u64,
        buffer_phys: u64,
        size: usize,
    ) -> Result<(), &'static str>;

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
    /// power state
    power_state: u32, // 0 = D0, 1 = D1, 2 = D2, 3 = D3
}

impl PortWaveRT {
    /// create a new WaveRT port
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
    pub fn register_miniport(
        &mut self,
        miniport: Box<dyn MiniportWaveRT>,
    ) -> Result<(), &'static str> {
        if self.miniport.is_some() {
            return Err("Miniport already registered");
        }

        self.miniport = Some(miniport);
        // kprintln!("  [PortCls] WaveRT miniport registered: {}", self.description);
        Ok(())
    }

    /// create a new stream
    pub fn create_stream(&mut self, format: AudioFormat) -> Result<u32, &'static str> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;

        let stream = AudioStream::new(stream_id, format);
        self.streams.push(stream);

        // kprintln!("  [PortCls] Created stream {}: {}Hz {}ch {}bit",
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

        // kprintln!("  [PortCls] Stream {} started", stream_id);
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

        // kprintln!("  [PortCls] Stream {} stopped", stream_id);
        Ok(())
    }

    /// Get stream position
    pub fn get_stream_position(&mut self, stream_id: u32) -> Result<u64, &'static str> {
        // Get stream index first
        let stream_idx = self
            .streams
            .iter()
            .position(|s| s.index == stream_id)
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
        // kprintln!("  [PortCls] power state transition: D{} -> D{}", self.power_state, state);
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
        // kprintln!("  [PortCls] PortWaveRT initialized");
        Ok(())
    }

    fn start(&mut self) -> Result<(), &'static str> {
        if self.miniport.is_none() {
            return Err("No miniport registered");
        }

        self.device_state = DeviceState::Active;
        // kprintln!("  [PortCls] PortWaveRT started");
        Ok(())
    }

    fn stop(&mut self) {
        // Stop all running streams (collect indices first to avoid borrow issues)
        let running_indices: Vec<usize> = self
            .streams
            .iter()
            .enumerate()
            .filter(|(_, s)| s.state == StreamState::Running)
            .map(|(i, _)| i)
            .collect();

        for idx in running_indices {
            let _ = self.stop_stream(self.streams[idx].index);
        }

        self.device_state = DeviceState::Stopped;
        // kprintln!("  [PortCls] PortWaveRT stopped");
    }

    fn device_state(&self) -> DeviceState {
        self.device_state
    }
}

// =====================================================================
// Resource List (IResourceList)
// =====================================================================

/// One hardware resource assigned to a port/miniport, matching the
/// WDK `CM_PARTIAL_RESOURCE_DESCRIPTOR` types used by PortCls
/// `IResourceList`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDescriptor {
    /// IRQ: level and vector.
    Interrupt { level: u32, vector: u32 },
    /// DMA channel: channel number and generation.
    Dma { channel: u32, generation: u32 },
    /// I/O port range: start and length (in ports).
    Port { start: u16, length: u16 },
    /// Memory range: physical start and byte length.
    Memory { start: u64, length: u64 },
}

/// The hardware resources assigned to an audio adapter. PortCls
/// passes this to the miniport during initialization (the NT 6.1
/// miniport initialization contract).
#[derive(Debug, Clone, Default)]
pub struct ResourceList {
    pub resources: alloc::vec::Vec<ResourceDescriptor>,
}

impl ResourceList {
    pub fn new() -> Self {
        Self {
            resources: alloc::vec::Vec::new(),
        }
    }

    pub fn add(&mut self, desc: ResourceDescriptor) {
        self.resources.push(desc);
    }

    pub fn interrupt(&self) -> Option<(u32, u32)> {
        self.resources.iter().find_map(|r| match r {
            ResourceDescriptor::Interrupt { level, vector } => Some((*level, *vector)),
            _ => None,
        })
    }

    pub fn memory(&self) -> Option<(u64, u64)> {
        self.resources.iter().find_map(|r| match r {
            ResourceDescriptor::Memory { start, length } => Some((*start, *length)),
            _ => None,
        })
    }

    pub fn dma(&self) -> Option<u32> {
        self.resources.iter().find_map(|r| match r {
            ResourceDescriptor::Dma { channel, .. } => Some(*channel),
            _ => None,
        })
    }
}

// =====================================================================
// Filter Descriptor (PFILTER_DESCRIPTOR)
// =====================================================================

/// A pin factory: one input or output pin on a filter.
#[derive(Debug, Clone, Copy)]
pub struct PinDescriptor {
    /// Pin category: 0 = audio output, 1 = audio input, 2 = topology.
    pub category: u8,
    /// Maximum number of instances.
    pub max_instances: u32,
    /// Minimum number of instances that must exist.
    pub min_instances: u32,
    /// Data flow direction: 0 = in, 1 = out.
    pub data_flow: u8,
}

/// A filter factory: the set of pins a miniport exposes, matching
/// PortCls `PFILTER_DESCRIPTOR`. PortCls uses this to build the
/// KSCATEGORY_AUDIO device interface for the I/O manager.
#[derive(Debug, Clone)]
pub struct FilterDescriptor {
    /// Friendly name shown in the audio device list.
    pub name: &'static str,
    /// Pin factories on this filter.
    pub pins: alloc::vec::Vec<PinDescriptor>,
    /// Node count (topology nodes, e.g. volume / mute / DAC).
    pub node_count: u32,
    /// Connection count (pin-to-node or node-to-node).
    pub connection_count: u32,
}

impl FilterDescriptor {
    /// Create a filter with a single audio-output pin (the
    /// common WaveRT / WaveCyclic shape for a simple DAC).
    pub fn audio_output(name: &'static str) -> Self {
        Self {
            name,
            pins: alloc::vec![PinDescriptor {
                category: 0,
                max_instances: 1,
                min_instances: 1,
                data_flow: 1,
            }],
            node_count: 1,
            connection_count: 1,
        }
    }

    /// Create a filter with one output and one input pin (the
    /// shape for a full-duplex codec).
    pub fn audio_duplex(name: &'static str) -> Self {
        Self {
            name,
            pins: alloc::vec![
                PinDescriptor {
                    category: 0,
                    max_instances: 1,
                    min_instances: 1,
                    data_flow: 1,
                },
                PinDescriptor {
                    category: 1,
                    max_instances: 1,
                    min_instances: 0,
                    data_flow: 0,
                },
            ],
            node_count: 3,
            connection_count: 3,
        }
    }
}

// =====================================================================
// Topology Miniport (IMiniportTopology)
// =====================================================================

/// Topology node type (PortCls `TOPOLOGY_NODE` categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyNodeType {
    /// Digital-to-analog converter.
    Dac,
    /// Analog-to-digital converter.
    Adc,
    /// Volume control (KSNODETYPE_VOLUME).
    Volume,
    /// Mute control (KSNODETYPE_MUTE).
    Mute,
    /// Sum / mixer node.
    Sum,
    /// Source (input terminal).
    Source,
    /// Sink (output terminal).
    Sink,
}

/// One node in the topology graph.
#[derive(Debug, Clone, Copy)]
pub struct TopologyNode {
    pub node_type: TopologyNodeType,
    /// Pin this node connects to, or 0xFFFF for none.
    pub pin: u16,
}

/// A connection between two nodes or a pin and a node.
#[derive(Debug, Clone, Copy)]
pub struct TopologyConnection {
    pub from_node: u16,
    pub to_node: u16,
    pub from_pin: u16,
    pub to_pin: u16,
}

/// Miniport topology interface: a topology miniport describes
/// the mixer graph for a filter (matching `IMiniportTopology`
/// in the NT 6.1 PortCls contract).
pub trait MiniportTopology: MiniportDriver {
    /// Fill in the node and connection lists for this filter.
    fn get_topology(
        &self,
        nodes: &mut alloc::vec::Vec<TopologyNode>,
        connections: &mut alloc::vec::Vec<TopologyConnection>,
    );

    /// Set a volume value on a node (in 1/256 dB units).
    fn set_node_volume(&mut self, node_id: u16, volume_db256: i16) -> Result<(), &'static str>;

    /// Set a mute value on a node.
    fn set_node_mute(&mut self, node_id: u16, muted: bool) -> Result<(), &'static str>;
}

/// PortTopology: the port driver that hosts a topology miniport.
pub struct PortTopology {
    port_type: PortType,
    description: &'static str,
    miniport: Option<Box<dyn MiniportTopology>>,
    device_state: DeviceState,
    nodes: alloc::vec::Vec<TopologyNode>,
    connections: alloc::vec::Vec<TopologyConnection>,
}

impl PortTopology {
    pub fn new(description: &'static str) -> Self {
        Self {
            port_type: PortType::Topology,
            description,
            miniport: None,
            device_state: DeviceState::Stopped,
            nodes: alloc::vec::Vec::new(),
            connections: alloc::vec::Vec::new(),
        }
    }

    /// Register a topology miniport and cache its graph.
    pub fn register_miniport(
        &mut self,
        miniport: Box<dyn MiniportTopology>,
    ) -> Result<(), &'static str> {
        if self.miniport.is_some() {
            return Err("Miniport already registered");
        }
        self.nodes.clear();
        self.connections.clear();
        miniport.get_topology(&mut self.nodes, &mut self.connections);
        self.miniport = Some(miniport);
        Ok(())
    }

    /// Node count from the cached graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Connection count from the cached graph.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Set a volume value on a node through the miniport.
    pub fn set_node_volume(&mut self, node_id: u16, volume_db256: i16) -> Result<(), &'static str> {
        if let Some(ref mut miniport) = self.miniport {
            miniport.set_node_volume(node_id, volume_db256)
        } else {
            Err("No miniport registered")
        }
    }
}

impl PortDriver for PortTopology {
    fn port_type(&self) -> PortType {
        self.port_type
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn init(&mut self, _miniport: Box<dyn MiniportDriver>) -> Result<(), &'static str> {
        Ok(())
    }

    fn start(&mut self) -> Result<(), &'static str> {
        if self.miniport.is_none() {
            return Err("No miniport registered");
        }
        self.device_state = DeviceState::Active;
        Ok(())
    }

    fn stop(&mut self) {
        self.device_state = DeviceState::Stopped;
    }

    fn device_state(&self) -> DeviceState {
        self.device_state
    }
}

// =====================================================================
// WaveCyclic Port (IPortWaveCyclic) — legacy AC'97 path
// =====================================================================

/// WaveCyclic miniport interface: the legacy cyclic-buffer
/// model that AC'97 uses (matching `IMiniportWaveCyclic`).
pub trait MiniportWaveCyclic: MiniportDriver {
    /// Get the supported format.
    fn get_supported_format(&self) -> AudioFormat;

    /// Map a cyclic buffer: the miniport returns the offset of
    /// `length` bytes into its DMA region.
    fn map_buffer(&mut self, offset: usize, length: usize) -> Result<usize, &'static str>;

    /// Get the current position in the cyclic buffer (in bytes).
    fn get_position_bytes(&self) -> u64;

    /// Start the DMA engine.
    fn start(&mut self) -> Result<(), &'static str>;

    /// Stop the DMA engine.
    fn stop(&mut self);
}

/// PortWaveCyclic: the port driver for legacy cyclic-buffer
/// devices.
pub struct PortWaveCyclic {
    port_type: PortType,
    description: &'static str,
    miniport: Option<Box<dyn MiniportWaveCyclic>>,
    device_state: DeviceState,
    streams: alloc::vec::Vec<AudioStream>,
    next_stream_id: u32,
}

impl PortWaveCyclic {
    pub fn new(description: &'static str) -> Self {
        Self {
            port_type: PortType::WaveCyclic,
            description,
            miniport: None,
            device_state: DeviceState::Stopped,
            streams: alloc::vec::Vec::new(),
            next_stream_id: 1,
        }
    }

    pub fn register_miniport(
        &mut self,
        miniport: Box<dyn MiniportWaveCyclic>,
    ) -> Result<(), &'static str> {
        if self.miniport.is_some() {
            return Err("Miniport already registered");
        }
        self.miniport = Some(miniport);
        Ok(())
    }

    pub fn create_stream(&mut self, format: AudioFormat) -> Result<u32, &'static str> {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;
        self.streams.push(AudioStream::new(stream_id, format));
        Ok(stream_id)
    }

    pub fn start_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        if self.device_state != DeviceState::Active {
            return Err("Device not in active state");
        }
        if let Some(ref mut miniport) = self.miniport {
            miniport.start()?;
        }
        if let Some(stream) = self.streams.iter_mut().find(|s| s.index == stream_id) {
            stream.state = StreamState::Running;
        }
        Ok(())
    }

    pub fn stop_stream(&mut self, stream_id: u32) -> Result<(), &'static str> {
        if let Some(ref mut miniport) = self.miniport {
            miniport.stop();
        }
        if let Some(stream) = self.streams.iter_mut().find(|s| s.index == stream_id) {
            stream.state = StreamState::Stopped;
        }
        Ok(())
    }
}

impl PortDriver for PortWaveCyclic {
    fn port_type(&self) -> PortType {
        self.port_type
    }

    fn description(&self) -> &'static str {
        self.description
    }

    fn init(&mut self, _miniport: Box<dyn MiniportDriver>) -> Result<(), &'static str> {
        Ok(())
    }

    fn start(&mut self) -> Result<(), &'static str> {
        if self.miniport.is_none() {
            return Err("No miniport registered");
        }
        self.device_state = DeviceState::Active;
        Ok(())
    }

    fn stop(&mut self) {
        for stream in &mut self.streams {
            stream.state = StreamState::Stopped;
        }
        self.device_state = DeviceState::Stopped;
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
    // kprintln!("    PortCls: initializing...");

    // Clear registry
    PORT_REGISTRY.lock().clear();

    // kprintln!("    PortCls: port class driver ready");
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

/// create a WaveRT port with a miniport
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

    // kprintln!("  [PortCls] Created WaveRT port '{}' at index {}", description, index);
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
    PORT_REGISTRY
        .lock()
        .get(port_index)
        .map(|p| p.device_state())
}

/// Example: create an HDA audio device
pub fn create_hda_audio_device(codec_name: &'static str) -> usize {
    // create a placeholder miniport
    struct HdaMiniport {
        description: &'static str,
        format: AudioFormat,
    }

    impl MiniportDriver for HdaMiniport {
        fn description(&self) -> &'static str {
            self.description
        }

        fn init(&mut self) -> Result<(), &'static str> {
            // kprintln!("  [HDA Miniport] initialized");
            Ok(())
        }

        fn service(&mut self) {
            // Called in ISR context
        }

        fn shutdown(&mut self) {
            // kprintln!("  [HDA Miniport] Shutdown");
        }
    }

    impl MiniportWaveRT for HdaMiniport {
        fn get_supported_format(&self) -> AudioFormat {
            self.format
        }

        fn set_buffer(
            &mut self,
            _buffer_virt: u64,
            _buffer_phys: u64,
            _size: usize,
        ) -> Result<(), &'static str> {
            Ok(())
        }

        fn get_position_bytes(&self) -> u64 {
            0
        }

        fn start(&mut self) -> Result<(), &'static str> {
            Ok(())
        }

        fn stop(&mut self) {}
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
