//! Loongson Display Connector Support
//
//! Implements display connector detection and configuration for HDMI,
//! DisplayPort, VGA, and DVI outputs.

/// Connector types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    /// HDMI connector
    Hdmi,
    /// DisplayPort connector
    DisplayPort,
    /// VGA connector
    Vga,
    /// DVI connector
    Dvi,
    /// LVDS panel
    Lvds,
    /// eDP panel
    Edp,
    /// Unknown type
    Unknown,
}

impl ConnectorType {
    /// Get connector name
    pub fn name(&self) -> &'static str {
        match self {
            ConnectorType::Hdmi => "HDMI",
            ConnectorType::DisplayPort => "DisplayPort",
            ConnectorType::Vga => "VGA",
            ConnectorType::Dvi => "DVI",
            ConnectorType::Lvds => "LVDS",
            ConnectorType::Edp => "eDP",
            ConnectorType::Unknown => "Unknown",
        }
    }
}

/// Connector status
#[derive(Debug, Clone, Copy)]
pub struct ConnectorStatus {
    /// Connector type
    pub connector_type: ConnectorType,
    /// Whether a display is connected
    pub connected: bool,
    /// Detected width (0 if not detected)
    pub width: u32,
    /// Detected height (0 if not detected)
    pub height: u32,
    /// Preferred refresh rate
    pub refresh_rate: u32,
    /// Hot-plug detect (HPD) status
    pub hpd: bool,
}

impl Default for ConnectorStatus {
    fn default() -> Self {
        Self {
            connector_type: ConnectorType::Unknown,
            connected: false,
            width: 0,
            height: 0,
            refresh_rate: 60,
            hpd: false,
        }
    }
}

/// Display encoder types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderType {
    /// Internal TMDS encoder
    InternalTmds,
    /// External TMDS encoder
    ExternalTmds,
    /// LVDS encoder
    Lvds,
    /// DisplayPort encoder
    DisplayPort,
    /// HDMI encoder
    Hdmi,
    /// DAC encoder (VGA)
    Dac,
    /// Unknown encoder
    Unknown,
}

/// Connector information
#[derive(Debug)]
pub struct Connector {
    /// Connector type
    pub connector_type: ConnectorType,
    /// Encoder type
    pub encoder: EncoderType,
    /// Associated CRTC (pipeline)
    pub crtc: u32,
    /// I2C address for EDID
    pub i2c_addr: u8,
}

impl Connector {
    /// Create a new connector
    pub fn new(connector_type: ConnectorType) -> Self {
        let encoder = match connector_type {
            ConnectorType::Hdmi => EncoderType::Hdmi,
            ConnectorType::DisplayPort => EncoderType::DisplayPort,
            ConnectorType::Vga => EncoderType::Dac,
            ConnectorType::Dvi => EncoderType::InternalTmds,
            ConnectorType::Lvds | ConnectorType::Edp => EncoderType::Lvds,
            ConnectorType::Unknown => EncoderType::Unknown,
        };

        Self {
            connector_type,
            encoder,
            crtc: 0, // Default to CRTC A
            i2c_addr: 0x50, // Standard EDID I2C address
        }
    }

    /// Get connector type name
    pub fn name(&self) -> &'static str {
        self.connector_type.name()
    }

    /// Check if connector supports a specific mode
    pub fn supports_mode(&self, width: u32, height: u32) -> bool {
        match self.connector_type {
            ConnectorType::Vga => {
                // VGA typically supports up to 2048x1536
                width <= 2048 && height <= 1536
            }
            ConnectorType::Dvi | ConnectorType::Hdmi => {
                // DVI/HDMI supports up to 4096x2160
                width <= 4096 && height <= 2160
            }
            ConnectorType::DisplayPort => {
                // DisplayPort supports up to 7680x4320
                width <= 7680 && height <= 4320
            }
            ConnectorType::Lvds | ConnectorType::Edp => {
                // Panels have fixed resolutions
                true
            }
            ConnectorType::Unknown => false,
        }
    }
}

/// Hot-plug detection manager
pub struct HpdManager {
    /// Whether HPD is enabled
    enabled: bool,
    /// Last HPD status for each connector
    last_hpd: [bool; 6],
    /// Callbacks for HPD events
    callbacks: [Option<fn(usize, bool)>; 6],
}

impl HpdManager {
    /// Create a new HPD manager
    pub fn new() -> Self {
        Self {
            enabled: false,
            last_hpd: [false; 6],
            callbacks: [None, None, None, None, None, None],
        }
    }

    /// Enable HPD
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable HPD
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if HPD is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Register HPD callback
    pub fn register_callback(&mut self, connector: usize, callback: fn(usize, bool)) {
        if connector < self.callbacks.len() {
            self.callbacks[connector] = Some(callback);
        }
    }

    /// Unregister HPD callback
    pub fn unregister_callback(&mut self, connector: usize) {
        if connector < self.callbacks.len() {
            self.callbacks[connector] = None;
        }
    }

    /// Update HPD status
    ///
    /// Call this when HPD interrupt fires.
    pub fn update_hpd(&mut self, connector: usize, hpd: bool) {
        if connector >= self.callbacks.len() {
            return;
        }

        let changed = self.last_hpd[connector] != hpd;
        self.last_hpd[connector] = hpd;

        if changed {
            // Invoke callback
            if let Some(callback) = self.callbacks[connector] {
                callback(connector, hpd);
            }
        }
    }

    /// Get HPD status for a connector
    pub fn get_hpd(&self, connector: usize) -> bool {
        if connector < self.last_hpd.len() {
            self.last_hpd[connector]
        } else {
            false
        }
    }
}

impl Default for HpdManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Encoder configuration
pub struct EncoderConfig {
    /// Encoder type
    pub encoder_type: EncoderType,
    /// Associated CRTC
    pub crtc: u32,
    /// Clock source
    pub clock_source: u32,
    /// Whether encoding is enabled
    pub enabled: bool,
}

impl EncoderConfig {
    /// Create a new encoder configuration
    pub fn new(encoder_type: EncoderType) -> Self {
        Self {
            encoder_type,
            crtc: 0,
            clock_source: 0,
            enabled: false,
        }
    }

    /// Enable the encoder
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the encoder
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

/// Display output configuration
#[derive(Debug)]
pub struct OutputConfig {
    /// Output connector
    pub connector: Connector,
    /// Encoder configuration
    pub encoder: EncoderConfig,
    /// Associated CRTC pipeline
    pub crtc: u32,
    /// Display mode
    pub width: u32,
    pub height: u32,
    pub refresh_rate: u32,
}

impl OutputConfig {
    /// Create a new output configuration
    pub fn new(connector: Connector, crtc: u32, width: u32, height: u32) -> Self {
        let mut encoder = EncoderConfig::new(connector.encoder);
        encoder.crtc = crtc;
        encoder.enable();

        Self {
            connector,
            encoder,
            crtc,
            width,
            height,
            refresh_rate: 60,
        }
    }

    /// Get output name
    pub fn name(&self) -> &'static str {
        self.connector.name()
    }
}
