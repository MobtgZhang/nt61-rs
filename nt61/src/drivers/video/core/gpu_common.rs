//! GPU Common Interface
//
//! Provides GPU device traits, PCI discovery, vendor ID database,
//! and common types used by all GPU drivers.
//
//! Clean-room implementation based on industry standards.

use crate::hal::common::pci::{self, PciDevice};
use alloc::vec::Vec;
use alloc::boxed::Box;

#[allow(dead_code)]

// =====================================================================
// GPU Vendor IDs
// =====================================================================

/// GPU Vendor IDs (PCI Vendor IDs)
pub mod vendors {
    pub const VENDOR_LOONGSON: u16 = 0x0014;    // Loongson Technology
    pub const VENDOR_INTEL: u16 = 0x8086;        // Intel
    pub const VENDOR_AMD: u16 = 0x1002;           // AMD/ATI
    pub const VENDOR_NVIDIA: u16 = 0x10DE;        // NVIDIA
    pub const VENDOR_ZHAOXIN: u16 = 0x1D17;       // Zhaoxin Electronics
    pub const VENDOR_GLENFLY: u16 = 0x1F31;      // Glenfly Technology
    pub const VENDOR_ROCKCHIP: u16 = 0x220E;      // Rockchip
    pub const VENDOR_ALLWINNER: u16 = 0x1D3D;    // Allwinner Technology
    pub const VENDOR_QUALCOMM: u16 = 0x5143;      // Qualcomm
    pub const VENDOR_STARFIVE: u16 = 0x1D6A;       // StarFive Technology (corrected)
    pub const VENDOR_VIRTIO: u16 = 0x1AF4;         // Red Hat (virtio)

    /// Check if a vendor ID is a known GPU vendor
    pub fn is_gpu_vendor(vendor_id: u16) -> bool {
        matches!(
            vendor_id,
            VENDOR_LOONGSON
                | VENDOR_INTEL
                | VENDOR_AMD
                | VENDOR_NVIDIA
                | VENDOR_ZHAOXIN
                | VENDOR_GLENFLY
                | VENDOR_ROCKCHIP
                | VENDOR_ALLWINNER
                | VENDOR_QUALCOMM
                | VENDOR_STARFIVE
                | VENDOR_VIRTIO
        )
    }

    /// Get vendor name
    pub fn vendor_name(vendor_id: u16) -> &'static str {
        // Note: `vendor_id` is pre-validated by `is_supported_vendor` so we
        // can cover the supported set in one combined arm and an explicit
        // Unknown fallback without triggering unreachable warnings.
        match vendor_id {
            VENDOR_LOONGSON => "Loongson",
            VENDOR_INTEL => "Intel",
            VENDOR_AMD => "AMD",
            VENDOR_NVIDIA => "NVIDIA",
            VENDOR_ZHAOXIN | VENDOR_GLENFLY => "Zhaoxin/Glenfly",
            VENDOR_ROCKCHIP => "Rockchip",
            VENDOR_ALLWINNER => "Allwinner",
            VENDOR_QUALCOMM => "Qualcomm",
            VENDOR_STARFIVE => "StarFive",
            VENDOR_VIRTIO => "virtio",
            _ => "Unknown",
        }
    }
}

// =====================================================================
// PCI Device Classes
// =====================================================================

/// PCI device class for display controllers
pub mod class_codes {
    pub const CLASS_DISPLAY: u8 = 0x03;
    /// VGA Controller
    pub const SUBCLASS_VGA: u8 = 0x00;
    /// Unaccelerated framebuffer
    pub const SUBCLASS_UNACCEL: u8 = 0x01;
    /// Other display controller
    pub const SUBCLASS_OTHER: u8 = 0x02;

    /// Check if a device is a display controller
    pub fn is_display_controller(class_code: u8, _subclass: u8) -> bool {
        class_code == CLASS_DISPLAY
    }

    /// Get subclass name
    pub fn subclass_name(subclass: u8) -> &'static str {
        match subclass {
            SUBCLASS_VGA => "VGA Controller",
            SUBCLASS_UNACCEL => "Unaccelerated Framebuffer",
            SUBCLASS_OTHER => "Other Display Controller",
            _ => "Unknown",
        }
    }
}

// =====================================================================
// GPU Device Information
// =====================================================================

/// Basic GPU device information
#[derive(Debug, Clone, Copy)]
pub struct GpuDeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

impl GpuDeviceInfo {
    /// Create new GPU device info from PCI device
    pub fn from_pci(pci_dev: &PciDevice) -> Self {
        Self {
            vendor_id: pci_dev.vendor_id,
            device_id: pci_dev.device_id,
            revision: 0,
            bus: pci_dev.bus,
            device: pci_dev.device,
            function: pci_dev.function,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
        }
    }

    /// Get vendor name
    pub fn vendor_name(&self) -> &'static str {
        vendors::vendor_name(self.vendor_id)
    }
}

// =====================================================================
// GPU Features
// =====================================================================

/// GPU hardware features
#[derive(Debug, Clone, Copy)]
pub struct GpuFeatures {
    /// Has 2D acceleration
    pub has_2d_accel: bool,
    /// Has 3D acceleration
    pub has_3d_accel: bool,
    /// Has video decode engine
    pub has_video_decode: bool,
    /// Has compute capability (GPGPU)
    pub has_compute: bool,
    /// Maximum texture size (in pixels)
    pub max_texture_size: u32,
    /// Maximum number of render targets
    pub max_render_targets: u32,
    /// Has hardware cursor support
    pub has_cursor: bool,
    /// Cursor size (typically 32, 64, or 256)
    pub cursor_size: u32,
    /// Has separate video memory
    pub has_vram: bool,
    /// VRAM size (in bytes)
    pub vram_size: u64,
}

impl Default for GpuFeatures {
    fn default() -> Self {
        Self {
            has_2d_accel: false,
            has_3d_accel: false,
            has_video_decode: false,
            has_compute: false,
            max_texture_size: 2048,
            max_render_targets: 1,
            has_cursor: false,
            cursor_size: 32,
            has_vram: false,
            vram_size: 0,
        }
    }
}

// =====================================================================
// Pixel Format
// =====================================================================

/// Pixel format for framebuffer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit BGRA (8:8:8:8)
    Bgra8888,
    /// 32-bit RGBA (8:8:8:8)
    Rgba8888,
    /// 16-bit BGR (5:6:5)
    Bgr565,
    /// 32-bit BGRX (8:8:8:8, X unused)
    Bgrx8888,
    /// 32-bit XRGB (8:8:8:8, X unused)
    Xrgb8888,
    /// 8-bit grayscale
    G8,
    /// Unknown format
    Unknown,
}

impl PixelFormat {
    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> u32 {
        match self {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 | PixelFormat::Bgrx8888
            | PixelFormat::Xrgb8888 => 4,
            PixelFormat::Bgr565 => 2,
            PixelFormat::G8 => 1,
            PixelFormat::Unknown => 0,
        }
    }

    /// Get format name
    pub fn name(&self) -> &'static str {
        match self {
            PixelFormat::Bgra8888 => "BGRA 8:8:8:8",
            PixelFormat::Rgba8888 => "RGBA 8:8:8:8",
            PixelFormat::Bgr565 => "RGB 5:6:5",
            PixelFormat::Bgrx8888 => "BGRX 8:8:8:8",
            PixelFormat::Xrgb8888 => "XRGB 8:8:8:8",
            PixelFormat::G8 => "Grayscale 8-bit",
            PixelFormat::Unknown => "Unknown",
        }
    }
}

// =====================================================================
// Display Mode
// =====================================================================

/// Display mode parameters
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    /// Horizontal resolution
    pub width: u32,
    /// Vertical resolution
    pub height: u32,
    /// Refresh rate in Hz
    pub refresh_rate: u32,
    /// Bits per pixel
    pub bpp: u32,
    /// Pixel format
    pub format: PixelFormat,
    /// Interlaced mode
    pub interlaced: bool,
}

impl DisplayMode {
    /// Create a new display mode
    pub fn new(width: u32, height: u32, refresh_rate: u32, bpp: u32) -> Self {
        let format = match bpp {
            32 => PixelFormat::Bgra8888,
            24 => PixelFormat::Bgrx8888,
            16 => PixelFormat::Bgr565,
            _ => PixelFormat::Unknown,
        };

        Self {
            width,
            height,
            refresh_rate,
            bpp,
            format,
            interlaced: false,
        }
    }

    /// Calculate bytes per row (stride)
    pub fn stride(&self) -> u32 {
        ((self.width * self.bpp / 8) + 127) & !127 // 128-byte alignment
    }

    /// Calculate framebuffer size
    pub fn framebuffer_size(&self) -> u64 {
        (self.stride() as u64) * (self.height as u64)
    }
}

// =====================================================================
// Framebuffer Information
// =====================================================================

/// Framebuffer information
#[derive(Debug, Clone, Copy)]
pub struct GpuFramebufferInfo {
    /// Physical address of framebuffer
    pub address: u64,
    /// Virtual address of framebuffer
    pub virtual_address: u64,
    /// Framebuffer size in bytes
    pub size: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per row (stride)
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u32,
    /// Pixel format
    pub format: PixelFormat,
}

impl GpuFramebufferInfo {
    /// Create new framebuffer info
    pub fn new(
        address: u64,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
    ) -> Self {
        let format = match bpp {
            32 => PixelFormat::Bgra8888,
            24 => PixelFormat::Bgrx8888,
            16 => PixelFormat::Bgr565,
            _ => PixelFormat::Unknown,
        };

        Self {
            address,
            virtual_address: 0,
            size: (pitch as u64) * (height as u64),
            width,
            height,
            pitch,
            bpp,
            format,
        }
    }
}

impl Default for GpuFramebufferInfo {
    fn default() -> Self {
        Self {
            address: 0,
            virtual_address: 0,
            size: 0,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
            format: PixelFormat::Unknown,
        }
    }
}

// =====================================================================
// Display Connectors
// =====================================================================

/// Display connector types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayConnector {
    /// Analog VGA
    AnalogVga,
    /// DDI Port A
    DdiA,
    /// DDI Port B
    DdiB,
    /// DDI Port C
    DdiC,
    /// DDI Port D
    DdiD,
    /// DDI Port E
    DdiE,
    /// DDI Port F
    DdiF,
    /// DDI Port G
    DdiG,
    /// DDI Port T (USB-C/Thunderbolt)
    DdiT,
    /// Embedded DisplayPort (eDP)
    EmbeddedDp,
    /// LVDS
    Lvds,
    /// DSI (Display Serial Interface)
    Dsi(u8),
}

impl DisplayConnector {
    /// Get connector name
    pub fn name(&self) -> &'static str {
        match self {
            DisplayConnector::AnalogVga => "VGA",
            DisplayConnector::DdiA => "DDI-A",
            DisplayConnector::DdiB => "DDI-B",
            DisplayConnector::DdiC => "DDI-C",
            DisplayConnector::DdiD => "DDI-D",
            DisplayConnector::DdiE => "DDI-E",
            DisplayConnector::DdiF => "DDI-F",
            DisplayConnector::DdiG => "DDI-G",
            DisplayConnector::DdiT => "DDI-T (USB-C)",
            DisplayConnector::EmbeddedDp => "eDP",
            DisplayConnector::Lvds => "LVDS",
            DisplayConnector::Dsi(_) => "DSI",
        }
    }
}

/// Connector status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorStatus {
    /// No display connected
    Disconnected,
    /// Display connected but not powered on
    Connected,
    /// Display connected and powered on
    Active,
}

/// Display configuration for a single head
#[derive(Debug, Clone)]
pub struct DisplayHead {
    /// Connector used by this head
    pub connector: DisplayConnector,
    /// Current mode
    pub mode: DisplayMode,
    /// Framebuffer info
    pub framebuffer: GpuFramebufferInfo,
    /// Is this head enabled
    pub enabled: bool,
    /// Clone source (if this is a cloned display)
    pub clone_of: Option<usize>,
}

impl DisplayHead {
    /// Create a new display head
    pub fn new(connector: DisplayConnector, mode: DisplayMode) -> Self {
        Self {
            connector,
            mode,
            framebuffer: GpuFramebufferInfo::default(),
            enabled: false,
            clone_of: None,
        }
    }
}

/// Multi-display mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayModeType {
    /// Single display
    Single,
    /// Clone (mirrored) displays
    Clone,
    /// Extended desktop (multiple displays)
    Extended,
    /// Single primary with others off
    SinglePrimary,
}

// =====================================================================
// GPU Interrupt Types
// =====================================================================

/// GPU interrupt types
#[derive(Debug, Clone, Copy)]
pub enum GpuInterrupt {
    /// Vertical blank interrupt (display head)
    VBlank(u32),
    /// Horizontal blank interrupt
    HBlank(u32),
    /// Page fault interrupt
    PageFault,
    /// Command buffer completed
    CmdComplete,
    /// Flip completed
    FlipComplete,
    /// GPU error
    Error(GpuError),
}

/// GPU error types
#[derive(Debug, Clone, Copy)]
pub enum GpuError {
    /// Command buffer underflow
    CmdUnderflow,
    /// Command buffer overflow
    CmdOverflow,
    /// Memory access error
    MemAccessError,
    /// Invalid command
    InvalidCmd,
    /// Timeout
    Timeout,
    /// Unknown error
    Unknown(u32),
}

// =====================================================================
// GPU Device Trait
// =====================================================================

/// Trait for GPU drivers
pub trait GpuDriver: Send + Sync {
    /// Get device information
    fn device_info(&self) -> GpuDeviceInfo;

    /// Get hardware features
    fn features(&self) -> GpuFeatures;

    /// Initialize the GPU and framebuffer
    fn init(&mut self) -> Result<(), GpuError>;

    /// Initialize framebuffer with a specific mode
    fn init_framebuffer(&mut self, mode: Option<DisplayMode>) -> Result<GpuFramebufferInfo, GpuError>;

    /// Set display mode
    fn set_mode(&mut self, mode: &DisplayMode) -> Result<(), GpuError>;

    /// Get current display mode
    fn get_mode(&self) -> Option<DisplayMode>;

    /// Enable vertical blank interrupt
    fn enable_vblank(&mut self, head: u32) -> Result<(), GpuError>;

    /// Disable vertical blank interrupt
    fn disable_vblank(&mut self, head: u32);

    /// Wait for vertical blank
    fn wait_vblank(&self, head: u32, timeout_ms: u32) -> Result<(), GpuError>;

    /// Clear framebuffer with a color
    fn clear(&mut self, color: u32);

    /// Set a single pixel
    fn set_pixel(&mut self, x: u32, y: u32, color: u32);

    /// Get framebuffer info
    fn framebuffer_info(&self) -> Option<GpuFramebufferInfo>;

    /// Enable bus mastering
    fn enable_bus_mastering(&mut self);

    /// Shutdown the GPU
    fn shutdown(&mut self);
}

/// Trait for multi-display GPU support
pub trait MultiHead: GpuDriver {
    /// Enumerate available display connectors
    fn enumerate_connectors(&self) -> Vec<DisplayConnector>;
    
    /// Get the status of a connector
    fn get_connector_status(&self, connector: DisplayConnector) -> ConnectorStatus;
    
    /// Enable a connector
    fn enable_connector(&mut self, connector: DisplayConnector, mode: DisplayMode) -> Result<(), GpuError>;
    
    /// Disable a connector
    fn disable_connector(&mut self, connector: DisplayConnector);
    
    /// Set the power state of a connector
    fn set_connector_power(&mut self, connector: DisplayConnector, on: bool);
    
    /// Get the number of available heads
    fn head_count(&self) -> usize;
    
    /// Configure multiple displays
    fn configure_multihead(&mut self, heads: &[DisplayHead], mode: DisplayModeType) -> Result<(), GpuError>;
}

// =====================================================================
// GPU Discovery
// =====================================================================

/// GPU discovery result
#[derive(Debug)]
pub enum DiscoveredGpu {
    /// Loongson GPU
    Loongson {
        device: PciDevice,
        chip: LoongsonChip,
    },
    /// Intel GPU
    Intel {
        device: PciDevice,
        generation: IntelGeneration,
    },
    /// AMD GPU
    Amd {
        device: PciDevice,
        family: AmdFamily,
    },
    /// NVIDIA GPU
    Nvidia {
        device: PciDevice,
        arch: NvidiaArch,
    },
    /// Zhaoxin GPU
    Zhaoxin {
        device: PciDevice,
        variant: ZhaoxinVariant,
    },
    /// Rockchip GPU
    Rockchip {
        device: PciDevice,
        soc: RockchipSoc,
    },
    /// Qualcomm GPU
    Qualcomm {
        device: PciDevice,
        generation: QualcommGen,
    },
    /// Allwinner GPU
    Allwinner {
        device: PciDevice,
        soc: AllwinnerSoc,
    },
    /// StarFive GPU (RISC-V)
    Starfive {
        device: PciDevice,
        soc: StarfiveSoc,
    },
    /// virtio-gpu (QEMU)
    VirtioGpu {
        device: PciDevice,
    },
    /// Unknown GPU
    Unknown {
        device: PciDevice,
    },
}

/// Loongson chip variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoongsonChip {
    /// LS7A chipset
    Ls7A,
    /// Loongson 3A5000 integrated DC
    Ls3A5000,
    /// Loongson 2K2000 integrated DC
    Ls2K2000,
    /// Loongson 2K3000 integrated DC
    Ls2K3000,
    /// Unknown variant
    Unknown,
}

/// Intel GPU generations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelGeneration {
    /// Ironlake (Clarkdale/Arrandale)
    Ironlake,
    /// Sandy Bridge (2nd Gen)
    SandyBridge,
    /// Ivy Bridge (3rd Gen)
    IvyBridge,
    /// Haswell (4th Gen)
    Haswell,
    /// Broadwell (5th Gen)
    Broadwell,
    /// Skylake (6th Gen)
    Skylake,
    /// Kaby Lake (7th Gen)
    KabyLake,
    /// Coffee Lake (8th Gen+)
    CoffeeLake,
    /// Comet Lake
    CometLake,
    /// Ice Lake
    IceLake,
    /// Tiger Lake (12th Gen)
    TigerLake,
    /// Rocket Lake (11th Gen)
    RocketLake,
    /// Alder Lake (12th Gen Desktop)
    AlderLake,
    /// Raptor Lake (13th Gen)
    RaptorLake,
    /// Arc GPUs (DG2/Alchemist)
    Arc,
    /// Meteor Lake
    MeteorLake,
    /// Unknown generation
    Unknown,
}

/// AMD GPU families
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdFamily {
    /// R600 (HD 2000-4000)
    R600,
    /// Evergreen (HD 5000-6000)
    Evergreen,
    /// Northern Islands (HD 6000-7000)
    Northern,
    /// Southern Islands / GCN 1.x (HD 7000)
    Southern,
    /// Sea Islands / GCN 2.x (R9 200/300)
    Sea,
    /// Volcanic Islands / GCN 3.x (R9 300/Fury)
    Volcanic,
    /// Polaris / GCN 4.x (RX 400/500)
    Polaris,
    /// Vega (GCN 5)
    Vega,
    /// Navi / RDNA 1
    Navi,
    /// RDNA 2 (Navi 2x)
    Rdna2,
    /// RDNA 3 (Navi 3x)
    Rdna3,
    /// Unknown family
    Unknown,
}

/// NVIDIA GPU architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaArch {
    /// Tesla (GeForce 8xxx-9xxx)
    Tesla,
    /// Fermi (GeForce GTX 400/500)
    Fermi,
    /// Kepler (GeForce GTX 600/700)
    Kepler,
    /// Maxwell (GeForce GTX 900)
    Maxwell,
    /// Pascal (GeForce GTX 1000)
    Pascal,
    /// Turing (RTX 2000)
    Turing,
    /// Ampere (RTX 3000)
    Ampere,
    /// Ada Lovelace (RTX 4000)
    AdaLovelace,
    /// Unknown architecture
    Unknown,
}

/// Zhaoxin variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZhaoxinVariant {
    /// ZX-D (Wudaokou)
    ZX_D,
    /// ZX-E / KX-6000 (Lujiazui)
    ZX_E,
    /// KX-7000 (Shijidadao)
    KX7000,
    /// Glenfly GT-10C0
    Glenfly,
    /// Unknown variant
    Unknown,
}

/// Rockchip SoC variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RockchipSoc {
    /// RK3066
    RK3066,
    /// RK3288
    RK3288,
    /// RK3399
    RK3399,
    /// RK3566
    RK3566,
    /// RK3568
    RK3568,
    /// RK3588
    RK3588,
    /// Unknown SoC
    Unknown,
}

/// Qualcomm Adreno generations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualcommGen {
    /// Adreno 3xx (Snapdragon S4)
    A3xx,
    /// Adreno 4xx (Snapdragon 800/801)
    A4xx,
    /// Adreno 5xx (Snapdragon 820/835)
    A5xx,
    /// Adreno 6xx (Snapdragon 845+)
    A6xx,
    /// Unknown generation
    Unknown,
}

/// Allwinner SoC variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllwinnerSoc {
    /// A10/A13 (Mali-400)
    A10,
    /// A20 (Mali-400)
    A20,
    /// A31 (PowerVR SGX544)
    A31,
    /// A33 (Mali-400)
    A33,
    /// A64 (Mali-400 MP2)
    A64,
    /// H3 (Mali-400)
    H3,
    /// H5 (Mali-450)
    H5,
    /// H6 (Mali-T720)
    H6,
    /// D1 (RISC-V)
    D1,
    /// Unknown SoC
    Unknown,
}

/// StarFive SoC variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StarfiveSoc {
    /// JH7100 - 2-core RISC-V + IMG BXE-4-32
    JH7100,
    /// JH7110 - 4-core RISC-V + IMG BXE-4-32
    JH7110,
    /// Unknown SoC
    Unknown,
}

/// virtio GPU variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioGpuDeviceId {
    /// Standard virtio-gpu
    VirtioGpu,
    /// virtio-gpu with VirGL acceleration
    VirtioGpuVirgl,
    /// Unknown
    Unknown,
}

/// Discover all GPUs in the system
pub fn discover_gpus() -> Vec<DiscoveredGpu> {
    let mut gpus = Vec::new();
    let devices = pci::enumerate();

    for dev in devices {
        // Check if it's a display controller
        if dev.class_code == class_codes::CLASS_DISPLAY {
            match dev.vendor_id {
                vendors::VENDOR_LOONGSON => {
                    let chip = loongson_chip_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Loongson {
                        device: *dev,
                        chip,
                    });
                }
                vendors::VENDOR_INTEL => {
                    let gen = intel_generation_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Intel {
                        device: *dev,
                        generation: gen,
                    });
                }
                vendors::VENDOR_AMD => {
                    let family = amd_family_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Amd {
                        device: *dev,
                        family,
                    });
                }
                vendors::VENDOR_NVIDIA => {
                    let arch = nvidia_arch_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Nvidia {
                        device: *dev,
                        arch,
                    });
                }
                vendors::VENDOR_ZHAOXIN | vendors::VENDOR_GLENFLY => {
                    let variant = zhaoxin_variant_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Zhaoxin {
                        device: *dev,
                        variant,
                    });
                }
                vendors::VENDOR_ROCKCHIP => {
                    let soc = rockchip_soc_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Rockchip {
                        device: *dev,
                        soc,
                    });
                }
                vendors::VENDOR_QUALCOMM => {
                    let gen = qualcomm_gen_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Qualcomm {
                        device: *dev,
                        generation: gen,
                    });
                }
                vendors::VENDOR_ALLWINNER => {
                    let soc = allwinner_soc_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Allwinner {
                        device: *dev,
                        soc,
                    });
                }
                vendors::VENDOR_STARFIVE => {
                    let soc = starfive_soc_from_device_id(dev.device_id);
                    gpus.push(DiscoveredGpu::Starfive {
                        device: *dev,
                        soc,
                    });
                }
                vendors::VENDOR_VIRTIO => {
                    gpus.push(DiscoveredGpu::VirtioGpu {
                        device: *dev,
                    });
                }
                _ => {
                    gpus.push(DiscoveredGpu::Unknown { device: *dev });
                }
            }
        }
    }

    gpus
}

/// Get Loongson chip type from device ID
fn loongson_chip_from_device_id(device_id: u16) -> LoongsonChip {
    match device_id {
        0x7A05 => LoongsonChip::Ls7A,
        0x7A0A => LoongsonChip::Ls3A5000,
        0x7A1A => LoongsonChip::Ls2K2000,
        0x7A2A => LoongsonChip::Ls2K3000,
        _ => LoongsonChip::Unknown,
    }
}

/// Get Intel generation from device ID
fn intel_generation_from_device_id(device_id: u16) -> IntelGeneration {
    // Ironlake
    if matches!(device_id, 0x0042 | 0x0046) {
        return IntelGeneration::Ironlake;
    }
    // Sandy Bridge
    if matches!(
        device_id,
        0x0102 | 0x0106 | 0x0112 | 0x0116 | 0x0122 | 0x0126
    ) {
        return IntelGeneration::SandyBridge;
    }
    // Ivy Bridge
    if matches!(device_id, 0x0152 | 0x0156 | 0x0162 | 0x0166) {
        return IntelGeneration::IvyBridge;
    }
    // Haswell
    if (0x0402..=0x042F).contains(&device_id) {
        return IntelGeneration::Haswell;
    }
    // Broadwell
    if (0x1602..=0x162F).contains(&device_id) || (0x0A02..=0x0A2F).contains(&device_id) {
        return IntelGeneration::Broadwell;
    }
    // Skylake
    if (0x1902..=0x193F).contains(&device_id) || (0x0902..=0x093F).contains(&device_id) {
        return IntelGeneration::Skylake;
    }
    // Kaby Lake
    if (0x5902..=0x591F).contains(&device_id) || (0x5912..=0x593F).contains(&device_id) {
        return IntelGeneration::KabyLake;
    }
    // Coffee Lake and later
    if (0x3E02..=0x3E1F).contains(&device_id) || (0x3E0A..=0x3E1A).contains(&device_id) {
        return IntelGeneration::CoffeeLake;
    }
    // Comet Lake
    if (0x9BA0..=0x9BCF).contains(&device_id) {
        return IntelGeneration::CometLake;
    }
    // Ice Lake
    if (0x8A50..=0x8A7F).contains(&device_id) {
        return IntelGeneration::IceLake;
    }
    // Rocket Lake (11th Gen) - 0x4C8x
    if (0x4C8A..=0x4C9F).contains(&device_id) {
        return IntelGeneration::RocketLake;
    }
    // Tiger Lake (12th Gen) - 0x9A4x
    if (0x9A40..=0x9A7F).contains(&device_id) {
        return IntelGeneration::TigerLake;
    }
    // Alder Lake (12th Gen Desktop) - 0x46xx
    if (0x4600..=0x46FF).contains(&device_id) {
        return IntelGeneration::AlderLake;
    }
    // Raptor Lake (13th Gen) - 0xA7xx
    if (0xA780..=0xA79F).contains(&device_id) {
        return IntelGeneration::RaptorLake;
    }
    // Arc GPUs (DG2/Alchemist) - 0x56xx
    if (0x5690..=0x56AF).contains(&device_id) {
        return IntelGeneration::Arc;
    }
    // Meteor Lake - 0x7Dxx
    if (0x7D00..=0x7DFF).contains(&device_id) {
        return IntelGeneration::MeteorLake;
    }
    IntelGeneration::Unknown
}

/// Get AMD family from device ID
fn amd_family_from_device_id(device_id: u16) -> AmdFamily {
    // This is a simplified version; the full database is in the AMD driver module
    // R600: 0x9440-0x95FF
    if (0x9440..=0x95FF).contains(&device_id) {
        return AmdFamily::R600;
    }
    // Evergreen: 0x68BE-0x69FF
    if (0x68BE..=0x69FF).contains(&device_id) {
        return AmdFamily::Evergreen;
    }
    // Southern Islands: 0x6760-0x67FF
    if (0x6760..=0x67FF).contains(&device_id) {
        return AmdFamily::Southern;
    }
    // Sea Islands: 0x6600-0x666F or 0x67B0-0x67FF
    if (0x6600..=0x666F).contains(&device_id) || (0x67B0..=0x67FF).contains(&device_id) {
        return AmdFamily::Sea;
    }
    // Polaris: 0x67C0-0x67FF or 0x69C0-0x69FF or 0x6FDF
    if (0x67C0..=0x67FF).contains(&device_id)
        || (0x69C0..=0x69FF).contains(&device_id)
        || device_id == 0x6FDF
    {
        return AmdFamily::Polaris;
    }
    AmdFamily::Unknown
}

/// Get NVIDIA architecture from device ID
fn nvidia_arch_from_device_id(device_id: u16) -> NvidiaArch {
    // Simplified version
    let family = device_id >> 8;
    match family {
        0x06 => NvidiaArch::Tesla,      // GeForce 8xxx-9xxx
        0x0F => NvidiaArch::Fermi,      // GeForce GTX 400/500
        0x10 | 0x11 | 0x12 => NvidiaArch::Kepler, // GeForce GTX 600/700
        0x13 => NvidiaArch::Maxwell,     // GeForce GTX 900
        0x14 | 0x15 | 0x16 => NvidiaArch::Pascal, // GeForce GTX 1000
        0x17 | 0x18 => NvidiaArch::Turing, // RTX 2000
        0x1E | 0x20 | 0x21 => NvidiaArch::Ampere, // RTX 3000
        0x22 | 0x23 | 0x24 | 0x25 => NvidiaArch::AdaLovelace, // RTX 4000
        _ => NvidiaArch::Unknown,
    }
}

/// Get Zhaoxin variant from device ID
fn zhaoxin_variant_from_device_id(device_id: u16) -> ZhaoxinVariant {
    // ZX-E / KX-6000: 0x0101-0x0108
    if (0x0101..=0x0108).contains(&device_id) {
        return ZhaoxinVariant::ZX_E;
    }
    // KX-7000: likely different range
    if device_id == 0x0B00 || device_id == 0x0B01 {
        return ZhaoxinVariant::KX7000;
    }
    // Glenfly GT-10C0
    if device_id == 0x000A {
        return ZhaoxinVariant::Glenfly;
    }
    ZhaoxinVariant::Unknown
}

/// Get Rockchip SoC from device ID
fn rockchip_soc_from_device_id(device_id: u16) -> RockchipSoc {
    // Rockchip typically uses MMIO devices, not standard PCI
    // This is for cases where it does expose PCI
    match device_id {
        0x3066 => RockchipSoc::RK3066,
        0x3288 => RockchipSoc::RK3288,
        0x3399 => RockchipSoc::RK3399,
        0x3566 => RockchipSoc::RK3566,
        0x3568 => RockchipSoc::RK3568,
        0x3588 => RockchipSoc::RK3588,
        _ => RockchipSoc::Unknown,
    }
}

/// Get Qualcomm generation from device ID
fn qualcomm_gen_from_device_id(device_id: u16) -> QualcommGen {
    // Adreno 3xx: 0x0300-0x0308
    if (0x0300..=0x0308).contains(&device_id) {
        return QualcommGen::A3xx;
    }
    // Adreno 4xx: 0x0400-0x0404
    if (0x0400..=0x0404).contains(&device_id) {
        return QualcommGen::A4xx;
    }
    // Adreno 5xx: 0x0500-0x0505
    if (0x0500..=0x0505).contains(&device_id) {
        return QualcommGen::A5xx;
    }
    // Adreno 6xx: 0x0600+
    if (0x0600..=0x0620).contains(&device_id) {
        return QualcommGen::A6xx;
    }
    QualcommGen::Unknown
}

/// Get Allwinner SoC from device ID
fn allwinner_soc_from_device_id(device_id: u16) -> AllwinnerSoc {
    // Allwinner uses device tree / MMIO, not standard PCI
    // This is for completeness
    match device_id {
        _ => AllwinnerSoc::Unknown,
    }
}

/// Get StarFive SoC from device ID
fn starfive_soc_from_device_id(device_id: u16) -> StarfiveSoc {
    match device_id {
        0x0001 | 0x0002 => StarfiveSoc::JH7100,
        0x0003 | 0x0004 => StarfiveSoc::JH7110,
        _ => StarfiveSoc::Unknown,
    }
}

/// Find GPU by vendor ID
pub fn find_gpu_by_vendor(vendor_id: u16) -> Option<DiscoveredGpu> {
    discover_gpus()
        .into_iter()
        .find(|gpu| match gpu {
            DiscoveredGpu::Loongson { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Intel { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Amd { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Nvidia { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Zhaoxin { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Rockchip { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Qualcomm { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Allwinner { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Starfive { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::VirtioGpu { device, .. } => device.vendor_id == vendor_id,
            DiscoveredGpu::Unknown { device, .. } => device.vendor_id == vendor_id,
        })
}

// =====================================================================
// Driver Registration
// =====================================================================

/// GPU driver registration
pub struct GpuDriverRegistry {
    drivers: Vec<Box<dyn GpuDriver>>,
}

impl GpuDriverRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self { drivers: Vec::new() }
    }

    /// Register a GPU driver
    pub fn register(&mut self, driver: impl GpuDriver + 'static) {
        self.drivers.push(Box::new(driver));
    }

    /// Get all registered drivers
    pub fn drivers(&self) -> &[Box<dyn GpuDriver>] {
        &self.drivers
    }
}

impl Default for GpuDriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_format_bpp() {
        assert_eq!(PixelFormat::Bgra8888.bytes_per_pixel(), 4);
        assert_eq!(PixelFormat::Rgba8888.bytes_per_pixel(), 4);
        assert_eq!(PixelFormat::Bgr565.bytes_per_pixel(), 2);
        assert_eq!(PixelFormat::G8.bytes_per_pixel(), 1);
        assert_eq!(PixelFormat::Unknown.bytes_per_pixel(), 0);
    }

    #[test]
    fn test_pixel_format_name() {
        assert_eq!(PixelFormat::Bgra8888.name(), "BGRA 8:8:8:8");
        assert_eq!(PixelFormat::Bgr565.name(), "RGB 5:6:5");
        assert_eq!(PixelFormat::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_display_mode_stride() {
        let mode = DisplayMode::new(1920, 1080, 60, 32);
        // Stride should be 128-byte aligned
        assert_eq!(mode.stride() & !127, mode.stride());
        assert_eq!(mode.stride(), 1920 * 4);
    }

    #[test]
    fn test_display_mode_framebuffer_size() {
        let mode = DisplayMode::new(1024, 768, 60, 32);
        let expected_size = 1024 * 4 * 768;
        assert_eq!(mode.framebuffer_size(), expected_size as u64);
    }

    #[test]
    fn test_display_mode_from_bpp() {
        let mode_32 = DisplayMode::new(1920, 1080, 60, 32);
        assert_eq!(mode_32.format, PixelFormat::Bgra8888);

        let mode_16 = DisplayMode::new(640, 480, 60, 16);
        assert_eq!(mode_16.format, PixelFormat::Bgr565);

        let mode_24 = DisplayMode::new(800, 600, 60, 24);
        assert_eq!(mode_24.format, PixelFormat::Bgrx8888);
    }

    #[test]
    fn test_display_connector_name() {
        assert_eq!(DisplayConnector::AnalogVga.name(), "VGA");
        assert_eq!(DisplayConnector::DdiA.name(), "DDI-A");
        assert_eq!(DisplayConnector::Lvds.name(), "LVDS");
    }

    #[test]
    fn test_display_head_new() {
        let mode = DisplayMode::new(1024, 768, 60, 32);
        let head = DisplayHead::new(DisplayConnector::AnalogVga, mode);
        assert_eq!(head.connector, DisplayConnector::AnalogVga);
        assert_eq!(head.enabled, false);
        assert!(head.clone_of.is_none());
    }

    #[test]
    fn test_gpu_features_default() {
        let features = GpuFeatures::default();
        assert!(!features.has_2d_accel);
        assert!(!features.has_3d_accel);
        assert_eq!(features.max_texture_size, 2048);
    }

    #[test]
    fn test_gpu_error_constructors() {
        let err = GpuError::CmdUnderflow;
        let _ = GpuError::MemAccessError;
        let _ = GpuError::Timeout;
        let _ = GpuError::Unknown(0xFF);
        assert!(matches!(err, GpuError::CmdUnderflow));
    }

    #[test]
    fn test_intel_generation_detection() {
        // Sandy Bridge device IDs
        let gen = intel_generation_from_device_id(0x0102);
        assert_eq!(gen, IntelGeneration::SandyBridge);

        // Ivy Bridge device IDs
        let gen = intel_generation_from_device_id(0x0152);
        assert_eq!(gen, IntelGeneration::IvyBridge);
    }

    #[test]
    fn test_amd_family_detection() {
        // Polaris device IDs
        let family = amd_family_from_device_id(0x67C0);
        assert_eq!(family, AmdFamily::Polaris);

        // R600 device IDs
        let family = amd_family_from_device_id(0x9440);
        assert_eq!(family, AmdFamily::R600);
    }

    #[test]
    fn test_nvidia_arch_detection() {
        let arch = nvidia_arch_from_device_id(0x1E00); // Ampere
        assert_eq!(arch, NvidiaArch::Ampere);

        let arch = nvidia_arch_from_device_id(0x0600); // Tesla
        assert_eq!(arch, NvidiaArch::Tesla);
    }

    #[test]
    fn test_vendor_name() {
        assert_eq!(vendors::vendor_name(vendors::VENDOR_INTEL), "Intel");
        assert_eq!(vendors::vendor_name(vendors::VENDOR_AMD), "AMD");
        assert_eq!(vendors::vendor_name(0xFFFF), "Unknown");
    }

    #[test]
    fn test_is_gpu_vendor() {
        assert!(vendors::is_gpu_vendor(vendors::VENDOR_INTEL));
        assert!(vendors::is_gpu_vendor(vendors::VENDOR_AMD));
        assert!(vendors::is_gpu_vendor(vendors::VENDOR_NVIDIA));
        assert!(!vendors::is_gpu_vendor(0x1234));
    }

    #[test]
    fn test_edid_standard_timing_resolution() {
        use crate::drivers::video::edid::EdidStandardTiming;
        let timing = EdidStandardTiming {
            horz_pixels_div_8_minus_31: 40, // (40+31)*8 = 568
            refresh_minus_60_and_aspect: 0, // 4:3 ratio, 60Hz
        };
        assert_eq!(timing.horizontal_resolution(), 568);
        // 4:3 aspect ratio: 568 * 3/4 = 426
        assert_eq!(timing.vertical_resolution(), 426);
        assert_eq!(timing.refresh_rate(), 60);
    }

    #[test]
    fn test_edid_standard_timing_wide() {
        use crate::drivers::video::edid::EdidStandardTiming;
        let timing = EdidStandardTiming {
            horz_pixels_div_8_minus_31: 60, // (60+31)*8 = 728
            refresh_minus_60_and_aspect: 0x80, // 16:9 ratio, 60Hz
        };
        assert_eq!(timing.horizontal_resolution(), 728);
        // 16:9 aspect ratio: 728 * 9/16 = 409.5
        assert_eq!(timing.vertical_resolution(), 409);
        assert_eq!(timing.refresh_rate(), 60);
    }

    #[test]
    fn test_display_info_default() {
        let info = GpuFramebufferInfo::default();
        assert_eq!(info.width, 0);
        assert_eq!(info.height, 0);
        assert_eq!(info.format, PixelFormat::Unknown);
    }

    #[test]
    fn test_loongson_chip_detection() {
        let chip = loongson_chip_from_device_id(0x7A05);
        assert_eq!(chip, LoongsonChip::Ls7A);

        let chip = loongson_chip_from_device_id(0x7A0A);
        assert_eq!(chip, LoongsonChip::Ls3A5000);

        let chip = loongson_chip_from_device_id(0xFFFF);
        assert_eq!(chip, LoongsonChip::Unknown);
    }

    #[test]
    fn test_rockchip_soc_detection() {
        let soc = rockchip_soc_from_device_id(0x3399);
        assert_eq!(soc, RockchipSoc::RK3399);

        let soc = rockchip_soc_from_device_id(0x3588);
        assert_eq!(soc, RockchipSoc::RK3588);
    }
}
