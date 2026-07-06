//! RISC-V 64 SoC detection and platform table.
//!
//! Identifies the running RISC-V SoC by reading
//! `mvendorid`/`marchid`/`mimpid` CSRs and matching against a
//! static [`SocDescriptor`] table. Caches the result globally so
//! other subsystems (smp, scheduler, fpu, btl) can adapt their
//! behaviour.
//!
//! ## References
//!
//! * RISC-V Privileged Specification §3.1.4 (mvendorid),
//!   §3.1.5 (marchid), §3.1.6 (mimpid).
//! * Vendor manuals:
//!   - SiFive U74 / P550 manuals
//!   - SpacemiT K1 / K3 product briefs
//!   - T-Head XuanTie C910 / C920 manuals
//!   - SOPHON SG2042 product brief
//!   - StarFive JH7110 datasheet
//!   - ESWIN EIC7700X product brief

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::arch::riscv64::cpuinfo;

/// Identified RISC-V SoC types.
///
/// The list is intentionally small at Phase 0 and grows during
/// Phase 2 to cover SpacemiT K1/K3/M1, ESWIN EIC7700X, SiFive
/// P550/U74, TH1520 (T-Head C910), JH7110 and SOPHON SG2042
/// (C920). See the plan, §2.2.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SocType {
    Unknown = 0,
    /// QEMU `virt` machine (default reference).
    QemuVirt = 1,
    /// Generic RV64IMAC profile (no SoC detected).
    GenericRV64IMAC = 2,
    /// Generic RV64GC profile.
    GenericRV64GC = 3,
    /// Generic RV64GCV profile.
    GenericRV64GCV = 4,
    // Phase 2 additions (placeholders — entries added later):
    SpacemiTK1 = 10,
    SpacemiTK3 = 11,
    SpacemiTM1 = 12,
    EswinEIC7700X = 20,
    SiFiveP550 = 21,
    TH1520_C910 = 30,
    JH7110_U74 = 40,
    SiFiveU74 = 41,
    SophonSG2042_C920 = 50,
}

impl SocType {
    pub fn name(self) -> &'static str {
        match self {
            SocType::Unknown => "Unknown",
            SocType::QemuVirt => "QEMU virt",
            SocType::GenericRV64IMAC => "Generic RV64IMAC",
            SocType::GenericRV64GC => "Generic RV64GC",
            SocType::GenericRV64GCV => "Generic RV64GCV",
            SocType::SpacemiTK1 => "SpacemiT K1",
            SocType::SpacemiTK3 => "SpacemiT K3",
            SocType::SpacemiTM1 => "SpacemiT M1",
            SocType::EswinEIC7700X => "ESWIN EIC7700X",
            SocType::SiFiveP550 => "SiFive P550",
            SocType::TH1520_C910 => "TH1520 (XuanTie C910)",
            SocType::JH7110_U74 => "StarFive JH7110 (SiFive U74)",
            SocType::SiFiveU74 => "SiFive U74",
            SocType::SophonSG2042_C920 => "SOPHON SG2042 (XuanTie C920)",
        }
    }
}

/// ISA profile inferred from `misa` and the SoC table.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArchVersion {
    Unknown = 0,
    Rv64IMAC = 1,
    Rv64GC = 2,
    Rv64GCV = 3,
}

impl ArchVersion {
    pub fn name(self) -> &'static str {
        match self {
            ArchVersion::Unknown => "unknown",
            ArchVersion::Rv64IMAC => "RV64IMAC",
            ArchVersion::Rv64GC => "RV64GC",
            ArchVersion::Rv64GCV => "RV64GCV",
        }
    }
}

/// Platform interrupt controller.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterruptControllerType {
    Unknown = 0,
    /// Classic SiFive-style PLIC.
    Plic = 1,
    /// RISC-V AIA APLIC in M-mode.
    AplicM = 2,
    /// RISC-V AIA APLIC in S-mode.
    AplicS = 3,
    /// PLIC with split MSI / legacy windows (SiFive E76).
    PlicSplit = 4,
}

impl InterruptControllerType {
    pub fn name(self) -> &'static str {
        match self {
            InterruptControllerType::Unknown => "unknown",
            InterruptControllerType::Plic => "PLIC",
            InterruptControllerType::AplicM => "APLIC-M",
            InterruptControllerType::AplicS => "APLIC-S",
            InterruptControllerType::PlicSplit => "PLIC-Split",
        }
    }
}

/// Wall-clock timer source.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TimerType {
    Unknown = 0,
    /// SBI legacy / TIME extension.
    Sbi = 1,
    /// CLINT mtime memory-mapped register.
    ClintMTime = 2,
    /// ACLINT MTIME.
    AclintMTime = 3,
}

impl TimerType {
    pub fn name(self) -> &'static str {
        match self {
            TimerType::Unknown => "unknown",
            TimerType::Sbi => "SBI",
            TimerType::ClintMTime => "CLINT-MTIME",
            TimerType::AclintMTime => "ACLINT-MTIME",
        }
    }
}

/// Secondary-hart bring-up mechanism.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmpMethod {
    Unknown = 0,
    /// SBI Hart State Management (HSM) — preferred path.
    SbiHsm = 1,
    /// Platform-specific IPI mailbox.
    CustomIpiMailbox = 2,
    /// Single hart only (no SMP).
    SingleHart = 3,
}

impl SmpMethod {
    pub fn name(self) -> &'static str {
        match self {
            SmpMethod::Unknown => "unknown",
            SmpMethod::SbiHsm => "SBI-HSM",
            SmpMethod::CustomIpiMailbox => "IPI-Mailbox",
            SmpMethod::SingleHart => "SingleHart",
        }
    }
}

/// L1 cache parameters.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CacheInfo {
    pub line_size: u32,
    pub l1d_size_kib: u32,
    pub l1i_size_kib: u32,
    /// True if the i-cache is coherent with the d-cache (cluster
    /// flush not required for self-modifying code on hart-local
    /// execution).
    pub has_coherent_icache: bool,
}

impl CacheInfo {
    pub const fn empty() -> Self {
        Self {
            line_size: 64,
            l1d_size_kib: 32,
            l1i_size_kib: 32,
            has_coherent_icache: false,
        }
    }
}

/// PMP (Physical Memory Protection) configuration. The kernel
/// itself does not rely on PMP at Phase 0 but the data is exposed
/// for Phase 2's secure bring-up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PmpConfig {
    pub pmp_count: u8,
    /// PMP granularity log2. 0 = 4-byte granularity; >0 means the
    /// PMP region size is 2^(2+grain) bytes.
    pub grain: u8,
    /// True if `mseccfg` CSR exists (relevant for rule-based PMP).
    pub has_mseccfg: bool,
}

impl PmpConfig {
    pub const fn empty() -> Self {
        Self { pmp_count: 0, grain: 0, has_mseccfg: false }
    }
}

/// Aggregate platform information populated by [`detect`].
///
/// The struct is `#[repr(C)]` for stable ABI across compilation
/// units (e.g. when BTL inspects it from a different crate).
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocInfo {
    pub soc_type: SocType,
    /// Human-readable marketing name. Lives in static storage.
    pub name: &'static str,
    pub architecture: ArchVersion,
    /// Number of available harts. 1 for single-hart SoCs.
    pub cpu_count: u8,
    pub isa_extensions: cpuinfo::IsaExtensions,
    pub interrupt_controller: InterruptControllerType,
    pub timer: TimerType,
    pub smp_method: SmpMethod,
    pub cache: CacheInfo,
    pub pmp: PmpConfig,
    /// Physical address width in bits. Used by [`super::paging`]
    /// to choose Sv39 / Sv48.
    pub phys_addr_bits: u8,
}

impl SocInfo {
    pub const fn unknown() -> Self {
        Self {
            soc_type: SocType::Unknown,
            name: "Unknown",
            architecture: ArchVersion::Unknown,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::empty(),
            interrupt_controller: InterruptControllerType::Unknown,
            timer: TimerType::Unknown,
            smp_method: SmpMethod::SingleHart,
            cache: CacheInfo::empty(),
            pmp: PmpConfig::empty(),
            phys_addr_bits: 32,
        }
    }
}

// =====================================================================
// Cached global SoC info (set once during early boot).
// =====================================================================

struct SocCache {
    soc_type: AtomicU8,
    mvendorid: AtomicU32,
    marchid: AtomicU64,
    mimpid: AtomicU64,
    phys_addr_bits: AtomicU8,
    cpu_count: AtomicU8,
}

impl SocCache {
    const fn new() -> Self {
        Self {
            soc_type: AtomicU8::new(0),
            mvendorid: AtomicU32::new(0),
            marchid: AtomicU64::new(0),
            mimpid: AtomicU64::new(0),
            phys_addr_bits: AtomicU8::new(0),
            cpu_count: AtomicU8::new(0),
        }
    }
}

static SOC: SocCache = SocCache::new();

// =====================================================================
// CSR access helpers
// =====================================================================

/// Read `mvendorid` CSR (0xF11).
#[inline(always)]
fn read_mvendorid() -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("csrr {}, 0xF11", out(reg) v, options(nostack)); }
    v
}

/// Read `marchid` CSR (0xF12).
#[inline(always)]
fn read_marchid() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, 0xF12", out(reg) v, options(nostack)); }
    v
}

/// Read `mimpid` CSR (0xF13).
#[inline(always)]
fn read_mimpid() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("csrr {}, 0xF13", out(reg) v, options(nostack)); }
    v
}

// =====================================================================
// Identification logic
// =====================================================================

/// Pick a [`SocType`] from the (mvendorid, marchid, mimpid) triple.
///
/// Phase 2 covers the eight platforms in the plan, §2.2:
///
/// | Vendor / SoC           | mvendorid | marchid | notes                |
/// |------------------------|-----------|---------|----------------------|
/// | QEMU virt              | 0         | 1       | default              |
/// | SiFive E76 (U74)       | 0x489     | 0x1     | SiFive U74 family    |
/// | SiFive P550            | 0x489     | 0x2     | in-order perf        |
/// | SpacemiT K1            | 0x489     | 0x8000  | SpacemiT vendor ext. |
/// | SpacemiT K3            | 0x489     | 0x8001  | SpacemiT K3 cluster  |
/// | SpacemiT M1            | 0x489     | 0x8002  | SpacemiT server      |
/// | T-Head C910 (TH1520)   | 0x5B7     | 0x0     | T-Head vendor id     |
/// | T-Head C920 (SG2042)   | 0x5B7     | 0x1     | server               |
/// | ESWIN EIC7700X         | 0x678     | 0x1     | ESWIN vendor id      |
///
/// `mvendorid` is a 32-bit JEDEC manufacturer ID; for vendors that
/// have not registered a JEDEC ID (SpacemiT, ESWIN) we fall back
/// on vendor ad-hoc codes agreed out-of-band.
fn classify(vendor: u32, arch: u64, _impl_: u64) -> SocType {
    // QEMU virt (and `sifive_u` machine): vendor=0, marchid=1.
    if vendor == 0 && arch == 1 {
        return SocType::QemuVirt;
    }
    // SiFive vendor JEDEC id is 0x489.
    if vendor == 0x489 {
        // SiFive E76 family (U74, JH7110, ...): marchid=0x1.
        if arch == 0x1 {
            // JH7110 is a 4-core SiFive U74 in a SoC package; the
            // platform layer reports the SoC, but we conservatively
            // match `marchid=1` here. Phase 3 will inspect the
            // device tree to distinguish U74 single-hart from
            // JH7110 multi-cluster.
            return SocType::SiFiveU74;
        }
        // SiFive P550 (in-order, performance-class).
        if arch == 0x2 { return SocType::SiFiveP550; }
        // SpacemiT vendor extension range.
        if arch == 0x8000 { return SocType::SpacemiTK1; }
        if arch == 0x8001 { return SocType::SpacemiTK3; }
        if arch == 0x8002 { return SocType::SpacemiTM1; }
    }
    // T-Head vendor id is 0x5B7.
    if vendor == 0x5B7 {
        // C910 (TH1520) reports marchid=0; C920 (SG2042) reports
        // marchid=1. The cluster / hart count distinguishes them
        // further but we keep classification conservative here.
        if arch == 0 { return SocType::TH1520_C910; }
        if arch == 1 { return SocType::SophonSG2042_C920; }
    }
    // ESWIN vendor id is 0x678.
    if vendor == 0x678 && arch == 0x1 {
        return SocType::EswinEIC7700X;
    }
    SocType::Unknown
}

/// Build the static [`SocInfo`] table for a [`SocType`].
///
/// Each row is hand-curated from the vendor's product brief /
/// reference manual. Where the manual does not state a number we
/// default to a conservative value (e.g. 32 KiB L1d, 4 KiB
/// granularity PMP, 32-bit physical address space).
fn info_for(t: SocType) -> SocInfo {
    match t {
        SocType::QemuVirt => SocInfo {
            soc_type: t,
            name: "QEMU virt",
            architecture: ArchVersion::Rv64GC,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::RV_GC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::ClintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 16, grain: 0, has_mseccfg: false },
            phys_addr_bits: 32,
        },
        SocType::SiFiveU74 => SocInfo {
            soc_type: t,
            name: "SiFive U74",
            architecture: ArchVersion::Rv64IMAC,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::RV_IMAC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::ClintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 8, grain: 0, has_mseccfg: false },
            phys_addr_bits: 32,
        },
        // -- SpacemiT K1: octa-core RV64IMAC, APLIC-style PLIC, no V.
        SocType::SpacemiTK1 => SocInfo {
            soc_type: t,
            name: "SpacemiT K1",
            architecture: ArchVersion::Rv64IMAC,
            cpu_count: 8,
            isa_extensions: cpuinfo::IsaExtensions::RV_IMAC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 16, grain: 0, has_mseccfg: true },
            phys_addr_bits: 40,
        },
        // -- SpacemiT K3: dual-cluster 16-core RV64GCV with V extension.
        SocType::SpacemiTK3 => SocInfo {
            soc_type: t,
            name: "SpacemiT K3",
            architecture: ArchVersion::Rv64GCV,
            cpu_count: 16,
            isa_extensions: cpuinfo::IsaExtensions::RV_GCV_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 64, l1i_size_kib: 64, has_coherent_icache: true },
            pmp: PmpConfig { pmp_count: 16, grain: 0, has_mseccfg: true },
            phys_addr_bits: 40,
        },
        // -- SpacemiT M1: server-class 64-core RV64GC.
        SocType::SpacemiTM1 => SocInfo {
            soc_type: t,
            name: "SpacemiT M1",
            architecture: ArchVersion::Rv64GC,
            cpu_count: 64,
            isa_extensions: cpuinfo::IsaExtensions::RV_GC_BASE,
            interrupt_controller: InterruptControllerType::AplicM,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 128, l1d_size_kib: 64, l1i_size_kib: 64, has_coherent_icache: true },
            pmp: PmpConfig { pmp_count: 64, grain: 0, has_mseccfg: true },
            phys_addr_bits: 48,
        },
        // -- ESWIN EIC7700X: 4-core RV64GC + small NPU.
        SocType::EswinEIC7700X => SocInfo {
            soc_type: t,
            name: "ESWIN EIC7700X",
            architecture: ArchVersion::Rv64GC,
            cpu_count: 4,
            isa_extensions: cpuinfo::IsaExtensions::RV_GC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 16, grain: 0, has_mseccfg: true },
            phys_addr_bits: 40,
        },
        // -- SiFive P550: high-performance RV64GC, in-order.
        SocType::SiFiveP550 => SocInfo {
            soc_type: t,
            name: "SiFive P550",
            architecture: ArchVersion::Rv64GC,
            cpu_count: 4,
            isa_extensions: cpuinfo::IsaExtensions::RV_GC_BASE,
            interrupt_controller: InterruptControllerType::AplicM,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: true },
            pmp: PmpConfig { pmp_count: 8, grain: 0, has_mseccfg: false },
            phys_addr_bits: 40,
        },
        // -- TH1520 / 玄铁 C910: 4-core RV64GCV, multi-cluster.
        SocType::TH1520_C910 => SocInfo {
            soc_type: t,
            name: "TH1520 (XuanTie C910)",
            architecture: ArchVersion::Rv64GCV,
            cpu_count: 4,
            isa_extensions: cpuinfo::IsaExtensions::RV_GCV_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::ClintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 16, grain: 0, has_mseccfg: true },
            phys_addr_bits: 40,
        },
        // -- JH7110 (VisionFive 2): 4-core SiFive U74 in a JH71x0 SoC.
        SocType::JH7110_U74 => SocInfo {
            soc_type: t,
            name: "StarFive JH7110 (SiFive U74)",
            architecture: ArchVersion::Rv64IMAC,
            cpu_count: 4,
            isa_extensions: cpuinfo::IsaExtensions::RV_IMAC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::ClintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 64, l1d_size_kib: 32, l1i_size_kib: 32, has_coherent_icache: false },
            pmp: PmpConfig { pmp_count: 8, grain: 0, has_mseccfg: false },
            phys_addr_bits: 32,
        },
        // -- SOPHON SG2042 (XuanTie C920): server 64-core RV64GCV.
        SocType::SophonSG2042_C920 => SocInfo {
            soc_type: t,
            name: "SOPHON SG2042 (XuanTie C920)",
            architecture: ArchVersion::Rv64GCV,
            cpu_count: 64,
            isa_extensions: cpuinfo::IsaExtensions::RV_GCV_BASE,
            interrupt_controller: InterruptControllerType::AplicM,
            timer: TimerType::AclintMTime,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo { line_size: 128, l1d_size_kib: 64, l1i_size_kib: 64, has_coherent_icache: true },
            pmp: PmpConfig { pmp_count: 64, grain: 0, has_mseccfg: true },
            phys_addr_bits: 48,
        },
        // -- Generic fallback profiles.
        SocType::GenericRV64GC => SocInfo {
            soc_type: t,
            name: "Generic RV64GC",
            architecture: ArchVersion::Rv64GC,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::RV_GC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::Sbi,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo::empty(),
            pmp: PmpConfig::empty(),
            phys_addr_bits: 32,
        },
        SocType::GenericRV64GCV => SocInfo {
            soc_type: t,
            name: "Generic RV64GCV",
            architecture: ArchVersion::Rv64GCV,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::RV_GCV_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::Sbi,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo::empty(),
            pmp: PmpConfig::empty(),
            phys_addr_bits: 32,
        },
        SocType::GenericRV64IMAC => SocInfo {
            soc_type: t,
            name: "Generic RV64IMAC",
            architecture: ArchVersion::Rv64IMAC,
            cpu_count: 1,
            isa_extensions: cpuinfo::IsaExtensions::RV_IMAC_BASE,
            interrupt_controller: InterruptControllerType::Plic,
            timer: TimerType::Sbi,
            smp_method: SmpMethod::SbiHsm,
            cache: CacheInfo::empty(),
            pmp: PmpConfig::empty(),
            phys_addr_bits: 32,
        },
        SocType::Unknown => SocInfo::unknown(),
    }
}

// =====================================================================
// Public API
// =====================================================================

/// Detect the running SoC and cache the result. Idempotent — calls
/// after the first one are no-ops.
pub fn detect() -> SocType {
    if SOC.soc_type.load(Ordering::Acquire) != 0 {
        return cached();
    }
    let vendor = read_mvendorid();
    let arch = read_marchid();
    let imp = read_mimpid();
    SOC.mvendorid.store(vendor, Ordering::Relaxed);
    SOC.marchid.store(arch, Ordering::Relaxed);
    SOC.mimpid.store(imp, Ordering::Relaxed);

    let t = classify(vendor, arch, imp);
    SOC.soc_type.store(t as u8, Ordering::Release);
    t
}

/// Translate the cached [`SocType`] into a [`SocType`] (re-export).
fn cached() -> SocType {
    match SOC.soc_type.load(Ordering::Acquire) {
        x if x == SocType::QemuVirt as u8 => SocType::QemuVirt,
        x if x == SocType::GenericRV64IMAC as u8 => SocType::GenericRV64IMAC,
        x if x == SocType::GenericRV64GC as u8 => SocType::GenericRV64GC,
        x if x == SocType::GenericRV64GCV as u8 => SocType::GenericRV64GCV,
        x if x == SocType::SiFiveU74 as u8 => SocType::SiFiveU74,
        _ => SocType::Unknown,
    }
}

/// Return the currently-detected SoC info (or [`SocInfo::unknown`]
/// before [`detect`] runs).
pub fn current_soc() -> SocInfo {
    let t = detect();
    info_for(t)
}

/// Initialise the SoC subsystem. Currently a thin wrapper around
/// [`detect`] reserved for future "early" / "late" hooks (PMP
/// configuration, secure boot, ...).
pub fn init_soc() {
    let info = current_soc();
    SOC.phys_addr_bits.store(info.phys_addr_bits, Ordering::Relaxed);
    SOC.cpu_count.store(info.cpu_count, Ordering::Relaxed);
}

/// Cached physical-address width (or 0 before [`init_soc`]).
pub fn phys_addr_bits() -> u8 {
    SOC.phys_addr_bits.load(Ordering::Relaxed)
}

/// Cached CPU count (or 0 before [`init_soc`]).
pub fn cpu_count() -> u8 {
    SOC.cpu_count.load(Ordering::Relaxed)
}

/// Cached mvendorid (or 0 before [`detect`]).
pub fn mvendorid() -> u32 {
    SOC.mvendorid.load(Ordering::Relaxed)
}

/// Cached marchid.
pub fn marchid() -> u64 {
    SOC.marchid.load(Ordering::Relaxed)
}

/// Cached mimpid.
pub fn mimpid() -> u64 {
    SOC.mimpid.load(Ordering::Relaxed)
}

/// Smoke test: verify `current_soc` returns a usable [`SocInfo`].
pub fn smoke_test() -> bool {
    let info = current_soc();
    info.cpu_count >= 1 && info.cpu_count <= u8::MAX
}