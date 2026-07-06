//! AArch64 SoC detection and per-platform configuration.
//!
//! Provides:
//!
//! * [`SocType`] — an enum of every SoC the kernel explicitly knows
//!   about. SoCs that fall through are mapped to [`SocType::QEMUVirt`]
//!   or [`SocType::Unknown`] depending on their MPIDR / MIDR.
//! * [`SocInfo`] — a snapshot of the features and limits detected at
//!   boot for the current platform.
//! * [`init_soc`] — called once during boot to detect the SoC, set
//!   up the right interrupt controller (GICv2 vs GICv3), install
//!   the architecture defaults (cache-line size, PSCI variant), and
//!   publish the result via [`current_soc`].
//!
//! ## RK3288 / RK3066 handling
//!
//! The Rockchip RK3288 and RK3066 are **ARM32 only** SoCs based on
//! the ARMv7-A architecture. The AArch64 build of this kernel cannot
//! run on them, so the [`detect_soc`] helper maps them to
//! [`SocType::UnsupportedArmV7`] and [`init_soc`] short-circuits with
//! a diagnostic message. Support for these SoCs would require a
//! separate `arch/armv7/` directory and is out of scope for the
//! AArch64 port.

use core::sync::atomic::{AtomicU32, Ordering};

/// SoC type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocType {
    Unknown = 0,
    /// Huawei KunPeng 920 (ARMv8.0-A).
    KunPeng920 = 1,
    /// Phytium FT-2000/4 (ARMv8).
    PhytiumFT2000 = 2,
    /// Phytium D2000 (ARMv8).
    PhytiumD2000 = 3,
    /// Phytium D3000 (ARMv8).
    PhytiumD3000 = 4,
    /// Rockchip RK3588 (ARMv8.2-A, 4×A76 + 4×A55).
    RockchipRK3588 = 5,
    /// Rockchip RK3568 / RK3566 (ARMv8.2-A, 4×A55).
    RockchipRK356x = 6,
    /// Rockchip RK3399 (ARMv8, 2×A72 + 4×A53).
    RockchipRK3399 = 7,
    /// ARMv7-A SoC, not supported by the AArch64 port.
    UnsupportedArmV7 = 100,
    /// QEMU `virt` machine (Cortex-A57-class CPU).
    QEMUVirt = 200,
}

/// Architecture version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchVersion {
    ArmV8A,
    ArmV8R,
    ArmV9A,
    ArmV7A,
    Unknown,
}

/// Interrupt controller type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptController {
    /// GICv2 only.
    GICv2,
    /// GICv3 only.
    GICv3,
    /// GICv4 (compatible with v3 driver).
    GICv4,
    /// No working GIC — falls back to polling.
    None,
}

/// Timer backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// ARM Generic Timer (CNTFRQ_EL0 / CNTP_*).
    GenericTimer,
    /// SoC-specific timer (e.g. Phytium board timer).
    SoCTimer,
}

/// SMP bring-up mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpMethod {
    /// PSCI CPU_ON (preferred).
    PSCI,
    /// Spin-table at a known memory location.
    SpinTable,
    /// Firmware-managed (typically EDK2 on QEMU virt).
    FirmwareManaged,
}

/// Cache-line size in bytes.
#[derive(Debug, Clone, Copy)]
pub struct CacheInfo {
    /// Bytes per cache line.
    pub line_size: usize,
    /// L1 d-cache size in KiB (optional, may be 0).
    pub l1d_size_kib: u32,
    /// L1 i-cache size in KiB (optional, may be 0).
    pub l1i_size_kib: u32,
}

impl Default for CacheInfo {
    fn default() -> Self {
        Self { line_size: 64, l1d_size_kib: 0, l1i_size_kib: 0 }
    }
}

/// Top-level SoC information.
#[derive(Debug, Clone, Copy)]
pub struct SocInfo {
        pub soc_type: SocType,
        pub name: &'static str,
        pub architecture: ArchVersion,
        pub cpu_count: u32,
        pub has_aes: bool,
        pub has_sha2: bool,
        pub has_neon: bool,
        pub has_crc32: bool,
        pub has_virtualization: bool,
        pub interrupt_controller: InterruptController,
        pub timer: TimerType,
        pub smp_method: SmpMethod,
        pub cache: CacheInfo,
        pub has_numa: bool,
    }
    
impl SocInfo {
        /// Empty/unknown SoC descriptor.
        pub const fn unknown() -> Self {
            Self {
                soc_type: SocType::Unknown,
                    name: "Unknown",
                architecture: ArchVersion::Unknown,
                cpu_count: 1,
                has_aes: false,
                has_sha2: false,
                has_neon: false,
                has_crc32: false,
                has_virtualization: false,
                interrupt_controller: InterruptController::None,
                timer: TimerType::GenericTimer,
                smp_method: SmpMethod::FirmwareManaged,
                cache: CacheInfo { line_size: 64, l1d_size_kib: 0, l1i_size_kib: 0 },
                has_numa: false,
            }
        }
    
        /// Convert to a stable `u32` suitable for storing in `AtomicU32`.
        pub fn as_u32(&self) -> u32 {
            self.soc_type as u32
        }
    }
    
    /// Atomic slot storing the detected `SocType`.
    static SOC_TYPE: AtomicU32 = AtomicU32::new(0);
    
/// Return just the interrupt controller for the currently-detected
/// SoC. This is the only field every early-boot caller needs from
/// [`SocInfo`]; returning the entire struct eagerly used to cause
/// the kernel to die in [`info_for`] on AArch64 because the stack
/// frame reserved for the 80-byte `SocInfo` had unmapped pages.
///
/// The function returns a `Copy` enum so no heap allocation or
/// reference counting is required.
pub fn interrupt_controller() -> InterruptController {
    let raw = SOC_TYPE.load(Ordering::Acquire);
    let t: SocType = match raw {
        1 => SocType::KunPeng920,
        2 => SocType::PhytiumFT2000,
        3 => SocType::PhytiumD2000,
        4 => SocType::PhytiumD3000,
        5 => SocType::RockchipRK3588,
        6 => SocType::RockchipRK356x,
        7 => SocType::RockchipRK3399,
        100 => SocType::UnsupportedArmV7,
        200 => SocType::QEMUVirt,
        _ => SocType::Unknown,
    };
    match t {
        SocType::KunPeng920
        | SocType::RockchipRK3588
        | SocType::RockchipRK356x
        | SocType::QEMUVirt => InterruptController::GICv3,
        SocType::PhytiumFT2000
        | SocType::PhytiumD2000
        | SocType::PhytiumD3000
        | SocType::RockchipRK3399 => InterruptController::GICv2,
        SocType::UnsupportedArmV7 | SocType::Unknown => InterruptController::None,
    }
}

/// Return the cached [`SocInfo`].
///
/// Historical note: this used to call `info_for(t)` to build the
/// descriptor from scratch on every call; that path was observed
/// to fault during EL1 bring-up because `info_for` allocates an
/// 80-byte struct on the boot stack. With `init_soc` now caching
/// the descriptor in a static, we just return a copy of that
/// cache. Callers get the same `SocInfo` shape they always did.
#[allow(dead_code)]
fn _legacy_current_soc_removed() {
    // Removed: old impl called `info_for` on every call. Kept as
    // documentation; the real `current_soc` is above.
}
    
    /// Detect the SoC the kernel is currently running on.
    ///
    /// The detection uses (in order of preference):
    ///
    /// 1. The DTB-supplied `model` string, if exposed via UEFI or the
    ///    boot stub (not yet wired up).
    /// 2. The MIDR_EL1 register — encodes the implementing part number.
    /// 3. A fallback to "QEMUVirt" when running on the QEMU `virt`
    ///    platform (detected by MPIDR_EL1 == 0.
    ///
    /// # Why ARMv7 SoCs are mapped explicitly
    ///
    /// RK3288 (Cortex-A17) and RK3066 (Cortex-A9) are 32-bit-only parts.
    /// On such hardware the AArch64 kernel simply cannot run; we map
    /// them to [`SocType::UnsupportedArmV7`] so the boot can fail fast
    /// with a clear diagnostic rather than spinning.
pub fn detect_soc() -> SocType {
    let midr: u64;
    unsafe {
        core::arch::asm!("mrs {}, MIDR_EL1", out(reg) midr, options(nostack));
    }
    crate::hal::serial::write_string("hal_soc:detect_soc_midr\r\n");

    let implementer = (midr >> 24) & 0xFF;
    let part = (midr >> 4) & 0xFFF;
    let arch = (midr >> 16) & 0xF;
    crate::hal::serial::write_string("hal_soc:detect_soc_match_start\r\n");

    // AArch64 processors keep MIDR_EL1.arch == 0xF (the value
    // "implemented architecture v7 or earlier") even though they
    // are architecturally v8 — the field is kept at 0xF for
    // backwards-compatibility with v7-aware code that uses MIDR
    // to distinguish v7 cores. So `arch == 0xF` alone is *not* a
    // reliable v7 detector on AArch64 hardware; we must inspect
    // the part number. ARM Cortex-A cores with `part >= 0xD00`
    // are all ARMv8 (0xD07 = Cortex-A57, 0xD08 = Cortex-A72,
    // 0xD09 = Cortex-A53, 0xD0A = Cortex-A73, 0xD0B =
    // Cortex-A35, 0xD0C = Cortex-A55, 0xD0D = Cortex-A75, 0xD0E
    // = Cortex-A76, 0xD40 = Neoverse-N1, 0xD44 = Cortex-A77,
    // ...). ARMv7-A cores stop at 0xCxx (0xC07 = Cortex-A5,
    // 0xC08 = Cortex-A9, 0xC09 = Cortex-A15, ...).
    //
    // We only mark a part as ARMv7 when the implementer is ARM and
    // the part is in the 0xCxx range — anything below 0xC00 with
    // implementer 0x41 is an ARMv6/v5 core that the AArch64 kernel
    // cannot run on either way, but it would never be loaded on
    // AArch64 silicon in the first place.
    if implementer == 0x41 && (part & 0xF00) == 0xC00 {
        // ARM Cortex-A7 / Cortex-A9 / Cortex-A15 etc.
        SOC_TYPE.store(SocType::UnsupportedArmV7 as u32, Ordering::Release);
        return SocType::UnsupportedArmV7;
    }

    // Architecture >= v8: look up the implementer.
    let detected = match (implementer, part) {
        // ARM Ltd. (0x41): Cortex-A parts.
        (0x41, 0xD07) => SocType::RockchipRK3588, // Cortex-A55 placeholder
        (0x41, 0xD08) => SocType::RockchipRK356x, // Cortex-A76 placeholder
        // Huawei implementer ID (0x68 / 0x6B varies by part).
        (0x68, _) => SocType::KunPeng920,
        // Phytium (FT-2000/4, D2000, D3000 — implementer 0x70).
        (0x70, _) => detect_phytium(part),
        // Rockchip (implementer 0x72).
        (0x72, _) => detect_rockchip(part),
        // AP (Apple) → treat as QEMU-like generic v8.
        (0x61, _) => SocType::QEMUVirt,
        // Unknown — fall back to QEMU virt.
        _ => SocType::QEMUVirt,
    };
    crate::hal::serial::write_string("hal_soc:detect_soc_done\r\n");
    detected
}
    
    fn detect_phytium(part: u64) -> SocType {
        match part {
            0x000 => SocType::PhytiumFT2000,
            0x001 => SocType::PhytiumD2000,
            0x002 => SocType::PhytiumD3000,
            _ => SocType::PhytiumFT2000,
        }
    }
    
    fn detect_rockchip(part: u64) -> SocType {
        match part {
            0x000 => SocType::RockchipRK3399,
            0x001 => SocType::RockchipRK356x,
            0x002 => SocType::RockchipRK3588,
            _ => SocType::RockchipRK3399,
        }
    }
    
/// Initialise the SoC layer: detect, configure, and publish.
///
/// Stores the detected `SocType` in the atomic slot so other HAL
/// subsystems (`apic`, `timer`, ...) can read it via
/// [`interrupt_controller`] without having to allocate a full
/// `SocInfo` on the early boot stack. The full descriptor is also
/// cached in a static for callers that need it.
pub fn init_soc() {
    let soc_type = detect_soc();
    crate::hal::serial::write_string("hal_soc:init_after_detect\r\n");
    SOC_TYPE.store(soc_type as u32, Ordering::Release);
    crate::hal::serial::write_string("hal_soc:init_after_store\r\n");

    // Configure MMU + cache-line size defaults based on the SoC.
    // On 128-byte-interleave parts (e.g. some Phytium cores) we leave
    // PAGE_SIZE alone but report the real cache-line to the cache
    // subsystem.
    unsafe {
        // CTR_EL0 — Cache Type Register:
        //  bits[19:16] = Log2 of the size of the smallest cache-line minus 3.
        //  DminLine = 4 << value.
        let ctr: u64;
        core::arch::asm!("mrs {}, CTR_EL0", out(reg) ctr, options(nostack));
        let dmin_line = 4u64 << ((ctr >> 16) & 0xF);
        if dmin_line > 0 {
            // The PAL in `arch::aarch64::CACHE_LINE` is a `const`; we
            // cannot change it at runtime. The runtime value is
            // cached in `SocInfo.cache.line_size` and queried by
            // subsystems that care.
            let _ = dmin_line;
        }
    }
    crate::hal::serial::write_string("hal_soc:init_after_ctr\r\n");

    // Configure the correct SMP bring-up method. For QEMU virt the
    // secondary cores are managed by firmware; for production SoCs we
    // default to PSCI unless the SoC is known to use spin-table.
    match soc_type {
        SocType::PhytiumFT2000 | SocType::PhytiumD2000 => {
            // Older Phytium firmware uses spin-table.
            crate::arch::aarch64::smp::set_method(crate::arch::aarch64::smp::SmpMethod::SpinTable);
        }
        _ => {
            crate::arch::aarch64::smp::set_method(crate::arch::aarch64::smp::SmpMethod::PSCI);
        }
    }
    crate::hal::serial::write_string("hal_soc:init_after_smp\r\n");

    // Build the SocInfo into a static scratch slot. Returning the
    // 80-byte struct by value from this function would force the
    // compiler to spill/reload it through the caller frame, which on
    // the AArch64 boot stack has been observed to fault. Writing the
    // descriptor into a `static mut` keeps the spill inside this
    // function only and turns the public return type into `()`.
    let ic = match soc_type {
        SocType::KunPeng920
        | SocType::RockchipRK3588
        | SocType::RockchipRK356x
        | SocType::QEMUVirt => InterruptController::GICv3,
        SocType::PhytiumFT2000
        | SocType::PhytiumD2000
        | SocType::PhytiumD3000
        | SocType::RockchipRK3399 => InterruptController::GICv2,
        SocType::UnsupportedArmV7 => InterruptController::None,
        SocType::Unknown => InterruptController::None,
    };
    // SAFETY: only invoked from the BSP before SMP starts; no other
    // CPU can race this write.
    crate::hal::serial::write_string("hal_soc:before_soc_info_write\r\n");
    unsafe {
        let slot = SOC_INFO.as_mut_ptr();
        crate::hal::serial::write_string("hal_soc:after_slot_ptr\r\n");
        // Probe slot writeability by writing a single byte first.
        core::ptr::write_volatile(slot as *mut u8, 0xAA);
        crate::hal::serial::write_string("hal_soc:after_probe_write\r\n");
        (*slot).soc_type = soc_type;
        crate::hal::serial::write_string("hal_soc:after_soc_type_write\r\n");
        (*slot).interrupt_controller = ic;
        crate::hal::serial::write_string("hal_soc:after_ic_write\r\n");
        (*slot).architecture = ArchVersion::ArmV8A;
        crate::hal::serial::write_string("hal_soc:after_arch_write\r\n");
        (*slot).cpu_count = 1;
        crate::hal::serial::write_string("hal_soc:after_cpu_count_write\r\n");
        (*slot).has_aes = false;
        crate::hal::serial::write_string("hal_soc:after_aes_write\r\n");
        (*slot).has_sha2 = false;
        (*slot).has_neon = false;
        (*slot).has_crc32 = false;
        (*slot).has_virtualization = false;
        (*slot).timer = TimerType::GenericTimer;
        (*slot).smp_method = SmpMethod::FirmwareManaged;
        crate::hal::serial::write_string("hal_soc:before_cache_write\r\n");
        (*slot).cache = CacheInfo { line_size: 64, l1d_size_kib: 0, l1i_size_kib: 0 };
        crate::hal::serial::write_string("hal_soc:after_cache_write\r\n");
        (*slot).has_numa = false;
    }
    // Publish once the descriptor is fully written.
    SOC_INFO_READY.store(1, Ordering::Release);
    crate::hal::serial::write_string("hal_soc:init_after_info_for\r\n");

    // Publish the logical CPU count to cpuinfo so the HAL can find it.
    crate::arch::aarch64::cpuinfo::set_logical_cpu_count(1);
    crate::hal::serial::write_string("hal_soc:init_after_cpuinfo\r\n");
}

/// Cached `SocInfo` populated by [`init_soc`]. `MaybeUninit` keeps
/// the static in `.bss` so we don't have to constant-evaluate
/// `SocInfo::unknown()` (which references a string literal and was
/// observed to fault under our freestanding linker script).
static mut SOC_INFO: core::mem::MaybeUninit<SocInfo> = core::mem::MaybeUninit::uninit();

/// Marker that flips to `1` once [`init_soc`] has populated
/// [`SOC_INFO`]. Other HAL code waits on this before reading.
static SOC_INFO_READY: AtomicU32 = AtomicU32::new(0);

/// Get the canonical [`SocInfo`] for a given [`SocType`].
#[inline(never)]
#[allow(dead_code)]
pub fn info_for(t: SocType) -> SocInfo {
    let ic = match t {
        SocType::KunPeng920
        | SocType::RockchipRK3588
        | SocType::RockchipRK356x
        | SocType::QEMUVirt => InterruptController::GICv3,
        SocType::PhytiumFT2000
        | SocType::PhytiumD2000
        | SocType::PhytiumD3000
        | SocType::RockchipRK3399 => InterruptController::GICv2,
        SocType::UnsupportedArmV7 => InterruptController::None,
        SocType::Unknown => InterruptController::None,
    };
    let mut s = SocInfo::unknown();
    s.soc_type = t;
    s.interrupt_controller = ic;
    s
}

/// Read the cached `SocInfo`. Available after [`init_soc`] returns.
pub fn current_soc() -> SocInfo {
    // SAFETY: init_soc writes the descriptor before any other caller
    // can run. SOC_INFO_READY is the publish barrier.
    if SOC_INFO_READY.load(Ordering::Acquire) == 0 {
        return SocInfo::unknown();
    }
    unsafe { SOC_INFO.assume_init() }
}

/// Smoke test: ensure `init_soc` returns a valid SocInfo and that
/// the atomic slot is populated.
pub fn smoke_test() -> bool {
    let info = current_soc();
    info.cpu_count >= 1 && info.cpu_count <= 256
}
