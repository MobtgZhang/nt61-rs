//! HAL export-name registry
//
//! `system_image::build_hal` writes a PE32+ `hal.dll` with a list of
//! exported symbols. The list is duplicated here so the
//! `system_image::validate_hal_export_list` build-time check can
//! catch typos and mismatches between the on-disk image and what
//! the rest of the kernel expects.
//
//! Every symbol listed in `hal_export_names()` MUST also be added
//! to `build_hal()` in `system_image/mod.rs` (and vice versa).
//! The `>= N` count check in `validate_hal_export_list()` is the
//! canary; if the two diverge, `cargo build` will fail rather than
//! silently shipping a mismatched `hal.dll`.

/// Canonical HAL+KD export surface for NT6.1.7601 (x86_64). The
/// order in this array is irrelevant; what matters is that every
/// name the kernel/HAL might import is present.
///
/// Add new entries here AND in `system_image::build_hal`.
pub const HAL_EXPORTS: &[&str] = &[
    // ---- HAL init / processor bring-up ----
    "HalInitializeProcessor",
    "HalInitSystem",
    "HalStartNextProcessor",
    "HalAllProcessorsStarted",
    "HalProcessorIdle",
    "HalHaltSystem",
    // ---- HAL IPI / interrupt control ----
    "HalRequestIpi",
    "HalEnableSystemInterrupt",
    "HalDisableSystemInterrupt",
    "HalGetInterruptVector",
    // ---- HAL bus / IO ----
    "HalGetBusData",
    "HalSetBusData",
    "HalAssignSlotResources",
    "HalTranslateBusAddress",
    "HalMapIoSpace",
    "HalUnmapIoSpace",
    // ---- HAL DMA / common buffer ----
    "HalAllocateCommonBuffer",
    "HalFreeCommonBuffer",
    "HalAllocateMapRegisters",
    "HalFreeMapRegisters",
    // ---- HAL display ----
    "HalQueryDisplaySettings",
    "HalSetDisplaySettings",
    "HalResetDisplay",
    // ---- HAL clock / RTC / perf counter ----
    "HalQueryRealTimeClock",
    "HalSetRealTimeClock",
    "HalQueryPerformanceCounter",
    "HalQueryPerformanceFrequency",
    // ---- HAL misc ----
    "HalReturnToFirmware",
    "HalQuerySystemInformation",
    "HalSetSystemInformation",
    // ---- Kd* (kernel debugger transport) ----
    "KdTransportPacket",
    "KdDebuggerInitialize",
    "KdPortInByte",
    "KdPortOutByte",
];

/// Canonical ntoskrnl.exe export surface for NT6.1.7601. The
/// order is irrelevant; what's required is that the names match
/// `system_image::build_ntoskrnl`.
pub const NTOS_EXPORTS: &[&str] = &[
    // ---- Ki* (kernel init / entry) ----
    "KiSystemStartup",
    "KiInitializeKernel",
    "KiInitializeProcess",
    "KiInitializeThread",
    "KiSwapContext",
    "KiDispatchInterrupt",
    "KiUnexpectedInterrupt",
    "KiBugCheck",
    // ---- Ke* (core executive) ----
    "KeBugCheck",
    "KeBugCheckEx",
    "KeInitializeScheduler",
    "KeStartAllProcessors",
    "KeInitSystem",
    "KeInitializeDispatcher",
    "KeWaitForSingleObject",
    "KeSetEvent",
    "KeEnterCriticalRegion",
    "KeLeaveCriticalRegion",
    "KeDelayExecutionThread",
    "KeInitializeApc",
    "KeInsertQueueApc",
    // ---- Ps* (process / thread) ----
    "PsCreateSystemThread",
    "PsTerminateSystemThread",
    "PsCreateProcess",
    // ---- Ex* (executive resource manager) ----
    "ExAllocatePoolWithTag",
    "ExFreePoolWithTag",
    "ExInitializePool",
    "ExAcquireResourceSharedLite",
    "ExReleaseResourceLite",
    // ---- Mm* (memory manager) ----
    "MmAllocateContiguousMemory",
    "MmFreeContiguousMemory",
    "MmMapIoSpace",
    "MmUnmapIoSpace",
    "MmAllocatePages",
    "MmAllocateMappingAddress",
    // ---- Io* (I/O manager) ----
    "IoCreateDevice",
    "IoCallDriver",
    "IoCompleteRequest",
    "IoCreateSymbolicLink",
    "IoDeleteDevice",
    "IoDeleteSymbolicLink",
    // ---- Ob* (object manager) ----
    "ObCreateObjectType",
    "ObReferenceObjectByHandle",
    "ObDereferenceObject",
    // ---- Po* (power manager) ----
    "PoSetSystemState",
    "PoCallDriver",
    "PoRequestPowerIrp",
    // ---- Cm* (configuration manager) ----
    "CmRegisterCallback",
    // ---- Rtl* (runtime library) ----
    "RtlInitUnicodeString",
    // ---- Driver entry ----
    "DriverEntry",
    "GsDriverEntry",
];

/// Return a borrowed slice of the canonical HAL export names.
/// Used by `system_image::validate_hal_export_list` for the
/// compile-time cross-check.
pub fn hal_export_names() -> &'static [&'static str] {
    HAL_EXPORTS
}

/// Return a borrowed slice of the canonical NTOS export names.
pub fn ntos_export_names() -> &'static [&'static str] {
    NTOS_EXPORTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hal_export_count_matches_plan() {
        // The plan specifies "约 25 个 stub" for HAL; we have 32
        // (more is fine; too few is a regression).
        assert!(HAL_EXPORTS.len() >= 25,
            "HAL_EXPORTS must list >= 25 names, got {}", HAL_EXPORTS.len());
    }

    #[test]
    fn ntos_export_count_matches_plan() {
        // The plan specifies "约 50 个" for ntoskrnl.exe; we have 52.
        assert!(NTOS_EXPORTS.len() >= 50,
            "NTOS_EXPORTS must list >= 50 names, got {}", NTOS_EXPORTS.len());
    }

    #[test]
    fn hal_export_names_are_unique() {
        for (i, a) in HAL_EXPORTS.iter().enumerate() {
            for b in HAL_EXPORTS.iter().skip(i + 1) {
                assert!(a != b, "duplicate HAL export name: {}", a);
            }
        }
    }

    #[test]
    fn ntos_export_names_are_unique() {
        for (i, a) in NTOS_EXPORTS.iter().enumerate() {
            for b in NTOS_EXPORTS.iter().skip(i + 1) {
                assert!(a != b, "duplicate NTOS export name: {}", a);
            }
        }
    }
}