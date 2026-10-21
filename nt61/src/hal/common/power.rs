//! Architecture-agnostic firmware power transitions.

/// Actions understood by `hal_return_to_firmware`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareAction {
    Halt,
    Reboot,
    Shutdown,
}

/// Return control to firmware. This function does not return.
pub fn return_to_firmware(action: FirmwareAction) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        let action = match action {
            FirmwareAction::Halt => crate::hal::x86_64::halt::firmware_action::HAL_HALT,
            FirmwareAction::Reboot => crate::hal::x86_64::halt::firmware_action::HAL_REBOOT,
            FirmwareAction::Shutdown => crate::hal::x86_64::halt::firmware_action::HAL_SHUTDOWN,
        };
        crate::hal::x86_64::halt::hal_return_to_firmware(u32::from(action));
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = action;
        crate::arch::halt_loop();
    }
}
