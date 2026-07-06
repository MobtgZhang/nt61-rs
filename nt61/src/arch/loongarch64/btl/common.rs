//! BTL — common helpers shared by the decoder/emitter/translator.

#![cfg(target_arch = "loongarch64")]

/// Boot-time hook (currently a no-op; reserves slot for shared
/// state such as the lock-free TLBI queue).
pub fn init() {}
