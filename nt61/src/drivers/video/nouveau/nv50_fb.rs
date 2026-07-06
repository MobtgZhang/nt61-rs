//! NVIDIA NV50 (Tesla) Framebuffer Driver
//
//! This module implements the framebuffer driver for NV50/Tesla GPUs
//! (GeForce 8xxx/9xxx series).
//
//! Clean-room implementation based on public specifications.

use super::nouveau_fb::NouveauDevice;
use crate::drivers::video::core::gpu_common::GpuError;

/// Initialize NV50 framebuffer
pub fn nv50_fb_init(dev: &mut NouveauDevice) -> Result<(), GpuError> {
    // Set architecture
    dev.arch = super::pci_ids::NouveauArchitecture::NV50;

    // NV50 uses PV Baptized for display
    let pv_offset = 0x000000;

    // Enable PV Baptized block
    dev.write_reg(pv_offset + 0x0000, 1);

    // Configure PFB (Performance and Frame Buffer)
    let pfb_off = 0x001000;

    // Enable PFB
    dev.write_reg(pfb_off + 0x004, 1);

    // Set framebuffer pitch
    dev.write_reg(pfb_off + nv50_reg::NV_FB_PITCH, dev.pitch);

    // Set framebuffer size
    dev.write_reg(pfb_off + 0x010, (dev.height << 16) | dev.width);

    // Configure PCRTC (CRT Controller)
    let crtc_off = 0x006000;

    // Calculate timing
    let h_total = dev.width + 160;
    let h_sync_start = dev.width + 48;
    let h_sync_end = dev.width + 112;
    let v_total = dev.height + 30;
    let v_sync_start = dev.height + 10;
    let v_sync_end = dev.height + 12;

    // Set horizontal timing via named register offsets.
    dev.write_reg(crtc_off + nv50_reg::NV_CRTC_H_TOTAL, (h_total << 16) | dev.width);
    dev.write_reg(crtc_off + nv50_reg::NV_CRTC_H_SYNC, (h_sync_end << 16) | h_sync_start);

    // Set vertical timing via named register offsets.
    dev.write_reg(crtc_off + nv50_reg::NV_CRTC_V_TOTAL, (v_total << 16) | dev.height);
    dev.write_reg(crtc_off + nv50_reg::NV_CRTC_V_SYNC, (v_sync_end << 16) | v_sync_start);

    // Enable CRTC
    dev.write_reg(crtc_off, 1);

    Ok(())
}

pub mod nv50_reg {
    /// PV Baptized register offset


    /// PFB register offset


    /// PFB pitch register (NV_FB_PITCH)
    pub const NV_FB_PITCH: u32 = 0x00100C;

    /// PCRTC register offset


    /// PCRTC horizontal total register
    pub const NV_CRTC_H_TOTAL: u32 = 0x006008;
    pub const NV_CRTC_H_SYNC: u32 = 0x00600C;
    pub const NV_CRTC_V_TOTAL: u32 = 0x006010;
    pub const NV_CRTC_V_SYNC: u32 = 0x006014;
}
