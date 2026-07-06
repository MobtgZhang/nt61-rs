//! Loongson CRT Controller (CRTC) Driver
//
//! Implements CRT controller support for both Pipeline A and B.

use crate::drivers::video::loongson::lsdc_reg::*;

/// CRT pipe identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrtcPipe {
    /// Pipeline A
    PipeA,
    /// Pipeline B
    PipeB,
}

/// Loongson CRT controller
pub struct LsDcCrtc {
    /// DC base address
    dc_base: u64,
    /// Pipe identifier
    pipe: CrtcPipe,
    /// Whether the CRTC is enabled
    enabled: bool,
    /// Current horizontal resolution
    width: u32,
    /// Current vertical resolution
    height: u32,
}

impl LsDcCrtc {
    /// Create a new CRT controller
    pub fn new(dc_base: u64, pipe: CrtcPipe) -> Self {
        Self {
            dc_base,
            pipe,
            enabled: false,
            width: 0,
            height: 0,
        }
    }

    /// Get control register offset
    fn ctrl_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_CTRL,
            CrtcPipe::PipeB => CRTC_B_CTRL,
        }
    }

    /// Get horizontal timing register
    fn timing_h_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_TIMING_H,
            CrtcPipe::PipeB => CRTC_B_TIMING_H,
        }
    }

    /// Get vertical timing register
    fn timing_v_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_TIMING_V,
            CrtcPipe::PipeB => CRTC_B_TIMING_V,
        }
    }

    /// Get sync register
    fn sync_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_SYNC,
            CrtcPipe::PipeB => CRTC_B_SYNC,
        }
    }

    /// Get polarity register
    fn polarity_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_POLARITY,
            CrtcPipe::PipeB => CRTC_B_POLARITY,
        }
    }

    /// Get address register
    fn addr_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_ADDR,
            CrtcPipe::PipeB => CRTC_B_ADDR,
        }
    }

    /// Get scanline register
    fn line_reg(&self) -> u32 {
        match self.pipe {
            CrtcPipe::PipeA => CRTC_A_LINE,
            CrtcPipe::PipeB => CRTC_B_LINE,
        }
    }

    /// Read a register
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.dc_base + offset as u64) as *const u32) }
    }

    /// Write a register
    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        unsafe {
            core::ptr::write_volatile(
                (self.dc_base + offset as u64) as *mut u32,
                value,
            )
        }
    }

    /// Enable the CRT controller
    pub fn enable(&mut self, width: u32, height: u32, fb_addr: u64) {
        self.width = width;
        self.height = height;

        // Disable CRTC for configuration
        self.write_reg(self.ctrl_reg(), 0);

        // Configure horizontal timing
        let h_total = width + 160;
        let h_sync_start = width + 48;
        let h_sync_end = width + 112;
        let h_timing = (h_total << 16) | (h_sync_end << 8) | h_sync_start;
        self.write_reg(self.timing_h_reg(), h_timing);

        // Configure vertical timing
        let v_total = height + 30;
        let v_sync_start = height + 10;
        let v_sync_end = height + 12;
        let v_timing = (v_total << 16) | (v_sync_end << 8) | v_sync_start;
        self.write_reg(self.timing_v_reg(), v_timing);

        // Configure sync signals (active mode)
        self.write_reg(self.sync_reg(), 0);
        self.write_reg(self.polarity_reg(), 0);

        // Set framebuffer address
        self.write_reg(self.addr_reg(), fb_addr as u32);

        // Enable CRTC
        self.write_reg(self.ctrl_reg(), CRTC_ENABLE | CRTC_DOUBLE_SCAN);

        self.enabled = true;
    }

    /// Disable the CRT controller
    pub fn disable(&mut self) {
        self.write_reg(self.ctrl_reg(), 0);
        self.enabled = false;
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get current scanline
    pub fn get_scanline(&self) -> u32 {
        self.read_reg(self.line_reg())
    }

    /// Get width
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get height
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get pipe identifier
    pub fn pipe(&self) -> CrtcPipe {
        self.pipe
    }

    /// Set display timing with custom parameters
    pub fn set_timing(
        &mut self,
        h_total: u32,
        h_sync_start: u32,
        h_sync_end: u32,
        v_total: u32,
        v_sync_start: u32,
        v_sync_end: u32,
        h_polarity_high: bool,
        v_polarity_high: bool,
    ) {
        // Horizontal timing
        let h_timing = (h_total << 16) | (h_sync_end << 8) | h_sync_start;
        self.write_reg(self.timing_h_reg(), h_timing);

        // Vertical timing
        let v_timing = (v_total << 16) | (v_sync_end << 8) | v_sync_start;
        self.write_reg(self.timing_v_reg(), v_timing);

        // Polarity
        let polarity = if h_polarity_high { CRTC_HPOLARITY_HIGH } else { 0 }
            | if v_polarity_high { CRTC_VPOLARITY_HIGH } else { 0 };
        self.write_reg(self.polarity_reg(), polarity);
    }

    /// Get status
    pub fn get_status(&self) -> CrtcStatus {
        let ctrl = self.read_reg(self.ctrl_reg());
        CrtcStatus {
            enabled: ctrl & CRTC_ENABLE != 0,
            double_scan: ctrl & CRTC_DOUBLE_SCAN != 0,
            interlaced: ctrl & CRTC_INTERLACE != 0,
            current_line: self.get_scanline(),
        }
    }
}

/// CRTC status information
#[derive(Debug, Clone, Copy)]
pub struct CrtcStatus {
    /// Whether CRTC is enabled
    pub enabled: bool,
    /// Whether double scan is enabled
    pub double_scan: bool,
    /// Whether interlaced mode is enabled
    pub interlaced: bool,
    /// Current scanline
    pub current_line: u32,
}

/// Dual CRTC manager
pub struct DualCrtcManager {
    /// CRTC A
    crtc_a: LsDcCrtc,
    /// CRTC B
    crtc_b: LsDcCrtc,
}

impl DualCrtcManager {
    /// Create a new dual CRTC manager
    pub fn new(dc_base: u64) -> Self {
        Self {
            crtc_a: LsDcCrtc::new(dc_base, CrtcPipe::PipeA),
            crtc_b: LsDcCrtc::new(dc_base, CrtcPipe::PipeB),
        }
    }

    /// Get CRTC A
    pub fn crtc_a(&mut self) -> &mut LsDcCrtc {
        &mut self.crtc_a
    }

    /// Get CRTC B
    pub fn crtc_b(&mut self) -> &mut LsDcCrtc {
        &mut self.crtc_b
    }

    /// Enable both CRTCs
    pub fn enable_both(&mut self, width_a: u32, height_a: u32, fb_addr_a: u64,
                       width_b: u32, height_b: u32, fb_addr_b: u64) {
        self.crtc_a.enable(width_a, height_a, fb_addr_a);
        self.crtc_b.enable(width_b, height_b, fb_addr_b);
    }

    /// Disable both CRTCs
    pub fn disable_both(&mut self) {
        self.crtc_a.disable();
        self.crtc_b.disable();
    }

    /// Get current mode
    pub fn get_mode(&self) -> Option<(u32, u32, u32, u32)> {
        if self.crtc_a.is_enabled() && self.crtc_b.is_enabled() {
            Some((
                self.crtc_a.width(),
                self.crtc_a.height(),
                self.crtc_b.width(),
                self.crtc_b.height(),
            ))
        } else if self.crtc_a.is_enabled() {
            Some((self.crtc_a.width(), self.crtc_a.height(), 0, 0))
        } else if self.crtc_b.is_enabled() {
            Some((0, 0, self.crtc_b.width(), self.crtc_b.height()))
        } else {
            None
        }
    }
}
