//! Intel i915 Display PLL (Phase-Locked Loop) Configuration
//
//! Configures the display PLLs to generate the correct pixel clocks
//! for various display modes. The PLL takes a reference clock
//! (typically 24MHz or 100MHz) and generates the required frequency.
//
//! Clean-room implementation based on Intel Graphics Programmer's
//! Reference Manual (PRM) for various generations.

use crate::drivers::video::log;

/// Reference clock frequencies
const REF_CLOCK_24MHZ: u32 = 24_000;


/// PLL configuration parameters
#[derive(Debug, Clone)]
pub struct PllConfig {
    /// Target pixel clock frequency in kHz
    pub clock_khz: u32,
    /// DPLL control value
    pub dpll: u32,
    /// DPLL divider value
    pub dpll_div: u32,
    /// DPLL magic divider value
    pub dpll_md: u32,
    /// Pipe configuration
    pub pipe_conf: u32,
    /// Clock computation parameters
    pub clock: u32,
    /// Frequency preset divider
    pub fp_div: u32,
    /// Frequency preset divider low
    pub fp_div_lo: u32,
}

/// DPLL register offsets (varies by generation)
const DPLL_A: u16 = 0x6014;
const DPLL_B: u16 = 0x6018;


const FP0: u16 = 0x6040;
const FP1: u16 = 0x6044;

/// DPLL control bits
const DPLL_ENABLE: u32 = 1 << 31;
const DPLL_VCO_ENABLE: u32 = 1 << 30;


/// DPLL reference clock selection
const DPLL_REFCLK_24MHZ: u32 = 0;


/// Clock computation result
#[derive(Debug, Clone, Default)]
pub struct ClockResult {
    pub clock: u32,
    pub dpll: u32,
    pub fp_div: u32,
    pub fp_div_lo: u32,
}

/// Calculate the best PLL configuration for a target clock
pub fn compute_clock(target_khz: u32) -> Option<ClockResult> {
    // Try to find the best divider combination
    let ref_clock = REF_CLOCK_24MHZ;
    
    // For a 24MHz reference:
    // VCO should be between 1.75 GHz and 3.5 GHz
    // pixel_clock = VCO / (dpll_ldot_count * dpll_frac_en)
    // dpll_frac_en is typically 1 for non-integer dividers
    
    let mut best_error = u32::MAX;
    let mut best_clock = 0u32;
    let mut best_dpll = 0u32;
    let mut best_fp_div = 0u32;
    let mut best_fp_div_lo = 0u32;
    
    // Search for best combination
    for dpll_div in 5..=10 {
        for fp_div in 10..=150 {
            let vco = ref_clock * fp_div;
            if vco < 1_750_000 || vco > 3_500_000 {
                continue;
            }
            
            let dpll_dot_div = vco / target_khz;
            if dpll_dot_div < 2 || dpll_dot_div > 127 {
                continue;
            }
            
            let clock = vco / dpll_dot_div;
            let error = if clock > target_khz {
                clock - target_khz
            } else {
                target_khz - clock
            };
            
            if error < best_error {
                best_error = error;
                best_clock = clock;
                best_dpll = ((fp_div - 2) as u32) << 16 | ((dpll_div - 2) as u32);
                best_fp_div = ((fp_div - 2) as u32) << 16 | ((dpll_div - 2) as u32);
                best_fp_div_lo = 0;
            }
        }
    }
    
    if best_error == u32::MAX || best_error > target_khz / 50 {
        return None; // Too much error
    }
    
    Some(ClockResult {
        clock: best_clock,
        dpll: best_dpll,
        fp_div: best_fp_div,
        fp_div_lo: best_fp_div_lo,
    })
}

/// Configure DPLL for a given pixel clock
pub fn configure_dpll(
    _mmio: u64,
    dpll_index: usize,
    clock_khz: u32,
) -> Result<PllConfig, &'static str> {
    let clock = compute_clock(clock_khz).ok_or("Cannot compute clock")?;

    log::video_log("i915-pll", &alloc::format!("Configuring DPLL{}: {} kHz", dpll_index, clock.clock));
    
    // Calculate actual clock
    let actual_clock = clock.clock;
    
    // Build DPLL value
    let dpll = DPLL_ENABLE 
        | DPLL_VCO_ENABLE 
        | DPLL_REFCLK_24MHZ
        | clock.dpll;
    
    // Build pipe configuration
    let pipe_conf = match clock_khz {
        0..=65000 => 0x00000000,  // Low frequency mode
        65001..=270000 => 0x00000000, // Standard mode
        _ => 0x00000000, // High frequency mode
    };
    
    Ok(PllConfig {
        clock_khz,
        dpll,
        dpll_div: clock.dpll,
        dpll_md: clock.fp_div,
        pipe_conf,
        clock: actual_clock,
        fp_div: clock.fp_div,
        fp_div_lo: clock.fp_div_lo,
    })
}

/// Enable a DPLL
pub fn enable_dpll(mmio: u64, dpll_index: usize, config: &PllConfig) {
    let dpll_reg = if dpll_index == 0 { DPLL_A } else { DPLL_B };
    let fp_reg = if dpll_index == 0 { FP0 } else { FP1 };
    
    // Disable DPLL first
    unsafe {
        core::ptr::write_volatile(
            (mmio + dpll_reg as u64) as *mut u32,
            config.dpll & !DPLL_ENABLE,
        );
    }
    
    // Wait for idle
    for _ in 0..100 {
        core::hint::spin_loop();
    }
    
    // Program frequency divider
    unsafe {
        core::ptr::write_volatile(
            (mmio + fp_reg as u64) as *mut u32,
            config.fp_div,
        );
    }
    
    // Enable DPLL
    unsafe {
        core::ptr::write_volatile(
            (mmio + dpll_reg as u64) as *mut u32,
            config.dpll | DPLL_ENABLE,
        );
    }
    
    // Wait for DPLL to lock
    for _ in 0..1000 {
        let val = unsafe {
            core::ptr::read_volatile((mmio + dpll_reg as u64) as *const u32)
        };
        if val & DPLL_ENABLE != 0 {
            break;
        }
    }
    
    log::video_log("i915-pll", &alloc::format!("DPLL{} enabled", dpll_index));
}

/// Disable a DPLL
pub fn disable_dpll(mmio: u64, dpll_index: usize) {
    let dpll_reg = if dpll_index == 0 { DPLL_A } else { DPLL_B };
    
    unsafe {
        let val = core::ptr::read_volatile(
            (mmio + dpll_reg as u64) as *const u32
        );
        core::ptr::write_volatile(
            (mmio + dpll_reg as u64) as *mut u32,
            val & !DPLL_ENABLE,
        );
    }
    
    log::video_log("i915-pll", &alloc::format!("DPLL{} disabled", dpll_index));
}

/// Get the best supported clock for a given resolution
pub fn get_best_clock(width: u32, height: u32, refresh: u32) -> u32 {
    // Calculate required pixel clock
    // Using typical blanking ratios:
    // H_total ≈ H_active * 1.2
    // V_total ≈ V_active * 1.08
    // pixel_clock = H_total * V_total * refresh / 1000000
    
    let h_total = (width as f32 * 1.25) as u32;
    let v_total = (height as f32 * 1.1) as u32;
    let pixel_clock = (h_total as u64 * v_total as u64 * refresh as u64 / 1_000_000) as u32;
    
    // Common clock values in kHz
    let common_clocks = [
        25175,  31500,  40000,  49500,  50000,  54000,  65000,  72000,
        75000,  78750,  85500,  94500,  108000, 115000, 121750, 135000,
        157500, 162000, 175500, 179500, 185625, 202500, 208000, 234000,
        262750, 268500, 315000, 340000, 355000, 368000, 397500, 438500,
    ];
    
    // Find closest supported clock
    let mut best_clock = common_clocks[0];
    let mut best_error = u32::MAX;
    
    for &clock in &common_clocks {
        let error = if clock > pixel_clock {
            clock - pixel_clock
        } else {
            pixel_clock - clock
        };
        
        if error < best_error {
            best_error = error;
            best_clock = clock;
        }
    }
    
    best_clock
}

/// Initialize the PLL subsystem
pub fn init() {
    log::video_log("i915-pll", "Display clock configuration ready");
}
