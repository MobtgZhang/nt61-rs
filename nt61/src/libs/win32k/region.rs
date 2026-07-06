//! Region and Clipping
//
//! Implements GDI regions for clipping and complex shape operations.
//
//! ## Windows 7 Region Architecture
//
//! Regions are stored as lists of rectangles. They support
//! set operations: union, intersection, difference, xor.
//
//! Reference: ReactOS win32ss/gdi/region

extern crate alloc;

use crate::kprintln;
use crate::libs::win32k::objects::Rect;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Region combination modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RegionCombineMode {
    Copy = 0,
    Union = 1,
    Xor = 2,
    Intersection = 3,
    Difference = 4,
}

/// Region type (returned by CombineRgn)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RegionType {
    Null = 0,
    Simple = 1,
    Complex = 2,
}

/// Maximum rectangles in a region
const MAX_RECTANGLES: usize = 256;

/// Region object
#[repr(C)]
pub struct GdiRegionData {
    pub count: i32,
    pub extents: Rect,
    pub rects: [Rect; MAX_RECTANGLES],
}

impl GdiRegionData {
    pub fn new() -> Self {
        Self {
            count: 0,
            extents: Rect::new(0, 0, 0, 0),
            rects: [Rect::new(0, 0, 0, 0); MAX_RECTANGLES],
        }
    }
}

/// Region handle wrapper
pub struct RegionHandle {
    pub data: Box<GdiRegionData>,
}

impl RegionHandle {
    pub fn new() -> Self {
        Self {
            data: Box::new(GdiRegionData::new()),
        }
    }

    pub fn from_rect(rect: &Rect) -> Self {
        let mut region = Self::new();
        region.data.count = 1;
        region.data.extents = *rect;
        region.data.rects[0] = *rect;
        region
    }
}

// =============================================================================
// Region Operations
// =============================================================================

/// Check if a rectangle is empty
fn is_empty_rect(rect: &Rect) -> bool {
    rect.left >= rect.right || rect.top >= rect.bottom
}

/// Check if rect A is contained in rect B
fn rect_contains(outer: &Rect, inner: &Rect) -> bool {
    inner.left >= outer.left &&
    inner.right <= outer.right &&
    inner.top >= outer.top &&
    inner.bottom <= outer.bottom
}

/// Check if two rectangles intersect
fn rects_intersect(a: &Rect, b: &Rect) -> bool {
    !(a.right <= b.left || a.left >= b.right ||
      a.bottom <= b.top || a.top >= b.bottom)
}

/// Compute intersection of two rectangles
fn rect_intersection(a: &Rect, b: &Rect) -> Option<Rect> {
    if !rects_intersect(a, b) {
        return None;
    }

    Some(Rect::new(
        a.left.max(b.left),
        a.top.max(b.top),
        a.right.min(b.right),
        a.bottom.min(b.bottom),
    ))
}

/// Create a simple rectangle region
pub fn GreCreateRectRgn(left: i32, top: i32, right: i32, bottom: i32) -> u64 {
    let region = crate::libs::win32k::objects::GdiCreateRectRgn(left, top, right, bottom);
    let _ = &region;
    // kprintln!("[win32k] GreCreateRectRgn: ({},{})-({},{}) -> handle=0x{:016x}",  // kprintln disabled (memcpy crash workaround)
//               left, top, right, bottom, region);
    region
}

/// Create a region from a RECT structure
pub fn GreCreateRectRgnIndirect(rect: &Rect) -> u64 {
    GreCreateRectRgn(rect.left, rect.top, rect.right, rect.bottom)
}

/// Delete a region
pub fn GreDeleteRegion(region: u64) -> bool {
    // Region is handled as GDI object
    let ok = crate::libs::win32k::objects::GdiDeleteObject(region);
    let _ = &region;
    ok
}

// =============================================================================
// Region Combination
// =============================================================================

/// Check if two rectangles overlap
fn rects_overlap(a: &Rect, b: &Rect) -> bool {
    a.left < b.right && a.right > b.left &&
    a.top < b.bottom && a.bottom > b.top
}

/// Simple region union - add a rectangle to existing region
fn add_rect_to_region(region: &mut GdiRegionData, rect: &Rect) {
    if is_empty_rect(rect) {
        return;
    }

    if region.count == 0 {
        region.count = 1;
        region.extents = *rect;
        region.rects[0] = *rect;
        return;
    }

    // Check if this rect can be merged with existing ones
    let mut merged = false;
    for i in 0..region.count as usize {
        if rects_overlap(&region.rects[i], rect) {
            // Merge by expanding the existing rect
            region.rects[i].left = region.rects[i].left.min(rect.left);
            region.rects[i].top = region.rects[i].top.min(rect.top);
            region.rects[i].right = region.rects[i].right.max(rect.right);
            region.rects[i].bottom = region.rects[i].bottom.max(rect.bottom);
            merged = true;
            break;
        }
    }

    // If not merged, add as new rectangle
    if !merged && region.count < MAX_RECTANGLES as i32 {
        region.rects[region.count as usize] = *rect;
        region.count += 1;
    }

    // Update extents
    region.extents.left = region.extents.left.min(rect.left);
    region.extents.top = region.extents.top.min(rect.top);
    region.extents.right = region.extents.right.max(rect.right);
    region.extents.bottom = region.extents.bottom.max(rect.bottom);
}

/// Compute the bounding box union of two regions
fn compute_union_bounds(r1: &crate::libs::win32k::objects::GdiRegion, 
                       r2: &crate::libs::win32k::objects::GdiRegion) -> Rect {
    Rect::new(
        r1.extents.left.min(r2.extents.left),
        r1.extents.top.min(r2.extents.top),
        r1.extents.right.max(r2.extents.right),
        r1.extents.bottom.max(r2.extents.bottom),
    )
}

/// Compute the intersection bounding box of two regions
fn compute_intersection_bounds(r1: &crate::libs::win32k::objects::GdiRegion,
                              r2: &crate::libs::win32k::objects::GdiRegion) -> Option<Rect> {
    let left = r1.extents.left.max(r2.extents.left);
    let _ = &left;
    let top = r1.extents.top.max(r2.extents.top);
    let _ = &top;
    let right = r1.extents.right.min(r2.extents.right);
    let _ = &right;
    let bottom = r1.extents.bottom.min(r2.extents.bottom);
    let _ = &bottom;
    
    if right > left && bottom > top {
        Some(Rect::new(left, top, right, bottom))
    } else {
        None
    }
}

/// Simple region intersection - keep only overlapping area
fn intersect_region_with_rect(region: &mut GdiRegionData, rect: &Rect) {
    if region.count == 0 {
        return;
    }

    let mut new_count: i32 = 0;

    for i in 0..region.count as usize {
        if let Some(intersection) = rect_intersection(&region.rects[i], rect) {
            if !is_empty_rect(&intersection) && new_count < MAX_RECTANGLES as i32 {
                region.rects[new_count as usize] = intersection;
                new_count += 1;
            }
        }
    }

    region.count = new_count;

    // Recalculate extents
    if new_count > 0 {
        region.extents = region.rects[0];
        for i in 1..new_count as usize {
            region.extents.left = region.extents.left.min(region.rects[i].left);
            region.extents.top = region.extents.top.min(region.rects[i].top);
            region.extents.right = region.extents.right.max(region.rects[i].right);
            region.extents.bottom = region.extents.bottom.max(region.rects[i].bottom);
        }
    }
}

/// Combine two regions using the specified mode.
/// This implementation handles all four combine modes:
/// - Copy: Copy src1 to dest
/// - Union: Union of src1 and src2
/// - Intersection: Intersection of src1 and src2
/// - Difference: src1 minus src2
/// - Xor: Union minus intersection
pub fn GreCombineRgn(
    dest_handle: u64,
    src1_handle: u64,
    src2_handle: u64,
    mode: RegionCombineMode,
) -> i32 {
    let dest_ptr = crate::libs::win32k::objects::GdiGetObjectPtr(dest_handle);
    let _ = &dest_ptr;
    let src1_ptr = crate::libs::win32k::objects::GdiGetObjectPtr(src1_handle);
    let _ = &src1_ptr;
    let src2_ptr = crate::libs::win32k::objects::GdiGetObjectPtr(src2_handle);
    let _ = &src2_ptr;

    // Both dest and src1 must be valid
    let (dest_ptr, src1_ptr) = match (dest_ptr, src1_ptr) {
        (Some(d), Some(s)) => (d, s),
        _ => return RegionType::Null as i32,
    };

    let src1_region = unsafe { &*(src1_ptr as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &src1_region;

    match mode {
        RegionCombineMode::Copy => {
            // Copy src1 to dest
            let dest_region = unsafe { &mut *(dest_ptr as *mut crate::libs::win32k::objects::GdiRegion) };
            let _ = &dest_region;
            *dest_region = *src1_region;
            // kprintln!("[win32k] GreCombineRgn: Copy -> {}",   // kprintln disabled (memcpy crash workaround)
//                 if dest_region.num_rects > 0 { "Simple" } else { "Null" });
        }
        RegionCombineMode::Union => {
            // Union of src1 and src2
            let dest_region = unsafe { &mut *(dest_ptr as *mut crate::libs::win32k::objects::GdiRegion) };
            let _ = &dest_region;
            *dest_region = *src1_region;
            
            if let Some(src2) = src2_ptr {
                let src2_region = unsafe { &*(src2 as *const crate::libs::win32k::objects::GdiRegion) };
                let _ = &src2_region;
                // Use proper bounding box union
                dest_region.extents = compute_union_bounds(src1_region, src2_region);
                dest_region.num_rects = 2; // Mark as potentially complex
                // kprintln!("[win32k] GreCombineRgn: Union -> bounds ({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//                     dest_region.extents.left, dest_region.extents.top,
//                     dest_region.extents.right, dest_region.extents.bottom);
            }
        }
        RegionCombineMode::Intersection => {
            // Intersection of src1 and src2
            let dest_region = unsafe { &mut *(dest_ptr as *mut crate::libs::win32k::objects::GdiRegion) };
            let _ = &dest_region;
            
            if let Some(src2) = src2_ptr {
                let src2_region = unsafe { &*(src2 as *const crate::libs::win32k::objects::GdiRegion) };
                let _ = &src2_region;
                
                if let Some(inter) = compute_intersection_bounds(src1_region, src2_region) {
                    dest_region.extents = inter;
                    dest_region.num_rects = 1;
                    // kprintln!("[win32k] GreCombineRgn: Intersection -> ({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//                         inter.left, inter.top, inter.right, inter.bottom);
                } else {
                    dest_region.num_rects = 0;
                    // kprintln!("[win32k] GreCombineRgn: Intersection -> Null (no overlap)")  // kprintln disabled (memcpy crash workaround);
                }
            } else {
                // src2 is null region
                dest_region.num_rects = 0;
            }
        }
        RegionCombineMode::Difference => {
            // src1 minus src2: simplified to just use src1
            // A full implementation would compute polygon difference
            let dest_region = unsafe { &mut *(dest_ptr as *mut crate::libs::win32k::objects::GdiRegion) };
            let _ = &dest_region;
            *dest_region = *src1_region;
            // kprintln!("[win32k] GreCombineRgn: Difference -> using src1 bounds")  // kprintln disabled (memcpy crash workaround);
        }
        RegionCombineMode::Xor => {
            // XOR of src1 and src2: simplified using bounding boxes
            // Full implementation would compute symmetric difference
            let dest_region = unsafe { &mut *(dest_ptr as *mut crate::libs::win32k::objects::GdiRegion) };
            let _ = &dest_region;
            *dest_region = *src1_region;

            if let Some(src2) = src2_ptr {
                let src2_region = unsafe { &*(src2 as *const crate::libs::win32k::objects::GdiRegion) };
                let _ = &src2_region;
                // Use bounding box union for XOR (approximation)
                dest_region.extents = compute_union_bounds(src1_region, src2_region);
                dest_region.num_rects = 2;
                // kprintln!("[win32k] GreCombineRgn: Xor -> union bounds ({},{})-({},{})",  // kprintln disabled (memcpy crash workaround)
//                     dest_region.extents.left, dest_region.extents.top,
//                     dest_region.extents.right, dest_region.extents.bottom);
            }
        }
    }

    // Return region type
    let dest_region = unsafe { &*(dest_ptr as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &dest_region;
    if dest_region.num_rects == 0 {
        RegionType::Null as i32
    } else if dest_region.num_rects == 1 {
        RegionType::Simple as i32
    } else {
        RegionType::Complex as i32
    }
}

// =============================================================================
// Region Queries
// =============================================================================

/// Check if two regions are equal
pub fn GreEqualRgn(region1: u64, region2: u64) -> bool {
    let ptr1 = crate::libs::win32k::objects::GdiGetObjectPtr(region1);
    let _ = &ptr1;
    let ptr2 = crate::libs::win32k::objects::GdiGetObjectPtr(region2);
    let _ = &ptr2;

    if ptr1.is_none() || ptr2.is_none() {
        return false;
    }

    let r1 = unsafe { &*(ptr1.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r1;
    let r2 = unsafe { &*(ptr2.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r2;

    r1.extents.left == r2.extents.left &&
    r1.extents.top == r2.extents.top &&
    r1.extents.right == r2.extents.right &&
    r1.extents.bottom == r2.extents.bottom &&
    r1.num_rects == r2.num_rects
}

/// Check if a point is in a region
pub fn GrePtInRegion(region: u64, x: i32, y: i32) -> bool {
    let ptr = crate::libs::win32k::objects::GdiGetObjectPtr(region);
    let _ = &ptr;
    if ptr.is_none() {
        return false;
    }

    let r = unsafe { &*(ptr.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r;

    // Check extents first
    if x < r.extents.left || x >= r.extents.right ||
       y < r.extents.top || y >= r.extents.bottom {
        return false;
    }

    // For simple regions, just check extents
    // Full implementation would check all rectangles
    true
}

/// Check if a rectangle is in a region
pub fn GreRectInRegion(region: u64, rect: &Rect) -> bool {
    let ptr = crate::libs::win32k::objects::GdiGetObjectPtr(region);
    let _ = &ptr;
    if ptr.is_none() {
        return false;
    }

    let r = unsafe { &*(ptr.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r;

    // Check if rect intersects region extents
    rects_intersect(&r.extents, rect)
}

/// Get region bounds
pub fn GreGetRgnBox(region: u64, rect: &mut Rect) -> i32 {
    let ptr = crate::libs::win32k::objects::GdiGetObjectPtr(region);
    let _ = &ptr;
    if ptr.is_none() {
        return RegionType::Null as i32;
    }

    let r = unsafe { &*(ptr.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r;

    *rect = r.extents;

    if r.num_rects == 0 {
        RegionType::Null as i32
    } else if r.num_rects == 1 {
        RegionType::Simple as i32
    } else {
        RegionType::Complex as i32
    }
}

// =============================================================================
// DC Clipping
// =============================================================================

/// Set the clip region of a DC
pub fn GreSelectClipRgn(dc: u64, region: u64) -> i32 {
    // Get DC
    if let Some(dc_obj) = crate::libs::win32k::dc::get_dc(dc) {
        let _old_region = dc_obj.clip_region;
        let _ = &_old_region;
        dc_obj.clip_region = region;
        
        if region == 0 {
            return RegionType::Null as i32;
        }

        let mut rect = Rect::new(0, 0, 0, 0);
        GreGetRgnBox(region, &mut rect)
    } else {
        RegionType::Null as i32
    }
}

/// Set DC origin
pub fn GreOffsetDCOrg(dc: u64, x: i32, y: i32) -> bool {
    if let Some(dc_obj) = crate::libs::win32k::dc::get_dc(dc) {
        dc_obj.viewport_org.x += x;
        dc_obj.viewport_org.y += y;
        true
    } else {
        false
    }
}

/// Set clip rectangle
pub fn GreSetDCClipping(dc: u64, rect: &Rect) -> bool {
    if let Some(dc_obj) = crate::libs::win32k::dc::get_dc(dc) {
        dc_obj.region = if !is_empty_rect(rect) {
            GreCreateRectRgn(rect.left, rect.top, rect.right, rect.bottom)
        } else {
            0
        };
        true
    } else {
        false
    }
}

// =============================================================================
// ExtExclude - Exclude rectangle from region
// =============================================================================

/// Exclude a rectangle from a region
pub fn GreExtExcludeClipRect(dc: u64, left: i32, top: i32, right: i32, bottom: i32) -> i32 {
    if let Some(dc_obj) = crate::libs::win32k::dc::get_dc(dc) {
        let _exclude_rect = Rect::new(left, top, right, bottom);
        let _ = &_exclude_rect;
        
        if dc_obj.clip_region != 0 {
            // Create a new region with the rectangle excluded
            // This is a simplified implementation
            // Full implementation would split the region around the rectangle
            
            let mut box_rect = Rect::new(0, 0, 0, 0);
            let _current_type = GreGetRgnBox(dc_obj.clip_region, &mut box_rect);
            let _ = &_current_type;
            
            // For simplicity, just clear the clip region
            dc_obj.clip_region = 0;
            
            return RegionType::Null as i32;
        }
        
        RegionType::Null as i32
    } else {
        RegionType::Null as i32
    }
}

// =============================================================================
// Debug
// =============================================================================

/// Dump region info
pub fn dump_region_info(region: u64) {
    let ptr = crate::libs::win32k::objects::GdiGetObjectPtr(region);
    let _ = &ptr;
    if ptr.is_none() {
        // kprintln!("[win32k] Region 0x{:016x}: NULL", region)  // kprintln disabled (memcpy crash workaround);
        return;
    }

    let r = unsafe { &*(ptr.unwrap() as *const crate::libs::win32k::objects::GdiRegion) };
    let _ = &r;
    
    // kprintln!("[win32k] Region 0x{:016x}:", region)  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  extents: ({},{})-({},{})",   // kprintln disabled (memcpy crash workaround)
//               r.extents.left, r.extents.top, r.extents.right, r.extents.bottom);
    // kprintln!("  rectangles: {}", r.num_rects)  // kprintln disabled (memcpy crash workaround);
}
