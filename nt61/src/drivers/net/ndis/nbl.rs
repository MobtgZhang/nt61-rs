//! Network Buffer List and Network Buffer structures
//
//! NDIS 6.0 uses NET_BUFFER_LIST (NBL) and NET_BUFFER (NB) to represent
//! network data. Each NBL can contain one or more NBs, and each NB
//! contains a pointer to an MDL (Memory Descriptor List) chain that
//! describes the data buffers.
//
//! Clean-room implementation based on NDIS 6.0 specification.

use crate::mm::pool::{self, PoolType};
use core::ptr;

/// Pool tags for NDIS structures
mod tags {
    use crate::mm::pool::make_tag;
    pub const NBL: u32 = make_tag(b'N', b'B', b'L', b' ');
    pub const NB: u32 = make_tag(b'N', b'B', b' ', b' ');
    pub const MDL: u32 = make_tag(b'M', b'D', b'L', b' ');
}

/// MDL (Memory Descriptor List) structure
/// Describes a physical memory buffer
#[repr(C)]
pub struct Mdl {
    pub next: *mut Mdl,      // Next MDL in chain
    pub size: u16,           // Size of MDL structure
    pub flags: u16,          // MDL flags
    pub phys_addr: u64,      // Physical address (if mapped)
    pub virt_addr: u64,      // Virtual address
}

impl Mdl {
    /// Allocate an MDL for a buffer
    pub fn allocate(data: *mut u8, length: usize) -> *mut Mdl {
        let mdl = pool::allocate_tagged(PoolType::NonPaged, core::mem::size_of::<Mdl>(), tags::MDL) as *mut Mdl;
        if mdl.is_null() {
            return core::ptr::null_mut();
        }

        unsafe {
            (*mdl).next = core::ptr::null_mut();
            (*mdl).size = core::mem::size_of::<Mdl>() as u16;
            (*mdl).flags = 0;
            (*mdl).phys_addr = virt_to_phys(data as u64).unwrap_or(0);
            (*mdl).virt_addr = data as u64;
        }

        mdl
    }

    /// Free an MDL
    pub fn free(mdl: *mut Mdl) {
        if !mdl.is_null() {
            pool::free_with_tag(mdl as *mut u8, tags::MDL);
        }
    }
}

/// NET_BUFFER structure
/// Represents a network data buffer
#[repr(C)]
pub struct NetBuffer {
    pub next: *mut NetBuffer,           // Next NB in chain
    pub parent_nbl: *mut NetBufferList, // Parent NBL
    pub mdl: *mut Mdl,                 // MDL chain
    pub data_offset: u32,               // Offset to valid data
    pub data_length: u32,               // Total data length
}

impl NetBuffer {
    /// Allocate a NB with an MDL
    pub fn allocate(data: *mut u8, length: usize) -> *mut NetBuffer {
        let nb = pool::allocate_tagged(PoolType::NonPaged, core::mem::size_of::<NetBuffer>(), tags::NB) as *mut NetBuffer;
        if nb.is_null() {
            return core::ptr::null_mut();
        }

        let mdl = Mdl::allocate(data, length);
        if mdl.is_null() {
            pool::free_with_tag(nb as *mut u8, tags::NB);
            return core::ptr::null_mut();
        }

        unsafe {
            (*nb).next = core::ptr::null_mut();
            (*nb).parent_nbl = core::ptr::null_mut();
            (*nb).mdl = mdl;
            (*nb).data_offset = 0;
            (*nb).data_length = length as u32;
        }

        nb
    }

    /// Free a NB and its MDL chain
    pub fn free(nb: *mut NetBuffer) {
        if nb.is_null() {
            return;
        }

        unsafe {
            // Free MDL chain
            let mut mdl = (*nb).mdl;
            while !mdl.is_null() {
                let next = (*mdl).next;
                Mdl::free(mdl);
                mdl = next;
            }
        }

        pool::free_with_tag(nb as *mut u8, tags::NB);
    }

    /// Get pointer to data
    pub fn get_data(&self) -> Option<*mut u8> {
        if self.mdl.is_null() {
            return None;
        }
        unsafe {
            Some((*self.mdl).virt_addr as *mut u8)
        }
    }

    /// Get data length
    pub fn get_length(&self) -> u32 {
        self.data_length - self.data_offset
    }
}

/// NET_BUFFER_LIST structure
/// Represents a list of network buffers
#[repr(C)]
pub struct NetBufferList {
    pub next: *mut NetBufferList,       // Next NBL in chain
    pub parent_nb: *mut NetBuffer,      // First NB
    pub context: *mut u8,               // Protocol driver context
    pub source_om_index: u32,          // Source OM index
    pub status: i32,                    // Status code
    pub info: [usize; 8],              // Information array
    pub nbl_count: u32,                // Count of NBLs in this chain
    pub nb_count: u32,                 // Count of NBs in this chain
}

impl NetBufferList {
    /// Allocate an NBL with a NB
    pub fn allocate(data: *mut u8, length: usize) -> *mut NetBufferList {
        let nbl = pool::allocate_tagged(PoolType::NonPaged, core::mem::size_of::<NetBufferList>(), tags::NBL) as *mut NetBufferList;
        if nbl.is_null() {
            return core::ptr::null_mut();
        }

        let nb = NetBuffer::allocate(data, length);
        if nb.is_null() {
            pool::free_with_tag(nbl as *mut u8, tags::NBL);
            return core::ptr::null_mut();
        }

        unsafe {
            (*nbl).next = core::ptr::null_mut();
            (*nbl).parent_nb = nb;
            (*nbl).context = core::ptr::null_mut();
            (*nbl).source_om_index = 0;
            (*nbl).status = 0;
            (*nbl).info = [0; 8];
            (*nbl).nbl_count = 1;
            (*nbl).nb_count = 1;

            // Link NB to NBL
            (*nb).parent_nbl = nbl;
        }

        nbl
    }

    /// Allocate an NBL with multiple NBs
    pub fn allocate_multi(nb_list: &[(*mut u8, usize)]) -> *mut NetBufferList {
        if nb_list.is_empty() {
            return core::ptr::null_mut();
        }

        let nbl = pool::allocate_tagged(PoolType::NonPaged, core::mem::size_of::<NetBufferList>(), tags::NBL) as *mut NetBufferList;
        if nbl.is_null() {
            return core::ptr::null_mut();
        }

        let mut first_nb: *mut NetBuffer = core::ptr::null_mut();
        let mut prev_nb: *mut NetBuffer = core::ptr::null_mut();
        let mut nb_count: u32 = 0;

        for (data, length) in nb_list {
            let nb = NetBuffer::allocate(*data, *length);
            if nb.is_null() {
                // Clean up on failure
                if !first_nb.is_null() {
                    NetBuffer::free(first_nb);
                }
                pool::free_with_tag(nbl as *mut u8, tags::NBL);
                return core::ptr::null_mut();
            }

            unsafe {
                if first_nb.is_null() {
                    first_nb = nb;
                }
                if !prev_nb.is_null() {
                    (*prev_nb).next = nb;
                }
                (*nb).parent_nbl = nbl;
            }
            prev_nb = nb;
            nb_count += 1;
        }

        unsafe {
            (*nbl).next = core::ptr::null_mut();
            (*nbl).parent_nb = first_nb;
            (*nbl).context = core::ptr::null_mut();
            (*nbl).source_om_index = 0;
            (*nbl).status = 0;
            (*nbl).info = [0; 8];
            (*nbl).nbl_count = 1;
            (*nbl).nb_count = nb_count;
        }

        nbl
    }

    /// Free an NBL and all its NBs
    pub fn free(nbl: *mut NetBufferList) {
        if nbl.is_null() {
            return;
        }

        unsafe {
            // Free all NBs
            let mut nb = (*nbl).parent_nb;
            while !nb.is_null() {
                let next = (*nb).next;
                NetBuffer::free(nb);
                nb = next;
            }
        }

        pool::free_with_tag(nbl as *mut u8, tags::NBL);
    }

    /// Get the first NB
    pub fn first_nb(&self) -> *mut NetBuffer {
        self.parent_nb
    }

    /// Set status
    pub fn set_status(&mut self, status: i32) {
        self.status = status;
    }
}

/// Convert virtual address to physical address
fn virt_to_phys(virt: u64) -> Option<u64> {
    Some(virt & 0x7FFFFFFFFFFF)
}
