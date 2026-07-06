//! MDL (Memory Descriptor List)
//
//! Memory descriptor list support

pub struct Mdl {
    pub next: *mut Mdl,
    pub size: u16,
    pub mdl_flags: u16,
}

impl Mdl {
    pub fn new() -> Self {
        Self {
            next: core::ptr::null_mut(),
            size: 0,
            mdl_flags: 0,
        }
    }
}