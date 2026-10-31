//! ALPC message attributes
//!
//! Windows 7 ALPC supports extended message attributes for:
//! - handle passing
//! - Security context
//! - View (section) attributes
//! - Direct user-mode data transfer
//!
//! This module implements the ALPC attribute system.

use super::section::AlpcSectionView;

pub const ALPC_ATTR_SECURITY: u32 = 0x00000001;
pub const ALPC_ATTR_VIEW: u32 = 0x00000002;
pub const ALPC_ATTR_CONTEXT: u32 = 0x00000004;
pub const ALPC_ATTR_HANDLE: u32 = 0x00000008;
pub const ALPC_ATTR_WORK_ON_BEHALF: u32 = 0x00000010;
pub const ALPC_ATTR_DIRECT: u32 = 0x00000020;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityAttribute {
    pub security_qos: u32,
    pub context_tracking: u32,
    pub effective_only: bool,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ViewAttribute {
    pub view: AlpcSectionView,
    pub flags: u32,
}

impl Default for ViewAttribute {
    fn default() -> Self {
        Self {
            view: AlpcSectionView::empty(),
            flags: 0,
        }
    }
}

/// Context attribute for user data
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ContextAttribute {
    pub port_context: u64,
    pub message_context: u64,
    pub sequence: u32,
    pub message_id: u64,
    pub callback_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HandleAttribute {
    pub flags: u32,
    pub handle: u64,
    pub object_type: u32,
    pub desired_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkOnBehalfAttribute {
    pub thread_id: u64,
    pub thread_creation_time: u64,
}

#[repr(C)]
pub struct AlpcMessageAttributes {
    pub valid_attrs: u32,
    pub security: SecurityAttribute,
    pub view: ViewAttribute,
    pub context: ContextAttribute,
    pub handle: HandleAttribute,
    pub work_on_behalf: WorkOnBehalfAttribute,
}

impl AlpcMessageAttributes {
    pub const fn new() -> Self {
        Self {
            valid_attrs: 0,
            security: SecurityAttribute {
                security_qos: 0,
                context_tracking: 0,
                effective_only: false,
            },
            view: ViewAttribute {
                view: AlpcSectionView::empty(),
                flags: 0,
            },
            context: ContextAttribute {
                port_context: 0,
                message_context: 0,
                sequence: 0,
                message_id: 0,
                callback_id: 0,
            },
            handle: HandleAttribute {
                flags: 0,
                handle: 0,
                object_type: 0,
                desired_access: 0,
            },
            work_on_behalf: WorkOnBehalfAttribute {
                thread_id: 0,
                thread_creation_time: 0,
            },
        }
    }

    pub fn has_attribute(&self, flag: u32) -> bool {
        (self.valid_attrs & flag) != 0
    }

    pub fn set_attribute(&mut self, flag: u32) {
        self.valid_attrs |= flag;
    }

    pub fn clear_attribute(&mut self, flag: u32) {
        self.valid_attrs &= !flag;
    }
}

impl Default for AlpcMessageAttributes {
    fn default() -> Self {
        Self::new()
    }
}

pub fn validate_attributes(attrs: &AlpcMessageAttributes) -> bool {
    if attrs.has_attribute(ALPC_ATTR_VIEW) && attrs.view.view.section_handle == 0 {
        return false;
    }

    if attrs.has_attribute(ALPC_ATTR_HANDLE) && attrs.handle.handle == 0 {
        return false;
    }

    true
}
