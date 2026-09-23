//! AppContainer and Capability Support
//!
//! Implements Windows 8+ AppContainer isolation and capability-based security.
//! AppContainers provide sandboxing for apps by:
//!   - Running with a unique AppContainer SID
//!   - Restricting access to resources unless explicitly granted capabilities
//!   - Enforcing network isolation
//!   - Limiting file system access
//!
//! Capabilities are special SIDs that grant specific permissions:
//!   - internetClient
//!   - privateNetworkClientServer
//!   - documentsLibrary
//!   - picturesLibrary
//!   - etc.
//!
//! References: Windows SDK, Windows Internals

use alloc::vec::Vec;

use super::sid::Sid;
use super::token::{Token, TokenGroup, SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT};

pub const TOKEN_IS_APP_CONTAINER: u32 = 0x00000001;
pub const TOKEN_IS_APP_SILO: u32 = 0x00000002;

pub mod capabilities {
    pub const CAPABILITY_INTERNET_CLIENT: u32 = 0x00000001;
    pub const CAPABILITY_INTERNET_CLIENT_SERVER: u32 = 0x00000002;
    pub const CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER: u32 = 0x00000003;
    pub const CAPABILITY_PICTURES_LIBRARY: u32 = 0x00000004;
    pub const CAPABILITY_VIDEOS_LIBRARY: u32 = 0x00000005;
    pub const CAPABILITY_MUSIC_LIBRARY: u32 = 0x00000006;
    pub const CAPABILITY_DOCUMENTS_LIBRARY: u32 = 0x00000007;
    pub const CAPABILITY_ENTERPRISE_AUTHENTICATION: u32 = 0x00000008;
    /// Shared user certificates capability

    pub const CAPABILITY_SHARED_USER_CERTIFICATES: u32 = 0x00000009;
    pub const CAPABILITY_REMOVABLE_STORAGE: u32 = 0x0000000A;
    pub const CAPABILITY_APPOINTMENTS: u32 = 0x0000000B;
    pub const CAPABILITY_CONTACTS: u32 = 0x0000000C;
}

pub fn create_capability_sid(capability_rid: u32) -> Sid {
    let ia = [0, 0, 0, 0, 0, 15];
    Sid::with_authority_and_subs_arr(
        ia,
        2,
        3, capability_rid, 0, 0, 0, 0, 0, 0,
    )
}

pub fn create_app_container_sid(package_name: &str) -> Sid {
    let ia = [0, 0, 0, 0, 0, 15];
    let hash = simple_string_hash(package_name);
    Sid::with_authority_and_subs_arr(
        ia,
        2,
        2, hash, 0, 0, 0, 0, 0, 0,
    )
}

fn simple_string_hash(s: &str) -> u32 {
    let mut hash = 0u32;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}

pub fn se_token_is_app_container(token: *const Token) -> bool {
    if token.is_null() {
        return false;
    }
    unsafe {
        ((*token).flags & TOKEN_IS_APP_CONTAINER) != 0
    }
}

pub fn se_create_app_container_token(
    parent_token: *const Token,
    package_sid: &Sid,
    capabilities: &[u32],
) -> *mut Token {
    if parent_token.is_null() {
        return core::ptr::null_mut();
    }

    let new_token = super::tokenmgmt::se_duplicate_token(
        parent_token,
        unsafe { (*parent_token).impersonation_level },
        unsafe { (*parent_token).token_type },
    );

    if new_token.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        let token = &mut *new_token;

        token.flags |= TOKEN_IS_APP_CONTAINER;

        // Set the AppContainer SID as the user
        token.user = *package_sid;

        for &cap_rid in capabilities {
            let cap_sid = create_capability_sid(cap_rid);
            token.add_group(TokenGroup {
                sid: cap_sid,
                attributes: SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT,
            });
        }

        for i in 0..token.privilege_count {
            token.privileges[i].attributes &= !super::token::SE_PRIVILEGE_ENABLED;
        }
    }

    new_token
}

pub fn se_query_app_container_info(
    token: *const Token,
) -> Option<(Sid, Vec<Sid>)> {
    if !se_token_is_app_container(token) {
        return None;
    }

    unsafe {
        let tok = &*token;
        let package_sid = tok.user;

        let mut capabilities = Vec::new();
        for i in 0..tok.group_count {
            let sid = &tok.groups[i].sid;
            if sid.identifier_authority() == 15 &&
               sid.sub_authority_count >= 1 &&
               sid.sub_authority[0] == 3 {
                capabilities.push(*sid);
            }
        }

        Some((package_sid, capabilities))
    }
}

pub fn se_token_has_capability(token: *const Token, capability_rid: u32) -> bool {
    if !se_token_is_app_container(token) {
        return false;
    }

    let cap_sid = create_capability_sid(capability_rid);

    unsafe {
        let tok = &*token;
        for i in 0..tok.group_count {
            if tok.groups[i].sid.equals(&cap_sid) &&
               (tok.groups[i].attributes & SE_GROUP_ENABLED) != 0 {
                return true;
            }
        }
    }

    false
}

pub fn se_app_container_access_check(
    token: *const Token,
    desired_access: u32,
    resource_type: AppContainerResourceType,
) -> bool {
    if !se_token_is_app_container(token) {
        // Not an AppContainer, use normal access check
        return true;
    }

    let required_capability = match resource_type {
        AppContainerResourceType::Network => capabilities::CAPABILITY_INTERNET_CLIENT,
        AppContainerResourceType::PrivateNetwork => capabilities::CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER,
        AppContainerResourceType::PicturesLibrary => capabilities::CAPABILITY_PICTURES_LIBRARY,
        AppContainerResourceType::VideosLibrary => capabilities::CAPABILITY_VIDEOS_LIBRARY,
        AppContainerResourceType::MusicLibrary => capabilities::CAPABILITY_MUSIC_LIBRARY,
        AppContainerResourceType::DocumentsLibrary => capabilities::CAPABILITY_DOCUMENTS_LIBRARY,
        AppContainerResourceType::RemovableStorage => capabilities::CAPABILITY_REMOVABLE_STORAGE,
        AppContainerResourceType::EnterpriseAuth => capabilities::CAPABILITY_ENTERPRISE_AUTHENTICATION,
    };

    se_token_has_capability(token, required_capability)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppContainerResourceType {
    Network,
    PrivateNetwork,
    PicturesLibrary,
    VideosLibrary,
    MusicLibrary,
    DocumentsLibrary,
    RemovableStorage,
    EnterpriseAuth,
}

pub fn se_derive_app_container_sid_from_name(
    package_name: &str,
) -> *mut Sid {
    let sid = create_app_container_sid(package_name);
    let sid_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Sid>(),
    ) as *mut Sid;

    if !sid_ptr.is_null() {
        unsafe {
            *sid_ptr = sid;
        }
    }

    sid_ptr
}

#[repr(C)]
pub struct SecurityAttributes {
    pub app_container_sid: Sid,
    pub capabilities: [Sid; 16],
    pub capability_count: usize,
}

impl SecurityAttributes {
    pub fn new() -> Self {
        Self {
            app_container_sid: Sid::new(),
            capabilities: [Sid::new(); 16],
            capability_count: 0,
        }
    }

    pub fn add_capability(&mut self, capability_rid: u32) -> bool {
        if self.capability_count >= 16 {
            return false;
        }
        self.capabilities[self.capability_count] = create_capability_sid(capability_rid);
        self.capability_count += 1;
        true
    }
}

pub fn init() {
}
