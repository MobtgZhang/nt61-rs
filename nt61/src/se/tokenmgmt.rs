//! Token Management Operations
//!
//! Implements Windows token management APIs:
//!   - Token creation (NtCreateToken)
//!   - Token duplication (NtDuplicateToken)
//!   - Privilege adjustment (NtAdjustPrivilegesToken)
//!   - Group adjustment (NtAdjustGroupsToken)
//!   - Token filtering (restricted tokens)
//!   - Token query/set operations
//!
//! References: Windows SDK, WRK

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use alloc::vec::Vec;

use super::token::{
    Token, TokenTypeEnum, TokenGroup, TokenPrivilege, ImpersonationLevel,
    Luid, SE_GROUP_ENABLED, SE_PRIVILEGE_ENABLED, TOKEN_MAX_GROUPS, TOKEN_MAX_PRIVILEGES,
};
use super::sid::Sid;

pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x00000004;

pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;

pub fn se_create_token(
    user: Sid,
    groups: &[TokenGroup],
    privileges: &[TokenPrivilege],
    token_type: TokenTypeEnum,
    impersonation_level: ImpersonationLevel,
) -> *mut Token {
    let token_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Token>(),
    ) as *mut Token;

    if token_ptr.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        let token = &mut *token_ptr;
        *token = Token::new();

        token.user = user;
        token.token_type = token_type;
        token.impersonation_level = impersonation_level;
        token.refcount = 1;

        let group_count = groups.len().min(TOKEN_MAX_GROUPS);
        for i in 0..group_count {
            token.groups[i] = groups[i];
        }
        token.group_count = group_count;

        let priv_count = privileges.len().min(TOKEN_MAX_PRIVILEGES);
        for i in 0..priv_count {
            token.privileges[i] = privileges[i];
        }
        token.privilege_count = priv_count;

        token.primary_group = super::sid::SID_USERS;

        static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1000);
        token.token_id = Luid::from_u64(NEXT_TOKEN_ID);
        NEXT_TOKEN_ID += 1;

        static NEXT_AUTH_ID: AtomicU64 = AtomicU64::new(2000);
        token.authentication_id = Luid::from_u64(NEXT_AUTH_ID);
        NEXT_AUTH_ID += 1;
    }

    token_ptr
}

pub fn se_duplicate_token(
    existing_token: *const Token,
    impersonation_level: ImpersonationLevel,
    token_type: TokenTypeEnum,
) -> *mut Token {
    if existing_token.is_null() {
        return core::ptr::null_mut();
    }

    let new_token_ptr = crate::mm::pool::allocate(
        crate::mm::pool::PoolType::NonPaged,
        core::mem::size_of::<Token>(),
    ) as *mut Token;

    if new_token_ptr.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        let src = &*existing_token;
        let dst = &mut *new_token_ptr;

        core::ptr::copy_nonoverlapping(src as *const Token, dst as *mut Token, 1);

        dst.token_type = token_type;
        dst.impersonation_level = impersonation_level;

        static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1000);
        dst.token_id = Luid::from_u64(NEXT_TOKEN_ID);
        NEXT_TOKEN_ID += 1;

        dst.authentication_id = src.authentication_id;

        dst.refcount = 1;

    }

    new_token_ptr
}

pub fn se_filter_token(
    existing_token: *const Token,
    flags: u32,
    sids_to_disable: &[Sid],
    privileges_to_delete: &[Luid],
    restricted_sids: &[Sid],
) -> *mut Token {
    if existing_token.is_null() {
        return core::ptr::null_mut();
    }

    let new_token = se_duplicate_token(
        existing_token,
        unsafe { (*existing_token).impersonation_level },
        unsafe { (*existing_token).token_type },
    );

    if new_token.is_null() {
        return core::ptr::null_mut();
    }

    unsafe {
        let token = &mut *new_token;

        for sid_to_disable in sids_to_disable {
            for i in 0..token.group_count {
                if token.groups[i].sid.equals(sid_to_disable) {
                    token.groups[i].attributes &= !SE_GROUP_ENABLED;
                    token.groups[i].attributes |= super::token::SE_GROUP_USE_FOR_DENY_ONLY;
                }
            }
        }

        for luid_to_delete in privileges_to_delete {
            for i in 0..token.privilege_count {
                if token.privileges[i].luid.equals(luid_to_delete) {
                    token.privileges[i].attributes = super::token::SE_PRIVILEGE_REMOVED;
                }
            }
        }

        for restricted_sid in restricted_sids {
            if token.group_count < TOKEN_MAX_GROUPS {
                token.groups[token.group_count] = TokenGroup {
                    sid: *restricted_sid,
                    attributes: SE_GROUP_ENABLED | super::token::SE_GROUP_USE_FOR_DENY_ONLY,
                };
                token.group_count += 1;
            }
        }

        token.flags |= super::token::TOKEN_WRITE_RESTRICTED;
    }

    new_token
}

pub fn se_token_is_restricted(token: *const Token) -> bool {
    if token.is_null() {
        return false;
    }
    unsafe {
        ((*token).flags & super::token::TOKEN_WRITE_RESTRICTED) != 0
    }
}

pub fn se_adjust_privileges_token(
    token: *mut Token,
    disable_all_privileges: bool,
    new_state: &[TokenPrivilege],
    mut previous_state: Option<&mut Vec<TokenPrivilege>>,
) -> bool {
    if token.is_null() {
        return false;
    }

    unsafe {
        let tok = &mut *token;

        if disable_all_privileges {
            for i in 0..tok.privilege_count {
                if let Some(prev) = previous_state.as_mut() {
                    prev.push(tok.privileges[i]);
                }
                tok.privileges[i].attributes &= !SE_PRIVILEGE_ENABLED;
            }
            return true;
        }

        let mut all_found = true;
        for new_priv in new_state {
            let mut found = false;
            for i in 0..tok.privilege_count {
                if tok.privileges[i].luid.equals(&new_priv.luid) {
                    if let Some(prev) = previous_state.as_mut() {
                        prev.push(tok.privileges[i]);
                    }
                    tok.privileges[i].attributes = new_priv.attributes;
                    found = true;
                    break;
                }
            }
            if !found {
                all_found = false;
            }
        }

        all_found
    }
}

pub fn se_adjust_groups_token(
    token: *mut Token,
    reset_to_default: bool,
    new_state: &[TokenGroup],
    mut previous_state: Option<&mut Vec<TokenGroup>>,
) -> bool {
    if token.is_null() {
        return false;
    }

    unsafe {
        let tok = &mut *token;

        if reset_to_default {
            for i in 0..tok.group_count {
                if let Some(prev) = previous_state.as_mut() {
                    prev.push(tok.groups[i]);
                }
                if (tok.groups[i].attributes & super::token::SE_GROUP_ENABLED_BY_DEFAULT) != 0 {
                    tok.groups[i].attributes |= SE_GROUP_ENABLED;
                } else {
                    tok.groups[i].attributes &= !SE_GROUP_ENABLED;
                }
            }
            return true;
        }

        let mut all_found = true;
        for new_group in new_state {
            let mut found = false;
            for i in 0..tok.group_count {
                if tok.groups[i].sid.equals(&new_group.sid) {
                    if let Some(prev) = previous_state.as_mut() {
                        prev.push(tok.groups[i]);
                    }
                    tok.groups[i].attributes = new_group.attributes;
                    found = true;
                    break;
                }
            }
            if !found {
                all_found = false;
            }
        }

        all_found
    }
}

pub fn se_query_information_token(
    token: *const Token,
    info_class: u32,
    buffer: *mut u8,
    buffer_length: u32,
    return_length: *mut u32,
) -> bool {
    if token.is_null() || return_length.is_null() {
        return false;
    }

    unsafe {
        let tok = &*token;

        match info_class {
            super::token::TokenUser => {
                let required = core::mem::size_of::<Sid>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut Sid, tok.user);
                true
            }
            super::token::TokenGroups => {
                let required = 4 + tok.group_count * core::mem::size_of::<TokenGroup>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut u32, tok.group_count as u32);
                let groups_ptr = buffer.add(4) as *mut TokenGroup;
                for i in 0..tok.group_count {
                    core::ptr::write(groups_ptr.add(i), tok.groups[i]);
                }
                true
            }
            super::token::TokenPrivileges => {
                let required = 4 + tok.privilege_count * core::mem::size_of::<TokenPrivilege>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut u32, tok.privilege_count as u32);
                let privs_ptr = buffer.add(4) as *mut TokenPrivilege;
                for i in 0..tok.privilege_count {
                    core::ptr::write(privs_ptr.add(i), tok.privileges[i]);
                }
                true
            }
            super::token::TokenType => {
                let required = core::mem::size_of::<TokenTypeEnum>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut TokenTypeEnum, tok.token_type);
                true
            }
            super::token::TokenImpersonationLevel => {
                let required = core::mem::size_of::<ImpersonationLevel>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut ImpersonationLevel, tok.impersonation_level);
                true
            }
            super::token::TokenSessionId => {
                let required = core::mem::size_of::<u32>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut u32, tok.session_id);
                true
            }
            super::token::TokenIntegrityLevel => {
                let required = core::mem::size_of::<u32>();
                *return_length = required as u32;
                if buffer.is_null() || buffer_length < required as u32 {
                    return false;
                }
                core::ptr::write(buffer as *mut u32, tok.integrity_level_rid);
                true
            }
            _ => {
                *return_length = 0;
                false
            }
        }
    }
}

pub fn se_set_information_token(
    token: *mut Token,
    info_class: u32,
    buffer: *const u8,
    buffer_length: u32,
) -> bool {
    if token.is_null() || buffer.is_null() {
        return false;
    }

    unsafe {
        let tok = &mut *token;

        match info_class {
            super::token::TokenSessionId => {
                if buffer_length < core::mem::size_of::<u32>() as u32 {
                    return false;
                }
                tok.session_id = *(buffer as *const u32);
                true
            }
            super::token::TokenIntegrityLevel => {
                if buffer_length < core::mem::size_of::<u32>() as u32 {
                    return false;
                }
                tok.integrity_level_rid = *(buffer as *const u32);
                true
            }
            _ => false,
        }
    }
}

pub fn se_token_type(token: *const Token) -> TokenTypeEnum {
    if token.is_null() {
        return TokenTypeEnum::TokenPrimary;
    }
    unsafe { (*token).token_type }
}

pub fn se_token_impersonation_level(token: *const Token) -> ImpersonationLevel {
    if token.is_null() {
        return ImpersonationLevel::SecurityAnonymous;
    }
    unsafe { (*token).impersonation_level }
}

pub fn init() {
}
