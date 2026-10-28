//! Legacy CryptoAPI implementation (CryptAcquireContext and friends).
//!
//! Provides Windows XP/2003-era cryptographic functions for backward
//! compatibility. These APIs predate CNG but are still used by legacy
//! applications.

#![allow(deprecated)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

#[repr(transparent)]
pub struct HCryptProv(pub usize);

#[repr(transparent)]
#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI hashes are compatibility-only; use bcrypt/CNG APIs"
)]
pub struct HCryptHash(pub usize);

#[repr(transparent)]
#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI keys are compatibility-only; use bcrypt/CNG APIs"
)]
pub struct HCryptKey(pub usize);

pub mod prov_type {
    pub const PROV_RSA_FULL: u32 = 1;
    pub const PROV_RSA_AES: u32 = 24;
    pub const PROV_DSS_DH: u32 = 13;
}

pub mod alg_id {
    pub const CALG_MD5: u32 = 0x00008003;
    pub const CALG_SHA1: u32 = 0x00008004;
    pub const CALG_SHA256: u32 = 0x0000800c;
    pub const CALG_SHA384: u32 = 0x0000800d;
    pub const CALG_SHA512: u32 = 0x0000800e;
    pub const CALG_RC4: u32 = 0x00006801;
    pub const CALG_DES: u32 = 0x00006601;
    pub const CALG_3DES: u32 = 0x00006603;
    pub const CALG_AES_128: u32 = 0x0000660e;
    pub const CALG_AES_192: u32 = 0x0000660f;
    pub const CALG_AES_256: u32 = 0x00006610;
    pub const CALG_RSA_KEYX: u32 = 0x0000a400;
    pub const CALG_RSA_SIGN: u32 = 0x00002400;
}

pub mod flags {
    pub const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;
    pub const CRYPT_NEWKEYSET: u32 = 0x00000008;
    pub const CRYPT_DELETEKEYSET: u32 = 0x00000010;
    pub const CRYPT_MACHINE_KEYSET: u32 = 0x00000020;
    pub const CRYPT_SILENT: u32 = 0x00000040;
}

pub mod hp {
    pub const HP_HASHVAL: u32 = 0x0002;
    pub const HP_HASHSIZE: u32 = 0x0004;
}

pub mod kp {
    pub const KP_IV: u32 = 0x0001;
    pub const KP_MODE: u32 = 0x0004;
    pub const KP_MODE_BITS: u32 = 0x0005;
    pub const KP_EFFECTIVE_KEYLEN: u32 = 0x0013;
}

pub mod cipher_mode {
    pub const CRYPT_MODE_CBC: u32 = 1;
    pub const CRYPT_MODE_ECB: u32 = 2;
    pub const CRYPT_MODE_CFB: u32 = 4;
}

/// Algorithm policy for the legacy CryptoAPI surface. These algorithm IDs
/// remain exported for ABI compatibility with binary callers, but the
/// kernel refuses them by policy: RC4 is a broken stream cipher and single
/// DES only has a 56-bit key. Every cipher/key operation below fails
/// closed (`0` / FALSE) for them and for any algorithm without a real
/// backend, so callers get a consistent refusal instead of a silent no-op.
pub fn is_alg_rejected_by_policy(alg_id: u32) -> bool {
    matches!(alg_id, alg_id::CALG_RC4 | alg_id::CALG_DES)
}

#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI algorithms are compatibility-only; use bcrypt/CNG APIs"
)]
pub struct ProviderContext {
    pub prov_type: u32,
    pub flags: u32,
    pub container: Option<String>,
}

#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI hashing is compatibility-only; use bcrypt/CNG APIs"
)]
pub struct HashContext {
    pub alg_id: u32,
    pub state: HashState,
}

#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI hash algorithms are compatibility-only; use bcrypt/CNG APIs"
)]
pub enum HashState {
    Md5(crate::crypto::hash::Md5),
    Sha1(crate::crypto::hash::Sha1),
    Sha256(crate::crypto::hash::Sha256),
    Sha384(crate::crypto::hash::Sha384),
    Sha512(crate::crypto::hash::Sha512),
}

#[deprecated(
    since = "0.1.0",
    note = "Legacy CryptoAPI key operations are compatibility-only; use bcrypt/CNG APIs"
)]
pub struct KeyContext {
    pub alg_id: u32,
    pub key_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub mode: u32,
}

static PROV_COUNTER: AtomicUsize = AtomicUsize::new(0x4000);

pub unsafe extern "C" fn crypt_acquire_context_a(
    prov: *mut usize,
    container: *const u8,
    _provider: *const u8,
    prov_type: u32,
    flags: u32,
) -> i32 {
    if prov.is_null() {
        return 0;
    }

    let container_name = if !container.is_null() {
        Some(read_ansi_string(container))
    } else {
        None
    };

    let _context = ProviderContext {
        prov_type,
        flags,
        container: container_name,
    };

    *prov = PROV_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
}

pub unsafe extern "C" fn crypt_acquire_context_w(
    prov: *mut usize,
    container: *const u16,
    _provider: *const u16,
    prov_type: u32,
    flags: u32,
) -> i32 {
    if prov.is_null() {
        return 0;
    }

    let container_name = if !container.is_null() {
        Some(read_wide_string(container))
    } else {
        None
    };

    let _context = ProviderContext {
        prov_type,
        flags,
        container: container_name,
    };

    *prov = PROV_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
}

pub unsafe extern "C" fn crypt_release_context(prov: usize, _flags: u32) -> i32 {
    if prov == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn crypt_create_hash(
    prov: usize,
    alg_id: u32,
    _key: usize,
    _flags: u32,
    hash: *mut usize,
) -> i32 {
    if prov == 0 || hash.is_null() {
        return 0;
    }

    let state = match alg_id {
        alg_id::CALG_MD5 => HashState::Md5(crate::crypto::hash::Md5::new()),
        alg_id::CALG_SHA1 => HashState::Sha1(crate::crypto::hash::Sha1::new()),
        alg_id::CALG_SHA256 => HashState::Sha256(crate::crypto::hash::Sha256::new()),
        alg_id::CALG_SHA384 => HashState::Sha384(crate::crypto::hash::Sha384::new()),
        alg_id::CALG_SHA512 => HashState::Sha512(crate::crypto::hash::Sha512::new()),
        _ => return 0,
    };

    let _context = HashContext { alg_id, state };
    let _ = _context;

    0 // FALSE: no persistent hash state is available
}

pub unsafe extern "C" fn crypt_hash_data(
    hash: usize,
    data: *const u8,
    data_len: u32,
    _flags: u32,
) -> i32 {
    if hash == 0 || data.is_null() {
        return 0;
    }

    let _input = core::slice::from_raw_parts(data, data_len as usize);
    let _ = _input;

    0 // FALSE: refusing to discard input
}

pub unsafe extern "C" fn crypt_get_hash_param(
    hash: usize,
    _param: u32,
    _data: *mut u8,
    data_len: *mut u32,
    _flags: u32,
) -> i32 {
    if hash == 0 || data_len.is_null() {
        return 0;
    }

    // No digest state is retained, so no hash parameter can be served
    // truthfully. Fail closed rather than fabricating values.
    0
}

pub unsafe extern "C" fn crypt_destroy_hash(hash: usize) -> i32 {
    if hash == 0 {
        return 0;
    }

    0 // FALSE: no cipher backend is available
}

pub unsafe extern "C" fn crypt_gen_key(
    prov: usize,
    _alg_id: u32,
    _flags: u32,
    key: *mut usize,
) -> i32 {
    if prov == 0 || key.is_null() {
        return 0;
    }

    // Generated key material cannot be stored, so no usable key handle
    // exists. Fail closed without handing out a fake handle.
    0
}

pub unsafe extern "C" fn crypt_import_key(
    prov: usize,
    data: *const u8,
    _data_len: u32,
    _pub_key: usize,
    _flags: u32,
    key: *mut usize,
) -> i32 {
    if prov == 0 || data.is_null() || key.is_null() {
        return 0;
    }

    // Imported keys are not parsed or stored; a handle handed out here
    // would make callers believe empty key material was imported.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_export_key(
    key: usize,
    _exp_key: usize,
    _blob_type: u32,
    _flags: u32,
    _data: *mut u8,
    data_len: *mut u32,
) -> i32 {
    if key == 0 || data_len.is_null() {
        return 0;
    }

    // No key material is retained, so nothing truthful can be exported.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_get_key_param(
    key: usize,
    _param: u32,
    _data: *mut u8,
    data_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key == 0 || data_len.is_null() {
        return 0;
    }

    // No key state is retained, so no key parameter can be served
    // truthfully. Fail closed rather than fabricating values.
    0
}

pub unsafe extern "C" fn crypt_set_key_param(
    key: usize,
    _param: u32,
    data: *const u8,
    _flags: u32,
) -> i32 {
    if key == 0 || data.is_null() {
        return 0;
    }

    // Parameters cannot be applied without a cipher backend.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_encrypt(
    key: usize,
    _hash: usize,
    _is_final: i32,
    _flags: u32,
    data: *mut u8,
    data_len: *mut u32,
    _buffer_len: u32,
) -> i32 {
    if key == 0 || data.is_null() || data_len.is_null() {
        return 0;
    }

    // No cipher backend: returning success here would pass caller data
    // through in plaintext while claiming encryption.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_decrypt(
    key: usize,
    _hash: usize,
    _is_final: i32,
    _flags: u32,
    data: *mut u8,
    data_len: *mut u32,
) -> i32 {
    if key == 0 || data.is_null() || data_len.is_null() {
        return 0;
    }

    // No cipher backend: returning success here would leave caller data
    // untouched while claiming a decryption result.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_destroy_key(key: usize) -> i32 {
    if key == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn crypt_gen_random(prov: usize, len: u32, buffer: *mut u8) -> i32 {
    if prov == 0 || buffer.is_null() {
        return 0;
    }

    let output = core::slice::from_raw_parts_mut(buffer, len as usize);

    if crate::crypto::csprng::fill(output) {
        1 // TRUE
    } else {
        0 // FALSE
    }
}

pub unsafe extern "C" fn crypt_sign_hash_a(
    hash: usize,
    _key_spec: u32,
    _description: *const u8,
    _flags: u32,
    _signature: *mut u8,
    sig_len: *mut u32,
) -> i32 {
    if hash == 0 || sig_len.is_null() {
        return 0;
    }

    // No signing backend: a zeroed signature would be a forgery waiting
    // to happen. Fail closed.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_verify_signature_a(
    hash: usize,
    signature: *const u8,
    _sig_len: u32,
    pub_key: usize,
    _description: *const u8,
    _flags: u32,
) -> i32 {
    if hash == 0 || signature.is_null() || pub_key == 0 {
        return 0;
    }

    // No verification backend: accepting every signature would make this
    // call a no-op security check.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_duplicate_hash(
    hash: usize,
    _reserved: *mut u32,
    _flags: u32,
    new_hash: *mut usize,
) -> i32 {
    if hash == 0 || new_hash.is_null() {
        return 0;
    }

    // No hash state is retained, so there is nothing to duplicate.
    0 // FALSE
}

pub unsafe extern "C" fn crypt_duplicate_key(
    key: usize,
    _reserved: *mut u32,
    _flags: u32,
    new_key: *mut usize,
) -> i32 {
    if key == 0 || new_key.is_null() {
        return 0;
    }

    // No key state is retained, so there is nothing to duplicate.
    0 // FALSE
}

unsafe fn read_ansi_string(ptr: *const u8) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 1024 {
            break;
        }
    }

    let slice = core::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(slice).into_owned()
}

unsafe fn read_wide_string(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 1024 {
            break;
        }
    }

    let slice = core::slice::from_raw_parts(ptr, len);
    let mut result = String::new();

    for &c in slice {
        if c < 128 {
            result.push(c as u8 as char);
        } else {
            result.push('?');
        }
    }

    result
}
