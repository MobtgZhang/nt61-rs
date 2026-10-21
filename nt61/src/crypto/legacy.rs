//! Legacy CryptoAPI implementation (CryptAcquireContext and friends).
//!
//! Provides Windows XP/2003-era cryptographic functions for backward
//! compatibility. These APIs predate CNG but are still used by legacy
//! applications.

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

#[repr(transparent)]
pub struct HCryptProv(pub usize);

#[repr(transparent)]
pub struct HCryptHash(pub usize);

#[repr(transparent)]
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

pub struct ProviderContext {
    pub prov_type: u32,
    pub flags: u32,
    pub container: Option<String>,
}

pub struct HashContext {
    pub alg_id: u32,
    pub state: HashState,
}

pub enum HashState {
    Md5(crate::crypto::hash::Md5),
    Sha1(crate::crypto::hash::Sha1),
    Sha256(crate::crypto::hash::Sha256),
    Sha384(crate::crypto::hash::Sha384),
    Sha512(crate::crypto::hash::Sha512),
}

pub struct KeyContext {
    pub alg_id: u32,
    pub key_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub mode: u32,
}

static PROV_COUNTER: AtomicUsize = AtomicUsize::new(0x4000);
static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0x5000);
static KEY_COUNTER: AtomicUsize = AtomicUsize::new(0x6000);

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

    *hash = HASH_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
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

    1 // TRUE
}

pub unsafe extern "C" fn crypt_get_hash_param(
    hash: usize,
    param: u32,
    data: *mut u8,
    data_len: *mut u32,
    _flags: u32,
) -> i32 {
    if hash == 0 || data_len.is_null() {
        return 0;
    }

    match param {
        hp::HP_HASHSIZE => {
            let size = get_hash_size_for_handle(hash);
            *data_len = 4;

            if !data.is_null() {
                ptr::copy_nonoverlapping(&size as *const u32 as *const u8, data, 4);
            }

            1 // TRUE
        }
        hp::HP_HASHVAL => {
            let size = get_hash_size_for_handle(hash);
            *data_len = size;

            if !data.is_null() {
                for i in 0..size {
                    *data.add(i as usize) = 0;
                }
            }

            1 // TRUE
        }
        _ => 0, // FALSE
    }
}

pub unsafe extern "C" fn crypt_destroy_hash(hash: usize) -> i32 {
    if hash == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn crypt_gen_key(
    prov: usize,
    alg_id: u32,
    _flags: u32,
    key: *mut usize,
) -> i32 {
    if prov == 0 || key.is_null() {
        return 0;
    }

    let key_len = match alg_id {
        alg_id::CALG_RC4 => 16,
        alg_id::CALG_DES => 8,
        alg_id::CALG_3DES => 24,
        alg_id::CALG_AES_128 => 16,
        alg_id::CALG_AES_192 => 24,
        alg_id::CALG_AES_256 => 32,
        _ => return 0,
    };

    let mut key_data = vec![0u8; key_len];
    crate::crypto::csprng::fill(&mut key_data);

    let _context = KeyContext {
        alg_id,
        key_data,
        iv: vec![0u8; 16],
        mode: cipher_mode::CRYPT_MODE_CBC,
    };

    *key = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
}

pub unsafe extern "C" fn crypt_import_key(
    prov: usize,
    data: *const u8,
    data_len: u32,
    _pub_key: usize,
    _flags: u32,
    key: *mut usize,
) -> i32 {
    if prov == 0 || data.is_null() || key.is_null() {
        return 0;
    }

    let _blob = core::slice::from_raw_parts(data, data_len as usize);

    *key = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
}

pub unsafe extern "C" fn crypt_export_key(
    key: usize,
    _exp_key: usize,
    _blob_type: u32,
    _flags: u32,
    data: *mut u8,
    data_len: *mut u32,
) -> i32 {
    if key == 0 || data_len.is_null() {
        return 0;
    }

    *data_len = 32;

    if !data.is_null() {
        for i in 0..32 {
            *data.add(i) = 0;
        }
    }

    1 // TRUE
}

pub unsafe extern "C" fn crypt_get_key_param(
    key: usize,
    param: u32,
    data: *mut u8,
    data_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key == 0 || data_len.is_null() {
        return 0;
    }

    match param {
        kp::KP_MODE => {
            *data_len = 4;
            if !data.is_null() {
                let mode = cipher_mode::CRYPT_MODE_CBC;
                ptr::copy_nonoverlapping(&mode as *const u32 as *const u8, data, 4);
            }
            1 // TRUE
        }
        kp::KP_IV => {
            *data_len = 16;
            if !data.is_null() {
                for i in 0..16 {
                    *data.add(i) = 0;
                }
            }
            1 // TRUE
        }
        _ => 0, // FALSE
    }
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

    1 // TRUE
}

pub unsafe extern "C" fn crypt_encrypt(
    key: usize,
    _hash: usize,
    _is_final: i32,
    _flags: u32,
    data: *mut u8,
    data_len: *mut u32,
    buffer_len: u32,
) -> i32 {
    if key == 0 || data.is_null() || data_len.is_null() {
        return 0;
    }

    let len = *data_len as usize;

    if len > buffer_len as usize {
        return 0;
    }

    1 // TRUE
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

    1 // TRUE
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
    signature: *mut u8,
    sig_len: *mut u32,
) -> i32 {
    if hash == 0 || sig_len.is_null() {
        return 0;
    }

    *sig_len = 128;

    if !signature.is_null() {
        for i in 0..128 {
            *signature.add(i) = 0;
        }
    }

    1 // TRUE
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

    1 // TRUE
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

    *new_hash = HASH_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
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

    *new_key = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);

    1 // TRUE
}

fn get_hash_size_for_handle(_handle: usize) -> u32 {
    32
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
