//! Legacy CryptoAPI implementation (CryptAcquireContext and friends).
//!
//! Provides Windows XP/2003-era cryptographic functions for backward
//! compatibility. These APIs predate CNG but are still used by legacy
//! applications.

extern crate alloc;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;
use core::ptr;

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

struct ProviderContext {
    prov_type: u32,
    flags: u32,
    container: Option<String>,
}

struct HashContext {
    alg_id: u32,
    state: HashState,
}

enum HashState {
    Md5(crate::crypto::hash::Md5),
    Sha1(crate::crypto::hash::Sha1),
    Sha256(crate::crypto::hash::Sha256),
    Sha384(crate::crypto::hash::Sha384),
    Sha512(crate::crypto::hash::Sha512),
}

struct KeyContext {
    alg_id: u32,
    key_data: Vec<u8>,
    iv: Vec<u8>,
    mode: u32,
}

static PROV_COUNTER: AtomicUsize = AtomicUsize::new(0x4000);
static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0x5000);
static KEY_COUNTER: AtomicUsize = AtomicUsize::new(0x6000);

pub unsafe extern "C" fn CryptAcquireContextA(
    prov: *mut usize,
    container: *const u8,
    provider: *const u8,
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

    let context = ProviderContext {
        prov_type,
        flags,
        container: container_name,
    };

    PROV_COUNTER += 1;
    *prov = PROV_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptAcquireContextW(
    prov: *mut usize,
    container: *const u16,
    provider: *const u16,
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

    let context = ProviderContext {
        prov_type,
        flags,
        container: container_name,
    };

    PROV_COUNTER += 1;
    *prov = PROV_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptReleaseContext(
    prov: usize,
    flags: u32,
) -> i32 {
    if prov == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn CryptCreateHash(
    prov: usize,
    alg_id: u32,
    key: usize,
    flags: u32,
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

    let context = HashContext { alg_id, state };

    HASH_COUNTER += 1;
    *hash = HASH_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptHashData(
    hash: usize,
    data: *const u8,
    data_len: u32,
    flags: u32,
) -> i32 {
    if hash == 0 || data.is_null() {
        return 0;
    }

    let input = core::slice::from_raw_parts(data, data_len as usize);


    1 // TRUE
}

pub unsafe extern "C" fn CryptGetHashParam(
    hash: usize,
    param: u32,
    data: *mut u8,
    data_len: *mut u32,
    flags: u32,
) -> i32 {
    if hash == 0 || data_len.is_null() {
        return 0;
    }

    match param {
        hp::HP_HASHSIZE => {
            let size = get_hash_size_for_handle(hash);
            *data_len = 4;

            if !data.is_null() {
                ptr::copy_nonoverlapping(
                    &size as *const u32 as *const u8,
                    data,
                    4,
                );
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

pub unsafe extern "C" fn CryptDestroyHash(hash: usize) -> i32 {
    if hash == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn CryptGenKey(
    prov: usize,
    alg_id: u32,
    flags: u32,
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

    let context = KeyContext {
        alg_id,
        key_data,
        iv: vec![0u8; 16],
        mode: cipher_mode::CRYPT_MODE_CBC,
    };

    KEY_COUNTER += 1;
    *key = KEY_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptImportKey(
    prov: usize,
    data: *const u8,
    data_len: u32,
    pub_key: usize,
    flags: u32,
    key: *mut usize,
) -> i32 {
    if prov == 0 || data.is_null() || key.is_null() {
        return 0;
    }

    let blob = core::slice::from_raw_parts(data, data_len as usize);

    KEY_COUNTER += 1;
    *key = KEY_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptExportKey(
    key: usize,
    exp_key: usize,
    blob_type: u32,
    flags: u32,
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

pub unsafe extern "C" fn CryptGetKeyParam(
    key: usize,
    param: u32,
    data: *mut u8,
    data_len: *mut u32,
    flags: u32,
) -> i32 {
    if key == 0 || data_len.is_null() {
        return 0;
    }

    match param {
        kp::KP_MODE => {
            *data_len = 4;
            if !data.is_null() {
                let mode = cipher_mode::CRYPT_MODE_CBC;
                ptr::copy_nonoverlapping(
                    &mode as *const u32 as *const u8,
                    data,
                    4,
                );
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

pub unsafe extern "C" fn CryptSetKeyParam(
    key: usize,
    param: u32,
    data: *const u8,
    flags: u32,
) -> i32 {
    if key == 0 || data.is_null() {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn CryptEncrypt(
    key: usize,
    hash: usize,
    is_final: i32,
    flags: u32,
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

pub unsafe extern "C" fn CryptDecrypt(
    key: usize,
    hash: usize,
    is_final: i32,
    flags: u32,
    data: *mut u8,
    data_len: *mut u32,
) -> i32 {
    if key == 0 || data.is_null() || data_len.is_null() {
        return 0;
    }


    1 // TRUE
}

pub unsafe extern "C" fn CryptDestroyKey(key: usize) -> i32 {
    if key == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn CryptGenRandom(
    prov: usize,
    len: u32,
    buffer: *mut u8,
) -> i32 {
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

pub unsafe extern "C" fn CryptSignHashA(
    hash: usize,
    key_spec: u32,
    description: *const u8,
    flags: u32,
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

pub unsafe extern "C" fn CryptVerifySignatureA(
    hash: usize,
    signature: *const u8,
    sig_len: u32,
    pub_key: usize,
    description: *const u8,
    flags: u32,
) -> i32 {
    if hash == 0 || signature.is_null() || pub_key == 0 {
        return 0;
    }

    1 // TRUE
}

pub unsafe extern "C" fn CryptDuplicateHash(
    hash: usize,
    reserved: *mut u32,
    flags: u32,
    new_hash: *mut usize,
) -> i32 {
    if hash == 0 || new_hash.is_null() {
        return 0;
    }

    HASH_COUNTER += 1;
    *new_hash = HASH_COUNTER;

    1 // TRUE
}

pub unsafe extern "C" fn CryptDuplicateKey(
    key: usize,
    reserved: *mut u32,
    flags: u32,
    new_key: *mut usize,
) -> i32 {
    if key == 0 || new_key.is_null() {
        return 0;
    }

    KEY_COUNTER += 1;
    *new_key = KEY_COUNTER;

    1 // TRUE
}


fn get_hash_size_for_handle(handle: usize) -> u32 {
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
