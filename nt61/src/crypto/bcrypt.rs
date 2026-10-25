//! Cryptography Next Generation (CNG) API implementation.
//!
//! BCrypt functions for Windows Vista+ crypto operations. Provides
//! modern cryptographic primitives through algorithm providers.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::crypto::rsa::RsaPrivateKey;
use crate::crypto::cipher::Aes128;
use crate::crypto::cipher::Aes256;
use crate::ke::sync::Spinlock;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

#[repr(transparent)]
pub struct BcryptAlgHandle(pub usize);

#[repr(transparent)]
pub struct BcryptHashHandle(pub usize);

#[repr(transparent)]
pub struct BcryptKeyHandle(pub usize);

pub mod algorithm {
    pub const AES: &str = "AES";
    pub const DES: &str = "DES";
    pub const DES3: &str = "3DES";
    pub const RC4: &str = "RC4";
    pub const RSA: &str = "RSA";
    pub const SHA1: &str = "SHA1";
    pub const SHA256: &str = "SHA256";
    pub const SHA384: &str = "SHA384";
    pub const SHA512: &str = "SHA512";
    pub const MD5: &str = "MD5";
}

pub mod property {
    pub const OBJECT_LENGTH: &str = "ObjectLength";
    pub const HASH_LENGTH: &str = "HashDigestLength";
    pub const BLOCK_LENGTH: &str = "BlockLength";
    pub const CHAINING_MODE: &str = "ChainingMode";
    pub const KEY_LENGTH: &str = "KeyLength";
}

pub mod chaining_mode {
    pub const CBC: &str = "ChainingModeCBC";
    pub const ECB: &str = "ChainingModeECB";
    pub const CFB: &str = "ChainingModeCFB";
    pub const CCM: &str = "ChainingModeCCM";
    pub const GCM: &str = "ChainingModeGCM";
}

pub mod flags {
    pub const ALG_HANDLE_HMAC: u32 = 0x00000008;
    pub const BLOCK_PADDING: u32 = 0x00000001;
}

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_BUFFER_TOO_SMALL: i32 = -1073741789; // 0xC0000023
pub const STATUS_INVALID_PARAMETER: i32 = -1073741811; // 0xC000000D
pub const STATUS_INVALID_HANDLE: i32 = -1073741816; // 0xC0000008
pub const STATUS_NOT_SUPPORTED: i32 = -1073741822; // 0xC00000BB

pub struct AlgorithmProvider {
    pub algorithm: String,
    pub flags: u32,
}

pub struct HashContext {
    pub algorithm: String,
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
    pub algorithm: String,
    pub key_data: Vec<u8>,
    pub chaining_mode: String,
    pub rsa_private: Option<RsaPrivateKey>,
}

static PROVIDER_COUNTER: AtomicUsize = AtomicUsize::new(0x1000);
static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0x2000);
static KEY_COUNTER: AtomicUsize = AtomicUsize::new(0x3000);
static PROVIDERS: Spinlock<Vec<(usize, AlgorithmProvider)>> = Spinlock::new(Vec::new());
static HASHES: Spinlock<Vec<(usize, HashContext)>> = Spinlock::new(Vec::new());
static KEYS: Spinlock<Vec<(usize, KeyContext)>> = Spinlock::new(Vec::new());

pub unsafe extern "C" fn bcrypt_open_algorithm_provider(
    alg_handle: *mut usize,
    alg_id: *const u16,
    _implementation: *const u16,
    flags: u32,
) -> i32 {
    if alg_handle.is_null() || alg_id.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let alg_str = match read_wide_string(alg_id) {
        Some(s) => s,
        None => return STATUS_INVALID_PARAMETER,
    };

    match alg_str.as_str() {
        algorithm::AES
        | algorithm::DES
        | algorithm::DES3
        | algorithm::RC4
        | algorithm::RSA
        | algorithm::SHA1
        | algorithm::SHA256
        | algorithm::SHA384
        | algorithm::SHA512
        | algorithm::MD5 => {}
        _ => return STATUS_NOT_SUPPORTED,
    }

    let provider = AlgorithmProvider {
        algorithm: alg_str,
        flags,
    };
    let handle = PROVIDER_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    PROVIDERS.lock().push((handle, provider));

    // Store provider (in real implementation would use proper storage)
    *alg_handle = handle;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_close_algorithm_provider(alg_handle: usize, _flags: u32) -> i32 {
    if alg_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_get_property(
    object_handle: usize,
    property: *const u16,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    _flags: u32,
) -> i32 {
    if property.is_null() || result_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let prop_str = match read_wide_string(property) {
        Some(s) => s,
        None => return STATUS_INVALID_PARAMETER,
    };

    let value: u32 = match prop_str.as_str() {
        property::HASH_LENGTH => match get_algorithm_for_handle(object_handle).as_str() {
            algorithm::MD5 => 16,
            algorithm::SHA1 => 20,
            algorithm::SHA256 => 32,
            algorithm::SHA384 => 48,
            algorithm::SHA512 => 64,
            _ => return STATUS_INVALID_PARAMETER,
        },
        property::OBJECT_LENGTH => 256, // Simplified
        property::BLOCK_LENGTH => 16,
        _ => return STATUS_NOT_SUPPORTED,
    };

    *result_len = 4;

    if output.is_null() || output_len < 4 {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ptr::copy_nonoverlapping(&value as *const u32 as *const u8, output, 4);

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_set_property(
    _object_handle: usize,
    property: *const u16,
    input: *const u8,
    _input_len: u32,
    _flags: u32,
) -> i32 {
    if property.is_null() || input.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let prop_str = match read_wide_string(property) {
        Some(s) => s,
        None => return STATUS_INVALID_PARAMETER,
    };

    match prop_str.as_str() {
        property::CHAINING_MODE => STATUS_SUCCESS,
        _ => STATUS_NOT_SUPPORTED,
    }
}

pub unsafe extern "C" fn bcrypt_create_hash(
    alg_handle: usize,
    hash_handle: *mut usize,
    _hash_object: *mut u8,
    _hash_object_len: u32,
    _secret: *const u8,
    _secret_len: u32,
    _flags: u32,
) -> i32 {
    if hash_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let algorithm = get_algorithm_for_handle(alg_handle);

    let state = match algorithm.as_str() {
        algorithm::MD5 => HashState::Md5(crate::crypto::hash::Md5::new()),
        algorithm::SHA1 => HashState::Sha1(crate::crypto::hash::Sha1::new()),
        algorithm::SHA256 => HashState::Sha256(crate::crypto::hash::Sha256::new()),
        algorithm::SHA384 => HashState::Sha384(crate::crypto::hash::Sha384::new()),
        algorithm::SHA512 => HashState::Sha512(crate::crypto::hash::Sha512::new()),
        _ => return STATUS_NOT_SUPPORTED,
    };

    let context = HashContext {
        algorithm: algorithm.clone(),
        state,
    };
    let handle = HASH_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    HASHES.lock().push((handle, context));

    *hash_handle = handle;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_hash_data(
    hash_handle: usize,
    input: *const u8,
    input_len: u32,
    _flags: u32,
) -> i32 {
    if hash_handle == 0 || input.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let input_data = core::slice::from_raw_parts(input, input_len as usize);
    let mut hashes = HASHES.lock();
    let Some((_, context)) = hashes.iter_mut().find(|(stored, _)| *stored == hash_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    match &mut context.state {
        HashState::Md5(state) => state.update(input_data),
        HashState::Sha1(state) => state.update(input_data),
        HashState::Sha256(state) => state.update(input_data),
        HashState::Sha384(state) => state.update(input_data),
        HashState::Sha512(state) => state.update(input_data),
    }
    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_finish_hash(
    hash_handle: usize,
    output: *mut u8,
    output_len: u32,
    _flags: u32,
) -> i32 {
    if hash_handle == 0 || output.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut hashes = HASHES.lock();
    let Some((_, context)) = hashes.iter_mut().find(|(stored, _)| *stored == hash_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let digest: Vec<u8> = match &mut context.state {
        HashState::Md5(state) => state.finalize().to_vec(),
        HashState::Sha1(state) => state.finalize().to_vec(),
        HashState::Sha256(state) => state.finalize().to_vec(),
        HashState::Sha384(state) => state.finalize().to_vec(),
        HashState::Sha512(state) => state.finalize().to_vec(),
    };
    let output_slice = core::slice::from_raw_parts_mut(output, output_len as usize);
    if output_slice.len() < digest.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    output_slice[..digest.len()].copy_from_slice(&digest);
    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_destroy_hash(hash_handle: usize) -> i32 {
    if hash_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_generate_symmetric_key(
    alg_handle: usize,
    key_handle: *mut usize,
    _key_object: *mut u8,
    _key_object_len: u32,
    secret: *const u8,
    secret_len: u32,
    _flags: u32,
) -> i32 {
    if key_handle.is_null() || secret.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let algorithm = get_algorithm_for_handle(alg_handle);
    let key_data = core::slice::from_raw_parts(secret, secret_len as usize).to_vec();

    let context = KeyContext {
        algorithm: algorithm.clone(),
        key_data,
        chaining_mode: String::from(chaining_mode::CBC),
        rsa_private: None,
    };
    let handle = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);
    KEYS.lock().push((handle, context));

    *key_handle = handle;

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_encrypt(
    key_handle: usize,
    input: *const u8,
    input_len: u32,
    _padding_info: *const core::ffi::c_void,
    _iv: *mut u8,
    _iv_len: u32,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key_handle == 0 || input.is_null() || result_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let input_data = core::slice::from_raw_parts(input, input_len as usize);
    if output.is_null() || output_len < input_len || input_len % 16 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(context) = key_context(key_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let mut iv = [0u8; 16];
    if !_iv.is_null() && _iv_len as usize >= 16 {
        iv.copy_from_slice(core::slice::from_raw_parts(_iv, 16));
    }
    let output_slice = core::slice::from_raw_parts_mut(output, output_len as usize);
    if !aes_cbc_encrypt(&context.key_data, &iv, input_data, output_slice) {
        return STATUS_NOT_SUPPORTED;
    }
    *result_len = input_len;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_decrypt(
    key_handle: usize,
    input: *const u8,
    input_len: u32,
    _padding_info: *const core::ffi::c_void,
    _iv: *mut u8,
    _iv_len: u32,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key_handle == 0 || input.is_null() || result_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let input_data = core::slice::from_raw_parts(input, input_len as usize);
    if output.is_null() || output_len < input_len || input_len % 16 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(context) = key_context(key_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let mut iv = [0u8; 16];
    if !_iv.is_null() && _iv_len as usize >= 16 {
        iv.copy_from_slice(core::slice::from_raw_parts(_iv, 16));
    }
    let output_slice = core::slice::from_raw_parts_mut(output, output_len as usize);
    if !aes_cbc_decrypt(&context.key_data, &iv, input_data, output_slice) {
        return STATUS_NOT_SUPPORTED;
    }
    *result_len = input_len;
    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_destroy_key(key_handle: usize) -> i32 {
    if key_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_generate_key_pair(
    alg_handle: usize,
    key_handle: *mut usize,
    key_length: u32,
    _flags: u32,
) -> i32 {
    if key_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let algorithm = get_algorithm_for_handle(alg_handle);

    match algorithm.as_str() {
        algorithm::RSA => {
            *key_handle = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);
            let private_key = RsaPrivateKey::generate(key_length as usize);
            KEYS.lock().push((
                *key_handle,
                KeyContext {
                    algorithm: algorithm.clone(),
                    key_data: Vec::new(),
                    chaining_mode: String::from(chaining_mode::CBC),
                    rsa_private: Some(private_key),
                },
            ));

            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

pub unsafe extern "C" fn bcrypt_finalize_key_pair(key_handle: usize, _flags: u32) -> i32 {
    if key_handle == 0 {
        return STATUS_INVALID_HANDLE;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_export_key(
    key_handle: usize,
    _export_key_handle: usize,
    blob_type: *const u16,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key_handle == 0 || blob_type.is_null() || result_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    *result_len = 32;

    if output.is_null() || output_len < 32 {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for i in 0..32 {
        *output.add(i) = 0;
    }

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_import_key(
    _alg_handle: usize,
    _import_key_handle: usize,
    blob_type: *const u16,
    key_handle: *mut usize,
    _key_object: *mut u8,
    _key_object_len: u32,
    input: *const u8,
    _input_len: u32,
    _flags: u32,
) -> i32 {
    if key_handle.is_null() || blob_type.is_null() || input.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    *key_handle = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);

    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_sign_hash(
    key_handle: usize,
    _padding_info: *const core::ffi::c_void,
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
    result_len: *mut u32,
    _flags: u32,
) -> i32 {
    if key_handle == 0 || input.is_null() || result_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let digest = core::slice::from_raw_parts(input, input_len as usize);
    let Some(context) = key_context(key_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some(private_key) = context.rsa_private.as_ref() else {
        return STATUS_NOT_SUPPORTED;
    };
    let signature = private_key.sign_pkcs1v15(digest);
    *result_len = signature.len() as u32;
    if output.is_null() || output_len < signature.len() as u32 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    core::slice::from_raw_parts_mut(output, signature.len())
        .copy_from_slice(&signature);
    STATUS_SUCCESS
}

pub unsafe extern "C" fn bcrypt_verify_signature(
    key_handle: usize,
    _padding_info: *const core::ffi::c_void,
    hash: *const u8,
    _hash_len: u32,
    signature: *const u8,
    _signature_len: u32,
    _flags: u32,
) -> i32 {
    if key_handle == 0 || hash.is_null() || signature.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let hash = core::slice::from_raw_parts(hash, _hash_len as usize);
    let signature_data = core::slice::from_raw_parts(signature, _signature_len as usize);
    let Some(context) = key_context(key_handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some(private_key) = context.rsa_private.as_ref() else {
        return STATUS_NOT_SUPPORTED;
    };
    if private_key.public_key().verify_pkcs1v15(hash, signature_data) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

pub unsafe extern "C" fn bcrypt_gen_random(
    _alg_handle: usize,
    buffer: *mut u8,
    buffer_len: u32,
    _flags: u32,
) -> i32 {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let output = core::slice::from_raw_parts_mut(buffer, buffer_len as usize);

    if crate::crypto::csprng::fill(output) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

fn get_algorithm_for_handle(handle: usize) -> String {
    PROVIDERS
        .lock()
        .iter()
        .find(|(stored, _)| *stored == handle)
        .map(|(_, provider)| provider.algorithm.clone())
        .unwrap_or_else(|| String::from(algorithm::SHA256))
}

fn key_context(key_handle: usize) -> Option<KeyContext> {
    let keys = KEYS.lock();
    keys.iter()
        .find(|(stored, _)| *stored == key_handle)
        .map(|(_, context)| KeyContext {
            algorithm: context.algorithm.clone(),
            key_data: context.key_data.clone(),
            chaining_mode: context.chaining_mode.clone(),
            rsa_private: context.rsa_private.clone(),
        })
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> bool {
    match key.len() {
        16 => match key.try_into() {
            Ok(key) => cbc_transform(&Aes128::new(key), iv, input, output, |cipher, block| {
                cipher.encrypt_block(block)
            }, true),
            Err(_) => false,
        },
        32 => match key.try_into() {
            Ok(key) => cbc_transform(&Aes256::new(key), iv, input, output, |cipher, block| {
                cipher.encrypt_block(block)
            }, true),
            Err(_) => false,
        },
        _ => false,
    }
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> bool {
    match key.len() {
        16 => match key.try_into() {
            Ok(key) => cbc_transform(&Aes128::new(key), iv, input, output, |cipher, block| {
                cipher.decrypt_block(block)
            }, false),
            Err(_) => false,
        },
        32 => match key.try_into() {
            Ok(key) => cbc_transform(&Aes256::new(key), iv, input, output, |cipher, block| {
                cipher.decrypt_block(block)
            }, false),
            Err(_) => false,
        },
        _ => false,
    }
}

fn cbc_transform<T, C>(cipher: &T, iv: &[u8; 16], input: &[u8], output: &mut [u8], transform: C, encrypt: bool) -> bool
where
    C: Fn(&T, &mut [u8; 16]),
{
    if input.len() != output.len() || input.len() % 16 != 0 {
        return false;
    }
    let mut feedback = *iv;
    for (input_block, output_block) in input.chunks(16).zip(output.chunks_mut(16)) {
        let mut block = [0u8; 16];
        block.copy_from_slice(input_block);
        if !encrypt {
            transform(cipher, &mut block);
            for index in 0..16 {
                block[index] ^= feedback[index];
            }
            output_block.copy_from_slice(&block);
        } else {
            for index in 0..16 {
                block[index] ^= feedback[index];
            }
            transform(cipher, &mut block);
            output_block.copy_from_slice(&block);
        }
        feedback.copy_from_slice(input_block);
    }
    true
}

unsafe fn read_wide_string(ptr: *const u16) -> Option<String> {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
        if len > 1024 {
            return None;
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

    Some(result)
}
