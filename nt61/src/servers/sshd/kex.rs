//! curve25519-sha256 key exchange (RFC 8731) over X25519 (RFC 7748).
//!
//! The field arithmetic below is a clean-room implementation of the
//! curve25519 prime field GF(2^255 - 19) using five 51-bit limbs, the
//! same decomposition used by the RFC 7748 reference behaviour. The
//! Montgomery ladder follows RFC 7748 section 5.

extern crate alloc;

use super::protocol::*;
use crate::crypto::csprng;
use crate::crypto::hash::Sha256;
use crate::crypto::rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use alloc::string::String;
use alloc::vec::Vec;

// ====================================================================
// curve25519 field arithmetic
// ====================================================================

/// Bits per limb in the 5x51-bit representation of GF(2^255-19).
const FE_LIMB_BITS: u32 = 51;
/// Bit mask covering one 51-bit limb.
const FE_LIMB_MASK: u64 = (1u64 << FE_LIMB_BITS) - 1;
/// 2^255 mod (2^255 - 19) = 19; multiplying a carry out of the top
/// limb by this folds it back into the field.
const FE_CARRY_FOLD: u128 = 19;
/// Public exponent base point u = 9 (RFC 7748 section 6.1).
pub const X25519_BASEPOINT_U: u8 = 9;
/// Encoded X25519 public keys are 32 bytes.
pub const X25519_KEY_LEN: usize = 32;

/// Element of GF(2^255-19) in five 51-bit limbs (little-endian).
#[derive(Clone, Copy)]
pub struct Fe([u64; 5]);

impl Fe {
    pub const fn zero() -> Self {
        Fe([0; 5])
    }

    pub const fn one() -> Self {
        Fe([1, 0, 0, 0, 0])
    }

    /// Decode a 32-byte little-endian u-coordinate (RFC 7748 section 5:
    /// the top bit of the final byte is masked).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        for (limb_index, limb) in limbs.iter_mut().enumerate() {
            for bit in 0..FE_LIMB_BITS {
                let bit_index = limb_index as u32 * FE_LIMB_BITS + bit;
                if bit_index < 255 {
                    let byte_index = (bit_index / 8) as usize;
                    let bit_in_byte = bit_index % 8;
                    if (bytes[byte_index] >> bit_in_byte) & 1 == 1 {
                        *limb |= 1u64 << bit;
                    }
                }
            }
        }
        Fe(limbs)
    }

    /// Encode to the canonical 32-byte little-endian form.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut limbs = self.0;
        fe_fold(&mut limbs);
        fe_subtract_p_if_ge(&mut limbs);

        let mut bytes = [0u8; 32];
        for (limb_index, limb) in limbs.iter().enumerate() {
            for bit in 0..FE_LIMB_BITS {
                let bit_index = limb_index as u32 * FE_LIMB_BITS + bit;
                if bit_index < 255 && (limb >> bit) & 1 == 1 {
                    let byte_index = (bit_index / 8) as usize;
                    bytes[byte_index] |= 1u8 << (bit_index % 8);
                }
            }
        }
        bytes
    }

    pub fn add(&self, other: &Fe) -> Fe {
        // Limb-wise addition keeps the represented value exact; the
        // fold normalises the limbs back below 2^52.
        let mut limbs = [
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ];
        fe_fold(&mut limbs);
        Fe(limbs)
    }

    pub fn sub(&self, other: &Fe) -> Fe {
        // Add 4p limb-wise so every partial result stays positive; 4p
        // is a multiple of p so the value is unchanged mod p.
        let mut limbs = [
            FOUR_P_LIMBS[0] - other.0[0] + self.0[0],
            FOUR_P_LIMBS[1] - other.0[1] + self.0[1],
            FOUR_P_LIMBS[2] - other.0[2] + self.0[2],
            FOUR_P_LIMBS[3] - other.0[3] + self.0[3],
            FOUR_P_LIMBS[4] - other.0[4] + self.0[4],
        ];
        fe_fold(&mut limbs);
        Fe(limbs)
    }

    pub fn neg(&self) -> Fe {
        Fe::zero().sub(self)
    }

    pub fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;
        // Terms with i+j >= 5 represent positions >= 2^255 and are
        // folded by the factor 19 (= 2^255 mod p).
        let c0 = (a[0] as u128) * (b[0] as u128)
            + 19 * ((a[1] as u128) * (b[4] as u128)
                + (a[2] as u128) * (b[3] as u128)
                + (a[3] as u128) * (b[2] as u128)
                + (a[4] as u128) * (b[1] as u128));
        let c1 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + 19 * ((a[2] as u128) * (b[4] as u128)
                + (a[3] as u128) * (b[3] as u128)
                + (a[4] as u128) * (b[2] as u128));
        let c2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + 19 * ((a[3] as u128) * (b[4] as u128) + (a[4] as u128) * (b[3] as u128));
        let c3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + 19 * (a[4] as u128) * (b[4] as u128);
        let c4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        let mut limbs = [0u64; 5];
        let mut carry: u128 = c0;
        limbs[0] = (carry as u64) & FE_LIMB_MASK;
        carry >>= FE_LIMB_BITS;
        carry += c1;
        limbs[1] = (carry as u64) & FE_LIMB_MASK;
        carry >>= FE_LIMB_BITS;
        carry += c2;
        limbs[2] = (carry as u64) & FE_LIMB_MASK;
        carry >>= FE_LIMB_BITS;
        carry += c3;
        limbs[3] = (carry as u64) & FE_LIMB_MASK;
        carry >>= FE_LIMB_BITS;
        carry += c4;
        limbs[4] = (carry as u64) & FE_LIMB_MASK;
        carry >>= FE_LIMB_BITS;

        // Fold the top carry (bits >= 2^255) back in with factor 19 and
        // normalise; fe_fold_carry preserves any residual carry across
        // fold rounds instead of dropping it.
        fe_fold_carry(&mut limbs, carry * FE_CARRY_FOLD);
        Fe(limbs)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    /// Raise to the power 2^255 - 21 (= p - 2), i.e. field inversion by
    /// Fermat's little theorem. Horner evaluation runs from the most
    /// significant exponent bit downwards.
    pub fn invert(&self) -> Fe {
        let mut result = Fe::one();
        let base = *self;
        for byte_index in (0..32).rev() {
            for bit in (0..8u32).rev() {
                result = result.square();
                if (P_MINUS_2_BYTES[byte_index] >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }
        result
    }
}

/// Limb decomposition of 4p (used to keep subtractions positive).
const FOUR_P_LIMBS: [u64; 5] = [
    (1 << 53) - 76,
    (1 << 53) - 4,
    (1 << 53) - 4,
    (1 << 53) - 4,
    (1 << 53) - 4,
];

/// p - 2 = 2^255 - 21 in little-endian bytes; used for field inversion.
const P_MINUS_2_BYTES: [u8; 32] = [
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Propagate carries between limbs and fold everything at bit 255+ back
/// into the field (multiply by 19). The pending value "initial_carry" is
/// added at bit position 0 before the first pass, letting callers fold a
/// pending high-product carry in the same normalisation loop. Each round
/// replaces "carry * 2^255" with "carry * 19" (equal modulo p), so the
/// residual shrinks geometrically and is never discarded.
fn fe_fold_carry(limbs: &mut [u64; 5], mut carry: u128) {
    loop {
        for limb in limbs.iter_mut() {
            carry += *limb as u128;
            *limb = (carry as u64) & FE_LIMB_MASK;
            carry >>= FE_LIMB_BITS;
        }
        if carry == 0 {
            break;
        }
        carry *= FE_CARRY_FOLD;
    }
}

/// Normalise limbs in place (no pending carry).
fn fe_fold(limbs: &mut [u64; 5]) {
    fe_fold_carry(limbs, 0);
}

/// Subtract p when the (canonical-form) value is >= p.
fn fe_subtract_p_if_ge(limbs: &mut [u64; 5]) {
    const P_LIMBS: [u64; 5] = [
        (1 << 51) - 19,
        (1 << 51) - 1,
        (1 << 51) - 1,
        (1 << 51) - 1,
        (1 << 51) - 1,
    ];
    let mut ge = false;
    for i in (0..5).rev() {
        if limbs[i] > P_LIMBS[i] {
            ge = true;
            break;
        }
        if limbs[i] < P_LIMBS[i] {
            break;
        }
    }
    // All-equal also means >= p.
    if limbs.iter().zip(P_LIMBS.iter()).all(|(a, b)| a == b) {
        ge = true;
    }
    if ge {
        let mut borrow: i64 = 0;
        for (limb, p_limb) in limbs.iter_mut().zip(P_LIMBS.iter()) {
            let value = *limb as i64 - *p_limb as i64 - borrow;
            if value < 0 {
                *limb = (value + (1i64 << 51)) as u64;
                borrow = 1;
            } else {
                *limb = value as u64;
                borrow = 0;
            }
        }
    }
}

// ====================================================================
// X25519 scalar multiplication (RFC 7748 section 5)
// ====================================================================

/// Scalar-multiply the u-coordinate point `u` by `scalar`.
pub fn x25519(scalar_bytes: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar per RFC 7748 section 5.
    let mut scalar = *scalar_bytes;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let mut decoded_u = *u_bytes;
    decoded_u[31] &= 127; // mask the top bit per RFC 7748 section 5.
    let x1 = Fe::from_bytes(&decoded_u);

    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();
    let mut swap = false;

    for bit_index in (0..255).rev() {
        let bit = (scalar[bit_index / 8] >> (bit_index % 8)) & 1 == 1;
        swap ^= bit;
        if swap {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        // a24 = 121665 for curve25519 (RFC 7748 section 5).
        z2 = e.mul(&aa.add(&e.mul(&Fe([121665, 0, 0, 0, 0]))));
    }
    if swap {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }

    x2.mul(&z2.invert()).to_bytes()
}

/// Public key belonging to `secret`: X25519(secret, 9).
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let mut u = [0u8; 32];
    u[0] = X25519_BASEPOINT_U;
    x25519(secret, &u)
}

// ====================================================================
// KEX state machine (RFC 4253 section 7-9, RFC 8731)
// ====================================================================

/// Algorithms negotiated from the KEXINIT name lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub host_key_algorithm: String,
}

/// Pick the first client-preferred match for a single algorithm slot.
fn negotiate_one(client_list: &[String], server_supported: &[&str]) -> Option<String> {
    client_list
        .iter()
        .find(|client_alg| server_supported.iter().any(|s| s == client_alg))
        .cloned()
}

/// Negotiate all slots from the client KEXINIT name lists. The server
/// list order is authoritative for server-preferred choices.
pub fn negotiate(client_kexinit_payload: &[u8]) -> Result<Negotiated, TransportError> {
    let mut reader = WireReader::new(client_kexinit_payload);
    let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
    let _cookie = reader.get_string().ok_or(TransportError::MalformedPacket)?;
    let client_kex = reader
        .get_name_list()
        .ok_or(TransportError::MalformedPacket)?;
    let client_host_keys = reader
        .get_name_list()
        .ok_or(TransportError::MalformedPacket)?;

    const SERVER_KEX_ALGORITHMS: [&str; 1] = [ALG_KEX_CURVE25519_SHA256];
    const SERVER_HOST_KEY_ALGORITHMS: [&str; 2] = [ALG_HOSTKEY_RSA_SHA2_256, ALG_HOSTKEY_SSH_RSA];

    negotiate_one(&client_kex, &SERVER_KEX_ALGORITHMS).ok_or(TransportError::MalformedPacket)?;
    let host_key_algorithm = negotiate_one(&client_host_keys, &SERVER_HOST_KEY_ALGORITHMS)
        .ok_or(TransportError::MalformedPacket)?;
    Ok(Negotiated { host_key_algorithm })
}

/// Build the server KEXINIT payload we advertise.
pub fn build_server_kexinit() -> Vec<u8> {
    let mut cookie = [0u8; 16];
    csprng::fill(&mut cookie);
    let mut w = WireWriter::new();
    w.put_u8(msg::KEXINIT);
    w.put_string(&cookie);
    w.put_name_list(&[ALG_KEX_CURVE25519_SHA256]);
    w.put_name_list(&[ALG_HOSTKEY_RSA_SHA2_256, ALG_HOSTKEY_SSH_RSA]);
    w.put_name_list(&[ALG_CIPHER_AES256_CTR]);
    w.put_name_list(&[ALG_CIPHER_AES256_CTR]);
    w.put_name_list(&[ALG_MAC_HMAC_SHA2_256]);
    w.put_name_list(&[ALG_MAC_HMAC_SHA2_256]);
    w.put_name_list(&[ALG_COMPRESSION_NONE]);
    w.put_name_list(&[ALG_COMPRESSION_NONE]);
    w.put_name_list(&[]);
    w.put_name_list(&[]);
    w.put_bool(false); // first_kex_packet_follows
    w.put_u32(0); // reserved
    w.into_vec()
}

/// Encode an RSA public key as an SSH "ssh-rsa" key blob:
/// string "ssh-rsa" || mpint e || mpint n.
pub fn rsa_public_key_blob(public_key: &RsaPublicKey) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.put_string_str(ALG_HOSTKEY_SSH_RSA);
    w.put_mpint(&public_key.e.to_bytes());
    w.put_mpint(&public_key.n.to_bytes());
    w.into_vec()
}

/// Parse an "ssh-rsa" key blob back into an RsaPublicKey.
pub fn parse_rsa_public_key_blob(blob: &[u8]) -> Option<RsaPublicKey> {
    let mut reader = WireReader::new(blob);
    let algorithm = reader.get_string()?;
    if algorithm != ALG_HOSTKEY_SSH_RSA.as_bytes() {
        return None;
    }
    let e_bytes = reader.get_string()?;
    let n_bytes = reader.get_string()?;
    Some(RsaPublicKey {
        e: BigUint::from_bytes(strip_leading_zero(e_bytes)),
        n: BigUint::from_bytes(strip_leading_zero(n_bytes)),
    })
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes.split_first() {
        Some((0, rest)) => rest,
        _ => bytes,
    }
}

/// Server-side ECDH exchange: computes the reply payload for
/// SSH_MSG_KEX_ECDH_REPLY given the client's public share `e`.
pub struct KexReply {
    pub payload: Vec<u8>,
    /// Raw shared secret (before mpint encoding).
    pub shared_secret: [u8; 32],
    /// Exchange hash H; doubles as the session identifier.
    pub exchange_hash: [u8; 32],
}

/// Perform the server side of curve25519-sha256 (RFC 8731 section 3).
pub fn kex_ecdh_reply(
    ephemeral_secret: &[u8; 32],
    client_public: &[u8; 32],
    client_version: &[u8],
    server_version: &[u8],
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    host_key: &RsaPrivateKey,
    host_key_algorithm: &str,
) -> Option<KexReply> {
    // Reject the all-zero output (point at infinity, RFC 7748 section 6).
    let shared = x25519(ephemeral_secret, client_public);
    if shared.iter().all(|byte| *byte == 0) {
        return None;
    }

    let server_public = x25519_public(ephemeral_secret);
    let host_key_blob = rsa_public_key_blob(&host_key.public_key());

    // H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K)
    //     (RFC 4253 section 8, as referenced by RFC 8731).
    let mut hasher = Sha256::new();
    let mut exchange_input = WireWriter::new();
    exchange_input.put_string(client_version);
    exchange_input.put_string(server_version);
    exchange_input.put_string(client_kexinit);
    exchange_input.put_string(server_kexinit);
    exchange_input.put_string(&host_key_blob);
    exchange_input.put_string(client_public);
    exchange_input.put_string(&server_public);
    exchange_input.put_mpint(&shared);
    hasher.update(&exchange_input.into_vec());
    let exchange_hash = hasher.finalize();

    let signature = sign_exchange_hash(host_key, host_key_algorithm, &exchange_hash)?;

    let mut w = WireWriter::new();
    w.put_u8(msg::KEX_ECDH_REPLY);
    w.put_string(&host_key_blob);
    w.put_string(&server_public);
    w.put_string(&signature);
    Some(KexReply {
        payload: w.into_vec(),
        shared_secret: shared,
        exchange_hash,
    })
}

/// Sign the exchange hash with the negotiated host key algorithm.
pub fn sign_exchange_hash(
    host_key: &RsaPrivateKey,
    algorithm: &str,
    exchange_hash: &[u8],
) -> Option<Vec<u8>> {
    let mut w = WireWriter::new();
    match algorithm {
        ALG_HOSTKEY_RSA_SHA2_256 => {
            let signature = host_key.sign_pkcs1v15(exchange_hash);
            w.put_string_str(ALG_HOSTKEY_RSA_SHA2_256);
            w.put_string(&signature);
        }
        ALG_HOSTKEY_SSH_RSA => {
            let digest = crate::crypto::hash::sha1(exchange_hash);
            let signature = host_key.sign_pkcs1v15(&digest);
            w.put_string_str(ALG_HOSTKEY_SSH_RSA);
            w.put_string(&signature);
        }
        _ => return None,
    }
    Some(w.into_vec())
}

/// RFC 4253 section 7.2 key derivation: extend the exchange hash to
/// the required length by re-hashing K || H || letter || session_id.
fn derive_bytes(
    shared_secret: &[u8; 32],
    exchange_hash: &[u8; 32],
    purpose: u8,
    len: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(len);
    let mut k = WireWriter::new();
    k.put_mpint(shared_secret);
    let k_bytes = k.into_vec();

    let mut hasher = Sha256::new();
    hasher.update(&k_bytes);
    hasher.update(exchange_hash);
    hasher.update(&[purpose]);
    hasher.update(exchange_hash);
    let mut block: Vec<u8> = hasher.finalize().to_vec();
    output.extend_from_slice(&block[..len.min(block.len())]);

    while output.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(&k_bytes);
        hasher.update(exchange_hash);
        hasher.update(&block);
        block = hasher.finalize().to_vec();
        output.extend_from_slice(&block);
    }
    output.truncate(len);
    output
}

/// Derive both directions' IV / encryption-key / MAC-key material
/// after a completed key exchange (RFC 4253 section 7.2).
pub struct DerivedKeys {
    pub client_to_server_iv: [u8; 16],
    pub server_to_client_iv: [u8; 16],
    pub client_to_server_key: [u8; CIPHER_KEY_LEN_AES256],
    pub server_to_client_key: [u8; CIPHER_KEY_LEN_AES256],
    pub client_to_server_mac: [u8; MAC_LEN_HMAC_SHA2_256],
    pub server_to_client_mac: [u8; MAC_LEN_HMAC_SHA2_256],
}

pub fn derive_keys(shared_secret: &[u8; 32], exchange_hash: &[u8; 32]) -> DerivedKeys {
    const PURPOSE_IV_C2S: u8 = b'A';
    const PURPOSE_IV_S2C: u8 = b'B';
    const PURPOSE_KEY_C2S: u8 = b'C';
    const PURPOSE_KEY_S2C: u8 = b'D';
    const PURPOSE_MAC_C2S: u8 = b'E';
    const PURPOSE_MAC_S2C: u8 = b'F';

    let to_array16 = |bytes: Vec<u8>| -> [u8; 16] {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[..16]);
        arr
    };
    let to_array32 = |bytes: Vec<u8>| -> [u8; CIPHER_KEY_LEN_AES256] {
        let mut arr = [0u8; CIPHER_KEY_LEN_AES256];
        arr.copy_from_slice(&bytes[..CIPHER_KEY_LEN_AES256]);
        arr
    };
    let to_array_mac = |bytes: Vec<u8>| -> [u8; MAC_LEN_HMAC_SHA2_256] {
        let mut arr = [0u8; MAC_LEN_HMAC_SHA2_256];
        arr.copy_from_slice(&bytes[..MAC_LEN_HMAC_SHA2_256]);
        arr
    };

    DerivedKeys {
        client_to_server_iv: to_array16(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_IV_C2S,
            16,
        )),
        server_to_client_iv: to_array16(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_IV_S2C,
            16,
        )),
        client_to_server_key: to_array32(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_KEY_C2S,
            CIPHER_KEY_LEN_AES256,
        )),
        server_to_client_key: to_array32(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_KEY_S2C,
            CIPHER_KEY_LEN_AES256,
        )),
        client_to_server_mac: to_array_mac(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_MAC_C2S,
            MAC_LEN_HMAC_SHA2_256,
        )),
        server_to_client_mac: to_array_mac(derive_bytes(
            shared_secret,
            exchange_hash,
            PURPOSE_MAC_S2C,
            MAC_LEN_HMAC_SHA2_256,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fe_field_arithmetic_known_answers() {
        let bytes = |first: u8| -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0] = first;
            b
        };
        let nine = Fe::from_bytes(&bytes(9));
        let one = Fe::one();
        assert_eq!(nine.sub(&one).to_bytes(), bytes(8), "sub(9,1)");
        assert_eq!(nine.add(&one).to_bytes(), bytes(10), "add(9,1)");

        // a = 2^255 - 11 (the non-canonical form sub(9,1) can produce).
        let mut big = [0xffu8; 32];
        big[0] = 0xf5;
        big[31] = 0x7f;
        let big_fe = Fe::from_bytes(&big);
        let eight = Fe::from_bytes(&bytes(8));
        assert_eq!(big_fe.sub(&eight).to_bytes(), bytes(0), "sub(2^255-11, 8)");
        assert_eq!(
            big_fe.add(&eight).to_bytes(),
            bytes(0x10),
            "add(2^255-11, 8)"
        );
        assert_eq!(
            big_fe.mul(&eight).to_bytes(),
            bytes(0x40),
            "mul(2^255-11, 8)"
        );
        assert_eq!(big_fe.square().to_bytes(), bytes(0x40), "square(2^255-11)");

        let ten = Fe::from_bytes(&bytes(10));
        let sixtyfour = Fe::from_bytes(&bytes(64));
        assert_eq!(ten.square().to_bytes(), bytes(100), "square(10)");
        assert_eq!(
            ten.mul(&sixtyfour).to_bytes()[0],
            0x80,
            "mul(10, 64) low byte"
        );

        // Algebraic property checks: any correct field implementation
        // must satisfy these identities for arbitrary operands.
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        csprng::fill(&mut a_bytes);
        csprng::fill(&mut b_bytes);
        let a = Fe::from_bytes(&a_bytes);
        let b = Fe::from_bytes(&b_bytes);
        let c = Fe::from_bytes(&bytes(42));

        // (a - b) + b == a
        assert_eq!(
            a.sub(&b).add(&b).to_bytes(),
            a.to_bytes(),
            "sub/add round trip"
        );
        // (a + b) - b == a
        assert_eq!(
            a.add(&b).sub(&b).to_bytes(),
            a.to_bytes(),
            "add/sub round trip"
        );
        // a * b == b * a
        assert_eq!(
            a.mul(&b).to_bytes(),
            b.mul(&a).to_bytes(),
            "mul commutativity"
        );
        // (a + b) * c == a*c + b*c
        let lhs = a.add(&b).mul(&c);
        let rhs = a.mul(&c).add(&b.mul(&c));
        assert_eq!(lhs.to_bytes(), rhs.to_bytes(), "distributivity");
        // a * 1 == a
        let one = Fe::from_bytes(&bytes(1));
        assert_eq!(a.mul(&one).to_bytes(), a.to_bytes(), "mul identity");
    }

    #[test]
    fn x25519_trace_matches_reference() {
        let a: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let mut scalar = a;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let mut u = [0u8; 32];
        u[0] = X25519_BASEPOINT_U;
        let x1 = Fe::from_bytes(&u);
        let mut x2 = Fe::one();
        let mut z2 = Fe::zero();
        let mut x3 = x1;
        let mut z3 = Fe::one();
        let mut swap = false;
        for bit_index in (0..255).rev() {
            let bit = (scalar[bit_index / 8] >> (bit_index % 8)) & 1 == 1;
            swap ^= bit;
            if swap {
                core::mem::swap(&mut x2, &mut x3);
                core::mem::swap(&mut z2, &mut z3);
            }
            swap = bit;
            let aa = x2.add(&z2).square();
            let bb = x2.sub(&z2).square();
            let e = aa.sub(&bb);
            let da = x3.sub(&z3).mul(&x2.add(&z2));
            let cb = x3.add(&z3).mul(&x2.sub(&z2));
            x3 = da.add(&cb).square();
            z3 = x1.mul(&da.sub(&cb).square());
            x2 = aa.mul(&bb);
            z2 = e.mul(&aa.add(&e.mul(&Fe([121665, 0, 0, 0, 0]))));
            match bit_index {
                254 => {
                    assert_eq!(
                        x2.to_bytes(),
                        [
                            0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        z2.to_bytes(),
                        [
                            0x20, 0x07, 0x66, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        x3.to_bytes(),
                        [
                            0x44, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        z3.to_bytes(),
                        [
                            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                }
                253 => {
                    assert_eq!(
                        x2.to_bytes(),
                        [
                            0x00, 0x00, 0x10, 0x1e, 0xbd, 0x96, 0x6a, 0x9f, 0x4d, 0x9a, 0x26, 0xa9,
                            0x7a, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        z2.to_bytes(),
                        [
                            0x00, 0x00, 0x00, 0x62, 0x47, 0xa8, 0xc8, 0x24, 0x56, 0xd1, 0x07, 0x4a,
                            0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        x3.to_bytes(),
                        [
                            0x00, 0x00, 0xb1, 0x49, 0x71, 0x14, 0x6e, 0xfb, 0x06, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                    assert_eq!(
                        z3.to_bytes(),
                        [
                            0x00, 0x00, 0x09, 0x26, 0x99, 0x22, 0x36, 0xa9, 0xe5, 0x13, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                        ]
                    );
                }
                130 => {
                    assert_eq!(
                        x2.to_bytes(),
                        [
                            0xd3, 0x0f, 0xae, 0x36, 0x41, 0xfc, 0x3d, 0xff, 0x1b, 0xd2, 0x4f, 0xc0,
                            0x45, 0x94, 0x59, 0x2e, 0x1b, 0x4f, 0xaf, 0x36, 0xdc, 0xa5, 0x8b, 0x9e,
                            0x25, 0x03, 0x1b, 0x6f, 0x5e, 0x4e, 0x35, 0x48
                        ]
                    );
                    assert_eq!(
                        z2.to_bytes(),
                        [
                            0x68, 0x34, 0xcc, 0xdb, 0x6a, 0x18, 0x3d, 0xee, 0xe7, 0xa6, 0x75, 0x91,
                            0x14, 0x3f, 0x61, 0x64, 0xc1, 0x5c, 0x8e, 0x53, 0xdf, 0xb1, 0x31, 0x6e,
                            0x7d, 0xc1, 0xd9, 0xc0, 0x22, 0x08, 0x90, 0x1b
                        ]
                    );
                    assert_eq!(
                        x3.to_bytes(),
                        [
                            0xfa, 0x68, 0xb2, 0x6d, 0x3d, 0xce, 0x6a, 0x2b, 0xb6, 0x30, 0x34, 0xc9,
                            0xcb, 0x9c, 0xa4, 0x92, 0xe0, 0x8f, 0x08, 0x08, 0x75, 0x32, 0x4d, 0x43,
                            0x74, 0xed, 0xb4, 0x16, 0x9e, 0x4b, 0xa8, 0x7c
                        ]
                    );
                    assert_eq!(
                        z3.to_bytes(),
                        [
                            0xb0, 0xd4, 0x02, 0xaf, 0xbe, 0x76, 0x67, 0x60, 0xf3, 0x5b, 0x07, 0x7a,
                            0x8e, 0xd5, 0xe0, 0xef, 0x10, 0x37, 0x20, 0xe7, 0xbf, 0x4c, 0x01, 0x29,
                            0x52, 0x14, 0xd9, 0x9f, 0x85, 0xb5, 0xcf, 0x53
                        ]
                    );
                }
                1 => {
                    assert_eq!(
                        x2.to_bytes(),
                        [
                            0xe9, 0xbe, 0x56, 0x66, 0xaa, 0x5f, 0x4a, 0xaf, 0xd7, 0xe3, 0xba, 0x5a,
                            0x4c, 0xc5, 0x3a, 0x6a, 0xcd, 0xc0, 0x13, 0x60, 0x96, 0xa6, 0x45, 0x70,
                            0x32, 0x42, 0x54, 0x58, 0x08, 0xd4, 0x1a, 0x13
                        ]
                    );
                    assert_eq!(
                        z2.to_bytes(),
                        [
                            0xe7, 0x89, 0xb8, 0xd2, 0x57, 0xdd, 0x36, 0x8a, 0xa9, 0xbd, 0xcf, 0x61,
                            0x34, 0x77, 0x6f, 0x90, 0xc0, 0xaa, 0xe0, 0x3a, 0x5d, 0x12, 0xac, 0xa4,
                            0x89, 0x2e, 0x7c, 0xe0, 0x99, 0x89, 0xcd, 0x49
                        ]
                    );
                    assert_eq!(
                        x3.to_bytes(),
                        [
                            0x52, 0x72, 0x6d, 0xea, 0x9f, 0x4a, 0x29, 0xad, 0xfb, 0xa2, 0xbb, 0xba,
                            0x64, 0x7f, 0x59, 0xfb, 0xff, 0x7d, 0x9c, 0x72, 0x28, 0xae, 0x86, 0x44,
                            0x09, 0xcb, 0xef, 0x16, 0xbd, 0xfd, 0x6c, 0x3b
                        ]
                    );
                    assert_eq!(
                        z3.to_bytes(),
                        [
                            0x19, 0xef, 0x0a, 0xe1, 0xbd, 0x53, 0x7d, 0x19, 0x3f, 0x8b, 0x76, 0xaf,
                            0xb5, 0x46, 0x5b, 0x0e, 0xb4, 0x8d, 0x6d, 0xaf, 0xa7, 0x9e, 0xe6, 0x03,
                            0x81, 0x6e, 0x68, 0x9d, 0xc3, 0x36, 0x84, 0x12
                        ]
                    );
                }
                0 => {
                    assert_eq!(
                        x2.to_bytes(),
                        [
                            0x45, 0x2e, 0xfe, 0xa9, 0x41, 0x45, 0x34, 0xc9, 0x99, 0x97, 0x35, 0xc6,
                            0xb9, 0xd9, 0x1c, 0xb5, 0x89, 0x02, 0x6e, 0xa5, 0x11, 0x68, 0x3f, 0x78,
                            0xae, 0x6f, 0xa7, 0xf8, 0x6f, 0x43, 0x9e, 0x55
                        ]
                    );
                    assert_eq!(
                        z2.to_bytes(),
                        [
                            0xfc, 0xa0, 0xac, 0x12, 0x7f, 0x53, 0x53, 0x3a, 0x1b, 0x1c, 0xe7, 0xdb,
                            0x44, 0x4b, 0xa2, 0x9d, 0x1f, 0x2d, 0xd8, 0x1b, 0x1c, 0x7b, 0xea, 0xa7,
                            0xaf, 0x4e, 0xa0, 0x71, 0x29, 0xec, 0x2f, 0x10
                        ]
                    );
                    assert_eq!(
                        x3.to_bytes(),
                        [
                            0xfb, 0xec, 0xca, 0x51, 0xf5, 0xc7, 0x7f, 0x51, 0xcb, 0x7c, 0x49, 0x24,
                            0x0a, 0x1c, 0x04, 0xe6, 0xb5, 0xab, 0x3e, 0xd0, 0xda, 0x48, 0x9d, 0x12,
                            0xb7, 0xf8, 0xea, 0x0c, 0x8d, 0xa0, 0x5e, 0x5a
                        ]
                    );
                    assert_eq!(
                        z3.to_bytes(),
                        [
                            0x5b, 0xc0, 0xe6, 0x07, 0x13, 0xc2, 0x51, 0x92, 0x5c, 0x48, 0xcd, 0x1f,
                            0x9d, 0x16, 0xe2, 0x00, 0xa9, 0xb3, 0x04, 0xbe, 0xf7, 0xe1, 0xce, 0x94,
                            0x29, 0x59, 0x42, 0x1a, 0xb4, 0xf5, 0xa4, 0x4c
                        ]
                    );
                }
                _ => {}
            }
        }
        if swap {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        let result = x2.mul(&z2.invert()).to_bytes();
        assert_eq!(result, x25519_public(&a));
    }

    #[test]
    fn x25519_rfc7748_section_5_1_vectors() {
        // Alice's private key, a:
        //   77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
        let a: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        // Alice's public key, X25519(a, 9):
        //   8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
        let a_pub_expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        // Bob's private key, b:
        //   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
        let b: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        // Bob's public key, X25519(b, 9):
        //   de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
        let b_pub_expected: [u8; 32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        // Their shared secret, K:
        //   4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
        let shared_expected: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        assert_eq!(x25519_public(&a), a_pub_expected);
        assert_eq!(x25519_public(&b), b_pub_expected);

        let ka = x25519(&a, &b_pub_expected);
        let kb = x25519(&b, &a_pub_expected);
        assert_eq!(ka, shared_expected);
        assert_eq!(kb, shared_expected);
    }

    #[test]
    fn x25519_is_commutative_dh() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        csprng::fill(&mut a);
        csprng::fill(&mut b);
        let a_pub = x25519_public(&a);
        let b_pub = x25519_public(&b);
        let ka = x25519(&a, &b_pub);
        let kb = x25519(&b, &a_pub);
        assert_eq!(ka, kb);
    }

    #[test]
    fn x25519_public_key_is_deterministic() {
        let secret = [7u8; 32];
        assert_eq!(x25519_public(&secret), x25519_public(&secret));
    }

    #[test]
    fn negotiation_prefers_client_order_within_server_support() {
        let mut w = WireWriter::new();
        w.put_u8(msg::KEXINIT);
        w.put_string(&[0u8; 16]);
        w.put_name_list(&[ALG_KEX_CURVE25519_SHA256]);
        w.put_name_list(&[ALG_HOSTKEY_SSH_RSA, ALG_HOSTKEY_RSA_SHA2_256]);
        let negotiated = negotiate(&w.into_vec()).unwrap();
        assert_eq!(negotiated.host_key_algorithm, ALG_HOSTKEY_SSH_RSA);
    }

    #[test]
    fn negotiation_rejects_unsupported_kex() {
        let mut w = WireWriter::new();
        w.put_u8(msg::KEXINIT);
        w.put_string(&[0u8; 16]);
        w.put_name_list(&["diffie-hellman-group14-sha256"]);
        w.put_name_list(&[ALG_HOSTKEY_RSA_SHA2_256]);
        assert!(negotiate(&w.into_vec()).is_err());
    }

    #[test]
    fn rsa_key_blob_round_trip() {
        let key = RsaPrivateKey::generate(512);
        let blob = rsa_public_key_blob(&key.public_key());
        let parsed = parse_rsa_public_key_blob(&blob).unwrap();
        assert_eq!(parsed.n.to_bytes(), key.n.to_bytes());
        assert_eq!(parsed.e.to_bytes(), key.e.to_bytes());
    }

    #[test]
    fn key_derivation_produces_distinct_direction_keys() {
        let secret = [1u8; 32];
        let hash = [2u8; 32];
        let keys = derive_keys(&secret, &hash);
        assert_ne!(keys.client_to_server_key, keys.server_to_client_key);
        assert_ne!(keys.client_to_server_mac, keys.server_to_client_mac);
    }
}
