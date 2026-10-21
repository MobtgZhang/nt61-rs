//! sshd user authentication (RFC 4252).
//!
//! Supports the "password" and "publickey" methods. Public-key
//! verification uses the "ssh-rsa" (RSA/SHA-1) and "rsa-sha2-256"
//! (RSA/SHA-256) signatures, matching the host-key algorithms
//! negotiated during KEX.

extern crate alloc;

use super::protocol::{WireReader, WireWriter, ALG_HOSTKEY_RSA_SHA2_256, ALG_HOSTKEY_SSH_RSA};
use crate::crypto::hash::sha256;
use crate::crypto::rsa::RsaPublicKey;
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;

/// A local account eligible for SSH login. A hash of None means the
/// account has no password (matching the kernel's default "user"
/// account, which boots with no password).
#[derive(Clone)]
pub struct UserAccount {
    pub name: String,
    pub password_sha256: Option<[u8; 32]>,
}

impl UserAccount {
    pub fn without_password(name: &str) -> Self {
        Self {
            name: String::from(name),
            password_sha256: None,
        }
    }

    pub fn with_password(name: &str, password: &str) -> Self {
        Self {
            name: String::from(name),
            password_sha256: Some(sha256(password.as_bytes())),
        }
    }
}

static ACCOUNTS: Spinlock<Vec<UserAccount>> = Spinlock::new(Vec::new());
static AUTHORIZED_KEYS: Spinlock<Vec<(String, RsaPublicKey)>> = Spinlock::new(Vec::new());

/// Replace the account list used for password authentication.
pub fn install_accounts(accounts: Vec<UserAccount>) {
    *ACCOUNTS.lock() = accounts;
}

/// Add an authorized public key for a user.
pub fn install_authorized_key(user: &str, key: RsaPublicKey) {
    AUTHORIZED_KEYS.lock().push((String::from(user), key));
}

/// Verify a password against the installed account list. Unknown
/// users always fail.
pub fn verify_password(user: &str, password: &[u8]) -> bool {
    let accounts = ACCOUNTS.lock();
    match accounts.iter().find(|account| account.name == user) {
        Some(account) => match account.password_sha256 {
            None => password.is_empty(),
            Some(hash) => sha256(password) == hash,
        },
        None => false,
    }
}

/// Whether public-key authentication is possible for a user at all
/// (drives the "publickey" flag in USERAUTH_FAILURE).
pub fn has_authorized_keys(user: &str) -> bool {
    AUTHORIZED_KEYS
        .lock()
        .iter()
        .any(|(owner, _)| owner == user)
}

/// Signature algorithms accepted for publickey verification.
const SUPPORTED_SIGNATURE_ALGORITHMS: [&str; 2] = [ALG_HOSTKEY_RSA_SHA2_256, ALG_HOSTKEY_SSH_RSA];

/// Verify an SSH_MSG_USERAUTH_REQUEST publickey signature (RFC 4252
/// section 7). The signature covers string(session-id) followed by
/// the request payload with the signature field left empty.
pub fn verify_public_key(
    user: &str,
    signature_algorithm: &str,
    key_blob: &[u8],
    signature: &[u8],
    data_to_sign: &[u8],
) -> bool {
    if !SUPPORTED_SIGNATURE_ALGORITHMS.contains(&signature_algorithm) {
        return false;
    }
    let key = match super::kex::parse_rsa_public_key_blob(key_blob) {
        Some(key) => key,
        None => return false,
    };

    let authorized = AUTHORIZED_KEYS.lock();
    if !authorized
        .iter()
        .any(|(owner, stored)| owner == user && rsa_keys_equal(stored, &key))
    {
        return false;
    }

    // Unwrap the SSH signature: string(alg) || string(rsa-signature).
    let mut reader = WireReader::new(signature);
    let alg = match reader.get_string() {
        Some(alg) => alg,
        None => return false,
    };
    let rsa_signature = match reader.get_string() {
        Some(sig) => sig,
        None => return false,
    };
    if alg != signature_algorithm.as_bytes() {
        return false;
    }

    match signature_algorithm {
        ALG_HOSTKEY_RSA_SHA2_256 => {
            let digest = sha256(data_to_sign);
            key.verify_pkcs1v15(&digest, rsa_signature)
        }
        ALG_HOSTKEY_SSH_RSA => {
            let digest = crate::crypto::hash::sha1(data_to_sign);
            key.verify_pkcs1v15(&digest, rsa_signature)
        }
        _ => false,
    }
}

fn rsa_keys_equal(a: &RsaPublicKey, b: &RsaPublicKey) -> bool {
    a.n.to_bytes() == b.n.to_bytes() && a.e.to_bytes() == b.e.to_bytes()
}

/// Rebuild the unsigned USERAUTH_REQUEST payload for publickey
/// signature verification (RFC 4252 section 7): identical to the
/// received packet except the final signature string is omitted.
pub fn publickey_data_to_sign(
    session_id: &[u8],
    request_payload_without_signature: &[u8],
) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.put_string(session_id);
    w.put_bytes(request_payload_without_signature);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rsa::{BigUint, RsaPrivateKey};
    use alloc::vec;

    #[test]
    fn password_matches_installed_account() {
        install_accounts(vec![
            UserAccount::without_password("user"),
            UserAccount::with_password("svc", "s3cret"),
        ]);
        assert!(verify_password("user", b""));
        assert!(!verify_password("user", b"wrong"));
        assert!(verify_password("svc", b"s3cret"));
        assert!(!verify_password("svc", b""));
        assert!(!verify_password("nobody", b""));
    }

    #[test]
    fn unknown_user_never_authenticates() {
        install_accounts(Vec::new());
        assert!(!verify_password("root", b""));
    }

    #[test]
    fn publickey_signature_round_trip_rsa_sha2_256() {
        let key = RsaPrivateKey::generate(512);
        install_authorized_key("user", key.public_key());

        let key_blob = super::super::kex::rsa_public_key_blob(&key.public_key());
        let data = b"signature-payload".to_vec();
        let signature = {
            let digest = sha256(&data);
            let mut w = WireWriter::new();
            w.put_string_str(ALG_HOSTKEY_RSA_SHA2_256);
            w.put_string(&key.sign_pkcs1v15(&digest));
            w.into_vec()
        };

        assert!(verify_public_key(
            "user",
            ALG_HOSTKEY_RSA_SHA2_256,
            &key_blob,
            &signature,
            &data
        ));
    }

    #[test]
    fn publickey_rejects_unknown_key() {
        let key = RsaPrivateKey::generate(512);
        let other = RsaPrivateKey::generate(512);
        install_authorized_key("user", key.public_key());
        install_accounts(Vec::new());

        let key_blob = super::super::kex::rsa_public_key_blob(&other.public_key());
        let data = b"signature-payload".to_vec();
        let signature = {
            let digest = sha256(&data);
            let mut w = WireWriter::new();
            w.put_string_str(ALG_HOSTKEY_RSA_SHA2_256);
            w.put_string(&other.sign_pkcs1v15(&digest));
            w.into_vec()
        };
        assert!(!verify_public_key(
            "user",
            ALG_HOSTKEY_RSA_SHA2_256,
            &key_blob,
            &signature,
            &data
        ));
    }

    #[test]
    fn biguint_round_trip_via_bytes() {
        let key = RsaPrivateKey::generate(512);
        let n = BigUint::from_bytes(&key.n.to_bytes());
        assert_eq!(n.to_bytes(), key.n.to_bytes());
    }

    #[test]
    fn rsa_encrypt_decrypt_round_trip() {
        let key = RsaPrivateKey::generate(512);
        let msg = b"hello world".to_vec();
        let encrypted = key.public_key().encrypt(&msg);
        let decrypted = key.decrypt(&encrypted);
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn rsa_sign_verify_round_trip() {
        let key = RsaPrivateKey::generate(512);
        let digest = sha256(b"test");
        let sig = key.sign_pkcs1v15(&digest);
        assert!(
            key.public_key().verify_pkcs1v15(&digest, &sig),
            "sign/verify failed"
        );
    }
}
