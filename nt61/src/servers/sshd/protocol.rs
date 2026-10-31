//! SSH-2.0 binary packet protocol and wire encoding.
//!
//! Implements the framing rules of RFC 4253 section 6 (packet length,
//! padding, sequence numbers, MAC) and the primitive wire encodings of
//! RFC 4251 sections 5-6 (byte, boolean, u32, string, mpint, name-list).
//! All protocol constants are named after the values they represent in
//! the RFCs; no numeric literals are embedded in the packet logic.

extern crate alloc;

use crate::crypto::cipher::{Aes256, Ctr};
use crate::crypto::csprng;
use crate::crypto::hash::{Hmac, Sha256};
use alloc::string::String;
use alloc::vec::Vec;

// ====================================================================
// Protocol constants (RFC 4253, RFC 4252, RFC 4254, RFC 8731)
// ====================================================================

/// Protocol version prefix every SSH-2.0 implementation must send
/// (RFC 4253 section 4.2).
pub const VERSION_PREFIX_SSH2: &str = "SSH-2.0-";
/// Version prefix accepted for backward compatibility with SSH 1.99.
pub const VERSION_PREFIX_SSH1_99: &str = "SSH-1.99-";
/// Our server identification string (comment part identifies the product).
pub const SERVER_VERSION_STRING: &str = "SSH-2.0-nt61_0.1";
/// RFC 4253 section 4.5 caps the version exchange line at 255 bytes.
pub const VERSION_LINE_MAX: usize = 255;

/// RFC 4253 section 6.1: packet_len must stay below 2^31 bytes.
pub const PACKET_LENGTH_MAX: usize = 0x7FFF_FFFF;
/// Defensive limit we enforce above the RFC minimum so a malformed
/// length cannot force a huge allocation.
pub const PACKET_LENGTH_LIMIT: usize = 64 * 1024;
/// RFC 4253 section 6.1: at least 4 bytes of padding are required.
pub const PADDING_MIN: usize = 4;
/// RFC 4253 section 6.1: the padding SHOULD be random.
pub const PADDING_RANDOM_BYTES: usize = 16;
/// Block size used while the connection is still unencrypted.
pub const BLOCK_SIZE_UNENCRYPTED: usize = 8;

// --- Message IDs (RFC 4253 section 12, RFC 4252 section 6,
//     RFC 4254 section 6, RFC 8731) ---
pub mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const DEBUG: u8 = 3;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

// --- Disconnection reason codes (RFC 4253 section 11.1) ---
pub mod disconnect_reason {
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const MAC_ERROR: u32 = 5;
    pub const SERVICE_NOT_AVAILABLE: u32 = 7;
}

// --- Algorithm names (RFC 8731, RFC 8332, RFC 4253, RFC 5647) ---
pub const ALG_KEX_CURVE25519_SHA256: &str = "curve25519-sha256";
pub const ALG_HOSTKEY_RSA_SHA2_256: &str = "rsa-sha2-256";
pub const ALG_HOSTKEY_SSH_RSA: &str = "ssh-rsa";
pub const ALG_CIPHER_AES256_CTR: &str = "aes256-ctr";
pub const ALG_MAC_HMAC_SHA2_256: &str = "hmac-sha2-256";
pub const ALG_COMPRESSION_NONE: &str = "none";

/// Service name for the user-authentication protocol (RFC 4252).
pub const SERVICE_USERAUTH: &str = "ssh-userauth";
/// Service name for the connection protocol (RFC 4254).
pub const SERVICE_CONNECTION: &str = "ssh-connection";

/// Channel type for an interactive shell / exec session (RFC 4254).
pub const CHANNEL_TYPE_SESSION: &str = "session";

/// RFC 4254 section 5.2: the remote end must never send a packet
/// larger than this (typical OpenSSH value).
pub const CHANNEL_PACKET_SIZE_MAX: u32 = 32768;
/// Initial receive window we advertise (2 MiB, per RFC 4254 section 5.2
/// recommendation to keep it comfortably above the max packet size).
pub const CHANNEL_WINDOW_INITIAL: u32 = 2 * 1024 * 1024;

/// aes256-ctr encrypts 16-byte blocks (RFC 5647).
pub const CIPHER_BLOCK_SIZE_AES: usize = 16;
/// aes256-ctr uses a 32-byte key (RFC 5647).
pub const CIPHER_KEY_LEN_AES256: usize = 32;
/// hmac-sha2-256 produces 32-byte MACs (RFC 6668).
pub const MAC_LEN_HMAC_SHA2_256: usize = 32;

// ====================================================================
// Wire encoding (RFC 4251 sections 5-6)
// ====================================================================

/// Append-only wire writer.
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn put_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn put_bool(&mut self, value: bool) {
        self.buf.push(u8::from(value));
    }

    pub fn put_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn put_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn put_string(&mut self, data: &[u8]) {
        self.put_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
    }

    pub fn put_string_str(&mut self, value: &str) {
        self.put_string(value.as_bytes());
    }

    pub fn put_name_list(&mut self, names: &[&str]) {
        let joined = names.join(",");
        self.put_string_str(&joined);
    }

    /// Encode a non-negative big-endian integer magnitude as SSH mpint:
    /// minimal length, with a leading zero byte when the value's top bit
    /// is set (RFC 4251 section 6.1).
    pub fn put_mpint(&mut self, magnitude_be: &[u8]) {
        let mut start = 0;
        while start + 1 < magnitude_be.len() && magnitude_be[start] == 0 {
            start += 1;
        }
        let value = &magnitude_be[start..];
        if !value.is_empty() && value[0] & 0x80 != 0 {
            self.put_u32(value.len() as u32 + 1);
            self.buf.push(0);
        } else {
            self.put_u32(value.len() as u32);
        }
        self.buf.extend_from_slice(&magnitude_be[start..]);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowing wire reader.
pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn get_u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    pub fn get_bool(&mut self) -> Option<bool> {
        Some(self.get_u8()? != 0)
    }

    pub fn get_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(bytes))
    }

    pub fn get_string(&mut self) -> Option<&'a [u8]> {
        let len = self.get_u32()? as usize;
        let slice = self.data.get(self.pos..self.pos.checked_add(len)?)?;
        self.pos += len;
        Some(slice)
    }

    pub fn get_name_list(&mut self) -> Option<Vec<String>> {
        let raw = self.get_string()?;
        let text = core::str::from_utf8(raw).ok()?;
        Some(
            text.split(',')
                .filter(|name| !name.is_empty())
                .map(String::from)
                .collect(),
        )
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_at_end(&self) -> bool {
        self.pos == self.data.len()
    }

    /// Current read offset within the underlying buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }
}

// ====================================================================
// Binary packet transport (RFC 4253 section 6)
// ====================================================================

/// I/O abstraction so the transport can be unit-tested without a
/// network stack: pull reads available bytes (WouldBlock when none),
/// push writes a whole buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    WouldBlock,
    Closed,
    MalformedPacket,
    MacVerificationFailed,
}

pub trait TransportIo {
    fn pull(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    fn push(&mut self, data: &[u8]) -> Result<usize, TransportError>;
}

/// Per-direction cipher + MAC state. Created when NEWKEYS switches
/// the transport to encrypted mode.
pub struct DirectionState {
    cipher: Ctr<Aes256>,
    mac_key: [u8; MAC_LEN_HMAC_SHA2_256],
}

impl DirectionState {
    pub fn new(key: &[u8; CIPHER_KEY_LEN_AES256], mac_key: &[u8; MAC_LEN_HMAC_SHA2_256]) -> Self {
        Self {
            cipher: Ctr::new_aes256(key, &[0u8; 16]),
            mac_key: *mac_key,
        }
    }
}

pub struct Transport {
    rx_buffer: Vec<u8>,
    seq_rx: u32,
    seq_tx: u32,
    receive: Option<DirectionState>,
    send: Option<DirectionState>,
}

impl Transport {
    pub fn new() -> Self {
        Self {
            rx_buffer: Vec::new(),
            seq_rx: 0,
            seq_tx: 0,
            receive: None,
            send: None,
        }
    }

    /// Switch both directions to the negotiated aes256-ctr /
    /// hmac-sha2-256 state (RFC 4253 section 7.3 NEWKEYS).
    pub fn activate_keys(
        &mut self,
        client_to_server: DirectionState,
        server_to_client: DirectionState,
    ) {
        self.receive = Some(client_to_server);
        self.send = Some(server_to_client);
    }

    pub fn is_encrypted(&self) -> bool {
        self.receive.is_some()
    }

    /// Push raw bytes into the receive buffer (used for bytes that
    /// were read while scanning the version banner).
    pub fn feed(&mut self, data: &[u8]) {
        self.rx_buffer.extend_from_slice(data);
    }

    /// Drain available bytes and return the next complete payload
    /// when one has fully arrived. Returns Ok(None) while more data
    /// is needed.
    pub fn read_packet(
        &mut self,
        io: &mut dyn TransportIo,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let mut chunk = [0u8; 4096];
        loop {
            match io.pull(&mut chunk) {
                Ok(0) => break,
                Ok(n) => self.rx_buffer.extend_from_slice(&chunk[..n]),
                Err(TransportError::WouldBlock) => break,
                Err(other) => return Err(other),
            }
        }

        let block = match &self.receive {
            Some(_) => CIPHER_BLOCK_SIZE_AES,
            None => BLOCK_SIZE_UNENCRYPTED,
        };

        if self.rx_buffer.len() < 4 {
            return Ok(None);
        }
        let packet_len = u32::from_be_bytes([
            self.rx_buffer[0],
            self.rx_buffer[1],
            self.rx_buffer[2],
            self.rx_buffer[3],
        ]) as usize;
        if !(PADDING_MIN + 1..=PACKET_LENGTH_LIMIT).contains(&packet_len)
            || !(packet_len + 4).is_multiple_of(block)
        {
            return Err(TransportError::MalformedPacket);
        }

        let mac_len = if self.receive.is_some() {
            MAC_LEN_HMAC_SHA2_256
        } else {
            0
        };
        let total = 4 + packet_len + mac_len;
        if self.rx_buffer.len() < total {
            return Ok(None);
        }
        let packet_bytes: Vec<u8> = self.rx_buffer.drain(..total).collect();

        let plain = match &mut self.receive {
            Some(state) => {
                // RFC 4253 section 6.4: the MAC covers the sequence
                // number and the *unencrypted* packet, so the body
                // must be decrypted before verification.
                let mut plain = packet_bytes[4..4 + packet_len].to_vec();
                state.cipher.process(&mut plain);
                let seq_bytes = self.seq_rx.to_be_bytes();
                let mut mac = Hmac::<Sha256>::new_sha256(&state.mac_key);
                mac.update(&seq_bytes);
                mac.update(&packet_bytes[..4]);
                mac.update(&plain);
                let expected = mac.finalize();
                let received_mac = &packet_bytes[4 + packet_len..];
                if received_mac != expected {
                    return Err(TransportError::MacVerificationFailed);
                }
                plain
            }
            None => packet_bytes[4..4 + packet_len].to_vec(),
        };

        let padding_len = plain[0] as usize;
        if padding_len + 1 > plain.len() {
            return Err(TransportError::MalformedPacket);
        }
        self.seq_rx = self.seq_rx.wrapping_add(1);
        Ok(Some(plain[1..plain.len() - padding_len].to_vec()))
    }

    /// Frame, (optionally) encrypt, and send one payload packet.
    pub fn write_packet(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        let block = match &self.send {
            Some(_) => CIPHER_BLOCK_SIZE_AES,
            None => BLOCK_SIZE_UNENCRYPTED,
        };
        // RFC 4253 section 6: the total on-wire size, including the
        // 4-byte length field, must be a multiple of the cipher block
        // size (8 when unencrypted). Size the packet so that the
        // padding stays at least PADDING_MIN bytes.
        let total_min = 4 + payload.len() + 1 + PADDING_MIN;
        let packet_len = round_up_to_multiple(total_min, block) - 4;
        let padding_len = packet_len - payload.len() - 1;

        let mut plain: Vec<u8> = Vec::with_capacity(packet_len);
        plain.push(padding_len as u8);
        plain.extend_from_slice(payload);
        let mut random_padding = [0u8; PADDING_RANDOM_BYTES];
        csprng::fill(&mut random_padding);
        plain.extend_from_slice(&random_padding[..padding_len.min(PADDING_RANDOM_BYTES)]);
        while plain.len() < packet_len {
            plain.push(0);
        }

        let mut frame: Vec<u8> = Vec::with_capacity(4 + packet_len + MAC_LEN_HMAC_SHA2_256);
        frame.extend_from_slice(&(packet_len as u32).to_be_bytes());
        frame.extend_from_slice(&plain);

        match &mut self.send {
            Some(state) => {
                let seq_bytes = self.seq_tx.to_be_bytes();
                let mut mac = Hmac::<Sha256>::new_sha256(&state.mac_key);
                mac.update(&seq_bytes);
                mac.update(&frame);
                let tag = mac.finalize();
                let mut ciphertext = frame[4..].to_vec();
                state.cipher.process(&mut ciphertext);
                let mut out = frame[..4].to_vec();
                out.extend_from_slice(&ciphertext);
                out.extend_from_slice(&tag);
                io.push(&out)?;
            }
            None => {
                io.push(&frame)?;
            }
        }
        self.seq_tx = self.seq_tx.wrapping_add(1);
        Ok(())
    }

    /// Bytes buffered but not yet forming a complete packet.
    pub fn pending_rx_len(&self) -> usize {
        self.rx_buffer.len()
    }
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

fn round_up_to_multiple(value: usize, multiple: usize) -> usize {
    value.div_ceil(multiple) * multiple
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LoopbackIo {
        buffer: Vec<u8>,
    }

    impl LoopbackIo {
        fn new() -> Self {
            Self { buffer: Vec::new() }
        }
    }

    impl TransportIo for LoopbackIo {
        fn pull(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
            if self.buffer.is_empty() {
                return Err(TransportError::WouldBlock);
            }
            let count = out.len().min(self.buffer.len());
            let bytes: Vec<u8> = self.buffer.drain(..count).collect();
            out[..count].copy_from_slice(&bytes);
            Ok(count)
        }

        fn push(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            self.buffer.extend_from_slice(data);
            Ok(data.len())
        }
    }

    #[test]
    fn packet_round_trip_unencrypted() {
        let mut sender = Transport::new();
        let mut receiver = Transport::new();
        let mut wire = LoopbackIo::new();

        sender.write_packet(&mut wire, b"HELLO").unwrap();
        assert!(!receiver.is_encrypted());
        let payload = receiver.read_packet(&mut wire).unwrap().unwrap();
        assert_eq!(payload, b"HELLO");
    }

    #[test]
    fn packet_round_trip_encrypted() {
        let mut sender = Transport::new();
        let mut receiver = Transport::new();
        let mut wire = LoopbackIo::new();

        let c2s_key = [0x11u8; CIPHER_KEY_LEN_AES256];
        let c2s_mac = [0x22u8; MAC_LEN_HMAC_SHA2_256];
        let s2c_key = [0x33u8; CIPHER_KEY_LEN_AES256];
        let s2c_mac = [0x44u8; MAC_LEN_HMAC_SHA2_256];

        sender.activate_keys(
            DirectionState::new(&s2c_key, &s2c_mac),
            DirectionState::new(&c2s_key, &c2s_mac),
        );
        receiver.activate_keys(
            DirectionState::new(&c2s_key, &c2s_mac),
            DirectionState::new(&s2c_key, &s2c_mac),
        );

        assert!(sender.is_encrypted());
        sender.write_packet(&mut wire, b"SECRET").unwrap();
        let payload = receiver.read_packet(&mut wire).unwrap().unwrap();
        assert_eq!(payload, b"SECRET");
    }

    #[test]
    fn mpint_encoding_adds_leading_zero_for_high_bit() {
        let mut w = WireWriter::new();
        w.put_mpint(&[0xFF, 0x01]);
        let bytes = w.into_vec();
        // length 3 = 0x00 0xFF 0x01
        assert_eq!(&bytes, &[0, 0, 0, 3, 0, 0xFF, 0x01]);
    }

    #[test]
    fn mpint_encoding_is_minimal() {
        let mut w = WireWriter::new();
        w.put_mpint(&[0x00, 0x00, 0x05]);
        let bytes = w.into_vec();
        // Minimal encoding: leading zeros are stripped; value 5 fits one byte.
        assert_eq!(&bytes, &[0, 0, 0, 1, 0x05]);
    }

    #[test]
    fn wire_round_trip_all_primitives() {
        let mut w = WireWriter::new();
        w.put_u8(0x42);
        w.put_bool(true);
        w.put_u32(0xDEAD_BEEF);
        w.put_string(b"hello");
        w.put_name_list(&["aes256-ctr", "hmac-sha2-256"]);

        let bytes = w.into_vec();
        let mut r = WireReader::new(&bytes);
        assert_eq!(r.get_u8(), Some(0x42));
        assert_eq!(r.get_bool(), Some(true));
        assert_eq!(r.get_u32(), Some(0xDEAD_BEEF));
        assert_eq!(r.get_string(), Some(b"hello".as_slice()));
        let names = r.get_name_list().unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], "aes256-ctr");
        assert_eq!(names[1], "hmac-sha2-256");
        assert!(r.is_at_end());
    }

    #[test]
    fn unencrypted_packet_round_trip() {
        let mut tx = Transport::new();
        let mut rx = Transport::new();
        let mut a_to_b = Vec::new();
        let payload = b"kexinit-payload".to_vec();
        tx.write_packet(&mut PushSink(&mut a_to_b), &payload)
            .unwrap();

        let mut sink = PullSink(&a_to_b);
        let received = rx.read_packet(&mut sink).unwrap().unwrap();
        assert_eq!(received, payload);
    }

    struct PushSink<'a>(&'a mut Vec<u8>);
    impl TransportIo for PushSink<'_> {
        fn pull(&mut self, _buffer: &mut [u8]) -> Result<usize, TransportError> {
            Err(TransportError::WouldBlock)
        }
        fn push(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    struct PullSink<'a>(&'a [u8]);
    impl TransportIo for PullSink<'_> {
        fn pull(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
            let n = buffer.len().min(self.0.len());
            buffer[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
        fn push(&mut self, _data: &[u8]) -> Result<usize, TransportError> {
            Err(TransportError::Closed)
        }
    }

    #[test]
    fn encrypted_packet_round_trip_with_separate_directions() {
        let mut key_bytes = [0u8; CIPHER_KEY_LEN_AES256];
        csprng::fill(&mut key_bytes);
        let mut mac_bytes = [0u8; MAC_LEN_HMAC_SHA2_256];
        csprng::fill(&mut mac_bytes);

        let mut tx = Transport::new();
        let mut rx = Transport::new();
        tx.activate_keys(
            DirectionState::new(&key_bytes, &mac_bytes),
            DirectionState::new(&key_bytes, &mac_bytes),
        );
        rx.activate_keys(
            DirectionState::new(&key_bytes, &mac_bytes),
            DirectionState::new(&key_bytes, &mac_bytes),
        );

        let mut wire = Vec::new();
        let payload = b"encrypted-channel-data".to_vec();
        tx.write_packet(&mut PushSink(&mut wire), &payload).unwrap();

        let mut sink = PullSink(&wire);
        let received = rx.read_packet(&mut sink).unwrap().unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn truncated_stream_returns_none() {
        let mut rx = Transport::new();
        let mut sink = PullSink(&[0, 0, 0]);
        assert!(matches!(rx.read_packet(&mut sink), Ok(None)));
    }
}
