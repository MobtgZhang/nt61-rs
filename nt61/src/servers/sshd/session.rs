//! SSH session driver: banner exchange, key exchange, user
//! authentication, and channel multiplexing (RFC 4253, RFC 4252,
//! RFC 4254).

extern crate alloc;

use super::auth;
use super::child::{self, ChildRequestKind};
use super::kex::{self, Negotiated};
use super::protocol::*;
use crate::crypto::csprng;
use crate::crypto::rsa::RsaPrivateKey;
use crate::ke::sync::Spinlock;
use alloc::string::String;
use alloc::vec::Vec;

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    New = 0,
    TcpAccepted = 1,
    BannerExchanged = 2,
    KexInit = 3,
    Encrypted = 4,
    UserauthRequested = 5,
    Authenticated = 6,
    ConnectionRequested = 7,
    ChannelOpen = 8,
    ExecRequest = 9,
    ChildSpawned = 10,
    Closed = 11,
}

impl SessionState {
    pub fn can_transition_to(self, next: SessionState) -> bool {
        if next == SessionState::Closed {
            return self != SessionState::Closed;
        }
        (next as u8) == (self as u8) + 1
    }

    pub fn transition(self, next: SessionState) -> Option<SessionState> {
        if self.can_transition_to(next) {
            Some(next)
        } else {
            None
        }
    }

    pub fn is_terminal(self) -> bool {
        self == SessionState::Closed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionStats {
    pub state: SessionState,
    pub kex_attempts: u32,
    pub auth_attempts: u32,
    pub bytes_from_client: u64,
    pub bytes_to_client: u64,
}

impl SessionStats {
    pub const fn new() -> Self {
        Self {
            state: SessionState::New,
            kex_attempts: 0,
            auth_attempts: 0,
            bytes_from_client: 0,
            bytes_to_client: 0,
        }
    }
}

// ====================================================================
// Host key
// ====================================================================

static HOST_KEY: Spinlock<Option<RsaPrivateKey>> = Spinlock::new(None);

/// Install a persistent host key (loaded from the key file at service
/// start-up so the host identity survives restarts).
pub fn install_host_key(key: RsaPrivateKey) {
    *HOST_KEY.lock() = Some(key);
}

/// Return the installed host key, generating a fresh one on first use
/// when none was installed.
pub fn host_key() -> RsaPrivateKey {
    let mut guard = HOST_KEY.lock();
    if guard.is_none() {
        let host_key = RsaPrivateKey::generate(HOST_KEY_BITS_DEFAULT)
            .expect("supported RSA host key size");
        *guard = Some(host_key);
    }
    guard.as_ref().expect("host key was just installed").clone()
}

/// RSA modulus size for auto-generated sshd host keys. 2048-bit is the
/// smallest commonly recommended size for RSA host keys today.
const HOST_KEY_BITS_DEFAULT: usize = 2048;

// ====================================================================
// Socket adapter
// ====================================================================

/// TransportIo implementation over a connected kernel TCP socket.
pub struct SocketIo {
    pub socket_id: u32,
}

impl TransportIo for SocketIo {
    fn pull(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        use crate::netstack::socket::{recv, SocketError};
        match recv(self.socket_id, buffer) {
            Ok(n) => Ok(n),
            Err(SocketError::WouldBlock) => Err(TransportError::WouldBlock),
            Err(_) => Err(TransportError::Closed),
        }
    }

    fn push(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        use crate::netstack::socket::{send, SocketError};
        match send(self.socket_id, data) {
            Ok(n) => Ok(n),
            Err(SocketError::WouldBlock) => Err(TransportError::WouldBlock),
            Err(_) => Err(TransportError::Closed),
        }
    }
}

// ====================================================================
// Session
// ====================================================================

/// One server-side SSH channel ("session" channels).
#[derive(Debug, Clone, Copy)]
struct Channel {
    /// Channel number chosen by the client.
    remote_id: u32,
    /// Channel number chosen by this side.
    local_id: u32,
    open: bool,
}

/// RFC 4254 section 5.1 channel-open failure reason "unknown channel type".
const CHANNEL_OPEN_REASON_UNKNOWN_TYPE: u32 = 3;

/// Exit code reported for exec requests when no command executor is
/// installed (127 = command could not be executed).
const EXIT_CODE_NO_EXECUTOR: u32 = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadOutcome {
    Continue,
    Close,
}

pub struct ActiveSession {
    pub socket_id: u32,
    pub state: SessionState,
    pub stats: SessionStats,
    transport: Transport,
    banner_buffer: Vec<u8>,
    client_version: Option<Vec<u8>>,
    server_version: Vec<u8>,
    server_kexinit: Option<Vec<u8>>,
    client_kexinit: Option<Vec<u8>>,
    ephemeral_secret: Option<[u8; kex::X25519_KEY_LEN]>,
    negotiated: Option<Negotiated>,
    session_id: Option<[u8; 32]>,
    derived_keys: Option<kex::DerivedKeys>,
    auth_attempts: u32,
    authenticated_user: Option<String>,
    next_channel_local_id: u32,
    channels: Vec<Channel>,
    line_buffer: Vec<u8>,
}

impl ActiveSession {
    pub fn new(socket_id: u32) -> Self {
        Self {
            socket_id,
            state: SessionState::TcpAccepted,
            stats: SessionStats::new(),
            transport: Transport::new(),
            banner_buffer: Vec::new(),
            client_version: None,
            server_version: SERVER_VERSION_STRING.as_bytes().to_vec(),
            server_kexinit: None,
            client_kexinit: None,
            ephemeral_secret: None,
            negotiated: None,
            session_id: None,
            derived_keys: None,
            auth_attempts: 0,
            authenticated_user: None,
            next_channel_local_id: 0,
            channels: Vec::new(),
            line_buffer: Vec::new(),
        }
    }

    /// Drive the session: complete the handshake when needed and
    /// process every packet that is fully available. Returns Ok(())
    /// when the session is waiting for more client data.
    pub fn step(&mut self, io: &mut dyn TransportIo) -> Result<(), TransportError> {
        if self.state == SessionState::TcpAccepted {
            if !self.exchange_banner(io)? {
                return Ok(());
            }
            let kexinit = kex::build_server_kexinit();
            self.server_kexinit = Some(kexinit.clone());
            self.advance_state(SessionState::BannerExchanged);
            self.advance_state(SessionState::KexInit);
            self.transport.write_packet(io, &kexinit)?;
        }

        loop {
            match self.transport.read_packet(io) {
                Ok(Some(payload)) => {
                    self.stats.bytes_from_client += payload.len() as u64;
                    if self.handle_payload(io, &payload)? == PayloadOutcome::Close {
                        self.state = SessionState::Closed;
                        return Ok(());
                    }
                }
                Ok(None) | Err(TransportError::WouldBlock) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    fn advance_state(&mut self, next: SessionState) {
        if let Some(reached) = self.state.transition(next) {
            self.state = reached;
        } else if self.state == next {
            self.state = next;
        }
    }

    // --- Version exchange (RFC 4253 section 4) ---

    /// Returns true when both banners have been exchanged. When the
    /// client banner is still incomplete, returns false and preserves
    /// the partial bytes for the next poll.
    fn exchange_banner(&mut self, io: &mut dyn TransportIo) -> Result<bool, TransportError> {
        if self.client_version.is_some() {
            return Ok(true);
        }
        loop {
            if let Some(newline) = self.banner_buffer.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.banner_buffer.drain(..=newline).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > VERSION_LINE_MAX {
                    return Err(TransportError::MalformedPacket);
                }
                let starts_ok = line.starts_with(VERSION_PREFIX_SSH2.as_bytes())
                    || line.starts_with(VERSION_PREFIX_SSH1_99.as_bytes());
                if !starts_ok {
                    return Err(TransportError::MalformedPacket);
                }
                self.client_version = Some(line);
                break;
            }
            if self.banner_buffer.len() > VERSION_LINE_MAX {
                return Err(TransportError::MalformedPacket);
            }
            let mut chunk = [0u8; 128];
            match io.pull(&mut chunk) {
                Ok(0) => return Err(TransportError::Closed),
                Ok(n) => self.banner_buffer.extend_from_slice(&chunk[..n]),
                Err(TransportError::WouldBlock) => return Ok(false),
                Err(other) => return Err(other),
            }
        }

        let mut banner = self.server_version.clone();
        banner.extend_from_slice(b"\r\n");
        io.push(&banner)?;
        self.stats.bytes_to_client += banner.len() as u64;
        Ok(true)
    }

    // --- Packet dispatch ---

    fn handle_payload(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let Some(&msg_id) = payload.first() else {
            return Ok(PayloadOutcome::Continue);
        };
        match msg_id {
            msg::DISCONNECT => Ok(PayloadOutcome::Close),
            msg::IGNORE | msg::DEBUG => Ok(PayloadOutcome::Continue),
            msg::KEXINIT => self.handle_kexinit(payload),
            msg::KEX_ECDH_INIT => self.handle_ecdh_init(io, payload),
            msg::NEWKEYS => self.handle_newkeys(),
            msg::SERVICE_REQUEST => self.handle_service_request(io, payload),
            msg::USERAUTH_REQUEST => self.handle_userauth_request(io, payload),
            msg::CHANNEL_OPEN => self.handle_channel_open(io, payload),
            msg::CHANNEL_REQUEST => self.handle_channel_request(io, payload),
            msg::CHANNEL_DATA => self.handle_channel_data(io, payload),
            msg::CHANNEL_EOF => Ok(PayloadOutcome::Continue),
            msg::CHANNEL_CLOSE => self.handle_channel_close(io, payload),
            _ => {
                self.send_disconnect(io, disconnect_reason::PROTOCOL_ERROR, "unhandled message");
                Ok(PayloadOutcome::Close)
            }
        }
    }

    fn handle_kexinit(&mut self, payload: &[u8]) -> Result<PayloadOutcome, TransportError> {
        let negotiated = kex::negotiate(payload).map_err(|_| TransportError::MalformedPacket)?;
        self.negotiated = Some(negotiated);
        self.client_kexinit = Some(payload.to_vec());
        let mut secret = [0u8; kex::X25519_KEY_LEN];
        csprng::fill(&mut secret);
        self.ephemeral_secret = Some(secret);
        self.stats.kex_attempts += 1;
        Ok(PayloadOutcome::Continue)
    }

    fn handle_ecdh_init(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let (Some(negotiated), Some(client_kexinit), Some(server_kexinit), Some(ephemeral_secret)) = (
            self.negotiated.as_ref(),
            self.client_kexinit.as_deref(),
            self.server_kexinit.as_deref(),
            self.ephemeral_secret,
        ) else {
            return Err(TransportError::MalformedPacket);
        };

        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let client_public_bytes = reader.get_string().ok_or(TransportError::MalformedPacket)?;
        if client_public_bytes.len() != kex::X25519_KEY_LEN {
            return Err(TransportError::MalformedPacket);
        }
        let mut client_public = [0u8; kex::X25519_KEY_LEN];
        client_public.copy_from_slice(client_public_bytes);

        let client_version = self.client_version.clone().unwrap_or_default();
        let host = host_key();
        let reply = kex::kex_ecdh_reply(
            &ephemeral_secret,
            &client_public,
            &client_version,
            &self.server_version,
            client_kexinit,
            server_kexinit,
            &host,
            &negotiated.host_key_algorithm,
        )
        .ok_or(TransportError::MalformedPacket)?;

        self.derived_keys = Some(kex::derive_keys(&reply.shared_secret, &reply.exchange_hash));
        self.session_id = Some(reply.exchange_hash);
        self.transport.write_packet(io, &reply.payload)?;
        self.transport.write_packet(io, &[msg::NEWKEYS])?;
        Ok(PayloadOutcome::Continue)
    }

    fn handle_newkeys(&mut self) -> Result<PayloadOutcome, TransportError> {
        let Some(keys) = self.derived_keys.take() else {
            return Err(TransportError::MalformedPacket);
        };
        let c2s = DirectionState::new(&keys.client_to_server_key, &keys.client_to_server_mac);
        let s2c = DirectionState::new(&keys.server_to_client_key, &keys.server_to_client_mac);
        self.transport.activate_keys(c2s, s2c);
        self.advance_state(SessionState::Encrypted);
        Ok(PayloadOutcome::Continue)
    }

    fn handle_service_request(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let service = reader.get_string().ok_or(TransportError::MalformedPacket)?;

        if service == SERVICE_USERAUTH.as_bytes() && self.state == SessionState::Encrypted {
            self.send_service_accept(io, SERVICE_USERAUTH)?;
            self.advance_state(SessionState::UserauthRequested);
            return Ok(PayloadOutcome::Continue);
        }
        if service == SERVICE_CONNECTION.as_bytes() && self.state == SessionState::Authenticated {
            self.send_service_accept(io, SERVICE_CONNECTION)?;
            self.advance_state(SessionState::ConnectionRequested);
            return Ok(PayloadOutcome::Continue);
        }
        self.send_disconnect(
            io,
            disconnect_reason::SERVICE_NOT_AVAILABLE,
            "service unavailable",
        );
        Ok(PayloadOutcome::Close)
    }

    fn handle_userauth_request(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        if self.state != SessionState::UserauthRequested {
            self.send_disconnect(
                io,
                disconnect_reason::PROTOCOL_ERROR,
                "userauth before service request",
            );
            return Ok(PayloadOutcome::Close);
        }
        self.auth_attempts += 1;
        self.stats.auth_attempts = self.auth_attempts;

        let max_tries = super::state_snapshot().config.max_auth_tries;
        if max_tries > 0 && self.auth_attempts > max_tries {
            self.send_disconnect(
                io,
                disconnect_reason::PROTOCOL_ERROR,
                "too many authentication attempts",
            );
            return Ok(PayloadOutcome::Close);
        }

        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let user_bytes = reader.get_string().ok_or(TransportError::MalformedPacket)?;
        let user = core::str::from_utf8(user_bytes).map_err(|_| TransportError::MalformedPacket)?;
        let _service = reader.get_string().ok_or(TransportError::MalformedPacket)?;
        let method = reader.get_string().ok_or(TransportError::MalformedPacket)?;

        let config = super::state_snapshot().config;
        let outcome = if method == b"password" {
            if !config.password_authentication {
                super::note_auth_failure();
                self.send_userauth_failure(io)?;
                return Ok(PayloadOutcome::Continue);
            }
            let _checked = reader.get_bool().ok_or(TransportError::MalformedPacket)?;
            let password = reader.get_string().ok_or(TransportError::MalformedPacket)?;
            auth::verify_password(user, password)
        } else if method == b"publickey" {
            let has_signature = reader.get_bool().ok_or(TransportError::MalformedPacket)?;
            let algorithm_bytes = reader.get_string().ok_or(TransportError::MalformedPacket)?;
            let algorithm = core::str::from_utf8(algorithm_bytes)
                .map_err(|_| TransportError::MalformedPacket)?;
            let key_blob = reader.get_string().ok_or(TransportError::MalformedPacket)?;
            if !super::launcher::config_allows_pubkey(&config, user) {
                super::note_auth_failure();
                self.send_userauth_failure(io)?;
                return Ok(PayloadOutcome::Continue);
            }
            if !has_signature {
                // RFC 4252 section 7: reply FAILURE carrying the
                // "publickey" flag so the client may retry with a
                // signature.
                self.send_userauth_failure(io)?;
                return Ok(PayloadOutcome::Continue);
            }
            let pos_after_blob = reader.pos();
            let signature = reader.get_string().ok_or(TransportError::MalformedPacket)?;
            // The signature covers string(session-id) followed by the
            // request payload with the signature field omitted.
            let session_id = self.session_id.unwrap_or([0u8; 32]);
            let data_to_sign =
                auth::publickey_data_to_sign(&session_id, &payload[..pos_after_blob]);
            auth::verify_public_key(user, &algorithm, key_blob, signature, &data_to_sign)
        } else {
            false
        };

        if outcome {
            self.authenticated_user = Some(String::from(user));
            let mut w = WireWriter::new();
            w.put_u8(msg::USERAUTH_SUCCESS);
            self.transport.write_packet(io, &w.into_vec())?;
            self.advance_state(SessionState::Authenticated);
        } else {
            super::note_auth_failure();
            self.send_userauth_failure(io)?;
        }
        Ok(PayloadOutcome::Continue)
    }

    // --- Channel layer (RFC 4254) ---

    fn handle_channel_open(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        if self.state != SessionState::Authenticated && self.state != SessionState::ConnectionRequested {
            self.send_disconnect(
                io,
                disconnect_reason::PROTOCOL_ERROR,
                "connection request before authentication",
            );
            return Ok(PayloadOutcome::Close);
        }
        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let channel_type = reader.get_string().ok_or(TransportError::MalformedPacket)?;
        let remote_id = reader.get_u32().unwrap_or(0);

        if channel_type != CHANNEL_TYPE_SESSION.as_bytes() {
            let mut w = WireWriter::new();
            w.put_u8(msg::CHANNEL_OPEN_FAILURE);
            w.put_u32(remote_id);
            w.put_u32(CHANNEL_OPEN_REASON_UNKNOWN_TYPE);
            w.put_string_str("only session channels are supported");
            w.put_string_str("");
            self.transport.write_packet(io, &w.into_vec())?;
            return Ok(PayloadOutcome::Continue);
        }

        let local_id = self.next_channel_local_id;
        self.next_channel_local_id += 1;
        self.channels.push(Channel {
            remote_id,
            local_id,
            open: true,
        });
        self.advance_state(SessionState::ChannelOpen);

        let mut w = WireWriter::new();
        w.put_u8(msg::CHANNEL_OPEN_CONFIRMATION);
        w.put_u32(remote_id);
        w.put_u32(local_id);
        w.put_u32(CHANNEL_WINDOW_INITIAL);
        w.put_u32(CHANNEL_PACKET_SIZE_MAX);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(PayloadOutcome::Continue)
    }

    fn handle_channel_request(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let recipient = reader.get_u32().ok_or(TransportError::MalformedPacket)?;
        let request = reader.get_string().ok_or(TransportError::MalformedPacket)?;

        let channel = self.find_channel(recipient);
        let channel_open = channel.map(|channel| channel.open).unwrap_or(false);
        // Replies are addressed to the client's channel number.
        let reply_recipient = channel
            .map(|channel| channel.remote_id)
            .unwrap_or(recipient);

        if request == b"pty-req" {
            return self.send_channel_reply(io, reply_recipient, msg::CHANNEL_SUCCESS);
        }
        if request == b"shell" {
            if !channel_open {
                return self.send_channel_reply(io, recipient, msg::CHANNEL_FAILURE);
            }
            let _ = child::register_child(shell_child_record());
            self.advance_state(SessionState::ExecRequest);
            self.advance_state(SessionState::ChildSpawned);
            return self.send_channel_reply(io, reply_recipient, msg::CHANNEL_SUCCESS);
        }
        if request == b"exec" || request == b"subsystem" {
            let command_bytes = reader.get_string().ok_or(TransportError::MalformedPacket)?;
            let command =
                core::str::from_utf8(command_bytes).map_err(|_| TransportError::MalformedPacket)?;
            let execution = match child::execute_line(command) {
                Some(execution) => execution,
                None => child::CommandExecution::new(
                    EXIT_CODE_NO_EXECUTOR,
                    Vec::new(),
                ),
            };
            let kind = if request == b"exec" {
                ChildRequestKind::Exec
            } else {
                ChildRequestKind::Subsystem
            };
            let _ = child::register_child(exec_child_record(kind));
            self.advance_state(SessionState::ExecRequest);
            self.advance_state(SessionState::ChildSpawned);
            if !execution.output.is_empty() {
                self.send_channel_data(io, reply_recipient, &execution.output)?;
            }
            self.send_exit_status(io, reply_recipient, execution.exit_code)?;
            return match channel.map(|channel| channel.local_id) {
                Some(local_id) => self.send_channel_eof_and_close(io, local_id, reply_recipient),
                None => Ok(PayloadOutcome::Continue),
            };
        }
        self.send_channel_reply(io, reply_recipient, msg::CHANNEL_FAILURE)
    }

    fn handle_channel_data(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let recipient = reader.get_u32().ok_or(TransportError::MalformedPacket)?;
        let data = reader.get_string().ok_or(TransportError::MalformedPacket)?;

        let Some(channel) = self.find_channel(recipient) else {
            return Ok(PayloadOutcome::Continue);
        };
        if !channel.open {
            return Ok(PayloadOutcome::Continue);
        }

        let mut buffer = core::mem::take(&mut self.line_buffer);
        for byte in data {
            if *byte == b'\n' || *byte == b'\r' {
                if let Ok(line) = core::str::from_utf8(&buffer) {
                    if !line.is_empty() {
                        match child::execute_line(line) {
                            Some(execution) => {
                                if !execution.output.is_empty() {
                                    self.send_channel_data(
                                        io,
                                        channel.remote_id,
                                        &execution.output,
                                    )?;
                                }
                                self.send_exit_status(
                                    io,
                                    channel.remote_id,
                                    execution.exit_code,
                                )?;
                            }
                            None => {
                                self.send_channel_reply(
                                    io,
                                    channel.remote_id,
                                    msg::CHANNEL_FAILURE,
                                )?;
                            }
                        }
                    }
                }
                buffer.clear();
            } else {
                buffer.push(*byte);
            }
        }
        self.line_buffer = buffer;
        Ok(PayloadOutcome::Continue)
    }

    fn handle_channel_close(
        &mut self,
        io: &mut dyn TransportIo,
        payload: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let mut reader = WireReader::new(payload);
        let _msg_id = reader.get_u8().ok_or(TransportError::MalformedPacket)?;
        let recipient = reader.get_u32().ok_or(TransportError::MalformedPacket)?;
        // Replies must be addressed to the client's channel number, while
        // the table lookup and retention use our own local channel number.
        let remote_recipient = self
            .find_channel(recipient)
            .map(|channel| channel.remote_id)
            .unwrap_or(recipient);
        self.channels
            .retain(|channel| channel.local_id != recipient);
        self.send_channel_reply(io, remote_recipient, msg::CHANNEL_CLOSE)
    }

    fn find_channel(&self, local_id: u32) -> Option<Channel> {
        self.channels
            .iter()
            .find(|channel| channel.local_id == local_id)
            .copied()
    }

    // --- Outbound helpers ---

    fn send_service_accept(
        &mut self,
        io: &mut dyn TransportIo,
        service: &str,
    ) -> Result<(), TransportError> {
        let mut w = WireWriter::new();
        w.put_u8(msg::SERVICE_ACCEPT);
        w.put_string_str(service);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(())
    }

    fn send_userauth_failure(&mut self, io: &mut dyn TransportIo) -> Result<(), TransportError> {
        let mut w = WireWriter::new();
        w.put_u8(msg::USERAUTH_FAILURE);
        w.put_string_str("password,publickey");
        w.put_bool(false);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(())
    }

    fn send_channel_reply(
        &mut self,
        io: &mut dyn TransportIo,
        recipient: u32,
        reply: u8,
    ) -> Result<PayloadOutcome, TransportError> {
        let mut w = WireWriter::new();
        w.put_u8(reply);
        w.put_u32(recipient);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(PayloadOutcome::Continue)
    }

    fn send_exit_status(
        &mut self,
        io: &mut dyn TransportIo,
        recipient: u32,
        exit_code: u32,
    ) -> Result<PayloadOutcome, TransportError> {
        let mut w = WireWriter::new();
        w.put_u8(msg::CHANNEL_REQUEST);
        w.put_u32(recipient);
        w.put_string_str("exit-status");
        w.put_bool(false);
        w.put_u32(exit_code);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(PayloadOutcome::Continue)
    }

    fn send_channel_data(
        &mut self,
        io: &mut dyn TransportIo,
        recipient: u32,
        data: &[u8],
    ) -> Result<PayloadOutcome, TransportError> {
        let mut w = WireWriter::new();
        w.put_u8(msg::CHANNEL_DATA);
        w.put_u32(recipient);
        w.put_string(data);
        self.transport.write_packet(io, &w.into_vec())?;
        Ok(PayloadOutcome::Continue)
    }

    fn send_channel_eof_and_close(
        &mut self,
        io: &mut dyn TransportIo,
        local_id: u32,
        remote_recipient: u32,
    ) -> Result<PayloadOutcome, TransportError> {
        self.send_channel_reply(io, remote_recipient, msg::CHANNEL_EOF)?;
        self.send_channel_reply(io, remote_recipient, msg::CHANNEL_CLOSE)?;
        self.channels.retain(|channel| channel.local_id != local_id);
        Ok(PayloadOutcome::Continue)
    }

    fn send_disconnect(&mut self, io: &mut dyn TransportIo, reason: u32, description: &str) {
        let mut w = WireWriter::new();
        w.put_u8(msg::DISCONNECT);
        w.put_u32(reason);
        w.put_string_str(description);
        w.put_string_str("");
        let _ = self.transport.write_packet(io, &w.into_vec());
    }
}

fn shell_child_record() -> child::ChildRecord {
    child::ChildRecord {
        pid: 0,
        exit_code: 0,
        finished: false,
        handles: child::ChildHandles::empty(),
        kind: ChildRequestKind::Shell,
    }
}

fn exec_child_record(kind: ChildRequestKind) -> child::ChildRecord {
    child::ChildRecord {
        pid: 0,
        exit_code: 0,
        finished: false,
        handles: child::ChildHandles::empty(),
        kind,
    }
}

// ====================================================================
// Server-side session table
// ====================================================================

static SESSIONS: Spinlock<Vec<ActiveSession>> = Spinlock::new(Vec::new());

/// Register a freshly accepted TCP connection as an SSH session.
pub fn accept_connection(socket_id: u32) {
    SESSIONS.lock().push(ActiveSession::new(socket_id));
}

/// Step every active session once. Returns the number of live sessions.
pub fn poll_sessions() -> usize {
    let socket_ids: Vec<u32> = SESSIONS
        .lock()
        .iter()
        .map(|session| session.socket_id)
        .collect();
    let mut live = 0;
    for socket_id in socket_ids {
        let mut io = SocketIo { socket_id };
        let mut sessions = SESSIONS.lock();
        let Some(session) = sessions
            .iter_mut()
            .find(|session| session.socket_id == socket_id)
        else {
            continue;
        };
        if session.step(&mut io).is_err() {
            session.state = SessionState::Closed;
        }
        if session.state == SessionState::Closed {
            sessions.retain(|session| session.socket_id != socket_id);
        } else {
            live += 1;
        }
    }
    live
}

/// Number of active sessions.
pub fn session_count() -> usize {
    SESSIONS.lock().len()
}
