//! Minimal sshd_config parser.
//!
//! OpenSSH's full sshd_config grammar is fairly rich. For the
//! bring-up stage we need only the directives actually consumed
//! by the launcher and connection acceptance:
//!
//!   Port, ListenAddress, HostKey, PidFile, PermitRootLogin,
//!   PubkeyAuthentication, PasswordAuthentication,
//!   ChallengeResponseAuthentication, AuthorizedKeysFile,
//!   Subsystem, UseDNS, LoginGraceTime, MaxAuthTries, ClientAliveInterval
//!
//! The parser is line-based. Lines starting with `#` are comments.
//! Empty lines are ignored. Each non-comment line is split at the
//! first run of whitespace into `Key` and the rest (arguments).
//! Values that are bare integers or booleans are normalised.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct SshdConfig {
    pub port: u16,
    pub listen_address: String,
    pub host_key: String,
    pub pid_file: Option<String>,
    pub permit_root_login: PermitRoot,
    pub pubkey_authentication: bool,
    pub password_authentication: bool,
    pub challenge_response_authentication: bool,
    pub authorized_keys_file: String,
    pub subsystem: Vec<(String, String)>,
    pub use_dns: bool,
    pub login_grace_time: u32,
    pub max_auth_tries: u32,
    pub client_alive_interval: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermitRoot {
    Yes,
    No,
    WithoutPassword,
    ProhibitPassword,
    ForcedCommandsOnly,
}

impl Default for SshdConfig {
    fn default() -> Self {
        Self {
            port: 22,
            listen_address: String::from("0.0.0.0"),
            host_key: String::from("C:\\Program Files\\OpenSSH\\ssh_host_ed25519_key"),
            pid_file: None,
            permit_root_login: PermitRoot::ProhibitPassword,
            pubkey_authentication: true,
            password_authentication: false,
            challenge_response_authentication: false,
            authorized_keys_file: String::from(".ssh\\authorized_keys"),
            subsystem: Vec::new(),
            use_dns: false,
            login_grace_time: 120,
            max_auth_tries: 6,
            client_alive_interval: 0,
        }
    }
}

impl SshdConfig {
    pub fn parse(text: &str) -> Self {
        let mut cfg = SshdConfig::default();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (key, value) = match split_key_value(trimmed) {
                Some(kv) => kv,
                None => continue,
            };
            let key_lower = key.to_ascii_lowercase();
            match key_lower.as_str() {
                "port" => {
                    if let Some(p) = parse_port(&value) {
                        cfg.port = p;
                    }
                }
                "listenaddress" => {
                    if let Some(first) = value.split_whitespace().next() {
                        cfg.listen_address = first.to_string();
                    }
                }
                "hostkey" => {
                    if let Some(first) = value.split_whitespace().next() {
                        cfg.host_key = first.to_string();
                    }
                }
                "pidfile" => {
                    if let Some(first) = value.split_whitespace().next() {
                        cfg.pid_file = Some(first.to_string());
                    }
                }
                "permitrootlogin" => {
                    cfg.permit_root_login = match value.trim().to_ascii_lowercase().as_str() {
                        "yes" => PermitRoot::Yes,
                        "no" => PermitRoot::No,
                        "without-password" => PermitRoot::WithoutPassword,
                        "prohibit-password" => PermitRoot::ProhibitPassword,
                        "forced-commands-only" => PermitRoot::ForcedCommandsOnly,
                        _ => cfg.permit_root_login,
                    };
                }
                "pubkeyauthentication" => {
                    cfg.pubkey_authentication = parse_bool(&value);
                }
                "passwordauthentication" => {
                    cfg.password_authentication = parse_bool(&value);
                }
                "challengeresponseauthentication" => {
                    cfg.challenge_response_authentication = parse_bool(&value);
                }
                "kbdinteractiveauthentication" => {
                    // Aliased to ChallengeResponseAuthentication in OpenSSH.
                    cfg.challenge_response_authentication = parse_bool(&value);
                }
                "authorizedkeysfile" => {
                    if let Some(first) = value.split_whitespace().next() {
                        cfg.authorized_keys_file = first.to_string();
                    }
                }
                "subsystem" => {
                    let mut it = value.split_whitespace();
                    let name = it.next().unwrap_or("").to_string();
                    let cmd = it.next().unwrap_or("").to_string();
                    if !name.is_empty() && !cmd.is_empty() {
                        cfg.subsystem.push((name, cmd));
                    }
                }
                "usedns" => {
                    cfg.use_dns = parse_bool(&value);
                }
                "logingraceTime" => {
                    if let Some(n) = parse_seconds(&value) {
                        cfg.login_grace_time = n;
                    }
                }
                "maxauthtries" => {
                    if let Some(n) = parse_u32(&value) {
                        cfg.max_auth_tries = n;
                    }
                }
                "clientaliveinterval" => {
                    if let Some(n) = parse_u32(&value) {
                        cfg.client_alive_interval = n;
                    }
                }
                _ => { /* unknown directive - tolerated */ }
            }
        }
        cfg
    }
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut split = line.splitn(2, |c: char| c == ' ' || c == '\t');
    let key = split.next()?.trim();
    let value = split.next()?.trim();
    if key.is_empty() || value.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

fn parse_port(s: &str) -> Option<u16> {
    let first = s.split_whitespace().next()?;
    first.parse::<u16>().ok()
}

fn parse_u32(s: &str) -> Option<u32> {
    let first = s.split_whitespace().next()?;
    first.parse::<u32>().ok()
}

fn parse_seconds(s: &str) -> Option<u32> {
    let first = s.split_whitespace().next()?;
    if let Some(stripped) = first.strip_suffix('s') {
        stripped.parse::<u32>().ok()
    } else {
        first.parse::<u32>().ok()
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "on" | "1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_like_config() {
        let cfg = SshdConfig::parse(include_str!("./testdata/sshd_config_basic.txt"));
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.listen_address, "0.0.0.0");
        assert!(cfg.pubkey_authentication);
        assert!(!cfg.password_authentication);
        assert_eq!(cfg.permit_root_login, PermitRoot::ProhibitPassword);
        assert!(!cfg.subsystem.is_empty(), "subsystem sftp must be parsed");
        let sftp = cfg.subsystem.iter().find(|(n, _)| n == "sftp").unwrap();
        assert_eq!(sftp.1, "sftp-server.exe");
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let cfg = SshdConfig::parse("# only a comment\n\n# another\n");
        assert_eq!(cfg.port, 22);
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        let cfg = SshdConfig::parse("CustomThing foo\nPort 2223\n");
        assert_eq!(cfg.port, 2223);
    }

    #[test]
    fn bool_parsing_normalises_yes_no() {
        assert!(parse_bool("yes"));
        assert!(parse_bool("YES"));
        assert!(!parse_bool("no"));
        assert!(!parse_bool("0"));
    }

    #[test]
    fn default_config_is_safe() {
        let cfg = SshdConfig::default();
        assert!(!cfg.password_authentication);
        assert!(cfg.pubkey_authentication);
        assert_eq!(cfg.port, 22);
    }
}