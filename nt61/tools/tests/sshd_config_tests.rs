//! Port of the sshd_config parser to the host so we can test it
//! without spinning up the bare-metal kernel.

use std::string::{String, ToString};
use std::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermitRoot {
    Yes,
    No,
    WithoutPassword,
    ProhibitPassword,
    ForcedCommandsOnly,
}

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

impl Default for SshdConfig {
    fn default() -> Self {
        Self {
            port: 22,
            listen_address: "0.0.0.0".to_string(),
            host_key: String::new(),
            pid_file: None,
            permit_root_login: PermitRoot::ProhibitPassword,
            pubkey_authentication: true,
            password_authentication: false,
            challenge_response_authentication: false,
            authorized_keys_file: ".ssh\\authorized_keys".to_string(),
            subsystem: Vec::new(),
            use_dns: false,
            login_grace_time: 120,
            max_auth_tries: 6,
            client_alive_interval: 0,
        }
    }
}

fn split(line: &str) -> Option<(&str, &str)> {
    let mut it = line.splitn(2, |c: char| c == ' ' || c == '\t');
    let k = it.next()?.trim();
    let v = it.next()?.trim();
    if k.is_empty() || v.is_empty() {
        None
    } else {
        Some((k, v))
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "on" | "1"
    )
}

fn first_word(s: &str) -> Option<&str> {
    s.split_whitespace().next()
}

/// Path-style directive values (HostKey, PidFile, AuthorizedKeysFile,
/// ListenAddress, subsystem command) may contain spaces, so they
/// should consume the rest of the line verbatim rather than only
/// the first whitespace-delimited token. We strip one optional
/// pair of surrounding double quotes — that is what OpenSSH does.
fn path_value(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn parse_u32(s: &str) -> Option<u32> {
    first_word(s).and_then(|x| x.parse::<u32>().ok())
}

pub fn parse(text: &str) -> SshdConfig {
    let mut cfg = SshdConfig::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = split(trimmed) else { continue };
        match k.to_ascii_lowercase().as_str() {
            "port" => {
                if let Some(p) = first_word(v).and_then(|x| x.parse::<u16>().ok()) {
                    cfg.port = p;
                }
            }
            "listenaddress" => {
                if let Some(p) = first_word(v) { cfg.listen_address = p.to_string(); }
            }
            "hostkey" => {
                cfg.host_key = path_value(v).to_string();
            }
            "pidfile" => {
                cfg.pid_file = Some(path_value(v).to_string());
            }
            "permitrootlogin" => {
                cfg.permit_root_login = match v.trim().to_ascii_lowercase().as_str() {
                    "yes" => PermitRoot::Yes,
                    "no" => PermitRoot::No,
                    "without-password" => PermitRoot::WithoutPassword,
                    "prohibit-password" => PermitRoot::ProhibitPassword,
                    "forced-commands-only" => PermitRoot::ForcedCommandsOnly,
                    _ => cfg.permit_root_login,
                };
            }
            "pubkeyauthentication" => cfg.pubkey_authentication = parse_bool(v),
            "passwordauthentication" => cfg.password_authentication = parse_bool(v),
            "challengeresponseauthentication" | "kbdinteractiveauthentication" => {
                cfg.challenge_response_authentication = parse_bool(v);
            }
            "authorizedkeysfile" => {
                if let Some(p) = first_word(v) { cfg.authorized_keys_file = p.to_string(); }
            }
            "subsystem" => {
                let mut it = v.splitn(2, char::is_whitespace);
                let n = it.next().unwrap_or("").to_string();
                let c = it.next().unwrap_or("").trim().to_string();
                if !n.is_empty() && !c.is_empty() {
                    cfg.subsystem.push((n, c));
                }
            }
            "usedns" => cfg.use_dns = parse_bool(v),
            "logingracetime" => {
                if let Some(p) = first_word(v).and_then(|x| {
                    x.strip_suffix('s').and_then(|y| y.parse::<u32>().ok())
                        .or_else(|| x.parse::<u32>().ok())
                }) {
                    cfg.login_grace_time = p;
                }
            }
            "maxauthtries" => {
                if let Some(p) = parse_u32(v) { cfg.max_auth_tries = p; }
            }
            "clientaliveinterval" => {
                if let Some(p) = parse_u32(v) { cfg.client_alive_interval = p; }
            }
            _ => {}
        }
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str = r#"
# sshd_config — bring-up test
Port 2222
ListenAddress 0.0.0.0
HostKey C:\Program Files\OpenSSH\ssh_host_ed25519_key
PidFile C:\Program Files\OpenSSH\sshd.pid
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh\authorized_keys
Subsystem sftp sftp-server.exe
UseDNS no
LoginGraceTime 60
MaxAuthTries 4
ClientAliveInterval 30
"#;

    #[test]
    fn parse_basic_full() {
        let cfg = parse(BASIC);
        assert_eq!(cfg.port, 2222);
        assert_eq!(cfg.listen_address, "0.0.0.0");
        assert_eq!(cfg.host_key, "C:\\Program Files\\OpenSSH\\ssh_host_ed25519_key");
        assert_eq!(cfg.pid_file.as_deref(),
            Some("C:\\Program Files\\OpenSSH\\sshd.pid"));
        assert_eq!(cfg.permit_root_login, PermitRoot::ProhibitPassword);
        assert!(cfg.pubkey_authentication);
        assert!(!cfg.password_authentication);
        assert!(!cfg.challenge_response_authentication);
        assert_eq!(cfg.authorized_keys_file, ".ssh\\authorized_keys");
        assert!(!cfg.use_dns);
        assert_eq!(cfg.login_grace_time, 60);
        assert_eq!(cfg.max_auth_tries, 4);
        assert_eq!(cfg.client_alive_interval, 30);

        let sftp = cfg.subsystem.iter().find(|(n, _)| n == "sftp").unwrap();
        assert_eq!(sftp.1, "sftp-server.exe");
    }

    #[test]
    fn blank_and_comment_lines_are_ignored() {
        let cfg = parse("\n\n# nothing here\n\n");
        assert_eq!(cfg.port, 22);
        assert!(cfg.pubkey_authentication);
    }

    #[test]
    fn unknown_keys_dont_panic() {
        let cfg = parse("NoSuchKey blah\nPort 1234\n");
        assert_eq!(cfg.port, 1234);
    }

    #[test]
    fn kbdinteractive_is_aliased() {
        let cfg = parse("KbdInteractiveAuthentication yes\n");
        assert!(cfg.challenge_response_authentication);
    }

    #[test]
    fn subsystem_requires_two_args() {
        let cfg = parse("Subsystem sftp\nSubsystem sftp sftp-server.exe\n");
        assert_eq!(cfg.subsystem.len(), 1);
        assert_eq!(cfg.subsystem[0].0, "sftp");
        assert_eq!(cfg.subsystem[0].1, "sftp-server.exe");
    }

    #[test]
    fn seconds_suffix_is_stripped() {
        let cfg = parse("LoginGraceTime 90s\n");
        assert_eq!(cfg.login_grace_time, 90);
    }

    #[test]
    fn yes_no_no_off() {
        let cfg = parse("PubkeyAuthentication yes\nPasswordAuthentication no\nUseDNS off\n");
        assert!(cfg.pubkey_authentication);
        assert!(!cfg.password_authentication);
        assert!(!cfg.use_dns, "off must be parsed as false");
    }
}