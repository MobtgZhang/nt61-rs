//! IPsec Integration Points
//!
//! Provides integration points for IPsec (Internet Protocol Security).
//! Supports:
//! - Security Associations (SA)
//! - Security Policy Database (SPD)
//! - ESP (Encapsulating Security Payload)
//! - AH (Authentication Header)
//! - IKE (Internet Key Exchange) hooks
//!
//! Clean-room implementation based on RFC 4301, RFC 4303, RFC 4302.

use crate::ke::sync::Spinlock;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecProtocol {
    AH = 51,
    ESP = 50,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsecMode {
    Transport,
    Tunnel,
}

#[derive(Debug, Clone)]
pub struct SecurityAssociation {
    pub spi: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: IpsecProtocol,
    pub mode: IpsecMode,
    pub enc_alg: u8,
    pub auth_alg: u8,
    pub enc_key: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub seq_num: u64,
    pub replay_window: u64,
    pub lifetime_sec: u64,
    pub created_at: u64,
}

impl SecurityAssociation {
    pub fn new(
        spi: u32,
        src_ip: u32,
        dst_ip: u32,
        protocol: IpsecProtocol,
        mode: IpsecMode,
    ) -> Self {
        Self {
            spi,
            src_ip,
            dst_ip,
            protocol,
            mode,
            enc_alg: 0,
            auth_alg: 0,
            enc_key: Vec::new(),
            auth_key: Vec::new(),
            seq_num: 0,
            replay_window: 0,
            lifetime_sec: 3600,
            created_at: crate::hal::common::pit::get_system_time_ms() as u64,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = crate::hal::common::pit::get_system_time_ms() as u64;
        let age_sec = (now - self.created_at) / 1000;
        age_sec > self.lifetime_sec
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityPolicy {
    pub id: u32,
    pub src_ip: u32,
    pub src_mask: u32,
    pub dst_ip: u32,
    pub dst_mask: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: PolicyAction,
    pub ipsec_protocol: Option<IpsecProtocol>,
    pub ipsec_mode: Option<IpsecMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Bypass,
    Protect,
    Discard,
}

struct IpsecDatabase {
    sa_out: Vec<SecurityAssociation>,
    sa_in: Vec<SecurityAssociation>,
    spd: Vec<SecurityPolicy>,
    next_spi: u32,
    next_policy_id: u32,
}

impl IpsecDatabase {
    fn new() -> Self {
        Self {
            sa_out: Vec::new(),
            sa_in: Vec::new(),
            spd: Vec::new(),
            next_spi: 1000,
            next_policy_id: 1,
        }
    }
}

static IPSEC_DB: Spinlock<IpsecDatabase> = Spinlock::new(IpsecDatabase {
    sa_out: Vec::new(),
    sa_in: Vec::new(),
    spd: Vec::new(),
    next_spi: 1000,
    next_policy_id: 1,
});

#[derive(Debug, Clone, Copy)]
pub struct IpsecStats {
    pub packets_protected: u64,
    pub packets_verified: u64,
    pub auth_failures: u64,
    pub replay_failures: u64,
    pub policy_drops: u64,
}

static IPSEC_STATS: Spinlock<IpsecStats> = Spinlock::new(IpsecStats {
    packets_protected: 0,
    packets_verified: 0,
    auth_failures: 0,
    replay_failures: 0,
    policy_drops: 0,
});

pub fn init() {
    *IPSEC_DB.lock() = IpsecDatabase::new();
    *IPSEC_STATS.lock() = IpsecStats {
        packets_protected: 0,
        packets_verified: 0,
        auth_failures: 0,
        replay_failures: 0,
        policy_drops: 0,
    };
}

pub fn add_sa_out(sa: SecurityAssociation) -> u32 {
    let mut db = IPSEC_DB.lock();
    let spi = sa.spi;
    db.sa_out.push(sa);
    spi
}

pub fn add_sa_in(sa: SecurityAssociation) -> u32 {
    let mut db = IPSEC_DB.lock();
    let spi = sa.spi;
    db.sa_in.push(sa);
    spi
}

pub fn remove_sa(spi: u32, inbound: bool) -> bool {
    let mut db = IPSEC_DB.lock();
    let sa_list = if inbound {
        &mut db.sa_in
    } else {
        &mut db.sa_out
    };
    let before = sa_list.len();
    sa_list.retain(|sa| sa.spi != spi);
    sa_list.len() != before
}

pub fn find_sa_out(dst_ip: u32, protocol: IpsecProtocol) -> Option<u32> {
    let db = IPSEC_DB.lock();
    db.sa_out
        .iter()
        .find(|sa| sa.dst_ip == dst_ip && sa.protocol == protocol && !sa.is_expired())
        .map(|sa| sa.spi)
}

pub fn find_sa_in(spi: u32) -> Option<SecurityAssociation> {
    let db = IPSEC_DB.lock();
    db.sa_in
        .iter()
        .find(|sa| sa.spi == spi && !sa.is_expired())
        .cloned()
}

pub fn add_policy(mut policy: SecurityPolicy) -> u32 {
    let mut db = IPSEC_DB.lock();
    policy.id = db.next_policy_id;
    db.next_policy_id += 1;
    db.spd.push(policy);
    policy.id
}

pub fn remove_policy(id: u32) -> bool {
    let mut db = IPSEC_DB.lock();
    let before = db.spd.len();
    db.spd.retain(|p| p.id != id);
    db.spd.len() != before
}

pub fn check_outbound_policy(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> PolicyAction {
    let db = IPSEC_DB.lock();

    for policy in &db.spd {
        let src_match = (src_ip & policy.src_mask) == (policy.src_ip & policy.src_mask);
        let dst_match = (dst_ip & policy.dst_mask) == (policy.dst_ip & policy.dst_mask);
        let src_port_match = policy.src_port == 0 || policy.src_port == src_port;
        let dst_port_match = policy.dst_port == 0 || policy.dst_port == dst_port;
        let proto_match = policy.protocol == 0 || policy.protocol == protocol;

        if src_match && dst_match && src_port_match && dst_port_match && proto_match {
            return policy.action;
        }
    }

    PolicyAction::Bypass
}

pub fn check_inbound_policy(
    src_ip: u32,
    dst_ip: u32,
    has_ipsec: bool,
) -> bool {
    let db = IPSEC_DB.lock();

    for policy in &db.spd {
        let src_match = (src_ip & policy.src_mask) == (policy.src_ip & policy.src_mask);
        let dst_match = (dst_ip & policy.dst_mask) == (policy.dst_ip & policy.dst_mask);

        if src_match && dst_match {
            match policy.action {
                PolicyAction::Bypass => return true,
                PolicyAction::Protect => return has_ipsec,
                PolicyAction::Discard => return false,
            }
        }
    }

    true
}

pub fn protect_packet(
    _payload: &[u8],
    _spi: u32,
) -> Option<Vec<u8>> {
    let mut stats = IPSEC_STATS.lock();
    stats.packets_protected += 1;

    None
}

pub fn verify_packet(
    _packet: &[u8],
    _spi: u32,
) -> Option<Vec<u8>> {
    let mut stats = IPSEC_STATS.lock();
    stats.packets_verified += 1;

    None
}

pub fn cleanup_expired_sa() {
    let mut db = IPSEC_DB.lock();
    db.sa_out.retain(|sa| !sa.is_expired());
    db.sa_in.retain(|sa| !sa.is_expired());
}

pub fn get_stats() -> IpsecStats {
    *IPSEC_STATS.lock()
}

pub fn active_sa_count() -> (usize, usize) {
    let db = IPSEC_DB.lock();
    (db.sa_out.len(), db.sa_in.len())
}

pub fn policy_count() -> usize {
    IPSEC_DB.lock().spd.len()
}
