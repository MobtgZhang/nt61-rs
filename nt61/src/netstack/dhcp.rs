//! DHCP Client Implementation
//
//! Implements a DHCP client for dynamic IP address configuration
//! as specified in RFC 2131 and RFC 2132.
//
//! The client follows the state machine:
//! INIT -> SELECTING -> REQUESTING -> BOUND -> RENEWING -> REBINDING
//
//! Clean-room implementation based on RFC 2131/2132.

use alloc::vec::Vec;
use alloc::format;
use alloc::string::String;

/// DHCP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl DhcpMessageType {
    fn to_u8(&self) -> u8 {
        match self {
            DhcpMessageType::Discover => 1,
            DhcpMessageType::Offer => 2,
            DhcpMessageType::Request => 3,
            DhcpMessageType::Decline => 4,
            DhcpMessageType::Ack => 5,
            DhcpMessageType::Nak => 6,
            DhcpMessageType::Release => 7,
            DhcpMessageType::Inform => 8,
        }
    }

    fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(DhcpMessageType::Discover),
            2 => Some(DhcpMessageType::Offer),
            3 => Some(DhcpMessageType::Request),
            4 => Some(DhcpMessageType::Decline),
            5 => Some(DhcpMessageType::Ack),
            6 => Some(DhcpMessageType::Nak),
            7 => Some(DhcpMessageType::Release),
            8 => Some(DhcpMessageType::Inform),
            _ => None,
        }
    }
}

/// DHCP operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOperation {
    BootRequest,
    BootReply,
}

/// DHCP option codes (RFC 2132)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOptionCode {
    Pad = 0,
    SubnetMask = 1,
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    NameServer = 5,
    DomainNameServer = 6,
    LogServer = 7,
    CookieServer = 8,
    LprServer = 9,
    ImpressServer = 10,
    ResourceLocationServer = 11,
    HostName = 12,
    BootFileSize = 13,
    MeritDumpFile = 14,
    DomainName = 15,
    SwapServer = 16,
    RootPath = 17,
    ExtensionsPath = 18,
    IpForwarding = 19,
    NonLocalSourceRouting = 20,
    PolicyFilter = 21,
    MaxDatagramReassemblySize = 22,
    DefaultIpTtl = 23,
    PathMtuAgingTimeout = 24,
    PathMtuPlateauTable = 25,
    InterfaceMtu = 26,
    AllSubnetsLocal = 27,
    BroadcastAddress = 28,
    PerformMaskDiscovery = 29,
    MaskSupplier = 30,
    RouterDiscovery = 31,
    RouterSolicitationAddress = 32,
    StaticRoutes = 33,
    TrailerEncapsulation = 34,
    ArpCacheTimeout = 35,
    EthernetEncapsulation = 36,
    TcpDefaultTtl = 37,
    TcpKeepaliveInterval = 38,
    TcpKeepaliveGarbage = 39,
    NetworkInformationServiceDomain = 40,
    NetworkInformationServers = 41,
    NtpServers = 42,
    VendorSpecificInformation = 43,
    NetbiosOverTcpipNameServer = 44,
    NetbiosOverTcpipDatagramDistribution = 45,
    NetbiosOverTcpipNodeType = 46,
    NetbiosOverTcpipScope = 47,
    XWindowSystemFontServer = 48,
    XWindowSystemDisplayManager = 49,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    OptionOverload = 52,
    DhcpMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaxDhcpMessageSize = 57,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassIdentifier = 60,
    ClientIdentifier = 61,
    NetworkInformationServicePlusDomain = 64,
    NetworkInformationServicePlusServers = 65,
    TftpServerName = 66,
    BootfileName = 67,
    MobileIpHomeAgent = 68,
    SmtpServer = 69,
    Pop3Server = 70,
    NntpServer = 71,
    DefaultWwwServer = 72,
    DefaultFingerServer = 73,
    DefaultIrcServer = 74,
    StreetTalkServer = 75,
    StdaServer = 76,
    End = 255,
}

impl DhcpOptionCode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(DhcpOptionCode::Pad),
            1 => Some(DhcpOptionCode::SubnetMask),
            2 => Some(DhcpOptionCode::TimeOffset),
            3 => Some(DhcpOptionCode::Router),
            4 => Some(DhcpOptionCode::TimeServer),
            5 => Some(DhcpOptionCode::NameServer),
            6 => Some(DhcpOptionCode::DomainNameServer),
            7 => Some(DhcpOptionCode::LogServer),
            8 => Some(DhcpOptionCode::CookieServer),
            9 => Some(DhcpOptionCode::LprServer),
            10 => Some(DhcpOptionCode::ImpressServer),
            11 => Some(DhcpOptionCode::ResourceLocationServer),
            12 => Some(DhcpOptionCode::HostName),
            13 => Some(DhcpOptionCode::BootFileSize),
            14 => Some(DhcpOptionCode::MeritDumpFile),
            15 => Some(DhcpOptionCode::DomainName),
            16 => Some(DhcpOptionCode::SwapServer),
            17 => Some(DhcpOptionCode::RootPath),
            18 => Some(DhcpOptionCode::ExtensionsPath),
            19 => Some(DhcpOptionCode::IpForwarding),
            20 => Some(DhcpOptionCode::NonLocalSourceRouting),
            21 => Some(DhcpOptionCode::PolicyFilter),
            22 => Some(DhcpOptionCode::MaxDatagramReassemblySize),
            23 => Some(DhcpOptionCode::DefaultIpTtl),
            24 => Some(DhcpOptionCode::PathMtuAgingTimeout),
            25 => Some(DhcpOptionCode::PathMtuPlateauTable),
            26 => Some(DhcpOptionCode::InterfaceMtu),
            27 => Some(DhcpOptionCode::AllSubnetsLocal),
            28 => Some(DhcpOptionCode::BroadcastAddress),
            29 => Some(DhcpOptionCode::PerformMaskDiscovery),
            30 => Some(DhcpOptionCode::MaskSupplier),
            31 => Some(DhcpOptionCode::RouterDiscovery),
            32 => Some(DhcpOptionCode::RouterSolicitationAddress),
            33 => Some(DhcpOptionCode::StaticRoutes),
            34 => Some(DhcpOptionCode::TrailerEncapsulation),
            35 => Some(DhcpOptionCode::ArpCacheTimeout),
            36 => Some(DhcpOptionCode::EthernetEncapsulation),
            37 => Some(DhcpOptionCode::TcpDefaultTtl),
            38 => Some(DhcpOptionCode::TcpKeepaliveInterval),
            39 => Some(DhcpOptionCode::TcpKeepaliveGarbage),
            40 => Some(DhcpOptionCode::NetworkInformationServiceDomain),
            41 => Some(DhcpOptionCode::NetworkInformationServers),
            42 => Some(DhcpOptionCode::NtpServers),
            43 => Some(DhcpOptionCode::VendorSpecificInformation),
            44 => Some(DhcpOptionCode::NetbiosOverTcpipNameServer),
            45 => Some(DhcpOptionCode::NetbiosOverTcpipDatagramDistribution),
            46 => Some(DhcpOptionCode::NetbiosOverTcpipNodeType),
            47 => Some(DhcpOptionCode::NetbiosOverTcpipScope),
            48 => Some(DhcpOptionCode::XWindowSystemFontServer),
            49 => Some(DhcpOptionCode::XWindowSystemDisplayManager),
            50 => Some(DhcpOptionCode::RequestedIpAddress),
            51 => Some(DhcpOptionCode::IpAddressLeaseTime),
            52 => Some(DhcpOptionCode::OptionOverload),
            53 => Some(DhcpOptionCode::DhcpMessageType),
            54 => Some(DhcpOptionCode::ServerIdentifier),
            55 => Some(DhcpOptionCode::ParameterRequestList),
            56 => Some(DhcpOptionCode::Message),
            57 => Some(DhcpOptionCode::MaxDhcpMessageSize),
            58 => Some(DhcpOptionCode::RenewalTimeValue),
            59 => Some(DhcpOptionCode::RebindingTimeValue),
            60 => Some(DhcpOptionCode::VendorClassIdentifier),
            61 => Some(DhcpOptionCode::ClientIdentifier),
            64 => Some(DhcpOptionCode::NetworkInformationServicePlusDomain),
            65 => Some(DhcpOptionCode::NetworkInformationServicePlusServers),
            66 => Some(DhcpOptionCode::TftpServerName),
            67 => Some(DhcpOptionCode::BootfileName),
            68 => Some(DhcpOptionCode::MobileIpHomeAgent),
            69 => Some(DhcpOptionCode::SmtpServer),
            70 => Some(DhcpOptionCode::Pop3Server),
            71 => Some(DhcpOptionCode::NntpServer),
            72 => Some(DhcpOptionCode::DefaultWwwServer),
            73 => Some(DhcpOptionCode::DefaultFingerServer),
            74 => Some(DhcpOptionCode::DefaultIrcServer),
            75 => Some(DhcpOptionCode::StreetTalkServer),
            76 => Some(DhcpOptionCode::StdaServer),
            255 => Some(DhcpOptionCode::End),
            _ => None,
        }
    }
}

/// DHCP state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    RenewingFailed,
}

impl DhcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpState::Init => "INIT",
            DhcpState::Selecting => "SELECTING",
            DhcpState::Requesting => "REQUESTING",
            DhcpState::Bound => "BOUND",
            DhcpState::Renewing => "RENEWING",
            DhcpState::Rebinding => "REBINDING",
            DhcpState::RenewingFailed => "RENEWING_FAILED",
        }
    }
}

/// DHCP lease information
#[derive(Debug, Clone, Default)]
pub struct DhcpLease {
    pub ip_address: u32,
    pub subnet_mask: u32,
    pub gateway: u32,
    pub dns_servers: [u32; 3],
    pub lease_time: u32,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub server_id: u32,
    pub lease_start: u64,
}

impl DhcpLease {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_ip(&mut self, ip: u32) {
        self.ip_address = ip;
    }

    pub fn set_subnet_mask(&mut self, mask: u32) {
        self.subnet_mask = mask;
    }

    pub fn set_gateway(&mut self, gw: u32) {
        self.gateway = gw;
    }

    pub fn set_dns(&mut self, servers: [u32; 3]) {
        self.dns_servers = servers;
    }

    pub fn set_lease_times(&mut self, lease: u32, renewal: u32, rebinding: u32) {
        self.lease_time = lease;
        self.renewal_time = renewal;
        self.rebinding_time = rebinding;
    }

    pub fn set_server_id(&mut self, id: u32) {
        self.server_id = id;
    }

    pub fn set_lease_start(&mut self, start: u64) {
        self.lease_start = start;
    }

    pub fn remaining_time(&self) -> u64 {
        use crate::hal::common::pit;
        let now = pit::get_system_time_ms() as u64;
        let elapsed = now.saturating_sub(self.lease_start);
        let lease_ms = (self.lease_time as u64).saturating_mul(1000);
        lease_ms.saturating_sub(elapsed)
    }

    pub fn time_until_renewal(&self) -> i64 {
        use crate::hal::common::pit;
        let now = pit::get_system_time_ms() as u64;
        let elapsed = now.saturating_sub(self.lease_start);
        let renewal_ms = (self.renewal_time as u64).saturating_mul(1000);
        renewal_ms as i64 - elapsed as i64
    }
}

/// Extended DHCP options parsing result
#[derive(Debug, Clone, Default)]
pub struct DhcpOptions {
    pub message_type: Option<DhcpMessageType>,
    pub server_id: Option<u32>,
    pub lease_time: Option<u32>,
    pub subnet_mask: Option<u32>,
    pub router: Option<u32>,
    pub dns_servers: Option<[u32; 3]>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub time_offset: Option<i32>,
    pub routers: Vec<u32>,
    pub time_servers: Vec<u32>,
    pub name_servers: Vec<u32>,
    pub domain_name: Option<Vec<u8>>,
    pub host_name: Option<Vec<u8>>,
    pub broadcast_address: Option<u32>,
    pub ntp_servers: Vec<u32>,
    pub vendor_class_id: Option<Vec<u8>>,
    pub client_id: Option<Vec<u8>>,
    pub tftp_server: Option<Vec<u8>>,
    pub bootfile_name: Option<Vec<u8>>,
    pub max_message_size: Option<u16>,
    pub ip_forwarding: Option<u8>,
    pub default_ttl: Option<u8>,
    pub bootfile: Option<Vec<u8>>,
    pub domain_name_servers: Vec<u32>,
}

impl DhcpOptions {
    fn parse(options: &[u8]) -> Self {
        let mut opts = DhcpOptions::default();
        let mut i = 0;
        
        while i < options.len() {
            let code = options[i];
            if code == 0 {
                i += 1;
                continue;
            }
            if code == 255 {
                break;
            }
            if i + 1 >= options.len() {
                break;
            }
            
            let len = options[i + 1] as usize;
            if i + 2 + len > options.len() {
                break;
            }
            
            let data = &options[i + 2..i + 2 + len];
            
            match code {
                1 => {
                    if data.len() >= 4 {
                        opts.subnet_mask = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                3 => {
                    for j in (0..data.len()).step_by(4) {
                        if j + 4 <= data.len() {
                            let router_ip = u32::from_be_bytes([data[j], data[j+1], data[j+2], data[j+3]]);
                            opts.routers.push(router_ip);
                            if opts.router.is_none() {
                                opts.router = Some(router_ip);
                            }
                        }
                    }
                }
                4 => {
                    for j in (0..data.len()).step_by(4) {
                        if j + 4 <= data.len() {
                            opts.time_servers.push(u32::from_be_bytes([data[j], data[j+1], data[j+2], data[j+3]]));
                        }
                    }
                }
                5 => {
                    for j in (0..data.len()).step_by(4) {
                        if j + 4 <= data.len() {
                            opts.name_servers.push(u32::from_be_bytes([data[j], data[j+1], data[j+2], data[j+3]]));
                        }
                    }
                }
                6 => {
                    let mut dns = [0u32; 3];
                    let dns_count = (data.len() / 4).min(3);
                    for j in 0..dns_count {
                        dns[j] = u32::from_be_bytes([data[j * 4], data[j * 4 + 1], data[j * 4 + 2], data[j * 4 + 3]]);
                    }
                    opts.dns_servers = Some(dns);
                    opts.domain_name_servers = opts.name_servers.clone();
                }
                12 => {
                    opts.host_name = Some(data.to_vec());
                }
                14 => {
                    opts.bootfile = Some(data.to_vec());
                }
                15 => {
                    opts.domain_name = Some(data.to_vec());
                }
                28 => {
                    if data.len() >= 4 {
                        opts.broadcast_address = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                42 => {
                    for j in (0..data.len()).step_by(4) {
                        if j + 4 <= data.len() {
                            opts.ntp_servers.push(u32::from_be_bytes([data[j], data[j+1], data[j+2], data[j+3]]));
                        }
                    }
                }
                50 => {
                    // Requested IP Address
                    if data.len() >= 4 {
                        let _requested_ip = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    }
                }
                51 => {
                    if data.len() >= 4 {
                        opts.lease_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                53 => {
                    if !data.is_empty() {
                        opts.message_type = DhcpMessageType::from_u8(data[0]);
                    }
                }
                54 => {
                    if data.len() >= 4 {
                        opts.server_id = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                55 => {
                }
                56 => {
                }
                57 => {
                    if data.len() >= 2 {
                        opts.max_message_size = Some(u16::from_be_bytes([data[0], data[1]]));
                    }
                }
                58 => {
                    if data.len() >= 4 {
                        opts.renewal_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                59 => {
                    if data.len() >= 4 {
                        opts.rebinding_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                    }
                }
                60 => {
                    opts.vendor_class_id = Some(data.to_vec());
                }
                61 => {
                    opts.client_id = Some(data.to_vec());
                }
                66 => {
                    opts.tftp_server = Some(data.to_vec());
                }
                67 => {
                    opts.bootfile_name = Some(data.to_vec());
                }
                _ => {
                }
            }
            
            i += 2 + len;
        }
        
        opts
    }

    pub fn get_routers(&self) -> &[u32] {
        &self.routers
    }

    pub fn get_dns_servers(&self) -> Option<[u32; 3]> {
        self.dns_servers
    }

    pub fn get_host_name(&self) -> Option<&[u8]> {
        self.host_name.as_deref()
    }

    pub fn get_domain_name(&self) -> Option<&[u8]> {
        self.domain_name.as_deref()
    }
}

/// DHCP client
pub struct DhcpClient {
    xid: u32,
    state: DhcpState,
    lease: DhcpLease,
    offered_server: u32,
    offered_ip: u32,
    retransmit_count: u8,
    state_start_time: u64,
    requested_ip: u32,
}

impl DhcpClient {
    pub fn new() -> Self {
        use crate::hal::common::pit;
        
        Self {
            xid: pit::get_system_time_ms() as u32,
            state: DhcpState::Init,
            lease: DhcpLease::default(),
            offered_server: 0,
            offered_ip: 0,
            retransmit_count: 0,
            state_start_time: pit::get_system_time_ms() as u64,
            requested_ip: 0,
        }
    }

    fn new_xid(&mut self) {
        use crate::hal::common::pit;
        self.xid = pit::get_system_time_ms() as u32 ^ 0xDEADBEEF;
    }

    pub fn start_discovery(&mut self, chaddr: &[u8; 6]) -> Vec<u8> {
        self.state = DhcpState::Selecting;
        self.new_xid();
        self.state_start_time = crate::hal::common::pit::get_system_time_ms() as u64;
        self.build_discover(chaddr)
    }

    fn build_discover(&self, chaddr: &[u8; 6]) -> Vec<u8> {
        let mut msg = self.build_base_message(DhcpOperation::BootRequest, chaddr);
        
        msg.push(DhcpOptionCode::DhcpMessageType as u8);
        msg.push(1);
        msg.push(DhcpMessageType::Discover.to_u8());
        
        msg.push(DhcpOptionCode::RequestedIpAddress as u8);
        msg.push(4);
        msg.extend_from_slice(&self.requested_ip.to_be_bytes());
        
        msg.push(DhcpOptionCode::ClientIdentifier as u8);
        msg.push(7);
        msg.push(1);
        msg.extend_from_slice(chaddr);
        
        msg.push(DhcpOptionCode::ParameterRequestList as u8);
        msg.push(3);
        msg.push(DhcpOptionCode::SubnetMask as u8);
        msg.push(DhcpOptionCode::Router as u8);
        msg.push(DhcpOptionCode::DomainNameServer as u8);
        
        msg.push(DhcpOptionCode::End as u8);
        
        msg
    }
    
    fn build_request(&self, chaddr: &[u8; 6], requested_ip: u32, server_id: u32) -> Vec<u8> {
        let mut msg = self.build_base_message(DhcpOperation::BootRequest, chaddr);
        
        msg.push(DhcpOptionCode::DhcpMessageType as u8);
        msg.push(1);
        msg.push(DhcpMessageType::Request.to_u8());
        
        msg.push(DhcpOptionCode::RequestedIpAddress as u8);
        msg.push(4);
        msg.extend_from_slice(&requested_ip.to_be_bytes());
        
        msg.push(DhcpOptionCode::ServerIdentifier as u8);
        msg.push(4);
        msg.extend_from_slice(&server_id.to_be_bytes());
        
        msg.push(DhcpOptionCode::ClientIdentifier as u8);
        msg.push(7);
        msg.push(1);
        msg.extend_from_slice(chaddr);
        
        msg.push(DhcpOptionCode::ParameterRequestList as u8);
        msg.push(3);
        msg.push(DhcpOptionCode::SubnetMask as u8);
        msg.push(DhcpOptionCode::Router as u8);
        msg.push(DhcpOptionCode::DomainNameServer as u8);
        
        msg.push(DhcpOptionCode::End as u8);
        
        msg
    }

    fn build_base_message(&self, op: DhcpOperation, chaddr: &[u8; 6]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(240 + 64);
        
        msg.push(match op {
            DhcpOperation::BootRequest => 1,
            DhcpOperation::BootReply => 2,
        });
        
        msg.push(1);
        msg.push(6);
        msg.push(0);
        msg.extend_from_slice(&self.xid.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0x8000u16.to_be_bytes());
        msg.extend_from_slice(&[0u8; 4]);
        msg.extend_from_slice(&[0u8; 4]);
        msg.extend_from_slice(&[0u8; 4]);
        msg.extend_from_slice(&[0u8; 4]);
        msg.extend_from_slice(chaddr);
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(&[0u8; 64]);
        msg.extend_from_slice(&[0u8; 128]);
        msg.extend_from_slice(&[99, 130, 83, 99]);
        
        msg
    }

    pub fn process_message(&mut self, msg: &[u8], chaddr: &[u8; 6]) -> bool {
        if msg.len() < 240 {
            return false;
        }

        if msg[0] != 2 {
            return false;
        }

        let received_xid = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        if received_xid != self.xid {
            return false;
        }

        // Verify hardware address matches (security check)
        let msg_chaddr = &msg[28..34];
        if msg_chaddr != chaddr {
            return false;
        }

        let options_data = if msg.len() > 240 {
            &msg[240..]
        } else {
            &[]
        };
        
        let options = DhcpOptions::parse(options_data);
        
        let your_ip = u32::from_be_bytes([msg[16], msg[17], msg[18], msg[19]]);
        
        match options.message_type {
            Some(DhcpMessageType::Offer) => {
                if self.state == DhcpState::Selecting {
                    self.offered_ip = your_ip;
                    self.requested_ip = your_ip;
                    self.offered_server = options.server_id.unwrap_or(0);
                    self.state = DhcpState::Requesting;
                    self.new_xid();
                    self.state_start_time = crate::hal::common::pit::get_system_time_ms() as u64;
                    true
                } else {
                    false
                }
            }
            Some(DhcpMessageType::Ack) => {
                if self.state == DhcpState::Requesting {
                    self.lease.set_ip(your_ip);
                    self.lease.set_subnet_mask(options.subnet_mask.unwrap_or(0xFFFFFF00));
                    self.lease.set_gateway(options.router.unwrap_or(0));
                    self.lease.set_server_id(options.server_id.unwrap_or(0));
                    self.lease.set_lease_times(
                        options.lease_time.unwrap_or(7200),
                        options.renewal_time.unwrap_or(options.lease_time.unwrap_or(7200) / 2),
                        options.rebinding_time.unwrap_or((options.lease_time.unwrap_or(7200) * 7) / 8),
                    );
                    
                    if let Some(dns) = options.dns_servers {
                        self.lease.set_dns(dns);
                    }
                    
                    self.lease.set_lease_start(crate::hal::common::pit::get_system_time_ms() as u64);
                    
                    self.state = DhcpState::Bound;
                    true
                } else {
                    false
                }
            }
            Some(DhcpMessageType::Nak) => {
                if self.state == DhcpState::Requesting || self.state == DhcpState::Renewing || self.state == DhcpState::Rebinding {
                    self.state = DhcpState::Init;
                    self.new_xid();
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub fn build_renewal_request(&self, chaddr: &[u8; 6]) -> Vec<u8> {
        self.build_request(chaddr, self.lease.ip_address, self.lease.server_id)
    }

    pub fn get_state(&self) -> DhcpState {
        self.state
    }
    
    pub fn get_state_str(&self) -> &'static str {
        self.state.as_str()
    }

    pub fn get_lease(&self) -> Option<&DhcpLease> {
        if self.state == DhcpState::Bound {
            Some(&self.lease)
        } else {
            None
        }
    }

    pub fn is_bound(&self) -> bool {
        self.state == DhcpState::Bound
    }

    pub fn check_lease(&mut self) {
        use crate::hal::common::pit;
        
        if self.state != DhcpState::Bound {
            return;
        }
        
        let now = pit::get_system_time_ms() as u64;
        let elapsed = now - self.lease.lease_start;
        
        if elapsed > (self.lease.renewal_time as u64 * 1000) {
            self.state = DhcpState::Renewing;
            self.new_xid();
            self.state_start_time = now;
        }
        
        if elapsed > (self.lease.rebinding_time as u64 * 1000) {
            self.state = DhcpState::Rebinding;
        }
        
        if elapsed > (self.lease.lease_time as u64 * 1000) {
            self.state = DhcpState::Init;
        }
    }

    pub fn time_since_state_start(&self) -> u64 {
        use crate::hal::common::pit;
        let now = pit::get_system_time_ms() as u64;
        now.saturating_sub(self.state_start_time)
    }

    pub fn should_retransmit(&self) -> bool {
        const RETRANSMIT_TIMEOUT_MS: u64 = 1000;
        self.time_since_state_start() > RETRANSMIT_TIMEOUT_MS
    }

    pub fn increment_retransmit(&mut self) {
        self.retransmit_count += 1;
        self.state_start_time = crate::hal::common::pit::get_system_time_ms() as u64;
    }

    pub fn get_retransmit_count(&self) -> u8 {
        self.retransmit_count
    }

    pub fn get_offered_ip(&self) -> u32 {
        self.offered_ip
    }

    pub fn get_offered_server(&self) -> u32 {
        self.offered_server
    }
}

pub fn format_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}",
        (ip >> 24) as u8,
        (ip >> 16) as u8,
        (ip >> 8) as u8,
        ip as u8
    )
}

/// DHCP client port (RFC 2131)
pub const DHCP_CLIENT_PORT: u16 = 68;
/// DHCP server port (RFC 2131)
pub const DHCP_SERVER_PORT: u16 = 67;
/// DHCP magic cookie
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;
/// IPv4 limited broadcast address
pub const IP_BROADCAST: u32 = 0xFFFF_FFFF;

use crate::netstack::udp;

/// Singleton UDP socket index for the DHCP client. `None` until
/// `init()` has bound the socket.
static DHCP_SOCKET_IDX: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);

pub fn init() {
    // Bind a UDP socket on the well-known DHCP client port (68).
    // `udp::create_socket` returns the socket index. We treat
    // `usize::MAX` as "not yet bound".
    if DHCP_SOCKET_IDX.load(core::sync::atomic::Ordering::Acquire)
        != usize::MAX
    {
        return;
    }
    if let Some(idx) = udp::create_socket(DHCP_CLIENT_PORT, 0) {
        DHCP_SOCKET_IDX.store(idx, core::sync::atomic::Ordering::Release);
    }
}

/// Send a serialised DHCP message via the bound DHCP client socket.
/// On failure returns `false`; the caller may retry per RFC 2131
/// retransmit rules.
pub fn send_dhcp_message(payload: &[u8]) -> bool {
    let idx = DHCP_SOCKET_IDX.load(core::sync::atomic::Ordering::Acquire);
    if idx == usize::MAX {
        return false;
    }
    udp::send(idx, IP_BROADCAST, DHCP_SERVER_PORT, payload).is_some()
}

/// Receive a DHCP message from the bound socket (non-blocking).
/// Returns `Some(n)` with the number of bytes copied into `buf` if a
/// datagram is available; `None` if the socket is unbound or empty.
pub fn recv_dhcp_message(buf: &mut [u8]) -> Option<usize> {
    let idx = DHCP_SOCKET_IDX.load(core::sync::atomic::Ordering::Acquire);
    if idx == usize::MAX {
        return None;
    }
    udp::receive(idx, buf).map(|(_src_ip, _src_port, n)| n)
}

pub fn create_client() -> DhcpClient {
    DhcpClient::new()
}

pub fn timer_tick(client: &mut DhcpClient) {
    client.check_lease();
}
