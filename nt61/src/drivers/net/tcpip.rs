
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, AtomicPtr, Ordering};

#[allow(non_snake_case)]
#[allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::io::{DeviceObject, DeviceType, DriverObject, Irp, IoStackLocation};
use crate::ke::sync::Spinlock;


const MAX_TDI_ADDRESS_OBJECTS: usize = 256;

const MAX_TDI_CONNECTION_OBJECTS: usize = 512;

const MAX_INTERFACES: usize = 16;

const TCPIP_DEVICE_NAME: &str = "\\Device\\Tcp";
const UDP_DEVICE_NAME: &str = "\\Device\\Udp";
const IP_DEVICE_NAME: &str = "\\Device\\Ip";
const RAWIP_DEVICE_NAME: &str = "\\Device\\RawIp";

const IOCTL_TDI_ACCEPT: u32 = 0x00120000;
const IOCTL_TDI_CONNECT: u32 = 0x00120001;
const IOCTL_TDI_DISCONNECT: u32 = 0x00120002;
const IOCTL_TDI_LISTEN: u32 = 0x00120003;
const IOCTL_TDI_QUERY_INFORMATION: u32 = 0x00120004;
const IOCTL_TDI_RECEIVE: u32 = 0x00120005;
const IOCTL_TDI_RECEIVE_DATAGRAM: u32 = 0x00120006;
const IOCTL_TDI_SEND: u32 = 0x00120007;
const IOCTL_TDI_SEND_DATAGRAM: u32 = 0x00120008;
const IOCTL_TDI_SET_EVENT_HANDLER: u32 = 0x00120009;
const IOCTL_TDI_SET_INFORMATION: u32 = 0x0012000A;
const IOCTL_TDI_ASSOCIATE_ADDRESS: u32 = 0x0012000B;
const IOCTL_TDI_DISASSOCIATE_ADDRESS: u32 = 0x0012000C;
const IOCTL_TDI_ACTION: u32 = 0x0012000D;

const IOCTL_TDI_INTERNAL_SEND: u32 = 0x00120100;
const IOCTL_TDI_INTERNAL_RECEIVE: u32 = 0x00120101;
const IOCTL_TDI_INTERNAL_CONNECT: u32 = 0x00120102;
const IOCTL_TDI_INTERNAL_DISCONNECT: u32 = 0x00120103;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TdiAddressType {
    Unspecified = 0,
    TdiAddressTypeIp = 2,      // AF_INET
    TdiAddressTypeIpv6 = 23,   // AF_INET6
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TdiAddressIp {
    pub sin_port: u16,
    pub in_addr: u32,
    pub sin_zero: [u8; 8],
}

impl TdiAddressIp {
    pub fn new(port: u16, addr: u32) -> Self {
        Self {
            sin_port: port.to_be(),
            in_addr: addr,
            sin_zero: [0; 8],
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        Some(Self {
            sin_port: u16::from_be_bytes([data[0], data[1]]),
            in_addr: u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
            sin_zero: [0; 8],
        })
    }

    pub fn to_netstack_addr(&self) -> crate::netstack::socket::SockAddr {
        crate::netstack::socket::SockAddr::new(
            2, // AF_INET
            self.sin_port,
            self.in_addr,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TdiAddressIpv6 {
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdiAddressState {
    Closed,
    Bound,
    Listening,
}

pub struct TdiAddressObject {
    pub valid: bool,
    pub id: u32,
    pub address_type: TdiAddressType,
    pub address_ip: Option<TdiAddressIp>,
    pub address_ipv6: Option<TdiAddressIpv6>,
    pub state: TdiAddressState,
    pub protocol: u8, // 6 = TCP, 17 = UDP
    pub socket_id: Option<u32>,
    pub connections: Vec<u32>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connect_event_handler: Option<u64>,
    pub disconnect_event_handler: Option<u64>,
    pub receive_event_handler: Option<u64>,
    pub receive_datagram_event_handler: Option<u64>,
    pub error_event_handler: Option<u64>,
}

impl TdiAddressObject {
    pub fn new(id: u32) -> Self {
        Self {
            valid: false,
            id,
            address_type: TdiAddressType::Unspecified,
            address_ip: None,
            address_ipv6: None,
            state: TdiAddressState::Closed,
            protocol: 0,
            socket_id: None,
            connections: Vec::new(),
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            connect_event_handler: None,
            disconnect_event_handler: None,
            receive_event_handler: None,
            receive_datagram_event_handler: None,
            error_event_handler: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdiConnectionState {
    Idle,
    Associated,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
}

pub struct TdiConnectionObject {
    pub valid: bool,
    pub id: u32,
    pub state: TdiConnectionState,
    pub address_object_id: Option<u32>,
    pub remote_address: Option<TdiAddressIp>,
    pub remote_address_ipv6: Option<TdiAddressIpv6>,
    pub tcp_socket_id: Option<u32>,
    pub send_buffer: Vec<u8>,
    pub receive_buffer: Vec<u8>,
    pub segments_sent: u64,
    pub segments_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub retransmits: u64,
    pub connection_context: u64,
}

impl TdiConnectionObject {
    pub fn new(id: u32) -> Self {
        Self {
            valid: false,
            id,
            state: TdiConnectionState::Idle,
            address_object_id: None,
            remote_address: None,
            remote_address_ipv6: None,
            tcp_socket_id: None,
            send_buffer: Vec::new(),
            receive_buffer: Vec::new(),
            segments_sent: 0,
            segments_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            retransmits: 0,
            connection_context: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetworkInterface {
    pub valid: bool,
    pub interface_index: u32,
    pub ip_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub mac_address: [u8; 6],
    pub mtu: u16,
    pub link_speed: u64,
    pub ipv6_addresses: [[u8; 16]; 4],
    pub ipv6_count: usize,
    pub up: bool,
    pub loopback: bool,
    pub multicast: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors_in: u64,
    pub errors_out: u64,
    pub drops_in: u64,
    pub drops_out: u64,
}

impl NetworkInterface {
    pub const fn new() -> Self {
        Self {
            valid: false,
            interface_index: 0,
            ip_address: [0, 0, 0, 0],
            subnet_mask: [255, 255, 255, 0],
            gateway: [0, 0, 0, 0],
            mac_address: [0, 0, 0, 0, 0, 0],
            mtu: 1500,
            link_speed: 1_000_000_000,
            ipv6_addresses: [[0; 16]; 4],
            ipv6_count: 0,
            up: false,
            loopback: false,
            multicast: false,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            errors_in: 0,
            errors_out: 0,
            drops_in: 0,
            drops_out: 0,
        }
    }
}


static TDI_ADDRESS_OBJECTS: Spinlock<Vec<TdiAddressObject>> = Spinlock::new(Vec::new());
static TDI_CONNECTION_OBJECTS: Spinlock<Vec<TdiConnectionObject>> = Spinlock::new(Vec::new());
static NETWORK_INTERFACES: Spinlock<[NetworkInterface; MAX_INTERFACES]> =
    Spinlock::new([const { NetworkInterface::new() }; MAX_INTERFACES]);

static NEXT_ADDRESS_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_CONNECTION_ID: AtomicU32 = AtomicU32::new(1);
static DRIVER_INITIALIZED: AtomicU32 = AtomicU32::new(0);

pub struct TcpIpStatistics {
    pub ip_packets_received: AtomicU64,
    pub ip_packets_sent: AtomicU64,
    pub ip_packets_forwarded: AtomicU64,
    pub ip_packets_discarded: AtomicU64,
    pub tcp_connections_established: AtomicU64,
    pub tcp_connections_reset: AtomicU64,
    pub tcp_segments_sent: AtomicU64,
    pub tcp_segments_received: AtomicU64,
    pub tcp_segments_retransmitted: AtomicU64,
    pub udp_datagrams_sent: AtomicU64,
    pub udp_datagrams_received: AtomicU64,
    pub icmp_messages_sent: AtomicU64,
    pub icmp_messages_received: AtomicU64,
    pub arp_requests_sent: AtomicU64,
    pub arp_replies_received: AtomicU64,
}

impl TcpIpStatistics {
    pub const fn new() -> Self {
        Self {
            ip_packets_received: AtomicU64::new(0),
            ip_packets_sent: AtomicU64::new(0),
            ip_packets_forwarded: AtomicU64::new(0),
            ip_packets_discarded: AtomicU64::new(0),
            tcp_connections_established: AtomicU64::new(0),
            tcp_connections_reset: AtomicU64::new(0),
            tcp_segments_sent: AtomicU64::new(0),
            tcp_segments_received: AtomicU64::new(0),
            tcp_segments_retransmitted: AtomicU64::new(0),
            udp_datagrams_sent: AtomicU64::new(0),
            udp_datagrams_received: AtomicU64::new(0),
            icmp_messages_sent: AtomicU64::new(0),
            icmp_messages_received: AtomicU64::new(0),
            arp_requests_sent: AtomicU64::new(0),
            arp_replies_received: AtomicU64::new(0),
        }
    }
}

static TCPIP_STATS: TcpIpStatistics = TcpIpStatistics::new();


pub fn init() {
    if DRIVER_INITIALIZED.load(Ordering::Acquire) != 0 {
        return;
    }

    {
        let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
        addr_objects.clear();
        addr_objects.reserve(MAX_TDI_ADDRESS_OBJECTS);
    }

    {
        let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
        conn_objects.clear();
        conn_objects.reserve(MAX_TDI_CONNECTION_OBJECTS);
    }

    {
        let mut interfaces = NETWORK_INTERFACES.lock();

        interfaces[0].valid = true;
        interfaces[0].interface_index = 1;
        interfaces[0].ip_address = [127, 0, 0, 1];
        interfaces[0].subnet_mask = [255, 0, 0, 0];
        interfaces[0].gateway = [127, 0, 0, 1];
        interfaces[0].mac_address = [0, 0, 0, 0, 0, 0];
        interfaces[0].mtu = 65536;
        interfaces[0].up = true;
        interfaces[0].loopback = true;
        interfaces[0].multicast = false;

        interfaces[1].valid = true;
        interfaces[1].interface_index = 2;
        interfaces[1].ip_address = [10, 0, 2, 15];
        interfaces[1].subnet_mask = [255, 255, 255, 0];
        interfaces[1].gateway = [10, 0, 2, 2];
        interfaces[1].mtu = 1500;
        interfaces[1].up = true;
        interfaces[1].loopback = false;
        interfaces[1].multicast = true;
    }

    crate::netstack::init();

    DRIVER_INITIALIZED.store(1, Ordering::Release);

    crate::boot_println!("[TCPIP] TCP/IP protocol driver initialized");
}

pub fn is_initialized() -> bool {
    DRIVER_INITIALIZED.load(Ordering::Acquire) != 0
}


pub fn tdi_create_address_object(protocol: u8) -> Option<u32> {
    let id = NEXT_ADDRESS_ID.fetch_add(1, Ordering::Relaxed);
    let mut addr_obj = TdiAddressObject::new(id);
    addr_obj.valid = true;
    addr_obj.protocol = protocol;

    let mut objects = TDI_ADDRESS_OBJECTS.lock();
    if objects.len() >= MAX_TDI_ADDRESS_OBJECTS {
        return None;
    }
    objects.push(addr_obj);
    Some(id)
}

pub fn tdi_delete_address_object(id: u32) -> bool {
    let mut objects = TDI_ADDRESS_OBJECTS.lock();
    if let Some(pos) = objects.iter().position(|obj| obj.id == id && obj.valid) {
        let obj = &mut objects[pos];

        if let Some(socket_id) = obj.socket_id {
            let _ = crate::netstack::socket::close(socket_id);
        }

        obj.valid = false;
        objects.remove(pos);
        return true;
    }
    false
}

pub fn tdi_bind_address(id: u32, address: &TdiAddressIp) -> Result<(), i32> {
    let mut objects = TDI_ADDRESS_OBJECTS.lock();
    let obj = objects.iter_mut()
        .find(|obj| obj.id == id && obj.valid)
        .ok_or(-1)?; // STATUS_INVALID_HANDLE

    let socket_type = if obj.protocol == 6 {
        crate::netstack::socket::SocketType::Stream
    } else if obj.protocol == 17 {
        crate::netstack::socket::SocketType::Dgram
    } else {
        crate::netstack::socket::SocketType::Raw
    };

    let socket_id = crate::netstack::socket::socket_auto(socket_type)
        .ok_or(-2)?; // STATUS_INSUFFICIENT_RESOURCES

    let netstack_addr = address.to_netstack_addr();
    crate::netstack::socket::bind(socket_id, &netstack_addr)
        .map_err(|_| -3)?; // STATUS_ADDRESS_ALREADY_ASSOCIATED

    obj.address_type = TdiAddressType::TdiAddressTypeIp;
    obj.address_ip = Some(*address);
    obj.socket_id = Some(socket_id);
    obj.state = TdiAddressState::Bound;

    Ok(())
}

pub fn tdi_listen(id: u32, backlog: u32) -> Result<(), i32> {
    let mut objects = TDI_ADDRESS_OBJECTS.lock();
    let obj = objects.iter_mut()
        .find(|obj| obj.id == id && obj.valid)
        .ok_or(-1)?;

    if obj.protocol != 6 {
        return Err(-2); // Not TCP
    }

    let socket_id = obj.socket_id.ok_or(-3)?;

    crate::netstack::socket::listen(socket_id, backlog)
        .map_err(|_| -4)?;

    obj.state = TdiAddressState::Listening;
    Ok(())
}


pub fn tdi_create_connection_object(context: u64) -> Option<u32> {
    let id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let mut conn_obj = TdiConnectionObject::new(id);
    conn_obj.valid = true;
    conn_obj.connection_context = context;

    let mut objects = TDI_CONNECTION_OBJECTS.lock();
    if objects.len() >= MAX_TDI_CONNECTION_OBJECTS {
        return None;
    }
    objects.push(conn_obj);
    Some(id)
}

pub fn tdi_delete_connection_object(id: u32) -> bool {
    let mut objects = TDI_CONNECTION_OBJECTS.lock();
    if let Some(pos) = objects.iter().position(|obj| obj.id == id && obj.valid) {
        let obj = &mut objects[pos];

        if let Some(socket_id) = obj.tcp_socket_id {
            let _ = crate::netstack::tcp::close(socket_id);
        }

        obj.valid = false;
        objects.remove(pos);
        return true;
    }
    false
}

pub fn tdi_associate_address(conn_id: u32, addr_id: u32) -> Result<(), i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    if conn.state != TdiConnectionState::Idle {
        return Err(-2); // Already associated
    }

    {
        let addr_objects = TDI_ADDRESS_OBJECTS.lock();
        if !addr_objects.iter().any(|obj| obj.id == addr_id && obj.valid) {
            return Err(-3); // Invalid address object
        }
    }

    conn.address_object_id = Some(addr_id);
    conn.state = TdiConnectionState::Associated;

    drop(conn_objects);
    let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
    if let Some(addr_obj) = addr_objects.iter_mut().find(|obj| obj.id == addr_id && obj.valid) {
        addr_obj.connections.push(conn_id);
    }

    Ok(())
}

pub fn tdi_disassociate_address(conn_id: u32) -> Result<(), i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    let addr_id = conn.address_object_id.ok_or(-2)?;
    conn.address_object_id = None;
    conn.state = TdiConnectionState::Idle;

    drop(conn_objects);
    let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
    if let Some(addr_obj) = addr_objects.iter_mut().find(|obj| obj.id == addr_id && obj.valid) {
        addr_obj.connections.retain(|&id| id != conn_id);
    }

    Ok(())
}

pub fn tdi_connect(
    conn_id: u32,
    remote_address: &TdiAddressIp,
    timeout: Option<u64>,
) -> Result<(), i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    if conn.state != TdiConnectionState::Associated {
        return Err(-2); // Not associated
    }

    let addr_id = conn.address_object_id.ok_or(-3)?;

    let (local_ip, local_port) = {
        let addr_objects = TDI_ADDRESS_OBJECTS.lock();
        let addr_obj = addr_objects.iter()
            .find(|obj| obj.id == addr_id && obj.valid)
            .ok_or(-4)?;

        let addr = addr_obj.address_ip.ok_or(-5)?;
        (addr.in_addr, u16::from_be(addr.sin_port))
    };

    let remote_ip = remote_address.in_addr;
    let remote_port = u16::from_be(remote_address.sin_port);

    let tcp_socket_id = crate::netstack::tcp::connect(local_ip, local_port, remote_ip, remote_port)
        .ok_or(-6)?; // Connection failed

    conn.tcp_socket_id = Some(tcp_socket_id);
    conn.remote_address = Some(*remote_address);
    conn.state = TdiConnectionState::Connecting;

    TCPIP_STATS.tcp_connections_established.fetch_add(1, Ordering::Relaxed);

    // TODO: Wait for connection to establish (with timeout)
    conn.state = TdiConnectionState::Connected;

    Ok(())
}

pub fn tdi_accept(addr_id: u32, conn_id: u32) -> Result<(), i32> {
    let child_socket_id = {
        let addr_objects = TDI_ADDRESS_OBJECTS.lock();
        let addr_obj = addr_objects.iter()
            .find(|obj| obj.id == addr_id && obj.valid)
            .ok_or(-1)?;

        if addr_obj.state != TdiAddressState::Listening {
            return Err(-2); // Not listening
        }

        let socket_id = addr_obj.socket_id.ok_or(-3)?;

        crate::netstack::socket::accept(socket_id)
            .map_err(|_| -4)? // No pending connections
    };

    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-5)?;

    conn.tcp_socket_id = Some(child_socket_id);
    conn.address_object_id = Some(addr_id);
    conn.state = TdiConnectionState::Connected;

    if let Some(remote_addr) = crate::netstack::socket::get_remote_addr(child_socket_id) {
        let tdi_addr = TdiAddressIp::new(remote_addr.port, remote_addr.ip());
        conn.remote_address = Some(tdi_addr);
    }

    Ok(())
}

pub fn tdi_disconnect(conn_id: u32, flags: u32) -> Result<(), i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    if conn.state != TdiConnectionState::Connected {
        return Err(-2); // Not connected
    }

    let socket_id = conn.tcp_socket_id.ok_or(-3)?;

    crate::netstack::tcp::close(socket_id);

    conn.state = TdiConnectionState::Disconnecting;
    conn.tcp_socket_id = None;

    Ok(())
}

pub fn tdi_send(conn_id: u32, data: &[u8], flags: u32) -> Result<usize, i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    if conn.state != TdiConnectionState::Connected {
        return Err(-2); // Not connected
    }

    let socket_id = conn.tcp_socket_id.ok_or(-3)?;

    let bytes_sent = crate::netstack::tcp::send(socket_id, data)
        .ok_or(-4)?; // Send failed

    conn.bytes_sent += bytes_sent as u64;
    conn.segments_sent += 1;
    TCPIP_STATS.tcp_segments_sent.fetch_add(1, Ordering::Relaxed);

    Ok(bytes_sent)
}

pub fn tdi_receive(conn_id: u32, buffer: &mut [u8], flags: u32) -> Result<usize, i32> {
    let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
    let conn = conn_objects.iter_mut()
        .find(|obj| obj.id == conn_id && obj.valid)
        .ok_or(-1)?;

    if conn.state != TdiConnectionState::Connected {
        return Err(-2); // Not connected
    }

    let socket_id = conn.tcp_socket_id.ok_or(-3)?;

    let bytes_received = crate::netstack::tcp::receive(socket_id, buffer)
        .ok_or(-4)?; // Receive failed or would block

    conn.bytes_received += bytes_received as u64;
    if bytes_received > 0 {
        conn.segments_received += 1;
        TCPIP_STATS.tcp_segments_received.fetch_add(1, Ordering::Relaxed);
    }

    Ok(bytes_received)
}

pub fn tdi_send_datagram(
    addr_id: u32,
    remote_address: &TdiAddressIp,
    data: &[u8],
) -> Result<usize, i32> {
    let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
    let addr_obj = addr_objects.iter_mut()
        .find(|obj| obj.id == addr_id && obj.valid)
        .ok_or(-1)?;

    if addr_obj.protocol != 17 {
        return Err(-2); // Not UDP
    }

    let socket_id = addr_obj.socket_id.ok_or(-3)?;

    let remote_ip = remote_address.in_addr;
    let remote_port = u16::from_be(remote_address.sin_port);

    let remote_sa = crate::netstack::socket::SockAddr::new(2, remote_port.to_be(), remote_ip);

    let bytes_sent = crate::netstack::socket::sendto(socket_id, data, &remote_sa)
        .map_err(|_| -4)?;

    addr_obj.bytes_sent += bytes_sent as u64;
    addr_obj.packets_sent += 1;
    TCPIP_STATS.udp_datagrams_sent.fetch_add(1, Ordering::Relaxed);

    Ok(bytes_sent)
}

pub fn tdi_receive_datagram(
    addr_id: u32,
    buffer: &mut [u8],
    remote_address: &mut TdiAddressIp,
) -> Result<usize, i32> {
    let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
    let addr_obj = addr_objects.iter_mut()
        .find(|obj| obj.id == addr_id && obj.valid)
        .ok_or(-1)?;

    if addr_obj.protocol != 17 {
        return Err(-2); // Not UDP
    }

    let socket_id = addr_obj.socket_id.ok_or(-3)?;

    let (bytes_received, remote_sa) = crate::netstack::socket::recvfrom(socket_id, buffer)
        .map_err(|_| -4)?;

    *remote_address = TdiAddressIp::new(remote_sa.port, remote_sa.ip());

    addr_obj.bytes_received += bytes_received as u64;
    addr_obj.packets_received += 1;
    TCPIP_STATS.udp_datagrams_received.fetch_add(1, Ordering::Relaxed);

    Ok(bytes_received)
}


pub fn register_interface(
    ip_addr: [u8; 4],
    subnet_mask: [u8; 4],
    gateway: [u8; 4],
    mac_addr: [u8; 6],
) -> Option<u32> {
    let mut interfaces = NETWORK_INTERFACES.lock();

    for iface in interfaces.iter_mut() {
        if !iface.valid {
            iface.valid = true;
            iface.interface_index = (iface as *const _ as usize / core::mem::size_of::<NetworkInterface>()) as u32 + 1;
            iface.ip_address = ip_addr;
            iface.subnet_mask = subnet_mask;
            iface.gateway = gateway;
            iface.mac_address = mac_addr;
            iface.up = true;

            return Some(iface.interface_index);
        }
    }

    None
}

pub fn unregister_interface(interface_index: u32) -> bool {
    let mut interfaces = NETWORK_INTERFACES.lock();

    for iface in interfaces.iter_mut() {
        if iface.valid && iface.interface_index == interface_index {
            iface.valid = false;
            iface.up = false;
            return true;
        }
    }

    false
}

pub fn get_interface(interface_index: u32) -> Option<NetworkInterface> {
    let interfaces = NETWORK_INTERFACES.lock();

    interfaces.iter()
        .find(|iface| iface.valid && iface.interface_index == interface_index)
        .copied()
}

pub fn get_interfaces() -> Vec<NetworkInterface> {
    let interfaces = NETWORK_INTERFACES.lock();
    interfaces.iter()
        .filter(|iface| iface.valid)
        .copied()
        .collect()
}


pub fn ipv4_input(src_ip: u32, dst_ip: u32, protocol: u8, data: &[u8]) {
    TCPIP_STATS.ip_packets_received.fetch_add(1, Ordering::Relaxed);

    let for_us = {
        let interfaces = NETWORK_INTERFACES.lock();
        interfaces.iter().any(|iface| {
            iface.valid && iface.up &&
            u32::from_be_bytes(iface.ip_address) == dst_ip
        })
    };

    if !for_us {
        TCPIP_STATS.ip_packets_discarded.fetch_add(1, Ordering::Relaxed);
        return;
    }

    match protocol {
        6 => tcp_input(src_ip, dst_ip, data),
        17 => udp_input(src_ip, dst_ip, data),
        1 => icmp_input(src_ip, dst_ip, data),
        _ => {
            TCPIP_STATS.ip_packets_discarded.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn tcp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    crate::netstack::tcp::tcp_input(src_ip, dst_ip, data);
    TCPIP_STATS.tcp_segments_received.fetch_add(1, Ordering::Relaxed);
}

fn udp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    crate::netstack::udp::udp_input(src_ip, dst_ip, data);
    TCPIP_STATS.udp_datagrams_received.fetch_add(1, Ordering::Relaxed);
}

fn icmp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    crate::netstack::icmp::icmp_input(src_ip, dst_ip, data);
    TCPIP_STATS.icmp_messages_received.fetch_add(1, Ordering::Relaxed);
}

pub fn ipv4_output(src_ip: u32, dst_ip: u32, protocol: u8, data: &[u8]) -> bool {
    let result = crate::netstack::ipv4::send_ipv4(src_ip, dst_ip, protocol, data);

    if result {
        TCPIP_STATS.ip_packets_sent.fetch_add(1, Ordering::Relaxed);
        match protocol {
            6 => TCPIP_STATS.tcp_segments_sent.fetch_add(1, Ordering::Relaxed),
            17 => TCPIP_STATS.udp_datagrams_sent.fetch_add(1, Ordering::Relaxed),
            1 => TCPIP_STATS.icmp_messages_sent.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    result
}


pub fn dispatch_create(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    if !is_initialized() {
        return 0xC0000001; // STATUS_UNSUCCESSFUL
    }

    unsafe {
        let stack = (*irp).get_current_stack_location();
        if stack.is_null() {
            return 0xC0000001;
        }

        let addr_id = tdi_create_address_object(6); // TCP

        if let Some(id) = addr_id {
            (*irp).IoStatus.Information = id as usize;
            (*irp).IoStatus.Status = 0; // STATUS_SUCCESS
            return 0; // STATUS_SUCCESS
        } else {
            (*irp).IoStatus.Status = 0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
            return 0xC000009A;
        }
    }
}

pub fn dispatch_close(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    unsafe {
        (*irp).IoStatus.Status = 0; // STATUS_SUCCESS
        (*irp).IoStatus.Information = 0;
        0 // STATUS_SUCCESS
    }
}

pub fn dispatch_cleanup(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    unsafe {
        (*irp).IoStatus.Status = 0;
        (*irp).IoStatus.Information = 0;
        0
    }
}

pub fn dispatch_device_control(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    if !is_initialized() {
        unsafe {
            (*irp).IoStatus.Status = 0xC0000001;
            return 0xC0000001;
        }
    }

    unsafe {
        let stack = (*irp).get_current_stack_location();
        if stack.is_null() {
            (*irp).IoStatus.Status = 0xC0000001;
            return 0xC0000001;
        }

        let ioctl_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

        let status = match ioctl_code {
            IOCTL_TDI_ACCEPT => handle_tdi_accept(irp, stack),
            IOCTL_TDI_CONNECT => handle_tdi_connect(irp, stack),
            IOCTL_TDI_DISCONNECT => handle_tdi_disconnect(irp, stack),
            IOCTL_TDI_LISTEN => handle_tdi_listen(irp, stack),
            IOCTL_TDI_RECEIVE => handle_tdi_receive(irp, stack),
            IOCTL_TDI_RECEIVE_DATAGRAM => handle_tdi_receive_datagram(irp, stack),
            IOCTL_TDI_SEND => handle_tdi_send(irp, stack),
            IOCTL_TDI_SEND_DATAGRAM => handle_tdi_send_datagram(irp, stack),
            IOCTL_TDI_ASSOCIATE_ADDRESS => handle_tdi_associate_address(irp, stack),
            IOCTL_TDI_DISASSOCIATE_ADDRESS => handle_tdi_disassociate_address(irp, stack),
            IOCTL_TDI_QUERY_INFORMATION => handle_tdi_query_information(irp, stack),
            IOCTL_TDI_SET_INFORMATION => handle_tdi_set_information(irp, stack),
            IOCTL_TDI_SET_EVENT_HANDLER => handle_tdi_set_event_handler(irp, stack),
            IOCTL_TDI_ACTION => handle_tdi_action(irp, stack),
            _ => {
                (*irp).IoStatus.Information = 0;
                0xC0000002 // STATUS_NOT_IMPLEMENTED
            }
        };

        (*irp).IoStatus.Status = status;
        status
    }
}

pub fn dispatch_internal_device_control(device: *mut DeviceObject, irp: *mut Irp) -> u32 {
    if !is_initialized() {
        unsafe {
            (*irp).IoStatus.Status = 0xC0000001;
            return 0xC0000001;
        }
    }

    unsafe {
        let stack = (*irp).get_current_stack_location();
        if stack.is_null() {
            (*irp).IoStatus.Status = 0xC0000001;
            return 0xC0000001;
        }

        let ioctl_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

        let status = match ioctl_code {
            IOCTL_TDI_INTERNAL_SEND => handle_tdi_send(irp, stack),
            IOCTL_TDI_INTERNAL_RECEIVE => handle_tdi_receive(irp, stack),
            IOCTL_TDI_INTERNAL_CONNECT => handle_tdi_connect(irp, stack),
            IOCTL_TDI_INTERNAL_DISCONNECT => handle_tdi_disconnect(irp, stack),
            _ => 0xC0000002, // STATUS_NOT_IMPLEMENTED
        };

        (*irp).IoStatus.Status = status;
        status
    }
}


unsafe fn handle_tdi_accept(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 8 {
        return 0xC000000D; // STATUS_INVALID_PARAMETER
    }

    let addr_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]);

    match tdi_accept(addr_id, conn_id) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0 // STATUS_SUCCESS
        }
        Err(_) => 0xC0000001, // STATUS_UNSUCCESSFUL
    }
}

unsafe fn handle_tdi_connect(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 20 {
        return 0xC000000D; // STATUS_INVALID_PARAMETER
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);

    let remote_addr_slice = core::slice::from_raw_parts(input_buffer.offset(4), 14);
    let remote_address = TdiAddressIp::from_bytes(remote_addr_slice)
        .ok_or(0xC000000D)?;

    let timeout = if input_length >= 22 {
        Some(u32::from_le_bytes([
            *input_buffer.offset(18),
            *input_buffer.offset(19),
            *input_buffer.offset(20),
            *input_buffer.offset(21),
        ]) as u64)
    } else {
        None
    };

    match tdi_connect(conn_id, &remote_address, timeout) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0 // STATUS_SUCCESS
        }
        Err(_) => 0xC0000001, // STATUS_UNSUCCESSFUL
    }
}

unsafe fn handle_tdi_disconnect(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 8 {
        return 0xC000000D;
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let flags = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]);

    match tdi_disconnect(conn_id, flags) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_listen(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 8 {
        return 0xC000000D;
    }

    let addr_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let backlog = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]);

    match tdi_listen(addr_id, backlog) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_send(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 12 {
        return 0xC000000D;
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let data_length = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]) as usize;
    let flags = u32::from_le_bytes([
        *input_buffer.offset(8),
        *input_buffer.offset(9),
        *input_buffer.offset(10),
        *input_buffer.offset(11),
    ]);

    if input_length < 12 + data_length {
        return 0xC000000D;
    }

    let data = core::slice::from_raw_parts(input_buffer.offset(12), data_length);

    match tdi_send(conn_id, data, flags) {
        Ok(bytes_sent) => {
            (*irp).IoStatus.Information = bytes_sent;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_receive(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let output_buffer = (*irp).UserBuffer as *mut u8;
    let output_length = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

    if input_buffer.is_null() || output_buffer.is_null() || output_length == 0 {
        return 0xC000000D;
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let flags = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]);

    let buffer = core::slice::from_raw_parts_mut(output_buffer, output_length);

    match tdi_receive(conn_id, buffer, flags) {
        Ok(bytes_received) => {
            (*irp).IoStatus.Information = bytes_received;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_send_datagram(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 22 {
        return 0xC000000D;
    }

    let addr_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);

    let remote_addr_slice = core::slice::from_raw_parts(input_buffer.offset(4), 14);
    let remote_address = TdiAddressIp::from_bytes(remote_addr_slice)
        .ok_or(0xC000000D)?;

    let data_length = u32::from_le_bytes([
        *input_buffer.offset(18),
        *input_buffer.offset(19),
        *input_buffer.offset(20),
        *input_buffer.offset(21),
    ]) as usize;

    if input_length < 22 + data_length {
        return 0xC000000D;
    }

    let data = core::slice::from_raw_parts(input_buffer.offset(22), data_length);

    match tdi_send_datagram(addr_id, &remote_address, data) {
        Ok(bytes_sent) => {
            (*irp).IoStatus.Information = bytes_sent;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_receive_datagram(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let output_buffer = (*irp).UserBuffer as *mut u8;
    let output_length = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

    if input_buffer.is_null() || output_buffer.is_null() || output_length < 14 {
        return 0xC000000D;
    }

    let addr_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);

    let data_buffer = core::slice::from_raw_parts_mut(output_buffer.offset(14), output_length - 14);
    let mut remote_address = TdiAddressIp::new(0, 0);

    match tdi_receive_datagram(addr_id, data_buffer, &mut remote_address) {
        Ok(bytes_received) => {
            output_buffer.offset(0).write(((remote_address.sin_port >> 8) & 0xFF) as u8);
            output_buffer.offset(1).write((remote_address.sin_port & 0xFF) as u8);
            output_buffer.offset(2).write(((remote_address.in_addr >> 24) & 0xFF) as u8);
            output_buffer.offset(3).write(((remote_address.in_addr >> 16) & 0xFF) as u8);
            output_buffer.offset(4).write(((remote_address.in_addr >> 8) & 0xFF) as u8);
            output_buffer.offset(5).write((remote_address.in_addr & 0xFF) as u8);

            (*irp).IoStatus.Information = 14 + bytes_received;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_associate_address(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 8 {
        return 0xC000000D;
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);
    let addr_id = u32::from_le_bytes([
        *input_buffer.offset(4),
        *input_buffer.offset(5),
        *input_buffer.offset(6),
        *input_buffer.offset(7),
    ]);

    match tdi_associate_address(conn_id, addr_id) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_disassociate_address(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    let input_buffer = (*stack).Parameters.DeviceIoControl.Type3InputBuffer as *const u8;
    let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

    if input_buffer.is_null() || input_length < 4 {
        return 0xC000000D;
    }

    let conn_id = u32::from_le_bytes([
        *input_buffer.offset(0),
        *input_buffer.offset(1),
        *input_buffer.offset(2),
        *input_buffer.offset(3),
    ]);

    match tdi_disassociate_address(conn_id) {
        Ok(()) => {
            (*irp).IoStatus.Information = 0;
            0
        }
        Err(_) => 0xC0000001,
    }
}

unsafe fn handle_tdi_query_information(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    (*irp).IoStatus.Information = 0;
    0 // STATUS_SUCCESS
}

unsafe fn handle_tdi_set_information(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    (*irp).IoStatus.Information = 0;
    0 // STATUS_SUCCESS
}

unsafe fn handle_tdi_set_event_handler(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    (*irp).IoStatus.Information = 0;
    0 // STATUS_SUCCESS
}

unsafe fn handle_tdi_action(irp: *mut Irp, stack: *mut IoStackLocation) -> u32 {
    (*irp).IoStatus.Information = 0;
    0 // STATUS_SUCCESS
}


pub fn get_statistics() -> &'static TcpIpStatistics {
    &TCPIP_STATS
}

pub fn get_address_object_count() -> usize {
    TDI_ADDRESS_OBJECTS.lock().len()
}

pub fn get_connection_object_count() -> usize {
    TDI_CONNECTION_OBJECTS.lock().len()
}

pub fn get_interface_count() -> usize {
    NETWORK_INTERFACES.lock().iter().filter(|i| i.valid).count()
}


pub fn DriverEntry(driver: *mut DriverObject) -> u32 {
    init();

    unsafe {
        if !driver.is_null() {
            use crate::io::major::*;
            (*driver).MajorFunction[IRP_MJ_CREATE] = Some(dispatch_create);
            (*driver).MajorFunction[IRP_MJ_CLOSE] = Some(dispatch_close);
            (*driver).MajorFunction[IRP_MJ_CLEANUP] = Some(dispatch_cleanup);
            (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL] = Some(dispatch_device_control);
            (*driver).MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = Some(dispatch_internal_device_control);
        }
    }

    crate::boot_println!("[TCPIP.SYS] Driver loaded successfully");

    0 // STATUS_SUCCESS
}

pub fn DriverUnload(driver: *mut DriverObject) {
    {
        let mut addr_objects = TDI_ADDRESS_OBJECTS.lock();
        addr_objects.clear();
    }

    {
        let mut conn_objects = TDI_CONNECTION_OBJECTS.lock();
        conn_objects.clear();
    }

    DRIVER_INITIALIZED.store(0, Ordering::Release);

    crate::boot_println!("[TCPIP.SYS] Driver unloaded");
}
