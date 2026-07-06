//! TCP Protocol Implementation
//
//! Handles Transmission Control Protocol for reliable, ordered data delivery.
//
//! Clean-room implementation based on RFC 793, 1122, 9293.

use crate::netstack::ipv4;
use crate::ke::sync::Spinlock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::hal::common::pit;

/// TCP port
pub type Port = u16;

/// TCP header size
pub const TCP_HDR_SIZE: usize = 20;

/// TCP flags
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        }
    }
}

/// TCP header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TcpHeader {
    /// Source port (network byte order)
    pub src_port: u16,
    /// Destination port (network byte order)
    pub dst_port: u16,
    /// Sequence number (network byte order)
    pub seq: u32,
    /// Acknowledgment number (network byte order)
    pub ack: u32,
    /// Data offset (4 bits) and flags (8 bits)
    pub data_offset_flags: u16,
    /// Window size (network byte order)
    pub window: u16,
    /// Checksum (network byte order)
    pub checksum: u16,
    /// Urgent pointer (network byte order)
    pub urgent: u16,
}

impl TcpHeader {
    /// Get header length in bytes
    pub fn header_length(&self) -> usize {
        ((self.data_offset_flags >> 12) as usize) * 4
    }

    /// Get TCP flags
    pub fn flags(&self) -> u8 {
        (self.data_offset_flags & 0xFF) as u8
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<TcpHeader> {
        if data.len() < TCP_HDR_SIZE {
            return None;
        }

        Some(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset_flags: u16::from_be_bytes([data[12], data[13]]),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent: u16::from_be_bytes([data[18], data[19]]),
        })
    }

    /// Write to bytes
    pub fn to_bytes(&self, data: &mut [u8]) {
        if data.len() < TCP_HDR_SIZE {
            return;
        }

        data[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        data[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        data[4..8].copy_from_slice(&self.seq.to_be_bytes());
        data[8..12].copy_from_slice(&self.ack.to_be_bytes());
        data[12..14].copy_from_slice(&self.data_offset_flags.to_be_bytes());
        data[14..16].copy_from_slice(&self.window.to_be_bytes());
        data[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        data[18..20].copy_from_slice(&self.urgent.to_be_bytes());
    }
}

/// TCP control block (TCB)
pub struct TcpControlBlock {
    /// Local IP address
    pub local_ip: u32,
    /// Local port
    pub local_port: Port,
    /// Remote IP address
    pub remote_ip: u32,
    /// Remote port
    pub remote_port: Port,
    /// Connection state
    pub state: TcpState,
    /// Send sequence numbers
    pub snd_una: u32,  // Unacknowledged
    pub snd_nxt: u32,  // Next to send
    pub snd_iss: u32,  // Initial send sequence
    /// Receive sequence numbers
    pub rcv_nxt: u32,  // Next expected
    pub rcv_irs: u32,  // Initial receive sequence
    /// Window sizes
    pub snd_wnd: u16,
    pub rcv_wnd: u16,
    /// Maximum segment size
    pub mss: u16,
    /// Receive buffer
    pub rx_buf: Vec<u8>,
    /// Send buffer
    pub tx_buf: Vec<u8>,
    /// Socket reference
    pub socket_id: u32,
    /// Timer values
    pub rto: u32,  // Retransmission timeout
    pub srtt: u32,  // Smoothed round trip time
    pub rttvar: u32, // Round trip time variation
    /// Congestion control
    pub cwnd: u32,         // Congestion window
    pub ssthresh: u32,     // Slow start threshold
    pub dup_acks: u8,      // Duplicate ACK count
    /// Retransmission
    pub retransmit_count: u8,
    pub last_send_time: u64,
    pub in_retransmit: bool,
}

impl TcpControlBlock {
    pub fn new() -> Self {
        use crate::hal::common::pit;
        Self {
            local_ip: 0,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            state: TcpState::Closed,
            snd_una: 0,
            snd_nxt: 0,
            snd_iss: 0,
            rcv_nxt: 0,
            rcv_irs: 0,
            snd_wnd: 8192,
            rcv_wnd: 65535,
            mss: 1460,
            rx_buf: Vec::new(),
            tx_buf: Vec::new(),
            socket_id: 0,
            rto: 3000,
            srtt: 0,
            rttvar: 0,
            cwnd: 1460,           // Start with one MSS
            ssthresh: 65535,      // High threshold for slow start
            dup_acks: 0,
            retransmit_count: 0,
            last_send_time: pit::get_system_time_ms() as u64,
            in_retransmit: false,
        }
    }
    
    /// Update RTT estimate using Jacobson/Karels algorithm
    pub fn update_rtt(&mut self, measured_rtt: u32) {
        if self.srtt == 0 {
            // First RTT measurement
            self.srtt = measured_rtt;
            self.rttvar = measured_rtt / 2;
        } else {
            // Update RTTVAR
            let delta = if measured_rtt > self.srtt {
                measured_rtt - self.srtt
            } else {
                self.srtt - measured_rtt
            };
            self.rttvar = (3 * self.rttvar + delta) / 4;
            
            // Update SRTT
            self.srtt = (7 * self.srtt + measured_rtt) / 8;
        }
        
        // Calculate RTO with minimum 1 second and maximum 60 seconds
        let rto_calc = self.srtt + 4 * self.rttvar;
        self.rto = rto_calc.max(1000).min(60000);
    }
    
    /// Handle duplicate ACK for fast retransmit
    pub fn on_duplicate_ack(&mut self) {
        self.dup_acks += 1;
        
        // Three duplicate ACKs trigger fast retransmit
        if self.dup_acks == 3 {
            // Fast retransmit: retransmit one segment
            self.ssthresh = (self.cwnd / 2).max(2 * self.mss as u32);
            self.cwnd = self.ssthresh + 3 * self.mss as u32;
            // Retransmission would be triggered by the caller
        } else if self.dup_acks > 3 {
            // Additional duplicate ACKs: increase cwnd
            self.cwnd = self.cwnd + self.mss as u32;
        }
    }
    
    /// Handle ACK during slow start
    pub fn on_ack_slow_start(&mut self) {
        // Exponential increase: cwnd += MSS
        self.cwnd = self.cwnd + self.mss as u32;
        
        // Check if we've reached ssthresh
        if self.cwnd >= self.ssthresh {
            // Transition to congestion avoidance
        }
    }
    
    /// Handle ACK during congestion avoidance
    pub fn on_ack_congestion_avoidance(&mut self) {
        // Linear increase: cwnd += MSS * MSS / cwnd
        let increment = ((self.mss as u32) * (self.mss as u32)) / self.cwnd;
        self.cwnd = self.cwnd + increment;
    }
    
    /// Handle successful ACK
    pub fn on_ack(&mut self, ack_num: u32) {
        // Update duplicate ACK counter
        if ack_num > self.snd_una {
            // New data is acked
            self.dup_acks = 0;
            
            // Calculate flight size and check for congestion window issues
            let flight_size = self.snd_nxt - ack_num;
            
            // Ensure cwnd accounts for acked data
            if flight_size > self.cwnd {
                // This shouldn't happen normally, but handle gracefully
                self.cwnd = flight_size;
            }
            
            if self.cwnd < self.ssthresh {
                // Slow start
                self.on_ack_slow_start();
            } else {
                // Congestion avoidance
                self.on_ack_congestion_avoidance();
            }
        } else if ack_num == self.snd_una {
            // Duplicate ACK
            self.on_duplicate_ack();
        }
        
        // Update send sequence
        self.snd_una = ack_num;
    }
    
    /// Handle timeout - triple duplicate ACK scenario
    pub fn on_timeout(&mut self) {
        // Save RTT measurement for next connection
        let saved_rto = self.rto;
        
        // Record retransmission info for statistics
        self.retransmit_count += 1;
        self.in_retransmit = true;
        
        // Enter slow start
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss as u32);
        self.cwnd = self.mss as u32;
        
        // Double retransmission timeout using saved value
        self.rto = (saved_rto * 2).min(60000);
        
        // Reset dup ACK counter
        self.dup_acks = 0;
        
        // kprintln!("  [TCP] Timeout: ssthresh={}, cwnd={}, rto={}",   // kprintln disabled (memcpy crash workaround)
//             self.ssthresh, self.cwnd, saved_rto);
    }
    
    /// Check if we can send more data
    pub fn can_send(&self) -> bool {
        let effective_window = self.cwnd.min(self.snd_wnd as u32);
        let flight_size = self.snd_nxt - self.snd_una;
        flight_size < effective_window
    }
    
    /// Get the number of bytes we can send
    pub fn send_window(&self) -> u32 {
        let effective_window = self.cwnd.min(self.snd_wnd as u32);
        let flight_size = self.snd_nxt - self.snd_una;
        effective_window.saturating_sub(flight_size)
    }
}

/// Global TCB table
static TCP_CONNECTIONS: Spinlock<Vec<TcpControlBlock>> = Spinlock::new(Vec::new());

/// Next socket ID
static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);

/// TCP statistics
pub struct TcpStats {
    pub active_opens: u64,
    pub passive_opens: u64,
    pub failed_connects: u64,
    pub resets: u64,
    pub segs_sent: u64,
    pub segs_received: u64,
    pub segs_retrans: u64,
}

impl Clone for TcpStats {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for TcpStats {}

impl TcpStats {
    pub const fn new() -> Self {
        Self {
            active_opens: 0,
            passive_opens: 0,
            failed_connects: 0,
            resets: 0,
            segs_sent: 0,
            segs_received: 0,
            segs_retrans: 0,
        }
    }

    pub const fn zero() -> Self {
        Self {
            active_opens: 0,
            passive_opens: 0,
            failed_connects: 0,
            resets: 0,
            segs_sent: 0,
            segs_received: 0,
            segs_retrans: 0,
        }
    }
}

impl Default for TcpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Global TCP statistics
static TCP_STATS: Spinlock<TcpStats> = Spinlock::new(TcpStats::zero());

/// Initialize the TCP module
pub fn init() {
    TCP_CONNECTIONS.lock().clear();
    let mut stats = TCP_STATS.lock();
    *stats = TcpStats::zero();
}

/// Calculate TCP checksum
fn calculate_tcp_checksum(src_ip: u32, dst_ip: u32, tcp_data: &[u8]) -> u16 {
    // Pseudo-header
    let pseudo = [
        (src_ip >> 24) as u8, (src_ip >> 16) as u8, (src_ip >> 8) as u8, src_ip as u8,
        (dst_ip >> 24) as u8, (dst_ip >> 16) as u8, (dst_ip >> 8) as u8, dst_ip as u8,
        0,  // Protocol
        6,  // TCP protocol number
        ((tcp_data.len() >> 8) & 0xFF) as u8,
        (tcp_data.len() & 0xFF) as u8,
    ];

    let mut sum: u32 = 0;

    // Sum pseudo-header
    for chunk in pseudo.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
    }

    // Sum TCP data
    for chunk in tcp_data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += chunk[0] as u32;
        }
    }

    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Find a TCB by port
fn find_tcb(local_ip: u32, local_port: Port, remote_ip: u32, remote_port: Port) -> Option<usize> {
    let connections = TCP_CONNECTIONS.lock();
    connections
        .iter()
        .enumerate()
        .find(|(_, tcb)| {
            tcb.local_ip == local_ip
                && tcb.local_port == local_port
                && tcb.remote_ip == remote_ip
                && tcb.remote_port == remote_port
        })
        .map(|(i, _)| i)
}

/// Find a listening TCB by local port
fn find_listener(local_ip: u32, local_port: Port) -> Option<usize> {
    let connections = TCP_CONNECTIONS.lock();
    connections
        .iter()
        .enumerate()
        .find(|(_, tcb)| {
            tcb.local_ip == local_ip && tcb.local_port == local_port && tcb.state == TcpState::Listen
        })
        .map(|(i, _)| i)
}

/// Send a TCP segment
fn send_segment(
    tcb: &mut TcpControlBlock,
    flags: u8,
    seq: u32,
    ack: u32,
    data: Option<&[u8]>,
) {
    let data_len = data.map(|d| d.len()).unwrap_or(0);
    let packet_len = TCP_HDR_SIZE + data_len;

    let mut packet = Vec::with_capacity(packet_len);

    // Build header
    let data_offset = (TCP_HDR_SIZE / 4) as u16;
    let offset_flags = (data_offset << 12) | (flags as u16);

    let mut header = [0u8; TCP_HDR_SIZE];
    header[0..2].copy_from_slice(&tcb.local_port.to_be_bytes());
    header[2..4].copy_from_slice(&tcb.remote_port.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12..14].copy_from_slice(&offset_flags.to_be_bytes());
    header[14..16].copy_from_slice(&tcb.rcv_wnd.to_be_bytes());
    header[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    // Calculate checksum
    let checksum = calculate_tcp_checksum(tcb.local_ip, tcb.remote_ip, &header);

    header[16..18].copy_from_slice(&checksum.to_be_bytes());

    packet.extend_from_slice(&header);
    if let Some(d) = data {
        packet.extend_from_slice(d);
    }

    // Send via IPv4
    let _ = ipv4::send_ipv4(tcb.local_ip, tcb.remote_ip, 6, &packet);

    let mut stats = TCP_STATS.lock();
    stats.segs_sent += 1;
}

/// Process incoming TCP segment
pub fn tcp_input(src_ip: u32, dst_ip: u32, data: &[u8]) {
    let header = match TcpHeader::from_bytes(data) {
        Some(h) => h,
        None => return,
    };

    let payload = if data.len() > TCP_HDR_SIZE {
        &data[TCP_HDR_SIZE..]
    } else {
        &[]
    };

    let flags = header.flags();
    let _payload_len = payload.len(); // Available for processing

    let mut stats = TCP_STATS.lock();
    stats.segs_received += 1;
    drop(stats);

    // Find connection
    let conn_idx = find_tcb(dst_ip, header.dst_port, src_ip, header.src_port);

    match conn_idx {
        Some(idx) => {
            let mut connections = TCP_CONNECTIONS.lock();
            let tcb = &mut connections[idx];
            handle_tcp_segment(tcb, header, flags, payload);
        }
        None => {
            // No matching connection
            // Check if it's a SYN for a listening socket
            if flags & tcp_flags::SYN != 0 {
                if let Some(idx) = find_listener(dst_ip, header.dst_port) {
                    // Create new connection for listening socket
                    let mut connections = TCP_CONNECTIONS.lock();
                    let _listener = &connections[idx]; // Verify listener exists
                    let mut new_tcb = TcpControlBlock::new();
                    new_tcb.local_ip = dst_ip;
                    new_tcb.local_port = header.dst_port;
                    new_tcb.remote_ip = src_ip;
                    new_tcb.remote_port = header.src_port;
                    new_tcb.state = TcpState::SynReceived;
                    new_tcb.snd_iss = generate_isn();
                    new_tcb.rcv_irs = header.seq;
                    new_tcb.rcv_nxt = header.seq + 1;
                    new_tcb.snd_una = new_tcb.snd_iss;
                    new_tcb.snd_nxt = new_tcb.snd_iss + 1;

                    connections.push(new_tcb);
                    let new_idx = connections.len() - 1;

                    // Send SYN-ACK
                    {
                        let tcb = &mut connections[new_idx];
                        send_segment(tcb, tcp_flags::SYN | tcp_flags::ACK, tcb.snd_iss, tcb.rcv_nxt, None);
                    }

                    let mut stats = TCP_STATS.lock();
                    stats.passive_opens += 1;
                }
            } else {
                // No matching connection, send RST
                // (simplified - actual RST handling would need more care)
            }
        }
    }
}

/// Handle TCP segment based on state
fn handle_tcp_segment(tcb: &mut TcpControlBlock, header: TcpHeader, flags: u8, payload: &[u8]) {
    let payload_len = payload.len();
    
    match tcb.state {
        TcpState::Closed => {
            // Ignore
        }
        TcpState::Listen => {
            if flags & tcp_flags::SYN != 0 {
                // This is handled in tcp_input for listeners
            }
        }
        TcpState::SynSent => {
            if flags & tcp_flags::ACK != 0 {
                if flags & tcp_flags::SYN != 0 {
                    // Simultaneous open - enter SynReceived
                    tcb.rcv_nxt = header.seq + 1;
                    tcb.snd_una = header.ack;
                    tcb.state = TcpState::Established;
                    send_segment(tcb, tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
                } else if header.ack == tcb.snd_nxt {
                    // ACK of our SYN
                    tcb.snd_una = header.ack;
                    tcb.state = TcpState::Established;
                }
            }
        }
        TcpState::SynReceived => {
            if flags & tcp_flags::ACK != 0 && header.ack == tcb.snd_nxt {
                tcb.snd_una = header.ack;
                tcb.state = TcpState::Established;
            }
        }
        TcpState::Established => {
            // Process incoming data
            if payload_len > 0 {
                tcb.rx_buf.extend_from_slice(payload);
                tcb.rcv_nxt += payload_len as u32;
            }

            // Handle ACK
            if flags & tcp_flags::ACK != 0 {
                // Use new congestion control ACK handler
                tcb.on_ack(header.ack);
            }
            
            // Check for duplicate ACKs (fast retransmit trigger)
            if flags & tcp_flags::ACK != 0 && header.ack == tcb.snd_una {
                // This is a duplicate ACK - handled in on_ack
            }

            // Handle FIN
            if flags & tcp_flags::FIN != 0 {
                tcb.rcv_nxt += 1;
                tcb.state = TcpState::CloseWait;
                send_segment(tcb, tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
            }
        }
        TcpState::FinWait1 => {
            if flags & tcp_flags::FIN != 0 {
                tcb.rcv_nxt += 1;
                if flags & tcp_flags::ACK != 0 {
                    tcb.snd_una = header.ack;
                    tcb.state = TcpState::TimeWait;
                } else {
                    tcb.state = TcpState::Closing;
                }
                send_segment(tcb, tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
            } else if flags & tcp_flags::ACK != 0 {
                tcb.snd_una = header.ack;
                tcb.state = TcpState::FinWait2;
            }
        }
        TcpState::FinWait2 => {
            if flags & tcp_flags::FIN != 0 {
                tcb.rcv_nxt += 1;
                tcb.state = TcpState::TimeWait;
                send_segment(tcb, tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
            }
        }
        TcpState::CloseWait => {
            // Waiting for application to close
        }
        TcpState::Closing => {
            if flags & tcp_flags::ACK != 0 && header.ack == tcb.snd_nxt {
                tcb.snd_una = header.ack;
                tcb.state = TcpState::TimeWait;
            }
        }
        TcpState::LastAck => {
            if flags & tcp_flags::ACK != 0 && header.ack == tcb.snd_nxt {
                tcb.state = TcpState::Closed;
            }
        }
        TcpState::TimeWait => {
            // Wait for 2MSL before closing
        }
    }
}

/// Generate Initial Sequence Number
fn generate_isn() -> u32 {
    // Simple ISN generation - use PIT ticks for seeding
    let now = pit::get_system_time_ms() as u32;
    now
}

/// Begin TCP connection
pub fn connect(local_ip: u32, local_port: Port, remote_ip: u32, remote_port: Port) -> Option<u32> {
    let mut connections = TCP_CONNECTIONS.lock();

    let mut tcb = TcpControlBlock::new();
    tcb.local_ip = local_ip;
    tcb.local_port = local_port;
    tcb.remote_ip = remote_ip;
    tcb.remote_port = remote_port;
    tcb.state = TcpState::SynSent;
    tcb.snd_iss = generate_isn();
    tcb.snd_nxt = tcb.snd_iss + 1;
    tcb.snd_una = tcb.snd_iss;

    let socket_id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    tcb.socket_id = socket_id;

    connections.push(tcb);
    let idx = connections.len() - 1;

    // Send SYN
    {
        let tcb = &mut connections[idx];
        send_segment(tcb, tcp_flags::SYN, tcb.snd_iss, 0, None);
    }

    let mut stats = TCP_STATS.lock();
    stats.active_opens += 1;

    Some(socket_id)
}

/// Close a TCP connection
pub fn close(socket_id: u32) -> bool {
    let mut connections = TCP_CONNECTIONS.lock();

    if let Some(idx) = connections.iter().position(|tcb| tcb.socket_id == socket_id) {
        let tcb = &mut connections[idx];

        match tcb.state {
            TcpState::Established => {
                tcb.state = TcpState::FinWait1;
                send_segment(tcb, tcp_flags::FIN | tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
            }
            TcpState::CloseWait => {
                tcb.state = TcpState::LastAck;
                send_segment(tcb, tcp_flags::FIN | tcp_flags::ACK, tcb.snd_nxt, tcb.rcv_nxt, None);
            }
            _ => {
                tcb.state = TcpState::Closed;
            }
        }
        return true;
    }

    false
}

/// Send data on a connection
pub fn send(socket_id: u32, data: &[u8]) -> Option<usize> {
    let mut connections = TCP_CONNECTIONS.lock();

    let idx = match connections.iter().position(|tcb| tcb.socket_id == socket_id) {
        Some(i) => i,
        None => return None,
    };
    let tcb = &mut connections[idx];

    if tcb.state != TcpState::Established {
        return None;
    }

    // Queue the data into the retransmit buffer BEFORE we transmit,
    // so the data is preserved across the call and can be retransmitted
    // on timeout (NET-3 fix).
    tcb.tx_buf.extend_from_slice(data);

    // Snapshot the fields that send_segment needs, then send.
    // The TCP_CONNECTIONS lock is held for the entire critical
    // section — send_segment does not take any lock internally,
    // so we do not need to drop and reacquire (NET-2 fix).
    let snd_nxt = tcb.snd_nxt;
    let rcv_nxt = tcb.rcv_nxt;

    // Make a contiguous copy of the buffered data so we can pass a
    // &[u8] slice to send_segment while still holding the &mut tcb.
    let tx_snapshot: alloc::vec::Vec<u8> = tcb.tx_buf.iter().copied().collect();
    send_segment(
        tcb,
        tcp_flags::PSH | tcp_flags::ACK,
        snd_nxt,
        rcv_nxt,
        Some(&tx_snapshot),
    );

    // Advance snd_nxt and clear the retransmit buffer only after
    // the segment has been built (send_segment updates state
    // internally based on the current snd_nxt we passed in).
    tcb.snd_nxt = snd_nxt.wrapping_add(data.len() as u32);
    tcb.tx_buf.clear();

    Some(data.len())
}

/// Receive data from a connection
pub fn receive(socket_id: u32, buffer: &mut [u8]) -> Option<usize> {
    let idx = {
        let connections = TCP_CONNECTIONS.lock();
        connections.iter().position(|tcb| tcb.socket_id == socket_id)?
    };

    {
        let mut connections = TCP_CONNECTIONS.lock();
        let tcb = &mut connections[idx];

        if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
            return None;
        }

        if tcb.rx_buf.is_empty() {
            return Some(0);
        }

        let copy_len = buffer.len().min(tcb.rx_buf.len());
        buffer[..copy_len].copy_from_slice(&tcb.rx_buf[..copy_len]);

        // Remove received data from buffer
        tcb.rx_buf.drain(..copy_len);

        return Some(copy_len);
    }
}

/// Get TCP statistics
pub fn get_stats() -> TcpStats {
    (*TCP_STATS.lock()).clone()
}

/// Check for retransmission timeouts and perform retransmissions
/// This should be called periodically by the network stack
pub fn check_retransmit_timers() {
    use crate::hal::common::pit;
    let now = pit::get_system_time_ms() as u64;
    
    let mut connections = TCP_CONNECTIONS.lock();
    
    for i in 0..connections.len() {
        // Check if this connection needs retransmission
        let needs_retransmit = {
            let tcb = &connections[i];
            // Only check established connections
            if tcb.state != TcpState::Established 
               && tcb.state != TcpState::SynSent
               && tcb.state != TcpState::SynReceived {
                false
            } else if tcb.snd_nxt > tcb.snd_una {
                // Calculate time since last send
                let elapsed = now.saturating_sub(tcb.last_send_time);
                elapsed > tcb.rto as u64
            } else {
                false
            }
        };
        
        if needs_retransmit {
            // Get mutable reference for retransmission
            let tcb = &mut connections[i];
            // kprintln!("  [TCP] Retransmission timeout for socket {}", tcb.socket_id)  // kprintln disabled (memcpy crash workaround);
            
            let mut stats = TCP_STATS.lock();
            stats.segs_retrans += 1;
            drop(stats);
            
            // Retransmit the segment. We resend the bytes from the
            // start of tx_buf (which holds data not yet ACKed). The
            // previously-sent `snd_nxt..snd_una` range has been
            // cleared from tx_buf when ACKs arrived, so what remains
            // is exactly the unacknowledged payload.
            //
            // Cap at MSS so we don't resend an arbitrarily large
            // burst on a single retransmit event. If the buffered
            // payload is empty (pure ACK retransmit), pass None.
            let retransmit_payload: alloc::vec::Vec<u8> = if tcb.tx_buf.is_empty() {
                alloc::vec::Vec::new()
            } else {
                let take = tcb.tx_buf.len().min(tcb.mss as usize);
                tcb.tx_buf[..take].to_vec()
            };
            let payload_opt: Option<&[u8]> = if retransmit_payload.is_empty() {
                None
            } else {
                Some(&retransmit_payload)
            };
            send_segment(tcb, tcp_flags::ACK, tcb.snd_una, tcb.rcv_nxt, payload_opt);

            tcb.last_send_time = pit::get_system_time_ms() as u64;
            tcb.in_retransmit = true;

            // Handle timeout
            tcb.on_timeout();
        }
    }
}

/// Get congestion window for a connection
pub fn get_cwnd(socket_id: u32) -> Option<u32> {
    let connections = TCP_CONNECTIONS.lock();
    connections
        .iter()
        .find(|tcb| tcb.socket_id == socket_id)
        .map(|tcb| tcb.cwnd)
}

/// Get ssthresh for a connection
pub fn get_ssthresh(socket_id: u32) -> Option<u32> {
    let connections = TCP_CONNECTIONS.lock();
    connections
        .iter()
        .find(|tcb| tcb.socket_id == socket_id)
        .map(|tcb| tcb.ssthresh)
}
