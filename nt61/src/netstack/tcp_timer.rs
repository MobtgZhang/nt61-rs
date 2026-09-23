//! TCP Timer Management
//!
//! Implements retransmission timers and other TCP timers according to RFC 6298.

use crate::ke::sync::Spinlock;
use alloc::collections::BTreeMap;
use crate::hal::common::pit;

/// TCP timer types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TcpTimerType {
    /// Retransmission timer (RTO)
    Retransmit,
    /// Keep-alive timer
    KeepAlive,
    /// TIME-WAIT timer (2MSL)
    TimeWait,
    /// Delayed ACK timer
    DelayedAck,
    /// Persist timer (zero window probe)
    Persist,
}

/// TCP timer entry
#[derive(Debug, Clone)]
pub struct TcpTimer {
    /// Socket ID this timer belongs to
    pub socket_id: u32,
    /// Timer type
    pub timer_type: TcpTimerType,
    /// When the timer fires (milliseconds since boot)
    pub next_fire: u64,
    /// Timer interval (for recurring timers)
    pub interval: u32,
    /// Whether the timer is active
    pub active: bool,
}

impl TcpTimer {
    pub fn new(socket_id: u32, timer_type: TcpTimerType, timeout_ms: u32) -> Self {
        let now = pit::get_system_time_ms() as u64;
        Self {
            socket_id,
            timer_type,
            next_fire: now + timeout_ms as u64,
            interval: timeout_ms,
            active: true,
        }
    }

    /// Check if timer has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.active && current_time >= self.next_fire
    }

    /// Reset the timer with a new timeout

    pub fn reset(&mut self, timeout_ms: u32) {
        let now = pit::get_system_time_ms() as u64;
        self.next_fire = now + timeout_ms as u64;
        self.interval = timeout_ms;
        self.active = true;
    }

    /// Stop the timer
    pub fn stop(&mut self) {
        self.active = false;
    }
}

/// TCP timer manager
pub struct TcpTimerManager {
    /// Active timers indexed by (socket_id, timer_type)
    timers: Spinlock<BTreeMap<(u32, TcpTimerType), TcpTimer>>,
}

impl TcpTimerManager {
    pub const fn new() -> Self {
        Self {
            timers: Spinlock::new(BTreeMap::new()),
        }
    }

    /// Set or update a timer
    pub fn set_timer(&self, socket_id: u32, timer_type: TcpTimerType, timeout_ms: u32) {
        let mut timers = self.timers.lock();
        let key = (socket_id, timer_type);

        if let Some(timer) = timers.get_mut(&key) {
            timer.reset(timeout_ms);
        } else {
            let timer = TcpTimer::new(socket_id, timer_type, timeout_ms);
            timers.insert(key, timer);
        }
    }

    /// Cancel a timer
    pub fn cancel_timer(&self, socket_id: u32, timer_type: TcpTimerType) {
        let mut timers = self.timers.lock();
        let key = (socket_id, timer_type);

        if let Some(timer) = timers.get_mut(&key) {
            timer.stop();
        }
    }

    /// Remove all timers for a socket
    pub fn remove_socket_timers(&self, socket_id: u32) {
        let mut timers = self.timers.lock();
        timers.retain(|(sid, _), _| *sid != socket_id);
    }

    /// Check for expired timers and return them
    pub fn check_timers(&self) -> alloc::vec::Vec<(u32, TcpTimerType)> {
        let current_time = pit::get_system_time_ms() as u64;
        let mut expired = alloc::vec::Vec::new();

        let timers = self.timers.lock();
        for ((socket_id, timer_type), timer) in timers.iter() {
            if timer.is_expired(current_time) {
                expired.push((*socket_id, *timer_type));
            }
        }

        expired
    }

    /// Get time until next timer expiry (for sleep/poll optimization)
    pub fn next_expiry(&self) -> Option<u64> {
        let current_time = pit::get_system_time_ms() as u64;
        let timers = self.timers.lock();

        timers
            .values()
            .filter(|t| t.active)
            .map(|t| t.next_fire.saturating_sub(current_time))
            .min()
    }
}

/// Global timer manager instance
static TCP_TIMER_MANAGER: TcpTimerManager = TcpTimerManager::new();

/// Get the global timer manager
pub fn get_timer_manager() -> &'static TcpTimerManager {
    &TCP_TIMER_MANAGER
}

/// RFC 6298 constants
pub mod rfc6298 {
    /// Initial RTO value (1 second)
    pub const INITIAL_RTO: u32 = 1000;

    /// Minimum RTO value (1 second)
    pub const MIN_RTO: u32 = 1000;

    /// Maximum RTO value (60 seconds)
    pub const MAX_RTO: u32 = 60000;

    /// Clock granularity (10 milliseconds)
    pub const CLOCK_GRANULARITY: u32 = 10;

    /// Alpha for SRTT calculation (1/8 = 0.125)
    pub const ALPHA: u32 = 125; // Scaled by 1000

    /// Beta for RTTVAR calculation (1/4 = 0.25)
    pub const BETA: u32 = 250; // Scaled by 1000

    /// K factor for RTO calculation
    pub const K: u32 = 4;
}

/// RFC 5681 constants
pub mod rfc5681 {
    /// Initial congestion window (in MSS units)
    pub const INITIAL_CWND_MSS: u32 = 10;

    /// Initial slow start threshold (typically 65535 bytes)
    pub const INITIAL_SSTHRESH: u32 = 65535;

    /// Duplicate ACK threshold for fast retransmit
    pub const DUP_ACK_THRESHOLD: u8 = 3;

    /// Maximum retransmission attempts before giving up
    pub const MAX_RETRANSMIT_ATTEMPTS: u8 = 15;
}
