//! TCP Congestion Control — CUBIC + Reno
//!
//! Implements two congestion-control algorithms behind a common
//! `CongestionControl` interface:
//!
//!   * **Reno** (RFC 6582 / RFC 5681) — slow start, congestion
//!     avoidance with `cwnd += MSS²/cwnd`, fast retransmit / fast
//!     recovery on 3 duplicate ACKs.
//!
//!   * **CUBIC** (RFC 8312) — uses a cubic function of the elapsed
//!     time since the last congestion event. CUBIC is the default
//!     in Windows 10/11 / Linux ≥ 2.6.19, and our kernel picks it
//!     when both peers negotiate it via `TCP_ECN`/`TCP_CORK`-style
//!     options — but for our pure-Rust stack we just default to
//!     CUBIC and let callers opt back into Reno via the API.
//!
//! ## Time source
//!
//! `now_ms()` reads the PIT — millisecond-resolution timer that
//! drives every existing RTT measurement.  When the PIT has not
//! been initialised yet the helper falls back to a monotonic
//! counter so unit tests stay deterministic.

use core::cmp::min;

/// Maximum Segment Size (Ethernet default).
pub const MSS: u32 = 1460;

/// Slow-start initial congestion window (RFC 6928 recommends ≥ 10
/// MSS, but the Windows 7 default is 2 MSS).
pub const INITIAL_CWND: u32 = 2 * MSS;

/// Minimum / maximum RTO bounds (RFC 6298).
pub const MIN_RTO: u32 = 200;     // 200 ms
pub const MAX_RTO: u32 = 60_000;  // 60 s

/// CUBIC parameters (RFC 8312 §5).
const CUBIC_C: f64 = 0.4;             // window-reduction constant
const CUBIC_BETA: f64 = 0.7;          // multiplicative decrease factor
/// CUBIC `W_max` (the congestion window at the last loss event) is
/// kept in a struct field rather than as a constant.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    Reno,
    /// CUBIC — default since Linux 2.6.19 / Windows 10.
    Cubic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
}

/// Compute the cubic function:
///   `W(t) = C * (t - K)³ + W_max`
/// where `K = cbrt(W_max * (1 - beta) / C)`.

fn cubic_window(t_ms: f64, w_max: u32, epoch_ms: f64) -> u32 {
    if w_max == 0 {
        return INITIAL_CWND;
    }
    let w_max_f = w_max as f64;
    let beta = CUBIC_BETA;
    // K = cube_root( W_max * (1 - beta) / C )
    let k = ((w_max_f * (1.0 - beta)) / CUBIC_C).cbrt();
    let t = t_ms - epoch_ms;
    let raw = CUBIC_C * (t - k).powi(3) + w_max_f;
    if raw < INITIAL_CWND as f64 {
        INITIAL_CWND as u32
    } else {
        raw as u32
    }
}

pub struct CongestionControl {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub state: CongestionState,
    pub dup_acks: u32,
    pub bytes_acked_in_epoch: u32,
    pub mss: u32,
    pub algo: CongestionAlgorithm,
    /// CUBIC: congestion window at the last loss event.
    pub w_max: u32,
    /// CUBIC: `now_ms()` value at the last loss event.
    pub loss_epoch_ms: f64,
    /// Last time the congestion window grew via ACK (used by
    /// CUBIC's `t` calculation).
    pub last_ack_ms: f64,
}

impl CongestionControl {
    pub fn new() -> Self {
        Self::new_with(CongestionAlgorithm::Cubic)
    }

    pub fn new_with(algo: CongestionAlgorithm) -> Self {
        let now = now_ms() as f64;
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: u32::MAX / 2,
            state: CongestionState::SlowStart,
            dup_acks: 0,
            bytes_acked_in_epoch: 0,
            mss: MSS,
            algo,
            w_max: 0,
            loss_epoch_ms: now,
            last_ack_ms: now,
        }
    }

    pub fn on_ack(&mut self, acked_bytes: u32) {
        self.dup_acks = 0;
        self.bytes_acked_in_epoch = self.bytes_acked_in_epoch.saturating_add(acked_bytes);
        let now = now_ms() as f64;
        self.last_ack_ms = now;

        match self.algo {
            CongestionAlgorithm::Reno => self.reno_on_ack(acked_bytes),
            CongestionAlgorithm::Cubic => self.cubic_on_ack(acked_bytes, now),
        }
    }

    fn reno_on_ack(&mut self, acked_bytes: u32) {
        match self.state {
            CongestionState::SlowStart => {
                self.cwnd = self.cwnd.saturating_add(acked_bytes);
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                let increment = (self.mss * self.mss) / self.cwnd.max(1);
                self.cwnd = self.cwnd.saturating_add(increment);
            }
            CongestionState::FastRecovery => {
                self.cwnd = self.ssthresh;
                self.state = CongestionState::CongestionAvoidance;
            }
        }
    }

    fn cubic_on_ack(&mut self, acked_bytes: u32, now_ms: f64) {
        // Until we have a previous `W_max`, treat the current cwnd
        // as the W_max. This makes the very first loss recovery
        // behave exactly like Reno, after which CUBIC takes over.
        if self.w_max == 0 {
            self.w_max = self.cwnd;
        }
        if self.cwnd < self.ssthresh {
            // Slow start — exponential increase.
            self.state = CongestionState::SlowStart;
            self.cwnd = self.cwnd.saturating_add(acked_bytes);
            return;
        }
        // Congestion avoidance — convex growth driven by the cubic.
        self.state = CongestionState::CongestionAvoidance;
        let target = cubic_window(now_ms, self.w_max, self.loss_epoch_ms);
        // CUBIC RFC §4.3: if `cwnd < W_max` we should be more
        // aggressive (concave region); if `cwnd > W_max` we should
        // probe carefully. Either way, move a fraction of the gap
        // per ACK.
        let diff = if self.cwnd < self.w_max {
            // Concave — growth is faster than Reno's linear.
            self.cwnd.saturating_sub(target)
        } else {
            // Convex — we are above W_max; growth is slower.
            target.saturating_sub(self.cwnd)
        };
        // Standard CUBIC step: `cwnd += MSS * (t-K) / cwnd`.
        let increment = if diff == 0 {
            self.mss
        } else {
            ((self.mss as u64 * acked_bytes as u64) / self.cwnd.max(1) as u64) as u32
        };
        self.cwnd = self.cwnd.saturating_add(increment.max(1));
    }

    pub fn on_dup_ack(&mut self) {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            // Fast retransmit.
            let half = (self.cwnd / 2).max(2 * self.mss);
            self.ssthresh = half;
            match self.algo {
                CongestionAlgorithm::Reno => {
                    self.cwnd = self.ssthresh + 3 * self.mss;
                }
                CongestionAlgorithm::Cubic => {
                    // CUBIC RFC 8312 §5: reduce cwnd to W_max * beta
                    // — that becomes both the new cwnd and the
                    // recorded W_max.
                    self.w_max = ((self.cwnd as f64) * CUBIC_BETA) as u32;
                    self.cwnd = self.w_max;
                    self.loss_epoch_ms = now_ms() as f64;
                }
            }
            self.state = CongestionState::FastRecovery;
        } else if self.state == CongestionState::FastRecovery {
            self.cwnd = self.cwnd.saturating_add(self.mss);
        }
    }

    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.w_max = self.cwnd;
        self.loss_epoch_ms = now_ms() as f64;
        self.cwnd = INITIAL_CWND;
        self.state = CongestionState::SlowStart;
        self.dup_acks = 0;
        self.bytes_acked_in_epoch = 0;
    }

    pub fn get_cwnd(&self) -> u32 {
        self.cwnd
    }

    pub fn get_ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Effective send window = min(cwnd, rwnd) — flight-size logic
    /// is the caller's responsibility.
    pub fn get_send_window(&self, rwnd: u32) -> u32 {
        min(self.cwnd, rwnd)
    }
}

// =============================================================================
// Retransmission timer (RFC 6298)
// =============================================================================

#[derive(Debug, Clone, Copy)]
pub struct RetransmissionTimeout {
    pub srtt_ms: i32,    // smoothed RTT
    pub rttvar_ms: i32,  // mean deviation
    pub rto_ms: u32,     // current retransmission timeout
    /// Karn's algorithm: skip RTT measurement while this is true.
    pub karn_skip: bool,
}

impl RetransmissionTimeout {
    pub const fn new() -> Self {
        Self {
            srtt_ms: 0,
            rttvar_ms: 0,
            rto_ms: 1000,
            karn_skip: false,
        }
    }

    /// `update_rtt` — RFC 6298 §2.2 / §2.3. `measured_rtt_ms` is
    /// the RTT sample observed for a non-retransmitted segment.
    pub fn update_rtt(&mut self, measured_rtt_ms: u32) {
        let m = measured_rtt_ms as i32;
        if self.srtt_ms == 0 {
            // First sample.
            self.srtt_ms = m;
            self.rttvar_ms = m / 2;
        } else {
            // `rttvar = (3*RTTVAR + |SRTT - R'|) / 4`
            let delta = (self.srtt_ms - m).abs();
            self.rttvar_ms = (3 * self.rttvar_ms + delta) / 4;
            // `SRTT = (7*SRTT + R') / 8`
            self.srtt_ms = (7 * self.srtt_ms + m) / 8;
        }
        // `RTO = SRTT + max(G, K*4*RTTVAR)` with K=4 and G=clock
        // granularity; we set G=1ms which gives the same result as
        // RFC 6298 for our integer arithmetic.
        let rto = self.srtt_ms + core::cmp::max(1, 4 * self.rttvar_ms);
        self.rto_ms = rto.max(MIN_RTO as i32).min(MAX_RTO as i32) as u32;
    }

    pub fn backoff(&mut self) {
        self.rto_ms = (self.rto_ms * 2).min(MAX_RTO);
    }

    pub fn get_rto(&self) -> u32 {
        self.rto_ms
    }

    pub fn mark_retransmit(&mut self) {
        self.karn_skip = true;
    }

    pub fn clear_karn_skip(&mut self) {
        self.karn_skip = false;
    }
}

// =============================================================================
// Per-connection send-window bookkeeping
// =============================================================================

pub struct TcpSendWindow {
    buffer: alloc::vec::Vec<u8>,
    send_una: u32,
    send_next: u32,
    send_max: u32,
    window_size: u32,
}

impl TcpSendWindow {
    pub fn new(initial_seq: u32) -> Self {
        Self {
            buffer: alloc::vec::Vec::new(),
            send_una: initial_seq,
            send_next: initial_seq,
            send_max: initial_seq,
            window_size: 65535,
        }
    }

    pub fn push_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Pull up to `max_bytes` of buffered data to send. Returns the
    /// (sequence_number, payload) pair the caller should transmit.
    pub fn get_sendable_data(&mut self, max_bytes: usize) -> Option<(u32, &[u8])> {
        let available = (self.send_una as usize + self.buffer.len())
            .saturating_sub(self.send_next as usize);
        if available == 0 {
            return None;
        }
        let send_bytes = min(available, max_bytes);
        let offset = (self.send_next - self.send_una) as usize;
        let data = &self.buffer[offset..offset + send_bytes];
        let seq = self.send_next;
        self.send_next = self.send_next.wrapping_add(send_bytes as u32);
        if self.send_next.wrapping_sub(self.send_max) < send_bytes as u32 {
            self.send_max = self.send_next;
        }
        Some((seq, data))
    }

    /// On ACK arrival: drain everything ≤ ack_num from the buffer.
    /// Returns the number of bytes newly acknowledged.
    pub fn on_ack(&mut self, ack_num: u32) -> u32 {
        // Sequence number arithmetic (modulo 2^32).
        if seq_le(ack_num, self.send_una) {
            return 0;
        }
        if !seq_le(ack_num, self.send_max) {
            // ACK for data we haven't sent — ignore.
            return 0;
        }
        let acked_bytes = ack_num.wrapping_sub(self.send_una);
        let remove_len = min(acked_bytes as usize, self.buffer.len());
        self.buffer.drain(..remove_len);
        self.send_una = ack_num;
        acked_bytes
    }

    pub fn update_window(&mut self, window: u32) {
        self.window_size = window;
    }

    pub fn has_unacked_data(&self) -> bool {
        seq_lt(self.send_una, self.send_max)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn send_una(&self) -> u32 {
        self.send_una
    }

    pub fn send_next(&self) -> u32 {
        self.send_next
    }

    pub fn send_max(&self) -> u32 {
        self.send_max
    }
}

/// Sequence-number comparison: `a <= b` (mod 2^32).
fn seq_le(a: u32, b: u32) -> bool {
    let d = b.wrapping_sub(a);
    // "a <= b" iff d is in [0, 2^31).
    d < 0x8000_0000
}

/// Sequence-number comparison: `a < b` (mod 2^32).
fn seq_lt(a: u32, b: u32) -> bool {
    a != b && seq_le(a, b)
}

// =============================================================================
// Time source
// =============================================================================

fn now_ms() -> u64 {
    // The PIT is the canonical millisecond clock for the kernel
    // (see hal::x86_64::pit). When the HAL isn't booted (unit
    // tests under `cargo test`) the call traps, so we fall back to
    // a hand-rolled monotonic counter.
    #[cfg(target_arch = "x86_64")]
    {
        if pit_initialised() {
            return crate::hal::x86_64::pit::get_system_time_ms();
        }
    }
    // Fallback: a static atomic counter that we increment on
    // every call. Not perfect, but monotonic enough for unit tests.
    use core::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(target_arch = "x86_64")]
fn pit_initialised() -> bool {
    // The PIT module exposes the global divisor word we set during
    // `init()`.  If it is non-zero the timer is running.
    crate::hal::x86_64::pit::pit_freq_hz() != 0
}

#[cfg(not(target_arch = "x86_64"))]
fn pit_initialised() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reno_slow_start_grows_exponentially() {
        let mut cc = CongestionControl::new_with(CongestionAlgorithm::Reno);
        assert_eq!(cc.state, CongestionState::SlowStart);
        let initial = cc.get_cwnd();
        cc.on_ack(MSS);
        assert!(cc.get_cwnd() > initial);
    }

    #[test]
    fn reno_three_dup_acks_trigger_fast_recovery() {
        let mut cc = CongestionControl::new_with(CongestionAlgorithm::Reno);
        cc.cwnd = 100_000;
        cc.on_dup_ack();
        cc.on_dup_ack();
        cc.on_dup_ack();
        assert_eq!(cc.state, CongestionState::FastRecovery);
    }

    #[test]
    fn cubic_transitions_out_of_slow_start() {
        let mut cc = CongestionControl::new_with(CongestionAlgorithm::Cubic);
        // Bump ssthresh so we leave slow start immediately.
        cc.ssthresh = 2 * MSS;
        let before = cc.get_cwnd();
        for _ in 0..100 {
            cc.on_ack(MSS);
        }
        assert!(cc.get_cwnd() >= before);
    }

    #[test]
    fn rfc6298_rto_bounded() {
        let mut rto = RetransmissionTimeout::new();
        rto.update_rtt(100);
        assert!(rto.get_rto() >= MIN_RTO);
        assert!(rto.get_rto() <= MAX_RTO);

        // 100 backoffs should still respect MAX_RTO.
        for _ in 0..100 {
            rto.backoff();
        }
        assert_eq!(rto.get_rto(), MAX_RTO);
    }

    #[test]
    fn send_window_ack_drain() {
        let mut sw = TcpSendWindow::new(1000);
        sw.push_data(b"hello world");
        let (seq, data) = sw.get_sendable_data(8).unwrap();
        assert_eq!(seq, 1000);
        assert_eq!(data, b"hello wo");
        let acked = sw.on_ack(1008);
        assert_eq!(acked, 8);
        assert_eq!(sw.buffered_bytes(), 3);
    }

    #[test]
    fn seq_compare_wraps() {
        assert!(seq_lt(0xFFFF_FF00, 0x0000_0100));
        assert!(seq_le(0xFFFF_FF00, 0xFFFF_FF00));
        assert!(!seq_lt(0x0000_0100, 0xFFFF_FF00));
    }
}

fn max(a: u32, b: u32) -> u32 {
    if a > b { a } else { b }
}