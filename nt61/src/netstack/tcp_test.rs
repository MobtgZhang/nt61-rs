//! TCP Protocol Stack Tests
//!
//! Tests for RFC 6298 retransmission timer and RFC 5681 congestion control

use super::tcp::*;
use super::tcp_timer;

/// Test RTT estimation according to RFC 6298
#[test]
fn test_rtt_estimation() {
    let mut tcb = TcpControlBlock::new();

    // First RTT measurement
    tcb.update_rtt(100);
    assert_eq!(tcb.srtt, 100);
    assert_eq!(tcb.rttvar, 50);

    // RTO should be SRTT + 4*RTTVAR = 100 + 4*50 = 300, but clamped to min 1000ms
    assert_eq!(tcb.rto, tcp_timer::rfc6298::MIN_RTO);

    // Second measurement with higher RTT
    tcb.update_rtt(200);
    // SRTT = (7*100 + 200)/8 = 112
    // RTTVAR = (3*50 + |112-200|)/4 = (150 + 88)/4 = 59
    assert!(tcb.srtt > 100 && tcb.srtt < 150);
    assert!(tcb.rttvar > 50);
}

/// Test slow start congestion control
#[test]
fn test_slow_start() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    // Initial cwnd should be 10 MSS
    assert_eq!(tcb.cwnd, 10 * mss);
    assert_eq!(tcb.congestion_state, CongestionState::SlowStart);

    // Simulate ACK for MSS bytes
    tcb.on_ack_slow_start(mss);

    // cwnd should increase by MSS
    assert_eq!(tcb.cwnd, 11 * mss);
}

/// Test congestion avoidance

#[test]
fn test_congestion_avoidance() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    // Set up for congestion avoidance
    tcb.cwnd = 20 * mss;
    tcb.ssthresh = 20 * mss;
    tcb.congestion_state = CongestionState::CongestionAvoidance;

    let old_cwnd = tcb.cwnd;

    // Simulate ACK
    tcb.on_ack_congestion_avoidance(mss);

    // cwnd should increase by approximately MSS*MSS/cwnd (linear growth)
    assert!(tcb.cwnd > old_cwnd);
    assert!(tcb.cwnd < old_cwnd + mss); // Less than MSS increase
}

/// Test fast retransmit trigger
#[test]
fn test_fast_retransmit() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    tcb.snd_una = 1000;
    tcb.snd_nxt = 2000;
    tcb.cwnd = 10 * mss;
    tcb.ssthresh = 65535;

    // First duplicate ACK
    tcb.on_duplicate_ack();
    assert_eq!(tcb.dup_acks, 1);
    assert_eq!(tcb.congestion_state, CongestionState::SlowStart);

    // Second duplicate ACK
    tcb.on_duplicate_ack();
    assert_eq!(tcb.dup_acks, 2);

    // Third duplicate ACK - should trigger fast retransmit
    tcb.on_duplicate_ack();
    assert_eq!(tcb.dup_acks, 3);
    assert_eq!(tcb.congestion_state, CongestionState::FastRecovery);

    // ssthresh should be set to half of cwnd (max 2*MSS)
    let expected_ssthresh = ((tcb.snd_nxt - tcb.snd_una) / 2).max(2 * mss);
    assert_eq!(tcb.ssthresh, expected_ssthresh);

    // cwnd should be ssthresh + 3*MSS
    assert_eq!(tcb.cwnd, tcb.ssthresh + 3 * mss);
}

/// Test timeout handling
#[test]
fn test_timeout() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    tcb.snd_una = 1000;
    tcb.snd_nxt = 2000;
    tcb.cwnd = 20 * mss;
    tcb.ssthresh = 65535;
    tcb.rto = 1000;
    tcb.retransmit_count = 0;

    let old_rto = tcb.rto;

    // Simulate timeout
    tcb.on_timeout();

    // RTO should double
    assert_eq!(tcb.rto, old_rto * 2);

    // Should enter slow start
    assert_eq!(tcb.congestion_state, CongestionState::SlowStart);
    assert_eq!(tcb.cwnd, mss);

    // ssthresh should be half of flight size
    let expected_ssthresh = ((2000 - 1000) / 2).max(2 * mss);
    assert_eq!(tcb.ssthresh, expected_ssthresh);

    // Retransmit count should increment
    assert_eq!(tcb.retransmit_count, 1);
    assert!(tcb.in_retransmit);
}

/// Test fast recovery exit
#[test]
fn test_fast_recovery_exit() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    tcb.snd_una = 1000;
    tcb.snd_nxt = 2000;
    tcb.cwnd = 20 * mss;
    tcb.ssthresh = 10 * mss;
    tcb.congestion_state = CongestionState::FastRecovery;
    tcb.recover = 2000;

    // ACK that covers recovery point
    tcb.on_ack(2000);

    // Should exit fast recovery
    assert_eq!(tcb.congestion_state, CongestionState::CongestionAvoidance);
    assert_eq!(tcb.cwnd, tcb.ssthresh);
    assert_eq!(tcb.dup_acks, 0);
}

/// Test send window calculation
#[test]
fn test_send_window() {
    let mut tcb = TcpControlBlock::new();

    tcb.snd_una = 1000;
    tcb.snd_nxt = 1500;
    tcb.cwnd = 10000;
    tcb.snd_wnd = 8000;

    // Effective window is min(cwnd, snd_wnd) = 8000
    // Flight size = snd_nxt - snd_una = 500
    // Available = 8000 - 500 = 7500
    assert_eq!(tcb.send_window(), 7500);
    assert!(tcb.can_send());

    // Fill the window
    tcb.snd_nxt = 9000;
    assert_eq!(tcb.send_window(), 0);
    assert!(!tcb.can_send());
}

/// Test RTO bounds according to RFC 6298
#[test]
fn test_rto_bounds() {
    let mut tcb = TcpControlBlock::new();

    // Very small RTT should result in minimum RTO
    tcb.update_rtt(10);
    assert!(tcb.rto >= tcp_timer::rfc6298::MIN_RTO);

    // Very large RTT should result in maximum RTO
    tcb.srtt = 100000;
    tcb.rttvar = 50000;
    tcb.update_rtt(100000);
    assert!(tcb.rto <= tcp_timer::rfc6298::MAX_RTO);
}

/// Test congestion window doesn't exceed limits
#[test]
fn test_cwnd_limits() {
    let mut tcb = TcpControlBlock::new();
    let mss = tcb.mss as u32;

    // Simulate many ACKs during slow start
    for _ in 0..100 {
        tcb.on_ack_slow_start(mss);
    }

    // cwnd should be reasonable (not overflow)
    assert!(tcb.cwnd > 10 * mss);
    assert!(tcb.cwnd < 1_000_000); // Reasonable upper bound
}

/// Test ACK processing with sequence number wrapping
#[test]
fn test_ack_with_wrapping() {
    let mut tcb = TcpControlBlock::new();

    // Set up near sequence number wrap
    tcb.snd_una = 0xFFFF_FF00;
    tcb.snd_nxt = 0xFFFF_FF50;

    // ACK that wraps around
    tcb.on_ack(0x0000_0010);

    // Should handle wrapping correctly
    assert_eq!(tcb.snd_una, 0x0000_0010);
    assert_eq!(tcb.dup_acks, 0);
}
