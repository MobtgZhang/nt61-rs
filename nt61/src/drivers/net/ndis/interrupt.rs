//! Network Interrupt Handler and DPC (Deferred Procedure Call) Implementation
//
//! Implements interrupt-driven packet processing for network adapters.
//! Uses the kernel's DPC mechanism to schedule packet processing.
//
//! Clean-room implementation.

use crate::kprintln;
use crate::ke::sync::Spinlock;

/// NIC interrupt handler trait
pub trait NicInterruptHandler: Send + Sync {
    /// Handle an interrupt from this NIC
    /// Returns true if there was work to do
    fn on_interrupt(&mut self) -> bool;
    
    /// Enable interrupts for this NIC
    fn enable_interrupt(&mut self);
    
    /// Disable interrupts for this NIC
    fn disable_interrupt(&mut self);
    
    /// Get the interrupt vector for this NIC
    fn interrupt_vector(&self) -> u8;
}

/// DPC work item for network processing
#[derive(Debug, Clone)]
pub struct NetworkDpcWork {
    /// NIC index
    pub nic_index: usize,
    /// Work type
    pub work_type: NetworkWorkType,
}

/// Types of network work
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkWorkType {
    /// Packet received
    PacketReceived,
    /// Packet sent (TX complete)
    PacketSent,
    /// Link status change
    LinkChange,
    /// Configuration change
    ConfigChange,
    /// Error occurred
    Error,
}

/// Global network DPC state
static NETWORK_DPC_WORK: Spinlock<Vec<NetworkDpcWork>> = Spinlock::new(Vec::new());

/// Initialize network DPC subsystem
pub fn init() {
    // kprintln!("    Network DPC: initializing...")  // kprintln disabled (memcpy crash workaround);
    
    // Clear any pending work
    NETWORK_DPC_WORK.lock().clear();
    
    // kprintln!("    Network DPC: ready")  // kprintln disabled (memcpy crash workaround);
}

/// Queue DPC work for processing
pub fn queue_dpc_work(work: NetworkDpcWork) {
    let mut work_queue = NETWORK_DPC_WORK.lock();
    
    // Avoid duplicates for the same NIC
    if !work_queue.iter().any(|w| 
        w.nic_index == work.nic_index && w.work_type == work.work_type
    ) {
        work_queue.push(work);
        // kprintln!("  [NET DPC] Queued {:?} for NIC {}", work.work_type, work.nic_index)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Process queued DPC work
/// This should be called from a DPC or timer interrupt
pub fn process_dpc_work() {
    let mut work_queue = NETWORK_DPC_WORK.lock();
    
    if work_queue.is_empty() {
        return;
    }
    
    // kprintln!("  [NET DPC] Processing {} work items", work_queue.len())  // kprintln disabled (memcpy crash workaround);
    
    // Process each work item
    for work in work_queue.iter() {
        match work.work_type {
            NetworkWorkType::PacketReceived => {
                process_received_packets(work.nic_index);
            }
            NetworkWorkType::PacketSent => {
                process_tx_completion(work.nic_index);
            }
            NetworkWorkType::LinkChange => {
                handle_link_change(work.nic_index);
            }
            NetworkWorkType::ConfigChange => {
                handle_config_change(work.nic_index);
            }
            NetworkWorkType::Error => {
                handle_nic_error(work.nic_index);
            }
        }
    }
    
    // Clear processed work
    work_queue.clear();
}

/// Process received packets from a NIC
fn process_received_packets(nic_index: usize) {
    use crate::drivers::net;
    
    let mut buffer = [0u8; 2048];
    
    // Receive packets until none available
    let mut count = 0;
    while let Some(len) = net::nic_receive(
        net::NicType::VirtioNet, 
        nic_index, 
        &mut buffer
    ) {
        if len > 0 {
            // Process the packet through the network stack
            let packet = &buffer[..len];
            crate::netstack::process_packet(
                packet,
                net::NicType::VirtioNet,
                nic_index
            );
            count += 1;
        }
    }
    
    if count > 0 {
        // kprintln!("  [NET DPC] Processed {} packets from NIC {}", count, nic_index)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Process TX completion
fn process_tx_completion(nic_index: usize) {
    use crate::drivers::net;
    
    // Poll TX queue for completed packets
    if let Some(ref nic) = net::get_nic(nic_index) {
        // In a real implementation, this would call the NIC's TX completion handler
        let tx_count = net::get_tx_count(nic_index);
        // kprintln!("  [NET DPC] TX packets sent: {}", tx_count)  // kprintln disabled (memcpy crash workaround);
    }
}

/// Handle link status change
fn handle_link_change(nic_index: usize) {
    use crate::drivers::net;
    
    if let Some(ref nic) = net::get_nic(nic_index) {
        let link_up = net::is_link_up(nic_index);
        // kprintln!("  [NET DPC] NIC {} link status: {}", nic_index, if link_up { "UP" } else { "DOWN" })  // kprintln disabled (memcpy crash workaround);
        
        // Update network stack with new link status
        if link_up {
            // Trigger DHCP or address configuration
            // kprintln!("  [NET DPC] Link up - ready for network operations")  // kprintln disabled (memcpy crash workaround);
        } else {
            // kprintln!("  [NET DPC] Link down - network unavailable")  // kprintln disabled (memcpy crash workaround);
        }
    }
}

/// Handle configuration change
fn handle_config_change(nic_index: usize) {
    use crate::drivers::net;
    
    if let Some(ref nic) = net::get_nic(nic_index) {
        // kprintln!("  [NET DPC] NIC {} configuration changed", nic_index)  // kprintln disabled (memcpy crash workaround);
        
        // Re-read configuration
        let mac = net::get_mac(nic_index);
        if let Some(mac) = mac {
            // kprintln!("  [NET DPC]   MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",  // kprintln disabled (memcpy crash workaround)
//                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
}

/// Handle NIC error
fn handle_nic_error(nic_index: usize) {
    use crate::drivers::net;
    
    // kprintln!("  [NET DPC] NIC {} error detected", nic_index)  // kprintln disabled (memcpy crash workaround);
    
    // Log error details
    // In a real implementation, would read error counters from NIC
    
    // Check TX queue state
    let free_count = net::get_tx_free_count(nic_index);
    // kprintln!("  [NET DPC]   TX queue free: {}/256", free_count)  // kprintln disabled (memcpy crash workaround);
}

/// Register a NIC's interrupt handler
/// This is called during NIC initialization
pub fn register_nic_interrupt(nic_index: usize, vector: u8) {
    // kprintln!("  [NET DPC] Registered NIC {} on vector {}", nic_index, vector)  // kprintln disabled (memcpy crash workaround);
    
    // In a real implementation, would:
    // 1. Install ISR in IDT for this vector
    // 2. Set up APIC/LAPIC routing
    // 3. Enable interrupts on the NIC
}

/// Schedule DPC from interrupt context
/// This is called by the ISR to schedule work
pub fn schedule_dpc_from_isr(nic_index: usize, work_type: NetworkWorkType) {
    // Queue the work for DPC processing
    queue_dpc_work(NetworkDpcWork {
        nic_index,
        work_type,
    });
    
    // In a real implementation, would also:
    // 1. Request DPC dispatch from the kernel
    // 2. The DPC would then call process_dpc_work()
}

/// Get pending work count
pub fn get_pending_work_count() -> usize {
    NETWORK_DPC_WORK.lock().len()
}

/// Clear all pending work
pub fn clear_pending_work() {
    NETWORK_DPC_WORK.lock().clear();
}

/// Check if there's pending work
pub fn has_pending_work() -> bool {
    !NETWORK_DPC_WORK.lock().is_empty()
}
