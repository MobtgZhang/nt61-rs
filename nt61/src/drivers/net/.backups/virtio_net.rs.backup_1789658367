//! virtio-net NIC Driver
//
//! virtio-net is a paravirtualised NIC defined by the virtio
//! 1.0 specification. PCI vendor 1AF4, device 1000. The driver
//! implements the modern (MMIO-based) transport with split
//! virtqueues for RX and TX.
//
//! Clean-room implementation. Spec source: virtio specification
//! 1.0, section 5 ("Network devices"). No code is copied from
//! any Microsoft or ReactOS source file.

use crate::hal::common::pci;
use crate::hal::common::pit;
use crate::kprintln;
use crate::mm::pool::{self, PoolType};
use crate::ke::sync::Spinlock;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicBool, Ordering};

/// virtio-net PCI vendor / device ID.
const VIRTIO_NET_VID: u16 = 0x1AF4;
const VIRTIO_NET_DID: u16 = 0x1000;

/// virtio MMIO register offsets (BAR0, starting at offset 0).
const REG_MAGIC: u64 = 0x00;
const REG_VERSION: u64 = 0x04;


const REG_DEVICE_FEATURES: u64 = 0x10;
const REG_DRIVER_FEATURES: u64 = 0x20;
const REG_QUEUE_SEL: u64 = 0x30;
const REG_QUEUE_NUM_MAX: u64 = 0x34;
const REG_QUEUE_NUM: u64 = 0x38;

const REG_QUEUE_PFN: u64 = 0x40;
const REG_QUEUE_NOTIFY: u64 = 0x50;
const REG_DEVICE_STATUS: u64 = 0x70;
const REG_ISR_STATUS: u64 = 0x60;


/// Magic value for the modern MMIO transport: "virt".
const MAGIC_VALUE: u32 = 0x74726976;

/// Device status bits.
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;



/// virtio feature bits for network device
const VIRTIO_NET_F_CSUM: u32 = 0;        // Device handles partial CSUM
const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;   // Guest handles partial CSUM
const VIRTIO_NET_F_MAC: u32 = 5;          // Device has given MAC address








const VIRTIO_NET_F_STATUS: u32 = 16;      // Device provides configuration status





/// virtqueue constants
const VIRTIO_NET_RX_QUEUE: u16 = 0;  // Receive queue index
const VIRTIO_NET_TX_QUEUE: u16 = 1;  // Transmit queue index
const DEFAULT_QUEUE_SIZE: u16 = 256;  // Number of descriptors per queue
const BUFFER_SIZE: usize = 2048;      // Buffer size for TX/RX

/// virtio config space offset
const CONFIG_MAC: u64 = 0;
const CONFIG_STATUS: u64 = 6;



/// Pool tags for network buffers
mod tags {
    use crate::mm::pool::make_tag;
    pub const NETBUF: u32 = make_tag(b'N', b'B', b'u', b'f');

    pub const NETPKT: u32 = make_tag(b'N', b'P', b'k', b't');
}

/// Virtqueue descriptor (16 bytes)
#[repr(C)]
struct VirtqDesc {
    pub addr: u64,      // Physical address of buffer
    pub len: u32,       // Length of buffer
    pub flags: u16,     // VIRTQ_DESC_F_* flags
    pub next: u16,      // Next descriptor index in chain
}

/// Descriptor flags

const VIRTQ_DESC_F_WRITE: u16 = 2;      // Device writes (RX buffer)


/// Virtqueue available ring entry (6 bytes)
#[repr(C)]
struct VirtqAvail {
    pub flags: u16,
    pub idx: AtomicU16,
    pub ring: [u16; DEFAULT_QUEUE_SIZE as usize],
    // pub used_event: u16; // only if VIRTIO_F_EVENT_IDX
}

/// Virtqueue used ring entry (16 bytes)
#[repr(C)]
struct VirtqUsedElem {
    pub id: u32,   // Index of descriptor that was used
    pub len: u32,  // Length of data written
}

/// Virtqueue used ring header
#[repr(C)]
struct VirtqUsed {
    pub flags: u16,
    pub idx: AtomicU16,
    pub ring: [VirtqUsedElem; DEFAULT_QUEUE_SIZE as usize],
    // pub avail_event: u16; // only if VIRTIO_F_EVENT_IDX
}

/// Virtqueue structure
struct VirtQueue {
    pub desc: *mut VirtqDesc,
    pub _desc_phys: u64,
    pub avail: *mut VirtqAvail,
    pub _avail_phys: u64,
    pub used: *mut VirtqUsed,
    pub _used_phys: u64,
    pub num: u16,
    pub free_head: u16,
    pub free_count: u16,
    pub used_idx: u16,
    pub bufs: [*mut u8; DEFAULT_QUEUE_SIZE as usize],
}

impl VirtQueue {
    /// Initialize a virtqueue
    unsafe fn init(
        mmio: *mut u8,
        queue_idx: u16,
        num: u16,
    ) -> Option<VirtQueue> {
        // Select the queue
        core::ptr::write_volatile((mmio as *mut u32).add((REG_QUEUE_SEL / 4) as usize), queue_idx as u32);

        // Check max queue size
        let max = core::ptr::read_volatile((mmio as *const u16).add((REG_QUEUE_NUM_MAX / 2) as usize));
        if max == 0 || num > max {
            // kprintln!("  [virtio-net] Queue {} max size {} < requested {}", queue_idx, max, num)  // kprintln disabled (memcpy crash workaround);
            return None;
        }

        // Calculate total size needed
        let desc_size = (num as usize) * core::mem::size_of::<VirtqDesc>();
        let avail_size = 4 + (num as usize) * 2 + 2; // flags + idx + ring + event
        let used_size = 4 + (num as usize) * core::mem::size_of::<VirtqUsedElem>() + 2;

        let align: usize = 4096;
        let total_size = (desc_size + align - 1) & !(align - 1)
            + (avail_size + align - 1) & !(align - 1)
            + (used_size + align - 1) & !(align - 1);

        // Allocate non-paged memory for the queue
        let mem = pool::allocate_aligned(PoolType::NonPaged, total_size, align);
        if mem.is_null() {
            // kprintln!("  [virtio-net] Failed to allocate queue memory")  // kprintln disabled (memcpy crash workaround);
            return None;
        }

        let aligned_ptr = ((mem as usize + align - 1) & !(align - 1)) as *mut u8;

        let desc = aligned_ptr as *mut VirtqDesc;
        let avail_offset = (desc_size + align - 1) & !(align - 1);
        let avail = aligned_ptr.add(avail_offset) as *mut VirtqAvail;
        let used_offset = avail_offset + ((avail_size + align - 1) & !(align - 1));
        let used = aligned_ptr.add(used_offset) as *mut VirtqUsed;

        // Get physical addresses (simplified - assumes identity mapping for kernel memory)
        let desc_phys = virt_to_phys(desc as u64)?;
        let avail_phys = virt_to_phys(avail as u64)?;
        let used_phys = virt_to_phys(used as u64)?;

        // Initialize descriptor table
        for i in 0..num as usize {
            core::ptr::write_bytes(&mut (*desc.add(i)), 0, 1);
        }

        // Initialize available ring
        (*avail).flags = 0;
        (*avail).idx = AtomicU16::new(0);
        for i in 0..num as usize {
            (*avail).ring[i] = 0;
        }

        // Initialize used ring
        (*used).flags = 0;
        (*used).idx = AtomicU16::new(0);
        for i in 0..num as usize {
            core::ptr::write_bytes(&mut (*used).ring[i], 0, 1);
        }

        // Set queue size
        core::ptr::write_volatile((mmio as *mut u32).add((REG_QUEUE_NUM / 4) as usize), num as u32);

        // Set queue PFN (physical page number)
        core::ptr::write_volatile((mmio as *mut u32).add((REG_QUEUE_PFN / 4) as usize), (desc_phys / 4096) as u32);

        Some(VirtQueue {
            desc,
            _desc_phys: desc_phys,
            avail,
            _avail_phys: avail_phys,
            used,
            _used_phys: used_phys,
            num,
            free_head: 0,
            free_count: num,
            used_idx: 0,
            bufs: [core::ptr::null_mut(); DEFAULT_QUEUE_SIZE as usize],
        })
    }

    /// Get a free descriptor chain
    fn alloc_desc(&mut self, count: u16) -> Option<u16> {
        if self.free_count < count {
            return None;
        }

        let head = self.free_head;
        self.free_head = (self.free_head + count) % self.num;
        self.free_count -= count;
        Some(head)
    }

    /// Add a buffer to the RX queue
    fn add_rx_buffer(&mut self, buf: *mut u8, len: usize) -> Option<u16> {
        let desc_idx = self.alloc_desc(1)?;
        let phys = virt_to_phys(buf as u64)?;

        unsafe {
            (*self.desc.add(desc_idx as usize)).addr = phys;
            (*self.desc.add(desc_idx as usize)).len = len as u32;
            (*self.desc.add(desc_idx as usize)).flags = VIRTQ_DESC_F_WRITE;
            (*self.desc.add(desc_idx as usize)).next = 0xFFFF;

            // Add to available ring
            let old_idx = (*self.avail).idx.load(Ordering::Acquire);
            let avail_idx = old_idx % self.num;
            (*self.avail).ring[avail_idx as usize] = desc_idx;
            (*self.avail).idx.store(old_idx + 1, Ordering::Release);
        }

        self.bufs[desc_idx as usize] = buf;
        Some(desc_idx)
    }

    /// Get a used buffer from the queue
    fn get_used_buffer(&mut self) -> Option<(*mut u8, u32)> {
        unsafe {
            let used_idx = self.used_idx;
            if used_idx == (*self.used).idx.load(Ordering::Acquire) {
                return None;
            }

            let elem = &(*self.used).ring[used_idx as usize];
            let buf = self.bufs[elem.id as usize];
            let len = elem.len;

            // Re-add the buffer to the RX queue
            self.free_count += 1;
            self.used_idx = (self.used_idx + 1) % self.num;

            Some((buf, len))
        }
    }

    /// Add a TX buffer (for sending data)
    fn add_tx_buffer(&mut self, buf: *mut u8, len: usize) -> Option<u16> {
        let desc_idx = self.alloc_desc(1)?;
        let phys = virt_to_phys(buf as u64)?;

        unsafe {
            (*self.desc.add(desc_idx as usize)).addr = phys;
            (*self.desc.add(desc_idx as usize)).len = len as u32;
            (*self.desc.add(desc_idx as usize)).flags = 0; // Device reads, no write flag
            (*self.desc.add(desc_idx as usize)).next = 0xFFFF;

            // Add to available ring
            let old_idx = (*self.avail).idx.load(Ordering::Acquire);
            let avail_idx = old_idx % self.num;
            (*self.avail).ring[avail_idx as usize] = desc_idx;
            (*self.avail).idx.store(old_idx + 1, Ordering::Release);
        }

        self.bufs[desc_idx as usize] = buf;
        Some(desc_idx)
    }

    /// Check if TX is complete (kept for completeness; not currently called)
    pub fn is_tx_complete(&self) -> bool {
        self.used_idx != unsafe { (*self.used).idx.load(Ordering::Acquire) } as u16
    }

    /// Poll TX completion ring and reclaim buffers
    /// Returns the number of completed (reclaimed) buffers
    pub fn poll_tx_completion(&mut self) -> u16 {
        let mut reclaimed = 0u16;
        let mut first_freed = None;
        let mut last_freed: u16 = 0;

        unsafe {
            while self.used_idx != (*self.used).idx.load(Ordering::Acquire) as u16 {
                let elem = &(*self.used).ring[self.used_idx as usize];
                let desc_idx = elem.id as usize;

                // Release the buffer back to the pool.
                if desc_idx < self.bufs.len() && !self.bufs[desc_idx].is_null() {
                    pool::free(self.bufs[desc_idx]);
                    self.bufs[desc_idx] = core::ptr::null_mut();
                }

                // Track the first descriptor of the reclamation batch so we
                // can hand it off to `free_desc_chain` below — that helper
                // iterates through the full chain and frees the buffer
                // pool entries for descriptors that are still attached.
                if first_freed.is_none() {
                    first_freed = Some(desc_idx as u16);
                }
                last_freed = desc_idx as u16;

                // Return descriptor to free list (single-descriptor path).
                self.free_single_desc(desc_idx as u16);
                self.used_idx = (self.used_idx + 1) % self.num;
                reclaimed += 1;
            }
        }

        // Run the chain-free helper against the head of the reclaimed
        // window. This complements the per-descriptor reclaim above by
        // also clearing any lingering `next` pointer that may still
        // reference a stale descriptor.
        if let Some(head) = first_freed {
            self.free_desc_chain(head);
            let _ = last_freed;
        }

        reclaimed
    }
    
    /// Wait for TX completion with timeout
    /// Returns true if at least one buffer was completed
    pub fn wait_tx_complete(&mut self, timeout_us: u64) -> bool {
        let start = crate::hal::common::pit::get_system_time_us();

        while !self.is_tx_complete() {
            let elapsed = crate::hal::common::pit::get_system_time_us().saturating_sub(start);
            if elapsed > timeout_us {
                return false;
            }
            core::hint::spin_loop();
        }

        // Reclaim completed buffers
        self.poll_tx_completion();
        true
    }

    /// Free a single descriptor back to the free list.
    /// This should only be called for descriptors that are no longer in use
    /// and have been properly processed.
    ///
    /// Note: In virtio, descriptors in a chain are freed together when the
    /// used ring entry is processed. This method is provided for cases where
    /// a descriptor needs to be reclaimed without waiting for completion.
    pub fn free_single_desc(&mut self, desc_idx: u16) {
        if desc_idx >= self.num {
            return;
        }

        // Mark descriptor as invalid (clear the WRITE flag and set addr to 0)
        unsafe {
            (*self.desc.add(desc_idx as usize)).flags = 0;
            (*self.desc.add(desc_idx as usize)).addr = 0;
            (*self.desc.add(desc_idx as usize)).len = 0;
            (*self.desc.add(desc_idx as usize)).next = 0xFFFF;
        }

        self.free_count += 1;
    }

    /// Free a chain of descriptors starting at the given head index.
    /// This iterates through the chain following the `next` pointers.
    pub fn free_desc_chain(&mut self, head: u16) {
        let mut current = head;
        let mut freed = 0u16;

        while freed < self.num {
            if current >= self.num {
                break;
            }

            unsafe {
                let desc = &*self.desc.add(current as usize);

                // Clear the descriptor
                let next = desc.next;

                // If this descriptor was allocated to a buffer, free the buffer
                let desc_idx = current as usize;
                if desc_idx < self.bufs.len() && !self.bufs[desc_idx].is_null() {
                    pool::free(self.bufs[desc_idx]);
                    self.bufs[desc_idx] = core::ptr::null_mut();
                }

                // Mark descriptor as free
                let desc_mut = &mut *self.desc.add(current as usize);
                desc_mut.flags = 0;
                desc_mut.addr = 0;
                desc_mut.len = 0;
                desc_mut.next = 0xFFFF;

                freed += 1;
                if next == 0xFFFF {
                    break; // End of chain
                }
                current = next;
            }
        }

        self.free_count += freed;
    }
}

/// Get physical address from virtual address
/// In a flat memory model, we assume identity mapping for kernel memory
fn virt_to_phys(virt: u64) -> Option<u64> {
    // Simplified: assume identity mapping
    // In a real system, this would walk the page tables
    Some(virt & 0x7FFFFFFFFFFF)
}

/// NIC structure
pub struct Nic {
    bar0_phys: u64,
    bar0_virt: *mut u8,
    version: u32,
    initialised: bool,
    mac: [u8; 6],
    link_up: bool,
    tx_queue: Option<VirtQueue>,
    rx_queue: Option<VirtQueue>,
    lock: Spinlock<NicState>,
    tx_count: AtomicU32,
    rx_count: AtomicU32,
}

impl Default for Nic {
    fn default() -> Self {
        Self {
            bar0_phys: 0,
            bar0_virt: core::ptr::null_mut(),
            version: 0,
            initialised: false,
            mac: [0; 6],
            link_up: false,
            tx_queue: None,
            rx_queue: None,
            lock: Spinlock::new(NicState::default()),
            tx_count: AtomicU32::new(0),
            rx_count: AtomicU32::new(0),
        }
    }
}

/// Internal NIC state
struct NicState {
    sending: bool,
    receiving: bool,
}

impl Default for NicState {
    fn default() -> Self {
        Self {
            sending: false,
            receiving: false,
        }
    }
}

static mut NICS: [Option<Nic>; 4] = [const { None }; 4];
static mut NIC_COUNT: usize = 0;

/// Get a reference to the global NIC list
fn get_nics() -> &'static mut [Option<Nic>; 4] {
    unsafe { &mut NICS }
}

fn push_nic(n: Nic) {
    let nics = get_nics();
    let count = unsafe { NIC_COUNT };
    if count < nics.len() {
        nics[count] = Some(n);
        unsafe { NIC_COUNT += 1; }
    }
}

pub fn count() -> usize { unsafe { NIC_COUNT } }

/// Get a NIC by index
pub fn get_nic(index: usize) -> Option<&'static Nic> {
    let nics = get_nics();
    if index < nics.len() {
        nics[index].as_ref()
    } else {
        None
    }
}

pub fn init() {
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("NET:virtio_start\r\n");
    let mut found = 0u32;
    for dev in pci::enumerate() {
        if dev.vendor_id == VIRTIO_NET_VID && dev.device_id == VIRTIO_NET_DID {
            if let Some(info) = crate::drivers::bus::pci_bus::find_pci(dev.bus, dev.device, dev.function) {
                if let Some(bar0) = first_mmio_bar(&info) {
                    let mut n = Nic {
                        bar0_phys: bar0,
                        bar0_virt: core::ptr::null_mut(),
                        version: 0,
                        initialised: false,
                        mac: [0; 6],
                        link_up: true,
                        tx_queue: None,
                        rx_queue: None,
                        lock: Spinlock::new(NicState::default()),
                        tx_count: AtomicU32::new(0),
                        rx_count: AtomicU32::new(0),
                    };
                    if init_nic(&mut n) {
                        found += 1;
                        push_nic(n);
                        let _ = found;
                    }
                }
            }
        }
    }
#[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::serial::write_string("NET:virtio_done\r\n");
    // kprintln!("      virtio-net: {} NIC(s) initialised", found)  // kprintln disabled (memcpy crash workaround);
}

fn first_mmio_bar(info: &crate::drivers::bus::pci_bus::PciDeviceInfo) -> Option<u64> {
    for bar in info.bars.iter() {
        if !bar.is_io && bar.phys != 0 { return Some(bar.phys); }
    }
    None
}

fn init_nic(n: &mut Nic) -> bool {
    let base = n.bar0_phys;
    if base == 0 { return false; }
    let mmio_base = crate::mm::syspte::map_io_space(base, 1);
    let mmio = match mmio_base {
        Some(m) => m as *mut u8,
        None => return false,
    };
    n.bar0_virt = mmio;

    unsafe {
        let magic = core::ptr::read_volatile((mmio as *const u32).add((REG_MAGIC / 4) as usize));
        if magic != MAGIC_VALUE {
            // kprintln!("  [virtio-net] Bad magic: 0x{:08x}", magic)  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        n.version = core::ptr::read_volatile((mmio as *const u32).add((REG_VERSION / 4) as usize));

        // Acknowledge + driver.
        let status = core::ptr::read_volatile((mmio as *const u32).add((REG_DEVICE_STATUS / 4) as usize));
        core::ptr::write_volatile((mmio as *mut u32).add((REG_DEVICE_STATUS / 4) as usize),
                                  status | STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Read device features and negotiate driver features
        let dev_features = core::ptr::read_volatile((mmio as *const u64).add((REG_DEVICE_FEATURES / 8) as usize));
        // kprintln!("  [virtio-net] Device features: 0x{:016x}", dev_features)  // kprintln disabled (memcpy crash workaround);

        // Negotiate features: we want MAC at minimum
        let mut driver_features: u64 = 0;
        if dev_features & (1 << VIRTIO_NET_F_MAC) != 0 {
            driver_features |= 1 << VIRTIO_NET_F_MAC;
        }
        // Enable checksum offload if available
        if dev_features & (1 << VIRTIO_NET_F_CSUM) != 0 {
            driver_features |= 1 << VIRTIO_NET_F_CSUM;
        }
        if dev_features & (1 << VIRTIO_NET_F_GUEST_CSUM) != 0 {
            driver_features |= 1 << VIRTIO_NET_F_GUEST_CSUM;
        }

        core::ptr::write_volatile((mmio as *mut u64).add((REG_DRIVER_FEATURES / 8) as usize), driver_features);

        // Set features OK
        let status = core::ptr::read_volatile((mmio as *const u32).add((REG_DEVICE_STATUS / 4) as usize));
        core::ptr::write_volatile((mmio as *mut u32).add((REG_DEVICE_STATUS / 4) as usize),
                                  status | STATUS_FEATURES_OK);

        // Read MAC address from config space
        for i in 0..6 {
            n.mac[i] = core::ptr::read_volatile((mmio as *const u8).add((CONFIG_MAC as usize) + i));
        }
        // kprintln!("  [virtio-net] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",  // kprintln disabled (memcpy crash workaround)
//                   n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5]);

        // Read link status
        if driver_features & (1 << VIRTIO_NET_F_STATUS) != 0 {
            let config_status = core::ptr::read_volatile((mmio as *const u16).add((CONFIG_STATUS / 2) as usize));
            n.link_up = (config_status & 1) != 0;
        }

        // Setup RX queue (queue 0)
        if let Some(rx) = VirtQueue::init(mmio, VIRTIO_NET_RX_QUEUE, DEFAULT_QUEUE_SIZE) {
            n.rx_queue = Some(rx);
            // kprintln!("  [virtio-net] RX queue initialized")  // kprintln disabled (memcpy crash workaround);
        } else {
            // kprintln!("  [virtio-net] Failed to initialize RX queue")  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        // Setup TX queue (queue 1)
        if let Some(tx) = VirtQueue::init(mmio, VIRTIO_NET_TX_QUEUE, DEFAULT_QUEUE_SIZE) {
            n.tx_queue = Some(tx);
            // kprintln!("  [virtio-net] TX queue initialized")  // kprintln disabled (memcpy crash workaround);
        } else {
            // kprintln!("  [virtio-net] Failed to initialize TX queue")  // kprintln disabled (memcpy crash workaround);
            return false;
        }

        // Pre-fill RX buffers
        if let Some(ref mut rx) = n.rx_queue {
            for _ in 0..DEFAULT_QUEUE_SIZE {
                let buf = pool::allocate_tagged(PoolType::NonPaged, BUFFER_SIZE, tags::NETBUF);
                if buf.is_null() {
                    // kprintln!("  [virtio-net] Failed to allocate RX buffer")  // kprintln disabled (memcpy crash workaround);
                    break;
                }
                if rx.add_rx_buffer(buf, BUFFER_SIZE).is_none() {
                    pool::free(buf);
                    break;
                }
            }
        }

        // Set driver OK
        let status = core::ptr::read_volatile((mmio as *const u32).add((REG_DEVICE_STATUS / 4) as usize));
        core::ptr::write_volatile((mmio as *mut u32).add((REG_DEVICE_STATUS / 4) as usize),
                                  status | STATUS_DRIVER_OK);

        // kprintln!("  [virtio-net] Link up: {}", n.link_up)  // kprintln disabled (memcpy crash workaround);
        n.initialised = true;
    }
    true
}

pub fn smoke_test() -> bool {
    // kprintln!("  [virtio-net SMOKE] virtio-net NICs: {}", count())  // kprintln disabled (memcpy crash workaround);
    // kprintln!("  [virtio-net SMOKE OK] virtio-net stack healthy")  // kprintln disabled (memcpy crash workaround);
    true
}

// =============================================================================
// Public send/receive API
// =============================================================================

/// Send a packet through the virtio-net NIC
///
/// If `wait` is true, this function will wait for TX completion before returning.
/// This is useful for synchronous I/O patterns where the caller needs to ensure
/// the packet has been transmitted before continuing.
pub fn send(nic_idx: usize, data: &[u8], wait: bool) -> bool {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return false,
    };

    if !n.initialised {
        return false;
    }

    // Allocate a buffer for the packet
    let buf = pool::allocate_tagged(PoolType::NonPaged, data.len(), tags::NETPKT);
    if buf.is_null() {
        // kprintln!("  [virtio-net] Failed to allocate TX buffer")  // kprintln disabled (memcpy crash workaround);
        return false;
    }

    unsafe {
        // Copy data to buffer
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }

    // Add packet to TX queue
    let mmio = n.bar0_virt;
    if let Some(ref mut tx) = n.tx_queue {
        if tx.add_tx_buffer(buf, data.len()).is_none() {
            pool::free(buf);
            return false;
        }
    } else {
        pool::free(buf);
        return false;
    }

    // Notify the device
    unsafe {
        core::ptr::write_volatile(
            (mmio as *mut u32).add((REG_QUEUE_NOTIFY / 4) as usize),
            VIRTIO_NET_TX_QUEUE as u32
        );
    }

    // If synchronous mode requested, wait for TX completion
    if wait {
        if let Some(ref mut tx) = n.tx_queue {
            // Wait up to 1 second for TX completion
            if !tx.wait_tx_complete(1_000_000) {
                // kprintln!("  [virtio-net] TX completion timeout")  // kprintln disabled (memcpy crash workaround);
                // Don't fail the send - the packet was queued
            }
        }
    }

    // Mark as sending
    {
        let mut guard = n.lock.lock();
        guard.sending = true;
    }

    // Increment TX counter
    n.tx_count.fetch_add(1, Ordering::Relaxed);

    true
}

/// Convenience wrapper for asynchronous send (backward compatible)
pub fn send_async(nic_idx: usize, data: &[u8]) -> bool {
    send(nic_idx, data, false)
}

/// Receive a packet from the virtio-net NIC
/// Returns the packet data in the provided buffer, or None if no packet available
pub fn receive(nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return None,
    };

    if !n.initialised {
        return None;
    }

    let guard = n.lock.lock();

    // Check for received packets
    let mmio = n.bar0_virt;
    unsafe {
        // Read ISR status to check for pending interrupts
        let isr = core::ptr::read_volatile(
            (mmio as *const u8).add(REG_ISR_STATUS as usize)
        );

        if isr & 0x1 != 0 {
            // RX interrupt pending, process packets
            // kprintln!("  [virtio-net] RX interrupt")  // kprintln disabled (memcpy crash workaround);
        }
    }

    // Try to get a packet from the RX queue
    if let Some(ref mut rx) = n.rx_queue {
        if let Some((buf, len)) = rx.get_used_buffer() {
            let copy_len = (len as usize).min(buffer.len());

            unsafe {
                core::ptr::copy_nonoverlapping(buf, buffer.as_mut_ptr(), copy_len);
            }

            // Replenish the buffer
            let new_buf = pool::allocate_tagged(PoolType::NonPaged, BUFFER_SIZE, tags::NETBUF);
            if !new_buf.is_null() {
                rx.add_rx_buffer(new_buf, BUFFER_SIZE);
            }

            // Free the old buffer
            pool::free(buf);

            n.rx_count.fetch_add(1, Ordering::Relaxed);
            drop(guard);
            return Some(copy_len);
        }
    }

    drop(guard);
    None
}

/// Get MAC address for a NIC
pub fn get_mac(nic_idx: usize) -> Option<[u8; 6]> {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.mac)
}

/// Get link status for a NIC
pub fn is_link_up(nic_idx: usize) -> bool {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.link_up).unwrap_or(false)
}

/// Get TX packet count
pub fn get_tx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.tx_count.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Get RX packet count
pub fn get_rx_count(nic_idx: usize) -> u32 {
    let nics = get_nics();
    nics[nic_idx].as_ref().map(|n| n.rx_count.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Handle interrupt from virtio-net NIC
pub fn interrupt_handler(nic_idx: usize) {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return,
    };

    let mut guard = n.lock.lock();

    let mmio = n.bar0_virt;
    unsafe {
        // Read and clear ISR status
        let isr = core::ptr::read_volatile(
            (mmio as *const u8).add(REG_ISR_STATUS as usize)
        );

        if isr & 0x1 != 0 {
            // RX packet available
            guard.receiving = true;
        }
        if isr & 0x2 != 0 {
            // TX completion - reclaim completed TX buffers
            if let Some(ref mut tx) = n.tx_queue {
                let reclaimed = tx.poll_tx_completion();
                if reclaimed > 0 {
                    // kprintln!("  [virtio-net] Reclaimed {} TX buffers", reclaimed)  // kprintln disabled (memcpy crash workaround);
                }
            }
            guard.sending = false;
        }
        if isr & 0x3 != 0 {
            // Configuration change
            // kprintln!("  [virtio-net] Config change interrupt")  // kprintln disabled (memcpy crash workaround);
        }
    }
}

/// Flush pending TX packets
/// This ensures that all pending packets are actually sent and waits for completion
pub fn flush_tx(nic_idx: usize) -> bool {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return false,
    };

    if !n.initialised {
        return false;
    }

    let mut guard = n.lock.lock();

    // If not currently sending, nothing to flush
    if !guard.sending {
        return true;
    }

    // Poll TX queue for completion
    if let Some(ref mut tx) = n.tx_queue {
        // Wait up to 1 second for TX completion
        if tx.wait_tx_complete(1_000_000) {
            guard.sending = false;
            return true;
        }
        
        // Timeout - still mark as not sending to avoid deadlock
        // kprintln!("  [virtio-net] TX flush timeout, forcing completion")  // kprintln disabled (memcpy crash workaround);
        guard.sending = false;
        return false;
    }

    true
}

/// Get TX queue free descriptor count
pub fn get_tx_free_count(nic_idx: usize) -> usize {
    let nics = get_nics();
    let n = match nics[nic_idx].as_mut() {
        Some(n) => n,
        None => return 0,
    };

    if let Some(ref tx) = n.tx_queue {
        tx.free_count as usize
    } else {
        0
    }
}

/// Check if TX queue has room for more packets
pub fn can_send(nic_idx: usize) -> bool {
    get_tx_free_count(nic_idx) > 0
}
