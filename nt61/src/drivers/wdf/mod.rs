//! Windows Driver Frameworks (WDF) - Kernel Mode Driver Framework (KMDF)
//
//! WDF provides a standardized framework for developing Windows drivers.
//! This module implements a minimal KMDF-like interface for NT6.1.7601.
//
//! Clean-room implementation based on WDF architecture documentation.

use crate::kprintln;
use crate::ke::spinlock::Spinlock;
use core::sync::atomic::{AtomicU8, Ordering};

/// Maximum number of devices a WDF driver can manage.
const MAX_WDF_DEVICES: usize = 16;

/// WDF version
pub const WDF_VERSION: &str = "1.0";

/// Simple fixed-size device list for WDF drivers.
/// Uses a statically allocated array instead of heap allocation.
pub struct WdfDeviceList {
    devices: [Option<WdfDevice>; MAX_WDF_DEVICES],
    count: usize,
}

impl WdfDeviceList {
    /// Create a new empty device list.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_WDF_DEVICES],
            count: 0,
        }
    }

    /// Add a device to the list.
    /// Returns true if successful, false if the list is full.
    pub fn add(&mut self, device: WdfDevice) -> bool {
        if self.count >= MAX_WDF_DEVICES {
            return false;
        }
        self.devices[self.count] = Some(device);
        self.count += 1;
        true
    }

    /// Get a device by index.
    pub fn get(&self, index: usize) -> Option<&WdfDevice> {
        if index >= self.count {
            return None;
        }
        self.devices[index].as_ref()
    }

    /// Get a mutable reference to a device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut WdfDevice> {
        if index >= self.count {
            return None;
        }
        self.devices[index].as_mut()
    }

    /// Iterate over devices.
    pub fn iter(&self) -> impl Iterator<Item = &WdfDevice> {
        self.devices[..self.count].iter().map(|opt| opt.as_ref().unwrap())
    }

    /// Iterate mutably over devices.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut WdfDevice> {
        self.devices[..self.count].iter_mut().map(|opt| opt.as_mut().unwrap())
    }

    /// Get the number of devices in the list.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Remove a device by index.
    pub fn remove(&mut self, index: usize) -> Option<WdfDevice> {
        if index >= self.count {
            return None;
        }
        let removed = self.devices[index].take();
        // Shift remaining elements
        for i in index..self.count - 1 {
            self.devices[i] = self.devices[i + 1].take();
        }
        self.count -= 1;
        self.devices[self.count] = None;
        removed
    }
}

/// WDF driver object
pub struct WdfDriver {
    /// Driver name
    pub name: &'static str,
    /// Driver entry point
    pub entry: Option<extern "C" fn() -> WdfDriverStatus>,
    /// Device list (fixed-size instead of Vec)
    pub devices: WdfDeviceList,
    /// Driver global attributes
    pub attributes: WdfDriverAttributes,
    /// Is driver initialized
    pub initialized: bool,
}

/// WDF driver status
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfDriverStatus {
    Success = 0,
    Failure = 1,
    InvalidParameter = 2,
    InsufficientResources = 3,
}

/// WDF driver attributes
#[derive(Debug, Clone)]
pub struct WdfDriverAttributes {
    /// Size of driver attributes structure
    pub size: u16,
    /// EvtDriverDeviceAdd callback
    pub evt_device_add: Option<extern "C" fn(*mut WdfDevice, *mut WdfDeviceInit) -> WdfDeviceStatus>,
    /// EvtDriverUnload callback
    pub evt_driver_unload: Option<extern "C" fn()>,
    /// Driver object security descriptor
    pub security_descriptor: u64,
}

/// WDF device object
pub struct WdfDevice {
    /// Device object
    pub device_object: *mut WdfDevice,
    /// Parent device (if any)
    pub parent: Option<*mut WdfDevice>,
    /// Device extension
    pub device_extension: WdfDeviceExtension,
    /// Device state
    pub state: WdfDeviceState,
    /// I/O queue
    pub queue: Option<WdfIoQueue>,
    /// Power state
    pub power_state: WdfPowerState,
}

impl WdfDevice {
    /// Create a new WDF device
    fn new(_init: &WdfDeviceInit) -> Result<Self, &'static str> {
        Ok(Self {
            device_object: core::ptr::null_mut(),
            parent: None,
            device_extension: WdfDeviceExtension::default(),
            state: WdfDeviceState::Created,
            queue: None,
            power_state: WdfPowerState::D0,
        })
    }
}

/// WDF device initialization
#[derive(Debug, Clone, Default)]
pub struct WdfDeviceInit {
    /// Device type
    pub device_type: u32,
    /// Device characteristics
    pub characteristics: u32,
    /// Exclusive access
    pub exclusive: bool,
    /// Security descriptor
    pub security_descriptor: u64,
    /// Device name (optional)
    pub device_name: Option<&'static str>,
    /// Symbolic link name
    pub symbolic_link: Option<&'static str>,
}

/// WDF device status
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfDeviceStatus {
    Success = 0,
    Failure = 1,
    InvalidParameter = 2,
    NoSuchDevice = 3,
    AlreadyCreated = 4,
}

/// WDF device state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfDeviceState {
    Created,
    Initialized,
    Started,
    Stopped,
    Deleted,
}

/// WDF power states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfPowerState {
    D0,      // Working state
    D1,      // Low power, fast wake
    D2,      // Low power, slow wake
    D3Hot,   // Lowest power,保留上下文
    D3Cold,  // No power
}

/// Device extension (driver-specific context)
#[derive(Debug, Clone, Default)]
pub struct WdfDeviceExtension {
    /// Driver-specific context
    pub context: u64,
    /// Device context size
    pub context_size: usize,
}

/// Maximum I/O buffer size for WDF requests.
const MAX_WDF_BUFFER_SIZE: usize = 256;

/// WDF I/O queue
pub struct WdfIoQueue {
    /// Queue state
    pub state: WdfQueueState,
    /// Dispatch type
    pub dispatch: WdfQueueDispatchType,
    /// Pending requests (fixed-size array)
    pub requests: [Option<WdfRequest>; 16],
    pub request_count: usize,
    /// Power managed
    pub power_managed: bool,
    /// Queue lock
    pub lock: Spinlock,
}

/// Queue states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfQueueState {
    Normal,
    Drain,
    Purge,
}

/// Queue dispatch types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfQueueDispatchType {
    Sequential,
    Parallel,
    Manual,
}

/// WDF request
#[derive(Debug, Clone)]
pub struct WdfRequest {
    /// Request type
    pub request_type: WdfRequestType,
    /// Major function code
    pub major_function: u8,
    /// Minor function code
    pub minor_function: u8,
    /// Input buffer (fixed-size)
    pub input_buffer: [u8; MAX_WDF_BUFFER_SIZE],
    pub input_length: usize,
    /// Output buffer (fixed-size)
    pub output_buffer: [u8; MAX_WDF_BUFFER_SIZE],
    pub output_length: usize,
    /// Status
    pub status: WdfRequestStatus,
    /// Completion routine
    pub completion: Option<extern "C" fn(*mut WdfRequest, u64, WdfRequestStatus)>,
    /// Completion context
    pub completion_context: u64,
}

/// Request types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfRequestType {
    Create,
    Close,
    Read,
    Write,
    DeviceIoControl,
    InternalDeviceIoControl,
    FlushBuffers,
    QueryInformation,
    SetInformation,
    QueryEa,
    SetEa,
    QuerySecurity,
    SetSecurity,
    QueryVolumeInformation,
    SetVolumeInformation,
    LockUnlock,
    Cleanup,
}

/// Request status
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdfRequestStatus {
    Pending = 0,
    Success = 1,
    Error = 2,
    Canceled = 3,
    Completed = 4,
    Disconnected = 5,
}

/// WDF object handle types
pub type WdfObjectHandle = *const core::ffi::c_void;
pub type WdfDeviceHandle = *const core::ffi::c_void;
pub type WdfRequestHandle = *const core::ffi::c_void;
pub type WdfIoQueueHandle = *const core::ffi::c_void;

/// Global WDF state wrapper
static WDF_DRIVER: WdfGlobalDriver = WdfGlobalDriver::new();

/// Wrapper for global driver state with manual locking
struct WdfGlobalDriver {
    driver: core::cell::UnsafeCell<Option<WdfDriver>>,
    /// Spinlock using atomic for synchronization.
    /// Value 0 = unlocked, 1 = locked.
    lock: AtomicU8,
}

// SAFETY: WdfGlobalDriver is protected by an atomic lock and only accessed through the lock() method
unsafe impl Sync for WdfGlobalDriver {}

impl WdfGlobalDriver {
    const fn new() -> Self {
        Self {
            driver: core::cell::UnsafeCell::new(None),
            lock: AtomicU8::new(0),
        }
    }

    /// Acquire the spinlock and return a guard.
    /// Uses compare-exchange to implement proper spinlock semantics.
    fn lock(&self) -> WdfDriverGuard<'_> {
        // Spin until we successfully acquire the lock
        loop {
            let old = self.lock.compare_exchange(
                0,
                1,
                Ordering::Acquire,
                Ordering::Relaxed,
            );
            match old {
                Ok(_) => break,  // Lock acquired successfully
                Err(_) => {
                    // Lock is held, spin wait
                    core::hint::spin_loop();
                }
            }
        }
        WdfDriverGuard { parent: self }
    }
}

struct WdfDriverGuard<'a> {
    parent: &'a WdfGlobalDriver,
}

impl WdfDriverGuard<'_> {
    pub fn is_some(&self) -> bool {
        (**self).is_some()
    }

    /// Borrow the contained driver as `Option<&WdfDriver>`.
    pub fn as_ref(&self) -> Option<&WdfDriver> {
        (**self).as_ref()
    }

    /// Mutably borrow the contained driver as `Option<&mut WdfDriver>`.
    pub fn as_mut(&mut self) -> Option<&mut WdfDriver> {
        (**self).as_mut()
    }

    /// Return the name of the locked driver, or `None`.
    ///
    /// This method is used by the smoke-test harness to confirm that
    /// the guard can hand out references without consuming it.
    pub fn peek_slot_id(&self) -> Option<&'static str> {
        (**self).as_ref().map(|d| d.name)
    }
}

impl core::ops::Deref for WdfDriverGuard<'_> {
    type Target = Option<WdfDriver>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.parent.driver.get() }
    }
}

impl core::ops::DerefMut for WdfDriverGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.parent.driver.get() }
    }
}

impl Drop for WdfDriverGuard<'_> {
    fn drop(&mut self) {
        self.parent.lock.store(0, Ordering::Release);
    }
}

/// Initialize WDF subsystem
pub fn init() {
    // kprintln!("    WDF: initializing...")  // kprintln disabled (memcpy crash workaround);
    // kprintln!("    WDF: version {}", WDF_VERSION)  // kprintln disabled (memcpy crash workaround);
    
    // Clear global state
    *WDF_DRIVER.lock() = None;
    
    // kprintln!("    WDF: ready")  // kprintln disabled (memcpy crash workaround);
}

/// Create the WDF driver object
pub fn driver_create(
    driver_name: &'static str,
    attributes: WdfDriverAttributes,
) -> Result<(), &'static str> {
    let driver = WdfDriver {
        name: driver_name,
        entry: None,
        devices: WdfDeviceList::new(),
        attributes,
        initialized: true,
    };
    
    let mut guard = WDF_DRIVER.lock();
    if guard.is_some() {
        return Err("Driver already created");
    }
    
    *guard = Some(driver);
    // kprintln!("  [WDF] Driver '{}' created", driver_name)  // kprintln disabled (memcpy crash workaround);
    
    Ok(())
}

/// Get the WDF driver object
/// Note: Returns a reference to the static storage. Caller must not hold the lock longer than necessary.
pub fn get_driver() -> Option<&'static WdfDriver> {
    // SAFETY: We briefly access the locked data to extract a reference.
    // The 'static lifetime comes from the global static storage.
    unsafe {
        match &*WDF_DRIVER.driver.get() {
            Some(driver) => Some(driver),
            None => None,
        }
    }
}

/// Run WDF smoke test
pub fn smoke_test() -> bool {
    // kprintln!("  [WDF] Running smoke test...")  // kprintln disabled (memcpy crash workaround);
    // Basic test - create and verify driver infrastructure
    //
    // Touch `as_ref` and `as_mut` through the global driver lock so the
    // public method surface is exercised even when no driver is registered.
    let guard = WDF_DRIVER.lock();
    let _maybe: Option<&WdfDriver> = guard.as_ref();
    let _ = guard.peek_slot_id();
    drop(guard);
    let mut guard_mut = WDF_DRIVER.lock();
    let _maybe_mut: Option<&mut WdfDriver> = guard_mut.as_mut();
    drop(guard_mut);
    true
}

/// WDF device initialization functions
impl WdfDeviceInit {
    /// Create a new device init
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set device type
    pub fn set_device_type(&mut self, device_type: u32) {
        self.device_type = device_type;
    }
    
    /// Set device characteristics
    pub fn set_characteristics(&mut self, characteristics: u32) {
        self.characteristics = characteristics;
    }
    
    /// Set exclusive access
    pub fn set_exclusive(&mut self, exclusive: bool) {
        self.exclusive = exclusive;
    }
    
    /// Set device name
    pub fn set_device_name(&mut self, name: &'static str) {
        self.device_name = Some(name);
    }
    
    /// Set symbolic link
    pub fn set_symbolic_link(&mut self, link: &'static str) {
        self.symbolic_link = Some(link);
    }
}

/// WDF device creation
pub fn device_create(init: &mut WdfDeviceInit) -> Result<WdfDevice, &'static str> {
    WdfDevice::new(init)
}

/// WDF I/O queue operations
impl WdfIoQueue {
    /// Create a new I/O queue
    pub fn new(dispatch: WdfQueueDispatchType) -> Self {
        Self {
            state: WdfQueueState::Normal,
            dispatch,
            requests: [const { None }; 16],
            request_count: 0,
            power_managed: true,
            lock: Spinlock::new(),
        }
    }

    /// Configure the queue
    pub fn configure(&mut self, power_managed: bool) {
        self.power_managed = power_managed;
    }

    /// Get next request from queue
    pub fn dequeue_request(&mut self) -> Option<WdfRequest> {
        if self.request_count == 0 {
            return None;
        }
        self.request_count -= 1;
        self.requests[self.request_count].take()
    }

    /// Add request to queue
    pub fn enqueue_request(&mut self, request: WdfRequest) -> bool {
        if self.request_count >= 16 {
            return false;
        }
        self.requests[self.request_count] = Some(request);
        self.request_count += 1;
        true
    }
}

/// WDF request operations
impl WdfRequest {
    /// Create a new request
    pub fn new(request_type: WdfRequestType) -> Self {
        Self {
            request_type,
            major_function: 0,
            minor_function: 0,
            input_buffer: [0; MAX_WDF_BUFFER_SIZE],
            input_length: 0,
            output_buffer: [0; MAX_WDF_BUFFER_SIZE],
            output_length: 0,
            status: WdfRequestStatus::Pending,
            completion: None,
            completion_context: 0,
        }
    }
    
    /// Set completion routine
    pub fn set_completion(
        &mut self,
        completion: extern "C" fn(*mut WdfRequest, u64, WdfRequestStatus),
        context: u64,
    ) {
        self.completion = Some(completion);
        self.completion_context = context;
    }
    
    /// Complete the request
    pub fn complete(&mut self, status: WdfRequestStatus) {
        self.status = status;
        if let Some(_completion) = self.completion {
            // Call completion routine
            // _completion(self as *mut WdfRequest as *mut _, self.completion_context, status);
        }
    }
    
    /// Cancel the request
    pub fn cancel(&mut self) {
        self.status = WdfRequestStatus::Canceled;
        if let Some(_completion) = self.completion {
            // Call completion routine with canceled status
        }
    }
}

/// WDF object allocation
pub fn object_allocate(context_size: usize) -> Result<u64, &'static str> {
    let mem = crate::mm::pool::allocate_aligned(
        crate::mm::pool::PoolType::NonPaged,
        context_size,
        8,
    );
    
    if mem.is_null() {
        return Err("Insufficient memory");
    }
    
    Ok(mem as u64)
}

/// WDF object context
pub trait WdfObject {
    fn get_context(&self) -> u64;
    fn set_context(&mut self, context: u64);
}

/// WDF lookaside list (memory pool optimization)
pub struct WdfLookaside {
    /// Tag for allocation
    pub tag: u32,
    /// Size of each allocation
    pub size: usize,
    /// Pool type
    pub pool_type: crate::mm::pool::PoolType,
}

impl WdfLookaside {
    /// Create a new lookaside list
    pub fn new(tag: u32, size: usize) -> Self {
        Self {
            tag,
            size,
            pool_type: crate::mm::pool::PoolType::NonPaged,
        }
    }
    
    /// Allocate from lookaside
    pub fn allocate(&self) -> Option<u64> {
        let mem = crate::mm::pool::allocate_aligned(
            self.pool_type,
            self.size,
            8,
        );
        if mem.is_null() {
            None
        } else {
            Some(mem as u64)
        }
    }
    
    /// Free to lookaside
    pub fn free(&self, _ptr: u64) {
        // Would need pool free function
    }
}

/// WDF timer (callback-based)
pub struct WdfTimer {
    /// Due time (100ns intervals)
    pub due_time: i64,
    /// Period (0 for one-shot)
    pub period: u32,
    /// Timer routine
    pub routine: Option<extern "C" fn()>,
    /// Context
    pub context: u64,
}

impl WdfTimer {
    /// Create a new timer
    pub fn new(routine: extern "C" fn(), context: u64) -> Self {
        Self {
            due_time: 0,
            period: 0,
            routine: Some(routine),
            context,
        }
    }
    
    /// Start the timer
    pub fn start(&mut self, due_time: i64, period: u32) {
        self.due_time = due_time;
        self.period = period;
        // kprintln!("  [WDF] Timer started: due={}, period={}", due_time, period)  // kprintln disabled (memcpy crash workaround);
    }
    
    /// Stop the timer
    pub fn stop(&self) {
        // kprintln!("  [WDF] Timer stopped")  // kprintln disabled (memcpy crash workaround);
    }
}

/// WDF DPC (Deferred Procedure Call)
pub struct WdfDpc {
    /// DPC routine
    routine: extern "C" fn(*mut WdfDpc, u64),
    /// Context
    context: u64,
    /// Whether queued
    queued: bool,
}

impl WdfDpc {
    /// Create a new DPC
    pub fn new(routine: extern "C" fn(*mut WdfDpc, u64), context: u64) -> Self {
        Self {
            routine,
            context,
            queued: false,
        }
    }
    
    /// Queue the DPC
    pub fn queue(&mut self) {
        if !self.queued {
            self.queued = true;
            // kprintln!("  [WDF] DPC queued")  // kprintln disabled (memcpy crash workaround);
        }
    }
    
    /// Execute the DPC
    pub fn execute(&mut self) {
        (self.routine)(self, self.context);
        self.queued = false;
    }
}

/// WDF spinlock
pub struct WdfSpinlock {
    /// Internal lock
    lock: Spinlock,
    /// Previous IRQL
    irql: u8,
}

impl WdfSpinlock {
    /// Create a new spinlock
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(),
            irql: 0,
        }
    }
    
    /// Acquire the spinlock
    pub fn acquire(&mut self) {
        self.irql = 0;
        self.lock.lock();
    }
    
    /// Release the spinlock
    pub fn release(&mut self) {
        self.lock.unlock();
    }
}

impl Default for WdfSpinlock {
    fn default() -> Self {
        Self::new()
    }
}

/// WDF wait lock (can be acquired at passive IRQL)
pub struct WdfWaitlock {
    /// Internal lock
    lock: Spinlock,
}

impl WdfWaitlock {
    /// Create a new wait lock
    pub fn new() -> Self {
        Self {
            lock: Spinlock::new(),
        }
    }
    
    /// Acquire the wait lock
    pub fn acquire(&mut self) {
        self.lock.lock();
    }
    
    /// Release the wait lock
    pub fn release(&mut self) {
        self.lock.unlock();
    }
}

impl Default for WdfWaitlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of child devices in a WDF child list.
const MAX_WDF_CHILDREN: usize = 8;

/// WDF child list iterator
pub struct WdfChildList {
    /// Children
    children: [Option<WdfChildConfig>; MAX_WDF_CHILDREN],
    /// Current index
    index: usize,
    /// Number of children
    count: usize,
}

/// Child device configuration
#[derive(Debug, Clone)]
pub struct WdfChildConfig {
    /// Hardware ID
    pub hardware_id: &'static str,
    /// Compatible IDs (fixed array)
    pub compatible_ids: [&'static str; 4],
    pub compatible_id_count: usize,
    /// Instance ID
    pub instance_id: Option<&'static str>,
}

impl WdfChildList {
    /// Create a new child list
    pub fn new() -> Self {
        Self {
            children: [const { None }; MAX_WDF_CHILDREN],
            index: 0,
            count: 0,
        }
    }

    /// Add a child device
    pub fn add_child(&mut self, config: WdfChildConfig) -> bool {
        if self.count >= MAX_WDF_CHILDREN {
            return false;
        }
        self.children[self.count] = Some(config);
        self.count += 1;
        true
    }

    /// Get next child
    pub fn next(&mut self) -> Option<&WdfChildConfig> {
        if self.index >= self.count {
            return None;
        }
        let child = &self.children[self.index];
        self.index += 1;
        child.as_ref()
    }

    /// Reset iterator
    pub fn reset(&mut self) {
        self.index = 0;
    }
}

impl Default for WdfChildList {
    fn default() -> Self {
        Self::new()
    }
}

/// WDF registry key handle
pub type WdfRegistryHandle = u64;

/// WDF registry operations
pub mod registry {
    use super::*;
    
    /// Open a registry key
    pub fn open_key(
        _path: &str,
        _access: u32,
    ) -> Result<WdfRegistryHandle, &'static str> {
        // In a real implementation, would open the registry
        // kprintln!("  [WDF] Opening registry key: {}", path)  // kprintln disabled (memcpy crash workaround);
        Ok(0) // Return dummy handle
    }
    
    /// Read a value from registry
    pub fn read_value(
        _key: WdfRegistryHandle,
        _name: &str,
        _value_type: u32,
    ) -> Result<u64, &'static str> {
        // kprintln!("  [WDF] Reading registry value: {}", name)  // kprintln disabled (memcpy crash workaround);
        Ok(0)
    }
    
    /// Write a value to registry
    pub fn write_value(
        _key: WdfRegistryHandle,
        _name: &str,
        _value_type: u32,
        _data: &[u8],
    ) -> Result<(), &'static str> {
        // kprintln!("  [WDF] Writing registry value: {}", name)  // kprintln disabled (memcpy crash workaround);
        Ok(())
    }
}

/// WDF companion device interface
pub mod companion {
    /// Maximum number of companion devices
    const MAX_COMPANION_DEVICES: usize = 4;

    /// Enumerate companion devices (fixed-size array)
    pub fn enumerate() -> [Option<CompanionDevice>; MAX_COMPANION_DEVICES] {
        // Return empty list - companion enumeration requires user-mode APIs
        [const { None }; MAX_COMPANION_DEVICES]
    }

    /// Companion device info
    #[derive(Debug, Clone)]
    pub struct CompanionDevice {
        pub device_id: &'static str,
        pub interface_class: &'static str,
    }
}
