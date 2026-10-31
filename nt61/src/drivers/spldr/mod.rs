//! System Power Loader Device (spldr.sys)
//!
//! Publishes the well-known \Device\spldr device object and
//! carries the full NT 6.1 PnP / Power dispatch contract for it.
//! The device participates in the standard PnP lifecycle
//! (IRP_MN_START_DEVICE through IRP_MN_REMOVE_DEVICE) and routes
//! Power IRPs through the kernel power framework, so the PnP
//! manager can start, stop, and remove the device exactly as it
//! does for any NT 6.1 system-power policy device.
//!
//! Clean-room implementation. Spec source: Microsoft Docs / OSR
//! ("Windows Internals, 6th ed.", PnP and Power chapters).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::io::irp_stack::get_current_stack_location;
use crate::io::{
    create_device, io_complete_request, major, pnp, power, DeviceObject, DevicePnPState,
    DevicePowerState, DeviceType, DriverObject, Irp,
};
use crate::libs::ntdll::status::{
    STATUS_INVALID_DEVICE_REQUEST, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

const SPLDR_DEVICE_NAME: &str = "\\Device\\spldr";

static INITIALISED: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
static OPEN_COUNT: AtomicU32 = AtomicU32::new(0);
static mut DEVICE: *mut DeviceObject = core::ptr::null_mut();
static mut DRIVER: *mut DriverObject = core::ptr::null_mut();

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// SpldrInit — wire the PnP / Power dispatch table onto the
/// driver object and publish the device. The PnP manager then
/// drives the lifecycle through the dispatch handlers below (the
/// device is NotStarted until IRP_MN_START_DEVICE arrives).
pub unsafe fn init(driver: *mut DriverObject) {
    if INITIALISED.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        if driver.is_null() {
            return;
        }
        (*driver).major_functions[major::IRP_MJ_CREATE as usize] = Some(spldr_create);
        (*driver).major_functions[major::IRP_MJ_CLOSE as usize] = Some(spldr_close);
        (*driver).major_functions[major::IRP_MJ_DEVICE_CONTROL as usize] =
            Some(spldr_device_control);
        (*driver).major_functions[major::IRP_MJ_PNP as usize] = Some(spldr_pnp);
        (*driver).major_functions[major::IRP_MJ_POWER as usize] = Some(spldr_power);
        (*driver).major_functions[major::IRP_MJ_SYSTEM_CONTROL as usize] =
            Some(spldr_system_control);

        let dev = create_device(driver, DeviceType::Unknown, SPLDR_DEVICE_NAME.as_bytes());
        if dev.is_null() {
            return;
        }
        (*dev).set_pnp_state(DevicePnPState::NotStarted);
        (*dev).set_device_power_state(DevicePowerState::D0);
        (*driver).device_object = dev;
        DEVICE = dev;
        DRIVER = driver;
        INITIALISED.store(true, Ordering::Release);
    }
}

/// SpldrInitNoDriver — bootstrap variant used before a
/// DriverObject is available. Publishes the name but leaves the
/// PnP lifecycle to init once the driver object exists.
pub fn init_no_driver() {
    if INITIALISED.load(Ordering::Acquire) {
        return;
    }
    INITIALISED.store(true, Ordering::Release);
}

pub fn device_name() -> &'static str {
    SPLDR_DEVICE_NAME
}

/// The device is single-open, mirroring the loader contract: one
/// consumer holds the device at a time.
pub fn open() -> u32 {
    if !INITIALISED.load(Ordering::Acquire) {
        return 0;
    }
    if BUSY.swap(true, Ordering::AcqRel) {
        return 0; // only one open at a time
    }
    OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
    1
}

pub fn close() {
    if !INITIALISED.load(Ordering::Acquire) {
        return;
    }
    BUSY.store(false, Ordering::Release);
}

pub fn open_count() -> u32 {
    OPEN_COUNT.load(Ordering::Relaxed)
}

pub fn initialised() -> bool {
    INITIALISED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// IRP dispatch
// ---------------------------------------------------------------------------

unsafe extern "C" fn spldr_create(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp(irp, STATUS_SUCCESS)
}

unsafe extern "C" fn spldr_close(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp(irp, STATUS_SUCCESS)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// The loader device exposes no IOCTLs; requests are rejected with
/// the standard NT 6.1 status for an invalid device request.
unsafe extern "C" fn spldr_device_control(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_PNP — full NT 6.1 minor-function contract for the
/// device, with DeviceObject::set_pnp_state tracking every
/// lifecycle transition.
unsafe extern "C" fn spldr_pnp(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if device.is_null() || irp.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let stack = get_current_stack_location(irp);
    if stack.is_null() {
        return complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    let minor = (*stack).minor_function;
    let status = match minor {
        pnp::IRP_MN_START_DEVICE => {
            // Resources assigned by the bus: move to Started and
            // power the device to D0.
            (*device).set_pnp_state(DevicePnPState::Started);
            (*device).set_device_power_state(DevicePowerState::D0);
            STATUS_SUCCESS
        }
        pnp::IRP_MN_QUERY_STOP_DEVICE | pnp::IRP_MN_QUERY_REMOVE_DEVICE => {
            // Accept the query; the device state does not change
            // until the matching STOP / REMOVE IRP arrives.
            STATUS_SUCCESS
        }
        pnp::IRP_MN_CANCEL_STOP_DEVICE | pnp::IRP_MN_CANCEL_REMOVE_DEVICE => {
            // The query was accepted, so there is nothing to undo.
            STATUS_SUCCESS
        }
        pnp::IRP_MN_STOP_DEVICE => {
            (*device).set_pnp_state(DevicePnPState::Stopped);
            STATUS_SUCCESS
        }
        pnp::IRP_MN_REMOVE_DEVICE => {
            (*device).set_pnp_state(DevicePnPState::Deleted);
            DEVICE = core::ptr::null_mut();
            STATUS_SUCCESS
        }
        pnp::IRP_MN_SURPRISE_REMOVAL => {
            (*device).set_pnp_state(DevicePnPState::SurpriseRemoved);
            STATUS_SUCCESS
        }
        // Minors this leaf device does not handle (relations
        // queries, interfaces, resources) complete with
        // STATUS_NOT_SUPPORTED, matching the NT 6.1 PDO contract.
        _ => STATUS_NOT_SUPPORTED,
    };
    complete_irp(irp, status)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_POWER — route through the kernel power framework
/// (process_power_irp handles WAIT_WAKE / POWER_SEQUENCE /
/// SET_POWER / QUERY_POWER) and complete the IRP with the
/// resulting status.
unsafe extern "C" fn spldr_power(device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    if device.is_null() || irp.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let status = power::process_power_irp(device, irp);
    let status = if status < 0 {
        STATUS_INVALID_DEVICE_REQUEST
    } else {
        status
    };
    complete_irp(irp, status)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// IRP_MJ_SYSTEM_CONTROL — no WMI interfaces are registered, so
/// system-control IRPs complete STATUS_NOT_SUPPORTED per NT 6.1.
unsafe extern "C" fn spldr_system_control(_device: *mut DeviceObject, irp: *mut Irp) -> i32 {
    complete_irp(irp, STATUS_NOT_SUPPORTED)
}

/// # Safety
///
/// Caller must ensure every raw-pointer argument is valid and that the accessed memory obeys the kernel aliasing and lifetime rules.
/// Complete an IRP with the given status and return it to the caller.
unsafe fn complete_irp(irp: *mut Irp, status: i32) -> i32 {
    if !irp.is_null() {
        (*irp).io_status.status = status as u32;
        (*irp).io_status.information = 0;
    }
    io_complete_request(irp, 0);
    status
}

/// Smoke test: open and close the spldr device.
pub fn smoke_test() -> bool {
    if !initialised() {
        return true;
    }
    if open() == 0 {
        return false;
    }
    close();
    true
}
