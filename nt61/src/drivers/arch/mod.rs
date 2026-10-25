//! Architecture-specific driver support.
//!
//! This module contains driver code that is specific to a particular
//! CPU architecture. Code that is portable across architectures lives
//! in the parent `drivers` module.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::register_storage_backends;

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn register_storage_backends() {
    crate::rtl::klog::phase_trace_marker(710);
    #[cfg(target_arch = "aarch64")]
    aarch64::register_dispatch();
    #[cfg(target_arch = "riscv64")]
    riscv64::register_dispatch();
    #[cfg(target_arch = "loongarch64")]
    loongarch64::register_dispatch();
    crate::rtl::klog::phase_trace_marker(711);
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::kdcom;
#[cfg(target_arch = "x86_64")]
pub use x86_64::loader;
#[cfg(target_arch = "x86_64")]
pub use x86_64::net::rtl8139;

pub fn init_rtl8139() {
    #[cfg(target_arch = "x86_64")]
    x86_64::net::rtl8139::init();
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ();
    }
}

/// Initialize the legacy 8042 PS/2 controller when present.
pub fn init_i8042() {
    #[cfg(target_arch = "x86_64")]
    crate::drivers::input::i8042::init_hardware();
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ();
    }
}

/// Report 8042 controller smoke-test status.
pub fn i8042_smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    return crate::drivers::input::i8042::smoke_hardware();
    #[cfg(not(target_arch = "x86_64"))]
    true
}

/// Run the aggregate input-stack smoke test.
pub fn input_smoke_test(usb_keyboard_smoke: fn() -> bool, usb_mouse_smoke: fn() -> bool) -> bool {
    i8042_smoke_test() && usb_keyboard_smoke() && usb_mouse_smoke()
}

/// Translate an HID modifier byte into the shifted/unshifted state.
pub fn hid_shift_state(modifiers: u8) -> bool {
    #[cfg(target_arch = "x86_64")]
    return crate::hal::x86_64::keyboard_unified::hid_shift_state(modifiers);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = modifiers;
        false
    }
}

/// Emit a decoded HID keyboard character into the unified input queue.
pub fn hid_emit(usage: u8, shift: bool, caps_lock: bool) {
    #[cfg(target_arch = "x86_64")]
    crate::hal::x86_64::keyboard_unified::hid_emit(usage, shift, caps_lock);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (usage, shift, caps_lock);
    }
}

/// Enqueue a decoded keyboard character into the unified keyboard queue.
pub fn keyboard_enqueue_char(ch: u8) {
    #[cfg(target_arch = "x86_64")]
    crate::hal::keyboard::enqueue_char(ch);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = ch;
}

pub fn send_to_rtl8139(nic_idx: usize, data: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::net::rtl8139::send(nic_idx, data);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (nic_idx, data);
        false
    }
}

pub fn receive_from_rtl8139(nic_idx: usize, buffer: &mut [u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::net::rtl8139::receive(nic_idx, buffer);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (nic_idx, buffer);
        None
    }
}

pub fn count_rtl8139() -> usize {
    #[cfg(target_arch = "x86_64")]
    return x86_64::net::rtl8139::count();
    #[cfg(not(target_arch = "x86_64"))]
    0
}

pub fn receive_rtl8139_mac(nic_idx: usize) -> Option<[u8; 6]> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::net::rtl8139::get_mac(nic_idx);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = nic_idx;
        None
    }
}

pub fn net_smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::net::smoke::smoke_test();
    #[cfg(not(target_arch = "x86_64"))]
    true
}

pub fn has_legacy_vga_text_console() -> bool {
    #[cfg(target_arch = "x86_64")]
    return true;
    #[cfg(not(target_arch = "x86_64"))]
    false
}

pub fn init_storage_backends() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::serial::write_string("S:ata_start\r\n");
        x86_64::storage::ata::init();
        crate::hal::serial::write_string("S:ata_done\r\n");
        crate::hal::serial::write_string("S:atapi_start\r\n");
        x86_64::storage::atapi::init();
        crate::hal::serial::write_string("S:atapi_done\r\n");
        crate::hal::serial::write_string("S:ahci_start\r\n");
        init_ahci();
        crate::hal::serial::write_string("S:ahci_done\r\n");
        crate::hal::serial::write_string("S:nvme_start\r\n");
        x86_64::storage::nvme::init();
        crate::hal::serial::write_string("S:nvme_done\r\n");
        crate::hal::serial::write_string("S:scsi_start\r\n");
        x86_64::storage::scsi::init();
        crate::hal::serial::write_string("S:scsi_done\r\n");
        crate::hal::serial::write_string("S:ataport_start\r\n");
        x86_64::storage::ataport::init();
        crate::hal::serial::write_string("S:ataport_done\r\n");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn init_ahci() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::ahci_x86::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn ahci_smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ahci_x86::smoke_test();
    #[cfg(not(target_arch = "x86_64"))]
    true
}

pub fn ahci_count() -> usize {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ahci_x86::count();
    #[cfg(not(target_arch = "x86_64"))]
    0
}

pub fn ahci_first_disk_location() -> Option<(usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ahci_x86::first_disk_location();
    #[cfg(not(target_arch = "x86_64"))]
    None
}

pub fn ahci_read_sector(controller: usize, port: usize, lba: u32, buf: &mut [u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ahci_x86::read_sector(controller, port, lba, buf);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (controller, port, lba, buf);
        false
    }
}

pub fn ahci_write_sector(controller: usize, port: usize, lba: u32, buf: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ahci_x86::write_sector(controller, port, lba, buf);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (controller, port, lba, buf);
        false
    }
}

pub fn init_ata() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::ata::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn init_atapi() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::atapi::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn init_nvme() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::nvme::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn init_scsi() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::scsi::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn ata_write_sector(idx: usize, lba: u32, buf: &[u16; 256]) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ata::write_sector(idx, lba, buf);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (idx, lba, buf);
        false
    }
}

pub fn init_ataport() {
    #[cfg(target_arch = "x86_64")]
    x86_64::storage::ataport::init();
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn ataport_initialize(channel: u8) -> u32 {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ataport::ata_port_initialize(channel);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = channel;
        0
    }
}

pub fn ataport_read_sector(channel: u8, lba: u32, buf: &mut [u16; 256]) -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ataport::read_sector(channel, lba, buf);
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (channel, lba, buf);
        false
    }
}

pub fn ataport_smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::ataport::smoke_test();
    #[cfg(not(target_arch = "x86_64"))]
    true
}

pub fn storage_smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    return x86_64::storage::smoke::smoke_test();
    #[cfg(not(target_arch = "x86_64"))]
    true
}

/// Initialise drivers that are tied to machine-specific transports.
pub fn init_machine_specific_drivers() {
    #[cfg(target_arch = "x86_64")]
    {
        kdcom::init();
        x86_64::pshed::init();
        crate::drivers::volsnap::init();
    }
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

pub fn init_machine_specific_buses() {
    #[cfg(target_arch = "x86_64")]
    {
        crate::hal::serial::write_string("D:acpi_start\r\n");
        crate::drivers::bus::acpi_bus::init();
        crate::hal::serial::write_string("D:acpi_done\r\n");
        crate::hal::serial::write_string("D:usb_bus_start\r\n");
        crate::drivers::bus::usb_bus::init();
        crate::hal::serial::write_string("D:usb_bus_done\r\n");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// Run machine-specific driver smoke tests.
pub fn smoke_test() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::smoke::smoke_test()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}
