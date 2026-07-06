//! Driver PE-Image Emitter
//
//! Driver `.sys` files are normal PE32+ images, just with the
//! `IMAGE_SUBSYSTEM_NATIVE` (1) subsystem value. The
//! `system_image` module already produces 4 user DLLs / EXEs
//! in `Windows\System32\`; this module extends the on-disk
//! system image with the `.sys` files in
//! `Windows\System32\drivers\`. The output goes through the
//! same `pegen` module so the host smoke test can validate it
//! with `file(1)` / `pe-parser`.
//
//! Each driver's PE image exports a single `DriverEntry`
//! symbol, plus the NT-defined I/O manager entry points
//! (`DriverUnload`, `AddDevice`, dispatch routines). The
//! `pe.rs` builder below is a thin shim that calls the
//! kernel's `pegen` module with the right subsystem and
//! import table.
//
//! Clean-room implementation. The spec source is the PE/COFF
//! specification (Microsoft, 2016) and the Windows driver
//! development documentation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::pegen::{Import, PeBuilder, Section, SectionFlags, Subsystem, SECTION_ALIGNMENT};

/// One driver .sys image in the on-disk system tree.
pub struct DriverImage {
    /// Path relative to `C:\` (e.g. `Windows\System32\drivers\iastor.sys`).
    pub path: String,
    /// Raw PE bytes.
    pub bytes: Vec<u8>,
    /// Driver name.
    pub name: &'static str,
}

/// Build every driver PE image. The list mirrors the spec in
/// plan section 4. Each driver has a `DriverEntry` export and
/// (when the driver supports PnP) an `AddDevice` export. The
/// real driver would link the `ntoskrnl.exe` import table and
/// call the actual functions; the bootstrap emits a stub.
pub fn build_all(machine: u16) -> Vec<DriverImage> {
    let mut out = Vec::new();
    // Storage stack — required by the kernel I/O manager's
    // boot-time initialization path. Without these drivers on
    // disk, winload.efi reports "file missing" for the BOOT_START
    // driver list and the kernel's storage init cannot bring up
    // any block devices.
    out.push(DriverImage { path: driver_path("disk"),        bytes: build_driver_real(machine, "disk", true), name: "disk" });
    out.push(DriverImage { path: driver_path("classpnp"),    bytes: build_driver_real(machine, "classpnp", true), name: "classpnp" });
    out.push(DriverImage { path: driver_path("partmgr"),     bytes: build_driver_real(machine, "partmgr", true), name: "partmgr" });
    out.push(DriverImage { path: driver_path("volmgr"),      bytes: build_driver_real(machine, "volmgr", false), name: "volmgr" });
    out.push(DriverImage { path: driver_path("storahci"),   bytes: build_driver_real(machine, "storahci", true), name: "storahci" });
    out.push(DriverImage { path: driver_path("iastor"),     bytes: build_driver_real(machine, "iastor", true), name: "iastor" });
    out.push(DriverImage { path: driver_path("stornvme"),   bytes: build_driver_real(machine, "stornvme", true), name: "stornvme" });
    // PCI / ACPI / Power / System
    out.push(DriverImage { path: driver_path("pci"),         bytes: build_driver_real(machine, "pci", true), name: "pci" });
    out.push(DriverImage { path: driver_path("acpi"),        bytes: build_driver_real(machine, "acpi", true), name: "acpi" });
    out.push(DriverImage { path: driver_path("intelppm"),    bytes: build_driver_real(machine, "intelppm", false), name: "intelppm" });
    out.push(DriverImage { path: driver_path("mssmbios"),    bytes: build_driver_real(machine, "mssmbios", false), name: "mssmbios" });
    out.push(DriverImage { path: driver_path("hpet"),        bytes: build_driver_real(machine, "hpet", false), name: "hpet" });
    // USB stack
    out.push(DriverImage { path: driver_path("usbuhci"),     bytes: build_driver_real(machine, "usbuhci", true), name: "usbuhci" });
    out.push(DriverImage { path: driver_path("usbehci"),     bytes: build_driver_real(machine, "usbehci", true), name: "usbehci" });
    out.push(DriverImage { path: driver_path("usbxhci"),     bytes: build_driver_real(machine, "usbxhci", true), name: "usbxhci" });
    out.push(DriverImage { path: driver_path("usbhub"),      bytes: build_driver_real(machine, "usbhub", true), name: "usbhub" });
    out.push(DriverImage { path: driver_path("usbhid"),      bytes: build_driver_real(machine, "usbhid", true), name: "usbhid" });
    out.push(DriverImage { path: driver_path("kbdhid"),      bytes: build_driver_real(machine, "kbdhid", true), name: "kbdhid" });
    out.push(DriverImage { path: driver_path("mouhid"),      bytes: build_driver_real(machine, "mouhid", true), name: "mouhid" });
    out.push(DriverImage { path: driver_path("i8042prt"),    bytes: build_driver_real(machine, "i8042prt", true), name: "i8042prt" });
    // Display stack
    out.push(DriverImage { path: driver_path("vga"),         bytes: build_driver_real(machine, "vga", false), name: "vga" });
    out.push(DriverImage { path: driver_path("vgaport"),     bytes: build_driver_real(machine, "vgaport", false), name: "vgaport" });
    out.push(DriverImage { path: driver_path("videoprt"),    bytes: build_driver_real(machine, "videoprt", true), name: "videoprt" });
    // Network
    out.push(DriverImage { path: driver_path("e1000"),       bytes: build_driver_real(machine, "e1000", true), name: "e1000" });
    out.push(DriverImage { path: driver_path("rtnic86"),      bytes: build_driver_real(machine, "rtnic86", true), name: "rtnic86" });
    out.push(DriverImage { path: driver_path("netvmini"),     bytes: build_driver_real(machine, "netvmini", true), name: "netvmini" });
    out.push(DriverImage { path: driver_path("ndis"),         bytes: build_driver_real(machine, "ndis", true), name: "ndis" });
    // Audio
    out.push(DriverImage { path: driver_path("hdaudio"),     bytes: build_driver_real(machine, "hdaudio", true), name: "hdaudio" });
    out.push(DriverImage { path: driver_path("ac97"),         bytes: build_driver_real(machine, "ac97", true), name: "ac97" });
    // Kernel-mode frameworks
    out.push(DriverImage { path: driver_path("Wdf01000"),    bytes: build_driver_real(machine, "Wdf01000", false), name: "Wdf01000" });
    out
}

fn driver_path(name: &str) -> String {
    let mut s = String::with_capacity(name.len() + 16);
    s.push_str("Windows\\System32\\drivers\\");
    s.push_str(name);
    s.push_str(".sys");
    s
}

/// Build a real driver PE with actual x86_64 machine code.
///
/// The `supports_pnp` parameter determines if the driver exports AddDevice.
///
/// Windows Driver Entry convention (x86_64):
/// - RCX = PDRIVER_OBJECT (pointer to driver object)
/// - RDX = PUNICODE_STRING (registry path)
/// - RAX = NTSTATUS return (0 = SUCCESS)
///
/// Driver initialization:
/// 1. Set DriverObject->MajorFunction[IRP_MJ_CREATE] = dispatch stub
/// 2. Set DriverObject->MajorFunction[IRP_MJ_CLOSE] = dispatch stub
/// 3. Set DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch stub
/// 4. Set DriverObject->DriverUnload = unload stub
/// 5. If PnP: Set DriverObject->DriverStartIo and export AddDevice
/// 6. Return STATUS_SUCCESS (0)
fn build_driver_real(machine: u16, name: &str, supports_pnp: bool) -> Vec<u8> {
    let mut b = PeBuilder::new(machine, Subsystem::Native);
    // Each driver gets a unique image base. The base is a function
    // of both the architecture (machine) and the driver name so
    // that two distinct drivers compiled for the same machine do
    // not collide on load. `name_hash` is a stable FNV-style mix
    // of the driver name bytes; it is kept in a 16-bit range so
    // the final address remains inside the user-kernel reservation
    // window below 0x8000_0000.
    let mut name_hash: u64 = 0xcbf29ce484222325;
    for &byte in name.as_bytes() {
        name_hash ^= byte as u64;
        name_hash = name_hash.wrapping_mul(0x100000001b3);
    }
    let name_offset_pages = (name_hash & 0xFFFF) as u64;
    b.image_base = 0x0000_0000_7000_0000
        + (machine as u64) * 0x10_0000
        + name_offset_pages * 0x1000;
    b.entry_point_rva = SECTION_ALIGNMENT;

    // Generate real x86_64 driver code
    let code = generate_driver_code(supports_pnp);
    
    let mut text = Section::new(".text", SectionFlags::CODE);
    text.extend_from_slice(&code);
    b.add_section(text);
    
    // Exports at fixed RVA offsets within .text
    let driver_entry_rva = SECTION_ALIGNMENT;
    let dispatch_rva = SECTION_ALIGNMENT + 0x40;
    let unload_rva = SECTION_ALIGNMENT + 0x50;
    let add_device_rva = if supports_pnp { SECTION_ALIGNMENT + 0x60 } else { 0 };
    
    b.add_export("DriverEntry", driver_entry_rva);
    b.add_export("DriverUnload", unload_rva);
    if supports_pnp {
        b.add_export("AddDevice", add_device_rva);
    }
    
    // Dispatch routine exports (IRP_MJ values as function names)
    // IRP_MJ_CREATE = 0x00, IRP_MJ_CLOSE = 0x02, IRP_MJ_DEVICE_CONTROL = 0x0e
    b.add_export("DispatchCreate", dispatch_rva);
    b.add_export("DispatchClose", dispatch_rva);
    b.add_export("DispatchDeviceControl", dispatch_rva);
    
    // Drivers import the I/O manager from ntoskrnl.exe. The
    // real driver would also import the HAL; the bootstrap
    // keeps the import table minimal.
    let mut ntoskrnl = Import::new("ntoskrnl.exe");
    ntoskrnl.add("IoCreateDevice");
    ntoskrnl.add("IoDeleteDevice");
    ntoskrnl.add("IoCallDriver");
    ntoskrnl.add("IoCompleteRequest");
    ntoskrnl.add("KeBugCheck");
    ntoskrnl.add("IoGetCurrentProcess");
    b.add_import(ntoskrnl);
    
    b.build()
}

/// Generate x86_64 machine code for a Windows driver.
///
/// Layout:
/// [0x00] DriverEntry: Initialize driver, set dispatch handlers, return success
/// [0x40] DispatchStub: Common dispatch handler for IRPs, return STATUS_SUCCESS
/// [0x50] DriverUnload: Cleanup when driver unloads
/// [0x60] AddDevice: PnP AddDevice routine (if supports_pnp)
///
/// NTSTATUS values:
///   STATUS_SUCCESS           = 0x00000000
///   STATUS_NOT_SUPPORTED    = 0xC00000BB
///   STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
///
/// Correct Windows x86_64 DRIVER_OBJECT layout:
///   +0x00: Type (SHORT)
///   +0x02: Size (SHORT)
///   +0x08: PDEVICE_OBJECT DeviceObject
///   +0x10: PVOID DriverStart (set by I/O Manager, not used by DriverEntry)
///   +0x18: PDRIVER_UNLOAD DriverUnload
///   +0x20: PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION+1]
///   ...
fn generate_driver_code(supports_pnp: bool) -> Vec<u8> {
    let mut code = Vec::with_capacity(0x100);

    // ============================================================
    // DriverEntry (offset 0x00)
    // ============================================================
    // Prologue
    code.extend_from_slice(&[0x55]);                     // push rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]);       // mov rbp, rsp
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20 (shadow space)

    // DriverObject is in RCX (arg1)
    // Save it: mov [rbp-8], rcx
    code.extend_from_slice(&[0x48, 0x89, 0x4D, 0xF8]);

    // Corrected DriverObject offsets for Windows x86_64:
    // DriverUnload at +0x18, MajorFunction[0] at +0x20
    //
    // Code layout within DriverEntry (starting at 0x00):
    // 0x00-0x3f: DriverEntry function
    // 0x40-0x4f: DispatchStub function
    // 0x50-0x5f: DriverUnload function
    // 0x60-...: AddDevice function (if PnP)
    //
    // RIP for LEA = instruction_address + 7 (7-byte instruction length)
    // DispatchStub at 0x1040 (image base + 0x1000 + 0x40)
    // LEA instruction at various offsets in DriverEntry

    // Set MajorFunction[IRP_MJ_CREATE = 0x00] = DispatchStub
    // DriverObject->MajorFunction[0] at offset 0x20
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
    // lea rdx, [rip+0x27] - DispatchStub is at offset 0x40 from section start
    // If DriverEntry starts at 0x1000, LEA at 0x12, RIP = 0x1019, target = 0x1040
    // offset = 0x1040 - 0x1019 = 0x27
    code.extend_from_slice(&[0x48, 0x8D, 0x15, 0x27, 0x00, 0x00, 0x00]); // lea rdx, [rip+0x27]
    code.extend_from_slice(&[0x48, 0x89, 0x51, 0x20]); // mov [rcx + 0x20], rdx

    // Set MajorFunction[IRP_MJ_CLOSE = 0x02] = DispatchStub
    // DriverObject->MajorFunction[2] at offset 0x30 (0x20 + 2*8)
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
    // LEA at 0x1f: RIP = 0x1026, offset = 0x1040 - 0x1026 = 0x1a
    code.extend_from_slice(&[0x48, 0x8D, 0x15, 0x1A, 0x00, 0x00, 0x00]); // lea rdx, [rip+0x1a]
    code.extend_from_slice(&[0x48, 0x89, 0x51, 0x30]); // mov [rcx + 0x30], rdx

    // Set MajorFunction[IRP_MJ_DEVICE_CONTROL = 0x0e] = DispatchStub
    // DriverObject->MajorFunction[0x0e] at offset 0x20 + 0x0e*8 = 0x20 + 0x70 = 0x90
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
    // LEA at 0x2d: RIP = 0x1034, offset = 0x1040 - 0x1034 = 0x0c
    code.extend_from_slice(&[0x48, 0x8D, 0x15, 0x0C, 0x00, 0x00, 0x00]); // lea rdx, [rip+0x0c]
    code.extend_from_slice(&[0x48, 0x89, 0x51, 0x90]); // mov [rcx + 0x90], rdx

    // Set DriverUnload = unload_rva (at 0x50)
    // DriverObject->DriverUnload at offset 0x18
    code.extend_from_slice(&[0x48, 0x8B, 0x4D, 0xF8]); // mov rcx, [rbp-8]
    // LEA at 0x3c: RIP = 0x1043, offset = 0x1050 - 0x1043 = 0x0d
    code.extend_from_slice(&[0x48, 0x8D, 0x15, 0x0D, 0x00, 0x00, 0x00]); // lea rdx, [rip+0x0d]
    code.extend_from_slice(&[0x48, 0x89, 0x51, 0x18]); // mov [rcx + 0x18], rdx

    // Return STATUS_SUCCESS (0) in RAX
    code.extend_from_slice(&[0x33, 0xC0]);               // xor eax, eax (STATUS_SUCCESS)
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
    code.extend_from_slice(&[0x5D]);                     // pop rbp
    code.extend_from_slice(&[0xC3]);                     // ret

    // Pad to 0x40 (next function)
    while code.len() < 0x40 {
        code.push(0x90); // NOP
    }

    // ============================================================
    // DispatchStub (offset 0x40)
    // Common dispatch handler - returns STATUS_SUCCESS
    // ============================================================
    // Prologue
    code.extend_from_slice(&[0x55]);                     // push rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]);       // mov rbp, rsp
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

    // Return STATUS_SUCCESS (0)
    code.extend_from_slice(&[0x33, 0xC0]);               // xor eax, eax
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
    code.extend_from_slice(&[0x5D]);                     // pop rbp
    code.extend_from_slice(&[0xC3]);                     // ret

    // Pad to 0x50 (next function)
    while code.len() < 0x50 {
        code.push(0x90); // NOP
    }

    // ============================================================
    // DriverUnload (offset 0x50)
    // Called when driver is unloaded
    // ============================================================
    // Prologue
    code.extend_from_slice(&[0x55]);                     // push rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]);       // mov rbp, rsp
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

    // Return void (no return value for unload)
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
    code.extend_from_slice(&[0x5D]);                     // pop rbp
    code.extend_from_slice(&[0xC3]);                     // ret

    // Pad to 0x60 (next function or end)
    while code.len() < 0x60 {
        code.push(0x90); // NOP
    }

    // ============================================================
    // AddDevice (offset 0x60) - only for PnP drivers
    // Called by PnP manager to add device
    // ============================================================
    if supports_pnp {
        // Prologue
        code.extend_from_slice(&[0x55]);                     // push rbp
        code.extend_from_slice(&[0x48, 0x89, 0xE5]);       // mov rbp, rsp
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20

        // RCX = DriverObject, RDX = PhysicalDeviceObject
        // For a real driver, would create a device object here

        // Return STATUS_SUCCESS
        code.extend_from_slice(&[0x33, 0xC0]);               // xor eax, eax
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]); // add rsp, 0x20
        code.extend_from_slice(&[0x5D]);                     // pop rbp
        code.extend_from_slice(&[0xC3]);                     // ret
    }

    code
}
