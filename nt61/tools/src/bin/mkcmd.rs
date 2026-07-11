//! Hand-crafted cmd.exe PE builder for the host.
//!
//! The kernel's `system_image::build_cmd_exe` uses `OwnedSection`
//! which is hard-wired to the kernel's `KERNEL_HEAP`. That
//! allocator returns null in the host process, so any code that
//! tries to build a PE on the host crashes with a null pointer
//! dereference. To work around that we ship a tiny PE writer
//! here that builds a minimal cmd.exe PE image (1 page of
//! .text + 1 page of .rdata) using `Vec<u8>` directly.
//!
//! The output matches what `system_image::build_cmd_exe` would
//! produce (modulo timestamps), and is the image the kernel
//! embeds via `include_bytes!("../resources/pe/cmd_x86_64.exe")`
//! for the Safe-Mode CMD boot path.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

const IMAGE_BASE: u64 = 0x0000_0000_6500_0000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;
const TEXT_RVA: u32 = SECTION_ALIGNMENT;
const RDATA_RVA: u32 = SECTION_ALIGNMENT * 2;

// Hand-encoded x86_64 entry point for the Safe-Mode `cmd.exe` stub.
// Skips the OUT instruction (which faults at Ring 3 in QEMU TCG even
// with RFLAGS.IOPL=3) and goes straight to SYS_PUTCHAR syscall.
//
// Layout (offsets into `.text`):
//   0x000  cmd_main:  B0 41                   mov al, 'A'
//              0x002  EB 09                   jmp short +9 -> 0x00D
//              0x004  CC EB FE                (int 3 ; jmp $ — disabled)
//   0x00D  cmd_svc:  41 B8 02 02 00 00        mov r8d, 0x0202 (SYS_PUTCHAR)
//              0x013  0F 05                   syscall             ; print 'A'
//              0x015  EB FE                   jmp $               ; halt
const TEXT_STUB: [u8; 132] = [
    0xB0, 0x41,                          // 0x000: mov al, 'A'
    0xEB, 0x0A,                          // 0x002: jmp short +10 -> 0x00E
    0xCC, 0xEB, 0xFE, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xB8, 0x02, 0x02, 0x00, 0x00,        // 0x00E: mov eax, SYS_PUTCHAR (0x0202)
    0x0F, 0x05,                          // 0x013: syscall            ; print 'A'
    0xEB, 0xFE,                          // 0x015: jmp $              ; halt
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

fn align_up(x: u32, align: u32) -> u32 {
    (x + align - 1) & !(align - 1)
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn build_cmd_exe() -> Vec<u8> {
    // ------------------------------------------------------------------
    // .text section (one page)
    // ------------------------------------------------------------------
    let text_data: Vec<u8> = {
        let mut v = TEXT_STUB.to_vec();
        v.resize(SECTION_ALIGNMENT as usize, 0);
        v
    };

    // ------------------------------------------------------------------
    // .rdata section: export directory + name strings
    // ------------------------------------------------------------------
    //
    // The export table has three entries: cmd_main, ConsoleMain,
    // and ExitProcess. cmd_main and ConsoleMain both point at
    // offset 0 in .text (the cmd_main label). ExitProcess points
    // at offset 0x10 in .text (the second syscall instruction).
    //
    // Layout (relative to RDATA_RVA):
    //   0x000  IMAGE_EXPORT_DIRECTORY (40 bytes)
    //   0x028  AddressOfFunctions (3 dwords = 12 bytes)
    //   0x034  AddressOfNames     (3 dwords = 12 bytes)
    //   0x040  AddressOfNameOrds  (3 words  = 6 bytes)
    //   0x050  Export name strings (NUL-terminated, ascending order)

    let mut rdata: Vec<u8> = vec![0u8; SECTION_ALIGNMENT as usize];

    // IMAGE_EXPORT_DIRECTORY (40 bytes) at offset 0
    write_u32(&mut rdata, 0x00, 0);                       // Characteristics
    write_u32(&mut rdata, 0x04, 0);                       // TimeDateStamp
    write_u16(&mut rdata, 0x08, 0);                       // MajorVersion
    write_u16(&mut rdata, 0x0A, 0);                       // MinorVersion
    write_u32(&mut rdata, 0x0C, RDATA_RVA + 0x050);       // Name RVA
    write_u32(&mut rdata, 0x10, 1);                       // Base
    write_u32(&mut rdata, 0x14, 3);                       // NumberOfFunctions
    write_u32(&mut rdata, 0x18, 3);                       // NumberOfNames
    write_u32(&mut rdata, 0x1C, RDATA_RVA + 0x028);       // AddressOfFunctions RVA
    write_u32(&mut rdata, 0x20, RDATA_RVA + 0x034);       // AddressOfNames RVA
    write_u32(&mut rdata, 0x24, RDATA_RVA + 0x040);       // AddressOfNameOrdinals RVA

    // AddressOfFunctions[3] at rdata+0x028
    write_u32(&mut rdata, 0x028, TEXT_RVA + 0x000);       // cmd_main
    write_u32(&mut rdata, 0x02C, TEXT_RVA + 0x010);       // ExitProcess
    write_u32(&mut rdata, 0x030, TEXT_RVA + 0x000);       // ConsoleMain

    // AddressOfNames[3] at rdata+0x034 (RVAs of name strings)
    let s_cmd_main = b"cmd_main\x00";
    let s_exit_process = b"ExitProcess\x00";
    let s_console_main = b"ConsoleMain\x00";
    let name_table_off = 0x050;
    let s_cmd_main_off = name_table_off;
    let s_exit_process_off = s_cmd_main_off + s_cmd_main.len();
    let s_console_main_off = s_exit_process_off + s_exit_process.len();
    write_u32(&mut rdata, 0x034, RDATA_RVA + s_cmd_main_off as u32);
    write_u32(&mut rdata, 0x038, RDATA_RVA + s_console_main_off as u32);
    write_u32(&mut rdata, 0x03C, RDATA_RVA + s_exit_process_off as u32);

    // Name strings at rdata+0x050
    rdata[s_cmd_main_off..s_cmd_main_off + s_cmd_main.len()]
        .copy_from_slice(s_cmd_main);
    rdata[s_exit_process_off..s_exit_process_off + s_exit_process.len()]
        .copy_from_slice(s_exit_process);
    rdata[s_console_main_off..s_console_main_off + s_console_main.len()]
        .copy_from_slice(s_console_main);

    // AddressOfNameOrdinals[3] at rdata+0x040 (each entry is a u16)
    write_u16(&mut rdata, 0x040, 0);                       // cmd_main    -> index 0
    write_u16(&mut rdata, 0x042, 1);                       // ConsoleMain -> index 1
    write_u16(&mut rdata, 0x044, 2);                       // ExitProcess -> index 2

    // ------------------------------------------------------------------
    // Section table (2 sections: .text, .rdata)
    // ------------------------------------------------------------------
    let text_raw_size = align_up(TEXT_STUB.len() as u32, FILE_ALIGNMENT);
    let rdata_raw_size = align_up(rdata.len() as u32, FILE_ALIGNMENT);

    // Section headers live immediately after the optional header
    // (per the PE/COFF spec: section table starts at
    // opt_off + SizeOfOptionalHeader = 0x98 + 240 = 0x188).
    let sect_off_u32: u32 = 0x188;
    let sect_off: usize = sect_off_u32 as usize;
    let text_raw_off: u32 = align_up(sect_off_u32 + 2 * 40, FILE_ALIGNMENT);
    let rdata_raw_off: u32 = text_raw_off + text_raw_size;
    let total_size: u32 = rdata_raw_off + rdata_raw_size;

    // SizeOfHeaders in the optional header is the total size of
    // all headers (DOS + PE sig + COFF + optional + section table)
    // rounded up to FileAlignment.
    let headers_size: u32 = align_up(sect_off_u32 + 2 * 40, FILE_ALIGNMENT);

    let mut out = vec![0u8; total_size as usize];

    // ------------------------------------------------------------------
    // DOS header
    // ------------------------------------------------------------------
    out[0..2].copy_from_slice(b"MZ");
    // e_lfanew at offset 0x3C -> PE header offset (0x80)
    write_u32(&mut out, 0x3C, 0x80);

    // ------------------------------------------------------------------
    // PE signature + COFF header + Optional header at offset 0x80
    // ------------------------------------------------------------------
    let pe_off = 0x80;
    out[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");

    // COFF File Header (20 bytes) at pe_off + 4
    let coff_off = pe_off + 4;
    write_u16(&mut out, coff_off + 0x00, 0x8664);          // Machine
    write_u16(&mut out, coff_off + 0x02, 2);               // NumberOfSections
    write_u32(&mut out, coff_off + 0x04, 0);               // TimeDateStamp
    write_u32(&mut out, coff_off + 0x08, 0);               // PointerToSymbolTable
    write_u32(&mut out, coff_off + 0x0C, 0);               // NumberOfSymbols
    write_u16(&mut out, coff_off + 0x10, 240);             // SizeOfOptionalHeader (PE32+ uses 240)
    write_u16(&mut out, coff_off + 0x12, 0x0022);          // Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)

    // Optional Header (PE32+ = 240 bytes) at coff_off + 0x14
    let opt_off = coff_off + 0x14;
    write_u16(&mut out, opt_off + 0x00, 0x020B);           // Magic: PE32+
    write_u16(&mut out, opt_off + 0x02, 14);              // MajorLinkerVersion
    write_u16(&mut out, opt_off + 0x04, 0);               // MinorLinkerVersion
    write_u32(&mut out, opt_off + 0x06, text_raw_size);    // SizeOfCode
    write_u32(&mut out, opt_off + 0x0A, rdata_raw_size);   // SizeOfInitializedData
    write_u32(&mut out, opt_off + 0x0E, 0);               // SizeOfUninitializedData
    write_u32(&mut out, opt_off + 0x10, TEXT_RVA);        // AddressOfEntryPoint
    write_u32(&mut out, opt_off + 0x14, TEXT_RVA);        // BaseOfCode
    // ImageBase (8 bytes for PE32+)
    write_u64(&mut out, opt_off + 0x18, IMAGE_BASE);
    write_u32(&mut out, opt_off + 0x20, SECTION_ALIGNMENT); // SectionAlignment
    write_u32(&mut out, opt_off + 0x24, FILE_ALIGNMENT);   // FileAlignment
    write_u16(&mut out, opt_off + 0x28, 10);              // MajorOperatingSystemVersion
    write_u16(&mut out, opt_off + 0x2A, 0);               // MinorOperatingSystemVersion
    write_u16(&mut out, opt_off + 0x2C, 0);               // MajorImageVersion
    write_u16(&mut out, opt_off + 0x2E, 0);               // MinorImageVersion
    write_u16(&mut out, opt_off + 0x30, 10);              // MajorSubsystemVersion
    write_u16(&mut out, opt_off + 0x32, 0);               // MinorSubsystemVersion
    write_u32(&mut out, opt_off + 0x34, 0);               // Win32VersionValue
    let size_of_image = RDATA_RVA + SECTION_ALIGNMENT;
    write_u32(&mut out, opt_off + 0x38, size_of_image);   // SizeOfImage
    write_u32(&mut out, opt_off + 0x3C, headers_size);    // SizeOfHeaders
    write_u32(&mut out, opt_off + 0x40, 0);               // CheckSum
    write_u16(&mut out, opt_off + 0x44, 3);               // Subsystem: WindowsCui
    write_u16(&mut out, opt_off + 0x46, 0x0160);          // DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
    write_u64(&mut out, opt_off + 0x48, 0x100000);        // SizeOfStackReserve
    write_u64(&mut out, opt_off + 0x50, 0x1000);          // SizeOfStackCommit
    write_u64(&mut out, opt_off + 0x58, 0x100000);        // SizeOfHeapReserve
    write_u64(&mut out, opt_off + 0x60, 0x1000);          // SizeOfHeapCommit
    write_u32(&mut out, opt_off + 0x68, 0);               // LoaderFlags
    write_u32(&mut out, opt_off + 0x6C, 16);              // NumberOfRvaAndSizes

    // Data directories (16 entries x 8 bytes = 128 bytes) at opt_off + 0x70
    // Only the export directory is non-zero.
    let dd_off = opt_off + 0x70;
    // [0] Export: VirtualAddress=RDATA_RVA, Size=size_of_rdata
    write_u32(&mut out, dd_off + 0x00, RDATA_RVA);
    write_u32(&mut out, dd_off + 0x04, rdata.len() as u32);
    // [1..16] = zero (already)

    // ------------------------------------------------------------------
    // Section headers (40 bytes each) at sect_off (= 0x188)
    // ------------------------------------------------------------------

    // .text
    let s = sect_off;
    out[s..s + 8].copy_from_slice(b".text\x00\x00\x00");
    write_u32(&mut out, s + 0x08, TEXT_STUB.len() as u32); // VirtualSize
    write_u32(&mut out, s + 0x0C, TEXT_RVA);              // VirtualAddress
    write_u32(&mut out, s + 0x10, text_raw_size);         // SizeOfRawData
    write_u32(&mut out, s + 0x14, text_raw_off);          // PointerToRawData
    write_u32(&mut out, s + 0x18, 0);                     // PointerToRelocations
    write_u32(&mut out, s + 0x1C, 0);                     // PointerToLineNumbers
    write_u16(&mut out, s + 0x20, 0);                     // NumberOfRelocations
    write_u16(&mut out, s + 0x22, 0);                     // NumberOfLineNumbers
    write_u32(&mut out, s + 0x24, 0x60000020);            // Characteristics: CODE | EXECUTE | READ

    // .rdata
    let s = sect_off + 40;
    out[s..s + 8].copy_from_slice(b".rdata\x00\x00");
    write_u32(&mut out, s + 0x08, rdata.len() as u32);    // VirtualSize
    write_u32(&mut out, s + 0x0C, RDATA_RVA);             // VirtualAddress
    write_u32(&mut out, s + 0x10, rdata_raw_size);        // SizeOfRawData
    write_u32(&mut out, s + 0x14, rdata_raw_off);         // PointerToRawData
    write_u32(&mut out, s + 0x18, 0);                     // PointerToRelocations
    write_u32(&mut out, s + 0x1C, 0);                     // PointerToLineNumbers
    write_u16(&mut out, s + 0x20, 0);                     // NumberOfRelocations
    write_u16(&mut out, s + 0x22, 0);                     // NumberOfLineNumbers
    write_u32(&mut out, s + 0x24, 0x40000040);            // Characteristics: INITIALIZED_DATA | READ

    // ------------------------------------------------------------------
    // Section data
    // ------------------------------------------------------------------
    out[text_raw_off as usize..(text_raw_off + text_data.len() as u32) as usize]
        .copy_from_slice(&text_data);
    out[rdata_raw_off as usize..(rdata_raw_off + rdata.len() as u32) as usize]
        .copy_from_slice(&rdata);

    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("src/resources/pe/cmd_x86_64.exe")
    };
    let bytes = build_cmd_exe();
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("mkdir parent");
    }
    let mut f = fs::File::create(&out_path).expect("create output");
    f.write_all(&bytes).expect("write");
    eprintln!("Wrote {} bytes to {}", bytes.len(), out_path.display());
}