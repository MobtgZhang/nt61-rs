//! Dump the cmd.exe image bytes for the kernel to `include_bytes!`.
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let machine: u16 = if args.len() > 1 {
        u16::from_str_radix(args[1].trim_start_matches("0x"), 16).unwrap_or(0x8664)
    } else {
        0x8664
    };
    let out_path = if args.len() > 2 {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("src/resources/pe/cmd_x86_64.exe")
    };
    let bytes = nt61::system_image::build_cmd_exe_for_machine(machine);
    eprintln!("dump_cmd: produced {} bytes", bytes.len());
    eprintln!("dump_cmd: first 32 bytes = {:02x?}", &bytes[..32.min(bytes.len())]);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("mkdir parent");
    }
    fs::write(&out_path, &bytes).expect("write cmd.exe");
    println!("Wrote {} bytes to {}", bytes.len(), out_path.display());
}