use nt61::loader::{load_image_full, ImageDatabase};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: load-pe <pe-file> [preferred-base-hex]");
        std::process::exit(2);
    };
    let preferred_base = args
        .next()
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let bytes = std::fs::read(&path).expect("failed to read PE file");
    let mut db = ImageDatabase::new();
    let name = std::path::Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("image");
    match load_image_full(name, &bytes, &mut db, preferred_base) {
        Some(image) => println!(
            "OK name={} base=0x{:x} entry=0x{:x} size=0x{:x} subsystem={}",
            image.name, image.image_base, image.entry_point, image.image_size, image.subsystem
        ),
        None => {
            println!("FAILED");
            std::process::exit(1);
        }
    }
}
