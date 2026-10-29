//! Standalone binary that generates all six NT 6.1 hive files
//! (BCD, SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT) and the
//! `etc/` files (hosts, lmhosts.sam, networks, protocol, services)
//! into a given output directory.
//!
//! Usage:
//!   cargo run -p nt61-tools --bin hive-gen-bin -- \
//!     --output build/x64/system/ROOT
//!
//! It then creates:
//!   ROOT/Windows/System32/config/BCD
//!   ROOT/Windows/System32/config/SYSTEM
//!   ROOT/Windows/System32/config/SOFTWARE
//!   ROOT/Windows/System32/config/SAM
//!   ROOT/Windows/System32/config/SECURITY
//!   ROOT/Windows/System32/config/DEFAULT
//!   ROOT/Windows/System32/drivers/etc/hosts
//!   ROOT/Windows/System32/drivers/etc/lmhosts.sam
//!   ROOT/Windows/System32/drivers/etc/networks
//!   ROOT/Windows/System32/drivers/etc/protocol
//!   ROOT/Windows/System32/drivers/etc/services

use std::env;
use std::fs;
use std::path::PathBuf;

use nt61_tools::hive_gen;

/// Pad a registry hive to the standard Windows size.
///
/// This function extends the hive to the target size by adding zero-filled
/// HBIN pages AFTER the existing data. It does NOT modify existing HBIN headers
/// or cell data.

fn main() {
    let args: Vec<String> = env::args().collect();
    let output = if let Some(idx) = args.iter().position(|a| a == "--output") {
        PathBuf::from(&args[idx + 1])
    } else {
        PathBuf::from("build/x64/system/ROOT")
    };
    fs::create_dir_all(&output).expect("create output dir");

    let config = output.join("Windows").join("System32").join("config");
    let etc = output
        .join("Windows")
        .join("System32")
        .join("drivers")
        .join("etc");
    fs::create_dir_all(&config).expect("create config dir");
    fs::create_dir_all(&etc).expect("create etc dir");

    // BCD - write without padding (our parser handles variable-size hives)
    let bcd = hive_gen::build_bcd();
    fs::write(config.join("BCD"), &bcd).expect("write BCD");

    // Other hives are written without padding (they will be padded elsewhere if needed)
    fs::write(config.join("SYSTEM"), hive_gen::build_system()).expect("write SYSTEM");
    fs::write(config.join("SOFTWARE"), hive_gen::build_software()).expect("write SOFTWARE");
    fs::write(config.join("SAM"), hive_gen::build_sam()).expect("write SAM");
    fs::write(config.join("SECURITY"), hive_gen::build_security()).expect("write SECURITY");
    fs::write(config.join("DEFAULT"), hive_gen::build_default()).expect("write DEFAULT");

    // etc/ files
    fs::write(etc.join("hosts"), hive_gen::HOSTS_CONTENT.as_bytes()).expect("write hosts");
    fs::write(
        etc.join("lmhosts.sam"),
        hive_gen::LMHOSTS_CONTENT.as_bytes(),
    )
    .expect("write lmhosts.sam");
    fs::write(etc.join("networks"), hive_gen::NETWORKS_CONTENT.as_bytes()).expect("write networks");
    fs::write(etc.join("protocol"), hive_gen::PROTOCOL_CONTENT.as_bytes()).expect("write protocol");
    fs::write(etc.join("services"), hive_gen::SERVICES_CONTENT.as_bytes()).expect("write services");

    println!("Wrote hives and etc files to {}", output.display());
}
