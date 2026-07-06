//! Logging utilities for build_tool.
//!
//! Provides colored, structured logging output for build operations.

use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbosity flag.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Set verbose mode.
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::SeqCst);
}

/// Check if verbose mode is enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::SeqCst)
}

/// ANSI color codes.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";

/// Print an info message.
pub fn info(msg: &str) {
    println!("{}info:{} {}", CYAN, RESET, msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    eprintln!("{}warn:{} {}", YELLOW, RESET, msg);
}

/// Print an error message.
pub fn error(msg: &str) {
    eprintln!("{}error:{} {}", RED, RESET, msg);
}

/// Print a success message.
pub fn success(msg: &str) {
    println!("{}success:{} {}", GREEN, RESET, msg);
}

/// Print a section header.
pub fn section(name: &str) {
    println!("\n{}{}{}{}", BOLD, CYAN, name, RESET);
}

/// Print a debug message (only in verbose mode).
pub fn debug(msg: &str) {
    if is_verbose() {
        println!("{}debug:{} {}", BLUE, RESET, msg);
    }
}

/// Print a verbose debug message with details.
#[allow(dead_code)]
pub fn debug_verbose(msg: &str, details: &str) {
    if is_verbose() {
        println!("{}debug:{} {}", BLUE, RESET, msg);
        println!("         {}", details);
    }
}

/// Print a banner.
pub fn banner(title: &str, subtitle: &str) {
    println!();
    println!("{}", CYAN);
    println!("{}", "=".repeat(60));
    println!("{}{}", BOLD, title);
    println!("{}", subtitle);
    println!("{}", "=".repeat(60));
    println!("{}", RESET);
    println!();
}

/// Print a completion summary.
pub fn summary(total_steps: usize, failed_steps: usize) {
    println!();
    println!("{}", "-".repeat(40));
    if failed_steps == 0 {
        println!("{}Build completed successfully!{} ({}/{} steps)", GREEN, RESET, total_steps - failed_steps, total_steps);
    } else {
        println!("{}Build completed with {} errors{} ({}/{} steps)", RED, failed_steps, RESET, total_steps - failed_steps, total_steps);
    }
    println!("{}", "-".repeat(40));
}
