//! cmd — Command Interpreter and BAT Batch File Parser
//!
//! This module provides the command interpreter functionality for NT6.1.7601,
//! including BAT batch file parsing with support for GOTO, IF, FOR, CALL, etc.

pub mod bat_parser;
#[cfg(target_arch = "x86_64")]
pub mod batch_runner;
#[cfg(target_arch = "x86_64")]
pub use batch_runner::{BatchExecutor, run_batch_file};
