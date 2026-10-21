//! cmd — Command Interpreter and BAT Batch File Parser
//!
//! This module provides the command interpreter functionality for NT6.1.7601,
//! including BAT batch file parsing with support for GOTO, IF, FOR, CALL, etc.

pub mod bat_parser;
pub mod batch_runner;
pub use batch_runner::{run_batch_file, BatchExecutor};
