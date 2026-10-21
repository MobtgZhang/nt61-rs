//! rpcrt4.dll — Remote Procedure Call Runtime
//
//! Implements the RPC runtime that allows inter-process communication
//! using the DCOM and named-pipe protocols. This is a stub that
//! provides the basic RPC entry points.
//
//! Clean-room implementation. Spec source: Windows RPC documentation,
//! "Windows Internals 6th ed." ch. 3.

// RPC runtime names (RpcBindingFromStringBindingW, RpcStatus, ...).

/// RPC status codes.
pub const RPC_S_OK: u32 = 0;
pub const RPC_S_INVALID_BINDING: u32 = 0x6A6;
pub const RPC_S_WRONG_KIND_OF_BINDING: u32 = 0x6A7;

/// Initialize the RPC runtime stub.
pub fn init() {
    // crate::kprintln!("    RPCRT4: init");
    // crate::kprintln!("      runtime:  ready (RpcServerUseAllProtseqs etc.)");
    // crate::kprintln!("      ncalrpc:  ready (local RPC)");
    // crate::kprintln!("      ncacn_np: ready (named pipe RPC)");
}

pub mod binding;
pub mod client;
pub mod security;
pub mod server;
pub mod types;
pub mod uuid;
