# NT6.1.7601

Windows NT 6.1 (Windows 7) compatible operating system kernel written in **Rust**.

## Overview

This is a clean-room implementation of a Windows 7 compatible operating system kernel. It is inspired by the ZirconOSAero project and aims to provide NT 6.1 kernel compatibility using modern Rust programming.

**Note**: This is a hobby/educational project for learning about operating system internals. It is not affiliated with Microsoft Corporation.

## Features

- **NT-Style Architecture**: Following the Windows NT kernel design
- **Multi-Architecture Support**: x86_64, AArch64, LoongArch64, RISC-V64
- **Modern Language**: Written entirely in Rust
- **Modular Design**: Clean separation of concerns

## Directory Structure

```
nt61/
├── src/
│   ├── arch/           # Architecture-specific code
│   │   ├── x86_64/     # x86_64 (primary target)
│   │   ├── aarch64/     # ARM64
│   │   ├── loongarch64/ # LoongArch64
│   │   └── riscv64/     # RISC-V64
│   ├── hal/            # Hardware Abstraction Layer
│   │   ├── common/      # Architecture-independent HAL
│   │   └── <arch>/      # Architecture-specific HAL
│   ├── ke/             # Kernel Executive
│   │   ├── scheduler/   # Process/thread scheduling
│   │   ├── sync/        # Synchronization primitives
│   │   ├── apc/         # APC dispatcher
│   │   ├── dpc/         # DPC dispatcher
│   │   └── time/        # Time keeping
│   ├── mm/             # Memory Manager
│   │   ├── vm/         # Virtual memory
│   │   ├── frame/      # Physical frame allocation
│   │   ├── pool/       # Kernel pool
│   │   ├── vad/        # Virtual Address Descriptors
│   │   └── mdl/        # Memory Descriptor Lists
│   ├── ob/             # Object Manager
│   ├── ps/             # Process Subsystem
│   │   ├── process/    # EPROCESS structures
│   │   └── thread/     # ETHREAD/KTHREAD structures
│   ├── io/             # I/O Manager
│   ├── lpc/            # Local Procedure Call
│   ├── rtl/            # Runtime Library
│   ├── fs/             # File Systems
│   │   ├── vfs/       # Virtual File System
│   │   ├── fat32/     # FAT32 implementation
│   │   └── ntfs/      # NTFS implementation
│   ├── loader/         # PE Loader
│   ├── se/             # Security Subsystem
│   ├── libs/           # User-mode Libraries
│   │   ├── ntdll/     # Native API
│   │   └── kernel32/  # Win32 API
│   ├── servers/        # System Servers
│   │   ├── pid1/      # System Server
│   │   ├── pid2/      # Session Manager (SMSS)
│   │   └── csrss/     # CSRSS
│   ├── subsystems/     # Win32 Subsystems
│   │   ├── win32/     # Win32 (User32, GDI32)
│   │   └── win32k/    # Win32 Kernel
│   ├── desktop/        # Desktop Environment
│   │   ├── dwm/      # Desktop Window Manager
│   │   └── aero/     # Aero Glass theme
│   └── registry/      # Registry Implementation
├── boot/              # Bootloader
│   ├── zbm/           # ZBM bootloader
│   └── stub/          # Boot stubs
├── link/              # Linker scripts
├── scripts/           # Build scripts
└── tests/             # Tests
```

## Building

### Prerequisites

- Rust nightly (or 2024 edition)
- QEMU (for running)
- NASM (for assembly)
- x86_64-elf tools

### Build Commands

```bash
# Build release kernel
make build

# Build debug kernel
make debug

# Run in QEMU
make run

# Run with graphical output
make run-graphic

# Create bootable ISO
make iso

# Run tests
make test

# Generate documentation
make doc

# Clean build
make clean
```

## Architecture Components

### Kernel Executive (ke/)

The kernel executive provides core services:
- **Scheduler**: Thread scheduling and quantum management
- **Sync**: Events, mutexes, semaphores, dispatch objects
- **APC**: Asynchronous Procedure Calls
- **DPC**: Deferred Procedure Calls
- **Time**: System time and tick counting
- **Bugcheck**: Blue screen handling

### Memory Manager (mm/)

Memory management subsystems:
- **Virtual Memory**: Address space management
- **Frame Allocator**: Physical page allocation (buddy system)
- **Pool Allocator**: Non-paged and paged pools
- **VAD Tree**: Virtual Address Descriptor management
- **MDL**: Memory Descriptor Lists for I/O

### Process Subsystem (ps/)

Process and thread management:
- **EPROCESS**: Process object structure
- **ETHREAD**: Thread object structure
- **PEB**: Process Environment Block
- **TEB**: Thread Environment Block
- **KTHREAD**: Kernel thread structure

### File Systems (fs/)

File system implementations:
- **VFS**: Virtual File System abstraction
- **FAT32**: FAT32 file system
- **NTFS**: NT File System

### User Libraries (libs/)

User-mode API implementations:
- **ntdll**: Native API (Nt* functions)
- **kernel32**: Win32 Base API (CreateFile, VirtualAlloc, etc.)

## System Servers

- **PID 1 (System)**: Main system server
- **PID 2 (SMSS)**: Session Manager
- **CSRSS**: Client/Server Runtime Subsystem

## Boot Process

1. **Phase 0**: Hardware initialization
2. **Phase 1**: Kernel executive init
3. **Phase 2**: I/O subsystem init
4. **Phase 3**: Subsystems init (CSRSS, Win32)
5. **Phase 4**: System ready for users

## Status

This project is in early development. The directory structure and core types are defined, but actual implementation is pending.

## Contributing

Contributions welcome! Please see the issues for areas needing work.

## License

MIT OR Apache-2.0

## References

- ZirconOSAero: https://github.com/... (inspiration)
- ReactOS: For NT kernel understanding
- Windows Research Kernel (WRK)
