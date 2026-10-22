# NT6.1 — A Windows 7–Compatible Operating System Kernel in Rust

NT6.1 is an experimental operating system that reimplements the Windows NT 6.1 (Windows 7) kernel architecture in Rust. It aims to provide a bootable kernel with NTFS support, a user-mode `cmd.exe` environment, a registry, a security subsystem, and a windowing desktop — all running natively on multiple CPU architectures without any binary dependencies on Windows itself.

## Overview

The project is organized as a `no_std` Rust kernel library (`nt61`) with a bare-metal binary entry point (`nt61-kernel`), a UEFI boot loader (`nt61-boot`), an NTOS-style loader (`nt61-winload`), a boot filesystem driver (`nt61-bootfs`), and a set of build tools. The kernel implements a significant subset of the Windows NT executive: process/thread management, virtual memory with paging and working sets, an object manager, a registry backed by hive files, a security reference monitor with access tokens and ACLs, and a driver model with bus/storage/input/video/network stacks.

On top of the kernel, user-mode server processes (`smss`, `csrss`, `wininit`, `winlogon`, `services`) and a `cmd.exe` shell provide a boot-to-prompt experience. A growing set of Win32-compatible libraries (`kernel32`, `user32`, `gdi32`, `ntdll`, `advapi32`, `ws2_32`, and others) are implemented in Rust under `nt61/src/libs/`.

## Supported Architectures

| Architecture | Boot | Status |
|---|---|---|
| x86_64 | UEFI (OVMF / EDK2) | Most complete; primary development target |
| aarch64 | UEFI (EDK2 ARM) | Functional; framebuffer and virtio supported |
| riscv64 | UEFI (EDK2 RISC-V) | Kernel boots; user-mode and input in progress |
| loongarch64 | UEFI (EDK2 LoongArch) | Kernel boots; user-mode and input in progress |

Each architecture has its own HAL (`nt61/src/hal/<arch>/`) and paging implementation (`nt61/src/arch/<arch>/paging.rs`). The x86_64 port uses 4-level paging; aarch64 uses ARMv8-A translation tables; riscv64 uses Sv39/ Sv48; loongarch64 uses LoongArch TLB-based paging.

## Features

### Kernel
- Preemptive scheduler with priorities, quantum-based dispatch, DPC, APC, and IRQL management
- Virtual memory manager with PFN database, VAD trees, working sets, section objects, copy-on-write, paging files, and dynamic paging
- Object manager with namespace, reference counting, and handle tables
- Registry with hive file format, transactions, quota, security descriptors, and notifications
- Security subsystem with SID management, access tokens, ACL evaluation, integrity levels, audit policy, and AppContainer support
- Local procedure call (LPC) / Advanced LPC for user-kernel communication
- SSDT and Shadow SSDT for system call dispatch
- Kernel heap with pool allocations and memory diagnostics

### File Systems
- NTFS (boot, read, write, journal replay, compression)
- FAT32 (read, write, LFN)
- ext4 / ext2 (read)
- ReFS (experimental)
- Filter manager framework

### Drivers
- Virtio (block, net, input, console over MMIO and PCI)
- Storage (disk, volume manager, partition manager, VSS, volume snapshots)
- Input (keyboard, mouse via virtio)
- Video (bootvid, framebuffer, Loongson LSDC GPU behind a feature flag)
- Network (virtio-net, NDIS-style miniport, TCP/IP stack)
- USB (experimental)
- WDF framework (experimental)

### Networking
- IPv4/IPv6 with ARP, ICMP, DHCP, DNS
- TCP with congestion control, window scaling, and keepalive
- UDP with checksum offload
- Sockets API (`ws2_32` compatible)

### User Mode
- `cmd.exe` shell with command extensions (`dir`, `type`, `copy`, `del`, `mkdir`, `rmdir`, `echo`, `set`, `ver`, and more)
- Session manager (`smss`), CSRSS, WinInit, WinLogon, and Service Control Manager
- SSH daemon with key exchange, authentication, and session multiplexing
- Desktop composition (DWM) with Aero-style effects

### Libraries (Win32 Compatibility Layer)
- `ntdll` — system call stubs, RTL string/heap/time utilities
- `kernel32` — process, thread, file, heap, synchronization, console, memory
- `user32` — window management, messages, input
- `gdi32` — text rendering, bitmaps, regions
- `advapi32` — registry, security, services
- `ws2_32` — Winsock 2 sockets
- `rpcrt4` — RPC runtime (partial)
- `winmm` — multimedia timers and wave audio
- `wow64` / `wow64win` — 32-bit compatibility layer (experimental)

## Building

### Prerequisites

- Rust nightly toolchain with `rust-src` for `no_std` cross-compilation
- `cargo` (part of Rust)
- `qemu-system-x86_64` (and optionally `qemu-system-aarch64`, `qemu-system-riscv64`, `qemu-system-loongarch64`)
- `mtools`, `dosfstools`, `e2fsprogs`, `ntfs-3g` (for disk image creation)
- EDK2 firmware files under `scripts/firmware/` (provided for QEMU debugging)

### Quick Start (x86_64 + NTFS)

```sh
make run
```

This builds the kernel and boot loader, creates a QEMU disk image with an NTFS system partition, and launches the VM with OVMF.

### Building for Other Architectures

```sh
# RISC-V 64
make -C nt61 build-riscv64-ntfs

# LoongArch 64
make -C nt61 build-loongarch64-ntfs

# ARM64
make -C nt61 build-aarch64-ntfs
```

### Building for Other File Systems

```sh
make -C nt61 build-x86_64-fat32
make -C nt61 build-x86_64-ext4
make -C nt61 build-x86_64-iso
```

### Running

```sh
make -C nt61 run-x86_64-ntfs          # QEMU with serial output
make -C nt61 run-x86_64-ntfs-serial   # Same, but always log to file
make -C nt61 run-x86_64-gtk           # QEMU with graphical window
make -C nt61 run-riscv64-ntfs
make -C nt61 run-loongarch64-ntfs
make -C nt61 run-aarch64-ntfs
```

Serial output is written to `nt61/build/<ARCH>/<FORMAT>/images/serial_<ARCH>_<FORMAT>.log`.

### Cleaning

```sh
make clean
```

This removes all Rust build artifacts and generated disk images.

## Project Layout

```
nt61/
├── Cargo.toml            # Workspace root
├── Makefile              # Build orchestration, QEMU launch
├── resources/            # Fonts, batch files, assets
├── tools/                # build-tool, cmd-stub-gen
└── src/
    ├── arch/             # Architecture-specific paging, traps, boot
    │   ├── aarch64/      # ARMv8-A paging, GIC, timer
    │   ├── loongarch64/  # LoongArch paging, CSR, traps
    │   ├── riscv64/      # Sv39 paging, CSRs, traps
    │   ├── x86_64/       # x86-64 paging, interrupts
    │   └── boot/         # Shared boot entry, framebuffer, kernel_entry
    ├── boot/             # UEFI boot loader crate
    ├── bootfs/           # Boot filesystem driver
    ├── boot_driver/      # Boot-time driver loading
    ├── crypto/           # Hash, cipher, RSA, PRNG
    ├── desktop/          # DWM, Aero, applications
    ├── drivers/          # Device driver model
    ├── fonts/            # Font rendering
    ├── fs/               # NTFS, FAT32, ext4, ReFS, VFS, cache
    ├── hal/              # Hardware abstraction (per-arch)
    ├── io/               # I/O manager
    ├── ke/               # Kernel executive (scheduler, IRQL, DPC, APC)
    ├── libs/             # Win32-compatible user-mode libraries
    ├── loader/           # Image loader / PE support
    ├── lpc/              # Local procedure call
    ├── mm/               # Memory management
    ├── netstack/         # TCP/IP network stack
    ├── ob/               # Object manager
    ├── ps/               # Process / thread management
    ├── registry/         # Registry and hive files
    ├── rtl/              # Runtime library (logging, strings)
    ├── se/               # Security subsystem
    ├── servers/          # User-mode servers (smss, csrss, wininit, sshd)
    ├── userland/         # User-mode programs (cmd)
    ├── userspace/        # User-mode runtime support
    ├── winload/          # NTOS-style loader (winload)
    └── bin/              # Binary targets
```

## Build Tool

The `nt61-tools` crate (under `nt61/tools/`) provides the `build-tool` binary that:

- Compiles the boot loader and kernel for the target architecture
- Generates ELF-to-PE conversion for UEFI
- Creates disk images with the selected filesystem
- Installs the boot loader and system files onto the image
- Prepares QEMU firmware (OVMF or EDK2 pflash) per architecture

The `cmd-stub-gen` tool generates C header stubs for the `cmd.exe` binary interface.

## Firmware

EDK2 firmware binaries for each architecture are stored under `scripts/firmware/`:

- `x86_64/` — OVMF code and variables
- `aarch64/` — ARM64 EDK2 QEMU EFI
- `riscv64/` — RISC-V EDK2 QEMU virt firmware
- `loongarch64/` — LoongArch EDK2 QEMU EFI

These are development builds used for local QEMU testing. Production use would require real firmware.

## Cargo Features

| Feature | Description |
|---|---|
| `x86_64` | Enable x86-64 architecture support |
| `aarch64` | Enable ARM64 architecture support |
| `riscv64` | Enable RISC-V 64-bit architecture support |
| `loongarch64` | Enable LoongArch 64-bit architecture support |
| `smp` | Enable multi-processor support |
| `acpi` | Enable ACPI table parsing |
| `debug` | Enable debug assertions and verbose logging |
| `btl` | Binary Translation Layer (aarch64 experimental) |
| `loongson_gpu` | Loongson LSDC GPU driver (loongarch64 experimental) |
| `crypto_libs` | Use RustCrypto-backed implementations for hash/cipher/RSA |
| `alloc` | Enable heap allocation (default) |

## Status and Limitations

NT6.1 is a research and hobbyist project. It is not a drop-in Windows 7 replacement. Key areas that are actively being developed include:

- RISC-V 64 and LoongArch 64 user-mode process support (Ring 3 transitions, keyboard input)
- Full 32-bit WOW64 execution
- ACPI-based power management on non-x86 architectures
- Network stack hardening and TLS
- Desktop compositor and windowing on non-x86 architectures

## Contributing

Contributions are welcome. Please ensure `cargo clippy` and `cargo build` pass for the default x86_64 target before submitting. For architecture-specific changes, verify the build for the affected architecture.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
