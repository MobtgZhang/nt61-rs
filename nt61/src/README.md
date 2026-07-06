# NT6.1.7601 Source Code

This folder contains the source code for the NT6.1.7601 operating system kernel.

## Source Organization

```
src/
├── arch/           # Architecture-specific code
│   ├── x86_64/    # x86_64 (primary target)
│   ├── aarch64/   # ARM64
│   ├── loongarch64/ # LoongArch64
│   ├── riscv64/   # RISC-V64
│   └── boot/      # Boot entry point
├── boot/          # Boot Manager (Windows 7 style)
│   ├── bcd/       # Boot Configuration Data store
│   ├── menu/      # Boot menu UI
│   ├── loader/     # Kernel loader
│   ├── disk/      # MBR/GPT partition support
│   ├── bios/      # BIOS boot path
│   └── uefi/      # UEFI boot path
├── hal/           # Hardware Abstraction Layer
├── ke/            # Kernel Executive
├── mm/            # Memory Manager
├── ob/            # Object Manager
├── ps/            # Process Subsystem
├── io/            # I/O Manager
├── lpc/           # Local Procedure Call
├── rtl/           # Runtime Library
├── fs/            # File Systems
├── loader/        # PE Loader
├── se/            # Security
├── libs/          # User-mode Libraries
├── servers/       # System Servers
├── subsystems/    # Win32 Subsystems
├── desktop/      # Desktop Environment
└── registry/     # Registry
```

## Boot Manager Structure

The boot manager follows the Windows 7 Boot Manager design:

- **BCD Store**: Boot Configuration Data with entries for normal boot, debug, safe mode, etc.
- **Menu UI**: Windows 7 style text-mode menu with timeout countdown
- **Kernel Loader**: ELF/PE kernel loading with Multiboot2 info
- **Disk Support**: MBR and GPT partition parsing

## Building

Use the root Makefile:

```bash
make build    # Build release kernel
make boot-stub  # Assemble boot stub
make iso       # Create bootable ISO
make run       # Run in QEMU
```
