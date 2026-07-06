# NT6.1.7601 UEFI Boot Manager

A Windows 7 Boot Manager style boot manager implemented in pure Rust using the UEFI framework.

## Features

- Windows 7 Boot Manager UI style
- UEFI Boot Manager Protocol
- BCD (Boot Configuration Data) store
- Multiple boot entries support
- Countdown timer for automatic boot
- Safe Mode boot options
- Keyboard navigation (arrows, Enter, ESC, F8)
- GNU FreeFont support

## Building

```bash
# Build boot manager for UEFI
cd src/boot
cargo build --release --target x86_64-unknown-uefi

# Or from root directory
make build-boot
```

## Output Structure

```
build/$ARCH/
├── system/
│   ├── EFI/
│   │   ├── Boot/
│   │   │   └── BOOTX64.EFI      # Primary boot loader (x64)
│   │   └── Microsoft/
│   │       └── Boot/
│   │           ├── BCD            # Boot Configuration Data
│   │           ├── Fonts/         # GNU FreeFont
│   │           ├── bootmgfw.efi   # Windows Boot Manager
│   │           ├── bootmgr.efi    # Boot Manager alias
│   │           └── memtest.efi    # Memory test (future)
│   └── ROOT/                     # System partition
│       └── Windows/
│           └── System32/
└── images/
    ├── nt64-x64.iso              # Bootable ISO
    └── nt64-x64.img              # Disk image
```

## Boot Entries

The default boot entries are:

1. **Windows 7** - Normal boot
2. **Windows 7 (Safe Mode)** - Safe mode boot
3. **Windows 7 (Safe Mode with Networking)** - Safe mode with network drivers
4. **Windows 7 (Safe Mode with Command Prompt)** - Safe mode command prompt
5. **Windows 7 (Debug)** - Debug mode with serial output
6. **Windows 7 (Recovery)** - System recovery

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate boot entries |
| Enter | Boot selected entry |
| F8 | Advanced boot options |
| ESC | Cancel and return to firmware |
| 1-6 | Quick select boot entry |

## Boot Manager UI

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          Windows Boot Manager                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Choose an operating system to start, or press TAB to select a tool:        │
│  (Use the arrow keys to highlight your choice, then press ENTER.)           │
│                                                                              │
│      > Windows 7                                                            │
│        Windows 7 (Safe Mode)                                                │
│        Windows 7 (Safe Mode with Networking)                                │
│        Windows 7 (Safe Mode with Command Prompt)                            │
│                                                                              │
│  To specify an advanced option for this choice, press F8.                   │
│                                                                              │
│  Seconds until the highlighted choice will be started automatically: 30       │
│                                                                              │
│  Tools(T):                                                                  │
│      Edit Boot Options                                                      │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                     ENTER=Choose  TAB=Switch  ESC=Cancel                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

## BCD Store

The BCD (Boot Configuration Data) store contains:

- Boot loader entries with device paths
- OS load options (/safeboot, /debug, etc.)
- Boot display order
- Timeout values
- Tool entries

BCD is serialized in Windows-compatible binary format.

## Dependencies

- `uefi` - UEFI protocol definitions (v0.37)
- `bitflags` - Bitfield operations

## Architecture Support

- **x86_64** (x64) - Primary target
- **aarch64** (arm64) - ARM64 support
- **arm** - ARM support

## Building ESP

```bash
# Generate complete ESP structure
make build-esp ARCH=x64

# Run in QEMU
make run-boot ARCH=x64
```

## License

MIT OR Apache-2.0
