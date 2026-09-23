# I/O Manager Implementation

This directory contains the complete Windows NT 6.1 I/O Manager subsystem implementation.

## Overview

The I/O Manager is the core NT kernel component that manages all I/O operations between
user-mode applications and kernel-mode device drivers. This implementation includes all
major NT I/O Manager features required for Windows 7 compatibility.

## Implemented Features

### 1. Core IRP Management (`mod.rs`)
- **IRP Allocation/Completion**: Full IRP lifecycle with I/O status blocks
- **Stack Locations**: Multi-layer IRP stack for driver chains
- **IRP Routing**: `IoCallDriver` for passing IRPs down device stacks
- **Completion**: `IoCompleteRequest` with priority boost support

### 2. Driver Loading (`driver_loader.rs`)
- **Service Start Types**:
  - `BOOT_START` (0): Loaded by boot loader
  - `SYSTEM_START` (1): Loaded during kernel init
  - `AUTO_START` (2): Loaded at system start
  - `DEMAND_START` (3): Manual load
  - `DISABLED` (4): Not loaded
- **Driver Registry**: Tracking of loaded drivers with reference counting
- **Driver Initialization**: `DriverEntry` callback support
- **Driver Unload**: Safe driver removal with ref count checks

### 3. Device Object Management (`mod.rs`)
- **Device Creation**: `create_device` with object manager integration
- **Device Attachment**: Building device stacks for filter drivers
- **Device Stack**: `DeviceStack` structure for managing layered devices
- **Reference Counting**: Proper lifetime management
- **Device Deletion**: Safe removal with dependency checks

### 4. File Object Management (`mod.rs`)
- **File Object Allocation**: Creating file handles for open operations
- **File Context**: Tracking current byte offset and flags
- **FCB/VPB Support**: File Control Blocks and Volume Parameter Blocks
- **Handle Management**: Reference counted file objects

### 5. Asynchronous I/O with APCs (`apc.rs`)
- **APC Types**: User APCs, Kernel APCs, Special Kernel APCs
- **APC Queuing**: Per-thread APC queues
- **APC Delivery**: Automatic delivery on return to user mode
- **I/O Completion APCs**: Asynchronous I/O notification mechanism

### 6. I/O Completion Ports (`iocomplete.rs`)
- **Port Creation**: `IoCreateCompletionPort`
- **Packet Queuing**: `NtSetIoCompletion` for driver completion
- **Packet Dequeue**: `NtRemoveIoCompletion` with timeout support
- **High-Performance**: Designed for scalable async I/O (like epoll/kqueue)

### 7. I/O Transfer Modes (`transfer.rs`)
- **Buffered I/O**: System buffer with copy to/from user space
- **Direct I/O**: MDL-based zero-copy with page locking
- **Neither I/O**: Direct user buffer access (for trusted drivers)
- **MDL Management**: Memory Descriptor Lists for physical page tracking

### 8. IRP Stack Management (`irp_stack.rs`)
- **Stack Location Access**: `get_current_stack_location`, `get_next_stack_location`
- **Stack Navigation**: `skip_current_stack_location`
- **Completion Routines**: Per-stack completion callbacks
- **Parameter Passing**: Read/write parameters in stack locations

### 9. Cancel-Safe IRP Queues (`cancel.rs`)
- **Thread-Safe Queuing**: Spinlock-protected IRP queues
- **Cancellation Support**: Safe IRP removal during cancellation
- **Cancel Routines**: Callback support for IRP cancellation
- **Queue Flushing**: Bulk IRP completion with status

### 10. IRP Timeout and Cancellation (`timeout.rs`)
- **Timeout Tracking**: Automatic IRP cancellation on timeout
- **Tick-Based Timing**: Timer interrupt-driven timeout processing
- **Configurable Timeouts**: Per-IRP timeout values
- **Default Timeout**: 30-second default for all I/O operations

### 11. Fast I/O Dispatch (`mod.rs`)
- **Fast I/O Table**: 14 fast I/O operations
- **Bypass IRP Path**: Direct function calls for common operations
- **Fast Read/Write**: High-performance synchronous I/O
- **Cache Manager Integration**: Fast I/O for cached files

### 12. File System Control (FSCTL) (`fsctl.rs`)
- **Volume Management**: Lock/unlock/dismount volume
- **Compression**: Get/set file compression
- **Reparse Points**: Junction points and symbolic links
- **Sparse Files**: Sparse file operations
- **Volume Information**: NTFS volume data queries

### 13. Plug and Play (PnP) (`mod.rs`)
- **Device Enumeration**: `pnp_query_device_relations`
- **Device Start**: `pnp_start_device` with capability queries
- **Device Removal**: Graceful and surprise removal support
- **Device State Machine**: NotStarted → Started → Stopped → Deleted
- **Minor Functions**: Full IRP_MN_* dispatch table

### 14. Power Management (`mod.rs`)
- **System Power States**: S0-S5 (working, sleep, hibernate, soft-off)
- **Device Power States**: D0-D3 (working, light sleep, deep sleep)
- **Power IRPs**: IRP_MJ_POWER with full minor function support
- **Power State Transitions**: Safe state tracking and transitions

### 15. Object Manager Integration (`mod.rs`)
- **Namespace Registration**: Drivers at `\Driver\<name>`
- **Device Registration**: Devices at `\Device\<name>`
- **Security Descriptors**: NULL DACL security (allow all access)
- **Handle Management**: Integration with NT object handles

### 16. Named and Anonymous Pipes (`pipe.rs`, `named_pipe.rs`)
- **Anonymous Pipes**: `CreatePipe` implementation
- **Named Pipes**: Server/client named pipe support
- **Pipe Directions**: Inbound, outbound, duplex
- **Pipe Modes**: Byte stream and message mode
- **OpenSSH Support**: Privilege separation pipe handling

### 17. Dispatch Tables (`dispatch.rs`, `mod.rs`)
- **Driver Dispatch**: 28 major function slots
- **Type-Safe Dispatch**: `DriverDispatchTable` helper
- **Automatic Installation**: Dispatch table → driver object
- **Default Handlers**: NULL and filesystem default implementations

## Architecture

```
User Mode Application
        ↓
   NtReadFile/NtWriteFile
        ↓
   I/O Manager (io/mod.rs)
        ↓
   IRP Allocation (allocate_irp)
        ↓
   IoCallDriver (dispatch to driver)
        ↓
   Driver Stack (filter → function → bus)
        ↓
   Hardware Device
        ↓
   IoCompleteRequest (completion)
        ↓
   APC Delivery (async notification)
```

## Major Function Codes

```rust
IRP_MJ_CREATE          0x00  // Open file/device
IRP_MJ_CLOSE           0x01  // Close file/device
IRP_MJ_READ            0x03  // Read data
IRP_MJ_WRITE           0x04  // Write data
IRP_MJ_DEVICE_CONTROL  0x0E  // IOCTL
IRP_MJ_PNP             0x0F  // Plug and Play
IRP_MJ_POWER           0x10  // Power management
IRP_MJ_CLEANUP         0x12  // Pre-close cleanup
```

## Testing

Run the I/O Manager smoke test:

```rust
io::smoke_test()
```

The smoke test verifies:
1. Driver allocation and registration
2. Device creation and attachment
3. IRP allocation and routing
4. I/O statistics tracking
5. IRP completion

## Statistics

The I/O Manager tracks comprehensive statistics:
- IRPs allocated/completed/cancelled
- Bytes read/written
- Read/write operation counts

Access via `io::io_stats()`.

## Integration Points

- **Object Manager** (`ob`): Device/driver namespace
- **Memory Manager** (`mm`): Pool allocation for IRPs/devices
- **Kernel Executive** (`ke`): Spinlocks, APCs
- **Security Manager** (`se`): Security descriptors
- **VFS** (`fs::vfs`): Filesystem integration

## File Structure

```
io/
├── mod.rs              # Core I/O Manager (IRPs, devices, drivers)
├── driver_loader.rs    # Driver loading subsystem
├── apc.rs              # Asynchronous Procedure Calls
├── transfer.rs         # I/O transfer modes (Buffered/Direct/Neither)
├── cancel.rs           # Cancel-safe IRP queues
├── fsctl.rs            # File system control (FSCTL) operations
├── irp_stack.rs        # IRP stack location management
├── timeout.rs          # IRP timeout and cancellation
├── iocomplete.rs       # I/O completion ports
├── pipe.rs             # Anonymous pipes
├── named_pipe.rs       # Named pipes
├── dispatch.rs         # Dispatch table helpers
└── smoke.rs            # I/O Manager smoke test
```

## API Summary

### Core APIs
- `allocate_irp(stack_locations)` - Allocate IRP
- `free_irp(irp)` - Free IRP
- `IoCallDriver(device, irp)` - Route IRP to driver
- `IoCompleteRequest(irp, boost)` - Complete IRP

### Driver Management
- `allocate_driver(name)` - Allocate driver object
- `register_driver(driver)` - Register in global list
- `load_driver(name, path, start_type)` - Load driver
- `unload_driver(driver)` - Unload driver

### Device Management
- `create_device(driver, type, name)` - Create device
- `delete_device(device)` - Delete device
- `attach_device(above, below)` - Build device stack
- `reference_device_object(device)` - Add reference
- `dereference_device_object(device)` - Remove reference

### File Objects
- `allocate_file_object(device, name)` - Create file object
- `free_file_object(file)` - Free file object

### Async I/O
- `build_async_irp(...)` - Create async IRP with APC
- `insert_io_apc(thread_id, mode, routine, ...)` - Queue APC
- `deliver_user_apcs(thread_id)` - Deliver pending APCs

### IOCP
- `IoCreateCompletionPort(key)` - Create completion port
- `NtSetIoCompletion(port, key, status, info)` - Queue completion
- `NtRemoveIoCompletion(port, timeout)` - Dequeue completion

### Transfer Modes
- `allocate_mdl(va, length, ...)` - Create MDL for Direct I/O
- `probe_and_lock_pages(mdl, mode, op)` - Lock pages
- `get_system_address_for_mdl(mdl)` - Get kernel VA

### PnP/Power
- `pnp_start_device(device)` - Start device
- `pnp_remove_device(device)` - Remove device
- `pnp_enumerate_and_start_all()` - Enumerate all devices

## Windows 7 Compatibility

This implementation provides full Windows 7 I/O Manager compatibility:
- ✅ All major IRP types (CREATE, READ, WRITE, IOCTL, PNP, POWER)
- ✅ Complete driver loading lifecycle
- ✅ Device stack management
- ✅ Async I/O with APCs and IOCP
- ✅ All three I/O transfer modes
- ✅ Fast I/O dispatch
- ✅ Cancel-safe queues
- ✅ PnP device enumeration
- ✅ Power management IRPs
- ✅ FSCTL support
- ✅ Named and anonymous pipes

## Known Limitations (Bootstrap)

1. **Driver Loading**: Doesn't load actual PE driver images from disk
2. **Hardware Access**: No real hardware I/O (simulation only)
3. **IRQL Management**: Simplified IRQL handling
4. **DMA Support**: No DMA subsystem
5. **WMI**: No WMI instrumentation
6. **Registry Integration**: Simplified registry interaction

## Future Enhancements

- [ ] Full PE driver image loading
- [ ] DMA and scatter-gather I/O
- [ ] WMI event tracing
- [ ] I/O prioritization
- [ ] Quota management
- [ ] Hot-plug device support
- [ ] Driver verification (Driver Verifier equivalent)
