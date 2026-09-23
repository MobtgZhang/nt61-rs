# PE Loader Implementation

## Overview

Complete implementation of Windows PE32/PE32+ loader matching Windows 7 ntdll's LdrLoadDll behavior.

## Components

### 1. Core Loader (`mod.rs`)
- **PE32+ (64-bit) Support**: Full loading pipeline for x64 images
- **Base Relocation Processing**: Complete implementation handling all relocation types
  - `IMAGE_REL_BASED_ABSOLUTE` (0) - padding
  - `IMAGE_REL_BASED_HIGHLOW` (3) - 32-bit VA correction
  - `IMAGE_REL_BASED_HIGHADJ` (5) - high 16-bit adjustment
  - `IMAGE_REL_BASED_REL32` (4) - RIP-relative 32-bit offset
  - `IMAGE_REL_BASED_DIR32NB` (7) - non-base 32-bit
  - `IMAGE_REL_BASED_DIR64` (10) - 64-bit VA correction
- **Import Resolution**: Full IAT patching with image database lookup
  - Name-based imports
  - Ordinal imports
  - Forwarder detection
- **Export Table Parsing**: Complete export directory parsing
  - Name table walking
  - Ordinal table indexing
  - Export address table resolution
- **TLS Callback Support**: Thread-local storage initialization
  - TLS directory parsing (data directory index 9)
  - Callback array iteration
  - DLL_PROCESS_ATTACH/DLL_THREAD_ATTACH handling
- **Exception Directory Parsing**: x64 structured exception handling
  - RUNTIME_FUNCTION table parsing (data directory index 3)
  - UNWIND_INFO structure reading
  - Exception handler detection
- **Delay-Load Import Support**: On-demand import resolution
  - IMAGE_DELAYLOAD_DESCRIPTOR parsing (data directory index 13)
  - Delay-load IAT patching
  - Module handle management
- **Bound Import Support**: Pre-resolved import handling
  - IMAGE_BOUND_IMPORT_DESCRIPTOR parsing (data directory index 11)
  - Timestamp validation
  - Forwarder reference chains

### 2. PE32 Loader (`pe32.rs`)
- **PE32 (32-bit) Support**: Complete WOW64 compatibility
- **Export Table Parsing**: Full implementation
  - IMAGE_EXPORT_DIRECTORY structure parsing
  - Name pointer table walking
  - Ordinal indexing
  - Function address resolution
- **Import Table Parsing**: Complete IAT/ILT processing
  - IMAGE_IMPORT_DESCRIPTOR array walking
  - Import lookup table (ILT) parsing
  - Import address table (IAT) location
  - Hint/name resolution
  - Ordinal import handling
- **Relocation Processing**: Full PE32 relocation support
  - Base relocation block iteration
  - HIGHLOW (3) - 32-bit full address
  - HIGH (1) - high 16-bit adjustment
  - LOW (2) - low 16-bit adjustment
  - HIGHADJ (4) - high 16-bit with low 16-bit parameter
- **TLS Support**: PE32 thread-local storage
  - IMAGE_TLS_DIRECTORY32 (24 bytes vs 40 for PE32+)
  - 32-bit callback arrays
  - TLS data initialization
- **SEH Detection**: Frame-based exception handling check
  - DLL characteristics NO_SEH flag inspection
- **Delay-Load Imports**: PE32 delay-load descriptor parsing
- **Image Database**: Symbol resolution infrastructure
  - Case-insensitive DLL name lookup
  - Export name hashing
  - Ordinal-based resolution

### 3. Loader Utilities (`utils.rs`)
- **Error Codes**: NT STATUS code mapping
  - STATUS_INVALID_IMAGE_FORMAT (0xC000007B)
  - STATUS_DLL_INIT_FAILED (0xC0000142)
  - STATUS_ORDINAL_NOT_FOUND (0xC0000138)
  - STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139)
  - STATUS_DLL_NOT_FOUND (0xC0000135)
  - STATUS_PROCEDURE_NOT_FOUND (0xC000007A)
- **String Hashing**: NT loader hash algorithm (RtlHashUnicodeString)
- **Checksum Validation**: PE image checksum verification
- **Address Validation**: Range checking and overflow detection
- **RVA Conversion**: Virtual address to file offset mapping
- **Forwarder Parsing**: "DLL.FunctionName" string parsing
- **Protection Flags**: Section characteristics to PAGE_* conversion
- **Dependency Resolution**: Topological sort for DLL load order
- **Loader Statistics**: Performance and diagnostic counters

## Architecture

### NT Loader Pattern Compliance

1. **LdrLoadDll Behavior**:
   - Parse PE headers (DOS, COFF, Optional)
   - Map sections with correct alignment
   - Apply base relocations if needed
   - Resolve imports through image database
   - Execute TLS callbacks
   - Call DllMain with DLL_PROCESS_ATTACH

2. **Image Database**:
   - Maintains loaded module list
   - Export table caching
   - Fast symbol lookup (name and ordinal)
   - Case-insensitive DLL name matching

3. **Section Mapping**:
   - Proper alignment (section and file alignment)
   - Memory protection flags (R/W/X combinations)
   - Uninitialized data handling (.bss)

4. **Relocation Algorithm**:
   - Page-based relocation blocks (4 KB pages)
   - Type-specific fixups
   - Delta calculation (actual_base - preferred_base)
   - Both PE32 and PE32+ support

## Data Directory Support

| Index | Type | Implementation |
|-------|------|----------------|
| 0 | Export Table | ✅ Complete |
| 1 | Import Table | ✅ Complete |
| 2 | Resource Table | ⚠️ Stub only |
| 3 | Exception Table | ✅ Complete (x64) |
| 4 | Certificate Table | ❌ Not implemented |
| 5 | Base Relocation | ✅ Complete |
| 6 | Debug Directory | ⚠️ Parsed but not used |
| 7 | Architecture | ❌ Not needed |
| 8 | Global Ptr | ❌ Not needed |
| 9 | TLS Table | ✅ Complete |
| 10 | Load Config | ⚠️ Stub only |
| 11 | Bound Import | ✅ Complete |
| 12 | IAT | ⚠️ Implicit in import resolution |
| 13 | Delay Import | ✅ Complete |
| 14 | COM Descriptor | ❌ Not needed |
| 15 | Reserved | ❌ Reserved |

## Relocation Types Supported

### PE32+ (x64)
- `IMAGE_REL_BASED_ABSOLUTE` (0) - No operation
- `IMAGE_REL_BASED_DIR64` (10) - 64-bit VA correction
- `IMAGE_REL_BASED_HIGHLOW` (3) - 32-bit VA correction
- `IMAGE_REL_BASED_REL32` (4) - RIP-relative offset
- `IMAGE_REL_BASED_DIR32NB` (7) - Non-base 32-bit

### PE32 (x86)
- `IMAGE_REL_BASED_ABSOLUTE` (0) - No operation
- `IMAGE_REL_BASED_HIGHLOW` (3) - 32-bit VA correction
- `IMAGE_REL_BASED_HIGH` (1) - High 16 bits
- `IMAGE_REL_BASED_LOW` (2) - Low 16 bits
- `IMAGE_REL_BASED_HIGHADJ` (4) - High 16 bits adjusted

## Exception Handling

### x64 (PE32+)
- **Structured Exception Handling (SEH)**: Table-based
- **RUNTIME_FUNCTION Table**: Complete parsing
- **UNWIND_INFO**: Version, flags, prolog size extraction
- **Exception Handler Detection**: UNW_FLAG_EHANDLER/UNW_FLAG_UHANDLER
- **Chained Unwind Info**: UNW_FLAG_CHAININFO support

### x86 (PE32)
- **Frame-Based SEH**: FS:[0] chain (no PE metadata)
- **NO_SEH Flag**: Detection in DLL characteristics

## TLS Callback Handling

### Process Attach (DLL_PROCESS_ATTACH = 1)
1. Parse TLS directory (data directory index 9)
2. Allocate TLS data template
3. Initialize TLS index
4. Iterate callback array until null terminator
5. Call each callback: `callback(image_base, DLL_PROCESS_ATTACH, 0)`

### Thread Attach (DLL_THREAD_ATTACH = 2)
1. Copy TLS template to thread-local storage
2. Call TLS callbacks with DLL_THREAD_ATTACH
3. Store TLS data pointer in TEB

## Import Resolution Process

1. **Parse Import Directory** (data directory index 1)
2. **For Each DLL**:
   - Read DLL name
   - Walk Import Lookup Table (ILT) or Import Address Table (IAT)
3. **For Each Import**:
   - Check ordinal bit (high bit set = ordinal, clear = name)
   - If ordinal: lookup by ordinal value
   - If name: read hint/name structure, lookup by name
4. **Patch IAT**:
   - Write resolved address to IAT slot
   - Leave 0xDEAD_BEEF_DEAD_BEEF for unresolved imports

## Delay-Load Import Resolution

1. **Parse Delay-Load Directory** (data directory index 13)
2. **For Each DLL**:
   - Read DLL name, module handle RVA, delay IAT RVA
   - Walk delay-load import name table
3. **On First Call**:
   - Load DLL if not already loaded
   - Resolve import address
   - Patch delay IAT entry
4. **Subsequent Calls**: Direct call through patched IAT

## Security Features

- **Address Space Layout Randomization (ASLR)**: Supported via relocations
- **Data Execution Prevention (DEP)**: Section protection flags
- **SafeSEH**: Exception handler registration validation (x86)
- **Control Flow Guard (CFG)**: Load config directory parsing (stub)
- **Checksum Validation**: Optional PE checksum verification

## Testing Recommendations

1. **Basic Loading**: ntdll.dll, kernel32.dll, user32.dll
2. **Relocations**: Load at non-preferred base address
3. **Imports**: Verify all IAT entries resolved correctly
4. **TLS**: DLL with TLS data and callbacks
5. **Delay-Load**: DLL with delay-load imports
6. **Forwarded Exports**: kernel32 → kernelbase forwarding
7. **Exception Directory**: Verify unwind info for x64 binaries
8. **WOW64**: Load 32-bit DLL in 64-bit process (requires full WOW64 layer)

## Known Limitations

1. **Resource Directory**: Basic parsing only, not full resource resolution
2. **Load Config**: Parsed but security features not enforced
3. **Certificate Validation**: Not implemented (requires crypto subsystem)
4. **API Sets**: Not implemented (Win8+ feature)
5. **Network Access**: No network-based DLL loading
6. **Side-by-Side (SxS)**: Manifest parsing not implemented

## Future Enhancements

1. **Load Config Security**: CFG, RFG, EHCONT enforcement
2. **API Set Resolution**: ApiSetSchema.dll integration
3. **Manifest Parsing**: Side-by-side assembly support
4. **Resource Loading**: Full .rsrc directory support
5. **Debug Symbols**: PDB loading for debugging
6. **Performance**: Export hash tables, binary search for large export tables
7. **Memory Efficiency**: Lazy page commitment, section merging

## References

- Microsoft PE/COFF Specification
- Windows Internals, 7th Edition (Part 1, Chapter 3: System Mechanisms)
- ReactOS LdrLoadDll implementation
- Geoff Chappell's PE format documentation
- ntdll.dll reverse engineering notes
