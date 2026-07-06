#!/bin/bash
#
# NT6.1.7601 - EDK2 Nightly Firmware Downloader
# =============================================
# Downloads UEFI firmware images for all supported architectures
# from https://retrage.github.io/edk2-nightly/
#
# Supported architectures: x86_64, aarch64, riscv64, loongarch64
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIRMWARE_DIR="${FIRMWARE_DIR:-$SCRIPT_DIR/firmware}"
EDK2_BASE_URL="https://retrage.github.io/edk2-nightly"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
NT6.1.7601 EDK2 Firmware Downloader

Usage: $0 [OPTIONS] [COMMAND]

Commands:
    download          Download all firmware files (default)
    verify           Verify downloaded firmware files
    list             List available firmware files
    run-x86_64       Run QEMU with x86_64 UEFI firmware
    run-aarch64      Run QEMU with aarch64 UEFI firmware
    run-riscv64      Run QEMU with riscv64 UEFI firmware
    run-loongarch64  Run QEMU with loongarch64 UEFI firmware

Options:
    -d, --dir DIR    Set firmware directory (default: ./firmware)
    -f, --force      Force re-download even if files exist
    -q, --quiet      Suppress non-error output
    -h, --help       Show this help message

Environment Variables:
    FIRMWARE_DIR     Override firmware directory

Examples:
    $0 download                    # Download all firmware
    $0 run-x86_64                  # Run x86_64 with UEFI
    FIRMWARE_DIR=/tmp/fw $0 download  # Custom firmware directory

EOF
}

download_file() {
    local url="$1"
    local dest="$2"
    local name="$3"

    if [[ -f "$dest" && ! "$FORCE" == "yes" ]]; then
        log_info "File exists: $dest (skipping)"
        return 0
    fi

    log_info "Downloading $name..."
    mkdir -p "$(dirname "$dest")"

    if command -v curl &>/dev/null; then
        curl -fL --progress-bar -o "$dest" "$url"
    elif command -v wget &>/dev/null; then
        wget --show-progress -O "$dest" "$url"
    else
        log_error "Neither curl nor wget found"
        return 1
    fi

    if [[ -f "$dest" && -s "$dest" ]]; then
        log_success "Downloaded: $name ($(du -h "$dest" | cut -f1))"
    else
        log_error "Download failed: $name"
        return 1
    fi
}

download_all() {
    log_info "EDK2 Nightly Base URL: $EDK2_BASE_URL"
    log_info "Firmware Directory: $FIRMWARE_DIR"
    echo ""

    local arch_firmwares=(
        "x86_64|DEBUGX64_OVMF_CODE.fd|$EDK2_BASE_URL/bin/DEBUGX64_OVMF_CODE.fd|$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_CODE.fd"
        "x86_64|DEBUGX64_OVMF_VARS.fd|$EDK2_BASE_URL/bin/DEBUGX64_OVMF_VARS.fd|$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_VARS.fd"
        "aarch64|DEBUGAARCH64_QEMU_EFI.fd|$EDK2_BASE_URL/bin/DEBUGAARCH64_QEMU_EFI.fd|$FIRMWARE_DIR/aarch64/DEBUGAARCH64_QEMU_EFI.fd"
        "aarch64|DEBUGAARCH64_QEMU_VARS.fd|$EDK2_BASE_URL/bin/DEBUGAARCH64_QEMU_VARS.fd|$FIRMWARE_DIR/aarch64/DEBUGAARCH64_QEMU_VARS.fd"
        "riscv64|DEBUGRISCV64_VIRT.fd|$EDK2_BASE_URL/bin/DEBUGRISCV64_VIRT.fd|$FIRMWARE_DIR/riscv64/DEBUGRISCV64_VIRT.fd"
        "loongarch64|DEBUGLOONGARCH64_QEMU_EFI.fd|$EDK2_BASE_URL/bin/DEBUGLOONGARCH64_QEMU_EFI.fd|$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_EFI.fd"
        "loongarch64|DEBUGLOONGARCH64_QEMU_VARS.fd|$EDK2_BASE_URL/bin/DEBUGLOONGARCH64_QEMU_VARS.fd|$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd"
    )

    local failed=0
    for entry in "${arch_firmwares[@]}"; do
        IFS='|' read -r arch name url dest <<< "$entry"
        if ! download_file "$url" "$dest" "$arch/$name"; then
            ((failed++))
        fi
    done

    echo ""
    if [[ $failed -eq 0 ]]; then
        log_success "All firmware files downloaded successfully!"
    else
        log_error "$failed file(s) failed to download"
        return 1
    fi
}

verify_firmware() {
    log_info "Verifying firmware files..."

    local all_ok=true
    local check_files=(
        "$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_CODE.fd"
        "$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_VARS.fd"
        "$FIRMWARE_DIR/aarch64/DEBUGAARCH64_QEMU_EFI.fd"
        "$FIRMWARE_DIR/aarch64/DEBUGAARCH64_QEMU_VARS.fd"
        "$FIRMWARE_DIR/riscv64/DEBUGRISCV64_VIRT.fd"
        "$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_EFI.fd"
        "$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd"
    )

    for f in "${check_files[@]}"; do
        if [[ -f "$f" && -s "$f" ]]; then
            local size=$(du -h "$f" | cut -f1)
            log_success "$(basename $f): $size"
        else
            log_error "$(basename $f): MISSING"
            all_ok=false
        fi
    done

    if $all_ok; then
        log_success "All firmware files verified!"
    else
        log_error "Some firmware files are missing or empty"
        return 1
    fi
}

list_firmware() {
    echo ""
    echo "=== EDK2 Nightly Firmware ==="
    echo ""
    echo "X64 (OVMF):"
    echo "  - DEBUGX64_OVMF_CODE.fd  (Firmware image)"
    echo "  - DEBUGX64_OVMF_VARS.fd  (Variable store)"
    echo ""
    echo "AARCH64 (ArmVirtPkg):"
    echo "  - DEBUGAARCH64_QEMU_EFI.fd  (Firmware image)"
    echo "  - DEBUGAARCH64_QEMU_VARS.fd  (Variable store)"
    echo ""
    echo "RISCV64:"
    echo "  - DEBUGRISCV64_VIRT.fd  (Combined firmware)"
    echo ""
    echo "LOONGARCH64:"
    echo "  - DEBUGLOONGARCH64_QEMU_EFI.fd  (Firmware image)"
    echo "  - DEBUGLOONGARCH64_QEMU_VARS.fd  (Variable store)"
    echo ""
    echo "Download location: $FIRMWARE_DIR"
}

run_qemu() {
    local arch="$1"
    local disk_img="${2:-build/images/disk.img}"
    local serial_log="${3:-build/images/serial.log}"

    if [[ ! -f "$disk_img" ]]; then
        log_warn "Disk image not found: $disk_img"
        log_info "Build the disk image first with: make build"
    fi

    mkdir -p "$(dirname "$serial_log")"
    mkdir -p "$(dirname "$disk_img")"

    case "$arch" in
        x86_64)
            local ovmf_code="$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_CODE.fd"
            local ovmf_vars="$FIRMWARE_DIR/x86_64/DEBUGX64_OVMF_VARS.fd"

            if [[ ! -f "$ovmf_code" ]]; then
                log_error "OVMF CODE not found: $ovmf_code"
                log_info "Run: $0 download"
                exit 1
            fi

            log_info "Starting QEMU (x86_64) with UEFI..."
            qemu-system-x86_64 \
                -machine q35 \
                -m 8G \
                -smp 2 \
                -drive if=pflash,format=raw,unit=0,readonly=on,file="$ovmf_code" \
                -drive if=pflash,format=raw,unit=1,file="$ovmf_vars" \
                -drive format=raw,file="$disk_img" \
                -boot c \
                -net none \
                -serial file:"$serial_log" \
                -display gtk
            ;;

        aarch64)
            local efi_fw="$FIRMWARE_DIR/aarch64/DEBUGAARCH64_QEMU_EFI.fd"

            if [[ ! -f "$efi_fw" ]]; then
                log_error "AArch64 firmware not found: $efi_fw"
                log_info "Run: $0 download"
                exit 1
            fi

            log_info "Starting QEMU (aarch64) with UEFI..."
            qemu-system-aarch64 \
                -machine virt \
                -m 8G \
                -smp 2 \
                -cpu cortex-a57 \
                -pflash "$efi_fw" \
                -drive if=none,file="$disk_img",format=raw,id=hd0 \
                -device virtio-blk-device,drive=hd0 \
                -boot firmware \
                -net none \
                -serial file:"$serial_log" \
                -display gtk
            ;;

        riscv64)
            local virt_fw="$FIRMWARE_DIR/riscv64/DEBUGRISCV64_VIRT.fd"

            if [[ ! -f "$virt_fw" ]]; then
                log_error "RISC-V firmware not found: $virt_fw"
                log_info "Run: $0 download"
                exit 1
            fi

            log_info "Starting QEMU (riscv64) with UEFI..."
            qemu-system-riscv64 \
                -machine virt \
                -m 8G \
                -smp 2 \
                -pflash "$virt_fw" \
                -drive if=none,file="$disk_img",format=raw,id=hd0 \
                -device virtio-blk-device,drive=hd0 \
                -boot firmware \
                -net none \
                -serial file:"$serial_log" \
                -display gtk
            ;;

        loongarch64)
            local efi_fw="$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_EFI.fd"
            local efi_vars="$FIRMWARE_DIR/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd"

            if [[ ! -f "$efi_fw" ]]; then
                log_error "LoongArch64 firmware not found: $efi_fw"
                log_info "Run: $0 download"
                exit 1
            fi

            log_info "Starting QEMU (loongarch64) with UEFI..."
            qemu-system-loongarch64 \
                -machine virt \
                -m 8G \
                -smp 2 \
                -pflash "$efi_fw" \
                -pflash "$efi_vars" \
                -drive if=none,file="$disk_img",format=raw,id=hd0 \
                -device virtio-blk-device,drive=hd0 \
                -boot firmware \
                -net none \
                -serial file:"$serial_log" \
                -display gtk
            ;;

        *)
            log_error "Unknown architecture: $arch"
            usage
            exit 1
            ;;
    esac
}

FORCE="no"
COMMAND=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)
            FIRMWARE_DIR="$2"
            shift 2
            ;;
        -f|--force)
            FORCE="yes"
            shift
            ;;
        -q|--quiet)
            exec >/dev/null 2>&1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        download|verify|list|run-x86_64|run-aarch64|run-riscv64|run-loongarch64)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

case "${COMMAND:-download}" in
    download)
        download_all
        ;;
    verify)
        verify_firmware
        ;;
    list)
        list_firmware
        ;;
    run-x86_64)
        run_qemu "x86_64" "$@"
        ;;
    run-aarch64)
        run_qemu "aarch64" "$@"
        ;;
    run-riscv64)
        run_qemu "riscv64" "$@"
        ;;
    run-loongarch64)
        run_qemu "loongarch64" "$@"
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
