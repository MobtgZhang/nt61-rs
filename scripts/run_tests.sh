#!/bin/bash
# Test Runner Script for NT6.1.7601
#
# This script runs all tests: host-side unit tests, tool tests, and QEMU smoke tests.
#
# Usage:
#   ./scripts/run_tests.sh           # Run all tests
#   ./scripts/run_tests.sh host      # Run host tests only
#   ./scripts/run_tests.sh pe        # Run PE validation tests
#   ./scripts/run_tests.sh qemu      # Run QEMU smoke tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NT61_DIR="$PROJECT_ROOT/nt61"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo not found. Please install Rust."
        exit 1
    fi

    # Check QEMU (for QEMU tests)
    if [ "$1" = "qemu" ] || [ "$1" = "all" ]; then
        if ! command -v qemu-system-x86_64 &> /dev/null; then
            log_error "qemu-system-x86_64 not found. Please install QEMU."
            exit 1
        fi
    fi

    log_info "Prerequisites OK"
}

# Run host-side tests
run_host_tests() {
    log_section "Running Host-Side Tests"

    cd "$NT61_DIR"

    log_info "Running nt61 unit tests..."
    cargo test -p nt61 --test '*' -- --nocapture || {
        log_warn "Some nt61 tests failed"
    }

    log_info "Running nt61-tools tests..."
    cargo test -p nt61-tools -- --nocapture || {
        log_warn "Some nt61-tools tests failed"
    }
}

# Run PE validation tests
run_pe_tests() {
    log_section "Running PE Validation Tests"

    cd "$NT61_DIR"

    log_info "Running PE validation..."
    cargo run -p nt61-tools --features with-nt61 --bin pe-test || {
        log_warn "PE validation tests failed"
    }
}

# Run QEMU smoke tests
run_qemu_tests() {
    log_section "Running QEMU Smoke Tests"

    cd "$NT61_DIR"

    # Check OVMF
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
    if [ ! -f "$OVMF_CODE" ]; then
        log_error "OVMF_CODE not found at $OVMF_CODE"
        log_info "Install with: sudo apt install ovmf"
        exit 1
    fi

    log_info "Building kernel..."
    make build-ntfs

    log_info "Running QEMU smoke tests (timeout 120s)..."

    mkdir -p build/images

    timeout 120 qemu-system-x86_64 \
        -machine q35 \
        -m 8G \
        -smp 2 \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
        -drive "if=pflash,format=raw,unit=1,file=/usr/share/OVMF/OVMF_VARS_4M.ms.fd,if=none,id=ovmf_vars" \
        -drive "format=raw,file=build/images/disk.img" \
        -boot c \
        -net none \
        -serial "file:build/images/serial.log" \
        -display none \
        || true

    log_info "Serial log output:"
    if [ -f build/images/serial.log ]; then
        cat build/images/serial.log
    else
        log_warn "Serial log not found"
    fi
}

# Run all tests
run_all_tests() {
    log_section "Running All Tests"

    run_host_tests
    run_pe_tests
    run_qemu_tests

    log_section "Test Summary"
    log_info "All tests completed!"
    log_info "Check the output above for any failures."
}

# Format check
run_fmt_check() {
    log_section "Running Format Check"

    cd "$NT61_DIR"

    log_info "Checking code formatting..."
    cargo fmt --all -- --check || {
        log_error "Code formatting issues found!"
        log_info "Fix with: cargo fmt --all"
        exit 1
    }

    log_info "Format check passed!"
}

# Main
main() {
    case "${1:-all}" in
        host)
            check_prerequisites host
            run_host_tests
            ;;
        pe)
            check_prerequisites pe
            run_pe_tests
            ;;
        qemu)
            check_prerequisites qemu
            run_qemu_tests
            ;;
        fmt|fmt-check)
            check_prerequisites fmt
            run_fmt_check
            ;;
        all)
            check_prerequisites all
            run_fmt_check
            run_all_tests
            ;;
        *)
            echo "Usage: $0 {host|pe|qemu|fmt|all}"
            echo ""
            echo "Commands:"
            echo "  host    - Run host-side unit tests only"
            echo "  pe      - Run PE validation tests only"
            echo "  qemu    - Run QEMU smoke tests only"
            echo "  fmt     - Run format check only"
            echo "  all     - Run all tests (default)"
            exit 1
            ;;
    esac
}

main "$@"
