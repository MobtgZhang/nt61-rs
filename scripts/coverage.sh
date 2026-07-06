#!/bin/bash
# Coverage Script for NT6.1.7601
#
# This script runs tests with coverage instrumentation and generates reports.
#
# Usage:
#   ./scripts/coverage.sh          # Run tests with coverage
#   ./scripts/coverage.sh html     # Generate HTML report
#   ./scripts/coverage.sh open     # Generate and open HTML report

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check for llvm-tools-preview
check_coverage_tools() {
    if ! command -v llvm-profdata &> /dev/null; then
        log_info "Installing llvm-tools-preview..."
        rustup component add llvm-tools-preview
    fi

    if ! command -v cargo-llvm-cov &> /dev/null; then
        log_info "Installing cargo-llvm-cov..."
        cargo install cargo-llvm-cov
    fi
}

# Run tests with coverage
run_coverage() {
    log_info "Running tests with coverage instrumentation..."

    cd "$PROJECT_ROOT/nt61"

    # Run nt61 host tests
    cargo llvm-cov test --package nt61 --test '*' -- --nocapture || true

    # Run nt61-tools tests
    cargo llvm-cov test --package nt61-tools -- || true

    log_info "Coverage data saved to $COVERAGE_DIR"
}

# Generate HTML report
generate_html_report() {
    log_info "Generating HTML coverage report..."

    cd "$PROJECT_ROOT/nt61"

    cargo llvm-cov report --html --open --output-dir "$COVERAGE_DIR"

    log_info "HTML report generated at: $COVERAGE_DIR/index.html"
}

# Generate text report
generate_text_report() {
    log_info "Generating text coverage report..."

    cd "$PROJECT_ROOT/nt61"

    cargo llvm-cov report --output-dir "$COVERAGE_DIR"

    log_info "Text report available in: $COVERAGE_DIR"
}

# Show coverage summary
show_summary() {
    log_info "Coverage Summary:"

    cd "$PROJECT_ROOT/nt61"

    cargo llvm-cov report --summary-only --output-dir "$COVERAGE_DIR" || true
}

# Main
main() {
    mkdir -p "$COVERAGE_DIR"

    case "${1:-run}" in
        run)
            check_coverage_tools
            run_coverage
            show_summary
            ;;
        html|open)
            check_coverage_tools
            run_coverage
            generate_html_report
            ;;
        report|text)
            check_coverage_tools
            generate_text_report
            show_summary
            ;;
        summary)
            check_coverage_tools
            show_summary
            ;;
        clean)
            log_info "Cleaning coverage data..."
            rm -rf "$COVERAGE_DIR"
            cargo llvm-cov clean
            ;;
        *)
            echo "Usage: $0 {run|html|open|report|text|summary|clean}"
            echo ""
            echo "Commands:"
            echo "  run     - Run tests with coverage (default)"
            echo "  html    - Generate HTML report"
            echo "  open    - Generate and open HTML report"
            echo "  report  - Generate text report"
            echo "  summary - Show coverage summary only"
            echo "  clean   - Clean coverage data"
            exit 1
            ;;
    esac
}

main "$@"
