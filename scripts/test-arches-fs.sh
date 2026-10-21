#!/bin/bash

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NT61_DIR="${ROOT}/nt61"
FIRMWARE_DIR="${FIRMWARE_DIR:-${ROOT}/scripts/firmware}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-35}"
BUILD_DIR="${BUILD_DIR:-${NT61_DIR}/build/x86_64/ntfs}"
if [[ "${BUILD_DIR}" = /* ]]; then
    BUILD_DIR="${BUILD_DIR%/}"
else
    BUILD_DIR="${NT61_DIR}/${BUILD_DIR%/}"
fi
LOG_DIR="${BUILD_DIR}/images/harness"
SUMMARY_FILE="${LOG_DIR}/summary.txt"

ARCHES=(
    x86_64
    aarch64
    riscv64
    loongarch64
)
FORMATS=(
    ntfs
    fat32
    ext4
)

pass_count=0
fail_count=0
declare -a failures=()

log() {
    printf '%s\n' "$*"
}

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required command '$1' is not installed"
        return 1
    fi
}

require_qemu() {
    local arch="$1"
    require "qemu-system-${arch}"
}

build_image() {
    local arch="$1"
    local format="$2"

    log "Building ${arch}/${format} image..."
    (cd "${NT61_DIR}" && env -u BUILD_DIR make ARCH="${arch}" FORMAT="${format}" build >/dev/null) || {
        log "ERROR: failed to build ${arch}/${format}"
        return 1
    }
}

prepare_x86_firmware() {
    local vars_file="$1"
    local template="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"

    mkdir -p "$(dirname "${vars_file}")"
    if [[ ! -f "${vars_file}" ]]; then
        if [[ -f "${template}" ]]; then
            cp "${template}" "${vars_file}"
        else
            dd if=/dev/zero of="${vars_file}" bs=1M count=1 2>/dev/null
        fi
    fi
}

prepare_padded_file() {
    local output="$1"
    local source_file="$2"
    local padded_mib="$3"

    mkdir -p "$(dirname "${output}")"
    if [[ -f "${output}" ]]; then
        return 0
    fi
    if [[ ! -f "${source_file}" ]]; then
        return 1
    fi

    dd if=/dev/zero of="${output}" bs=1M count="${padded_mib}" 2>/dev/null
    dd if="${source_file}" of="${output}" conv=notrunc 2>/dev/null
}

run_cell() {
    local arch="$1"
    local format="$2"
    local label="${arch}/${format}"
    local build_root="${BUILD_DIR%/}"
    local images_dir
    local serial_log

    images_dir="${NT61_DIR}/build/${arch}/${format}/images"
    serial_log="${images_dir}/serial.log"

    build_image "${arch}" "${format}" || {
        printf '%-18s : FAIL (build)\n' "${label}" | tee -a "${SUMMARY_FILE}"
        return 1
    }

    require_qemu "${arch}" || {
        printf '%-18s : FAIL (qemu-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
        return 1
    }

    local qemu_cmd=()
    case "${arch}" in
        x86_64)
            local ovmf_code="/usr/share/OVMF/OVMF_CODE_4M.fd"
            local edk2_ovmf="${FIRMWARE_DIR}/x86_64/DEBUGX64_OVMF_CODE.fd"
            if [[ ! -f "${ovmf_code}" && ! -f "${edk2_ovmf}" ]]; then
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            fi
            prepare_x86_firmware "${images_dir}/OVMF_VARS.fd"
            qemu_cmd=(qemu-system-x86_64 -machine q35 -m 4G -smp 2)
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=${ovmf_code}")
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=1,file=${images_dir}/OVMF_VARS.fd")
            qemu_cmd+=(-drive "format=raw,file=${images_dir}/disk.img")
            qemu_cmd+=(-boot c -net none)
            ;;
        aarch64)
            local source_code="${FIRMWARE_DIR}/aarch64/DEBUGAARCH64_QEMU_EFI.fd"
            local source_vars="${FIRMWARE_DIR}/aarch64/DEBUGAARCH64_QEMU_VARS.fd"
            prepare_padded_file "${images_dir}/edk2_aarch64_efi_padded.fd" "${source_code}" 64 || {
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            }
            prepare_padded_file "${images_dir}/edk2_aarch64_vars.fd" "${source_vars}" 64 || {
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            }
            qemu_cmd=(qemu-system-aarch64 -machine virt -m 4G -smp 2 -cpu cortex-a57)
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=${images_dir}/edk2_aarch64_efi_padded.fd")
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=1,file=${images_dir}/edk2_aarch64_vars.fd")
            qemu_cmd+=(-drive "if=none,file=${images_dir}/disk.img,format=raw,id=hd0")
            qemu_cmd+=(-device virtio-blk-pci,drive=hd0 -boot order=c -net none)
            ;;
        riscv64)
            local source_code="${FIRMWARE_DIR}/riscv64/DEBUGRISCV64_VIRT.fd"
            prepare_padded_file "${images_dir}/edk2_riscv64_virt_padded.fd" "${source_code}" 32 || {
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            }
            local source_x86_vars="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
            prepare_padded_file "${images_dir}/edk2_ovmf_vars_riscv64.fd" "${source_x86_vars}" 64 || {
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            }
            qemu_cmd=(qemu-system-riscv64 -machine virt -m 4G -smp 2 -cpu rv64)
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=${images_dir}/edk2_riscv64_virt_padded.fd")
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=1,file=${images_dir}/edk2_ovmf_vars_riscv64.fd")
            qemu_cmd+=(-drive "if=none,file=${images_dir}/disk.img,format=raw,id=hd0")
            qemu_cmd+=(-device virtio-blk-pci,drive=hd0 -boot order=c -net none)
            ;;
        loongarch64)
            local source_code="${FIRMWARE_DIR}/loongarch64/DEBUGLOONGARCH64_QEMU_EFI.fd"
            local source_vars="${FIRMWARE_DIR}/loongarch64/DEBUGLOONGARCH64_QEMU_VARS.fd"
            if [[ ! -f "${source_code}" || ! -f "${source_vars}" ]]; then
                printf '%-18s : FAIL (firmware-missing)\n' "${label}" | tee -a "${SUMMARY_FILE}"
                return 1
            fi
            qemu_cmd=(qemu-system-loongarch64 -machine virt -m 4G -smp 2 -cpu la464)
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=${source_code}")
            qemu_cmd+=(-drive "if=pflash,format=raw,unit=1,file=${source_vars}")
            qemu_cmd+=(-drive "if=none,file=${images_dir}/disk.img,format=raw,id=hd0")
            qemu_cmd+=(-device virtio-blk-pci,drive=hd0 -boot order=c -net none)
            ;;
        *)
            printf '%-18s : FAIL (unsupported-arch)\n' "${label}" | tee -a "${SUMMARY_FILE}"
            return 1
            ;;
    esac

    rm -f "${serial_log}"
    mkdir -p "${images_dir}"
    log "Running QEMU ${label} (${BOOT_TIMEOUT}s watchdog)..."
    if [[ "${BOOT_TIMEOUT}" -gt 0 ]] 2>/dev/null; then
        timeout "${BOOT_TIMEOUT}" "${qemu_cmd[@]}" -display none -serial "file:${serial_log}" >/dev/null 2>&1 || true
    else
        "${qemu_cmd[@]}" -display none -serial "file:${serial_log}" >/dev/null 2>&1 || true
    fi

    if [[ -f "${serial_log}" ]] && grep -qE 'C:\\>|^Phase 15|Boot mode: Safe Mode' "${serial_log}"; then
        printf '%-18s : PASS\n' "${label}" | tee -a "${SUMMARY_FILE}"
        return 0
    fi

    printf '%-18s : FAIL (cmd-not-reached, log=%s)\n' "${label}" "${serial_log}" | tee -a "${SUMMARY_FILE}"
    return 1
}

mkdir -p "${LOG_DIR}"
: > "${SUMMARY_FILE}"

log "=== Multi-arch QEMU boot grid ==="
for arch in "${ARCHES[@]}"; do
    for format in "${FORMATS[@]}"; do
        if run_cell "${arch}" "${format}"; then
            pass_count=$((pass_count + 1))
        else
            fail_count=$((fail_count + 1))
            failures+=("${arch}/${format}")
        fi
    done
done

log ""
log "=== Summary: ${pass_count} passed, ${fail_count} failed ==="
if (( fail_count > 0 )); then
    log "Failures: ${failures[*]}"
    exit 1
fi
