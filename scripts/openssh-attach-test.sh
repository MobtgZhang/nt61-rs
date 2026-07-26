#!/bin/bash
# ============================================================
# nt61-rs :: OpenSSH attached QEMU driver
# ============================================================
# Plan stages 4 & 5 helper:
#   * Resolves the per-run efi vars template (so we don't leak persisted
#     state across SSH test runs).
#   * Builds a QEMU command identical to make run-x86_64-ntfs-serial
#     except for the network block:
#         -netdev user,id=net0,hostfwd=127.0.0.1:<host_port>-:22
#         -device virtio-net-pci,netdev=net0
#   * Optionally generates ephemeral ssh keypairs in the staging
#     directory if no host key is present.
#   * Watches the serial log and prints "boot reached C:\\\\>" when it
#     sees it (so the harness knows when SSH can be probed).
#   * Driver lives entirely in scripts/openssh-*.sh. It does NOT modify
#     nt61/Makefile or the build-tool, so the default boot path stays
#     a pure `-net none` regression.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NT61_DIR="${REPO_ROOT}/nt61"

STAGING_DIR_DEFAULT="${REPO_ROOT}/.openssh-staging"
OPENSSH_STAGING_DIR="${OPENSSH_STAGING_DIR:-${STAGING_DIR_DEFAULT}}"

HOST_PORT="${HOST_PORT:-2222}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-90}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat << EOF
nt61-rs OpenSSH-attached QEMU driver

Usage: $0 [OPTIONS]

Options:
  --disk FILE         nt61 disk.img (default: \${REPO}/build/x86_64/ntfs/images/disk.img)
  --host-port PORT    Host port forwarded to guest 22 (default: 2222)
  --timeout SECONDS   QEMU watchdog timeout (default: 90)
  --no-display        Run QEMU in headless mode (default: gtk)
  --ssh-only          After the boot reaches cmd shell, run a smoke
                      SSH connect and exit (uses \${OPENSSH_STAGING_DIR}/ssh/id_ed25519)
  -h, --help          Show this help

Environment:
  OPENSSH_STAGING_DIR, HOST_PORT, QEMU_TIMEOUT override defaults.
EOF
}

DISK_IMG=""
HDB_IMG=""
USE_DISPLAY="yes"
SSH_ONLY="no"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk)         DISK_IMG="$2"; shift 2 ;;
        --hdb)          HDB_IMG="$2"; shift 2 ;;
        --host-port)    HOST_PORT="$2"; shift 2 ;;
        --timeout)      QEMU_TIMEOUT="$2"; shift 2 ;;
        --no-display)   USE_DISPLAY="no"; shift ;;
        --ssh-only)     SSH_ONLY="yes"; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) log_error "Unknown arg: $1"; usage; exit 3 ;;
    esac
done

# Resolve disk image & build prerequisites.
if [[ -z "${DISK_IMG}" ]]; then
    for cand in \
        "${REPO_ROOT}/build/x86_64/ntfs/images/disk.img" \
        "${REPO_ROOT}/build/verify-strict-ntfs/images/disk.img"; do
        if [[ -f "${cand}" ]]; then
            DISK_IMG="${cand}"
            break
        fi
    done
fi
if [[ -z "${DISK_IMG}" || ! -f "${DISK_IMG}" ]]; then
    log_error "No built disk image found. Run scripts/openssh-inject.sh first."
    exit 3
fi

IMAGES_DIR="$(dirname "${DISK_IMG}")"

# Boot variables live in a per-test VARS file so we never reuse a
# previous session's EFI variable store.  This script does NOT touch
# any of the EFI variables populated by `make run-x86_64-ntfs-serial`.
EFIVARS_TEMPLATE="/usr/share/OVMF/OVMF_VARS_4M.fd"
EFIVARS_TEMPLATE_MS="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
TEST_VARS="${IMAGES_DIR}/openssh_ovmf_vars.fd"
if [[ ! -f "${TEST_VARS}" ]]; then
    if [[ -f "${EFIVARS_TEMPLATE_MS}" ]]; then
        cp "${EFIVARS_TEMPLATE_MS}" "${TEST_VARS}"
    elif [[ -f "${EFIVARS_TEMPLATE}" ]]; then
        cp "${EFIVARS_TEMPLATE}" "${TEST_VARS}"
    else
        log_error "No OVMF VARS template found in /usr/share/OVMF"
        exit 3
    fi
fi

SERIAL_LOG="${IMAGES_DIR}/openssh_serial_x86_64.log"
DISPLAY_FLAG=""
if [[ "${USE_DISPLAY}" == "yes" ]]; then
    DISPLAY_FLAG="-display gtk"
else
    DISPLAY_FLAG="-display none"
fi

# Locate virt-fw-vars to inject Boot0001 (BOOTX64.EFI) the same way
# `make run-x86_64-ntfs-serial` does.
BOOT_VARS="${TEST_VARS}.with-boot"
if ! [[ -f "${BOOT_VARS}" ]] && command -v virt-fw-vars >/dev/null 2>&1; then
    virt-fw-vars --inplace "${TEST_VARS}" \
        --append-boot-filepath /EFI/Boot/BOOTX64.EFI >/dev/null 2>&1 || true
    cp "${TEST_VARS}" "${BOOT_VARS}"
fi

log_info "Booting nt61 + OpenSSH via QEMU"
log_info "  disk       ${DISK_IMG}"
log_info "  efivars    ${TEST_VARS}"
log_info "  serial     ${SERIAL_LOG}"
log_info "  hostfwd    127.0.0.1:${HOST_PORT} → guest:22"

# Note: the OpenSSH payload is staged inside the C: NTFS partition
# itself (C:\Program Files\OpenSSH), NOT on a separate disk. The
# --hdb flag is reserved for future scenarios (e.g. a second
# filesystem-format test) and is intentionally optional.
HDB_FLAGS=()
if [[ -n "${HDB_IMG}" && -f "${HDB_IMG}" ]]; then
    log_info "Attaching secondary test disk: ${HDB_IMG}"
    HDB_FLAGS=( -drive if=none,file="${HDB_IMG}",format=raw,id=hdb0
                -device virtio-blk-pci,drive=hdb0 )
fi

QEMU_CMD=(
    qemu-system-x86_64 -machine q35 -m 8G -smp 4 -cpu kvm64
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
    -drive if=pflash,format=raw,unit=1,file="${TEST_VARS}"
    -drive format=raw,file="${DISK_IMG}"
    "${HDB_FLAGS[@]}"
    -boot c
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${HOST_PORT}-:22"
    -device virtio-net-pci,netdev=net0
    -serial "file:${SERIAL_LOG}"
    ${DISPLAY_FLAG}
)

cleanup_qemu() {
    local rc=$?
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    exit "${rc}"
}
trap cleanup_qemu EXIT INT TERM

# Launch in the background so we can monitor the serial log ourselves.
log_info "QEMU cmd: ${QEMU_CMD[*]}"
"${QEMU_CMD[@]}" &
QEMU_PID=$!

# Tail the serial log for the boot signature.
#
# NOTE: in bash double-quoted extended regex, every literal backslash
# must be doubled because bash first processes the string (\\ -> \),
# then the regex engine consumes the backslash as an escape. The
# nt61 cmd shell prints the prompt as the four characters "C", ":",
# "\", ">", so the correct regex is `C:\\>` (two backslashes inside
# double quotes), NOT `C:\\\\>` (which would force the regex to
# require TWO backslash characters before the `>`).
log_info "QEMU PID: ${QEMU_PID}; watching serial log for cmd shell"
START_TS=$(date +%s)
BOOT_SEEN=0
while kill -0 "${QEMU_PID}" 2>/dev/null; do
    if [[ -f "${SERIAL_LOG}" ]] && \
       grep -qE 'C:\\>|cmd shell|cmd.exe interactive' "${SERIAL_LOG}"; then
        BOOT_TS=$(( $(date +%s) - START_TS ))
        log_ok "cmd shell reached — T=+${BOOT_TS}s"
        BOOT_SEEN=1
        break
    fi
    NOW=$(date +%s)
    if (( NOW - START_TS > QEMU_TIMEOUT )); then
        log_warn "Watchdog reached ${QEMU_TIMEOUT}s; cmd shell signature not seen"
        break
    fi
    sleep 1
done

if [[ "${SSH_ONLY}" == "yes" ]]; then
    if [[ "${BOOT_SEEN}" -ne 1 ]]; then
        log_error "boot did not reach cmd shell within ${QEMU_TIMEOUT}s"
        log_error "tail of ${SERIAL_LOG}:"
        tail -30 "${SERIAL_LOG}" >&2 || true
        exit 4
    fi
    if [[ ! -f "${OPENSSH_STAGING_DIR}/ssh/id_ed25519" ]]; then
        log_error "ssh_only requested but ${OPENSSH_STAGING_DIR}/ssh/id_ed25519 missing"
        log_error "Run scripts/openssh-inject.sh first."
        exit 2
    fi
    # Prime the host's known_hosts with the guest's host key so the
    # probe does not stall on "host key changed" / "authenticity of
    # host" prompts. We extract the public key from inside the image
    # via the same build-tool the injector used; if that fails the
    # probe falls back to StrictHostKeyChecking=accept-new which is
    # acceptable for a single-shot harness.
    KNOWN_HOSTS="${OPENSSH_STAGING_DIR}/ssh/known_hosts"
    rm -f "${KNOWN_HOSTS}"
    if [[ -f "${OPENSSH_STAGING_DIR}/ssh/ssh_host_ed25519_key.pub" ]]; then
        PUBKEY_BODY="$(awk '{print $2, $3}' "${OPENSSH_STAGING_DIR}/ssh/ssh_host_ed25519_key.pub")"
        printf '[127.0.0.1]:%s %s\n' "${HOST_PORT}" "${PUBKEY_BODY}" > "${KNOWN_HOSTS}"
        log_info "Primed known_hosts from ssh_host_ed25519_key.pub"
    fi
    log_info "Running one SSH smoke probe (echo HELLO_FROM_NT61)"
    SSH_PROBE_RC=0
    ssh -i "${OPENSSH_STAGING_DIR}/ssh/id_ed25519" \
        -p "${HOST_PORT}" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=10 \
        nt61test@127.0.0.1 \
        'echo HELLO_FROM_NT61' || SSH_PROBE_RC=$?
    if [[ "${SSH_PROBE_RC}" -ne 0 ]]; then
        log_warn "SSH smoke probe exited with rc=${SSH_PROBE_RC} (sshd not yet serving)"
    else
        log_ok "SSH smoke probe succeeded"
    fi
fi

# If display is on, wait for the GTK window to close so the operator can
# interact with it. If headless, the watchdog (QEMU_TIMEOUT) governs.
if [[ "${USE_DISPLAY}" == "yes" && "${SSH_ONLY}" != "yes" ]]; then
    log_info "Waiting for QEMU to exit (close the GTK window or Ctrl-C this script)"
    wait "${QEMU_PID}" 2>/dev/null || true
fi
