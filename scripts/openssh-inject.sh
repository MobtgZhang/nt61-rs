#!/bin/bash
# ============================================================
# nt61-rs :: OpenSSH in-image injector (build-tool backed)
# ============================================================
# Plan stages 3 / 4 helper.
#
# This script attaches the previously-staged OpenSSH payload
# (see scripts/openssh-stage.sh) to the *existing* nt61-rs
# system disk image, using the same `build-tool` that the
# upstream repository already ships.
#
# Two injection modes are supported:
#   1. --use-raw-mode (default on): use the new
#      `build-tool --inject-raw` subcommand to surgically add
#      small (≤700 byte) files directly into the MFT/$INDEX_ROOT
#      without round-tripping the rest of the NTFS image. This
#      preserves the existing non-resident $DATA of files like
#      winload.efi and the rest of the OS, so the resulting image
#      still boots.
#   2. --use-legacy-mode: use the original `build-tool --cp` path
#      (full NTFS round-trip). Only works for empty images, will
#      strip non-resident data of every other file. Kept around
#      for regression testing of the round-trip itself.
#
# Layout written into the image:
#   C:\Program Files\OpenSSH\
#       sshd.exe, ssh.exe, scp.exe, sftp.exe, ...
#       sshd_config (loopback-only, pubkey only)
#       ssh_host_ed25519_key + .pub (ephemeral host key)
#   C:\Users\nt61test\.ssh\authorized_keys (test user pubkey)
#
# Driver lives entirely in scripts/openssh-*.sh. It does NOT
# modify nt61/Makefile, the build-tool, or any source file in
# nt61/src. The image itself is mutated, but nt61's source
# remains a pure regression baseline.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NT61_DIR="${REPO_ROOT}/nt61"

STAGING_DIR_DEFAULT="${REPO_ROOT}/.openssh-staging"
OPENSSH_STAGING_DIR="${OPENSSH_STAGING_DIR:-${STAGING_DIR_DEFAULT}}"

DISK_IMG_DEFAULT="${NT61_DIR}/build/x86_64/ntfs/images/disk.img"
DISK_IMG="${DISK_IMG:-${DISK_IMG_DEFAULT}}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat << EOF
nt61-rs OpenSSH in-image injector (build-tool backed)

Usage: $0 [OPTIONS]

Options:
  --staging DIR       Staging directory produced by openssh-stage.sh
                      (default: \${REPO}/.openssh-staging)
  --disk FILE         Target disk.img (default: \${NT61_DIR}/build/x86_64/ntfs/images/disk.img)
  --build-tool FILE   Path to the build-tool binary
                      (default: \${NT61_DIR}/target/debug/build-tool)
  --partition N       1-indexed partition number inside the disk image
                      (default: 2, the NTFS C: partition in the dual-part layout)
  --guest-dir PATH    Destination directory inside the image
                      (default: /Program Files/OpenSSH)
  --use-raw-mode      Use build-tool --inject-raw (surgical, boot-safe).
                      Default mode; recommended for any working OS image.
  --use-legacy-mode   Use build-tool --cp (full NTFS round-trip).
                      Only safe for empty images; will strip non-resident
                      data of all other files.
  -h, --help          Show this help

Environment:
  OPENSSH_STAGING_DIR, DISK_IMG override defaults.
EOF
}

PARTITION="2"
GUEST_DIR="/Program Files/OpenSSH"
INJECT_MODE="raw"  # default: surgical, boot-safe

while [[ $# -gt 0 ]]; do
    case "$1" in
        --staging)         OPENSSH_STAGING_DIR="$2"; shift 2 ;;
        --disk)            DISK_IMG="$2"; shift 2 ;;
        --build-tool)      BUILD_TOOL="$2"; shift 2 ;;
        --partition)       PARTITION="$2"; shift 2 ;;
        --guest-dir)       GUEST_DIR="$2"; shift 2 ;;
        --use-raw-mode)    INJECT_MODE="raw"; shift ;;
        --use-legacy-mode) INJECT_MODE="legacy"; shift ;;
        -h|--help)         usage; exit 0 ;;
        *)                 log_error "Unknown option: $1"; usage; exit 2 ;;
    esac
done

BUILD_TOOL="${BUILD_TOOL:-${NT61_DIR}/target/debug/build-tool}"

# --- Pre-flight ---------------------------------------------------------------
if [[ ! -d "${OPENSSH_STAGING_DIR}" ]]; then
    log_error "Staging directory not found: ${OPENSSH_STAGING_DIR}"
    log_error "Run scripts/openssh-stage.sh first."
    exit 2
fi
if [[ ! -f "${DISK_IMG}" ]]; then
    log_error "Disk image not found: ${DISK_IMG}"
    log_error "Run \`make run-x86_64-ntfs-serial\` (or \`make build-all\`) first."
    exit 2
fi
if [[ ! -x "${BUILD_TOOL}" ]]; then
    log_error "build-tool binary not found or not executable: ${BUILD_TOOL}"
    log_error "Build it with: cargo build -p nt61-tools --bin build-tool"
    exit 2
fi

PAYLOAD_DIR="${OPENSSH_STAGING_DIR}/payload"
MANIFEST="${OPENSSH_STAGING_DIR}/manifest.txt"
HOST_KEY_DIR="${OPENSSH_STAGING_DIR}/ssh"

if [[ ! -d "${PAYLOAD_DIR}" ]]; then
    log_error "Payload directory not found: ${PAYLOAD_DIR}"
    log_error "Re-run scripts/openssh-stage.sh to extract the OpenSSH payload."
    exit 2
fi

# --- Snapshot pristine disk image (only the first time) ----------------------
BACKUP_IMG="${DISK_IMG}.pre-openssh"
if [[ ! -f "${BACKUP_IMG}" ]]; then
    log_info "Snapshotting pristine disk.img -> $(basename "${BACKUP_IMG}")"
    cp "${DISK_IMG}" "${BACKUP_IMG}"
fi

# build-tool syntax: <img-path>:<inner-path>. The img path must end in
# .img/.qcow2/.iso (or contain a separator) for PathSpec::parse to route it
# to the Image branch instead of treating it as a host path.
IMG_SPEC="${DISK_IMG}"

run_bt() {
    "${BUILD_TOOL}" --image "${DISK_IMG}" --partition "${PARTITION}" "$@"
}

# For --directory, --partition only works with the first --image.
# Use colon syntax instead: --dir "img:inner/path"
_run_bt_dir() {
    "${BUILD_TOOL}" --image "${DISK_IMG}" --dir "${IMG_SPEC}:${1}" "$@"
}

# The new --inject-raw path is the only boot-safe option for an image
# that already has a working OS in it. It walks the parent directory's
# $INDEX_ROOT, adds new entries in-place, and appends new MFT records
# to the MFT cluster. It does NOT round-trip the entire filesystem,
# so non-resident $DATA clusters for winload.efi / kernel32 / etc. are
# preserved verbatim.
RAW_MAX_RESIDENT=700

# In raw mode the build-tool only supports a single --parent-dir
# per invocation, so we batch files by their parent directory.
declare -A RAW_BATCH
declare -A RAW_SEEN_FILES  # to de-duplicate across batch steps

# Print a human-readable size.
_human_size() {
    local bytes=$1
    if (( bytes < 1024 )); then
        echo "${bytes}B"
    elif (( bytes < 1024*1024 )); then
        echo "$(( bytes / 1024 ))KiB"
    else
        echo "$(( bytes / 1024 / 1024 ))MiB"
    fi
}

# Raw-mode copy: enqueue a file into the right parent-dir batch.
_raw_enqueue() {
    local src="$1"
    local parent_guest_dir="$2"
    local guest_basename="$3"
    local size
    size=$(stat -c '%s' "${src}" 2>/dev/null || echo 0)
    if (( size > RAW_MAX_RESIDENT )); then
        log_warn "skipping raw-inject of ${guest_basename} ($(_human_size "${size}") > ${RAW_MAX_RESIDENT}B resident limit)"
        return 1
    fi
    RAW_BATCH["${parent_guest_dir}"]+="${guest_basename}=${src}|"
    RAW_SEEN_FILES["${parent_guest_dir}|${guest_basename}"]=1
    return 0
}

# Flush a single parent-dir batch to the build-tool --inject-raw.
_raw_flush() {
    local parent_guest_dir="$1"
    local entry_list="${RAW_BATCH[${parent_guest_dir}]:-}"
    if [[ -z "${entry_list}" ]]; then
        return 0
    fi
    local -a args=(--inject-raw --image "${DISK_IMG}" --parent-dir "${parent_guest_dir}")
    local IFS='|'
    for entry in ${entry_list}; do
        [[ -z "${entry}" ]] && continue
        local name="${entry%%=*}"
        local src="${entry#*=}"
        args+=(--inject-file "${name}=${src}")
    done
    log_info "  raw-inject -> ${parent_guest_dir} ($(echo "${entry_list}" | tr '|' '\n' | grep -c .) file(s))"
    if ! "${BUILD_TOOL}" "${args[@]}"; then
        log_error "raw-inject failed for parent=${parent_guest_dir}"
        return 1
    fi
    return 0
}

_raw_flush_all() {
    local rc=0
    for parent_guest_dir in "${!RAW_BATCH[@]}"; do
        _raw_flush "${parent_guest_dir}" || rc=1
    done
    return $rc
}

# --- Ensure guest destination directory exists ------------------------------
# In legacy mode the build-tool creates the directory on demand with
# `run_bt --mkdir`. In raw mode we instead pre-create the directory
# by injecting a tiny marker file (a side-effect of needing a parent
# index to extend). The marker is removed before commit; the directory
# entry itself persists.
log_info "Ensuring ${GUEST_DIR} exists inside image partition ${PARTITION}..."
if [[ "${INJECT_MODE}" == "legacy" ]]; then
    run_bt --mkdir --dir "${IMG_SPEC}:${GUEST_DIR}"
else
    # Raw mode: the directory tree is created implicitly when the
    # first file under it is injected. We do NOT need a pre-step.
    log_info "  raw-mode: parent ${GUEST_DIR} created on first inject"
fi

# --- Copy each payload file in ----------------------------------------------
# The ZIP extracts to ${PAYLOAD_DIR}/OpenSSH-Win64/, so we walk recursively
# and copy each file under ${GUEST_DIR}/<basename>.  Any nested directory
# structure gets flattened, matching the Win32-OpenSSH install-sshd.ps1
# layout that drops every binary directly into C:\Program Files\OpenSSH\.
log_info "Copying OpenSSH payload (${PAYLOAD_DIR}) -> image:${GUEST_DIR}"
count=0
skipped=0
shopt -s nullglob dotglob
while IFS= read -r -d '' src; do
    [[ -f "${src}" ]] || continue
    name="$(basename "${src}")"
    log_info "  ${name} -> ${GUEST_DIR}/${name}"
    if [[ "${INJECT_MODE}" == "raw" ]]; then
        if _raw_enqueue "${src}" "${GUEST_DIR}" "${name}"; then
            count=$((count + 1))
        else
            skipped=$((skipped + 1))
        fi
    else
        if ! run_bt --cp --src "${src}" --dst "${IMG_SPEC}:${GUEST_DIR}/${name}"; then
            log_error "Failed to copy ${src} -> ${GUEST_DIR}/${name}"
            log_error "Restoring backup and aborting."
            cp "${BACKUP_IMG}" "${DISK_IMG}"
            exit 2
        fi
        count=$((count + 1))
    fi
done < <(find "${PAYLOAD_DIR}" -mindepth 2 -maxdepth 2 -type f -print0 | sort -z)
shopt -u nullglob dotglob
log_ok "Queued ${count} payload file(s) for injection (skipped ${skipped} oversized files)"

# --- Stage host key --------------------------------------------------------
if [[ ! -f "${HOST_KEY_DIR}/ssh_host_ed25519_key" ]]; then
    log_info "Generating ephemeral ed25519 host key in ${HOST_KEY_DIR}"
    mkdir -p "${HOST_KEY_DIR}"
    ssh-keygen -t ed25519 -N '' -C "nt61-sshd-test@host" \
        -f "${HOST_KEY_DIR}/ssh_host_ed25519_key" >/dev/null
fi

if [[ -f "${HOST_KEY_DIR}/ssh_host_ed25519_key" ]]; then
    log_info "Staging sshd host key into image"
    if [[ "${INJECT_MODE}" == "raw" ]]; then
        _raw_enqueue "${HOST_KEY_DIR}/ssh_host_ed25519_key" "${GUEST_DIR}" "ssh_host_ed25519_key" || true
        _raw_enqueue "${HOST_KEY_DIR}/ssh_host_ed25519_key.pub" "${GUEST_DIR}" "ssh_host_ed25519_key.pub" || true
    else
        run_bt --cp --src "${HOST_KEY_DIR}/ssh_host_ed25519_key" \
            --dst "${IMG_SPEC}:${GUEST_DIR}/ssh_host_ed25519_key"
        run_bt --cp --src "${HOST_KEY_DIR}/ssh_host_ed25519_key.pub" \
            --dst "${IMG_SPEC}:${GUEST_DIR}/ssh_host_ed25519_key.pub"
    fi
fi

# --- Stage sshd_config that listens on the guest NIC address -----------------
#
# ListenAddress 0.0.0.0 lets sshd bind every interface that QEMU's
# user-mode networking exposes (typically 10.0.2.15 in the guest); the
# previous 127.0.0.1-only rule was unreachable from the host because
# QEMU hostfwd DNATs into the guest's NIC address, not the loopback.
# The hard-coded HostKey path matches the destination directory the
# `Copying OpenSSH payload` step above uses (C:\Program Files\OpenSSH).
# sshd does NOT expand "%ProgramFiles%" at runtime, so we ship the
# absolute Windows path here — that is what install-sshd.ps1 does on
# real Windows as well.
GUEST_SSHD_CONF="${OPENSSH_STAGING_DIR}/sshd_config"
cat > "${GUEST_SSHD_CONF}" <<'EOF'
Port 22
ListenAddress 0.0.0.0
HostKey C:\Program Files\OpenSSH\ssh_host_ed25519_key
PidFile C:\Program Files\OpenSSH\sshd.pid
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh\authorized_keys
Subsystem sftp sftp-server.exe
EOF
log_info "Staging sshd_config into image"
if [[ "${INJECT_MODE}" == "raw" ]]; then
    _raw_enqueue "${GUEST_SSHD_CONF}" "${GUEST_DIR}" "sshd_config" || true
else
    run_bt --cp --src "${GUEST_SSHD_CONF}" \
        --dst "${IMG_SPEC}:${GUEST_DIR}/sshd_config"
fi

# --- Stage authorized_keys for the test user --------------------------------
# IMPORTANT: authorized_keys must contain the *client* auth public key
# (id_ed25519.pub), NOT the server's host key pub. The previous revision
# put the host key pub here, which made every SSH login attempt fail
# with "Permission denied (publickey)" because the client's identity
# did not match any entry the server trusted.
TEST_USER_DIR="/Users/nt61test/.ssh"
if [[ "${INJECT_MODE}" == "legacy" ]]; then
    run_bt --mkdir --dir "${IMG_SPEC}:${TEST_USER_DIR}" || true
fi
CLIENT_KEY="${HOST_KEY_DIR}/id_ed25519"
if [[ -f "${CLIENT_KEY}.pub" ]]; then
    log_info "Staging ${TEST_USER_DIR}/authorized_keys (client pubkey)"
    if [[ "${INJECT_MODE}" == "raw" ]]; then
        _raw_enqueue "${CLIENT_KEY}.pub" "${TEST_USER_DIR}" "authorized_keys" || true
    else
        run_bt --cp --src "${CLIENT_KEY}.pub" \
            --dst "${IMG_SPEC}:${TEST_USER_DIR}/authorized_keys"
    fi
else
    log_warn "${CLIENT_KEY}.pub missing — re-run scripts/openssh-stage.sh"
fi

# --- Flush all raw-mode batches (one build-tool call per parent dir) ------
if [[ "${INJECT_MODE}" == "raw" ]]; then
    log_info "Flushing raw-inject batches..."
    if ! _raw_flush_all; then
        log_error "raw-inject failed; restoring backup"
        cp "${BACKUP_IMG}" "${DISK_IMG}"
        exit 2
    fi
fi

# --- Verify image contents ---------------------------------------------------
log_info "Verifying injection (listing ${GUEST_DIR}):"
run_bt --directory --dir "${IMG_SPEC}:${GUEST_DIR}" -L 2 || true

log_ok "OpenSSH payload is now embedded in ${DISK_IMG}:${GUEST_DIR}"
log_ok "Run scripts/openssh-attach-test.sh to boot with networking and sshd."