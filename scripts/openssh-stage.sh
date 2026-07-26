#!/bin/bash
# ============================================================
# nt61-rs :: OpenSSH-Win64 external test fixture staging
# ============================================================
# Downloads Win32-OpenSSH and unpacks it to a host-side staging
# directory that lives OUTSIDE the workspace. The script is the
# only place that touches the upstream ZIP; nothing it does
# copies binaries into the nt61 source tree, the build output,
# or the disk image.
#
#   * Staging root:   ${OPENSSH_STAGING_DIR:-<repo>/.openssh-staging}
#   * Cache:          <staging>/cache/OpenSSH-Win64.zip
#   * Payload:        <staging>/payload/   (extracted files)
#   * Manifest:       <staging>/manifest.txt
#   * Ephemeral host key + sshd_config are NOT produced here;
#     openssh-attach-test.sh / openssh-inject.sh handle those.
#
# Re-running the script reuses the cached ZIP if its size / SHA
# match the expected fingerprint; otherwise it re-downloads.
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OPENSSH_STAGING_DIR="${OPENSSH_STAGING_DIR:-${REPO_ROOT}/.openssh-staging}"
OPENSSH_VERSION="${OPENSSH_VERSION:-V10.0.0.0p2-Preview}"
# GitHub release asset name (case sensitive). PowerShell/Win32-OpenSSH ships
# the binary as `OpenSSH-Win64.zip` at the root of every tag's release tarball
# attachment; the version string we splice into the URL also has to be the
# exact tag (without the leading 'V').
OPENSSH_TAG="${OPENSSH_TAG:-10.0.0.0p2-Preview}"
OPENSSH_URL="${OPENSSH_URL:-https://github.com/PowerShell/Win32-OpenSSH/releases/download/${OPENSSH_TAG}/OpenSSH-Win64.zip}"
# Expected compressed size (bytes). The 10.0.0.0p2-Preview tag's x64 zip is
# ~10 MB; the value below is the published size as of 2025-09. If GitHub
# ever serves a different binary, we'll surface the mismatch instead of
# silently going forward.
OPENSSH_MIN_BYTES="${OPENSSH_MIN_BYTES:-1048576}"   # 1 MiB sanity floor
OPENSSH_MAX_BYTES="${OPENSSH_MAX_BYTES:-33554432}"  # 32 MiB hard ceiling

CACHE_DIR="${OPENSSH_STAGING_DIR}/cache"
PAYLOAD_DIR="${OPENSSH_STAGING_DIR}/payload"
MANIFEST="${OPENSSH_STAGING_DIR}/manifest.txt"
ZIP_PATH="${CACHE_DIR}/OpenSSH-Win64.zip"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat << EOF
nt61-rs OpenSSH staging helper

Usage: $0 [OPTIONS]

Options:
  --staging-dir DIR   Override the staging root (default: <repo>/.openssh-staging)
  --url URL           Override the upstream ZIP URL
  --tag TAG           Override the GitHub tag (used to splice a derived URL)
  --force            Re-download even when cache is intact
  --clean            Remove the entire staging directory and exit
  -h, --help         Show this help

Environment:
  OPENSSH_STAGING_DIR, OPENSSH_URL, OPENSSH_TAG, OPENSSH_VERSION override
  the defaults declared at the top of this script.

Exit codes:
  0  success
  2  download / verification failure (network, fingerprint mismatch, etc.)
  3  internal staging directory error
EOF
}

require_bin() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required host tool not found: $1"
        exit 3
    fi
}

require_bin unzip
require_bin sha256sum
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER=(curl -fL --connect-timeout 15 --max-time 600 -o)
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER=(wget -q --timeout=600 -O)
else
    log_error "Neither curl nor wget is available on the host"
    exit 3
fi

FORCE="no"
CLEAN_ONLY="no"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --staging-dir) OPENSSH_STAGING_DIR="$2"; shift 2 ;;
        --url)          OPENSSH_URL="$2"; shift 2 ;;
        --tag)          OPENSSH_TAG="$2"; shift 2 ;;
        --force)        FORCE="yes"; shift ;;
        --clean)
            CLEAN_ONLY="yes"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) log_error "Unknown arg: $1"; usage; exit 3 ;;
    esac
done

if [[ "${CLEAN_ONLY}" == "yes" ]]; then
    log_info "Removing ${OPENSSH_STAGING_DIR}"
    rm -rf "${OPENSSH_STAGING_DIR}"
    log_ok "staging directory removed"
    exit 0
fi

mkdir -p "${CACHE_DIR}" "${PAYLOAD_DIR}"

# ---- 1. Download (or reuse) the ZIP -----------------------------------------
download_zip() {
    log_info "Downloading OpenSSH-Win64 (tag=${OPENSSH_TAG}) → ${ZIP_PATH}"
    "${DOWNLOADER[@]}" "${ZIP_PATH}.partial" "${OPENSSH_URL}"

    # Sanity check size.
    local size
    size=$(stat -c '%s' "${ZIP_PATH}.partial")
    if (( size < OPENSSH_MIN_BYTES )); then
        log_error "Downloaded ZIP is too small: ${size} bytes (min ${OPENSSH_MIN_BYTES})"
        rm -f "${ZIP_PATH}.partial"
        exit 2
    fi
    if (( size > OPENSSH_MAX_BYTES )); then
        log_error "Downloaded ZIP exceeds ceiling: ${size} bytes (max ${OPENSSH_MAX_BYTES})"
        rm -f "${ZIP_PATH}.partial"
        exit 2
    fi

    mv -f "${ZIP_PATH}.partial" "${ZIP_PATH}"
}

if [[ -s "${ZIP_PATH}" && "${FORCE}" != "yes" ]]; then
    log_info "Reusing cached ZIP: ${ZIP_PATH}"
else
    download_zip
fi

# ---- 2. Verify ZIP signature (publisher fingerprint) -----------------------
#
# Win32-OpenSSH releases are signed by Microsoft. We don't have the offline
# signature for every preview, so we record the SHA-256 fingerprint the
# *first* time we download the ZIP. On subsequent runs we recompute and
# compare; on mismatch the script aborts before anything is unpacked.
FINGERPRINT_PATH="${CACHE_DIR}/OpenSSH-Win64.zip.sha256"
ZIP_SHA=$(sha256sum "${ZIP_PATH}" | awk '{print $1}')

if [[ ! -f "${FINGERPRINT_PATH}" && "${FORCE}" != "yes" ]]; then
    log_info "Recording first-time SHA-256 fingerprint (${ZIP_SHA:0:16}…)"
    echo "${ZIP_SHA}  OpenSSH-Win64.zip" > "${FINGERPRINT_PATH}"
else
    EXPECTED_SHA=$(awk '{print $1}' "${FINGERPRINT_PATH}")
    if [[ "${EXPECTED_SHA}" != "${ZIP_SHA}" ]]; then
        log_error "ZIP fingerprint changed (expected ${EXPECTED_SHA:0:16}…, got ${ZIP_SHA:0:16}…)."
        log_error "This usually means the cache was overwritten or the upstream ZIP rolled."
        log_error "Re-run with --force to re-record the fingerprint."
        exit 2
    fi
    log_ok "ZIP SHA-256 matches recorded fingerprint"
fi

# ---- 3. Extract with anti-traversal guards ---------------------------------
extract_zip() {
    log_info "Extracting to ${PAYLOAD_DIR} (with anti-traversal guard)"
    # Re-extract from scratch every time; the staging dir is throwaway.
    rm -rf "${PAYLOAD_DIR}"
    mkdir -p "${PAYLOAD_DIR}"

    # Build a list of ZIP entries and reject any with absolute paths or
    # '../' components.  We need to do this *before* invoking `unzip -o`
    # because the default extract behaviour would happily materialise
    # an absolute path or escape the destination directory.
    local entry
    local bad="no"
    while IFS= read -r entry; do
        case "${entry}" in
            /*|*/../*|*/..|../*|*/\\*|*\\..|CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])
                log_error "Rejecting unsafe ZIP entry: ${entry}"
                bad="yes"
                ;;
        esac
    done < <(unzip -Z1 "${ZIP_PATH}")

    if [[ "${bad}" == "yes" ]]; then
        log_error "ZIP contains path-traversal or reserved-DOS entries; aborting."
        exit 2
    fi

    # Now actually extract (we have already validated every entry).
    if ! unzip -q -o "${ZIP_PATH}" -d "${PAYLOAD_DIR}"; then
        log_error "unzip failed for ${ZIP_PATH}"
        exit 2
    fi
}

extract_zip

# ---- 4. Build a deterministic manifest -------------------------------------
log_info "Building manifest: ${MANIFEST}"

{
    echo "# nt61-rs OpenSSH staging manifest"
    echo "# generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "# version:   ${OPENSSH_VERSION}"
    echo "# tag:       ${OPENSSH_TAG}"
    echo "# url:       ${OPENSSH_URL}"
    echo "# sha256:    ${ZIP_SHA}"
    echo "# files:"
} > "${MANIFEST}"

# Stable, sorted list — `find -print` is deterministic enough for our purposes.
while IFS= read -r -d '' f; do
    rel="${f#${PAYLOAD_DIR}/}"
    size=$(stat -c '%s' "${f}")
    sha=$(sha256sum "${f}" | awk '{print $1}')
    printf '  %-12s  %s  %s\n' "${size}" "${sha:0:16}…" "${rel}" >> "${MANIFEST}"
done < <(find "${PAYLOAD_DIR}" -type f -print0 | sort -z)

# ---- 5. Verify mandatory executables & PE machine type ---------------------
require_pe_machine() {
    local exe_path="$1"
    local want_machine="$2"  # e.g. 0x8664
    if [[ ! -f "${exe_path}" ]]; then
        log_error "Required binary missing: ${exe_path}"
        exit 2
    fi
    # MZ -> e_lfanew @ 0x3c (LE u32), then IMAGE_FILE_HEADER.Machine is at
    # e_lfanew+4 (LE u16). We read raw bytes and interpret them little-endian.
    #
    # We use od (not xxd) because od emits one byte at a time and we don't
    # have to reverse a continuous hex string just to compute a u32.
    local b0 b1 b2 b3 machine
    read -r b0 b1 b2 b3 < <(od -An -tu1 -N4 -j 0x3c "${exe_path}")
    local e_lfanew=$(( b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) ))
    local machine_offset=$(( e_lfanew + 4 ))
    read -r machine < <(od -An -tu2 -N2 -j "${machine_offset}" "${exe_path}")
    # `od -tu2 -N2` prints the LE-decoded u16, so no byte juggling needed.
    local want_lc
    want_lc=$(echo "${want_machine}" | tr 'A-F' 'a-f')
    want_lc="${want_lc#0x}"
    local machine_lc
    machine_lc=$(printf '%x' "${machine}")
    if [[ "${machine_lc}" != "${want_lc}" ]]; then
        log_error "PE machine type mismatch: ${exe_path} got 0x${machine_lc}, want 0x${want_lc}"
        exit 2
    fi
    log_ok "$(basename "${exe_path}") Machine=0x${machine_lc}"
}

for exe in sshd.exe ssh.exe scp.exe sftp.exe ssh-keygen.exe ssh-keyscan.exe; do
    # Different releases ship binaries in either /OpenSSH/ or / at the zip root;
    # fall back to top-level search so a future release layout change doesn't break us.
    cand=$(find "${PAYLOAD_DIR}" -type f -iname "${exe}" -print -quit || true)
    if [[ -z "${cand}" ]]; then
        log_error "Required binary not found in payload: ${exe}"
        exit 2
    fi
    require_pe_machine "${cand}" "0x8664"
done

log_ok "staged ${OPENSSH_VERSION} → ${PAYLOAD_DIR}"
log_ok "manifest   ${MANIFEST}"

# ---- 6. Generate ephemeral keys (server host key + client auth key) -------
# Two distinct keypairs are produced here, both ed25519, both with empty
# passphrases:
#
#   ssh_host_ed25519_key  - the server's host key. Lands at
#                           <Program Files>\OpenSSH\ssh_host_ed25519_key
#                           in the image. The matching .pub is the
#                           reference fingerprint used by
#                           openssh-attach-test.sh to verify the guest
#                           over hostfwd.
#
#   id_ed25519            - the client's authentication key. The matching
#                           .pub is written to
#                           <Users\nt61test>\.ssh\authorized_keys in the
#                           image, so the host ssh client can log in to
#                           the guest sshd without a password.
#
# Keeping the two pairs strictly separate is what the previous revision
# got wrong: it mistakenly put the *server* host key's public key in
# authorized_keys, which made every SSH login attempt reject the
# fingerprint mismatch.
HOST_KEY_DIR="${OPENSSH_STAGING_DIR}/ssh"
mkdir -p "${HOST_KEY_DIR}"
HOST_KEY="${HOST_KEY_DIR}/ssh_host_ed25519_key"
if [[ ! -f "${HOST_KEY}" ]]; then
    log_info "Generating ephemeral sshd host key: ${HOST_KEY}"
    ssh-keygen -t ed25519 -N '' -C "nt61-sshd-hostkey@host" \
        -f "${HOST_KEY}" >/dev/null
else
    log_info "Reusing cached host key: ${HOST_KEY}"
fi

CLIENT_KEY="${HOST_KEY_DIR}/id_ed25519"
if [[ ! -f "${CLIENT_KEY}" ]]; then
    log_info "Generating ephemeral client auth key: ${CLIENT_KEY}"
    ssh-keygen -t ed25519 -N '' -C "nt61-sshd-client@host" \
        -f "${CLIENT_KEY}" >/dev/null
else
    log_info "Reusing cached client key: ${CLIENT_KEY}"
fi

echo
echo "Next step: scripts/openssh-inject.sh --disk <disk.img>"
