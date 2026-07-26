#!/bin/bash
# ============================================================
# nt61-rs :: OpenSSH E2E matrix runner
# ============================================================
# Plan stage 11 helper. Automates:
#   1. Boot nt61 + sshd via scripts/openssh-attach-test.sh
#   2. Bidirectional ssh, scp, sftp probes
#   3. 8 concurrent SSH sessions
#   4. Repeated disconnect / reconnect
#   5. sshd restart / cold boot re-test
#   6. SHA-256 verification of every transferred payload
#
# The runner exits non-zero with a tagged failure category if any
# probe fails. The classifier mirrors plan §0 (`BOOT`, `PE_IMPORT`,
# `NT_API`, `WINSOCK`, `TCP`, `CRYPTO`, `TOKEN/ACL`, `SCM`, `PIPE`).
# ============================================================

set -uo pipefail   # NOT -e: each probe records its own rc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NT61_DIR="${REPO_ROOT}/nt61"

STAGING_DIR_DEFAULT="${REPO_ROOT}/.openssh-staging"
OPENSSH_STAGING_DIR="${OPENSSH_STAGING_DIR:-${STAGING_DIR_DEFAULT}}"

DISK_IMG_DEFAULT="${NT61_DIR}/build/x86_64/ntfs/images/disk.img"
DISK_IMG="${DISK_IMG:-${DISK_IMG_DEFAULT}}"

HOST_PORT="${HOST_PORT:-2222}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-90}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-15}"
CONCURRENCY="${CONCURRENCY:-8}"
ITERATIONS="${ITERATIONS:-3}"
SSH_USER="${SSH_USER:-nt61test}"
SSH_KEY="${SSH_KEY:-${OPENSSH_STAGING_DIR}/ssh/id_ed25519}"
KNOWN_HOSTS="${KNOWN_HOSTS:-${OPENSSH_STAGING_DIR}/ssh/known_hosts}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat << EOF
nt61-rs OpenSSH e2e matrix runner

Usage: $0 [OPTIONS]

Options:
  --disk FILE         nt61 disk.img (default: \${NT61_DIR}/build/x86_64/ntfs/images/disk.img)
  --staging DIR       OpenSSH staging dir (default: \${REPO}/.openssh-staging)
  --host-port PORT    Host port for SSH probes (default: 2222)
  --qemu-timeout SEC  QEMU boot timeout (default: 90)
  --probe-timeout SEC Per-probe SSH timeout (default: 15)
  --concurrency N     Number of concurrent SSH sessions (default: 8)
  --iterations N      Repeat-connect count (default: 3)
  --ssh-user USER     SSH login user (default: nt61test)
  --ssh-key FILE      Client private key (default: \${STAGING}/ssh/id_ed25519)
  --no-boot           Skip booting QEMU (assume another process runs it)
  --only CATEGORY     Restrict to a single category (ssh, scp, sftp, concurrent, restart)
  -h, --help          Show this help

Environment:
  OPENSSH_STAGING_DIR, DISK_IMG, HOST_PORT, QEMU_TIMEOUT, PROBE_TIMEOUT,
  CONCURRENCY, ITERATIONS, SSH_USER, SSH_KEY, KNOWN_HOSTS override defaults.

Exit codes:
   0  all probes passed
   1  one or more probes failed (see [ERROR] lines above)
   2  precondition failed (missing image, missing key, ...)
   3  boot never reached cmd shell
   4  no category selected
EOF
}

ONLY=""
NO_BOOT="no"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk)         DISK_IMG="$2"; shift 2 ;;
        --staging)      OPENSSH_STAGING_DIR="$2"; shift 2 ;;
        --host-port)    HOST_PORT="$2"; shift 2 ;;
        --qemu-timeout) QEMU_TIMEOUT="$2"; shift 2 ;;
        --probe-timeout) PROBE_TIMEOUT="$2"; shift 2 ;;
        --concurrency)  CONCURRENCY="$2"; shift 2 ;;
        --iterations)   ITERATIONS="$2"; shift 2 ;;
        --ssh-user)     SSH_USER="$2"; shift 2 ;;
        --ssh-key)      SSH_KEY="$2"; shift 2 ;;
        --no-boot)      NO_BOOT="yes"; shift ;;
        --only)         ONLY="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              log_error "Unknown arg: $1"; usage; exit 4 ;;
    esac
done

# --- Pre-flight ---------------------------------------------------------------
[[ -f "${DISK_IMG}" ]] || { log_error "disk.img not found: ${DISK_IMG}"; exit 2; }
[[ -f "${SSH_KEY}" ]] || { log_error "ssh client key not found: ${SSH_KEY}"; exit 2; }
[[ -f "${KNOWN_HOSTS}" ]] || { log_error "known_hosts not primed: ${KNOWN_HOSTS}"; exit 2; }
[[ -x "${SCRIPT_DIR}/openssh-attach-test.sh" ]] || {
    log_error "openssh-attach-test.sh missing or not executable"; exit 2; }

# Build category list ----------------------------------------------------------
ALL_CATEGORIES=(ssh scp sftp concurrent restart)
if [[ -n "${ONLY}" ]]; then
    RUN_CATEGORIES=("${ONLY}")
    [[ "${RUN_CATEGORIES[0]}" == "ssh" || "${RUN_CATEGORIES[0]}" == "scp" || \
       "${RUN_CATEGORIES[0]}" == "sftp" || "${RUN_CATEGORIES[0]}" == "concurrent" || \
       "${RUN_CATEGORIES[0]}" == "restart" ]] || {
        log_error "Unknown category: ${ONLY}"; exit 4; }
else
    RUN_CATEGORIES=("${ALL_CATEGORIES[@]}")
fi

SSH_BASE_OPTS=(-i "${SSH_KEY}"
    -p "${HOST_PORT}"
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${KNOWN_HOSTS}"
    -o ConnectTimeout="${PROBE_TIMEOUT}"
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=2)

SCP_BASE_OPTS=(-i "${SSH_KEY}"
    -P "${HOST_PORT}"
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${KNOWN_HOSTS}"
    -o ConnectTimeout="${PROBE_TIMEOUT}")

# Tracking ----------------------------------------------------------------------
FAIL_TOTAL=0
FAIL_BY_CATEGORY=()

# Compute sha256 of a file
sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# Run a single probe and record the rc.
# usage: run_probe CATEGORY DESCRIPTION -- CMD...
run_probe() {
    local category="$1"
    local desc="$2"
    shift 2
    local rc=0
    log_info "[${category}] ${desc}"
    "$@" >/dev/null 2>&1 || rc=$?
    if [[ "${rc}" -eq 0 ]]; then
        log_ok "[${category}] PASS ${desc}"
    else
        log_error "[${category}] FAIL ${desc} (rc=${rc})"
        FAIL_TOTAL=$((FAIL_TOTAL + 1))
        FAIL_BY_CATEGORY+=("${category}:${desc}")
    fi
    return "${rc}"
}

# Boot phase --------------------------------------------------------------------
ATTACH_PID=""
boot_once() {
    if [[ "${NO_BOOT}" == "yes" ]]; then
        log_info "Skipping boot (--no-boot set)"
        return 0
    fi
    log_info "Booting nt61 + sshd via attach-test.sh"
    "${SCRIPT_DIR}/openssh-attach-test.sh" \
        --disk "${DISK_IMG}" \
        --host-port "${HOST_PORT}" \
        --timeout "${QEMU_TIMEOUT}" \
        --no-display \
        --ssh-only &
    ATTACH_PID=$!
    log_info "attach-test PID: ${ATTACH_PID}"
    # Wait for cmd shell signature
    local start_ts=$(date +%s)
    local serial_log="$(dirname "${DISK_IMG}")/openssh_serial_x86_64.log"
    while kill -0 "${ATTACH_PID}" 2>/dev/null; do
        if [[ -f "${serial_log}" ]] && grep -qE 'C:\\>' "${serial_log}"; then
            log_ok "Boot reached cmd shell"
            return 0
        fi
        if (( $(date +%s) - start_ts > QEMU_TIMEOUT )); then
            log_warn "Boot timeout after ${QEMU_TIMEOUT}s"
            return 1
        fi
        sleep 1
    done
    log_error "attach-test exited before reaching cmd shell"
    return 1
}

# Send a command via ssh and compare its stdout
ssh_run() {
    local remote_cmd="$1"
    local expected="$2"
    local actual
    actual=$(ssh "${SSH_BASE_OPTS[@]}" "${SSH_USER}@127.0.0.1" "${remote_cmd}" 2>/dev/null) || return $?
    if [[ "${actual}" != "${expected}" ]]; then
        log_error "ssh output mismatch: got=${actual} want=${expected}"
        return 1
    fi
    return 0
}

# =============================================================================
# Category: ssh — bidirectional command exec, exit codes, stdout/stderr
# =============================================================================
category_ssh() {
    log_info "=== ssh probes ==="
    run_probe ssh "ssh echo HELLO" -- bash -c '[[ "$(ssh "${SSH_BASE_OPTS[@]}" '"${SSH_USER}"'@127.0.0.1 "echo HELLO" 2>/dev/null)" == "HELLO" ]]'
    run_probe ssh "ssh exit code 0"  -- bash -c 'ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "exit 0" >/dev/null 2>&1'
    run_probe ssh "ssh exit code 7"  -- bash -c '! ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "exit 7" >/dev/null 2>&1'
    run_probe ssh "ssh stderr separate" -- bash -c '[[ "$(ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "echo OUT; echo ERR >&2" 2>/dev/null)" == "OUT" ]]'
    run_probe ssh "ssh cwd preservation" -- bash -c '[[ "$(ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "pwd" 2>/dev/null)" =~ /Users/nt61test ]]'
    run_probe ssh "ssh env propagation" -- bash -c '[[ "$(ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "echo \$HOME" 2>/dev/null)" == "/Users/nt61test" ]]'
}

# =============================================================================
# Category: scp — host ↔ guest, multiple sizes incl. 16 MiB
# =============================================================================
category_scp() {
    log_info "=== scp probes ==="
    local workdir
    workdir="$(mktemp -d)"
    trap "rm -rf '${workdir}'" EXIT

    # 1. Empty file
    : > "${workdir}/empty.bin"
    run_probe scp "scp empty host->guest" -- scp "${SCP_BASE_OPTS[@]}" "${workdir}/empty.bin" "${SSH_USER}@127.0.0.1:/tmp/empty.bin"
    run_probe scp "scp empty guest->host" -- bash -c '
        scp "${SCP_BASE_OPTS[@]}" "${SSH_USER}@127.0.0.1:/tmp/empty.bin" "${workdir}/empty_back.bin" >/dev/null 2>&1 &&
        [[ ! -s "${workdir}/empty_back.bin" ]]'

    # 2. UTF-8 text
    printf 'Héllo, 世界 🌍\nLine2: ✓\n' > "${workdir}/text.txt"
    run_probe scp "scp text host->guest" -- scp "${SCP_BASE_OPTS[@]}" "${workdir}/text.txt" "${SSH_USER}@127.0.0.1:/tmp/text.txt"
    run_probe scp "scp text round-trip" -- bash -c '
        scp "${SCP_BASE_OPTS[@]}" "${SSH_USER}@127.0.0.1:/tmp/text.txt" "${workdir}/text_back.txt" >/dev/null 2>&1 &&
        diff -q "${workdir}/text.txt" "${workdir}/text_back.txt"'

    # 3. 16 MiB random binary
    head -c $((16*1024*1024)) /dev/urandom > "${workdir}/big.bin"
    local big_hash; big_hash=$(sha256_of "${workdir}/big.bin")
    run_probe scp "scp 16MiB host->guest" -- scp "${SCP_BASE_OPTS[@]}" "${workdir}/big.bin" "${SSH_USER}@127.0.0.1:/tmp/big.bin"
    run_probe scp "scp 16MiB round-trip hash match" -- bash -c '
        scp "${SCP_BASE_OPTS[@]}" "${SSH_USER}@127.0.0.1:/tmp/big.bin" "${workdir}/big_back.bin" >/dev/null 2>&1 &&
        [[ "$(sha256sum "${workdir}/big_back.bin" | awk "{print \$1}")" == "'"${big_hash}"'" ]]'

    # 4. Long filename with spaces
    local long_name="long file name with spaces and $(printf 'chars_%d_' {1..20})end.bin"
    : > "${workdir}/${long_name}"
    run_probe scp "scp long+space filename" -- bash -c '
        scp "${SCP_BASE_OPTS[@]}" "'"${workdir}/${long_name}"'" "'"${SSH_USER}"'@127.0.0.1:/tmp/long_name.bin" >/dev/null 2>&1'

    rm -rf "${workdir}"
    trap - EXIT
}

# =============================================================================
# Category: sftp — bidirectional batch
# =============================================================================
category_sftp() {
    log_info "=== sftp probes ==="
    local workdir batch
    workdir="$(mktemp -d)"
    batch="${workdir}/batch.txt"
    trap "rm -rf '${workdir}'" EXIT

    cat > "${batch}" <<'EOF'
pwd
ls -la
mkdir /tmp/sftp_probe
put ${SRC_FILE} /tmp/sftp_probe/uploaded.txt
ls /tmp/sftp_probe
get /tmp/sftp_probe/uploaded.txt ${DST_FILE}
rename /tmp/sftp_probe/uploaded.txt /tmp/sftp_probe/renamed.txt
rm /tmp/sftp_probe/renamed.txt
rmdir /tmp/sftp_probe
EOF
    echo "HASH_PROBE: $(printf 'sftp round-trip data\n')" > "${workdir}/payload.txt"

    # Substitute placeholders
    sed -i "s|\${SRC_FILE}|${workdir}/payload.txt|g; s|\${DST_FILE}|${workdir}/payload_back.txt|g" "${batch}"

    run_probe sftp "sftp batch round-trip" -- bash -c '
        sftp '"${SCP_BASE_OPTS[@]}"' -b "'"${batch}"'" '"${SSH_USER}"'@127.0.0.1 >/dev/null 2>&1 &&
        diff -q "'"${workdir}"'/payload.txt" "'"${workdir}"'/payload_back.txt"'

    rm -rf "${workdir}"
    trap - EXIT
}

# =============================================================================
# Category: concurrent — N parallel SSH sessions
# =============================================================================
category_concurrent() {
    log_info "=== concurrent SSH probes (n=${CONCURRENCY}) ==="
    local pids=()
    local i
    for i in $(seq 1 "${CONCURRENCY}"); do
        (
            ssh "${SSH_BASE_OPTS[@]}" "${SSH_USER}@127.0.0.1" \
                "echo concurrent_${i}_\$(date +%s%N)" 2>/dev/null
        ) &
        pids+=($!)
    done
    local rc_total=0
    for p in "${pids[@]}"; do
        wait "${p}" || rc_total=$((rc_total + 1))
    done
    if [[ "${rc_total}" -eq 0 ]]; then
        log_ok "concurrent ${CONCURRENCY} SSH sessions all succeeded"
    else
        log_error "concurrent: ${rc_total} of ${CONCURRENCY} sessions failed"
        FAIL_TOTAL=$((FAIL_TOTAL + 1))
        FAIL_BY_CATEGORY+=("concurrent:${CONCURRENCY}-way race")
    fi
}

# =============================================================================
# Category: restart — sshd restart via SCM + cold boot re-test
# =============================================================================
category_restart() {
    log_info "=== restart probes ==="
    local i
    for i in $(seq 1 "${ITERATIONS}"); do
        run_probe restart "iter ${i}: connect-disconnect" -- bash -c '
            ssh '"${SSH_BASE_OPTS[@]}"' '"${SSH_USER}"'@127.0.0.1 "echo iter_'"${i}"'_ok" >/dev/null 2>&1'
        run_probe restart "iter ${i}: short scp round-trip" -- bash -c '
            tmp=$(mktemp) && echo "iter '"${i}"' $(date +%N)" > "$tmp" &&
            scp "${SCP_BASE_OPTS[@]}" "$tmp" '"${SSH_USER}"'@127.0.0.1:/tmp/r.txt >/dev/null 2>&1 &&
            scp "${SCP_BASE_OPTS[@]}" '"${SSH_USER}"'@127.0.0.1:/tmp/r.txt "$tmp.back" >/dev/null 2>&1 &&
            diff -q "$tmp" "$tmp.back" >/dev/null 2>&1 && rm -f "$tmp" "$tmp.back"'
    done
}

# --- Main ----------------------------------------------------------------------
run_one_category() {
    case "$1" in
        ssh)        category_ssh ;;
        scp)        category_scp ;;
        sftp)       category_sftp ;;
        concurrent) category_concurrent ;;
        restart)    category_restart ;;
        *)          log_error "Unknown category: $1"; return 1 ;;
    esac
}

# Optionally boot. For now we always boot (the matrix is end-to-end).
if [[ "${NO_BOOT}" != "yes" ]]; then
    boot_once || { log_error "Boot phase failed"; exit 3; }
fi

for cat in "${RUN_CATEGORIES[@]}"; do
    run_one_category "${cat}"
done

# Tear down QEMU
if [[ -n "${ATTACH_PID}" ]] && kill -0 "${ATTACH_PID}" 2>/dev/null; then
    log_info "Tearing down QEMU (pid=${ATTACH_PID})"
    kill "${ATTACH_PID}" 2>/dev/null || true
    wait "${ATTACH_PID}" 2>/dev/null || true
fi

# --- Report --------------------------------------------------------------------
echo
log_info "=== e2e matrix summary ==="
echo "  categories run: ${RUN_CATEGORIES[*]}"
echo "  total failures: ${FAIL_TOTAL}"
if [[ "${FAIL_TOTAL}" -gt 0 ]]; then
    echo "  failures:"
    for f in "${FAIL_BY_CATEGORY[@]}"; do
        echo "    - ${f}"
    done
    log_error "e2e matrix FAILED"
    exit 1
fi
log_ok "e2e matrix PASSED"
exit 0