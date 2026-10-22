#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=nt61-qemu-bridge:bookworm

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -f Dockerfile.qemu-bridge -t "$IMAGE" "$REPO_ROOT"
fi

exec docker run --rm --privileged --net=host \
  -v "$REPO_ROOT":/work \
  -v /usr/share/OVMF:/host-firmware:ro \
  -w /work \
  -e BRIDGE="${BRIDGE:-br0}" \
  -e PHYSICAL_IF="${PHYSICAL_IF:-eno2}" \
  -e TCP_HOST_PORT="${TCP_HOST_PORT:-18001}" \
  "$IMAGE" \
  ./scripts/qemu-bridge-inner.sh
