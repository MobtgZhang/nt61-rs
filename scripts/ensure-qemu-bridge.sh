#!/usr/bin/env bash
set -euo pipefail

BRIDGE="${BRIDGE:-br0}"
HELPER="/usr/lib/qemu/qemu-bridge-helper"
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

need_setup=0

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
  need_setup=1
fi

if [ ! -f /etc/qemu/bridge.conf ] || ! grep -qx "allow $BRIDGE" /etc/qemu/bridge.conf; then
  need_setup=1
fi

if [ -x "$HELPER" ] && [ "$(stat -c '%a' "$HELPER")" != "4755" ]; then
  need_setup=1
fi

if [ "$need_setup" -eq 0 ]; then
  exit 0
fi

echo "QEMU bridge not ready; configuring (may prompt for sudo password)..."
sudo "$REPO_ROOT/scripts/setup-qemu-bridge.sh"
if [ -x "$HELPER" ] && [ "$(stat -c '%a' "$HELPER")" != "4755" ]; then
  sudo chmod u+s "$HELPER"
fi
echo "Bridge setup complete."
