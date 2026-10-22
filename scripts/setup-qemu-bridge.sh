#!/usr/bin/env bash
set -euo pipefail

BRIDGE="${BRIDGE:-br0}"
PHYSICAL_IF="${PHYSICAL_IF:-eno2}"

if [[ $EUID -ne 0 ]]; then
  echo "This script must run as root (for example: sudo ./scripts/setup-qemu-bridge.sh)." >&2
  exit 1
fi

if ! ip link show "$PHYSICAL_IF" >/dev/null 2>&1; then
  echo "Physical interface $PHYSICAL_IF does not exist." >&2
  exit 1
fi

addr_line=$(ip -4 -o addr show dev "$PHYSICAL_IF" scope global | head -n 1 || true)
if [[ -z $addr_line ]]; then
  echo "Physical interface $PHYSICAL_IF has no global IPv4 address." >&2
  exit 1
fi
read -r _ _ _ BRIDGE_CIDR _ <<< "$addr_line"
GATEWAY=$(ip route show default dev "$PHYSICAL_IF" | awk '/via/ {print $3; exit}' || true)

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
  ip link add "$BRIDGE" type bridge
fi
ip link set "$BRIDGE" up
ip link set "$PHYSICAL_IF" promisc on

if ! bridge link | grep -q "master $BRIDGE"; then
  ip link set "$PHYSICAL_IF" master "$BRIDGE"
fi

if ! ip -4 -o addr show dev "$BRIDGE" scope global | grep -Fq "$BRIDGE_CIDR"; then
  ip addr flush dev "$PHYSICAL_IF"
  ip addr add "$BRIDGE_CIDR" dev "$BRIDGE"
fi

if [[ -n $GATEWAY ]] && ! ip route show default | grep -q "via $GATEWAY dev $BRIDGE"; then
  ip route replace default via "$GATEWAY" dev "$BRIDGE"
fi

mkdir -p /etc/qemu
grep -qx "allow $BRIDGE" /etc/qemu/bridge.conf 2>/dev/null \
  || echo "allow $BRIDGE" >> /etc/qemu/bridge.conf

echo "Bridge ready: $BRIDGE port=$PHYSICAL_IF cidr=$BRIDGE_CIDR gateway=${GATEWAY:-unknown}"
