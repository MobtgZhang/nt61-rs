#!/usr/bin/env bash
set -euo pipefail

BRIDGE="${BRIDGE:-br0}"
PHYSICAL_IF="${PHYSICAL_IF:-eno2}"
TCP_HOST_PORT="${TCP_HOST_PORT:-18001}"
QEMU_PID=

cleanup() {
  [[ -n $QEMU_PID ]] && kill "$QEMU_PID" 2>/dev/null || true
  [[ -n ${nc_pid:-} ]] && kill "$nc_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

/work/scripts/setup-qemu-bridge.sh

host_ip=$(ip -4 -o addr show dev "$BRIDGE" scope global | awk '{sub(/\/.*/, "", $4); print $4; exit}')
nc -l -s "$host_ip" -p "$TCP_HOST_PORT" &
nc_pid=$!
sleep 0.2
if ! kill -0 "$nc_pid" 2>/dev/null; then
  echo "Failed to start TCP listener on $host_ip:$TCP_HOST_PORT." >&2
  exit 1
fi

rm -f /work/nt61/build/x86_64/ntfs/images/net-bridge.pcap
rm -f /work/nt61/build/x86_64/ntfs/images/serial_x86_64_net_bridge.log

cd /work/nt61
timeout 180s qemu-system-x86_64 \
  -accel kvm -cpu host \
  -machine q35 \
  -m 4G -smp 4 \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/host-firmware/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,unit=1,file=build/x86_64/ntfs/images/edk2_ovmf_vars_x86_64.fd \
  -drive format=raw,file=build/x86_64/ntfs/images/disk.img \
  -boot c \
  -netdev bridge,id=n0,br="$BRIDGE" \
  -device virtio-net-pci,netdev=n0 \
  -object filter-dump,id=f0,netdev=n0,file=build/x86_64/ntfs/images/net-bridge.pcap \
  -serial file:build/x86_64/ntfs/images/serial_x86_64_net_bridge.log \
  -display none \
  -monitor none

QEMU_PID=

echo "Serial log: /work/nt61/build/x86_64/ntfs/images/serial_x86_64_net_bridge.log"
echo "Packet capture: /work/nt61/build/x86_64/ntfs/images/net-bridge.pcap"
