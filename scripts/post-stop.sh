#!/bin/bash

echo "Fortress Post-Stop: Cleaning up..."

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    ip link set dev $IFACE xdp off 2>/dev/null || true
fi

ipset save fortress_blocklist > /opt/fortress/data/blocklist_backup.ipset 2>/dev/null || true
ipset save fortress_whitelist > /opt/fortress/data/whitelist_backup.ipset 2>/dev/null || true

iptables -D INPUT -j FORTRESS 2>/dev/null || true
iptables -F FORTRESS 2>/dev/null || true
iptables -X FORTRESS 2>/dev/null || true

echo "Fortress Post-Stop: Complete"
exit 0
