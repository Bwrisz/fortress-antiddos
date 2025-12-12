#!/bin/bash

echo "Fortress Pre-Start: Initializing..."

sysctl -p /etc/sysctl.d/99-fortress.conf 2>/dev/null || true

modprobe nf_conntrack 2>/dev/null || true
modprobe ip_conntrack 2>/dev/null || true

mkdir -p /var/log/fortress
mkdir -p /opt/fortress/data

ipset create fortress_blocklist hash:ip maxelem 10000000 hashsize 1048576 -exist 2>/dev/null || true
ipset create fortress_blocklist_net hash:net maxelem 1000000 hashsize 262144 -exist 2>/dev/null || true
ipset create fortress_whitelist hash:ip maxelem 100000 hashsize 16384 -exist 2>/dev/null || true
ipset create fortress_whitelist_net hash:net maxelem 10000 hashsize 4096 -exist 2>/dev/null || true
ipset create fortress_geoblock hash:net maxelem 500000 hashsize 131072 -exist 2>/dev/null || true
ipset create fortress_ratelimit hash:ip maxelem 1000000 timeout 300 hashsize 262144 -exist 2>/dev/null || true

if [ -f /opt/fortress/data/whitelist.txt ]; then
    while IFS= read -r ip || [ -n "$ip" ]; do
        [[ "$ip" =~ ^#.*$ ]] && continue
        [[ -z "$ip" ]] && continue
        ipset add fortress_whitelist "$ip" -exist 2>/dev/null || true
    done < /opt/fortress/data/whitelist.txt
fi

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    ip link set dev $IFACE xdp off 2>/dev/null || true
fi

echo "Fortress Pre-Start: Complete"
exit 0
