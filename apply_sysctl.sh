#!/bin/bash
set -e

cp /opt/fortress/sysctl_fortress.conf /etc/sysctl.d/99-fortress.conf

modprobe nf_conntrack
modprobe ip_conntrack

sysctl -p /etc/sysctl.d/99-fortress.conf

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 2097152
* hard nofile 2097152
* soft nproc 65535
* hard nproc 65535
root soft nofile 2097152
root hard nofile 2097152
EOF

cat >> /etc/pam.d/common-session << 'EOF'
session required pam_limits.so
EOF

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    ethtool -K $IFACE gro on 2>/dev/null || true
    ethtool -K $IFACE gso on 2>/dev/null || true
    ethtool -K $IFACE tso on 2>/dev/null || true
    ethtool -K $IFACE rx on 2>/dev/null || true
    ethtool -K $IFACE tx on 2>/dev/null || true
    ethtool -G $IFACE rx 4096 2>/dev/null || true
    ethtool -G $IFACE tx 4096 2>/dev/null || true
fi

echo "Kernel parameters applied successfully"
