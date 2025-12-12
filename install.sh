#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         FORTRESS ANTI-DDOS INSTALLATION SCRIPT                ║"
echo "║                    XDP/eBPF Protection                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}[1/8] Updating system and installing dependencies...${NC}"
apt update
apt upgrade -y

apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-$(uname -r) \
    gcc \
    make \
    pkg-config \
    libssl-dev \
    libcap-dev \
    bpftool \
    ipset \
    iptables \
    iptables-persistent \
    netfilter-persistent \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    curl \
    wget \
    git \
    jq

echo -e "${YELLOW}[2/8] Installing Python dependencies...${NC}"
apt install -y python3-bpfcc python3-pyroute2 2>/dev/null || true

pip3 install --break-system-packages \
    pyroute2 \
    scapy \
    pyyaml \
    requests \
    prometheus-client \
    psutil 2>/dev/null || pip3 install \
    pyroute2 \
    scapy \
    pyyaml \
    requests \
    prometheus-client \
    psutil 2>/dev/null || true

echo -e "${YELLOW}[3/8] Creating directory structure...${NC}"
mkdir -p /opt/fortress/{src,ebpf,config,logs,data,scripts}
mkdir -p /etc/fortress
mkdir -p /var/log/fortress

echo -e "${YELLOW}[4/8] Copying files...${NC}"
cp -r "$SCRIPT_DIR/src/"* /opt/fortress/src/ 2>/dev/null || true
cp -r "$SCRIPT_DIR/ebpf/"* /opt/fortress/ebpf/ 2>/dev/null || true
cp "$SCRIPT_DIR/config/fortress.yaml" /etc/fortress/ 2>/dev/null || true
cp "$SCRIPT_DIR/sysctl_fortress.conf" /etc/sysctl.d/99-fortress.conf 2>/dev/null || true
cp "$SCRIPT_DIR/scripts/"* /opt/fortress/scripts/ 2>/dev/null || true
cp -r "$SCRIPT_DIR/data/"* /opt/fortress/data/ 2>/dev/null || true

chmod +x /opt/fortress/src/*.py
chmod +x /opt/fortress/scripts/*.sh

echo -e "${YELLOW}[5/8] Compiling eBPF programs...${NC}"
cd /opt/fortress/ebpf
make clean 2>/dev/null || true
make 2>&1 || {
    echo -e "${YELLOW}eBPF compilation skipped (will use BCC runtime compilation)${NC}"
}

echo -e "${YELLOW}[6/8] Applying kernel parameters...${NC}"
sysctl -p /etc/sysctl.d/99-fortress.conf

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 2097152
* hard nofile 2097152
* soft nproc 65535
* hard nproc 65535
root soft nofile 2097152
root hard nofile 2097152
EOF

echo -e "${YELLOW}[7/8] Installing systemd service...${NC}"
cp "$SCRIPT_DIR/fortress.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable fortress

echo -e "${YELLOW}[8/8] Creating CLI symlink...${NC}"
ln -sf /opt/fortress/src/fortress_cli.py /usr/local/bin/fortress
chmod +x /usr/local/bin/fortress

IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    sed -i "s/interface: eth0/interface: $IFACE/" /etc/fortress/fortress.yaml
    echo -e "${GREEN}Detected network interface: $IFACE${NC}"
fi

touch /opt/fortress/data/whitelist.txt
touch /opt/fortress/data/local_blocklist.txt

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              INSTALLATION COMPLETE!                           ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Start service:    systemctl start fortress                   ║"
echo "║  Check status:     fortress status                            ║"
echo "║  View logs:        fortress logs                              ║"
echo "║  Watch traffic:    fortress watch                             ║"
echo "║  Block IP:         fortress block <ip>                        ║"
echo "║  Config file:      /etc/fortress/fortress.yaml                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Starting Fortress service...${NC}"
systemctl start fortress

sleep 2
systemctl status fortress --no-pager || true

echo -e "${GREEN}Fortress is now protecting your server!${NC}"
