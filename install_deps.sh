#!/bin/bash
set -e

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
    libc6-dev-i386 \
    graphviz \
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
    jq \
    htop \
    iotop \
    iftop \
    tcpdump \
    net-tools \
    iproute2 \
    ethtool

pip3 install --break-system-packages \
    bcc \
    pyroute2 \
    scapy \
    pyyaml \
    requests \
    prometheus-client \
    psutil \
    hypothesis \
    pytest

mkdir -p /opt/fortress/{src,config,logs,data,ebpf}
mkdir -p /var/log/fortress
mkdir -p /etc/fortress

echo "Dependencies installed successfully"
