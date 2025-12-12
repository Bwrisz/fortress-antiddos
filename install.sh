#!/bin/bash
set -e

VERSION="3.0.0"
INSTALL_DIR="/opt/fortress"
CONFIG_DIR="/etc/fortress"
LOG_DIR="/var/log/fortress"
WHITELIST_IP="78.165.141.159"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    [[ $EUID -ne 0 ]] && error "Root yetkisi gerekli"
}

echo ""
echo "============================================"
echo "  FORTRESS ANTI-DDOS v$VERSION"
echo "  Enterprise DDoS Mitigation System"
echo "============================================"
echo ""

check_root

log "Bagimliliklar yukleniyor..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-dev \
    iptables ipset nftables conntrack \
    net-tools procps gcc make \
    clang llvm libbpf-dev 2>/dev/null || true
apt-get install -y -qq linux-headers-$(uname -r) 2>/dev/null || true
apt-get install -y -qq bpftool 2>/dev/null || true
apt-get install -y -qq nginx curl wget
pip3 install --quiet pyyaml psutil 2>/dev/null || true
success "Bagimliliklar yuklendi"

log "Dizinler olusturuluyor..."
mkdir -p $INSTALL_DIR/{src,xdp,nginx,data,scripts,ebpf}
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR
success "Dizinler olusturuldu"

log "Dosyalar kopyalaniyor..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r $SCRIPT_DIR/src/* $INSTALL_DIR/src/ 2>/dev/null || true
cp -r $SCRIPT_DIR/xdp/* $INSTALL_DIR/xdp/ 2>/dev/null || true
cp -r $SCRIPT_DIR/ebpf/* $INSTALL_DIR/ebpf/ 2>/dev/null || true
cp -r $SCRIPT_DIR/nginx/* $INSTALL_DIR/nginx/ 2>/dev/null || true
cp -r $SCRIPT_DIR/data/* $INSTALL_DIR/data/ 2>/dev/null || true
cp -r $SCRIPT_DIR/scripts/* $INSTALL_DIR/scripts/ 2>/dev/null || true
cp $SCRIPT_DIR/config/fortress.yaml $CONFIG_DIR/ 2>/dev/null || true
success "Dosyalar kopyalandi"

log "Kernel parametreleri ayarlaniyor..."
cat > /etc/sysctl.d/99-fortress.conf << 'SYSCTL'
# TCP SYN Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1

# TCP Timeouts - Daha kisa
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_probes = 2
net.ipv4.tcp_keepalive_intvl = 10

# TCP Reuse
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.ip_local_port_range = 1024 65535

# Network Buffers
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# IP Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1

# ICMP Protection
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# Conntrack - Buyuk tablo, kisa timeout
net.netfilter.nf_conntrack_max = 4000000
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 10
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# TCP Memory
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Disable IPv6 (attack surface reduction)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-fortress.conf 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
success "Kernel ayarlandi"

log "XDP derleniyor..."
XDP_ENABLED=0
if [[ -f $INSTALL_DIR/xdp/xdp_filter.c ]]; then
    cd $INSTALL_DIR/xdp
    if clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -c xdp_filter.c -o xdp_filter.o 2>/dev/null; then
        success "XDP derlendi"
        IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [[ -n "$IFACE" ]]; then
            ip link set dev $IFACE xdp off 2>/dev/null || true
            if ip link set dev $IFACE xdp obj xdp_filter.o sec xdp 2>/dev/null; then
                success "XDP yuklendi: $IFACE"
                XDP_ENABLED=1
            else
                warn "XDP yuklenemedi, iptables fallback kullanilacak"
            fi
        fi
    else
        warn "XDP derlenemedi, iptables fallback kullanilacak"
    fi
fi
cd "$SCRIPT_DIR"

log "IPSet'ler olusturuluyor..."
for set in fortress_block fortress_allow fortress_ratelimit fortress_http fortress_syn; do
    ipset destroy $set 2>/dev/null || true
done
sleep 1
ipset create fortress_block hash:ip maxelem 10000000 hashsize 1048576 timeout 3600
ipset create fortress_allow hash:ip maxelem 100000 hashsize 16384
ipset create fortress_ratelimit hash:ip maxelem 1000000 hashsize 262144 timeout 60
ipset create fortress_http hash:ip maxelem 1000000 hashsize 262144 timeout 300
ipset create fortress_syn hash:ip maxelem 1000000 hashsize 262144 timeout 120
ipset add fortress_allow 127.0.0.1
ipset add fortress_allow $WHITELIST_IP
success "IPSet'ler olusturuldu"

log "iptables ayarlaniyor..."
iptables -D INPUT -j FORTRESS 2>/dev/null || true
for chain in FORTRESS FORTRESS_TCP FORTRESS_UDP FORTRESS_HTTP FORTRESS_ICMP; do
    iptables -F $chain 2>/dev/null || true
    iptables -X $chain 2>/dev/null || true
done

for chain in FORTRESS FORTRESS_TCP FORTRESS_UDP FORTRESS_HTTP FORTRESS_ICMP; do
    iptables -N $chain
done

iptables -I INPUT 1 -j FORTRESS

iptables -A FORTRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORTRESS -i lo -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_allow src -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_block src -j DROP
iptables -A FORTRESS -m set --match-set fortress_ratelimit src -j DROP
iptables -A FORTRESS -m set --match-set fortress_http src -j DROP
iptables -A FORTRESS -m set --match-set fortress_syn src -j DROP

iptables -A FORTRESS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,URG URG -j DROP

iptables -A FORTRESS -f -j DROP
iptables -A FORTRESS -m conntrack --ctstate INVALID -j DROP
iptables -A FORTRESS -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

iptables -A FORTRESS -p tcp -j FORTRESS_TCP
iptables -A FORTRESS -p udp -j FORTRESS_UDP
iptables -A FORTRESS -p icmp -j FORTRESS_ICMP
iptables -A FORTRESS -p tcp --dport 80 -j FORTRESS_HTTP
iptables -A FORTRESS -p tcp --dport 443 -j FORTRESS_HTTP
iptables -A FORTRESS -j RETURN

# SYN Flood Protection - Daha agresif
iptables -A FORTRESS_TCP --syn -m limit --limit 30/s --limit-burst 50 -j ACCEPT
iptables -A FORTRESS_TCP --syn -m connlimit --connlimit-above 3 --connlimit-mask 32 -j DROP
iptables -A FORTRESS_TCP --syn -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name syn --hashlimit-htable-expire 5000 -j DROP
iptables -A FORTRESS_TCP --syn -m recent --name SYN --set
iptables -A FORTRESS_TCP --syn -m recent --name SYN --update --seconds 1 --hitcount 10 -j DROP
iptables -A FORTRESS_TCP --syn -j ACCEPT

# ACK Flood Protection
iptables -A FORTRESS_TCP -p tcp --tcp-flags ALL ACK -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A FORTRESS_TCP -p tcp --tcp-flags ALL ACK -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip --hashlimit-name ack --hashlimit-htable-expire 5000 -j DROP

# RST Flood Protection
iptables -A FORTRESS_TCP -p tcp --tcp-flags RST RST -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A FORTRESS_TCP -p tcp --tcp-flags RST RST -j DROP

# New Connection Rate Limit
iptables -A FORTRESS_TCP -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A FORTRESS_TCP -m conntrack --ctstate NEW -j DROP
iptables -A FORTRESS_TCP -j RETURN

# Growtopia UDP Port 17091 - Ozel koruma
iptables -A FORTRESS_UDP -p udp --dport 17091 -m limit --limit 500/s --limit-burst 1000 -j ACCEPT
iptables -A FORTRESS_UDP -p udp --dport 17091 -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-name gtps --hashlimit-htable-expire 5000 -j DROP
iptables -A FORTRESS_UDP -p udp --dport 17091 -j ACCEPT

# Genel UDP Rate Limit
iptables -A FORTRESS_UDP -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A FORTRESS_UDP -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name udp --hashlimit-htable-expire 5000 -j DROP

# DNS Amplification Block
iptables -A FORTRESS_UDP --sport 53 -m limit --limit 5/s -j ACCEPT
iptables -A FORTRESS_UDP --sport 53 -j DROP

# Amplification Attack Sources - Tum portlar
iptables -A FORTRESS_UDP --sport 123 -j DROP
iptables -A FORTRESS_UDP --sport 161 -j DROP
iptables -A FORTRESS_UDP --sport 1900 -j DROP
iptables -A FORTRESS_UDP --sport 11211 -j DROP
iptables -A FORTRESS_UDP --sport 19 -j DROP
iptables -A FORTRESS_UDP --sport 17 -j DROP
iptables -A FORTRESS_UDP --sport 389 -j DROP
iptables -A FORTRESS_UDP --sport 111 -j DROP
iptables -A FORTRESS_UDP --sport 137 -j DROP
iptables -A FORTRESS_UDP --sport 138 -j DROP
iptables -A FORTRESS_UDP --sport 520 -j DROP
iptables -A FORTRESS_UDP --sport 1434 -j DROP

# Suspicious UDP Sizes
iptables -A FORTRESS_UDP -m length --length 0:28 -j DROP
iptables -A FORTRESS_UDP -m length --length 1400:65535 -j DROP

# Default UDP DROP
iptables -A FORTRESS_UDP -j DROP

# HTTP Connection Limits - Daha siki
iptables -A FORTRESS_HTTP -m connlimit --connlimit-above 2 --connlimit-mask 32 -j DROP
iptables -A FORTRESS_HTTP -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name http --hashlimit-htable-expire 5000 -j DROP

# HTTP Request Tracking
iptables -A FORTRESS_HTTP -m recent --name HTTP --set
iptables -A FORTRESS_HTTP -m recent --name HTTP --update --seconds 1 --hitcount 5 -j DROP

# GET/POST Rate Limits
iptables -A FORTRESS_HTTP -m string --string "GET" --algo bm -m recent --name GET --set
iptables -A FORTRESS_HTTP -m string --string "GET" --algo bm -m recent --name GET --update --seconds 1 --hitcount 10 -j DROP
iptables -A FORTRESS_HTTP -m string --string "POST" --algo bm -m recent --name POST --set
iptables -A FORTRESS_HTTP -m string --string "POST" --algo bm -m recent --name POST --update --seconds 1 --hitcount 5 -j DROP

# Slowloris Protection - Kucuk paketleri engelle
iptables -A FORTRESS_HTTP -p tcp --dport 80 -m length --length 0:100 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A FORTRESS_HTTP -p tcp --dport 80 -m length --length 0:100 -j DROP

# New HTTP Connection Limit
iptables -A FORTRESS_HTTP -m state --state NEW -m limit --limit 20/s --limit-burst 40 -j ACCEPT
iptables -A FORTRESS_HTTP -m state --state NEW -j DROP
iptables -A FORTRESS_HTTP -j RETURN

iptables -A FORTRESS_ICMP --icmp-type echo-request -m limit --limit 2/s --limit-burst 5 -j ACCEPT
iptables -A FORTRESS_ICMP -j DROP

success "iptables ayarlandi"

log "Nginx ayarlaniyor..."
if [[ -f $INSTALL_DIR/nginx/fortress.conf ]]; then
    cp $INSTALL_DIR/nginx/fortress.conf /etc/nginx/sites-available/fortress
    ln -sf /etc/nginx/sites-available/fortress /etc/nginx/sites-enabled/fortress
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t 2>/dev/null && systemctl reload nginx
    success "Nginx ayarlandi"
else
    warn "Nginx config bulunamadi"
fi

log "Servisler ayarlaniyor..."
chmod +x $INSTALL_DIR/src/*.py 2>/dev/null || true

cat > /etc/systemd/system/fortress.service << 'SERVICE'
[Unit]
Description=Fortress Anti-DDoS Protection System
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/fortress/src/threat_engine.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable fortress
systemctl start fortress
systemctl start nginx 2>/dev/null || true

success "Servisler baslatildi"

ln -sf $INSTALL_DIR/src/fortress_cli.py /usr/local/bin/fortress 2>/dev/null || true

echo ""
echo "============================================"
echo "  KURULUM TAMAMLANDI!"
echo "============================================"
echo ""
if [[ "$XDP_ENABLED" == "1" ]]; then
    echo -e "XDP Status: ${GREEN}AKTIF${NC}"
else
    echo -e "XDP Status: ${YELLOW}KAPALI (iptables fallback)${NC}"
fi
echo ""
echo "Koruma Aktif:"
echo "  - SYN Flood: 30/s global, 10/s per IP, 3 conn limit"
echo "  - HTTP Flood: 5/s limit, IP basi 2 baglanti"
echo "  - UDP Flood: 50/s limit, amplification DROP"
echo "  - Growtopia UDP 17091: 500/s global, 100/s per IP"
echo "  - Nginx Rate Limit: 5 req/s, 3s timeout"
echo "  - Auto-Ban: 3+ conn = ban, 2+ SYN = ban"
echo "  - Escalating Ban: 30min -> 1hr -> 24hr"
echo ""
echo "Whitelist: $WHITELIST_IP"
echo ""
echo "Komutlar:"
echo "  systemctl status fortress"
echo "  watch -n 1 'iptables -L FORTRESS -v -n | head -30'"
echo "  tail -f /var/log/fortress/threat_engine.log"
echo "  ipset list fortress_block | tail -20"
echo ""
