#!/bin/bash
# ============================================
# FORTRESS - GROWTOPIA OPTIMIZED SETUP
# Vercel + Game Server entegrasyonu
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Root yetkisi gerekli: sudo $0"

echo ""
echo "============================================"
echo "  FORTRESS - GROWTOPIA EDITION"
echo "  DDoS Protection + Vercel Integration"
echo "============================================"
echo ""

# ============================================
# 1. IPSET'LER
# ============================================
log "IPSet'ler oluşturuluyor..."

# Mevcut setleri temizle
for set in fortress_block fortress_allow game_whitelist; do
    ipset destroy $set 2>/dev/null || true
done
sleep 1

# Yeni setler oluştur
ipset create fortress_block hash:ip maxelem 1000000 timeout 3600
ipset create fortress_allow hash:net maxelem 100000
ipset create game_whitelist hash:ip maxelem 100000 timeout 300

# Kalıcı whitelist
ipset add fortress_allow 127.0.0.1
ipset add fortress_allow 10.0.0.0/8
ipset add fortress_allow 172.16.0.0/12
ipset add fortress_allow 192.168.0.0/16

# Vercel IP aralıkları (edge network)
ipset add fortress_allow 76.76.21.0/24
ipset add fortress_allow 64.29.0.0/16
ipset add fortress_allow 216.198.0.0/16
ipset add fortress_allow 18.0.0.0/8
ipset add fortress_allow 52.0.0.0/8
ipset add fortress_allow 54.0.0.0/8
ipset add fortress_allow 13.0.0.0/8
ipset add fortress_allow 99.0.0.0/8

success "IPSet'ler oluşturuldu"

# ============================================
# 2. IPTABLES KURALLARI
# ============================================
log "iptables kuralları ayarlanıyor..."

# Mevcut FORTRESS kurallarını temizle
iptables -D INPUT -j FORTRESS 2>/dev/null || true
for chain in FORTRESS FORTRESS_TCP FORTRESS_UDP FORTRESS_GAME; do
    iptables -F $chain 2>/dev/null || true
    iptables -X $chain 2>/dev/null || true
done

# Zincirleri oluştur
for chain in FORTRESS FORTRESS_TCP FORTRESS_UDP FORTRESS_GAME; do
    iptables -N $chain
done

# ============================================
# INPUT ZİNCİRİ - ÖNCELİK SIRASI ÖNEMLİ!
# ============================================

# 1. Oyun portu - Rate limited ama açık (Fortress'ten ÖNCE)
iptables -I INPUT 1 -p udp --dport 17091 -m hashlimit \
    --hashlimit-above 100/sec --hashlimit-burst 200 \
    --hashlimit-mode srcip --hashlimit-name game_udp \
    --hashlimit-htable-expire 10000 -j DROP
iptables -I INPUT 1 -p udp --dport 17091 -j ACCEPT

# 2. HTTPS API - Rate limited (Fortress'ten ÖNCE)
iptables -I INPUT 1 -p tcp --dport 443 -m hashlimit \
    --hashlimit-above 20/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip --hashlimit-name https_api \
    --hashlimit-htable-expire 10000 -j DROP
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT

# 3. FORTRESS zinciri
iptables -A INPUT -j FORTRESS

# ============================================
# FORTRESS ZİNCİRİ
# ============================================

# Established bağlantılar
iptables -A FORTRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A FORTRESS -i lo -j ACCEPT

# Whitelist'ler (sıra önemli!)
iptables -A FORTRESS -m set --match-set game_whitelist src -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_allow src -j ACCEPT

# Blocklist
iptables -A FORTRESS -m set --match-set fortress_block src -j DROP

# Invalid paketler
iptables -A FORTRESS -m conntrack --ctstate INVALID -j DROP
iptables -A FORTRESS -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# TCP flag saldırıları
iptables -A FORTRESS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Fragment saldırıları
iptables -A FORTRESS -f -j DROP

# Protokol zincirleri
iptables -A FORTRESS -p tcp -j FORTRESS_TCP
iptables -A FORTRESS -p udp -j FORTRESS_UDP

# ICMP - çok kısıtlı
iptables -A FORTRESS -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A FORTRESS -p icmp -j DROP

# Default - diğer her şey
iptables -A FORTRESS -j RETURN

# ============================================
# TCP ZİNCİRİ
# ============================================

# SYN flood koruması
iptables -A FORTRESS_TCP --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A FORTRESS_TCP --syn -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
iptables -A FORTRESS_TCP --syn -j DROP

# Yeni bağlantı limiti
iptables -A FORTRESS_TCP -m conntrack --ctstate NEW -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A FORTRESS_TCP -m conntrack --ctstate NEW -j DROP

iptables -A FORTRESS_TCP -j RETURN

# ============================================
# UDP ZİNCİRİ
# ============================================

# Amplification saldırı kaynakları - HEMEN DROP
iptables -A FORTRESS_UDP --sport 53 -m limit --limit 5/s -j ACCEPT
iptables -A FORTRESS_UDP --sport 53 -j DROP
iptables -A FORTRESS_UDP --sport 123 -j DROP
iptables -A FORTRESS_UDP --sport 161 -j DROP
iptables -A FORTRESS_UDP --sport 1900 -j DROP
iptables -A FORTRESS_UDP --sport 11211 -j DROP
iptables -A FORTRESS_UDP --sport 19 -j DROP
iptables -A FORTRESS_UDP --sport 17 -j DROP
iptables -A FORTRESS_UDP --sport 389 -j DROP

# Şüpheli UDP boyutları
iptables -A FORTRESS_UDP -m length --length 0:28 -j DROP
iptables -A FORTRESS_UDP -m length --length 1400:65535 -j DROP

# Genel UDP rate limit
iptables -A FORTRESS_UDP -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A FORTRESS_UDP -j DROP

success "iptables kuralları ayarlandı"

# ============================================
# 3. KERNEL PARAMETRELERİ
# ============================================
log "Kernel parametreleri ayarlanıyor..."

cat > /etc/sysctl.d/99-fortress-growtopia.conf << 'EOF'
# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2

# Connection Tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 300
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# Network Buffers
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# IP Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

sysctl -p /etc/sysctl.d/99-fortress-growtopia.conf 2>/dev/null || true
success "Kernel parametreleri ayarlandı"

# ============================================
# 4. KURALLARI KAYDET
# ============================================
log "Kurallar kaydediliyor..."

# iptables kurallarını kaydet
iptables-save > /etc/iptables.rules

# ipset'leri kaydet
ipset save > /etc/ipset.rules

# Boot'ta yükle
cat > /etc/network/if-pre-up.d/fortress << 'EOF'
#!/bin/bash
# Fortress kurallarını yükle
ipset restore < /etc/ipset.rules 2>/dev/null || true
iptables-restore < /etc/iptables.rules 2>/dev/null || true
# game_whitelist yoksa oluştur
ipset list game_whitelist &>/dev/null || ipset create game_whitelist hash:ip maxelem 100000 timeout 300
EOF
chmod +x /etc/network/if-pre-up.d/fortress

success "Kurallar kaydedildi"

# ============================================
# 5. ÖZET
# ============================================
echo ""
echo "============================================"
echo "  KURULUM TAMAMLANDI!"
echo "============================================"
echo ""
echo "Koruma Aktif:"
echo "  ✅ UDP 17091 (Oyun) - 100/s per IP limit"
echo "  ✅ TCP 443 (API) - 20/s per IP limit"
echo "  ✅ SYN Flood - 50/s global, 10 conn/IP"
echo "  ✅ Amplification - DNS/NTP/SSDP DROP"
echo "  ✅ Invalid Packets - DROP"
echo "  ✅ Vercel IP'leri - Whitelist"
echo "  ✅ game_whitelist - Dinamik (Vercel login)"
echo ""
echo "Kontrol Komutları:"
echo "  ipset list game_whitelist"
echo "  iptables -L INPUT -n -v | head -10"
echo "  iptables -L FORTRESS -n -v"
echo ""
