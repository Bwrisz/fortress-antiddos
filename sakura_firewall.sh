#!/bin/bash
# ============================================
# SAKURA GOAT FIREWALL
# Growtopia Private Server - Ultimate Protection
# ============================================
#
# MANTIK:
# - TCP 443: Rate limited (Vercel API için)
# - TCP 22: Port knocking + fail2ban (sonra)
# - UDP 31847: SADECE whitelist (oyun trafiği)
# - Diğer her şey: DROP
#
# WHITELIST AKIŞI:
# 1. Oyuncu Vercel'den login olur
# 2. Vercel → Rust /api/whitelist → IP eklenir (5dk)
# 3. Oyuncu UDP ile bağlanır
# 4. Rust server aktif bağlantıları takip eder
# 5. Oyuncu çıkınca → 5dk sonra whitelist'ten silinir
# ============================================

set -e

# ============================================
# CONFIGURATION
# ============================================
GAME_PORT=31847          # Yeni UDP portu (gizli)
HTTPS_PORT=443           # Login API
SSH_PORT=22              # SSH (port knocking ile korunacak)

# Rate limits
HTTPS_RATE="30/sec"      # TCP 443 rate limit
HTTPS_BURST="60"         # TCP 443 burst

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================
# ROOT CHECK
# ============================================
[[ $EUID -ne 0 ]] && error "Root yetkisi gerekli: sudo $0"

echo ""
echo "============================================"
echo "  SAKURA GOAT FIREWALL"
echo "  Ultimate DDoS Protection"
echo "============================================"
echo ""
echo "Ports:"
echo "  - HTTPS API: $HTTPS_PORT (rate limited)"
echo "  - Game UDP:  $GAME_PORT (whitelist only)"
echo "  - SSH:       $SSH_PORT (fail2ban)"
echo ""

# ============================================
# 1. IPSET OLUŞTUR
# ============================================
log "IPSet'ler oluşturuluyor..."

# Mevcut setleri temizle
ipset destroy game_whitelist 2>/dev/null || true
ipset destroy sakura_banned 2>/dev/null || true
sleep 1

# game_whitelist: Login olan oyuncuların IP'leri
# timeout 300 = 5 dakika (UDP trafiği yoksa silinir)
ipset create game_whitelist hash:ip maxelem 100000 timeout 300 hashsize 4096

# sakura_banned: Saldırgan IP'leri (1 saat ban)
ipset create sakura_banned hash:ip maxelem 1000000 timeout 3600 hashsize 65536

success "IPSet'ler oluşturuldu"

# ============================================
# 2. IPTABLES TEMİZLE
# ============================================
log "iptables temizleniyor..."

# Mevcut kuralları temizle
iptables -F INPUT 2>/dev/null || true
iptables -F OUTPUT 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true

# Custom chain'leri temizle
iptables -F SAKURA_TCP 2>/dev/null || true
iptables -F SAKURA_UDP 2>/dev/null || true
iptables -X SAKURA_TCP 2>/dev/null || true
iptables -X SAKURA_UDP 2>/dev/null || true

# FORTRESS chain'lerini temizle (eski sistem)
iptables -D INPUT -j FORTRESS 2>/dev/null || true
for chain in FORTRESS FORTRESS_TCP FORTRESS_UDP FORTRESS_HTTP FORTRESS_ICMP; do
    iptables -F $chain 2>/dev/null || true
    iptables -X $chain 2>/dev/null || true
done

success "iptables temizlendi"

# ============================================
# 3. DEFAULT POLICY
# ============================================
log "Default policy ayarlanıyor..."

# Default: DROP (güvenli)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

success "Default policy: INPUT=DROP, OUTPUT=ACCEPT"

# ============================================
# 4. LOOPBACK & ESTABLISHED
# ============================================
log "Temel kurallar ekleniyor..."

# Loopback her zaman izinli
iptables -A INPUT -i lo -j ACCEPT

# Established bağlantılar izinli
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Invalid paketler DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

success "Temel kurallar eklendi"

# ============================================
# 5. BANNED IP'LER
# ============================================
log "Ban listesi kuralı ekleniyor..."

# Banned IP'ler direkt DROP
iptables -A INPUT -m set --match-set sakura_banned src -j DROP

success "Ban listesi aktif"

# ============================================
# 6. TCP 443 - HTTPS API (Rate Limited)
# ============================================
log "TCP 443 (HTTPS API) kuralları ekleniyor..."

# Rate limiting - saniyede max 30 bağlantı, burst 60
iptables -A INPUT -p tcp --dport $HTTPS_PORT -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-above $HTTPS_RATE --hashlimit-burst $HTTPS_BURST \
    --hashlimit-mode srcip --hashlimit-name https_limit \
    --hashlimit-htable-expire 10000 -j DROP

# Connection limit - IP başına max 20 bağlantı
iptables -A INPUT -p tcp --dport $HTTPS_PORT -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP

# SYN flood koruması
iptables -A INPUT -p tcp --dport $HTTPS_PORT --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport $HTTPS_PORT --syn -j DROP

# Normal TCP 443 trafiği
iptables -A INPUT -p tcp --dport $HTTPS_PORT -j ACCEPT

success "TCP 443 kuralları eklendi (rate: $HTTPS_RATE, burst: $HTTPS_BURST)"

# ============================================
# 7. TCP 22 - SSH (Geçici - sonra port knocking)
# ============================================
log "TCP 22 (SSH) kuralları ekleniyor..."

# SSH rate limiting - brute force koruması
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW \
    -m recent --name SSH --set

iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW \
    -m recent --name SSH --update --seconds 60 --hitcount 5 -j DROP

# SSH izinli
iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT

success "TCP 22 kuralları eklendi (5 deneme/dakika)"

# ============================================
# 8. UDP GAME PORT - SADECE WHITELIST
# ============================================
log "UDP $GAME_PORT (Game) kuralları ekleniyor..."

# SADECE whitelist'teki IP'ler bağlanabilir
iptables -A INPUT -p udp --dport $GAME_PORT -m set --match-set game_whitelist src -j ACCEPT

# Whitelist'te olmayan → DROP (log yok, sessiz)
iptables -A INPUT -p udp --dport $GAME_PORT -j DROP

success "UDP $GAME_PORT kuralları eklendi (SADECE WHITELIST)"

# ============================================
# 9. ICMP - Minimal
# ============================================
log "ICMP kuralları ekleniyor..."

# Ping - çok kısıtlı (saniyede 1)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

success "ICMP kuralları eklendi"

# ============================================
# 10. FINAL DROP (Log)
# ============================================
log "Final DROP kuralı ekleniyor..."

# Diğer her şey DROP (opsiyonel log)
# iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "SAKURA_DROP: " --log-level 4
iptables -A INPUT -j DROP

success "Final DROP aktif"

# ============================================
# 11. KERNEL PARAMETERS
# ============================================
log "Kernel parametreleri ayarlanıyor..."

cat > /etc/sysctl.d/99-sakura-firewall.conf << 'EOF'
# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Connection Tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 300
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# Network Buffers
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# IP Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 (attack surface reduction)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl -p /etc/sysctl.d/99-sakura-firewall.conf 2>/dev/null || true

success "Kernel parametreleri ayarlandı"

# ============================================
# 12. KURALLARI KAYDET
# ============================================
log "Kurallar kaydediliyor..."

# iptables kurallarını kaydet
iptables-save > /etc/iptables.sakura.rules

# ipset'leri kaydet
ipset save > /etc/ipset.sakura.rules

# Boot'ta yükle
cat > /etc/network/if-pre-up.d/sakura-firewall << 'EOF'
#!/bin/bash
# Sakura Firewall - Boot restore
ipset restore < /etc/ipset.sakura.rules 2>/dev/null || {
    ipset create game_whitelist hash:ip maxelem 100000 timeout 300 hashsize 4096 2>/dev/null || true
    ipset create sakura_banned hash:ip maxelem 1000000 timeout 3600 hashsize 65536 2>/dev/null || true
}
iptables-restore < /etc/iptables.sakura.rules 2>/dev/null || true
EOF
chmod +x /etc/network/if-pre-up.d/sakura-firewall

success "Kurallar kaydedildi"

# ============================================
# ÖZET
# ============================================
echo ""
echo "============================================"
echo "  SAKURA GOAT FIREWALL - AKTIF"
echo "============================================"
echo ""
echo "AÇIK PORTLAR:"
echo "  ✅ TCP 443  - HTTPS API (rate limited)"
echo "  ✅ TCP 22   - SSH (5 deneme/dk)"
echo "  ✅ UDP $GAME_PORT - Game (SADECE WHITELIST)"
echo ""
echo "KORUMA:"
echo "  ✅ TCP 443 rate limit: $HTTPS_RATE"
echo "  ✅ TCP 443 conn limit: 20/IP"
echo "  ✅ SSH brute force: 5/dk"
echo "  ✅ UDP whitelist only"
echo "  ✅ Invalid packets: DROP"
echo "  ✅ Banned IPs: DROP"
echo ""
echo "KOMUTLAR:"
echo "  ipset list game_whitelist     # Whitelist'i gör"
echo "  ipset add game_whitelist IP   # Manuel ekle"
echo "  ipset del game_whitelist IP   # Manuel sil"
echo "  iptables -L -n -v             # Kuralları gör"
echo ""
echo "⚠️  ÖNEMLİ: Rust server'da port değişikliği gerekli!"
echo "    .env dosyasında: SERVER_PORT=$GAME_PORT"
echo "    .env dosyasında: GAME_PORTS=$GAME_PORT"
echo ""
