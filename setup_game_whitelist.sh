#!/bin/bash
# ============================================
# GAME WHITELIST SETUP
# Vercel login -> Rust server whitelist entegrasyonu
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
echo "  GAME WHITELIST SETUP"
echo "  Vercel -> Rust Server Entegrasyonu"
echo "============================================"
echo ""

# 1. game_whitelist ipset oluştur (yoksa)
log "game_whitelist ipset kontrol ediliyor..."
if ! ipset list game_whitelist &>/dev/null; then
    log "game_whitelist ipset oluşturuluyor..."
    ipset create game_whitelist hash:ip maxelem 100000 timeout 300
    success "game_whitelist ipset oluşturuldu"
else
    success "game_whitelist ipset zaten var"
fi

# 2. iptables kuralı ekle - FORTRESS zincirinin BAŞINA
log "iptables kuralı kontrol ediliyor..."

# Önce mevcut kuralı kontrol et
if iptables -L FORTRESS -n 2>/dev/null | grep -q "game_whitelist"; then
    success "game_whitelist iptables kuralı zaten var"
else
    # FORTRESS zinciri var mı kontrol et
    if iptables -L FORTRESS -n &>/dev/null; then
        # FORTRESS zincirinin 3. sırasına ekle (ESTABLISHED ve lo'dan sonra)
        # Mevcut kuralları kontrol et
        RULE_NUM=3
        
        # fortress_allow'dan ÖNCE ekle
        iptables -I FORTRESS $RULE_NUM -m set --match-set game_whitelist src -j ACCEPT
        success "game_whitelist kuralı FORTRESS zincirine eklendi (pozisyon $RULE_NUM)"
    else
        # FORTRESS zinciri yoksa INPUT'a direkt ekle
        warn "FORTRESS zinciri bulunamadı, INPUT'a ekleniyor..."
        
        # Mevcut kuralı sil (varsa)
        iptables -D INPUT -m set --match-set game_whitelist src -j ACCEPT 2>/dev/null || true
        
        # INPUT'un başına ekle
        iptables -I INPUT 1 -m set --match-set game_whitelist src -j ACCEPT
        success "game_whitelist kuralı INPUT zincirine eklendi"
    fi
fi

# 3. Kuralları kaydet (reboot sonrası kalıcı olması için)
log "iptables kuralları kaydediliyor..."
if command -v iptables-save &>/dev/null; then
    iptables-save > /etc/iptables.rules 2>/dev/null || true
    
    # Restore script oluştur
    cat > /etc/network/if-pre-up.d/iptables << 'EOF'
#!/bin/bash
/sbin/iptables-restore < /etc/iptables.rules
# game_whitelist ipset'i oluştur (yoksa)
ipset list game_whitelist &>/dev/null || ipset create game_whitelist hash:ip maxelem 100000 timeout 300
EOF
    chmod +x /etc/network/if-pre-up.d/iptables 2>/dev/null || true
    success "iptables kuralları kaydedildi"
fi

# 4. Test
echo ""
log "Kurulum test ediliyor..."
echo ""

echo "ipset list game_whitelist:"
ipset list game_whitelist | head -10
echo ""

echo "iptables kuralları (game_whitelist):"
iptables -L -n -v | grep -i game_whitelist || echo "(Kural bulunamadı - FORTRESS içinde olabilir)"
echo ""

if iptables -L FORTRESS -n -v 2>/dev/null | grep -q game_whitelist; then
    echo "FORTRESS zincirinde game_whitelist kuralı:"
    iptables -L FORTRESS -n -v | grep game_whitelist
fi

echo ""
echo "============================================"
echo "  KURULUM TAMAMLANDI!"
echo "============================================"
echo ""
echo "Nasıl çalışır:"
echo "  1. Oyuncu Vercel login sayfasından giriş yapar"
echo "  2. Vercel, Rust server'a /api/whitelist isteği gönderir"
echo "  3. Rust server, IP'yi game_whitelist ipset'ine ekler"
echo "  4. iptables, game_whitelist'teki IP'leri otomatik kabul eder"
echo "  5. Oyuncu 5 dakika içinde oyuna bağlanabilir"
echo ""
echo "Test komutları:"
echo "  ipset list game_whitelist"
echo "  iptables -L FORTRESS -n -v | grep game_whitelist"
echo "  journalctl -u sakura -f | grep -i whitelist"
echo ""
