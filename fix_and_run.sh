#!/bin/bash
set -e

echo "=== FORTRESS FIX SCRIPT ==="

echo "[1/6] Servisi durdur..."
systemctl stop fortress 2>/dev/null || true

echo "[2/6] iptables kurallarini temizle..."
iptables -D INPUT -j FORTRESS 2>/dev/null || true
iptables -F FORTRESS 2>/dev/null || true
iptables -X FORTRESS 2>/dev/null || true

echo "[3/6] ipset'leri sil ve yeniden olustur..."
ipset destroy fortress_blocklist 2>/dev/null || true
ipset destroy fortress_blocklist_net 2>/dev/null || true
ipset destroy fortress_whitelist 2>/dev/null || true
ipset destroy fortress_whitelist_net 2>/dev/null || true
ipset destroy fortress_geoblock 2>/dev/null || true
ipset destroy fortress_ratelimit 2>/dev/null || true

sleep 1

ipset create fortress_blocklist hash:ip maxelem 10000000 hashsize 1048576
ipset create fortress_blocklist_net hash:net maxelem 1000000 hashsize 262144
ipset create fortress_whitelist hash:ip maxelem 100000 hashsize 16384
ipset create fortress_whitelist_net hash:net maxelem 10000 hashsize 4096
ipset create fortress_geoblock hash:net maxelem 500000 hashsize 131072
ipset create fortress_ratelimit hash:ip maxelem 1000000 hashsize 262144

echo "[4/6] Whitelist'e IP ekle..."
ipset add fortress_whitelist 127.0.0.1
ipset add fortress_whitelist 8.8.8.8
ipset add fortress_whitelist 8.8.4.4
ipset add fortress_whitelist 1.1.1.1

echo "[5/6] iptables koruma kurallarini ekle..."
iptables -N FORTRESS 2>/dev/null || iptables -F FORTRESS
iptables -I INPUT 1 -j FORTRESS

iptables -A FORTRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORTRESS -i lo -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_whitelist src -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_blocklist src -j DROP

iptables -A FORTRESS -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A FORTRESS -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP
iptables -A FORTRESS -p tcp --syn -j DROP

iptables -A FORTRESS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,URG URG -j DROP

iptables -A FORTRESS -p udp -m limit --limit 500/s --limit-burst 1000 -j ACCEPT
iptables -A FORTRESS -p udp --sport 53 -m limit --limit 50/s -j ACCEPT
iptables -A FORTRESS -p udp --sport 123 -m limit --limit 10/s -j ACCEPT
iptables -A FORTRESS -p udp --sport 161 -j DROP
iptables -A FORTRESS -p udp --sport 1900 -j DROP
iptables -A FORTRESS -p udp --sport 11211 -j DROP
iptables -A FORTRESS -p udp -m length --length 0:28 -j DROP
iptables -A FORTRESS -p udp -m length --length 1400:65535 -j DROP

iptables -A FORTRESS -p icmp --icmp-type echo-request -m limit --limit 5/s --limit-burst 10 -j ACCEPT
iptables -A FORTRESS -p icmp -j DROP

iptables -A FORTRESS -f -j DROP
iptables -A FORTRESS -m conntrack --ctstate INVALID -j DROP

echo "[6/6] Servisi baslat..."
systemctl start fortress

echo ""
echo "=== TAMAMLANDI ==="
echo ""
echo "Sunucu IP: $(curl -s ifconfig.me)"
echo ""
echo "Koruma AKTIF:"
echo "  - SYN Flood korumasi (100/s limit)"
echo "  - UDP Flood korumasi (500/s limit)"
echo "  - ICMP Flood korumasi (5/s limit)"
echo "  - Invalid TCP flags drop"
echo "  - Amplification korumasi (DNS/NTP/SSDP/Memcached)"
echo "  - Fragment drop"
echo "  - Connlimit (IP basi 20 baglanti)"
echo ""
echo "Kullanim:"
echo "  IP engelle:    ipset add fortress_blocklist X.X.X.X"
echo "  IP serbest:    ipset del fortress_blocklist X.X.X.X"
echo "  Whitelist:     ipset add fortress_whitelist X.X.X.X"
echo "  Durum:         iptables -L FORTRESS -v -n"
echo "  Canli izle:    watch -n 1 'iptables -L FORTRESS -v -n | head -30'"
echo ""
