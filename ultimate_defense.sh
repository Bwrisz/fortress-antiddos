#!/bin/bash
set -e

echo "=== FORTRESS ULTIMATE DEFENSE ==="
echo "En agresif koruma modu aktif ediliyor..."

systemctl stop fortress 2>/dev/null || true
pkill -f auto_ban.sh 2>/dev/null || true

iptables -D INPUT -j FORTRESS 2>/dev/null || true
iptables -F FORTRESS 2>/dev/null || true
iptables -X FORTRESS 2>/dev/null || true

ipset destroy fortress_blocklist 2>/dev/null || true
ipset destroy fortress_whitelist 2>/dev/null || true
ipset destroy fortress_ratelimit 2>/dev/null || true

sleep 1

ipset create fortress_blocklist hash:ip maxelem 10000000 hashsize 1048576
ipset create fortress_whitelist hash:ip maxelem 100000 hashsize 16384
ipset create fortress_ratelimit hash:ip maxelem 1000000 hashsize 262144

ipset add fortress_whitelist 127.0.0.1
ipset add fortress_whitelist 78.165.141.159

iptables -N FORTRESS
iptables -I INPUT 1 -j FORTRESS

iptables -A FORTRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORTRESS -i lo -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_whitelist src -j ACCEPT
iptables -A FORTRESS -m set --match-set fortress_blocklist src -j DROP

iptables -A FORTRESS -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT
iptables -A FORTRESS -p tcp --syn -m connlimit --connlimit-above 3 --connlimit-mask 32 -j DROP
iptables -A FORTRESS -p tcp --syn -j DROP

iptables -A FORTRESS -p tcp --dport 80 -m connlimit --connlimit-above 3 --connlimit-mask 32 -j DROP
iptables -A FORTRESS -p tcp --dport 443 -m connlimit --connlimit-above 3 --connlimit-mask 32 -j DROP
iptables -A FORTRESS -p tcp --dport 80 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name http -j DROP
iptables -A FORTRESS -p tcp --dport 443 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name https -j DROP

iptables -A FORTRESS -p tcp -m string --string "GET" --algo bm -m recent --name HTTP --set
iptables -A FORTRESS -p tcp -m string --string "GET" --algo bm -m recent --name HTTP --update --seconds 1 --hitcount 20 -j DROP
iptables -A FORTRESS -p tcp -m string --string "POST" --algo bm -m recent --name HTTP --set
iptables -A FORTRESS -p tcp -m string --string "POST" --algo bm -m recent --name HTTP --update --seconds 1 --hitcount 10 -j DROP

iptables -A FORTRESS -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A FORTRESS -p tcp --tcp-flags ACK,URG URG -j DROP

iptables -A FORTRESS -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A FORTRESS -p udp --sport 53 -m limit --limit 10/s -j ACCEPT
iptables -A FORTRESS -p udp --sport 123 -j DROP
iptables -A FORTRESS -p udp --sport 161 -j DROP
iptables -A FORTRESS -p udp --sport 1900 -j DROP
iptables -A FORTRESS -p udp --sport 11211 -j DROP
iptables -A FORTRESS -p udp -m length --length 0:28 -j DROP
iptables -A FORTRESS -p udp -m length --length 1400:65535 -j DROP
iptables -A FORTRESS -p udp -j DROP

iptables -A FORTRESS -p icmp -j DROP
iptables -A FORTRESS -f -j DROP
iptables -A FORTRESS -m conntrack --ctstate INVALID -j DROP
iptables -A FORTRESS -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A FORTRESS -j RETURN

cat > /opt/fortress/ultra_ban.sh << 'BANSCRIPT'
#!/bin/bash
LOG=/var/log/fortress/autoban.log
echo "$(date): Ultra Auto-Ban started" >> $LOG
while true; do
  ss -ntu state established 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | while read count ip; do
    if [[ "$count" -gt 10 ]] && [[ -n "$ip" ]] && [[ "$ip" != "0.0.0.0" ]] && [[ "$ip" != "127.0.0.1" ]] && [[ "$ip" != "78.165.141.159" ]]; then
      if ! ipset test fortress_whitelist $ip 2>/dev/null; then
        ipset add fortress_blocklist $ip 2>/dev/null && echo "$(date): BANNED $ip ($count conn)" >> $LOG
      fi
    fi
  done
  
  ss -ntu state syn-recv 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | while read count ip; do
    if [[ "$count" -gt 5 ]] && [[ -n "$ip" ]]; then
      if ! ipset test fortress_whitelist $ip 2>/dev/null; then
        ipset add fortress_blocklist $ip 2>/dev/null && echo "$(date): SYN-BANNED $ip ($count syn)" >> $LOG
      fi
    fi
  done
  
  sleep 1
done
BANSCRIPT
chmod +x /opt/fortress/ultra_ban.sh

mkdir -p /var/log/fortress
nohup /opt/fortress/ultra_ban.sh > /dev/null 2>&1 &

echo ""
echo "=== ULTIMATE DEFENSE AKTIF ==="
echo ""
echo "Koruma Seviyeleri:"
echo "  - SYN Flood: 25/s limit, IP basi 3 baglanti"
echo "  - HTTP Flood: 10/s limit, IP basi 3 baglanti"
echo "  - HTTP Request: 20 GET/s, 10 POST/s limit"
echo "  - UDP: 100/s limit, amplification DROP"
echo "  - ICMP: Tamamen DROP"
echo "  - Auto-Ban: 10+ baglanti = aninda ban"
echo "  - Auto-Ban: 5+ SYN = aninda ban"
echo ""
echo "Whitelist: 78.165.141.159 (senin IP)"
echo ""
echo "Izleme: watch -n 1 'iptables -L FORTRESS -v -n | head -40'"
echo "Ban log: tail -f /var/log/fortress/autoban.log"
echo ""
