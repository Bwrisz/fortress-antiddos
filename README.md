# FORTRESS ANTI-DDOS SYSTEM

XDP/eBPF tabanli, kernel seviyesinde calisan, ultra-yuksek performansli DDoS koruma sistemi.

## OZELLIKLER

- XDP ile kernel bypass (10M+ PPS)
- eBPF ile akilli trafik analizi
- SYN flood korumasi (SYN cookies)
- UDP flood ve amplification korumasi
- GeoIP filtreleme
- ipset entegrasyonu (O(1) lookup)
- Adaptive rate limiting (Token bucket)
- Connection tracking
- Protocol validation
- Real-time monitoring
- Otomatik blocklist guncelleme
- iptables fallback

## KURULUM

```bash
chmod +x install.sh
sudo ./install.sh
```

## KULLANIM

```bash
# Durum kontrolu
fortress status

# Canli trafik izleme
fortress watch

# IP engelleme
fortress block 1.2.3.4
fortress block 1.2.3.4 -t 3600 -r "attack"

# IP engel kaldirma
fortress unblock 1.2.3.4

# Whitelist ekleme
fortress whitelist 5.6.7.8

# Engelli IP listesi
fortress list

# Loglar
fortress logs -n 100

# Servis yonetimi
fortress start
fortress stop
fortress restart
fortress reload
```

## KONFIGÜRASYON

`/etc/fortress/fortress.yaml` dosyasini duzenleyin:

```yaml
interface: eth0

rate_limits:
  per_ip_pps: 10000
  syn_pps: 10000
  udp_pps: 50000

geoip:
  enabled: true
  blocked_countries:
    - CN
    - RU
    - KP
    - IR

protection:
  syn_cookies: true
  tcp_validation: true
  udp_validation: true
  fragment_protection: true
```

## MONITORING

Prometheus metrics: `http://localhost:9100/metrics`
Status API: `http://localhost:9100/status`

## DOSYA YAPISI

```
/opt/fortress/
├── src/           # Python kaynak kodlari
├── ebpf/          # eBPF/XDP programlari
├── config/        # Konfigürasyon dosyalari
├── data/          # Veri dosyalari (blocklist, whitelist, geoip)
├── scripts/       # Yardimci scriptler
└── logs/          # Log dosyalari

/etc/fortress/
└── fortress.yaml  # Ana konfigürasyon

/var/log/fortress/
├── fortress.log   # Ana log
├── blocked.log    # Engellenen IP loglari
└── manual.log     # Manuel islem loglari
```

## PERFORMANS

- 10M+ PPS islem kapasitesi
- <100ns paket isleme suresi
- 10M+ IP blocklist destegi
- 2M+ aktif baglanti takibi
- Per-CPU veri yapilari (lock-free)

## KORUMA KATMANLARI

1. XDP Layer (Driver seviyesi)
   - GeoIP filtreleme
   - Blocklist kontrolu
   - Protocol validation
   - Rate limiting

2. eBPF TC Layer
   - SYN flood korumasi
   - UDP flood korumasi
   - Connection tracking
   - Attack fingerprinting

3. Kernel Stack
   - iptables fallback
   - ipset entegrasyonu
   - conntrack

4. Userspace
   - Daemon yonetimi
   - Monitoring
   - Blocklist guncelleme
   - Alerting
