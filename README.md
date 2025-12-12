# Fortress Anti-DDoS v3.0

Enterprise-grade DDoS mitigation system with multi-layer protection.

## Protection Layers

### Layer 1: XDP/eBPF (Kernel Level)
- Packet filtering at driver level (fastest)
- SYN flood protection
- UDP flood protection  
- Invalid packet detection
- Rate limiting per IP

### Layer 2: iptables (Netfilter)
- Multi-chain architecture (FORTRESS, FORTRESS_TCP, FORTRESS_UDP, FORTRESS_HTTP, FORTRESS_ICMP)
- Connection tracking
- SYN cookies
- Hashlimit rate limiting
- Invalid flag detection
- Amplification attack blocking

### Layer 3: IPSet
- High-performance IP blocklists
- Auto-expiring bans
- Whitelist support
- 10M+ IP capacity

### Layer 4: Nginx (Layer 7)
- HTTP rate limiting (10 req/s)
- Connection limits per IP
- Bad bot blocking
- Request size limits

### Layer 5: Threat Engine (Python)
- Real-time connection monitoring
- SYN state tracking
- Auto-ban on threshold breach
- Nginx log analysis
- Traffic pattern analysis

## Quick Install

```bash
git clone https://github.com/Bwrisz/fortress-antiddos.git
cd fortress-antiddos
chmod +x install.sh
sudo ./install.sh
```

## Protection Thresholds

| Layer | Attack Type | Threshold | Action |
|-------|-------------|-----------|--------|
| XDP | SYN Flood | 20/s per IP | DROP + Auto-Block |
| XDP | UDP Flood | 50/s per IP | DROP + Auto-Block |
| XDP | Connection | 30/s per IP | DROP + Auto-Block |
| iptables | SYN Flood | 30/s global, 10/s per IP | DROP |
| iptables | HTTP | 5/s per IP, 2 conn max | DROP |
| iptables | ACK Flood | 100/s global | DROP |
| iptables | RST Flood | 10/s global | DROP |
| iptables | Growtopia UDP 17091 | 500/s, 100/s per IP | ACCEPT (protected) |
| Nginx | Rate Limit | 5 req/s | 444 |
| Nginx | Connection | 5 per IP | 444 |
| Nginx | Timeout | 3s | 444 (Slowloris) |
| Threat Engine | Connection | 3+ conn = ban | Auto-Ban |
| Threat Engine | SYN | 2+ SYN = ban | Auto-Ban |
| Threat Engine | HTTP | 15+ req = ban | Auto-Ban |
| ICMP | All | 2/s | DROP |

## Files Structure

```
fortress/
├── install.sh              # Main installer
├── config/
│   └── fortress.yaml       # Configuration
├── src/
│   ├── threat_engine.py    # Auto-ban engine
│   ├── firewall_manager.py # iptables/ipset management
│   ├── connection_tracker.py # Connection monitoring
│   ├── traffic_analyzer.py # Traffic analysis
│   ├── fortress_daemon.py  # Main daemon
│   ├── fortress_cli.py     # CLI tool
│   └── xdp_loader.py       # XDP management
├── xdp/
│   ├── xdp_filter.c        # XDP kernel filter
│   └── Makefile
├── ebpf/
│   ├── xdp_fortress.c      # Advanced eBPF program
│   ├── maps.h              # BPF maps
│   └── common.h            # Common definitions
├── nginx/
│   └── fortress.conf       # Nginx rate limiting
└── data/
    ├── whitelist.txt       # Whitelisted IPs
    └── local_blocklist.txt # Manual blocklist
```

## Commands

```bash
# Service status
systemctl status fortress

# View blocked IPs
ipset list fortress_block | tail -20

# View iptables stats
watch -n 1 'iptables -L FORTRESS -v -n | head -30'

# View logs
tail -f /var/log/fortress/threat_engine.log

# Manual ban
ipset add fortress_block 1.2.3.4 timeout 3600

# Manual unban
ipset del fortress_block 1.2.3.4
```

## Whitelist

Default whitelist: ???? yıour ip

Add more IPs to `/opt/fortress/data/whitelist.txt`

## Requirements

- Debian/Ubuntu Linux
- Root access
- Python 3.8+
- iptables, ipset
- nginx (optional, for Layer 7)
- clang, llvm (optional, for XDP)

## License

MIT
