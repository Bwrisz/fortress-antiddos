#!/usr/bin/env python3
import os
import sys
import time
import signal
import struct
import socket
import logging
import threading
import yaml
import ctypes
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

try:
    from bcc import BPF, XDPFlags
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

try:
    import pyroute2
    from pyroute2 import IPRoute
    HAS_PYROUTE2 = True
except ImportError:
    HAS_PYROUTE2 = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fortress')

@dataclass
class Config:
    interface: str = "eth0"
    log_level: str = "INFO"
    log_file: str = "/var/log/fortress/fortress.log"
    xdp_mode: str = "native"
    pps_limit: int = 10000
    cps_limit: int = 100
    syn_limit: int = 10000
    udp_limit: int = 50000
    icmp_limit: int = 1000
    conn_timeout: int = 300
    geoip_enabled: bool = True
    blocked_countries: List[str] = field(default_factory=list)
    blocklist_enabled: bool = True
    blocklist_feeds: List[str] = field(default_factory=list)
    whitelist_file: str = "/opt/fortress/data/whitelist.txt"
    syn_cookies_enabled: bool = True
    tcp_validation: bool = True
    udp_validation: bool = True
    fragment_protection: bool = True

class LPMKey(ctypes.Structure):
    _fields_ = [
        ("prefixlen", ctypes.c_uint32),
        ("addr", ctypes.c_uint32)
    ]

class BlocklistVal(ctypes.Structure):
    _fields_ = [
        ("added_time", ctypes.c_uint64),
        ("expire_time", ctypes.c_uint64),
        ("hit_count", ctypes.c_uint32),
        ("reason", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3)
    ]

class GeoIPVal(ctypes.Structure):
    _fields_ = [
        ("country_code", ctypes.c_uint16),
        ("is_blocked", ctypes.c_uint8),
        ("pad", ctypes.c_uint8)
    ]

class ConfigStruct(ctypes.Structure):
    _fields_ = [
        ("pps_limit", ctypes.c_uint32),
        ("cps_limit", ctypes.c_uint32),
        ("syn_limit", ctypes.c_uint32),
        ("udp_limit", ctypes.c_uint32),
        ("icmp_limit", ctypes.c_uint32),
        ("conn_timeout", ctypes.c_uint32),
        ("blocked_countries", ctypes.c_uint16 * 32),
        ("blocked_country_count", ctypes.c_uint8),
        ("geoip_enabled", ctypes.c_uint8),
        ("ratelimit_enabled", ctypes.c_uint8),
        ("blocklist_enabled", ctypes.c_uint8),
        ("syn_cookies_enabled", ctypes.c_uint8),
        ("tcp_validation", ctypes.c_uint8),
        ("udp_validation", ctypes.c_uint8),
        ("fragment_protection", ctypes.c_uint8)
    ]

class FortressDaemon:
    def __init__(self, config_path: str = "/etc/fortress/fortress.yaml"):
        self.config_path = config_path
        self.config = Config()
        self.bpf: Optional[BPF] = None
        self.running = False
        self.interface = "eth0"
        self.xdp_attached = False
        self.metrics_thread: Optional[threading.Thread] = None
        self.blocklist_thread: Optional[threading.Thread] = None
        
    def load_config(self) -> bool:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    data = yaml.safe_load(f)
                
                self.config.interface = data.get('interface', 'eth0')
                self.config.log_level = data.get('log_level', 'INFO')
                self.config.log_file = data.get('log_file', '/var/log/fortress/fortress.log')
                
                xdp = data.get('xdp', {})
                self.config.xdp_mode = xdp.get('mode', 'native')
                
                limits = data.get('rate_limits', {})
                self.config.pps_limit = limits.get('per_ip_pps', 10000)
                self.config.cps_limit = limits.get('per_ip_cps', 100)
                self.config.syn_limit = limits.get('syn_pps', 10000)
                self.config.udp_limit = limits.get('udp_pps', 50000)
                self.config.icmp_limit = limits.get('icmp_pps', 1000)
                
                timeouts = data.get('timeouts', {})
                self.config.conn_timeout = timeouts.get('connection_idle', 300)
                
                geoip = data.get('geoip', {})
                self.config.geoip_enabled = geoip.get('enabled', True)
                self.config.blocked_countries = geoip.get('blocked_countries', [])
                
                blocklist = data.get('blocklist', {})
                self.config.blocklist_enabled = blocklist.get('enabled', True)
                self.config.blocklist_feeds = blocklist.get('feeds', [])
                
                protection = data.get('protection', {})
                self.config.syn_cookies_enabled = protection.get('syn_cookies', True)
                self.config.tcp_validation = protection.get('tcp_validation', True)
                self.config.udp_validation = protection.get('udp_validation', True)
                self.config.fragment_protection = protection.get('fragment_protection', True)
                
                self.interface = self.config.interface
                
            logger.info(f"Configuration loaded from {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return False
    
    def ip_to_int(self, ip: str) -> int:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def int_to_ip(self, ip_int: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    
    def country_to_code(self, country: str) -> int:
        if len(country) != 2:
            return 0
        return (ord(country[0]) << 8) | ord(country[1])
    
    def load_ebpf_program(self) -> bool:
        if not HAS_BCC:
            logger.error("BCC not available")
            return False
        
        try:
            ebpf_path = "/opt/fortress/ebpf/xdp_fortress.c"
            if not os.path.exists(ebpf_path):
                ebpf_path = os.path.join(os.path.dirname(__file__), 
                                         "../ebpf/xdp_fortress.c")
            
            with open(ebpf_path, 'r') as f:
                src = f.read()
            
            cflags = [
                "-I/opt/fortress/ebpf",
                "-I/usr/include/bpf",
                "-O2",
                "-Wall"
            ]
            
            self.bpf = BPF(text=src, cflags=cflags)
            logger.info("eBPF program loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load eBPF program: {e}")
            return False
    
    def attach_xdp(self) -> bool:
        if not self.bpf:
            return False
        
        try:
            fn = self.bpf.load_func("xdp_fortress", BPF.XDP)
            
            flags = 0
            if self.config.xdp_mode == "native":
                flags = XDPFlags.DRV_MODE
            elif self.config.xdp_mode == "offload":
                flags = XDPFlags.HW_MODE
            else:
                flags = XDPFlags.SKB_MODE
            
            self.bpf.attach_xdp(self.interface, fn, flags)
            self.xdp_attached = True
            logger.info(f"XDP attached to {self.interface} in {self.config.xdp_mode} mode")
            return True
        except Exception as e:
            logger.error(f"Failed to attach XDP: {e}")
            try:
                flags = XDPFlags.SKB_MODE
                self.bpf.attach_xdp(self.interface, fn, flags)
                self.xdp_attached = True
                logger.info(f"XDP attached to {self.interface} in SKB mode (fallback)")
                return True
            except Exception as e2:
                logger.error(f"Fallback also failed: {e2}")
                return False
    
    def detach_xdp(self):
        if self.bpf and self.xdp_attached:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                self.xdp_attached = False
                logger.info(f"XDP detached from {self.interface}")
            except Exception as e:
                logger.error(f"Failed to detach XDP: {e}")
    
    def update_config_map(self):
        if not self.bpf:
            return
        
        try:
            config_map = self.bpf["config_map"]
            
            cfg = ConfigStruct()
            cfg.pps_limit = self.config.pps_limit
            cfg.cps_limit = self.config.cps_limit
            cfg.syn_limit = self.config.syn_limit
            cfg.udp_limit = self.config.udp_limit
            cfg.icmp_limit = self.config.icmp_limit
            cfg.conn_timeout = self.config.conn_timeout
            cfg.geoip_enabled = int(self.config.geoip_enabled)
            cfg.ratelimit_enabled = 1
            cfg.blocklist_enabled = int(self.config.blocklist_enabled)
            cfg.syn_cookies_enabled = int(self.config.syn_cookies_enabled)
            cfg.tcp_validation = int(self.config.tcp_validation)
            cfg.udp_validation = int(self.config.udp_validation)
            cfg.fragment_protection = int(self.config.fragment_protection)
            
            for i, country in enumerate(self.config.blocked_countries[:32]):
                cfg.blocked_countries[i] = self.country_to_code(country)
            cfg.blocked_country_count = min(len(self.config.blocked_countries), 32)
            
            config_map[ctypes.c_uint32(0)] = cfg
            logger.info("Config map updated")
        except Exception as e:
            logger.error(f"Failed to update config map: {e}")
    
    def add_to_blocklist(self, ip: str, ttl: int = 3600, reason: int = 0):
        if not self.bpf:
            return
        
        try:
            blocklist = self.bpf["blocklist_map"]
            
            key = LPMKey()
            key.prefixlen = 32
            key.addr = self.ip_to_int(ip)
            
            val = BlocklistVal()
            val.added_time = int(time.time() * 1e9)
            val.expire_time = val.added_time + (ttl * 1e9) if ttl > 0 else 0
            val.hit_count = 0
            val.reason = reason
            
            blocklist[key] = val
            logger.debug(f"Added {ip} to blocklist")
        except Exception as e:
            logger.error(f"Failed to add {ip} to blocklist: {e}")
    
    def remove_from_blocklist(self, ip: str):
        if not self.bpf:
            return
        
        try:
            blocklist = self.bpf["blocklist_map"]
            
            key = LPMKey()
            key.prefixlen = 32
            key.addr = self.ip_to_int(ip)
            
            del blocklist[key]
            logger.debug(f"Removed {ip} from blocklist")
        except Exception as e:
            logger.error(f"Failed to remove {ip} from blocklist: {e}")
    
    def add_to_whitelist(self, ip: str):
        if not self.bpf:
            return
        
        try:
            whitelist = self.bpf["whitelist_map"]
            
            key = LPMKey()
            key.prefixlen = 32
            key.addr = self.ip_to_int(ip)
            
            whitelist[key] = ctypes.c_uint8(1)
            logger.debug(f"Added {ip} to whitelist")
        except Exception as e:
            logger.error(f"Failed to add {ip} to whitelist: {e}")
    
    def load_geoip_database(self, filepath: str):
        if not self.bpf or not os.path.exists(filepath):
            return
        
        try:
            geoip_map = self.bpf["geoip_map"]
            
            with open(filepath, 'rb') as f:
                count = struct.unpack('I', f.read(4))[0]
                
                for _ in range(count):
                    data = f.read(11)
                    ip, prefix, country, blocked = struct.unpack('IIHB', data)
                    
                    key = LPMKey()
                    key.prefixlen = prefix
                    key.addr = ip
                    
                    val = GeoIPVal()
                    val.country_code = country
                    val.is_blocked = blocked
                    
                    geoip_map[key] = val
            
            logger.info(f"Loaded {count} GeoIP entries")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
    
    def load_whitelist(self):
        if not os.path.exists(self.config.whitelist_file):
            return
        
        try:
            with open(self.config.whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_to_whitelist(line)
            logger.info("Whitelist loaded")
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
    
    def get_metrics(self) -> Dict[str, int]:
        if not self.bpf:
            return {}
        
        try:
            metrics_map = self.bpf["metrics_map"]
            metrics = {}
            
            metric_names = [
                "packets_total", "packets_passed", "packets_dropped",
                "bytes_total", "bytes_passed", "bytes_dropped",
                "syn_total", "syn_dropped", "udp_total", "udp_dropped",
                "icmp_total", "icmp_dropped", "blocklist_hits", "geoip_hits",
                "ratelimit_hits", "conntrack_new", "conntrack_est", 
                "conntrack_closed", "signature_hits", "amplification_hits"
            ]
            
            for i, name in enumerate(metric_names):
                try:
                    val = metrics_map[ctypes.c_uint32(i)]
                    total = sum(val)
                    metrics[name] = total
                except:
                    metrics[name] = 0
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {}
    
    def print_metrics(self):
        metrics = self.get_metrics()
        if not metrics:
            return
        
        print("\n" + "="*60)
        print("FORTRESS METRICS")
        print("="*60)
        print(f"Packets: {metrics.get('packets_total', 0):,} total, "
              f"{metrics.get('packets_passed', 0):,} passed, "
              f"{metrics.get('packets_dropped', 0):,} dropped")
        print(f"Bytes: {metrics.get('bytes_total', 0):,} total, "
              f"{metrics.get('bytes_passed', 0):,} passed, "
              f"{metrics.get('bytes_dropped', 0):,} dropped")
        print(f"SYN: {metrics.get('syn_total', 0):,} total, "
              f"{metrics.get('syn_dropped', 0):,} dropped")
        print(f"UDP: {metrics.get('udp_total', 0):,} total, "
              f"{metrics.get('udp_dropped', 0):,} dropped")
        print(f"Blocklist hits: {metrics.get('blocklist_hits', 0):,}")
        print(f"GeoIP hits: {metrics.get('geoip_hits', 0):,}")
        print(f"Rate limit hits: {metrics.get('ratelimit_hits', 0):,}")
        print(f"Connections: {metrics.get('conntrack_new', 0):,} new, "
              f"{metrics.get('conntrack_est', 0):,} established")
        print("="*60)
    
    def metrics_loop(self):
        while self.running:
            self.print_metrics()
            time.sleep(5)
    
    def signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def apply_iptables_fallback(self):
        import subprocess
        logger.info("Applying iptables fallback rules...")
        
        rules = [
            "iptables -N FORTRESS 2>/dev/null || iptables -F FORTRESS",
            "iptables -I INPUT 1 -j FORTRESS 2>/dev/null || true",
            "iptables -A FORTRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "iptables -A FORTRESS -i lo -j ACCEPT",
            "iptables -A FORTRESS -m set --match-set fortress_whitelist src -j ACCEPT 2>/dev/null || true",
            "iptables -A FORTRESS -m set --match-set fortress_blocklist src -j DROP 2>/dev/null || true",
            "iptables -A FORTRESS -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT",
            "iptables -A FORTRESS -p tcp --syn -j DROP",
            "iptables -A FORTRESS -p tcp --tcp-flags ALL NONE -j DROP",
            "iptables -A FORTRESS -p tcp --tcp-flags ALL ALL -j DROP",
            "iptables -A FORTRESS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
            "iptables -A FORTRESS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
            "iptables -A FORTRESS -p udp -m limit --limit 500/s --limit-burst 1000 -j ACCEPT",
            "iptables -A FORTRESS -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT",
            "iptables -A FORTRESS -p icmp -j DROP",
            "iptables -A FORTRESS -f -j DROP",
            "iptables -A FORTRESS -m conntrack --ctstate INVALID -j DROP",
        ]
        
        for rule in rules:
            subprocess.run(rule, shell=True, capture_output=True)
        
        logger.info("iptables fallback rules applied")
    
    def run(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        if not self.load_config():
            logger.error("Failed to load configuration")
            return 1
        
        ebpf_loaded = False
        xdp_attached = False
        
        if HAS_BCC:
            if self.load_ebpf_program():
                ebpf_loaded = True
                if self.attach_xdp():
                    xdp_attached = True
        
        if not xdp_attached:
            logger.warning("XDP not available, using iptables fallback")
            self.apply_iptables_fallback()
        
        if ebpf_loaded:
            self.update_config_map()
        self.load_whitelist()
        
        geoip_path = "/opt/fortress/data/geoip.dat"
        if os.path.exists(geoip_path):
            self.load_geoip_database(geoip_path)
        
        self.running = True
        
        self.metrics_thread = threading.Thread(target=self.metrics_loop, daemon=True)
        self.metrics_thread.start()
        
        logger.info("Fortress daemon started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.detach_xdp()
            logger.info("Fortress daemon stopped")
        
        return 0

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fortress Anti-DDoS Daemon')
    parser.add_argument('-c', '--config', default='/etc/fortress/fortress.yaml',
                       help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    daemon = FortressDaemon(args.config)
    return daemon.run()

if __name__ == "__main__":
    sys.exit(main())
