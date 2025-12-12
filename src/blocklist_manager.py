#!/usr/bin/env python3
import os
import re
import time
import socket
import struct
import logging
import requests
import threading
from typing import Set, List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger('fortress.blocklist')

DEFAULT_FEEDS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset"
]

@dataclass
class BlockedIP:
    ip: str
    prefix: int
    added_time: float
    expire_time: float
    reason: str
    source: str
    hit_count: int = 0

class BlocklistManager:
    def __init__(self, data_dir: str = "/opt/fortress/data"):
        self.data_dir = data_dir
        self.blocklist: Dict[str, BlockedIP] = {}
        self.whitelist: Set[str] = set()
        self.feeds: List[str] = DEFAULT_FEEDS
        self.update_interval: int = 3600
        self.default_ttl: int = 86400
        self.lock = threading.Lock()
        self.running = False
        self.update_thread: Optional[threading.Thread] = None
        self.callback = None
        
    def ip_to_int(self, ip: str) -> int:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def is_valid_ip(self, ip: str) -> bool:
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def is_valid_cidr(self, cidr: str) -> bool:
        try:
            if '/' in cidr:
                ip, prefix = cidr.split('/')
                prefix = int(prefix)
                if prefix < 0 or prefix > 32:
                    return False
                socket.inet_aton(ip)
                return True
            return self.is_valid_ip(cidr)
        except:
            return False
    
    def parse_cidr(self, cidr: str) -> tuple:
        if '/' in cidr:
            ip, prefix = cidr.split('/')
            return ip, int(prefix)
        return cidr, 32
    
    def download_feed(self, url: str) -> Set[str]:
        ips = set()
        try:
            resp = requests.get(url, timeout=30, headers={
                'User-Agent': 'Fortress-AntiDDoS/1.0'
            })
            if resp.status_code != 200:
                logger.warning(f"Failed to download {url}: HTTP {resp.status_code}")
                return ips
            
            for line in resp.text.splitlines():
                line = line.strip()
                
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                
                parts = line.split()
                if parts:
                    candidate = parts[0]
                    
                    candidate = re.sub(r'[,;].*$', '', candidate)
                    
                    if self.is_valid_cidr(candidate):
                        ips.add(candidate)
            
            logger.info(f"Downloaded {len(ips)} IPs from {url}")
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
        
        return ips
    
    def download_all_feeds(self) -> Set[str]:
        all_ips = set()
        
        for feed in self.feeds:
            ips = self.download_feed(feed)
            all_ips.update(ips)
        
        logger.info(f"Total unique IPs from all feeds: {len(all_ips)}")
        return all_ips
    
    def load_local_blocklist(self, filepath: str) -> Set[str]:
        ips = set()
        if not os.path.exists(filepath):
            return ips
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if self.is_valid_cidr(line):
                            ips.add(line)
            logger.info(f"Loaded {len(ips)} IPs from {filepath}")
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
        
        return ips
    
    def load_whitelist(self, filepath: str):
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if self.is_valid_cidr(line):
                            self.whitelist.add(line)
            logger.info(f"Loaded {len(self.whitelist)} whitelist entries")
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")
    
    def is_whitelisted(self, ip: str) -> bool:
        if ip in self.whitelist:
            return True
        
        ip_int = self.ip_to_int(ip)
        for entry in self.whitelist:
            if '/' in entry:
                net_ip, prefix = self.parse_cidr(entry)
                net_int = self.ip_to_int(net_ip)
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                if (ip_int & mask) == (net_int & mask):
                    return True
        
        return False
    
    def add_ip(self, ip: str, reason: str = "manual", source: str = "local",
               ttl: int = None, prefix: int = 32):
        if ttl is None:
            ttl = self.default_ttl
        
        if self.is_whitelisted(ip):
            logger.debug(f"Skipping whitelisted IP: {ip}")
            return False
        
        with self.lock:
            now = time.time()
            self.blocklist[ip] = BlockedIP(
                ip=ip,
                prefix=prefix,
                added_time=now,
                expire_time=now + ttl if ttl > 0 else 0,
                reason=reason,
                source=source
            )
        
        if self.callback:
            self.callback('add', ip, prefix, ttl, reason)
        
        return True
    
    def remove_ip(self, ip: str):
        with self.lock:
            if ip in self.blocklist:
                del self.blocklist[ip]
                
                if self.callback:
                    self.callback('remove', ip, 32, 0, "")
                
                return True
        return False
    
    def update_from_feeds(self):
        logger.info("Updating blocklist from feeds...")
        
        feed_ips = self.download_all_feeds()
        
        local_file = os.path.join(self.data_dir, "local_blocklist.txt")
        local_ips = self.load_local_blocklist(local_file)
        
        all_ips = feed_ips | local_ips
        
        with self.lock:
            current_ips = set(self.blocklist.keys())
            
            for ip in all_ips:
                if ip not in current_ips and not self.is_whitelisted(ip):
                    ip_addr, prefix = self.parse_cidr(ip)
                    self.add_ip(ip_addr, reason="feed", source="threat_intel",
                               ttl=self.default_ttl, prefix=prefix)
            
            for ip in current_ips:
                entry = self.blocklist.get(ip)
                if entry and entry.source == "threat_intel" and ip not in all_ips:
                    self.remove_ip(ip)
        
        logger.info(f"Blocklist updated: {len(self.blocklist)} entries")
    
    def cleanup_expired(self):
        now = time.time()
        expired = []
        
        with self.lock:
            for ip, entry in self.blocklist.items():
                if entry.expire_time > 0 and now > entry.expire_time:
                    expired.append(ip)
            
            for ip in expired:
                del self.blocklist[ip]
                if self.callback:
                    self.callback('remove', ip, 32, 0, "expired")
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired entries")
    
    def get_all_ips(self) -> List[tuple]:
        with self.lock:
            return [(e.ip, e.prefix, e.expire_time, e.reason) 
                    for e in self.blocklist.values()]
    
    def get_stats(self) -> Dict:
        with self.lock:
            sources = {}
            for entry in self.blocklist.values():
                sources[entry.source] = sources.get(entry.source, 0) + 1
            
            return {
                'total': len(self.blocklist),
                'by_source': sources,
                'whitelist_count': len(self.whitelist)
            }
    
    def save_to_file(self, filepath: str):
        with self.lock:
            with open(filepath, 'w') as f:
                f.write(f"# Fortress Blocklist - {datetime.now().isoformat()}\n")
                f.write(f"# Total entries: {len(self.blocklist)}\n\n")
                
                for ip, entry in sorted(self.blocklist.items()):
                    if entry.prefix == 32:
                        f.write(f"{ip}\n")
                    else:
                        f.write(f"{ip}/{entry.prefix}\n")
        
        logger.info(f"Saved blocklist to {filepath}")
    
    def update_loop(self):
        while self.running:
            try:
                self.update_from_feeds()
                self.cleanup_expired()
            except Exception as e:
                logger.error(f"Error in update loop: {e}")
            
            for _ in range(self.update_interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def start(self, callback=None):
        self.callback = callback
        self.running = True
        
        whitelist_file = os.path.join(self.data_dir, "whitelist.txt")
        self.load_whitelist(whitelist_file)
        
        self.update_from_feeds()
        
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.update_thread.start()
        
        logger.info("Blocklist manager started")
    
    def stop(self):
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        logger.info("Blocklist manager stopped")

def main():
    logging.basicConfig(level=logging.INFO)
    
    manager = BlocklistManager()
    manager.feeds = DEFAULT_FEEDS[:2]
    
    def on_update(action, ip, prefix, ttl, reason):
        print(f"[{action.upper()}] {ip}/{prefix} - {reason}")
    
    manager.start(callback=on_update)
    
    try:
        while True:
            time.sleep(60)
            stats = manager.get_stats()
            print(f"Stats: {stats}")
    except KeyboardInterrupt:
        manager.stop()

if __name__ == "__main__":
    main()
