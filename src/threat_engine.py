#!/usr/bin/env python3

import subprocess
import threading
import time
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Callable

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/fortress/threat_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('fortress.threat')


@dataclass
class IPProfile:
    ip: str
    connections: int = 0
    syn_count: int = 0
    http_requests: int = 0
    error_count: int = 0
    threat_score: float = 0.0
    first_seen: float = 0
    last_seen: float = 0


class ThreatEngine:
    
    def __init__(self):
        self.whitelist: Set[str] = {'127.0.0.1', '78.165.141.159'}
        self.profiles: Dict[str, IPProfile] = {}
        self.ban_counts: Dict[str, int] = defaultdict(int)
        self.running = False
        self.lock = threading.Lock()
        
        # Daha agresif thresholdlar
        self.conn_threshold = 3      # 3 baglanti = ban
        self.syn_threshold = 2       # 2 SYN = ban
        self.http_threshold = 15     # 15 HTTP req = ban
        self.error_threshold = 2     # 2 error = ban
        self.check_interval = 0.3    # Daha hizli kontrol
        
        self.callbacks: List[Callable] = []
    
    def add_callback(self, cb: Callable):
        self.callbacks.append(cb)
    
    def start(self):
        if self.running:
            return
        self.running = True
        
        threading.Thread(target=self._conn_monitor, daemon=True).start()
        threading.Thread(target=self._syn_monitor, daemon=True).start()
        threading.Thread(target=self._cleanup, daemon=True).start()
        
        logger.info("Threat engine started")
    
    def stop(self):
        self.running = False
        logger.info("Threat engine stopped")
    
    def _conn_monitor(self):
        while self.running:
            try:
                result = subprocess.run(
                    ['ss', '-ntu', 'state', 'established'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode != 0:
                    time.sleep(self.check_interval)
                    continue
                
                counts: Dict[str, int] = defaultdict(int)
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    remote = parts[5] if 'tcp' in parts[0] and len(parts) > 5 else parts[4] if len(parts) > 4 else ''
                    if ':' not in remote:
                        continue
                    ip = remote.rsplit(':', 1)[0].strip('[]')
                    if ip in ('*', '0.0.0.0', '::'):
                        continue
                    counts[ip] += 1
                
                for ip, count in counts.items():
                    if ip in self.whitelist:
                        continue
                    
                    with self.lock:
                        if ip not in self.profiles:
                            self.profiles[ip] = IPProfile(ip=ip, first_seen=time.time())
                        self.profiles[ip].connections = count
                        self.profiles[ip].last_seen = time.time()
                    
                    if count > self.conn_threshold:
                        self._ban(ip, 'connection_flood', count)
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
            
            time.sleep(self.check_interval)
    
    def _syn_monitor(self):
        while self.running:
            try:
                result = subprocess.run(
                    ['ss', '-ntu', 'state', 'syn-recv'],
                    capture_output=True, text=True, timeout=2
                )
                if result.returncode != 0:
                    time.sleep(self.check_interval)
                    continue
                
                counts: Dict[str, int] = defaultdict(int)
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    remote = parts[5] if len(parts) > 5 else parts[4] if len(parts) > 4 else ''
                    if ':' not in remote:
                        continue
                    ip = remote.rsplit(':', 1)[0].strip('[]')
                    if ip in ('*', '0.0.0.0', '::'):
                        continue
                    counts[ip] += 1
                
                for ip, count in counts.items():
                    if ip in self.whitelist:
                        continue
                    
                    with self.lock:
                        if ip not in self.profiles:
                            self.profiles[ip] = IPProfile(ip=ip, first_seen=time.time())
                        self.profiles[ip].syn_count = count
                        self.profiles[ip].last_seen = time.time()
                    
                    if count > self.syn_threshold:
                        self._ban(ip, 'syn_flood', count)
                
            except Exception as e:
                logger.error(f"SYN monitor error: {e}")
            
            time.sleep(self.check_interval)
    
    def _cleanup(self):
        while self.running:
            try:
                now = time.time()
                cutoff = now - 300
                
                with self.lock:
                    expired = [ip for ip, p in self.profiles.items() if p.last_seen < cutoff]
                    for ip in expired:
                        del self.profiles[ip]
                
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
            
            time.sleep(60)
    
    def _ban(self, ip: str, reason: str, count: int):
        if ip in self.whitelist:
            return
        
        self.ban_counts[ip] += 1
        ban_count = self.ban_counts[ip]
        
        # Escalating ban duration
        if ban_count == 1:
            duration = 1800      # 30 dakika
        elif ban_count == 2:
            duration = 3600      # 1 saat
        elif ban_count >= 3:
            duration = 86400     # 24 saat (permanent)
        
        try:
            subprocess.run(
                ['ipset', 'add', 'fortress_block', ip, 'timeout', str(duration), '-exist'],
                capture_output=True, timeout=2
            )
            logger.warning(f"BANNED: {ip} ({reason}: {count}, ban_count: {ban_count})")
            
            for cb in self.callbacks:
                try:
                    cb(ip, reason, count)
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"Ban error: {e}")
    
    def process_http_request(self, ip: str, status: int):
        if ip in self.whitelist:
            return
        
        with self.lock:
            if ip not in self.profiles:
                self.profiles[ip] = IPProfile(ip=ip, first_seen=time.time())
            
            p = self.profiles[ip]
            p.http_requests += 1
            p.last_seen = time.time()
            
            if status in (400, 408, 444):
                p.error_count += 1
            
            if p.http_requests > self.http_threshold:
                self._ban(ip, 'http_flood', p.http_requests)
                p.http_requests = 0
            
            if p.error_count > self.error_threshold:
                self._ban(ip, 'error_flood', p.error_count)
                p.error_count = 0
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'tracked_ips': len(self.profiles),
                'total_bans': sum(self.ban_counts.values()),
                'unique_banned': len(self.ban_counts)
            }


class NginxLogWatcher:
    
    def __init__(self, engine: ThreatEngine, log_path: str = '/var/log/nginx/access.log'):
        self.engine = engine
        self.log_path = log_path
        self.running = False
    
    def start(self):
        if not os.path.exists(self.log_path):
            logger.warning(f"Nginx log not found: {self.log_path}")
            return
        
        self.running = True
        threading.Thread(target=self._watch, daemon=True).start()
        logger.info("Nginx log watcher started")
    
    def stop(self):
        self.running = False
    
    def _watch(self):
        try:
            process = subprocess.Popen(
                ['tail', '-F', self.log_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                
                self._parse_line(line.strip())
            
            process.terminate()
            
        except Exception as e:
            logger.error(f"Log watcher error: {e}")
    
    def _parse_line(self, line: str):
        try:
            import re
            
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                return
            
            ip = ip_match.group(1)
            
            status_match = re.search(r'" (\d{3}) ', line)
            status = int(status_match.group(1)) if status_match else 200
            
            self.engine.process_http_request(ip, status)
            
        except Exception:
            pass


if __name__ == '__main__':
    engine = ThreatEngine()
    watcher = NginxLogWatcher(engine)
    
    engine.start()
    watcher.start()
    
    try:
        while True:
            print(engine.get_stats())
            time.sleep(5)
    except KeyboardInterrupt:
        engine.stop()
        watcher.stop()
