#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import threading
import socket
import struct
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque

logger = logging.getLogger('fortress.monitor')

@dataclass
class AttackInfo:
    timestamp: float
    attack_type: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    severity: int
    pps: int
    bps: int

@dataclass
class MetricsSnapshot:
    timestamp: float
    packets_total: int
    packets_passed: int
    packets_dropped: int
    bytes_total: int
    bytes_passed: int
    bytes_dropped: int
    syn_total: int
    syn_dropped: int
    udp_total: int
    udp_dropped: int
    icmp_total: int
    icmp_dropped: int
    blocklist_hits: int
    geoip_hits: int
    ratelimit_hits: int
    conntrack_new: int
    conntrack_est: int
    active_attacks: int

class MonitorService:
    def __init__(self, daemon=None):
        self.daemon = daemon
        self.running = False
        self.metrics_history: deque = deque(maxlen=3600)
        self.attacks: deque = deque(maxlen=1000)
        self.blocked_ips: Dict[str, Dict] = {}
        self.alert_webhook: Optional[str] = None
        self.alert_threshold_pps: int = 100000
        self.alert_threshold_drop_rate: float = 0.5
        self.lock = threading.Lock()
        self.collect_thread: Optional[threading.Thread] = None
        self.http_thread: Optional[threading.Thread] = None
        self.http_port: int = 9100
        self.last_metrics: Optional[MetricsSnapshot] = None
        self.attack_detected: bool = False
        self.attack_start_time: float = 0
        
    def int_to_ip(self, ip_int: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    
    def collect_metrics(self) -> Optional[MetricsSnapshot]:
        if not self.daemon:
            return None
        
        try:
            raw_metrics = self.daemon.get_metrics()
            
            snapshot = MetricsSnapshot(
                timestamp=time.time(),
                packets_total=raw_metrics.get('packets_total', 0),
                packets_passed=raw_metrics.get('packets_passed', 0),
                packets_dropped=raw_metrics.get('packets_dropped', 0),
                bytes_total=raw_metrics.get('bytes_total', 0),
                bytes_passed=raw_metrics.get('bytes_passed', 0),
                bytes_dropped=raw_metrics.get('bytes_dropped', 0),
                syn_total=raw_metrics.get('syn_total', 0),
                syn_dropped=raw_metrics.get('syn_dropped', 0),
                udp_total=raw_metrics.get('udp_total', 0),
                udp_dropped=raw_metrics.get('udp_dropped', 0),
                icmp_total=raw_metrics.get('icmp_total', 0),
                icmp_dropped=raw_metrics.get('icmp_dropped', 0),
                blocklist_hits=raw_metrics.get('blocklist_hits', 0),
                geoip_hits=raw_metrics.get('geoip_hits', 0),
                ratelimit_hits=raw_metrics.get('ratelimit_hits', 0),
                conntrack_new=raw_metrics.get('conntrack_new', 0),
                conntrack_est=raw_metrics.get('conntrack_est', 0),
                active_attacks=len(self.attacks)
            )
            
            return snapshot
        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
            return None
    
    def detect_attack(self, current: MetricsSnapshot, 
                      previous: Optional[MetricsSnapshot]) -> Optional[AttackInfo]:
        if not previous:
            return None
        
        time_diff = current.timestamp - previous.timestamp
        if time_diff <= 0:
            return None
        
        pps = (current.packets_total - previous.packets_total) / time_diff
        drop_pps = (current.packets_dropped - previous.packets_dropped) / time_diff
        
        if current.packets_total > previous.packets_total:
            drop_rate = (current.packets_dropped - previous.packets_dropped) / \
                       (current.packets_total - previous.packets_total)
        else:
            drop_rate = 0
        
        attack_type = None
        severity = 0
        
        syn_pps = (current.syn_dropped - previous.syn_dropped) / time_diff
        if syn_pps > 1000:
            attack_type = "SYN_FLOOD"
            severity = min(10, int(syn_pps / 10000) + 1)
        
        udp_pps = (current.udp_dropped - previous.udp_dropped) / time_diff
        if udp_pps > 5000:
            if not attack_type or udp_pps > syn_pps:
                attack_type = "UDP_FLOOD"
                severity = min(10, int(udp_pps / 50000) + 1)
        
        if drop_rate > self.alert_threshold_drop_rate and pps > self.alert_threshold_pps:
            if not attack_type:
                attack_type = "VOLUMETRIC"
                severity = min(10, int(pps / 100000) + 1)
        
        if attack_type:
            return AttackInfo(
                timestamp=current.timestamp,
                attack_type=attack_type,
                src_ip="0.0.0.0",
                dst_ip="0.0.0.0",
                src_port=0,
                dst_port=0,
                protocol="MIXED",
                severity=severity,
                pps=int(pps),
                bps=int((current.bytes_total - previous.bytes_total) / time_diff * 8)
            )
        
        return None
    
    def log_blocked_ip(self, ip: str, reason: str, details: Dict = None):
        with self.lock:
            self.blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': reason,
                'details': details or {},
                'count': self.blocked_ips.get(ip, {}).get('count', 0) + 1
            }
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'reason': reason,
            'details': details
        }
        
        log_file = "/var/log/fortress/blocked.log"
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to log: {e}")
    
    def send_alert(self, attack: AttackInfo):
        if not self.alert_webhook:
            return
        
        try:
            import requests
            
            payload = {
                'timestamp': datetime.fromtimestamp(attack.timestamp).isoformat(),
                'type': attack.attack_type,
                'severity': attack.severity,
                'pps': attack.pps,
                'bps': attack.bps,
                'message': f"Attack detected: {attack.attack_type} "
                          f"(severity: {attack.severity}/10, {attack.pps:,} pps)"
            }
            
            requests.post(self.alert_webhook, json=payload, timeout=5)
            logger.info(f"Alert sent: {attack.attack_type}")
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    def get_prometheus_metrics(self) -> str:
        if not self.last_metrics:
            return ""
        
        m = self.last_metrics
        lines = [
            "# HELP fortress_packets_total Total packets processed",
            "# TYPE fortress_packets_total counter",
            f"fortress_packets_total {m.packets_total}",
            "",
            "# HELP fortress_packets_passed Packets passed",
            "# TYPE fortress_packets_passed counter",
            f"fortress_packets_passed {m.packets_passed}",
            "",
            "# HELP fortress_packets_dropped Packets dropped",
            "# TYPE fortress_packets_dropped counter",
            f"fortress_packets_dropped {m.packets_dropped}",
            "",
            "# HELP fortress_bytes_total Total bytes processed",
            "# TYPE fortress_bytes_total counter",
            f"fortress_bytes_total {m.bytes_total}",
            "",
            "# HELP fortress_syn_dropped SYN packets dropped",
            "# TYPE fortress_syn_dropped counter",
            f"fortress_syn_dropped {m.syn_dropped}",
            "",
            "# HELP fortress_udp_dropped UDP packets dropped",
            "# TYPE fortress_udp_dropped counter",
            f"fortress_udp_dropped {m.udp_dropped}",
            "",
            "# HELP fortress_blocklist_hits Blocklist hits",
            "# TYPE fortress_blocklist_hits counter",
            f"fortress_blocklist_hits {m.blocklist_hits}",
            "",
            "# HELP fortress_geoip_hits GeoIP blocks",
            "# TYPE fortress_geoip_hits counter",
            f"fortress_geoip_hits {m.geoip_hits}",
            "",
            "# HELP fortress_ratelimit_hits Rate limit hits",
            "# TYPE fortress_ratelimit_hits counter",
            f"fortress_ratelimit_hits {m.ratelimit_hits}",
            "",
            "# HELP fortress_connections_active Active connections",
            "# TYPE fortress_connections_active gauge",
            f"fortress_connections_active {m.conntrack_est}",
            "",
            "# HELP fortress_attack_active Attack in progress",
            "# TYPE fortress_attack_active gauge",
            f"fortress_attack_active {1 if self.attack_detected else 0}",
        ]
        
        return '\n'.join(lines)
    
    def get_dashboard_data(self) -> Dict:
        data = {
            'timestamp': time.time(),
            'status': 'attack' if self.attack_detected else 'normal',
            'metrics': asdict(self.last_metrics) if self.last_metrics else {},
            'recent_attacks': [asdict(a) for a in list(self.attacks)[-10:]],
            'blocked_ips_count': len(self.blocked_ips),
            'top_blocked': sorted(
                self.blocked_ips.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:10]
        }
        
        if self.metrics_history:
            history = list(self.metrics_history)
            if len(history) >= 2:
                first = history[0]
                last = history[-1]
                time_diff = last.timestamp - first.timestamp
                if time_diff > 0:
                    data['avg_pps'] = (last.packets_total - first.packets_total) / time_diff
                    data['avg_bps'] = (last.bytes_total - first.bytes_total) / time_diff * 8
        
        return data
    
    def collect_loop(self):
        previous_metrics = None
        
        while self.running:
            try:
                metrics = self.collect_metrics()
                if metrics:
                    with self.lock:
                        self.metrics_history.append(metrics)
                        self.last_metrics = metrics
                    
                    attack = self.detect_attack(metrics, previous_metrics)
                    if attack:
                        with self.lock:
                            self.attacks.append(attack)
                        
                        if not self.attack_detected:
                            self.attack_detected = True
                            self.attack_start_time = time.time()
                            logger.warning(f"Attack detected: {attack.attack_type}")
                            self.send_alert(attack)
                    else:
                        if self.attack_detected and \
                           time.time() - self.attack_start_time > 60:
                            self.attack_detected = False
                            logger.info("Attack subsided")
                    
                    previous_metrics = metrics
                
            except Exception as e:
                logger.error(f"Error in collect loop: {e}")
            
            time.sleep(1)
    
    def start(self, http_port: int = 9100, alert_webhook: str = None):
        self.http_port = http_port
        self.alert_webhook = alert_webhook
        self.running = True
        
        self.collect_thread = threading.Thread(target=self.collect_loop, daemon=True)
        self.collect_thread.start()
        
        self.start_http_server()
        
        logger.info(f"Monitor service started on port {http_port}")
    
    def start_http_server(self):
        monitor = self
        
        class MetricsHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                if self.path == '/metrics':
                    content = monitor.get_prometheus_metrics()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(content.encode())
                elif self.path == '/status':
                    content = json.dumps(monitor.get_dashboard_data(), indent=2)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(content.encode())
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()
        
        def run_server():
            server = HTTPServer(('0.0.0.0', self.http_port), MetricsHandler)
            while self.running:
                server.handle_request()
        
        self.http_thread = threading.Thread(target=run_server, daemon=True)
        self.http_thread.start()
    
    def stop(self):
        self.running = False
        logger.info("Monitor service stopped")

def main():
    logging.basicConfig(level=logging.INFO)
    
    monitor = MonitorService()
    monitor.start(http_port=9100)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()

if __name__ == "__main__":
    main()
