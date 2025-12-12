#!/usr/bin/env python3
"""
Fortress Traffic Analyzer
Real-time traffic analysis and attack detection
"""

import logging
import threading
import time
import subprocess
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from collections import deque
from enum import Enum
import statistics

logger = logging.getLogger('fortress.analyzer')


class TrafficType(Enum):
    NORMAL = 'normal'
    SUSPICIOUS = 'suspicious'
    ATTACK = 'attack'
    UNKNOWN = 'unknown'


class AttackType(Enum):
    NONE = 'none'
    SYN_FLOOD = 'syn_flood'
    UDP_FLOOD = 'udp_flood'
    HTTP_FLOOD = 'http_flood'
    SLOWLORIS = 'slowloris'
    CONNECTION_FLOOD = 'connection_flood'
    AMPLIFICATION = 'amplification'
    MIXED = 'mixed'


@dataclass
class TrafficSample:
    timestamp: float
    tcp_connections: int = 0
    udp_connections: int = 0
    syn_packets: int = 0
    unique_ips: int = 0


@dataclass
class AnalysisResult:
    traffic_type: TrafficType
    attack_type: AttackType
    confidence: float
    details: Dict
    suspicious_ips: List[str]
    recommended_actions: List[str]


class TrafficAnalyzer:
    
    def __init__(self, sample_interval: float = 0.5, history_size: int = 300):
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        self._sample_interval = sample_interval
        self._samples: deque = deque(maxlen=history_size)
        
        self._callbacks: List[Callable[[AnalysisResult], None]] = []
        
        self._thresholds = {
            'syn_rate': 50,
            'connection_rate': 100,
            'unique_ip_rate': 50,
            'ip_connection_limit': 10,
        }
    
    def set_thresholds(self, thresholds: Dict):
        with self._lock:
            self._thresholds.update(thresholds)
    
    def add_callback(self, callback: Callable[[AnalysisResult], None]):
        self._callbacks.append(callback)
    
    def start(self):
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self._thread.start()
        logger.info("Traffic analyzer started")
    
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Traffic analyzer stopped")
    
    def _analysis_loop(self):
        while self._running:
            try:
                sample = self._collect_sample()
                
                with self._lock:
                    self._samples.append(sample)
                
                result = self._analyze_traffic()
                
                if result.traffic_type != TrafficType.NORMAL:
                    for callback in self._callbacks:
                        try:
                            callback(result)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                
                time.sleep(self._sample_interval)
                
            except Exception as e:
                logger.error(f"Analysis loop error: {e}")
                time.sleep(1)
    
    def _collect_sample(self) -> TrafficSample:
        sample = TrafficSample(timestamp=time.time())
        
        try:
            result = subprocess.run(
                ['ss', '-ntu', 'state', 'established'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                sample.tcp_connections = max(0, len(lines) - 1)
                
                ips = set()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote = parts[5] if 'tcp' in parts[0] and len(parts) > 5 else parts[4]
                        if ':' in remote:
                            ip = remote.rsplit(':', 1)[0].strip('[]')
                            if ip not in ('*', '0.0.0.0', '::'):
                                ips.add(ip)
                sample.unique_ips = len(ips)
        except Exception:
            pass
        
        try:
            result = subprocess.run(
                ['ss', '-ntu', 'state', 'syn-recv'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                sample.syn_packets = max(0, len(lines) - 1)
        except Exception:
            pass
        
        return sample
    
    def _analyze_traffic(self) -> AnalysisResult:
        with self._lock:
            if len(self._samples) < 5:
                return AnalysisResult(
                    traffic_type=TrafficType.UNKNOWN,
                    attack_type=AttackType.NONE,
                    confidence=0.0,
                    details={},
                    suspicious_ips=[],
                    recommended_actions=[]
                )
            
            samples = list(self._samples)
        
        current = samples[-1]
        recent = samples[-10:] if len(samples) >= 10 else samples
        
        avg_connections = statistics.mean([s.tcp_connections for s in recent])
        avg_syn = statistics.mean([s.syn_packets for s in recent])
        avg_ips = statistics.mean([s.unique_ips for s in recent])
        
        attack_indicators = []
        attack_type = AttackType.NONE
        confidence = 0.0
        actions = []
        
        if current.syn_packets > self._thresholds['syn_rate']:
            attack_indicators.append('high_syn_rate')
            attack_type = AttackType.SYN_FLOOD
            confidence = min(1.0, current.syn_packets / (self._thresholds['syn_rate'] * 2))
            actions.append('enable_syn_cookies')
        
        if current.tcp_connections > self._thresholds['connection_rate'] * 5:
            attack_indicators.append('high_connection_count')
            if attack_type == AttackType.NONE:
                attack_type = AttackType.CONNECTION_FLOOD
            else:
                attack_type = AttackType.MIXED
            confidence = max(confidence, min(1.0, current.tcp_connections / (self._thresholds['connection_rate'] * 10)))
            actions.append('reduce_connection_limits')
        
        if current.unique_ips > self._thresholds['unique_ip_rate'] * 3:
            attack_indicators.append('high_unique_ip_rate')
            confidence = max(confidence, 0.7)
        
        if len(recent) >= 5:
            syn_trend = [s.syn_packets for s in recent[-5:]]
            if all(syn_trend[i] < syn_trend[i+1] for i in range(len(syn_trend)-1)):
                attack_indicators.append('increasing_syn_trend')
                confidence = max(confidence, 0.6)
        
        if attack_indicators:
            traffic_type = TrafficType.ATTACK if confidence > 0.7 else TrafficType.SUSPICIOUS
        else:
            traffic_type = TrafficType.NORMAL
        
        details = {
            'current_connections': current.tcp_connections,
            'current_syn': current.syn_packets,
            'current_unique_ips': current.unique_ips,
            'avg_connections': avg_connections,
            'avg_syn': avg_syn,
            'avg_unique_ips': avg_ips,
            'indicators': attack_indicators
        }
        
        return AnalysisResult(
            traffic_type=traffic_type,
            attack_type=attack_type,
            confidence=confidence,
            details=details,
            suspicious_ips=[],
            recommended_actions=actions
        )
    
    def get_current_stats(self) -> Dict:
        with self._lock:
            if not self._samples:
                return {}
            
            current = self._samples[-1]
            recent = list(self._samples)[-60:] if len(self._samples) >= 60 else list(self._samples)
        
        return {
            'timestamp': current.timestamp,
            'connections': current.tcp_connections,
            'syn_packets': current.syn_packets,
            'unique_ips': current.unique_ips,
            'avg_connections_1m': statistics.mean([s.tcp_connections for s in recent]),
            'avg_syn_1m': statistics.mean([s.syn_packets for s in recent]),
            'max_connections_1m': max([s.tcp_connections for s in recent]),
            'max_syn_1m': max([s.syn_packets for s in recent])
        }
    
    def get_suspicious_ips(self, threshold: Optional[int] = None) -> List[tuple]:
        if threshold is None:
            threshold = self._thresholds['ip_connection_limit']
        
        try:
            result = subprocess.run(
                ['ss', '-ntu', 'state', 'established'],
                capture_output=True, text=True, timeout=2
            )
            
            if result.returncode != 0:
                return []
            
            from collections import defaultdict
            ip_counts: Dict[str, int] = defaultdict(int)
            
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[5] if 'tcp' in parts[0] and len(parts) > 5 else parts[4]
                    if ':' in remote:
                        ip = remote.rsplit(':', 1)[0].strip('[]')
                        if ip not in ('*', '0.0.0.0', '::'):
                            ip_counts[ip] += 1
            
            suspicious = [(ip, count) for ip, count in ip_counts.items() if count > threshold]
            return sorted(suspicious, key=lambda x: x[1], reverse=True)
            
        except Exception as e:
            logger.error(f"Suspicious IP check error: {e}")
            return []


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    analyzer = TrafficAnalyzer()
    analyzer.start()
    
    try:
        while True:
            print(analyzer.get_current_stats())
            time.sleep(5)
    except KeyboardInterrupt:
        analyzer.stop()
