#!/usr/bin/env python3
"""
Fortress Connection Tracker
Real-time connection monitoring and analysis
"""

import subprocess
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger('fortress.conntrack')


class ConnectionState(Enum):
    NEW = 'NEW'
    ESTABLISHED = 'ESTABLISHED'
    RELATED = 'RELATED'
    TIME_WAIT = 'TIME_WAIT'
    CLOSE_WAIT = 'CLOSE_WAIT'
    SYN_SENT = 'SYN_SENT'
    SYN_RECV = 'SYN_RECV'
    FIN_WAIT = 'FIN_WAIT'
    CLOSE = 'CLOSE'
    LAST_ACK = 'LAST_ACK'
    LISTEN = 'LISTEN'
    CLOSING = 'CLOSING'
    UNKNOWN = 'UNKNOWN'


@dataclass
class Connection:
    protocol: str
    state: ConnectionState
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes: int = 0


@dataclass
class IPStats:
    ip: str
    total_connections: int = 0
    established: int = 0
    syn_recv: int = 0
    time_wait: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    ports: Dict[int, int] = field(default_factory=dict)
    first_seen: float = 0
    last_seen: float = 0


class ConnectionTracker:
    
    def __init__(self):
        self._lock = threading.Lock()
        self._ip_stats: Dict[str, IPStats] = {}
        self._connection_cache: List[Connection] = []
        self._cache_time: float = 0
        self._cache_ttl: float = 0.5
        self._history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._history_window: float = 60.0
    
    def _run_ss(self, args: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                ['ss'] + args,
                capture_output=True,
                text=True,
                timeout=3
            )
            return result.returncode == 0, result.stdout
        except subprocess.TimeoutExpired:
            return False, ""
        except Exception as e:
            logger.error(f"ss error: {e}")
            return False, ""
    
    def get_connections(self, protocol: Optional[str] = None, state: Optional[str] = None) -> List[Connection]:
        now = time.time()
        
        if now - self._cache_time < self._cache_ttl and self._connection_cache:
            connections = self._connection_cache
        else:
            connections = self._fetch_connections()
            with self._lock:
                self._connection_cache = connections
                self._cache_time = now
        
        if protocol:
            connections = [c for c in connections if c.protocol.lower() == protocol.lower()]
        
        if state:
            try:
                state_enum = ConnectionState[state.upper().replace('-', '_')]
                connections = [c for c in connections if c.state == state_enum]
            except KeyError:
                pass
        
        return connections
    
    def _fetch_connections(self) -> List[Connection]:
        connections = []
        success, output = self._run_ss(['-ntu', '-a'])
        if success:
            connections.extend(self._parse_ss_output(output))
        return connections
    
    def _parse_ss_output(self, output: str) -> List[Connection]:
        connections = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:
            try:
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                protocol = parts[0].lower()
                state_str = parts[1] if protocol == 'tcp' else 'ESTABLISHED'
                
                try:
                    state = ConnectionState[state_str.upper().replace('-', '_')]
                except KeyError:
                    state = ConnectionState.UNKNOWN
                
                local = parts[4] if protocol == 'tcp' else parts[3]
                remote = parts[5] if protocol == 'tcp' and len(parts) > 5 else parts[4] if len(parts) > 4 else ''
                
                if ':' not in local or ':' not in remote:
                    continue
                
                local_parts = local.rsplit(':', 1)
                dst_ip = local_parts[0].strip('[]')
                dst_port = int(local_parts[1]) if local_parts[1] != '*' else 0
                
                remote_parts = remote.rsplit(':', 1)
                src_ip = remote_parts[0].strip('[]')
                src_port = int(remote_parts[1]) if remote_parts[1] != '*' else 0
                
                if src_ip in ('*', '0.0.0.0', '::'):
                    continue
                
                connections.append(Connection(
                    protocol=protocol,
                    state=state,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                ))
                
            except (IndexError, ValueError):
                continue
        
        return connections
    
    def get_ip_stats(self, ip: Optional[str] = None) -> Dict[str, IPStats]:
        connections = self.get_connections()
        stats: Dict[str, IPStats] = {}
        now = time.time()
        
        for conn in connections:
            src = conn.src_ip
            
            if ip and src != ip:
                continue
            
            if src not in stats:
                stats[src] = IPStats(ip=src, first_seen=now, last_seen=now)
            
            s = stats[src]
            s.total_connections += 1
            s.last_seen = now
            
            if conn.dst_port not in s.ports:
                s.ports[conn.dst_port] = 0
            s.ports[conn.dst_port] += 1
            
            if conn.state == ConnectionState.ESTABLISHED:
                s.established += 1
            elif conn.state == ConnectionState.SYN_RECV:
                s.syn_recv += 1
            elif conn.state == ConnectionState.TIME_WAIT:
                s.time_wait += 1
        
        with self._lock:
            self._ip_stats = stats
        
        return stats
    
    def get_connection_count(self, ip: Optional[str] = None, state: Optional[str] = None) -> int:
        connections = self.get_connections(state=state)
        if ip:
            return len([c for c in connections if c.src_ip == ip])
        return len(connections)
    
    def get_syn_count(self, ip: Optional[str] = None) -> int:
        return self.get_connection_count(ip, 'SYN_RECV')
    
    def get_established_count(self, ip: Optional[str] = None) -> int:
        return self.get_connection_count(ip, 'ESTABLISHED')
    
    def get_top_connections(self, limit: int = 20) -> List[Tuple[str, int]]:
        stats = self.get_ip_stats()
        sorted_stats = sorted(stats.items(), key=lambda x: x[1].total_connections, reverse=True)
        return [(ip, s.total_connections) for ip, s in sorted_stats[:limit]]
    
    def get_top_syn(self, limit: int = 20) -> List[Tuple[str, int]]:
        stats = self.get_ip_stats()
        sorted_stats = sorted(stats.items(), key=lambda x: x[1].syn_recv, reverse=True)
        return [(ip, s.syn_recv) for ip, s in sorted_stats[:limit] if s.syn_recv > 0]
    
    def get_connections_by_port(self, port: int) -> List[Connection]:
        connections = self.get_connections()
        return [c for c in connections if c.dst_port == port]
    
    def get_port_stats(self) -> Dict[int, int]:
        connections = self.get_connections()
        port_counts: Dict[int, int] = defaultdict(int)
        for conn in connections:
            port_counts[conn.dst_port] += 1
        return dict(port_counts)
    
    def get_connection_rate(self, ip: str, window: float = 10.0) -> float:
        now = time.time()
        cutoff = now - window
        
        with self._lock:
            history = self._history.get(ip, [])
            recent = [(t, c) for t, c in history if t > cutoff]
        
        if len(recent) < 2:
            return 0.0
        
        total_connections = sum(c for _, c in recent)
        time_span = recent[-1][0] - recent[0][0]
        
        if time_span <= 0:
            return 0.0
        
        return total_connections / time_span
    
    def get_suspicious_ips(self, conn_threshold: int = 10, syn_threshold: int = 5) -> List[str]:
        suspicious = set()
        stats = self.get_ip_stats()
        
        for ip, s in stats.items():
            if s.total_connections > conn_threshold:
                suspicious.add(ip)
            if s.syn_recv > syn_threshold:
                suspicious.add(ip)
        
        return list(suspicious)
    
    def get_summary(self) -> Dict:
        connections = self.get_connections()
        stats = self.get_ip_stats()
        
        state_counts = defaultdict(int)
        protocol_counts = defaultdict(int)
        
        for conn in connections:
            state_counts[conn.state.value] += 1
            protocol_counts[conn.protocol] += 1
        
        return {
            'total_connections': len(connections),
            'unique_ips': len(stats),
            'by_state': dict(state_counts),
            'by_protocol': dict(protocol_counts),
            'top_connections': self.get_top_connections(10),
            'top_syn': self.get_top_syn(10)
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    tracker = ConnectionTracker()
    print(tracker.get_summary())
