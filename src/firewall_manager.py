#!/usr/bin/env python3

import subprocess
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger('fortress.firewall')


class IPSetManager:
    
    SETS = {
        'fortress_block': {'type': 'hash:ip', 'maxelem': 10000000, 'timeout': 3600},
        'fortress_allow': {'type': 'hash:ip', 'maxelem': 100000, 'timeout': 0},
        'fortress_ratelimit': {'type': 'hash:ip', 'maxelem': 1000000, 'timeout': 60},
        'fortress_http': {'type': 'hash:ip', 'maxelem': 1000000, 'timeout': 300},
        'fortress_syn': {'type': 'hash:ip', 'maxelem': 1000000, 'timeout': 120},
    }
    
    def __init__(self):
        pass
    
    def _run(self, args: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(['ipset'] + args, capture_output=True, text=True, timeout=5)
            return result.returncode == 0, result.stdout
        except Exception as e:
            return False, str(e)
    
    def create_all(self) -> bool:
        for name, config in self.SETS.items():
            self._run(['destroy', name])
        
        import time
        time.sleep(1)
        
        for name, config in self.SETS.items():
            args = ['create', name, config['type'], 'maxelem', str(config['maxelem']), 'hashsize', '262144']
            if config['timeout'] > 0:
                args.extend(['timeout', str(config['timeout'])])
            
            success, _ = self._run(args)
            if not success:
                logger.error(f"Failed to create ipset: {name}")
                return False
            logger.info(f"Created ipset: {name}")
        
        return True
    
    def add(self, set_name: str, ip: str, timeout: Optional[int] = None) -> bool:
        args = ['add', set_name, ip, '-exist']
        if timeout:
            args.extend(['timeout', str(timeout)])
        success, _ = self._run(args)
        return success
    
    def remove(self, set_name: str, ip: str) -> bool:
        success, _ = self._run(['del', set_name, ip])
        return success
    
    def test(self, set_name: str, ip: str) -> bool:
        success, _ = self._run(['test', set_name, ip])
        return success
    
    def list(self, set_name: str) -> List[str]:
        success, output = self._run(['list', set_name])
        if not success:
            return []
        
        ips = []
        in_members = False
        for line in output.split('\n'):
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                ips.append(line.split()[0])
        return ips
    
    def count(self, set_name: str) -> int:
        return len(self.list(set_name))
    
    def stats(self) -> Dict[str, int]:
        return {name: self.count(name) for name in self.SETS}


class IPTablesManager:
    
    CHAINS = ['FORTRESS', 'FORTRESS_TCP', 'FORTRESS_UDP', 'FORTRESS_HTTP', 'FORTRESS_ICMP']
    
    def __init__(self):
        pass
    
    def _run(self, args: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(['iptables'] + args, capture_output=True, text=True, timeout=5)
            return result.returncode == 0, result.stdout
        except Exception as e:
            return False, str(e)
    
    def cleanup(self):
        self._run(['-D', 'INPUT', '-j', 'FORTRESS'])
        for chain in self.CHAINS:
            self._run(['-F', chain])
            self._run(['-X', chain])
    
    def setup(self) -> bool:
        self.cleanup()
        
        for chain in self.CHAINS:
            self._run(['-N', chain])
        
        self._run(['-I', 'INPUT', '1', '-j', 'FORTRESS'])
        
        rules = [
            ['-A', 'FORTRESS', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-i', 'lo', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_allow', 'src', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_block', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_ratelimit', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_http', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_syn', 'src', '-j', 'DROP'],
            
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'ALL', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'FIN,PSH,URG', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'SYN,FIN,PSH,URG', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN,RST', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'SYN,FIN', 'SYN,FIN', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'FIN,RST', 'FIN,RST', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ACK,FIN', 'FIN', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ACK,PSH', 'PSH', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ACK,URG', 'URG', '-j', 'DROP'],
            
            ['-A', 'FORTRESS', '-f', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '!', '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'DROP'],
            
            ['-A', 'FORTRESS', '-p', 'tcp', '-j', 'FORTRESS_TCP'],
            ['-A', 'FORTRESS', '-p', 'udp', '-j', 'FORTRESS_UDP'],
            ['-A', 'FORTRESS', '-p', 'icmp', '-j', 'FORTRESS_ICMP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--dport', '80', '-j', 'FORTRESS_HTTP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--dport', '443', '-j', 'FORTRESS_HTTP'],
            ['-A', 'FORTRESS', '-j', 'RETURN'],
            
            ['-A', 'FORTRESS_TCP', '--syn', '-m', 'limit', '--limit', '50/s', '--limit-burst', '100', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_TCP', '--syn', '-m', 'connlimit', '--connlimit-above', '5', '--connlimit-mask', '32', '-j', 'DROP'],
            ['-A', 'FORTRESS_TCP', '--syn', '-m', 'hashlimit', '--hashlimit-above', '20/sec', '--hashlimit-burst', '40', '--hashlimit-mode', 'srcip', '--hashlimit-name', 'syn', '--hashlimit-htable-expire', '10000', '-j', 'DROP'],
            ['-A', 'FORTRESS_TCP', '--syn', '-m', 'recent', '--name', 'SYN', '--set'],
            ['-A', 'FORTRESS_TCP', '--syn', '-m', 'recent', '--name', 'SYN', '--update', '--seconds', '1', '--hitcount', '20', '-j', 'DROP'],
            ['-A', 'FORTRESS_TCP', '--syn', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_TCP', '-m', 'conntrack', '--ctstate', 'NEW', '-m', 'limit', '--limit', '100/s', '--limit-burst', '200', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_TCP', '-j', 'RETURN'],
            
            ['-A', 'FORTRESS_UDP', '-m', 'limit', '--limit', '100/s', '--limit-burst', '200', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_UDP', '-m', 'hashlimit', '--hashlimit-above', '50/sec', '--hashlimit-burst', '100', '--hashlimit-mode', 'srcip', '--hashlimit-name', 'udp', '--hashlimit-htable-expire', '10000', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '53', '-m', 'limit', '--limit', '10/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_UDP', '--sport', '123', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '161', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '1900', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '11211', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '19', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '--sport', '17', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '-m', 'length', '--length', '0:28', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '-m', 'length', '--length', '1400:65535', '-j', 'DROP'],
            ['-A', 'FORTRESS_UDP', '-j', 'DROP'],
            
            ['-A', 'FORTRESS_HTTP', '-m', 'connlimit', '--connlimit-above', '3', '--connlimit-mask', '32', '-j', 'DROP'],
            ['-A', 'FORTRESS_HTTP', '-m', 'hashlimit', '--hashlimit-above', '10/sec', '--hashlimit-burst', '20', '--hashlimit-mode', 'srcip', '--hashlimit-name', 'http', '--hashlimit-htable-expire', '10000', '-j', 'DROP'],
            ['-A', 'FORTRESS_HTTP', '-m', 'recent', '--name', 'HTTP', '--set'],
            ['-A', 'FORTRESS_HTTP', '-m', 'recent', '--name', 'HTTP', '--update', '--seconds', '1', '--hitcount', '10', '-j', 'DROP'],
            ['-A', 'FORTRESS_HTTP', '-m', 'string', '--string', 'GET', '--algo', 'bm', '-m', 'recent', '--name', 'GET', '--set'],
            ['-A', 'FORTRESS_HTTP', '-m', 'string', '--string', 'GET', '--algo', 'bm', '-m', 'recent', '--name', 'GET', '--update', '--seconds', '1', '--hitcount', '15', '-j', 'DROP'],
            ['-A', 'FORTRESS_HTTP', '-m', 'string', '--string', 'POST', '--algo', 'bm', '-m', 'recent', '--name', 'POST', '--set'],
            ['-A', 'FORTRESS_HTTP', '-m', 'string', '--string', 'POST', '--algo', 'bm', '-m', 'recent', '--name', 'POST', '--update', '--seconds', '1', '--hitcount', '10', '-j', 'DROP'],
            ['-A', 'FORTRESS_HTTP', '-m', 'state', '--state', 'NEW', '-m', 'limit', '--limit', '30/s', '--limit-burst', '60', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_HTTP', '-j', 'RETURN'],
            
            ['-A', 'FORTRESS_ICMP', '--icmp-type', 'echo-request', '-m', 'limit', '--limit', '2/s', '--limit-burst', '5', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS_ICMP', '-j', 'DROP'],
        ]
        
        for rule in rules:
            success, _ = self._run(rule)
            if not success:
                logger.error(f"Failed to add rule: {' '.join(rule)}")
        
        logger.info("iptables configured")
        return True
    
    def get_stats(self) -> Dict:
        stats = {'total_packets': 0, 'dropped_packets': 0}
        
        success, output = self._run(['-L', 'FORTRESS', '-v', '-n'])
        if success:
            for line in output.split('\n')[2:]:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pkts = self._parse_count(parts[0])
                        stats['total_packets'] += pkts
                        if 'DROP' in line:
                            stats['dropped_packets'] += pkts
                    except ValueError:
                        pass
        
        return stats
    
    def _parse_count(self, value: str) -> int:
        value = value.strip()
        mult = {'K': 1000, 'M': 1000000, 'G': 1000000000}
        for s, m in mult.items():
            if value.endswith(s):
                return int(float(value[:-1]) * m)
        return int(value)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    ipset = IPSetManager()
    ipset.create_all()
    ipset.add('fortress_allow', '127.0.0.1')
    ipset.add('fortress_allow', '78.165.141.159')
    print(ipset.stats())
    
    iptables = IPTablesManager()
    iptables.setup()
    print(iptables.get_stats())
