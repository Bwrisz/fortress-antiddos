#!/usr/bin/env python3
import os
import subprocess
import logging
from typing import List

logger = logging.getLogger('fortress.iptables')

class IPTablesFallback:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.rules_applied = False
        
    def run_cmd(self, cmd: List[str]) -> bool:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except:
            return False
    
    def flush_rules(self):
        self.run_cmd(['iptables', '-F', 'FORTRESS'])
        self.run_cmd(['iptables', '-X', 'FORTRESS'])
    
    def setup_chain(self):
        self.run_cmd(['iptables', '-N', 'FORTRESS'])
        self.run_cmd(['iptables', '-I', 'INPUT', '1', '-j', 'FORTRESS'])
    
    def apply_rules(self):
        self.flush_rules()
        self.setup_chain()
        
        rules = [
            ['-A', 'FORTRESS', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-i', 'lo', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_whitelist', 'src', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_whitelist_net', 'src', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_blocklist', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_blocklist_net', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'set', '--match-set', 'fortress_geoblock', 'src', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--syn', '-m', 'limit', '--limit', '100/s', '--limit-burst', '200', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--syn', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'ALL', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'FIN,PSH,URG', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'ALL', 'SYN,RST,ACK,FIN,URG', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN,RST', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--tcp-flags', 'SYN,FIN', 'SYN,FIN', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'udp', '-m', 'limit', '--limit', '500/s', '--limit-burst', '1000', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'udp', '--sport', '53', '-m', 'limit', '--limit', '100/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'udp', '--sport', '123', '-m', 'limit', '--limit', '10/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'udp', '--sport', '161', '-m', 'limit', '--limit', '10/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'udp', '--sport', '1900', '-m', 'limit', '--limit', '10/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'udp', '--sport', '11211', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'icmp', '--icmp-type', 'echo-request', '-m', 'limit', '--limit', '10/s', '-j', 'ACCEPT'],
            ['-A', 'FORTRESS', '-p', 'icmp', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-f', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '-m', 'connlimit', '--connlimit-above', '100', '--connlimit-mask', '32', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-m', 'recent', '--name', 'portscan', '--rcheck', '--seconds', '60', '--hitcount', '10', '-j', 'DROP'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--dport', '22', '-m', 'recent', '--name', 'ssh', '--set'],
            ['-A', 'FORTRESS', '-p', 'tcp', '--dport', '22', '-m', 'recent', '--name', 'ssh', '--rcheck', '--seconds', '60', '--hitcount', '5', '-j', 'DROP'],
        ]
        
        for rule in rules:
            self.run_cmd(['iptables'] + rule)
        
        self.rules_applied = True
        logger.info("iptables fallback rules applied")
    
    def remove_rules(self):
        self.run_cmd(['iptables', '-D', 'INPUT', '-j', 'FORTRESS'])
        self.flush_rules()
        self.rules_applied = False
        logger.info("iptables fallback rules removed")
    
    def save_rules(self):
        self.run_cmd(['netfilter-persistent', 'save'])
        logger.info("iptables rules saved")

def main():
    logging.basicConfig(level=logging.INFO)
    
    fallback = IPTablesFallback()
    fallback.apply_rules()
    print("iptables fallback rules applied")

if __name__ == "__main__":
    main()
