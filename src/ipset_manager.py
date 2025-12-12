#!/usr/bin/env python3
import os
import subprocess
import logging
import threading
import time
from typing import Set, Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger('fortress.ipset')

@dataclass
class IPSetEntry:
    ip: str
    prefix: int
    timeout: int
    added_time: float

class IPSetManager:
    def __init__(self):
        self.sets: Dict[str, Set[str]] = {}
        self.lock = threading.Lock()
        self.initialized = False
        
    def run_cmd(self, cmd: List[str], check: bool = True) -> tuple:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            return False, "", "timeout"
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return False, "", str(e)
    
    def ipset_exists(self, name: str) -> bool:
        success, _, _ = self.run_cmd(['ipset', 'list', name], check=False)
        return success
    
    def create_set(self, name: str, set_type: str = "hash:ip", 
                   maxelem: int = 10000000, timeout: int = 0) -> bool:
        if self.ipset_exists(name):
            logger.info(f"IPSet {name} already exists")
            self.sets[name] = set()
            return True
        
        cmd = ['ipset', 'create', name, set_type, 
               'maxelem', str(maxelem), 'hashsize', '1048576']
        
        if timeout > 0:
            cmd.extend(['timeout', str(timeout)])
        
        success, _, err = self.run_cmd(cmd)
        if success:
            logger.info(f"Created ipset {name}")
            self.sets[name] = set()
            return True
        else:
            logger.error(f"Failed to create ipset {name}: {err}")
            return False
    
    def destroy_set(self, name: str) -> bool:
        success, _, err = self.run_cmd(['ipset', 'destroy', name])
        if success:
            logger.info(f"Destroyed ipset {name}")
            if name in self.sets:
                del self.sets[name]
            return True
        else:
            logger.error(f"Failed to destroy ipset {name}: {err}")
            return False
    
    def flush_set(self, name: str) -> bool:
        success, _, err = self.run_cmd(['ipset', 'flush', name])
        if success:
            logger.info(f"Flushed ipset {name}")
            if name in self.sets:
                self.sets[name] = set()
            return True
        else:
            logger.error(f"Failed to flush ipset {name}: {err}")
            return False
    
    def add_ip(self, name: str, ip: str, timeout: int = 0) -> bool:
        with self.lock:
            if name not in self.sets:
                return False
            
            if ip in self.sets[name]:
                return True
            
            cmd = ['ipset', 'add', name, ip, '-exist']
            if timeout > 0:
                cmd.extend(['timeout', str(timeout)])
            
            success, _, err = self.run_cmd(cmd)
            if success:
                self.sets[name].add(ip)
                return True
            else:
                logger.debug(f"Failed to add {ip} to {name}: {err}")
                return False
    
    def del_ip(self, name: str, ip: str) -> bool:
        with self.lock:
            if name not in self.sets:
                return False
            
            cmd = ['ipset', 'del', name, ip, '-exist']
            success, _, err = self.run_cmd(cmd)
            if success:
                self.sets[name].discard(ip)
                return True
            else:
                logger.debug(f"Failed to delete {ip} from {name}: {err}")
                return False
    
    def test_ip(self, name: str, ip: str) -> bool:
        success, _, _ = self.run_cmd(['ipset', 'test', name, ip], check=False)
        return success
    
    def list_set(self, name: str) -> Set[str]:
        success, stdout, _ = self.run_cmd(['ipset', 'list', name])
        if not success:
            return set()
        
        ips = set()
        in_members = False
        for line in stdout.splitlines():
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                ip = line.split()[0]
                ips.add(ip)
        
        return ips
    
    def save_set(self, name: str, filepath: str) -> bool:
        success, stdout, err = self.run_cmd(['ipset', 'save', name])
        if success:
            with open(filepath, 'w') as f:
                f.write(stdout)
            logger.info(f"Saved ipset {name} to {filepath}")
            return True
        else:
            logger.error(f"Failed to save ipset {name}: {err}")
            return False
    
    def restore_set(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
        
        with open(filepath, 'r') as f:
            data = f.read()
        
        proc = subprocess.Popen(
            ['ipset', 'restore', '-exist'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        _, err = proc.communicate(input=data)
        
        if proc.returncode == 0:
            logger.info(f"Restored ipset from {filepath}")
            return True
        else:
            logger.error(f"Failed to restore ipset: {err}")
            return False
    
    def batch_add(self, name: str, ips: List[str], timeout: int = 0) -> int:
        if name not in self.sets:
            return 0
        
        commands = []
        for ip in ips:
            if ip not in self.sets[name]:
                if timeout > 0:
                    commands.append(f"add {name} {ip} timeout {timeout}")
                else:
                    commands.append(f"add {name} {ip}")
        
        if not commands:
            return 0
        
        batch_data = '\n'.join(commands)
        
        proc = subprocess.Popen(
            ['ipset', 'restore', '-exist'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        _, err = proc.communicate(input=batch_data)
        
        if proc.returncode == 0:
            with self.lock:
                self.sets[name].update(ips)
            return len(commands)
        else:
            logger.error(f"Batch add failed: {err}")
            return 0
    
    def initialize(self) -> bool:
        self.create_set('fortress_blocklist', 'hash:ip', 10000000, 0)
        self.create_set('fortress_blocklist_net', 'hash:net', 1000000, 0)
        self.create_set('fortress_whitelist', 'hash:ip', 100000, 0)
        self.create_set('fortress_whitelist_net', 'hash:net', 10000, 0)
        self.create_set('fortress_geoblock', 'hash:net', 500000, 0)
        self.create_set('fortress_ratelimit', 'hash:ip', 1000000, 300)
        
        self.initialized = True
        logger.info("IPSet manager initialized")
        return True
    
    def setup_iptables(self, interface: str = "eth0") -> bool:
        rules = [
            f"-A INPUT -i {interface} -m set --match-set fortress_whitelist src -j ACCEPT",
            f"-A INPUT -i {interface} -m set --match-set fortress_whitelist_net src -j ACCEPT",
            f"-A INPUT -i {interface} -m set --match-set fortress_blocklist src -j DROP",
            f"-A INPUT -i {interface} -m set --match-set fortress_blocklist_net src -j DROP",
            f"-A INPUT -i {interface} -m set --match-set fortress_geoblock src -j DROP",
            f"-A INPUT -i {interface} -m set --match-set fortress_ratelimit src -j DROP",
        ]
        
        for rule in rules:
            cmd = ['iptables'] + rule.split()
            self.run_cmd(cmd, check=False)
        
        logger.info("iptables rules configured")
        return True
    
    def get_stats(self) -> Dict:
        stats = {}
        for name in self.sets:
            success, stdout, _ = self.run_cmd(['ipset', 'list', name, '-t'])
            if success:
                for line in stdout.splitlines():
                    if 'Number of entries' in line:
                        count = int(line.split(':')[1].strip())
                        stats[name] = count
                        break
        return stats

def main():
    logging.basicConfig(level=logging.INFO)
    
    manager = IPSetManager()
    manager.initialize()
    
    manager.add_ip('fortress_blocklist', '1.2.3.4')
    manager.add_ip('fortress_blocklist', '5.6.7.8')
    
    print(f"Stats: {manager.get_stats()}")
    
    print(f"Test 1.2.3.4: {manager.test_ip('fortress_blocklist', '1.2.3.4')}")
    print(f"Test 9.9.9.9: {manager.test_ip('fortress_blocklist', '9.9.9.9')}")

if __name__ == "__main__":
    main()
