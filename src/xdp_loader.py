#!/usr/bin/env python3
"""
Fortress XDP Loader
Load and manage XDP/eBPF programs
"""

import os
import sys
import subprocess
import logging
import struct
from typing import Optional, Dict

logger = logging.getLogger('fortress.xdp')


class XDPLoader:
    
    def __init__(self, interface: str = 'auto', xdp_obj: str = '/opt/fortress/xdp/xdp_filter.o'):
        self.interface = interface
        self.xdp_obj = xdp_obj
        self.attached = False
    
    def _detect_interface(self) -> str:
        try:
            result = subprocess.run(
                ['ip', 'route', 'get', '8.8.8.8'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == 'dev' and i + 1 < len(parts):
                        return parts[i + 1]
        except Exception:
            pass
        return 'eth0'
    
    def check_requirements(self) -> bool:
        try:
            result = subprocess.run(['which', 'ip'], capture_output=True)
            if result.returncode != 0:
                logger.error("iproute2 not found")
                return False
            
            if not os.path.exists(self.xdp_obj):
                logger.warning(f"XDP object file not found: {self.xdp_obj}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Requirement check failed: {e}")
            return False
    
    def compile(self, source: str = None) -> bool:
        if source is None:
            source = self.xdp_obj.replace('.o', '.c')
        
        if not os.path.exists(source):
            logger.error(f"Source file not found: {source}")
            return False
        
        try:
            cmd = [
                'clang', '-O2', '-g', '-target', 'bpf',
                '-D__TARGET_ARCH_x86',
                '-Wall', '-c', source, '-o', self.xdp_obj
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return False
            
            logger.info(f"Compiled XDP program: {self.xdp_obj}")
            return True
            
        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return False
    
    def attach(self, mode: str = 'skb') -> bool:
        if not self.check_requirements():
            return False
        
        if self.interface == 'auto':
            self.interface = self._detect_interface()
        
        self.detach()
        
        try:
            if mode == 'native':
                flag = '-N'
            elif mode == 'offload':
                flag = '-H'
            else:
                flag = '-S'
            
            cmd = ['ip', 'link', 'set', 'dev', self.interface, 'xdp', 'obj', 
                   self.xdp_obj, 'sec', 'xdp', flag]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"XDP attach failed: {result.stderr}")
                return False
            
            self.attached = True
            logger.info(f"XDP attached to {self.interface} (mode: {mode})")
            return True
            
        except Exception as e:
            logger.error(f"XDP attach error: {e}")
            return False
    
    def detach(self) -> bool:
        try:
            if self.interface == 'auto':
                self.interface = self._detect_interface()
            
            cmd = ['ip', 'link', 'set', 'dev', self.interface, 'xdp', 'off']
            subprocess.run(cmd, capture_output=True)
            self.attached = False
            logger.info(f"XDP detached from {self.interface}")
            return True
        except Exception as e:
            logger.error(f"XDP detach error: {e}")
            return False
    
    def is_attached(self) -> bool:
        try:
            if self.interface == 'auto':
                self.interface = self._detect_interface()
            
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True, text=True
            )
            return 'xdp' in result.stdout.lower()
        except Exception:
            return False
    
    def add_blocked_ip(self, ip: str) -> bool:
        return self._map_update('blocked', ip)
    
    def remove_blocked_ip(self, ip: str) -> bool:
        return self._map_delete('blocked', ip)
    
    def add_whitelist_ip(self, ip: str) -> bool:
        return self._map_update('whitelist', ip)
    
    def _map_update(self, map_name: str, ip: str) -> bool:
        try:
            import socket
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            cmd = ['bpftool', 'map', 'update', 'name', map_name,
                   'key', 'hex'] + [f'{b:02x}' for b in struct.pack('I', ip_int)] + \
                  ['value', 'hex'] + ['00'] * 8
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.debug(f"Map update error: {e}")
            return False
    
    def _map_delete(self, map_name: str, ip: str) -> bool:
        try:
            import socket
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            cmd = ['bpftool', 'map', 'delete', 'name', map_name,
                   'key', 'hex'] + [f'{b:02x}' for b in struct.pack('I', ip_int)]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.debug(f"Map delete error: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'dropped_packets': 0,
            'dropped_bytes': 0
        }
        
        try:
            cmd = ['bpftool', 'map', 'dump', 'name', 'stats', '-j']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                import json
                data = json.loads(result.stdout)
                if data:
                    entry = data[0]
                    value = entry.get('value', {})
                    stats.update(value)
                    
        except Exception as e:
            logger.debug(f"Stats error: {e}")
        
        return stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fortress XDP Loader')
    parser.add_argument('-i', '--interface', default='auto', help='Network interface')
    parser.add_argument('-o', '--object', default='/opt/fortress/xdp/xdp_filter.o', help='XDP object file')
    parser.add_argument('action', choices=['attach', 'detach', 'status', 'compile'], help='Action')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    loader = XDPLoader(args.interface, args.object)
    
    if args.action == 'attach':
        if loader.attach():
            print("XDP attached successfully")
        else:
            print("XDP attach failed")
            sys.exit(1)
    
    elif args.action == 'detach':
        if loader.detach():
            print("XDP detached successfully")
        else:
            print("XDP detach failed")
            sys.exit(1)
    
    elif args.action == 'status':
        if loader.is_attached():
            print(f"XDP is attached to {loader.interface}")
            stats = loader.get_statistics()
            print(f"Statistics: {stats}")
        else:
            print("XDP is not attached")
    
    elif args.action == 'compile':
        if loader.compile():
            print("Compilation successful")
        else:
            print("Compilation failed")
            sys.exit(1)


if __name__ == '__main__':
    main()
