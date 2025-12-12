#!/usr/bin/env python3
import os
import struct
import socket
import requests
import csv
import gzip
import io
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass

GEOIP_SOURCES = [
    "https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv",
    "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"
]

@dataclass
class IPRange:
    start_ip: int
    end_ip: int
    prefix_len: int
    country_code: str

class GeoIPLoader:
    def __init__(self, data_dir: str = "/opt/fortress/data"):
        self.data_dir = data_dir
        self.ranges: List[IPRange] = []
        self.blocked_countries: Set[str] = set()
        
    def ip_to_int(self, ip: str) -> int:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def int_to_ip(self, ip_int: int) -> str:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    
    def cidr_to_range(self, cidr: str) -> Tuple[int, int, int]:
        if '/' in cidr:
            ip, prefix = cidr.split('/')
            prefix_len = int(prefix)
        else:
            ip = cidr
            prefix_len = 32
        
        ip_int = self.ip_to_int(ip)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        start = ip_int & mask
        end = start | (~mask & 0xFFFFFFFF)
        return start, end, prefix_len
    
    def download_database(self) -> bool:
        for url in GEOIP_SOURCES:
            try:
                print(f"Downloading GeoIP database from {url}")
                resp = requests.get(url, timeout=30)
                if resp.status_code == 200:
                    self.parse_csv(resp.text)
                    return True
            except Exception as e:
                print(f"Failed to download from {url}: {e}")
                continue
        return False
    
    def parse_csv(self, content: str):
        self.ranges = []
        reader = csv.reader(io.StringIO(content))
        
        for row in reader:
            if len(row) < 3:
                continue
            
            try:
                if '/' in row[0]:
                    start, end, prefix_len = self.cidr_to_range(row[0])
                    country = row[1] if len(row) > 1 else ""
                elif '.' in row[0]:
                    start = self.ip_to_int(row[0])
                    end = self.ip_to_int(row[1]) if len(row) > 1 and '.' in row[1] else start
                    prefix_len = 32
                    country = row[2] if len(row) > 2 else ""
                else:
                    continue
                
                if country and len(country) == 2:
                    self.ranges.append(IPRange(
                        start_ip=start,
                        end_ip=end,
                        prefix_len=prefix_len,
                        country_code=country.upper()
                    ))
            except Exception:
                continue
        
        print(f"Loaded {len(self.ranges)} IP ranges")
    
    def load_local_database(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
        
        try:
            with open(filepath, 'r') as f:
                self.parse_csv(f.read())
            return True
        except Exception as e:
            print(f"Failed to load local database: {e}")
            return False
    
    def set_blocked_countries(self, countries: List[str]):
        self.blocked_countries = set(c.upper() for c in countries)
    
    def generate_bpf_data(self) -> List[Tuple[int, int, int, bool]]:
        result = []
        for r in self.ranges:
            is_blocked = r.country_code in self.blocked_countries
            result.append((r.start_ip, r.prefix_len, 
                          self.country_to_code(r.country_code), is_blocked))
        return result
    
    def country_to_code(self, country: str) -> int:
        if len(country) != 2:
            return 0
        return (ord(country[0]) << 8) | ord(country[1])
    
    def save_binary(self, filepath: str):
        data = self.generate_bpf_data()
        with open(filepath, 'wb') as f:
            f.write(struct.pack('I', len(data)))
            for ip, prefix, country, blocked in data:
                f.write(struct.pack('IIHB', ip, prefix, country, int(blocked)))
        print(f"Saved {len(data)} entries to {filepath}")
    
    def load_binary(self, filepath: str) -> List[Tuple[int, int, int, bool]]:
        result = []
        with open(filepath, 'rb') as f:
            count = struct.unpack('I', f.read(4))[0]
            for _ in range(count):
                data = f.read(11)
                ip, prefix, country, blocked = struct.unpack('IIHB', data)
                result.append((ip, prefix, country, bool(blocked)))
        return result

def main():
    loader = GeoIPLoader()
    
    blocked = ["CN", "RU", "KP", "IR"]
    loader.set_blocked_countries(blocked)
    
    if not loader.load_local_database("/opt/fortress/data/geoip.csv"):
        if not loader.download_database():
            print("Failed to load GeoIP database")
            return 1
    
    loader.save_binary("/opt/fortress/data/geoip.dat")
    print(f"GeoIP database ready with {len(loader.ranges)} ranges")
    print(f"Blocked countries: {blocked}")
    return 0

if __name__ == "__main__":
    exit(main())
