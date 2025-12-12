#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import struct
import argparse
import subprocess
from typing import Optional

def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def run_cmd(cmd: list, capture: bool = True) -> tuple:
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, timeout=30)
            return result.returncode == 0, "", ""
    except Exception as e:
        return False, "", str(e)

def cmd_status(args):
    print("\n" + "="*60)
    print("FORTRESS ANTI-DDOS STATUS")
    print("="*60)
    
    success, stdout, _ = run_cmd(['systemctl', 'is-active', 'fortress'])
    status = stdout.strip() if success else "unknown"
    print(f"Service Status: {status}")
    
    success, stdout, _ = run_cmd(['ip', 'link', 'show'])
    if success:
        for line in stdout.splitlines():
            if 'xdp' in line.lower():
                print(f"XDP Status: ATTACHED")
                break
        else:
            print(f"XDP Status: NOT ATTACHED")
    
    success, stdout, _ = run_cmd(['ipset', 'list', '-t'])
    if success:
        print("\nIPSet Statistics:")
        current_set = None
        for line in stdout.splitlines():
            if line.startswith('Name:'):
                current_set = line.split(':')[1].strip()
            elif 'Number of entries' in line and current_set:
                count = line.split(':')[1].strip()
                if 'fortress' in current_set:
                    print(f"  {current_set}: {count} entries")
    
    try:
        import requests
        resp = requests.get('http://127.0.0.1:9100/status', timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            metrics = data.get('metrics', {})
            print(f"\nTraffic Metrics:")
            print(f"  Packets Total: {metrics.get('packets_total', 0):,}")
            print(f"  Packets Passed: {metrics.get('packets_passed', 0):,}")
            print(f"  Packets Dropped: {metrics.get('packets_dropped', 0):,}")
            print(f"  Blocklist Hits: {metrics.get('blocklist_hits', 0):,}")
            print(f"  GeoIP Blocks: {metrics.get('geoip_hits', 0):,}")
            print(f"  Rate Limit Hits: {metrics.get('ratelimit_hits', 0):,}")
            print(f"\nStatus: {data.get('status', 'unknown').upper()}")
    except:
        print("\nMetrics: Unable to connect to monitor service")
    
    print("="*60 + "\n")

def cmd_block(args):
    ip = args.ip
    ttl = args.ttl
    reason = args.reason or "manual"
    
    try:
        socket.inet_aton(ip)
    except:
        print(f"Error: Invalid IP address: {ip}")
        return 1
    
    cmd = ['ipset', 'add', 'fortress_blocklist', ip, '-exist']
    if ttl > 0:
        cmd.extend(['timeout', str(ttl)])
    
    success, _, err = run_cmd(cmd)
    if success:
        print(f"Blocked: {ip} (TTL: {ttl}s, Reason: {reason})")
        
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'action': 'block',
            'ip': ip,
            'ttl': ttl,
            'reason': reason
        }
        try:
            with open('/var/log/fortress/manual.log', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except:
            pass
        return 0
    else:
        print(f"Error: Failed to block {ip}: {err}")
        return 1

def cmd_unblock(args):
    ip = args.ip
    
    success, _, err = run_cmd(['ipset', 'del', 'fortress_blocklist', ip, '-exist'])
    if success:
        print(f"Unblocked: {ip}")
        return 0
    else:
        print(f"Error: Failed to unblock {ip}: {err}")
        return 1

def cmd_whitelist(args):
    ip = args.ip
    
    try:
        socket.inet_aton(ip)
    except:
        print(f"Error: Invalid IP address: {ip}")
        return 1
    
    success, _, err = run_cmd(['ipset', 'add', 'fortress_whitelist', ip, '-exist'])
    if success:
        print(f"Whitelisted: {ip}")
        
        whitelist_file = '/opt/fortress/data/whitelist.txt'
        try:
            with open(whitelist_file, 'a') as f:
                f.write(f"{ip}\n")
        except:
            pass
        return 0
    else:
        print(f"Error: Failed to whitelist {ip}: {err}")
        return 1

def cmd_list_blocked(args):
    success, stdout, _ = run_cmd(['ipset', 'list', 'fortress_blocklist'])
    if success:
        print("Blocked IPs:")
        in_members = False
        count = 0
        for line in stdout.splitlines():
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                print(f"  {line.strip()}")
                count += 1
        print(f"\nTotal: {count} entries")
    else:
        print("Error: Failed to list blocked IPs")
        return 1
    return 0

def cmd_metrics(args):
    try:
        import requests
        resp = requests.get('http://127.0.0.1:9100/metrics', timeout=2)
        if resp.status_code == 200:
            print(resp.text)
        else:
            print("Error: Failed to get metrics")
            return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0

def cmd_reload(args):
    success, _, err = run_cmd(['systemctl', 'reload', 'fortress'])
    if success:
        print("Configuration reloaded")
        return 0
    else:
        print(f"Error: Failed to reload: {err}")
        return 1

def cmd_restart(args):
    success, _, err = run_cmd(['systemctl', 'restart', 'fortress'])
    if success:
        print("Service restarted")
        return 0
    else:
        print(f"Error: Failed to restart: {err}")
        return 1

def cmd_stop(args):
    success, _, err = run_cmd(['systemctl', 'stop', 'fortress'])
    if success:
        print("Service stopped")
        return 0
    else:
        print(f"Error: Failed to stop: {err}")
        return 1

def cmd_start(args):
    success, _, err = run_cmd(['systemctl', 'start', 'fortress'])
    if success:
        print("Service started")
        return 0
    else:
        print(f"Error: Failed to start: {err}")
        return 1

def cmd_logs(args):
    lines = args.lines
    run_cmd(['tail', '-n', str(lines), '/var/log/fortress/fortress.log'], capture=False)
    return 0

def cmd_watch(args):
    print("Watching traffic (Ctrl+C to stop)...")
    print("-" * 80)
    
    try:
        import requests
        prev_metrics = None
        
        while True:
            try:
                resp = requests.get('http://127.0.0.1:9100/status', timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    metrics = data.get('metrics', {})
                    
                    if prev_metrics:
                        pps = metrics.get('packets_total', 0) - prev_metrics.get('packets_total', 0)
                        drop_pps = metrics.get('packets_dropped', 0) - prev_metrics.get('packets_dropped', 0)
                        
                        status = data.get('status', 'normal')
                        status_str = f"\033[91mATTACK\033[0m" if status == 'attack' else f"\033[92mNORMAL\033[0m"
                        
                        print(f"\r[{status_str}] PPS: {pps:>8,} | Dropped: {drop_pps:>8,} | "
                              f"Blocklist: {metrics.get('blocklist_hits', 0):>8,} | "
                              f"GeoIP: {metrics.get('geoip_hits', 0):>8,}", end='')
                    
                    prev_metrics = metrics
            except:
                print("\rError: Unable to connect to monitor service", end='')
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
    
    return 0

def main():
    parser = argparse.ArgumentParser(
        description='Fortress Anti-DDoS CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    status_parser = subparsers.add_parser('status', help='Show system status')
    status_parser.set_defaults(func=cmd_status)
    
    block_parser = subparsers.add_parser('block', help='Block an IP address')
    block_parser.add_argument('ip', help='IP address to block')
    block_parser.add_argument('-t', '--ttl', type=int, default=3600, help='TTL in seconds (0=permanent)')
    block_parser.add_argument('-r', '--reason', help='Reason for blocking')
    block_parser.set_defaults(func=cmd_block)
    
    unblock_parser = subparsers.add_parser('unblock', help='Unblock an IP address')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    unblock_parser.set_defaults(func=cmd_unblock)
    
    whitelist_parser = subparsers.add_parser('whitelist', help='Whitelist an IP address')
    whitelist_parser.add_argument('ip', help='IP address to whitelist')
    whitelist_parser.set_defaults(func=cmd_whitelist)
    
    list_parser = subparsers.add_parser('list', help='List blocked IPs')
    list_parser.set_defaults(func=cmd_list_blocked)
    
    metrics_parser = subparsers.add_parser('metrics', help='Show Prometheus metrics')
    metrics_parser.set_defaults(func=cmd_metrics)
    
    reload_parser = subparsers.add_parser('reload', help='Reload configuration')
    reload_parser.set_defaults(func=cmd_reload)
    
    restart_parser = subparsers.add_parser('restart', help='Restart service')
    restart_parser.set_defaults(func=cmd_restart)
    
    stop_parser = subparsers.add_parser('stop', help='Stop service')
    stop_parser.set_defaults(func=cmd_stop)
    
    start_parser = subparsers.add_parser('start', help='Start service')
    start_parser.set_defaults(func=cmd_start)
    
    logs_parser = subparsers.add_parser('logs', help='Show logs')
    logs_parser.add_argument('-n', '--lines', type=int, default=50, help='Number of lines')
    logs_parser.set_defaults(func=cmd_logs)
    
    watch_parser = subparsers.add_parser('watch', help='Watch traffic in real-time')
    watch_parser.set_defaults(func=cmd_watch)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
