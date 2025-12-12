// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKED 1000000
#define MAX_WHITELIST 10000
#define MAX_RATE 100000
#define SYN_LIMIT 20
#define UDP_LIMIT 50
#define CONN_LIMIT 30
#define WINDOW_NS 1000000000ULL

struct rate_data {
    __u64 timestamp;
    __u32 syn;
    __u32 udp;
    __u32 conn;
    __u32 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED);
    __type(key, __u32);
    __type(value, __u64);
} blocked SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, __u32);
    __type(value, __u64);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RATE);
    __type(key, __u32);
    __type(value, struct rate_data);
} ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Stats update
    __u32 key = 0;
    __u64 *rx_packets = bpf_map_lookup_elem(&stats, &key);
    if (rx_packets) __sync_fetch_and_add(rx_packets, 1);
    
    key = 1;
    __u64 *rx_bytes = bpf_map_lookup_elem(&stats, &key);
    if (rx_bytes) __sync_fetch_and_add(rx_bytes, data_end - data);
    
    // Parse ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->ihl < 5)
        return XDP_DROP;
    
    __u32 src_ip = ip->saddr;
    
    // Whitelist check
    if (bpf_map_lookup_elem(&whitelist, &src_ip))
        return XDP_PASS;
    
    // Blocklist check
    if (bpf_map_lookup_elem(&blocked, &src_ip)) {
        key = 2;
        __u64 *drop_packets = bpf_map_lookup_elem(&stats, &key);
        if (drop_packets) __sync_fetch_and_add(drop_packets, 1);
        return XDP_DROP;
    }
    
    // Rate limiting
    __u64 now = bpf_ktime_get_ns();
    struct rate_data *rate = bpf_map_lookup_elem(&ratelimit, &src_ip);
    struct rate_data new_rate = {0};
    
    if (rate) {
        if (now - rate->timestamp > WINDOW_NS) {
            new_rate.timestamp = now;
            new_rate.packets = 1;
        } else {
            new_rate = *rate;
            new_rate.packets++;
        }
    } else {
        new_rate.timestamp = now;
        new_rate.packets = 1;
    }
    
    // TCP processing
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        
        // Invalid flags check
        __u8 flags = ((__u8 *)tcp)[13];
        if (flags == 0 || flags == 0x3F)
            return XDP_DROP;
        if ((flags & 0x06) == 0x06) // SYN+RST
            return XDP_DROP;
        if ((flags & 0x03) == 0x03) // SYN+FIN
            return XDP_DROP;
        
        // SYN flood check
        if ((flags & 0x02) && !(flags & 0x10)) { // SYN without ACK
            new_rate.syn++;
            if (new_rate.syn > SYN_LIMIT) {
                __u64 ban_time = now;
                bpf_map_update_elem(&blocked, &src_ip, &ban_time, BPF_ANY);
                return XDP_DROP;
            }
        }
        
        new_rate.conn++;
        if (new_rate.conn > CONN_LIMIT) {
            __u64 ban_time = now;
            bpf_map_update_elem(&blocked, &src_ip, &ban_time, BPF_ANY);
            return XDP_DROP;
        }
    }
    // UDP processing
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        
        __u16 sport = bpf_ntohs(udp->source);
        
        // Amplification attack sources
        if (sport == 53 || sport == 123 || sport == 161 || 
            sport == 1900 || sport == 11211 || sport == 19 || sport == 17)
            return XDP_DROP;
        
        // UDP size check
        __u16 ulen = bpf_ntohs(udp->len);
        if (ulen < 8 || ulen > 1400)
            return XDP_DROP;
        
        new_rate.udp++;
        if (new_rate.udp > UDP_LIMIT) {
            __u64 ban_time = now;
            bpf_map_update_elem(&blocked, &src_ip, &ban_time, BPF_ANY);
            return XDP_DROP;
        }
    }
    // ICMP - drop all
    else if (ip->protocol == IPPROTO_ICMP) {
        return XDP_DROP;
    }
    
    bpf_map_update_elem(&ratelimit, &src_ip, &new_rate, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
