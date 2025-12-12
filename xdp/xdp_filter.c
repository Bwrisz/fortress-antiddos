#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define MAX_BLOCKED 1000000
#define MAX_WHITELIST 10000
#define MAX_RATE 100000
// Daha agresif limitler
#define SYN_LIMIT 20
#define UDP_LIMIT 50
#define CONN_LIMIT 30
#define WINDOW_NS 1000000000

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct rate_data {
    __u64 timestamp;
    __u32 syn;
    __u32 udp;
    __u32 conn;
    __u32 packets;
    __u64 bytes;
};

struct stats_data {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 drop_packets;
    __u64 drop_bytes;
};

struct bpf_map_def SEC("maps") blocked = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_BLOCKED,
};

struct bpf_map_def SEC("maps") whitelist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_WHITELIST,
};

struct bpf_map_def SEC("maps") ratelimit = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct rate_data),
    .max_entries = MAX_RATE,
};

struct bpf_map_def SEC("maps") stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct stats_data),
    .max_entries = 1,
};

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

static __always_inline int check_tcp_flags(struct tcphdr *tcp) {
    __u8 f = 0;
    if (tcp->syn) f |= 0x02;
    if (tcp->ack) f |= 0x10;
    if (tcp->fin) f |= 0x01;
    if (tcp->rst) f |= 0x04;
    if (tcp->psh) f |= 0x08;
    if (tcp->urg) f |= 0x20;
    
    if (f == 0 || f == 0x3F) return 0;
    if ((f & 0x06) == 0x06) return 0;
    if ((f & 0x03) == 0x03) return 0;
    return 1;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    __u32 len = end - data;
    
    __u32 key = 0;
    struct stats_data *s = bpf_map_lookup_elem(&stats, &key);
    if (!s) return XDP_PASS;
    
    __sync_fetch_and_add(&s->rx_packets, 1);
    __sync_fetch_and_add(&s->rx_bytes, len);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->ihl < 5) return XDP_DROP;
    
    __u32 src = ip->saddr;
    
    if (bpf_map_lookup_elem(&whitelist, &src)) return XDP_PASS;
    if (bpf_map_lookup_elem(&blocked, &src)) {
        __sync_fetch_and_add(&s->drop_packets, 1);
        __sync_fetch_and_add(&s->drop_bytes, len);
        return XDP_DROP;
    }
    
    __u64 now = bpf_ktime_get_ns();
    struct rate_data *r = bpf_map_lookup_elem(&ratelimit, &src);
    struct rate_data nr = {0};
    
    if (r) {
        if (now - r->timestamp > WINDOW_NS) {
            nr.timestamp = now;
            nr.packets = 1;
            nr.bytes = len;
        } else {
            nr = *r;
            nr.timestamp = now;
            nr.packets++;
            nr.bytes += len;
        }
    } else {
        nr.timestamp = now;
        nr.packets = 1;
        nr.bytes = len;
    }
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > end) return XDP_DROP;
        
        if (!check_tcp_flags(tcp)) {
            __sync_fetch_and_add(&s->drop_packets, 1);
            return XDP_DROP;
        }
        
        if (tcp->syn && !tcp->ack) {
            nr.syn++;
            if (nr.syn > SYN_LIMIT) {
                __u64 t = now;
                bpf_map_update_elem(&blocked, &src, &t, BPF_ANY);
                __sync_fetch_and_add(&s->drop_packets, 1);
                return XDP_DROP;
            }
        }
        
        nr.conn++;
        if (nr.conn > CONN_LIMIT) {
            __u64 t = now;
            bpf_map_update_elem(&blocked, &src, &t, BPF_ANY);
            __sync_fetch_and_add(&s->drop_packets, 1);
            return XDP_DROP;
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > end) return XDP_DROP;
        
        __u16 sport = __constant_ntohs(udp->source);
        if (sport == 123 || sport == 161 || sport == 1900 || sport == 11211 || sport == 19 || sport == 17) {
            __sync_fetch_and_add(&s->drop_packets, 1);
            return XDP_DROP;
        }
        
        __u16 ulen = __constant_ntohs(udp->len);
        if (ulen < 28 || ulen > 1400) {
            __sync_fetch_and_add(&s->drop_packets, 1);
            return XDP_DROP;
        }
        
        nr.udp++;
        if (nr.udp > UDP_LIMIT) {
            __u64 t = now;
            bpf_map_update_elem(&blocked, &src, &t, BPF_ANY);
            __sync_fetch_and_add(&s->drop_packets, 1);
            return XDP_DROP;
        }
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&s->drop_packets, 1);
        return XDP_DROP;
    }
    
    bpf_map_update_elem(&ratelimit, &src, &nr, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
