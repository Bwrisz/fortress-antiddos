#ifndef __FORTRESS_MAPS_H
#define __FORTRESS_MAPS_H

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_ENTRIES_STATS);
    __type(key, __u32);
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES_BLOCKLIST);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct blocklist_val);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES_GEOIP);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct geoip_val);
} geoip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES_CONNTRACK);
    __type(key, struct conn_key);
    __type(value, struct conn_entry);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_ENTRIES_RATELIMIT);
    __type(key, __u32);
    __type(value, struct rate_limit);
} ratelimit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_SIGNATURES);
    __type(key, struct signature_key);
    __type(value, __u8);
} signatures_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_ENTRIES_METRICS);
    __type(key, __u32);
    __type(value, __u64);
} metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_cookie);
} syn_cookie_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u64);
} dns_requests_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} port_stats_map SEC(".maps");

static __always_inline void update_metric(__u32 idx, __u64 val) {
    __u64 *counter = bpf_map_lookup_elem(&metrics_map, &idx);
    if (counter)
        __sync_fetch_and_add(counter, val);
}

static __always_inline struct ip_stats *get_ip_stats(__u32 ip) {
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &ip);
    if (!stats) {
        struct ip_stats new_stats = {0};
        new_stats.first_seen = get_nsec();
        new_stats.last_seen = new_stats.first_seen;
        bpf_map_update_elem(&ip_stats_map, &ip, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&ip_stats_map, &ip);
    }
    return stats;
}

static __always_inline struct rate_limit *get_rate_limit(__u32 ip) {
    struct rate_limit *rl = bpf_map_lookup_elem(&ratelimit_map, &ip);
    if (!rl) {
        struct rate_limit new_rl = {0};
        new_rl.tokens = DEFAULT_PPS_LIMIT;
        new_rl.syn_tokens = DEFAULT_SYN_LIMIT;
        new_rl.udp_tokens = DEFAULT_UDP_LIMIT;
        new_rl.icmp_tokens = DEFAULT_ICMP_LIMIT;
        new_rl.last_update = get_nsec();
        new_rl.bucket_size = DEFAULT_PPS_LIMIT;
        new_rl.refill_rate = DEFAULT_PPS_LIMIT;
        bpf_map_update_elem(&ratelimit_map, &ip, &new_rl, BPF_NOEXIST);
        rl = bpf_map_lookup_elem(&ratelimit_map, &ip);
    }
    return rl;
}

static __always_inline int check_blocklist(__u32 ip) {
    struct lpm_key key = {.prefixlen = 32, .addr = ip};
    struct blocklist_val *val = bpf_map_lookup_elem(&blocklist_map, &key);
    if (val) {
        __u64 now = get_nsec();
        if (val->expire_time > 0 && now > val->expire_time)
            return 0;
        __sync_fetch_and_add(&val->hit_count, 1);
        return 1;
    }
    return 0;
}

static __always_inline int check_whitelist(__u32 ip) {
    struct lpm_key key = {.prefixlen = 32, .addr = ip};
    return bpf_map_lookup_elem(&whitelist_map, &key) != NULL;
}

static __always_inline int check_geoip(__u32 ip, struct config *cfg) {
    if (!cfg || !cfg->geoip_enabled)
        return 0;
    struct lpm_key key = {.prefixlen = 32, .addr = ip};
    struct geoip_val *val = bpf_map_lookup_elem(&geoip_map, &key);
    if (val && val->is_blocked)
        return 1;
    return 0;
}

static __always_inline void send_event(__u32 src_ip, __u32 dst_ip, 
                                       __u16 src_port, __u16 dst_port,
                                       __u8 protocol, __u8 attack_type,
                                       __u8 drop_reason) {
    struct attack_event *event;
    event = bpf_ringbuf_reserve(&events_map, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp = get_nsec();
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = protocol;
    event->attack_type = attack_type;
    event->drop_reason = drop_reason;
    event->severity = 1;
    event->pps = 0;
    event->bps = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline struct conn_entry *get_conn(struct conn_key *key) {
    return bpf_map_lookup_elem(&conntrack_map, key);
}

static __always_inline int create_conn(struct conn_key *key, __u8 state,
                                       __u32 seq, __u32 ack) {
    struct conn_entry entry = {0};
    entry.state = state;
    entry.seq = seq;
    entry.ack = ack;
    entry.created = get_nsec();
    entry.last_seen = entry.created;
    entry.packets = 1;
    return bpf_map_update_elem(&conntrack_map, key, &entry, BPF_NOEXIST);
}

static __always_inline void update_conn(struct conn_entry *entry, __u8 state,
                                        __u32 seq, __u32 ack, __u32 len) {
    entry->state = state;
    entry->seq = seq;
    entry->ack = ack;
    entry->last_seen = get_nsec();
    entry->packets++;
    entry->bytes += len;
}

#endif
