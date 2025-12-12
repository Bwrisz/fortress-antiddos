#ifndef __FORTRESS_COMMON_H
#define __FORTRESS_COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES_STATS      1000000
#define MAX_ENTRIES_BLOCKLIST  10000000
#define MAX_ENTRIES_GEOIP      500000
#define MAX_ENTRIES_CONNTRACK  2000000
#define MAX_ENTRIES_RATELIMIT  1000000
#define MAX_ENTRIES_SIGNATURES 100000
#define MAX_ENTRIES_METRICS    64
#define RINGBUF_SIZE           (256 * 1024)

#define DEFAULT_PPS_LIMIT      10000
#define DEFAULT_CPS_LIMIT      100
#define DEFAULT_SYN_LIMIT      10000
#define DEFAULT_UDP_LIMIT      50000
#define DEFAULT_ICMP_LIMIT     1000

#define CONN_TIMEOUT_SYN       30
#define CONN_TIMEOUT_EST       300
#define CONN_TIMEOUT_FIN       30
#define CONN_TIMEOUT_UDP       30

#define AMPLIFICATION_PORT_DNS      53
#define AMPLIFICATION_PORT_NTP      123
#define AMPLIFICATION_PORT_SNMP     161
#define AMPLIFICATION_PORT_SSDP     1900
#define AMPLIFICATION_PORT_MEMCACHED 11211
#define AMPLIFICATION_PORT_CHARGEN  19
#define AMPLIFICATION_PORT_QOTD     17
#define AMPLIFICATION_PORT_LDAP     389
#define AMPLIFICATION_PORT_CLDAP    389
#define AMPLIFICATION_PORT_MSSQL    1434
#define AMPLIFICATION_PORT_RIP      520
#define AMPLIFICATION_PORT_PORTMAP  111

#define UDP_MAX_SIZE_UNTRUSTED 512

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

enum conn_state {
    CONN_NEW = 0,
    CONN_SYN_SENT,
    CONN_SYN_RECV,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT1,
    CONN_FIN_WAIT2,
    CONN_CLOSE_WAIT,
    CONN_CLOSING,
    CONN_LAST_ACK,
    CONN_TIME_WAIT,
    CONN_CLOSED
};

enum attack_type {
    ATTACK_NONE = 0,
    ATTACK_SYN_FLOOD,
    ATTACK_UDP_FLOOD,
    ATTACK_ICMP_FLOOD,
    ATTACK_ACK_FLOOD,
    ATTACK_RST_FLOOD,
    ATTACK_AMPLIFICATION,
    ATTACK_SLOWLORIS,
    ATTACK_HTTP_FLOOD,
    ATTACK_DNS_FLOOD,
    ATTACK_FRAGMENTATION,
    ATTACK_MALFORMED,
    ATTACK_UNKNOWN
};

enum drop_reason {
    DROP_NONE = 0,
    DROP_BLOCKLIST,
    DROP_GEOIP,
    DROP_RATE_LIMIT,
    DROP_SYN_FLOOD,
    DROP_UDP_FLOOD,
    DROP_ICMP_FLOOD,
    DROP_INVALID_PACKET,
    DROP_INVALID_STATE,
    DROP_AMPLIFICATION,
    DROP_OVERSIZED,
    DROP_SIGNATURE,
    DROP_FRAGMENT,
    DROP_MALFORMED
};

enum metric_idx {
    METRIC_PACKETS_TOTAL = 0,
    METRIC_PACKETS_PASSED,
    METRIC_PACKETS_DROPPED,
    METRIC_BYTES_TOTAL,
    METRIC_BYTES_PASSED,
    METRIC_BYTES_DROPPED,
    METRIC_SYN_TOTAL,
    METRIC_SYN_DROPPED,
    METRIC_UDP_TOTAL,
    METRIC_UDP_DROPPED,
    METRIC_ICMP_TOTAL,
    METRIC_ICMP_DROPPED,
    METRIC_BLOCKLIST_HITS,
    METRIC_GEOIP_HITS,
    METRIC_RATELIMIT_HITS,
    METRIC_CONNTRACK_NEW,
    METRIC_CONNTRACK_EST,
    METRIC_CONNTRACK_CLOSED,
    METRIC_SIGNATURE_HITS,
    METRIC_AMPLIFICATION_HITS,
    METRIC_MAX
};

struct ip_stats {
    __u64 packets;
    __u64 bytes;
    __u64 syn_packets;
    __u64 ack_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 first_seen;
    __u64 last_seen;
    __u32 connections;
    __u32 blocked_count;
    __u16 threat_level;
    __u8  is_blocked;
    __u8  flags;
};

struct rate_limit {
    __u64 tokens;
    __u64 last_update;
    __u32 bucket_size;
    __u32 refill_rate;
    __u64 syn_tokens;
    __u64 udp_tokens;
    __u64 icmp_tokens;
};

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct conn_entry {
    __u8  state;
    __u8  flags;
    __u16 pad;
    __u32 seq;
    __u32 ack;
    __u64 packets;
    __u64 bytes;
    __u64 created;
    __u64 last_seen;
};

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct blocklist_val {
    __u64 added_time;
    __u64 expire_time;
    __u32 hit_count;
    __u8  reason;
    __u8  pad[3];
};

struct geoip_val {
    __u16 country_code;
    __u8  is_blocked;
    __u8  pad;
};

struct signature_key {
    __u8  protocol;
    __u8  flags;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u32 payload_hash;
};

struct attack_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  attack_type;
    __u8  drop_reason;
    __u8  severity;
    __u64 pps;
    __u64 bps;
};

struct syn_cookie {
    __u32 secret[2];
    __u64 last_rotation;
    __u32 count;
    __u8  active;
    __u8  pad[3];
};

struct config {
    __u32 pps_limit;
    __u32 cps_limit;
    __u32 syn_limit;
    __u32 udp_limit;
    __u32 icmp_limit;
    __u32 conn_timeout;
    __u16 blocked_countries[32];
    __u8  blocked_country_count;
    __u8  geoip_enabled;
    __u8  ratelimit_enabled;
    __u8  blocklist_enabled;
    __u8  syn_cookies_enabled;
    __u8  tcp_validation;
    __u8  udp_validation;
    __u8  fragment_protection;
};

static __always_inline __u64 get_nsec(void) {
    return bpf_ktime_get_ns();
}

static __always_inline __u32 hash_ip(__u32 ip) {
    ip ^= ip >> 16;
    ip *= 0x85ebca6b;
    ip ^= ip >> 13;
    ip *= 0xc2b2ae35;
    ip ^= ip >> 16;
    return ip;
}

static __always_inline __u32 hash_conn(struct conn_key *key) {
    __u32 h = key->src_ip;
    h ^= key->dst_ip;
    h ^= ((__u32)key->src_port << 16) | key->dst_port;
    h ^= key->protocol;
    return hash_ip(h);
}

static __always_inline int is_amplification_port(__u16 port) {
    switch (port) {
        case AMPLIFICATION_PORT_DNS:
        case AMPLIFICATION_PORT_NTP:
        case AMPLIFICATION_PORT_SNMP:
        case AMPLIFICATION_PORT_SSDP:
        case AMPLIFICATION_PORT_MEMCACHED:
        case AMPLIFICATION_PORT_CHARGEN:
        case AMPLIFICATION_PORT_QOTD:
        case AMPLIFICATION_PORT_LDAP:
        case AMPLIFICATION_PORT_MSSQL:
        case AMPLIFICATION_PORT_RIP:
        case AMPLIFICATION_PORT_PORTMAP:
            return 1;
        default:
            return 0;
    }
}

static __always_inline int is_invalid_tcp_flags(__u8 flags) {
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) == (TCP_FLAG_SYN | TCP_FLAG_FIN))
        return 1;
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_RST)) == (TCP_FLAG_SYN | TCP_FLAG_RST))
        return 1;
    if ((flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) == (TCP_FLAG_FIN | TCP_FLAG_RST))
        return 1;
    if (flags == 0)
        return 1;
    if ((flags & TCP_FLAG_ACK) == 0 && (flags & TCP_FLAG_SYN) == 0 && 
        (flags & TCP_FLAG_RST) == 0 && (flags & TCP_FLAG_FIN) == 0)
        return 1;
    return 0;
}

#endif
