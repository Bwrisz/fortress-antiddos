#include "common.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

struct packet_info {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;
    __u8 protocol;
    __u8 tcp_flags;
};

static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_info *pkt) {
    pkt->data = (void *)(long)ctx->data;
    pkt->data_end = (void *)(long)ctx->data_end;
    
    pkt->eth = pkt->data;
    if ((void *)(pkt->eth + 1) > pkt->data_end)
        return -1;
    
    if (pkt->eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    pkt->ip = (void *)(pkt->eth + 1);
    if ((void *)(pkt->ip + 1) > pkt->data_end)
        return -1;
    
    if (pkt->ip->ihl < 5)
        return -1;
    
    __u32 ip_hdr_len = pkt->ip->ihl * 4;
    if ((void *)pkt->ip + ip_hdr_len > pkt->data_end)
        return -1;
    
    pkt->src_ip = pkt->ip->saddr;
    pkt->dst_ip = pkt->ip->daddr;
    pkt->protocol = pkt->ip->protocol;
    pkt->payload_len = bpf_ntohs(pkt->ip->tot_len) - ip_hdr_len;
    
    pkt->tcp = NULL;
    pkt->udp = NULL;
    pkt->icmp = NULL;
    pkt->src_port = 0;
    pkt->dst_port = 0;
    pkt->tcp_flags = 0;
    
    void *l4_hdr = (void *)pkt->ip + ip_hdr_len;
    
    if (pkt->protocol == IPPROTO_TCP) {
        pkt->tcp = l4_hdr;
        if ((void *)(pkt->tcp + 1) > pkt->data_end)
            return -1;
        pkt->src_port = bpf_ntohs(pkt->tcp->source);
        pkt->dst_port = bpf_ntohs(pkt->tcp->dest);
        pkt->tcp_flags = (((__u8 *)pkt->tcp)[13]);
        pkt->payload_len -= pkt->tcp->doff * 4;
    } else if (pkt->protocol == IPPROTO_UDP) {
        pkt->udp = l4_hdr;
        if ((void *)(pkt->udp + 1) > pkt->data_end)
            return -1;
        pkt->src_port = bpf_ntohs(pkt->udp->source);
        pkt->dst_port = bpf_ntohs(pkt->udp->dest);
        pkt->payload_len = bpf_ntohs(pkt->udp->len) - sizeof(struct udphdr);
    } else if (pkt->protocol == IPPROTO_ICMP) {
        pkt->icmp = l4_hdr;
        if ((void *)(pkt->icmp + 1) > pkt->data_end)
            return -1;
    }
    
    return 0;
}

static __always_inline int validate_ip_header(struct packet_info *pkt) {
    if (pkt->ip->version != 4)
        return -1;
    if (pkt->ip->ihl < 5 || pkt->ip->ihl > 15)
        return -1;
    __u16 tot_len = bpf_ntohs(pkt->ip->tot_len);
    if (tot_len < (pkt->ip->ihl * 4))
        return -1;
    if (pkt->ip->ttl == 0)
        return -1;
    return 0;
}

static __always_inline int validate_tcp_header(struct packet_info *pkt) {
    if (!pkt->tcp)
        return 0;
    if (pkt->tcp->doff < 5 || pkt->tcp->doff > 15)
        return -1;
    if (is_invalid_tcp_flags(pkt->tcp_flags))
        return -1;
    if (pkt->src_port == 0 || pkt->dst_port == 0)
        return -1;
    return 0;
}

static __always_inline int validate_udp_header(struct packet_info *pkt) {
    if (!pkt->udp)
        return 0;
    __u16 udp_len = bpf_ntohs(pkt->udp->len);
    if (udp_len < sizeof(struct udphdr))
        return -1;
    if (pkt->src_port == 0)
        return -1;
    return 0;
}

static __always_inline int check_rate_limit_token(struct rate_limit *rl, 
                                                   __u64 now, __u32 limit) {
    __u64 elapsed = now - rl->last_update;
    __u64 refill = (elapsed * limit) / 1000000000ULL;
    
    if (refill > 0) {
        rl->tokens += refill;
        if (rl->tokens > limit)
            rl->tokens = limit;
        rl->last_update = now;
    }
    
    if (rl->tokens > 0) {
        rl->tokens--;
        return 0;
    }
    return -1;
}

static __always_inline int process_tcp(struct packet_info *pkt, 
                                       struct config *cfg,
                                       struct ip_stats *stats,
                                       struct rate_limit *rl) {
    __u64 now = get_nsec();
    
    if (pkt->tcp_flags & TCP_FLAG_SYN) {
        stats->syn_packets++;
        
        if (cfg->syn_cookies_enabled) {
            if (check_rate_limit_token(rl, now, cfg->syn_limit) < 0) {
                update_metric(METRIC_SYN_DROPPED, 1);
                send_event(pkt->src_ip, pkt->dst_ip, pkt->src_port, 
                          pkt->dst_port, IPPROTO_TCP, ATTACK_SYN_FLOOD, 
                          DROP_SYN_FLOOD);
                return XDP_DROP;
            }
        }
        
        if (!(pkt->tcp_flags & TCP_FLAG_ACK)) {
            struct conn_key key = {
                .src_ip = pkt->src_ip,
                .dst_ip = pkt->dst_ip,
                .src_port = pkt->src_port,
                .dst_port = pkt->dst_port,
                .protocol = IPPROTO_TCP
            };
            create_conn(&key, CONN_SYN_RECV, bpf_ntohl(pkt->tcp->seq), 0);
            update_metric(METRIC_CONNTRACK_NEW, 1);
        }
    }
    
    if (pkt->tcp_flags & TCP_FLAG_ACK) {
        stats->ack_packets++;
        
        struct conn_key key = {
            .src_ip = pkt->dst_ip,
            .dst_ip = pkt->src_ip,
            .src_port = pkt->dst_port,
            .dst_port = pkt->src_port,
            .protocol = IPPROTO_TCP
        };
        
        struct conn_entry *conn = get_conn(&key);
        if (conn) {
            if (conn->state == CONN_SYN_RECV && 
                (pkt->tcp_flags & TCP_FLAG_SYN) == 0) {
                update_conn(conn, CONN_ESTABLISHED, 
                           bpf_ntohl(pkt->tcp->seq),
                           bpf_ntohl(pkt->tcp->ack_seq),
                           pkt->payload_len);
                update_metric(METRIC_CONNTRACK_EST, 1);
            } else if (conn->state == CONN_ESTABLISHED) {
                update_conn(conn, CONN_ESTABLISHED,
                           bpf_ntohl(pkt->tcp->seq),
                           bpf_ntohl(pkt->tcp->ack_seq),
                           pkt->payload_len);
            }
        }
    }
    
    if (pkt->tcp_flags & TCP_FLAG_RST) {
        struct conn_key key = {
            .src_ip = pkt->src_ip,
            .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port,
            .dst_port = pkt->dst_port,
            .protocol = IPPROTO_TCP
        };
        bpf_map_delete_elem(&conntrack_map, &key);
        update_metric(METRIC_CONNTRACK_CLOSED, 1);
    }
    
    if (pkt->tcp_flags & TCP_FLAG_FIN) {
        struct conn_key key = {
            .src_ip = pkt->src_ip,
            .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port,
            .dst_port = pkt->dst_port,
            .protocol = IPPROTO_TCP
        };
        struct conn_entry *conn = get_conn(&key);
        if (conn) {
            update_conn(conn, CONN_FIN_WAIT1,
                       bpf_ntohl(pkt->tcp->seq),
                       bpf_ntohl(pkt->tcp->ack_seq),
                       pkt->payload_len);
        }
    }
    
    return XDP_PASS;
}

static __always_inline int process_udp(struct packet_info *pkt,
                                       struct config *cfg,
                                       struct ip_stats *stats,
                                       struct rate_limit *rl) {
    __u64 now = get_nsec();
    stats->udp_packets++;
    
    if (check_rate_limit_token(rl, now, cfg->udp_limit) < 0) {
        update_metric(METRIC_UDP_DROPPED, 1);
        send_event(pkt->src_ip, pkt->dst_ip, pkt->src_port,
                  pkt->dst_port, IPPROTO_UDP, ATTACK_UDP_FLOOD,
                  DROP_UDP_FLOOD);
        return XDP_DROP;
    }
    
    if (is_amplification_port(pkt->src_port)) {
        __u64 *req = bpf_map_lookup_elem(&dns_requests_map, &pkt->src_ip);
        if (!req) {
            update_metric(METRIC_AMPLIFICATION_HITS, 1);
            send_event(pkt->src_ip, pkt->dst_ip, pkt->src_port,
                      pkt->dst_port, IPPROTO_UDP, ATTACK_AMPLIFICATION,
                      DROP_AMPLIFICATION);
            return XDP_DROP;
        }
    }
    
    if (!check_whitelist(pkt->src_ip)) {
        __u16 udp_len = bpf_ntohs(pkt->udp->len);
        if (udp_len > UDP_MAX_SIZE_UNTRUSTED) {
            update_metric(METRIC_UDP_DROPPED, 1);
            send_event(pkt->src_ip, pkt->dst_ip, pkt->src_port,
                      pkt->dst_port, IPPROTO_UDP, ATTACK_UDP_FLOOD,
                      DROP_OVERSIZED);
            return XDP_DROP;
        }
    }
    
    if (pkt->dst_port == 53) {
        __u64 ts = now;
        bpf_map_update_elem(&dns_requests_map, &pkt->dst_ip, &ts, BPF_ANY);
    }
    
    return XDP_PASS;
}

static __always_inline int process_icmp(struct packet_info *pkt,
                                        struct config *cfg,
                                        struct ip_stats *stats,
                                        struct rate_limit *rl) {
    __u64 now = get_nsec();
    stats->icmp_packets++;
    
    if (check_rate_limit_token(rl, now, cfg->icmp_limit) < 0) {
        update_metric(METRIC_ICMP_DROPPED, 1);
        send_event(pkt->src_ip, pkt->dst_ip, 0, 0, IPPROTO_ICMP,
                  ATTACK_ICMP_FLOOD, DROP_RATE_LIMIT);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_fortress(struct xdp_md *ctx) {
    struct packet_info pkt = {0};
    
    if (parse_packet(ctx, &pkt) < 0)
        return XDP_PASS;
    
    __u32 pkt_len = (__u32)(pkt.data_end - pkt.data);
    update_metric(METRIC_PACKETS_TOTAL, 1);
    update_metric(METRIC_BYTES_TOTAL, pkt_len);
    
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg)
        return XDP_PASS;
    
    if (check_whitelist(pkt.src_ip)) {
        update_metric(METRIC_PACKETS_PASSED, 1);
        update_metric(METRIC_BYTES_PASSED, pkt_len);
        return XDP_PASS;
    }
    
    if (cfg->blocklist_enabled && check_blocklist(pkt.src_ip)) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        update_metric(METRIC_BLOCKLIST_HITS, 1);
        return XDP_DROP;
    }
    
    if (cfg->geoip_enabled && check_geoip(pkt.src_ip, cfg)) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        update_metric(METRIC_GEOIP_HITS, 1);
        send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol, ATTACK_NONE, DROP_GEOIP);
        return XDP_DROP;
    }
    
    if (validate_ip_header(&pkt) < 0) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol, ATTACK_MALFORMED, DROP_MALFORMED);
        return XDP_DROP;
    }
    
    if (cfg->tcp_validation && validate_tcp_header(&pkt) < 0) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol, ATTACK_MALFORMED, DROP_MALFORMED);
        return XDP_DROP;
    }
    
    if (cfg->udp_validation && validate_udp_header(&pkt) < 0) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol, ATTACK_MALFORMED, DROP_MALFORMED);
        return XDP_DROP;
    }
    
    if (cfg->fragment_protection && (bpf_ntohs(pkt.ip->frag_off) & 0x3FFF)) {
        update_metric(METRIC_PACKETS_DROPPED, 1);
        update_metric(METRIC_BYTES_DROPPED, pkt_len);
        send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol, ATTACK_FRAGMENTATION, DROP_FRAGMENT);
        return XDP_DROP;
    }
    
    struct ip_stats *stats = get_ip_stats(pkt.src_ip);
    if (!stats)
        return XDP_PASS;
    
    stats->packets++;
    stats->bytes += pkt_len;
    stats->last_seen = get_nsec();
    
    struct rate_limit *rl = get_rate_limit(pkt.src_ip);
    if (!rl)
        return XDP_PASS;
    
    __u64 now = get_nsec();
    if (cfg->ratelimit_enabled) {
        if (check_rate_limit_token(rl, now, cfg->pps_limit) < 0) {
            update_metric(METRIC_PACKETS_DROPPED, 1);
            update_metric(METRIC_BYTES_DROPPED, pkt_len);
            update_metric(METRIC_RATELIMIT_HITS, 1);
            stats->blocked_count++;
            send_event(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                      pkt.protocol, ATTACK_UNKNOWN, DROP_RATE_LIMIT);
            return XDP_DROP;
        }
    }
    
    int action = XDP_PASS;
    
    if (pkt.protocol == IPPROTO_TCP) {
        update_metric(METRIC_SYN_TOTAL, 1);
        action = process_tcp(&pkt, cfg, stats, rl);
    } else if (pkt.protocol == IPPROTO_UDP) {
        update_metric(METRIC_UDP_TOTAL, 1);
        action = process_udp(&pkt, cfg, stats, rl);
    } else if (pkt.protocol == IPPROTO_ICMP) {
        update_metric(METRIC_ICMP_TOTAL, 1);
        action = process_icmp(&pkt, cfg, stats, rl);
    }
    
    if (action == XDP_PASS) {
        update_metric(METRIC_PACKETS_PASSED, 1);
        update_metric(METRIC_BYTES_PASSED, pkt_len);
    }
    
    return action;
}
