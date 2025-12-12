/*
 * Fortress Packet Filter
 * User-space packet filtering using NFQUEUE
 * Fallback when XDP is not available
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_TRACKED_IPS 1000000
#define HASH_SIZE 65536
#define RATE_WINDOW 1
#define SYN_THRESHOLD 20
#define CONN_THRESHOLD 50
#define UDP_THRESHOLD 100
#define CLEANUP_INTERVAL 60

typedef struct ip_entry {
    uint32_t ip;
    uint32_t syn_count;
    uint32_t conn_count;
    uint32_t udp_count;
    uint32_t packet_count;
    uint64_t byte_count;
    time_t first_seen;
    time_t last_seen;
    time_t window_start;
    int blocked;
    struct ip_entry *next;
} ip_entry_t;

typedef struct {
    ip_entry_t *buckets[HASH_SIZE];
    pthread_mutex_t locks[HASH_SIZE];
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dropped_packets;
    uint64_t dropped_bytes;
    uint32_t tracked_ips;
    uint32_t blocked_ips;
} ip_tracker_t;

typedef struct {
    uint32_t ip;
    int whitelisted;
} whitelist_entry_t;

static ip_tracker_t tracker;
static whitelist_entry_t whitelist[1000];
static int whitelist_count = 0;
static volatile int running = 1;
static FILE *log_file = NULL;

static uint32_t hash_ip(uint32_t ip) {
    return ip % HASH_SIZE;
}

static void log_message(const char *level, const char *format, ...) {
    if (!log_file) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(log_file, "%s [%s] ", time_buf, level);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}

static int is_whitelisted(uint32_t ip) {
    for (int i = 0; i < whitelist_count; i++) {
        if (whitelist[i].ip == ip) {
            return 1;
        }
    }
    return 0;
}

static void add_whitelist(const char *ip_str) {
    if (whitelist_count >= 1000) return;
    
    struct in_addr addr;
    if (inet_aton(ip_str, &addr)) {
        whitelist[whitelist_count].ip = ntohl(addr.s_addr);
        whitelist[whitelist_count].whitelisted = 1;
        whitelist_count++;
        log_message("INFO", "Whitelisted: %s", ip_str);
    }
}

static ip_entry_t *get_or_create_entry(uint32_t ip) {
    uint32_t hash = hash_ip(ip);
    
    pthread_mutex_lock(&tracker.locks[hash]);
    
    ip_entry_t *entry = tracker.buckets[hash];
    while (entry) {
        if (entry->ip == ip) {
            pthread_mutex_unlock(&tracker.locks[hash]);
            return entry;
        }
        entry = entry->next;
    }
    
    entry = (ip_entry_t *)calloc(1, sizeof(ip_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&tracker.locks[hash]);
        return NULL;
    }
    
    entry->ip = ip;
    entry->first_seen = time(NULL);
    entry->last_seen = entry->first_seen;
    entry->window_start = entry->first_seen;
    entry->next = tracker.buckets[hash];
    tracker.buckets[hash] = entry;
    tracker.tracked_ips++;
    
    pthread_mutex_unlock(&tracker.locks[hash]);
    return entry;
}

static void reset_window(ip_entry_t *entry, time_t now) {
    if (now - entry->window_start >= RATE_WINDOW) {
        entry->syn_count = 0;
        entry->conn_count = 0;
        entry->udp_count = 0;
        entry->window_start = now;
    }
}

static int check_and_update(ip_entry_t *entry, int is_syn, int is_udp, uint32_t bytes) {
    time_t now = time(NULL);
    
    reset_window(entry, now);
    
    entry->last_seen = now;
    entry->packet_count++;
    entry->byte_count += bytes;
    
    if (is_syn) {
        entry->syn_count++;
        if (entry->syn_count > SYN_THRESHOLD) {
            if (!entry->blocked) {
                entry->blocked = 1;
                tracker.blocked_ips++;
                
                struct in_addr addr;
                addr.s_addr = htonl(entry->ip);
                log_message("BLOCK", "SYN flood from %s (count: %u)", 
                           inet_ntoa(addr), entry->syn_count);
                
                char cmd[256];
                snprintf(cmd, sizeof(cmd), 
                        "ipset add fortress_block %s timeout 3600 -exist 2>/dev/null",
                        inet_ntoa(addr));
                system(cmd);
            }
            return 0;
        }
    }
    
    if (is_udp) {
        entry->udp_count++;
        if (entry->udp_count > UDP_THRESHOLD) {
            if (!entry->blocked) {
                entry->blocked = 1;
                tracker.blocked_ips++;
                
                struct in_addr addr;
                addr.s_addr = htonl(entry->ip);
                log_message("BLOCK", "UDP flood from %s (count: %u)", 
                           inet_ntoa(addr), entry->udp_count);
                
                char cmd[256];
                snprintf(cmd, sizeof(cmd), 
                        "ipset add fortress_block %s timeout 3600 -exist 2>/dev/null",
                        inet_ntoa(addr));
                system(cmd);
            }
            return 0;
        }
    }
    
    entry->conn_count++;
    if (entry->conn_count > CONN_THRESHOLD) {
        if (!entry->blocked) {
            entry->blocked = 1;
            tracker.blocked_ips++;
            
            struct in_addr addr;
            addr.s_addr = htonl(entry->ip);
            log_message("BLOCK", "Connection flood from %s (count: %u)", 
                       inet_ntoa(addr), entry->conn_count);
            
            char cmd[256];
            snprintf(cmd, sizeof(cmd), 
                    "ipset add fortress_block %s timeout 3600 -exist 2>/dev/null",
                    inet_ntoa(addr));
            system(cmd);
        }
        return 0;
    }
    
    return 1;
}

static int validate_tcp_flags(struct tcphdr *tcp) {
    uint8_t flags = 0;
    
    if (tcp->syn) flags |= 0x02;
    if (tcp->ack) flags |= 0x10;
    if (tcp->fin) flags |= 0x01;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;
    if (tcp->urg) flags |= 0x20;
    
    /* NULL scan */
    if (flags == 0) return 0;
    /* XMAS scan */
    if (flags == 0x3F) return 0;
    /* SYN+RST */
    if ((flags & 0x06) == 0x06) return 0;
    /* SYN+FIN */
    if ((flags & 0x03) == 0x03) return 0;
    /* RST+FIN */
    if ((flags & 0x05) == 0x05) return 0;
    /* FIN without ACK */
    if ((flags & 0x11) == 0x01) return 0;
    /* PSH without ACK */
    if ((flags & 0x18) == 0x08) return 0;
    /* URG without ACK */
    if ((flags & 0x30) == 0x20) return 0;
    
    return 1;
}

static int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                         struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;
    uint32_t id = 0;
    int verdict = NF_ACCEPT;
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    tracker.total_packets++;
    tracker.total_bytes += payload_len;
    
    struct iphdr *ip = (struct iphdr *)payload;
    
    if (ip->version != 4) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    uint32_t src_ip = ntohl(ip->saddr);
    
    if (is_whitelisted(src_ip)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    ip_entry_t *entry = get_or_create_entry(src_ip);
    if (!entry) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    if (entry->blocked) {
        tracker.dropped_packets++;
        tracker.dropped_bytes += payload_len;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    
    int is_syn = 0;
    int is_udp = 0;
    
    if (ip->protocol == IPPROTO_TCP) {
        int ip_hdr_len = ip->ihl * 4;
        if (payload_len >= ip_hdr_len + (int)sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr *)(payload + ip_hdr_len);
            
            if (!validate_tcp_flags(tcp)) {
                tracker.dropped_packets++;
                tracker.dropped_bytes += payload_len;
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            
            if (tcp->syn && !tcp->ack) {
                is_syn = 1;
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        is_udp = 1;
        
        int ip_hdr_len = ip->ihl * 4;
        if (payload_len >= ip_hdr_len + (int)sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr *)(payload + ip_hdr_len);
            uint16_t sport = ntohs(udp->source);
            
            /* Block amplification attack sources */
            if (sport == 123 || sport == 161 || sport == 1900 || 
                sport == 11211 || sport == 19 || sport == 17) {
                tracker.dropped_packets++;
                tracker.dropped_bytes += payload_len;
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            
            /* Block suspicious UDP sizes */
            int udp_len = payload_len - ip_hdr_len;
            if (udp_len < 28 || udp_len > 1400) {
                tracker.dropped_packets++;
                tracker.dropped_bytes += payload_len;
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
    } else if (ip->protocol == IPPROTO_ICMP) {
        /* Drop all ICMP during attack */
        tracker.dropped_packets++;
        tracker.dropped_bytes += payload_len;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    
    if (!check_and_update(entry, is_syn, is_udp, payload_len)) {
        tracker.dropped_packets++;
        tracker.dropped_bytes += payload_len;
        verdict = NF_DROP;
    }
    
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static void *cleanup_thread(void *arg) {
    while (running) {
        sleep(CLEANUP_INTERVAL);
        
        time_t now = time(NULL);
        time_t cutoff = now - 300;
        
        for (int i = 0; i < HASH_SIZE; i++) {
            pthread_mutex_lock(&tracker.locks[i]);
            
            ip_entry_t **pp = &tracker.buckets[i];
            while (*pp) {
                ip_entry_t *entry = *pp;
                
                if (entry->last_seen < cutoff && !entry->blocked) {
                    *pp = entry->next;
                    free(entry);
                    tracker.tracked_ips--;
                } else {
                    pp = &entry->next;
                }
            }
            
            pthread_mutex_unlock(&tracker.locks[i]);
        }
        
        log_message("INFO", "Cleanup: tracked=%u blocked=%u packets=%lu dropped=%lu",
                   tracker.tracked_ips, tracker.blocked_ips,
                   tracker.total_packets, tracker.dropped_packets);
    }
    
    return NULL;
}

static void signal_handler(int sig) {
    running = 0;
}

static void print_stats() {
    printf("\n=== Fortress Packet Filter Statistics ===\n");
    printf("Total Packets:   %lu\n", tracker.total_packets);
    printf("Total Bytes:     %lu\n", tracker.total_bytes);
    printf("Dropped Packets: %lu\n", tracker.dropped_packets);
    printf("Dropped Bytes:   %lu\n", tracker.dropped_bytes);
    printf("Tracked IPs:     %u\n", tracker.tracked_ips);
    printf("Blocked IPs:     %u\n", tracker.blocked_ips);
    printf("==========================================\n");
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    pthread_t cleanup_tid;
    
    log_file = fopen("/var/log/fortress/packet_filter.log", "a");
    if (!log_file) {
        log_file = stderr;
    }
    
    log_message("INFO", "Fortress Packet Filter starting...");
    
    for (int i = 0; i < HASH_SIZE; i++) {
        pthread_mutex_init(&tracker.locks[i], NULL);
    }
    
    add_whitelist("127.0.0.1");
    add_whitelist("78.165.141.159");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    h = nfq_open();
    if (!h) {
        log_message("ERROR", "Failed to open nfqueue handle");
        return 1;
    }
    
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        log_message("WARN", "Failed to unbind existing handler");
    }
    
    if (nfq_bind_pf(h, AF_INET) < 0) {
        log_message("ERROR", "Failed to bind nfqueue handler");
        nfq_close(h);
        return 1;
    }
    
    qh = nfq_create_queue(h, 0, &process_packet, NULL);
    if (!qh) {
        log_message("ERROR", "Failed to create queue");
        nfq_close(h);
        return 1;
    }
    
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_message("ERROR", "Failed to set packet copy mode");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }
    
    fd = nfq_fd(h);
    
    pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL);
    
    log_message("INFO", "Fortress Packet Filter running");
    printf("Fortress Packet Filter running (Ctrl+C to stop)\n");
    
    while (running) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else if (errno != EINTR) {
            log_message("ERROR", "recv failed: %s", strerror(errno));
            break;
        }
    }
    
    print_stats();
    
    pthread_join(cleanup_tid, NULL);
    
    nfq_destroy_queue(qh);
    nfq_close(h);
    
    if (log_file && log_file != stderr) {
        fclose(log_file);
    }
    
    log_message("INFO", "Fortress Packet Filter stopped");
    
    return 0;
}
