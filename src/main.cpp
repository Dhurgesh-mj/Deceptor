#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define MAX_ETHER 1518
#define SIZE_ETHERNET 14

typedef unsigned char byte;

/* ---------------- Ethernet / IP / ICMP / TCP Headers ---------------- */
#pragma pack(push, 1)
struct eth_hdr {
    byte dst[6];
    byte src[6];
    uint16_t ethertype; /* 0x0800 for IPv4 */
};

struct ip_hdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t doff_res_flags; /* data offset, reserved, flags */
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

/* ---------------- Internet Checksum ---------------- */
static uint16_t inet_checksum_bytes(const void* vbuf, size_t len) {
    const uint8_t* buf = (const uint8_t*)vbuf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)buf[0] << 8) | buf[1];
        buf += 2;
        len -= 2;
    }

    if (len == 1)
        sum += ((uint16_t)buf[0] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ---------------- TCP checksum (with IPv4 pseudo-header) ---------------- */
struct pseudo_hdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

static uint16_t tcp_checksum(const struct ip_hdr* ip, const struct tcp_hdr* tcp, const uint8_t* payload, size_t payload_len) {
    struct pseudo_hdr ph;
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.zero = 0;
    ph.protocol = ip->protocol;
    uint16_t tcp_len = htons((uint16_t)(sizeof(struct tcp_hdr) + payload_len));
    ph.tcp_length = tcp_len;

    size_t buf_len = sizeof(ph) + sizeof(struct tcp_hdr) + payload_len;
    uint8_t* buf = (byte*)malloc(buf_len);
    if (!buf) return 0;

    uint8_t* p = buf;
    memcpy(p, &ph, sizeof(ph)); p += sizeof(ph);
    memcpy(p, tcp, sizeof(struct tcp_hdr)); p += sizeof(struct tcp_hdr);
    if (payload_len && payload)
        memcpy(p, payload, payload_len);

    uint16_t ch = inet_checksum_bytes(buf, buf_len);
    free(buf);
    return ch;
}

/* ---------------- Context ---------------- */
struct cb_ctx {
    uint32_t dst_ip_nbo;
    pcap_t* handle;
};

/* ---------------- Send Packet using pcap_inject() ---------------- */
static int send_frame_pcap(pcap_t* handle, const byte* frame, size_t len) {
    if (pcap_inject(handle, frame, len) == -1) {
        fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    printf("[+] Frame sent successfully (len=%zu)\n", len);
    return 0;
}

/* ---------------- Callback ---------------- */
static void pcap_callback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    struct cb_ctx* ctx = (struct cb_ctx*)user;
    uint32_t dst_ip_nbo = ctx->dst_ip_nbo;

    if (hdr->caplen < SIZE_ETHERNET + sizeof(struct ip_hdr))
        return;

    int pktlen = (int)hdr->caplen;
    byte* copy = (byte *)malloc(pktlen);
    if (!copy)
        return;
    memcpy(copy, pkt, pktlen);

    struct eth_hdr* eth = (struct eth_hdr*)copy;
    if (ntohs(eth->ethertype) != 0x0800) {
        free(copy);
        return;
    }

    struct ip_hdr* ip = (struct ip_hdr*)(copy + SIZE_ETHERNET);
    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl = ip->ver_ihl & 0x0F;

    if (version != 4 || ihl < 5) {
        free(copy);
        return;
    }

    int ip_hdr_len = ihl * 4;
    int ip_total_len = ntohs(ip->tot_len);

    if (SIZE_ETHERNET + ip_total_len > pktlen) {
        free(copy);
        return;
    }

    struct in_addr saddr = {ip->saddr};
    struct in_addr daddr = {ip->daddr};
    if (ip->protocol == IPPROTO_ICMP) {
        if (SIZE_ETHERNET + ip_hdr_len + sizeof(struct icmp_hdr) > pktlen) {
            free(copy);
            return;
        }
        struct icmp_hdr* icmp = (struct icmp_hdr*)(copy + SIZE_ETHERNET + ip_hdr_len);
        printf("Captured: %s -> %s, ICMP type=%u code=%u\n",
               inet_ntoa(saddr), inet_ntoa(daddr),
               icmp->type, icmp->code);

        /* If Echo Request to our destination IP */
        if (icmp->type == 8 && icmp->code == 0 && ip->daddr == dst_ip_nbo) {
            printf("[+] ICMP echo-request for %s detected — forging reply\n", inet_ntoa(daddr));

            /* Swap MACs */
            byte tmp_mac[6];
            memcpy(tmp_mac, eth->src, 6);
            memcpy(eth->src, eth->dst, 6);
            memcpy(eth->dst, tmp_mac, 6);

            /* Swap IPs */
            uint32_t orig_saddr = ip->saddr;
            ip->daddr = orig_saddr;
            ip->saddr = dst_ip_nbo;

            /* Recompute IP checksum */
            ip->checksum = 0;
            ip->checksum = htons(inet_checksum_bytes(ip, ip_hdr_len));

            /* Make ICMP reply */
            int icmp_len = ip_total_len - ip_hdr_len;
            if (icmp_len >= (int)sizeof(struct icmp_hdr)) {
                icmp->type = 0; /* Echo Reply */
                icmp->checksum = 0;
                icmp->checksum = htons(inet_checksum_bytes(icmp, icmp_len));

                size_t frame_len = SIZE_ETHERNET + ip_total_len;
                send_frame_pcap(ctx->handle, copy, frame_len);
            }
            free(copy);
            return;
        }
        free(copy);
        return;
    }

    /* TCP SYN scan handling: If incoming TCP SYN to our dst IP, send SYN-ACK to mark port open */
    if (ip->protocol == IPPROTO_TCP && ip->daddr == dst_ip_nbo) {
        /* Ensure there's at least a TCP header in packet */
        if (SIZE_ETHERNET + ip_hdr_len + sizeof(struct tcp_hdr) > pktlen) {
            free(copy);
            return;
        }

        struct tcp_hdr* tcp = (struct tcp_hdr*)(copy + SIZE_ETHERNET + ip_hdr_len);
        uint16_t tcp_flags = ntohs(tcp->doff_res_flags) & 0x01FF; /* keep lowest 9 bits (flags) */
        uint8_t tcp_doff = (ntohs(tcp->doff_res_flags) >> 12) & 0x0F;
        int tcp_hdr_len = tcp_doff * 4;
        int orig_tcp_len = ip_total_len - ip_hdr_len;
        if (orig_tcp_len < 20) {
            free(copy);
            return;
        }

        int is_syn = (tcp_flags & 0x0002) != 0;
        int is_ack = (tcp_flags & 0x0010) != 0; /* ACK flag is 0x10 in standard map */

        printf("Captured TCP: %s:%u -> %s:%u flags=0x%x\n",
               inet_ntoa(saddr), ntohs(tcp->source),
               inet_ntoa(daddr), ntohs(tcp->dest),
               tcp_flags);

        /* If SYN and not ACK -> likely a SYN scan / connection attempt */
        if (is_syn && !is_ack) {
            printf("[+] TCP SYN to %s detected on port %u — forging SYN-ACK (open)\n",
                   inet_ntoa(daddr), ntohs(tcp->dest));

            /* We'll craft a SYN-ACK reply */
            /* Swap MACs */
            byte tmp_mac[6];
            memcpy(tmp_mac, eth->src, 6);
            memcpy(eth->src, eth->dst, 6);
            memcpy(eth->dst, tmp_mac, 6);

            /* Swap IPs */
            uint32_t orig_saddr = ip->saddr;
            ip->daddr = orig_saddr;
            ip->saddr = dst_ip_nbo;

            /* Build TCP reply in place of existing TCP header */
            struct tcp_hdr reply_tcp;
            memset(&reply_tcp, 0, sizeof(reply_tcp));
            reply_tcp.source = tcp->dest; /* src port = dst port of original (network order preserved) */
            reply_tcp.dest = tcp->source; /* dst port = src port of original */

            /* Set seq (random) and ack = orig_seq + 1 */
            uint32_t orig_seq = ntohl(tcp->seq);
            srand((unsigned)time(NULL) ^ (uint32_t)orig_seq);
            uint32_t our_seq = (uint32_t)rand();
            reply_tcp.seq = htonl(our_seq);
            reply_tcp.ack_seq = htonl(orig_seq + 1);

            /* data offset = 5 (20 bytes), flags = SYN|ACK (0x12), window = 65535 */
            uint16_t doff_flags = (5 << 12) | 0x12; /* data offset in high 4 bits, flags low bits */
            reply_tcp.doff_res_flags = htons(doff_flags);
            reply_tcp.window = htons(65535);
            reply_tcp.check = 0;
            reply_tcp.urg_ptr = 0;

            /* Place reply TCP into packet buffer (overwrite original tcp header) */
            /* We'll send a smaller IP total length (no options, no payload) */
            int reply_tcp_len = sizeof(struct tcp_hdr);
            int reply_ip_total_len = ip_hdr_len + reply_tcp_len;

            /* Copy reply TCP header into buffer location where original TCP header starts */
            memcpy(copy + SIZE_ETHERNET + ip_hdr_len, &reply_tcp, sizeof(struct tcp_hdr));

            /* Recompute TCP checksum: note pseudo-header uses ip.saddr/ip.daddr (already swapped above) */
            struct ip_hdr* ip_reply = (struct ip_hdr*)(copy + SIZE_ETHERNET);
            ip_reply->protocol = IPPROTO_TCP;
            ip_reply->ttl = 64;
            ip_reply->tot_len = htons((uint16_t)reply_ip_total_len);
            ip_reply->checksum = 0;
            ip_reply->checksum = htons(inet_checksum_bytes(ip_reply, ip_hdr_len));

            /* TCP checksum requires pseudo-header with new src/dst (we already set ip_reply->saddr/daddr above) */
            struct tcp_hdr* tcp_in_buffer = (struct tcp_hdr*)(copy + SIZE_ETHERNET + ip_hdr_len);
            tcp_in_buffer->check = 0;
            uint16_t tcp_ch = tcp_checksum(ip_reply, tcp_in_buffer, NULL, 0);
            tcp_in_buffer->check = htons(tcp_ch);

            size_t frame_len = SIZE_ETHERNET + reply_ip_total_len;
            send_frame_pcap(ctx->handle, copy, frame_len);

            free(copy);
            return;
        }
    }

    free(copy);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <dst-ip>\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    const char* dst_ip_str = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[256];
    uint32_t dst_ip_nbo;
    if (inet_pton(AF_INET, dst_ip_str, &dst_ip_nbo) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", dst_ip_str);
        return 1;
    }

    /* Open pcap handle for both capture & inject */
    pcap_t* handle = pcap_open_live(iface, MAX_ETHER, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }
    snprintf(filter_exp, sizeof(filter_exp), "icmp or (tcp and dst host %s)", dst_ip_str);

    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error compiling/setting filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    /* Prepare context */
    struct cb_ctx ctx;
    ctx.dst_ip_nbo = dst_ip_nbo;
    ctx.handle = handle;

    printf("[+] Listening on %s for ICMP echo requests and TCP SYNs to %s\n", iface, dst_ip_str);
    pcap_loop(handle, -1, pcap_callback, (u_char*)&ctx);

    pcap_close(handle);
    return 0;
}