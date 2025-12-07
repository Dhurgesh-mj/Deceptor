#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define MAX_ETHER 1518
#define SIZE_ETHERNET 14

typedef unsigned char byte;

/* ---------------- Ethernet / IP / ICMP / TCP Headers ---------------- */
#pragma pack(push, 1)
struct eth_hdr {
    byte dst[6];
    byte src[6];
    uint16_t ethertype;
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
    uint16_t doff_res_flags;
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

/* ---------------- TCP checksum ---------------- */
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
    ph.tcp_length = htons(sizeof(struct tcp_hdr) + payload_len);

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

/* ---------------- FAKE IP AUTO ADD / REMOVE ---------------- */
static const char* g_iface = NULL;
static const char* g_ip = NULL;

void add_fake_ip_on_start(const char* iface, const char* ip) {
#ifdef __linux__
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "ip addr show dev %s | grep -q \"%s\" || ip addr add %s/32 dev %s",
        iface, ip, ip, iface);

    printf("[+] Adding fake IP: %s\n", cmd);
    system(cmd);

    g_iface = iface;
    g_ip = ip;
#endif
}

void remove_fake_ip_on_exit(void) {
#ifdef __linux__
    if (!g_iface || !g_ip) return;

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "ip addr del %s/32 dev %s",
        g_ip, g_iface);

    printf("\n[+] Removing fake IP: %s\n", cmd);
    system(cmd);
#endif
}

void sig_handler(int sig) {
    (void)sig;
    remove_fake_ip_on_exit();
    exit(0);
}

/* ---------------- Send Packet ---------------- */
static int send_frame_pcap(pcap_t* handle, const byte* frame, size_t len) {
    if (pcap_inject(handle, frame, len) == -1) {
        fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    printf("[+] Frame sent successfully (len=%zu)\n", len);
    return 0;
}

/* ---------------- Callback (UNCHANGED LOGIC) ---------------- */
static void pcap_callback(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    struct cb_ctx* ctx = (struct cb_ctx*)user;
    uint32_t dst_ip_nbo = ctx->dst_ip_nbo;

    if (hdr->caplen < SIZE_ETHERNET + sizeof(struct ip_hdr))
        return;

    int pktlen = (int)hdr->caplen;
    byte* copy = (byte*)malloc(pktlen);
    if (!copy) return;
    memcpy(copy, pkt, pktlen);

    struct eth_hdr* eth = (struct eth_hdr*)copy;
    if (ntohs(eth->ethertype) != 0x0800) {
        free(copy);
        return;
    }

    struct ip_hdr* ip = (struct ip_hdr*)(copy + SIZE_ETHERNET);
    int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
    int ip_total_len = ntohs(ip->tot_len);

    struct in_addr saddr = { ip->saddr };
    struct in_addr daddr = { ip->daddr };

    /* ---------------- ICMP  ---------------- */
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmp_hdr* icmp = (struct icmp_hdr*)(copy + SIZE_ETHERNET + ip_hdr_len);

        printf("Captured: %s -> %s, ICMP type=%u\n",
            inet_ntoa(saddr), inet_ntoa(daddr), icmp->type);

        if (icmp->type == 8 && ip->daddr == dst_ip_nbo) {
            byte tmp[6];
            memcpy(tmp, eth->src, 6);
            memcpy(eth->src, eth->dst, 6);
            memcpy(eth->dst, tmp, 6);

            uint32_t orig = ip->saddr;
            ip->saddr = dst_ip_nbo;
            ip->daddr = orig;

            ip->checksum = 0;
            ip->checksum = htons(inet_checksum_bytes(ip, ip_hdr_len));

            icmp->type = 0;
            icmp->checksum = 0;
            icmp->checksum = htons(inet_checksum_bytes(icmp, ip_total_len - ip_hdr_len));

            send_frame_pcap(ctx->handle, copy, SIZE_ETHERNET + ip_total_len);
        }
    }

    /* ---------------- TCP REPLY ---------------- */
    if (ip->protocol == IPPROTO_TCP && ip->daddr == dst_ip_nbo) {
        struct tcp_hdr* tcp = (struct tcp_hdr*)(copy + SIZE_ETHERNET + ip_hdr_len);
        printf("Captured TCP: %u -> %u\n",
       ntohs(tcp->source), ntohs(tcp->dest));
        uint16_t flags = ntohs(tcp->doff_res_flags);

        /* If SYN → reply*/
        if (flags & 0x002) {   // SYN flag

            /* Swap MAC */
            byte tmp[6];
            memcpy(tmp, eth->src, 6);
            memcpy(eth->src, eth->dst, 6);
            memcpy(eth->dst, tmp, 6);

            /* Swap IP */
            uint32_t orig = ip->saddr;
            ip->saddr = dst_ip_nbo;
            ip->daddr = orig;

            /* Swap TCP ports */
            uint16_t sport = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = sport;

            /* Build SYN-ACK */
            tcp->ack_seq = htonl(ntohl(tcp->seq) + 1);
            tcp->seq = htonl(rand());
            tcp->doff_res_flags = htons((5 << 12) | 0x12); // SYN + ACK
            tcp->window = htons(64240);
            tcp->urg_ptr = 0;

            tcp->check = 0;
            tcp->check = tcp_checksum(ip, tcp, NULL, 0);

            ip->checksum = 0;
            ip->checksum = htons(inet_checksum_bytes(ip, ip_hdr_len));

            send_frame_pcap(ctx->handle,
                copy, SIZE_ETHERNET + ip_hdr_len + sizeof(struct tcp_hdr));
        }
    }

    free(copy);
}
/* ---------------- MAIN ---------------- */
int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <dst-ip>\n", argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    const char* dst_ip_str = argv[2];
    //check if Linux [add ip to list] 
    add_fake_ip_on_start(iface, dst_ip_str);
    atexit(remove_fake_ip_on_exit);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    uint32_t dst_ip_nbo;
    inet_pton(AF_INET, dst_ip_str, &dst_ip_nbo);

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[256];

    pcap_t* handle = pcap_open_live(iface, MAX_ETHER, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    snprintf(filter_exp, sizeof(filter_exp), "icmp or (tcp and dst host %s)", dst_ip_str);

    pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    struct cb_ctx ctx;
    ctx.dst_ip_nbo = dst_ip_nbo;
    ctx.handle = handle;

    printf("[+] Listening on %s for ICMP & TCP to %s\n", iface, dst_ip_str);
    pcap_loop(handle, -1, pcap_callback, (u_char*)&ctx);

    pcap_close(handle);
    return 0;
}
