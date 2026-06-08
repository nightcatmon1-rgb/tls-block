#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define proto_tcp 6
#define proto_raw 255
#define hdr_incl 3

#define tcp_rst 0x04
#define tcp_ack 0x10

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ip_hdr {
    uint8_t  v_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t off;
    uint8_t  ttl;
    uint8_t  p;
    uint16_t sum;
    uint32_t src;
    uint32_t dst;
};

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_res;
    uint8_t  flags;
    uint16_t win;
    uint16_t sum;
    uint16_t urp;
};
#pragma pack(pop)

char* target_server_name;

void usage(void) {
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

uint16_t calc_sum(uint16_t* p, int n) {
    uint32_t s = 0;
    while (n > 1) {
        s += *p++;
        n -= 2;
    }
    if (n == 1) {
        s += *(uint8_t*)p;
    }
    while (s >> 16) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return (uint16_t)(~s);
}

uint16_t make_tcp_sum(struct ip_hdr* i, struct tcp_hdr* t, uint8_t* d, int l) {
    struct fake_hdr {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } h;

    int tl = sizeof(struct tcp_hdr) + l;
    int sz = sizeof(struct fake_hdr) + tl;
    uint8_t* buf = (uint8_t*)malloc(sz);

    h.src = i->src;
    h.dst = i->dst;
    h.zero = 0;
    h.proto = proto_tcp;
    h.tcp_len = htons(tl);

    memcpy(buf, &h, sizeof(h));
    memcpy(buf + sizeof(h), t, sizeof(struct tcp_hdr));
    if (l > 0) {
        memcpy(buf + sizeof(h) + sizeof(struct tcp_hdr), d, l);
    }

    uint16_t r = calc_sum((uint16_t*)buf, sz);
    free(buf);
    return r;
}

void send_forward_rst(pcap_t* h, struct eth_hdr* e, struct ip_hdr* i, struct tcp_hdr* t, int payload_len) {
    uint8_t buf[1500];
    memset(buf, 0, sizeof(buf));

    struct eth_hdr* ne = (struct eth_hdr*)buf;
    struct ip_hdr* ni = (struct ip_hdr*)(buf + sizeof(struct eth_hdr));
    struct tcp_hdr* nt = (struct tcp_hdr*)(buf + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

    memcpy(ne->dmac, e->dmac, 6);
    memcpy(ne->smac, e->smac, 6);
    ne->type = e->type;

    ni->v_ihl = 0x45;
    ni->tos = 0;
    ni->len = htons(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
    ni->id = 0;
    ni->off = 0;
    ni->ttl = 128;
    ni->p = proto_tcp;
    ni->src = i->src;
    ni->dst = i->dst;
    ni->sum = 0;
    ni->sum = calc_sum((uint16_t*)ni, sizeof(struct ip_hdr));

    nt->sport = t->sport;
    nt->dport = t->dport;
    nt->seq = htonl(ntohl(t->seq) + payload_len);
    nt->ack = t->ack;
    nt->off_res = (5 << 4);
    nt->flags = tcp_rst | tcp_ack;
    nt->win = 0;
    nt->urp = 0;
    nt->sum = 0;
    nt->sum = make_tcp_sum(ni, nt, NULL, 0);

    pcap_sendpacket(h, buf, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
}

void send_backward_rst(struct ip_hdr* i, struct tcp_hdr* t, int payload_len) {
    int s = socket(AF_INET, SOCK_RAW, proto_raw);
    if (s < 0) return;

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, hdr_incl, &one, sizeof(one)) < 0) {
        close(s);
        return;
    }

    uint8_t buf[1500];
    memset(buf, 0, sizeof(buf));

    struct ip_hdr* ni = (struct ip_hdr*)buf;
    struct tcp_hdr* nt = (struct tcp_hdr*)(buf + sizeof(struct ip_hdr));

    ni->v_ihl = 0x45;
    ni->tos = 0;
    ni->len = htons(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
    ni->id = 0;
    ni->off = 0;
    ni->ttl = 128;
    ni->p = proto_tcp;
    
    ni->src = i->dst;
    ni->dst = i->src;
    ni->sum = 0;
    ni->sum = calc_sum((uint16_t*)ni, sizeof(struct ip_hdr));

    nt->sport = t->dport;
    nt->dport = t->sport;
    nt->seq = t->ack;
    nt->ack = htonl(ntohl(t->seq) + payload_len);
    nt->off_res = (5 << 4);
    nt->flags = tcp_rst | tcp_ack;
    nt->win = 0;
    nt->urp = 0;
    nt->sum = 0;
    nt->sum = make_tcp_sum(ni, nt, NULL, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ni->dst;

    sendto(s, buf, sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), 0, (struct sockaddr*)&addr, sizeof(addr));
    close(s);
}

int parse_tls_sni(uint8_t* data, int len) {
    if (len < 5) return 0;

    if (data[0] != 0x16) return 0;
    if (len < 6 || data[5] != 0x01) return 0;

    int idx = 5 + 4;
    idx += 2 + 32; 
    if (idx >= len) return 0;

    uint8_t session_id_len = data[idx];
    idx += 1 + session_id_len;
    if (idx >= len) return 0;

    if (idx + 2 > len) return 0;
    uint16_t cipher_len = ntohs(*(uint16_t*)(data + idx));
    idx += 2 + cipher_len;
    if (idx >= len) return 0;

    if (idx + 1 > len) return 0;
    uint8_t comp_len = data[idx];
    idx += 1 + comp_len;
    if (idx >= len) return 0;

    if (idx + 2 > len) return 0;
    uint16_t ext_total_len = ntohs(*(uint16_t*)(data + idx));
    idx += 2;

    int ext_end = idx + ext_total_len;
    if (ext_end > len) ext_end = len;

    while (idx + 4 <= ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t*)(data + idx));
        uint16_t ext_len = ntohs(*(uint16_t*)(data + idx + 2));
        idx += 4;

        if (idx + ext_len > ext_end) break;

        if (ext_type == 0x0000) {
            int sni_idx = idx;
            if (sni_idx + 2 > ext_end) break;
            
            sni_idx += 2; 
            if (sni_idx + 3 > ext_end) break;

            uint8_t name_type = data[sni_idx];
            uint16_t name_len = ntohs(*(uint16_t*)(data + sni_idx + 1));
            sni_idx += 3;

            if (name_type == 0x00 && sni_idx + name_len <= ext_end) {
                char* sni_name = (char*)malloc(name_len + 1);
                memcpy(sni_name, data + sni_idx, name_len);
                sni_name[name_len] = '\0';

                if (strstr(sni_name, target_server_name) != NULL) {
                    printf("[Blocked] SNI Detected: %s\n", sni_name);
                    free(sni_name);
                    return 1;
                }
                free(sni_name);
            }
        }
        idx += ext_len;
    }

    return 0;
}

void packet_handler(uint8_t* param, const struct pcap_pkthdr* header, const uint8_t* pkt) {
    pcap_t* ph = (pcap_t*)param;
    struct eth_hdr* e = (struct eth_hdr*)pkt;

    if (ntohs(e->type) != 0x0800) return;

    struct ip_hdr* i = (struct ip_hdr*)(pkt + sizeof(struct eth_hdr));
    if (i->p != proto_tcp) return;

    int ip_hdr_len = (i->v_ihl & 0x0F) * 4;
    struct tcp_hdr* t = (struct tcp_hdr*)((uint8_t*)i + ip_hdr_len);
    int tcp_hdr_len = ((t->off_res & 0xF0) >> 4) * 4;

    uint8_t* payload = (uint8_t*)t + tcp_hdr_len;
    int payload_len = ntohs(i->len) - ip_hdr_len - tcp_hdr_len;

    if (payload_len <= 0) return;

    if (parse_tls_sni(payload, payload_len)) {
        send_forward_rst(ph, e, i, t, payload_len);
        send_backward_rst(i, t, payload_len);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    target_server_name = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* h = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (h == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    printf("SNI Block Monitoring Start... (Target: %s)\n", target_server_name);
    pcap_loop(h, 0, packet_handler, (uint8_t*)h);

    pcap_close(h);
    return 0;
}
