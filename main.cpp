#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iso646.h>
#include <errno.h>
#include <string>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

std::string http_methods[9] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
std::string filter_host_prefix = "Host: ";
std::string target_host;

static unsigned int extract_packet_id(struct nfq_data *data) {
    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(data);
    return header ? ntohl(header->packet_id) : 0;
}

static bool inspect_http_host(const unsigned char *pkt, int len) {
    if (len < (int)sizeof(libnet_ipv4_hdr)) return false;
    const libnet_ipv4_hdr *ip_hdr = reinterpret_cast<const libnet_ipv4_hdr*>(pkt);
    if (ip_hdr->ip_p != IPPROTO_TCP) return false;
    int ip_hl = ip_hdr->ip_hl * 4;
    if (ip_hl < 20 || len < ip_hl + (int)sizeof(libnet_tcp_hdr)) return false;
    const libnet_tcp_hdr *tcp_hdr = reinterpret_cast<const libnet_tcp_hdr*>(pkt + ip_hl);
    int tcp_hl = tcp_hdr->th_off * 4;
    if (tcp_hl < 20 || len < ip_hl + tcp_hl) return false;
    uint16_t sport = ntohs(tcp_hdr->th_sport);
    uint16_t dport = ntohs(tcp_hdr->th_dport);
    if (sport != 80 and dport != 80) return false;

    const char *payload = reinterpret_cast<const char*>(pkt + ip_hl + tcp_hl);
    int payload_len = len - (ip_hl + tcp_hl);
    if (payload_len <= 0) return false;

    bool is_http = false;
    for (const auto &m : http_methods) {
        if (payload_len >= (int)m.size() && memcmp(payload, m.c_str(), m.size()) == 0) {
            is_http = true; break;
        }
    }
    if (!is_http) return false;

    int header_len = payload_len;
    for (int i = 0; i + 3 < payload_len; ++i) {
        if (payload[i] == '\r' && payload[i+1] == '\n' && payload[i+2] == '\r' && payload[i+3] == '\n') {
            header_len = i + 2; break;
        }
    }

    const int pref_len = (int)filter_host_prefix.size();
    const int host_len = (int)target_host.size();
    for (int i = 0; i + pref_len + host_len <= header_len; ++i) {
        if (memcmp(payload + i, filter_host_prefix.c_str(), pref_len) == 0) {
            const char *host_start = payload + i + pref_len;
            if (memcmp(host_start, target_host.c_str(), host_len) == 0) {
                char next = (i + pref_len + host_len < header_len) ? host_start[host_len] : '\r';
                if (next == '\r' || next == '\n' || next == ':') return true;
            }
        }
    }
    return false;
}

static int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, void *) {
    unsigned char *pkt = nullptr;
    unsigned int id = extract_packet_id(nfa);
    int len = nfq_get_payload(nfa, &pkt);
    if (len > 0 && pkt && inspect_http_host(pkt, len)) return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("syntax : netfilter-test <host>\n");
        printf("sample : netfilter-test test.gilgil.net\n");
        return 1;
    }
    target_host = argv[1];

    struct nfq_handle *handle = nfq_open();
    if (!handle) { perror("nfq_open failed"); return 1; }
    nfq_unbind_pf(handle, AF_INET);
    if (nfq_bind_pf(handle, AF_INET) < 0) { perror("nfq_bind_pf failed"); return 1; }
    struct nfq_q_handle *qhandle = nfq_create_queue(handle, 0, &process_packet, nullptr);
    if (!qhandle) { perror("nfq_create_queue failed"); return 1; }
    if (nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) < 0) { perror("nfq_set_mode failed"); return 1; }

    int fd = nfq_fd(handle);
    alignas(4096) char buf[1 << 16];
    while (true) {
        int len = recv(fd, buf, sizeof(buf), 0);
        if (len >= 0) { nfq_handle_packet(handle, buf, len); continue; }
        if (errno == ENOBUFS) { fprintf(stderr, "packet loss detected\n"); continue; }
        perror("recv failed"); break;
    }
    nfq_destroy_queue(qhandle);
    nfq_close(handle);
    return 0;
}

