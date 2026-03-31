#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <pcap.h>
#else
    #include <arpa/inet.h>
    #include <pcap.h>
#endif

#define DNS_PORT 53

FILE *logFile;

/* Extract DNS name safely (no OS structs required) */
void parse_dns_name(const unsigned char *dns, char *output) {
    int pos = 12;
    int j = 0;

    while (dns[pos] != 0 && pos < 255) {
        int len = dns[pos++];

        if (len == 0 || len > 63) break;

        for (int i = 0; i < len; i++) {
            output[j++] = dns[pos++];
        }
        output[j++] = '.';
    }

    if (j > 0) output[j - 1] = '\0';
}

/* Extract IPv4 addresses manually from Ethernet frame */
void extract_ips(const unsigned char *packet, char *src_ip, char *dst_ip) {
    const unsigned char *ip = packet + 14;

    sprintf(src_ip, "%u.%u.%u.%u",
        ip[12], ip[13], ip[14], ip[15]);

    sprintf(dst_ip, "%u.%u.%u.%u",
        ip[16], ip[17], ip[18], ip[19]);
}

void packet_handler(unsigned char *args,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet) {

    // Minimum Ethernet + IP header sanity check
    if (header->caplen < 14 + 20) {
        return;
    }

    const unsigned char *ip = packet + 14;

    // Ensure IPv4 only
    int version = ip[0] >> 4;
    if (version != 4) {
        return;
    }

    // Ensure UDP only
    int protocol = ip[9];
    if (protocol != 17) {
        return;
    }

    int ip_header_len = (ip[0] & 0x0F) * 4;

    // Additional safety check
    if (header->caplen < 14 + ip_header_len + 8) {
        return;
    }

    const unsigned char *udp = packet + 14 + ip_header_len;

    int udp_len = 8;
    const unsigned char *dns = udp + udp_len;

    // Basic DNS sanity check (avoid garbage parsing)
    if (dns + 12 > packet + header->caplen) {
        return;
    }

    char domain[256] = {0};
    char src[32] = {0};
    char dst[32] = {0};

    extract_ips(packet, src, dst);

    parse_dns_name(dns, domain);

    time_t now = time(NULL);

    fprintf(logFile,
        "[%lld] %s -> %s | %s\n",
        (long long)now,
        src,
        dst,
        domain);

    fflush(logFile);

    printf("DNS: %s -> %s\n", src, domain);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    logFile = fopen("dns_log.txt", "w");

    if (!logFile) {
        printf("Failed to open log file\n");
        return 1;
    }

    pcap_t *handle;

#ifdef _WIN32
    handle = pcap_open_live("\\Device\\NPF_Loopback", 65536, 1, 1000, errbuf);
#else
    handle = pcap_open_live("any", 65536, 1, 1000, errbuf);
#endif

    if (!handle) {
        printf("pcap error: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "udp port 53", 0, 0);
    pcap_setfilter(handle, &fp);

    printf("[+] DNS sniffer running...\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    fclose(logFile);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}