#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

#define BUFFER_SIZE 65535

void parse_dns_name(unsigned char *buffer, char *output) {
    int pos = 12;
    int j = 0;

    while (buffer[pos] != 0) {
        int len = buffer[pos++];
        for (int i = 0; i < len; i++) {
            output[j++] = buffer[pos++];
        }
        output[j++] = '.';
    }

    output[j - 1] = '\0';
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    int sock;
    struct sockaddr_in addr, sender;
    socklen_t sender_len = sizeof(sender);
    unsigned char buffer[BUFFER_SIZE];

    FILE *logFile = fopen("dns_log.txt", "w");

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    printf("[+] DNS Sniffer running...\n");

    while (1) {
        int bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                             (struct sockaddr*)&sender, &sender_len);

        if (bytes > 0) {
            char domain[256] = {0};
            parse_dns_name(buffer, domain);

            fprintf(logFile, "DNS Query: %s\n", domain);
            fflush(logFile);

            printf("DNS Query: %s\n", domain);
        }
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    fclose(logFile);
    return 0;
}