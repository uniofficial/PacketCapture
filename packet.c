#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// Ethernet \ud5e4\ub354
struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short type;
};

// IP \ud5e4\ub354
struct ip_header {
    u_char version_ihl; // \ubc84\uc804(4\ube44\ud2b8) + IHL(4\ube44\ud2b8)
    u_char tos;
    u_short total_length;
    u_short id;
    u_short fragment_offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    struct in_addr src_ip;
    struct in_addr dest_ip;
};

// UDP \ud5e4\ub354
struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short length;
    u_short checksum;
};

// TCP \ud5e4\ub354
struct tcp_header {
    u_short src_port;
u_short dest_port;
    u_int seq_num;
    u_int ack_num;
    u_char data_offset;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
};

// ICMP \ud5e4\ub354
struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;
};

// DNS \ud5e4\ub354
struct dns_header {
    u_short id;
    u_short flags;
    u_short q_count;
    u_short ans_count;
    u_short auth_count;
    u_short add_count;
};

// \ud328\ud0b7 \ubd84\uc11d \ud568\uc218
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethernet_header *eth = (struct ethernet_header *)packet;
    struct ip_header *ip = (struct ip_header *)(packet + 14);

    printf("\n[Packet Captured]\n");
    printf("Source IP: %s\n", inet_ntoa(ip->src_ip));
    printf("Destination IP: %s\n", inet_ntoa(ip->dest_ip));
    printf("Protocol: %d\n", ip->protocol);
    // UDP \ud504\ub85c\ud1a0\ucf5c \ubd84\uc11d
    if (ip->protocol == 17) { // UDP
        struct udp_header *udp = (struct udp_header *)(packet + 14 + ((ip->version_ihl & 0x0F) * 4));
        printf("[UDP Packet]\n");
        printf("Source Port: %d\n", ntohs(udp->src_port));
        printf("Destination Port: %d\n", ntohs(udp->dest_port));
        
        // DNS \ud504\ub85c\ud1a0\ucf5c \ubd84\uc11d
        if (ntohs(udp->dest_port) == 53 || ntohs(udp->src_port) == 53) {
            struct dns_header *dns = (struct dns_header *)(packet + 14 + ((ip->version_ihl & 0x0F) * 4) + 8);
            printf("[DNS Packet]\n");
            printf("Transaction ID: 0x%x\n", ntohs(dns->id));
            printf("Questions: %d\n", ntohs(dns->q_count));
            printf("Answers: %d\n", ntohs(dns->ans_count));
        }
    }

    // TCP \ud504\ub85c\ud1a0\ucf5c \ubd84\uc11d
    else if (ip->protocol == 6) { // TCP
        struct tcp_header *tcp = (struct tcp_header *)(packet + 14 + ((ip->version_ihl & 0x0F) * 4));
        u_char *payload = (u_char *)(packet + 14 + ((ip->version_ihl & 0x0F) * 4) + ((tcp->data_offset >> 4) * 4));
        printf("[TCP Packet]\n");
        printf("Source Port: %d\n", ntohs(tcp->src_port));
        printf("Destination Port: %d\n", ntohs(tcp->dest_port));
        printf("Sequence Number: %u\n", ntohl(tcp->seq_num));
        printf("Acknowledgment Number: %u\n", ntohl(tcp->ack_num));

        // HTTP \ud504\ub85c\ud1a0\ucf5c \ubd84\uc11d
        if (strncmp((char *)payload, "GET", 3) == 0 || strncmp((char *)payload, "POST", 4) == 0) {
            printf("[HTTP Packet]\n");
            printf("HTTP Request: %s\n", payload);
        }
        if (strncmp((char *)payload, "HTTP/", 5) == 0) {
        printf("[HTTP Response Packet]\n");
        printf("HTTP Response: %s\n", payload);
    }
    }
// ICMP \ud504\ub85c\ud1a0\ucf5c \ubd84\uc11d
    else if (ip->protocol == 1) { // ICMP
        int ip_header_length = (ip->version_ihl & 0x0F) * 4; // IHL \uac12 \uacc4\uc0b0
        struct icmp_header *icmp = (struct icmp_header *)(packet + 14 + ip_header_length);

        printf("[ICMP Packet]\n");
        printf("Type: %d\n", icmp->type);
        printf("Code: %d\n", icmp->code);
        printf("Identifier: %d\n", ntohs(icmp->id));
        printf("Sequence Number: %d\n", ntohs(icmp->seq));
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "icmp or tcp or udp";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // \ub124\ud2b8\uc6cc\ud06c \uc7a5\uce58 \uc120\ud0dd
    pcap_if_t *alldevs, *d;
    int i = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No devices found.\n");
        return EXIT_FAILURE;
    }

    // \uc7a5\uce58 \ubaa9\ub85d \ucd9c\ub825
    printf("Available devices:\n");
    for (d = alldevs; d != NULL; d = d->next) {
	printf("%d: %s - %s\n", ++i, d->name, d->description ? d->description : "No description available");
    }

    printf("Enter the number of the device to capture: ");
    int dev_num;
    scanf("%d", &dev_num);

    if (dev_num < 1 || dev_num > i) {
        fprintf(stderr, "Invalid device number.\n");
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // \uc120\ud0dd\ud55c \uc7a5\uce58\ub85c \uc774\ub3d9
    d = alldevs;
    for (i = 1; i < dev_num; i++) {
        d = d->next;
    }

    // \ub124\ud2b8\uc6cc\ud06c \uc815\ubcf4 \uac00\uc838\uc624\uae30
    if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", d->name, errbuf);
        net = 0;
        mask = 0;
    }

    // \ucea1\ucc98 \ud578\ub4e4\ub7ec \ucd08\uae30\ud654
    printf("Capturing on device: %s\n", d->name);
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // \ud544\ud130 \uc124\uc815
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	pcap_close(handle);
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // \uc7a5\uce58 \ubaa9\ub85d \ud574\uc81c
    pcap_freealldevs(alldevs);

    // \ud328\ud0b7 \ucea1\ucc98 \uc2dc\uc791
    printf("Starting packet capture\u2026\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    // \ucea1\ucc98 \uc885\ub8cc
    pcap_close(handle);
    printf("Packet capture complete. Exiting.\n");

    return EXIT_SUCCESS;
}
