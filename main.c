#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

unsigned short checksum(void *data, int len)
{
    unsigned int sum = 0;
    unsigned short *ptr = data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(unsigned char *)ptr;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
};

int main(void)
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    int ifindex = if_nametoindex("eth0"); // set to your nic name unless it is eth0 by standard
    if (ifindex == 0) {
        perror("if_nametoindex");
        exit(1);
    }

    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));

    device.sll_family   = AF_PACKET;
    device.sll_ifindex  = ifindex;
    device.sll_halen    = ETH_ALEN;
    
    // Destination address MAC of target dvc
    unsigned char dst_mac[6] = {
        0xd8, 0x43, 0xae, 0x96, 0xe5, 0x9f
    };

    // Source address MAC of sending dvc
    unsigned char src_mac[6] = {
        0x88, 0xa2, 0x9e, 0x4b, 0x63, 0x08
    };

    memcpy(device.sll_addr, dst_mac, 6);

    unsigned char packet[1500];
    memset(packet, 0, sizeof(packet));

    struct ether_header *eth = (struct ether_header *)packet;

    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));

    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id       = htons(0x1337);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr    = inet_addr("192.168.178.29"); // set to source ip ALWAYS IPv4!
    ip->daddr    = inet_addr("192.168.178.97"); // set to target ip ALWAYS IPv4!
    ip->check    = checksum(ip, sizeof(struct iphdr));

    struct tcphdr *tcp = (struct tcphdr *)(
        packet + sizeof(struct ether_header) + sizeof(struct iphdr)
    );

    tcp->source  = htons(44444);
    tcp->dest    = htons(80);
    tcp->seq     = htonl(0xdeadbeef);
    tcp->ack_seq = 0;
    tcp->doff    = 5;
    tcp->syn     = 1;
    tcp->window  = htons(64240);
    tcp->check   = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header psh;
    psh.src     = ip->saddr;
    psh.dst     = ip->daddr;
    psh.zero    = 0;
    psh.proto   = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    unsigned char pseudo_packet[
        sizeof(struct pseudo_header) + sizeof(struct tcphdr)
    ];

    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));

    tcp->check = checksum(pseudo_packet, sizeof(pseudo_packet));

    int frame_len =
        sizeof(struct ether_header) +
        sizeof(struct iphdr) +
        sizeof(struct tcphdr);

    if (sendto(sock, packet, frame_len, 0,
               (struct sockaddr *)&device, sizeof(device)) < 0) {
        perror("sendto");
    } else {
        printf("Raw SYN frame sent successfully\n");
    }

    close(sock);
    return 0;
}
