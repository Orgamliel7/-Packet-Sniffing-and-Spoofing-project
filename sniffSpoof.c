#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <unistd.h>

#define ETHER_ADDR_LEN 6

struct ipheader {
    unsigned char iph_ihl:4, // IP header length
    iph_ver:4; // IP version
    unsigned char iph_tos;   // type of service
    unsigned short int iph_len; // IP packet length ( data + header )
    unsigned short int iph_ident; // identifier
    unsigned short int iph_flag:3, // fragmentation flag
    iph_offset: 13; // flag offset
    unsigned char iph_ttl; // tome to live
    unsigned char iph_protocol; // protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct in_addr iph_sourceip; // source IP address
    struct in_addr iph_destip; // destination IP address
};

struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; // destination host address
    u_char ether_shost[ETHER_ADDR_LEN]; // source host address
    u_short ether_type; // IP? ARP? RARP? etc
};

struct icmpheader {
    unsigned char icmp_type; // icmp message
    unsigned char icmp_code; // error code
    unsigned short int icmp_chksum; // checksum for cimp header and data
    unsigned short int icmp_id; // used for identifying request
    unsigned short int icmp_seq; // sequence number
};

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // set 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // step 3: Provide needed info about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_sourceip;

    // step 4: send the packet out
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*)&dest_info, sizeof(dest_info));

    printf("\t FROM: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("\t TO: %s\n", inet_ntoa(ip->iph_destip));

    close(sock);
}

void send_echo_reply(struct ipheader * ip) {
    int ip_header_len = ip->iph_ihl * 4;
    const char buffer[1500];

    // make copy from original packet
    memset((char *)buffer, 0, 1500);
    memcpy((char *)buffer, ip, ntohs(ip->iph_len));
    struct ipheader* newip = (struct ipheader*) buffer;
    struct icmpheader* newicmp = (struct icmpheader*) (buffer + sizeof(ip_header_len));

    // IP swap source and destination to fake the echo response
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip   = ip->iph_sourceip;
    newip->iph_ttl = 64;

    // icmp echo response is type 0
    newicmp->icmp_type = 0;

    send_raw_ip_packet(newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader*) packet;

    if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP TYPE
        struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
        struct tcphdr *tcp  = (struct tcphdr*) ((u_char*) ip + sizeof(struct ipheader));

        unsigned short pktlen = ntohs(ip->iph_len);

        printf("\t FROM: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("\t TO: %s\n", inet_ntoa(ip->iph_destip));

        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                printf(" Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf(" Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf(" Protocol: ICMP\n");
                send_echo_reply(ip);
                return;
            default:
                printf(" Protocol: other\n");
                return;
        }

    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
