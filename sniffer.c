#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length
    iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
    iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));


        switch (ip->iph_protocol)
        {
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //filter we want to change
    //2.1B- char filter_exp[] = "icmp and src host 192.168.1.5 and dst host 8.8.8.8";
    //2.1B- char filter_exp[] = "tcp and portrange 10-100";
    //2.1C sniffing passwords- "tcp port telnet";
    char filter_exp[] = "tcp port telnet";
    bpf_u_int32 net;

    //Open live pcap session - 0 normal mode and 1 for promiscuous mode
    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);

    //Compile and setfilter
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    //Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    //Close
    pcap_close(handle);
    return 0;
}