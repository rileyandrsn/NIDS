#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include "sniffer.h"

int packetParser(const struct pcap_pkthdr *hdr, const u_char *packet)
/*
@param const struct pcap_pkthdr *hdr:   
    - struct timeval ts; // time stamp
    - bpf_u_int32 caplen // length of portion present in data
    - bpf_u_int32 len; // length of packet before slicing

@param const u_char *packet:
*/
{
printf("<! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - !>\n");
    for (int i = 0; i < hdr->caplen; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
printf("<! - - - ETHERNET HEADER - - - !>\n");
printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);

    uint16_t eth_type = (packet[12] << 8) | packet[13];
    printf("EtherType: 0x%04x\n",eth_type);
    if(eth_type != 0x0800)//not IPv4
    {
        printf("Not an IPV4 packet - skipping\n");
        return -1;
    }

    const int ip_start = 14;
    uint8_t version_ihl = packet[ip_start];
    uint8_t version = version_ihl >> 4;
    uint8_t ihl = version_ihl & 0x0f;

    printf("\n<! - - - IP HEADER - - - !>\n");
    printf("Version: %d\n",version);
    printf("Header Length: %d bytes\n",ihl * 4);
    uint8_t protocol = packet[ip_start + 9];
    printf("Protocol: %d\n",protocol);
    if(protocol == 6)printf("(TCP)\n");
    else if (protocol == 17)printf("(UDP)\n");
    else printf("(Other)\n");

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &packet[ip_start+12],src_ip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &packet[ip_start+16],dst_ip,INET_ADDRSTRLEN);

    printf("Source IP: %s\n",src_ip);
    printf("Destination IP: %s\n", dst_ip);

    int transport_start = ip_start + ihl * 4;

    if(protocol == 6 || protocol == 17){
        uint16_t src_port = (packet[transport_start] << 8) | packet[transport_start + 1];
        uint16_t dst_port = (packet[transport_start + 2] << 8) | packet[transport_start + 3];

        printf("\n<! - - - TRANSPORT HEADER - - - !>\n");
        printf("Source Port: %u\n",src_port);
        printf("Destination Port: %u\n",dst_port);

        if(protocol == 6){
            uint8_t tcp_flags = packet[transport_start + 13];
            printf("TCP Flags: ");
            if(tcp_flags & 0x01) printf("FIN ");
            if(tcp_flags & 0x02) printf("SYN ");
            if(tcp_flags & 0x04) printf("RST ");
            if(tcp_flags & 0x08) printf("PSH ");
            if(tcp_flags & 0x10) printf("ACK ");
            if(tcp_flags & 0x020) printf("URG ");
            printf("\n");
            printf("<! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - !>\n");
        }
    }
    return 0;
}