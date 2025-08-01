#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include "sniffer.h"
#include <stdint.h>

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} eth_header;

typedef struct {
    uint8_t version_ihl;
    uint8_t service;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags_frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_header;

typedef struct {
    uint32_t ver_tc_fl; // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
} ipv6_header;

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint32_t spa; // sender protocol addre (IPv4 addr)
    uint32_t tpa; // target protocol addr (IPv4 addr)
} __attribute__((packed)) arp_header; // Ensures structure is packed tightly (no compiler-inserted padding)

typedef union {
    ipv4_header ipv4_hdr;
    ipv6_header ipv6_hdr;
    arp_header arp_hdr;
} ip_header_union;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} udp_header;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} icmp_header;

typedef union{
    tcp_header tcp_hdr;
    udp_header udp_hdr;
    icmp_header icmp_hdr;
} protocol_union;

typedef struct {
    uint16_t transaction_id;
    uint16_t flags; // QR (1 bit) + OPCODE (4 bits) + AA (1 bit) + TC (1 bit) + RD (1 bit) + RA (1 bit) + Z (1 bit) + AD (1 bit) + CD (1 bit) + RCODE (4 bits)
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authority_rr;
    uint16_t num_additional_rr;
} dns_header;

typedef struct {
    eth_header eth_hdr;
    ip_header_union ip_hdr;
    protocol_union proto;
} packet_t;


int packetParser(const u_char *packet)
/*
@param const u_char *packet : pointer to packet data - raw bytes of captured packet
*/
{
/* TODO: Parsing logic
     -ethernet header (done)
     -ipv4 header (done)
     -ipv6 header (done)

     -tcp header (next header = 6) (done)
     -udp header (next header = 17) (done)
     -icmpv6 header (next header = 58)
     -dns header (tcp/udp port 53)
*/
    // Print entire raw hex of packet
    printf("Raw packet hex dump:\n");
    for (int i = 0; i < 66; i++) { // Print first 66 bytes to check
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
    
    packet_t pkt;

    int internet_layer_start = 14;
    int transport_layer_start;

    memcpy(pkt.eth_hdr.dst_mac,packet,6);
    memcpy(pkt.eth_hdr.src_mac,packet+6,6);
    pkt.eth_hdr.eth_type = ntohs(*(uint16_t *)(packet + 12));
    
    // Print Ethernet header fields
    printf("=== Ethernet Header ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           pkt.eth_hdr.dst_mac[0], pkt.eth_hdr.dst_mac[1], pkt.eth_hdr.dst_mac[2],
           pkt.eth_hdr.dst_mac[3], pkt.eth_hdr.dst_mac[4], pkt.eth_hdr.dst_mac[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           pkt.eth_hdr.src_mac[0], pkt.eth_hdr.src_mac[1], pkt.eth_hdr.src_mac[2],
           pkt.eth_hdr.src_mac[3], pkt.eth_hdr.src_mac[4], pkt.eth_hdr.src_mac[5]);
    printf("Ethernet Type: 0x%04x (%u)\n", pkt.eth_hdr.eth_type, pkt.eth_hdr.eth_type);

    if(pkt.eth_hdr.eth_type == 2048){ // hex: 0x0800 (IPv4)
        printf("=== IPv4 Header ===\n");
        
        memcpy(&pkt.ip_hdr.ipv4_hdr.version_ihl,packet+internet_layer_start,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.service,packet+internet_layer_start+1,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.total_len,packet+internet_layer_start+2,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.identification,packet+internet_layer_start+4,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.flags_frag_offset,packet+internet_layer_start+6,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.ttl,packet+internet_layer_start+8,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.protocol,packet+internet_layer_start+9,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.hdr_checksum,packet+internet_layer_start+10,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.src_ip,packet+internet_layer_start+12,4);
        memcpy(&pkt.ip_hdr.ipv4_hdr.dst_ip,packet+internet_layer_start+16,4);
        
        // Print IPv4 header fields
        printf("Version/IHL: 0x%02x\n", pkt.ip_hdr.ipv4_hdr.version_ihl);
        printf("Service: 0x%02x\n", pkt.ip_hdr.ipv4_hdr.service);
        printf("Total Length: %u\n", ntohs(pkt.ip_hdr.ipv4_hdr.total_len));
        printf("Identification: 0x%04x\n", ntohs(pkt.ip_hdr.ipv4_hdr.identification));
        printf("Flags/Fragment Offset: 0x%04x\n", ntohs(pkt.ip_hdr.ipv4_hdr.flags_frag_offset));
        printf("TTL: %u\n", pkt.ip_hdr.ipv4_hdr.ttl);
        printf("Protocol: %u\n", pkt.ip_hdr.ipv4_hdr.protocol);
        printf("Header Checksum: 0x%04x\n", ntohs(pkt.ip_hdr.ipv4_hdr.hdr_checksum));
        
        // Convert IP addresses to readable format
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = pkt.ip_hdr.ipv4_hdr.src_ip;
        dst_addr.s_addr = pkt.ip_hdr.ipv4_hdr.dst_ip;
        printf("Source IP: %s\n", inet_ntoa(src_addr));
        printf("Destination IP: %s\n", inet_ntoa(dst_addr));

    } else if(pkt.eth_hdr.eth_type == 34525){ // hex: 0x86DD (IPv6)
        printf("=== IPv6 Header ===\n");
        memcpy(&pkt.ip_hdr.ipv6_hdr.ver_tc_fl,packet+internet_layer_start,4);
        memcpy(&pkt.ip_hdr.ipv6_hdr.payload_len,packet+internet_layer_start+4,2);
        memcpy(&pkt.ip_hdr.ipv6_hdr.next_hdr, packet + internet_layer_start + 6, 1);
        memcpy(&pkt.ip_hdr.ipv6_hdr.hop_limit, packet + internet_layer_start + 7, 1);
        memcpy(&pkt.ip_hdr.ipv6_hdr.src_addr, packet + internet_layer_start + 8, 16);
        memcpy(&pkt.ip_hdr.ipv6_hdr.dst_addr, packet + internet_layer_start + 24, 16);        
        
        // Print IPv6 header fields
        printf("Version/Traffic Class/Flow Label: 0x%08x\n", ntohl(pkt.ip_hdr.ipv6_hdr.ver_tc_fl));
        printf("Payload Length: %u\n", ntohs(pkt.ip_hdr.ipv6_hdr.payload_len));
        printf("Next Header: %u\n", pkt.ip_hdr.ipv6_hdr.next_hdr);
        printf("Hop Limit: %u\n", pkt.ip_hdr.ipv6_hdr.hop_limit);
        
        // Convert IPv6 addresses to readable format
        char src_ipv6[INET6_ADDRSTRLEN], dst_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt.ip_hdr.ipv6_hdr.src_addr, src_ipv6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &pkt.ip_hdr.ipv6_hdr.dst_addr, dst_ipv6, INET6_ADDRSTRLEN);
        printf("Source IPv6: %s\n", src_ipv6);
        printf("Destination IPv6: %s\n", dst_ipv6);
    } else if(pkt.eth_hdr.eth_type == 2054){ // hex: 0x0806 (ARP)
        memcpy(&pkt.ip_hdr.arp_hdr.hardware_type,packet + internet_layer_start,2);
        printf("\n ARP HARDWARE TYPE: %x \n",ntohs(pkt.ip_hdr.arp_hdr.hardware_type));
        memcpy(&pkt.ip_hdr.arp_hdr.protocol_type,packet + internet_layer_start+2,2);
        printf("\n ARP PROTOCOL TYPE: %x \n",pkt.ip_hdr.arp_hdr.protocol_type);
        memcpy(&pkt.ip_hdr.arp_hdr.hardware_len,packet + internet_layer_start+4,1);
        printf("\n ARP HARDWARE LENGTH: %x \n",pkt.ip_hdr.arp_hdr.hardware_len);
        memcpy(&pkt.ip_hdr.arp_hdr.protocol_len,packet + internet_layer_start+5,1);
        printf("\n ARP PROTOCOL LENGTH: %x \n",pkt.ip_hdr.arp_hdr.protocol_len);
        memcpy(&pkt.ip_hdr.arp_hdr.operation,packet + internet_layer_start+6,2);
        printf("\n ARP OPCODE: %x \n",ntohs(pkt.ip_hdr.arp_hdr.operation));
        memcpy(&pkt.ip_hdr.arp_hdr.spa,packet + internet_layer_start + 14, 4);
        memcpy(&pkt.ip_hdr.arp_hdr.tpa,packet + internet_layer_start + 24, 4);

        // Convert IP addresses to readable format
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = pkt.ip_hdr.arp_hdr.spa;
        dst_addr.s_addr = pkt.ip_hdr.arp_hdr.tpa;
        printf("\n ARP SENDER IP: %s\n", inet_ntoa(src_addr));
        printf("\n ARP TARGET IP: %s\n", inet_ntoa(dst_addr));
    } 

    if(pkt.ip_hdr.ipv4_hdr.protocol == 6){
        printf("\n < ! - - - - - TCP HEADER IPv4 - - - - - ! >\n");
        uint8_t ihl = pkt.ip_hdr.ipv4_hdr.version_ihl & 0x0f; //bit mask rightmost 4 bits for IHL
        printf("IHL: %x\n",ihl);
        transport_layer_start = (ihl * 32)/8;
        printf(" Trans layer start: %d\n",transport_layer_start);
        memcpy(&pkt.proto.tcp_hdr.src_port,packet + internet_layer_start + transport_layer_start, 2);
        printf("SRC PORT: %u\n",ntohs(pkt.proto.tcp_hdr.src_port));
        memcpy(&pkt.proto.tcp_hdr.dst_port,packet + internet_layer_start + transport_layer_start + 2, 2);
        printf("DST PORT: %u\n",ntohs(pkt.proto.tcp_hdr.dst_port));
        memcpy(&pkt.proto.tcp_hdr.sequence_num,packet + internet_layer_start + transport_layer_start + 4, 4);
        printf("Sequence Number (raw): %x\n",ntohl(pkt.proto.tcp_hdr.sequence_num));
        memcpy(&pkt.proto.tcp_hdr.ack_num,packet + internet_layer_start + transport_layer_start + 8, 4); // issue: ntohs only goes up to 16 bits, needed to change to ntohl (32 bits) [fixed]
        printf("ACK NUM: %x\n",ntohl(pkt.proto.tcp_hdr.ack_num));
        memcpy(&pkt.proto.tcp_hdr.data_offset_reserved,packet + internet_layer_start + transport_layer_start + 12, 1);
        printf("Data offset + reserved: %x\n",ntohs(pkt.proto.tcp_hdr.data_offset_reserved));
        memcpy(&pkt.proto.tcp_hdr.flags,packet + internet_layer_start + transport_layer_start + 13, 1);
        printf("Flags: %x\n",pkt.proto.tcp_hdr.flags);
        if((pkt.proto.tcp_hdr.flags & 0x01) == 0x01)printf("-FIN\n");
        if((pkt.proto.tcp_hdr.flags & 0x02) == 0x02)printf("-SYN\n");
        if((pkt.proto.tcp_hdr.flags & 0x04) == 0x04)printf("-RESET\n");
        if((pkt.proto.tcp_hdr.flags & 0x08) == 0x08)printf("-PUSH\n");\
        if((pkt.proto.tcp_hdr.flags & 0x10) == 0x10)printf("-ACK\n");
        if((pkt.proto.tcp_hdr.flags & 0x20) == 0x20)printf("-URGENT\n");
        if((pkt.proto.tcp_hdr.flags & 0x40) == 0x40)printf("-ECE\n");
        if((pkt.proto.tcp_hdr.flags & 0x80) == 0x80)printf("-CWR\n");
        memcpy(&pkt.proto.tcp_hdr.window_size,packet + internet_layer_start + transport_layer_start + 14, 2);
        printf("\nWindow Size: %u\n",ntohs(pkt.proto.tcp_hdr.window_size));
        memcpy(&pkt.proto.tcp_hdr.checksum,packet + internet_layer_start + transport_layer_start + 16, 2);
        printf("\n Checksum: %x \n",ntohs(pkt.proto.tcp_hdr.checksum));
        memcpy(&pkt.proto.tcp_hdr.urgent_pointer,packet + internet_layer_start + transport_layer_start + 18, 2);
        printf("\n Urgent Pointer: %x \n",ntohs(pkt.proto.tcp_hdr.urgent_pointer));

    } else if(pkt.ip_hdr.ipv6_hdr.next_hdr == 6){
        printf("\n < ! - - - - - TCP HEADER IPv6 - - - - - ! >\n");
        transport_layer_start = 40;
        printf(" Trans layer start: %d\n",transport_layer_start);
        memcpy(&pkt.proto.tcp_hdr.src_port,packet + internet_layer_start + transport_layer_start, 2);
        printf("SRC PORT: %u\n",ntohs(pkt.proto.tcp_hdr.src_port));
        memcpy(&pkt.proto.tcp_hdr.dst_port,packet + internet_layer_start + transport_layer_start + 2, 2);
        printf("DST PORT: %u\n",ntohs(pkt.proto.tcp_hdr.dst_port));
        memcpy(&pkt.proto.tcp_hdr.sequence_num,packet + internet_layer_start + transport_layer_start + 4, 4);
        printf("Sequence Number (raw): %x\n",ntohl(pkt.proto.tcp_hdr.sequence_num));
        memcpy(&pkt.proto.tcp_hdr.ack_num,packet + internet_layer_start + transport_layer_start + 8, 4); // issue: ntohs only goes up to 16 bits, needed to change to ntohl (32 bits) [fixed]
        printf("ACK NUM: %x\n",ntohl(pkt.proto.tcp_hdr.ack_num));
        memcpy(&pkt.proto.tcp_hdr.data_offset_reserved,packet + internet_layer_start + transport_layer_start + 12, 1);
        printf("Data offset + reserved: %x\n",ntohs(pkt.proto.tcp_hdr.data_offset_reserved));
        memcpy(&pkt.proto.tcp_hdr.flags,packet + internet_layer_start + transport_layer_start + 13, 1);
        printf("Flags: %x\n",pkt.proto.tcp_hdr.flags);
        if((pkt.proto.tcp_hdr.flags & 0x01) == 0x01)printf("-FIN\n");
        if((pkt.proto.tcp_hdr.flags & 0x02) == 0x02)printf("-SYN\n");
        if((pkt.proto.tcp_hdr.flags & 0x04) == 0x04)printf("-RESET\n");
        if((pkt.proto.tcp_hdr.flags & 0x08) == 0x08)printf("-PUSH\n");\
        if((pkt.proto.tcp_hdr.flags & 0x10) == 0x10)printf("-ACK\n");
        if((pkt.proto.tcp_hdr.flags & 0x20) == 0x20)printf("-URGENT\n");
        if((pkt.proto.tcp_hdr.flags & 0x40) == 0x40)printf("-ECE\n");
        if((pkt.proto.tcp_hdr.flags & 0x80) == 0x80)printf("-CWR\n");
        memcpy(&pkt.proto.tcp_hdr.window_size,packet + internet_layer_start + transport_layer_start + 14, 2);
        printf("\nWindow Size: %u\n",ntohs(pkt.proto.tcp_hdr.window_size));
        memcpy(&pkt.proto.tcp_hdr.checksum,packet + internet_layer_start + transport_layer_start + 16, 2);
        printf("\n Checksum: %x \n",ntohs(pkt.proto.tcp_hdr.checksum));
        memcpy(&pkt.proto.tcp_hdr.urgent_pointer,packet + internet_layer_start + transport_layer_start + 18, 2);
        printf("\n Urgent Pointer: %x \n",ntohs(pkt.proto.tcp_hdr.urgent_pointer));
    } else if(pkt.ip_hdr.ipv4_hdr.protocol == 17 || pkt.ip_hdr.ipv6_hdr.next_hdr == 17){
        if (pkt.ip_hdr.ipv4_hdr.protocol == 17) {
            transport_layer_start = 20;
        } else {
            transport_layer_start = 40;
        }        
        printf("\n < ! - - - - - UDP HEADER - - - - - ! >\n");
        memcpy(&pkt.proto.udp_hdr.src_port, packet + internet_layer_start + transport_layer_start, 2);
        printf("Source Port: %u\n",ntohs(pkt.proto.udp_hdr.src_port));
        memcpy(&pkt.proto.udp_hdr.dst_port, packet + internet_layer_start + transport_layer_start + 2, 2);
        printf("Destination Port: %u\n",ntohs(pkt.proto.udp_hdr.dst_port));
        memcpy(&pkt.proto.udp_hdr.len, packet + internet_layer_start + transport_layer_start + 4, 2);
        printf("Length: %u\n",ntohs(pkt.proto.udp_hdr.len));
        memcpy(&pkt.proto.udp_hdr.checksum, packet + internet_layer_start + transport_layer_start + 6, 2);
        printf("Checksum: %x\n",ntohs(pkt.proto.udp_hdr.checksum));
    } else if(pkt.ip_hdr.ipv6_hdr.next_hdr == 58){
        transport_layer_start = 40;
        printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
        memcpy(&pkt.proto.icmp_hdr.type,packet+internet_layer_start+transport_layer_start, 1);
        printf("Type: %u\n",pkt.proto.icmp_hdr.type);
        memcpy(&pkt.proto.icmp_hdr.code,packet+internet_layer_start+transport_layer_start +1, 1);
        printf("Code: %u\n",pkt.proto.icmp_hdr.code);
        memcpy(&pkt.proto.icmp_hdr.checksum,packet+internet_layer_start+transport_layer_start +2, 2);
        printf("Checksum: %x\n",pkt.proto.icmp_hdr.checksum);
    }

    //void *payload;
    //int payload_len;

    return 0;
}