#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sniffer.h"

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
  uint32_t ver_tc_fl;
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
  uint8_t sha[6];
  uint32_t spa;        
  uint8_t tha[6];                
  uint32_t tpa;                        
} __attribute__((packed)) arp_header;

typedef union {
  ipv4_header ipv4_hdr;
  ipv6_header ipv6_hdr;
  arp_header arp_hdr;
} network_layer_union;

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

typedef union {
  tcp_header tcp_hdr;
  udp_header udp_hdr;
  icmp_header icmp_hdr;
} transport_layer_union;

typedef struct {
  eth_header eth_hdr;
  network_layer_union net_hdr;
  transport_layer_union trans_hdr;
} packet_t;

void print_hex_dump(const u_char *packet, int packet_len);
void parse_ethernet_header(const u_char *packet,packet_t *pkt);
void parse_icmp_header(const u_char *packet,packet_t *pkt, int offset);
void parse_udp_header(const u_char *packet,packet_t *pkt, int offset);
void parse_tcp_header(const u_char *packet,packet_t *pkt, int offset);
void parse_arp_header(const u_char *packet,packet_t *pkt, int offset);
void parse_ipv4_header(const u_char *packet,packet_t *pkt, int offset);
void parse_ipv6_header(const u_char *packet,packet_t *pkt, int offset);

int packetParser(const u_char *packet, int packet_len){
    packet_t pkt;
    print_hex_dump(packet,packet_len);
    parse_ethernet_header(packet,&pkt);

    switch(ntohs(pkt.eth_hdr.eth_type)){
    case 0x0800:
        parse_ipv4_header(packet,&pkt,14);
        break;
    case 0x86DD:
        parse_ipv6_header(packet,&pkt,14);
        break;
    case 0x0806:
        parse_arp_header(packet,&pkt,14);
        break;
    default:
        printf("\nUKNOWN PROTOCOL\n");
    }

    if (pkt.net_hdr.ipv4_hdr.protocol == 6) {
        uint8_t ihl = pkt.net_hdr.ipv4_hdr.version_ihl & 0x0f;
        uint8_t offset = ((ihl * 32) / 8)+14;
        parse_tcp_header(packet,&pkt,offset);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 6) {
        parse_tcp_header(packet,&pkt,54);
    } else if (pkt.net_hdr.ipv4_hdr.protocol == 17 || pkt.net_hdr.ipv6_hdr.next_hdr == 17) {
        int offset = (pkt.net_hdr.ipv4_hdr.protocol == 17) ? 34 : 54;
        parse_udp_header(packet,&pkt,offset);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 58) {
        parse_icmp_header(packet,&pkt,54);
    }
return 0;
}

void print_hex_dump(const u_char *packet, int packet_len){
    printf("Raw packet hex dump:\n");
    for (int i = 0; i < packet_len; i++) {
    printf("%02x ", packet[i]);
    if ((i + 1) % 16 == 0) {
    printf("\n");
    }}
    printf("\n");
}

void parse_ethernet_header(const u_char *packet,packet_t *pkt){
    memcpy(&pkt->eth_hdr.dst_mac, packet, 6);
    memcpy(&pkt->eth_hdr.src_mac, packet + 6, 6);
    memcpy(&pkt->eth_hdr.eth_type, packet + 12, 2);
    printf("=== Ethernet Header ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pkt->eth_hdr.dst_mac[0], pkt->eth_hdr.dst_mac[1], pkt->eth_hdr.dst_mac[2],
        pkt->eth_hdr.dst_mac[3], pkt->eth_hdr.dst_mac[4], pkt->eth_hdr.dst_mac[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
        pkt->eth_hdr.src_mac[0], pkt->eth_hdr.src_mac[1], pkt->eth_hdr.src_mac[2], 
        pkt->eth_hdr.src_mac[3], pkt->eth_hdr.src_mac[4], pkt->eth_hdr.src_mac[5]);
    printf("Ethernet Type: 0x%04x\n", ntohs(pkt->eth_hdr.eth_type));
}

void parse_tcp_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->trans_hdr.tcp_hdr.src_port, packet + offset, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.dst_port, packet + offset + 2, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.sequence_num, packet + offset + 4, 4);
    memcpy(&pkt->trans_hdr.tcp_hdr.ack_num, packet + offset + 8, 4);
    memcpy(&pkt->trans_hdr.tcp_hdr.data_offset_reserved, packet + offset + 12, 1);
    memcpy(&pkt->trans_hdr.tcp_hdr.flags, packet + offset + 13, 1);
    memcpy(&pkt->trans_hdr.tcp_hdr.window_size, packet + offset + 14, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.checksum, packet + offset + 16, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.urgent_pointer, packet + offset + 18, 2);

    printf("\n < ! - - - - - TCP HEADER - - - - - ! >\n");
    printf("SRC PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.src_port));
    printf("DST PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.dst_port));
    printf("Sequence Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.sequence_num));
    printf("Acknowledgement Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.ack_num));
    printf("Data offset + reserved: 0x%x\n", ntohs(pkt->trans_hdr.tcp_hdr.data_offset_reserved));
    printf("Flags: 0x%x\n", pkt->trans_hdr.tcp_hdr.flags);
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x01) == 0x01) printf("-FIN\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x02) == 0x02) printf("-SYN\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x04) == 0x04) printf("-RESET\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x08) == 0x08) printf("-PUSH\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x10) == 0x10) printf("-ACK\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x20) == 0x20) printf("-URGENT\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x40) == 0x40) printf("-ECE\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x80) == 0x80) printf("-CWR\n");
    printf("\nWindow Size: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.window_size));
    printf("\nChecksum: 0x%x \n", ntohs(pkt->trans_hdr.tcp_hdr.checksum));
    printf("\nUrgent Pointer: %x \n", ntohs(pkt->trans_hdr.tcp_hdr.urgent_pointer));
}

void parse_udp_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->trans_hdr.udp_hdr.src_port, packet + offset, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.dst_port, packet + offset + 2, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.len, packet + offset + 4, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.checksum, packet + offset + 6, 2);
    printf("\n < ! - - - - - UDP HEADER - - - - - ! >\n");
    printf("Source Port: %u\n", ntohs(pkt->trans_hdr.udp_hdr.src_port));
    printf("Destination Port: %u\n", ntohs(pkt->trans_hdr.udp_hdr.dst_port));
    printf("Length: %u\n", ntohs(pkt->trans_hdr.udp_hdr.len));
    printf("Checksum: 0x%x\n", ntohs(pkt->trans_hdr.udp_hdr.checksum));
}

void parse_icmp_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->trans_hdr.icmp_hdr.type, packet + offset, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.code, packet + offset + 1, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.checksum, packet + offset + 2, 2);
    printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
    printf("Type: %u\n", pkt->trans_hdr.icmp_hdr.type);
    printf("Code: %u\n", pkt->trans_hdr.icmp_hdr.code);
    printf("Checksum: 0x%x\n", ntohs(pkt->trans_hdr.icmp_hdr.checksum));
}

void parse_arp_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->net_hdr.arp_hdr.hardware_type, packet + offset, 2);
    memcpy(&pkt->net_hdr.arp_hdr.protocol_type, packet + offset + 2, 2);
    memcpy(&pkt->net_hdr.arp_hdr.hardware_len, packet + offset + 4, 1);
    memcpy(&pkt->net_hdr.arp_hdr.protocol_len, packet + offset + 5, 1);
    memcpy(&pkt->net_hdr.arp_hdr.operation, packet + offset + 6, 2);
    memcpy(&pkt->net_hdr.arp_hdr.sha, packet + offset + 8, 6);
    memcpy(&pkt->net_hdr.arp_hdr.spa, packet + offset + 14, 4);
    memcpy(&pkt->net_hdr.arp_hdr.tha, packet + offset + 18, 6);
    memcpy(&pkt->net_hdr.arp_hdr.tpa, packet + offset + 24, 4);
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = pkt->net_hdr.arp_hdr.spa;
    dst_addr.s_addr = pkt->net_hdr.arp_hdr.tpa;
    
    printf("\n ARP HARDWARE TYPE: %x \n", ntohs(pkt->net_hdr.arp_hdr.hardware_type));
    printf("\n ARP PROTOCOL TYPE: %x \n", pkt->net_hdr.arp_hdr.protocol_type);
    printf("\n ARP HARDWARE LENGTH: %x \n", pkt->net_hdr.arp_hdr.hardware_len);
    printf("\n ARP PROTOCOL LENGTH: %x \n", pkt->net_hdr.arp_hdr.protocol_len);
    printf("\n ARP OPCODE: %x \n", ntohs(pkt->net_hdr.arp_hdr.operation));
    printf("\n ARP SENDER HARDWARE ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pkt->net_hdr.arp_hdr.sha[0], pkt->net_hdr.arp_hdr.sha[1], pkt->net_hdr.arp_hdr.sha[2],
        pkt->net_hdr.arp_hdr.sha[3], pkt->net_hdr.arp_hdr.sha[4], pkt->net_hdr.arp_hdr.sha[5]);
    printf("\n ARP SENDER IP: %s\n", inet_ntoa(src_addr));
    printf("\n ARP TARGET HARDWARE ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pkt->net_hdr.arp_hdr.tha[0], pkt->net_hdr.arp_hdr.tha[1], pkt->net_hdr.arp_hdr.tha[2],
        pkt->net_hdr.arp_hdr.tha[3], pkt->net_hdr.arp_hdr.tha[4], pkt->net_hdr.arp_hdr.tha[5]);
    printf("\n ARP TARGET IP: %s\n", inet_ntoa(dst_addr));
}

void parse_ipv4_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->net_hdr.ipv4_hdr.version_ihl, packet + offset, 1);
    memcpy(&pkt->net_hdr.ipv4_hdr.service, packet + offset + 1, 1);
    memcpy(&pkt->net_hdr.ipv4_hdr.total_len, packet + offset + 2, 2);
    memcpy(&pkt->net_hdr.ipv4_hdr.identification, packet + offset + 4, 2);
    memcpy(&pkt->net_hdr.ipv4_hdr.flags_frag_offset, packet + offset + 6, 2);
    memcpy(&pkt->net_hdr.ipv4_hdr.ttl, packet + offset + 8, 1);
    memcpy(&pkt->net_hdr.ipv4_hdr.protocol, packet + offset + 9, 1);
    memcpy(&pkt->net_hdr.ipv4_hdr.hdr_checksum, packet + offset + 10, 2);
    memcpy(&pkt->net_hdr.ipv4_hdr.src_ip, packet + offset + 12, 4);
    memcpy(&pkt->net_hdr.ipv4_hdr.dst_ip, packet + offset + 16, 4);

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = pkt->net_hdr.ipv4_hdr.src_ip;
    dst_addr.s_addr = pkt->net_hdr.ipv4_hdr.dst_ip;
    printf("=== IPv4 Header ===\n");
    printf("Version/IHL: 0x%02x\n", pkt->net_hdr.ipv4_hdr.version_ihl);
    printf("Service: 0x%02x\n", pkt->net_hdr.ipv4_hdr.service);
    printf("Total Length: %u\n", ntohs(pkt->net_hdr.ipv4_hdr.total_len));
    printf("Identification: 0x%04x\n", ntohs(pkt->net_hdr.ipv4_hdr.identification));
    printf("Flags/Fragment Offset: 0x%04x\n", ntohs(pkt->net_hdr.ipv4_hdr.flags_frag_offset));
    printf("TTL: %u\n", pkt->net_hdr.ipv4_hdr.ttl);
    printf("Protocol: %u\n", pkt->net_hdr.ipv4_hdr.protocol);
    printf("Header Checksum: 0x%04x\n", ntohs(pkt->net_hdr.ipv4_hdr.hdr_checksum));
    printf("Source IP: %s\n", inet_ntoa(src_addr));
    printf("Destination IP: %s\n", inet_ntoa(dst_addr));
}

void parse_ipv6_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->net_hdr.ipv6_hdr.ver_tc_fl, packet + offset, 4);
    memcpy(&pkt->net_hdr.ipv6_hdr.payload_len, packet + offset + 4, 2);
    memcpy(&pkt->net_hdr.ipv6_hdr.next_hdr, packet + offset + 6, 1);
    memcpy(&pkt->net_hdr.ipv6_hdr.hop_limit, packet + offset + 7, 1);
    memcpy(&pkt->net_hdr.ipv6_hdr.src_addr, packet + offset + 8, 16);
    memcpy(&pkt->net_hdr.ipv6_hdr.dst_addr, packet + offset + 24, 16);
    char src_ipv6[INET6_ADDRSTRLEN], dst_ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &pkt->net_hdr.ipv6_hdr.src_addr, src_ipv6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &pkt->net_hdr.ipv6_hdr.dst_addr, dst_ipv6, INET6_ADDRSTRLEN);
    printf("=== IPv6 Header ===\n");
    printf("Version/Traffic Class/Flow Label: 0x%08x\n", ntohl(pkt->net_hdr.ipv6_hdr.ver_tc_fl));
    printf("Payload Length: %u\n", ntohs(pkt->net_hdr.ipv6_hdr.payload_len));
    printf("Next Header: %u\n", pkt->net_hdr.ipv6_hdr.next_hdr);
    printf("Hop Limit: %u\n", pkt->net_hdr.ipv6_hdr.hop_limit);
    printf("Source IPv6: %s\n", src_ipv6);
    printf("Destination IPv6: %s\n", dst_ipv6);
}