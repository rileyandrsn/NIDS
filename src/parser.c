#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sniffer.h"
#include "rules.h"

void parse_hex_input(char *input, int len, struct json_object *parsed_json);
void print_hex_dump(const u_char *packet, int packet_len); // Prints raw hex dump of packet
void parse_ethernet_header(const u_char *packet,packet_t *pkt); // Parses ethernet header and creates ethernet header struct
// Parses either IPv4, IPv6, or ARP header and creates respective struct
void parse_ipv4_header(const u_char *packet,packet_t *pkt, int offset);
void parse_ipv6_header(const u_char *packet,packet_t *pkt, int offset);
void parse_arp_header(const u_char *packet,packet_t *pkt, int offset);
// Parses either TCP, UDP, or ICMP header and creates respective struct
void parse_tcp_header(const u_char *packet,packet_t *pkt, int offset);
void parse_udp_header(const u_char *packet,packet_t *pkt, int offset); 
void parse_icmp_header(const u_char *packet,packet_t *pkt, int offset);

int packetParser(const u_char *packet, int packet_len, struct json_object *parsed_json) {
    packet_t pkt; // Create instance of packet
    print_hex_dump(packet,packet_len); 
    parse_ethernet_header(packet,&pkt);
    
    // Switch statement to select respective protocol
    switch(ntohs(pkt.eth_hdr.eth_type)){
    case 0x0800: // 0x0800 = IPv4

        parse_ipv4_header(packet,&pkt,14);
        break;
    case 0x86DD: // 0x86DD = IPv6
        parse_ipv6_header(packet,&pkt,14);
        break;
    case 0x0806: // 0x0806 = ARP
        parse_arp_header(packet,&pkt,14);
        break;
    default:
        printf("\nUKNOWN PROTOCOL\n");
    }

    // Selects respective protocol given protocol/next header specifiers
    // IPv4 protocol == IPv6 Next header
    if (pkt.net_hdr.ipv4_hdr.protocol == 6) {
        uint8_t ihl = pkt.net_hdr.ipv4_hdr.version_ihl & 0x0f; // Bit mask to select last 4 bits
        uint8_t offset = ((ihl * 32) / 8)+14; // Offset for start of TCP header given IPv4 internet header length (IHL)
        parse_tcp_header(packet,&pkt,offset);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 6) { 
        parse_tcp_header(packet,&pkt,54);
    } else if (pkt.net_hdr.ipv4_hdr.protocol == 17 || pkt.net_hdr.ipv6_hdr.next_hdr == 17) {
        int offset = (pkt.net_hdr.ipv4_hdr.protocol == 17) ? 34 : 54; // Select offset based on internet protocol version
        parse_udp_header(packet,&pkt,offset);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 58) {
        parse_icmp_header(packet,&pkt,54); // ICMPv6
    }
    rule_check(parsed_json, pkt);
return 0;
}

void parse_hex_input(char *input, int len, struct json_object *parsed_json) {
    if (input == NULL || len <= 0) {
        fprintf(stderr, "Error: Null or invalid input.\n");
        exit(EXIT_FAILURE);
    }

    // Ensure length is even (2 hex = 1 byte)
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex input must contain an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

    //
    for (int i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)input[i])) { // Check if each character as a valid hexadecimal digit
            fprintf(stderr, "Error: Invalid hex character '%c' at position %d.\n", input[i], i);
            exit(EXIT_FAILURE);
        }
    }

    int output_len = len / 2; // u_char (1 byte) is represented by 2 hexadecimal digits
    u_char *output = malloc(output_len);
    if (output == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    // Convert pairs of hex characters to u_char
    for (int i = 0; i < output_len; i++) {
        char byte_str[3] = { input[2*i], input[2*i + 1], '\0' };
        output[i] = (u_char)strtoul(byte_str, NULL, 16);
    }

    packetParser(output,output_len, parsed_json);
    free(output);
}


void print_hex_dump(const u_char *packet, int packet_len){
    printf("\nRaw packet hex dump:\n");
    for (int i = 0; i < packet_len; i++) {
    printf("%02x ", packet[i]);
    if ((i + 1) % 16 == 0) {
    printf("\n");
    }}
    printf("\n");
}

// Parse/print ethernet header fields
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

// Parse/print TCP header fields
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
    strcpy(pkt->proto,"TCP");
    printf("\n < ! - - - - - TCP HEADER - - - - - ! >\n");
    printf("SRC PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.src_port));
    printf("DST PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.dst_port));
    printf("Sequence Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.sequence_num));
    printf("Acknowledgement Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.ack_num));
    printf("Data offset + reserved: 0x%x\n", ntohs(pkt->trans_hdr.tcp_hdr.data_offset_reserved));
    printf("Flags: 0x%x\n", pkt->trans_hdr.tcp_hdr.flags);
    // Display flags with bitwise AND operations
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

// Parse/print UDP header fields
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
    strcpy(pkt->proto,"UDP");
}

// Parse/print ICMP header fields
void parse_icmp_header(const u_char *packet,packet_t *pkt, int offset){
    memcpy(&pkt->trans_hdr.icmp_hdr.type, packet + offset, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.code, packet + offset + 1, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.checksum, packet + offset + 2, 2);
    printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
    printf("Type: %u\n", pkt->trans_hdr.icmp_hdr.type);
    printf("Code: %u\n", pkt->trans_hdr.icmp_hdr.code);
    printf("Checksum: 0x%x\n", ntohs(pkt->trans_hdr.icmp_hdr.checksum));
    strcpy(pkt->proto,"ICMP");
}

// Parse/print ARP header fields
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
    strcpy(pkt->proto,"ARP");
}

// Parse/print IPv4 Header fields
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
 // Parse/print IPv6 Header fields
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