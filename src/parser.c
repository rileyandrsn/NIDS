// --- External header imports ---
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Internal header imports ---
#include "packet.h"
#include "rule.h"
#include "rules.h"
#include "sniffer.h"

// --- Function declarations ---

/*
Function: void parse_hex_input(char *input, int len, rule_t *rule)
Takes user's hex input and validates it, assembles it as a packet, and checks it against rules

Parameters:
*input - user's raw hex input
len - length of user's input
*rule - pointer pointing toward head node of linked list storing rules

Returns: void
*/
void parse_hex_input(char *input, int len, rule_t *rule)
{
    if (input == NULL || len <= 0) {
        fprintf(stderr, "Error: Null or invalid input.\n");
        exit(EXIT_FAILURE);
    }

    // Ensure length is even (2 hex = 1 byte)
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex input must contain an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

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

    // Convert pairs of hex characters to u_char byte
    for (int i = 0; i < output_len; i++) {
        char byte_str[3] = { input[2 * i], input[2 * i + 1], '\0' };
        output[i] = (u_char)strtoul(byte_str, NULL, 16);
    }

    packetParser(output, output_len, rule);
    free(output);
}

/*
Function: void print_hex_dump(const u_char *packet, int packet_len)
Prints the raw hex stream of captured packet

Parameters:
*packet - raw u_char bytes of packet data
packet_len - length of packet in bytes

Returns: void
*/
void print_hex_dump(const u_char *packet, int packet_len)
{
    printf("\nRaw packet hex dump:\n");
    for (int i = 0; i < packet_len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

/*
Function: void parse_ethernet_header(const u_char *packet, packet_t *pkt)
Parses packet and sets packet fields to values corresponding to ethernet header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values

Returns: void
*/
void parse_ethernet_header(const u_char *packet, packet_t *pkt)
{
    memcpy(&pkt->eth_hdr.dst_mac, packet, 6);
    memcpy(&pkt->eth_hdr.src_mac, packet + 6, 6);
    memcpy(&pkt->eth_hdr.eth_type, packet + 12, 2);
}

/*
Function: void print_ethernet_header(packet_t *pkt)
Prints contents of packet's ethernet header (first 14 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_ethernet_header(packet_t *pkt)
{
    printf("=== Ethernet Header ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pkt->eth_hdr.dst_mac[0], pkt->eth_hdr.dst_mac[1], pkt->eth_hdr.dst_mac[2],
        pkt->eth_hdr.dst_mac[3], pkt->eth_hdr.dst_mac[4], pkt->eth_hdr.dst_mac[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        pkt->eth_hdr.src_mac[0], pkt->eth_hdr.src_mac[1], pkt->eth_hdr.src_mac[2],
        pkt->eth_hdr.src_mac[3], pkt->eth_hdr.src_mac[4], pkt->eth_hdr.src_mac[5]);
    printf("Ethernet Type: 0x%04x\n", ntohs(pkt->eth_hdr.eth_type));
}

/*
Function: void parse_tcp_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to TCP header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte TCP header starts

Returns: void
*/
void parse_tcp_header(const u_char *packet, packet_t *pkt, int offset)
{
    memcpy(&pkt->trans_hdr.tcp_hdr.src_port, packet + offset, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.dst_port, packet + offset + 2, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.sequence_num, packet + offset + 4, 4);
    memcpy(&pkt->trans_hdr.tcp_hdr.ack_num, packet + offset + 8, 4);
    memcpy(&pkt->trans_hdr.tcp_hdr.data_offset_reserved, packet + offset + 12, 1);
    memcpy(&pkt->trans_hdr.tcp_hdr.flags, packet + offset + 13, 1);
    memcpy(&pkt->trans_hdr.tcp_hdr.window_size, packet + offset + 14, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.checksum, packet + offset + 16, 2);
    memcpy(&pkt->trans_hdr.tcp_hdr.urgent_pointer, packet + offset + 18, 2);
    strcpy(pkt->proto, "TCP");
}

/*
Function: void print_tcp_header(packet_t *pkt)
Prints contents of packet's TCP header (20-60 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_tcp_header(packet_t *pkt)
{
    printf("\n < ! - - - - - TCP HEADER - - - - - ! >\n");
    printf("SRC PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.src_port));
    printf("DST PORT: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.dst_port));
    printf("Sequence Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.sequence_num));
    printf("Acknowledgement Number (raw): 0x%x\n", ntohl(pkt->trans_hdr.tcp_hdr.ack_num));
    printf("Data offset + reserved: 0x%x\n", ntohs(pkt->trans_hdr.tcp_hdr.data_offset_reserved));
    printf("Flags: 0x%x\n", pkt->trans_hdr.tcp_hdr.flags);
    // Display flags with bitwise AND operations
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x01) == 0x01)
        printf("-FIN\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x02) == 0x02)
        printf("-SYN\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x04) == 0x04)
        printf("-RESET\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x08) == 0x08)
        printf("-PUSH\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x10) == 0x10)
        printf("-ACK\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x20) == 0x20)
        printf("-URGENT\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x40) == 0x40)
        printf("-ECE\n");
    if ((pkt->trans_hdr.tcp_hdr.flags & 0x80) == 0x80)
        printf("-CWR\n");
    printf("\nWindow Size: %u\n", ntohs(pkt->trans_hdr.tcp_hdr.window_size));
    printf("\nChecksum: 0x%x \n", ntohs(pkt->trans_hdr.tcp_hdr.checksum));
    printf("\nUrgent Pointer: %x \n", ntohs(pkt->trans_hdr.tcp_hdr.urgent_pointer));
}

/*
Function: void parse_udp_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to UDP header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte UDP header starts

Returns: void
*/
void parse_udp_header(const u_char *packet, packet_t *pkt, int offset)
{
    strcpy(pkt->proto, "UDP");
    memcpy(&pkt->trans_hdr.udp_hdr.src_port, packet + offset, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.dst_port, packet + offset + 2, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.len, packet + offset + 4, 2);
    memcpy(&pkt->trans_hdr.udp_hdr.checksum, packet + offset + 6, 2);
}

/*
Function: void print_udp_header(packet_t *pkt)
Prints contents of packet's UDP header (8 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_udp_header(packet_t *pkt)
{
    printf("\n < ! - - - - - UDP HEADER - - - - - ! >\n");
    printf("Source Port: %u\n", ntohs(pkt->trans_hdr.udp_hdr.src_port));
    printf("Destination Port: %u\n", ntohs(pkt->trans_hdr.udp_hdr.dst_port));
    printf("Length: %u\n", ntohs(pkt->trans_hdr.udp_hdr.len));
    printf("Checksum: 0x%x\n", ntohs(pkt->trans_hdr.udp_hdr.checksum));
}

/*
Function: void parse_icmp_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to ICMP header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte ICMP header starts

Returns: void
*/
void parse_icmp_header(const u_char *packet, packet_t *pkt, int offset)
{
    strcpy(pkt->proto, "ICMP");
    memcpy(&pkt->trans_hdr.icmp_hdr.type, packet + offset, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.code, packet + offset + 1, 1);
    memcpy(&pkt->trans_hdr.icmp_hdr.checksum, packet + offset + 2, 2);
}

/*
Function: void print_icmp_header(packet_t *pkt)
Prints contents of packet's ICMPv6 header (8 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_icmp_header(packet_t *pkt)
{
    printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
    printf("Type: %u\n", pkt->trans_hdr.icmp_hdr.type);
    printf("Code: %u\n", pkt->trans_hdr.icmp_hdr.code);
    printf("Checksum: 0x%x\n", ntohs(pkt->trans_hdr.icmp_hdr.checksum));
}

/*
Function: void parse_arp_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to ARP header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte ARP header starts

Returns: void
*/
void parse_arp_header(const u_char *packet, packet_t *pkt, int offset)
{
    memcpy(&pkt->net_hdr.arp_hdr.hardware_type, packet + offset, 2);
    memcpy(&pkt->net_hdr.arp_hdr.protocol_type, packet + offset + 2, 2);
    memcpy(&pkt->net_hdr.arp_hdr.hardware_len, packet + offset + 4, 1);
    memcpy(&pkt->net_hdr.arp_hdr.protocol_len, packet + offset + 5, 1);
    memcpy(&pkt->net_hdr.arp_hdr.operation, packet + offset + 6, 2);
    memcpy(&pkt->net_hdr.arp_hdr.sha, packet + offset + 8, 6);
    memcpy(&pkt->net_hdr.arp_hdr.spa, packet + offset + 14, 4);
    memcpy(&pkt->net_hdr.arp_hdr.tha, packet + offset + 18, 6);
    memcpy(&pkt->net_hdr.arp_hdr.tpa, packet + offset + 24, 4);
    strcpy(pkt->proto, "ARP");
}

/*
Function: void print_arp_header(packet_t *pkt)
Prints contents of packet's ARP header (28 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_arp_header(packet_t *pkt)
{
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

/*
Function: void parse_ipv4_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to IPv4 header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte IPv4 header starts

Returns: void
*/
void parse_ipv4_header(const u_char *packet, packet_t *pkt, int offset)
{
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
}

/*
Function: void print_ipv4_header(packet_t *pkt)
Prints contents of packet's IPv4 header (20-60 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_ipv4_header(packet_t *pkt)
{
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

/*
Function: void parse_ipv6_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to IPv6 header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte IPv6 header starts

Returns: void
*/
void parse_ipv6_header(const u_char *packet, packet_t *pkt, int offset)
{
    memcpy(&pkt->net_hdr.ipv6_hdr.ver_tc_fl, packet + offset, 4);
    memcpy(&pkt->net_hdr.ipv6_hdr.payload_len, packet + offset + 4, 2);
    memcpy(&pkt->net_hdr.ipv6_hdr.next_hdr, packet + offset + 6, 1);
    memcpy(&pkt->net_hdr.ipv6_hdr.hop_limit, packet + offset + 7, 1);
    memcpy(&pkt->net_hdr.ipv6_hdr.src_addr, packet + offset + 8, 16);
    memcpy(&pkt->net_hdr.ipv6_hdr.dst_addr, packet + offset + 24, 16);
}

/*
Function: void print_ipv6_header(packet_t *pkt)
Prints contents of packet's IPv6 header (40 bytes)

Parameters:
*pkt - packet structure to store values

Returns: void
*/
void print_ipv6_header(packet_t *pkt)
{
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

/*
Function: void packetParser(const u_char *packet, int packet_len, rule_t *rule)

Parameters:
*packet - raw u_char bytes of packet data
packet_len - length of packet in bytes
*rule - pointer pointing toward head node of linked list storing rules

Returns: void
*/
void packetParser(const u_char *packet, int packet_len, rule_t *rule)
{
    packet_t pkt; // Create instance of packet
    print_hex_dump(packet, packet_len);
    parse_ethernet_header(packet, &pkt);
    //print_ethernet_header(&pkt);

    // Switch statement to select respective protocol
    switch (ntohs(pkt.eth_hdr.eth_type)) {
    case 0x0800: // 0x0800 = IPv4
        parse_ipv4_header(packet, &pkt, 14);
        //print_ipv4_header(&pkt);
        break;
    case 0x86DD: // 0x86DD = IPv6
        parse_ipv6_header(packet, &pkt, 14);
        //print_ipv6_header(&pkt);
        break;
    case 0x0806: // 0x0806 = ARP
        parse_arp_header(packet, &pkt, 14);
        //print_arp_header(&pkt);
        break;
    default:
        printf("\nUKNOWN PROTOCOL\n");
    }

    // Selects respective protocol given protocol/next header specifiers
    // IPv4 protocol == IPv6 Next header
    if (pkt.net_hdr.ipv4_hdr.protocol == 6 && (ntohs(pkt.eth_hdr.eth_type)) == 0x0800) {
        uint8_t ihl = pkt.net_hdr.ipv4_hdr.version_ihl & 0x0f; // Bit mask to select last 4 bits
        uint8_t offset = ((ihl * 32) / 8) + 14; // Offset for start of TCP header given IPv4 internet header length (IHL)
        parse_tcp_header(packet, &pkt, offset);
        //print_tcp_header(&pkt);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 6 && (ntohs(pkt.eth_hdr.eth_type)) == 0x86dd) {
        parse_tcp_header(packet, &pkt, 54);
        //print_tcp_header(&pkt);
    } else if ((pkt.net_hdr.ipv4_hdr.protocol == 17 && (ntohs(pkt.eth_hdr.eth_type)) == 0x0800) || (pkt.net_hdr.ipv6_hdr.next_hdr == 17 && (ntohs(pkt.eth_hdr.eth_type)) == 0x86dd)) {
        int offset = (pkt.net_hdr.ipv4_hdr.protocol == 17) ? 34 : 54; // Select offset based on internet protocol version
        parse_udp_header(packet, &pkt, offset);
        //print_udp_header(&pkt);
    } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 58) { // ICMPv6
        parse_icmp_header(packet, &pkt, 54);
        //print_icmp_header(&pkt);
    }
    rule_check(rule, pkt);
}
