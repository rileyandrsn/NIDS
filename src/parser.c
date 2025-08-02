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
  uint32_t ver_tc_fl;  // Version (4 bits), Traffic Class (8 bits), Flow Label
                       // (20 bits)
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
} __attribute__((packed)) arp_header;  // Ensures structure is packed tightly (no compiler-inserted padding)

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

// typedef struct {
//     uint16_t transaction_id;
//     uint16_t flags; // QR (1 bit) + OPCODE (4 bits) + AA (1 bit) + TC (1 bit)
//     + RD (1 bit) + RA (1 bit) + Z (1 bit) + AD (1 bit) + CD (1 bit) + RCODE
//     (4 bits) uint16_t num_questions; uint16_t num_answers; uint16_t
//     num_authority_rr; uint16_t num_additional_rr;
// } dns_header;

typedef struct {
  eth_header eth_hdr;
  network_layer_union net_hdr;
  transport_layer_union trans_hdr;
} packet_t;

int packetParser(const u_char *packet, int packet_len)
/*
@param const u_char *packet : pointer to packet data - raw bytes of captured
packet
@param int packet_len : length of the packet in bytes
*/
{
  /* TODO: Parsing logic
       -ethernet header (done)
       -ipv4 header (done)
       -ipv6 header (done)

       -tcp header (next header = 6) (done)
       -udp header (next header = 17) (done)
       -icmpv6 header (next header = 58) (done)
       -dns header (tcp/udp port 53) (finish later)
  */
  // Print entire raw hex of packet
  printf("Raw packet hex dump:\n");
  int bytes_to_print = (packet_len < 66) ? packet_len : 66;  // Print up to 66 bytes or packet length, whichever is smaller
  for (int i = 0; i < bytes_to_print; i++) {
    printf("%02x ", packet[i]);
    if ((i + 1) % 16 == 0) {
      printf("\n");
    }
  }
  printf("\n");

  packet_t pkt;

  int net_layer_start = 14;
  int trans_layer_start;

  memcpy(pkt.eth_hdr.dst_mac, packet, 6);
  memcpy(pkt.eth_hdr.src_mac, packet + 6, 6);
  pkt.eth_hdr.eth_type = ntohs(*(uint16_t *)(packet + 12));

  // Print Ethernet header fields
  printf("=== Ethernet Header ===\n");
  printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         pkt.eth_hdr.dst_mac[0], pkt.eth_hdr.dst_mac[1], pkt.eth_hdr.dst_mac[2],
         pkt.eth_hdr.dst_mac[3], pkt.eth_hdr.dst_mac[4],
         pkt.eth_hdr.dst_mac[5]);
  printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", pkt.eth_hdr.src_mac[0],
         pkt.eth_hdr.src_mac[1], pkt.eth_hdr.src_mac[2], pkt.eth_hdr.src_mac[3],
         pkt.eth_hdr.src_mac[4], pkt.eth_hdr.src_mac[5]);
  printf("Ethernet Type: 0x%04x (%u)\n", pkt.eth_hdr.eth_type,
         pkt.eth_hdr.eth_type);

  if (pkt.eth_hdr.eth_type == 2048) {  // hex: 0x0800 (IPv4)
    printf("=== IPv4 Header ===\n");

    memcpy(&pkt.net_hdr.ipv4_hdr.version_ihl, packet + net_layer_start, 1);
    memcpy(&pkt.net_hdr.ipv4_hdr.service, packet + net_layer_start + 1, 1);
    memcpy(&pkt.net_hdr.ipv4_hdr.total_len, packet + net_layer_start + 2, 2);
    memcpy(&pkt.net_hdr.ipv4_hdr.identification, packet + net_layer_start + 4,
           2);
    memcpy(&pkt.net_hdr.ipv4_hdr.flags_frag_offset,
           packet + net_layer_start + 6, 2);
    memcpy(&pkt.net_hdr.ipv4_hdr.ttl, packet + net_layer_start + 8, 1);
    memcpy(&pkt.net_hdr.ipv4_hdr.protocol, packet + net_layer_start + 9, 1);
    memcpy(&pkt.net_hdr.ipv4_hdr.hdr_checksum, packet + net_layer_start + 10,
           2);
    memcpy(&pkt.net_hdr.ipv4_hdr.src_ip, packet + net_layer_start + 12, 4);
    memcpy(&pkt.net_hdr.ipv4_hdr.dst_ip, packet + net_layer_start + 16, 4);

    // Print IPv4 header fields
    printf("Version/IHL: 0x%02x\n", pkt.net_hdr.ipv4_hdr.version_ihl);
    printf("Service: 0x%02x\n", pkt.net_hdr.ipv4_hdr.service);
    printf("Total Length: %u\n", ntohs(pkt.net_hdr.ipv4_hdr.total_len));
    printf("Identification: 0x%04x\n",
           ntohs(pkt.net_hdr.ipv4_hdr.identification));
    printf("Flags/Fragment Offset: 0x%04x\n",
           ntohs(pkt.net_hdr.ipv4_hdr.flags_frag_offset));
    printf("TTL: %u\n", pkt.net_hdr.ipv4_hdr.ttl);
    printf("Protocol: %u\n", pkt.net_hdr.ipv4_hdr.protocol);
    printf("Header Checksum: 0x%04x\n",
           ntohs(pkt.net_hdr.ipv4_hdr.hdr_checksum));

    // Convert IP addresses to readable format
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = pkt.net_hdr.ipv4_hdr.src_ip;
    dst_addr.s_addr = pkt.net_hdr.ipv4_hdr.dst_ip;
    printf("Source IP: %s\n", inet_ntoa(src_addr));
    printf("Destination IP: %s\n", inet_ntoa(dst_addr));

  } else if (pkt.eth_hdr.eth_type == 34525) {  // hex: 0x86DD (IPv6)
    printf("=== IPv6 Header ===\n");
    memcpy(&pkt.net_hdr.ipv6_hdr.ver_tc_fl, packet + net_layer_start, 4);
    memcpy(&pkt.net_hdr.ipv6_hdr.payload_len, packet + net_layer_start + 4, 2);
    memcpy(&pkt.net_hdr.ipv6_hdr.next_hdr, packet + net_layer_start + 6, 1);
    memcpy(&pkt.net_hdr.ipv6_hdr.hop_limit, packet + net_layer_start + 7, 1);
    memcpy(&pkt.net_hdr.ipv6_hdr.src_addr, packet + net_layer_start + 8, 16);
    memcpy(&pkt.net_hdr.ipv6_hdr.dst_addr, packet + net_layer_start + 24, 16);

    // Print IPv6 header fields
    printf("Version/Traffic Class/Flow Label: 0x%08x\n",
           ntohl(pkt.net_hdr.ipv6_hdr.ver_tc_fl));
    printf("Payload Length: %u\n", ntohs(pkt.net_hdr.ipv6_hdr.payload_len));
    printf("Next Header: %u\n", pkt.net_hdr.ipv6_hdr.next_hdr);
    printf("Hop Limit: %u\n", pkt.net_hdr.ipv6_hdr.hop_limit);

    // Convert IPv6 addresses to readable format
    char src_ipv6[INET6_ADDRSTRLEN], dst_ipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &pkt.net_hdr.ipv6_hdr.src_addr, src_ipv6,
              INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &pkt.net_hdr.ipv6_hdr.dst_addr, dst_ipv6,
              INET6_ADDRSTRLEN);
    printf("Source IPv6: %s\n", src_ipv6);
    printf("Destination IPv6: %s\n", dst_ipv6);
  } else if (pkt.eth_hdr.eth_type == 2054) {  // hex: 0x0806 (ARP)
    memcpy(&pkt.net_hdr.arp_hdr.hardware_type, packet + net_layer_start, 2);
    printf("\n ARP HARDWARE TYPE: %x \n",
           ntohs(pkt.net_hdr.arp_hdr.hardware_type));
    memcpy(&pkt.net_hdr.arp_hdr.protocol_type, packet + net_layer_start + 2, 2);
    printf("\n ARP PROTOCOL TYPE: %x \n", pkt.net_hdr.arp_hdr.protocol_type);
    memcpy(&pkt.net_hdr.arp_hdr.hardware_len, packet + net_layer_start + 4, 1);
    printf("\n ARP HARDWARE LENGTH: %x \n", pkt.net_hdr.arp_hdr.hardware_len);
    memcpy(&pkt.net_hdr.arp_hdr.protocol_len, packet + net_layer_start + 5, 1);
    printf("\n ARP PROTOCOL LENGTH: %x \n", pkt.net_hdr.arp_hdr.protocol_len);
    memcpy(&pkt.net_hdr.arp_hdr.operation, packet + net_layer_start + 6, 2);
    printf("\n ARP OPCODE: %x \n", ntohs(pkt.net_hdr.arp_hdr.operation));
    memcpy(&pkt.net_hdr.arp_hdr.sha, packet + net_layer_start + 8, 6);
    memcpy(&pkt.net_hdr.arp_hdr.spa, packet + net_layer_start + 14, 4);
    memcpy(&pkt.net_hdr.arp_hdr.tha, packet + net_layer_start + 18, 6);
    memcpy(&pkt.net_hdr.arp_hdr.tpa, packet + net_layer_start + 24, 4);

    // Convert IP addresses to readable format
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = pkt.net_hdr.arp_hdr.spa;
    dst_addr.s_addr = pkt.net_hdr.arp_hdr.tpa;
    printf("\n ARP SENDER HARDWARE ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt.net_hdr.arp_hdr.sha[0], pkt.net_hdr.arp_hdr.sha[1], pkt.net_hdr.arp_hdr.sha[2],
           pkt.net_hdr.arp_hdr.sha[3], pkt.net_hdr.arp_hdr.sha[4], pkt.net_hdr.arp_hdr.sha[5]);
    printf("\n ARP SENDER IP: %s\n", inet_ntoa(src_addr));
    printf("\n ARP TARGET HARDWARE ADDR: %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt.net_hdr.arp_hdr.tha[0], pkt.net_hdr.arp_hdr.tha[1], pkt.net_hdr.arp_hdr.tha[2],
           pkt.net_hdr.arp_hdr.tha[3], pkt.net_hdr.arp_hdr.tha[4], pkt.net_hdr.arp_hdr.tha[5]);
    printf("\n ARP TARGET IP: %s\n", inet_ntoa(dst_addr));
  }

  if (pkt.net_hdr.ipv4_hdr.protocol == 6) {
    printf("\n < ! - - - - - TCP HEADER IPv4 - - - - - ! >\n");
    uint8_t ihl = pkt.net_hdr.ipv4_hdr.version_ihl &
                  0x0f;  // bit mask rightmost 4 bits for IHL
    printf("IHL: %x\n", ihl);
    trans_layer_start = (ihl * 32) / 8;
    printf(" Trans layer start: %d\n", trans_layer_start);
    memcpy(&pkt.trans_hdr.tcp_hdr.src_port,
           packet + net_layer_start + trans_layer_start, 2);
    printf("SRC PORT: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.src_port));
    memcpy(&pkt.trans_hdr.tcp_hdr.dst_port,
           packet + net_layer_start + trans_layer_start + 2, 2);
    printf("DST PORT: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.dst_port));
    memcpy(&pkt.trans_hdr.tcp_hdr.sequence_num,
           packet + net_layer_start + trans_layer_start + 4, 4);
    printf("Sequence Number (raw): %x\n",
           ntohl(pkt.trans_hdr.tcp_hdr.sequence_num));
    memcpy(&pkt.trans_hdr.tcp_hdr.ack_num,
           packet + net_layer_start + trans_layer_start + 8,
           4);  // issue: ntohs only goes up to 16 bits, needed to change to
                // ntohl (32 bits) [fixed]
    printf("ACK NUM: %x\n", ntohl(pkt.trans_hdr.tcp_hdr.ack_num));
    memcpy(&pkt.trans_hdr.tcp_hdr.data_offset_reserved,
           packet + net_layer_start + trans_layer_start + 12, 1);
    printf("Data offset + reserved: %x\n",
           ntohs(pkt.trans_hdr.tcp_hdr.data_offset_reserved));
    memcpy(&pkt.trans_hdr.tcp_hdr.flags,
           packet + net_layer_start + trans_layer_start + 13, 1);
    printf("Flags: %x\n", pkt.trans_hdr.tcp_hdr.flags);
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x01) == 0x01) printf("-FIN\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x02) == 0x02) printf("-SYN\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x04) == 0x04) printf("-RESET\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x08) == 0x08) printf("-PUSH\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x10) == 0x10) printf("-ACK\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x20) == 0x20) printf("-URGENT\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x40) == 0x40) printf("-ECE\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x80) == 0x80) printf("-CWR\n");
    memcpy(&pkt.trans_hdr.tcp_hdr.window_size,
           packet + net_layer_start + trans_layer_start + 14, 2);
    printf("\nWindow Size: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.window_size));
    memcpy(&pkt.trans_hdr.tcp_hdr.checksum,
           packet + net_layer_start + trans_layer_start + 16, 2);
    printf("\n Checksum: %x \n", ntohs(pkt.trans_hdr.tcp_hdr.checksum));
    memcpy(&pkt.trans_hdr.tcp_hdr.urgent_pointer,
           packet + net_layer_start + trans_layer_start + 18, 2);
    printf("\n Urgent Pointer: %x \n",
           ntohs(pkt.trans_hdr.tcp_hdr.urgent_pointer));

  } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 6) {
    printf("\n < ! - - - - - TCP HEADER IPv6 - - - - - ! >\n");
    trans_layer_start = 40;
    printf(" Trans layer start: %d\n", trans_layer_start);
    memcpy(&pkt.trans_hdr.tcp_hdr.src_port,
           packet + net_layer_start + trans_layer_start, 2);
    printf("SRC PORT: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.src_port));
    memcpy(&pkt.trans_hdr.tcp_hdr.dst_port,
           packet + net_layer_start + trans_layer_start + 2, 2);
    printf("DST PORT: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.dst_port));
    memcpy(&pkt.trans_hdr.tcp_hdr.sequence_num,
           packet + net_layer_start + trans_layer_start + 4, 4);
    printf("Sequence Number (raw): %x\n",
           ntohl(pkt.trans_hdr.tcp_hdr.sequence_num));
    memcpy(&pkt.trans_hdr.tcp_hdr.ack_num,
           packet + net_layer_start + trans_layer_start + 8,
           4);
    printf("ACK NUM: %x\n", ntohl(pkt.trans_hdr.tcp_hdr.ack_num));
    memcpy(&pkt.trans_hdr.tcp_hdr.data_offset_reserved,
           packet + net_layer_start + trans_layer_start + 12, 1);
    printf("Data offset + reserved: %x\n",
           ntohs(pkt.trans_hdr.tcp_hdr.data_offset_reserved));
    memcpy(&pkt.trans_hdr.tcp_hdr.flags,
           packet + net_layer_start + trans_layer_start + 13, 1);
    printf("Flags: %x\n", pkt.trans_hdr.tcp_hdr.flags);
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x01) == 0x01) printf("-FIN\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x02) == 0x02) printf("-SYN\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x04) == 0x04) printf("-RESET\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x08) == 0x08) printf("-PUSH\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x10) == 0x10) printf("-ACK\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x20) == 0x20) printf("-URGENT\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x40) == 0x40) printf("-ECE\n");
    if ((pkt.trans_hdr.tcp_hdr.flags & 0x80) == 0x80) printf("-CWR\n");
    memcpy(&pkt.trans_hdr.tcp_hdr.window_size,
           packet + net_layer_start + trans_layer_start + 14, 2);
    printf("\nWindow Size: %u\n", ntohs(pkt.trans_hdr.tcp_hdr.window_size));
    memcpy(&pkt.trans_hdr.tcp_hdr.checksum,
           packet + net_layer_start + trans_layer_start + 16, 2);
    printf("\n Checksum: %x \n", ntohs(pkt.trans_hdr.tcp_hdr.checksum));
    memcpy(&pkt.trans_hdr.tcp_hdr.urgent_pointer,
           packet + net_layer_start + trans_layer_start + 18, 2);
    printf("\n Urgent Pointer: %x \n",
           ntohs(pkt.trans_hdr.tcp_hdr.urgent_pointer));
  } else if (pkt.net_hdr.ipv4_hdr.protocol == 17 ||
             pkt.net_hdr.ipv6_hdr.next_hdr == 17) {
    if (pkt.net_hdr.ipv4_hdr.protocol == 17) {
      trans_layer_start = 20;
    } else {
      trans_layer_start = 40;
    }
    printf("\n < ! - - - - - UDP HEADER - - - - - ! >\n");
    memcpy(&pkt.trans_hdr.udp_hdr.src_port,
           packet + net_layer_start + trans_layer_start, 2);
    printf("Source Port: %u\n", ntohs(pkt.trans_hdr.udp_hdr.src_port));
    memcpy(&pkt.trans_hdr.udp_hdr.dst_port,
           packet + net_layer_start + trans_layer_start + 2, 2);
    printf("Destination Port: %u\n", ntohs(pkt.trans_hdr.udp_hdr.dst_port));
    memcpy(&pkt.trans_hdr.udp_hdr.len,
           packet + net_layer_start + trans_layer_start + 4, 2);
    printf("Length: %u\n", ntohs(pkt.trans_hdr.udp_hdr.len));
    memcpy(&pkt.trans_hdr.udp_hdr.checksum,
           packet + net_layer_start + trans_layer_start + 6, 2);
    printf("Checksum: %x\n", ntohs(pkt.trans_hdr.udp_hdr.checksum));
  } else if (pkt.net_hdr.ipv6_hdr.next_hdr == 58) {
    trans_layer_start = 40;
    printf("\n < ! - - - - - ICMP HEADER - - - - - ! >\n");
    memcpy(&pkt.trans_hdr.icmp_hdr.type,
           packet + net_layer_start + trans_layer_start, 1);
    printf("Type: %u\n", pkt.trans_hdr.icmp_hdr.type);
    memcpy(&pkt.trans_hdr.icmp_hdr.code,
           packet + net_layer_start + trans_layer_start + 1, 1);
    printf("Code: %u\n", pkt.trans_hdr.icmp_hdr.code);
    memcpy(&pkt.trans_hdr.icmp_hdr.checksum,
           packet + net_layer_start + trans_layer_start + 2, 2);
    printf("Checksum: %x\n", ntohs(pkt.trans_hdr.icmp_hdr.checksum));
  }

  // void *payload;
  // int payload_len;

  return 0;
}