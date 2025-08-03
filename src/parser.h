#ifndef PARSER_H
#define PARSER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sniffer.h"

// Struct definitions

typedef struct {
  uint8_t dst_mac[6]; // Destination Mac Address (6 bytes)
  uint8_t src_mac[6]; // Source Mac Address (6 bytes)
  uint16_t eth_type; // EtherType (2 bytes)
} eth_header;

typedef struct {
  uint8_t version_ihl; // Version constant 4 (4 bits) + Internet Header Length (IHL)
  uint8_t service; // Differentiated services (first six bits) + Explicit Congestion Notification (last two bits)
  uint16_t total_len; // Total length of packet in bytes (2 bytes)
  uint16_t identification; // Fragmentation identification (2 bytes)
  uint16_t flags_frag_offset; // Flags (first 3 bits), fragment offset (last 13 bits)
  uint8_t ttl; // Time to live (1 byte)
  uint8_t protocol; // Transport layer protocol (1 byte)
  uint16_t hdr_checksum; // Checksum of the header (2 bytes)
  uint32_t src_ip; // Source IPv4 Address (4 bytes)
  uint32_t dst_ip; // Destination IPv4 Address (4 bytes)
} ipv4_header;

typedef struct {
  uint32_t ver_tc_fl; // Version (4 bits) + Traffic Class (6 + 2 bits) + Flow Label (20 bits)
  uint16_t payload_len; // Size of payload in bytes (2 bytes)
  uint8_t next_hdr; // Transport layer protocol/ extension header
  uint8_t hop_limit; // Time to live
  struct in6_addr src_addr; // Source IPv6 Address (16 bytes)
  struct in6_addr dst_addr; // Destination IPv6 Address (16 bytes)
} ipv6_header;

typedef struct {
  uint16_t hardware_type; // Specifies network link protocol type (2 bytes)
  uint16_t protocol_type; // Specifies internetwork protocol for which the ARP request is intended (2 bytes)
  uint8_t hardware_len; // Length (in bytes) of a hardware address (1 byte)
  uint8_t protocol_len; // Length (in bytes) of internetwork address (1 byte)
  uint16_t operation; // Specifies the operation that sender is performing
  uint8_t sha[6]; // Sender Hardware Address - media address of sender (6 bytes)
  uint32_t spa; // Sender Protocol Address - internetwork address of sender (4 bytes)
  uint8_t tha[6]; // Target Hardware Address - media address of intended receiver (6 bytes)
  uint32_t tpa; // Target Protocol Address - internetwork address of intended receiver (4 bytes)
} __attribute__((packed)) arp_header;

typedef union {
  ipv4_header ipv4_hdr; // IPv4 header struct
  ipv6_header ipv6_hdr; // IPv6 header struct
  arp_header arp_hdr; // ARP header struct
} network_layer_union; // Union for storing different network layer headers

typedef struct {
  uint16_t src_port; // Source/sending port (2 bytes)
  uint16_t dst_port; // Destination/receiving port (2 bytes)
  uint32_t sequence_num; // Sequence number (4 bytes)
  uint32_t ack_num; // Acknowledgement number (4 bytes)
  uint8_t data_offset_reserved; // Data offset (first 4 bits) specifies the size of the TCP header in 32-bit words; Reserved (last 4 bits)
  uint8_t flags; // 8 1-bit flags (1 total byte)
  uint16_t window_size; // Size of the receive window (2 bytes)
  uint16_t checksum; // Used for error-checking TCP header, payload, and an IP pseudo-header (2 bytes)
  uint16_t urgent_pointer; // Indicates end of urgent data in a TCP segment when URG flag is set
} tcp_header;

typedef struct {
  uint16_t src_port; // Source/sending port (2 bytes)
  uint16_t dst_port; // Destination/receiving port (2 bytes)
  uint16_t len; // Length in bytes of the UDP datagram (2 bytes)
  uint16_t checksum; // Used for error-checking of the header and data
} udp_header;

typedef struct {
  uint8_t type; // Type of message (1 byte)
  uint8_t code; // Depends on type, provides additional level of message granularity
  uint16_t checksum; // Provides minimal level of integrity for ICMP message
} icmp_header;

typedef union {
  tcp_header tcp_hdr; // TCP header struct
  udp_header udp_hdr; // UDP header struct
  icmp_header icmp_hdr; // ICMP header struct
} transport_layer_union;

/*packet struct of packet_t type with 
-ethernet header 
-one network-layer header (IPV4/IPv6/ARP)
-one transport-layer header (TCP,UDP,ICMP)
*/
typedef struct {
  eth_header eth_hdr;
  network_layer_union net_hdr;
  transport_layer_union trans_hdr;
} packet_t;

// Function declarations

void print_hex_dump(const u_char *packet, int packet_len);
void parse_ethernet_header(const u_char *packet, packet_t *pkt);
void parse_ipv4_header(const u_char *packet, packet_t *pkt, int offset);
void parse_ipv6_header(const u_char *packet, packet_t *pkt, int offset);
void parse_arp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_tcp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_udp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_icmp_header(const u_char *packet, packet_t *pkt, int offset);

int packetParser(const u_char *packet, int packet_len);
/*
@param const u_char *packet : pointer to packet data - raw bytes of captured
packet
@param int packet_len : length of the packet in bytes
*/

#endif  // PARSER_H