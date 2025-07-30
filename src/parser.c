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

typedef union {
    ipv4_header ipv4_hdr;
    ipv6_header ipv6_hdr;
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

typedef struct { // IPv6 next_hdr = 0
    uint8_t next_hdr;
    uint8_t hdr_ext_len;
    uint8_t options[];
} ipv6_ext_hop;

typedef struct { // IPv6 next_hdr = 43
    uint8_t next_hdr;
    uint8_t hdr_ext_len;
    uint8_t routing_type;
    uint8_t segments_left;
    uint8_t data[];
} ipv6_ext_routing;

typedef struct { // IPv6 next_hdr = 44
    uint8_t next_hdr;
    uint8_t reserved;
    uint16_t fragoff_res2_m; // Fragment offset (13 bits), Reserved (2 bits), M Flag (1 bit)
    uint32_t identification; 
} ipv6_ext_frag;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
    uint8_t data[];
} udp_header;

typedef struct {
    uint16_t transaction_id;
    uint16_t flags; // QR (1 bit) + OPCODE (4 bits) + AA (1 bit) + TC (1 bit) + RD (1 bit) + RA (1 bit) + Z (1 bit) + AD (1 bit) + CD (1 bit) + RCODE (4 bits)
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authority_rr;
    uint16_t num_additional_rr;
} dns_header;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
    uint8_t data[];
} icmp_header;

typedef struct {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed)) arp_header; // Ensures structure is packed tightly (no compiler-inserted padding)

typedef struct {
    eth_header eth_hdr;
    ip_header_union ip_hdr;
} packet_t;


int packetParser(const u_char *packet)
/*
@param const u_char *packet : pointer to packet data - raw bytes of captured packet
*/
{
    // TODO: Parsing logic
    packet_t pkt;
    int internet_layer_start = 14;

    memcpy(pkt.eth_hdr.dst_mac,packet,6);
    memcpy(pkt.eth_hdr.src_mac,packet+6,6);
    pkt.eth_hdr.eth_type = ntohs(*(uint16_t *)(packet + 12));
    printf("%hu",pkt.eth_hdr.eth_type);

    if(pkt.eth_hdr.eth_type == 2048){ // hex: 0x0800 (IPv4)
        memcpy(&pkt.ip_hdr.ipv4_hdr.version_ihl,packet+internet_layer_start,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.service,packet+internet_layer_start+1,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.total_len,packet+internet_layer_start+1,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.identification,packet+internet_layer_start+2,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.flags_frag_offset,packet+internet_layer_start+2,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.ttl,packet+internet_layer_start+2,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.protocol,packet+internet_layer_start+1,1);
        memcpy(&pkt.ip_hdr.ipv4_hdr.hdr_checksum,packet+internet_layer_start+1,2);
        memcpy(&pkt.ip_hdr.ipv4_hdr.src_ip,packet+internet_layer_start+2,4);
        memcpy(&pkt.ip_hdr.ipv4_hdr.dst_ip,packet+internet_layer_start+4,4);

    } else if(pkt.eth_hdr.eth_type == 34525){ // hex: 0x86DD (IPv6)
        memcpy(&pkt.ip_hdr.ipv6_hdr.ver_tc_fl,packet+internet_layer_start,4);
        memcpy(&pkt.ip_hdr.ipv6_hdr.payload_len,packet+internet_layer_start+4,2);
        memcpy(&pkt.ip_hdr.ipv6_hdr.next_hdr,packet+internet_layer_start+2,1);
        memcpy(&pkt.ip_hdr.ipv6_hdr.hop_limit,packet+internet_layer_start+1,1);
        memcpy(&pkt.ip_hdr.ipv6_hdr.hop_limit,packet+internet_layer_start+1,1);
        memcpy(&pkt.ip_hdr.ipv6_hdr.src_addr,packet+internet_layer_start+1,16);
        memcpy(&pkt.ip_hdr.ipv6_hdr.dst_addr,packet+internet_layer_start+16,16);
    }
    //void *payload;
    //int payload_len;



    return 0;
}