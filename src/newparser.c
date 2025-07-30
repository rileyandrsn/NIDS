#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include "sniffer.h"
#include <stdint.h>

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct ipv4_header {
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
};

struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};



struct packet_data_ipv6 {
    uint32_t ver_tc_fl; // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

struct ipv6_ext_hop{ // IPv6 next_hdr = 0
    uint8_t next_hdr;
    uint8_t hdr_ext_len;
    uint8_t options[];
};

struct ipv6_ext_routing{ // IPv6 next_hdr = 43
    uint8_t next_hdr;
    uint8_t hdr_ext_len;
    uint8_t routing_type;
    uint8_t segments_left;
    uint8_t data[];
};

struct ipv6_ext_frag{ // IPv6 next_hdr = 44
    uint8_t next_hdr;
    uint8_t reserved;
    uint16_t fragoff_res2_m; // Fragment offset (13 bits), Reserved (2 bits), M Flag (1 bit)
    uint32_t identification; 
};

struct packet_data_udp{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
    uint8_t data[];
};

struct packet_data_dns{
    uint16_t transaction_id;
    uint16_t flags; // QR (1 bit) + OPCODE (4 bits) + AA (1 bit) + TC (1 bit) + RD (1 bit) + RA (1 bit) + Z (1 bit) + AD (1 bit) + CD (1 bit) + RCODE (4 bits)
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authority_rr;
    uint16_t num_additional_rr;
};

struct packet_data_icmp{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header;
    uint8_t data[];
};

struct packet_data_arp{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed)); // Ensures structure is packed tightly (no compiler-inserted padding)


int packetParser(const struct pcap_pkthdr *hdr, const u_char *packet)
{
    void *payload;
    int payload_len;
}