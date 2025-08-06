#ifndef PACKET_H
#define PACKET_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>

// --- Struct definitions ---

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
    char proto[8];
} packet_t;

#endif // PACKET_H