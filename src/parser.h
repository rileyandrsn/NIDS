#ifndef PARSER_H
#define PARSER_H

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
#include "rules.h"
#include "sniffer.h"
#include "rule.h"

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
void parse_hex_input(char *input, int len, rule_t *rule);

/*
Function: void print_hex_dump(const u_char *packet, int packet_len)
Prints the raw hex stream of captured packet

Parameters:
*packet - raw u_char bytes of packet data
packet_len - length of packet in bytes

Returns: void
*/
void print_hex_dump(const u_char *packet, int packet_len);

/*
Function: void parse_ethernet_header(const u_char *packet, packet_t *pkt)
Parses packet and sets packet fields to values corresponding to ethernet header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values

Returns: void
*/
void parse_ethernet_header(const u_char *packet, packet_t *pkt);

/*
Function: void parse_*_header(const u_char *packet, packet_t *pkt, int offset)
Parses packet and sets packet fields to values corresponding to each header

Parameters:
*packet - raw u_char bytes of packet data
*pkt - packet structure to store values
offset - integer offset indicating at what byte each header starts

Returns: void
*/
void parse_ipv4_header(const u_char *packet, packet_t *pkt, int offset);
void parse_ipv6_header(const u_char *packet, packet_t *pkt, int offset);
void parse_arp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_tcp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_udp_header(const u_char *packet, packet_t *pkt, int offset);
void parse_icmp_header(const u_char *packet, packet_t *pkt, int offset);

/*
Function: void packetParser(const u_char *packet, int packet_len, rule_t *rule)

Parameters:
*packet - raw u_char bytes of packet data
packet_len - length of packet in bytes
*rule - pointer pointing toward head node of linked list storing rules

Returns: void
*/
void packetParser(const u_char *packet, int packet_len, rule_t *rule);

#endif // PARSER_H
