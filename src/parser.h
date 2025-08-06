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
void parse_hex_input(char *input, int len, rule_t *rule);

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
