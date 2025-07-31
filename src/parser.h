#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include "sniffer.h"
#include <stdint.h>

// Function declarations


int packetParser(const u_char *packet, int packet_len);
/*
@param const u_char *packet : pointer to packet data - raw bytes of captured packet
@param int packet_len : length of the packet in bytes
*/

#endif // PARSER_H