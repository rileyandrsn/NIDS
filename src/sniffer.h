#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Function declaration
int packetSniffer(void);

#endif // SNIFFER_H
