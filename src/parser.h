#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>

int packetParser(const struct pcap_pkthdr *hdr, const u_char *packet);

#endif // PARSER_H