#include <stdio.h>
#include "sniffer.h"

int packetParser(const struct pcap_pkthdr *hdr, const u_char *packet)
/*
@param const struct pcap_pkthdr *hdr:   
    - struct timeval ts; // time stamp
    - bpf_u_int32 caplen // length of portion present in data
    - bpf_u_int32 len; // length of packet before slicing

@param const u_char *packet:
*/
{
printf("%p\n",packet);
printf("%s",*packet);
}