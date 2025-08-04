#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "cli.h"

const int INFINITE_CNT = -1;
char error_buffer[PCAP_ERRBUF_SIZE];

int validate_dev(char *device);
void packet_handler(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *packet);
int packetSniffer(char *device) {

int result = validate_dev(device);
if(result == 0){
    fprintf(stderr, "Error finding device: %s", device);
    exit(EXIT_FAILURE);
}
pcap_t *capture_handle = pcap_create(device,error_buffer);
if(capture_handle == NULL){
    fprintf(stderr, "Error creating capture handle with device: %s\nError buffer: %s\n", device,error_buffer);
    exit(EXIT_FAILURE);
}

//todo: set options using cli args
pcap_set_snaplen(capture_handle, PACKET_BUFFER_SIZE); // Amount of data captured for each frame in bytes
pcap_set_promisc(capture_handle, 1); // Sets whether promiscuous mode should be set on capture handle, set on non-zero promisc arg
pcap_set_timeout(capture_handle, 1000); // Packet capture timeout in milliseconds (ms)
pcap_set_buffer_size(capture_handle, 1024 * 1024); // Set buffer size (in bytes) of how much memory kernel should allocate for buffer
pcap_set_tstamp_precision(capture_handle, PCAP_TSTAMP_PRECISION_NANO); // Packet timestamp precision down to nanoseconds
pcap_set_tstamp_type(capture_handle, PCAP_TSTAMP_ADAPTER); // Timestamp source is network adapter's hardware clock
pcap_set_datalink(capture_handle, DLT_EN10MB); // Set datalink to Ethernet (10Mb)
pcap_set_rfmon(capture_handle, 0); // Sets whether monitor mode should be set on capture handle, set on non-zero rfmon arg
pcap_set_immediate_mode(capture_handle, 0); // Sets whether immediate mode should be set on capture handle, set on non-zero immediate_mode arg
// todo: ifdef __linux__ pcap_set_protocol_linux()
result = pcap_activate(capture_handle);
if(result != 0){
    fprintf(stderr,"Error activating handle\n");
    exit(EXIT_FAILURE);
}
result = pcap_loop(capture_handle, INFINITE_CNT, packet_handler, NULL);
if(result != 0 ){
    fprintf(stderr,"Error processing packets\n");
    exit(EXIT_FAILURE);
}
pcap_close(capture_handle);

return 0;
}

int validate_dev(char *device){
    pcap_if_t *dev_ptr;
    int result = pcap_findalldevs(&dev_ptr,error_buffer); // Returns 0 on success, PCAP_ERROR on failure
    if(result == PCAP_ERROR){
        fprintf(stderr,"Error finding device: %s",error_buffer);
        exit(EXIT_FAILURE);
    }
    pcap_if_t *temp = dev_ptr;
    while(temp != NULL){
        if(strcmp(temp->name, device) == 0){
            return 1; 
        }else{
            temp = temp->next;
        }
    }
    pcap_freealldevs(dev_ptr);
    return 0; 
}

void packet_handler(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *packet){
    packetParser(packet, pkt_hdr->len);
}