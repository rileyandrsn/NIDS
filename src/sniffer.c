#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

#define PACKET_BUFFER_SIZE 65536  // Maximum packet buffer size in bytes

int packetSniffer(void) {
    char error_buffer[PCAP_ERRBUF_SIZE];  // Standard pcap error buffer size
    char *device = "en0";  // Default device name

    // Validate the network interface device
    int is_dev = is_valid_dev(device, error_buffer);
    if (is_dev == 0) {
        printf("Invalid device specified\n");
        return -1;
    }
    // Open live packet capture session
    pcap_t *capture_handle = pcap_open_live(device, PACKET_BUFFER_SIZE, 1, 1000, error_buffer);
    if (capture_handle == NULL) {
        printf("Error opening device\n");
        return -1;
    }
    int p_loop = pcap_loop(capture_handle, -1, packet_handler, NULL);
    printf("Starting packet capture on device: %s\n", device);
    printf("Press Ctrl+C to stop capture\n");
    printf("\n\n");
    if (p_loop == -1) {
        printf("Error in pcap_loop\n");
        pcap_close(capture_handle);
        return -1;
    }
    pcap_close(capture_handle);
    printf("Packet capture stopped\n");

    return 0;
}

int is_valid_dev(char *device, char *error_buffer) {
    pcap_if_t *all_devices_ptr;  // Pointer to head node of all devices list
    int pcap_result = pcap_findalldevs(&all_devices_ptr, error_buffer);
    if (pcap_result != 0) {
        perror("Failed to initialize device list");
        exit(EXIT_FAILURE);
    }

    int is_dev = 0;  // Set to 1 if device is found
    pcap_if_t *temp_ptr = all_devices_ptr;
    
    while (temp_ptr != NULL) {
        if (strcmp(device, temp_ptr->name) == 0) {
            is_dev = 1;
            printf("Found device: %s\n", temp_ptr->name);
            break;
        }
        temp_ptr = temp_ptr->next;
    }

    if (!is_dev) {
        printf("Device %s not found. Available devices:\n", device);
        temp_ptr = all_devices_ptr;
        while (temp_ptr != NULL) {
            printf("%s\n", temp_ptr->name);
            temp_ptr = temp_ptr->next;
        }
    }
    pcap_freealldevs(all_devices_ptr); 
    return is_dev;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
    printf("\n=== Packet Information ===\n");
    printf("Packet Address: %p\n", packet);
    printf("Packet Length: %d bytes\n", hdr->len);
    printf("Captured Length: %d bytes\n", hdr->caplen);
    packetParser(packet, hdr->len); // parser.c
}