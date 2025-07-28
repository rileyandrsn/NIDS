#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

int packetSniffer(void){
    char errbuff[PCAP_ERRBUF_SIZE]; // Size defined as 256
    char *device = "en0"; // Default device name
    
    // Definition: pcap_if_t
    /**********************
    typedef struct pcap_if{
        struct pcap_if *next;
        char *name;
        char *description
    }pcap_if_t;
    ***********************/

    // Definition: pcap_pkthdr
    /*
    struct pcap_pkthdr{
        struct timeval ts; // time stamp
        bpf_u_int32 caplen; // length of portion present in data
        bpf_u_int32 len; // length f this packet prior to any slicing
    }
    */

    // Initialize alldevs_ptr as a pcap_if_t pointer pointing toward head node of linked list storing all devices
    pcap_if_t *alldevs_ptr;
    int pcap_fad = pcap_findalldevs(&alldevs_ptr, errbuff); // Returns -1 on error, 0 otherwise
    if(pcap_fad == 0){
        printf("Successfully initialized alldevs_ptr\n");
    }else{
        perror("Unsuccessfully initialized alldevs_ptr :(");
        exit(EXIT_FAILURE);
    }
    
    int isDev = 0;
    pcap_if_t *temp_ptr = alldevs_ptr;
    while(temp_ptr != NULL){
        if(strcmp(device, temp_ptr->name) == 0){
            isDev = 1;
            printf("Found device: %s\n", temp_ptr->name);
            break;
        }
        temp_ptr = temp_ptr->next;
    }
    
    if(!isDev){
        printf("Device %s not found. Available devices:\n", device);
        temp_ptr = alldevs_ptr;
        while(temp_ptr != NULL){
            printf("  %s", temp_ptr->name);
            if(temp_ptr->description)
                printf(" (%s)", temp_ptr->description);
            printf("\n");
            temp_ptr = temp_ptr->next;
        }
    }

    pcap_freealldevs(alldevs_ptr); // Free alldevs_ptr - pointer pointing toward head of linked list storing alldevs
    
    return 0;
}