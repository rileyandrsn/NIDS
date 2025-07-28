#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
//char *device; // Name of device (i.e. eth0)
char errbuff[PCAP_ERRBUF_SIZE]; // Size defined as 256

//Definition: pcap_if_t
/**********************
typdef struct pcap_if{
    struct pcap_if *next;
    char *name;
    char *description
}pcap_if_t;
***********************/

// Initialize alldevs_ptr as a pcap_if_t pointer pointing toward head node of linked list storing all devices
pcap_if_t *alldevs_ptr;
int pcap_fad = pcap_findalldevs(alldevs_ptr,errbuff); // Returns -1 on error, 0 otherwise
if(pcap_fad == 0){
    printf("Successfully initialized alldevs_ptr");
}else{
    perror("Unsuccessfully initalized alldevs_ptr :(");
    exit(EXIT_FAILURE);
}

pcap_freealldevs(alldevs_ptr); // Free alldevs_ptr - pointer pointing toward head of linked list storing alldevs

}