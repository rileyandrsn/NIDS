#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_BUFFER_SIZE 65536 // Maximum packet buffer size in bytes 

int is_valid_dev(char *device,char *error_buffer)
{
/* - Initialize pcap_if_t pointer pointing toward head node of all devices - */

pcap_if_t *all_devices_ptr; // Initialize alldevs_ptr as a pcap_if_t pointer pointing toward head node of linked list storing all devices
int pcap_result = pcap_findalldevs(&all_devices_ptr, error_buffer); // Returns -1 on error, 0 otherwise
if(pcap_result == 0){
    printf("Successfully initialized alldevs_ptr\n");
    }else{
    perror("Unsuccessfully initialized alldevs_ptr :(");
    exit(EXIT_FAILURE);
    }

/* - is_dev: initialized to 0 - set to 1 if device corresponding to users argument following "-i" is valid - */
    
int is_dev = 0;
/* - temp pointer to iterate through all devices -> compare name of device indicated in command argument to see if valid - */
pcap_if_t *temp_ptr = all_devices_ptr; 
while(temp_ptr != NULL){
    if(strcmp(device, temp_ptr->name) == 0){
        is_dev = 1;
        printf("Found device: %s\n", temp_ptr->name);
        break;
    }
    temp_ptr = temp_ptr->next; // iterate to next node in linked list of all devices
}
    
/* -  If device is NOT found, display list of available devices for user to add as an argument following "-i" - */

if(!is_dev){
    printf("Device %s not found. Available devices:\n", device);
    temp_ptr = all_devices_ptr;
    while(temp_ptr != NULL){
        printf("  %s", temp_ptr->name);
        if(temp_ptr->description)
            printf(" (%s)", temp_ptr->description);
            printf("\n");
            temp_ptr = temp_ptr->next;
        }
    pcap_freealldevs(all_devices_ptr);
    return -1;
}    
// Free the all_devices_ptr before returning
pcap_freealldevs(all_devices_ptr);
return is_dev;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet){
    printf("Packet:%p |  Length: %d bytes\n", packet,hdr->len);
}


int packetSniffer(void){
    char error_buffer[PACKET_BUFFER_SIZE]; // Size defined as 256
    char *device = "en0"; // Default device name <! - TEMPORARY - !>

    int is_dev = is_valid_dev(device, error_buffer);
    if(is_dev == 0){
        return -1;
    }

    pcap_t *capture_handle;
    capture_handle = pcap_open_live(device, PACKET_BUFFER_SIZE, 1, 1000, error_buffer);
    if(capture_handle == NULL){
        printf("Error opening device %s: %s\n", device, error_buffer);
        return -1;
    }
    
    int p_loop = pcap_loop(capture_handle, -1, packet_handler, NULL);
    if(p_loop == -1){
        printf("Error in pcap_loop");
    }

    pcap_close(capture_handle); // Close packet capture handle capture_handle

    return 0;
}


