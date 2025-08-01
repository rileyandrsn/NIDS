#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

#define PACKET_BUFFER_SIZE 65536  // Maximum packet buffer size in bytes

int is_valid_dev(char *device, char *error_buffer)
/* <! - Checks if the device user indicates with "-i" flag is a valid network
   interface controller - !>*/
/*
@param *device : Derefrenced pointer - name of device user specified
@param error_buffer : Error buffer (256)
@return int: is_dev
*/
{
  pcap_if_t *all_devices_ptr;  // Initialize pcap_if_t pointer "all_devices_ptr"
                               // pointing toward head node of all devices
  int pcap_result = pcap_findalldevs(
      &all_devices_ptr, error_buffer);  // Returns -1 on error, 0 otherwise
  if (pcap_result == 0) {
    printf("Successfully initialized all_devices_ptr\n");
  } else {
    perror("Unsuccessfully initialized all_devices_ptr :(");
    exit(EXIT_FAILURE);
  }

  int is_dev = 0;  // is_dev: Initialized to 0 - set to 1 if device
                   // corresponding to users argument following "-i" is valid
  pcap_if_t *temp_ptr =
      all_devices_ptr;  // Temp pointer to iterate through all devices ->
                        // compare name of device indicated in command argument
                        // to see if valid
  while (temp_ptr != NULL) {
    if (strcmp(device, temp_ptr->name) ==
        0) {  // IF: device indicated by user is a member of "findalldevs"
              // linked list -> is_dev = 1: valid device
      is_dev = 1;
      printf("Found device: %s\n", temp_ptr->name);
      break;
    }
    temp_ptr =
        temp_ptr->next;  // Iterate to next node in linked list of all devices
  }

  if (!is_dev) {  // IF: device is NOT found, display list of available devices
                  // for user to add as an argument
    printf("Device %s not found. Available devices:\n", device);
    temp_ptr = all_devices_ptr;
    while (temp_ptr != NULL) {
      printf("%s\n", temp_ptr->name);
      temp_ptr = temp_ptr->next;
    }
    pcap_freealldevs(all_devices_ptr);
    return is_dev;
  }
  // Free all_devices_ptr before returning
  pcap_freealldevs(all_devices_ptr);
  return is_dev;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr,
                    const u_char *packet)
/* <! - Displays packet address and size in bytes - !> */
/*
@param args : User data
@param *hdr : Packet header
@param *packet : Packet bytes
*/
{
  printf("\n\nThis is a packet: Packet:%p |  Length: %d bytes\n", packet,
         hdr->len);
  packetParser(packet, hdr->len);
}

int packetSniffer(void)
/* <! - Validates a network interface device (NIC)
      - Opens a live packet capture session on respective NIC
      - Continuously processes incoming packets until stop or an error occurs. -
   !>*/
{
  char error_buffer[PACKET_BUFFER_SIZE];  // Size defined as 256
  char *device = "en0";  // Default device name <! - TEMPORARY - !>

  int is_dev = is_valid_dev(device, error_buffer);
  if (is_dev == 0) {
    return -1;  // NOT a valid device
  }

  pcap_t *capture_handle;  // Packet capture handle
  capture_handle =
      pcap_open_live(device, PACKET_BUFFER_SIZE, 1, 1000, error_buffer);
  if (capture_handle == NULL) {
    printf("Error opening device %s: %s\n", device, error_buffer);
    return -1;
  }

  int p_loop = pcap_loop(capture_handle, -1, packet_handler, NULL);
  if (p_loop == -1) {
    printf("Error in pcap_loop");
  }

  pcap_close(capture_handle);  // Close packet capture handle capture_handle

  return 0;
}