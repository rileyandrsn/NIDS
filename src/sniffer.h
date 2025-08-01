#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Constants
#define PACKET_BUFFER_SIZE 65536  // Maximum packet buffer size in bytes

// Function declarations

int is_valid_dev(char *device, char *error_buffer);
/* <! - Checks if the device user indicates with "-i" flag is a valid network
 * interface controller - !> */
/*
@param *device : Derefrenced pointer - name of device user specified
@param error_buffer : Error buffer (256)
@return int: is_dev
*/

void packet_handler(u_char *args, const struct pcap_pkthdr *hdr,
                    const u_char *packet);
/* <! - Displays packet address and size in bytes - !> */
/*
@param args : User data
@param *hdr : Packet header
@param *packet : Packet bytes
*/

int packetSniffer(void);
/* <! - Validates a network interface device (NIC)
      - Opens a live packet capture session on respective NIC
      - Continuously processes incoming packets until stop or an error occurs. -
   !>*/

#endif  // SNIFFER_H
