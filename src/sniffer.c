// --- External header imports ---
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// --- Internal header imports ---
#include "parser.h"

// --- Global variables ---
char error_buffer[PCAP_ERRBUF_SIZE];
enum {
    VALID_DEV = 0,
    INVALID_DEV = -1,
    INFINITE_CNT = -1,
    ACTIVE_HANDLE = 0,
    LOOP_BREAK = 0,
    SUCCESSFULLY_SET = 0
};

// --- Function declarations ---

/*
Function: validate_dev(char *device)
Validates user specified device by checking list of all possible devices

Parameters:
*device - the name of the device user specified
Returns: int
VALID_DEV if corresponding device is found in list of capture devices
INVALID_DEV if device user specified is not a valid capture device
*/
int validate_dev(char *device)
{
    pcap_if_t *dev_ptr;
    int result = pcap_findalldevs(&dev_ptr, error_buffer); // Returns 0 on success, PCAP_ERROR on failure
    if (result == PCAP_ERROR) {
        fprintf(stderr, "Error getting all devices: %s\n", error_buffer);
        exit(EXIT_FAILURE);
    }
    pcap_if_t *temp = dev_ptr;
    while (temp != NULL) {
        if (strcmp(temp->name, device) == 0) {
            pcap_freealldevs(dev_ptr);
            return VALID_DEV;
        } else {
            temp = temp->next;
        }
    }
    pcap_freealldevs(dev_ptr);
    return INVALID_DEV;
}

/*
Function: packet_handler(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *packet)
Sends data from each packet captured in pcap_loop to be parsed

Parameters:
*args - custom argument: parsed json struct
*pkt_hdr - packet header: holds timestamp, captured length of packet, and actual length of packet
*packet - holds the raw bytes of packet data
Returns: void
*/
void packet_handler(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *packet)
{
    if (!args || !pkt_hdr || !packet) {
        fprintf(stderr, "Error setting arguments\n");
        exit(EXIT_FAILURE);
    }
    struct json_object *parsed_json = (struct json_object *)args; // Cast args back
    packetParser(packet, pkt_hdr->len, parsed_json);
}

/*
Function: set_pcap_option(int result, const char *option_name, pcap_t *handle)
Handles errors from pcap setter methods

Parameters:
result - integer return value from pcap setter method
*option_name - name of the setter type being set
*handle - capture handle being affected
Returns: void
*/
void set_pcap_option(int result, const char *option_name, pcap_t *handle)
{
    if (result != 0) {
        fprintf(stderr, "Failed to set %s: %s\n", option_name, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
}

/*
Function: configure_pcap_handle(pcap_t *capture_handle)
Configuration function for capture handle

Parameters:
*capture_handle - the capture handle to have options set
Returns: void
*/
void configure_pcap_handle(pcap_t *capture_handle)
{
    set_pcap_option(pcap_set_snaplen(capture_handle, PACKET_BUFFER_SIZE), "snaplen", capture_handle);
    set_pcap_option(pcap_set_promisc(capture_handle, 1), "promiscuous mode", capture_handle);
    set_pcap_option(pcap_set_timeout(capture_handle, 1000), "timeout", capture_handle);
    set_pcap_option(pcap_set_buffer_size(capture_handle, 1024 * 1024), "buffer size", capture_handle);
    // set_pcap_option(pcap_set_tstamp_precision(capture_handle, PCAP_TSTAMP_PRECISION_NANO), "timestamp precision", capture_handle);
    // set_pcap_option(pcap_set_tstamp_type(capture_handle, PCAP_TSTAMP_ADAPTER), "timestamp type", capture_handle);
    // set_pcap_option(pcap_set_datalink(capture_handle, DLT_EN10MB), "datalink", capture_handle);
    set_pcap_option(pcap_set_rfmon(capture_handle, 0), "rfmon", capture_handle);
    set_pcap_option(pcap_set_immediate_mode(capture_handle, 0), "immediate mode", capture_handle);
}

/*
Function: packetSniffer(char *device, struct json_object *parsed_json)
Takes user specified device, validates it, creates a capture handle for device, captures packets

Parameters:
*device - the name of the device user specified
*parsed_json - json object holding data from rules.json file
Returns: void
*/
void packetSniffer(char *device, struct json_object *parsed_json)
{
    if (!device || !parsed_json) {
        fprintf(stderr, "Invalid arguments to packetSniffer\n");
        exit(EXIT_FAILURE);
    }
    int result = validate_dev(device);
    if (result == INVALID_DEV) {
        fprintf(stderr, "Error finding device: %s\n", device);
        exit(EXIT_FAILURE);
    }
    pcap_t *capture_handle = pcap_create(device, error_buffer);
    if (capture_handle == NULL) {
        fprintf(stderr, "Error creating capture handle with device: %s\nError buffer: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    // todo: set options using cli args
    configure_pcap_handle(capture_handle);

    result = pcap_activate(capture_handle);
    if (result != ACTIVE_HANDLE) {
        fprintf(stderr, "Error activating handle\n");
        exit(EXIT_FAILURE);
    }
    result = pcap_loop(capture_handle, INFINITE_CNT, packet_handler, (u_char *)parsed_json);
    if (result != LOOP_BREAK) {
        fprintf(stderr, "Error processing packets\n");
        exit(EXIT_FAILURE);
    }
    pcap_close(capture_handle);
}
