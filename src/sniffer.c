// --- External header imports ---
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// --- Internal header imports ---
#include "parser.h"
#include "rule.h"

// --- Global variables ---
char ERR_BUFFER[PCAP_ERRBUF_SIZE];

const int VALID_DEV = 0;
const int INVALID_DEV = -1;
const int INFINITE_CNT = -1;
const int ACTIVE_HANDLE = 0;
const int LOOP_BREAK = 0;
const int SUCCESSFULLY_SET = 0;

int packet_counter = 0;

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
    int result = pcap_findalldevs(&dev_ptr, ERR_BUFFER); // Returns 0 on success, PCAP_ERROR on failure
    if (result == PCAP_ERROR) {
        fprintf(stderr, "Error getting all devices: %s\n", ERR_BUFFER);
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
*args - custom argument: pointer to head node of linked list storing rules
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
    rule_t *rule = (rule_t *)args; // Cast args back
    packet_counter++;
    printf("#%d", packet_counter);
    packetParser(packet, pkt_hdr->len, rule);
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
    set_pcap_option(pcap_set_rfmon(capture_handle, 0), "rfmon", capture_handle);
    set_pcap_option(pcap_set_immediate_mode(capture_handle, 0), "immediate mode", capture_handle);
}

/*
Function: pcap_iterator(pcap_t *handle, int count, pcap_handler callback, u_char *user)
Takes parameters to run pcap_loop, interface to allow both load_pcap_file and packetSniffer to use

Parameters:
*capture_handle - the handle to be used to capture packets
count - number of packets to be iterated over; -1 for infinite/until exhausted-of-packets
callback - function to handle functionality with each packet
*user - (u_char *) casted rule to be passed in as a custom argument

Returns: int
result - return value of pcap_loop; returns 0 if count is exhausted or file has no more available packets
*/
int pcap_iterator(pcap_t *handle, int count, pcap_handler callback, u_char *rule)
{
    int result = pcap_loop(handle, count, callback, rule);
    return result;
}

/*
Function: load_pcap_file(char *filepath, rule_t *rule)
Opens specified file designated by user and prepares a capture handle to be iterated over

Parameters:
*filepath - absolute file path designated by user
*rule - head node of linked list of rules
Returns: int
-1 - any error occurs
result - return value of pcap_iterator
*/
int load_pcap_file(char *filepath, rule_t *rule)
{
    printf(" File name: %s", filepath);
    FILE *fileptr = fopen(filepath, "r");
    if (!fileptr) {
        fclose(fileptr);
        return -1;
    }
    pcap_t *file_handle;
    file_handle = pcap_fopen_offline(fileptr, ERR_BUFFER);

    if (file_handle == NULL) {
        return -1;
    }
    printf("here");
    int result = pcap_iterator(file_handle, INFINITE_CNT, packet_handler, (u_char *)rule);
    pcap_close(file_handle);
    if (result != 0) {
        return -1;
    } else {
        return result;
    }
}

/*
Function: load_device(char *device, struct json_object *parsed_json)
Takes user specified device, validates it, creates a capture handle for device, captures packets

Parameters:
*device - the name of the device user specified
*rule - pointer to head of linked list storing rules
Returns: void
*/
void load_device(char *device, rule_t *rule)
{
    if (!device || !rule) {
        fprintf(stderr, "Invalid arguments to packetSniffer\n");
        exit(EXIT_FAILURE);
    }
    int result = validate_dev(device);
    if (result == INVALID_DEV) {
        fprintf(stderr, "Error finding device: %s\n", device);
        exit(EXIT_FAILURE);
    }
    pcap_t *capture_handle = pcap_create(device, ERR_BUFFER);
    if (capture_handle == NULL) {
        fprintf(stderr, "Error creating capture handle with device: %s\nError buffer: %s\n", device, ERR_BUFFER);
        exit(EXIT_FAILURE);
    }

    configure_pcap_handle(capture_handle);

    result = pcap_activate(capture_handle);
    if (result != ACTIVE_HANDLE) {
        fprintf(stderr, "Error activating handle\n");
        exit(EXIT_FAILURE);
    }
    result = pcap_iterator(capture_handle, INFINITE_CNT, packet_handler, (u_char *)rule);
    if (result != LOOP_BREAK) {
        fprintf(stderr, "Error processing packets\n");
        exit(EXIT_FAILURE);
    }
    pcap_close(capture_handle);
}
