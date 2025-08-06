#ifndef SNIFFER_H
#define SNIFFER_H

// --- External header imports ---
#include <json-c/json.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Global Variables ---
#define PACKET_BUFFER_SIZE 65535 // Maximum packet buffer size in bytes

// --- Function declarations ---

/*
Function: packetSniffer(char *device, struct json_object *parsed_json)
Takes user specified device, validates it, creates a capture handle for device, captures packets

Parameters:
*device - the name of the device user specified
*parsed_json - json object holding data from rules.json file
Returns: void
*/
void packetSniffer(char *device, struct json_object *parsed_json);

#endif // SNIFFER_H
