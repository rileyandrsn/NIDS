#ifndef SNIFFER_H
#define SNIFFER_H

// --- External header imports ---
#include <json-c/json.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Internal header imports ---
#include "rule.h"

// --- Global Variables ---
#define PACKET_BUFFER_SIZE 65535 // Maximum packet buffer size in bytes

// --- Function declarations ---

/*
Function: packetSniffer(char *device, struct json_object *parsed_json)
Takes user specified device, validates it, creates a capture handle for device, captures packets

Parameters:
*device - the name of the device user specified
*rule - pointer to head of linked list storing rules
Returns: void
*/
void packetSniffer(char *device, rule_t *rule);

#endif // SNIFFER_H
