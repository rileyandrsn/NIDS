#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

int packetSniffer(char *device, struct json_object *parsed_json);

#endif  // SNIFFER_H
