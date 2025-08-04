#ifndef CLI_H
#define CLI_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sniffer.h"

// Constants
extern const int PACKET_BUFFER_SIZE;
extern const uint8_t FLAG_DEVICE;
extern const uint8_t FLAG_HEX;
extern const uint8_t FLAG_VERBOSE;
extern const uint8_t FLAG_WEB;

// Hex configuration structure
typedef struct{
    char *hex; // Hex values for parsing
    int hex_len; // Length of hex input
}hex_config_t;

// Union for type configuration (either hex or device)
typedef union{
    hex_config_t hex_t;
    char dev[16];
} type_config;

// Main CLI configuration structure
typedef struct{
    type_config type; // Choose either hex or device
    uint8_t flags; // Flag options
}cli_config_t;

// Function declarations
cli_config_t arg_handler(int argc, char *argv[]);
void printUsage();

#endif // CLI_H