#ifndef CLI_H
#define CLI_H

// --- External header imports ---
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Internal header imports ---
#include "sniffer.h"

// --- Global Variables ---
extern const uint8_t FLAG_DEVICE;
extern const uint8_t FLAG_HEX;
extern const uint8_t FLAG_VERBOSE;
extern const uint8_t FLAG_WEB;

// --- Struct definitions ---

// Hex configuration structure
typedef struct {
    char *hex; // Hex values for parsing
    int hex_len; // Length of hex input
} hex_config_t;

// Union for type configuration (either hex or device)
typedef union {
    hex_config_t hex_t;
    char dev[16];
} type_config;

// Main CLI configuration structure
typedef struct {
    type_config type; // Choose either hex or device
    uint8_t flags; // Flag options
} cli_config_t;

// --- Function declarations ---

/*
Function: print_usage()
Prints all possible commands and how to use them

Returns: void
*/
void printUsage();

/*
Function: cli_config_t arg_handler(int argc, char *argv[])
Takes users cli input and handles it by creating a structure of users intent

Parameters:
argc - number of arguments
*argv[] - char array holding each argument

Returns: cli_config_t
config - structure of user's arguments
*/
cli_config_t arg_handler(int argc, char *argv[]);

/*
Function: int arg_validator(int argc)
Takes users cli input and handles it by checking if length of argument is valid

Parameters:
argc - number of arguments

Returns: int
-1 - number of arguments is invalid
0 - valid number of arguments
*/
int arg_validator(int argc);

#endif // CLI_H