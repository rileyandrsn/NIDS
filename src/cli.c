// --- External header imports ---
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Internal header imports ---
#include "sniffer.h"

// --- Global Variables ---

// Hex values to bit mask flags
const uint8_t FLAG_DEVICE = 0x01;
const uint8_t FLAG_HEX = 0x02;
const uint8_t FLAG_VERBOSE = 0x04;
const uint8_t FLAG_WEB = 0x08;
const int MAX_VALID_ARGS = 7;

// --- Struct definitions ---

typedef struct {
    char *hex; // Hex values for parsing
    int hex_len; // Length of hex input
} hex_config_t;

typedef union {
    hex_config_t hex_t;
    char dev[16];
} type_config;

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
void print_usage()
{ // Print all available commands and usages
    printf("\nIntended use: ./pinids FLAGS start\n");
    printf("List of flags:\n");
    printf("-i <device | Max size 16 chars> : Indicate which device to capture packets from\n");
    printf("-c <hex bytes | Max size 65,536 chars> : Enter custom packet input as bytes NOT separated by whitespace\n");
    printf("-v : Enter verbose mode, displays all packet information; default is nonverbose mode\n");
    printf("-web : Opens localhost web page for visualization\n");
    printf("\nIf both -i and -c flag are set, device will be ignored and hex will be run\n");
}

/*
Function: cli_config_t arg_handler(int argc, char *argv[])
Takes users cli input and handles it by creating a structure of users intent

Parameters:
argc - number of arguments
*argv[] - char array holding each argument

Returns: cli_config_t
config - structure of user's arguments
*/
cli_config_t arg_handler(int argc, char *argv[])
{
    cli_config_t config;
    config.flags = 0;
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-i") == 0) {
            if ((i + 1) >= argc) { // Throw error if user does not specify name of device
                fprintf(stderr, "DEVICE NOT GIVEN\n");
                exit(EXIT_FAILURE);
            } else if (config.flags & FLAG_HEX) { // Throw error if user tries setting both device and hex flags
                fprintf(stderr, "CANNOT HAVE BOTH DEVICE AND HEX FLAGS SET\n");
                exit(EXIT_FAILURE);
            }
            strncpy(config.type.dev, argv[i + 1], sizeof(config.type.dev) - 1);
            config.type.dev[sizeof(config.type.dev) - 1] = '\0';
            config.flags |= FLAG_DEVICE;
            printf("Dev: %s\n", config.type.dev);
            printf("-FLAG_DEVICE SET\n");
            i++;

        } else if (strcmp(argv[i], "-c") == 0) {
            if ((i + 1) >= argc) {
                fprintf(stderr, "HEX NOT GIVEN\n");
                exit(EXIT_FAILURE);
            } else if (config.flags & FLAG_DEVICE) { // Throw error if user tries setting both device and hex flags
                fprintf(stderr, "CANNOT HAVE BOTH DEVICE AND HEX FLAGS SET\n");
                exit(EXIT_FAILURE);
            }
            config.type.hex_t.hex_len = strlen(argv[i + 1]);
            if (config.type.hex_t.hex_len > PACKET_BUFFER_SIZE) { // Throw error if hex input is larger than max size of a packet
                fprintf(stderr, "TOO MANY BYTES");
                exit(EXIT_FAILURE);
            }
            config.type.hex_t.hex = (char *)malloc(config.type.hex_t.hex_len + 1); // Allocate memory for hex input
            strncpy(config.type.hex_t.hex, argv[i + 1], config.type.hex_t.hex_len); // Copy hex input into struct hex field
            config.type.hex_t.hex[config.type.hex_t.hex_len] = '\0';
            config.flags |= FLAG_HEX;
            printf("HEX: %s\n", config.type.hex_t.hex);
            printf("-FLAG_HEX SET\n");
            i++;

        } else if (strcmp(argv[i], "-v") == 0) {
            config.flags |= FLAG_VERBOSE;
            printf("-FLAG_VERBOSE SET\n");
        } else if (strcmp(argv[i], "-web") == 0) {
            config.flags |= FLAG_WEB;
            printf("-FLAG_WEB SET\n");
        } else if (strcmp(argv[i], "-help") == 0) {
            print_usage();
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "UNKNOWN COMMAND FOUND: %s\nUse ./pinids -help for list of commands\n", argv[i]);
        }

        i++;
    }

    printf("FLAGS: %d", config.flags);
    return config;
}

/*
Function: int arg_validator(int argc)
Takes users cli input and handles it by checking if length of argument is valid

Parameters:
argc - number of arguments

Returns: int
-1 - number of arguments is invalid
0 - valid number of arguments
*/
int arg_validator(int argc)
{
    if (!argc) { // Return -1 if no arguments found
        return -1;
    } else if (argc > MAX_VALID_ARGS) {
        fprintf(stderr, "TOO MANY ARGUMENTS");
        return -1;
    } else if (argc < 2) {
        print_usage();
        return -1;
    } else {
        return 0;
    }
}