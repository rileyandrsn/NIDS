// --- External header imports ---
#include <json-c/json.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// --- Internal header imports ---
#include "cli.h"
#include "parser.h"
#include "rule.h"
#include "rules.h"
#include "sniffer.h"

// --- Global Variables ---

const int RESULT_ERR = -1;

void intro_text()
{
    printf("Welcome to\n\n\n");
    printf("#####      #####      #####      ##########       ############\n");
    usleep(100000);
    printf("#######    #####      #####      ###########      ###         \n");
    usleep(100000);
    printf("#########  #####      #####      ####     ###     ##          \n");
    usleep(100000);
    printf("#####  ### #####      #####      ####      ###    #########   \n");
    usleep(100000);
    printf("#####   ########      #####      ####      ###       #########\n");
    usleep(100000);
    printf("#####    #######      #####      ####     ###               ##\n");
    usleep(100000);
    printf("#####     ######      #####      ###########               ###\n");
    usleep(100000);
    printf("#####      #####      #####      ##########       ############\n");
    usleep(150000);
}

// --- Program entry point ---

int main(int argc, char *argv[])
{
    intro_text();
    int result = arg_validator(argc);
    if (result == RESULT_ERR) {
        exit(EXIT_FAILURE);
    }

    cli_config_t config = arg_handler(argc, argv);

    struct json_object *json = load_rules();
    if (json == NULL) {
        exit(EXIT_FAILURE);
    }

    rule_t *rule = validate_rules(json);
    if (rule == NULL) {
        json_object_put(json);
        exit(EXIT_FAILURE);
    }

    if (config.flags & FLAG_DEVICE) {
        load_device(config.type.dev, rule);
    } else if (config.flags & FLAG_HEX) {
        parse_hex_input(config.type.hex_t.hex, config.type.hex_t.hex_len, rule);
        free(config.type.hex_t.hex);
    } else if (config.flags & FLAG_FILE) {
        load_pcap_file(config.type.filepath, rule);
        free(config.type.filepath);
    } else {
        fprintf(stderr, "No valid flags set. Use --help for usage information.\n");
    }

    json_object_put(json);
    return 0;
}
