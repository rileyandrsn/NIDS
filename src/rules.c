// --- External header imports ---
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

// --- Internal header imports ---
#include "packet.h"
#include "rules.h"

// --- Global variables ---
const int NAME_SIZE = 128;
const int ACTION_SIZE = 16;
const int MSG_SIZE = 256;
const int PROTOCOL_SIZE = 8;
const char *ACTION_TYPES[] = { "ALERT", "LOG" };
const int ACTION_TYPES_LEN = sizeof(ACTION_TYPES) / sizeof(ACTION_TYPES[0]);
const char *PROTOCOL_TYPES[] = { "TCP", "UDP", "ICMP", "ARP" };
const int PROTOCOL_TYPES_LEN = sizeof(PROTOCOL_TYPES) / sizeof(PROTOCOL_TYPES[0]);
const int VALID_RULE = 0;
const int INVALID_RULE = -1;
const int FILE_BUFF_SIZE = 1024;

// --- Function declarations ---

/*
Function: load_rules()
Loads rules.json file and reads contents to a json_object struct

Returns: struct json_object *pointer
parsed_json - pointer to json_object holding parsed_json form rules.json
NULL - Error opening rules.json file
*/
struct json_object *load_rules()
{
    char buffer[FILE_BUFF_SIZE]; // buffer to hold json file content
    struct json_object *parsed_json; // json_object struct to hold json file content
    FILE *file_ptr;

    file_ptr = fopen("/Users/rileyanderson/Documents/GitHub/NIDS/config/rules.json", "r");

    if (!file_ptr) {
        fprintf(stderr, "Error opening file");
        return NULL;
    }

    fread(buffer, FILE_BUFF_SIZE, 1, file_ptr);
    fclose(file_ptr);

    parsed_json = json_tokener_parse(buffer);
    return parsed_json;
}

/*
Function: int validate_rule(rule_t rule)
Checking if fields user specified in rules.json have valid values

Parameters:
rule - rule structure holding fields specified in rules.json
Returns: int
INVALID_RULE - If value user specified for a field does not match any allowed values
VALID_RULE - All values user specifies for rule fields are valid
*/
int validate_rule(rule_t rule)
{
    int is_valid = 0;

    for (int i = 0; i < ACTION_TYPES_LEN; i++) {
        if (strcmp(ACTION_TYPES[i], rule.action) == 0) {
            is_valid = 1;
        }
    }

    printf("1. %d\n", is_valid);

    if (is_valid == 0) {
        fprintf(stderr, "INVALID ACTION TYPE IN RULE\n");
        return INVALID_RULE;
    }

    is_valid = 0;

    for (int i = 0; i < PROTOCOL_TYPES_LEN; i++) {
        if (strcmp(PROTOCOL_TYPES[i], rule.protocol) == 0) {
            is_valid = 1;
        }
    }

    printf("2. %d\n", is_valid);

    if (is_valid == 0) {
        fprintf(stderr, "INVALID PROTOCOL TYPE IN RULE\n");
        return INVALID_RULE;
    }

    printf("ALL RULES VALID\n");
    return VALID_RULE;
}

/*
Function: rule_t *validate_rules(struct json_object *parsed_json)
Creates a structure to hold rule fields for each rule in rules.json and calls validate_rule() to check if each rule is valid

Parameters:
*parsed_json - json_object holding content of rules.json

Returns: rule_t
*pointer pointing toward head node of linked list storing rules
NULL if an invalid rule is detected
*/
rule_t *validate_rules(struct json_object *parsed_json)
{
    rule_t *head = NULL;
    rule_t *current = NULL;
    struct json_object *json_rule; // Stores each separate rule
    struct json_object *json_name;
    struct json_object *json_action;
    struct json_object *json_msg;
    struct json_object *json_protocol;
    int len = json_object_array_length(parsed_json);

    for (int i = 0; i < len; i++) {
        rule_t *rule = malloc(sizeof(rule_t));
        if(rule == NULL){
            //add something else here
            exit(EXIT_FAILURE);
        }
        json_rule = json_object_array_get_idx(parsed_json, i);
        printf("\nRule: %s\n", json_object_get_string(json_rule));

        // Copy values from JSON fields into struct's fields
        json_object_object_get_ex(json_rule, "name", &json_name);
        strncpy(rule->name, json_object_get_string(json_name), NAME_SIZE - 1);
        rule->name[NAME_SIZE - 1] = '\0';

        json_object_object_get_ex(json_rule, "action", &json_action);
        strncpy(rule->action, json_object_get_string(json_action), ACTION_SIZE - 1);
        rule->action[ACTION_SIZE - 1] = '\0';

        json_object_object_get_ex(json_rule, "msg", &json_msg);
        strncpy(rule->msg, json_object_get_string(json_msg), MSG_SIZE - 1);
        rule->msg[MSG_SIZE - 1] = '\0';

        json_object_object_get_ex(json_rule, "protocol", &json_protocol);
        strncpy(rule->protocol, json_object_get_string(json_protocol), PROTOCOL_SIZE - 1);
        rule->protocol[PROTOCOL_SIZE - 1] = '\0';

        int result = validate_rule(*rule);
        if (result != VALID_RULE) {
            return NULL;
        }

        if(head==NULL){
            head = rule;
        }else{
            current->next = rule;
        }
        current = rule;

        printf("\n{\n");
        printf("name: %s \n", rule->name);
        printf("action: %s \n", rule->action);
        printf("msg: %s \n", rule->msg);
        printf("protocol: %s \n}", rule->protocol);
    }
    return head;
}

/*
Function: void rule_check(rule_t *head, packet_t pkt)
Checks each rule specified in rules.json against a packet

Parameters:
*head - head node of linked list storing rules
pkt - packet structure to be checked

Returns: void
*/
void rule_check(rule_t *head, packet_t pkt)
{
    rule_t *temp = head;
    while(temp != NULL){
        if(strcmp(pkt.proto,temp->protocol) == 0){
            printf("ALERT");
        }
        temp = temp->next;
    }

}
