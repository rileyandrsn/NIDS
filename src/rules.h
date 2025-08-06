#ifndef RULES_H
#define RULES_H

// --- External header imports ---
#include <json-c/json.h>
#include <stdio.h>


// --- Internal header imports ---
#include "packet.h"
#include "parser.h"
#include "rule.h"

// --- Function declarations ---

// --- Function declarations ---

/*
Function: load_rules()
Loads rules.json file and reads contents to a json_object struct

Returns: struct json_object *pointer
parsed_json - pointer to json_object holding parsed_json form rules.json
NULL - Error opening rules.json file
*/
struct json_object *load_rules();

/*
Function: rule_t *validate_rules(struct json_object *parsed_json)
Creates a structure to hold rule fields for each rule in rules.json and calls validate_rule() to check if each rule is valid

Parameters:
*parsed_json - json_object holding content of rules.json

Returns: rule_t
*pointer pointing toward head node of linked list storing rules
NULL if an invalid rule is detected
*/
rule_t *validate_rules(struct json_object *parsed_json);

/*
Function: void rule_check(rule_t *head, packet_t pkt)
Checks each rule specified in rules.json against a packet

Parameters:
*head - head node of linked list storing rules
pkt - packet structure to be checked

Returns: void
*/
void rule_check(rule_t *rule, packet_t pkt);

#endif // RULES_H
