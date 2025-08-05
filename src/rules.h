#ifndef RULES_H
#define RULES_H

#include <json-c/json.h>
#include <stdio.h>
#include "parser.h"



typedef struct {
    char name[128];       // or use [NAME_SIZE] after the extern fix
    char action[16];
    char msg[256];
    char protocol[8];
} rule_t;

int validate_rule(rule_t rule);
int validate_rules(struct json_object *parsed_json);
struct json_object *load_rules();
int rule_check(struct json_object *parsed_json, packet_t pkt);

#endif // RULES_H
