#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include "parser.h"

const int NAME_SIZE = 128;
const int ACTION_SIZE = 16;
const int MSG_SIZE = 256;
const int PROTOCOL_SIZE = 8;
const char *ACTION_TYPES[] = {"ALERT", "LOG"};
const int ACTION_TYPES_LEN = sizeof(ACTION_TYPES) / sizeof(ACTION_TYPES[0]);
const char *PROTOCOL_TYPES[] = {"TCP", "UDP", "ICMP", "ARP"};
const int PROTOCOL_TYPES_LEN = sizeof(PROTOCOL_TYPES) / sizeof(PROTOCOL_TYPES[0]);

typedef struct{
    char name[NAME_SIZE];
    char action [ACTION_SIZE];
    char msg [MSG_SIZE];
    char protocol[8];
} rule_t;

struct json_object *load_rules() {
    FILE *fp;
    char buffer[1024];

    struct json_object *parsed_json;

    fp = fopen("/Users/rileyanderson/Documents/GitHub/NIDS/config/rules.json","r");
    if(!fp){
        printf("err");
    }
    fread(buffer,1024,1,fp);
    fclose(fp);
    parsed_json = json_tokener_parse(buffer);

return parsed_json;
}

int validate_rule(rule_t rule){
    int is_valid = 0;
    for(int i = 0; i < ACTION_TYPES_LEN; i++){
        if(strcmp(ACTION_TYPES[i], rule.action) == 0){
            is_valid = 1;
        }  
    }
    printf("1. %d\n", is_valid);
    if(is_valid == 0){
        fprintf(stderr, "INVALID ACTION TYPE IN RULE\n");
        return -1;
    }
    is_valid = 0;
    for(int i = 0; i < PROTOCOL_TYPES_LEN; i++){
        if(strcmp(PROTOCOL_TYPES[i], rule.protocol) == 0){
            is_valid = 1;
        }
    }
    printf("2. %d\n", is_valid);
    if(is_valid == 0){
        fprintf(stderr, "INVALID PROTOCOL TYPE IN RULE\n");
        return -2;
    }
    printf("ALL RULES VALID\n");
    return 0;
}

int validate_rules(struct json_object *parsed_json){
    rule_t rule;
    struct json_object *json_rule; // Stores each separate rule
    struct json_object *json_name;
    struct json_object *json_action;
    struct json_object *json_msg;
    struct json_object *json_protocol;
    int len = json_object_array_length(parsed_json);
    
    for(int i = 0; i<len; i++){
        json_rule = json_object_array_get_idx(parsed_json, i);
        printf("\nRule: %s\n",json_object_get_string(json_rule));

        // Copy values from JSON fields into struct's fields
        json_object_object_get_ex(json_rule,"name",&json_name);
        strncpy(rule.name,json_object_get_string(json_name),NAME_SIZE - 1);
        rule.name[NAME_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"action",&json_action);
        strncpy(rule.action,json_object_get_string(json_action),ACTION_SIZE - 1);
        rule.action[ACTION_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"msg",&json_msg);
        strncpy(rule.msg,json_object_get_string(json_msg),MSG_SIZE - 1);
        rule.msg[MSG_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"protocol",&json_protocol);
        strncpy(rule.protocol,json_object_get_string(json_protocol),PROTOCOL_SIZE - 1);
        rule.protocol[PROTOCOL_SIZE -1] = '\0';
        validate_rule(rule);

        printf("\n{\n");
        printf("name: %s \n", rule.name);
        printf("action: %s \n", rule.action);
        printf("msg: %s \n", rule.msg);
        printf("protocol: %s \n}", rule.protocol);
    }
    return 1;
}

int rule_check(struct json_object *parsed_json, packet_t pkt){
    rule_t rule;
    struct json_object *json_rule; // Stores each separate rule
    struct json_object *json_name;
    struct json_object *json_action;
    struct json_object *json_msg;
    struct json_object *json_protocol;
    int len = json_object_array_length(parsed_json);
    
    for(int i = 0; i<len; i++){
        json_rule = json_object_array_get_idx(parsed_json, i);

        // Copy values from JSON fields into struct's fields
        json_object_object_get_ex(json_rule,"name",&json_name);
        strncpy(rule.name,json_object_get_string(json_name),NAME_SIZE - 1);
        rule.name[NAME_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"action",&json_action);
        strncpy(rule.action,json_object_get_string(json_action),ACTION_SIZE - 1);
        rule.action[ACTION_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"msg",&json_msg);
        strncpy(rule.msg,json_object_get_string(json_msg),MSG_SIZE - 1);
        rule.msg[MSG_SIZE -1] = '\0';

        json_object_object_get_ex(json_rule,"protocol",&json_protocol);
        strncpy(rule.protocol,json_object_get_string(json_protocol),PROTOCOL_SIZE - 1);
        rule.protocol[PROTOCOL_SIZE -1] = '\0';
        validate_rule(rule);

        printf("\n%s\n",pkt.proto);

        printf("\n%s\n",rule.protocol);

        if(strcmp(pkt.proto, rule.protocol) == 0){
            printf("\nALERT\n");
        }
    }

    return 0;
}

