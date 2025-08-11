// --- External header imports ---
#include <arpa/inet.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// --- Internal header imports ---
#include "packet.h"
#include "parser.h"
#include "rule.h"

// --- Global variables ---
const int NAME_SIZE = 128;
const int ACTION_SIZE = 16;
const int MSG_SIZE = 256;
const int PROTOCOL_SIZE = 8;
const int PORT_SIZE = 6;
const int ADDR_SIZE = 32;
const char *ACTION_TYPES[] = { "ALERT", "LOG" };
const int ACTION_TYPES_LEN = sizeof(ACTION_TYPES) / sizeof(ACTION_TYPES[0]);
const char *PROTOCOL_TYPES[] = { "TCP", "UDP", "ICMP", "ARP", "ANY" };
const int PROTOCOL_TYPES_LEN = sizeof(PROTOCOL_TYPES) / sizeof(PROTOCOL_TYPES[0]);
const int VALID_RULE = 0;
const int INVALID_RULE = -1;
const int FILE_BUFF_SIZE = 6000;
const char *const LOG_FILE_PATH = "/Users/rileyanderson/Documents/GitHub/NIDS/docs/events.log";
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
    struct json_object *json_src_addr;
    struct json_object *json_src_port;
    struct json_object *json_dst_addr;
    struct json_object *json_dst_port;
    struct json_object *json_flags;
    int len = json_object_array_length(parsed_json);

    for (int i = 0; i < len; i++) {
        rule_t *rule = malloc(sizeof(rule_t));
        if (rule == NULL) {
            return NULL;
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

        if (json_object_object_get_ex(json_rule, "protocol", &json_protocol)) {
            strncpy(rule->protocol, json_object_get_string(json_protocol), PROTOCOL_SIZE - 1);
            rule->protocol[PROTOCOL_SIZE - 1] = '\0';
        } else {
            strncpy(rule->protocol, "ANY", PROTOCOL_SIZE - 1);
            rule->protocol[PROTOCOL_SIZE - 1] = '\0';
        }

        if (json_object_object_get_ex(json_rule, "src_addr", &json_src_addr)) {
            strncpy(rule->src_addr, json_object_get_string(json_src_addr), ADDR_SIZE - 1);
            rule->src_addr[ADDR_SIZE - 1] = '\0';
        } else {
            strncpy(rule->src_addr, "ANY", ADDR_SIZE - 1);
            rule->src_addr[ADDR_SIZE - 1] = '\0';
        }

        if (json_object_object_get_ex(json_rule, "src_port", &json_src_port)) {
            strncpy(rule->src_port, json_object_get_string(json_src_port), PORT_SIZE - 1);
            rule->src_port[PORT_SIZE - 1] = '\0';
        } else {
            strncpy(rule->src_port, "ANY", PORT_SIZE - 1);
            rule->src_port[PORT_SIZE - 1] = '\0';
        }

        if (json_object_object_get_ex(json_rule, "dst_addr", &json_dst_addr)) {
            strncpy(rule->dst_addr, json_object_get_string(json_dst_addr), ADDR_SIZE - 1);
            rule->dst_addr[ADDR_SIZE - 1] = '\0';
        } else {
            strncpy(rule->dst_addr, "ANY", ADDR_SIZE - 1);
            rule->dst_addr[ADDR_SIZE - 1] = '\0';
        }

        if (json_object_object_get_ex(json_rule, "dst_port", &json_dst_port)) {
            strncpy(rule->dst_port, json_object_get_string(json_dst_port), PORT_SIZE - 1);
            rule->dst_port[PORT_SIZE - 1] = '\0';
        } else {
            strncpy(rule->dst_port, "ANY", PORT_SIZE - 1);
            rule->dst_port[PORT_SIZE - 1] = '\0';
        }

        if (json_object_object_get_ex(json_rule, "flags", &json_flags)) {
            rule->flags = json_object_get_uint64(json_flags);
        } else {
            rule->flags = 255;
        }

        int result = validate_rule(*rule);
        if (result != VALID_RULE) {
            free(rule);
            return NULL;
        }

        if (head == NULL) {
            head = rule;
        } else {
            current->next = rule;
        }
        current = rule;

        printf("\n{\n");
        printf("name: %s \n", rule->name);
        printf("action: %s \n", rule->action);
        printf("msg: %s \n", rule->msg);
        printf("protocol: %s \n}", rule->protocol);
        printf("source addr: %s \n}", rule->src_addr);
        printf("source port: %s \n}", rule->src_port);
        printf("dest addr: %s \n}", rule->dst_addr);
        printf("dest port: %s \n}", rule->dst_port);
    }
    return head;
}

// Function pointer for rule-matching functions
typedef int (*rule_match_func)(rule_t *rule, packet_t pkt);

/*
Function: int match_protocol(rule_t *rule, packet_t pkt)
Check if rule's protocol field matches packet's protocol field

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_protocol(rule_t *rule, packet_t pkt)
{
    if (strcmp(rule->protocol, pkt.proto) == 0 || strcmp(rule->protocol, "ANY") == 0) {
        return 0;
    } else {
        return 1;
    }
}

/*
Function: int match_src_port(rule_t *rule, packet_t pkt)
Check if rule's source port field matches packet's source port

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_src_port(rule_t *rule, packet_t pkt)
{
    if (strcmp(rule->src_port, "ANY") == 0) {
        return 0;
    } else if ((pkt.net_hdr.ipv4_hdr.protocol == 6) || (pkt.net_hdr.ipv6_hdr.next_hdr == 6)) {
        char str[6];
        sprintf(str, "%d", ntohs(pkt.trans_hdr.tcp_hdr.src_port));
        if (strcmp(rule->src_port, str) == 0) {
            return 0;
        } else {
            return 1;
        }
    } else if ((pkt.net_hdr.ipv4_hdr.protocol == 17) || (pkt.net_hdr.ipv6_hdr.next_hdr == 17)) {
        char str[6];
        sprintf(str, "%d", ntohs(pkt.trans_hdr.udp_hdr.src_port));
        if (strcmp(rule->src_port, str) == 0) {
            return 0;
        } else {
            return 1;
        }
    } else {
        return 1;
    }
}

/*
Function: int match_dst_port(rule_t *rule, packet_t pkt)
Check if rule's destination port field matches packet's destination port

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_dst_port(rule_t *rule, packet_t pkt)
{
    if (strcmp(rule->dst_port, "ANY") == 0) {
        return 0;
    } else if ((pkt.net_hdr.ipv4_hdr.protocol == 6) || (pkt.net_hdr.ipv6_hdr.next_hdr == 6)) {
        char str[6];
        sprintf(str, "%d", ntohs(pkt.trans_hdr.tcp_hdr.dst_port));
        if (strcmp(rule->dst_port, str) == 0) {
            return 0;
        } else {
            return 1;
        }
    } else if ((pkt.net_hdr.ipv4_hdr.protocol == 17) || (pkt.net_hdr.ipv6_hdr.next_hdr == 17)) {
        char str[6];
        sprintf(str, "%d", ntohs(pkt.trans_hdr.udp_hdr.dst_port));
        if (strcmp(rule->dst_port, str) == 0) {
            return 0;
        } else {
            return 1;
        }
    } else {
        return 1;
    }
}

/*
Function: int match_src_addr(rule_t *rule, packet_t pkt)
Check if rule's source IP address matches packet's source IP address

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_src_addr(rule_t *rule, packet_t pkt)
{
    if (strcmp(rule->src_addr, "ANY") == 0)
        return 0;

    switch (ntohs(pkt.eth_hdr.eth_type)) {
    case 0x0800: { // IPv4
        struct in_addr src_ipv4;
        src_ipv4.s_addr = pkt.net_hdr.ipv4_hdr.src_ip;
        if (strcmp(rule->src_addr, inet_ntoa(src_ipv4)) == 0) {
            return 0;
        } else {
            return 1;
        }
        break;
    }
    case 0x86DD: { // IPv6
        char src_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt.net_hdr.ipv6_hdr.src_addr, src_ipv6, INET6_ADDRSTRLEN);
        if (strcmp(rule->src_addr, src_ipv6) == 0) {
            return 0;
        } else {
            return 1;
        }
        break;
    }
    default:
        printf("\nUNKNOWN PROTOCOL\n");
        return 1;
    }
}

/*
Function: int match_dst_addr(rule_t *rule, packet_t pkt)
Check if rule's destination IP address matches packet's destination IP address

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_dst_addr(rule_t *rule, packet_t pkt)
{
    if (strcmp(rule->dst_addr, "ANY") == 0)
        return 0;

    switch (ntohs(pkt.eth_hdr.eth_type)) {
    case 0x0800: { // IPv4
        struct in_addr dst_ipv4;
        dst_ipv4.s_addr = pkt.net_hdr.ipv4_hdr.dst_ip;
        if (strcmp(rule->dst_addr, inet_ntoa(dst_ipv4)) == 0) {
            return 0;
        } else {
            return 1;
        }
        break;
    }
    case 0x86DD: { // IPv6
        char dst_ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pkt.net_hdr.ipv6_hdr.dst_addr, dst_ipv6, INET6_ADDRSTRLEN);
        if (strcmp(rule->dst_addr, dst_ipv6) == 0) {
            return 0;
        } else {
            return 1;
        }
        break;
    }
    default:
        printf("\nUNKNOWN PROTOCOL\n");
        return 1;
    }
}

/*
Function: int match_flags(rule_t *rule, packet_t pkt)
Check if rule's TCP flags match with the TCP flags of the packet
(NOTE): the input for rule->flags is like wireshark, ex: tcp.flags == 16 to match Flags: 0x10 (ACK)

Parameters:
*rule - list node storing a rule structure
pkt - packet structure to be checked

Returns: int
0 - if a match is found
1 - if no match is found
*/
int match_flags(rule_t *rule, packet_t pkt)
{
    if (rule->flags == 255)
        return 0;
    if ((rule->flags == pkt.trans_hdr.tcp_hdr.flags) && strcmp(rule->protocol, "TCP") == 0) {
        return 0;
    } else {
        return 1;
    }
}

int log_event(rule_t *rule)
{
    printf("Log\n");
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    if (!log_file)
        return 0;
    fprintf(log_file, "%s |[%s] %s | %s %s %s -> %s %s {Flags: 0x%x/%d}\n",
        timestamp, rule->action, rule->msg, rule->protocol, rule->src_addr, rule->src_port, rule->dst_addr, rule->dst_port, rule->flags, rule->flags);
    fclose(log_file);
    return 1;
}

/*
Function: void trigger_action(rule_t *rule)
Triggers selected action specified by action field in rules.jsons

Parameters:
*rule - list node storing a rule structure

Returns: void
*/
void trigger_action(rule_t *rule)
{
    if (strcmp(rule->action, "ALERT") == 0) {
        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        timestamp[strlen(timestamp) - 1] = '\0';
        printf("%s |[%s] %s | %s %s %s -> %s %s {Flags: 0x%x/%d}\n",
            timestamp, rule->action, rule->msg, rule->protocol, rule->src_addr, rule->src_port, rule->dst_addr, rule->dst_port, rule->flags, rule->flags);
    } else if (strcmp(rule->action, "LOG") == 0) {
        if (!log_event(rule)) {
            fprintf(stderr, "Error printing log\n");
        }
    }
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
    rule_match_func match_functions[] = {
        match_protocol,
        match_src_addr,
        match_src_port,
        match_dst_addr,
        match_dst_port,
        match_flags
    };

    int num_matchers = sizeof(match_functions) / sizeof(match_functions[0]);

    for (rule_t *r = head; r != NULL; r = r->next) {
        int matched_all = 1; // Assume the rule matches until a matcher fails

        for (int i = 0; i < num_matchers; i++) {
            if (match_functions[i](r, pkt) != 0) {
                matched_all = 0; // This rule field did not match
                break; // Stop checking this rule
            }
        }

        if (matched_all) {
            trigger_action(r); // All fields matched
        }
    }
}
