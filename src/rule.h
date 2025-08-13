#ifndef RULE_H
#define RULE_H

// --- Struct definitions ---

typedef struct rule_t {
    char name[128];
    char action[16];
    char msg[256];
    char protocol[8];
    char src_addr[32];
    char src_port[6];
    char dst_addr[32];
    char dst_port[6];
    uint8_t flags;
    struct rule_t *next;
} rule_t;

#endif