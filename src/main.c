#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sniffer.h"
const int PACKET_BUFFER_SIZE = 65536;  // Maximum packet buffer size in bytes
const int max_valid_args = 7;
const uint8_t FLAG_DEVICE = 0x01;
const uint8_t FLAG_HEX = 0x02;
const uint8_t FLAG_VERBOSE = 0x04;
const uint8_t FLAG_WEB = 0x08;
uint8_t flags;
char dev[16];
char *hex;

int main(int argc, char *argv[]) {
    if(!argc)return -1;
    if(argc > max_valid_args){
        printf("TOO MANY ARGUMENTS");
        exit(EXIT_FAILURE);
    }else if(argc < 2){
        printf("\nIntended use: ./pinids FLAGS start\n");
        printf("List of flags:\n");
        printf("-i <device | Max size 16 chars> : Indicate which device to capture packets from\n");
        printf("-c <hex bytes | Max size 65,536 chars> : Enter custom packet input as bytes NOT separated by whitespace\n");
        printf("-v : Enter verbose mode, displays all packet information; default is nonverbose mode\n");
        printf("-web : Opens localhost web page for visualization\n");
        printf("\nIf both -i and -c flag are set, device will be ignored and hex will be run\n");
        exit(EXIT_FAILURE);
    }
    int i = 1;
    while(i < argc){
        if(strcmp(argv[i],"-i") == 0){
            if((i+1) >= argc){
                printf("DEVICE NOT GIVEN\n");
                exit(EXIT_FAILURE);
            }
            strncpy(dev,argv[i+1],sizeof(dev)-1);
            dev[sizeof(dev) - 1] = '\0';
            flags |= FLAG_DEVICE;
            printf("Dev: %s\n",dev);
            printf("-FLAG_DEVICE SET\n");
            i++;
        }else if(strcmp(argv[i],"-c") == 0){
            if((i+1) >= argc){
                printf("HEX NOT GIVEN\n");
                exit(EXIT_FAILURE);
            }
            int hex_len = strlen(argv[i+1]);
            if(hex_len > PACKET_BUFFER_SIZE){
                printf("TOO MANY BYTES");
                exit(EXIT_FAILURE);
            }
            hex = malloc(hex_len + 1);
            strncpy(hex,argv[i+1],hex_len);
            hex[hex_len] = '\0';
            flags |= FLAG_HEX;
            printf("HEX: %s\n",hex);
            printf("-FLAG_HEX SET\n");
            i++;
        }else if(strcmp(argv[i],"-v") == 0){
            flags |= FLAG_VERBOSE;
            printf("-FLAG_VERBOSE SET\n");
        }else if(strcmp(argv[i],"-web") == 0){
            flags |= FLAG_WEB;
            printf("-FLAG_WEB SET\n");
        }else{
            printf("UNKNOWN COMMAND FOUND: %s\n",argv[i]);
            printf("Use ./pinids -help for list of commands\n");
        }
    i++;
    }
printf("FLAGS: %d",flags);
if(flags & FLAG_HEX) free(hex);
return 0;
}