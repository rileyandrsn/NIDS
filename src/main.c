#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sniffer.h"
#include "cli.h"
const int max_valid_args = 7;

int main(int argc, char *argv[]) {

    if(!argc){ // Return -1 if no arguments found
        return -1;
    }else if(argc > max_valid_args){
       fprintf(stderr,"TOO MANY ARGUMENTS");
        exit(EXIT_FAILURE);
    }else if(argc < 2){
        printUsage();
        exit(EXIT_FAILURE);
    }else{
        cli_config_t config = arg_handler(argc,argv);
        if(!config){
            fprintf(stderr,"Issue handling arguments\n");
        }else if(config.flags & FLAG_DEVICE){
            //TODO: send to sniffer.c
        }else if (config.flags & FLAG_HEX){
            //TODO send to parser.c
        }
    }


return 0;
}