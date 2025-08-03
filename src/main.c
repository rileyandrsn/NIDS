#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sniffer.h"

int main(int argc, char *argv[]) {
  char *device = "en0";  // TEMP default device name
  if (argc >= 2) {
    if (strcmp("-i", argv[1]) == 0 && argc >= 3) {
      device = argv[2];
      printf("Using device: %s\n", device);
    } else if (strcmp("start", argv[1]) == 0) {
      printf("Starting sniffer\n");
      packetSniffer();
      return 0;
    } else {
      printf("Usage: %s [-i <device>] | start\n", argv[0]);
      printf("  -i <device>  Specify network device (default: en0)\n");
      printf("  start        Start the packet sniffer\n");
      return 1;
    }
  } else {
    printf("Usage: %s [-i <device>] | start\n", argv[0]);
    printf("  -i <device>  Specify network device (default: en0)\n");
    printf("  start        Start the packet sniffer\n");
    return 1;
  }

  return 0;
}
