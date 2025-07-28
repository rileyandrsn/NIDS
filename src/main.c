#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
int main() 
{
//char *device; // Name of device (i.e. eth0)
char errorBuffer[PCAP_ERRBUF_SIZE]; // Size defined as 256 in 'pcap.h'

pcap_if_t *alldevs;
pcap_if_t *dev;

pcap_findalldevs(&alldevs,errorBuffer);
printf("%s\n",alldevs->name);
pcap_if_t *temp = alldevs->next;

while(temp != NULL){
printf("%s\n",temp->name);
temp = temp->next;
}
pcap_freealldevs(alldevs);
pcap_freealldevs(temp);




//printf("Device: %s",device);
}