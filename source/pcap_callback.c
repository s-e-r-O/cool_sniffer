#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"


void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    
	static int count = 1;
	printf("\n========================================\n\n");
    printf("Count: %d\nCaplen: %u\nLen: %u\n", count, h->caplen, h->len);
    
    count++;

    if ((h->caplen) == (h->len))
    {
    	ether_reader(bytes, h->len);
    }

      
}