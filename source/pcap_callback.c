#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <time.h>

#include "header_reader.h"

void print_time(struct timeval tv);

void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    static int count = 1;
    
    printf("\n========================================\n\n");
    printf("Packet #%d\n", count);
    count++;

    print_time(h->ts);
    printf("Captured Length: %u\nPacket Length: %u\n", count, h->caplen, h->len);
   
    if ((h->caplen) == (h->len))
    {
    	ether_reader(bytes, h->len);
    }
      
}

void print_time(struct timeval tv){
	time_t time;
	struct tm *local_time;
	char timeStr[64];
	
	time = tv.tv_sec;
	local_time = localtime(&time);

	strftime(timeStr, sizeof(timeStr), "%d-%m-%Y (%H:%M:%S", local_time);
	printf("%s.%06ld)\n", timeStr, tv.tv_usec);
}