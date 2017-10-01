#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>

#include "header_reader.h"

int tcp_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
  printf("\n----------------- TCP ------------------\n\n");

	struct tcphdr *headerTCP = (struct tcphdr *) bytes;
	
  printf("Source Port: %u\n", ntohs(headerTCP->th_sport));
  printf("Destination Port: %u\n", ntohs(headerTCP->th_dport));
  
  if(ntohs(headerTCP->th_dport) == 20 || ntohs(headerTCP->th_sport == 20))
  {
    printf("  File Transfer Protocol FTP.\n");
  }
  else if(ntohs(headerTCP->th_dport) == 80 || ntohs(headerTCP->th_sport == 80))
  {
    printf("  Hypertext Transfer Protocol HTTP.\n");
  }
  else if(ntohs(headerTCP->th_dport) == 443 || ntohs(headerTCP->th_sport == 443))
  {
    printf("  Hypertext Transfer Protocol HTTPS.\n");
  }

  printf("Sequence Number: %u\n", ntohl(headerTCP->th_seq));
  printf("Acknowledgment Number: %u\n", ntohl(headerTCP->th_ack));
  printf("Data Offset: %u\n", headerTCP->th_off);
  printf("Flags:\n");
  if (!headerTCP->th_flags) 
  {
  	printf("\tNone\n");
  } 
  else 
  {
  	u_int8_t flags[6] = {TH_URG, TH_ACK, TH_PUSH, TH_RST, TH_SYN, TH_FIN};
  	char* flagsStr[6] = {"URG", "ACK", "PSH", "RST", "SYN", "FIN"};
  	int i;
  	for (i = 0; i < 6; i++)
    {
  		printf("\t%s: ", flagsStr[i]);
	 		if (headerTCP->th_flags & flags[i])
	 			printf("On\n");
	 		else
	 			printf("Off\n");	
  	}
  }
  printf("Window: %u\n", ntohs(headerTCP->th_win));
  printf("Checksum: %u\n", ntohs(headerTCP->th_sum));
  printf("Urgent Pointer: %u\n", ntohs(headerTCP->th_urp));

  http_reader(bytes + headerTCP->th_off*4, dataLength - headerTCP->th_off*4);
}	
