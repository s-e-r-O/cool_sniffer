#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>

#include "header_reader.h"

int tcp_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	struct tcphdr *headerTCP = (struct tcphdr *) bytes;
	
  printf("Source Port: %u\n", ntohs(headerTCP->th_sport));
  printf("Destination Port: %u\n", ntohs(headerTCP->th_dport));
  printf("Sequence Number: %u\n", ntohl(headerTCP->th_seq));
  printf("Acknowledgment Number: %u\n", ntohl(headerTCP->th_ack));
  printf("Data Offset: %u\n", headerTCP->th_off);
  printf("Flags:\n");
  if (!headerTCP->th_flags) {
  	printf("\tNone\n");
  } else {
  	u_int8_t flags[6] = {TH_URG, TH_ACK, TH_PUSH, TH_RST, TH_SYN, TH_FIN};
  	char* flagsStr[6] = {"URG", "ACK", "PSH", "RST", "SYN", "FIN"};
  	int i;
  	for (i = 0; i < 6; i++){
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

  //SEND TO AN APLICATION LAYER FUNCTION THE NEXT PARAMETER (bytes + headerTCP -> th_off * 4);
}	
