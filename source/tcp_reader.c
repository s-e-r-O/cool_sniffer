#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>

#include "header_reader.h"

int tcp_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
  printf("\n----------------- TCP ------------------\n\n");

  //printf("Data Length: %u\n", dataLength);
	struct tcphdr *headerTCP = (struct tcphdr *) bytes;
	
  printf("Source Port: %u\n", ntohs(headerTCP->th_sport));
  printf("Destination Port: %u\n", ntohs(headerTCP->th_dport));
  
  u_int32_t app_port;

  if(ntohs(headerTCP->th_dport) == PORT_FTP || ntohs(headerTCP->th_sport == PORT_FTP))
  {
    printf("\tFile Transfer Protocol (FTP).\n");
    app_port = PORT_FTP;
  }
  else if(ntohs(headerTCP->th_dport) == PORT_HTTP || ntohs(headerTCP->th_sport == PORT_HTTP))
  {
    printf("\tHypertext Transfer Protocol (HTTP).\n");
    app_port = PORT_HTTP;
  }
  else if(ntohs(headerTCP->th_dport) == PORT_HTTPS || ntohs(headerTCP->th_sport == PORT_HTTPS))
  {
    printf("\tHypertext Transfer Protocol (HTTPS).\n");
    app_port = PORT_HTTPS;
  }
  else if(ntohs(headerTCP->th_dport) == PORT_SSH || ntohs(headerTCP->th_sport == PORT_SSH))
  {
    printf("\tSecure Shell (SSH).\n");
    app_port = PORT_SSH;
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
  switch(app_port)
  {
    case PORT_FTP:
      //ftp_reader(bytes + headerTCP->th_off*4, dataLength - headerTCP->th_off*4);
      break;
    case PORT_HTTP:
      http_reader(bytes + headerTCP->th_off*4, dataLength - headerTCP->th_off*4);
      break;
    case PORT_HTTPS:
      //https_reader(bytes + headerTCP->th_off*4, dataLength - headerTCP->th_off*4);
      break;
    case PORT_SSH:
      //ssh_reader(bytes + headerTCP->th_off*4, dataLength - headerTCP->th_off*4);
      break;
  }
  
}	
